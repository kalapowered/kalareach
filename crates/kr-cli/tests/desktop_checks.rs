//! `kr host desktop-checks` against a real control daemon and the worker of a real session.
//!
//! The daemon and the worker are the `kr-controller-held` and `kr-worker` executables the workspace
//! builds beside this test. A workspace build always has them; a build of this crate alone that has
//! not built them yet fails and says why, rather than passing without having tested anything. Each
//! is copied to the internal disk before it starts, every process's working directory is inside
//! this test's own temporary host, and the daemon keeps its keys in that host's own secrets
//! directory. The host creates its sessions headless, whatever machine the test runs on, so the
//! worker of the session the case creates is the one the checks are performed in.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use kr_ipc::client::LocalClient;
use kr_ipc::testing::started_environment::{StartedEnvironment, USER_MANAGER_VARIABLES};
use kr_protocol::ids::BuildId;
use kr_protocol::local::LocalClientKind;
use serde_json::Value;

mod support;
#[path = "../../kr-controller/tests/teardown/mod.rs"]
mod teardown;

use support::kr;

/// How long a wait for something to happen is given. It fails when the thing never happens.
const LIVENESS_DEADLINE: Duration = Duration::from_secs(120);

/// Returns an executable the workspace builds beside this test, when it has been built.
fn beside_this_test(name: &str) -> Option<PathBuf> {
    let executable = std::env::current_exe().ok()?;
    // `<target>/<profile>/deps/<this test>`: the executables are in `<target>/<profile>`.
    let profile = executable.parent()?.parent()?;
    let candidate = profile.join(format!("{name}{}", std::env::consts::EXE_SUFFIX));
    candidate.is_file().then_some(candidate)
}

/// Copies an executable into `directory` and starts the copy once, where nothing is timed.
fn copy_into(source: &Path, directory: &Path, name: &str) -> PathBuf {
    let destination = directory.join(format!("{name}{}", std::env::consts::EXE_SUFFIX));
    kr_ipc::testing::place_and_start_once(source, &destination, &["--version"]);
    destination
}

fn build() -> BuildId {
    BuildId::new("kr-test/0").expect("a build identifier")
}

/// A host tree with a running daemon, and the `kr` that talks to it.
///
/// However a test ends, what it started ends with it and before its tree goes: the daemon here,
/// and then, through the tree, every worker the daemon recorded that is still running.
struct Host {
    daemon: Option<std::process::Child>,
    temp: teardown::Tree,
}

impl Drop for Host {
    fn drop(&mut self) {
        // The daemon first, so nothing it launches can follow the tree's count; a daemon that
        // cannot be established as ended keeps the tree instead.
        if let Some(mut daemon) = self.daemon.take()
            && let Err(error) = daemon.kill().and_then(|()| daemon.wait().map(|_| ()))
        {
            self.temp.hold(format!(
                "the daemon this test started could not be established as ended: {error}"
            ));
        }
    }
}

impl Host {
    /// Starts the daemon on a host of its own that creates its sessions headless, or fails and
    /// says why it cannot.
    async fn start() -> Self {
        let (Some(controller), Some(worker)) = (
            beside_this_test("kr-controller-held"),
            beside_this_test("kr-worker"),
        ) else {
            panic!(
                "the kr-controller-held and kr-worker executables are not built beside this test, \
                 so this check cannot run; a workspace test run builds them, and so do \
                 `cargo build -p kr-controller --features testing --bin kr-controller-held` \
                 and `cargo build -p kr-worker`"
            );
        };
        let temp = teardown::Tree::create();
        let bin = temp.root().join("bin");
        std::fs::create_dir_all(&bin).expect("a directory for the executables");
        let controller = copy_into(&controller, &bin, "kr-controller-held");
        let worker = copy_into(&worker, &bin, "kr-worker");

        let mut document = kr_protocol::hostinfo::configuration::ConfigurationDocument::empty();
        document.revision = 1;
        document.preferences.worker_profile = kr_protocol::scalars::Nullable::some(
            kr_protocol::identity::WorkerProfile::HeadlessUser,
        );
        let environment = temp.environment();
        let path = kr_protocol::hostinfo::configuration::document_path(
            environment.state_dir(),
            environment.state_root(),
            environment.environment_id(),
        );
        std::fs::create_dir_all(path.parent().expect("the document's directory"))
            .expect("the state directory");
        kr_ipc::paths::write_owner_only_file(
            &path,
            kr_protocol::hostinfo::configuration::contents(&document).as_bytes(),
        )
        .expect("the configuration document");

        let log = std::fs::File::create(temp.root().join("daemon.log")).expect("the daemon's log");
        let mut command = std::process::Command::new(&controller);
        StartedEnvironment::within(temp.root())
            .apply_keeping(&mut command, &USER_MANAGER_VARIABLES);
        let child = command
            .current_dir(temp.root())
            .arg("--runtime-dir")
            .arg(temp.root().join("r"))
            .arg("--state-dir")
            .arg(temp.root().join("s"))
            .arg("--worker")
            .arg(&worker)
            .arg("--secret-store")
            .arg("file")
            .stdin(std::process::Stdio::null())
            .stdout(log.try_clone().expect("duplicates the log"))
            .stderr(log)
            .spawn()
            .expect("the daemon starts");
        let host = Self {
            daemon: Some(child),
            temp,
        };
        let endpoint = host
            .temp
            .environment()
            .controller_endpoint()
            .expect("an endpoint");
        let started = Instant::now();
        while LocalClient::connect(&endpoint, LocalClientKind::Cli, build())
            .await
            .is_err()
        {
            assert!(
                started.elapsed() < LIVENESS_DEADLINE,
                "the daemon did not answer; its log says: {}",
                std::fs::read_to_string(host.temp.root().join("daemon.log")).unwrap_or_default()
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        host
    }

    /// Runs `kr` against this host from `directory`, with nothing of this test's own environment.
    fn kr_in(&self, directory: &Path, arguments: &[&str]) -> std::process::Output {
        let mut command = std::process::Command::new(kr());
        StartedEnvironment::within(self.temp.root()).apply(&mut command);
        command
            .args(arguments)
            .env(
                "KR_RUNTIME_DIR",
                self.temp.paths().runtime_root().display().to_string(),
            )
            .env(
                "KR_STATE_DIR",
                self.temp.paths().state_root().display().to_string(),
            )
            .current_dir(directory)
            .output()
            .expect("runs kr")
    }

    /// Runs `kr` from the root directory and reads what it printed as JSON, failing with what it
    /// said when it failed.
    fn kr_json(&self, arguments: &[&str]) -> Value {
        let output = self.kr_in(Path::new("/"), arguments);
        assert!(
            output.status.success(),
            "kr {}: {}",
            arguments.join(" "),
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).expect("kr printed JSON")
    }
}

/// What a result says of one capability: its state and the reason a person is given.
fn record_of(result: &Value, capability: &str) -> (String, String) {
    let record = result["desktop"]["capabilities"]
        .as_array()
        .expect("the capabilities")
        .iter()
        .find(|record| record["capability"] == capability)
        .unwrap_or_else(|| panic!("{capability} has a record: {result}"));
    (
        record["state"].as_str().expect("a state").to_owned(),
        record["disabled_reason"]
            .as_str()
            .unwrap_or_default()
            .to_owned(),
    )
}

/// KR-REQ-03.29 and KR-REQ-03.02: a person runs the disclosed checks from `kr`, and names the file
/// the read check reads. The worker of a real session reads that file and the findings come back
/// in the command's own answer; a path relative to the person's directory is read as the person
/// meant it; with no file the read check reads nothing and says so; and with no session to run
/// them in the command fails and says why.
#[tokio::test(flavor = "multi_thread")]
async fn the_read_check_reads_the_file_a_person_names_and_a_run_with_no_session_says_why() {
    const READ: &str = "desktop.authorised_file_read";
    let host = Host::start().await;
    let directory = host.temp.root().to_path_buf();

    // With no session of the kind the host creates, nothing is started and the command fails.
    let refused = host.kr_in(&directory, &["host", "desktop-checks", "--json"]);
    assert!(!refused.status.success(), "no session to run the checks in");
    let said: Value = serde_json::from_slice(&refused.stdout).unwrap_or_else(|_| {
        panic!(
            "the command answers with a document; it said: {}",
            String::from_utf8_lossy(&refused.stderr)
        )
    });
    assert_eq!(said["checks"]["failure"], "no_session", "{said}");

    let created = host.kr_json(&[
        "new",
        "--shell-mode",
        "native_compat",
        "--invisible",
        "--headless",
        "--cwd",
        &directory.display().to_string(),
        "--shell",
        "/bin/sh",
        "--startup",
        "interactive",
        "--json",
    ]);
    let display = created["display_number"].to_string();

    // A file named by its full path is read in the session's worker.
    let named = directory.join("named.txt");
    std::fs::write(&named, b"a file the person named").expect("the file");
    let found = host.kr_json(&[
        "host",
        "desktop-checks",
        "--file",
        &named.display().to_string(),
        "--json",
    ]);
    assert_eq!(found["checks"]["state"], "current", "{found}");
    let (state, reason) = record_of(&found, READ);
    assert_eq!(state, "qualified_available", "{found}");
    assert!(reason.contains("23 bytes"), "{reason}");

    // A path relative to the directory the person runs the command in is the file they meant.
    std::fs::write(directory.join("relative.txt"), b"seven b").expect("the file");
    let output = host.kr_in(
        &directory,
        &["host", "desktop-checks", "--file", "relative.txt", "--json"],
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let found: Value = serde_json::from_slice(&output.stdout).expect("kr printed JSON");
    let (state, reason) = record_of(&found, READ);
    assert_eq!(state, "qualified_available", "{found}");
    assert!(reason.contains("7 bytes"), "{reason}");

    // With no file the read check reads nothing.
    let none = host.kr_json(&["host", "desktop-checks", "--json"]);
    assert_eq!(none["checks"]["state"], "current", "{none}");
    let (state, _) = record_of(&none, READ);
    assert_ne!(state, "qualified_available", "{none}");

    // Said to a person, the findings follow a heading, a line to each check.
    let output = host.kr_in(
        &directory,
        &["host", "desktop-checks", "--file", "relative.txt"],
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let said = String::from_utf8_lossy(&output.stdout);
    assert!(said.starts_with("Disclosed desktop checks"), "{said}");
    assert!(
        said.lines()
            .any(|line| line.contains(READ) && line.contains("qualified_available")),
        "{said}"
    );

    let _ = host.kr_json(&["close", &display, "--json"]);
}
