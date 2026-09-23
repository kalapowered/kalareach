//! `kr skill install`, `kr skill status` and `kr skill remove`, run the way a person runs them.
//!
//! The command is the real `kr`, copied to the internal disk and run with this test's own runtime
//! and state directories against a control daemon of this test's own. A user-scope installation
//! writes into the daemon's home directory, so the daemon has to be a process of its own with a
//! home directory the test made: it is this test binary, copied beside `kr` and started again for
//! the ignored test below, which hosts the daemon until it is killed. Because the daemon finds `kr`
//! beside itself, the entry an installation writes names that copy.
//!
//! Nothing outside the test's temporary tree is read or written, and the daemon keeps its keys in
//! that tree's own secrets directory.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::Arc;

use kr_controller::service::{Controller, ControllerSetup};
use kr_controller::supervision::{LaunchOutcome, WorkerLaunch, WorkerSupervisor};
use kr_crypto::store::{StoreSelection, open_store_in};
use kr_ipc::client::LocalClient;
use kr_ipc::endpoint::Listener;
use kr_ipc::paths::HostPaths;
use kr_ipc::verify::ControllerIdentity;
use kr_protocol::ids::BuildId;
use kr_protocol::local::LocalClientKind;
use serde_json::Value;

/// Names the tree the daemon half of this suite hosts, when this binary is started as that half.
const DAEMON_ROOT: &str = "KR_SKILL_TEST_DAEMON_ROOT";

/// The test that hosts the daemon, by the name the harness runs it under.
const DAEMON_TEST: &str = "a_daemon_for_the_command_tests";

fn build() -> BuildId {
    BuildId::new("kr-test/0").expect("a build identifier")
}

/// A supervisor that starts nothing. Installing a skill needs no worker.
#[derive(Debug)]
struct NoWorkers;

impl WorkerSupervisor for NoWorkers {
    fn start(&self, _launch: &WorkerLaunch) -> LaunchOutcome {
        LaunchOutcome::NotStarted {
            detail: "this test starts no workers".to_owned(),
        }
    }

    fn describe(&self) -> &'static str {
        "a supervisor that starts nothing"
    }
}

/// Hosts a control daemon on the tree [`DAEMON_ROOT`] names, until this process is killed.
///
/// It runs only when the test below starts this binary for it, with the daemon's home directory
/// in `HOME`; run any other way, it has no tree to host and returns.
#[test]
#[ignore = "the daemon half of the command tests, started by them in a process of its own"]
fn a_daemon_for_the_command_tests() {
    let Some(root) = std::env::var_os(DAEMON_ROOT).map(PathBuf::from) else {
        return;
    };
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("a runtime");
    runtime.block_on(async move {
        let paths = HostPaths::new(root.join("r"), root.join("s")).expect("absolute roots");
        let environment_id = paths.open_environment_id().expect("the tree's environment");
        let environment = paths.environment(environment_id);
        let secrets = environment.secrets_dir();
        let controller = Controller::start(ControllerSetup {
            paths: environment.clone(),
            environment_id,
            identity: Box::new(move || {
                let store = open_store_in(&secrets).expect("a secret store in the test tree");
                Ok(
                    ControllerIdentity::open(store.store.as_ref(), environment_id, false)
                        .expect("an identity"),
                )
            }),
            secret_store: StoreSelection::File,
            boot_identity: kr_ipc::identity::boot_identity().expect("a boot identity"),
            supervisor: Box::new(NoWorkers),
            worker_program: root.join("no-such-worker"),
            build_id: build(),
            release: "0".to_owned(),
            shell_packages: None,
            terminal: Box::new(kr_controller::supervision::NoTerminal),
        })
        .await
        .expect("the daemon starts");
        let endpoint = environment.controller_endpoint().expect("an endpoint");
        let listener = Listener::bind(&endpoint).expect("binds the endpoint");
        tokio::spawn(Arc::clone(&controller).serve_clients(listener));
        std::future::pending::<()>().await;
    });
}

/// Starts a copied program, retrying while another copy made by this process is still open.
fn spawn(command: &mut Command) -> std::process::Child {
    let mut attempted = 0;
    loop {
        attempted += 1;
        match command.spawn() {
            Ok(child) => return child,
            // A copy this process was still writing when another thread forked is held open in
            // that child for a moment. The window closes in milliseconds.
            Err(error)
                if error.kind() == std::io::ErrorKind::ExecutableFileBusy && attempted < 100 =>
            {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            Err(error) => panic!("{command:?} starts, after {attempted} attempts: {error:?}"),
        }
    }
}

/// The daemon half, killed where it stands when the test ends.
struct Daemon(std::process::Child);

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// The tree, the copied commands and the daemon one test runs against.
struct Setup {
    host: kr_ipc::testing::TempHost,
    kr: PathBuf,
    home: PathBuf,
    project: PathBuf,
    _daemon: Daemon,
}

impl Setup {
    async fn start() -> Self {
        let host = kr_ipc::testing::TempHost::create();
        let commands = host.root().join("bin");
        std::fs::create_dir_all(&commands).expect("a directory for the commands");
        let kr = commands.join("kr");
        std::fs::copy(env!("CARGO_BIN_EXE_kr"), &kr).expect("copies the command");
        let hosting = commands.join("daemon-host");
        std::fs::copy(std::env::current_exe().expect("this test binary"), &hosting)
            .expect("copies this test binary");
        let home = host.root().join("home");
        let project = host.root().join("project");
        std::fs::create_dir_all(&home).expect("a home directory");
        std::fs::create_dir_all(project.join(".codex")).expect("a project directory");
        let log = std::fs::File::create(host.root().join("daemon.log")).expect("a log");
        let daemon = Daemon(spawn(
            Command::new(&hosting)
                .args(["--exact", DAEMON_TEST, "--ignored", "--nocapture"])
                .env(DAEMON_ROOT, host.root())
                .env("HOME", &home)
                .env("KR_RUNTIME_DIR", host.root().join("r"))
                .env("KR_STATE_DIR", host.root().join("s"))
                .current_dir(host.root())
                .stdin(Stdio::null())
                .stdout(log.try_clone().expect("duplicates the log"))
                .stderr(log),
        ));
        let setup = Self {
            host,
            kr,
            home,
            project,
            _daemon: daemon,
        };
        setup.wait_for_the_daemon().await;
        setup
    }

    async fn wait_for_the_daemon(&self) {
        let endpoint = self
            .host
            .environment()
            .controller_endpoint()
            .expect("an endpoint");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
        while LocalClient::connect(&endpoint, LocalClientKind::Cli, build())
            .await
            .is_err()
        {
            assert!(
                std::time::Instant::now() < deadline,
                "the daemon did not answer within two minutes; its log says: {}",
                std::fs::read_to_string(self.host.root().join("daemon.log"))
                    .unwrap_or_else(|error| format!("<unreadable: {error}>"))
            );
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    }

    /// Runs `kr` with these arguments against this tree's daemon.
    fn kr(&self, arguments: &[&str]) -> Output {
        spawn(
            Command::new(&self.kr)
                .args(arguments)
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .env("HOME", &self.home)
                .env("KR_RUNTIME_DIR", self.host.root().join("r"))
                .env("KR_STATE_DIR", self.host.root().join("s"))
                .current_dir("/")
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped()),
        )
        .wait_with_output()
        .expect("the command finishes")
    }

    /// Runs `kr --json skill <arguments>` and returns its document, which must say it succeeded.
    fn skill(&self, arguments: &[&str]) -> Value {
        let mut all = vec!["--json", "skill"];
        all.extend_from_slice(arguments);
        let output = self.kr(&all);
        assert!(
            output.status.success(),
            "kr {} failed: {}{}",
            all.join(" "),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let document: Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
            panic!(
                "kr {} printed a JSON document ({error}): {}",
                all.join(" "),
                String::from_utf8_lossy(&output.stdout)
            )
        });
        assert_eq!(document["ok"], true, "{document}");
        document
    }
}

fn json_document(path: &Path) -> Value {
    serde_json::from_str(
        &std::fs::read_to_string(path)
            .unwrap_or_else(|error| panic!("{}: {error}", path.display())),
    )
    .expect("JSON")
}

/// The operations a document lists, in an order that does not depend on the order they ran in.
fn operations(listed: &Value) -> Vec<String> {
    let mut rendered: Vec<String> = listed
        .as_array()
        .expect("a list of operations")
        .iter()
        .map(Value::to_string)
        .collect();
    rendered.sort();
    rendered
}

/// KR-REQ-11.50: `kr skill install`, `kr skill status` and `kr skill remove` work end to end at
/// user scope and at project scope. The installation writes the skill package and the
/// `kr agent-tools --stdio` entry beside the settings already there and prints the operations it
/// recorded; the status prints the removal record, operation for operation; and the removal runs
/// that record and nothing else, so every other setting is as it was.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_commands_install_report_and_remove_the_skill_at_both_scopes() {
    let setup = Setup::start().await;
    // Somebody's own settings, which neither the installation nor the removal may disturb.
    std::fs::write(
        setup.home.join(".claude.json"),
        r#"{"mcpServers":{"theirs":{"command":"their-server"}},"theme":"dark"}"#,
    )
    .expect("writes the user's configuration");
    std::fs::write(
        setup.project.join(".codex/config.toml"),
        "# a comment somebody wrote\nmodel = \"theirs\"\n\n[mcp_servers.theirs]\ncommand = \"their-server\"\n",
    )
    .expect("writes the project's configuration");
    let project = setup.project.display().to_string();
    let user: [&str; 4] = ["--agent", "claude-code", "--scope", "user"];
    let in_project: [&str; 6] = [
        "--agent",
        "codex",
        "--scope",
        "project",
        "--project-dir",
        &project,
    ];
    let installed_user = setup.skill(&[&["install"][..], &user[..]].concat());
    let installed_project = setup.skill(&[&["install"][..], &in_project[..]].concat());
    for installed in [&installed_user["install"], &installed_project["install"]] {
        assert_eq!(installed["finished"], true, "{installed}");
        assert_eq!(installed["already_installed"], false, "{installed}");
        assert!(
            installed["operations"]
                .as_array()
                .expect("operations")
                .iter()
                .any(|operation| operation["operation"] == "write_file"
                    && operation["sha256"]
                        .as_str()
                        .is_some_and(|hex| hex.len() == 64)),
            "the installation lists each file it wrote with its digest: {installed}"
        );
    }
    let user_skill = setup.home.join(".claude/skills/kalareach-contact");
    let project_skill = setup.project.join(".agents/skills/kalareach-contact");
    for skill in [&user_skill, &project_skill] {
        for file in ["SKILL.md", "TOOLS.md", "manifest.json"] {
            assert!(
                skill.join(file).is_file(),
                "{} is installed",
                skill.join(file).display()
            );
        }
    }
    let configuration = json_document(&setup.home.join(".claude.json"));
    assert_eq!(
        configuration["mcpServers"]["kalareach"]["command"],
        setup.kr.display().to_string(),
        "the entry runs the kr beside the daemon"
    );
    assert_eq!(
        configuration["mcpServers"]["kalareach"]["args"],
        serde_json::json!(["agent-tools", "--stdio"])
    );
    assert_eq!(
        configuration["mcpServers"]["theirs"]["command"],
        "their-server"
    );
    assert_eq!(configuration["theme"], "dark");
    let codex = std::fs::read_to_string(setup.project.join(".codex/config.toml")).expect("reads");
    assert!(codex.contains("[mcp_servers.kalareach]"), "{codex}");
    assert!(codex.contains("# a comment somebody wrote"), "{codex}");

    // The status prints the removal record, which is exactly what each installation did.
    let status_user = setup.skill(&[&["status"][..], &user[..]].concat());
    let status_project = setup.skill(&[&["status"][..], &in_project[..]].concat());
    for (status, installed) in [
        (&status_user["status"], &installed_user["install"]),
        (&status_project["status"], &installed_project["install"]),
    ] {
        assert_eq!(status["installed"], true, "{status}");
        assert!(
            status["drift"].as_array().expect("drift").is_empty(),
            "{status}"
        );
        assert!(
            status["files"]
                .as_array()
                .expect("files")
                .iter()
                .all(|file| file["intact"] == true),
            "{status}"
        );
        assert!(!operations(&status["removal"]).is_empty());
        assert_eq!(
            operations(&status["removal"]),
            operations(&installed["operations"]),
            "the removal record undoes exactly what the installation did"
        );
    }
    let lines = setup.kr(&[
        "skill",
        "status",
        "--agent",
        "claude-code",
        "--scope",
        "user",
    ]);
    assert!(lines.status.success());
    let lines = String::from_utf8_lossy(&lines.stdout);
    assert!(
        lines.contains("kalareach-contact") && lines.contains("is installed for claude-code"),
        "{lines}"
    );

    // Removal runs the record: everything it installed goes, and nothing else does.
    let removed_user = setup.skill(&[&["remove"][..], &user[..]].concat());
    let removed_project = setup.skill(&[&["remove"][..], &in_project[..]].concat());
    for (removed, status) in [
        (&removed_user["remove"], &status_user["status"]),
        (&removed_project["remove"], &status_project["status"]),
    ] {
        assert_eq!(
            operations(&removed["removed"]),
            operations(&status["removal"]),
            "the removal ran the record it reported"
        );
        assert!(
            removed["retained"].as_array().expect("retained").is_empty(),
            "{removed}"
        );
    }
    assert!(!user_skill.exists());
    assert!(!project_skill.exists());
    let configuration = json_document(&setup.home.join(".claude.json"));
    assert!(
        configuration["mcpServers"].get("kalareach").is_none(),
        "{configuration}"
    );
    assert_eq!(
        configuration["mcpServers"]["theirs"]["command"],
        "their-server"
    );
    assert_eq!(configuration["theme"], "dark");
    let codex = std::fs::read_to_string(setup.project.join(".codex/config.toml")).expect("reads");
    assert!(!codex.contains("kalareach"), "{codex}");
    assert!(codex.contains("# a comment somebody wrote"), "{codex}");
    assert!(codex.contains("[mcp_servers.theirs]"), "{codex}");

    // Nothing is recorded any more, so a status says so and fails as a check.
    for arguments in [&user[..], &in_project[..]] {
        let output = setup.kr(&[&["--json", "skill", "status"][..], arguments].concat());
        let document: Value = serde_json::from_slice(&output.stdout).expect("a JSON document");
        assert_eq!(document["status"]["installed"], false, "{document}");
        assert_eq!(document["ok"], false, "{document}");
    }
}
