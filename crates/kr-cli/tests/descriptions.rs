//! `kr host descriptions` against a real control daemon: what setup shows before anything is
//! fetched, the owner's two settings written to the host's configuration and applied at once, a
//! fetch cancelled when none is running, and the same in the shape a script reads.
//!
//! The daemon is the `kr-controller` executable the workspace builds beside this test, copied to
//! the internal disk and given a host tree of its own; it ships the profiles this build ships, and
//! nothing here asks it to fetch, which would reach the network. What a fetch does is established
//! against a local server by the daemon's own tests. A build of this crate alone that has not
//! built the daemon yet fails and says why, rather than counting a check it did not run.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use kr_ipc::client::LocalClient;
use kr_protocol::ids::BuildId;
use kr_protocol::local::LocalClientKind;
use serde_json::Value;

mod support;

use support::kr;

/// How long a wait for something to happen is given. It fails when the thing never happens.
const LIVENESS_DEADLINE: Duration = Duration::from_secs(120);

/// Returns an executable the workspace builds beside this test, when it has been built.
fn beside_this_test(name: &str) -> Option<PathBuf> {
    let executable = std::env::current_exe().ok()?;
    let profile = executable.parent()?.parent()?;
    let candidate = profile.join(format!("{name}{}", std::env::consts::EXE_SUFFIX));
    candidate.is_file().then_some(candidate)
}

/// A host tree with a running daemon, and the `kr` that talks to it.
struct Host {
    daemon: Option<std::process::Child>,
    temp: kr_ipc::testing::TempHost,
}

impl Drop for Host {
    fn drop(&mut self) {
        if let Some(mut daemon) = self.daemon.take() {
            let _ = daemon.kill();
            let _ = daemon.wait();
        }
    }
}

impl Host {
    async fn start() -> Self {
        let controller = beside_this_test("kr-controller").unwrap_or_else(|| {
            panic!(
                "the kr-controller executable is not built beside this test, so this check cannot \
                 run; a workspace test run builds it, and so does `cargo build -p kr-controller`"
            )
        });
        let temp = kr_ipc::testing::TempHost::create();
        let bin = temp.root().join("bin");
        std::fs::create_dir_all(&bin).expect("a directory for the executable");
        let controller = {
            let destination = bin.join(controller.file_name().expect("the executable has a name"));
            kr_ipc::testing::place_program(&controller, &destination);
            destination
        };
        let log = std::fs::File::create(temp.root().join("daemon.log")).expect("the daemon's log");
        let child = std::process::Command::new(&controller)
            .current_dir(temp.root())
            .arg("--runtime-dir")
            .arg(temp.root().join("r"))
            .arg("--state-dir")
            .arg(temp.root().join("s"))
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
        while LocalClient::connect(
            &endpoint,
            LocalClientKind::Cli,
            BuildId::new("kr-test/0").expect("a build identifier"),
        )
        .await
        .is_err()
        {
            assert!(
                started.elapsed() < LIVENESS_DEADLINE,
                "the daemon did not answer; its log says: {}",
                host.log()
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        host
    }

    fn log(&self) -> String {
        std::fs::read_to_string(self.temp.root().join("daemon.log")).unwrap_or_default()
    }

    /// Runs `kr` on plain pipes, with this host's directories and nothing of this test's own.
    fn kr(&self, arguments: &[&str]) -> std::process::Output {
        std::process::Command::new(kr())
            .args(arguments)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("KR_RUNTIME_DIR", self.temp.paths().runtime_root())
            .env("KR_STATE_DIR", self.temp.paths().state_root())
            .current_dir(Path::new("/"))
            .stdin(std::process::Stdio::null())
            .output()
            .expect("runs kr")
    }

    /// What `kr` printed, which has to have succeeded.
    fn said(&self, arguments: &[&str]) -> String {
        let output = self.kr(arguments);
        assert!(
            output.status.success(),
            "kr {}: {}\n{}",
            arguments.join(" "),
            String::from_utf8_lossy(&output.stderr),
            self.log()
        );
        String::from_utf8_lossy(&output.stdout).into_owned()
    }

    /// What `kr --json` printed, as JSON.
    fn json(&self, arguments: &[&str]) -> Value {
        let mut line = vec!["--json"];
        line.extend_from_slice(arguments);
        serde_json::from_str(&self.said(&line)).expect("kr printed JSON")
    }
}

/// KR-REQ-22.01: with no option the command reads, and shows the cost first: the model, its exact
/// size, where the fetch would reach and that no account is needed, and that nothing has been
/// fetched. Nothing was fetched by asking, and the same is in the shape a script reads.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn setup_shows_the_cost_before_anything_is_fetched() {
    let host = Host::start().await;
    let shown = host.said(&["host", "descriptions"]);
    assert!(shown.contains("Session descriptions are on"), "{shown}");
    assert!(shown.contains("bytes, fetched from"), "{shown}");
    assert!(shown.contains("no account is needed"), "{shown}");
    assert!(shown.contains("Nothing has been fetched."), "{shown}");
    assert!(
        shown.contains("kr host descriptions --download fetches the files"),
        "{shown}"
    );
    assert!(
        !host.temp.root().join("s").join("models").exists(),
        "reading fetched nothing and made no model directory: {shown}"
    );

    let document = host.json(&["host", "descriptions"]);
    assert_eq!(document["ok"], true);
    assert_eq!(document["offered"], true);
    assert_eq!(document["enabled"], true);
    assert_eq!(document["download"], "not_started");
    assert_eq!(document["paused"], "not_downloaded");
    assert_eq!(document["needs_hosted_account"], false);
    // The protocol writes a 64-bit number as text.
    assert!(
        document["asset_bytes"]
            .as_str()
            .and_then(|bytes| bytes.parse::<u64>().ok())
            .is_some_and(|bytes| bytes > 0),
        "{document}"
    );
    assert!(
        document["sources"]
            .as_array()
            .is_some_and(|sources| !sources.is_empty()),
        "{document}"
    );
}

/// KR-REQ-22.01: the owner's settings are written to the host's configuration and show at once in
/// the answer: off, then on again, and the battery setting on its own, each leaving the other as
/// it was. Cancelling a fetch when none runs is answered with what setup shows, and is no fault.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_settings_apply_at_once_and_each_leaves_the_other_as_it_was() {
    let host = Host::start().await;

    let off = host.json(&["host", "descriptions", "--off"]);
    assert_eq!(off["enabled"], false);
    assert_eq!(off["on_battery"], false);
    let read = host.said(&["host", "descriptions"]);
    assert!(read.contains("Session descriptions are off"), "{read}");

    let battery = host.json(&["host", "descriptions", "--battery", "on"]);
    assert_eq!(battery["on_battery"], true);
    assert_eq!(
        battery["enabled"], false,
        "the other setting stays as it was"
    );

    let on = host.json(&["host", "descriptions", "--on", "--battery", "off"]);
    assert_eq!(on["enabled"], true);
    assert_eq!(on["on_battery"], false);

    let cancelled = host.json(&["host", "descriptions", "--cancel"]);
    assert_eq!(cancelled["download"], "not_started");
    assert_eq!(cancelled["can_cancel"], false);

    // What was set is what the configuration holds, so a daemon that restarts keeps it.
    let document =
        std::fs::read_to_string(kr_worker::config::document_path(&host.temp.environment()))
            .expect("the configuration document");
    assert!(document.contains("descriptions"), "{document}");

    // A battery setting that is neither word is a usage failure and changes nothing.
    let refused = host.kr(&["host", "descriptions", "--battery", "sometimes"]);
    assert_eq!(refused.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains("on or off"),
        "{}",
        String::from_utf8_lossy(&refused.stderr)
    );
    assert_eq!(host.json(&["host", "descriptions"])["on_battery"], false);
}

/// The options that cannot be asked together are refused by the parser before any daemon is
/// reached: a fetch and a cancellation, a fetch and turning descriptions off, on and off.
#[test]
fn options_that_contradict_are_refused_before_a_daemon_is_asked() {
    use clap::Parser as _;

    for line in [
        &["host", "descriptions", "--download", "--cancel"][..],
        &["host", "descriptions", "--download", "--off"],
        &["host", "descriptions", "--on", "--off"],
    ] {
        let parsed =
            kr_cli::cli::Cli::try_parse_from(std::iter::once("kr").chain(line.iter().copied()));
        assert!(parsed.is_err(), "kr {} parses", line.join(" "));
    }
    for line in [
        &["host", "descriptions"][..],
        &["host", "descriptions", "--download"],
        &["host", "descriptions", "--cancel"],
        &["host", "descriptions", "--off", "--battery", "off"],
        &[
            "host",
            "descriptions",
            "--environment",
            "01234567-89ab-4def-8123-456789abcdef",
        ],
    ] {
        let parsed =
            kr_cli::cli::Cli::try_parse_from(std::iter::once("kr").chain(line.iter().copied()));
        assert!(parsed.is_ok(), "kr {} does not parse", line.join(" "));
    }
}
