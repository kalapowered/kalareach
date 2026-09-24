//! `kr new`, `kr attach`, `kr detach` and `kr close`, and their one-letter forms, against a real
//! control daemon and the workers it starts.
//!
//! The daemon and the worker are the `kr-controller` and `kr-worker` executables the workspace
//! builds beside this test. A workspace build always has them; a build of this crate alone that
//! has not built them yet prints why and stops rather than testing something else. Each is copied
//! to the internal disk before it starts, every process's working directory is inside this test's
//! own temporary host, and the daemon keeps its keys in that host's own secrets directory.

#![cfg(unix)]

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use kr_ipc::client::LocalClient;
use kr_protocol::ids::{BuildId, SessionId};
use kr_protocol::local::LocalClientKind;
use kr_protocol::method::Method;
use portable_pty::{CommandBuilder, PtySize, native_pty_system};
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

/// A host tree with a running daemon, and the `kr` that talks to it.
///
/// However a test ends, what it started ends with it and before its tree goes: the daemon here,
/// and then, through the tree, every worker the daemon recorded that is still running and on macOS
/// every launchd job defined inside this host's own state directory.
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
    /// Starts the daemon on a host of its own, or says why it cannot.
    async fn start() -> Option<Self> {
        let (Some(controller), Some(worker)) = (
            beside_this_test("kr-controller"),
            beside_this_test("kr-worker"),
        ) else {
            eprintln!(
                "skipped: the kr-controller and kr-worker executables are not built beside this \
                 test; a workspace test run builds them"
            );
            return None;
        };
        let temp = teardown::Tree::create();
        let bin = temp.root().join("bin");
        std::fs::create_dir_all(&bin).expect("a directory for the executables");
        let controller = copy_into(&controller, &bin);
        let worker = copy_into(&worker, &bin);
        let log = std::fs::File::create(temp.root().join("daemon.log")).expect("the daemon's log");
        let child = std::process::Command::new(&controller)
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
        Some(host)
    }

    /// Runs `kr` against this host with nothing of this test's own environment.
    fn kr(&self, arguments: &[&str]) -> std::process::Output {
        std::process::Command::new(kr())
            .args(arguments)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env(
                "KR_RUNTIME_DIR",
                self.temp.paths().runtime_root().display().to_string(),
            )
            .env(
                "KR_STATE_DIR",
                self.temp.paths().state_root().display().to_string(),
            )
            .current_dir("/")
            .output()
            .expect("runs kr")
    }

    /// Runs `kr` and reads what it printed as JSON, failing with what it said when it failed.
    fn kr_json(&self, arguments: &[&str]) -> Value {
        let output = self.kr(arguments);
        assert!(
            output.status.success(),
            "kr {}: {}",
            arguments.join(" "),
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).expect("kr printed JSON")
    }

    /// Returns the process identifier of the worker this host started for a session.
    #[cfg(target_os = "macos")]
    fn worker_of(&self, session_id: SessionId) -> u64 {
        let worker = kr_ipc::descriptor::read_all(&self.temp.environment())
            .expect("reads the runtime directory")
            .into_iter()
            .filter_map(|entry| entry.descriptor.ok())
            .find(|descriptor| descriptor.session_id == session_id)
            .expect("the session's descriptor is published")
            .process_start_identity;
        worker.pid.get()
    }

    /// Returns the attachments this session's worker holds, by identity.
    async fn attachments(&self, session_id: SessionId) -> Vec<String> {
        let descriptor = kr_ipc::descriptor::read_all(&self.temp.environment())
            .expect("reads the runtime directory")
            .into_iter()
            .filter_map(|entry| entry.descriptor.ok())
            .find(|descriptor| descriptor.session_id == session_id)
            .expect("the session's descriptor is published");
        let endpoint =
            kr_ipc::paths::Endpoint::from_path(&descriptor.endpoint).expect("an endpoint");
        let mut client = LocalClient::connect(&endpoint, LocalClientKind::Cli, build())
            .await
            .expect("reaches the worker");
        client
            .verify_worker(&descriptor)
            .await
            .expect("the worker answers its descriptor's challenge");
        let snapshot: kr_protocol::recovery::EventsSnapshotResult = client
            .request(
                Method::EventsSnapshot,
                &kr_protocol::recovery::EventsSnapshotParams {
                    session_id,
                    agent_resources_from: kr_protocol::scalars::Nullable::null(),
                },
            )
            .await
            .expect("the call reaches the worker")
            .expect("the worker answers")
            .to_typed()
            .expect("decodes");
        snapshot
            .attachments
            .iter()
            .map(|summary| summary.attachment_id.to_string())
            .collect()
    }
}

fn build() -> BuildId {
    BuildId::new("kr-test/0").expect("a build identifier")
}

/// Copies an executable into `directory` and starts the copy once, where nothing is timed, so the
/// operating system's check of a newly written executable is paid here rather than inside the
/// daemon's start or a create's rendezvous.
fn copy_into(source: &Path, directory: &Path) -> PathBuf {
    let destination = directory.join(source.file_name().expect("an executable has a name"));
    kr_ipc::testing::place_and_start_once(source, &destination, &["--version"]);
    destination
}

/// Everything a terminal has produced, collected off the test's own thread.
#[derive(Clone)]
struct TerminalOutput {
    seen: Arc<std::sync::Mutex<Vec<u8>>>,
}

impl TerminalOutput {
    fn collect(mut reader: Box<dyn Read + Send>) -> Self {
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let collected = Arc::clone(&seen);
        std::thread::spawn(move || {
            let mut buffer = [0_u8; 4096];
            while let Ok(read) = reader.read(&mut buffer) {
                if read == 0 {
                    break;
                }
                if let Ok(mut seen) = collected.lock() {
                    seen.extend_from_slice(&buffer[..read]);
                }
            }
        });
        Self { seen }
    }

    fn text(&self) -> String {
        String::from_utf8_lossy(
            &self
                .seen
                .lock()
                .map(|seen| seen.clone())
                .unwrap_or_default(),
        )
        .into_owned()
    }

    /// Waits for `marker`, and fails with how long it waited when it never arrives.
    fn expect_within(&self, marker: &str, what: &str) {
        let started = Instant::now();
        while !self.text().contains(marker) {
            assert!(
                started.elapsed() < LIVENESS_DEADLINE,
                "{what}: waited {:?} for {marker:?} in the terminal: {}",
                started.elapsed(),
                self.text().escape_debug()
            );
            // Short, because the command's capability handshake has a second in total and one of
            // the things waiting here is the thread that answers it.
            std::thread::sleep(Duration::from_millis(2));
        }
    }
}

/// A terminal, with `kr attach` running on it through a shell that reports how it ended.
struct Attached {
    _pty: portable_pty::PtyPair,
    shell: Box<dyn portable_pty::Child + Send + Sync>,
    output: TerminalOutput,
    writer: Arc<std::sync::Mutex<Box<dyn Write + Send>>>,
}

impl Attached {
    fn open(host: &Host, attach: &str, display: &str) -> Self {
        let pty = native_pty_system()
            .openpty(PtySize {
                rows: 24,
                cols: 80,
                pixel_width: 0,
                pixel_height: 0,
            })
            .expect("opens a terminal");
        let mut builder = CommandBuilder::new("/bin/sh");
        builder.arg("-c");
        builder.arg(format!(
            "{} {attach} {display}; printf 'attach-finished-%s\\n' \"$?\"",
            kr().display()
        ));
        builder.env_clear();
        builder.env("PATH", "/usr/bin:/bin");
        builder.env("TERM", "xterm-256color");
        builder.env(
            "KR_RUNTIME_DIR",
            host.temp.paths().runtime_root().display().to_string(),
        );
        builder.env(
            "KR_STATE_DIR",
            host.temp.paths().state_root().display().to_string(),
        );
        builder.cwd("/");
        let shell = pty.slave.spawn_command(builder).expect("starts the shell");
        let output = TerminalOutput::collect(pty.master.try_clone_reader().expect("a reader"));
        let writer = Arc::new(std::sync::Mutex::new(
            pty.master.take_writer().expect("a writer"),
        ));
        // The command asks the terminal what it is before it changes anything, and a terminal
        // answers. Without the answer the bounded handshake fails and there is nothing to attach.
        let answering = {
            let output = output.clone();
            let writer = Arc::clone(&writer);
            std::thread::spawn(move || {
                output.expect_within("\x1b[c", "the command asked this terminal what it is");
                let mut writer = writer.lock().expect("the writer");
                writer
                    .write_all(b"\x1b[?5u\x1b[>4;2m\x1b[?62;22c")
                    .expect("answers");
                writer.flush().expect("flushes");
            })
        };
        answering.join().expect("the terminal answered the command");
        Self {
            _pty: pty,
            shell,
            output,
            writer,
        }
    }

    fn types(&self, text: &str) {
        let mut writer = self.writer.lock().expect("the writer");
        writer.write_all(text.as_bytes()).expect("types");
        writer.flush().expect("flushes");
    }
}

/// Waits until `kr status` reports the session closed.
fn closed(host: &Host, display: &str) {
    let number: u64 = display.parse().expect("a display number");
    let started = Instant::now();
    loop {
        let listed = host.kr_json(&["list", "--json"]);
        let still_live = listed["sessions"]
            .as_array()
            .expect("sessions")
            .iter()
            .any(|session| {
                session["display_number"].as_u64() == Some(number) && session["state"] != "closed"
            });
        if !still_live {
            return;
        }
        assert!(
            started.elapsed() < LIVENESS_DEADLINE,
            "session {display} did not close: {listed}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// KR-REQ-01.09: the local command line creates a session with `kr new`, attaches a terminal to it
/// with `kr attach`, ends that attachment with `kr detach` and closes the session with `kr close`,
/// and `kr n`, `kr a`, `kr d` and `kr c` do the same, against a real daemon and the workers it
/// starts.
#[tokio::test(flavor = "multi_thread")]
async fn new_attach_detach_and_close_work_in_full_and_in_one_letter() {
    let Some(host) = Host::start().await else {
        return;
    };
    let cwd = host.temp.root().display().to_string();
    for (form, new, attach, detach, close) in [
        ("full", "new", "attach", "detach", "close"),
        ("short", "n", "a", "d", "c"),
    ] {
        let created = host.kr_json(&[
            new,
            "--invisible",
            "--headless",
            "--cwd",
            &cwd,
            "--shell",
            "/bin/sh",
            "--startup",
            "interactive",
            "--json",
        ]);
        assert_eq!(created["state"], "live", "kr {new}: {created}");
        let display = created["display_number"].to_string();
        let session_id: SessionId = created["session_id"]
            .as_str()
            .expect("a session identifier")
            .parse()
            .expect("parses");

        let terminal = Attached::open(&host, attach, &display);
        terminal.types(&format!("printf 'kr-%s-%s\\n' attached {form}\r"));
        terminal.output.expect_within(
            &format!("kr-attached-{form}"),
            &format!("kr {attach} carried the typed line to the shell and its output back"),
        );

        let attachments = host.attachments(session_id).await;
        assert_eq!(
            attachments.len(),
            1,
            "one terminal is attached: {attachments:?}"
        );
        let detached = host.kr(&[detach, &display, "--attachment", &attachments[0]]);
        assert!(
            detached.status.success(),
            "kr {detach}: {}",
            String::from_utf8_lossy(&detached.stderr)
        );
        terminal.output.expect_within(
            "attach-finished-0",
            &format!("kr {detach} ended the attachment and kr {attach} ended with success"),
        );
        assert!(
            host.attachments(session_id).await.is_empty(),
            "the session has no attachment left after kr {detach}"
        );

        let closing = host.kr_json(&[close, &display, "--json"]);
        assert!(closing.is_object(), "kr {close}: {closing}");
        closed(&host, &display);
        let mut shell = terminal.shell;
        let _ = shell.wait();
    }
}

/// Returns what `launchctl print` says about the job in `domain` whose process is `pid`.
#[cfg(target_os = "macos")]
fn launchd_job_of(domain: &str, pid: u64) -> Option<String> {
    let listed = std::process::Command::new("/bin/launchctl")
        .arg("list")
        .output()
        .expect("launchctl lists the jobs");
    String::from_utf8_lossy(&listed.stdout)
        .lines()
        .filter_map(|line| line.split_whitespace().nth(2))
        .filter(|label| label.starts_with("kr-worker-"))
        .find_map(|label| {
            let printed = std::process::Command::new("/bin/launchctl")
                .arg("print")
                .arg(format!("{domain}/{label}"))
                .output()
                .ok()?;
            let text = String::from_utf8_lossy(&printed.stdout).into_owned();
            text.lines()
                .any(|line| line.trim() == format!("pid = {pid}"))
                .then_some(text)
        })
}

/// Reads one `name = value` field of a `launchctl print` description.
#[cfg(target_os = "macos")]
fn field(printed: &str, name: &str) -> String {
    printed
        .lines()
        .find_map(|line| line.trim().strip_prefix(&format!("{name} = ")))
        .unwrap_or_else(|| panic!("the job names its {name}: {printed}"))
        .to_owned()
}

/// KR-REQ-03.02: on macOS the daemon starts each worker as a per-user launchd job, never a system
/// one: a headless session's worker in this user's own background domain and a desktop session's
/// in this user's graphical login domain. Each job is defined inside this installation's own state
/// directory and runs in the directory the host gave its worker there, so a launched worker
/// inherits no working directory from whoever asked for it.
#[cfg(target_os = "macos")]
#[tokio::test(flavor = "multi_thread")]
async fn a_worker_on_macos_is_a_per_user_launchd_job_in_its_own_directory() {
    let uid = kr_ipc::paths::current_uid();
    let graphical = std::process::Command::new("/bin/launchctl")
        .arg("print")
        .arg(format!("gui/{uid}"))
        .output()
        .is_ok_and(|output| output.status.success());
    if !graphical {
        eprintln!("skipped: this user has no graphical login session for launchd to start jobs in");
        return;
    }
    let Some(host) = Host::start().await else {
        return;
    };
    let cwd = host.temp.root().display().to_string();
    let state_root = std::fs::canonicalize(host.temp.paths().state_root()).expect("the state root");
    let worker_program = std::fs::canonicalize(host.temp.root().join("bin/kr-worker"))
        .expect("the worker this daemon starts");
    for (execution, domain) in [
        ("--headless", format!("user/{uid}")),
        ("--desktop", format!("gui/{uid}")),
    ] {
        let created = host.kr_json(&[
            "new",
            "--invisible",
            execution,
            "--cwd",
            &cwd,
            "--shell",
            "/bin/sh",
            "--startup",
            "interactive",
            "--json",
        ]);
        let display = created["display_number"].to_string();
        let session_id: SessionId = created["session_id"]
            .as_str()
            .expect("a session identifier")
            .parse()
            .expect("parses");
        let pid = host.worker_of(session_id);

        let printed = launchd_job_of(&domain, pid)
            .unwrap_or_else(|| panic!("the {execution} worker {pid} is a job in {domain}"));
        // The graphical domain is followed by the login session it belongs to.
        assert_eq!(
            field(&printed, "domain").split_whitespace().next(),
            Some(domain.as_str()),
            "{printed}"
        );
        assert_eq!(
            std::fs::canonicalize(field(&printed, "program")).expect("the job's program"),
            worker_program,
            "{printed}"
        );
        let definition =
            std::fs::canonicalize(field(&printed, "path")).expect("the job's definition");
        assert!(
            definition.starts_with(&state_root),
            "the job is defined inside this installation's state directory: {printed}"
        );
        let directory = std::fs::canonicalize(field(&printed, "working directory"))
            .expect("the job's working directory");
        assert!(
            directory.starts_with(&state_root) && directory.ends_with(session_id.to_string()),
            "the worker runs in its own directory inside this installation's state: {printed}"
        );

        let _ = host.kr_json(&["close", &display, "--json"]);
        closed(&host, &display);
    }
}
