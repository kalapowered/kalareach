//! The content-bearing export of `kr doctor --bundle`, against a real control daemon and real
//! workers.
//!
//! KR-REQ-29.04: a real-content capture is opt-in, leaves private sessions out and is shown to the
//! person before it is written. KR-REQ-26.44 holds the first of those: no content entry without
//! `--include-content`.
//!
//! Everything here is real. The daemon is the control service, started in this process with the
//! detached supervisor, so each session's worker is a process of its own: the one this workspace
//! builds, copied to the internal disk. `kr` is the real binary. Every directory a launched
//! process uses is on the internal disk.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::{Duration, Instant};

use kr_controller::service::{Controller, ControllerSetup};
use kr_controller::supervision::{DetachedSupervisor, NoTerminal};
use kr_crypto::store::{StoreSelection, open_store_in};
use kr_ipc::endpoint::Listener;
use kr_ipc::verify::ControllerIdentity;
use kr_protocol::ids::BuildId;
use serde_json::Value;

mod support;

use support::kr;

/// How long a wait for something to happen is given. It fails when the thing never happens.
const LIVENESS_DEADLINE: Duration = Duration::from_secs(120);

fn build() -> BuildId {
    BuildId::new("kr-test/0").expect("a build identifier")
}

/// The worker binary the daemon starts: the one this workspace built, copied to the internal disk
/// beside the command binaries and run once there before anything is timed.
///
/// # Panics
///
/// Panics when the build has no worker. A check that skipped would report a pass for a path it
/// never ran: a workspace test run builds the worker, and so does `cargo build -p kr-worker`.
fn worker() -> &'static Path {
    static COPIED: OnceLock<PathBuf> = OnceLock::new();
    COPIED.get_or_init(|| {
        let mut directory = std::env::current_exe().expect("the test binary");
        directory.pop();
        if directory.file_name().is_some_and(|name| name == "deps") {
            directory.pop();
        }
        let built = directory.join("kr-worker");
        assert!(
            built.is_file(),
            "this check starts a real worker process and there is none at {}; build it with \
             `cargo build -p kr-worker`",
            built.display()
        );
        let copied = support::command_binaries().join("kr-worker");
        kr_ipc::testing::place_and_start_once(&built, &copied, &["--version"]);
        copied
    })
}

/// A host tree, its daemon, and the sessions this test created in it.
struct Host {
    temp: kr_ipc::testing::TempHost,
    work: PathBuf,
    home: PathBuf,
    _controller: Option<Arc<Controller>>,
    serving: Vec<tokio::task::JoinHandle<kr_controller::error::Result<()>>>,
    created: Mutex<Vec<String>>,
}

impl Drop for Host {
    fn drop(&mut self) {
        // A session this test left open would keep its worker and its shell running, so each is
        // closed and its descriptor, which its worker removes as it ends, is waited for before the
        // tree it lives in goes. Nothing here asserts: this runs while a failure may be unwinding.
        let created =
            std::mem::take(&mut *self.created.lock().unwrap_or_else(PoisonError::into_inner));
        for session in created {
            let closed = self.kr(&["close", &session]);
            if !closed.status.success() {
                eprintln!("session {session} could not be closed when the test ended");
                continue;
            }
            if let Ok(session_id) = session.parse::<kr_protocol::ids::SessionId>() {
                let descriptor = self.temp.environment().descriptor_file(session_id);
                let started = Instant::now();
                while descriptor.exists() && started.elapsed() < LIVENESS_DEADLINE {
                    std::thread::sleep(Duration::from_millis(50));
                }
            }
        }
        for task in &self.serving {
            task.abort();
        }
    }
}

impl Host {
    async fn start() -> Self {
        let worker = worker().to_path_buf();
        let temp = kr_ipc::testing::TempHost::create();
        let work = temp.root().join("w");
        let home = temp.root().join("h");
        for directory in [&work, &home] {
            std::fs::create_dir(directory).expect("a directory on the internal disk");
        }
        let environment = temp.environment();
        let environment_id = temp.environment_id();
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
            supervisor: Box::new(DetachedSupervisor::new()),
            worker_program: worker,
            build_id: build(),
            release: "0".to_owned(),
            shell_packages: None,
            terminal: Box::new(NoTerminal),
        })
        .await
        .expect("the daemon starts");
        let rendezvous = Listener::bind(&environment.rendezvous_endpoint().expect("an endpoint"))
            .expect("binds the rendezvous endpoint");
        let clients = Listener::bind(&environment.controller_endpoint().expect("an endpoint"))
            .expect("binds the control endpoint");
        let serving = vec![
            tokio::spawn(Arc::clone(&controller).serve_rendezvous(rendezvous)),
            tokio::spawn(Arc::clone(&controller).serve_clients(clients)),
        ];
        Self {
            temp,
            work,
            home,
            _controller: Some(controller),
            serving,
            created: Mutex::new(Vec::new()),
        }
    }

    /// The environment every `kr` this test runs is given: this host's directories, a home of its
    /// own, and nothing of the person running the test.
    fn variables(&self) -> Vec<(&'static str, String)> {
        vec![
            ("PATH", "/usr/bin:/bin".to_owned()),
            ("TERM", "xterm-256color".to_owned()),
            ("HOME", self.home.display().to_string()),
            (
                "KR_RUNTIME_DIR",
                self.temp.paths().runtime_root().display().to_string(),
            ),
            (
                "KR_STATE_DIR",
                self.temp.paths().state_root().display().to_string(),
            ),
        ]
    }

    /// Runs `kr` as a command in another window: no terminal, and this host's directories.
    fn kr(&self, line: &[&str]) -> std::process::Output {
        std::process::Command::new(kr())
            .args(line)
            .env_clear()
            .envs(self.variables())
            .current_dir(&self.work)
            .stdin(std::process::Stdio::null())
            .output()
            .expect("kr runs")
    }

    /// Runs `kr` with `--json` and reads the one document it printed.
    fn json(&self, line: &[&str]) -> (Option<i32>, Value) {
        let mut asked = line.to_vec();
        asked.push("--json");
        let output = self.kr(&asked);
        let document = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
            panic!(
                "kr {} printed no document ({error}): {}{}",
                asked.join(" "),
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )
        });
        (output.status.code(), document)
    }

    /// Runs `kr` with `--json`, requires it to succeed, and returns what it printed.
    fn kr_json(&self, line: &[&str]) -> Value {
        let (status, document) = self.json(line);
        assert_eq!(status, Some(0), "kr {}: {document}", line.join(" "));
        document
    }

    /// Creates a session with no terminal of its own, and returns its identifier.
    fn create(&self) -> String {
        self.create_in(&self.work)
    }

    /// Creates a session whose working directory is `directory`, which is made if it is not there.
    fn create_in(&self, directory: &Path) -> String {
        std::fs::create_dir_all(directory).expect("a directory on the internal disk");
        let directory = directory.display().to_string();
        let created = self.kr_json(&[
            "new",
            "--invisible",
            "--headless",
            "--shell",
            "/bin/sh",
            "--startup",
            "interactive",
            "--cwd",
            &directory,
        ]);
        let session = created["session_id"]
            .as_str()
            .expect("an identifier")
            .to_owned();
        self.created
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(session.clone());
        session
    }

    /// Closes a session and waits until its worker has gone.
    fn close(&self, session: &str) {
        let closed = self.kr(&["close", session]);
        assert!(
            closed.status.success(),
            "kr close: {}",
            String::from_utf8_lossy(&closed.stderr)
        );
        let session_id: kr_protocol::ids::SessionId = session.parse().expect("an identifier");
        let descriptor = self.temp.environment().descriptor_file(session_id);
        let started = Instant::now();
        while descriptor.exists() {
            assert!(
                started.elapsed() < LIVENESS_DEADLINE,
                "session {session}'s descriptor is still at {}",
                descriptor.display()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        self.created
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|created| created != session);
    }

    /// Waits until `holds` says privacy mode's report is what the test needs, and returns it.
    fn privacy_until(&self, what: &str, holds: impl Fn(&Value) -> bool) -> Value {
        let started = Instant::now();
        loop {
            let report = self.kr_json(&["privacy", "status"]);
            if holds(&report) {
                return report;
            }
            assert!(
                started.elapsed() < LIVENESS_DEADLINE,
                "privacy mode never reached {what}: {report}"
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// Turns privacy mode on and waits until every live session has answered that its cleanup is
    /// done: what is left owing is only sessions whose worker has gone.
    fn privacy_on(&self, live: &[&str]) {
        // The change is recorded before it finishes taking effect, so the command may report that
        // it is still settling; the status says how far it has got.
        let _ = self.kr(&["privacy", "on"]);
        self.privacy_until("on, with every live session's cleanup done", |report| {
            report["enabled"] == Value::Bool(true)
                && report["sessions"].as_array().is_some_and(|owing| {
                    owing.iter().all(|owed| {
                        owed["standing"]["state"] == "worker_ended"
                            || !live
                                .iter()
                                .any(|session| owed["session_id"].as_str() == Some(*session))
                    })
                })
        });
    }

    /// Turns privacy mode off, which is refused while a live session still owes cleanup, until it
    /// is accepted. Accepted means recorded: the change can still report that it is not finished
    /// taking effect, as it does for good while a session whose worker ended owes its cleanup.
    fn privacy_off(&self) {
        let started = Instant::now();
        loop {
            let output = self.kr(&["privacy", "off"]);
            if self.kr_json(&["privacy", "status"])["enabled"] == Value::Bool(false) {
                return;
            }
            assert!(
                started.elapsed() < LIVENESS_DEADLINE,
                "privacy mode would not turn off: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// Writes a bundle with the content export to `name` in this host's tree, and returns what
    /// the command did. The command is run with `--json`, so its one document is on standard output
    /// and what it said of the export is on the error stream.
    fn bundle(&self, name: &str) -> Bundle {
        let path = self.temp.root().join(name);
        let output = self.kr(&[
            "doctor",
            "--bundle",
            path.to_str().expect("a path"),
            "--include-content",
            "--json",
        ]);
        Bundle { path, output }
    }

    /// A connection of this test's own to the daemon, the way `kr doctor` has one.
    async fn connect(&self) -> kr_ipc::client::LocalClient {
        let endpoint = self
            .temp
            .environment()
            .controller_endpoint()
            .expect("an endpoint");
        kr_ipc::client::LocalClient::connect(
            &endpoint,
            kr_protocol::local::LocalClientKind::Cli,
            build(),
        )
        .await
        .expect("reaches the daemon")
    }
}

/// A connection to the daemon that does something of the test's own the moment the session list
/// has been read, and before the second privacy read: the hold between the two reads, decided by
/// what has happened rather than by how long anything takes.
struct Holding<'a> {
    client: kr_ipc::client::LocalClient,
    at_the_hold: Option<Box<dyn FnOnce() + 'a>>,
}

impl kr_cli::doctor::content::Host for Holding<'_> {
    async fn privacy(&mut self) -> kr_cli::Result<kr_protocol::privacy::PrivacyReport> {
        self.client.privacy().await
    }

    async fn sessions(
        &mut self,
        environment_id: kr_protocol::ids::EnvironmentId,
    ) -> kr_cli::Result<kr_protocol::session::SessionListResult> {
        let listed = self.client.sessions(environment_id).await;
        if let Some(act) = self.at_the_hold.take() {
            act();
        }
        listed
    }
}

/// What `kr doctor --bundle` did.
struct Bundle {
    path: PathBuf,
    output: std::process::Output,
}

impl Bundle {
    /// The document the command printed on standard output.
    fn document(&self) -> Value {
        serde_json::from_slice(&self.output.stdout).unwrap_or_else(|error| {
            panic!(
                "kr doctor printed no document ({error}): {}{}",
                String::from_utf8_lossy(&self.output.stdout),
                self.said()
            )
        })
    }

    /// What the command said on the error stream.
    fn said(&self) -> String {
        String::from_utf8_lossy(&self.output.stderr).into_owned()
    }

    /// The archive's entries: each name with its bytes.
    fn entries(&self) -> Vec<(String, Vec<u8>)> {
        let bytes = std::fs::read(&self.path).expect("the bundle was written");
        let mut entries = Vec::new();
        let mut at = 0;
        while at + 512 <= bytes.len() && bytes[at] != 0 {
            let header = &bytes[at..at + 512];
            let name_end = header[..100]
                .iter()
                .position(|byte| *byte == 0)
                .unwrap_or(100);
            let name = String::from_utf8_lossy(&header[..name_end]).into_owned();
            let size = usize::from_str_radix(
                String::from_utf8_lossy(&header[124..135])
                    .trim_matches(['\0', ' '])
                    .trim(),
                8,
            )
            .expect("an octal size");
            entries.push((name, bytes[at + 512..at + 512 + size].to_vec()));
            at += 512 + size.div_ceil(512) * 512;
        }
        entries
    }

    /// One entry's text.
    fn entry(&self, name: &str) -> Option<String> {
        self.entries()
            .into_iter()
            .find(|(entry, _)| entry == name)
            .map(|(_, bytes)| String::from_utf8_lossy(&bytes).into_owned())
    }

    /// The sessions the content entry names, by identifier.
    fn sessions(&self) -> Vec<String> {
        let content = self
            .entry("content/sessions.json")
            .expect("a content entry");
        let record: Value = serde_json::from_str(&content).expect("the entry is JSON");
        record["sessions"]
            .as_array()
            .expect("a list of sessions")
            .iter()
            .map(|session| session["session_id"].as_str().expect("an id").to_owned())
            .collect()
    }
}

/// What the bundle document says was left out of the content export: each reason and its count.
fn left_out(bundle: &Bundle) -> Value {
    bundle.document()["bundle"]["content_left_out"].clone()
}

/// KR-REQ-29.04: with privacy mode off and never turned on, the content export holds every session
/// of the environment, live or closed: nothing is left out where nothing is private.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn privacy_mode_never_enabled_leaves_no_session_out_of_the_content_export() {
    let host = Host::start().await;
    let live = host.create();
    let closed = host.create();
    host.close(&closed);

    let bundle = host.bundle("never.tar");
    let mut sessions = bundle.sessions();
    sessions.sort();
    let mut expected = vec![live, closed];
    expected.sort();
    assert_eq!(sessions, expected, "{}", bundle.said());
    assert!(
        !bundle.said().contains("left out"),
        "nothing is said to be left out: {}",
        bundle.said()
    );
    let document = bundle.document();
    assert_eq!(document["bundle"]["content_entries"], 1, "{document}");
    assert_eq!(left_out(&bundle), serde_json::json!([]), "{document}");
}

/// KR-REQ-26.44: without `--include-content` the bundle carries no content entry, whatever the
/// host holds.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_bundle_asked_for_without_content_carries_no_content_entry() {
    let host = Host::start().await;
    host.create();
    let path = host.temp.root().join("plain.tar");
    let output = host.kr(&["doctor", "--bundle", path.to_str().expect("a path")]);
    let bundle = Bundle { path, output };
    let names: Vec<String> = bundle.entries().into_iter().map(|(name, _)| name).collect();
    assert_eq!(
        names,
        vec!["manifest.json".to_owned(), "report.txt".to_owned()]
    );
}

/// KR-REQ-29.04: with privacy mode on and two sessions live, the content export names neither, and
/// the preview, the manifest and the bundle document say why; the command still writes the bundle
/// and exits as the diagnostics alone would have. The control is the same host with privacy mode
/// never enabled: there both are in, and a directory name planted in one session's working
/// directory is in the content; with privacy mode on it is in no entry of the bundle.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn privacy_mode_on_leaves_every_session_out_of_the_content_export() {
    const MARKER: &str = "cwd-marker-4c1e";
    let host = Host::start().await;
    let first = host.create_in(&host.work.join(MARKER));
    let second = host.create();

    // The control: privacy mode is off, and both are in.
    let control = host.bundle("control.tar");
    let mut listed = control.sessions();
    listed.sort();
    let mut both = vec![first.clone(), second.clone()];
    both.sort();
    assert_eq!(listed, both, "{}", control.said());
    assert!(
        control
            .entry("content/sessions.json")
            .is_some_and(|content| content.contains(MARKER)),
        "the planted directory is in the control's content"
    );

    host.privacy_on(&[&first, &second]);
    let diagnostics = host.kr(&["doctor"]);
    let private = host.bundle("private.tar");

    assert_eq!(
        private.sessions(),
        Vec::<String>::new(),
        "no session is named: {}",
        private.said()
    );
    for (name, bytes) in private.entries() {
        let text = String::from_utf8_lossy(&bytes);
        for planted in [first.as_str(), second.as_str(), MARKER] {
            assert!(!text.contains(planted), "{planted} is in {name}: {text}");
        }
    }
    assert!(
        private
            .said()
            .contains("2 sessions left out: privacy mode is on"),
        "the preview says why: {}",
        private.said()
    );
    assert!(
        !private.said().contains(MARKER),
        "and names nothing of them: {}",
        private.said()
    );
    let manifest = private.entry("manifest.json").expect("a manifest");
    assert!(
        manifest.contains("2 sessions left out: privacy mode is on"),
        "the manifest says why: {manifest}"
    );
    assert_eq!(
        left_out(&private),
        serde_json::json!([{"reason": "privacy_mode_on", "sessions": 2}]),
        "{}",
        private.document()
    );
    assert_eq!(private.document()["bundle"]["content_entries"], 1);
    assert_eq!(
        private.output.status.code(),
        diagnostics.status.code(),
        "leaving sessions out changes nothing about the exit status: {}",
        private.said()
    );
}

/// KR-REQ-29.04: a session whose worker had ended when privacy mode went on stays out after privacy
/// mode is off, because what it kept is the archive's; a session that ran through the private
/// interval and owes nothing is in, and so is one created since. The controls are the two that are
/// in.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_session_whose_worker_had_ended_stays_out_after_privacy_mode_is_off() {
    let host = Host::start().await;
    let ended = host.create();
    host.close(&ended);
    let through = host.create();

    host.privacy_on(&[&through]);
    // The daemon takes a session whose worker has gone for ended on its own pass, so wait for it
    // to say so; it keeps saying so for good, which is what the test needs.
    let owes = |report: &Value| {
        report["sessions"].as_array().is_some_and(|owing| {
            owing.iter().any(|owed| {
                owed["session_id"].as_str() == Some(ended.as_str())
                    && owed["standing"]["state"] == "worker_ended"
            })
        })
    };
    host.privacy_until("the closed session's cleanup owed for good", owes);
    host.privacy_off();
    let report = host.kr_json(&["privacy", "status"]);
    assert!(
        owes(&report),
        "it outlasts turning privacy mode off: {report}"
    );
    let since = host.create();

    let bundle = host.bundle("after.tar");
    let mut listed = bundle.sessions();
    listed.sort();
    let mut expected = vec![through, since];
    expected.sort();
    assert_eq!(listed, expected, "{}", bundle.said());
    assert!(
        bundle
            .said()
            .contains("1 session left out: privacy cleanup is still owed"),
        "{}",
        bundle.said()
    );
    assert_eq!(
        left_out(&bundle),
        serde_json::json!([{"reason": "owes_privacy_cleanup", "sessions": 1}]),
        "{}",
        bundle.document()
    );
    assert_eq!(bundle.document()["bundle"]["content_entries"], 1);
}

/// Reads the content export through a connection that does `at_the_hold` between the session read
/// and the second privacy read, and returns what was composed.
async fn export_held<'a>(
    host: &'a Host,
    at_the_hold: impl FnOnce() + 'a,
) -> kr_cli::doctor::content::Composed {
    let mut holding = Holding {
        client: host.connect().await,
        at_the_hold: Some(Box::new(at_the_hold)),
    };
    let reading = kr_cli::doctor::content::read(&mut holding, host.temp.environment_id())
        .await
        .expect("a reading");
    kr_cli::doctor::content::compose(&reading).expect("composes")
}

/// The sessions a composed export names.
fn named(composed: kr_cli::doctor::content::Composed) -> Vec<String> {
    let record: Value =
        serde_json::from_slice(&composed.into_content().bytes).expect("the entry is JSON");
    record["sessions"]
        .as_array()
        .expect("a list of sessions")
        .iter()
        .map(|session| session["session_id"].as_str().expect("an id").to_owned())
        .collect()
}

/// KR-REQ-29.04: privacy mode turned on between the session read and the second privacy read
/// leaves every session out: the list may have been read before the change, and nothing read across
/// a change is exported. The control is the same hold doing nothing, where the session is in.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn privacy_mode_turned_on_between_the_reads_exports_nothing() {
    let host = Host::start().await;
    let live = host.create();

    let control = export_held(&host, || {}).await;
    assert_eq!(
        named(control),
        vec![live.clone()],
        "nothing changed: it is in"
    );

    let held = export_held(&host, || host.privacy_on(&[&live])).await;
    assert_eq!(
        held.left_out(),
        [(kr_cli::doctor::content::Why::PrivacyOn, 1)]
    );
    assert_eq!(named(held), Vec::<String>::new());
}

/// KR-REQ-29.04: privacy mode turned on and off again between the reads leaves every session out
/// too, although it is off at both ends: the generation moved, which is all a reader across the
/// cycle can know. The live session has finished its cleanup by then and owes nothing, so the
/// generation is the only reason it is out.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_full_cycle_of_privacy_mode_between_the_reads_exports_nothing() {
    let host = Host::start().await;
    let live = host.create();

    let held = export_held(&host, || {
        host.privacy_on(&[&live]);
        host.privacy_off();
    })
    .await;
    let report = host.kr_json(&["privacy", "status"]);
    assert_eq!(
        report["enabled"],
        Value::Bool(false),
        "off at the end: {report}"
    );
    assert_eq!(
        report["sessions"],
        Value::Array(Vec::new()),
        "and it owes nothing: {report}"
    );
    assert_eq!(held.left_out(), [(kr_cli::doctor::content::Why::Moved, 1)]);
    assert_eq!(named(held), Vec::<String>::new());
}
