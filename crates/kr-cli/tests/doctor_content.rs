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

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::{Duration, Instant};

use kr_controller::service::{Controller, ControllerSetup};
use kr_controller::supervision::{DetachedSupervisor, NoTerminal};
use kr_crypto::store::{StoreSelection, open_store_in};
use kr_ipc::endpoint::Listener;
use kr_ipc::verify::ControllerIdentity;
use kr_protocol::ids::BuildId;
use portable_pty::{CommandBuilder, PtySize, native_pty_system};
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

/// A session this test created, and the process of its worker.
struct Created {
    session: String,
    worker: Option<u64>,
}

/// A host tree, its daemon, and the sessions this test created in it.
struct Host {
    temp: kr_ipc::testing::TempHost,
    work: PathBuf,
    home: PathBuf,
    _controller: Option<Arc<Controller>>,
    serving: Vec<tokio::task::JoinHandle<kr_controller::error::Result<()>>>,
    created: Mutex<Vec<Created>>,
}

/// Whether the process `pid` has ended: it is gone, or it is a zombie nobody has waited for. Asked
/// of `ps`, which says both the same way on every Unix this runs on. `Err` says `ps` could not be
/// asked, which the cleanup reports without panicking, because it runs while a failure may unwind.
fn has_ended(pid: u64) -> Result<bool, String> {
    let listed = std::process::Command::new("/bin/ps")
        .args(["-o", "stat=", "-p", &pid.to_string()])
        .output()
        .map_err(|error| format!("ps could not be run: {error}"))?;
    let state = String::from_utf8_lossy(&listed.stdout);
    Ok(state.trim().is_empty() || state.trim().starts_with('Z'))
}

impl Drop for Host {
    fn drop(&mut self) {
        // A session this test left open would keep its worker and its shell running, so each is
        // closed and its descriptor is waited for, and then its worker's process, before the tree
        // it lives in goes. A failure to end one is reported once all are tried and the daemon is
        // stopped, unless the test is already failing: this runs while a failure may be unwinding.
        let created =
            std::mem::take(&mut *self.created.lock().unwrap_or_else(PoisonError::into_inner));
        let mut failures = Vec::new();
        for Created { session, worker } in created {
            if let Some(failure) = self.end(&session, worker) {
                failures.push(failure);
            }
        }
        for task in &self.serving {
            task.abort();
        }
        if !failures.is_empty() && !std::thread::panicking() {
            panic!("cleanup failed: {failures:?}");
        }
    }
}

impl Host {
    /// Closes `session` and waits until its descriptor has gone and its worker's process has ended.
    /// Returns what went wrong, if anything.
    fn end(&self, session: &str, worker: Option<u64>) -> Option<String> {
        let closed = self.kr(&["close", session]);
        if !closed.status.success() {
            return Some(format!(
                "session {session} could not be closed: {}",
                String::from_utf8_lossy(&closed.stderr)
            ));
        }
        let session_id: kr_protocol::ids::SessionId = session.parse().ok()?;
        let descriptor = self.temp.environment().descriptor_file(session_id);
        let started = Instant::now();
        loop {
            let running = match worker.map(has_ended) {
                Some(Ok(ended)) => !ended,
                Some(Err(failure)) => return Some(failure),
                None => false,
            };
            if !descriptor.exists() && !running {
                break;
            }
            if started.elapsed() >= LIVENESS_DEADLINE {
                return Some(format!(
                    "session {session}'s worker (process {worker:?}) did not end: its descriptor \
                     is {}there",
                    if descriptor.exists() { "" } else { "not " }
                ));
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        None
    }

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
        // The worker's own process, which its descriptor names: what ending the session has to
        // wait for, since the descriptor goes before the process does.
        let worker = kr_ipc::descriptor::read(
            &self.temp.environment(),
            session.parse().expect("an identifier"),
        )
        .expect("the descriptor reads")
        .map(|descriptor| descriptor.process_start_identity.pid.get());
        assert!(
            worker.is_some(),
            "a created session has a worker descriptor"
        );
        self.created
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(Created {
                session: session.clone(),
                worker,
            });
        session
    }

    /// Closes a session and waits until its worker has gone.
    fn close(&self, session: &str) {
        let worker = self
            .created
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .find(|created| created.session == session)
            .and_then(|created| created.worker);
        if let Some(failure) = self.end(session, worker) {
            panic!("{failure}");
        }
        self.created
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|created| created.session != session);
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

    /// Runs `kr doctor --bundle <name> --include-content --json` with `more` after it, with no
    /// terminal, and returns what the command did.
    fn doctor(&self, name: &str, more: &[&str]) -> Bundle {
        let path = self.temp.root().join(name);
        let mut line = vec![
            "doctor",
            "--bundle",
            path.to_str().expect("a path"),
            "--include-content",
            "--json",
        ];
        line.extend_from_slice(more);
        let output = self.kr(&line);
        Bundle { path, output }
    }

    /// Previews the content export, as a person who is not at a terminal must, and returns the
    /// digest it printed. Nothing is written by a preview.
    fn preview(&self, name: &str, more: &[&str]) -> (Bundle, String) {
        let mut line = vec!["--preview"];
        line.extend_from_slice(more);
        let before = std::fs::read(self.temp.root().join(name)).ok();
        let previewed = self.doctor(name, &line);
        let document = previewed.document();
        assert_eq!(
            document["content_written"],
            Value::Bool(false),
            "{document}"
        );
        let digest = document["content_digest"]
            .as_str()
            .unwrap_or_else(|| panic!("a preview prints its digest: {document}"))
            .to_owned();
        assert_eq!(
            std::fs::read(&previewed.path).ok(),
            before,
            "a preview writes nothing: the file is as it was, or still not there"
        );
        (previewed, digest)
    }

    /// Writes a bundle with the content export to `name` in this host's tree: a preview, then the
    /// run that confirms its digest, which is the one returned.
    fn bundle(&self, name: &str) -> Bundle {
        let (_, digest) = self.preview(name, &[]);
        let written = self.doctor(name, &["--confirm-content", &digest]);
        assert!(
            written.path.exists(),
            "the confirmed run writes the bundle: {}",
            written.said()
        );
        written
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
    bundle.document()["content_left_out"].clone()
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
/// and the second privacy read, as a preview, and returns what was composed.
async fn export_held<'a>(
    host: &'a Host,
    at_the_hold: impl FnOnce() + 'a,
) -> kr_cli::doctor::content::Exported {
    let mut holding = Holding {
        client: host.connect().await,
        at_the_hold: Some(Box::new(at_the_hold)),
    };
    kr_cli::doctor::content::export(
        &mut holding,
        host.temp.environment_id(),
        kr_cli::doctor::content::Decision::Preview,
        Vec::new(),
        &kr_cli::doctor::content::Rules::here(),
    )
    .await
    .expect("an export")
}

/// The sessions a composed export names.
fn named(exported: &kr_cli::doctor::content::Exported) -> Vec<String> {
    let record: Value =
        serde_json::from_str(exported.composed().text()).expect("the entry is JSON");
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
        named(&control),
        vec![live.clone()],
        "nothing changed: it is in"
    );

    let held = export_held(&host, || host.privacy_on(&[&live])).await;
    assert_eq!(
        held.composed().left_out(),
        [(kr_cli::doctor::content::Why::PrivacyOn, 1)]
    );
    assert_eq!(named(&held), Vec::<String>::new());
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
    assert_eq!(
        held.composed().left_out(),
        [(kr_cli::doctor::content::Why::Moved, 1)]
    );
    assert_eq!(named(&held), Vec::<String>::new());
}

/// KR-REQ-29.04: planted credentials in a session's working directory reach neither the bundle's
/// content, nor its manifest, nor what the command printed; the control is an ordinary directory
/// name, which stays readable in the content.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn planted_credentials_in_a_working_directory_reach_nothing_the_command_writes_or_prints() {
    const TOKEN: &str = "marker-token-6f2a";
    const PASSWORD: &str = "marker-password-3b9c";
    const ORDINARY: &str = "ordinary-project-name";
    let host = Host::start().await;
    host.create_in(&host.work.join(format!("TOKEN={TOKEN}")));
    host.create_in(&host.work.join(format!("run --password {PASSWORD} now")));
    host.create_in(&host.work.join(ORDINARY));

    let bundle = host.bundle("planted.tar");
    for (name, bytes) in bundle.entries() {
        let text = String::from_utf8_lossy(&bytes);
        for planted in [TOKEN, PASSWORD] {
            assert!(!text.contains(planted), "{planted} is in {name}: {text}");
        }
    }
    for planted in [TOKEN, PASSWORD] {
        assert!(
            !bundle.said().contains(planted),
            "{planted}: {}",
            bundle.said()
        );
        assert!(
            !String::from_utf8_lossy(&bundle.output.stdout).contains(planted),
            "{planted} on standard output"
        );
    }
    let content = bundle.entry("content/sessions.json").expect("the entry");
    assert!(
        content.contains(ORDINARY),
        "an ordinary name stays readable: {content}"
    );
}

/// The content lines a run printed on the error stream, as the file's own text: the lines between
/// the header that says it is exactly what will be written and the digest, with the preview's
/// indent taken off.
fn printed_content(said: &str) -> String {
    let mut lines = said
        .lines()
        .skip_while(|line| !line.starts_with("Redacted by the rules"));
    lines.next();
    let mut content = Vec::new();
    for line in lines {
        if line.starts_with("Digest ") {
            break;
        }
        content.push(line.strip_prefix("    ").unwrap_or(line).to_owned());
    }
    content.join("\n")
}

/// KR-REQ-29.04: what is written is what was shown. The run that confirms a preview's digest
/// prints the content again, and the entry in the archive is that text byte for byte, under the
/// digest the preview printed. The control is the preview itself, which wrote nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_written_content_is_the_content_the_command_printed() {
    let host = Host::start().await;
    host.create();
    host.create();
    let diagnostics = host.kr(&["doctor"]);
    let (previewed, digest) = host.preview("shown.tar", &[]);
    assert!(
        previewed.said().contains(&digest),
        "the preview prints the digest it reports: {}",
        previewed.said()
    );
    assert_eq!(
        previewed.output.status.code(),
        diagnostics.status.code(),
        "a preview exits as the diagnostics alone would have"
    );

    let written = host.doctor("shown.tar", &["--confirm-content", &digest]);
    let document = written.document();
    assert_eq!(document["content_written"], Value::Bool(true), "{document}");
    assert_eq!(document["content_digest"], Value::String(digest.clone()));
    assert_eq!(
        printed_content(&written.said()),
        written.entry("content/sessions.json").expect("the entry"),
        "the archive holds the text that was printed"
    );
    assert_eq!(
        printed_content(&previewed.said()),
        printed_content(&written.said()),
        "and it is the text the preview printed"
    );
    let manifest = written.entry("manifest.json").expect("a manifest");
    assert!(
        manifest.contains(&digest),
        "the manifest records it: {manifest}"
    );
    assert!(
        manifest.contains("printed before it was written"),
        "and that it was shown: {manifest}"
    );
}

/// KR-REQ-29.04: a digest that is not the content's, or a content that changed since the preview,
/// writes nothing and prints none of the content, and an existing file at the destination is left
/// as it was. The control is the digest of the unchanged content, which writes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_digest_that_does_not_match_writes_nothing_and_prints_no_content() {
    let host = Host::start().await;
    let first = host.create();
    let (_, digest) = host.preview("kept.tar", &[]);

    let destination = host.temp.root().join("kept.tar");
    std::fs::write(&destination, b"the bundle that was here before").expect("an existing file");
    let before = std::fs::read(&destination).expect("reads it");
    let refuse = |bundle: &Bundle| {
        let document = bundle.document();
        assert_eq!(bundle.output.status.code(), Some(1), "{document}");
        assert_eq!(document["ok"], Value::Bool(false), "{document}");
        assert!(
            document["message"]
                .as_str()
                .is_some_and(|message| message.contains("not what was shown")),
            "{document}"
        );
        assert_eq!(
            bundle.said(),
            "",
            "nothing was printed on the error stream, so no content: {}",
            bundle.said()
        );
        assert!(
            !document.to_string().contains(&first),
            "none of it on standard output either: {document}"
        );
        assert!(
            document.get("bundle").is_none(),
            "no bundle member: {document}"
        );
        assert_eq!(
            std::fs::read(&destination).expect("still there"),
            before,
            "the file that was there is untouched"
        );
    };

    refuse(&host.doctor("kept.tar", &["--confirm-content", &"ab".repeat(32)]));

    // The host changes after the preview: one more session, so another digest.
    host.create();
    refuse(&host.doctor("kept.tar", &["--confirm-content", &digest]));

    // The control: the digest of what the host holds now writes.
    let (_, current) = host.preview("kept.tar", &[]);
    let written = host.doctor("kept.tar", &["--confirm-content", &current]);
    assert_eq!(
        written.document()["content_written"],
        Value::Bool(true),
        "{}",
        written.said()
    );
    assert_ne!(std::fs::read(&destination).expect("replaced"), before);
}

/// KR-REQ-29.04: a session named with `--exclude-session` is left out and said to be left out by
/// choice, the exclusion is part of what the digest confirms, and a session the host never listed
/// is a usage failure.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_session_excluded_by_name_is_left_out_and_confirmed_with_it() {
    let host = Host::start().await;
    let kept = host.create();
    let dropped = host.create();

    let (previewed, digest) = host.preview("excluded.tar", &["--exclude-session", &dropped]);
    assert_eq!(
        previewed.document()["content_left_out"],
        serde_json::json!([{"reason": "left_out_by_choice", "sessions": 1}])
    );
    assert!(!previewed.said().contains(&dropped), "{}", previewed.said());

    // The same digest without the exclusion is another content.
    let without = host.doctor("excluded.tar", &["--confirm-content", &digest]);
    assert_eq!(without.output.status.code(), Some(1), "{}", without.said());
    assert!(!without.path.exists());

    let written = host.doctor(
        "excluded.tar",
        &["--confirm-content", &digest, "--exclude-session", &dropped],
    );
    assert_eq!(written.sessions(), vec![kept], "{}", written.said());

    let unknown = host.doctor(
        "unknown.tar",
        &[
            "--preview",
            "--exclude-session",
            "0badc0de-0000-4000-8000-00000000c105",
        ],
    );
    assert_eq!(unknown.output.status.code(), Some(2), "{}", unknown.said());
    let malformed = host.doctor(
        "unknown.tar",
        &["--preview", "--exclude-session", "not-an-id"],
    );
    assert_eq!(malformed.output.status.code(), Some(2));
    assert!(!host.temp.root().join("unknown.tar").exists());
}

/// A terminal window the command runs in, with the person's side of it: what the window has shown,
/// and a way to type.
struct Window {
    _terminal: portable_pty::PtyPair,
    shell: Box<dyn portable_pty::Child + Send + Sync>,
    typing: Box<dyn Write + Send>,
    seen: Arc<Mutex<Vec<u8>>>,
}

impl Drop for Window {
    fn drop(&mut self) {
        let _ = self.shell.kill();
        let _ = self.shell.wait();
    }
}

impl Window {
    /// Opens a window whose shell runs `kr` with `arguments` and then prints the status it ended
    /// with.
    fn run(host: &Host, arguments: &[&str]) -> Self {
        let terminal = native_pty_system()
            .openpty(PtySize {
                rows: 24,
                cols: 200,
                pixel_width: 0,
                pixel_height: 0,
            })
            .expect("opens a terminal");
        let kr = kr().display().to_string();
        let words = std::iter::once(kr)
            .chain(arguments.iter().map(|argument| (*argument).to_owned()))
            .map(|word| {
                assert!(
                    !word.contains('\''),
                    "the words this script quotes hold no quote"
                );
                format!("'{word}'")
            })
            .collect::<Vec<_>>()
            .join(" ");
        let mut command = CommandBuilder::new("/bin/sh");
        command.arg("-c");
        command.arg(format!("{words}; echo \"kr ended $?\""));
        command.env_clear();
        for (name, value) in host.variables() {
            command.env(name, value);
        }
        command.cwd(&host.work);
        let shell = terminal
            .slave
            .spawn_command(command)
            .expect("starts the window's shell");
        let mut reader = terminal.master.try_clone_reader().expect("a reader");
        let typing = terminal.master.take_writer().expect("a writer");
        let seen = Arc::new(Mutex::new(Vec::new()));
        let collected = Arc::clone(&seen);
        std::thread::spawn(move || {
            let mut buffer = [0_u8; 4096];
            while let Ok(read) = reader.read(&mut buffer) {
                if read == 0 {
                    break;
                }
                collected
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .extend_from_slice(&buffer[..read]);
            }
        });
        Self {
            _terminal: terminal,
            shell,
            typing,
            seen,
        }
    }

    /// What the window has shown so far, with the terminal's own line endings made plain.
    fn shown(&self) -> String {
        String::from_utf8_lossy(&self.seen.lock().unwrap_or_else(PoisonError::into_inner))
            .replace("\r\n", "\n")
    }

    /// Waits until the window has shown `marker` at least `times` times, and returns what it has
    /// shown. It fails when it never does.
    fn wait_for(&self, marker: &str, times: usize) -> String {
        let started = Instant::now();
        loop {
            let shown = self.shown();
            if shown.matches(marker).count() >= times {
                return shown;
            }
            assert!(
                started.elapsed() < LIVENESS_DEADLINE,
                "the window never showed {marker:?} {times} times: {}",
                shown.escape_debug()
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Ends the person's input, as Ctrl-D does at the start of a line.
    fn end_of_input(&mut self) {
        self.typing
            .write_all(&[0x04])
            .and_then(|()| self.typing.flush())
            .expect("types into the window");
    }

    /// Types one line, as a person does.
    fn type_line(&mut self, line: &str) {
        self.typing
            .write_all(format!("{line}\n").as_bytes())
            .and_then(|()| self.typing.flush())
            .expect("types into the window");
    }
}

/// The question the command asks at a terminal, as far as a test waits for it.
const QUESTION: &str = "Type yes to write the bundle with this content";

/// KR-REQ-29.04: at a real terminal the command prints the content, asks, and writes only on yes.
/// The window is a pseudo-terminal, and the person's answer is typed into it. The content that is
/// written is the content the window showed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn at_a_terminal_yes_writes_the_content_that_was_shown() {
    let host = Host::start().await;
    let session = host.create();
    let path = host.temp.root().join("yes.tar");
    let mut window = Window::run(
        &host,
        &[
            "doctor",
            "--bundle",
            path.to_str().expect("a path"),
            "--include-content",
        ],
    );
    let shown = window.wait_for(QUESTION, 1);
    assert!(
        shown.contains(&session),
        "the content is shown first: {}",
        shown.escape_debug()
    );
    assert!(!path.exists(), "and nothing is written while it is asked");

    window.type_line("yes");
    let shown = window.wait_for("kr ended", 1);
    assert!(
        path.exists(),
        "yes writes the bundle: {}",
        shown.escape_debug()
    );
    let bundle = Bundle {
        path,
        output: std::process::Output {
            status: std::process::ExitStatus::default(),
            stdout: Vec::new(),
            stderr: shown.clone().into_bytes(),
        },
    };
    assert_eq!(
        printed_content(&shown),
        bundle.entry("content/sessions.json").expect("the entry"),
        "the archive holds the text the window showed"
    );
}

/// KR-REQ-29.04: at a terminal, anything but yes writes nothing and says so, and so does the end of
/// the person's input; the control is the yes above.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn at_a_terminal_declining_writes_nothing() {
    let host = Host::start().await;
    host.create();
    for answer in ["no", "perhaps", "end of input"] {
        let path = host
            .temp
            .root()
            .join(format!("{}.tar", answer.replace(' ', "-")));
        let mut window = Window::run(
            &host,
            &[
                "doctor",
                "--bundle",
                path.to_str().expect("a path"),
                "--include-content",
            ],
        );
        window.wait_for(QUESTION, 1);
        if answer == "end of input" {
            window.end_of_input();
        } else {
            window.type_line(answer);
        }
        let shown = window.wait_for("kr ended", 1);
        assert!(
            shown.contains("nothing was written"),
            "{}",
            shown.escape_debug()
        );
        assert!(
            shown.contains("kr ended 1"),
            "the status is stated: {}",
            shown.escape_debug()
        );
        assert!(!path.exists(), "{answer}: no file");
    }
}

/// KR-REQ-29.04: at a terminal a session can be left out by typing its identifier: the content is
/// shown again without it, an identifier that is not in the content is asked about again, and the
/// bundle holds what the second showing held.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn at_a_terminal_a_session_can_be_left_out_by_its_identifier() {
    let host = Host::start().await;
    let kept = host.create();
    let dropped = host.create();
    let path = host.temp.root().join("drop.tar");
    let mut window = Window::run(
        &host,
        &[
            "doctor",
            "--bundle",
            path.to_str().expect("a path"),
            "--include-content",
        ],
    );
    window.wait_for(QUESTION, 1);
    window.type_line("0badc0de-0000-4000-8000-00000000c105");
    window.wait_for("That is not the identifier of a session in this content", 1);
    window.type_line(&dropped);
    let shown = window.wait_for("Digest ", 2);
    window.wait_for(QUESTION, 2);
    window.type_line("yes");
    let shown_after = window.wait_for("kr ended", 1);
    assert!(path.exists(), "{}", shown_after.escape_debug());
    let second = shown_after
        .rsplit("Redacted by the rules")
        .next()
        .expect("the second showing");
    assert!(
        second.contains(&kept) && !second.contains(&dropped),
        "{}",
        second.escape_debug()
    );
    assert!(
        shown.contains("left out by choice"),
        "{}",
        shown.escape_debug()
    );
    let bundle = Bundle {
        path,
        output: std::process::Output {
            status: std::process::ExitStatus::default(),
            stdout: Vec::new(),
            stderr: Vec::new(),
        },
    };
    assert_eq!(bundle.sessions(), vec![kept]);
}

/// KR-REQ-29.04: a yes is for the content the window showed. Privacy mode turned on after the
/// content was shown and before the person answers means nothing is written, and nothing but what
/// was shown is ever printed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn privacy_mode_turned_on_while_the_person_is_asked_writes_nothing() {
    let host = Host::start().await;
    let session = host.create();
    let path = host.temp.root().join("late.tar");
    let mut window = Window::run(
        &host,
        &[
            "doctor",
            "--bundle",
            path.to_str().expect("a path"),
            "--include-content",
        ],
    );
    window.wait_for(QUESTION, 1);
    host.privacy_on(&[&session]);
    window.type_line("yes");
    let shown = window.wait_for("kr ended", 1);
    assert!(
        shown.contains("not what was shown"),
        "{}",
        shown.escape_debug()
    );
    assert!(!path.exists(), "no file: {}", shown.escape_debug());
    assert_eq!(
        shown.matches("Digest ").count(),
        1,
        "only the content that was asked about was ever printed: {}",
        shown.escape_debug()
    );
}

/// KR-REQ-29.04: a preview that cannot be written stops the command before it writes anything, and
/// a bundle already at the destination is left as it was. The error stream is `/dev/full`, which
/// takes no write, so the failure is the real one. The control is the same confirmation with an
/// error stream that works, which writes.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_preview_the_error_stream_cannot_take_writes_nothing() {
    let host = Host::start().await;
    host.create();
    let (_, digest) = host.preview("full.tar", &[]);
    let destination = host.temp.root().join("full.tar");
    std::fs::write(&destination, b"the bundle that was here before").expect("an existing file");
    let before = std::fs::read(&destination).expect("reads it");

    let mut command = std::process::Command::new(kr());
    command
        .args([
            "doctor",
            "--bundle",
            destination.to_str().expect("a path"),
            "--include-content",
            "--json",
            "--confirm-content",
            &digest,
        ])
        .env_clear()
        .envs(host.variables())
        .current_dir(&host.work)
        .stdin(std::process::Stdio::null())
        .stderr(
            std::fs::OpenOptions::new()
                .write(true)
                .open("/dev/full")
                .expect("/dev/full"),
        );
    let output = command.output().expect("kr runs");
    let document: Value = serde_json::from_slice(&output.stdout).expect("a failure document");
    assert_eq!(document["ok"], Value::Bool(false), "{document}");
    assert!(
        document["message"]
            .as_str()
            .is_some_and(|message| message.contains("nothing was written")),
        "{document}"
    );
    assert!(document.get("bundle").is_none(), "{document}");
    assert_eq!(
        std::fs::read(&destination).expect("still there"),
        before,
        "the bundle that was there is untouched"
    );

    let written = host.doctor("full.tar", &["--confirm-content", &digest]);
    assert_eq!(
        written.document()["content_written"],
        Value::Bool(true),
        "{}",
        written.said()
    );
    assert_ne!(std::fs::read(&destination).expect("replaced"), before);
}
