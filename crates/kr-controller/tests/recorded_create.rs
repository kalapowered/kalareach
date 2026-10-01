//! What a daemon keeps of the environment its creator sent with a session create.
//!
//! A CLI sends its environment with `session.create`, and an exported credential is in it. The
//! worker needs the variables to build the shell's environment, and nothing after the launch does.
//! These tests start a real daemon and a real worker, create a session carrying a marker variable
//! whose value is random, and read every byte of every file under the environment's state and
//! runtime directories as raw bytes, write-ahead log and shared-memory file included: the marker
//! is found nowhere, while the shell the worker started still has the variable.
//!
//! Beside them are the controls the daemon owes the same change: a repeated create token returns
//! its session, the same token with another payload conflicts, a launch held across a daemon
//! restart resolves as one that produced no session, a registry an earlier build wrote is rewritten
//! when it opens, and a claim that has no variables to take is refused and fails its reservation.
//!
//! Everything a launched process opens is on the internal disk, under the test's own tree.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::time::Duration;

use kr_controller::registry::{LaunchPhase, Registry};
use kr_controller::service::{Controller, ControllerSetup};
use kr_controller::supervision::{LaunchOutcome, WorkerLaunch, WorkerSupervisor};
use kr_crypto::store::{StoreSelection, open_store_in};
use kr_ipc::client::LocalClient;
use kr_ipc::endpoint::{Connection, Listener};
use kr_ipc::verify::{ControllerIdentity, WorkerIdentity};
use kr_protocol::envelope::{ActionTarget, ControlFrame};
use kr_protocol::error::ErrorCode;
use kr_protocol::hello::PROTOCOL_VERSION;
use kr_protocol::ids::{ActionId, ActorId, BuildId, EnvironmentId, SessionEpoch};
use kr_protocol::local::LocalClientKind;
use kr_protocol::method::Method;
use kr_protocol::scalars::{Digest256, Nullable};
use kr_protocol::session::{
    EnvironmentVariable, Presentation, SessionCreateParams, SessionCreateResult, ShellMode,
};

mod teardown;

/// How long a test waits for something the daemon or the shell does on its own. Generous, because
/// a loaded machine is slow and none of these is timed by the product itself.
const PATIENCE: Duration = Duration::from_secs(40);

/// The name of the variable the creator's environment carries.
const MARKER_NAME: &str = "RECORDED_CREATE_MARKER";

fn build() -> BuildId {
    BuildId::new("kr-test/0").expect("a build identifier")
}

/// Returns the worker binary beside this test's own.
fn worker_beside_this_test() -> PathBuf {
    let mut directory = std::env::current_exe().expect("the test binary");
    directory.pop();
    if directory.file_name().is_some_and(|name| name == "deps") {
        directory.pop();
    }
    let worker = directory.join("kr-worker");
    assert!(
        worker.is_file(),
        "this test starts a worker process and there is none at {}; build it with \
         `cargo build -p kr-worker`, or run the whole workspace's tests, which build it",
        worker.display()
    );
    worker
}

/// A random value no other byte of the environment's files can equal.
fn marker_value() -> String {
    format!("marker-{}", kr_ipc::new_uuid())
}

/// How long a killed daemon is given to be collected, and a started one to answer.
const COLLECT_BOUND: Duration = Duration::from_secs(30);
const DAEMON_START_DEADLINE: Duration = Duration::from_secs(120);

/// A daemon this test started as a process of its own, ended when it goes out of scope however that
/// happens. Its handle is kept until the daemon is established as ended: one that was not collected
/// keeps the host tree, so the directories it may still be reading are never removed from under it.
struct Daemon {
    child: Option<std::process::Child>,
    tree: teardown::Holder,
}

impl Daemon {
    /// Ends it now, without giving it a chance to tidy up, and says whether it was seen to end.
    fn stop(&mut self) -> Result<(), String> {
        let Some(child) = self.child.as_mut() else {
            return Ok(());
        };
        child
            .kill()
            .map_err(|error| format!("the daemon could not be killed: {error}"))?;
        let deadline = std::time::Instant::now() + COLLECT_BOUND;
        let ended = loop {
            match child.try_wait() {
                Ok(Some(_)) => break Ok(()),
                Ok(None) if std::time::Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Ok(None) => {
                    break Err(format!(
                        "the daemon had not ended {COLLECT_BOUND:?} after it was killed"
                    ));
                }
                Err(error) => break Err(format!("the daemon could not be waited for: {error}")),
            }
        };
        if ended.is_ok() {
            self.child = None;
        }
        ended
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        if let Err(error) = self.stop() {
            self.tree.hold(format!(
                "the daemon this test started could not be established as ended: {error}"
            ));
        }
    }
}

/// A daemon process that starts real workers, on a tree this test owns, writing its own output to
/// the environment's `controller.log` as a daemon under a service manager does.
struct Host {
    daemon: Option<Daemon>,
    endpoint: kr_ipc::paths::Endpoint,
    environment_id: EnvironmentId,
    program: PathBuf,
    worker: PathBuf,
    /// The file a held worker waits for, where the worker is held, and the file that ends it
    /// without letting it go on.
    gate: Option<(PathBuf, PathBuf)>,
    /// Last, so it goes last: it ends every worker the daemon started.
    tree: teardown::Tree,
}

impl Host {
    async fn start() -> Self {
        Self::start_holding(false).await
    }

    /// A host whose workers wait, before they do anything, for a file this test creates: the hold
    /// that lets the test act between a reservation and its worker's claim, decided by a condition
    /// and never by a delay.
    async fn start_held() -> Self {
        Self::start_holding(true).await
    }

    async fn start_holding(held: bool) -> Self {
        let tree = teardown::Tree::create();
        let worker = tree.root().join("kr-worker");
        let program = tree.root().join("kr-controller");
        let mut gate = None;
        if held {
            // On the internal disk, and started once here, where nothing is timed. What the daemon
            // launches is a script that waits at the gate and then becomes the worker, so the
            // process the launcher recorded is the one that claims.
            let real = tree.root().join("kr-worker-real");
            kr_ipc::testing::place_and_start_once(
                &worker_beside_this_test(),
                &real,
                &["--version"],
            );
            let opening = tree.root().join("gate");
            let cancelling = tree.root().join("cancel");
            std::fs::write(
                &worker,
                format!(
                    "#!/bin/sh\nwhile [ ! -e '{}' ]; do\n  if [ -e '{}' ]; then exit 0; fi\n  \
                     /bin/sleep 0.1\ndone\nexec '{}' \"$@\"\n",
                    opening.display(),
                    cancelling.display(),
                    real.display()
                ),
            )
            .expect("writes the held worker");
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&worker, std::fs::Permissions::from_mode(0o755))
                .expect("makes it runnable");
            gate = Some((opening, cancelling));
        } else {
            kr_ipc::testing::place_and_start_once(
                &worker_beside_this_test(),
                &worker,
                &["--version"],
            );
        }
        kr_ipc::testing::place_and_start_once(
            Path::new(env!("CARGO_BIN_EXE_kr-controller")),
            &program,
            &["--version"],
        );
        let environment = tree.environment();
        let mut host = Self {
            daemon: None,
            endpoint: environment.controller_endpoint().expect("an endpoint"),
            environment_id: tree.environment_id(),
            program,
            worker,
            gate,
            tree,
        };
        host.run().await;
        host
    }

    /// Lets every held worker go on.
    fn open_gate(&self) {
        let (gate, _) = self.gate.as_ref().expect("a host with a held worker");
        std::fs::write(gate, b"").expect("opens the gate");
    }

    /// Ends every held worker that has not been let go, without it becoming a worker.
    fn cancel_held_workers(&self) {
        if let Some((_, cancelling)) = &self.gate {
            let _ = std::fs::write(cancelling, b"");
        }
    }

    /// Ends the daemon where it stands, without starting another.
    fn kill_daemon(&mut self) {
        let mut daemon = self.daemon.take().expect("a daemon");
        daemon.stop().expect("the daemon ends where it stands");
    }

    /// Every reservation the registry records, as its phase and its launcher's process number.
    fn reservations(&self) -> Vec<(String, Option<i64>)> {
        let Ok(connection) = rusqlite::Connection::open_with_flags(
            self.tree.environment().registry_database(),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        ) else {
            return Vec::new();
        };
        let _ = connection.busy_timeout(PATIENCE);
        let Ok(mut statement) = connection
            .prepare("SELECT phase, launcher_pid FROM reservations ORDER BY created_at_ms")
        else {
            return Vec::new();
        };
        statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .map(|rows| rows.flatten().collect())
            .unwrap_or_default()
    }

    /// Starts the daemon on the tree and waits until it answers.
    async fn run(&mut self) {
        let environment = self.tree.environment();
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(environment.state_dir().join("controller.log"))
            .expect("opens the daemon's log");
        let child = std::process::Command::new(&self.program)
            .arg("--runtime-dir")
            .arg(environment.runtime_root())
            .arg("--state-dir")
            .arg(environment.state_root())
            .arg("--worker")
            .arg(&self.worker)
            // Its keys belong to this run: they go in this environment's own secrets directory.
            .arg("--secret-store")
            .arg("file")
            // Never this test's own directory: the build tree can be on a removable volume.
            .current_dir(self.tree.root())
            .stdin(std::process::Stdio::null())
            .stdout(log.try_clone().expect("duplicates the log"))
            .stderr(log)
            .spawn()
            .expect("starts the daemon");
        self.daemon = Some(Daemon {
            child: Some(child),
            tree: self.tree.holder(),
        });
        let started = std::time::Instant::now();
        loop {
            let remaining = DAEMON_START_DEADLINE.saturating_sub(started.elapsed());
            assert!(
                !remaining.is_zero(),
                "the daemon did not answer on {}",
                self.endpoint.as_text()
            );
            if let Ok(Ok(_answered)) = tokio::time::timeout(
                remaining,
                LocalClient::connect(&self.endpoint, LocalClientKind::Cli, build()),
            )
            .await
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// Ends the daemon where it stands and starts another on the same tree, the way a restart of
    /// the host does: every durable record stays, nothing held in memory does, and the workers go
    /// on running.
    async fn restart(&mut self) {
        let mut daemon = self.daemon.take().expect("a daemon");
        daemon.stop().expect("the daemon ends where it stands");
        drop(daemon);
        self.run().await;
    }

    async fn client(&self) -> LocalClient {
        LocalClient::connect(&self.endpoint, LocalClientKind::Cli, build())
            .await
            .expect("connects")
    }

    fn target(&self, session: Option<&SessionCreateResult>) -> ActionTarget {
        ActionTarget {
            environment_id: self.environment_id,
            session_id: Nullable::from(session.map(|created| created.session.session_id)),
            session_epoch: Nullable::from(session.map(|created| created.session.session_epoch)),
            application_instance_id: Nullable::null(),
            agent_binding_revision: Nullable::null(),
        }
    }

    /// A create request whose environment carries the marker, for a shell started in `cwd`.
    fn request(&self, cwd: &Path, value: &str) -> SessionCreateParams {
        SessionCreateParams {
            environment_id: self.environment_id,
            presentation: Presentation::Invisible,
            shell: Nullable::some("/bin/sh".to_owned()),
            shell_mode: ShellMode::NativeCompat,
            cwd: Nullable::some(cwd.display().to_string()),
            dimensions: Nullable::null(),
            worker_profile: kr_protocol::identity::WorkerProfile::HeadlessUser,
            environment_snapshot: vec![EnvironmentVariable {
                name: MARKER_NAME.to_owned(),
                value: value.to_owned(),
            }],
            palette: Nullable::null(),
            launch_profile: kr_protocol::session::LaunchProfile::default(),
            terminal: Nullable::null(),
        }
    }

    /// Creates a session with a real worker, and returns it once it is live.
    async fn create(&self, request: &SessionCreateParams) -> SessionCreateResult {
        self.client()
            .await
            .mutate(
                Method::SessionCreate,
                ActionId::new(kr_ipc::new_uuid()),
                self.target(None),
                request,
            )
            .await
            .expect("reaches the daemon")
            .expect("the session is created")
            .to_typed()
            .expect("decodes")
    }

    async fn close(&self, created: &SessionCreateResult) {
        let session = &created.session;
        let _: kr_protocol::session::SessionCloseResult = self
            .client()
            .await
            .mutate(
                Method::SessionClose,
                ActionId::new(kr_ipc::new_uuid()),
                self.target(Some(created)),
                &kr_protocol::session::SessionCloseParams {
                    session_id: session.session_id,
                },
            )
            .await
            .expect("reaches the daemon")
            .expect("closes")
            .to_typed()
            .expect("decodes");
    }

    /// Waits until the session's closure is complete: the daemon has recorded it and retired the
    /// session's descriptor, and the worker has removed its own endpoint. `session.close` answers
    /// when the daemon has accepted it, which is earlier.
    async fn until_closed(&self, created: &SessionCreateResult) {
        let environment = self.tree.environment();
        let descriptor = environment.descriptor_file(created.session.session_id);
        let endpoint = environment
            .worker_endpoint(created.session.display_number)
            .expect("the worker's endpoint");
        until("the session's closure to finish", || {
            (!descriptor.exists() && !endpoint.as_path().exists()).then_some(())
        })
        .await;
    }

    /// Types `line` into a session's terminal as a person at an attached terminal does.
    async fn type_into(&self, created: &SessionCreateResult, line: &str) -> LocalClient {
        let session = &created.session;
        let endpoint = self
            .tree
            .environment()
            .worker_endpoint(session.display_number)
            .expect("the worker's endpoint");
        let mut client = LocalClient::connect(&endpoint, LocalClientKind::Cli, build())
            .await
            .expect("connects to the session's worker");
        let target = self.target(Some(created));
        let mut requested = kr_protocol::scalars::CanonicalSet::new();
        requested.insert(kr_protocol::attachment::AttachmentCapability::ObserveTerminal);
        requested.insert(kr_protocol::attachment::AttachmentCapability::Input);
        let attached: kr_protocol::attachment::SessionAttachResult = client
            .mutate(
                Method::SessionAttach,
                ActionId::new(kr_ipc::new_uuid()),
                target.clone(),
                &kr_protocol::attachment::SessionAttachParams {
                    session_id: session.session_id,
                    mode: kr_protocol::attachment::AttachMode::Terminal,
                    claim_geometry: false,
                    dimensions: Nullable::some(kr_protocol::session::Dimensions::new(80, 24)),
                    terminal_profile_id: Nullable::some("xterm-256color".to_owned()),
                    requested,
                },
            )
            .await
            .expect("reaches the worker")
            .expect("the attachment is accepted")
            .to_typed()
            .expect("decodes");
        let acquired: kr_protocol::input::InputAcquireResult = client
            .mutate(
                Method::InputAcquire,
                ActionId::new(kr_ipc::new_uuid()),
                target,
                &kr_protocol::input::InputAcquireParams {
                    session_id: session.session_id,
                    attachment_id: attached.attachment.attachment_id,
                    expected_epoch: Nullable::null(),
                },
            )
            .await
            .expect("reaches the worker")
            .expect("the lease is acquired")
            .to_typed()
            .expect("decodes");
        client
            .request(
                Method::InputWrite,
                &kr_protocol::input::InputWriteParams {
                    session_id: session.session_id,
                    attachment_id: attached.attachment.attachment_id,
                    epoch: acquired.lease.epoch,
                    sequence: kr_protocol::ids::InputSequence::new(0),
                    bytes: kr_protocol::scalars::Bytes::new(line.as_bytes().to_vec()),
                },
            )
            .await
            .expect("reaches the worker")
            .expect("the line reaches the terminal");
        client
    }

    /// Reads every regular file under this environment's state and runtime directories as raw
    /// bytes, and says which hold `needle` and which could not be read.
    fn scan_for(&self, needle: &str) -> Scanned {
        let paths = self.tree.paths();
        let mut scanned = Scanned::default();
        for root in [paths.state_root(), paths.runtime_root()] {
            // Below a root a file that has gone is nothing; a root that is not there means this
            // test is looking in the wrong place.
            if !root.is_dir() {
                scanned
                    .unreadable
                    .push(format!("{} is not a directory to scan", root.display()));
                continue;
            }
            scan(root, needle.as_bytes(), &mut scanned);
        }
        scanned.holding.sort();
        scanned
    }

    /// Notes, for `moment`, every file that holds the variable's value or its name, and every
    /// directory or file that could not be read: a scan that skipped something proves nothing
    /// about it.
    fn note_where(&self, value: &str, moment: &str, noted: &mut Vec<String>) {
        let registry = self.tree.environment().registry_database();
        for (what, needle) in [("value", value), ("name", MARKER_NAME)] {
            let scanned = self.scan_for(needle);
            // The scan must have read the registry, the one file the variable was in before the
            // fix: a scan that did not read it says nothing about its absence there.
            if !scanned.read.contains(&registry) {
                noted.push(format!(
                    "{moment}: the scan did not read {}",
                    registry.display()
                ));
            }
            // And its write-ahead log, where there is one: that is where the variable was while a
            // session was live.
            let log = PathBuf::from(format!("{}-wal", registry.display()));
            if log.exists() && !scanned.read.contains(&log) {
                noted.push(format!("{moment}: the scan did not read {}", log.display()));
            }
            for path in scanned.holding {
                noted.push(format!(
                    "{moment}: the variable's {what} is in {}",
                    path.display()
                ));
            }
            for refusal in scanned.unreadable {
                noted.push(format!("{moment}: {refusal}"));
            }
        }
    }
}

/// What a scan found: the files that hold the needle, and what it could not look at.
#[derive(Default)]
struct Scanned {
    holding: Vec<PathBuf>,
    unreadable: Vec<String>,
    /// Every regular file whose bytes were read, which is what says the scan looked where the
    /// variable would be.
    read: Vec<PathBuf>,
}

/// Reads every regular file under `directory` and records, in `scanned`, those whose bytes contain
/// `needle`. A file that has gone since the directory was listed is not an error; anything else
/// that cannot be read is.
fn scan(directory: &Path, needle: &[u8], scanned: &mut Scanned) {
    let entries = match std::fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
        Err(error) => {
            scanned.unreadable.push(format!(
                "{} could not be listed: {error}",
                directory.display()
            ));
            return;
        }
    };
    for entry in entries {
        let path = match entry {
            Ok(entry) => entry.path(),
            Err(error) => {
                scanned.unreadable.push(format!(
                    "an entry of {} could not be listed: {error}",
                    directory.display()
                ));
                continue;
            }
        };
        let about = match std::fs::symlink_metadata(&path) {
            Ok(about) => about,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                scanned.unreadable.push(format!(
                    "{} could not be looked at: {error}",
                    path.display()
                ));
                continue;
            }
        };
        if about.is_dir() {
            scan(&path, needle, scanned);
        } else if about.is_file() {
            match std::fs::read(&path) {
                Ok(bytes) => {
                    if bytes.windows(needle.len()).any(|window| window == needle) {
                        scanned.holding.push(path.clone());
                    }
                    scanned.read.push(path);
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => scanned
                    .unreadable
                    .push(format!("{} could not be read: {error}", path.display())),
            }
        }
    }
}

/// Polls `read` until it returns something, and fails the test where the patience runs out.
async fn until<T>(what: &str, mut read: impl FnMut() -> Option<T>) -> T {
    let deadline = tokio::time::Instant::now() + PATIENCE;
    loop {
        if let Some(found) = read() {
            return found;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "nothing came of: {what}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// The session's shell has the variable the creator sent: the launch still carries it.
async fn shell_has(host: &Host, created: &SessionCreateResult, value: &str, shown: &Path) {
    let _attached = host
        .type_into(created, &format!("env > {}\n", shown.display()))
        .await;
    until("the shell writing its environment", || {
        std::fs::read_to_string(shown)
            .ok()
            .filter(|text| text.contains(&format!("{MARKER_NAME}={value}")))
    })
    .await;
}

/// The creator's variable is in none of the environment's files while the session is live, after
/// the daemon restarts, and after the session closes; the shell the worker started has it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_creators_variable_is_at_rest_nowhere_in_a_session_hosts_files() {
    let mut host = Host::start().await;
    // Where the shell writes what it sees: outside the directories this test reads, since what the
    // shell writes is the one place the variable is meant to appear.
    let outside = tempfile::tempdir().expect("a directory on the internal disk");
    let value = marker_value();
    let request = host.request(outside.path(), &value);
    let created = host.create(&request).await;
    let mut at_rest = Vec::new();

    shell_has(&host, &created, &value, &outside.path().join("shown.txt")).await;
    host.note_where(&value, "with the session live", &mut at_rest);

    host.restart().await;
    host.note_where(&value, "after the daemon restarted", &mut at_rest);

    host.close(&created).await;
    host.until_closed(&created).await;
    host.note_where(&value, "after the session closed", &mut at_rest);
    assert!(
        at_rest.is_empty(),
        "the creator's variable is at rest in: {at_rest:#?}"
    );
}

impl Drop for Host {
    /// A test that ends before it opens the gate does not leave a held worker behind: the daemon
    /// that started it may be gone, and nothing else would end it.
    fn drop(&mut self) {
        self.cancel_held_workers();
    }
}

/// A create token asked twice returns the session the first asked for, and the same token with
/// another payload is a conflict: the digest stays, and the record the daemon keeps is not what
/// either answer reads.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_repeated_create_token_returns_its_session_and_another_payload_conflicts() {
    let host = Host::start().await;
    let outside = tempfile::tempdir().expect("a directory on the internal disk");
    let value = marker_value();
    let request = host.request(outside.path(), &value);
    let action = ActionId::new(kr_ipc::new_uuid());
    let mut client = host.client().await;
    let mutation = client
        .compose(Method::SessionCreate, action, host.target(None), &request)
        .await
        .expect("composes the request");
    let first: SessionCreateResult = client
        .repeat(&mutation)
        .await
        .expect("reaches the daemon")
        .expect("the session is created")
        .to_typed()
        .expect("decodes");
    assert!(!first.deduplicated, "the first ask makes the session");

    let again: SessionCreateResult = host
        .client()
        .await
        .repeat(&mutation)
        .await
        .expect("reaches the daemon")
        .expect("the repeat is answered")
        .to_typed()
        .expect("decodes");
    assert!(again.deduplicated, "the repeat is marked as one");
    assert_eq!(
        again.session.session_id, first.session.session_id,
        "and it is the same session"
    );

    let mut other = request.clone();
    other.cwd = Nullable::some(host.tree.root().display().to_string());
    let mut conflicting = host.client().await;
    let changed = conflicting
        .compose(Method::SessionCreate, action, host.target(None), &other)
        .await
        .expect("composes the request");
    let refusal = conflicting
        .repeat(&changed)
        .await
        .expect("reaches the daemon")
        .expect_err("the same token with another payload is refused");
    assert_eq!(refusal.code, ErrorCode::IdConflict);

    host.close(&first).await;
}

/// A launch held between its reservation and its worker's claim, across a daemon restart, resolves
/// as a launch that produced no session: the worker the old daemon started claims on the new one,
/// which no longer holds the creator's variables, so it is refused and nothing starts with an empty
/// environment. The caller's own token is answered from what the host recorded.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_launch_held_across_a_restart_resolves_as_one_that_produced_no_session() {
    let mut host = Host::start_held().await;
    let outside = tempfile::tempdir().expect("a directory on the internal disk");
    let value = marker_value();
    let request = host.request(outside.path(), &value);
    let mut client = host.client().await;
    let mutation = client
        .compose(
            Method::SessionCreate,
            ActionId::new(kr_ipc::new_uuid()),
            host.target(None),
            &request,
        )
        .await
        .expect("composes the request");
    let creating = tokio::spawn({
        let mutation = mutation.clone();
        async move { client.repeat(&mutation).await }
    });

    // The launch is under way: the reservation is spawned and its launcher recorded, and the worker
    // is held at the gate, so nothing has claimed it.
    until("the reservation to be spawned with its launcher", || {
        host.reservations()
            .iter()
            .any(|(phase, launcher)| phase == "spawned" && launcher.is_some())
            .then_some(())
    })
    .await;
    host.kill_daemon();
    // The caller's connection died with the daemon.
    let _ = tokio::time::timeout(PATIENCE, creating)
        .await
        .expect("the caller's connection ends with the daemon");
    host.run().await;
    host.open_gate();

    until(
        "the held launch to be resolved as a launch that produced no session",
        || {
            host.reservations()
                .iter()
                .any(|(phase, _)| phase == "failed")
                .then_some(())
        },
    )
    .await;
    let listed: kr_protocol::session::SessionListResult = host
        .client()
        .await
        .request(
            Method::SessionList,
            &kr_protocol::session::SessionListParams {
                environment_id: Nullable::some(host.environment_id),
                include_closed: true,
            },
        )
        .await
        .expect("reaches the daemon")
        .expect("lists")
        .to_typed()
        .expect("decodes");
    assert!(
        listed.sessions.is_empty(),
        "no session was started: {:?}",
        listed.sessions
    );

    // The same token, asked again, is answered from the record and starts nothing.
    let replay = host
        .client()
        .await
        .repeat(&mutation)
        .await
        .expect("reaches the daemon");
    assert!(
        replay.is_err(),
        "a create whose launch produced no session is not answered with one: {replay:?}"
    );
    let mut at_rest = Vec::new();
    host.note_where(&value, "after the held launch was refused", &mut at_rest);
    assert!(
        at_rest.is_empty(),
        "the creator's variable is at rest in: {at_rest:#?}"
    );
}

/// A held worker that is cancelled ends without becoming a worker: a test that fails before it
/// opens the gate leaves nothing running, even when the daemon that started the worker is gone.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_held_worker_that_is_cancelled_ends_without_becoming_a_worker() {
    let mut host = Host::start_held().await;
    let outside = tempfile::tempdir().expect("a directory on the internal disk");
    let request = host.request(outside.path(), &marker_value());
    let mut client = host.client().await;
    let mutation = client
        .compose(
            Method::SessionCreate,
            ActionId::new(kr_ipc::new_uuid()),
            host.target(None),
            &request,
        )
        .await
        .expect("composes the request");
    let creating = tokio::spawn(async move { client.repeat(&mutation).await });
    let held = until("the held worker to be started", || {
        host.reservations()
            .iter()
            .find_map(|(phase, launcher)| (phase == "spawned").then_some(*launcher).flatten())
    })
    .await;
    host.kill_daemon();
    let _ = tokio::time::timeout(PATIENCE, creating)
        .await
        .expect("the caller's connection ends with the daemon");
    assert!(
        is_running(held),
        "the held worker is waiting at its gate after the daemon has gone"
    );

    host.cancel_held_workers();
    until("the held worker to end", || {
        (!is_running(held)).then_some(())
    })
    .await;
    assert_eq!(
        host.reservations(),
        vec![("spawned".to_owned(), Some(held))],
        "it ended without claiming anything: the one reservation is as the daemon left it"
    );
}

/// Whether the process is there and not a zombie waiting to be collected.
fn is_running(pid: i64) -> bool {
    let output = std::process::Command::new("ps")
        .args(["-o", "stat=", "-p", &pid.to_string()])
        .output()
        .expect("asks the process table");
    let state = String::from_utf8_lossy(&output.stdout);
    let state = state.trim();
    !state.is_empty() && !state.starts_with('Z')
}

/// The shape of a create request that a build before the launch profile recorded, as bytes the
/// current build must still read.
#[derive(serde::Serialize)]
struct EarlierCreate {
    environment_id: EnvironmentId,
    presentation: Presentation,
    shell: Nullable<String>,
    shell_mode: ShellMode,
    cwd: Nullable<String>,
    dimensions: Nullable<kr_protocol::session::Dimensions>,
    worker_profile: kr_protocol::identity::WorkerProfile,
    environment_snapshot: Vec<EnvironmentVariable>,
    palette: Nullable<kr_protocol::session::PaletteRequest>,
}

/// A registry an earlier build wrote, with the creator's variables in a reservation of each phase
/// and in the earlier shape, is rewritten when it opens: the variables are in none of the file's
/// bytes, its write-ahead log or its shared-memory file afterwards, and every record still reads
/// as a create request.
#[test]
fn a_registry_an_earlier_build_wrote_is_rewritten_when_it_opens() {
    let directory = tempfile::tempdir().expect("a directory on the internal disk");
    let environment_id = EnvironmentId::new(kr_ipc::new_uuid());
    let path = directory.path().join("registry.sqlite3");
    let actor = ActorId::new("local:test").expect("a principal");
    let phases = [
        LaunchPhase::Reserved,
        LaunchPhase::Spawned,
        LaunchPhase::Claimed,
        LaunchPhase::Live,
        LaunchPhase::Closed,
        LaunchPhase::Failed,
        LaunchPhase::Fenced,
    ];
    let current = |value: &str| SessionCreateParams {
        environment_id,
        presentation: Presentation::Terminal,
        shell: Nullable::some("zsh".to_owned()),
        shell_mode: ShellMode::Managed,
        cwd: Nullable::some("/work".to_owned()),
        dimensions: Nullable::null(),
        worker_profile: kr_protocol::identity::WorkerProfile::DesktopBound,
        environment_snapshot: vec![EnvironmentVariable {
            name: MARKER_NAME.to_owned(),
            value: value.to_owned(),
        }],
        palette: Nullable::null(),
        launch_profile: kr_protocol::session::LaunchProfile::default(),
        terminal: Nullable::null(),
    };
    let mut values = Vec::new();
    {
        let mut registry = Registry::open(&path, environment_id).expect("opens the registry");
        let mut reserve = |intent: Vec<u8>, phase: LaunchPhase| {
            let admission = registry
                .reserve(
                    &actor,
                    kr_ipc::new_uuid(),
                    Digest256::from_bytes([7; 32]),
                    &intent,
                    kr_ipc::now_ms(),
                )
                .expect("reserves");
            // Each move rewrites the row, which leaves the earlier copy of it behind.
            registry
                .set_phase(admission.reservation.reservation_id, LaunchPhase::Spawned)
                .expect("moves");
            registry
                .set_phase(admission.reservation.reservation_id, phase)
                .expect("moves");
        };
        for phase in phases {
            let value = marker_value();
            reserve(
                kr_cbor::to_canonical_vec(&current(&value)).expect("encodes"),
                phase,
            );
            values.push(value);
        }
        let value = marker_value();
        let earlier = EarlierCreate {
            environment_id,
            presentation: Presentation::Terminal,
            shell: Nullable::some("zsh".to_owned()),
            shell_mode: ShellMode::Managed,
            cwd: Nullable::some("/work".to_owned()),
            dimensions: Nullable::null(),
            worker_profile: kr_protocol::identity::WorkerProfile::DesktopBound,
            environment_snapshot: vec![EnvironmentVariable {
                name: MARKER_NAME.to_owned(),
                value: value.clone(),
            }],
            palette: Nullable::null(),
        };
        reserve(
            kr_cbor::to_canonical_vec(&earlier).expect("encodes"),
            LaunchPhase::Live,
        );
        values.push(value);
    }
    // What the previous build left: the same file, at the schema it wrote.
    rusqlite::Connection::open(&path)
        .expect("opens the file")
        .execute("UPDATE schema_version SET version = 6", [])
        .expect("labels it as the earlier build did");

    let holding = |needle: &str| {
        let mut scanned = Scanned::default();
        scan(directory.path(), needle.as_bytes(), &mut scanned);
        assert!(scanned.unreadable.is_empty(), "{:?}", scanned.unreadable);
        scanned.holding
    };
    for value in &values {
        assert!(
            !holding(value).is_empty(),
            "the earlier build's file holds {value}, which is what this test starts from"
        );
    }

    let registry = Registry::open(&path, environment_id).expect("opens the earlier registry");
    let mut decoded = 0;
    for phase in phases {
        for reservation in registry.reservations_in(phase).expect("reads") {
            let recorded = reservation
                .create_intent
                .expect("the request is still recorded");
            let create: SessionCreateParams =
                kr_cbor::from_canonical_slice(&recorded, &kr_cbor::Limits::DEFAULT)
                    .expect("the record still reads as a create request");
            assert!(
                create.environment_snapshot.is_empty(),
                "a {phase:?} reservation keeps no variables"
            );
            assert_eq!(
                create.worker_profile,
                kr_protocol::identity::WorkerProfile::DesktopBound,
                "and the rest of the request is as it was recorded"
            );
            assert_eq!(create.cwd, Nullable::some("/work".to_owned()));
            decoded += 1;
        }
    }
    assert_eq!(decoded, values.len(), "every reservation was read back");
    // While the registry is open: the file has been rebuilt and its log emptied. Closing the last
    // connection would checkpoint and remove the log, and say nothing about a daemon that keeps
    // the registry open. The log is the one write that moved the version, not a frame for each
    // page the compaction wrote.
    for value in &values {
        assert!(
            holding(value).is_empty(),
            "{value} is in {:?}, with the registry open",
            holding(value)
        );
    }
    assert!(
        holding(MARKER_NAME).is_empty(),
        "the variable's name is in {:?}, with the registry open",
        holding(MARKER_NAME)
    );
    let length =
        |name: &str| std::fs::metadata(directory.path().join(name)).map_or(0, |about| about.len());
    assert!(
        length("registry.sqlite3-wal") < length("registry.sqlite3"),
        "the log of a registry that is open is shorter than its file"
    );
    drop(registry);

    for value in &values {
        assert!(
            holding(value).is_empty(),
            "{value} is still in {:?}",
            holding(value)
        );
    }
    assert!(
        holding(MARKER_NAME).is_empty(),
        "the variable's name is still in {:?}",
        holding(MARKER_NAME)
    );
}

/// A supervisor that says it started a worker, which is this test process, and does nothing else:
/// the test itself answers the daemon's rendezvous as that worker.
#[derive(Debug, Default)]
struct ThisProcessIsTheWorker {
    launched: std::sync::Arc<std::sync::Mutex<Vec<WorkerLaunch>>>,
}

impl WorkerSupervisor for ThisProcessIsTheWorker {
    fn start(&self, launch: &WorkerLaunch) -> LaunchOutcome {
        self.launched
            .lock()
            .expect("the record is not poisoned")
            .push(launch.clone());
        LaunchOutcome::Started(
            kr_ipc::identity::current_process_start_identity().expect("this process"),
        )
    }

    fn describe(&self) -> &'static str {
        "a supervisor that starts nothing and names this test as the worker"
    }
}

/// A daemon on `temp`, in this process, serving its clients and its rendezvous.
struct InProcess {
    clients: kr_ipc::paths::Endpoint,
    rendezvous: kr_ipc::paths::Endpoint,
    launched: std::sync::Arc<std::sync::Mutex<Vec<WorkerLaunch>>>,
}

async fn rendezvous_daemon(temp: &kr_ipc::testing::TempHost) -> InProcess {
    let supervisor = ThisProcessIsTheWorker::default();
    let launched = std::sync::Arc::clone(&supervisor.launched);
    let environment = temp.environment();
    let environment_id = temp.environment_id();
    let secrets = environment.secrets_dir();
    let controller = Controller::start(ControllerSetup {
        paths: environment.clone(),
        environment_id,
        identity: Box::new(move || {
            let store = open_store_in(&secrets).expect("a secret store");
            Ok(
                ControllerIdentity::open(store.store.as_ref(), environment_id, false)
                    .expect("an identity"),
            )
        }),
        secret_store: StoreSelection::File,
        boot_identity: kr_ipc::identity::boot_identity().expect("a boot identity"),
        supervisor: Box::new(supervisor),
        worker_program: PathBuf::from("/nonexistent/kr-worker"),
        build_id: build(),
        release: "0".to_owned(),
        shell_packages: None,
        terminal: Box::new(kr_controller::supervision::NoTerminal),
    })
    .await
    .expect("the daemon starts");
    let rendezvous = environment.rendezvous_endpoint().expect("an endpoint");
    let listener = Listener::bind(&rendezvous).expect("binds the rendezvous");
    tokio::spawn(std::sync::Arc::clone(&controller).serve_rendezvous(listener));
    let clients = environment.controller_endpoint().expect("an endpoint");
    let listener = Listener::bind(&clients).expect("binds the endpoint");
    tokio::spawn(std::sync::Arc::clone(&controller).serve_clients(listener));
    InProcess {
        clients,
        rendezvous,
        launched,
    }
}

/// What the daemon sent a claiming worker back: its launch specification, or nothing.
enum Answer {
    Specification(Box<kr_protocol::worker::WorkerLaunchSpec>),
    Refused,
}

/// Claims `reservation` as the worker the daemon started, which is this process, and returns what
/// the daemon answers.
async fn claim(
    endpoint: &kr_ipc::paths::Endpoint,
    reservation: kr_protocol::worker::ReservationId,
    session_id: kr_protocol::ids::SessionId,
) -> (
    Answer,
    (kr_ipc::framed::FrameReader, kr_ipc::framed::FrameWriter),
) {
    let identity = WorkerIdentity::generate(
        session_id,
        SessionEpoch::V1,
        kr_ipc::identity::boot_identity().expect("a boot identity"),
        kr_ipc::identity::current_process_start_identity().expect("this process"),
        PROTOCOL_VERSION,
    )
    .expect("a session key");
    let connection = Connection::connect(endpoint)
        .await
        .expect("connects to the rendezvous");
    let (mut reader, mut writer) =
        kr_ipc::framed::split(connection, kr_protocol::frame::StreamKind::Control);
    writer
        .write_message(&ControlFrame::Hello(kr_protocol::local::LocalHello {
            offered_versions: vec![PROTOCOL_VERSION],
            build_id: build(),
            client: LocalClientKind::Worker,
            capabilities: kr_protocol::scalars::CanonicalSet::new(),
            max_receive: kr_protocol::hello::ReceiveLimits::default(),
        }))
        .await
        .expect("writes the hello");
    let acknowledgement: ControlFrame = reader.read_message().await.expect("the daemon answers");
    assert!(matches!(acknowledgement, ControlFrame::HelloAck(_)));
    writer
        .write_message(&ControlFrame::Rendezvous(
            identity.rendezvous(reservation).expect("a startup claim"),
        ))
        .await
        .expect("writes the startup claim");
    let answer = match reader.read_message::<ControlFrame>().await {
        Ok(ControlFrame::LaunchSpec(specification)) => Answer::Specification(specification),
        Ok(_) | Err(_) => Answer::Refused,
    };
    // The connection is handed back, so a worker that says nothing more keeps it open.
    (answer, (reader, writer))
}

/// Seeds a reservation the way a daemon that has since ended left one: recorded with `phase`, a
/// create request that names the marker, and this process as its launcher.
fn seed_reservation(
    temp: &kr_ipc::testing::TempHost,
    phase: LaunchPhase,
    value: &str,
) -> (
    kr_protocol::worker::ReservationId,
    kr_protocol::ids::SessionId,
) {
    let environment_id = temp.environment_id();
    let mut registry = Registry::open(temp.environment().registry_database(), environment_id)
        .expect("opens the registry");
    let intent = kr_cbor::to_canonical_vec(&SessionCreateParams {
        environment_id,
        presentation: Presentation::Invisible,
        shell: Nullable::some("/bin/sh".to_owned()),
        shell_mode: ShellMode::NativeCompat,
        cwd: Nullable::some("/".to_owned()),
        dimensions: Nullable::null(),
        worker_profile: kr_protocol::identity::WorkerProfile::HeadlessUser,
        environment_snapshot: vec![EnvironmentVariable {
            name: MARKER_NAME.to_owned(),
            value: value.to_owned(),
        }],
        palette: Nullable::null(),
        launch_profile: kr_protocol::session::LaunchProfile::default(),
        terminal: Nullable::null(),
    })
    .expect("encodes");
    let admission = registry
        .reserve(
            &ActorId::new("local:test").expect("a principal"),
            kr_ipc::new_uuid(),
            Digest256::from_bytes([9; 32]),
            &intent,
            kr_ipc::now_ms(),
        )
        .expect("reserves");
    let reservation = admission.reservation;
    registry
        .set_phase(reservation.reservation_id, LaunchPhase::Spawned)
        .expect("moves");
    registry
        .record_launch(
            reservation.reservation_id,
            &kr_ipc::identity::current_process_start_identity().expect("this process"),
        )
        .expect("records the launcher");
    if phase != LaunchPhase::Spawned {
        registry
            .set_phase(reservation.reservation_id, phase)
            .expect("moves");
    }
    (reservation.reservation_id, reservation.session_id)
}

/// The phase and claimed key of the one reservation `temp`'s registry holds.
fn recorded_phase(temp: &kr_ipc::testing::TempHost) -> (String, Option<Vec<u8>>) {
    let connection = rusqlite::Connection::open_with_flags(
        temp.environment().registry_database(),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .expect("opens the registry to read");
    connection
        .query_row("SELECT phase, claimed_key FROM reservations", [], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })
        .expect("reads the reservation")
}

/// A claim on a reservation whose create is gone, which is what a daemon that started after the
/// reservation was written finds, has no variables to take: it is refused and sent no launch
/// specification, its reservation is failed with no key recorded, and nothing started with an
/// empty environment.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_claim_that_finds_no_variables_is_refused_and_fails_its_reservation() {
    let temp = kr_ipc::testing::TempHost::create();
    let value = marker_value();
    let (reservation, session_id) = seed_reservation(&temp, LaunchPhase::Spawned, &value);
    let daemon = rendezvous_daemon(&temp).await;

    match claim(&daemon.rendezvous, reservation, session_id).await.0 {
        Answer::Specification(specification) => panic!(
            "a launch specification was sent for a create whose variables the daemon no longer \
             holds: {:?}",
            specification.create.environment_snapshot
        ),
        Answer::Refused => {}
    }
    let (phase, key) = recorded_phase(&temp);
    assert_eq!(
        phase, "failed",
        "the reservation is a launch that produced no session"
    );
    assert_eq!(key, None, "and no worker key was recorded for it");
}

/// A second claim on a reservation that was already claimed still fences it, whatever the daemon
/// holds: the one rule that says two processes cannot both own a session.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_second_claim_still_fences_the_reservation() {
    let temp = kr_ipc::testing::TempHost::create();
    let (reservation, session_id) = seed_reservation(&temp, LaunchPhase::Claimed, &marker_value());
    let daemon = rendezvous_daemon(&temp).await;

    match claim(&daemon.rendezvous, reservation, session_id).await.0 {
        Answer::Specification(_) => panic!("a second claim was sent a launch specification"),
        Answer::Refused => {}
    }
    let (phase, _) = recorded_phase(&temp);
    assert_eq!(phase, "fenced", "the second claim fences the reservation");
}

/// What a create waiting on a worker is told when the worker the daemon started has not reported
/// itself, and what the worker then finds.
struct Waiting {
    daemon: InProcess,
    creating: tokio::task::JoinHandle<
        kr_ipc::Result<
            std::result::Result<
                kr_protocol::envelope::ParamsValue,
                kr_protocol::error::ProtocolError,
            >,
        >,
    >,
    value: String,
}

impl Waiting {
    /// Asks the daemon for a session whose creator's environment carries the marker, and returns
    /// once the daemon has asked its supervisor for the worker.
    async fn start(temp: &kr_ipc::testing::TempHost) -> Self {
        let daemon = rendezvous_daemon(temp).await;
        let value = marker_value();
        let environment_id = temp.environment_id();
        let request = SessionCreateParams {
            environment_id,
            presentation: Presentation::Invisible,
            shell: Nullable::some("/bin/sh".to_owned()),
            shell_mode: ShellMode::NativeCompat,
            cwd: Nullable::some("/".to_owned()),
            dimensions: Nullable::null(),
            worker_profile: kr_protocol::identity::WorkerProfile::HeadlessUser,
            environment_snapshot: vec![EnvironmentVariable {
                name: MARKER_NAME.to_owned(),
                value: value.clone(),
            }],
            palette: Nullable::null(),
            launch_profile: kr_protocol::session::LaunchProfile::default(),
            terminal: Nullable::null(),
        };
        let mut client = LocalClient::connect(&daemon.clients, LocalClientKind::Cli, build())
            .await
            .expect("connects");
        let creating = tokio::spawn(async move {
            client
                .mutate(
                    Method::SessionCreate,
                    ActionId::new(kr_ipc::new_uuid()),
                    ActionTarget::environment(environment_id),
                    &request,
                )
                .await
        });
        let this = Self {
            daemon,
            creating,
            value,
        };
        until("the daemon to ask for a worker", || {
            (!this.launched().is_empty()).then_some(())
        })
        .await;
        this
    }

    fn launched(&self) -> Vec<WorkerLaunch> {
        self.daemon
            .launched
            .lock()
            .expect("the record is not poisoned")
            .clone()
    }

    /// Waits for the create's answer, which comes when the daemon stops waiting for the worker.
    async fn answer(self) -> kr_protocol::error::ProtocolError {
        tokio::time::timeout(
            kr_controller::service::RENDEZVOUS_TIMEOUT + PATIENCE,
            self.creating,
        )
        .await
        .expect("the create is answered when the daemon stops waiting")
        .expect("the create task ends")
        .expect("reaches the daemon")
        .expect_err("a worker that never reported itself leaves the create without a session")
    }
}

/// A create whose worker claimed in time and was sent its launch specification, and then said
/// nothing until the daemon stopped waiting, is told its outcome is unknown: the worker has the
/// creator's variables and may still report itself, so the caller asks again under the same token
/// and is neither told the create failed nor invited to make a second session.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_create_whose_worker_took_the_variables_and_went_quiet_is_told_the_outcome_is_unknown() {
    let temp = kr_ipc::testing::TempHost::create();
    let waiting = Waiting::start(&temp).await;
    let launch = waiting.launched().remove(0);
    let (answer, _held_open) = claim(
        &waiting.daemon.rendezvous,
        launch.reservation_id,
        launch.session_id,
    )
    .await;
    match answer {
        Answer::Specification(specification) => assert!(
            specification
                .create
                .environment_snapshot
                .iter()
                .any(|variable| variable.name == MARKER_NAME && variable.value == waiting.value),
            "the launch still carries the variables the creator sent"
        ),
        Answer::Refused => panic!("a claim made while the create waits is refused"),
    }
    let refusal = waiting.answer().await;
    assert_eq!(
        refusal.code,
        ErrorCode::OutcomeUnknown,
        "the launch may still complete: {}",
        refusal.message
    );
}

/// A create whose worker never claimed is told it has no session, and a worker that claims after
/// the daemon stopped waiting is refused: the caller was already told, and a session that starts
/// without the creator's variables, or after its caller was told there is none, is not one it
/// asked for.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_claim_after_its_create_gave_up_is_refused_and_fails_the_reservation() {
    let temp = kr_ipc::testing::TempHost::create();
    let waiting = Waiting::start(&temp).await;
    let launch = waiting.launched().remove(0);
    let daemon_endpoint = waiting.daemon.rendezvous.clone();
    let refusal = waiting.answer().await;
    assert_eq!(
        refusal.code,
        ErrorCode::ResourceUnavailable,
        "no claim took the variables, so no session can come: {}",
        refusal.message
    );

    match claim(&daemon_endpoint, launch.reservation_id, launch.session_id)
        .await
        .0
    {
        Answer::Specification(specification) => panic!(
            "a worker that claimed after its create gave up was sent a launch specification: {:?}",
            specification.create.environment_snapshot
        ),
        Answer::Refused => {}
    }
    let (phase, key) = recorded_phase(&temp);
    assert_eq!(phase, "failed");
    assert_eq!(key, None);
}
