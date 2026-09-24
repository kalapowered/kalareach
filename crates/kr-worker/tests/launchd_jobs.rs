//! A worker's launchd job goes when its worker does.
//!
//! On macOS a worker runs as a launchd job of its own, and launchd keeps a job loaded after its
//! process has exited until something removes it. Each test here starts real workers through the
//! platform's own supervisor and asks launchd itself what it still has loaded: after a session is
//! closed, after a worker is ended outright, after a launch that could not say what it started, and
//! after a daemon starts on a host where one worker ended while no daemon was running and another
//! is still running.
//!
//! Every path these tests use is on the internal disk: the worker is copied there before it is
//! started, and every session runs in the test's own tree. The one process a test ends itself is a
//! worker whose job its own daemon defined, and launchd ends it, by the job's label: no process is
//! signalled by a number.

#![cfg(target_os = "macos")]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use kr_controller::service::{Controller, ControllerSetup};
use kr_controller::supervision::{
    LaunchOutcome, LaunchdSupervisor, ServiceLaunch, WorkerSupervisor,
};
use kr_crypto::store::{StoreSelection, open_store_in};
use kr_ipc::client::LocalClient;
use kr_ipc::endpoint::Listener;
use kr_ipc::identity::{ProcessState, process_state};
use kr_ipc::verify::ControllerIdentity;
use kr_protocol::envelope::ActionTarget;
use kr_protocol::identity::{ProcessStartIdentity, ProcessStartSource, WorkerProfile};
use kr_protocol::ids::{ActionId, BuildId, EnvironmentId, SessionEpoch, SessionId};
use kr_protocol::local::LocalClientKind;
use kr_protocol::method::Method;
use kr_protocol::scalars::{Nullable, Uuid};
use kr_protocol::session::{
    ClosureReason, EnvironmentVariable, LaunchProfile, Presentation, SessionCloseParams,
    SessionCloseResult, SessionCreateParams, SessionCreateResult, SessionReadParams,
    SessionReadResult, SessionState, ShellMode,
};
use kr_protocol::worker::ReservationId;

#[path = "../../kr-controller/tests/teardown/mod.rs"]
mod teardown;

/// How long something that has to happen is given. A liveness bound rather than a measurement,
/// as in the host suite: it fails when something never happens, and a loaded machine that takes a
/// while is slow rather than broken.
const LIVENESS_DEADLINE: Duration = Duration::from_secs(120);

/// How long a replacement daemon is given to take the environment over from the one before it.
const ENVIRONMENT_HANDOVER_DEADLINE: Duration = Duration::from_secs(120);

/// What `launchctl print` exits with for a domain that is not there.
const NO_SUCH_DOMAIN: i32 = 112;

/// What `launchctl print` exits with for a job the domain does not have.
const NOT_LOADED: i32 = 113;

/// A host tree on the internal disk, with the worker beside it.
struct Host {
    /// The tree, which ends whatever its daemon started, and removes that daemon's jobs, however
    /// a test ends.
    temp: teardown::Tree,
    worker: PathBuf,
    environment_id: EnvironmentId,
}

/// A daemon serving this host, and the tasks serving for it.
struct RunningDaemon {
    controller: Arc<Controller>,
    serving: Vec<tokio::task::JoinHandle<kr_controller::Result<()>>>,
}

impl RunningDaemon {
    /// Ends this daemon the way its process exiting would: nothing it would have done afterwards
    /// happens.
    async fn stop(self) {
        for task in &self.serving {
            task.abort();
        }
        for task in self.serving {
            let _ = task.await;
        }
        drop(self.controller);
    }
}

impl Host {
    fn create() -> Self {
        let temp = teardown::Tree::create();
        let environment_id = temp.environment_id();
        // Copied to the internal disk before it is started: a process launchd starts is its own
        // identity to the operating system, and one that reached a removable volume would ask the
        // person at the machine for permission. The copy is started once here, where nothing is
        // timed, so the operating system's check of a new executable is not paid inside a
        // create's rendezvous.
        let worker = temp.root().join("kr-worker");
        kr_ipc::testing::place_and_start_once(
            Path::new(env!("CARGO_BIN_EXE_kr-worker")),
            &worker,
            &["--version"],
        );
        Self {
            temp,
            worker,
            environment_id,
        }
    }

    fn paths(&self) -> kr_ipc::paths::EnvironmentPaths {
        self.temp.environment()
    }

    /// Starts a daemon that starts its workers through launchd, as this platform's host does.
    async fn start(&self) -> RunningDaemon {
        self.start_with(|| Box::new(LaunchdSupervisor::new())).await
    }

    /// Starts a daemon that starts its workers through the supervisor `supervisor` makes.
    async fn start_with(
        &self,
        supervisor: impl Fn() -> Box<dyn WorkerSupervisor>,
    ) -> RunningDaemon {
        assert!(
            LaunchdSupervisor::available(),
            "this user has no graphical launchd domain on this host, so a worker is not started as \
             a launchd job here and these checks have nothing to look at"
        );
        let environment = self.paths();
        let environment_id = self.environment_id;
        let started = Instant::now();
        let controller = loop {
            let secrets = environment.secrets_dir();
            let outcome = Controller::start(ControllerSetup {
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
                supervisor: self.temp.supervisor(supervisor()),
                worker_program: self.worker.clone(),
                build_id: build(),
                release: "0".to_owned(),
                shell_packages: None,
                terminal: Box::new(kr_controller::supervision::NoTerminal),
            })
            .await;
            match outcome {
                Ok(controller) => break controller,
                // The daemon this one replaces has not let go of the environment yet.
                Err(kr_controller::ControllerError::AlreadyRunning { .. })
                    if started.elapsed() < ENVIRONMENT_HANDOVER_DEADLINE => {}
                Err(error) => panic!(
                    "the daemon did not start in {:.1?}: {error}",
                    started.elapsed()
                ),
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        };
        let rendezvous = Listener::bind(&environment.rendezvous_endpoint().expect("an endpoint"))
            .expect("binds the rendezvous");
        let clients = Listener::bind(&environment.controller_endpoint().expect("an endpoint"))
            .expect("binds the client endpoint");
        let serving = vec![
            tokio::spawn(Arc::clone(&controller).serve_rendezvous(rendezvous)),
            tokio::spawn(Arc::clone(&controller).serve_clients(clients)),
        ];
        RunningDaemon {
            controller,
            serving,
        }
    }

    async fn client(&self) -> LocalClient {
        LocalClient::connect(
            &self.paths().controller_endpoint().expect("an endpoint"),
            LocalClientKind::Cli,
            build(),
        )
        .await
        .expect("connects to the daemon")
    }

    /// Creates a session whose shell waits, in the given execution context.
    async fn new_session(&self, client: &mut LocalClient, profile: WorkerProfile) -> SessionId {
        let params = SessionCreateParams {
            environment_id: self.environment_id,
            presentation: Presentation::Invisible,
            shell: Nullable::some(kr_worker::testing::posix_shell()),
            shell_mode: ShellMode::NativeCompat,
            cwd: Nullable::some(self.temp.root().display().to_string()),
            dimensions: Nullable::null(),
            worker_profile: profile,
            palette: Nullable::null(),
            environment_snapshot: vec![EnvironmentVariable {
                name: "PATH".to_owned(),
                value: "/usr/bin:/bin".to_owned(),
            }],
            launch_profile: LaunchProfile::default(),
            terminal: Nullable::null(),
        };
        let created: SessionCreateResult = client
            .mutate(
                Method::SessionCreate,
                ActionId::new(kr_ipc::new_uuid()),
                ActionTarget::environment(self.environment_id),
                &params,
            )
            .await
            .expect("the call reaches the daemon")
            .map(|value| value.to_typed().expect("decodes"))
            .unwrap_or_else(|error| panic!("the create failed: {error}"));
        assert_eq!(created.session.state, SessionState::Live);
        created.session.session_id
    }

    /// Asks the daemon to close a session, which it accepts before the worker has ended.
    async fn close(&self, client: &mut LocalClient, session_id: SessionId) {
        let _: SessionCloseResult = client
            .mutate(
                Method::SessionClose,
                ActionId::new(kr_ipc::new_uuid()),
                ActionTarget {
                    environment_id: self.environment_id,
                    session_id: Nullable::some(session_id),
                    session_epoch: Nullable::some(SessionEpoch::V1),
                    application_instance_id: Nullable::null(),
                    agent_binding_revision: Nullable::null(),
                },
                &SessionCloseParams { session_id },
            )
            .await
            .expect("the call reaches the daemon")
            .map(|value| value.to_typed().expect("decodes"))
            .unwrap_or_else(|error| panic!("the close failed: {error}"));
    }

    /// Reads a session through the daemon, which is also how a daemon comes to look at a worker
    /// it can no longer reach.
    async fn read(&self, client: &mut LocalClient, session_id: SessionId) -> SessionReadResult {
        client
            .request(Method::SessionRead, &SessionReadParams { session_id })
            .await
            .expect("the call reaches the daemon")
            .map(|value| value.to_typed().expect("decodes"))
            .unwrap_or_else(|error| panic!("the read failed: {error}"))
    }

    /// Reads a session until the daemon reports it closed, and returns how it says it ended.
    async fn until_closed(&self, client: &mut LocalClient, session_id: SessionId) -> ClosureReason {
        let started = Instant::now();
        loop {
            let read = self.read(client, session_id).await;
            if read.session.state == SessionState::Closed {
                return read
                    .session
                    .closure
                    .0
                    .expect("a closed session carries its closure")
                    .reason;
            }
            assert!(
                started.elapsed() < LIVENESS_DEADLINE,
                "session {session_id} was not closed {:?} later",
                started.elapsed()
            );
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }

    /// The reservation a session was created under, from the daemon's registry, read through a
    /// connection that cannot write.
    fn reservation(&self, session_id: SessionId) -> (ReservationId, Option<ProcessStartIdentity>) {
        let connection = rusqlite::Connection::open_with_flags(
            self.paths().registry_database(),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .expect("opens the registry to read");
        connection
            .busy_timeout(Duration::from_secs(5))
            .expect("waits for a writer");
        let (reservation, pid, source, start): (Vec<u8>, Option<i64>, Option<String>, Option<i64>) =
            connection
                .query_row(
                    "SELECT reservation_id, launcher_pid, launcher_source, launcher_start
                     FROM reservations WHERE session_id = ?1",
                    [session_id.get().as_bytes().as_slice()],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .expect("the session has a reservation");
        let reservation_id = ReservationId::new(Uuid::from_bytes(
            reservation
                .try_into()
                .expect("a reservation is sixteen bytes"),
        ));
        let launched = match (pid, source, start) {
            (Some(pid), Some(source), Some(start)) => {
                let source: ProcessStartSource =
                    serde_json::from_value(serde_json::Value::String(source))
                        .expect("a source this build knows");
                Some(ProcessStartIdentity::new(
                    u64::try_from(pid).expect("a process identifier"),
                    source,
                    u64::try_from(start).expect("a start time"),
                ))
            }
            _ => None,
        };
        (reservation_id, launched)
    }

    /// The label of the job the worker of a session was started as.
    fn job_of(&self, session_id: SessionId) -> String {
        label(self.reservation(session_id).0)
    }

    /// The process the worker of a session is.
    fn worker_of(&self, session_id: SessionId) -> ProcessStartIdentity {
        self.reservation(session_id)
            .1
            .expect("the launch recorded its process")
    }

    /// Where this environment keeps the definition of the job labelled `label`.
    fn definition(&self, label: &str) -> PathBuf {
        self.paths().jobs_dir().join(format!("{label}.plist"))
    }

    /// Waits until launchd has the job labelled `label` loaded in neither of this user's domains
    /// and its definition has gone. The definition goes last, once launchd has said the job has.
    async fn until_retired(&self, label: &str, what: &str) {
        let started = Instant::now();
        loop {
            let still = loaded(label);
            let defined = self.definition(label).exists();
            if still.is_empty() && !defined {
                return;
            }
            assert!(
                started.elapsed() < LIVENESS_DEADLINE,
                "{what}: {:?} later launchd still has {still:?} loaded, and the definition is {}",
                started.elapsed(),
                if defined { "still there" } else { "gone" }
            );
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }
}

fn build() -> BuildId {
    BuildId::new("kr-test/0").expect("a build identifier")
}

/// The label a worker started for `reservation_id` runs under, spelt as the host spells it.
fn label(reservation_id: ReservationId) -> String {
    format!("kr-worker-{reservation_id}")
}

/// The domain a worker of `profile` is started in: the graphical login for a desktop-bound
/// worker, and the background for a headless one.
fn domain(profile: WorkerProfile) -> String {
    let uid = kr_ipc::paths::current_uid();
    match profile {
        WorkerProfile::DesktopBound => format!("gui/{uid}"),
        WorkerProfile::HeadlessUser => format!("user/{uid}"),
    }
}

/// Every one of this user's domains that has `label` loaded, as `<domain>/<label>`.
fn loaded(label: &str) -> Vec<String> {
    let uid = kr_ipc::paths::current_uid();
    let mut found = Vec::new();
    for domain in [format!("gui/{uid}"), format!("user/{uid}")] {
        let target = format!("{domain}/{label}");
        let status = std::process::Command::new("/bin/launchctl")
            .args(["print", &target])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .expect("runs launchctl");
        match status.code() {
            Some(0) => found.push(target),
            Some(NO_SUCH_DOMAIN | NOT_LOADED) => {}
            _ => panic!("launchctl could not say whether {target} is loaded: {status}"),
        }
    }
    found
}

/// Whether launchd describes `target` as loaded with a process running in it.
fn has_process(target: &str) -> bool {
    let printed = std::process::Command::new("/bin/launchctl")
        .args(["print", target])
        .output()
        .expect("runs launchctl");
    assert!(
        printed.status.success(),
        "launchd does not have {target} loaded"
    );
    String::from_utf8_lossy(&printed.stdout)
        .lines()
        .any(|line| line.starts_with("\tpid = "))
}

/// Waits until the kernel says a process has ended.
async fn until_ended(identity: &ProcessStartIdentity, what: &str) {
    let started = Instant::now();
    while process_state(identity) != ProcessState::Ended {
        assert!(
            started.elapsed() < LIVENESS_DEADLINE,
            "{what} was still running {:?} later",
            started.elapsed()
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Starts each worker's job through launchd as this host does, with the system's own shell in place
/// of a worker, waiting until the test creates `release`, and then says it cannot tell whether
/// anything started, which is what a launch answers when its kickstart failed part way. The labels
/// it started are kept for the test.
#[derive(Debug)]
struct NamesNoProcess {
    started: Arc<std::sync::Mutex<Vec<String>>>,
    release: PathBuf,
}

impl WorkerSupervisor for NamesNoProcess {
    fn start(&self, launch: &kr_controller::supervision::WorkerLaunch) -> LaunchOutcome {
        let mut service = launch.service();
        service.program = PathBuf::from("/bin/sh");
        service.arguments = vec![
            "-c".to_owned(),
            "while [ ! -e \"$0\" ]; do sleep 0.1; done".to_owned(),
            self.release.display().to_string(),
        ];
        let outcome = LaunchdSupervisor::new().start_service(&service);
        self.started
            .lock()
            .expect("the list of started jobs is not poisoned")
            .push(service.label);
        match outcome {
            LaunchOutcome::NotStarted { detail } => LaunchOutcome::NotStarted { detail },
            LaunchOutcome::Started(_) | LaunchOutcome::Uncertain { .. } => {
                LaunchOutcome::Uncertain {
                    detail: "the launch could not say what it started".to_owned(),
                    pid: None,
                }
            }
        }
    }

    fn describe(&self) -> &'static str {
        "launchd, naming no process for what it starts"
    }
}

/// A closed session leaves no job loaded, in either domain a worker is started in, and the job's
/// definition goes with it while what the worker wrote to its diagnostics stays.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_closed_session_leaves_no_loaded_job() {
    let host = Host::create();
    let daemon = host.start().await;
    let mut client = host.client().await;

    for profile in [WorkerProfile::HeadlessUser, WorkerProfile::DesktopBound] {
        let session_id = host.new_session(&mut client, profile).await;
        let job = host.job_of(session_id);
        assert_eq!(
            loaded(&job),
            vec![format!("{}/{job}", domain(profile))],
            "the worker of a live {profile:?} session is a job in its own domain"
        );
        host.close(&mut client, session_id).await;
        assert_eq!(
            host.until_closed(&mut client, session_id).await,
            ClosureReason::CloseRequested
        );
        host.until_retired(&job, "the job of a closed session, and its definition")
            .await;
        assert!(
            host.paths()
                .jobs_dir()
                .join(format!("{job}.diagnostics"))
                .exists(),
            "and the diagnostics the worker's job wrote stay"
        );
    }

    daemon.stop().await;
}

/// A worker ended outright has its job removed once the daemon finds it gone.
///
/// The worker is ended by launchd, through the label of the job this test's daemon defined, which
/// reaches exactly the process launchd started for it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_worker_ended_outright_has_its_job_removed() {
    let host = Host::create();
    let daemon = host.start().await;
    let mut client = host.client().await;
    let session_id = host
        .new_session(&mut client, WorkerProfile::HeadlessUser)
        .await;
    let job = host.job_of(session_id);
    let worker = host.worker_of(session_id);
    let target = format!("{}/{job}", domain(WorkerProfile::HeadlessUser));
    assert_eq!(loaded(&job), vec![target.clone()]);

    let killed = std::process::Command::new("/bin/launchctl")
        .args(["kill", "SIGKILL", &target])
        .output()
        .expect("runs launchctl");
    assert!(
        killed.status.success(),
        "launchd ends the worker of its own job: {}",
        String::from_utf8_lossy(&killed.stderr)
    );
    until_ended(&worker, "the worker launchd was told to end").await;

    // Asking about the session is what brings the daemon to look at a worker it can no longer
    // reach, and a worker the kernel says is gone is recorded as having crashed.
    assert_eq!(
        host.until_closed(&mut client, session_id).await,
        ClosureReason::WorkerCrash
    );
    host.until_retired(&job, "the job of a worker that was ended outright")
        .await;

    daemon.stop().await;
}

/// A launch that could not say what it started still has its job removed, once the process in it
/// has ended: the job is asked about until launchd lets it go, not once, and while its process runs
/// it is left alone.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_launch_that_named_no_process_has_its_job_removed_once_it_ends() {
    let host = Host::create();
    let started = Arc::new(std::sync::Mutex::new(Vec::new()));
    let release = host.temp.root().join("release");
    let daemon = host
        .start_with(|| {
            Box::new(NamesNoProcess {
                started: Arc::clone(&started),
                release: release.clone(),
            })
        })
        .await;
    let mut client = host.client().await;
    let params = SessionCreateParams {
        environment_id: host.environment_id,
        presentation: Presentation::Invisible,
        shell: Nullable::some(kr_worker::testing::posix_shell()),
        shell_mode: ShellMode::NativeCompat,
        cwd: Nullable::some(host.temp.root().display().to_string()),
        dimensions: Nullable::null(),
        worker_profile: WorkerProfile::HeadlessUser,
        palette: Nullable::null(),
        environment_snapshot: Vec::new(),
        launch_profile: LaunchProfile::default(),
        terminal: Nullable::null(),
    };
    let refused = client
        .mutate(
            Method::SessionCreate,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(host.environment_id),
            &params,
        )
        .await
        .expect("the call reaches the daemon");
    assert!(
        refused.is_err(),
        "a launch that could not say what it started fails the create: {refused:?}"
    );
    let job = started
        .lock()
        .expect("the list of started jobs is not poisoned")
        .first()
        .cloned()
        .expect("the supervisor started a job");
    let target = format!("gui/{}/{job}", kr_ipc::paths::current_uid());
    assert!(
        has_process(&target),
        "the job's process runs until this test lets it end"
    );
    // A moment in which the daemon has looked at the job and found its process running.
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert_eq!(
        loaded(&job),
        vec![target.clone()],
        "a job whose process still runs is left loaded"
    );
    assert!(has_process(&target), "and its process was not ended");

    std::fs::write(&release, b"").expect("lets the job's process end");
    host.until_retired(&job, "the job of a launch that named no process")
        .await;

    // A restart settles the launch the daemon could not: no process was recorded for it, so it is
    // resolved as failed and stops occupying the environment.
    drop(client);
    daemon.stop().await;
    host.start().await.stop().await;
}

/// A daemon that starts removes the job of every worker that has ended, and leaves the job of a
/// worker that is still running exactly as it is.
///
/// Two jobs have ended with no daemon running to see it. One is a session's, whose worker was asked
/// through its own endpoint to close while no daemon ran and ended itself. The other is a job this
/// environment defined whose registry names no session at all, which only the start's own look at
/// every job it has defined can find. Both are gone by the time the new daemon serves, and the live
/// session keeps its job, its worker and its answer.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_starting_host_removes_ended_jobs_and_leaves_live_ones() {
    let host = Host::create();
    let first = host.start().await;
    let mut client = host.client().await;
    let live = host
        .new_session(&mut client, WorkerProfile::HeadlessUser)
        .await;
    let closed = host
        .new_session(&mut client, WorkerProfile::HeadlessUser)
        .await;
    let live_job = host.job_of(live);
    let live_worker = host.worker_of(live);
    let closed_job = host.job_of(closed);
    let closed_worker = host.worker_of(closed);

    drop(client);
    first.stop().await;

    // With no daemon running, one worker is asked to close its session through its own endpoint,
    // and ends itself. Nothing is left running to see it go, so its job stays loaded.
    let descriptor = kr_ipc::descriptor::read_all(&host.paths())
        .expect("the descriptors are readable")
        .into_iter()
        .filter_map(|entry| entry.descriptor.ok())
        .find(|descriptor| descriptor.session_id == closed)
        .expect("the session's worker published its descriptor");
    assert!(
        teardown::ask_one_to_close(descriptor, host.environment_id)
            .await
            .is_some(),
        "the worker accepts the close through its own endpoint"
    );
    until_ended(&closed_worker, "the worker of the closed session").await;
    assert_eq!(
        loaded(&closed_job),
        vec![format!(
            "{}/{closed_job}",
            domain(WorkerProfile::HeadlessUser)
        )],
        "with no daemon running, the ended worker's job is still loaded"
    );

    // A job this environment defined for a worker that has ended, which no registry row names.
    let orphan = label(ReservationId::new(kr_ipc::new_uuid()));
    let planted = LaunchdSupervisor::new().start_service(&ServiceLaunch {
        label: orphan.clone(),
        // The system's own program that ends at once, from the system's own volume.
        program: PathBuf::from("/usr/bin/true"),
        arguments: Vec::new(),
        jobs_directory: host.paths().jobs_dir(),
        working_directory: host.temp.root().to_path_buf(),
    });
    assert!(
        !matches!(planted, LaunchOutcome::NotStarted { .. }),
        "the job was started: {planted:?}"
    );
    let orphan_target = format!("gui/{}/{orphan}", kr_ipc::paths::current_uid());
    let started = Instant::now();
    while has_process(&orphan_target) {
        assert!(
            started.elapsed() < LIVENESS_DEADLINE,
            "the planted job's process did not end"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(loaded(&orphan), vec![orphan_target.clone()]);

    let second = host.start().await;
    assert!(
        loaded(&orphan).is_empty() && loaded(&closed_job).is_empty(),
        "the jobs of workers that ended while no daemon ran are gone before the daemon serves: \
         {:?} {:?}",
        loaded(&orphan),
        loaded(&closed_job)
    );
    assert!(!host.definition(&orphan).exists());
    assert!(!host.definition(&closed_job).exists());
    assert_eq!(
        loaded(&live_job),
        vec![format!(
            "{}/{live_job}",
            domain(WorkerProfile::HeadlessUser)
        )],
        "the live session's job is still loaded"
    );
    assert!(host.definition(&live_job).exists());
    assert_eq!(
        process_state(&live_worker),
        ProcessState::Running,
        "and its worker is still running"
    );
    let mut client = host.client().await;
    assert_eq!(
        host.read(&mut client, live).await.session.state,
        SessionState::Live,
        "and the session still answers through the new daemon"
    );

    // Closed through the new daemon, the live session's job goes as any other does.
    host.close(&mut client, live).await;
    host.until_closed(&mut client, live).await;
    host.until_retired(&live_job, "the job of a session closed after a restart")
        .await;

    drop(client);
    second.stop().await;
}
