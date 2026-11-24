//! The disclosed checks across sessions of the host agent, with real worker processes.
//!
//! KR-REQ-03.29: the checks are repeated after a host-agent update. The host agent is the worker
//! that performs the checks, and its build is the release it states to the daemon. Each session
//! has a worker process of its own, so this suite starts real ones through the daemon's own
//! `session.create`; workers that run in this process, as the other suite's do, share one
//! identity and cannot show one session's worker apart from another's. What this suite shows is
//! what does not end the findings (another session of one build) and what does (the worker that
//! made them leaving, or the daemon starting again); a worker that states a newer release is shown
//! on the daemon's own report in the controller's unit cases. Each case runs on a daemon that
//! starts its sessions as detached processes, in a tree of its own on the internal disk, and no
//! case reaches a service manager of the account.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use kr_controller::service::{Controller, ControllerSetup};
use kr_controller::supervision::{
    DetachedSupervisor, LaunchOutcome, WorkerLaunch, WorkerSupervisor,
};
use kr_crypto::store::{StoreSelection, open_store_in};
use kr_ipc::client::LocalClient;
use kr_ipc::endpoint::Listener;
use kr_ipc::testing::started_environment::StartedEnvironment;
use kr_ipc::verify::ControllerIdentity;
use kr_protocol::desktop::{
    CapabilityChecks, CapabilityChecksState, EnvironmentCapabilitiesCheckParams,
    EnvironmentCapabilitiesParams, EnvironmentCapabilitiesResult, capabilities,
};
use kr_protocol::envelope::ActionTarget;
use kr_protocol::hostinfo::configuration::{self, ConfigurationDocument};
use kr_protocol::identity::{ProcessStartIdentity, WorkerProfile};
use kr_protocol::ids::{ActionId, BuildId, EnvironmentId, SessionId};
use kr_protocol::local::LocalClientKind;
use kr_protocol::method::Method;
use kr_protocol::scalars::{Nullable, TimestampMs};
use kr_protocol::session::{Presentation, SessionCreateParams, SessionCreateResult, ShellMode};

mod teardown;

/// How long a test waits for something the daemon or a worker does on its own, which nothing here
/// times: it ends a wait that never ends.
const PATIENCE: Duration = Duration::from_secs(60);

fn build() -> BuildId {
    BuildId::new("kr-test/0").expect("a build identifier")
}

/// The worker program beside this test's own binary.
fn worker_beside_this_test() -> PathBuf {
    let mut directory = std::env::current_exe().expect("the test binary");
    directory.pop();
    if directory.file_name().is_some_and(|name| name == "deps") {
        directory.pop();
    }
    let worker = directory.join("kr-worker");
    assert!(
        worker.is_file(),
        "this test starts worker processes and there is none at {}; build it with \
         `cargo build -p kr-worker`, or run the whole workspace's tests, which build it",
        worker.display()
    );
    worker
}

/// A document that has this host create its sessions headless, whatever machine the test runs on,
/// so the sessions the test creates are the ones the checks are performed in.
fn headless() -> ConfigurationDocument {
    let mut document = ConfigurationDocument::empty();
    document.revision = 1;
    document.preferences.worker_profile = Nullable::some(WorkerProfile::HeadlessUser);
    document
}

/// One worker the daemon asked the supervisor for.
#[derive(Clone, Debug)]
struct Launched {
    session_id: SessionId,
    process: ProcessStartIdentity,
}

/// The detached-process supervisor, recording the process of each worker it starts.
#[derive(Debug)]
struct Recording {
    inner: Box<dyn WorkerSupervisor>,
    launched: Arc<Mutex<Vec<Launched>>>,
}

impl WorkerSupervisor for Recording {
    fn start(&self, launch: &WorkerLaunch) -> LaunchOutcome {
        let outcome = self.inner.start(launch);
        if let LaunchOutcome::Started(process) = &outcome {
            self.launched
                .lock()
                .expect("the record is not poisoned")
                .push(Launched {
                    session_id: launch.session_id,
                    process: process.clone(),
                });
        }
        outcome
    }

    fn describe(&self) -> &'static str {
        "the detached-process supervisor, recording what it starts"
    }
}

/// A daemon whose sessions have real workers.
struct Hosted {
    controller: Option<Arc<Controller>>,
    serving: Vec<tokio::task::JoinHandle<kr_controller::error::Result<()>>>,
    endpoint: kr_ipc::paths::Endpoint,
    environment_id: EnvironmentId,
    worker: PathBuf,
    launched: Arc<Mutex<Vec<Launched>>>,
    // Declared last: the tree ends every worker the daemon started before it goes.
    tree: teardown::Tree,
}

impl Hosted {
    /// Starts a daemon on a fresh tree, with a headless host and the worker program placed.
    async fn start() -> Self {
        let tree = teardown::Tree::create().without_service_manager();
        let environment = tree.environment();
        let path = configuration::document_path(
            environment.state_dir(),
            environment.state_root(),
            environment.environment_id(),
        );
        std::fs::create_dir_all(path.parent().expect("the state directory"))
            .expect("the state directory");
        kr_ipc::paths::write_owner_only_file(
            &path,
            configuration::contents(&headless()).as_bytes(),
        )
        .expect("the configuration document");
        let worker = tree.root().join("kr-worker");
        // On the internal disk, and started once here, where nothing is timed.
        kr_ipc::testing::place_and_start_once(&worker_beside_this_test(), &worker, &["--version"]);
        let mut hosted = Self {
            controller: None,
            serving: Vec::new(),
            endpoint: environment.controller_endpoint().expect("an endpoint"),
            environment_id: tree.environment_id(),
            worker,
            launched: Arc::default(),
            tree,
        };
        hosted.run().await;
        hosted
    }

    /// Starts the daemon on the tree, serving its clients and its workers' rendezvous.
    async fn run(&mut self) {
        let environment = self.tree.environment();
        let environment_id = self.environment_id;
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
            supervisor: Box::new(Recording {
                inner: self.tree.supervisor(Box::new(DetachedSupervisor::new())),
                launched: Arc::clone(&self.launched),
            }),
            worker_program: self.worker.clone(),
            build_id: build(),
            release: "0".to_owned(),
            shell_packages: None,
            terminal: Box::new(kr_controller::supervision::NoTerminal),
        })
        .await
        .expect("the daemon starts");
        // Its sessions run a login shell: they are given a home inside the tree, not the person's.
        controller
            .set_host_environment(StartedEnvironment::within(self.tree.root()).host_variables());
        let clients = Listener::bind(&self.endpoint).expect("binds the endpoint");
        let rendezvous = Listener::bind(&environment.rendezvous_endpoint().expect("an endpoint"))
            .expect("binds the rendezvous");
        self.serving = vec![
            tokio::spawn(Arc::clone(&controller).serve_clients(clients)),
            tokio::spawn(Arc::clone(&controller).serve_rendezvous(rendezvous)),
        ];
        self.controller = Some(controller);
    }

    /// Stops the daemon and starts another on the same tree, as a restart of the host does: every
    /// durable record stays, nothing held in memory does, and the workers go on running.
    async fn restart(&mut self) {
        for serving in self.serving.drain(..) {
            serving.abort();
            let _ = serving.await;
        }
        let controller = self.controller.take().expect("a daemon");
        let deadline = tokio::time::Instant::now() + PATIENCE;
        while Arc::strong_count(&controller) > 1 {
            assert!(
                tokio::time::Instant::now() < deadline,
                "the stopped daemon is still held in {} places",
                Arc::strong_count(&controller) - 1
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        drop(controller);
        self.run().await;
    }

    async fn client(&self) -> LocalClient {
        LocalClient::connect(&self.endpoint, LocalClientKind::Cli, build())
            .await
            .expect("connects")
    }

    /// Creates a headless session, whose worker is a process of its own, and returns it once it is
    /// live.
    async fn session(&self) -> SessionCreateResult {
        let params = SessionCreateParams {
            environment_id: self.environment_id,
            presentation: Presentation::Invisible,
            shell: Nullable::some("/bin/sh".to_owned()),
            shell_mode: ShellMode::NativeCompat,
            cwd: Nullable::some(self.tree.root().display().to_string()),
            dimensions: Nullable::null(),
            worker_profile: WorkerProfile::HeadlessUser,
            environment_snapshot: Vec::new(),
            palette: Nullable::null(),
            launch_profile: kr_protocol::session::LaunchProfile::default(),
            terminal: Nullable::null(),
        };
        let mut client = self.client().await;
        let created = client.mutate(
            Method::SessionCreate,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(self.environment_id),
            &params,
        );
        tokio::time::timeout(PATIENCE, created)
            .await
            .expect("the daemon creates the session in time")
            .expect("reaches the daemon")
            .expect("the session is created")
            .to_typed()
            .expect("decodes")
    }

    /// Closes a session made by [`Self::session`], whose worker then leaves the host.
    async fn close(&self, created: &SessionCreateResult) {
        let session = &created.session;
        let params = kr_protocol::session::SessionCloseParams {
            session_id: session.session_id,
        };
        let target = ActionTarget {
            environment_id: self.environment_id,
            session_id: Nullable::some(session.session_id),
            session_epoch: Nullable::some(session.session_epoch),
            application_instance_id: Nullable::null(),
            agent_binding_revision: Nullable::null(),
        };
        let mut client = self.client().await;
        let closed = client.mutate(
            Method::SessionClose,
            ActionId::new(kr_ipc::new_uuid()),
            target,
            &params,
        );
        let _: kr_protocol::session::SessionCloseResult = tokio::time::timeout(PATIENCE, closed)
            .await
            .expect("the daemon closes the session in time")
            .expect("reaches the daemon")
            .expect("closes")
            .to_typed()
            .expect("decodes");
    }

    /// The process the daemon started for `session_id`'s worker.
    fn process_of(&self, session_id: SessionId) -> ProcessStartIdentity {
        self.launched
            .lock()
            .expect("the record is not poisoned")
            .iter()
            .find(|launched| launched.session_id == session_id)
            .map(|launched| launched.process.clone())
            .expect("the daemon started a worker for the session")
    }

    /// Asks for the checks at the daemon's own socket, naming `file`.
    async fn ask(&self, file: &Path) -> CapabilityChecks {
        let params = EnvironmentCapabilitiesCheckParams {
            environment_id: self.environment_id,
            authorised_file: Nullable::some(file.display().to_string()),
        };
        let mut client = self.client().await;
        let asked = client.mutate(
            Method::EnvironmentCapabilitiesCheck,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(self.environment_id),
            &params,
        );
        tokio::time::timeout(PATIENCE, asked)
            .await
            .expect("the daemon answers the request for the checks in time")
            .expect("reaches the daemon")
            .expect("the checks are asked for")
            .to_typed()
            .expect("decodes")
    }

    /// What `environment.capabilities` shows at the daemon's own socket.
    async fn shown(&self) -> EnvironmentCapabilitiesResult {
        let read = async {
            self.client()
                .await
                .request(
                    Method::EnvironmentCapabilities,
                    &EnvironmentCapabilitiesParams {
                        environment_id: self.environment_id,
                    },
                )
                .await
                .expect("the call reaches the daemon")
                .expect("environment.capabilities succeeds")
                .to_typed()
                .expect("decodes")
        };
        tokio::time::timeout(PATIENCE, read)
            .await
            .expect("the daemon shows the capabilities in time")
    }

    /// Reads until the checks stand as `Current` and have finished a run later than `after`, or
    /// until `PATIENCE` has passed, and then says what the last read showed.
    async fn until_current_after(
        &self,
        after: Option<TimestampMs>,
    ) -> EnvironmentCapabilitiesResult {
        let deadline = tokio::time::Instant::now() + PATIENCE;
        loop {
            let answer = self.shown().await;
            let later = after.is_none_or(|after| {
                answer
                    .checks
                    .finished_at_ms
                    .as_ref()
                    .is_some_and(|finished| *finished > after)
            });
            if answer.checks.state == CapabilityChecksState::Current && later {
                return answer;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "no run finished after {after:?}; the last read showed {:?}",
                answer.checks
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// Reads until the checks stand as `state`, or until `PATIENCE` has passed, and then says what
    /// the last read showed.
    async fn until(&self, state: CapabilityChecksState) -> EnvironmentCapabilitiesResult {
        let deadline = tokio::time::Instant::now() + PATIENCE;
        loop {
            let answer = self.shown().await;
            if answer.checks.state == state {
                return answer;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "the checks did not come to {state:?}; the last read showed {:?}",
                answer.checks
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// Ends the daemon's tasks. The tree then ends the workers.
    fn stop(self) {
        for serving in &self.serving {
            serving.abort();
        }
    }
}

/// KR-REQ-03.29: checks performed in a host agent that has left the host are not current, and the
/// run asked for after the update is performed by the host agent that remains.
///
/// The first session's worker performs the checks. The updated host agent's worker then serves and
/// the first worker is retired by closing its session, which takes it out of the host. What it
/// found is about a worker that is gone, so it reads as stale and its finding is not served, and
/// the repeat is performed by the remaining worker.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_03_29_findings_of_a_host_agent_that_has_left_are_stale_and_the_repeat_is_in_the_one_that_remains()
 {
    let host = Hosted::start().await;
    let directory = tempfile::tempdir().expect("a directory of this test's own");
    let file = directory.path().join("authorised.txt");
    std::fs::write(&file, b"the person nominated this").expect("the test's file");

    let earlier = host.session().await;
    host.ask(&file).await;
    let first = host.until_current_after(None).await;
    assert_eq!(
        first.checks.session_id.as_ref(),
        Some(&earlier.session.session_id)
    );
    let finished = first
        .checks
        .finished_at_ms
        .0
        .expect("a finished run says when");

    let later = host.session().await;
    host.close(&earlier).await;

    let stale = host.until(CapabilityChecksState::Stale).await;
    assert!(
        stale
            .desktop
            .record(capabilities::AUTHORISED_FILE_READ)
            .is_none(),
        "the finding of the worker that has left is not served: {:?}",
        stale.desktop.record(capabilities::AUTHORISED_FILE_READ)
    );

    host.ask(&file).await;
    let repeated = host.until_current_after(Some(finished)).await;
    assert_eq!(
        repeated
            .desktop
            .record(capabilities::AUTHORISED_FILE_READ)
            .and_then(|record| record.subject.session_id.as_ref()),
        Some(&later.session.session_id),
        "the finding names the session of the worker that performed the repeat"
    );

    host.stop();
}

/// KR-REQ-03.29: a second session of the same build is not a host-agent update, so the findings
/// the first session's worker made stay current while it serves.
///
/// Each session has a worker process of its own, so a new session adds a newer process of the same
/// program. The findings are about the program's permissions on this desktop, and starting another
/// session does not ask the person to repeat them.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_03_29_findings_stay_current_when_another_session_of_the_same_build_starts() {
    let host = Hosted::start().await;
    let directory = tempfile::tempdir().expect("a directory of this test's own");
    let file = directory.path().join("authorised.txt");
    std::fs::write(&file, b"the person nominated this").expect("the test's file");

    let first = host.session().await.session.session_id;
    host.ask(&file).await;
    let done = host.until_current_after(None).await;

    let second = host.session().await.session.session_id;
    assert_ne!(
        host.process_of(first),
        host.process_of(second),
        "a second session has a worker process of its own"
    );

    let shown = host.shown().await;
    assert_eq!(
        shown.checks, done.checks,
        "another session of the same build ends nothing"
    );
    assert_eq!(
        shown
            .desktop
            .record(capabilities::AUTHORISED_FILE_READ)
            .and_then(|record| record.subject.session_id.as_ref()),
        Some(&first),
        "the finding still names the session whose worker made it"
    );

    host.stop();
}

/// KR-REQ-03.29: a release update reaches the daemon as a restart, and what it found before is not
/// kept across it: the checks read as not run, and the repeat the owner asks for is performed
/// again, in the worker that still serves.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_03_29_findings_do_not_outlive_a_restart_of_the_daemon_and_the_repeat_is_performed_again()
 {
    let mut host = Hosted::start().await;
    let directory = tempfile::tempdir().expect("a directory of this test's own");
    let file = directory.path().join("authorised.txt");
    std::fs::write(&file, b"the person nominated this").expect("the test's file");

    let session = host.session().await.session.session_id;
    host.ask(&file).await;
    let before = host.until_current_after(None).await;
    let finished = before
        .checks
        .finished_at_ms
        .0
        .expect("a finished run says when");

    host.restart().await;
    let restarted = host.shown().await;
    assert_eq!(
        restarted.checks.state,
        CapabilityChecksState::NotRun,
        "a daemon that starts again has asked nothing: {:?}",
        restarted.checks
    );
    assert!(
        restarted
            .desktop
            .record(capabilities::AUTHORISED_FILE_READ)
            .is_none(),
        "the finding is not kept across the restart"
    );

    // The daemon meets the worker again as it starts, and a run is asked for once it has.
    let deadline = tokio::time::Instant::now() + PATIENCE;
    loop {
        if host.ask(&file).await.state != CapabilityChecksState::Failed {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the daemon never reached the worker again"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let repeated = host.until_current_after(None).await;
    assert!(
        repeated
            .checks
            .finished_at_ms
            .as_ref()
            .is_some_and(|again| *again > finished),
        "the repeat is a run of its own"
    );
    assert_eq!(
        repeated
            .desktop
            .record(capabilities::AUTHORISED_FILE_READ)
            .and_then(|record| record.subject.session_id.as_ref()),
        Some(&session),
        "the finding names the worker that performed the repeat"
    );

    host.stop();
}
