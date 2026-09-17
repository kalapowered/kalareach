//! The whole host path, with real processes.
//!
//! A control daemon, a worker it started, a real shell in a real pseudo-terminal, and the things
//! the specification says must survive: a daemon that restarts while the shell is producing
//! output, a session limit that refuses before anything is spawned, and a create token that is
//! retried.
//!
//! Every path these tests use is on the internal disk: the worker is copied there before it is
//! started, and the host gives it a working directory of its own there rather than letting it
//! inherit this process's. A process a service manager launches is its own identity to the
//! operating system, and one that reaches a removable volume asks the person sitting at the
//! machine for permission; a test suite must never do that, so every create checks what the
//! kernel actually gave the process it started.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use kr_controller::registry::Registry;
use kr_controller::service::{Controller, ControllerSetup};
use kr_controller::supervision::DetachedSupervisor;
use kr_crypto::store::open_store;
use kr_ipc::client::LocalClient;
use kr_ipc::endpoint::Listener;
use kr_ipc::verify::{CONTROLLER_SECRET_SERVICE, ControllerIdentity};
use kr_protocol::envelope::ActionTarget;
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::{ActionId, BuildId, EnvironmentId, SessionId};
use kr_protocol::local::LocalClientKind;
use kr_protocol::method::Method;
use kr_protocol::scalars::Nullable;
use kr_protocol::session::{
    Presentation, SessionCloseParams, SessionCloseResult, SessionCreateParams, SessionCreateResult,
    SessionListParams, SessionListResult, SessionState, ShellMode,
};

/// A host tree on the internal disk, with the worker beside it.
struct Host {
    temp: kr_ipc::testing::TempHost,
    worker: PathBuf,
    environment_id: EnvironmentId,
}

impl Host {
    fn create() -> Self {
        let temp = kr_ipc::testing::TempHost::create();
        let environment_id = temp.environment_id();
        // The worker is copied to the internal disk before it is started. The build tree may live
        // on a removable volume, and a launched process that reaches one prompts the person at the
        // machine for permission.
        let worker = temp.root().join("kr-worker");
        std::fs::copy(env!("CARGO_BIN_EXE_kr-worker"), &worker).expect("copies the worker");
        Self {
            temp,
            worker,
            environment_id,
        }
    }

    fn paths(&self) -> kr_ipc::paths::EnvironmentPaths {
        self.temp.environment()
    }

    async fn start(&self) -> RunningDaemon {
        let environment = self.paths();
        let environment_id = self.environment_id;
        let started = std::time::Instant::now();
        let controller = loop {
            let secrets = environment.secrets_dir();
            let outcome = Controller::start(ControllerSetup {
                paths: environment.clone(),
                environment_id,
                identity: Box::new(move || {
                    let store =
                        open_store(CONTROLLER_SECRET_SERVICE, &secrets).expect("a secret store");
                    Ok(
                        ControllerIdentity::open(store.store.as_ref(), environment_id, false)
                            .expect("an identity"),
                    )
                }),
                boot_identity: kr_ipc::identity::boot_identity().expect("a boot identity"),
                supervisor: Box::new(DetachedSupervisor::new()),
                worker_program: self.worker.clone(),
                build_id: build(),
                release: "0".to_owned(),
            })
            .await;
            match outcome {
                Ok(controller) => break controller,
                // The daemon this one replaces has not let go of the environment yet. Waiting for
                // it is a liveness condition: what a restart test asserts is that the replacement
                // takes the environment over, not how soon the runtime drops the last reference to
                // the one before it. Anything else fails at once.
                Err(kr_controller::ControllerError::AlreadyRunning { .. })
                    if started.elapsed() < ENVIRONMENT_HANDOVER_DEADLINE => {}
                Err(error) => panic!(
                    "the daemon did not start in {:.1?}: {error}",
                    started.elapsed()
                ),
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        };
        let rendezvous = Listener::bind(&environment.rendezvous_endpoint().expect("an endpoint"))
            .expect("binds the rendezvous");
        let clients = Listener::bind(&environment.controller_endpoint().expect("an endpoint"))
            .expect("binds the client endpoint");
        let generation = controller.generation();
        let serving = vec![
            tokio::spawn(Arc::clone(&controller).serve_rendezvous(rendezvous)),
            tokio::spawn(Arc::clone(&controller).serve_clients(clients)),
        ];
        RunningDaemon {
            controller,
            serving,
            generation,
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
}

/// How long a replacement daemon is given to take the environment over.
///
/// The environment's singleton lock is released when the last reference to the controller goes,
/// which is after the serving tasks have been dropped, so a replacement starting at once can find
/// the environment still held. A bound this generous fails only when the handover never happens.
const ENVIRONMENT_HANDOVER_DEADLINE: std::time::Duration = std::time::Duration::from_secs(120);

/// A control daemon that is running, and the tasks that are serving for it.
///
/// Stopping one in a test is the same thing as the process exiting: the tasks end, the last
/// reference goes, and the environment's singleton lock is released with it.
struct RunningDaemon {
    controller: Arc<Controller>,
    serving: Vec<tokio::task::JoinHandle<kr_controller::Result<()>>>,
    generation: kr_protocol::ids::ControllerGeneration,
}

impl RunningDaemon {
    /// Ends this daemon the way its process exiting would.
    async fn stop(self) {
        for task in &self.serving {
            task.abort();
        }
        for task in self.serving {
            let _ = task.await;
        }
        drop(self.controller);
        // The lock is released when the last reference goes, and references the runtime still has
        // to drop, or a task this test never awaited, can keep it a moment longer. The next start
        // waits for it rather than assuming a fixed delay is enough.
    }
}

fn build() -> BuildId {
    BuildId::new("kr-test/0").expect("a build identifier")
}

/// A shell that prints a marker and then waits, so its output is observable and it does not exit.
fn create_params(environment_id: EnvironmentId, cwd: &Path) -> SessionCreateParams {
    SessionCreateParams {
        environment_id,
        presentation: Presentation::Invisible,
        shell: Nullable::some("/bin/sh".to_owned()),
        shell_mode: ShellMode::NativeCompat,
        cwd: Nullable::some(cwd.display().to_string()),
        dimensions: Nullable::null(),
        worker_profile: kr_protocol::identity::WorkerProfile::HeadlessUser,
        environment_snapshot: vec![
            kr_protocol::session::EnvironmentVariable {
                name: "PATH".to_owned(),
                value: "/usr/bin:/bin".to_owned(),
            },
            kr_protocol::session::EnvironmentVariable {
                name: "PS1".to_owned(),
                value: String::new(),
            },
        ],
    }
}

async fn create(client: &mut LocalClient, host: &Host) -> SessionCreateResult {
    let outcome = client
        .mutate(
            Method::SessionCreate,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(host.environment_id),
            &create_params(host.environment_id, host.temp.root()),
        )
        .await
        .expect("the call reaches the daemon");
    let created: SessionCreateResult = outcome
        .map(|value| value.to_typed().expect("decodes"))
        .unwrap_or_else(|error| panic!("the create failed: {error}"));
    runs_where_the_host_put_it(host, created.session.session_id);
    created
}

/// Returns the working directory the operating system gave a running process.
///
/// Read from the process table rather than from anything this test arranged: what is being checked
/// is what the process actually got, and a launch that quietly inherited a directory looks exactly
/// like one that was given the right one until the kernel is asked. `None` means this platform has
/// no way to ask; a platform that has one and refuses to answer is a failure, not a skip.
fn working_directory_of(pid: u32) -> Option<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        Some(
            std::fs::read_link(format!("/proc/{pid}/cwd")).unwrap_or_else(|error| {
                panic!("the working directory of process {pid} could not be read: {error}")
            }),
        )
    }
    #[cfg(target_os = "macos")]
    {
        let output = std::process::Command::new("/usr/sbin/lsof")
            .args(["-a", "-d", "cwd", "-p", &pid.to_string(), "-Fn"])
            .output()
            .unwrap_or_else(|error| panic!("the process table could not be read: {error}"));
        Some(
            String::from_utf8_lossy(&output.stdout)
                .lines()
                .find_map(|line| line.strip_prefix('n').map(PathBuf::from))
                .unwrap_or_else(|| {
                    panic!("the process table named no working directory for process {pid}")
                }),
        )
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = pid;
        None
    }
}

/// Asserts that the worker this host started runs in the directory the host gave it.
///
/// A worker is deliberately not a child of the process that asked for it, so it inherits nothing
/// worth having: a directory inherited from the daemon belongs to whoever started the daemon, and
/// on this machine that is a build tree on a removable volume. A process holding one open is a
/// volume the person at the machine cannot eject and, on macOS, a permission prompt for every
/// rebuilt binary.
fn runs_where_the_host_put_it(host: &Host, session_id: SessionId) {
    let registry = Registry::open(host.paths().registry_database(), host.environment_id)
        .expect("opens the registry");
    let worker = registry
        .workers()
        .expect("reads the worker records")
        .into_iter()
        .find(|worker| worker.session_id == session_id)
        .expect("the created session has a worker record");
    let pid = u32::try_from(worker.process_identity.pid.get()).expect("a process identifier");
    let expected = std::fs::canonicalize(host.paths().worker_dir(session_id))
        .expect("the worker's own directory exists");
    // Checked whatever the process table can be asked: the directory the host configured and the
    // binary it started are both outside the workspace, which may be on a removable volume.
    let workspace = workspace_root();
    assert!(
        !expected.starts_with(&workspace),
        "no process this suite starts has a working directory inside the workspace: {}",
        expected.display()
    );
    assert!(
        !host.worker.starts_with(&workspace),
        "and the binary it started is not inside it either: {}",
        host.worker.display()
    );
    let Some(actual) = working_directory_of(pid) else {
        // Nothing to compare against rather than a comparison that failed. Saying so is better
        // than a pass that checked nothing.
        eprintln!(
            "skipped: this platform does not report another process's working directory here"
        );
        return;
    };
    assert_eq!(
        std::fs::canonicalize(&actual).unwrap_or(actual),
        expected,
        "the worker runs in the directory the host configured"
    );
}

/// Returns the workspace this test was built from.
fn workspace_root() -> PathBuf {
    let mut root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    // `<workspace>/crates/<crate>`.
    root.pop();
    root.pop();
    std::fs::canonicalize(&root).unwrap_or(root)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_daemon_restart_keeps_the_session_and_its_shell() {
    let host = Host::create();
    let first = host.start().await;
    let mut client = host.client().await;
    let created = create(&mut client, &host).await;
    assert_eq!(created.session.state, SessionState::Live);
    let session_id = created.session.session_id;
    let root = created
        .session
        .root_process
        .as_ref()
        .cloned()
        .expect("the session names its root shell");
    drop(client);

    // The daemon goes. Nothing about the session does: the worker is not this process's child, and
    // a restart is not a reason to end a shell.
    let generation = first.generation;
    first.stop().await;
    let second = host.start().await;
    assert!(
        second.generation.get() > generation.get(),
        "a replacement daemon advances the generation"
    );
    assert_eq!(
        kr_ipc::identity::process_state(&root),
        kr_ipc::identity::ProcessState::Running,
        "the root shell is still running after the daemon restarted"
    );

    let mut client = host.client().await;
    let listed: SessionListResult = client
        .request(
            Method::SessionList,
            &SessionListParams {
                environment_id: Nullable::null(),
                include_closed: false,
            },
        )
        .await
        .expect("the call reaches the daemon")
        .expect("the list succeeds")
        .to_typed()
        .expect("decodes");
    assert!(
        listed
            .sessions
            .iter()
            .any(|summary| summary.session_id == session_id && summary.state == SessionState::Live),
        "the replacement daemon found the session again and proved its worker"
    );
    // And the directory that worker is running in is still there. A replacement daemon sweeps
    // what no session claims, and an adopted session claims its own.
    runs_where_the_host_put_it(&host, session_id);

    close(&mut client, &host, session_id).await;
    second.stop().await;
}

/// A worker that reports it could not start resolves its own reservation, and the directory the
/// host prepared for it goes back.
///
/// Managed shell mode is the one thing a worker can be asked for and refuse before it has a
/// session: it needs a qualified shell package, and this host launches the stock shell. So the
/// worker starts, claims its reservation, says it cannot go on, and exits.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_worker_that_reports_it_could_not_start_leaves_no_directory() {
    let host = Host::create();
    let _controller = host.start().await;
    let mut client = host.client().await;
    let mut params = create_params(host.environment_id, host.temp.root());
    params.shell_mode = ShellMode::Managed;

    let refused = client
        .mutate(
            Method::SessionCreate,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(host.environment_id),
            &params,
        )
        .await
        .expect("the call reaches the daemon")
        .expect_err("a worker that cannot serve managed mode says so");
    // The daemon reports that it could not start a worker, and carries the worker's own words.
    assert_eq!(refused.code, ErrorCode::ResourceUnavailable);
    assert!(
        refused.message.contains("SHELL_INTEGRATION_UNSUPPORTED"),
        "the worker's own words reach the caller: {refused}"
    );
    // The reservation the report resolved stops occupying the environment, and what was prepared
    // for that worker is given back with it.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        let left = worker_dirs(&host);
        if left.is_empty() {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the directory prepared for a worker that never started is still there: {left:?}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
}

/// Returns the sessions that still have a directory under this environment's workers folder.
fn worker_dirs(host: &Host) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(host.paths().workers_dir()) else {
        return Vec::new();
    };
    let mut names: Vec<String> = entries
        .flatten()
        .filter_map(|entry| entry.file_name().to_str().map(str::to_owned))
        .collect();
    names.sort();
    names
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_environment_limit_refuses_before_anything_is_spawned() {
    let host = Host::create();
    {
        // The limit is part of the environment's record, so it is set before the daemon starts.
        let mut registry = Registry::open(host.paths().registry_database(), host.environment_id)
            .expect("opens the registry");
        registry.set_session_limit(1).expect("sets the limit");
    }
    let _controller = host.start().await;
    let mut client = host.client().await;
    let created = create(&mut client, &host).await;

    let refused = client
        .mutate(
            Method::SessionCreate,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(host.environment_id),
            &create_params(host.environment_id, host.temp.root()),
        )
        .await
        .expect("the call reaches the daemon");
    assert_eq!(
        refused.err().map(|error| error.code),
        Some(ErrorCode::SessionLimit),
        "the environment is full and nothing is evicted to make room"
    );
    close(&mut client, &host, created.session.session_id).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_repeated_create_token_returns_the_same_session() {
    let host = Host::create();
    let _controller = host.start().await;
    let mut client = host.client().await;
    let token = ActionId::new(kr_ipc::new_uuid());
    let params = create_params(host.environment_id, host.temp.root());

    let first: SessionCreateResult = client
        .mutate(
            Method::SessionCreate,
            token,
            ActionTarget::environment(host.environment_id),
            &params,
        )
        .await
        .expect("the call reaches the daemon")
        .expect("the create succeeds")
        .to_typed()
        .expect("decodes");
    let second: SessionCreateResult = client
        .mutate(
            Method::SessionCreate,
            token,
            ActionTarget::environment(host.environment_id),
            &params,
        )
        .await
        .expect("the call reaches the daemon")
        .expect("the retry succeeds")
        .to_typed()
        .expect("decodes");
    assert_eq!(
        second.session.session_id, first.session.session_id,
        "one token, one session"
    );
    assert!(second.deduplicated, "the retry says it is one");
    close(&mut client, &host, first.session.session_id).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_closed_session_answers_with_the_record_its_worker_wrote() {
    let host = Host::create();
    let _controller = host.start().await;
    let mut client = host.client().await;
    let created = create(&mut client, &host).await;
    let session_id = created.session.session_id;
    let shell = created.session.shell_path.clone();

    let closed = close(&mut client, &host, session_id).await;
    assert_eq!(closed.session_id, session_id);

    // The worker's own record, not a reconstruction: the shell it ran survives the session.
    //
    // A close is accepted before anything is signalled, so the tombstone appears once the daemon
    // has seen the worker end. The list is asked until it does, rather than once and immediately:
    // asking once would be a test of how busy the machine is.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let summary = loop {
        let listed: SessionListResult = client
            .request(
                Method::SessionList,
                &SessionListParams {
                    environment_id: Nullable::null(),
                    include_closed: true,
                },
            )
            .await
            .expect("the call reaches the daemon")
            .expect("the list succeeds")
            .to_typed()
            .expect("decodes");
        let found = listed
            .sessions
            .iter()
            .find(|summary| summary.session_id == session_id)
            .cloned();
        if let Some(summary) = found {
            break summary;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the closed session is listed"
        );
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    };
    assert_eq!(summary.state, SessionState::Closed);
    assert_eq!(
        summary.shell_path, shell,
        "the closed session still says which shell it ran"
    );
    assert!(
        summary.closure.is_present(),
        "a closed session carries its closure record"
    );
}

async fn close(client: &mut LocalClient, host: &Host, session_id: SessionId) -> SessionCloseResult {
    let outcome = client
        .mutate(
            Method::SessionClose,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget {
                environment_id: host.environment_id,
                session_id: Nullable::some(session_id),
                session_epoch: Nullable::some(kr_protocol::ids::SessionEpoch::V1),
                application_instance_id: Nullable::null(),
                agent_binding_revision: Nullable::null(),
            },
            &SessionCloseParams { session_id },
        )
        .await
        .expect("the call reaches the daemon");
    let closed: SessionCloseResult = outcome
        .map(|value| value.to_typed().expect("decodes"))
        .unwrap_or_else(|error| panic!("the close failed: {error}"));
    // The acceptance says `closing`; the closure finishes afterwards. Waiting for the record is
    // what makes the next assertion about the record rather than about the acceptance.
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
    while tokio::time::Instant::now() < deadline {
        let listed: SessionListResult = client
            .request(
                Method::SessionList,
                &SessionListParams {
                    environment_id: Nullable::null(),
                    include_closed: true,
                },
            )
            .await
            .expect("the call reaches the daemon")
            .expect("the list succeeds")
            .to_typed()
            .expect("decodes");
        if listed.sessions.iter().any(|summary| {
            summary.session_id == session_id && summary.state == SessionState::Closed
        }) {
            return closed;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    panic!("the session did not finish closing");
}
