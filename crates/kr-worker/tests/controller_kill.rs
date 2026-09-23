//! The control daemon killed while a session is producing output.
//!
//! The daemon here is a process of its own, so ending it is what ending a daemon is: `SIGKILL`,
//! with no drop, no flush and nothing said to anybody. That process is this test binary run again
//! in a mode where it serves a control daemon and nothing else, which is the daemon library the
//! `kr-controller` executable runs, started the same way. The worker it starts is the real worker
//! executable, and the terminal that watches is a local client on the worker's own endpoint.
//!
//! Everything a launched process touches is on the internal disk: both executables are copied into
//! the test's temporary host, which is also every process's working directory.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use kr_controller::service::{Controller, ControllerSetup};
use kr_controller::supervision::DetachedSupervisor;
use kr_crypto::store::{StoreSelection, open_store_in};
use kr_ipc::client::LocalClient;
use kr_ipc::endpoint::Listener;
use kr_ipc::verify::ControllerIdentity;
use kr_protocol::envelope::ActionTarget;
use kr_protocol::identity::ProcessStartIdentity;
use kr_protocol::ids::{ActionId, AttachmentId, BuildId, EnvironmentId, SessionId};
use kr_protocol::local::LocalClientKind;
use kr_protocol::method::Method;
use kr_protocol::scalars::Nullable;
use kr_protocol::session::{
    Dimensions, Presentation, SessionCloseParams, SessionCreateParams, SessionCreateResult,
    SessionListParams, SessionListResult, SessionReadParams, SessionReadResult, SessionState,
    ShellMode,
};

/// Where the daemon half finds the host it serves.
const ROOT: &str = "KR_KILL_TEST_ROOT";

/// The worker executable the daemon half starts.
const WORKER: &str = "KR_KILL_TEST_WORKER";

/// The name of the daemon half, as the test harness selects it.
const DAEMON_HALF: &str = "serve_a_control_daemon_for_the_kill_test";

/// How long a wait for something to happen is given. It fails when the thing never happens.
const LIVENESS_DEADLINE: Duration = Duration::from_secs(120);

fn build() -> BuildId {
    BuildId::new("kr-test/0").expect("a build identifier")
}

/// The daemon half: serves a control daemon for the host `KR_KILL_TEST_ROOT` names until it is
/// killed. It does nothing at all unless the kill test started it.
#[test]
#[ignore = "the daemon half of the kill test, run only as that test's own child process"]
fn serve_a_control_daemon_for_the_kill_test() {
    let (Some(root), Some(worker)) = (std::env::var_os(ROOT), std::env::var_os(WORKER)) else {
        return;
    };
    let root = PathBuf::from(root);
    let worker = PathBuf::from(worker);
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("a runtime")
        .block_on(async move {
            let paths = kr_ipc::paths::HostPaths::new(root.join("r"), root.join("s"))
                .expect("the host's roots");
            let environment_id = paths.open_environment_id().expect("the environment");
            let environment = paths.environment(environment_id);
            let started = std::time::Instant::now();
            let controller = loop {
                let secrets = environment.secrets_dir();
                match Controller::start(ControllerSetup {
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
                    supervisor: Box::new(DetachedSupervisor::new()),
                    worker_program: worker.clone(),
                    build_id: build(),
                    release: "0".to_owned(),
                    shell_packages: None,
                    terminal: Box::new(kr_controller::supervision::NoTerminal),
                })
                .await
                {
                    Ok(controller) => break controller,
                    // The killed daemon's environment lock goes with its process; waiting for
                    // the kernel to let go of it is a liveness condition, not a measurement.
                    Err(kr_controller::ControllerError::AlreadyRunning { .. })
                        if started.elapsed() < LIVENESS_DEADLINE =>
                    {
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                    Err(error) => panic!("the daemon did not start: {error}"),
                }
            };
            let rendezvous =
                Listener::bind(&environment.rendezvous_endpoint().expect("an endpoint"))
                    .expect("binds the rendezvous");
            let clients = Listener::bind(&environment.controller_endpoint().expect("an endpoint"))
                .expect("binds the client endpoint");
            let serving = tokio::spawn(Arc::clone(&controller).serve_rendezvous(rendezvous));
            let _ = Arc::clone(&controller).serve_clients(clients).await;
            let _ = serving.await;
        });
}

/// The processes this test started, ended however the test ends.
struct Started {
    daemon: Option<std::process::Child>,
    worker: Option<ProcessStartIdentity>,
}

impl Started {
    /// Kills the daemon where it stands, and waits for the kernel to report it gone.
    fn kill_daemon(&mut self) {
        if let Some(mut daemon) = self.daemon.take() {
            daemon
                .kill()
                .expect("the daemon this test started is killed");
            daemon.wait().expect("and reaped");
        }
    }
}

impl Drop for Started {
    fn drop(&mut self) {
        self.kill_daemon();
        // A worker this test's daemon started, if a failure left it running. Its terminal goes
        // with it, and everything in the session's process group with that.
        if let Some(worker) = self.worker.take()
            && kr_ipc::identity::process_state(&worker) == kr_ipc::identity::ProcessState::Running
            && let Ok(pid) = i32::try_from(worker.pid.get())
            && let Some(pid) = rustix::process::Pid::from_raw(pid)
        {
            let _ = rustix::process::kill_process(pid, rustix::process::Signal::KILL);
        }
    }
}

/// Starts the daemon half as a process of its own, on this host.
fn start_daemon(
    program: &Path,
    host: &kr_ipc::testing::TempHost,
    worker: &Path,
) -> std::process::Child {
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(host.root().join("daemon.log"))
        .expect("opens the daemon's log");
    let mut attempted = 0;
    loop {
        attempted += 1;
        let started = std::process::Command::new(program)
            .args([
                "--exact",
                DAEMON_HALF,
                "--include-ignored",
                "--nocapture",
                "--test-threads",
                "1",
            ])
            .env(ROOT, host.root())
            .env(WORKER, worker)
            .current_dir(host.root())
            .stdin(std::process::Stdio::null())
            .stdout(log.try_clone().expect("duplicates the log"))
            .stderr(log.try_clone().expect("duplicates the log"))
            .spawn();
        match started {
            Ok(child) => return child,
            Err(error)
                if error.kind() == std::io::ErrorKind::ExecutableFileBusy && attempted < 100 =>
            {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => panic!("the daemon starts, after {attempted} attempts: {error:?}"),
        }
    }
}

/// Connects to the daemon once it answers.
async fn daemon_client(host: &kr_ipc::testing::TempHost) -> LocalClient {
    let endpoint = host
        .environment()
        .controller_endpoint()
        .expect("an endpoint");
    let started = std::time::Instant::now();
    loop {
        if let Ok(client) = LocalClient::connect(&endpoint, LocalClientKind::Cli, build()).await {
            return client;
        }
        assert!(
            started.elapsed() < LIVENESS_DEADLINE,
            "the daemon did not answer within {LIVENESS_DEADLINE:?}; its log says: {}",
            std::fs::read_to_string(host.root().join("daemon.log"))
                .unwrap_or_else(|error| format!("<unreadable: {error}>"))
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn session_target(environment_id: EnvironmentId, session_id: SessionId) -> ActionTarget {
    ActionTarget {
        environment_id,
        session_id: Nullable::some(session_id),
        session_epoch: Nullable::some(kr_protocol::ids::SessionEpoch::V1),
        application_instance_id: Nullable::null(),
        agent_binding_revision: Nullable::null(),
    }
}

/// A terminal attached on this machine, on the worker's own endpoint.
struct LocalTerminal {
    client: LocalClient,
    session_id: SessionId,
    attachment_id: AttachmentId,
    epoch: Option<kr_protocol::ids::InputLeaseEpoch>,
    sequence: u64,
    seen: String,
}

impl LocalTerminal {
    async fn attach(
        host: &kr_ipc::testing::TempHost,
        session_id: SessionId,
        dimensions: Dimensions,
        keys: bool,
    ) -> Self {
        use kr_protocol::attachment::{AttachMode, AttachmentCapability, SessionAttachParams};
        use kr_protocol::scalars::CanonicalSet;

        let descriptor = kr_ipc::descriptor::read_all(&host.environment())
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
            .expect("the worker answers the descriptor's challenge");
        let target = session_target(descriptor.environment_id, session_id);
        let mut requested = CanonicalSet::new();
        requested.insert(AttachmentCapability::ObserveTerminal);
        requested.insert(AttachmentCapability::Input);
        let attached: kr_protocol::attachment::SessionAttachResult = client
            .mutate(
                Method::SessionAttach,
                ActionId::new(kr_ipc::new_uuid()),
                target.clone(),
                &SessionAttachParams {
                    session_id,
                    mode: AttachMode::Terminal,
                    claim_geometry: false,
                    dimensions: Nullable::some(dimensions),
                    terminal_profile_id: Nullable::some("xterm-256color".to_owned()),
                    requested,
                },
            )
            .await
            .expect("the call reaches the worker")
            .expect("the worker attaches the terminal")
            .to_typed()
            .expect("decodes");
        let attachment_id = attached.attachment.attachment_id;
        let epoch = if keys {
            let lease: kr_protocol::input::InputAcquireResult = client
                .mutate(
                    Method::InputAcquire,
                    ActionId::new(kr_ipc::new_uuid()),
                    target,
                    &kr_protocol::input::InputAcquireParams {
                        session_id,
                        attachment_id,
                        expected_epoch: Nullable::null(),
                    },
                )
                .await
                .expect("the call reaches the worker")
                .expect("the worker hands this terminal the keys")
                .to_typed()
                .expect("decodes");
            Some(lease.lease.epoch)
        } else {
            None
        };
        // Subscribing is the last call: the screen this terminal is drawn is queued the moment it
        // subscribes, and a client drops what arrives while it waits for an answer of its own.
        let mut streams = CanonicalSet::new();
        streams.insert(kr_protocol::recovery::EventStream::Output);
        client
            .request(
                Method::EventsSubscribe,
                &kr_protocol::recovery::EventsSubscribeParams {
                    session_id,
                    attachment_id,
                    streams,
                    from_cursor: Nullable::null(),
                },
            )
            .await
            .expect("the call reaches the worker")
            .expect("the worker subscribes the terminal");
        Self {
            client,
            session_id,
            attachment_id,
            epoch,
            sequence: 0,
            seen: String::new(),
        }
    }

    /// Types one line into the session, under this terminal's lease.
    async fn type_line(&mut self, line: &str) {
        let epoch = self.epoch.expect("this terminal holds the keys");
        let _: kr_protocol::input::InputWriteResult = self
            .client
            .request(
                Method::InputWrite,
                &kr_protocol::input::InputWriteParams {
                    session_id: self.session_id,
                    attachment_id: self.attachment_id,
                    epoch,
                    sequence: kr_protocol::ids::InputSequence::new(self.sequence),
                    bytes: kr_protocol::scalars::Bytes::new(format!("{line}\n").into_bytes()),
                },
            )
            .await
            .expect("the call reaches the worker")
            .expect("the worker takes the line")
            .to_typed()
            .expect("decodes");
        self.sequence += 1;
    }

    fn count(&self, marker: &str) -> usize {
        self.seen.matches(marker).count()
    }

    /// Waits until `marker` has reached this terminal `times` times in all.
    async fn shown(&mut self, marker: &str, times: usize) {
        let started = tokio::time::Instant::now();
        let deadline = started + LIVENESS_DEADLINE;
        while self.count(marker) < times {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            match tokio::time::timeout(remaining, self.client.recv()).await {
                Ok(Ok(kr_protocol::envelope::ControlFrame::Notification(notification)))
                    if notification.event_type.as_str() == "session.output" =>
                {
                    if let Ok(event) = notification
                        .payload
                        .to_typed::<kr_protocol::recovery::OutputEvent>()
                    {
                        self.seen
                            .push_str(&String::from_utf8_lossy(event.bytes.as_slice()));
                    }
                }
                Ok(Ok(_)) => {}
                Ok(Err(error)) => panic!(
                    "waited {:?} for {times} of {marker:?} and the connection ended ({error}): \
                     {:?}",
                    started.elapsed(),
                    self.seen
                ),
                Err(_) => panic!(
                    "waited {:?} for {times} of {marker:?}: {:?}",
                    started.elapsed(),
                    self.seen
                ),
            }
        }
    }

    /// The tick numbers this terminal has been shown, in the order they arrived.
    fn ticks(&self) -> Vec<u64> {
        self.seen
            .split("kr-tick-")
            .skip(1)
            .filter_map(|rest| {
                let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
                (!digits.is_empty() && rest[digits.len()..].starts_with('.'))
                    .then(|| digits.parse().expect("a number"))
            })
            .collect()
    }
}

/// KR-ACC-006: the control daemon is killed while the session is producing output. The terminal
/// attached on this machine keeps receiving that output, every line of it in order, and keeps
/// typing into the shell while no daemon exists; a replacement daemon finds the session live with
/// that terminal still attached; and a terminal attaching after the reconnect is drawn the screen
/// as it now is.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_daemon_killed_during_output_leaves_local_work_running_and_a_reconnect_finds_it() {
    let host = kr_ipc::testing::TempHost::create();
    let environment_id = host.environment_id();
    let worker = host.root().join("kr-worker");
    std::fs::copy(env!("CARGO_BIN_EXE_kr-worker"), &worker).expect("copies the worker");
    let program = host.root().join("kill-test-daemon");
    std::fs::copy(
        std::env::current_exe().expect("this test's own executable"),
        &program,
    )
    .expect("copies the daemon half");
    let mut started = Started {
        daemon: Some(start_daemon(&program, &host, &worker)),
        worker: None,
    };

    let mut local = daemon_client(&host).await;
    let created: SessionCreateResult = local
        .mutate(
            Method::SessionCreate,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(environment_id),
            &SessionCreateParams {
                environment_id,
                presentation: Presentation::Invisible,
                shell: Nullable::some(kr_worker::testing::posix_shell()),
                shell_mode: ShellMode::NativeCompat,
                cwd: Nullable::some(host.root().display().to_string()),
                dimensions: Nullable::null(),
                worker_profile: kr_protocol::identity::WorkerProfile::HeadlessUser,
                palette: Nullable::null(),
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
                launch_profile: kr_protocol::session::LaunchProfile::default(),
                terminal: Nullable::null(),
            },
        )
        .await
        .expect("the call reaches the daemon")
        .unwrap_or_else(|error| panic!("the create failed: {error}"))
        .to_typed()
        .expect("decodes");
    let session_id = created.session.session_id;
    let dimensions = created.session.dimensions;
    started.worker = kr_ipc::descriptor::read_all(&host.environment())
        .expect("reads the runtime directory")
        .into_iter()
        .filter_map(|entry| entry.descriptor.ok())
        .find(|descriptor| descriptor.session_id == session_id)
        .map(|descriptor| descriptor.process_start_identity);
    drop(local);

    // A terminal on this machine starts a ticker: numbered lines, one every tenth of a second,
    // until a file appears in the session's directory. The shell echoes the command with `%d`,
    // so only the ticker itself prints a number.
    let mut watching = LocalTerminal::attach(&host, session_id, dimensions, true).await;
    watching
        .type_line(
            "i=0; (while [ ! -e kr-stop ] && [ $i -lt 3000 ]; do i=$((i+1)); \
             printf 'kr-tick-%d.\\n' $i; sleep 0.1; done) &",
        )
        .await;
    watching.shown("kr-tick-", 3).await;

    // The daemon is killed while the ticker is writing.
    started.kill_daemon();
    let before_the_kill = watching.ticks().len();
    let shown = watching.count("kr-tick-");
    watching.shown("kr-tick-", shown + 5).await;
    watching
        .type_line("printf 'kr-%s\\n' typed-with-no-daemon")
        .await;
    watching.shown("kr-typed-with-no-daemon", 1).await;

    // A replacement daemon finds the session live, with the terminal still attached.
    started.daemon = Some(start_daemon(&program, &host, &worker));
    let mut local = daemon_client(&host).await;
    let listed: SessionListResult = local
        .request(
            Method::SessionList,
            &SessionListParams {
                environment_id: Nullable::null(),
                include_closed: false,
            },
        )
        .await
        .expect("the call reaches the replacement")
        .expect("the list succeeds")
        .to_typed()
        .expect("decodes");
    assert!(
        listed
            .sessions
            .iter()
            .any(|summary| summary.session_id == session_id && summary.state == SessionState::Live),
        "the replacement daemon found the session again: {listed:?}"
    );
    let read: SessionReadResult = local
        .request(Method::SessionRead, &SessionReadParams { session_id })
        .await
        .expect("the call reaches the replacement")
        .expect("the read succeeds")
        .to_typed()
        .expect("decodes");
    assert_eq!(read.session.state, SessionState::Live);
    assert_eq!(
        read.session.attachment_count.get(),
        1,
        "the terminal that watched through the kill is still attached"
    );

    // The output never stopped and nothing was lost or repeated: the terminal was shown every
    // tick, in order, from the first.
    watching
        .type_line(": > kr-stop; printf 'kr-%s\\n' settled")
        .await;
    watching.shown("kr-settled", 1).await;
    let ticks = watching.ticks();
    assert!(
        ticks.len() >= before_the_kill + 5,
        "output kept arriving after the daemon was killed: {before_the_kill} lines before it, \
         {ticks:?} in all"
    );
    assert_eq!(
        ticks,
        (1..=ticks.len() as u64).collect::<Vec<_>>(),
        "every line the session wrote reached the terminal once, in order"
    );

    // A terminal attaching after the reconnect is drawn the screen as it now is.
    let mut late = LocalTerminal::attach(&host, session_id, dimensions, false).await;
    late.shown("kr-settled", 1).await;

    let _ = local
        .mutate(
            Method::SessionClose,
            ActionId::new(kr_ipc::new_uuid()),
            session_target(environment_id, session_id),
            &SessionCloseParams { session_id },
        )
        .await;
}
