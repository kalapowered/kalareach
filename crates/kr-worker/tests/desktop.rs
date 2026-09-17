//! The desktop execution context, the two profiles, their lifetimes and the host power setting.
//!
//! Section 3 separates where a session is shown from where its processes run. These tests hold
//! that separation to its consequences with real daemons, real workers and real shells: the
//! identity a desktop is bound by, what survives an attachment going and a daemon restarting, what
//! a logout and a reboot end, what may actually be done on a desktop, and what the host is allowed
//! to do to its own sleep policy.
//!
//! Each test names the requirement it closes.
//!
//! Every path here is on the internal disk and the worker is copied there before it is started. A
//! process a service manager launches is its own identity to the operating system, and one that
//! reaches a removable volume asks the person at the machine for permission; a test must never do
//! that.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use kr_controller::desktop::power::{self, Demand, Inhibitor};
use kr_controller::service::{Controller, ControllerSetup};
use kr_controller::supervision::DetachedSupervisor;
use kr_crypto::store::open_store;
use kr_ipc::client::LocalClient;
use kr_ipc::endpoint::Listener;
use kr_ipc::verify::{CONTROLLER_SECRET_SERVICE, ControllerIdentity};
use kr_protocol::desktop::{
    CapabilityEvidenceSource, CapabilityState, ContainerEnvironment, DesktopAvailability,
    DesktopSessionKind, DisplayServer, InhibitionReason, LogoutPersistence, PowerSource,
    SleepInhibitionSetting, capabilities, setting,
};
use kr_protocol::envelope::ActionTarget;
use kr_protocol::hostinfo::HostInfoResult;
use kr_protocol::identity::{DesktopBinding, WorkerProfile};
use kr_protocol::ids::{
    ActionId, BuildId, CapabilityRevision, EnvironmentId, SessionEpoch, SessionId,
};
use kr_protocol::local::LocalClientKind;
use kr_protocol::method::{Method, REGISTRY};
use kr_protocol::scalars::{Nullable, Uuid};
use kr_protocol::session::{
    ClosureReason, Dimensions, DisplayNumber, Presentation, SessionCloseParams, SessionCloseResult,
    SessionCreateParams, SessionCreateResult, SessionListParams, SessionListResult,
    SessionReadParams, SessionReadResult, SessionState, ShellMode,
};
use kr_worker::desktop;
use kr_worker::pty::ShellCommand;
use kr_worker::runtime::SessionRuntime;
use kr_worker::session::{Session, SessionConfig};

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
}

/// A control daemon that is running, and the tasks serving for it.
struct RunningDaemon {
    controller: Arc<Controller>,
    serving: Vec<tokio::task::JoinHandle<kr_controller::Result<()>>>,
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
    }
}

/// How long a replacement daemon is given to take the environment over.
///
/// The environment's singleton lock is released when the last reference to the controller goes,
/// which is after the serving tasks have been dropped, and a reference this daemon handed to
/// something of its own outlives that moment. A bound this generous fails only when the handover
/// never happens.
const ENVIRONMENT_HANDOVER_DEADLINE: Duration = Duration::from_secs(120);

fn build() -> BuildId {
    BuildId::new("kr-test/0").expect("a build identifier")
}

/// A create request for one session, in one execution context.
fn create_params(
    environment_id: EnvironmentId,
    cwd: &Path,
    presentation: Presentation,
    profile: WorkerProfile,
) -> SessionCreateParams {
    SessionCreateParams {
        environment_id,
        presentation,
        shell: Nullable::some("/bin/sh".to_owned()),
        shell_mode: ShellMode::NativeCompat,
        cwd: Nullable::some(cwd.display().to_string()),
        dimensions: Nullable::null(),
        worker_profile: profile,
        environment_snapshot: vec![
            kr_protocol::session::EnvironmentVariable {
                name: "PATH".to_owned(),
                value: "/usr/bin:/bin:/sbin:/usr/sbin".to_owned(),
            },
            kr_protocol::session::EnvironmentVariable {
                name: "PS1".to_owned(),
                value: String::new(),
            },
            // A creator's snapshot cannot give a session a desktop. These are here so the tests
            // below establish that rather than assume it.
            kr_protocol::session::EnvironmentVariable {
                name: "DISPLAY".to_owned(),
                value: ":99".to_owned(),
            },
            kr_protocol::session::EnvironmentVariable {
                name: "WAYLAND_DISPLAY".to_owned(),
                value: "wayland-99".to_owned(),
            },
        ],
    }
}

async fn create(
    client: &mut LocalClient,
    host: &Host,
    presentation: Presentation,
    profile: WorkerProfile,
) -> SessionCreateResult {
    let outcome = client
        .mutate(
            Method::SessionCreate,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(host.environment_id),
            &create_params(host.environment_id, host.temp.root(), presentation, profile),
        )
        .await
        .expect("the call reaches the daemon");
    outcome
        .map(|value| value.to_typed().expect("decodes"))
        .unwrap_or_else(|error| panic!("the create failed: {error}"))
}

async fn close(client: &mut LocalClient, host: &Host, session_id: SessionId) {
    let outcome = client
        .mutate(
            Method::SessionClose,
            ActionId::new(kr_ipc::new_uuid()),
            session_target(host.environment_id, session_id),
            &SessionCloseParams { session_id },
        )
        .await
        .expect("the call reaches the daemon");
    let _: SessionCloseResult = outcome
        .map(|value| value.to_typed().expect("decodes"))
        .unwrap_or_else(|error| panic!("the close failed: {error}"));
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    while tokio::time::Instant::now() < deadline {
        if closed(client, session_id).await.is_some() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("the session did not finish closing");
}

async fn closed(
    client: &mut LocalClient,
    session_id: SessionId,
) -> Option<kr_protocol::session::SessionSummary> {
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
    listed
        .sessions
        .into_iter()
        .find(|summary| summary.session_id == session_id && summary.state == SessionState::Closed)
}

fn session_target(environment_id: EnvironmentId, session_id: SessionId) -> ActionTarget {
    ActionTarget {
        environment_id,
        session_id: Nullable::some(session_id),
        session_epoch: Nullable::some(SessionEpoch::V1),
        application_instance_id: Nullable::null(),
        agent_binding_revision: Nullable::null(),
    }
}

/// Whether this host has a graphical login session to bind a session to.
fn has_desktop() -> bool {
    let context = desktop::context(
        WorkerProfile::DesktopBound,
        kr_ipc::identity::boot_identity().expect("a boot identity"),
    );
    context.is_desktop() && context.graphic_access
}

/// The desktop this host has, where it has one.
fn live_desktop() -> Option<desktop::Login> {
    match desktop::current() {
        desktop::Reading::Desktop(login) => Some(login),
        desktop::Reading::None | desktop::Reading::Unavailable => None,
    }
}

/// The profile a session is created with on this host.
///
/// A host with no graphical login has no desktop to bind to, so the tests that are about a desktop
/// say what they could not establish rather than failing on a machine that has none.
fn profile_here() -> WorkerProfile {
    if has_desktop() {
        WorkerProfile::DesktopBound
    } else {
        WorkerProfile::HeadlessUser
    }
}

/// Returns the process group of one process, as the operating system reports it.
fn process_group(pid: u32) -> Option<u32> {
    let output = std::process::Command::new("/bin/ps")
        .args(["-o", "pgid=", "-p", &pid.to_string()])
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().parse().ok())
        .flatten()
}

/// KR-REQ-03.18: the desktop context binds the user, the platform login-session identifier, the
/// host boot identity and the login-session generation, and a reused platform session number is
/// not the same desktop.
#[test]
fn the_desktop_identity_binds_the_user_the_platform_session_the_boot_and_the_generation() {
    let boot = kr_ipc::identity::boot_identity().expect("a boot identity");
    let reading = desktop::current();
    let live = match &reading {
        desktop::Reading::Desktop(login) => login.clone(),
        // The platform answered that there is no graphical login, or would not answer at all.
        // Either way there is no identity on this host to read, and the identity's own rules are
        // established by the assertions below on a reading taken from the platform's own shape.
        desktop::Reading::None | desktop::Reading::Unavailable => {
            // A host whose platform does describe a graphical login must produce a complete
            // identity from it. Anything else is this reader failing, not this host lacking a
            // desktop, and the test says which by asking the platform itself.
            #[cfg(target_os = "macos")]
            assert!(
                !std::process::Command::new("/bin/launchctl")
                    .args(["print", &format!("gui/{}", kr_ipc::paths::current_uid())])
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status()
                    .is_ok_and(|status| status.success()),
                "this host has a graphical login domain and no complete desktop identity was read"
            );
            let context = desktop::context(WorkerProfile::DesktopBound, boot);
            assert!(!context.is_desktop());
            assert_eq!(context.kind, DesktopSessionKind::None);
            assert!(!context.graphic_access);
            return;
        }
    };

    // A reading that describes a login session describes all four parts of the identity, or it is
    // not a desktop at all.
    assert!(live.is_desktop(), "{live:?}");
    assert!(
        live.anchor.is_some(),
        "the reading names the process that owns the login session: {live:?}"
    );
    assert_ne!(
        live.generation_source,
        kr_protocol::desktop::DesktopGenerationSource::Unavailable,
        "and says what the generation was read from"
    );
    assert_eq!(
        live.generation,
        live.anchor.as_ref().map(|anchor| anchor.start_value.get()),
        "the generation is that process's own start value"
    );

    let context = desktop::from_login(&live, WorkerProfile::DesktopBound, boot.clone());
    let name = context
        .desktop_session_id
        .as_ref()
        .expect("a desktop has a name")
        .to_string();
    let uid = context.uid.as_ref().expect("a user").get();
    assert!(name.contains(&format!("uid={uid}")), "{name}");
    assert!(
        name.contains(&format!("user={}", context.os_user)),
        "{name}"
    );
    assert!(
        name.contains(
            context
                .platform_session
                .as_ref()
                .expect("the platform names its login session")
        ),
        "{name}"
    );
    assert!(name.contains("boot="), "{name}");
    assert!(
        name.contains(&format!(
            "generation={}",
            context
                .login_generation
                .as_ref()
                .expect("a generation")
                .get()
        )),
        "{name}"
    );
    assert_eq!(
        context.boot_identity, boot,
        "the boot is part of the identity"
    );

    // The same platform session number in a later login is a different desktop, because the
    // generation moved with it.
    let mut relogin = live.clone();
    relogin.generation = live.generation.map(|value| value.wrapping_add(1));
    let later = desktop::from_login(&relogin, WorkerProfile::DesktopBound, boot.clone());
    assert_eq!(later.platform_session, context.platform_session);
    assert!(
        !later.is_same_desktop(&context),
        "a reused platform session number is not the same desktop"
    );

    // And the same reading in another boot is a different desktop again.
    let mut other_boot = boot;
    other_boot.value = kr_protocol::scalars::Bytes::new(b"another boot".to_vec());
    let rebooted = desktop::from_login(&live, WorkerProfile::DesktopBound, other_boot);
    assert!(!rebooted.is_same_desktop(&context));

    // A reading with no generation is not an identity at all, whatever else it carries.
    let mut nameless = live;
    nameless.generation = None;
    nameless.anchor = None;
    let incomplete = desktop::from_login(
        &nameless,
        WorkerProfile::DesktopBound,
        context.boot_identity.clone(),
    );
    assert!(
        !incomplete.is_desktop(),
        "a platform session number without a generation is not a desktop"
    );
}

/// KR-REQ-01.10, KR-REQ-03.19: an invisible session keeps the selected desktop's graphical access,
/// and the presentation neither migrates execution nor changes its permission context.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_invisible_session_keeps_the_desktop_and_the_presentation_changes_nothing_else() {
    let host = Host::create();
    let daemon = host.start().await;
    let mut client = host.client().await;
    let profile = profile_here();

    let invisible = create(&mut client, &host, Presentation::Invisible, profile).await;
    let terminal = create(&mut client, &host, Presentation::Terminal, profile).await;

    // The same execution context, whatever the presentation. This is the whole of KR-REQ-03.19:
    // changing where a session is shown moves nothing about where it runs.
    assert_eq!(invisible.session.worker_profile, profile);
    assert_eq!(terminal.session.worker_profile, profile);
    assert_eq!(
        invisible.session.desktop.desktop_session_id, terminal.session.desktop.desktop_session_id,
        "two presentations of the same execution context name the same desktop"
    );
    assert_eq!(
        invisible.session.desktop.login_generation,
        terminal.session.desktop.login_generation
    );

    if profile == WorkerProfile::DesktopBound {
        // KR-REQ-01.10: the invisible session is in the graphical login session, so a command
        // inside it has that desktop's access. The platform is asked from inside the session's own
        // execution context rather than assumed from the absence of a terminal.
        assert!(
            invisible.session.desktop.desktop_session_id.is_present(),
            "an invisible session created in a desktop context keeps that desktop"
        );
        let context = desktop::context(
            WorkerProfile::DesktopBound,
            kr_ipc::identity::boot_identity().expect("a boot identity"),
        );
        assert!(
            context.graphic_access,
            "the execution context these sessions were created in has graphical access"
        );
        assert_eq!(
            context.desktop_session_id, invisible.session.desktop.desktop_session_id,
            "and it is the desktop the invisible session records"
        );
    }

    close(&mut client, &host, invisible.session.session_id).await;
    close(&mut client, &host, terminal.session.session_id).await;
    daemon.stop().await;
}

/// KR-REQ-03.23, KR-REQ-07.58: a desktop-bound session survives every attachment going and the
/// control daemon restarting, and the service manager rather than the daemon owns its worker.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_desktop_bound_session_survives_no_attachments_and_a_daemon_restart() {
    let host = Host::create();
    let first = host.start().await;
    let mut client = host.client().await;
    let created = create(&mut client, &host, Presentation::Invisible, profile_here()).await;
    let session_id = created.session.session_id;
    if has_desktop() {
        assert_eq!(
            created.session.worker_profile,
            WorkerProfile::DesktopBound,
            "this host has a desktop, so this is the profile the test is about"
        );
        assert!(
            created.session.desktop.desktop_session_id.is_present(),
            "and the session is bound to it"
        );
    }
    assert_eq!(created.session.attachment_count.get(), 0, "no attachment");
    let root = created
        .session
        .root_process
        .as_ref()
        .cloned()
        .expect("the session names its root shell");

    // The worker is not in this process's own process group, which is what keeps it out of
    // anything aimed at the daemon that started it.
    let worker_group = process_group(u32::try_from(root.pid.get()).expect("a process identifier"));
    if let Some(worker_group) = worker_group {
        assert_ne!(
            Some(worker_group),
            process_group(std::process::id()),
            "a worker's lifetime does not belong to the daemon that asked for it"
        );
    }

    drop(client);
    first.stop().await;
    let second = host.start().await;
    assert_eq!(
        kr_ipc::identity::process_state(&root),
        kr_ipc::identity::ProcessState::Running,
        "the shell is still running after the daemon restarted"
    );

    let mut client = host.client().await;
    let summary: SessionReadResult = client
        .request(Method::SessionRead, &SessionReadParams { session_id })
        .await
        .expect("the call reaches the daemon")
        .expect("the read succeeds")
        .to_typed()
        .expect("decodes");
    assert_eq!(summary.session.state, SessionState::Live);
    assert_eq!(
        summary.session.worker_profile,
        profile_here(),
        "the replacement daemon reports the execution context the session was created with"
    );

    close(&mut client, &host, session_id).await;
    second.stop().await;
}

/// KR-REQ-03.23: a desktop-bound session closes with `desktop_lost` when the login session it was
/// bound to ends.
///
/// The login session is ended in the harness rather than on the machine: the session is bound to a
/// desktop that is not the one this host is in, which is what a worker sees the moment its own
/// login has gone.
#[tokio::test(flavor = "multi_thread")]
async fn a_desktop_bound_session_closes_with_desktop_lost_when_its_login_ends() {
    let host = kr_ipc::testing::TempHost::create();
    let session_id = SessionId::new(kr_ipc::new_uuid());
    let config = SessionConfig {
        session_id,
        session_epoch: SessionEpoch::V1,
        environment_id: host.environment_id(),
        display_number: DisplayNumber::new(1),
        shell: ShellCommand {
            program: "/bin/sh".to_owned(),
            arguments: vec!["-c".to_owned(), "exec cat".to_owned()],
            cwd: "/".to_owned(),
            environment: vec![("PATH".to_owned(), "/usr/bin:/bin".to_owned())],
        },
        shell_mode: ShellMode::NativeCompat,
        worker_profile: WorkerProfile::DesktopBound,
        // A desktop no host is in: another user, another session, another generation, another
        // boot. Every part of the identity differs, so this is a login that has ended.
        desktop: DesktopBinding {
            desktop_session_id: Nullable::some(
                kr_protocol::ids::DesktopSessionId::new(
                    "macos_security_session:uid=0:session=0:generation=0:boot=00",
                )
                .expect("a name"),
            ),
            login_generation: Nullable::some(kr_protocol::scalars::U64::new(0)),
        },
        dimensions: Dimensions::new(80, 24),
        journal_path: Some(host.environment().journal_database(session_id)),
        spool_directory: Some(host.environment().session_spool(session_id)),
        send_queue_bytes: 8 * 1024 * 1024,
        resident_bytes: 1024 * 1024,
    };
    let mut session = Session::open(config).expect("opens");
    session.launch().expect("launches");
    let runtime = SessionRuntime::start(session).expect("starts");

    let record = tokio::time::timeout(Duration::from_secs(30), runtime.wait_closed())
        .await
        .expect("the session closes when its desktop ends");
    assert_eq!(
        record.reason,
        ClosureReason::DesktopLost,
        "the closure names the desktop rather than the shell"
    );

    // The control that makes the case above mean something: a watch bound to the desktop this
    // host is actually in is not lost, however often it is asked.
    if let Some(live) = live_desktop() {
        let boot = kr_ipc::identity::boot_identity().expect("a boot identity");
        let context = desktop::from_login(&live, WorkerProfile::DesktopBound, boot);
        let mut watch =
            desktop::Watch::bind(WorkerProfile::DesktopBound, &desktop::binding(&context));
        let now = std::time::Instant::now();
        assert!(
            !watch.lost(now),
            "a session bound to this host's own desktop has not lost it"
        );
        assert!(
            !watch.lost(now + desktop::RECHECK_INTERVAL * 3),
            "and asking again does not change that"
        );
        assert_eq!(
            watch.bound_name(),
            context.desktop_session_id.as_ref(),
            "the watch is bound to the desktop the record names"
        );
    }
}

/// KR-REQ-03.23, KR-REQ-07.58: a graphical job the service manager tears down ends the processes
/// in it, which is what a logout does to a desktop-bound worker on this platform.
///
/// The job is this test's own, bootstrapped into the user's graphical domain and booted out of it
/// again. Nothing belonging to the person at the machine is touched, and the machine is never
/// logged out: what is demonstrated is the mechanism, and `docs/host/platforms.md` records what a
/// real logout does with it.
#[cfg(target_os = "macos")]
#[test]
fn a_graphical_job_torn_down_by_the_service_manager_ends_the_processes_in_it() {
    let host = kr_ipc::testing::TempHost::create();
    let uid = kr_ipc::paths::current_uid();
    let domain = format!("gui/{uid}");
    if !std::process::Command::new("/bin/launchctl")
        .args(["print", &domain])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
    {
        // No graphical domain on this host, so there is no teardown to observe.
        return;
    }
    let label = format!("kr-test-desktop-{}", std::process::id());
    let job = host.root().join(format!("{label}.plist"));
    // The program is the platform's own sleep, which is on the internal disk. A job that reached
    // the workspace volume would ask the person at the machine for permission.
    let document = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \
         \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
         <plist version=\"1.0\"><dict>\
         <key>Label</key><string>{label}</string>\
         <key>ProgramArguments</key><array><string>/bin/sleep</string><string>600</string></array>\
         <key>RunAtLoad</key><false/><key>KeepAlive</key><false/>\
         </dict></plist>\n"
    );
    std::fs::write(&job, document).expect("writes the job definition");
    let bootstrap = std::process::Command::new("/bin/launchctl")
        .args(["bootstrap", &domain, &job.display().to_string()])
        .output()
        .expect("runs the service manager");
    assert!(
        bootstrap.status.success(),
        "the job is bootstrapped into the graphical domain: {}",
        String::from_utf8_lossy(&bootstrap.stderr)
    );
    let started = std::process::Command::new("/bin/launchctl")
        .args(["kickstart", "-p", &format!("{domain}/{label}")])
        .output()
        .expect("runs the service manager");
    let printed = String::from_utf8_lossy(&started.stdout).into_owned();
    let pid = printed
        .split_whitespace()
        .rev()
        .find_map(|word| word.trim_end_matches('.').parse::<u32>().ok());
    let identity = pid.and_then(|pid| {
        // The job's own process, by identity rather than by identifier: this test ends only what
        // it started.
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            if let Ok(identity) = kr_ipc::identity::process_start_identity(pid) {
                return Some(identity);
            }
            if std::time::Instant::now() >= deadline {
                return None;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    });
    let identity = identity.expect("the service manager reported the process it started");
    assert_eq!(
        kr_ipc::identity::process_state(&identity),
        kr_ipc::identity::ProcessState::Running,
        "the job is running in the graphical domain"
    );

    // The teardown a logout performs on every job in the graphical domain, performed on this
    // test's own job and no other.
    let booted_out = std::process::Command::new("/bin/launchctl")
        .args(["bootout", &format!("{domain}/{label}")])
        .output()
        .expect("runs the service manager");
    assert!(
        booted_out.status.success(),
        "the job is booted out: {}",
        String::from_utf8_lossy(&booted_out.stderr)
    );
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        if kr_ipc::identity::process_state(&identity) == kr_ipc::identity::ProcessState::Ended {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "tearing the job down ended the process in it"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// KR-REQ-03.23: a transient locked or otherwise unavailable desktop is reported separately from
/// process life.
#[test]
fn a_locked_or_unavailable_desktop_is_reported_separately_from_process_life() {
    let boot = kr_ipc::identity::boot_identity().expect("a boot identity");
    // What this host measured, where it has a desktop to measure. macOS and Linux each publish a
    // lock state; a platform that publishes none says `unknown` rather than claiming the screen is
    // there for the taking.
    if let Some(live) = live_desktop() {
        assert!(
            matches!(
                live.availability,
                DesktopAvailability::Available
                    | DesktopAvailability::Locked
                    | DesktopAvailability::Background
                    | DesktopAvailability::Unknown
            ),
            "{:?}",
            live.availability
        );
        #[cfg(target_os = "macos")]
        assert_ne!(
            live.availability,
            DesktopAvailability::Unknown,
            "this platform publishes a lock state, so the reading is a measurement"
        );
    }
    let mut login = live_desktop().unwrap_or_else(desktop::Login::none);
    if !login.is_desktop() {
        // Stand in a reading for a host that has no desktop of its own, so the distinction is
        // still established here.
        login = desktop::Login {
            kind: DesktopSessionKind::LinuxLogind,
            platform_session: Some("2".to_owned()),
            generation: Some(7),
            generation_source: kr_protocol::desktop::DesktopGenerationSource::LinuxSessionLeader,
            anchor: None,
            graphic_access: true,
            remote: false,
            availability: DesktopAvailability::Available,
            display_server: DisplayServer::Wayland,
            compositor: Some("sway".to_owned()),
        };
    }
    for (availability, present) in [
        (DesktopAvailability::Available, true),
        (DesktopAvailability::Locked, true),
        (DesktopAvailability::Background, true),
        (DesktopAvailability::Ended, false),
    ] {
        let mut reading = login.clone();
        reading.availability = availability;
        let context = desktop::from_login(&reading, WorkerProfile::DesktopBound, boot.clone());
        assert_eq!(context.availability, availability);
        assert_eq!(
            context.availability.is_present(),
            present,
            "{} is the desktop's own state, not the session's",
            availability.as_str()
        );
        let report = desktop::capability::report(
            EnvironmentId::new(Uuid::from_bytes([1; 16])),
            None,
            context,
            CapabilityRevision::new(1),
        );
        let capture = report
            .record(capabilities::SCREEN_CAPTURE)
            .expect("a record per capability");
        if availability == DesktopAvailability::Locked {
            assert_eq!(
                capture.state,
                CapabilityState::TemporarilyUnavailable,
                "a locked desktop refuses the screen"
            );
            assert!(
                capture
                    .disabled_reason
                    .as_ref()
                    .is_some_and(|reason| reason.contains("processes it owns are unaffected")),
                "and says the session is unaffected"
            );
        }
    }
}

/// KR-REQ-03.23: a reboot ends the live executions of both profiles, and a boot identity that is
/// not this one closes them on startup with the reason that says so.
///
/// The boot is changed where the host records it, in its own state directory, which is the record
/// a real reboot leaves behind: a runtime directory and the descriptors in it are cleared with the
/// boot they belonged to, so a daemon that compared those would find nothing to compare after
/// exactly the event it was looking for.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_boot_that_is_not_this_one_closes_the_live_executions_of_both_profiles() {
    let host = Host::create();
    let first = host.start().await;
    let mut client = host.client().await;
    let headless = create(
        &mut client,
        &host,
        Presentation::Invisible,
        WorkerProfile::HeadlessUser,
    )
    .await;
    let bound = if has_desktop() {
        Some(
            create(
                &mut client,
                &host,
                Presentation::Invisible,
                WorkerProfile::DesktopBound,
            )
            .await,
        )
    } else {
        None
    };
    // Each worker's endpoint and recorded process are kept so this test can end what it started
    // and see that it ended: the workers themselves are still running afterwards, because this
    // test moved a record rather than a machine.
    let mut workers = Vec::new();
    for entry in kr_ipc::descriptor::read_all(&host.paths()).expect("reads the descriptors") {
        let descriptor = entry.descriptor.expect("a descriptor");
        workers.push((
            descriptor.session_id,
            descriptor.endpoint.clone(),
            descriptor.process_start_identity.clone(),
        ));
    }
    assert!(!workers.is_empty(), "the sessions published descriptors");
    drop(client);
    first.stop().await;

    let recorded = host
        .paths()
        .state_dir()
        .join(kr_controller::service::BOOT_FILE);
    assert!(
        recorded.exists(),
        "the daemon recorded the boot it was running in"
    );

    // A damaged record is a damaged record. This runs first, while the sessions are still live,
    // because what it establishes is that nothing was closed on the strength of one.
    kr_ipc::paths::write_owner_only_file(&recorded, b"not a boot identity").expect("writes");
    let damaged = host.start().await;
    let mut client = host.client().await;
    for session_id in [headless.session.session_id] {
        assert!(
            closed(&mut client, session_id).await.is_none(),
            "a damaged boot record closed a live session"
        );
    }
    let written = std::fs::read(&recorded).expect("reads the record");
    let named: kr_protocol::identity::BootIdentity =
        kr_cbor::from_canonical_slice(&written, &kr_cbor::Limits::DEFAULT)
            .expect("a damaged record is replaced with a good one");
    assert_eq!(
        named,
        kr_ipc::identity::boot_identity().expect("a boot identity"),
        "and the good one names the boot this host is running"
    );
    drop(client);
    damaged.stop().await;
    // A boot identity this host is not running, in the form the record holds: a damaged file is a
    // damaged file rather than evidence of a reboot, so the test writes a real one.
    let another = kr_protocol::identity::BootIdentity {
        source: kr_protocol::identity::BootIdentitySource::BootTime,
        value: kr_protocol::scalars::Bytes::new(b"a boot this host is not running".to_vec()),
    };
    let encoded = kr_cbor::to_canonical_vec(&another).expect("encodes");
    kr_ipc::paths::write_owner_only_file(&recorded, &encoded).expect("records another boot");

    let second = host.start().await;
    let mut client = host.client().await;
    let mut expected = vec![headless.session.session_id];
    if let Some(bound) = bound.as_ref() {
        expected.push(bound.session.session_id);
    }
    for session_id in expected {
        let summary = closed(&mut client, session_id)
            .await
            .expect("a session from an earlier boot is closed on startup");
        let closure = summary.closure.as_ref().expect("a closure record");
        assert_eq!(
            closure.reason,
            ClosureReason::HostShutdown,
            "the record says the host restarted"
        );
    }
    // And the record now names this boot, so a second start closes nothing again.
    let written = std::fs::read(&recorded).expect("reads the record");
    let named: kr_protocol::identity::BootIdentity =
        kr_cbor::from_canonical_slice(&written, &kr_cbor::Limits::DEFAULT).expect("decodes");
    assert_eq!(
        named,
        kr_ipc::identity::boot_identity().expect("a boot identity"),
        "the daemon recorded the boot it is actually running in"
    );

    drop(client);
    second.stop().await;

    for (session_id, endpoint, _) in &workers {
        let session_id = *session_id;
        let Ok(endpoint) = kr_ipc::paths::Endpoint::from_path(endpoint) else {
            continue;
        };
        let connected = tokio::time::timeout(
            WORKER_CALL_BOUND,
            LocalClient::connect(&endpoint, LocalClientKind::Cli, build()),
        )
        .await;
        let Ok(Ok(mut worker)) = connected else {
            continue;
        };
        let _ = tokio::time::timeout(
            WORKER_CALL_BOUND,
            worker.mutate(
                Method::SessionClose,
                ActionId::new(kr_ipc::new_uuid()),
                session_target(host.environment_id, session_id),
                &SessionCloseParams { session_id },
            ),
        )
        .await;
    }
    // What says a worker has gone is the kernel's answer about the process the descriptor recorded,
    // not an endpoint that stopped answering: a worker that dropped its socket and stayed would
    // pass that. This run started these processes, so it waits for each of them and says which
    // ones are left if they outlast the bound.
    let deadline = std::time::Instant::now() + WORKER_EXIT_DEADLINE;
    let mut running: Vec<String> = Vec::new();
    loop {
        running.clear();
        for (session_id, _, process) in &workers {
            if kr_ipc::identity::process_state(process) == kr_ipc::identity::ProcessState::Running {
                running.push(format!("{session_id} as {}", process.pid.get()));
            }
        }
        if running.is_empty() || std::time::Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        running.is_empty(),
        "workers this test started were still running {WORKER_EXIT_DEADLINE:?} after they were \
         asked to close: {}",
        running.join(", ")
    );
}

/// How long a worker this test closed is given to end.
const WORKER_EXIT_DEADLINE: Duration = Duration::from_secs(60);

/// How long one call to a worker this test is ending may take.
const WORKER_CALL_BOUND: Duration = Duration::from_secs(10);

/// KR-REQ-03.23: the desktop a session was created on outlives its worker, so a host that finds
/// the worker gone can say whether the desktop went with it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_desktop_a_session_was_created_on_is_readable_after_its_worker_has_gone() {
    let host = Host::create();
    let daemon = host.start().await;
    let mut client = host.client().await;
    let created = create(&mut client, &host, Presentation::Invisible, profile_here()).await;
    let session_id = created.session.session_id;
    close(&mut client, &host, session_id).await;

    // The worker's own journal, read the way a daemon reads it after the worker has gone.
    let journal =
        kr_worker::journal::Journal::open_read_only(host.paths().journal_database(session_id))
            .expect("the journal outlives the worker");
    let recorded = journal
        .read_session(session_id)
        .expect("the journal is readable")
        .expect("the worker recorded what its session was");
    assert_eq!(
        recorded.worker_profile, created.session.worker_profile,
        "the record says which execution context the session ran in"
    );
    assert_eq!(
        recorded.desktop.desktop_session_id, created.session.desktop.desktop_session_id,
        "and which desktop it was bound to, which is what a later daemon compares"
    );
    if profile_here() == WorkerProfile::DesktopBound {
        assert!(
            recorded.desktop.desktop_session_id.is_present(),
            "a desktop-bound session records the desktop it was created on"
        );
        let live = live_desktop().expect("this host has a desktop");
        assert_eq!(
            desktop::describes(&live, &recorded.desktop),
            Some(true),
            "and that record still describes the desktop this host is in"
        );
        // The question a host asks about a worker that has gone is about the login session that
        // worker was created on, asked of the platform by name. This desktop is still here, so the
        // answer is that it is present: the session ended for some other reason.
        assert_eq!(
            desktop::recorded_presence(&recorded.desktop),
            desktop::Presence::Present,
            "the recorded login session is still there, whatever became of its worker"
        );
        // A record naming a login session this platform does not have is that desktop gone, and it
        // is a different answer from the one above although the host and its desktop are the same.
        // The name is the recorded one with a session identifier no platform here hands out.
        let elsewhere = kr_protocol::identity::DesktopBinding {
            desktop_session_id: Nullable::some(
                kr_protocol::ids::DesktopSessionId::new(
                    recorded
                        .desktop
                        .desktop_session_id
                        .as_ref()
                        .expect("a name")
                        .as_str()
                        .replace(":session=", ":session=99"),
                )
                .expect("a name"),
            ),
            login_generation: recorded.desktop.login_generation,
        };
        assert_eq!(
            desktop::recorded_presence(&elsewhere),
            desktop::Presence::Ended,
            "a login session this platform does not have is one that has ended"
        );
    }
    daemon.stop().await;
}

/// KR-REQ-03.24, KR-REQ-07.59: a headless session is bound to no desktop and inherits none of a
/// desktop's handles, and this host reports whether its configured per-user service survives
/// logout rather than assuming it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_headless_session_inherits_no_graphical_access_and_logout_is_reported_per_platform() {
    let host = Host::create();
    let daemon = host.start().await;
    let mut client = host.client().await;
    let created = create(
        &mut client,
        &host,
        Presentation::Invisible,
        WorkerProfile::HeadlessUser,
    )
    .await;
    assert_eq!(created.session.worker_profile, WorkerProfile::HeadlessUser);
    assert!(
        !created.session.desktop.desktop_session_id.is_present(),
        "a headless session is bound to no desktop"
    );
    assert!(
        !created.session.desktop.login_generation.is_present(),
        "and to no login generation"
    );

    // The creator's own snapshot carried a display and a compositor socket. Neither reaches the
    // session: the execution context supplies those or nothing does.
    let context = kr_worker::environment::ExecutionContext::resolve(WorkerProfile::HeadlessUser);
    assert!(
        context.variables.is_empty(),
        "a headless context supplies no desktop variable"
    );
    let built = kr_worker::environment::build(
        &create_params(
            host.environment_id,
            host.temp.root(),
            Presentation::Invisible,
            WorkerProfile::HeadlessUser,
        )
        .environment_snapshot,
        &context,
        "/bin/sh",
        "0",
        created.session.session_id,
    );
    for name in kr_worker::environment::DESKTOP_VARIABLES {
        assert!(
            !built.variables.contains_key(*name),
            "{name} reached a headless session from the creator's snapshot"
        );
        assert!(
            built.removed.iter().any(|removed| removed == name)
                || !create_params(
                    host.environment_id,
                    host.temp.root(),
                    Presentation::Invisible,
                    WorkerProfile::HeadlessUser
                )
                .environment_snapshot
                .iter()
                .any(|variable| variable.name == *name),
            "{name} is removed rather than quietly dropped"
        );
    }

    // The launch context, not only the variables. A headless worker that was started inside the
    // graphical login would have that login's access however little of its environment it was
    // given, so the supervisor this host would use says which context each profile gets.
    let supervisor = kr_controller::supervision::detect().describe();
    #[cfg(target_os = "macos")]
    if has_desktop() {
        assert!(
            supervisor.contains("background") && supervisor.contains("graphical"),
            "the service manager starts the two profiles in different login contexts: {supervisor}"
        );
    }
    assert!(!supervisor.is_empty());

    // What logout does to each profile is this platform's answer, reported with the mechanism it
    // is about. A claim that a headless session survives logout has to name what makes it survive.
    let reported = kr_controller::desktop::persistence(&supervisor);
    let headless = reported
        .iter()
        .find(|entry| entry.profile == WorkerProfile::HeadlessUser)
        .expect("the headless profile is reported");
    assert!(!headless.mechanism.is_empty());
    assert!(!headless.detail.is_empty());
    match headless.persistence {
        LogoutPersistence::SurvivesLogout => assert!(
            headless.detail.to_ascii_lowercase().contains("linger"),
            "a survival claim names the explicit choice behind it: {}",
            headless.detail
        ),
        LogoutPersistence::AvailableByChoice => assert!(
            headless.detail.to_ascii_lowercase().contains("explicit"),
            "an available-by-choice answer says the choice is explicit: {}",
            headless.detail
        ),
        LogoutPersistence::NotEstablished => assert!(
            headless
                .detail
                .to_ascii_lowercase()
                .contains("not established"),
            "an answer this host has not established says so: {}",
            headless.detail
        ),
        LogoutPersistence::EndsAtLogout | LogoutPersistence::NoServiceManager => {}
    }
    let bound = reported
        .iter()
        .find(|entry| entry.profile == WorkerProfile::DesktopBound)
        .expect("the desktop profile is reported");
    assert_eq!(bound.persistence, LogoutPersistence::EndsAtLogout);
    assert!(bound.detail.contains("desktop_lost"));

    close(&mut client, &host, created.session.session_id).await;
    daemon.stop().await;
}

/// KR-REQ-03.25: the default execution context is this host's own, the create receipt records the
/// choice, and a lost desktop is never rebound to a new login.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_default_context_is_the_hosts_own_and_the_receipt_records_what_was_used() {
    let host = Host::create();
    let daemon = host.start().await;
    let mut client = host.client().await;

    // What the host says it will use, before anything is created.
    let info: HostInfoResult = client
        .request(Method::HostInfo, &())
        .await
        .expect("the call reaches the daemon")
        .expect("the read succeeds")
        .to_typed()
        .expect("decodes");
    assert_eq!(
        info.default_worker_profile,
        profile_here(),
        "a desktop host defaults to its desktop and a headless one to its user context"
    );

    // An invisible presentation is not an implicit headless mode: the receipt records the
    // execution context the host said it would use.
    let created = create(
        &mut client,
        &host,
        Presentation::Invisible,
        info.default_worker_profile,
    )
    .await;
    assert_eq!(created.session.worker_profile, info.default_worker_profile);
    if info.default_worker_profile == WorkerProfile::DesktopBound {
        assert!(
            created.session.desktop.desktop_session_id.is_present(),
            "the receipt records the desktop the session was bound to"
        );
    }

    // A lost desktop is never rebound. The watch answers for a session bound to a desktop that is
    // not this host's, and it goes on answering the same way however often it is asked.
    let mut watch = desktop::Watch::bind(
        WorkerProfile::DesktopBound,
        &DesktopBinding {
            desktop_session_id: Nullable::some(
                kr_protocol::ids::DesktopSessionId::new(
                    "macos_security_session:uid=0:session=0:generation=0:boot=00",
                )
                .expect("a name"),
            ),
            login_generation: Nullable::some(kr_protocol::scalars::U64::new(0)),
        },
    );
    let now = std::time::Instant::now();
    assert!(watch.lost(now));
    assert!(
        watch.lost(now + desktop::REREAD_INTERVAL * 4),
        "a new login is a different desktop and nothing is rebound to it"
    );

    close(&mut client, &host, created.session.session_id).await;
    daemon.stop().await;
}

/// Returns whether one entry of a method's authority is the automation right.
fn requires_automation(required: &kr_protocol::authority::RequiredRight) -> bool {
    matches!(
        required.authority,
        kr_protocol::authority::RequiredAuthority::Right {
            right: kr_protocol::rights::ActionRight::AutomationManage
        }
    )
}

/// KR-REQ-03.26: no method in the registry controls a desktop, and `automation.manage` is about
/// workflow definitions.
#[test]
fn no_method_in_the_registry_controls_a_desktop() {
    // A desktop-control surface would live in one of these namespaces. None of them exists,
    // because desktop automation means the user's own tools running in the selected context under
    // the permissions the operating system actually granted, not an interface this host offers.
    const CONTROL_NAMESPACES: &[&str] = &[
        "desktop.",
        "screen.",
        "display.",
        "pointer.",
        "mouse.",
        "keyboard.",
        "window.",
        "gui.",
        "app.",
        "ui.",
    ];
    for entry in REGISTRY {
        for namespace in CONTROL_NAMESPACES {
            assert!(
                !entry.name.starts_with(namespace),
                "{} is in the {namespace} namespace, and there is no such surface",
                entry.name
            );
        }
        // The only input any method carries is bytes to a session's own pseudo-terminal, under the
        // single input lease. That is not a desktop's keyboard, and there is nothing else.
        if entry.name.starts_with("input.") {
            assert!(
                matches!(
                    entry.name,
                    "input.acquire" | "input.release" | "input.interrupt" | "input.write"
                ),
                "{} is an input method outside the terminal lease surface",
                entry.name
            );
        }
        if entry.name.starts_with("terminal.") {
            assert!(
                matches!(
                    entry.name,
                    "terminal.resize" | "terminal.geometry.transfer" | "terminal.palette.set"
                ),
                "{} is a terminal method outside the geometry and palette surface",
                entry.name
            );
        }
        if entry.name.starts_with("input.") || entry.name.starts_with("terminal.") {
            assert!(
                !entry.required_rights.iter().any(requires_automation),
                "{} is a terminal method and does not borrow the automation right",
                entry.name
            );
        }
    }
    assert!(
        kr_protocol::rights::ActionRight::AutomationManage
            .as_str()
            .starts_with("automation."),
        "the automation right names automation"
    );
    // Every method that requires it is an automation definition or run, never a desktop action.
    for entry in REGISTRY {
        if entry.required_rights.iter().any(requires_automation) {
            assert!(
                entry.name.starts_with("automation.")
                    || entry.name.starts_with("workflow.")
                    || entry.name.starts_with("plugin.action."),
                "{} requires the automation right and is not an automation definition",
                entry.name
            );
        }
    }
}

/// KR-REQ-03.26, KR-REQ-03.22: a capability record per desktop in the shared shape, produced by
/// bounded disclosed probes; selecting a desktop alone never reports capture or injection as
/// available; and a container or WSL environment cannot control the desktop of the machine hosting
/// it.
#[test]
fn a_capability_record_per_desktop_says_what_produced_it_and_refuses_a_container() {
    let boot = kr_ipc::identity::boot_identity().expect("a boot identity");
    let environment_id = EnvironmentId::new(Uuid::from_bytes([2; 16]));
    let context = desktop::context(WorkerProfile::DesktopBound, boot.clone());
    let report = desktop::capability::report(
        environment_id,
        None,
        context.clone(),
        CapabilityRevision::new(3),
    );
    let names = [
        capabilities::ACCESSIBILITY,
        capabilities::APPLICATION_LAUNCH,
        capabilities::DISPLAY_SERVER,
        capabilities::INPUT_INJECTION,
        capabilities::SCREEN_CAPTURE,
    ];
    for name in names {
        let record = report.record(name).expect("a record per capability");
        assert_eq!(record.revision, CapabilityRevision::new(3));
        assert_eq!(record.subject.environment_id, environment_id);
        assert_eq!(
            record.subject.desktop_session_id, context.desktop_session_id,
            "the record names the desktop it is about"
        );
        assert!(
            record.state.is_available() || record.disabled_reason.is_present(),
            "{name} is either available or says why it is not"
        );
        assert!(
            !record.invalidation.is_empty(),
            "{name} says what makes it stale"
        );
    }
    for name in [capabilities::SCREEN_CAPTURE, capabilities::INPUT_INJECTION] {
        let record = report.record(name).expect("a record");
        assert!(
            !record.state.is_available(),
            "{name} was reported available on a desktop selection alone"
        );
        // What produced the answer depends on the platform: a refusal the platform itself
        // establishes is a platform query, and everything else is an answer nothing has run.
        assert!(
            matches!(
                record.evidence_source,
                CapabilityEvidenceSource::NotProbed | CapabilityEvidenceSource::PlatformQuery
            ),
            "{name} claims evidence nothing produced: {record:?}"
        );
        if record.evidence_source == CapabilityEvidenceSource::PlatformQuery {
            assert!(
                matches!(
                    record.state,
                    CapabilityState::PermissionRequired
                        | CapabilityState::MissingInstallation
                        | CapabilityState::TemporarilyUnavailable
                        | CapabilityState::Incompatible
                ),
                "a platform query can only refuse: {record:?}"
            );
        }
    }
    // The display server is its own answer, which on Linux distinguishes X11 from Wayland and
    // names the compositor beside it.
    let server = report
        .record(capabilities::DISPLAY_SERVER)
        .expect("a record");
    if context.is_desktop() {
        assert!(server.state.is_available());
        assert_ne!(context.display_server, DisplayServer::None);
    }

    // A container reaches no desktop, whatever a login session it can see says.
    for inside in [ContainerEnvironment::Container, ContainerEnvironment::Wsl] {
        let mut contained = desktop::from_login(
            &desktop::Login {
                kind: DesktopSessionKind::LinuxLogind,
                platform_session: Some("2".to_owned()),
                generation: Some(1),
                generation_source:
                    kr_protocol::desktop::DesktopGenerationSource::LinuxSessionLeader,
                anchor: None,
                graphic_access: true,
                remote: false,
                availability: DesktopAvailability::Available,
                display_server: DisplayServer::X11,
                compositor: Some("i3".to_owned()),
            },
            WorkerProfile::DesktopBound,
            boot.clone(),
        );
        contained.container = inside;
        let report = desktop::capability::report(
            environment_id,
            None,
            contained,
            CapabilityRevision::new(4),
        );
        for record in &report.records {
            assert!(
                !record.state.is_available(),
                "{} was available inside a {}",
                record.capability,
                inside.as_str()
            );
            assert!(
                record
                    .disabled_reason
                    .as_ref()
                    .is_some_and(|reason| reason.contains("machine hosting it")),
                "the answer says a container does not reach the parent desktop"
            );
        }
    }
    // And whatever this host is, the context it reports and the capabilities it answers agree
    // about it: a container or a distribution reaches no parent desktop, and a host reaches its
    // own.
    assert!(!ContainerEnvironment::Container.reaches_parent_desktop());
    assert!(!ContainerEnvironment::Wsl.reaches_parent_desktop());
    assert!(ContainerEnvironment::Host.reaches_parent_desktop());
    if !context.container.reaches_parent_desktop() {
        for record in &report.records {
            assert!(
                !record.state.is_available(),
                "{} was available inside a {}",
                record.capability,
                context.container.as_str()
            );
        }
    }
}

/// KR-REQ-03.27, KR-REQ-07.69: the power setting is off until it is chosen, appears in host status
/// with its reason, and a host's sleep policy is never changed silently.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_power_setting_is_off_until_chosen_and_host_status_reports_it() {
    let host = Host::create();
    let daemon = host.start().await;
    let mut client = host.client().await;

    let info: HostInfoResult = client
        .request(Method::HostInfo, &())
        .await
        .expect("the call reaches the daemon")
        .expect("the read succeeds")
        .to_typed()
        .expect("decodes");
    assert_eq!(
        info.power.setting,
        SleepInhibitionSetting::Off,
        "installing a host does not change its sleep policy"
    );
    assert!(!info.power.active, "and nothing is held");
    assert!(
        info.power.describe().contains("unchanged"),
        "host status says so in words: {}",
        info.power.describe()
    );
    assert!(
        !host.paths().state_dir().join(setting::FILE_NAME).exists(),
        "no setting file is created by starting a host"
    );

    // The owner's explicit choice, written the way the command writes it.
    kr_ipc::paths::write_owner_only_file(
        &host.paths().state_dir().join(setting::FILE_NAME),
        setting::document(SleepInhibitionSetting::MainsOnly).as_bytes(),
    )
    .expect("writes the setting");
    let info: HostInfoResult = client
        .request(Method::HostInfo, &())
        .await
        .expect("the call reaches the daemon")
        .expect("the read succeeds")
        .to_typed()
        .expect("decodes");
    assert_eq!(info.power.setting, SleepInhibitionSetting::MainsOnly);
    assert!(
        !info.power.active,
        "an enabled setting with nothing outstanding holds nothing"
    );
    assert!(
        info.power.withheld_reason.is_present(),
        "and says why: {}",
        info.power.describe()
    );

    // Turning it off again releases whatever was held and says the policy is unchanged.
    kr_ipc::paths::write_owner_only_file(
        &host.paths().state_dir().join(setting::FILE_NAME),
        setting::document(SleepInhibitionSetting::Off).as_bytes(),
    )
    .expect("writes the setting");
    let info: HostInfoResult = client
        .request(Method::HostInfo, &())
        .await
        .expect("the call reaches the daemon")
        .expect("the read succeeds")
        .to_typed()
        .expect("decodes");
    assert_eq!(info.power.setting, SleepInhibitionSetting::Off);
    assert!(!info.power.active);

    daemon.stop().await;
}

/// KR-REQ-03.27: the assertion is held only while verified foreground work or pending requests
/// exist, names its reason, and is released when that condition ends.
#[test]
fn an_assertion_is_held_for_admitted_work_and_released_when_it_ends() {
    let mut inhibitor = Inhibitor::new();
    // Work alone is not enough: the setting decides.
    let off = inhibitor.evaluate(
        SleepInhibitionSetting::Off,
        Demand {
            sessions_with_work: 2,
            pending_requests: 1,
        },
        PowerSource::Mains,
    );
    assert!(
        !off.active,
        "a host whose owner chose nothing holds nothing"
    );

    let held = inhibitor.evaluate(
        SleepInhibitionSetting::BatteryToo,
        Demand {
            sessions_with_work: 0,
            pending_requests: 1,
        },
        PowerSource::Battery,
    );
    // This platform has the facility, so an assertion is what the answer has to be.
    #[cfg(target_os = "macos")]
    assert!(
        held.active,
        "this platform holds power-management assertions: {held:?}"
    );
    if !held.active {
        // A platform with no assertion facility says so rather than claiming one.
        assert!(held.withheld_reason.is_present());
        return;
    }
    assert_eq!(
        held.reason.as_ref().copied(),
        Some(InhibitionReason::PendingRequests),
        "the reason is the condition that justified it"
    );
    assert!(
        held.holder.is_present(),
        "the assertion names itself so a person can find it in the platform's own listing"
    );
    assert!(held.describe().contains("sleep inhibited"));

    let released = inhibitor.evaluate(
        SleepInhibitionSetting::BatteryToo,
        Demand::default(),
        PowerSource::Battery,
    );
    assert!(
        !released.active,
        "the assertion is released when its condition ends"
    );

    // And a mains-only choice holds nothing on battery, or on a host that will not say.
    let mut inhibitor = Inhibitor::new();
    for source in [PowerSource::Battery, PowerSource::Unknown] {
        let state = inhibitor.evaluate(
            SleepInhibitionSetting::MainsOnly,
            Demand {
                sessions_with_work: 1,
                pending_requests: 0,
            },
            source,
        );
        assert!(
            !state.active,
            "mains-only held an assertion on {}",
            source.as_str()
        );
    }
}

/// KR-REQ-03.27: lid closure, forced sleep and an operating-system override are a possible loss of
/// reachability, and waking never revives expired authority.
#[test]
fn waking_from_a_suspension_does_not_revive_an_expired_action_window() {
    use kr_transport::clock::{ContinuousClock, ManualClock};
    use kr_transport::window::{ActionWindowIssuer, WindowRefusal};

    let clock = ManualClock::new();
    let shared: Arc<dyn ContinuousClock> = Arc::new(clock.clone());
    let issuer = ActionWindowIssuer::new(Arc::clone(&shared), Duration::from_secs(30));
    let connection_id = kr_protocol::ids::ConnectionId::new(kr_ipc::new_uuid());
    let boot_epoch =
        kr_ipc::identity::boot_epoch(&kr_ipc::identity::boot_identity().expect("a boot identity"))
            .expect("a boot epoch");
    let window = issuer
        .issue(connection_id, boot_epoch)
        .expect("a window is issued");
    assert!(
        issuer
            .validate(&window.action_window_id, connection_id, boot_epoch)
            .is_ok(),
        "the window admits a request while it is valid"
    );

    // The machine sleeps: a closed lid, a forced sleep, or a platform policy that overrode the
    // host's request not to. Every deadline is measured on the suspend-aware continuous clock, so
    // the time spent suspended is time spent.
    clock.advance(Duration::from_secs(3_600));
    assert_eq!(
        issuer.validate(&window.action_window_id, connection_id, boot_epoch),
        Err(WindowRefusal::Expired),
        "waking up does not bring an expired window back"
    );
    assert!(power::expired_at_wake(
        &shared,
        shared
            .now()
            .checked_add(Duration::ZERO)
            .expect("an instant")
    ));
}

/// KR-REQ-07.58, KR-REQ-07.69: per-user startup uses the platform's own service mechanism, the
/// worker it starts is outside the daemon's kill tree, and nothing about the host's sleep policy
/// changes as a side effect.
#[test]
fn per_user_startup_uses_the_platform_service_mechanism_and_changes_no_sleep_policy() {
    let supervisor = kr_controller::supervision::detect();
    let described = supervisor.describe();
    assert!(
        !described.is_empty(),
        "the host says which service mechanism starts its workers"
    );
    #[cfg(target_os = "macos")]
    assert!(
        described.contains("launchd") || described.contains("detached"),
        "{described}"
    );
    #[cfg(target_os = "linux")]
    assert!(
        described.contains("systemd") || described.contains("detached"),
        "{described}"
    );

    // What logout does to that mechanism is reported rather than assumed, and a claim that a
    // headless session survives logout names the configuration that makes it survive.
    let persistence = kr_controller::desktop::headless_persistence();
    assert!(!persistence.mechanism.is_empty());
    assert!(!persistence.detail.is_empty());
    if persistence.persistence == LogoutPersistence::SurvivesLogout {
        assert!(
            persistence.detail.to_ascii_lowercase().contains("linger"),
            "{}",
            persistence.detail
        );
    }
    #[cfg(target_os = "macos")]
    assert_eq!(
        persistence.persistence,
        LogoutPersistence::NotEstablished,
        "this platform's background domain outlives the graphical login and this host does not \
         read how long it lasts"
    );

    // Starting a host, and asking it anything, never writes a power setting.
    let host = kr_ipc::testing::TempHost::create();
    assert_eq!(
        power::read(&host.environment()),
        SleepInhibitionSetting::Off,
        "a host with no chosen setting inhibits nothing"
    );
    assert!(
        !host
            .environment()
            .state_dir()
            .join(setting::FILE_NAME)
            .exists(),
        "and no file was written to say otherwise"
    );
}
