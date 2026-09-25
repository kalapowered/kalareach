//! Adoption, and the session's announcement of its agent instances.
//!
//! This test process plays the root shell. The program adoption finds is this test binary, placed
//! as `claude` and started with the one case below that only sleeps, as this process's own child
//! in a process group of its own, as a shell with job control starts a foreground job. It is a
//! copy of this binary rather than of a system program, because macOS stops a copy of a system
//! program from running, and a link to one would run under the system program's own name.
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-REQ-12.07 | a program the root shell ran that the integration did not launch is adopted as a native terminal instance with no process record, with the bypass its line was answered with, its bridges refused, and ended when it exits; a program the integration launched is not adopted; a view that installs the session's list and applies the announcements after it holds each instance once |

#![cfg(unix)]

use std::os::unix::process::CommandExt as _;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use kr_protocol::broker::IntegrationMode;
use kr_protocol::identity::ProcessStartIdentity;
use kr_protocol::ids::{ApplicationInstanceId, SessionId};
use kr_protocol::projection::{AgentInstanceEvent, AgentInstanceSummary};
use kr_protocol::root::CommandBypassReason;
use kr_protocol::scalars::{Digest256, Nullable, TimestampMs, U64, Uuid};
use kr_worker::broker::Broker;
use kr_worker::broker::adoption::{ADOPTED_REFUSAL, Adoptions, Foreground};
use kr_worker::broker::connectors::{ConnectorSources, fixture};
use kr_worker::broker::process::{BrokerTransport, Credential, ManagedProcess, TransportHandle};
use kr_worker::persistence::JournalHealth;

/// The variable that makes a placed copy of this binary the stand-in program: it sleeps for as
/// many seconds as it names.
const STAND_IN: &str = "KR_ADOPTION_STAND_IN";

/// How long a test waits for something that should happen promptly, before it calls it a failure.
const LIVENESS: Duration = Duration::from_secs(60);

/// The stand-in program's body. Run by the test harness with nothing set, it does nothing.
#[test]
fn the_stand_in_program() {
    if let Ok(seconds) = std::env::var(STAND_IN) {
        std::thread::sleep(Duration::from_secs(seconds.parse().unwrap_or(60)));
    }
}

fn session() -> SessionId {
    SessionId::new(Uuid::from_bytes([1; 16]))
}

/// A host tree with the Claude Code connector installed, the stand-in placed as `claude`, and one
/// session's adoptions on a broker of its own.
struct Setup {
    host: kr_ipc::testing::TempHost,
    broker: Arc<Broker>,
    adoptions: Adoptions,
    program: PathBuf,
    plugin_id: kr_protocol::ids::PluginId,
}

impl Setup {
    fn new() -> Self {
        let host = kr_ipc::testing::TempHost::create();
        let bin = host.root().join("bin");
        std::fs::create_dir_all(&bin).expect("a bin directory");
        let program = bin.join(fixture::COMMAND);
        kr_ipc::testing::place_program(
            &std::env::current_exe().expect("this test's own binary"),
            &program,
        );
        let store = host.root().join("store");
        std::fs::create_dir_all(&store).expect("a store");
        let sources = Arc::new(ConnectorSources::new());
        let source =
            fixture::claude_code_package(&store, &bin.join("kr-hook")).expect("the package");
        assert!(
            sources.replace(vec![source]).is_empty(),
            "the connector is installed"
        );
        let plugin_id = sources
            .for_command(fixture::COMMAND)
            .expect("the connector")
            .plugin_id();
        let broker = Arc::new(
            Broker::open(None, session(), JournalHealth::shared()).expect("the broker opens"),
        );
        let adoptions = Adoptions::new(Arc::clone(&broker), sources, host.environment_id());
        Self {
            host,
            broker,
            adoptions,
            program,
            plugin_id,
        }
    }

    /// Starts the stand-in as this process's own child, in a process group of its own.
    fn start(&self) -> Started {
        let child = Command::new(&self.program)
            .args(["--exact", "the_stand_in_program", "--test-threads", "1"])
            .env(STAND_IN, "60")
            .current_dir(self.host.root())
            .process_group(0)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("the stand-in starts");
        let process = kr_ipc::identity::process_start_identity(child.id())
            .expect("the stand-in is identified");
        Started { child, process }
    }

    /// What the session would read with the stand-in in the foreground.
    fn foreground(
        started: &Started,
        answered: Vec<(String, Option<CommandBypassReason>)>,
    ) -> Foreground {
        Foreground {
            group: i32::try_from(started.child.id()).expect("a process identifier"),
            root_shell: kr_ipc::identity::current_process_start_identity().expect("this process"),
            answered,
        }
    }

    /// Looks until the stand-in is adopted: a program at a new path can take a while to start.
    fn adopt(&self, foreground: &Foreground) -> Vec<AgentInstanceSummary> {
        let started = std::time::Instant::now();
        loop {
            let told = self.adoptions.look(foreground);
            if !told.is_empty() || started.elapsed() > LIVENESS {
                return told;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

/// The stand-in, running.
struct Started {
    child: Child,
    process: ProcessStartIdentity,
}

impl Started {
    fn end(mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// KR-REQ-12.07: a program the root shell ran that the integration did not launch is recorded as
/// a native terminal instance with the profile it was observed running, and nothing else: no
/// process record, so nothing a bridge could authenticate against, and an announcement that says
/// its bridges are refused. It is adopted once, and ended when it exits.
#[test]
fn kr_req_12_07_a_program_the_integration_did_not_launch_is_adopted_without_a_launch_record() {
    let setup = Setup::new();
    let started = setup.start();
    let foreground = Setup::foreground(&started, Vec::new());

    let told = setup.adopt(&foreground);
    assert_eq!(told.len(), 1, "the stand-in is adopted: {told:?}");
    let summary = &told[0];
    assert_eq!(summary.mode, IntegrationMode::NativeTerminal);
    assert_eq!(summary.plugin_id.as_ref(), Some(&setup.plugin_id));
    assert!(
        summary.bypass.as_ref().is_none(),
        "its line was not answered"
    );
    assert!(!summary.ended_at.is_present());
    assert_eq!(
        summary.refusal.as_ref().map(String::as_str),
        Some(ADOPTED_REFUSAL)
    );
    let instance = summary.application_instance_id;
    assert_eq!(setup.adoptions.adopted(&started.process), Some(instance));

    assert!(
        !setup.broker.holds_process(&started.process),
        "an adopted program has no process record, so no launch stands behind it"
    );
    let profile = setup
        .broker
        .profile_of(instance)
        .expect("the profile it was observed running");
    assert_eq!(profile.mode, IntegrationMode::NativeTerminal);
    assert_eq!(
        summary.profile_id.as_ref(),
        Some(&profile.profile_id),
        "the announcement names the recorded profile"
    );
    assert!(
        profile.binary.resolved_path.ends_with("/claude"),
        "the kernel's executable: {}",
        profile.binary.resolved_path
    );
    assert_eq!(
        profile.arguments.get(1..),
        Some(
            &[
                "--exact".to_owned(),
                "the_stand_in_program".to_owned(),
                "--test-threads".to_owned(),
                "1".to_owned()
            ][..]
        ),
        "the kernel's argument vector"
    );
    assert!(setup.broker.binding_state(instance).is_ok());

    assert!(
        setup.adoptions.look(&foreground).is_empty(),
        "a program is adopted once"
    );
    assert!(setup.adoptions.sweep().is_empty(), "it is still running");

    started.end();
    let ended = setup.adoptions.sweep();
    assert_eq!(ended.len(), 1, "its end is announced: {ended:?}");
    assert_eq!(ended[0].application_instance_id, instance);
    assert!(ended[0].ended_at.is_present());
    assert!(
        setup.broker.binding_state(instance).is_err(),
        "the instance ended with its program"
    );
}

/// KR-REQ-12.07: a program the shell ran as typed is adopted with the reason its line was
/// answered with, matched to the file the kernel reports however the shell named it.
#[test]
fn kr_req_12_07_an_adopted_program_carries_the_bypass_its_line_was_answered_with() {
    let setup = Setup::new();
    let started = setup.start();
    let named = setup.host.root().join("named-claude");
    std::os::unix::fs::symlink(&setup.program, &named).expect("the name the shell found");
    let foreground = Setup::foreground(
        &started,
        vec![
            ("/nowhere/claude".to_owned(), None),
            (
                named.display().to_string(),
                Some(CommandBypassReason::AbsolutePath),
            ),
        ],
    );
    let told = setup.adopt(&foreground);
    assert_eq!(told.len(), 1, "the stand-in is adopted: {told:?}");
    assert_eq!(
        told[0].bypass.as_ref(),
        Some(&CommandBypassReason::AbsolutePath)
    );
    started.end();
}

/// KR-REQ-12.07: a program the integration launched is not adopted as well. The launch registered
/// the process that presented itself, and that process keeps its identity when it execs the
/// program, so the broker already holds it.
#[test]
fn kr_req_12_07_a_program_the_integration_launched_is_not_adopted() {
    let setup = Setup::new();
    let started = setup.start();
    let launched = ApplicationInstanceId::new(Uuid::from_bytes([7; 16]));
    setup
        .broker
        .register_instance(
            launched,
            IntegrationMode::NativeBridge,
            None,
            Some(ManagedProcess::new(
                launched,
                started.process.clone(),
                TransportHandle {
                    transport: BrokerTransport::PrivateSocket,
                    application_instance_id: launched,
                    executable_digest: Digest256::from_bytes([3; 32]),
                    process: started.process.clone(),
                },
                Credential::from_bytes([9; 32]),
                false,
                TimestampMs::new(1),
            )),
        )
        .expect("the launch registered its process");
    let foreground = Setup::foreground(&started, Vec::new());

    // Long enough for the program to have started, which an adoption would need.
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while std::time::Instant::now() < deadline {
        assert!(
            setup.adoptions.look(&foreground).is_empty(),
            "a launched program is not adopted"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(setup.adoptions.adopted(&started.process), None);
    started.end();
}

/// A session with one attached view, and that view's own delivery stream.
fn session_and_view(
    host: &kr_ipc::testing::TempHost,
) -> (
    Arc<kr_worker::runtime::SessionRuntime>,
    kr_worker::output::OutputStream,
) {
    let mut requested = kr_protocol::scalars::CanonicalSet::new();
    requested.insert(kr_protocol::attachment::AttachmentCapability::ObserveTerminal);
    let config = kr_worker::session::SessionConfig {
        session_id: session(),
        session_epoch: kr_protocol::ids::SessionEpoch::V1,
        environment_id: host.environment_id(),
        display_number: kr_protocol::session::DisplayNumber::new(1),
        shell: kr_worker::testing::posix_script("exec cat"),
        shell_mode: kr_protocol::session::ShellMode::NativeCompat,
        worker_profile: kr_protocol::identity::WorkerProfile::HeadlessUser,
        desktop: kr_protocol::identity::DesktopBinding::none(),
        dimensions: kr_protocol::session::Dimensions::new(80, 24),
        journal_path: Some(host.environment().journal_database(session())),
        spool_directory: Some(host.environment().session_spool(session())),
        worker_endpoint: None,
        send_queue_bytes: 8 * 1024 * 1024,
        resident_bytes: 1024 * 1024,
        time: kr_worker::action::time::TimeSources::system(),
        launch_profile: kr_protocol::session::LaunchProfile::default(),
    };
    let mut opened = kr_worker::session::Session::open(config).expect("opens");
    opened.launch().expect("launches");
    let attachment_id = kr_protocol::ids::AttachmentId::new(Uuid::from_bytes([5; 16]));
    let params = kr_protocol::attachment::SessionAttachParams {
        session_id: session(),
        mode: kr_protocol::attachment::AttachMode::Terminal,
        claim_geometry: false,
        dimensions: Nullable::some(kr_protocol::session::Dimensions::new(80, 24)),
        terminal_profile_id: Nullable::some("xterm-256color".to_owned()),
        requested: requested.clone(),
    };
    opened
        .attach(&params, requested, attachment_id)
        .expect("attaches");
    let stream = opened.subscribe(attachment_id).expect("subscribes");
    let runtime = Arc::new(
        kr_worker::runtime::SessionRuntime::start(
            opened,
            Arc::new(kr_ipc::clock::SystemSharedClock),
        )
        .expect("starts"),
    );
    (runtime, stream)
}

/// One instance, as a launch or an adoption would announce it.
fn summary(number: u8) -> AgentInstanceSummary {
    AgentInstanceSummary {
        application_instance_id: ApplicationInstanceId::new(Uuid::from_bytes([number; 16])),
        plugin_id: Nullable::null(),
        profile_id: Nullable::null(),
        mode: IntegrationMode::NativeTerminal,
        bypass: Nullable::null(),
        started_at: TimestampMs::new(u64::from(number)),
        ended_at: Nullable::null(),
        refusal: Nullable::null(),
    }
}

/// The next announcement the view is sent, or none within a short wait.
async fn next_announcement(
    view: &mut kr_worker::output::OutputStream,
) -> Option<AgentInstanceEvent> {
    loop {
        match tokio::time::timeout(Duration::from_secs(2), view.recv()).await {
            Ok(Some(kr_worker::output::OutputDelivery::AgentInstance { event, bytes })) => {
                view.written(bytes);
                return Some(*event);
            }
            Ok(Some(delivery)) => view.written(delivery.len()),
            Ok(None) | Err(_) => return None,
        }
    }
}

/// What a view holds after it installs a list and applies the announcements above its sequence.
fn apply(
    list: &kr_protocol::projection::AgentInstanceList,
    events: &[AgentInstanceEvent],
) -> Vec<AgentInstanceSummary> {
    let mut held = list.instances.clone();
    for event in events {
        if event.sequence.get() <= list.sequence.get() {
            continue;
        }
        if event.instance.ended_at.is_present() {
            held.retain(|instance| {
                instance.application_instance_id != event.instance.application_instance_id
            });
        } else {
            held.push(event.instance.clone());
        }
    }
    held
}

/// KR-REQ-12.07: the session counts, keeps and publishes its announcements under one lock, so a
/// list taken between two announcements carries the first, and a view that installs it and applies
/// the announcements above its sequence ends with both, each once, and without one that ended.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kr_req_12_07_a_list_and_the_announcements_after_it_hold_each_instance_once() {
    let host = kr_ipc::testing::TempHost::create();
    let (runtime, mut view) = session_and_view(&host);

    runtime.session().announce_instance(summary(1));
    let resynchronised = runtime
        .session()
        .snapshot(kr_protocol::projection::AgentResourceSnapshot {
            snapshot_id: U64::ZERO,
            stream_generation: U64::ZERO,
            cursor: U64::ZERO,
            resources: Vec::new(),
            continue_after: Nullable::null(),
        })
        .agent_instances;
    runtime.session().announce_instance(summary(2));

    // The view was subscribed before either, so both are in its stream.
    let mut events = Vec::new();
    while let Some(event) = next_announcement(&mut view).await {
        events.push(event);
        if events.len() == 2 {
            break;
        }
    }
    assert_eq!(events.len(), 2, "both announcements reach the view");
    assert!(events[0].sequence.get() < events[1].sequence.get());
    assert_eq!(events[0].session_id, session());
    assert_eq!(resynchronised.instances, vec![summary(1)]);
    assert_eq!(
        apply(&resynchronised, &events),
        vec![summary(1), summary(2)],
        "each instance once"
    );

    // An instance that ends leaves the list, and a view applying its end drops it.
    let mut ended = summary(1);
    ended.ended_at = Nullable::some(TimestampMs::new(9));
    runtime.session().announce_instance(ended);
    let last = next_announcement(&mut view)
        .await
        .expect("the end reaches the view");
    events.push(last);
    let now = runtime.session().agent_instances();
    assert_eq!(now.instances, vec![summary(2)]);
    assert_eq!(apply(&resynchronised, &events), vec![summary(2)]);
    assert_eq!(apply(&now, &events), vec![summary(2)]);
}

/// KR-REQ-12.07: the watch ends an adopted program that exited at its next tick while another
/// program's image is still being read, since an identification runs on a thread of its own and
/// no tick waits for it; and a session that closes meanwhile ends every adoption, after which that
/// identification records nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kr_req_12_07_a_slow_identification_holds_no_end_and_adopts_nothing_after_the_close() {
    let setup = Setup::new();
    let first = setup.start();
    let told = setup.adopt(&Setup::foreground(&first, Vec::new()));
    assert_eq!(told.len(), 1, "the first program is adopted");
    let first_instance = told[0].application_instance_id;

    let second = setup.start();
    let second_process = second.process.clone();
    let (arrived, release) = setup.adoptions.pause_before_reading();
    let adoptions = Arc::new(setup.adoptions);
    let foreground = Setup::foreground(&second, Vec::new());
    let watching = tokio::spawn(kr_worker::broker::adoption::watch_foreground(
        Arc::clone(&adoptions),
        move || Some(Some(foreground.clone())),
    ));
    tokio::task::spawn_blocking(move || arrived.recv_timeout(LIVENESS))
        .await
        .expect("joined")
        .expect("the second program's image read is reached");

    first.end();
    let ended = tokio::time::timeout(Duration::from_secs(2), async {
        while setup.broker.binding_state(first_instance).is_ok() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    assert!(
        ended.is_ok(),
        "the first program's end is found while the second's image is being read"
    );

    let closed = adoptions.close();
    assert!(
        closed.is_empty(),
        "nothing else was adopted when the session closed: {closed:?}"
    );
    release.send(()).expect("the reading is let go");
    tokio::time::timeout(LIVENESS, watching)
        .await
        .expect("the watch ends with the session")
        .expect("joined");
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        adoptions.adopted(&second_process),
        None,
        "an identification that finished after the close records nothing"
    );
    second.end();
}
