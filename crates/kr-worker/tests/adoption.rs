//! Adoption, and the session's announcement of its agent instances.
//!
//! In most cases this test process plays the root shell. The program adoption finds is this test
//! binary, placed as `claude` and started with the one case below that only sleeps, as this
//! process's own child in a process group of its own, as a shell with job control starts a
//! foreground job. It is a copy of this binary rather than of a system program, because macOS stops
//! a copy of a system program from running, and a link to one would run under the system program's
//! own name. The watch's own cases run a session whose root shell is a POSIX shell with job
//! control, which starts the same program as a foreground job when a line is typed into it.
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-REQ-12.07 | a program the root shell ran that the integration did not launch is adopted as a native terminal instance with no process record, with the bypass its line was answered with, its bridges refused, and ended when it exits; a program the integration launched is not adopted; a view that installs the session's list and applies the announcements after it holds each instance once; the watch finds a program the root shell starts from a typed line within two seconds of it running, at once or after four silent seconds, and its end within two seconds of its exit, and looks when the integration asks about an invocation or reports a command starting |
//! | KR-PERF-003 | a session nothing is happening in reads its terminal's foreground on no more than one interval in four, less often the longer it stays quiet, before and after its own traffic, and after an adopted program has ended |

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

/// The variable that names a file the stand-in writes to once it is running: its process
/// identifier, and when it started on [`monotonic`], for a test that measures from that moment.
const STAND_IN_RUNNING: &str = "KR_ADOPTION_STAND_IN_RUNNING";

/// How long a test waits for something that should happen promptly, before it calls it a failure.
const LIVENESS: Duration = Duration::from_secs(60);

/// The stand-in program's body. Run by the test harness with nothing set, it does nothing.
#[test]
fn the_stand_in_program() {
    if let Ok(seconds) = std::env::var(STAND_IN) {
        if let Some(running) = std::env::var_os(STAND_IN_RUNNING) {
            let started = monotonic().as_nanos();
            std::fs::write(running, format!("{} {started}", std::process::id()))
                .expect("says it is running");
        }
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
    open_session(
        host,
        kr_worker::testing::posix_script("exec cat"),
        &[kr_protocol::attachment::AttachmentCapability::ObserveTerminal],
    )
}

/// The view every session in these tests is attached to.
const VIEW: kr_protocol::ids::AttachmentId =
    kr_protocol::ids::AttachmentId::new(Uuid::from_bytes([5; 16]));

/// A session whose root shell runs `shell`, with one view attached with `capabilities`, and that
/// view's own delivery stream.
fn open_session(
    host: &kr_ipc::testing::TempHost,
    shell: kr_worker::pty::ShellCommand,
    capabilities: &[kr_protocol::attachment::AttachmentCapability],
) -> (
    Arc<kr_worker::runtime::SessionRuntime>,
    kr_worker::output::OutputStream,
) {
    let mut requested = kr_protocol::scalars::CanonicalSet::new();
    for capability in capabilities {
        requested.insert(*capability);
    }
    let config = kr_worker::session::SessionConfig {
        session_id: session(),
        session_epoch: kr_protocol::ids::SessionEpoch::V1,
        environment_id: host.environment_id(),
        display_number: kr_protocol::session::DisplayNumber::new(1),
        shell,
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
    let params = kr_protocol::attachment::SessionAttachParams {
        session_id: session(),
        mode: kr_protocol::attachment::AttachMode::Terminal,
        claim_geometry: false,
        dimensions: Nullable::some(kr_protocol::session::Dimensions::new(80, 24)),
        terminal_profile_id: Nullable::some("xterm-256color".to_owned()),
        requested: requested.clone(),
    };
    opened.attach(&params, requested, VIEW).expect("attaches");
    let stream = opened.subscribe(VIEW).expect("subscribes");
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
    let group = foreground.group;
    let watching = tokio::spawn(kr_worker::broker::adoption::watch_foreground(
        Arc::clone(&adoptions),
        kr_worker::lifecycle::Activity::new(),
        move || Some(Some(group)),
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

/// How long after its latest traffic a session counts as one nothing is happening in.
const QUIET_AFTER: Duration = Duration::from_secs(4);

/// How many intervals a quiet session is watched for.
const QUIET_INTERVALS: u32 = 16;

/// The most foreground reads a quiet session may make in [`QUIET_INTERVALS`]: one in four.
const QUIET_READS: usize = 4;

/// A session whose one view holds the input lease, and the view's own delivery stream.
struct Typing {
    runtime: Arc<kr_worker::runtime::SessionRuntime>,
    epoch: u64,
    sequence: u64,
    _view: kr_worker::output::OutputStream,
}

impl Typing {
    /// Starts a session whose root shell runs `shell`, with a view that can type into it.
    fn start(host: &kr_ipc::testing::TempHost, shell: kr_worker::pty::ShellCommand) -> Self {
        let (runtime, view) = open_session(
            host,
            shell,
            &[
                kr_protocol::attachment::AttachmentCapability::ObserveTerminal,
                kr_protocol::attachment::AttachmentCapability::Input,
            ],
        );
        let epoch = {
            let mut session = runtime.session();
            session
                .acquire_input(
                    VIEW,
                    kr_protocol::ids::ConnectionId::new(kr_ipc::new_uuid()),
                    None,
                )
                .expect("takes the lease");
            session.lease().epoch.get()
        };
        Self {
            runtime,
            epoch,
            sequence: 0,
            _view: view,
        }
    }

    /// Types `bytes` into the terminal, as the view holding the lease does.
    fn type_in(&mut self, bytes: &[u8]) {
        self.runtime
            .session()
            .write_input(
                VIEW,
                self.epoch,
                self.sequence,
                bytes,
                None,
                std::time::Instant::now(),
            )
            .expect("the input is accepted");
        self.sequence += 1;
        self.runtime.flush_input();
    }

    /// How many times the terminal's foreground has been read.
    fn reads(&self) -> usize {
        self.runtime.session().foreground_reads().len()
    }

    /// Asserts that the session reads its foreground on no more than one interval in four over the
    /// next [`QUIET_INTERVALS`] intervals.
    ///
    /// From [`QUIET_AFTER`] on, the watch waits about a second and more between looks, a quarter of
    /// the time since the traffic, each wait longer than the one before, so it reads at most four
    /// times in these sixteen intervals; a watch on a clock reads on every interval. The window is
    /// fixed by the times the session recorded for its reads, so when this task wakes to count them
    /// changes nothing.
    async fn quiet(&self, what: &str) {
        let from = std::time::Instant::now();
        let until = from + kr_worker::broker::adoption::WATCH_INTERVAL * QUIET_INTERVALS;
        tokio::time::sleep_until(until.into()).await;
        let read = self
            .runtime
            .session()
            .foreground_reads()
            .into_iter()
            .filter(|at| *at > from && *at <= until)
            .count();
        assert!(
            read <= QUIET_READS,
            "{what} reads its foreground on no more than one interval in four: {read} reads in \
             {QUIET_INTERVALS} intervals"
        );
    }

    /// Closes the session and waits for it to have closed.
    async fn close(self) {
        let (_, gate) = self
            .runtime
            .close(kr_protocol::session::ClosureReason::CloseRequested);
        gate.release();
        tokio::time::timeout(LIVENESS, self.runtime.wait_closed())
            .await
            .expect("the session closes");
    }
}

/// Waits up to `limit` for `condition` to hold, and says whether it held by then.
///
/// A condition first seen to hold after the deadline counts as not holding by it, however late
/// this task was woken to look: a bound is a bound on when it held, not on when it was checked.
async fn within(limit: Duration, mut condition: impl FnMut() -> bool) -> bool {
    let deadline = tokio::time::Instant::now() + limit;
    loop {
        if condition() {
            return tokio::time::Instant::now() <= deadline;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// The system's monotonic clock, read the same way here and in the stand-in, so that a time one
/// process records can be compared with a time the other does.
fn monotonic() -> Duration {
    let now = rustix::time::clock_gettime(rustix::time::ClockId::Monotonic);
    Duration::new(
        u64::try_from(now.tv_sec).expect("a time after the clock's start"),
        u32::try_from(now.tv_nsec).expect("a fraction of a second"),
    )
}

/// KR-PERF-003 and KR-REQ-12.07: a session nothing is happening in does not read its terminal's
/// foreground on every interval. The watch looks often while the root shell starts and after the
/// session's own input and output, and less and less often the longer nothing happens.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kr_perf_003_an_idle_session_does_not_read_its_foreground_on_every_interval() {
    let setup = Setup::new();
    let mut typing = Typing::start(&setup.host, kr_worker::testing::posix_script("exec cat"));
    let adoptions = Arc::new(setup.adoptions);
    let watching = tokio::spawn(kr_worker::broker::adoption::watch(
        Arc::clone(&adoptions),
        Arc::downgrade(&typing.runtime),
    ));

    tokio::time::sleep(QUIET_AFTER).await;
    typing
        .quiet("a session nothing has happened in since its shell started")
        .await;

    // Its own input, and the output that comes of it, ask the watch to look again.
    let before = typing.reads();
    typing.type_in(b"kr-adoption-marker\n");
    assert!(
        within(Duration::from_secs(2), || typing.reads() > before).await,
        "the session's traffic asks the watch to look"
    );
    tokio::time::sleep(QUIET_AFTER).await;
    typing
        .quiet("the same session once its traffic has settled")
        .await;

    let _ = adoptions.close();
    tokio::time::timeout(LIVENESS, watching)
        .await
        .expect("the watch ends with the session's adoptions")
        .expect("joined");
    typing.close().await;
}

/// KR-REQ-12.07: a program the root shell starts from a line typed into the session, which the
/// integration did not launch, is found by the watch within two seconds of running and adopted,
/// its end is found within two seconds of its exit, and the session is quiet again after that. The
/// shell asks nothing, as a shell without the integration does, and runs the program as a job of
/// its own in the foreground, which neither reads nor writes the terminal.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kr_req_12_07_the_watch_adopts_a_program_the_root_shell_starts_from_a_typed_line() {
    adopts_from_a_typed_line("").await;
}

/// KR-REQ-12.07: the same when the line keeps the root shell busy for four seconds before it
/// starts the program, with the root shell's own group holding the terminal and nothing written:
/// the watch looks less often by then, and still finds the program within two seconds of running.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kr_req_12_07_the_watch_adopts_a_program_a_typed_line_starts_after_a_silent_delay() {
    adopts_from_a_typed_line("delay=$(sleep 4); ").await;
}

/// Types a line into a POSIX shell with job control that runs `before` and then the stand-in, and
/// holds the watch to its bounds.
async fn adopts_from_a_typed_line(before: &str) {
    let setup = Setup::new();
    let running = setup.host.root().join("running");
    let mut shell = kr_worker::testing::posix_script(&format!(
        "set -m; read line; {before}\"$KR_ADOPTION_PROGRAM\" --exact the_stand_in_program \
         --test-threads 1 </dev/null >/dev/null 2>&1; read line"
    ));
    shell.environment.extend([
        (
            "KR_ADOPTION_PROGRAM".to_owned(),
            setup.program.display().to_string(),
        ),
        (STAND_IN.to_owned(), "60".to_owned()),
        (STAND_IN_RUNNING.to_owned(), running.display().to_string()),
    ]);
    let mut typing = Typing::start(&setup.host, shell);
    let (arrived, release) = setup.adoptions.pause_before_reading();
    // Waiting before the program can start, so the moment the watch reaches it is taken as it
    // happens rather than whenever this test next looks.
    let reached = tokio::task::spawn_blocking(move || {
        arrived.recv_timeout(LIVENESS).ok().map(|()| monotonic())
    });
    let adoptions = Arc::new(setup.adoptions);
    let watching = tokio::spawn(kr_worker::broker::adoption::watch(
        Arc::clone(&adoptions),
        Arc::downgrade(&typing.runtime),
    ));
    tokio::time::sleep(QUIET_AFTER).await;

    typing.type_in(b"\n");
    let mut said = None;
    assert!(
        within(LIVENESS, || {
            said = std::fs::read_to_string(&running).ok().and_then(|text| {
                let (pid, started) = text.trim().split_once(' ')?;
                Some((pid.parse::<u32>().ok()?, started.parse::<u64>().ok()?))
            });
            said.is_some()
        })
        .await,
        "the root shell starts the program"
    );
    let (pid, started) = said.expect("the program says it is running");
    let started = Duration::from_nanos(started);
    let reached = reached
        .await
        .expect("joined")
        .expect("the watch reaches the program");
    let took = reached.saturating_sub(started);
    println!("the watch reached the program {took:?} after it started running");
    assert!(
        took <= Duration::from_secs(2),
        "the watch reaches the program within two seconds of it running: {took:?}"
    );
    // Let go, unless it has already gone on by itself.
    let _ = release.send(());
    let process = kr_ipc::identity::process_start_identity(pid).expect("the program is identified");
    assert!(
        within(LIVENESS, || adoptions.adopted(&process).is_some()).await,
        "the program is adopted"
    );
    let instance = adoptions.adopted(&process).expect("adopted");
    assert!(
        !setup.broker.holds_process(&process),
        "with no process record behind it"
    );

    let _ = rustix::process::kill_process(
        rustix::process::Pid::from_raw(i32::try_from(pid).expect("an identifier"))
            .expect("a process"),
        rustix::process::Signal::TERM,
    );
    assert!(
        within(Duration::from_secs(2), || setup
            .broker
            .binding_state(instance)
            .is_err())
        .await,
        "its end is found within two seconds of its exit"
    );
    assert_eq!(adoptions.adopted(&process), None);

    // The root shell has the terminal back and waits for its next line.
    tokio::time::sleep(QUIET_AFTER).await;
    typing
        .quiet("a session whose adopted program has ended")
        .await;

    let _ = adoptions.close();
    tokio::time::timeout(LIVENESS, watching)
        .await
        .expect("the watch ends with the session's adoptions")
        .expect("joined");
    typing.close().await;
}

/// KR-REQ-12.07: the invocation the shell's integration asks about and a command it reports
/// starting each ask the watch to look, without any input or output, and a command's end does not.
/// A program a line runs is looked for as the line starts.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kr_req_12_07_a_command_the_integration_reports_starting_asks_the_watch_to_look() {
    use kr_protocol::root::{CwdRevision, PromptGeneration, RootCommandBlockParams};
    use kr_worker::fence::{CommandHook, Effects, Step};

    let setup = Setup::new();
    let typing = Typing::start(&setup.host, kr_worker::testing::posix_script("exec cat"));
    let hook = |hook: CommandHook| {
        let _ = typing.runtime.session().apply_fence_effects(Effects {
            steps: vec![Step::CommandHook(
                kr_protocol::ids::RequestId::new(1),
                Box::new(hook),
            )],
            ..Effects::default()
        });
    };
    let block = |exit_status: Option<u64>| RootCommandBlockParams {
        session_id: session(),
        prompt_generation: PromptGeneration::new(1),
        command: "claude".to_owned(),
        started_at_ms: TimestampMs::new(1),
        duration_ms: Nullable(exit_status.map(|_| kr_protocol::scalars::DurationMs::new(1))),
        exit_status: Nullable(exit_status.map(U64::new)),
        cwd: "/".to_owned(),
        cwd_revision: CwdRevision::new(0),
    };

    // The marks themselves, read before any watch runs to take them: the root program neither
    // reads nor writes, so nothing else marks this session meanwhile.
    let activity = typing.runtime.session().activity();
    let _ = activity.take_foreground();
    hook(CommandHook::Resolve(
        kr_protocol::root::RootCommandResolveParams {
            session_id: session(),
            prompt_generation: PromptGeneration::new(1),
            argv: vec!["claude".to_owned()],
            executable: "/usr/local/bin/claude".to_owned(),
            interactive: true,
            cwd: "/".to_owned(),
            cwd_revision: CwdRevision::new(0),
        },
    ));
    assert!(activity.take_foreground(), "the invocation asked about");
    hook(CommandHook::Block(Box::new(block(None))));
    assert!(activity.take_foreground(), "a command starting");
    hook(CommandHook::Block(Box::new(block(Some(0)))));
    assert!(
        !activity.take_foreground(),
        "a command's end asks for nothing"
    );

    // And the watch they wake.
    let adoptions = Arc::new(setup.adoptions);
    let watching = tokio::spawn(kr_worker::broker::adoption::watch(
        Arc::clone(&adoptions),
        Arc::downgrade(&typing.runtime),
    ));
    tokio::time::sleep(QUIET_AFTER).await;
    typing.quiet("a session nothing has happened in").await;
    let before = typing.reads();
    hook(CommandHook::Block(Box::new(block(None))));
    assert!(
        within(Duration::from_secs(1), || typing.reads() > before).await,
        "a command starting asks the watch to look"
    );
    tokio::time::sleep(QUIET_AFTER).await;
    typing.quiet("the session after that command").await;

    let _ = adoptions.close();
    tokio::time::timeout(LIVENESS, watching)
        .await
        .expect("the watch ends with the session's adoptions")
        .expect("joined");
    typing.close().await;
}
