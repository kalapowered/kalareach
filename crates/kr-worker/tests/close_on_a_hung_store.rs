//! KR-REQ-07.57: an authorised stop is not kept from happening by a storage call that does not
//! return.
//!
//! The worker is the real service on its real socket, with a real shell, and the journal's own
//! stall seams hold one storage call where a disk that has stopped answering would hold it. Each
//! case closes the session while that call stands, and records what the person gets and after how
//! long: the close's answer, the graceful request reaching the shell, the shell ending, the closure
//! being recorded and a second close being answered. The stall is let go after a bound of the
//! case's own, so a close that never comes is ended by that bound and not by the suite, and what
//! the let-go brings is recorded too.
//!
//! A case passes when the stop happens within the times section 7 gives it: five seconds of grace
//! and two of drain, with an answer inside the seven seconds the daemon's close allows in all.
//!
//! The cases of a read of a held session hold the session where a storage call would, and read it
//! from another connection. The read answers within its bound and says the state the session is in:
//! for a close that was admitted a moment before the summary the session published says so, the
//! state comes from the input domain. Each of them has a control in which nothing holds the session
//! and the read is the one that takes it.

#![cfg(unix)]

use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use kr_ipc::client::LocalClient;
use kr_ipc::clock::SharedClock as _;
use kr_ipc::endpoint::Listener;
use kr_ipc::identity::{ProcessState, process_state};
use kr_ipc::verify::{ControllerIdentity, WorkerIdentity};
use kr_protocol::broker::IntegrationMode;
use kr_protocol::envelope::ActionTarget;
use kr_protocol::gateway::NativeFraming;
use kr_protocol::hello::PROTOCOL_VERSION;
use kr_protocol::identity::{
    DesktopBinding, ProcessStartIdentity, ProcessStartSource, WorkerProfile,
};
use kr_protocol::ids::{
    ActionId, ApplicationInstanceId, BrokerBindingId, BuildId, ConnectionId, ControllerGeneration,
    EnvironmentId, InputLeaseEpoch, SessionEpoch, SessionId,
};
use kr_protocol::local::LocalClientKind;
use kr_protocol::method::Method;
use kr_protocol::scalars::{Digest256, Nullable, TimestampMs, Uuid};
use kr_protocol::session::{
    ApplicationState, Dimensions, DisplayNumber, SessionCloseParams, SessionCloseResult,
    SessionReadParams, SessionReadResult, SessionState, ShellMode,
};
use kr_shell_integration::contract::fence::LeaseView;
use kr_shell_integration::contract::requests::LaunchTransactionId;
use kr_worker::application::{Holder, Producer};
use kr_worker::broker::binder::MatchedExecutable;
use kr_worker::broker::catalogue::{Admissions, testing};
use kr_worker::broker::connectors::{
    ConnectorSources, InstalledConnector, QualifiedExecutable, fixture,
};
use kr_worker::broker::{
    BrokerTransport, Carried, Credential, Duplex, Framing, ManagedProcess, TransportHandle,
};
use kr_worker::fence::FenceDriver;
use kr_worker::published::TAKE_BOUND;
use kr_worker::runtime::SessionRuntime;
use kr_worker::service::{ServiceBinding, WorkerService};
use kr_worker::session::{Session, SessionConfig};
use tokio::io::AsyncReadExt as _;

/// What a person waits for the answer to a close: the whole exchange the daemon allows.
const ANSWER_BOUND: Duration = Duration::from_secs(7);
/// The grace section 7 gives the session's processes, and the drain it gives output.
const GRACE: Duration = Duration::from_secs(5);
const DRAIN: Duration = Duration::from_secs(2);
/// What a loaded machine may add to a step that has no wait of its own.
const SLACK: Duration = Duration::from_secs(3);
/// How long a case watches a stall that stands, from the first close, before it lets it go.
const WINDOW: Duration = Duration::from_secs(17);
/// How long a case watches for what the let-go brings.
const AFTER_LET_GO: Duration = Duration::from_secs(25);
/// How long a case waits for its work to reach its stall.
const REACH: Duration = Duration::from_secs(20);
/// What a loaded gate machine may add to a read's bound: the round trip on the local socket and the
/// steps of the take, which the bound does not count. A read that took longer than the bound and
/// this has waited for the session, whatever it was held by.
const MARGIN: Duration = Duration::from_secs(2);
/// How long a case allows a read of a held session: the take's bound and the margin. Each of those
/// cases waits no longer, so that a read that waits for the session ends the case by an assertion
/// and not by the runner's limit.
const READ_BOUND: Duration = TAKE_BOUND.saturating_add(MARGIN);
/// How long a case waits for a session that was asked to stop to record its closure.
const CLOSURE_WAIT: Duration = Duration::from_secs(20);
/// How long a case waits for a question that was asked to run out of time on the loop's own timer,
/// which is fifteen seconds.
const QUESTION_WAIT: Duration = Duration::from_secs(30);
/// How long a question that a case moves the clock for lives: an hour, on the session's clock and
/// on the wall clock, so that only the case's move of the session's clock makes it due.
const QUESTION_EXPIRY_MS: u64 = 3_600_000;

fn build() -> BuildId {
    BuildId::new("kr-test/0").expect("a build identifier")
}

struct Host {
    service: Arc<WorkerService>,
    runtime: Arc<SessionRuntime>,
    session_id: SessionId,
    environment_id: EnvironmentId,
    endpoint: kr_ipc::paths::Endpoint,
    /// The files the shell writes: when it is ready, and when it was asked to stop.
    marks: tempfile::TempDir,
    // Ends the serving task when the fixture is dropped, whether or not a case closed it.
    _serving: kr_ipc::testing::Serving,
    // Declared last: the directory is removed after every field above has let go of its files.
    _temp: kr_ipc::testing::TempHost,
}

impl Drop for Host {
    /// Stops the shell this fixture started, however the case ended.
    fn drop(&mut self) {
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = self.runtime.session().force_close();
        }));
    }
}

impl Host {
    fn ready(&self) -> std::path::PathBuf {
        self.marks.path().join("ready")
    }

    fn asked(&self) -> std::path::PathBuf {
        self.marks.path().join("asked")
    }

    fn target(&self) -> ActionTarget {
        ActionTarget {
            environment_id: self.environment_id,
            session_id: Nullable::some(self.session_id),
            session_epoch: Nullable::some(SessionEpoch::V1),
            application_instance_id: Nullable::null(),
            agent_binding_revision: Nullable::null(),
        }
    }

    async fn client(&self) -> LocalClient {
        LocalClient::connect(&self.endpoint, LocalClientKind::Cli, build())
            .await
            .expect("connects")
    }
}

/// A session whose shell notes the request to stop and goes on, so the graceful request and the
/// force that follows it are told apart.
async fn host() -> Host {
    host_of(false).await
}

/// A session whose shell ends when it is asked to stop, or one that notes the request and goes on.
async fn host_of(ends_when_asked: bool) -> Host {
    host_on(ends_when_asked, Arc::new(kr_ipc::clock::SystemSharedClock)).await
}

/// As [`host`], for a session whose runtime reads the continuous clock `clock`, which a case may
/// move by hand: a question's deadline on that clock passes when the case moves it.
async fn host_on_a_clock(clock: &kr_ipc::clock::ManualSharedClock) -> Host {
    host_on(false, Arc::new(clock.clone())).await
}

async fn host_on(ends_when_asked: bool, shared_clock: Arc<dyn kr_ipc::clock::SharedClock>) -> Host {
    let marks = tempfile::tempdir().expect("a directory on the internal disk");
    let ready = kr_worker::testing::shell_quoted(&marks.path().join("ready"));
    let script = if ends_when_asked {
        format!("touch {ready}; while true; do sleep 1; done")
    } else {
        format!(
            "trap 'echo TERM >> {asked}' TERM; trap 'echo HUP >> {asked}' HUP; \
             trap 'echo INT >> {asked}' INT; touch {ready}; while true; do sleep 1; done",
            asked = kr_worker::testing::shell_quoted(&marks.path().join("asked")),
        )
    };
    let temp = kr_ipc::testing::TempHost::create();
    let environment = temp.environment();
    let environment_id = temp.environment_id();
    let session_id = SessionId::new(kr_ipc::new_uuid());
    let boot = kr_ipc::identity::boot_identity().expect("a boot identity");
    let process = kr_ipc::identity::current_process_start_identity().expect("a process identity");
    let identity = Arc::new(
        WorkerIdentity::generate(
            session_id,
            SessionEpoch::V1,
            boot.clone(),
            process,
            PROTOCOL_VERSION,
        )
        .expect("a session key"),
    );
    let store =
        kr_crypto::store::open_store_in(&environment.secrets_dir()).expect("a secret store");
    let controller = Arc::new(
        ControllerIdentity::initialise(store.store.as_ref(), environment_id)
            .expect("a controller identity"),
    );
    let journal_path = environment.journal_database(session_id);
    if let Some(parent) = journal_path.parent() {
        std::fs::create_dir_all(parent).expect("the journal directory");
    }
    let config = SessionConfig {
        session_id,
        session_epoch: SessionEpoch::V1,
        environment_id,
        display_number: DisplayNumber::new(1),
        shell: kr_worker::testing::posix_script(&script),
        shell_mode: ShellMode::NativeCompat,
        worker_profile: WorkerProfile::HeadlessUser,
        launch_profile: kr_protocol::session::LaunchProfile::default(),
        worker_endpoint: None,
        desktop: DesktopBinding::none(),
        dimensions: Dimensions::new(80, 24),
        journal_path: Some(journal_path.clone()),
        spool_directory: Some(environment.session_spool(session_id)),
        send_queue_bytes: 1024 * 1024,
        resident_bytes: 64 * 1024,
        time: kr_worker::action::time::TimeSources::system(),
    };
    let mut session = Session::open(config).expect("opens the session");
    session.launch().expect("launches the shell");
    let runtime =
        Arc::new(SessionRuntime::start(session, shared_clock).expect("starts the runtime"));
    let endpoint = environment
        .worker_endpoint(DisplayNumber::new(1))
        .expect("an endpoint");
    let listener = Listener::bind(&endpoint).expect("binds the endpoint");
    let service = Arc::new(
        WorkerService::new(
            Arc::clone(&runtime),
            identity,
            endpoint.clone(),
            ServiceBinding {
                environment_id,
                boot_identity: boot,
                controller_public_key: *controller.public_key(),
                controller_generation: ControllerGeneration::new(1),
                journal_path: Some(journal_path),
                build_id: build(),
            },
        )
        .expect("a worker service"),
    );
    let serving = kr_ipc::testing::Serving::spawn(Arc::clone(&service).serve(listener));
    let host = Host {
        service,
        runtime,
        session_id,
        environment_id,
        endpoint,
        marks,
        _serving: serving,
        _temp: temp,
    };
    let started = Instant::now();
    while !host.ready().exists() {
        assert!(
            started.elapsed() < Duration::from_secs(30),
            "the shell never said it was ready"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    host
}

fn attach_params(session_id: SessionId) -> kr_protocol::attachment::SessionAttachParams {
    let mut requested = kr_protocol::scalars::CanonicalSet::new();
    requested.insert(kr_protocol::attachment::AttachmentCapability::ObserveTerminal);
    requested.insert(kr_protocol::attachment::AttachmentCapability::Input);
    kr_protocol::attachment::SessionAttachParams {
        session_id,
        mode: kr_protocol::attachment::AttachMode::Terminal,
        claim_geometry: false,
        dimensions: Nullable::some(Dimensions::new(80, 24)),
        terminal_profile_id: Nullable::some("xterm-256color".to_owned()),
        requested,
    }
}

/// What a close was answered, and after how long counted from its own send.
type Answer = (Duration, Result<SessionCloseResult, String>);
type Slot = Arc<std::sync::Mutex<Option<Answer>>>;

/// Sends a close on `client` and records its answer in the slot it returns. It keeps no bound of
/// its own: the case that spawned it decides how long to look.
fn send_close(host: &Host, mut client: LocalClient) -> Slot {
    let slot: Slot = Arc::new(std::sync::Mutex::new(None));
    let (target, session_id) = (host.target(), host.session_id);
    let answered = Arc::clone(&slot);
    let sent = Instant::now();
    tokio::spawn(async move {
        let outcome = client
            .mutate(
                Method::SessionClose,
                ActionId::new(kr_ipc::new_uuid()),
                target,
                &SessionCloseParams { session_id },
            )
            .await;
        let result = match outcome {
            Ok(Ok(value)) => value.to_typed().map_err(|error| format!("{error}")),
            Ok(Err(error)) => Err(format!("refused: {error}")),
            Err(error) => Err(format!("failed: {error}")),
        };
        *answered
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some((sent.elapsed(), result));
    });
    slot
}

fn look(slot: &Slot) -> Option<Answer> {
    slot.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
}

/// A stall that stands: what lets it go, and the work that is stopped in it.
struct Standing {
    release: std::sync::mpsc::Sender<()>,
    _holder: Option<tokio::task::JoinHandle<()>>,
}

async fn reached(reached: tokio::sync::oneshot::Receiver<()>, what: &str) {
    tokio::time::timeout(REACH, reached)
        .await
        .unwrap_or_else(|_| panic!("{what}: the work did not reach its stall within {REACH:?}"))
        .unwrap_or_else(|_| panic!("{what}: the stall was dropped before it was reached"));
}

/// The kinds of storage call a case holds.
#[derive(Clone, Copy, Debug)]
enum Stalled {
    /// Another mutation's dispatch marker, committed with the dispatch barrier and the session
    /// held.
    Marker,
    /// Another mutation's settlement, which stands the moment after it committed, with both held.
    Settlement,
    /// The maintenance pass's prune, committed with both held.
    Prune,
}

/// Arms `stalled` and starts the work that stands in it. `holder` is the connection that a
/// mutation is sent on, made before the stall so that nothing in the case waits to connect.
async fn stall(host: &Host, stalled: Stalled, holder: LocalClient) -> Standing {
    let (arrived, release) = {
        let mut session = host.runtime.session();
        let journal = session.journal_mut().expect("this session keeps a journal");
        match stalled {
            Stalled::Marker => journal.stall_next_marker_blocking(),
            Stalled::Settlement => journal.stall_after_next_settlement(),
            Stalled::Prune => journal.stall_next_prune_blocking(),
        }
    };
    let held = match stalled {
        Stalled::Marker | Stalled::Settlement => {
            let (target, session_id) = (host.target(), host.session_id);
            let mut holder = holder;
            tokio::spawn(async move {
                let _ = holder
                    .mutate(
                        Method::SessionAttach,
                        ActionId::new(kr_ipc::new_uuid()),
                        target,
                        &attach_params(session_id),
                    )
                    .await;
            })
        }
        Stalled::Prune => {
            // As maintenance runs: on the worker's own runtime.
            let service = Arc::clone(&host.service);
            tokio::spawn(async move { service.maintain_now() })
        }
    };
    reached(arrived, &format!("{stalled:?}")).await;
    Standing {
        release,
        _holder: Some(held),
    }
}

/// Watches for the closure's record without taking the session's lock on the case's own thread.
fn watch_the_closure(runtime: &Arc<SessionRuntime>) -> std::sync::mpsc::Receiver<Instant> {
    let (sender, receiver) = std::sync::mpsc::channel();
    let runtime = Arc::clone(runtime);
    std::thread::spawn(move || {
        let waiting = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("a runtime for the watch");
        waiting.block_on(runtime.wait_closed());
        let _ = sender.send(Instant::now());
    });
    receiver
}

/// What a case saw, each moment counted from the first close's send.
#[derive(Default)]
struct Seen {
    first: Option<Answer>,
    second: Option<Answer>,
    asked: Option<Duration>,
    ended: Option<Duration>,
    closed: Option<Duration>,
}

/// What a case watches while it waits.
struct Watch<'a> {
    host: &'a Host,
    root: kr_protocol::identity::ProcessStartIdentity,
    closure: std::sync::mpsc::Receiver<Instant>,
    started: Instant,
    first: Slot,
    second: Option<Slot>,
    seen: Seen,
}

impl Watch<'_> {
    /// Looks once at everything, and says whether everything is known.
    fn look(&mut self) -> bool {
        let now = self.started.elapsed();
        if self.seen.first.is_none() {
            self.seen.first = look(&self.first);
        }
        if self.seen.second.is_none() {
            self.seen.second = self.second.as_ref().and_then(look);
        }
        if self.seen.asked.is_none() && self.host.asked().exists() {
            self.seen.asked = Some(now);
        }
        if self.seen.ended.is_none() && matches!(process_state(&self.root), ProcessState::Ended) {
            self.seen.ended = Some(now);
        }
        if self.seen.closed.is_none()
            && let Ok(at) = self.closure.try_recv()
        {
            self.seen.closed = Some(at.saturating_duration_since(self.started));
        }
        self.seen.first.is_some()
            && self.seen.second.is_some()
            && self.seen.asked.is_some()
            && self.seen.ended.is_some()
            && self.seen.closed.is_some()
    }

    /// Looks until everything is known or `until` has passed since the first close, whichever is
    /// first.
    async fn until(&mut self, until: Duration) {
        while self.started.elapsed() < until {
            if self.look() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        self.look();
    }
}

fn said(moment: Option<Duration>) -> String {
    moment.map_or_else(|| "never".to_owned(), |at| format!("{at:.2?}"))
}

fn answer_said(answer: &Option<Answer>) -> String {
    match answer {
        None => "never".to_owned(),
        Some((after, Ok(result))) => format!(
            "{after:.2?} as {:?} with durability {:?}",
            result.state, result.durability
        ),
        Some((after, Err(error))) => format!("{after:.2?} as an error: {error}"),
    }
}

impl Seen {
    fn line(&self) -> String {
        format!(
            "first close answered {}; second close answered {}; the shell was asked to stop {}; \
             the shell ended {}; the closure was recorded {}",
            answer_said(&self.first),
            answer_said(&self.second),
            said(self.asked),
            said(self.ended),
            said(self.closed),
        )
    }

    /// What of the stop did not happen within its times, counted from the first close.
    fn shortfalls(&self) -> Vec<String> {
        let mut missed = Vec::new();
        match &self.first {
            Some((after, Ok(_))) if *after <= ANSWER_BOUND => {}
            Some((after, Ok(_))) => {
                missed.push(format!(
                    "the close was answered after {after:?}, past {ANSWER_BOUND:?}"
                ));
            }
            Some((after, Err(error))) => {
                missed.push(format!("the close was refused after {after:?}: {error}"));
            }
            None => missed.push("the close was never answered".to_owned()),
        }
        let within =
            |moment: Option<Duration>, bound: Duration| moment.is_some_and(|at| at <= bound);
        if !within(self.asked, SLACK) {
            missed.push(format!(
                "the shell was asked to stop {}, past {SLACK:?}",
                said(self.asked)
            ));
        }
        if !within(self.ended, GRACE + SLACK) {
            missed.push(format!(
                "the shell ended {}, past {:?}",
                said(self.ended),
                GRACE + SLACK
            ));
        }
        if !within(self.closed, GRACE + DRAIN + SLACK) {
            missed.push(format!(
                "the closure was recorded {}, past {:?}",
                said(self.closed),
                GRACE + DRAIN + SLACK
            ));
        }
        if let Some(second) = &self.second {
            if !matches!(second, (after, Ok(_)) if *after <= ANSWER_BOUND) {
                missed.push(format!(
                    "the second close: {}",
                    answer_said(&Some(second.clone()))
                ));
            }
        } else {
            missed.push("the second close was never answered".to_owned());
        }
        missed
    }
}

/// Watches a close that has been sent, lets `standing` go after the window, watches for what the
/// let-go brings, says what it saw and fails when the stop did not happen within its times.
///
/// A second close is sent one second after the first, as a person asks again.
#[allow(clippy::too_many_arguments)]
async fn the_stop_is_watched(
    case: &str,
    host: &Host,
    root: kr_protocol::identity::ProcessStartIdentity,
    closure: std::sync::mpsc::Receiver<Instant>,
    started: Instant,
    first: Slot,
    second_client: LocalClient,
    standing: Option<Standing>,
) {
    let mut watch = Watch {
        host,
        root,
        closure,
        started,
        first,
        second: None,
        seen: Seen::default(),
    };
    watch.until(Duration::from_secs(1)).await;
    watch.second = Some(send_close(host, second_client));
    let second_sent = watch.started.elapsed();
    // The second close's answer is counted from its own send, which is where the watch started
    // looking at it.
    watch.until(WINDOW).await;
    let standing_line = watch.seen.line();
    let shortfalls = watch.seen.shortfalls();
    let let_go_at = watch.started.elapsed();
    if let Some(standing) = standing {
        // The stall is let go, which is what any stall does in the end.
        let _ = standing.release.send(());
        watch.until(let_go_at + AFTER_LET_GO).await;
    }
    eprintln!(
        "RESULT {case}: second close sent at {second_sent:.2?}; stall let go at {let_go_at:.2?}\n\
         RESULT {case}: while it stood (to {WINDOW:?}): {standing_line}\n\
         RESULT {case}: at the end (to {:?} after the let-go): {}\n\
         RESULT {case}: the shell's record of what it was asked: {:?}\n\
         RESULT {case}: shortfalls inside its times: {shortfalls:?}",
        AFTER_LET_GO,
        watch.seen.line(),
        std::fs::read_to_string(host.asked()).unwrap_or_default(),
    );
    assert!(
        shortfalls.is_empty(),
        "{case}: the authorised stop did not happen within its times while the storage call stood \
         still: {shortfalls:?}"
    );
}

/// Control: nothing stands still, and the stop happens within its times. It shows what the cases
/// below measure with.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_close_with_nothing_standing_still_stops_within_its_times() {
    let host = host().await;
    let root = host
        .runtime
        .session()
        .root_identity()
        .expect("a root shell");
    let closure = watch_the_closure(&host.runtime);
    let (first, second) = (host.client().await, host.client().await);
    let started = Instant::now();
    let slot = send_close(&host, first);
    the_stop_is_watched("control", &host, root, closure, started, slot, second, None).await;
}

/// A close at the worker's socket while another mutation's dispatch marker stands still: the
/// mutation holds the dispatch barrier and the session across the commit.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "shows an open finding"]
async fn a_close_stops_the_session_while_a_marker_write_stands_still() {
    a_close_while(Stalled::Marker, "marker").await;
}

/// The same while another mutation's settlement stands still.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "shows an open finding"]
async fn a_close_stops_the_session_while_a_settlement_stands_still() {
    a_close_while(Stalled::Settlement, "settlement").await;
}

/// The same while the maintenance pass's prune stands still.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "shows an open finding"]
async fn a_close_stops_the_session_while_the_maintenance_prune_stands_still() {
    a_close_while(Stalled::Prune, "prune").await;
}

async fn a_close_while(stalled: Stalled, case: &str) {
    let host = host().await;
    let root = host
        .runtime
        .session()
        .root_identity()
        .expect("a root shell");
    let closure = watch_the_closure(&host.runtime);
    let (holder, first, second) = (
        host.client().await,
        host.client().await,
        host.client().await,
    );
    let standing = stall(&host, stalled, holder).await;
    let started = Instant::now();
    let slot = send_close(&host, first);
    the_stop_is_watched(
        case,
        &host,
        root,
        closure,
        started,
        slot,
        second,
        Some(standing),
    )
    .await;
}

/// A close that was admitted before the stall, with a prune that stands still from then on: the
/// graceful request goes out when the close is admitted, and the force and the closure's record
/// each need the session again, five and seven seconds later.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "shows an open finding"]
async fn a_close_that_was_admitted_is_carried_out_while_a_prune_stands_still() {
    let host = host().await;
    let root = host
        .runtime
        .session()
        .root_identity()
        .expect("a root shell");
    let closure = watch_the_closure(&host.runtime);
    let (first, second) = (host.client().await, host.client().await);
    let started = Instant::now();
    let slot = send_close(&host, first);
    // The close is admitted and answered before anything stands still.
    let admitted = Instant::now();
    while look(&slot).is_none() {
        assert!(
            admitted.elapsed() < ANSWER_BOUND,
            "the close was not answered within {ANSWER_BOUND:?} with nothing standing still"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let standing = stall(&host, Stalled::Prune, host.client().await).await;
    eprintln!(
        "RESULT admitted: the stall stood {:.2?} after the close was sent",
        started.elapsed()
    );
    the_stop_is_watched(
        "admitted",
        &host,
        root,
        closure,
        started,
        slot,
        second,
        Some(standing),
    )
    .await;
}

/// The close's own marker write stands still: the close holds the dispatch barrier and the session
/// across it, and nothing has been answered or signalled.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "shows an open finding"]
async fn a_close_whose_own_marker_write_stands_still_stops_the_session() {
    own_write_stands_still(Stalled::Marker, "own marker").await;
}

/// The close's own settlement stands still, after its effect has happened and before it is
/// answered.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "shows an open finding"]
async fn a_close_whose_own_settlement_stands_still_stops_the_session() {
    own_write_stands_still(Stalled::Settlement, "own settlement").await;
}

async fn own_write_stands_still(stalled: Stalled, case: &str) {
    let host = host().await;
    let root = host
        .runtime
        .session()
        .root_identity()
        .expect("a root shell");
    let closure = watch_the_closure(&host.runtime);
    let (first, second) = (host.client().await, host.client().await);
    let (arrived, release) = {
        let mut session = host.runtime.session();
        let journal = session.journal_mut().expect("this session keeps a journal");
        match stalled {
            Stalled::Marker => journal.stall_next_marker_blocking(),
            Stalled::Settlement => journal.stall_after_next_settlement(),
            Stalled::Prune => unreachable!("the close does not prune"),
        }
    };
    let started = Instant::now();
    let slot = send_close(&host, first);
    reached(arrived, case).await;
    let standing = Standing {
        release,
        _holder: None,
    };
    the_stop_is_watched(
        case,
        &host,
        root,
        closure,
        started,
        slot,
        second,
        Some(standing),
    )
    .await;
}

/// What a read was answered, and after how long counted from its own send.
type ReadAnswer = (Duration, SessionReadResult);

/// Reads the session on `client`. The read is waited for no longer than [`READ_BOUND`], so a read
/// that waits for the session fails the case by an assertion that names what was waited for.
async fn read_within_its_bound(client: &mut LocalClient, host: &Host, what: &str) -> ReadAnswer {
    let sent = Instant::now();
    let outcome = tokio::time::timeout(
        READ_BOUND,
        client.request(
            Method::SessionRead,
            &SessionReadParams {
                session_id: host.session_id,
            },
        ),
    )
    .await
    .unwrap_or_else(|_| panic!("{what}: the read was not answered within {READ_BOUND:?}"));
    let answered = sent.elapsed();
    let result = match outcome {
        Ok(Ok(value)) => value
            .to_typed::<SessionReadResult>()
            .unwrap_or_else(|error| panic!("{what}: the answer could not be read: {error}")),
        Ok(Err(error)) => panic!("{what}: the read was refused: {error}"),
        Err(error) => panic!("{what}: the read failed: {error}"),
    };
    eprintln!(
        "RESULT {what}: read answered after {answered:.2?} as {:?}",
        result.session.state
    );
    (answered, result)
}

/// Reads the receipt of `action_id` on `client`, waited for no longer than [`READ_BOUND`], and
/// returns the host's answer, the host's error when it refused.
async fn receipt_within_its_bound(
    client: &mut LocalClient,
    action_id: ActionId,
    what: &str,
) -> (
    Duration,
    Result<kr_protocol::receipt::ActionReadResult, kr_protocol::error::ProtocolError>,
) {
    let sent = Instant::now();
    let outcome = tokio::time::timeout(
        READ_BOUND,
        client.request(
            Method::ActionRead,
            &kr_protocol::receipt::ActionReadParams {
                action_id,
                session_id: None,
            },
        ),
    )
    .await
    .unwrap_or_else(|_| panic!("{what}: the read was not answered within {READ_BOUND:?}"));
    let answered = sent.elapsed();
    let result = match outcome {
        Ok(Ok(value)) => Ok(value
            .to_typed()
            .unwrap_or_else(|error| panic!("{what}: the answer could not be read: {error}"))),
        Ok(Err(error)) => Err(error),
        Err(error) => panic!("{what}: the read failed: {error}"),
    };
    eprintln!(
        "RESULT {what}: receipt read answered after {answered:.2?}: {:?}",
        result.as_ref().map(|_| ()).map_err(|error| error.code)
    );
    (answered, result)
}

/// The lifecycle state the input domain holds, which is what the session's admission of a close
/// changes.
fn domain_state(host: &Host) -> SessionState {
    host.runtime.input().lock().state()
}

/// What the application is doing, as the input domain holds it, which is where a read of a held
/// session finds it.
fn domain_application_state(host: &Host) -> Option<kr_protocol::session::ApplicationState> {
    host.runtime.input().lock().application_state()
}

/// Waits until the input domain holds `expected`, which the evidence loop writes when it reads
/// what the broker holds. The case does not call the producer: the wait ends the case when the
/// loop does not read the fact within [`CLOSURE_WAIT`].
async fn domain_application_state_becomes(
    host: &Host,
    expected: Option<kr_protocol::session::ApplicationState>,
    what: &str,
) {
    let began = Instant::now();
    while domain_application_state(host) != expected {
        assert!(
            began.elapsed() < CLOSURE_WAIT,
            "{what}: the input domain did not come to say {expected:?} within {CLOSURE_WAIT:?}, it says {:?}",
            domain_application_state(host)
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Reads the held session until its application state is `expected`, for no longer than
/// [`CLOSURE_WAIT`], and returns the state the last read gave. Each read is answered within its
/// bound while the session is held, and none of them takes the session.
async fn held_application_state_becomes(
    reader: &mut LocalClient,
    host: &Host,
    expected: Option<kr_protocol::session::ApplicationState>,
    what: &str,
) -> Option<kr_protocol::session::ApplicationState> {
    let began = Instant::now();
    loop {
        let (_, read) = read_within_its_bound(reader, host, what).await;
        assert!(
            read.launch_profile.0.is_none(),
            "{what}: the read was answered while the session was held"
        );
        let said = read.session.application_state.0;
        if said == expected || began.elapsed() >= CLOSURE_WAIT {
            return said;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

const AGENT_NOW: TimestampMs = TimestampMs::new(10);
const AGENT_START: &str = r#"{"id":1,"method":"thread/start","params":{}}"#;
const TURN_7_STARTED: &str =
    r#"{"method":"turn/started","params":{"threadId":"thread-1","turn":{"id":"turn-7"}}}"#;
const TURN_7_ENDED: &str =
    r#"{"method":"turn/completed","params":{"threadId":"thread-1","turn":{"id":"turn-7"}}}"#;
const TURN_8_STARTED: &str =
    r#"{"method":"turn/started","params":{"threadId":"thread-1","turn":{"id":"turn-8"}}}"#;

/// One gateway instance bound to the host's own broker, and the connection that its application's
/// frames reach the broker by. What the host's evidence loop reads is what these frames change.
struct Agent {
    owner: Arc<Duplex>,
    /// What the owner wrote to the server.
    upstream: tokio::io::DuplexStream,
    /// What the owner wrote to the terminal.
    _client: tokio::io::DuplexStream,
    writes: tokio::task::JoinHandle<()>,
    _package: tempfile::TempDir,
}

impl Drop for Agent {
    fn drop(&mut self) {
        self.writes.abort();
    }
}

/// Binds an instance of the answering gateway package to the host's broker and opens the native
/// connection that the application's frames travel on.
async fn bind_agent(host: &Host) -> Agent {
    let instance = ApplicationInstanceId::new(Uuid::from_bytes([2; 16]));
    let process = || ProcessStartIdentity::new(41, ProcessStartSource::MacosProcBsdInfo, 900);
    let executable = Digest256::from_bytes([3; 32]);
    let package = tempfile::tempdir().expect("a directory for the package");
    let mut source = fixture::package(
        package.path(),
        Path::new(fixture::FORWARDER),
        &fixture::Shape::codex_backend_answering(),
    )
    .expect("the package is written");
    source.qualified = vec![QualifiedExecutable {
        digest: executable,
        version: fixture::GATEWAY_QUALIFIED_VERSION.to_owned(),
    }];
    let connector = InstalledConnector::read(source.clone()).expect("the package is read");
    let broker = host.service.broker();
    let frame = testing::admit(
        &Admissions::new(),
        &ConnectorSources::new(),
        broker,
        vec![testing::admitted(&source)],
        1,
    );
    broker
        .register_instance(
            instance,
            IntegrationMode::Gateway,
            None,
            Some(ManagedProcess::new(
                instance,
                process(),
                TransportHandle {
                    transport: BrokerTransport::PrivateSocket,
                    application_instance_id: instance,
                    executable_digest: executable,
                    process: process(),
                },
                Credential::from_bytes([9; 32]),
                TimestampMs::new(1),
            )),
        )
        .expect("the instance is registered");
    broker
        .bind(
            BrokerBindingId::new(Uuid::from_bytes([7; 16])),
            instance,
            source.package_digest,
            frame,
            MatchedExecutable {
                path: "/usr/local/bin/codex".to_owned(),
                digest: executable,
            },
            AGENT_NOW,
        )
        .expect("the package is bound");
    broker
        .withhold_thread(instance)
        .expect("the instance withholds its thread");
    let tables = broker
        .pin_compiled(instance, &connector, &executable)
        .expect("the compiled tables are pinned");
    let connection = broker
        .open_native_connection(
            instance,
            &[9; 32],
            &process(),
            &connector.plugin_id(),
            &tables.protocol_version,
        )
        .expect("a native connection opens");
    let (upstream_here, upstream) = tokio::io::duplex(1 << 20);
    let (client_here, client) = tokio::io::duplex(1 << 20);
    let (owner, writes) = Duplex::new(
        Arc::clone(broker),
        connection,
        Framing::new(NativeFraming::JsonLines),
        upstream_here,
        client_here,
        EnvironmentId::new(Uuid::from_bytes([4; 16])),
        "agent-user",
    );
    let dispatch = owner.dispatch().expect("the connection has a dispatch");
    broker.bind_connection_dispatch(connection, dispatch.clone());
    broker
        .bind_dispatch(instance, dispatch)
        .expect("the instance has a transport");
    Agent {
        owner,
        upstream,
        _client: client,
        writes: tokio::spawn(writes),
        _package: package,
    }
}

impl Agent {
    /// The server says something of its own, as the broker receives it from the application. It
    /// is carried within [`REACH`], so a frame that waits for the session fails the case here.
    async fn says(&self, frame: &str) {
        tokio::time::timeout(REACH, self.owner.from_upstream(frame.as_bytes(), AGENT_NOW))
            .await
            .unwrap_or_else(|_| panic!("the frame was not carried within {REACH:?}"))
            .expect("the frame is carried");
    }

    /// The terminal selects a thread and the server answers, so that the binding names it.
    async fn selects_a_thread(&mut self) {
        let selecting = match self
            .owner
            .from_client(AGENT_START.as_bytes(), AGENT_NOW)
            .await
            .expect("the request is carried")
        {
            Carried::ClientRequest {
                upstream_request_id,
                ..
            } => upstream_request_id,
            other => panic!("not a request of the terminal's: {other:?}"),
        };
        self.reads_a_line().await;
        self.says(&format!(
            r#"{{"id":{},"result":{{"thread":{{"id":"thread-1"}}}}}}"#,
            selecting.as_str()
        ))
        .await;
    }

    /// Reads the next line the owner wrote to the server.
    async fn reads_a_line(&mut self) {
        let mut byte = [0_u8; 1];
        loop {
            self.upstream.read_exact(&mut byte).await.expect("a byte");
            if byte[0] == b'\n' {
                return;
            }
        }
    }
}

/// The read of a session that nothing holds is the one that takes it: the control of the cases
/// below. It carries the session's content and its state, as it always did.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_read_of_a_session_nothing_holds_takes_it_and_gives_its_content() {
    let host = host().await;
    host.runtime
        .session()
        .set_application(Some("an editor".to_owned()));
    let mut reader = host.client().await;
    let (answered, read) = read_within_its_bound(&mut reader, &host, "control read").await;
    assert!(answered <= READ_BOUND, "answered after {answered:?}");
    assert_eq!(read.session.state, SessionState::Live);
    assert_eq!(read.session.application.as_deref(), Some("an editor"));
    assert!(
        read.launch_profile.0.is_some(),
        "a read that takes the session gives the profile it was launched with"
    );
    assert!(
        read.endpoint.0.is_some(),
        "a running session names its endpoint"
    );
}

/// A live session that the maintenance pass holds behind a storage call: the read answers within
/// its bound, says that the session is live, and says what the session was when it launched its
/// shell, which the record made when the session was made does not have.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_read_of_a_live_session_that_is_held_answers_within_its_bound_and_says_live() {
    let host = host().await;
    let (holder, mut reader) = (host.client().await, host.client().await);
    let standing = stall(&host, Stalled::Prune, holder).await;
    let (answered, read) = read_within_its_bound(&mut reader, &host, "held live").await;
    let _ = standing.release.send(());
    assert!(
        answered <= READ_BOUND,
        "the read of a held session was answered after {answered:?}, past {READ_BOUND:?}"
    );
    assert_eq!(read.session.state, SessionState::Live);
    assert!(
        read.session.root_process.0.is_some(),
        "the session published its summary when it launched its shell"
    );
    assert_eq!(read.session.session_id, host.session_id);
    assert!(
        read.launch_profile.0.is_none() && read.last_command_block.0.is_none(),
        "a read of a held session gives no content of the session"
    );
    assert!(
        read.endpoint.0.is_some(),
        "a live session names its endpoint"
    );
}

/// The name of the application in the session's foreground is published when it changes, so a read
/// of a held session names the application that the session had when it was held.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_read_of_a_held_session_names_the_application_the_session_had() {
    let host = host().await;
    host.runtime
        .session()
        .set_application(Some("an editor".to_owned()));
    let (holder, mut reader) = (host.client().await, host.client().await);
    let standing = stall(&host, Stalled::Prune, holder).await;
    let (answered, read) = read_within_its_bound(&mut reader, &host, "held application").await;
    let _ = standing.release.send(());
    assert!(
        answered <= READ_BOUND,
        "the read of a held session was answered after {answered:?}, past {READ_BOUND:?}"
    );
    assert!(
        read.launch_profile.0.is_none(),
        "the read was answered while the session was held"
    );
    assert_eq!(read.session.application.as_deref(), Some("an editor"));
}

/// What the application is doing changes without its name changing, and the session counts the
/// launches that wait for the reader. A read of the held session says both as the session has them:
/// the state and the count are read from the input domain.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_read_of_a_held_session_says_what_the_application_is_doing_and_the_launches_that_wait() {
    let host = host().await;
    // A session with a managed root editor counts the launches that wait for its reader.
    host.runtime.session().install_fence(FenceDriver::new(
        host.session_id,
        LeaseView::unheld(InputLeaseEpoch::new(0)),
        Arc::new(kr_transport::clock::ManualClock::new()),
    ));
    let producer = Producer::new(Arc::downgrade(&host.runtime));
    producer.observe_holder(Holder::Program(Some("an editor".to_owned())));
    producer.settle();
    let named = host.runtime.published().latest();
    assert_eq!(named.application.as_deref(), Some("an editor"));
    assert_eq!(named.application_state.0, None);
    // Two launches wait for the reader, and the state changes with the name the same.
    let waiting: Vec<_> = (0..2)
        .map(|_| {
            host.runtime
                .session()
                .register_launch(LaunchTransactionId::new(kr_ipc::new_uuid()))
        })
        .collect();
    producer.observe_broker(false, true);
    producer.settle();
    // What the case stands on: the domain holds the state, and the name is the one it was.
    assert_eq!(
        host.runtime.published().latest().application,
        named.application
    );
    assert_eq!(
        domain_application_state(&host),
        Some(kr_protocol::session::ApplicationState::AgentBusy),
        "the producer writes what the application is doing to the input domain"
    );
    let mut control = host.client().await;
    let (_, taken) = read_within_its_bound(&mut control, &host, "control state").await;
    assert_eq!(
        taken.outstanding_launches.0.map(|count| count.get()),
        Some(2)
    );
    assert!(
        taken.launch_profile.0.is_some(),
        "the control read takes the session"
    );
    let (holder, mut reader) = (host.client().await, host.client().await);
    let standing = stall(&host, Stalled::Prune, holder).await;
    let (answered, read) = read_within_its_bound(&mut reader, &host, "held state").await;
    let _ = standing.release.send(());
    assert!(
        answered <= READ_BOUND,
        "the read of a held session was answered after {answered:?}, past {READ_BOUND:?}"
    );
    assert!(
        read.launch_profile.0.is_none(),
        "the read was answered while the session was held"
    );
    assert_eq!(read.session.application.as_deref(), Some("an editor"));
    assert_eq!(
        read.session.application_state.0,
        Some(kr_protocol::session::ApplicationState::AgentBusy),
        "a held session says what its application is doing"
    );
    assert_eq!(
        read.outstanding_launches.0.map(|count| count.get()),
        Some(2),
        "a held session says how many launches wait for the reader"
    );
    drop(waiting);
}

/// A fact that the producer takes while a storage call holds the session is written where a read of
/// the held session finds it, and taking it does not wait for the session. The case calls the
/// producer itself, with no evidence loop and no broker: it shows the producer's own contract and
/// not the order in which the product's loop meets a hold, which the cases that run the loop show.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_fact_the_producer_takes_during_the_hold_is_in_the_read_of_the_held_session() {
    let host = host().await;
    let producer = Producer::new(Arc::downgrade(&host.runtime));
    producer.observe_holder(Holder::Program(Some("an editor".to_owned())));
    // The publication that names the program has been made, so that none that follows it changes
    // what the session published, whichever the order of the two facts.
    producer.settle();
    producer.observe_broker(false, true);
    producer.observe_broker(false, false);
    producer.settle();
    // What the case stands on: the turn has ended and the session says nothing is happening.
    assert_eq!(domain_application_state(&host), None);
    assert_eq!(host.runtime.published().latest().application_state.0, None);
    let (holder, mut reader) = (host.client().await, host.client().await);
    let standing = stall(&host, Stalled::Prune, holder).await;
    // The new turn is taken while the session is held, and taking it returns at once.
    let began = Instant::now();
    producer.observe_broker(false, true);
    assert!(
        began.elapsed() < READ_BOUND,
        "the producer waited {:?} for the held session to take a fact",
        began.elapsed()
    );
    assert_eq!(
        domain_application_state(&host),
        Some(ApplicationState::AgentBusy)
    );
    let (answered, read) = read_within_its_bound(&mut reader, &host, "held new turn").await;
    let _ = standing.release.send(());
    assert!(
        answered <= READ_BOUND,
        "the read of a held session was answered after {answered:?}, past {READ_BOUND:?}"
    );
    assert!(
        read.launch_profile.0.is_none(),
        "the read was answered while the session was held"
    );
    assert_eq!(
        read.session.application_state.0,
        Some(ApplicationState::AgentBusy),
        "a held session says the turn that the producer took during the hold"
    );
    producer.settle();
}

/// A turn that the daemon's last scan saw ends and a new turn starts, in ONE hold. The host's own
/// evidence loop reads both from the real broker, as the connector's frames change it, and the
/// read of the held session says that the new turn runs: the sleep demand counts it, and a session
/// that shows no demand under a turn lets the host sleep.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_read_of_a_held_session_says_the_new_turn_when_a_turn_ended_and_a_new_one_began_in_the_hold()
 {
    let host = host().await;
    let mut agent = bind_agent(&host).await;
    agent.selects_a_thread().await;
    agent.says(TURN_7_STARTED).await;
    // What the case stands on: the loop has read the turn, and the scan could have seen it.
    domain_application_state_becomes(&host, Some(ApplicationState::AgentBusy), "first turn").await;
    let (holder, mut reader) = (host.client().await, host.client().await);
    let standing = stall(&host, Stalled::Prune, holder).await;
    agent.says(TURN_7_ENDED).await;
    // The loop reads the end during the hold. What it does next is what the case is about.
    domain_application_state_becomes(&host, Some(ApplicationState::ShellReady), "turn ended").await;
    agent.says(TURN_8_STARTED).await;
    let said = held_application_state_becomes(
        &mut reader,
        &host,
        Some(ApplicationState::AgentBusy),
        "held read after the new turn",
    )
    .await;
    let _ = standing.release.send(());
    assert_eq!(
        said,
        Some(ApplicationState::AgentBusy),
        "the read of a held session said {said:?} for {CLOSURE_WAIT:?} after a new turn began in the same hold in which the previous one ended"
    );
}

/// A turn that the daemon's last scan saw ends before a storage call holds the session, and the
/// host's evidence loop reads the end. The read of the held session says what the application is
/// doing now.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_read_of_a_held_session_says_that_the_turn_ended_before_the_hold() {
    let host = host().await;
    let mut agent = bind_agent(&host).await;
    agent.selects_a_thread().await;
    agent.says(TURN_7_STARTED).await;
    domain_application_state_becomes(&host, Some(ApplicationState::AgentBusy), "turn").await;
    agent.says(TURN_7_ENDED).await;
    domain_application_state_becomes(&host, Some(ApplicationState::ShellReady), "turn ended").await;
    let (holder, mut reader) = (host.client().await, host.client().await);
    let standing = stall(&host, Stalled::Prune, holder).await;
    let said = held_application_state_becomes(
        &mut reader,
        &host,
        Some(ApplicationState::ShellReady),
        "held read after the turn ended",
    )
    .await;
    let _ = standing.release.send(());
    assert_eq!(
        said,
        Some(ApplicationState::ShellReady),
        "the read of a held session said {said:?} for a turn that ended before the hold"
    );
}

/// A turn starts while a storage call holds the session, after the evidence loop read a session
/// that showed no demand. The read of the held session says that the agent works.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_read_of_a_held_session_says_the_turn_that_began_after_a_read_that_saw_no_demand() {
    let host = host().await;
    let mut agent = bind_agent(&host).await;
    agent.selects_a_thread().await;
    agent.says(TURN_7_STARTED).await;
    domain_application_state_becomes(&host, Some(ApplicationState::AgentBusy), "turn").await;
    agent.says(TURN_7_ENDED).await;
    domain_application_state_becomes(&host, Some(ApplicationState::ShellReady), "turn ended").await;
    let (holder, mut reader) = (host.client().await, host.client().await);
    let standing = stall(&host, Stalled::Prune, holder).await;
    agent.says(TURN_8_STARTED).await;
    let said = held_application_state_becomes(
        &mut reader,
        &host,
        Some(ApplicationState::AgentBusy),
        "held read after the turn began",
    )
    .await;
    let _ = standing.release.send(());
    assert_eq!(
        said,
        Some(ApplicationState::AgentBusy),
        "the read of a held session said {said:?} for a turn that began in the hold"
    );
}

/// A turn ends while a storage call holds the session and none follows. The read of the held
/// session says that nothing is happening: a session that shows a turn that has ended keeps the
/// host awake for nothing, until the hold ends.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_read_of_a_held_session_says_that_the_turn_ended_in_the_hold_when_none_followed() {
    let host = host().await;
    let mut agent = bind_agent(&host).await;
    agent.selects_a_thread().await;
    agent.says(TURN_7_STARTED).await;
    domain_application_state_becomes(&host, Some(ApplicationState::AgentBusy), "turn").await;
    let (holder, mut reader) = (host.client().await, host.client().await);
    let standing = stall(&host, Stalled::Prune, holder).await;
    agent.says(TURN_7_ENDED).await;
    let said = held_application_state_becomes(
        &mut reader,
        &host,
        Some(ApplicationState::ShellReady),
        "held read after the turn ended",
    )
    .await;
    let _ = standing.release.send(());
    assert_eq!(
        said,
        Some(ApplicationState::ShellReady),
        "the read of a held session said {said:?} for a turn that ended in the hold"
    );
}

/// A question's commit stands in the question ledger and holds the ledger's lock, as a commit to a
/// disk that has stopped does, while a storage call holds the session. A turn starts, ends, and
/// another starts. The evidence loop reads each of them from the broker although the ledger's
/// reader is blocked (a loop that read the ledger itself would stand in the commit after the first
/// and read no further), so the read of the held session says what the agent does after each. Once
/// the commit returns, the ledger's reader says the question.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_read_of_a_held_session_says_the_turn_while_a_question_commit_stands_in_the_ledger() {
    let host = host().await;
    let mut agent = bind_agent(&host).await;
    agent.selects_a_thread().await;
    let (arrived, let_go) = host.service.questions().stall_next_commit();
    let asking = {
        let service = Arc::clone(&host.service);
        let session_id = host.session_id;
        std::thread::spawn(move || ask_a_question(&service, session_id))
    };
    reached(arrived, "the question's commit").await;
    // The session is held by the seam that takes it and waits: a stalled prune would need the
    // store that the ledger's commit stands in, and the maintenance pass sweeps the ledger first.
    let mut reader = host.client().await;
    let (held, hold) = host.runtime.hold_the_session();
    reached(held, "the session's hold").await;
    // What the case stands on: the stalled commit holds the ledger's lock, so a read of the
    // ledger on a thread of the case's own does not return while the commit stands.
    let probe = {
        let service = Arc::clone(&host.service);
        std::thread::spawn(move || {
            let _ = service.questions().any_open(kr_worker::questions::Now {
                utc_ms: kr_ipc::now_ms(),
                boot_ms: kr_ipc::clock::boot_elapsed_ms(),
            });
        })
    };
    agent.says(TURN_7_STARTED).await;
    let began = held_application_state_becomes(
        &mut reader,
        &host,
        Some(ApplicationState::AgentBusy),
        "held read after the turn began while the ledger's commit stands",
    )
    .await;
    // The loop has read the first turn and asked its reader, which stands in the commit. The turn
    // ends and another begins, and the loop must read both.
    agent.says(TURN_7_ENDED).await;
    let ended = held_application_state_becomes(
        &mut reader,
        &host,
        Some(ApplicationState::ShellReady),
        "held read after the turn ended while the ledger's commit stands",
    )
    .await;
    agent.says(TURN_8_STARTED).await;
    let again = held_application_state_becomes(
        &mut reader,
        &host,
        Some(ApplicationState::AgentBusy),
        "held read after the next turn began while the ledger's commit stands",
    )
    .await;
    assert!(
        !probe.is_finished(),
        "a read of the ledger returned while the commit stood: the ledger's lock was not held"
    );
    let _ = let_go.send(());
    let _ = hold.send(());
    asking.join().expect("the question's thread ended");
    probe.join().expect("the probe's thread ended");
    assert_eq!(
        (began, ended, again),
        (
            Some(ApplicationState::AgentBusy),
            Some(ApplicationState::ShellReady),
            Some(ApplicationState::AgentBusy)
        ),
        "the reads of a held session while a commit stood in the ledger said these states after a turn began, ended and another began"
    );
    domain_application_state_becomes(
        &host,
        Some(ApplicationState::AwaitingInput),
        "the question once its commit returned",
    )
    .await;
}

/// A question is created from the host's own process, which stands in its commit when the case has
/// armed the ledger's stall.
fn ask_a_question(service: &WorkerService, session_id: SessionId) {
    ask_a_question_expiring(service, session_id, "req-1", None);
}

/// As [`ask_a_question`], for the request `request`, which runs out of time after `expiry_ms` where
/// that is given.
fn ask_a_question_expiring(
    service: &WorkerService,
    session_id: SessionId,
    request: &str,
    expiry_ms: Option<u64>,
) {
    ask_a_question_at(
        service,
        session_id,
        request,
        expiry_ms,
        kr_worker::questions::Now {
            utc_ms: kr_ipc::now_ms(),
            boot_ms: kr_ipc::clock::boot_elapsed_ms(),
        },
    );
}

/// As [`ask_a_question_expiring`], asked at `now`, whose continuous reading is the clock that the
/// question's deadline on it is measured from.
fn ask_a_question_at(
    service: &WorkerService,
    session_id: SessionId,
    request: &str,
    expiry_ms: Option<u64>,
    now: kr_worker::questions::Now,
) {
    let source = kr_worker::questions::VerifiedSource {
        process: kr_ipc::identity::current_process_start_identity().expect("a process identity"),
        executable: Some("/bin/agent".to_owned()),
        session_member: true,
        ancestry: true,
        launch_channel: true,
        connection_id: ConnectionId::new(kr_ipc::new_uuid()),
    };
    service
        .questions()
        .create(
            &source,
            &kr_protocol::question::QuestionCreateParams {
                session_id,
                request_id: request.to_owned(),
                agent_name: Nullable::some("an agent".to_owned()),
                context: "two ways to do it".to_owned(),
                question: "which one".to_owned(),
                kind: kr_protocol::question::QuestionKind::Confirm,
                choices: Vec::new(),
                requested_expiry_ms: expiry_ms.map_or_else(Nullable::null, |ms| {
                    Nullable::some(kr_protocol::scalars::DurationMs::new(ms))
                }),
                wait_ms: Nullable::null(),
            },
            now,
        )
        .expect("a verified source creates a question");
}

/// A fact that joins after the publisher has taken the session and before it reads the facts is
/// the one it publishes: the facts are read under the session, so what is published is the latest
/// the facts say and not what they said when the publisher was told. The publisher is confirmed at
/// its pause after the take and again at its pause before the send, so the case checks the FIRST
/// publication while the publisher is held there (a channel that keeps only its latest value would
/// hide it), and does not wait on a clock.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_publication_that_waited_for_the_session_is_the_latest_the_facts_say() {
    let host = host().await;
    let producer = Producer::new(Arc::downgrade(&host.runtime));
    let (took, let_go_after_the_take) = producer.pause_after_the_take();
    producer.observe_holder(Holder::Program(Some("first".to_owned())));
    tokio::time::timeout(REACH, took)
        .await
        .expect("the publisher took the session within a bound")
        .expect("the pause was dropped before it was reached");
    // The publisher has the session and has read nothing; the second fact joins now, and joining
    // takes no session.
    producer.observe_holder(Holder::Program(Some("second".to_owned())));
    let (about_to_send, let_go_before_the_send) = producer.pause_before_the_send();
    let _ = let_go_after_the_take.send(());
    tokio::time::timeout(REACH, about_to_send)
        .await
        .expect("the publisher reached its send within a bound")
        .expect("the pause was dropped before it was reached");
    // What the first publication carries, while the publisher is held before telling anyone: the
    // name it wrote into the session.
    assert_eq!(
        host.runtime.published().latest().application.as_deref(),
        Some("second"),
        "the first publication after the take was not the latest the facts say"
    );
    assert_eq!(
        producer.application().name,
        None,
        "nothing is shown to a receiver before the publisher sends"
    );
    let _ = let_go_before_the_send.send(());
    producer.settle();
    assert_eq!(producer.application().name.as_deref(), Some("second"));
}

/// A fact changes back to the value that is published while a publication of the other value is in
/// flight: the publisher has read the facts and stands before it sends them. The change back wakes
/// the publisher too, so the value that stands is the one the facts say now, and not the older one
/// that the publication in flight carried.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_change_back_to_the_published_value_while_a_publication_is_in_flight_is_published() {
    let host = host().await;
    let producer = Producer::new(Arc::downgrade(&host.runtime));
    let (arrived, let_go) = producer.pause_before_the_send();
    producer.observe_holder(Holder::Program(Some("editor".to_owned())));
    tokio::time::timeout(REACH, arrived)
        .await
        .expect("the publisher arrived at its pause within a bound")
        .expect("the pause was dropped before it was reached");
    // What the case stands on: the publisher has written the program's name into the session and
    // stands before it tells a receiver, so the producer still shows what it showed before.
    assert_eq!(
        host.runtime.published().latest().application.as_deref(),
        Some("editor")
    );
    assert_eq!(producer.application().name, None);
    // The shell holds the terminal again: what the facts say is what the producer shows.
    producer.observe_holder(Holder::Shell);
    let _ = let_go.send(());
    // The publication in flight goes out, and the change back is published after it. The case polls
    // for the end state, so that a publisher that never makes the second publication fails the
    // assertion here and not a wait of the test's own seam.
    let began = Instant::now();
    while producer.application().name.is_some()
        || host.runtime.published().latest().application.is_some()
    {
        assert!(
            began.elapsed() < CLOSURE_WAIT,
            "the publication in flight left the older program standing: the producer shows {:?} and the session {:?}",
            producer.application().name,
            host.runtime.published().latest().application
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Waits until the evidence loop has begun a round after round `after` and has come to its wait on
/// its stream, with the facts it read in that round, and returns that round's number. A round is
/// counted once it has made its subscriptions, so a wake that comes while the loop waits in a round
/// that the count shows is one that the round hears.
async fn the_loop_waits_after_round(producer: &Producer, after: usize, what: &str) -> usize {
    let began = Instant::now();
    loop {
        let (rounds, waits) = producer.loop_rounds();
        if rounds > after && rounds == waits {
            return rounds;
        }
        assert!(
            began.elapsed() < CLOSURE_WAIT,
            "the evidence loop did not go round and wait {what} within {CLOSURE_WAIT:?}"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// The session, held on a thread of its own until this is dropped.
struct SessionHeld {
    _release: std::sync::mpsc::Sender<()>,
}

/// Takes the session on a thread of its own and returns once that thread has it. The thread lets it
/// go when the returned value is dropped, also when a case fails before it gets there.
async fn hold_the_session(runtime: &Arc<SessionRuntime>) -> SessionHeld {
    let (taken, has_taken) = std::sync::mpsc::channel();
    let (release, released) = std::sync::mpsc::channel::<()>();
    let runtime = Arc::clone(runtime);
    std::thread::spawn(move || {
        let _session = runtime.session();
        let _ = taken.send(());
        // Returns when the sender is dropped.
        let _ = released.recv();
    });
    tokio::task::spawn_blocking(move || has_taken.recv_timeout(REACH))
        .await
        .expect("the thread that takes the session ended")
        .expect("the session was taken within a bound");
    SessionHeld { _release: release }
}

/// Waits until the evidence loop waits (a round that began has come to its wait, read on both sides
/// of the other counts) and every ask that it queued for the ledger's reader is a read that the
/// reader has finished: no read of the ledger is pending or under way.
async fn the_reader_has_finished_every_ask(producer: &Producer, what: &str) {
    let began = Instant::now();
    loop {
        let (rounds, waits) = producer.loop_rounds();
        let (queued, done) = producer.ledger_asks();
        if producer.loop_rounds() == (rounds, waits) && rounds == waits && queued == done {
            return;
        }
        assert!(
            began.elapsed() < CLOSURE_WAIT,
            "the ledger's reader did not finish every read that the loop asked of it {what} within {CLOSURE_WAIT:?}"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// A question that runs out of time stops counting without anything else waking the evidence loop.
/// The loop re-reads the ledger on a timer while a question is open, and it arms that timer when the
/// ledger's reader says that a question is open, which is a wake of the reader's own. The question
/// lives an hour on the session's clock, which the case moves by hand, so it runs out of time when
/// the case moves the clock and not before.
///
/// The order of events, each step confirmed by what the case observes and none by a delay:
/// 1. the loop waits with no question open;
/// 2. the reader is held after it has read the ledger, the question is asked, and the loop is shown
///    to have gone round and to wait with the question fact still false, so that it can arm its
///    timer only through the reader's wake;
/// 3. the reader is let go and the session's domain says that a question is open;
/// 4. the loop is shown to go round once more, on the reader's wake, and to wait with the open
///    fact, so that its timer is armed with the clock still before the question's deadline;
/// 5. the case takes the session and holds it to the end: the host's maintenance pass takes the
///    session before it sweeps the ledger on the same clock (and a sweep wakes the loop when a
///    question ends), so no pass gets to its sweep from here on. The first pass was made when the
///    host began to serve and the next is 30 seconds or more after it, which is why the hold is
///    only a guard;
/// 6. the loop waits again and every ask that it queued for the ledger's reader is a read that the
///    reader has finished (`ledger_asks`): no read is pending or under way, so the next read of the
///    ledger comes only from a round that a wake begins;
/// 7. only then does the clock move past the deadline. The question's waiters are the loop's timer
///    (which the case waits for), the sweep (shut out in 5), a client's call that reads or sweeps
///    the ledger (the case makes none) and the reader's own read (none is pending, and the reader
///    asks nothing itself). The session stops counting the question, and the mutant that removes
///    the timer's branch leaves it counted.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_question_that_runs_out_of_time_stops_counting_with_no_other_wake() {
    let clock = kr_ipc::clock::ManualSharedClock::new();
    let host = host_on_a_clock(&clock).await;
    let producer = Arc::clone(host.service.application());
    let before = the_loop_waits_after_round(&producer, 0, "with no question open").await;
    let (read, let_go) = producer.pause_ledger_reader_before_its_fact();
    ask_a_question_at(
        &host.service,
        host.session_id,
        "short",
        Some(QUESTION_EXPIRY_MS),
        kr_worker::questions::Now {
            utc_ms: kr_ipc::now_ms(),
            boot_ms: clock.boot_elapsed_ms(),
        },
    );
    tokio::time::timeout(REACH, read)
        .await
        .expect("the ledger's reader read the ledger within a bound")
        .expect("the pause was dropped before it was reached");
    // The question's creation woke the loop, which asked the reader and now waits with the question
    // fact false: the reader has not recorded what it found.
    let waiting = the_loop_waits_after_round(
        &producer,
        before,
        "after the question was asked, with the reader held",
    )
    .await;
    assert_eq!(
        domain_application_state(&host),
        Some(ApplicationState::ShellReady),
        "the question fact was recorded before the loop waited"
    );
    let _ = let_go.send(());
    domain_application_state_becomes(
        &host,
        Some(ApplicationState::AwaitingInput),
        "the question is open",
    )
    .await;
    // The reader's wake takes the loop round again, and it arms its timer with the fact open.
    the_loop_waits_after_round(
        &producer,
        waiting,
        "after the reader recorded the open question: the reader's wake did not reach the loop",
    )
    .await;
    let held = hold_the_session(&host.runtime).await;
    the_reader_has_finished_every_ask(
        &producer,
        "with the fact open, the session held and the clock unmoved",
    )
    .await;
    assert_eq!(
        domain_application_state(&host),
        Some(ApplicationState::AwaitingInput),
        "the question stopped counting before the clock moved"
    );
    clock.advance(Duration::from_millis(QUESTION_EXPIRY_MS + 1));
    let began = Instant::now();
    while domain_application_state(&host) == Some(ApplicationState::AwaitingInput) {
        assert!(
            began.elapsed() < QUESTION_WAIT,
            "the session still counted a question that ran out of time {QUESTION_WAIT:?} after its deadline passed"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(
        domain_application_state(&host),
        Some(ApplicationState::ShellReady),
        "the session's domain said something other than a shell at its prompt once the question had run out of time"
    );
    drop(held);
}

/// Two questions are open, and the maintenance pass's prune holds the session inside a write
/// transaction of the file that the question ledger shares. One question runs out of time, so the
/// ledger's reader writes its expiry, which fails after its busy wait. The other question stays
/// open, and the question fact keeps its last value: a read of the held session still says that a
/// question waits, where a reader that took the error for "no question" says that nothing does.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_question_fact_that_cannot_be_read_keeps_its_last_value() {
    let host = host().await;
    let mut agent = bind_agent(&host).await;
    agent.selects_a_thread().await;
    ask_a_question_expiring(&host.service, host.session_id, "short", Some(4_000));
    ask_a_question_expiring(&host.service, host.session_id, "long", None);
    domain_application_state_becomes(
        &host,
        Some(ApplicationState::AwaitingInput),
        "the questions are open",
    )
    .await;
    let (holder, mut reader) = (host.client().await, host.client().await);
    let standing = stall(&host, Stalled::Prune, holder).await;
    // The short question is due. A wake of the loop asks the ledger's reader, whose expiry write
    // meets the write lock that the prune holds and fails after five seconds.
    tokio::time::sleep(Duration::from_millis(4_500)).await;
    agent.says(TURN_7_STARTED).await;
    agent.says(TURN_7_ENDED).await;
    let began = Instant::now();
    let mut said = None;
    while began.elapsed() < Duration::from_secs(9) {
        let (_, read) =
            read_within_its_bound(&mut reader, &host, "held read after the write failed").await;
        said = read.session.application_state.0;
        assert_eq!(
            said,
            Some(ApplicationState::AwaitingInput),
            "the read of a held session said {said:?} {:?} after the ledger's expiry write was asked for, with a question still open",
            began.elapsed()
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    let _ = standing.release.send(());
    assert_eq!(said, Some(ApplicationState::AwaitingInput));
}

/// The application's two helper threads end with their owners: the reader of the question ledger
/// with the evidence loop, when the session closes, and the publisher with the producer, when the
/// service goes. A producer that is dropped ends its publisher too.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn the_helper_threads_of_the_application_end_with_their_owners() {
    let alone = Producer::new(std::sync::Weak::new());
    let alive = alone.helpers_alive();
    assert_eq!(alive.load(std::sync::atomic::Ordering::SeqCst), 1);
    drop(alone);
    helpers_alive_become(&alive, 0, "a producer that was dropped").await;

    let host = host_of(true).await;
    let alive = host.service.application().helpers_alive();
    helpers_alive_become(&alive, 2, "a worker that follows its application").await;
    let (_, gate) = host
        .runtime
        .close(kr_protocol::session::ClosureReason::CloseRequested);
    gate.release();
    tokio::time::timeout(CLOSURE_WAIT, host.runtime.wait_closed())
        .await
        .expect("the session closes");
    helpers_alive_become(&alive, 1, "a worker whose session has closed").await;
    drop(host);
    helpers_alive_become(&alive, 0, "a worker that has gone").await;
}

async fn helpers_alive_become(alive: &std::sync::atomic::AtomicUsize, expected: usize, what: &str) {
    let began = Instant::now();
    while alive.load(std::sync::atomic::Ordering::SeqCst) != expected {
        assert!(
            began.elapsed() < CLOSURE_WAIT,
            "{what}: {} helper threads were alive {CLOSURE_WAIT:?} on, and {expected} were expected",
            alive.load(std::sync::atomic::Ordering::SeqCst)
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// A read that names another session is refused whether or not the session is held.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_read_of_another_session_is_refused_while_the_session_is_held() {
    let host = host().await;
    let (holder, mut reader) = (host.client().await, host.client().await);
    let standing = stall(&host, Stalled::Prune, holder).await;
    let sent = Instant::now();
    let outcome = tokio::time::timeout(
        READ_BOUND,
        reader.request(
            Method::SessionRead,
            &SessionReadParams {
                session_id: SessionId::new(kr_ipc::new_uuid()),
            },
        ),
    )
    .await
    .expect("the read of another session was answered within its bound");
    let _ = standing.release.send(());
    assert!(sent.elapsed() <= READ_BOUND);
    assert!(
        matches!(outcome, Ok(Err(_))),
        "a read that names another session is refused: {outcome:?}"
    );
}

/// A close that was admitted and whose later calls stand still, while the summary the session
/// published says that it is live: the domain says that the session is closing, and so does the
/// read. Without the state from the domain the read says live.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_read_of_a_session_whose_close_is_underway_says_closing_from_the_domain() {
    let host = host().await;
    let (closer, mut reader) = (host.client().await, host.client().await);
    let (arrived, release) = host.runtime.session().stall_next_close_tail_blocking();
    let slot = send_close(&host, closer);
    reached(arrived, "the close's tail").await;
    // What the case stands on: the close was admitted, and the summary does not know it yet.
    assert_eq!(domain_state(&host), SessionState::Closing);
    assert_eq!(
        host.runtime.published().latest().state,
        SessionState::Live,
        "the published summary precedes the close's admission"
    );
    let (answered, read) = read_within_its_bound(&mut reader, &host, "held closing").await;
    let _ = release.send(());
    assert!(
        answered <= READ_BOUND,
        "the read of a held session was answered after {answered:?}, past {READ_BOUND:?}"
    );
    assert!(
        read.launch_profile.0.is_none(),
        "the read was answered while the session was held"
    );
    assert_eq!(
        read.session.state,
        SessionState::Closing,
        "the session is closing and the read says so"
    );
    assert!(
        read.endpoint.0.is_some(),
        "a closing session still names its endpoint"
    );
    // Once the close has gone on, the admission is published.
    let began = Instant::now();
    while look(&slot).is_none() {
        assert!(
            began.elapsed() < ANSWER_BOUND,
            "the close was not answered within {ANSWER_BOUND:?} once it was let go"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(
        host.runtime.published().latest().state,
        SessionState::Closing,
        "the close's admission is published"
    );
}

/// The control of the case above: the close was admitted and nothing holds the session, so the read
/// takes it and gives what it always gave.
///
/// The case keeps the close's gate, which is what starts the stop that takes the session again and
/// again, so that nothing but the case decides who holds the session. It first takes the session
/// itself, with a wait that no loaded machine runs out, to show that nothing holds it.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_read_of_a_session_whose_close_is_underway_and_nothing_holds_takes_it() {
    let host = host().await;
    let mut reader = host.client().await;
    let (acceptance, _gate) = host
        .runtime
        .close(kr_protocol::session::ClosureReason::CloseRequested);
    assert!(acceptance.initiated, "the close was admitted");
    assert_eq!(domain_state(&host), SessionState::Closing);
    drop(
        host.runtime
            .session_within(CLOSURE_WAIT)
            .expect("nothing holds the session once the close is admitted and its gate is kept"),
    );
    let (_, read) = read_within_its_bound(&mut reader, &host, "control closing").await;
    assert_eq!(read.session.state, SessionState::Closing);
    assert!(
        read.launch_profile.0.is_some(),
        "a read of a session that nothing holds takes it and gives its content"
    );
}

/// A receipt is read from the journal under the session: while the session is held behind a storage
/// call the read answers within its bound that the journal is not reachable, and the same read
/// gives the receipt once the session is let go.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_read_of_a_receipt_while_the_session_is_held_is_answered_within_its_bound() {
    let host = host().await;
    let (mut owner, holder, mut reader) = (
        host.client().await,
        host.client().await,
        host.client().await,
    );
    let action_id = ActionId::new(kr_ipc::new_uuid());
    let attached = owner
        .mutate(
            Method::SessionAttach,
            action_id,
            host.target(),
            &attach_params(host.session_id),
        )
        .await
        .expect("the attach reached the worker");
    assert!(attached.is_ok(), "the attach was accepted: {attached:?}");
    let (_, control) = receipt_within_its_bound(&mut reader, action_id, "control receipt").await;
    assert!(
        control.is_ok(),
        "a receipt is read when nothing holds the session"
    );
    let standing = stall(&host, Stalled::Prune, holder).await;
    let (answered, held) = receipt_within_its_bound(&mut reader, action_id, "held receipt").await;
    let _ = standing.release.send(());
    assert!(
        answered <= READ_BOUND,
        "the receipt read was answered after {answered:?}, past {READ_BOUND:?}"
    );
    let refusal = held.expect_err("a receipt that cannot be read now is refused");
    assert_eq!(
        refusal.code,
        kr_protocol::error::ErrorCode::StorageUnavailable,
        "a receipt that cannot be read now is said to be unreachable"
    );
    assert!(
        refusal
            .message
            .contains("The session did not answer in time, so the receipt was not read."),
        "a take that missed says that the session did not answer: {}",
        refusal.message
    );
    // The stall let go, the same read gives the receipt again.
    let began = Instant::now();
    loop {
        let (_, again) = receipt_within_its_bound(&mut reader, action_id, "after the let-go").await;
        if again.is_ok() {
            break;
        }
        assert!(
            began.elapsed() < AFTER_LET_GO,
            "the receipt was not readable {AFTER_LET_GO:?} after the stall was let go"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// The session is taken and the store does not answer the read of the receipt: the read answers
/// within its bound that the receipt could not be read, and the thread that stands in the store
/// keeps the session, so a read of the session is answered from the published summary until the
/// store answers. Let go, the same read gives the receipt again.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_read_of_a_receipt_that_the_store_does_not_answer_is_answered_within_its_bound() {
    let host = host().await;
    let (mut owner, mut reader, mut other) = (
        host.client().await,
        host.client().await,
        host.client().await,
    );
    let action_id = ActionId::new(kr_ipc::new_uuid());
    let attached = owner
        .mutate(
            Method::SessionAttach,
            action_id,
            host.target(),
            &attach_params(host.session_id),
        )
        .await
        .expect("the attach reached the worker");
    assert!(attached.is_ok(), "the attach was accepted: {attached:?}");
    let (_, control) = receipt_within_its_bound(&mut reader, action_id, "control receipt").await;
    assert!(control.is_ok(), "a receipt is read when the store answers");
    let (arrived, release) = {
        let mut session = host.runtime.session();
        session
            .journal_mut()
            .expect("this session keeps a journal")
            .stall_next_result_read_blocking()
    };
    let (answered, stalled) =
        receipt_within_its_bound(&mut reader, action_id, "stalled receipt").await;
    // The read had taken the session and stood in the store when it was refused.
    reached(arrived, "the receipt read").await;
    assert!(
        answered <= READ_BOUND,
        "the receipt read was answered after {answered:?}, past {READ_BOUND:?}"
    );
    let refusal = stalled.expect_err("a receipt that the store did not answer is refused");
    assert_eq!(
        refusal.code,
        kr_protocol::error::ErrorCode::StorageUnavailable,
        "a receipt that the store did not answer is said to be unreachable"
    );
    assert!(
        refusal
            .message
            .contains("The session's store did not answer in time, so the receipt was not read."),
        "a read that ran past its bound says that the store did not answer: {}",
        refusal.message
    );
    // What the stalled read still holds: the session, until the store answers.
    let (answered, held) =
        read_within_its_bound(&mut other, &host, "held by the receipt read").await;
    assert!(
        answered <= READ_BOUND,
        "the read of a held session was answered after {answered:?}, past {READ_BOUND:?}"
    );
    assert!(
        held.launch_profile.0.is_none(),
        "the read was answered while the stalled receipt read held the session"
    );
    let _ = release.send(());
    // The store answered, so the same read gives the receipt again.
    let began = Instant::now();
    loop {
        let (_, again) = receipt_within_its_bound(&mut reader, action_id, "after the let-go").await;
        if again.is_ok() {
            break;
        }
        assert!(
            began.elapsed() < AFTER_LET_GO,
            "the receipt was not readable {AFTER_LET_GO:?} after the store answered"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// A receipt read of a held session is refused at its take, and the thread that made the take ends
/// with the bound of its own take. Without that bound the thread waits for the session for as long as
/// the hold lasts, so on a store that has stopped for good the threads grow with each read. Each such
/// thread is counted by the service from its start to its end, and the case counts those threads
/// while the hold stands, whatever else holds a reference to the runtime.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_receipt_read_of_a_held_session_leaves_no_thread_waiting_for_the_session() {
    let host = host().await;
    let (holder, mut reader) = (host.client().await, host.client().await);
    let standing = stall(&host, Stalled::Prune, holder).await;
    for read in 1..=3 {
        let (_, refused) = receipt_within_its_bound(
            &mut reader,
            ActionId::new(kr_ipc::new_uuid()),
            &format!("held receipt {read}"),
        )
        .await;
        assert!(
            refused.is_err(),
            "a receipt read of a held session is refused"
        );
    }
    // The threads end a step after their refusal; the session is still held.
    let began = Instant::now();
    while host.service.receipt_threads_alive() != 0 {
        assert!(
            began.elapsed() < READ_BOUND,
            "{} receipt threads still wait for the held session {READ_BOUND:?} after their refusals",
            host.service.receipt_threads_alive()
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let _ = standing.release.send(());
}

/// A receipt read's thread takes the session and stands before it tells its caller. The caller's
/// deadline passes and the caller is refused. The thread, let go, finds that nobody waits for it:
/// it lets the session go and makes no call to the store.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_receipt_read_whose_caller_has_gone_lets_the_session_go_and_makes_no_call_to_the_store() {
    let host = host().await;
    let (mut owner, mut reader) = (host.client().await, host.client().await);
    let action_id = ActionId::new(kr_ipc::new_uuid());
    let attached = owner
        .mutate(
            Method::SessionAttach,
            action_id,
            host.target(),
            &attach_params(host.session_id),
        )
        .await
        .expect("the attach reached the worker");
    assert!(attached.is_ok(), "the attach was accepted: {attached:?}");
    let (store_reached, _store_release) = {
        let mut session = host.runtime.session();
        session
            .journal_mut()
            .expect("this session keeps a journal")
            .stall_next_result_read_blocking()
    };
    let (thread_reached, let_the_thread_go) = host.service.pause_receipt_before_the_send();
    let (_, refused) = receipt_within_its_bound(&mut reader, action_id, "late send").await;
    reached(thread_reached, "the receipt read's thread").await;
    let refusal = refused.expect_err("a read whose thread told nobody is refused");
    assert!(
        refusal
            .message
            .contains("The session did not answer in time, so the receipt was not read."),
        "the caller's wait ran out, and says so: {}",
        refusal.message
    );
    let _ = let_the_thread_go.send(());
    assert!(
        tokio::time::timeout(Duration::from_secs(1), store_reached)
            .await
            .is_err(),
        "a thread whose caller had gone made a call to the store"
    );
    let began = Instant::now();
    while host.service.receipt_threads_alive() != 0 {
        assert!(
            began.elapsed() < READ_BOUND,
            "the receipt read's thread was still alive {READ_BOUND:?} after it was let go"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    drop(
        host.runtime
            .session_within(CLOSURE_WAIT)
            .expect("the thread let the session go"),
    );
}

/// A receipt read's thread starts late: it stands before its first step while its caller's wait
/// runs out, and the session is held. Let go, it has the one deadline that its caller had, which
/// is behind it, so it tries the session once and ends, and does not wait a bound of its own.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_receipt_read_thread_that_starts_after_its_callers_deadline_tries_once_and_ends() {
    let host = host().await;
    let (holder, mut reader) = (host.client().await, host.client().await);
    let (thread_reached, let_the_thread_go) = host.service.pause_receipt_before_the_take();
    let standing = stall(&host, Stalled::Prune, holder).await;
    let (_, refused) = receipt_within_its_bound(
        &mut reader,
        ActionId::new(kr_ipc::new_uuid()),
        "late thread",
    )
    .await;
    reached(thread_reached, "the receipt read's thread").await;
    assert!(
        refused.is_err(),
        "a receipt read of a held session is refused"
    );
    let _ = let_the_thread_go.send(());
    let bound = TAKE_BOUND / 2;
    let began = Instant::now();
    while host.service.receipt_threads_alive() != 0 {
        assert!(
            began.elapsed() < bound,
            "the receipt read's thread was still waiting for the session {bound:?} after it was let go, past its caller's deadline"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let _ = standing.release.send(());
}

/// A session that has recorded its closure publishes it: the summary says closed and carries the
/// record.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_closed_session_publishes_its_closure() {
    let host = host_of(true).await;
    let closure = watch_the_closure(&host.runtime);
    let closer = host.client().await;
    let _slot = send_close(&host, closer);
    let began = Instant::now();
    while closure.try_recv().is_err() {
        assert!(
            began.elapsed() < CLOSURE_WAIT,
            "the closure was not recorded within {CLOSURE_WAIT:?}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // The closure is recorded under the session, which this takes after it.
    drop(host.runtime.session());
    let published = host.runtime.published().latest();
    assert_eq!(published.state, SessionState::Closed);
    assert!(
        published.closure.0.is_some(),
        "the published summary carries the closure record"
    );
    assert_eq!(domain_state(&host), SessionState::Closed);
}
