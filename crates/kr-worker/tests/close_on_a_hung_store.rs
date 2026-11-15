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

#![cfg(unix)]

use std::sync::Arc;
use std::time::{Duration, Instant};

use kr_ipc::client::LocalClient;
use kr_ipc::endpoint::Listener;
use kr_ipc::identity::{ProcessState, process_state};
use kr_ipc::verify::{ControllerIdentity, WorkerIdentity};
use kr_protocol::envelope::ActionTarget;
use kr_protocol::hello::PROTOCOL_VERSION;
use kr_protocol::identity::{DesktopBinding, WorkerProfile};
use kr_protocol::ids::{
    ActionId, BuildId, ControllerGeneration, EnvironmentId, SessionEpoch, SessionId,
};
use kr_protocol::local::LocalClientKind;
use kr_protocol::method::Method;
use kr_protocol::scalars::Nullable;
use kr_protocol::session::{
    Dimensions, DisplayNumber, SessionCloseParams, SessionCloseResult, ShellMode,
};
use kr_worker::runtime::SessionRuntime;
use kr_worker::service::{ServiceBinding, WorkerService};
use kr_worker::session::{Session, SessionConfig};

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
    let marks = tempfile::tempdir().expect("a directory on the internal disk");
    let script = format!(
        "trap 'echo TERM >> {asked}' TERM; trap 'echo HUP >> {asked}' HUP; \
         trap 'echo INT >> {asked}' INT; touch {ready}; while true; do sleep 1; done",
        asked = kr_worker::testing::shell_quoted(&marks.path().join("asked")),
        ready = kr_worker::testing::shell_quoted(&marks.path().join("ready")),
    );
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
    let runtime = Arc::new(
        SessionRuntime::start(session, Arc::new(kr_ipc::clock::SystemSharedClock))
            .expect("starts the runtime"),
    );
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
