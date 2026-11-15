//! KR-REQ-07.57 through the control daemon: an authorised stop is not kept from happening by a
//! storage call of the worker that does not return.
//!
//! One real daemon, a real worker it adopts (the worker's own service over a real pseudo-terminal,
//! with its journal) and a shell that notes the request to stop and goes on. The journal's own
//! stall seam holds the worker's next dispatch marker, which holds the worker's dispatch barrier
//! and its session. The case then closes the session at the daemon, as `kr close` does and as a
//! paired device does, and records what the person gets and after how long, what state the session
//! is left in, and what the let-go of the stall brings. The stall is let go after a bound of the
//! case's own.
//!
//! A case passes when the stop happens within the times section 7 gives it: the answer inside the
//! seven seconds the daemon's close allows, the shell asked to stop at once, forced after five
//! seconds and the closure recorded two seconds after that.

#![cfg(unix)]

mod net_support;

use std::sync::Arc;
use std::time::{Duration, Instant};

use kr_ipc::identity::{ProcessState, process_state};
use kr_protocol::ids::ActionId;
use kr_protocol::method::Method;
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::Nullable;
use kr_protocol::session::{Dimensions, SessionCloseParams, SessionCloseResult};

use net_support::worker::Adopted;
use net_support::{Device, RawDevice, pair_with, proposal};

const ANSWER_BOUND: Duration = Duration::from_secs(7);
const GRACE: Duration = Duration::from_secs(5);
const DRAIN: Duration = Duration::from_secs(2);
const SLACK: Duration = Duration::from_secs(3);
/// How long a case watches a stall that stands before it lets it go. A paired device's call has
/// thirty seconds of its own, so its case watches longer.
const WINDOW: Duration = Duration::from_secs(17);
const DEVICE_WINDOW: Duration = Duration::from_secs(45);
const AFTER_LET_GO: Duration = Duration::from_secs(25);
const REACH: Duration = Duration::from_secs(20);
/// How long a probe of what the daemon says of the session may take before it is called unanswered.
const PROBE: Duration = Duration::from_secs(5);

/// The shell the session runs: it notes the request to stop and goes on, so the graceful request
/// and the force that follows it are told apart.
fn stubborn(marks: &std::path::Path) -> String {
    format!(
        "trap 'echo TERM >> {asked}' TERM; trap 'echo HUP >> {asked}' HUP; \
         trap 'echo INT >> {asked}' INT; touch {ready}; while true; do sleep 1; done",
        asked = kr_worker::testing::shell_quoted(&marks.join("asked")),
        ready = kr_worker::testing::shell_quoted(&marks.join("ready")),
    )
}

/// A daemon with an adopted worker running the stubborn shell.
struct Rig {
    adopted: Adopted,
    marks: tempfile::TempDir,
    root: kr_protocol::identity::ProcessStartIdentity,
    closure: std::sync::mpsc::Receiver<Instant>,
}

impl Drop for Rig {
    /// Stops the shell this fixture started, however the case ended: a close that was lost leaves
    /// a shell that only a force ends.
    fn drop(&mut self) {
        let runtime = Arc::clone(self.adopted.workers[0].runtime());
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = runtime.session().force_close();
        }));
    }
}

impl Rig {
    async fn start() -> Self {
        let marks = tempfile::tempdir().expect("a directory on the internal disk");
        let adopted = Adopted::start_running(&stubborn(marks.path())).await;
        let started = Instant::now();
        while !marks.path().join("ready").exists() {
            assert!(
                started.elapsed() < Duration::from_secs(30),
                "the shell never said it was ready"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let runtime = Arc::clone(adopted.workers[0].runtime());
        let root = runtime.session().root_identity().expect("a root shell");
        let (sender, closure) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let waiting = tokio::runtime::Builder::new_current_thread()
                .build()
                .expect("a runtime for the watch");
            waiting.block_on(runtime.wait_closed());
            let _ = sender.send(Instant::now());
        });
        Self {
            adopted,
            marks,
            root,
            closure,
        }
    }

    fn worker(&self) -> &net_support::worker::Worker {
        &self.adopted.workers[0]
    }

    fn target(&self) -> kr_protocol::envelope::ActionTarget {
        self.worker().target(self.adopted.host.environment_id)
    }

    /// Stops the worker's next dispatch marker, sends a mutation on the worker's own socket that
    /// stands in it, and returns what lets it go.
    async fn stall_a_marker(&self) -> std::sync::mpsc::Sender<()> {
        let (arrived, release) = {
            let mut session = self.worker().runtime().session();
            let journal = session.journal_mut().expect("this session keeps a journal");
            journal.stall_next_marker_blocking()
        };
        let mut holder = self.worker().client().await;
        let (target, session_id) = (self.target(), self.worker().session_id);
        let mut requested = kr_protocol::scalars::CanonicalSet::new();
        requested.insert(kr_protocol::attachment::AttachmentCapability::ObserveTerminal);
        tokio::spawn(async move {
            let _ = holder
                .mutate(
                    Method::SessionAttach,
                    ActionId::new(kr_ipc::new_uuid()),
                    target,
                    &kr_protocol::attachment::SessionAttachParams {
                        session_id,
                        mode: kr_protocol::attachment::AttachMode::Terminal,
                        claim_geometry: false,
                        dimensions: Nullable::some(Dimensions::new(80, 24)),
                        terminal_profile_id: Nullable::some("xterm-256color".to_owned()),
                        requested,
                    },
                )
                .await;
        });
        tokio::time::timeout(REACH, arrived)
            .await
            .unwrap_or_else(|_| panic!("the mutation did not reach its stall within {REACH:?}"))
            .expect("the stall was dropped before it was reached");
        release
    }
}

/// What a close was answered, counted from its own send.
type Answer = (Duration, Result<SessionCloseResult, String>);
type Slot = Arc<std::sync::Mutex<Option<Answer>>>;

fn look(slot: &Slot) -> Option<Answer> {
    slot.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
}

/// Sends a close at the daemon's local socket, as `kr close` does.
async fn close_at_the_daemon(rig: &Rig) -> Slot {
    let slot: Slot = Arc::new(std::sync::Mutex::new(None));
    let mut client = rig.adopted.host.client().await;
    let (target, session_id) = (rig.target(), rig.worker().session_id);
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

/// Sends a close from a paired device that holds the right to close.
async fn close_from_a_device(rig: &Rig, device: RawDevice) -> Slot {
    let slot: Slot = Arc::new(std::sync::Mutex::new(None));
    let (target, session_id) = (rig.target(), rig.worker().session_id);
    let answered = Arc::clone(&slot);
    let sent = Instant::now();
    tokio::spawn(async move {
        let outcome = device
            .mutate(
                Method::SessionClose,
                ActionId::new(kr_ipc::new_uuid()),
                target,
                &SessionCloseParams { session_id },
            )
            .await;
        let result = match outcome {
            Ok(value) => value.to_typed().map_err(|error| format!("{error}")),
            Err(error) => Err(format!("refused: {error}")),
        };
        *answered
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some((sent.elapsed(), result));
        device.close();
    });
    slot
}

/// What the daemon says of the session, or that it did not say within [`PROBE`].
async fn the_daemon_says(rig: &Rig) -> String {
    let mut client = rig.adopted.host.client().await;
    let session_id = rig.worker().session_id;
    let read = tokio::time::timeout(
        PROBE,
        client.request(
            Method::SessionRead,
            &kr_protocol::session::SessionReadParams { session_id },
        ),
    )
    .await;
    match read {
        Err(_) => format!("no answer to a read within {PROBE:?}"),
        Ok(Err(error)) => format!("the read failed: {error}"),
        Ok(Ok(Err(error))) => format!("the read was refused: {error}"),
        Ok(Ok(Ok(value))) => value
            .to_typed::<kr_protocol::session::SessionReadResult>()
            .map_or_else(
                |error| format!("an answer that does not decode: {error}"),
                |read| format!("state {:?}", read.session.state),
            ),
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

#[derive(Default)]
struct Seen {
    first: Option<Answer>,
    asked: Option<Duration>,
    ended: Option<Duration>,
    closed: Option<Duration>,
}

impl Seen {
    fn line(&self) -> String {
        format!(
            "close answered {}; the shell was asked to stop {}; the shell ended {}; the closure \
             was recorded {}",
            answer_said(&self.first),
            said(self.asked),
            said(self.ended),
            said(self.closed),
        )
    }

    fn shortfalls(&self) -> Vec<String> {
        let mut missed = Vec::new();
        match &self.first {
            Some((after, Ok(_))) if *after <= ANSWER_BOUND => {}
            Some((after, Ok(_))) => missed.push(format!(
                "the close was answered after {after:?}, past {ANSWER_BOUND:?}"
            )),
            Some((after, Err(error))) => {
                missed.push(format!(
                    "the close was not accepted after {after:?}: {error}"
                ));
            }
            None => missed.push("the close was never answered".to_owned()),
        }
        let within =
            |moment: Option<Duration>, bound: Duration| moment.is_some_and(|at| at <= bound);
        if !within(self.asked, SLACK) {
            missed.push(format!("the shell was asked to stop {}", said(self.asked)));
        }
        if !within(self.ended, GRACE + SLACK) {
            missed.push(format!("the shell ended {}", said(self.ended)));
        }
        if !within(self.closed, GRACE + DRAIN + SLACK) {
            missed.push(format!("the closure was recorded {}", said(self.closed)));
        }
        missed
    }
}

/// Watches a close that has been sent, says what the daemon says of the session meanwhile, lets
/// the stall go after `window`, watches for what the let-go brings, and fails when the stop did
/// not happen within its times.
async fn the_stop_is_watched(
    case: &str,
    rig: &Rig,
    started: Instant,
    first: &Slot,
    window: Duration,
    release: Option<std::sync::mpsc::Sender<()>>,
) {
    let mut seen = Seen::default();
    let mut looked_at_the_daemon = false;
    let mut daemon_while_it_stood = String::new();
    let mut step = |seen: &mut Seen| {
        let now = started.elapsed();
        if seen.first.is_none() {
            seen.first = look(first);
        }
        if seen.asked.is_none() && rig.marks.path().join("asked").exists() {
            seen.asked = Some(now);
        }
        if seen.ended.is_none() && matches!(process_state(&rig.root), ProcessState::Ended) {
            seen.ended = Some(now);
        }
        if seen.closed.is_none()
            && let Ok(at) = rig.closure.try_recv()
        {
            seen.closed = Some(at.saturating_duration_since(started));
        }
        seen.first.is_some()
            && seen.asked.is_some()
            && seen.ended.is_some()
            && seen.closed.is_some()
    };
    while started.elapsed() < window {
        if step(&mut seen) {
            break;
        }
        if !looked_at_the_daemon
            && started.elapsed() > window.saturating_sub(Duration::from_secs(8))
        {
            looked_at_the_daemon = true;
            daemon_while_it_stood = the_daemon_says(rig).await;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    step(&mut seen);
    let standing_line = seen.line();
    let shortfalls = seen.shortfalls();
    let let_go_at = started.elapsed();
    let mut daemon_after = String::new();
    if let Some(release) = release {
        let _ = release.send(());
        while started.elapsed() < let_go_at + AFTER_LET_GO {
            if step(&mut seen) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        step(&mut seen);
        daemon_after = the_daemon_says(rig).await;
    }
    eprintln!(
        "RESULT {case}: stall let go at {let_go_at:.2?}\n\
         RESULT {case}: while it stood (to {window:?}): {standing_line}; the daemon said of the \
         session: {daemon_while_it_stood}\n\
         RESULT {case}: at the end (to {AFTER_LET_GO:?} after the let-go): {}; the daemon said \
         of the session: {daemon_after}\n\
         RESULT {case}: the shell's record of what it was asked: {:?}\n\
         RESULT {case}: shortfalls inside its times: {shortfalls:?}",
        seen.line(),
        std::fs::read_to_string(rig.marks.path().join("asked")).unwrap_or_default(),
    );
    assert!(
        shortfalls.is_empty(),
        "{case}: the authorised stop did not happen within its times while the storage call stood \
         still: {shortfalls:?}"
    );
}

/// Control: nothing stands still, and a close at the daemon stops the session within its times.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_close_at_the_daemon_with_nothing_standing_still_stops_within_its_times() {
    let rig = Rig::start().await;
    let started = Instant::now();
    let first = close_at_the_daemon(&rig).await;
    the_stop_is_watched("control", &rig, started, &first, WINDOW, None).await;
}

/// `kr close` while the worker's dispatch marker stands still: the daemon's seven seconds, what
/// the person is told, and the state the session is left in.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "shows an open finding"]
async fn a_close_at_the_daemon_stops_the_session_while_a_marker_write_stands_still() {
    let rig = Rig::start().await;
    let release = rig.stall_a_marker().await;
    let started = Instant::now();
    let first = close_at_the_daemon(&rig).await;
    the_stop_is_watched("daemon", &rig, started, &first, WINDOW, Some(release)).await;
}

/// The same from a paired device that holds the right to close.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "shows an open finding"]
async fn a_close_from_a_paired_device_stops_the_session_while_a_marker_write_stands_still() {
    let rig = Rig::start().await;
    let device = Device::create().await;
    let record = pair_with(
        &rig.adopted.host,
        &device,
        &rig.adopted.owner,
        proposal(&[ActionRight::SessionView, ActionRight::SessionClose]),
    )
    .await;
    let connection = RawDevice::connect(&rig.adopted.host, &device, &record).await;
    let release = rig.stall_a_marker().await;
    let started = Instant::now();
    let first = close_from_a_device(&rig, connection).await;
    the_stop_is_watched(
        "device",
        &rig,
        started,
        &first,
        DEVICE_WINDOW,
        Some(release),
    )
    .await;
}
