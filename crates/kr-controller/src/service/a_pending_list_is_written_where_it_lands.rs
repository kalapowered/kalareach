//! Where the owner's list of outstanding confirmations lands.
//!
//! The local door lists the challenges twice, from the same entries and before the local owner's
//! lease is asked again: the list under the scope the caller was decided for, and the list under
//! the scope that no lease serves. The bound of the lease the first was decided under is held by
//! the list's carrier, since a read has no landing of its own. The writer asks the footing's one
//! question with that bound immediately before the transport takes any byte, and that question
//! alone chooses which list the transport takes.
//!
//! The order of events of the cases that stop the list before the writer: the daemon's read of the
//! list ends (its last real wait is the join of the blocking read that made both lists); the case
//! makes the footing the door makes after that read; the case ends what it ends, in a step of its
//! own, with nothing running beside it; the writer is then called, and its question stands after
//! that step. The writer's own waits are the lease's reading, which a method held to the lease
//! takes and this method does not, and the wait for room on a full socket.
//!
//! The four cases of the wait for room run the other way round: the writer starts first, on a
//! socket the case has filled to the byte, and stops at the pause that stands after its wait for
//! room. Before the fill the case consumes the writable mark that the connection's registration
//! keeps, so that the writer's readiness call finds the socket full and waits; the case counts that
//! wait, reads filler frames one at a time, under a bound, until the writer reports its arrival at
//! the pause, and asserts that at least one read was needed (how many reads the kernel needs before
//! a socket is writable again is its own, and a case does not rest on one). An arrival at the pause
//! shows that a read of the peer ended a wait, and no more than that. The case ends what it ends
//! there, the writer goes on, and the fillers that remain are read. The replies are read whole.
//!
//! The pause holds the writer's worker thread, and the worker that runs the writer's task when the
//! socket turns writable is the one that drives the runtime's timers and socket events: until the
//! case lets the writer go, nothing drives them. So between the arming of the pause and the
//! release of the writer the case awaits no timer and no event of the runtime that it could still
//! be waiting on when the writer arrives: the fillers it reads are queued and need no event, the
//! count of the writer's wait is read on a thread of the blocking pool, and the writer's arrival
//! is waited for with the channel's own bounded wait on that pool. A thread of the standard
//! library, the case's watch, fails a case that stays in one stage for longer than its bound.

use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use kr_protocol::confirmation::{
    ConfirmationDisplay, OwnerConfirmationPendingParams, OwnerConfirmationPendingResult,
    PendingConfirmation,
};
use kr_protocol::envelope::{ControlFrame, Outcome, ParamsValue, Request, Response};
use kr_protocol::frame::StreamKind;
use kr_protocol::ids::{ActionId, RequestId};
use kr_protocol::method::{Method, MethodVersion};
use kr_protocol::pairing::SensitiveAction;
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{CanonicalSet, Digest256};

use super::a_result_the_lease_ended_over::connected_under_a_lease_that_can_be_presented_again;
use super::an_owner_establishes_the_clock::Door;
use crate::given::local_door::WrittenUnder;
use crate::service::net::owner::Resolved;

const REQUEST: RequestId = RequestId::new(11);

/// What ends between the daemon's read of the list and the writer's question.
#[derive(Clone, Copy, Debug)]
enum Ends {
    /// Nothing: the control.
    Nothing,
    /// The lease's time: the continuous clock passes its end.
    TheLeasesTime,
    /// The lease is presented again, which publishes another lineage in the bound's cell.
    TheLeaseIsPresentedAgain,
    /// The lease's time and the connection's registration: the caller is withdrawn.
    #[cfg(unix)]
    TheLeaseAndTheRegistrationEnd,
    /// The lease's time passes before the writer begins, so that the list asked first is refused
    /// with no byte written and the list that no lease serves is the frame whose own write waits
    /// for room; nothing ends in that wait.
    #[cfg(unix)]
    TheReplacementWaitsAndStands,
    /// As [`Ends::TheReplacementWaitsAndStands`], and the connection's registration ends in the
    /// replacement's own wait for room.
    #[cfg(unix)]
    TheReplacementWaitsAndItsRegistrationEnd,
}

fn resolved(display: ConfirmationDisplay) -> Resolved {
    Resolved {
        action: SensitiveAction::ChangeHostAuthority,
        digest: Digest256::from_bytes([9; 32]),
        destination: None,
        rights: CanonicalSet::new(),
        display,
        bootstrap: false,
    }
}

/// The reply that carries `list` to the request, as the door tells it.
fn told(list: &[PendingConfirmation]) -> ControlFrame {
    ControlFrame::Response(Response {
        request_id: REQUEST,
        outcome: Outcome::Ok(
            ParamsValue::from_typed(&OwnerConfirmationPendingResult {
                pending: list.to_vec(),
            })
            .expect("the list encodes"),
        ),
    })
}

/// Everything a case holds once the daemon has read the list and the door has made the footing: the
/// connection's two ends, the answer and the standing the writer is handed, and the two lists that
/// could be written.
struct Staged {
    _temp: kr_ipc::testing::TempHost,
    controller: Arc<crate::service::Controller>,
    continuous: kr_transport::clock::ManualClock,
    presenter: super::a_result_the_lease_ended_over::Presenter,
    writer: kr_ipc::framed::FrameWriter,
    reader: kr_ipc::framed::FrameReader,
    #[cfg(unix)]
    connection_id: kr_protocol::ids::ConnectionId,
    answer: ControlFrame,
    under: WrittenUnder,
    full: ControlFrame,
    closed: ControlFrame,
}

/// Reads the list through the door and makes the standing the writer is handed.
async fn staged() -> Staged {
    let (temp, controller, continuous, presenter, writer, reader) =
        connected_under_a_lease_that_can_be_presented_again().await;
    let door = Door::open(&temp, &controller).await;
    let revision = controller.admitted_revision(door.connection_id()).ok();
    let deadline = controller
        .clock
        .now()
        .checked_add(Duration::from_secs(3600))
        .expect("a deadline");
    let caller = controller
        .local_caller(door.actor_id())
        .landed(controller.pairing_landing(door.connection_id(), revision, Some(deadline)));
    // Two challenges: the confirmation of the clock, which the scope that no lease serves holds,
    // and the one that makes the host exclusive, which it does not.
    let displays = [
        ConfirmationDisplay::EstablishClock,
        ConfirmationDisplay::ExclusiveManagement {
            exclusive: true,
            organisation_ids: Vec::new(),
        },
    ];
    let mut every = Vec::new();
    for (position, display) in displays.into_iter().enumerate() {
        let owner = Arc::clone(controller.owner_authority());
        let caller = caller.clone();
        let shown = display.clone();
        let action = (
            ActionId::new(kr_ipc::new_uuid()),
            Digest256::from_bytes([3 + u8::try_from(position).expect("a small position"); 32]),
        );
        let requested = tokio::task::spawn_blocking(move || {
            owner.request(&caller, resolved(display), action, &AtomicBool::new(false))
        })
        .await
        .expect("the request ends")
        .expect("the request is recorded");
        every.push(PendingConfirmation {
            request: requested.request,
            display: shown,
            answered: false,
        });
    }
    let closed = told(&every[..1]);
    let full = told(&every);
    let request = Request {
        request_id: REQUEST,
        method: Method::OwnerConfirmationPending.into(),
        method_version: MethodVersion::V1,
        params: ParamsValue::from_typed(&OwnerConfirmationPendingParams {})
            .expect("the parameters encode"),
    };
    let (answer, instead) = controller.local_read(door.actor_id(), &request).await;
    let under = WrittenUnder::of_a_read(controller.footing_of_a_request(door.connection_id()))
        .listing(instead);
    Staged {
        _temp: temp,
        controller,
        continuous,
        presenter,
        writer,
        reader,
        #[cfg(unix)]
        connection_id: door.connection_id(),
        answer,
        under,
        full,
        closed,
    }
}

/// What the writer put on the connection when `ends` came after the daemon's read of the list and
/// before the writer's question, and the two lists that could have been written: the one the caller
/// was decided for and the one that no lease serves.
async fn written_when(ends: Ends) -> (ControlFrame, ControlFrame, ControlFrame) {
    let Staged {
        _temp,
        controller,
        continuous,
        presenter,
        mut writer,
        mut reader,
        answer,
        under,
        full,
        closed,
        ..
    } = staged().await;
    match ends {
        Ends::Nothing => {}
        Ends::TheLeasesTime => continuous.advance(Duration::from_secs(16 * 60)),
        Ends::TheLeaseIsPresentedAgain => presenter.present(&[ActionRight::FilesRead]),
        #[cfg(unix)]
        Ends::TheLeaseAndTheRegistrationEnd
        | Ends::TheReplacementWaitsAndStands
        | Ends::TheReplacementWaitsAndItsRegistrationEnd => {
            unreachable!("the wait for room is where these cases end what they end")
        }
    }
    let writing = {
        let controller = Arc::clone(&controller);
        tokio::spawn(async move {
            let stood = controller
                .write_answer(
                    &mut writer,
                    StreamKind::Control,
                    &answer,
                    Some(Method::OwnerConfirmationPending),
                    REQUEST,
                    &under,
                )
                .await;
            drop(writer);
            stood
        })
    };
    let read = tokio::time::timeout(Duration::from_secs(30), reader.read_message())
        .await
        .expect("the daemon wrote or ended the connection")
        .expect("the list reads");
    assert!(
        writing.await.expect("the write ends"),
        "the connection goes on"
    );
    (read, full, closed)
}

/// KR-REQ-17.54: where the bound the list was decided under stands at the question, the list the
/// caller was decided for is written, whole: both challenges, oldest first.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_list_whose_bound_stands_at_its_question_is_written_whole() {
    let (read, full, closed) = written_when(Ends::Nothing).await;
    assert_ne!(full, closed, "the two lists differ");
    assert_eq!(read, full);
}

/// KR-REQ-17.54: a lease that ends after the daemon's read of the list and before the writer's
/// question is found by the question: the list under the scope that no lease serves is written,
/// whole, and the challenge it does not hold is not shown.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_list_whose_bound_ends_before_the_question_is_written_under_the_closed_scope() {
    let (read, full, closed) = written_when(Ends::TheLeasesTime).await;
    assert_ne!(full, closed, "the two lists differ");
    assert_eq!(read, closed);
}

/// KR-REQ-17.54: a lease that is presented again before the writer's question moves the bound to another
/// lineage, which counts as an ended lease: the list under the scope that no lease serves is
/// written, whole.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_list_whose_bound_moves_before_the_question_is_written_under_the_closed_scope() {
    let (read, full, closed) = written_when(Ends::TheLeaseIsPresentedAgain).await;
    assert_ne!(full, closed, "the two lists differ");
    assert_eq!(read, closed);
}

/// KR-REQ-17.54: the local door decodes the list's parameters as the device's door does: a request
/// that names a member the parameters do not have is refused with the refusal that decoding gives,
/// whole, and no list is read. The control: the same request with no member is answered with the
/// list.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_list_asked_for_with_an_unknown_member_is_refused_as_the_devices_door_refuses_it() {
    #[derive(serde::Serialize)]
    struct Unknown {
        zz_unknown: u8,
    }
    let (temp, controller, _continuous, _presenter, _writer, _reader) =
        connected_under_a_lease_that_can_be_presented_again().await;
    let door = Door::open(&temp, &controller).await;
    let asked = |params: ParamsValue| Request {
        request_id: REQUEST,
        method: Method::OwnerConfirmationPending.into(),
        method_version: MethodVersion::V1,
        params,
    };
    let unknown =
        ParamsValue::from_typed(&Unknown { zz_unknown: 1 }).expect("the parameters encode");
    let error = crate::service::net::methods::decode_pending_params(&unknown)
        .expect_err("the parameters name a member that they do not have");
    let (answer, _) = controller
        .local_read(door.actor_id(), &asked(unknown))
        .await;
    assert_eq!(answer, crate::service::respond(REQUEST, Err(error)));
    let none = ParamsValue::from_typed(&OwnerConfirmationPendingParams {}).expect("encodes");
    let (answer, _) = controller.local_read(door.actor_id(), &asked(none)).await;
    assert_eq!(
        answer,
        told(&[]),
        "the control: no challenge is outstanding"
    );
}

/// How long the writer's arrival, or the count of its wait, is waited for on a thread of the
/// blocking pool.
#[cfg(unix)]
const ARRIVAL: Duration = Duration::from_secs(30);

/// Reads one filler frame. The frames the case reads are queued whole, so a read finds its bytes
/// and waits for no event of the runtime; the case's watch bounds the stage.
#[cfg(unix)]
async fn filler(reader: &mut kr_ipc::framed::FrameReader) {
    reader.read_payload().await.expect("a filler frame");
}

/// Reads filler frames, one at a time, until the writer says it has reached the end of its wait for
/// room, and returns how many were read. How many frames the socket must lose before it is
/// writable again is the kernel's to say (Linux reports a Unix socket writable only when what is
/// queued on it has fallen to a fraction of its send buffer, which one frame's read need not do), so
/// the case reads until the writer arrives and does not assume that one read is enough. Where every
/// filler has been read the socket is empty, and the writer is waited for with the channel's own
/// bounded wait on a thread of the blocking pool: a timer of the runtime would wait on a driver
/// that the writer, once it has arrived, holds in its pause.
#[cfg(unix)]
async fn drained_until_the_writer_arrives(
    reader: &mut kr_ipc::framed::FrameReader,
    arrived: std::sync::mpsc::Receiver<()>,
    fillers: usize,
) -> usize {
    let mut read = 0;
    while arrived.try_recv().is_err() {
        if read == fillers {
            tokio::task::spawn_blocking(move || arrived.recv_timeout(ARRIVAL))
                .await
                .expect("the wait for the writer ends")
                .unwrap_or_else(|_| {
                    panic!(
                        "the writer reaches the end of its wait within {ARRIVAL:?}, {read} of {fillers} fillers read"
                    )
                });
            break;
        }
        filler(reader).await;
        read += 1;
        // The writer's task runs on what the read freed: no pause is put between two reads, since
        // a loaded machine stretches a pause and the bound is on the whole.
        tokio::task::yield_now().await;
    }
    read
}

/// Fills the connection's socket to the byte with whole filler frames, so that the next frame the
/// writer is handed meets a socket that takes none of it, and returns the number of filler frames
/// the peer has yet to read. The case owns both ends: it writes small frames one byte at a time
/// until a one-byte write is refused (a one-byte write goes whole or not at all, so the refused one
/// is taken back), and where that stopped inside a filler frame it reads two frames, finishes that
/// frame and writes one frame of exactly the room that is left.
#[cfg(unix)]
async fn filled(
    writer: &mut kr_ipc::framed::FrameWriter,
    reader: &mut kr_ipc::framed::FrameReader,
) -> usize {
    use kr_ipc::framed::Wrote;
    let codec = kr_protocol::frame::FrameCodec::new(StreamKind::Control);
    let small = codec.encode(&[7]).expect("a frame");
    let (mut whole, mut dangling) = (0_usize, 0_usize);
    loop {
        match writer
            .begin_frame(&small[dangling..=dangling])
            .expect("the peer is there")
        {
            Wrote::Complete => {
                dangling += 1;
                if dangling == small.len() {
                    dangling = 0;
                    whole += 1;
                }
            }
            Wrote::Blocked => {
                assert!(
                    writer.withdraw_unstarted(),
                    "a byte goes whole or not at all"
                );
                break;
            }
        }
    }
    if dangling != 0 {
        for _ in 0..2 {
            filler(reader).await;
        }
        for byte in &small[dangling..] {
            assert_eq!(
                writer.begin_frame(&[*byte]).expect("the peer is there"),
                Wrote::Complete
            );
        }
        let last = codec
            .encode(&vec![8; dangling + 1])
            .expect("a frame of the room that is left");
        for byte in &last {
            assert_eq!(
                writer.begin_frame(&[*byte]).expect("the peer is there"),
                Wrote::Complete
            );
        }
    }
    assert_eq!(
        writer.begin_frame(&[0]).expect("the peer is there"),
        Wrote::Blocked,
        "the socket takes no byte more"
    );
    assert!(writer.withdraw_unstarted());
    whole
}

/// The end of a case that needs no runtime: a thread of the standard library, started with the
/// case and ended with it, that tells the case the name of its stage when one stage has lasted
/// longer than [`Watch::BOUND`]. Each [`Watch::stage`] starts the bound afresh. The thread waits on
/// a condition variable with a time bound and tells the case through a channel whose send needs no
/// runtime either, so a runtime whose every worker is held cannot stop it. The case then fails
/// with the stage's name. Where the case has not ended [`Watch::GRACE`] after that, the thread
/// ends the test program with the stage's name on standard error, since a case that its own
/// failure cannot end holds the list just as a stand does. A stage of a correct run lasts
/// milliseconds, and seconds on a loaded machine; the bound is a minute, so the watch cannot
/// fire in a slow but correct run.
#[cfg(unix)]
struct Watch {
    stage: Arc<(std::sync::Mutex<Stage>, std::sync::Condvar)>,
    thread: Option<std::thread::JoinHandle<()>>,
}

/// Where the case is, and since when; `ended` is set by the case's end.
#[cfg(unix)]
struct Stage {
    name: &'static str,
    since: std::time::Instant,
    ended: bool,
}

#[cfg(unix)]
impl Watch {
    const BOUND: Duration = Duration::from_secs(60);
    const GRACE: Duration = Duration::from_secs(30);

    /// Starts the watch at the stage `first`, and returns the end that carries the name of a stage
    /// that stood past its bound.
    fn armed(first: &'static str) -> (Self, tokio::sync::oneshot::Receiver<&'static str>) {
        let stage = Arc::new((
            std::sync::Mutex::new(Stage {
                name: first,
                since: std::time::Instant::now(),
                ended: false,
            }),
            std::sync::Condvar::new(),
        ));
        let (expires, expired) = tokio::sync::oneshot::channel();
        let thread = std::thread::spawn({
            let stage = Arc::clone(&stage);
            move || {
                let (lock, changed) = &*stage;
                let mut at = lock
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let mut told = Some(expires);
                loop {
                    if at.ended {
                        return;
                    }
                    let past = at.since.elapsed();
                    let bound = if told.is_some() {
                        Self::BOUND
                    } else {
                        Self::GRACE
                    };
                    if let Some(left) = bound.checked_sub(past).filter(|left| !left.is_zero()) {
                        at = changed
                            .wait_timeout(at, left)
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .0;
                    } else if let Some(expires) = told.take() {
                        let _ = expires.send(at.name);
                        at.since = std::time::Instant::now();
                    } else {
                        eprintln!(
                            "the case stood in the stage \"{}\" and its failure did not end it",
                            at.name
                        );
                        std::process::exit(101);
                    }
                }
            }
        });
        (
            Self {
                stage,
                thread: Some(thread),
            },
            expired,
        )
    }

    /// The case has reached the stage `name`.
    fn stage(&self, name: &'static str) {
        let mut at = self
            .stage
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        at.name = name;
        at.since = std::time::Instant::now();
    }
}

#[cfg(unix)]
impl Drop for Watch {
    fn drop(&mut self) {
        self.stage
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .ended = true;
        self.stage.1.notify_all();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// What the writer put on the connection when the socket had no room for the list and `ends` came
/// in that wait: the frames are read once the writer has gone on. A case that stays in one stage
/// past the watch's bound fails with the stage's name.
#[cfg(unix)]
async fn written_after_a_wait_for_room(ends: Ends) -> (ControlFrame, ControlFrame, ControlFrame) {
    let (watch, mut stood) = Watch::armed("the connection is staged");
    tokio::select! {
        written = written_in_stages(ends, &watch) => written,
        Ok(stage) = &mut stood => panic!(
            "the case stood in the stage \"{stage}\" for more than {:?}",
            Watch::BOUND
        ),
    }
}

/// The stages of [`written_after_a_wait_for_room`].
#[cfg(unix)]
async fn written_in_stages(
    ends: Ends,
    watch: &Watch,
) -> (ControlFrame, ControlFrame, ControlFrame) {
    let Staged {
        _temp,
        controller,
        continuous,
        presenter,
        mut writer,
        mut reader,
        answer,
        under,
        full,
        closed,
        connection_id,
        ..
    } = staged().await;
    // The registration of the writer's descriptor keeps a writable mark until a readiness call
    // consumes it, and a call that finds the mark returns at once, with the socket full. The mark
    // is consumed here, while the socket is empty, so that the readiness call the writer makes
    // after the fill finds the socket full and waits for it.
    watch.stage("the registration's mark is consumed");
    tokio::time::timeout(Duration::from_secs(30), writer.writable().ready())
        .await
        .expect("the readiness call on the empty socket returns")
        .expect("the connection can be waited on");
    watch.stage("the socket is filled");
    let fillers = filled(&mut writer, &mut reader).await;
    let replacement_waits = matches!(
        ends,
        Ends::TheReplacementWaitsAndStands | Ends::TheReplacementWaitsAndItsRegistrationEnd
    );
    if replacement_waits {
        continuous.advance(Duration::from_secs(16 * 60));
    }
    watch.stage("the writer is started");
    let (arrived, go) = controller.pause_after_a_wait_for_room();
    let writing = {
        let controller = Arc::clone(&controller);
        tokio::spawn(async move {
            let stood = controller
                .write_answer(
                    &mut writer,
                    StreamKind::Control,
                    &answer,
                    Some(Method::OwnerConfirmationPending),
                    REQUEST,
                    &under,
                )
                .await;
            drop(writer);
            stood
        })
    };
    // The writer is waiting for room once its wait has been counted. The count is read on a thread
    // of the blocking pool: no timer of the runtime is waited on from here to the writer's release.
    watch.stage("the wait for room is counted");
    {
        let controller = Arc::clone(&controller);
        tokio::task::spawn_blocking(move || {
            let begun = std::time::Instant::now();
            while controller.local_writes_blocked() < 1 {
                assert!(
                    begun.elapsed() < ARRIVAL,
                    "the writer waits for room within {ARRIVAL:?}"
                );
                std::thread::sleep(Duration::from_millis(1));
            }
        })
        .await
        .expect("the writer waits for room");
    }
    if replacement_waits {
        assert_eq!(
            controller.local_writes_blocked(),
            1,
            "the one wait for room is the replacement's own: the list asked first was refused \
             with no byte written"
        );
    }
    watch.stage("the fillers are read until the writer arrives");
    let drained = drained_until_the_writer_arrives(&mut reader, arrived, fillers).await;
    assert!(
        drained >= 1,
        "the peer read at least one filler before the writer arrived, so a read ended its wait"
    );
    match ends {
        Ends::Nothing => {}
        Ends::TheLeasesTime => continuous.advance(Duration::from_secs(16 * 60)),
        Ends::TheLeaseIsPresentedAgain => presenter.present(&[ActionRight::FilesRead]),
        Ends::TheLeaseAndTheRegistrationEnd => {
            continuous.advance(Duration::from_secs(16 * 60));
            controller.deregister(connection_id);
        }
        Ends::TheReplacementWaitsAndStands => {}
        Ends::TheReplacementWaitsAndItsRegistrationEnd => controller.deregister(connection_id),
    }
    go.send(()).expect("the writer goes on");
    watch.stage("the rest of the fillers is read");
    for _ in drained..fillers {
        filler(&mut reader).await;
    }
    watch.stage("the reply is read");
    let read = tokio::time::timeout(Duration::from_secs(30), reader.read_message())
        .await
        .expect("the daemon wrote or ended the connection")
        .expect("the list reads");
    watch.stage("the writer's task ends");
    assert!(
        tokio::time::timeout(Duration::from_secs(30), writing)
            .await
            .expect("the writer's task ends")
            .expect("the write ends"),
        "the connection goes on"
    );
    (read, full, closed)
}

/// KR-REQ-17.54: where the socket has no room for the list and the bound stands when the wait for
/// room ends, the question after that wait lets the list through, whole.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_list_that_waited_for_room_with_its_bound_standing_is_written_whole() {
    let (read, full, closed) = written_after_a_wait_for_room(Ends::Nothing).await;
    assert_ne!(full, closed, "the two lists differ");
    assert_eq!(read, full);
}

/// KR-REQ-17.54: a lease that ends in the wait for room is found by the question that follows the
/// wait: the list under the scope that no lease serves is written, whole, and not the list that
/// was decided under the lease.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_list_whose_bound_ends_in_the_wait_for_room_is_written_under_the_closed_scope() {
    let (read, full, closed) = written_after_a_wait_for_room(Ends::TheLeasesTime).await;
    assert_ne!(full, closed, "the two lists differ");
    assert_eq!(read, closed);
}

/// KR-REQ-17.54: a caller whose registration ends in the wait for room, with its lease, is told the
/// refusal of the registration, whole, and no byte of either list is written: the question after
/// the wait reads the registration before the lease's bound, so the list under the scope that no
/// lease serves is not chosen for a caller that has been withdrawn.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_caller_whose_registration_ends_in_the_wait_for_room_is_refused_and_no_list_is_written() {
    let (read, full, closed) =
        written_after_a_wait_for_room(Ends::TheLeaseAndTheRegistrationEnd).await;
    assert_ne!(read, full);
    assert_ne!(read, closed);
    let refusal = crate::service::Lapse::Withdrawn.refusal();
    assert_eq!(
        read,
        crate::service::error_reply(REQUEST, refusal.code(), refusal.to_string())
    );
}

/// KR-REQ-17.54: a caller whose lease ended before the writer began is given the list under the
/// scope that no lease serves from its first byte, and that frame's own write waits for room: where
/// nothing ends in that wait it is written, whole; where the connection's registration ends in it,
/// the question after the wait refuses it, the caller is told the refusal of the registration,
/// whole, and no byte of either list is written.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_caller_whose_registration_ends_in_the_replacements_own_wait_is_refused_and_no_list_is_written()
 {
    let (read, full, closed) =
        written_after_a_wait_for_room(Ends::TheReplacementWaitsAndStands).await;
    assert_ne!(full, closed, "the two lists differ");
    assert_eq!(read, closed);
    let (read, full, closed) =
        written_after_a_wait_for_room(Ends::TheReplacementWaitsAndItsRegistrationEnd).await;
    assert_ne!(read, full);
    assert_ne!(read, closed);
    let refusal = crate::service::Lapse::Withdrawn.refusal();
    assert_eq!(
        read,
        crate::service::error_reply(REQUEST, refusal.code(), refusal.to_string())
    );
}
