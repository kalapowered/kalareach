//! What the local writer asks after its last wait, and what it writes in place of a frame that the
//! question stops.
//!
//! The writer reads the local owner's lease first, which waits for the policy lock, and then asks
//! the one question of the request's footing, which reads atomics and clocks alone. Each case here
//! changes one member in the pause that stands after the lease's reading and before the question,
//! so that nothing but the question stands between the change and the transport, and reads what the
//! caller is handed: every frame that reached the connection, in order.

use std::sync::Arc;
use std::time::Duration;

use kr_ipc::framed::{FrameReader, FrameWriter};
use kr_protocol::envelope::{ControlFrame, Outcome, ParamsValue, Response};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::frame::StreamKind;
use kr_protocol::ids::{AuthorityRevision, ConnectionId, RequestId};
use kr_protocol::method::Method;

use super::a_result_the_lease_ended_over::{
    connected, connected_under_a_lease, connected_under_a_lease_that_can_be_presented_again,
    registered,
};
use super::{Lapse, error_reply, respond};
use crate::authority::AdmissionLapse;
use crate::error::ControllerError;
use crate::given::local_door::WrittenUnder;
use crate::service::Controller;

/// The request that the frames answer.
const REQUEST: RequestId = RequestId::new(7);

/// A change made at the pause that stands after the lease's reading.
type Change = Box<dyn FnOnce() + Send>;

/// The result of a request's effect.
fn result() -> ControlFrame {
    ControlFrame::Response(Response {
        request_id: REQUEST,
        outcome: Outcome::Ok(ParamsValue::empty()),
    })
}

/// A refusal that says nothing was done.
fn a_definite_refusal() -> ControlFrame {
    ControlFrame::Response(Response {
        request_id: REQUEST,
        outcome: Outcome::Error(ProtocolError::new(
            ErrorCode::InvalidArgument,
            "the request names no such thing",
        )),
    })
}

/// A reply that says another request spent the identifier of this one.
fn a_conflict() -> ControlFrame {
    ControlFrame::Response(Response {
        request_id: REQUEST,
        outcome: Outcome::Error(ProtocolError::new(
            ErrorCode::IdConflict,
            "the identifier was used with another request",
        )),
    })
}

/// What a caller is told of an outcome the host will not show.
fn not_shown() -> ControlFrame {
    respond(REQUEST, Err(ControllerError::outcome_not_shown()))
}

/// What a caller is told, in the words of `lapse`, when a request is refused for it.
fn refused_for(lapse: Lapse) -> ControlFrame {
    let refusal = lapse.refusal();
    error_reply(REQUEST, refusal.code(), refusal.to_string())
}

/// What a reader of a withdrawn registration is told: the words of the door's own check of the
/// registration.
fn registration_gone() -> ControlFrame {
    refused_for(Lapse::Withdrawn)
}

/// Waits until a pause says that it has been reached, and fails the case when it is not within
/// thirty seconds.
async fn arrival(arrived: std::sync::mpsc::Receiver<()>) {
    tokio::task::spawn_blocking(move || arrived.recv_timeout(Duration::from_secs(30)))
        .await
        .expect("the waiting thread ends")
        .expect("the writer reaches its question");
}

/// A fence owed, or given back.
fn fence(controller: &Arc<Controller>, owed: bool) -> Change {
    let controller = Arc::clone(controller);
    Box::new(move || controller.hold_fence(owed))
}

/// The registration of `connection_id` withdrawn.
fn withdrawal(controller: &Arc<Controller>, connection_id: ConnectionId) -> Change {
    let controller = Arc::clone(controller);
    Box::new(move || controller.deregister(connection_id))
}

/// Another device's revocation: the stamps of the registrations move to the next revision, none
/// is withdrawn, and the revision in memory moves with them.
fn restamp(controller: &Arc<Controller>) -> Change {
    let controller = Arc::clone(controller);
    Box::new(move || {
        controller
            .admitted_write()
            .values_mut()
            .for_each(|connection| {
                connection.admitted_revision =
                    AuthorityRevision::new(connection.admitted_revision.get() + 1);
            });
        controller
            .copies
            .raise_revision(AuthorityRevision::new(controller.copies.revision() + 1));
    })
}

/// Writes `frame` as the answer to a request for `method`, under `under`, and returns whether the
/// connection goes on with every frame that reached the caller, in order. Each of `changes` is
/// made in turn at the pause after the lease's reading: the first at the first ask, the next at
/// the ask that offers the frame again.
async fn what_the_caller_is_handed(
    controller: &Arc<Controller>,
    mut writer: FrameWriter,
    reader: FrameReader,
    frame: &ControlFrame,
    method: Method,
    under: WrittenUnder,
    changes: Vec<Change>,
) -> (bool, Vec<ControlFrame>) {
    what_the_caller_is_handed_when(controller, reader, changes, || {
        let controller = Arc::clone(controller);
        let frame = frame.clone();
        tokio::spawn(async move {
            let stood = controller
                .write_answer(
                    &mut writer,
                    StreamKind::Control,
                    &frame,
                    Some(method),
                    REQUEST,
                    &under,
                )
                .await;
            // The connection ends with the writer, as it does when the daemon's loop stops.
            drop(writer);
            stood
        })
    })
    .await
}

/// As [`what_the_caller_is_handed`], for a write that `write` starts: the pause is armed before it
/// starts.
async fn what_the_caller_is_handed_when(
    controller: &Arc<Controller>,
    mut reader: FrameReader,
    changes: Vec<Change>,
    write: impl FnOnce() -> tokio::task::JoinHandle<bool>,
) -> (bool, Vec<ControlFrame>) {
    let mut changes = changes.into_iter().peekable();
    let mut armed = changes
        .peek()
        .is_some()
        .then(|| controller.pause_after_the_lease_is_read());
    let writing = write();
    while let Some(change) = changes.next() {
        let (arrived, go) = armed.take().expect("the pause is armed");
        arrival(arrived).await;
        change();
        // The next pause is armed before this one lets the writer go, so the ask that offers the
        // frame again stops there.
        armed = changes
            .peek()
            .is_some()
            .then(|| controller.pause_after_the_lease_is_read());
        go.send(()).expect("the writer goes on");
    }
    let stood = writing.await.expect("the write ends");
    let mut handed = Vec::new();
    while let Ok(read) = tokio::time::timeout(
        Duration::from_secs(30),
        reader.read_message::<ControlFrame>(),
    )
    .await
    .expect("the daemon wrote or ended the connection")
    {
        handed.push(read);
    }
    (stood, handed)
}

/// KR-REQ-09.09: a read's answer is asked the registration where the transport takes it. The
/// registration is withdrawn after the lease's reading, and the answer is not written: the caller
/// is handed the refusal of the registration in the words of the door's own check, and no other
/// frame. The control: with the registration standing, the answer is written once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_read_on_a_set_latch_writes_no_byte_of_its_answer() {
    for withdrawn in [false, true] {
        let (_temp, controller, writer, reader) = connected(false).await;
        let (connection_id, _, footing) = registered(&controller);
        let changes = if withdrawn {
            vec![withdrawal(&controller, connection_id)]
        } else {
            vec![]
        };
        let (stood, handed) = what_the_caller_is_handed(
            &controller,
            writer,
            reader,
            &result(),
            Method::SessionRead,
            WrittenUnder::of_a_read(footing),
            changes,
        )
        .await;
        assert!(stood, "the connection goes on");
        if withdrawn {
            assert_eq!(handed, vec![registration_gone()]);
        } else {
            assert_eq!(handed, vec![result()], "the control");
        }
    }
}

/// KR-REQ-09.09: where the writer withholds a frame it asks once more, and a frame that the second
/// ask lets through is offered afresh, once: a fence given back between the two asks does not
/// withhold a reply read from a record. The controls: with no fence the reply is written once, and
/// with the fence still owed at the second ask it is withheld, once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_frame_that_passes_the_second_ask_is_offered_afresh_and_written_once() {
    for (name, changes_of, expected) in [
        (
            "no fence",
            (|_: &Arc<Controller>| vec![]) as fn(&Arc<Controller>) -> Vec<Change>,
            result(),
        ),
        (
            "a fence given back before the second ask",
            |controller| vec![fence(controller, true), fence(controller, false)],
            result(),
        ),
        (
            "a fence that stays",
            |controller| vec![fence(controller, true), fence(controller, true)],
            not_shown(),
        ),
    ] {
        let (_temp, controller, writer, reader) = connected(false).await;
        let (_, _, footing) = registered(&controller);
        let (stood, handed) = what_the_caller_is_handed(
            &controller,
            writer,
            reader,
            &result(),
            Method::PrivacySet,
            WrittenUnder::for_a_record_case(footing, false),
            changes_of(&controller),
        )
        .await;
        controller.hold_fence(false);
        assert!(stood, "{name}: the connection goes on");
        assert_eq!(handed, vec![expected], "{name}");
    }
}

/// KR-REQ-09.09: a reply read from a record is asked the fence, the revision it was admitted under
/// and the registration, and what replaces it comes from the member that refused at that ask. A
/// copy of what an earlier request did is not shown whichever member refused. A reply that says
/// another request spent the identifier is refused in the words of the member, which is true: that
/// request had no effect of its own.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reply_read_from_a_record_is_replaced_by_the_reply_of_the_member_that_refused() {
    for (member, lapse) in [
        ("the fence", Lapse::FenceOwed),
        ("the revision", Lapse::Admission(AdmissionLapse::Revoked)),
        (
            "the registration",
            Lapse::Admission(AdmissionLapse::Deregistered),
        ),
    ] {
        for conflict in [false, true] {
            let (_temp, controller, writer, reader) = connected(false).await;
            let (connection_id, _, footing) = registered(&controller);
            let change = match lapse {
                Lapse::FenceOwed => fence(&controller, true),
                Lapse::Admission(AdmissionLapse::Revoked) => restamp(&controller),
                _ => withdrawal(&controller, connection_id),
            };
            let frame = if conflict { a_conflict() } else { result() };
            let (stood, handed) = what_the_caller_is_handed(
                &controller,
                writer,
                reader,
                &frame,
                Method::PrivacySet,
                WrittenUnder::for_a_record_case(footing, conflict),
                // The second ask stands at the pause that follows, and the member that refused at
                // the first refuses at it too: the fence stays owed through it.
                vec![change, fence(&controller, lapse == Lapse::FenceOwed)],
            )
            .await;
            controller.hold_fence(false);
            let expected = if conflict {
                refused_for(lapse)
            } else {
                not_shown()
            };
            assert!(stood, "{member}, a conflict: {conflict}");
            assert_eq!(handed, vec![expected], "{member}, a conflict: {conflict}");
        }
    }
}

/// KR-REQ-09.09: a mutation's own reply asks the registration and the lease and no fence: a fence
/// that comes after the door told it does not take back what the request did, and the second
/// asks the same. A reply whose registration has gone follows the rule of what the door told: not
/// shown where it may have taken effect, and the refusal in the words of the registration where it
/// says nothing was done. A revision that moved is no member of its ask.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_fresh_reply_asks_the_registration_and_no_fence() {
    for (name, frame, taken_effect, change_of, expected) in [
        (
            "a result with a fence owed",
            result(),
            true,
            (|controller: &Arc<Controller>, _| fence(controller, true))
                as fn(&Arc<Controller>, ConnectionId) -> Change,
            result(),
        ),
        (
            "a result with the revision moved",
            result(),
            true,
            |controller, _| restamp(controller),
            result(),
        ),
        (
            "a result with its registration withdrawn",
            result(),
            true,
            withdrawal,
            not_shown(),
        ),
        (
            "a refusal with its registration withdrawn",
            a_definite_refusal(),
            false,
            withdrawal,
            registration_gone(),
        ),
        (
            "a refusal with a fence owed",
            a_definite_refusal(),
            false,
            |controller, _| fence(controller, true),
            a_definite_refusal(),
        ),
    ] {
        let (_temp, controller, writer, reader) = connected(false).await;
        let (connection_id, _, footing) = registered(&controller);
        let (stood, handed) = what_the_caller_is_handed(
            &controller,
            writer,
            reader,
            &frame,
            Method::PrivacySet,
            WrittenUnder::for_an_own_effect_case(footing, taken_effect),
            vec![change_of(&controller, connection_id)],
        )
        .await;
        controller.hold_fence(false);
        assert!(stood, "{name}: the connection goes on");
        assert_eq!(handed, vec![expected], "{name}");
    }
}

/// KR-REQ-09.09: a refusal that the door made after the request had changed something does not say
/// that nothing was done, and it is the door's verdict that reaches the writer, whatever the code
/// of the refusal is. Told through the door and written through the sink, such a refusal whose
/// registration is withdrawn in the pause after the lease's reading is not shown, where a fresh
/// refusal of the same code is the registration's refusal, and so is one that a service withheld
/// (its answer is a refusal read from a record that is not the caller's to be told). The control:
/// with the registration standing, the refusal is written as it is.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refusal_made_after_an_effect_is_not_shown_when_its_registration_goes_before_the_write() {
    use crate::given::local_door::{ReplySink, Standing, told};
    use crate::given::{Given, Settled};

    for (name, given_of, withdrawn, expected) in [
        (
            "after an effect, the registration withdrawn",
            Given::after_an_effect as fn(ControlFrame) -> Given<ControlFrame>,
            true,
            not_shown(),
        ),
        (
            "after an effect, the registration standing",
            Given::after_an_effect,
            false,
            a_definite_refusal(),
        ),
        (
            "a fresh refusal, the registration withdrawn",
            Given::fresh,
            true,
            registration_gone(),
        ),
        (
            "a refusal the service withheld, the registration withdrawn",
            Given::withheld,
            true,
            not_shown(),
        ),
    ] {
        let (_temp, controller, mut writer, reader) = connected(false).await;
        let (connection_id, _, footing) = registered(&controller);
        let reply = told(
            Settled::of(given_of(a_definite_refusal())),
            &Standing::new(&controller, footing, REQUEST),
        )
        .await;
        let changes = if withdrawn {
            vec![withdrawal(&controller, connection_id)]
        } else {
            vec![]
        };
        let (stood, handed) = what_the_caller_is_handed_when(&controller, reader, changes, || {
            let controller = Arc::clone(&controller);
            tokio::spawn(async move {
                let stood = ReplySink::new(&mut writer, StreamKind::Control)
                    .write(&controller, reply, Some(Method::PrivacySet))
                    .await;
                drop(writer);
                stood
            })
        })
        .await;
        assert!(stood, "{name}: the connection goes on");
        assert_eq!(handed, vec![expected], "{name}");
    }
}

/// KR-REQ-09.09, KR-REQ-17.54: a lease that ends after the writer has read it stops the frame of
/// every kind, and the reply is the lease's own: the outcome of a write that is unknown, a read's
/// refusal. The control: with the lease standing the frame is written.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_lease_that_ends_after_it_is_read_is_answered_in_the_leases_words() {
    for (name, method, record) in [
        ("a write's own reply", Method::PrivacySet, false),
        ("a read's answer", Method::SessionRead, false),
        ("a write's copy of a record", Method::PrivacySet, true),
    ] {
        for ends in [false, true] {
            let (_temp, controller, continuous, writer, reader) = connected_under_a_lease().await;
            let (_, _, footing) = registered(&controller);
            let under = if record {
                WrittenUnder::for_a_record_case(footing, false)
            } else if method == Method::SessionRead {
                WrittenUnder::of_a_read(footing)
            } else {
                WrittenUnder::for_an_own_effect_case(footing, true)
            };
            let change: Change = if ends {
                Box::new(move || continuous.advance(Duration::from_secs(16 * 60)))
            } else {
                Box::new(|| {})
            };
            let (stood, handed) = what_the_caller_is_handed(
                &controller,
                writer,
                reader,
                &result(),
                method,
                under,
                vec![change],
            )
            .await;
            assert!(stood, "{name}: the connection goes on");
            let expected = if ends {
                controller.lease_ended_reply(REQUEST, Some(method))
            } else {
                result()
            };
            assert_eq!(handed, vec![expected], "{name}, the lease ended: {ends}");
        }
    }
}

/// KR-REQ-17.54: a lease's bound that moved to another run between the writer's reading of the
/// lease and its question is decided by no refusal of the question's own: the writer reads the
/// lease again, goes by that reading, and the frame is written once. The lease is presented again
/// with other rights at each of the two pauses, which narrows it and starts another run of its
/// bound each time, so that the reading that follows the first is found moved too. A moved bound
/// taken as a pass never reaches the second pause, taken as the lease's end it is answered in the
/// lease's words, and returned without the writer's reading again it is not shown.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_bound_that_moved_is_decided_by_the_writers_own_reading_of_the_lease() {
    use crate::grants::policy::{HeldBound, Stands};
    use kr_protocol::rights::ActionRight;

    let (_temp, controller, _continuous, presenter, writer, reader) =
        connected_under_a_lease_that_can_be_presented_again().await;
    let (_, _, footing) = registered(&controller);
    let first = controller
        .local_hold(Method::PrivacySet)
        .expect("the lease is live")
        .bound
        .expect("the lease has a bound");
    // The bound that the writer's second reading finds, which the second pause's change takes
    // before it presents the lease again.
    let second: Arc<std::sync::Mutex<Option<HeldBound>>> = Arc::default();
    let presenter = Arc::new(std::sync::Mutex::new(presenter));
    let first_presentation: Change = Box::new({
        let presenter = Arc::clone(&presenter);
        move || {
            presenter
                .lock()
                .expect("the presenter is free")
                .present(&[ActionRight::FilesRead]);
        }
    });
    let second_presentation: Change = Box::new({
        let controller = Arc::clone(&controller);
        let second = Arc::clone(&second);
        move || {
            *second.lock().expect("the reading is free") = controller
                .local_hold(Method::PrivacySet)
                .expect("the lease is live")
                .bound;
            presenter
                .lock()
                .expect("the presenter is free")
                .present(&[ActionRight::SessionView]);
        }
    });
    let (stood, handed) = what_the_caller_is_handed(
        &controller,
        writer,
        reader,
        &result(),
        Method::PrivacySet,
        WrittenUnder::for_an_own_effect_case(footing, true),
        vec![first_presentation, second_presentation],
    )
    .await;
    assert!(stood, "the connection goes on");
    assert_eq!(handed, vec![result()], "the writer goes by its own reading");
    // Each presentation moved the bound to another run than the one the writer had read.
    let second = second
        .lock()
        .expect("the reading is free")
        .take()
        .expect("the writer read the lease again at the second pause");
    let now = controller.clock.now();
    let utc = controller.settled_utc_now();
    for (reading, bound) in [("first", &first), ("second", &second)] {
        assert_eq!(
            bound.stands_at(now, utc),
            Stands::Moved,
            "the presentation after the {reading} reading started another run of the bound"
        );
    }
}

/// KR-REQ-17.54: the ask that finds a bound moved does not refuse it. Asked by itself, with no
/// offer of the frame again behind it (the attention release asks once), it reads the lease again
/// and goes by that reading: the lease stands, so it passes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_ask_that_finds_a_bound_moved_reads_the_lease_again_and_does_not_refuse() {
    let (_temp, controller, _continuous, presenter, _writer, _reader) =
        connected_under_a_lease_that_can_be_presented_again().await;
    let (_, _, footing) = registered(&controller);
    let under = WrittenUnder::for_an_own_effect_case(footing, true);
    let (arrived, go) = controller.pause_after_the_lease_is_read();
    let asking = tokio::task::spawn_blocking({
        let controller = Arc::clone(&controller);
        move || controller.ask_where_a_frame_lands(Some(Method::PrivacySet), &under)
    });
    arrival(arrived).await;
    presenter.present(&[kr_protocol::rights::ActionRight::FilesRead]);
    // The second reading of the lease reaches the pause again: the ask read it, and does not
    // return the moved bound as a pass.
    let (arrived_again, go_again) = controller.pause_after_the_lease_is_read();
    go.send(()).expect("the ask goes on");
    arrival(arrived_again).await;
    go_again.send(()).expect("the ask goes on");
    assert!(
        asking.await.expect("the ask ends").is_ok(),
        "the ask goes by the lease's second reading"
    );
}

/// KR-REQ-09.09: a frame larger than one checked write is asked once before each piece, and what
/// the question of one piece was asked with is let go before the question of the next. The shared
/// value's count at the pause after the lease's reading of the second piece is the count at the
/// first piece's pause: a slot left to be overwritten by the next question would hold the old
/// value across that question, and the count would be one more. The reader reads while the writer
/// writes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn what_a_piece_was_asked_with_is_let_go_before_the_next_piece_is_asked() {
    let (_temp, controller, _continuous, writer, mut reader) = connected_under_a_lease().await;
    let (_, _, footing) = registered(&controller);
    let under = WrittenUnder::for_an_own_effect_case(footing, true);
    let frame = ControlFrame::Response(Response {
        request_id: REQUEST,
        outcome: Outcome::Ok(
            ParamsValue::from_typed(&"x".repeat(3 * kr_ipc::framed::CHECKED_WRITE_BYTES / 2))
                .expect("a large value"),
        ),
    });
    let reading = tokio::spawn(async move {
        let mut handed = Vec::new();
        while let Ok(read) = tokio::time::timeout(
            Duration::from_secs(30),
            reader.read_message::<ControlFrame>(),
        )
        .await
        .expect("the daemon wrote or ended the connection")
        {
            handed.push(read);
        }
        handed
    });
    let (arrived, go) = controller.pause_after_the_lease_is_read();
    let writing = tokio::spawn({
        let controller = Arc::clone(&controller);
        let frame = frame.clone();
        async move {
            let mut writer = writer;
            let stood = controller
                .write_answer(
                    &mut writer,
                    StreamKind::Control,
                    &frame,
                    Some(Method::PrivacySet),
                    REQUEST,
                    &under,
                )
                .await;
            drop(writer);
            stood
        }
    });
    arrival(arrived).await;
    let at_the_first_piece = Arc::strong_count(&controller.copies);
    let (arrived, go_again) = controller.pause_after_the_lease_is_read();
    go.send(()).expect("the writer goes on");
    arrival(arrived).await;
    let at_the_second_piece = Arc::strong_count(&controller.copies);
    go_again.send(()).expect("the writer goes on");
    assert!(
        writing.await.expect("the write ends"),
        "the connection goes on"
    );
    assert_eq!(
        reading.await.expect("the reader ends"),
        vec![frame],
        "the whole frame reached the reader"
    );
    assert_eq!(
        at_the_second_piece, at_the_first_piece,
        "what the first piece was asked with is let go before the second is asked"
    );
}
