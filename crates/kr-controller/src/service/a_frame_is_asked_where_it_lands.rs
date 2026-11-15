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
    let refusal = lapse.refusal().expect("the member has words of its own");
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
    mut reader: FrameReader,
    frame: &ControlFrame,
    method: Method,
    under: WrittenUnder,
    changes: Vec<Change>,
) -> (bool, Vec<ControlFrame>) {
    let mut changes = changes.into_iter().peekable();
    let mut armed = changes
        .peek()
        .is_some()
        .then(|| controller.pause_after_the_lease_is_read());
    let writing = tokio::spawn({
        let controller = Arc::clone(controller);
        let frame = frame.clone();
        async move {
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
        }
    });
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
                vec![change, fence(&controller, false)],
            )
            .await;
            // The second ask stands at the pause that follows; the frame is withheld at it again
            // unless the change was the fence, which the second change gave back.
            let expected = if lapse == Lapse::FenceOwed {
                frame
            } else if conflict {
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
    for (name, frame, change_of, expected) in [
        (
            "a result with a fence owed",
            result(),
            (|controller: &Arc<Controller>, _| fence(controller, true))
                as fn(&Arc<Controller>, ConnectionId) -> Change,
            result(),
        ),
        (
            "a result with the revision moved",
            result(),
            |controller, _| restamp(controller),
            result(),
        ),
        (
            "a result with its registration withdrawn",
            result(),
            withdrawal,
            not_shown(),
        ),
        (
            "a refusal with its registration withdrawn",
            a_definite_refusal(),
            withdrawal,
            registration_gone(),
        ),
        (
            "a refusal with a fence owed",
            a_definite_refusal(),
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
            WrittenUnder::for_an_own_effect_case(footing),
            vec![change_of(&controller, connection_id)],
        )
        .await;
        controller.hold_fence(false);
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
                WrittenUnder::for_an_own_effect_case(footing)
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
/// with other rights, which narrows it and starts another run of its bound.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_bound_that_moved_is_decided_by_the_writers_own_reading_of_the_lease() {
    let (_temp, controller, _continuous, presenter, writer, reader) =
        connected_under_a_lease_that_can_be_presented_again().await;
    let (_, _, footing) = registered(&controller);
    let held = controller
        .local_hold(Method::PrivacySet)
        .expect("the lease is live")
        .bound
        .expect("the lease has a bound");
    let (stood, handed) = what_the_caller_is_handed(
        &controller,
        writer,
        reader,
        &result(),
        Method::PrivacySet,
        WrittenUnder::for_an_own_effect_case(footing),
        vec![Box::new(move || {
            presenter.present(&[kr_protocol::rights::ActionRight::FilesRead]);
        })],
    )
    .await;
    assert!(stood, "the connection goes on");
    assert_eq!(handed, vec![result()], "the writer goes by its own reading");
    // The bound that the pause's change moved is another run than the one the writer first read.
    let now = controller.clock.now();
    let utc = controller.settled_utc_now();
    assert_eq!(
        held.stands_at(now, utc),
        crate::grants::policy::Stands::Moved,
        "the presentation started another run of the bound"
    );
}
