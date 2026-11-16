//! The network writer asks the standing of an answer read from a record where it lands.
//!
//! A kept answer, and a conflict that names a reused identifier, are read from a record and go only
//! while the standing their request was admitted under holds. The writer reads the authority
//! feed's refusal last among the reads that take a lock, and then asks, once and with no lock, the
//! request's footing, the bounds the answer is written under and the grant's own end. Each case
//! stops the writer where the feed has been read and before that question, ends the standing there,
//! and finds that none of the answer was handed to the stream.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use kr_protocol::envelope::{ControlFrame, Outcome, ParamsValue, Response};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::ids::{DeviceId, RequestId, SessionId};
use kr_protocol::method::Method;
use kr_protocol::rights::ActionRight;

use super::decision::Answered;
use super::write_boundary::{Recording, paired_connection_expiring};
use crate::service::Reach;

/// What an answer read from a record is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Record {
    /// A receipt kept from an earlier submission of an action.
    KeptAnswer,
    /// A refusal that says another request spent the identifier of this one.
    ReusedIdentifier,
}

/// What ends in the pause between the feed's refusal and the standing's question.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Ends {
    /// Nothing: the control.
    Nothing,
    /// A fence this host comes to owe.
    AFence,
    /// The registration the request was admitted under, withdrawn.
    TheRegistration,
    /// Another device's revocation moves the revision in force.
    TheRevision,
    /// The connection's grant runs out on the wall clock.
    TheGrantsOwnEnd,
}

/// What the case found after the writer had gone on.
struct Found {
    /// Whether the connection stood.
    stood: bool,
    /// What the stream was handed.
    frames: Vec<ControlFrame>,
    /// The answer that the writer was given.
    answer: ControlFrame,
    /// What the door says of the standing now, as the check of a request admitted under the same
    /// revision gives it.
    refusal: Option<ProtocolError>,
    request_id: RequestId,
}

/// Writes `record` to a connection whose grant runs out ten minutes after the case begins, stops
/// the writer once the feed's refusal is read, lets `ends` happen there and lets the writer go on.
async fn written_with(record: Record, ends: Ends) -> Found {
    let temp = kr_ipc::testing::TempHost::create();
    let (_continuous, wall, clocks) = super::super::tests::manual_clocks();
    let controller = super::super::tests::daemon_on(&temp, clocks).await;
    let expires_at_ms = wall.load(Ordering::SeqCst) + 10 * 60 * 1000;
    let recording = Arc::new(Recording::default());
    let connection = paired_connection_expiring(
        &controller,
        71,
        &[ActionRight::SessionView, ActionRight::SessionRename],
        kr_protocol::grant::GrantExpiry::At {
            expires_at_ms: kr_protocol::scalars::TimestampMs::new(expires_at_ms),
        },
        Box::new(Arc::clone(&recording)),
    );
    let session_id = SessionId::new(kr_ipc::new_uuid());
    let admitted = connection
        .admitted_at()
        .await
        .expect("the connection is admitted");
    let decided = connection
        .ask(Some(session_id), Method::SessionRename.entry(), false)
        .expect("the action is decided");
    let request_id = RequestId::new(91);
    let (asked, answer) = match record {
        Record::KeptAnswer => (
            decided.kept(admitted),
            ControlFrame::Response(Response {
                request_id,
                outcome: Outcome::Ok(ParamsValue::empty()),
            }),
        ),
        Record::ReusedIdentifier => (
            decided.admitted_under(admitted),
            super::failure(
                request_id,
                ProtocolError::new(ErrorCode::IdConflict, "the identifier was spent"),
            ),
        ),
    };

    let connection_id = connection.connection_id;
    let (arrived, go) = controller.pause_after_the_feed_is_read();
    let writing = tokio::spawn({
        let answer = answer.clone();
        async move {
            let stood = connection
                .write_answer(
                    connection.output(),
                    Answered {
                        frame: answer,
                        asked: Some(asked),
                    },
                )
                .await;
            (stood, connection)
        }
    });
    tokio::task::spawn_blocking(move || arrived.recv_timeout(Duration::from_secs(30)))
        .await
        .expect("the wait ends")
        .expect("the writer reaches the place after the feed's refusal is read");
    match ends {
        Ends::Nothing => {}
        Ends::AFence => controller.hold_fence(true),
        Ends::TheRegistration => {
            controller.deregister(connection_id);
        }
        Ends::TheRevision => {
            let other = DeviceId::new(kr_ipc::new_uuid());
            let debt = controller
                .owe_debt("the revocation of a device", Reach::Device(other))
                .expect("the debt is written");
            let own = controller.publish_debts(&[(debt, Reach::Device(other))]);
            controller
                .barrier(own)
                .await
                .expect("the barrier is raised");
        }
        Ends::TheGrantsOwnEnd => wall.store(expires_at_ms + 1_000, Ordering::SeqCst),
    }
    go.send(()).expect("the writer goes on");
    let (stood, connection) = writing.await.expect("the write ends");
    let refusal = connection.admitted_to_answer(admitted).err();
    controller.hold_fence(false);
    let frames = recording.frames();
    drop(connection);
    drop(controller);
    Found {
        stood,
        frames,
        answer,
        refusal,
        request_id,
    }
}

/// What a device is told of an answer that was read from a record and stopped: the outcome that is
/// not shown for a kept answer, and the refusal of the check that failed for a conflict.
fn told_of_the_stop(found: &Found, record: Record) -> ControlFrame {
    let told = match record {
        Record::KeptAnswer => super::failure(found.request_id, super::outcome_not_shown()),
        Record::ReusedIdentifier => super::failure(
            found.request_id,
            found
                .refusal
                .clone()
                .expect("the check that failed refuses the request"),
        ),
    };
    // What a device is shown of a failure is what the writer maps it to.
    super::super::device_errors::frame_for_a_device(&told).into_owned()
}

/// An answer that nothing ended is written whole.
async fn nothing_ends_and_the_answer_is_written_whole(record: Record) {
    let found = written_with(record, Ends::Nothing).await;
    assert!(found.stood, "the connection stands");
    assert_eq!(
        found.frames,
        [found.answer.clone()],
        "{record:?} was written"
    );
}

/// An answer that the standing stopped is not handed to the stream, and the device is told why.
async fn the_standing_ends_and_the_stream_is_handed_none_of_the_answer(record: Record, ends: Ends) {
    let found = written_with(record, ends).await;
    assert!(
        found.refusal.is_some(),
        "the door's own check refuses the request after {ends:?}"
    );
    assert!(
        found.stood,
        "the connection stands: only the standing of the answer ended"
    );
    assert_eq!(
        found.frames,
        [told_of_the_stop(&found, record)],
        "{record:?} was not written after {ends:?}; only what the check that failed says was"
    );
}

/// The connection ends with the grant's own end or its registration, and nothing is written.
async fn the_connection_ends_and_the_stream_is_handed_nothing(record: Record, ends: Ends) {
    let found = written_with(record, ends).await;
    assert!(!found.stood, "the connection ends after {ends:?}");
    assert!(
        found.frames.is_empty(),
        "{record:?} was not handed to the stream after {ends:?}: {:?}",
        found.frames
    );
}

/// KR-REQ-09.12: a kept answer that the writer has stopped at after the feed's refusal was read is
/// asked its standing there, with no lock, and written whole when nothing has ended.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_kept_answer_is_written_whole_when_nothing_ends_after_the_feed_is_read() {
    nothing_ends_and_the_answer_is_written_whole(Record::KeptAnswer).await;
}

/// KR-REQ-09.12: a fence this host comes to owe after the feed's refusal was read stops a kept
/// answer, and the device is told the outcome is not shown.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_kept_answer_is_not_written_when_a_fence_is_owed_after_the_feed_is_read() {
    the_standing_ends_and_the_stream_is_handed_none_of_the_answer(Record::KeptAnswer, Ends::AFence)
        .await;
}

/// KR-REQ-09.12: another device's revocation that moves the revision after the feed's refusal was
/// read stops a kept answer admitted under the old revision.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_kept_answer_is_not_written_when_the_revision_moves_after_the_feed_is_read() {
    the_standing_ends_and_the_stream_is_handed_none_of_the_answer(
        Record::KeptAnswer,
        Ends::TheRevision,
    )
    .await;
}

/// KR-REQ-09.12: a registration withdrawn after the feed's refusal was read ends the connection
/// with none of a kept answer written.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_kept_answer_is_not_written_when_its_registration_is_withdrawn_after_the_feed_is_read() {
    the_connection_ends_and_the_stream_is_handed_nothing(Record::KeptAnswer, Ends::TheRegistration)
        .await;
}

/// KR-REQ-09.12: a grant that runs out after the feed's refusal was read ends the connection with
/// none of a kept answer written: the grant's own end is the writer's last question.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_kept_answer_is_not_written_when_the_grant_ends_after_the_feed_is_read() {
    the_connection_ends_and_the_stream_is_handed_nothing(Record::KeptAnswer, Ends::TheGrantsOwnEnd)
        .await;
}

/// KR-REQ-09.09: a reused identifier read from a record is written whole when nothing has ended.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reused_identifier_is_written_whole_when_nothing_ends_after_the_feed_is_read() {
    nothing_ends_and_the_answer_is_written_whole(Record::ReusedIdentifier).await;
}

/// KR-REQ-09.09: a fence this host comes to owe after the feed's refusal was read stops a reused
/// identifier's answer, and the device is told the refusal of the check that failed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reused_identifier_is_not_written_when_a_fence_is_owed_after_the_feed_is_read() {
    the_standing_ends_and_the_stream_is_handed_none_of_the_answer(
        Record::ReusedIdentifier,
        Ends::AFence,
    )
    .await;
}

/// KR-REQ-09.09: another device's revocation that moves the revision after the feed's refusal was
/// read stops a reused identifier's answer admitted under the old revision.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reused_identifier_is_not_written_when_the_revision_moves_after_the_feed_is_read() {
    the_standing_ends_and_the_stream_is_handed_none_of_the_answer(
        Record::ReusedIdentifier,
        Ends::TheRevision,
    )
    .await;
}

/// KR-REQ-09.09: a registration withdrawn after the feed's refusal was read ends the connection
/// with none of a reused identifier's answer written.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reused_identifier_is_not_written_when_its_registration_is_withdrawn_after_the_feed_is_read()
 {
    the_connection_ends_and_the_stream_is_handed_nothing(
        Record::ReusedIdentifier,
        Ends::TheRegistration,
    )
    .await;
}

/// KR-REQ-09.09: a grant that runs out after the feed's refusal was read ends the connection with
/// none of a reused identifier's answer written.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reused_identifier_is_not_written_when_the_grant_ends_after_the_feed_is_read() {
    the_connection_ends_and_the_stream_is_handed_nothing(
        Record::ReusedIdentifier,
        Ends::TheGrantsOwnEnd,
    )
    .await;
}

/// KR-REQ-09.12: a kept answer whose grant runs out while the feed's refusal waits for the
/// connection's shares lock is not written. The first reading of the feed is the writer's decision
/// before its attempt and the second is the attempt's own; the grant runs out in the second.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_kept_answer_is_not_written_when_the_grant_ends_while_the_feed_waits_for_the_shares_lock()
{
    for ends in [false, true] {
        let temp = kr_ipc::testing::TempHost::create();
        let (_continuous, wall, clocks) = super::super::tests::manual_clocks();
        let controller = super::super::tests::daemon_on(&temp, clocks).await;
        let expires_at_ms = wall.load(Ordering::SeqCst) + 10 * 60 * 1000;
        let recording = Arc::new(Recording::default());
        let connection = paired_connection_expiring(
            &controller,
            72,
            &[ActionRight::SessionView, ActionRight::SessionRename],
            kr_protocol::grant::GrantExpiry::At {
                expires_at_ms: kr_protocol::scalars::TimestampMs::new(expires_at_ms),
            },
            Box::new(Arc::clone(&recording)),
        );
        let admitted = connection.admitted_at().await.expect("admitted");
        let asked = connection
            .ask(
                Some(SessionId::new(kr_ipc::new_uuid())),
                Method::SessionRename.entry(),
                false,
            )
            .expect("the action is decided")
            .kept(admitted);
        let answer = ControlFrame::Response(Response {
            request_id: RequestId::new(92),
            outcome: Outcome::Ok(ParamsValue::empty()),
        });
        let (arrived, go) = controller.pause_before_the_shares_lock();
        let writing = tokio::spawn({
            let answer = answer.clone();
            async move {
                let stood = connection
                    .write_answer(
                        connection.output(),
                        Answered {
                            frame: answer,
                            asked: Some(asked),
                        },
                    )
                    .await;
                (stood, connection)
            }
        });
        tokio::task::spawn_blocking(move || arrived.recv_timeout(Duration::from_secs(30)))
            .await
            .expect("the wait ends")
            .expect("the writer's decision reaches the shares lock");
        let (arrived, go_again) = controller.pause_before_the_shares_lock();
        go.send(()).expect("the decision goes on");
        tokio::task::spawn_blocking(move || arrived.recv_timeout(Duration::from_secs(30)))
            .await
            .expect("the wait ends")
            .expect("the attempt's feed reaches the shares lock");
        if ends {
            wall.store(expires_at_ms + 1_000, Ordering::SeqCst);
        }
        go_again.send(()).expect("the attempt goes on");
        let (stood, connection) = writing.await.expect("the write ends");
        let frames = recording.frames();
        if ends {
            assert!(!stood, "the connection ends");
            assert!(
                frames.is_empty(),
                "none of the kept answer was handed to the stream: {frames:?}"
            );
        } else {
            assert!(stood, "the connection stands");
            assert_eq!(frames, [answer], "the kept answer was written");
        }
        drop(connection);
        drop(controller);
    }
}
