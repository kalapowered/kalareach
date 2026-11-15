//! What a local caller is told when the local owner's lease ends before the answer to its mutation
//! is written.
//!
//! The effect of a held mutation has run by then, so the answer that is withheld is a result the
//! caller never sees, and "refused" would say that nothing was done. The caller is told the outcome
//! is unknown, which is what sends a client to read what the host shows before it decides
//! anything. These tests write an answer on a real local connection with the lease ended, and
//! read what arrives.

use std::sync::Arc;

use kr_ipc::endpoint::{Connection, Listener};
use kr_ipc::framed::{FrameReader, FrameWriter, split};
use kr_protocol::envelope::{ControlFrame, Outcome, ParamsValue, Response};
use kr_protocol::error::{ErrorCode, RetryCategory};
use kr_protocol::frame::StreamKind;
use kr_protocol::ids::RequestId;
use kr_protocol::method::Method;

use crate::service::Controller;

/// The request the answer in these tests is to.
const REQUEST: RequestId = RequestId::new(7);

/// A daemon that is exclusively organisation-managed when `exclusive`, whose local owner has no
/// lease, and a local connection to it: the writer the daemon answers on and the reader its caller
/// reads from.
async fn connected(
    exclusive: bool,
) -> (
    kr_ipc::testing::TempHost,
    Arc<Controller>,
    FrameWriter,
    FrameReader,
) {
    let temp = kr_ipc::testing::TempHost::create();
    let controller = Controller::start(super::a_floor_owed_its_record::setup(&temp))
        .await
        .expect("the daemon starts");
    controller
        .policy
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .set_exclusively_managed(exclusive);
    let (writer, reader) = local_connection(&temp).await;
    (temp, controller, writer, reader)
}

/// A local connection to the daemon of `temp`: the writer the daemon answers on and the reader its
/// caller reads from.
async fn local_connection(temp: &kr_ipc::testing::TempHost) -> (FrameWriter, FrameReader) {
    let endpoint = temp
        .environment()
        .controller_endpoint()
        .expect("an endpoint");
    let listener = Listener::bind(&endpoint).expect("binds the endpoint");
    let dialled = tokio::spawn(async move { Connection::connect(&endpoint).await });
    let (connection, _) = listener.accept().await.expect("accepts");
    let caller = dialled.await.expect("the task ends").expect("connects");
    let (_, writer) = split(connection, StreamKind::Control);
    let (reader, _) = split(caller, StreamKind::Control);
    (writer, reader)
}

/// A daemon on clocks the test moves by hand, exclusively organisation-managed, whose local owner
/// holds a membership lease that is live for its fifteen minutes, and a local connection to it.
/// Returns the continuous clock too, which the test moves past the lease's end.
async fn connected_under_a_lease() -> (
    kr_ipc::testing::TempHost,
    Arc<Controller>,
    kr_transport::clock::ManualClock,
    FrameWriter,
    FrameReader,
) {
    let temp = kr_ipc::testing::TempHost::create();
    let (continuous, wall, clocks) = crate::service::net::tests::manual_clocks();
    let controller = crate::service::net::tests::daemon_on_clocks_to_move(&temp, clocks).await;
    let now = wall.load(std::sync::atomic::Ordering::SeqCst);
    let organisation =
        crate::grants::organisation::testing::TestOrganisation::new(0x31, now - 60 * 60 * 1000);
    let reading = crate::service::net::devices::ObservedUtc {
        now: kr_protocol::scalars::TimestampMs::new(now),
        behind_ms: 0,
    };
    controller
        .update_policy(|policy| {
            let verified = policy
                .verify_enrolment(&organisation.authority(now), Some(&reading))
                .expect("the chain verifies");
            let revision = policy.authority_revision();
            policy.enrol(verified, revision).expect("the host enrols");
            policy.set_exclusively_managed(true);
        })
        .expect("the enrolment is written down");
    let key = kr_crypto::keys::AuthorisationKeyPair::generate().expect("a device key");
    let account = kr_protocol::ids::AccountId::new("ada").expect("an account");
    let lease = organisation.lease(
        &account,
        *key.public(),
        now,
        &[kr_protocol::rights::ActionRight::SessionView],
    );
    controller
        .update_policy(|policy| {
            policy.install_lease(crate::grants::organisation::LeasePresentation {
                lease: &lease,
                device_id: controller.local_owner_device(),
                proven_key: key.public(),
                reading: Some(reading),
                now: controller.clock.now(),
                generation: controller.generation(),
            })
        })
        .expect("the lease is written down")
        .expect("the lease installs and binds the owner's device");
    let (writer, reader) = local_connection(&temp).await;
    (temp, controller, continuous, writer, reader)
}

/// The answer the effect produced: a result.
fn result() -> ControlFrame {
    ControlFrame::Response(Response {
        request_id: REQUEST,
        outcome: Outcome::Ok(ParamsValue::empty()),
    })
}

/// Writes `answer` to the caller of `method` and returns what the caller reads.
async fn written_for(method: Method, exclusive: bool) -> ControlFrame {
    let (_temp, controller, mut writer, mut reader) = connected(exclusive).await;
    assert!(
        controller
            .write_answer(
                &mut writer,
                StreamKind::Control,
                &result(),
                Some(method),
                REQUEST,
                None
            )
            .await,
        "the connection goes on"
    );
    tokio::time::timeout(std::time::Duration::from_secs(30), reader.read_message())
        .await
        .expect("the daemon wrote an answer")
        .expect("the answer reads")
}

/// The error a caller is given in place of an answer, or none when it is given the answer.
async fn refusal_for(method: Method, exclusive: bool) -> Option<kr_protocol::error::ProtocolError> {
    let ControlFrame::Response(response) = written_for(method, exclusive).await else {
        panic!("a response");
    };
    match response.outcome {
        Outcome::Error(error) => Some(error),
        Outcome::Ok(_) => None,
    }
}

/// A held mutation whose answer is written after the local owner's lease ended gets the outcome
/// unknown, and not a refusal that says nothing happened: its effect has run, and the lease cannot
/// un-run it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_held_mutations_result_withheld_after_the_lease_ended_is_answered_as_unknown() {
    let error = refusal_for(Method::GrantCreate, true)
        .await
        .expect("the result is withheld, so the caller is not given it");
    assert_eq!(error.code, ErrorCode::OutcomeUnknown);
    assert_eq!(error.retry, RetryCategory::OutcomeUnknown);
}

/// A held read has no effect to be unsure of: it is refused, and its caller is not told to check
/// whether something happened.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_held_reads_result_withheld_after_the_lease_ended_is_refused() {
    let error = refusal_for(Method::SessionRead, true)
        .await
        .expect("the result is withheld, so the caller is not given it");
    assert_eq!(error.code, ErrorCode::PermissionDenied);
}

/// The controls: with no lease needed, or for a method that needs none, the caller gets the result.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_result_is_written_where_no_lease_is_needed() {
    for (method, exclusive) in [
        (Method::GrantCreate, false),
        (Method::SessionRead, false),
        (Method::GrantRevoke, true),
        (Method::GrantList, true),
    ] {
        assert_eq!(
            written_for(method, exclusive).await,
            result(),
            "{method} with exclusive management {exclusive}"
        );
    }
}

/// When the fence lands relative to the write of a reply read from a record.
#[derive(Clone, Copy, Debug)]
enum FenceLands {
    /// Not at all: the control.
    Never,
    /// Before the write begins.
    Before,
    /// While the write waits for the peer, which has read none of it.
    DuringTheWait,
}

/// KR-REQ-09.09: a reply read from a record passed the kept answer's check, and is asked the standing
/// that check asked again where its bytes are handed to the transport, after every wait for the
/// peer. A fence this host comes to owe stops it: where none of it has gone the caller is told the
/// outcome is not shown, and where the peer has part of it the connection ends, so the stored answer
/// never reaches the caller whole. The control: with no fence the whole answer is read.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reply_read_from_a_record_is_not_written_whole_when_a_fence_is_owed_before_or_in_the_wait()
 {
    use kr_protocol::ids::{ActorId, ConnectionId};

    for (conflict, lands) in [false, true].into_iter().flat_map(|conflict| {
        [
            FenceLands::Never,
            FenceLands::Before,
            FenceLands::DuringTheWait,
        ]
        .map(|lands| (conflict, lands))
    }) {
        let (_temp, controller, mut writer, mut reader) = connected(false).await;
        let connection_id = ConnectionId::new(kr_ipc::new_uuid());
        let revision = controller.policy().authority_revision();
        controller.admitted_write().insert(
            connection_id,
            crate::service::AdmittedConnection::new(
                ActorId::new("owner").expect("a principal"),
                revision,
            ),
        );
        // More than a socket holds, so the write waits for the peer to read. A conflict is a reply
        // that says another request spent the identifier.
        let answer = ControlFrame::Response(Response {
            request_id: REQUEST,
            outcome: if conflict {
                Outcome::Error(kr_protocol::error::ProtocolError::new(
                    ErrorCode::IdConflict,
                    "x".repeat(256 * 1024),
                ))
            } else {
                Outcome::Ok(
                    ParamsValue::from_typed(&"x".repeat(256 * 1024)).expect("a large value"),
                )
            },
        });
        if matches!(lands, FenceLands::Before) {
            controller.hold_fence(true);
        }
        let writing = {
            let controller = Arc::clone(&controller);
            let answer = answer.clone();
            tokio::spawn(async move {
                let stood = controller
                    .write_answer(
                        &mut writer,
                        StreamKind::Control,
                        &answer,
                        Some(Method::PrivacySet),
                        REQUEST,
                        Some(if conflict {
                            crate::given::local_door::FromARecord::for_a_conflict_case(
                                connection_id,
                                revision,
                            )
                        } else {
                            crate::given::local_door::FromARecord::for_a_case(
                                connection_id,
                                revision,
                            )
                        }),
                    )
                    .await;
                // The connection ends with the writer, as it does when the daemon's loop stops.
                drop(writer);
                stood
            })
        };
        if matches!(lands, FenceLands::DuringTheWait) {
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            controller.hold_fence(true);
        }
        let read = tokio::time::timeout(std::time::Duration::from_secs(30), reader.read_message())
            .await
            .expect("the daemon wrote or ended the connection");
        controller.hold_fence(false);
        let stood = writing.await.expect("the write ends");
        match (lands, read) {
            (FenceLands::Never, Ok(read)) => {
                assert_eq!(
                    read, answer,
                    "the whole answer is read, a conflict: {conflict}"
                );
                assert!(stood);
            }
            (FenceLands::Before, Ok(ControlFrame::Response(response)))
            | (FenceLands::DuringTheWait, Ok(ControlFrame::Response(response))) => {
                let Outcome::Error(told) = response.outcome else {
                    panic!("{lands:?}: the stored answer reached the caller");
                };
                if conflict {
                    // The request had no effect of its own: the caller is told the refusal of
                    // the check that failed, not an unknown outcome.
                    assert_eq!(
                        told.code,
                        ErrorCode::PermissionDenied,
                        "a conflict, {lands:?}: {told:?}"
                    );
                } else {
                    assert_eq!(told.code, ErrorCode::OutcomeUnknown, "{lands:?}: {told:?}");
                    assert_eq!(
                        told.message,
                        crate::error::ControllerError::outcome_not_shown()
                            .to_protocol_error()
                            .message
                    );
                }
            }
            // The peer had part of it, so the connection ended and the answer is never whole.
            (FenceLands::DuringTheWait, Err(_)) => assert!(!stood),
            (lands, read) => panic!("a conflict: {conflict}, {lands:?}: {read:?}"),
        }
    }
}

/// KR-REQ-09.09, KR-REQ-17.54: a reply read from a record is asked the standing it passed under
/// after the last lock that its check takes. The reading of the local owner's lease waits for the
/// policy lock, which a policy commit holds across its storage writes, and a fence this host comes
/// to owe in that wait stops the reply before the transport takes it, so the stored answer is
/// never written: the caller is told the outcome is not shown. The control: with no fence the
/// whole answer is read.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reply_read_from_a_record_is_not_written_when_a_fence_is_owed_while_the_lease_is_read() {
    use kr_protocol::ids::{ActorId, ConnectionId};

    for owed in [false, true] {
        let (_temp, controller, mut writer, mut reader) = connected(false).await;
        let connection_id = ConnectionId::new(kr_ipc::new_uuid());
        let revision = controller.policy().authority_revision();
        controller.admitted_write().insert(
            connection_id,
            crate::service::AdmittedConnection::new(
                ActorId::new("owner").expect("a principal"),
                revision,
            ),
        );
        let (arrived, go) = controller.pause_before_the_policy_lock();
        let writing = {
            let controller = Arc::clone(&controller);
            tokio::spawn(async move {
                let stood = controller
                    .write_answer(
                        &mut writer,
                        StreamKind::Control,
                        &result(),
                        Some(Method::PrivacySet),
                        REQUEST,
                        Some(crate::given::local_door::FromARecord::for_a_case(
                            connection_id,
                            revision,
                        )),
                    )
                    .await;
                drop(writer);
                stood
            })
        };
        // The lease's reading has arrived at the policy lock, which is where it waits for a commit.
        tokio::task::spawn_blocking(move || {
            arrived.recv_timeout(std::time::Duration::from_secs(30))
        })
        .await
        .expect("the wait ends")
        .expect("the lease is read for the reply");
        controller.hold_fence(owed);
        go.send(()).expect("the reading goes on");
        let read = tokio::time::timeout(std::time::Duration::from_secs(30), reader.read_message())
            .await
            .expect("the daemon wrote or ended the connection");
        controller.hold_fence(false);
        writing.await.expect("the write ends");
        if owed {
            let Ok(ControlFrame::Response(response)) = read else {
                panic!("the caller is told the outcome is not shown: {read:?}");
            };
            let Outcome::Error(told) = response.outcome else {
                panic!("the stored answer reached the caller");
            };
            assert_eq!(told.code, ErrorCode::OutcomeUnknown, "{told:?}");
        } else {
            assert_eq!(read.expect("the answer reads"), result(), "the control");
        }
    }
}

/// KR-REQ-09.09: a reply that says another request spent the identifier is told by the local door
/// as it is while its standing holds, and is written under that standing, as a copy of a record
/// is. A fence this host comes to owe between the telling and the write stops it, and the caller
/// is told the refusal of the check that failed: the request had no effect of its own, so that is
/// true, and an unknown outcome is not. The control: with no fence the conflict is written.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_conflict_the_local_door_told_is_written_as_the_checks_refusal_when_a_fence_is_owed() {
    use crate::given::local_door::{ReplySink, Standing, told};
    use crate::given::{Given, Settled};
    use kr_protocol::ids::{ActorId, ConnectionId};

    for owed in [false, true] {
        let (_temp, controller, mut writer, mut reader) = connected(false).await;
        let connection_id = ConnectionId::new(kr_ipc::new_uuid());
        let revision = controller.policy().authority_revision();
        controller.admitted_write().insert(
            connection_id,
            crate::service::AdmittedConnection::new(
                ActorId::new("owner").expect("a principal"),
                revision,
            ),
        );
        let conflict = ControlFrame::Response(Response {
            request_id: REQUEST,
            outcome: Outcome::Error(kr_protocol::error::ProtocolError::new(
                ErrorCode::IdConflict,
                "the identifier was used with another request",
            )),
        });
        let reply = told(
            Settled::of(Given::fresh(conflict.clone())),
            &Standing::new(&controller, connection_id, Some(revision), REQUEST),
        )
        .await;
        controller.hold_fence(owed);
        assert!(
            ReplySink::new(&mut writer, StreamKind::Control)
                .write(&controller, reply, Some(Method::PrivacySet))
                .await,
            "the connection goes on"
        );
        controller.hold_fence(false);
        let read = tokio::time::timeout(std::time::Duration::from_secs(30), reader.read_message())
            .await
            .expect("the daemon wrote an answer")
            .expect("the answer reads");
        if owed {
            let ControlFrame::Response(response) = read else {
                panic!("a response");
            };
            let Outcome::Error(told) = response.outcome else {
                panic!("the stored conflict reached the caller");
            };
            assert_eq!(told.code, ErrorCode::PermissionDenied, "{told:?}");
        } else {
            assert_eq!(read, conflict, "the control");
        }
    }
}

/// KR-REQ-17.54: a reply read from a record is written under a lease that is live when the write is
/// let go, not only when its reading began. The record's own check takes locks after the lease is
/// read, and a lease that ends in that wait stops the reply before the transport takes it: the
/// stored answer is never written, and the caller is told the outcome is unknown. The control: where
/// the lease still stands after the wait, the whole answer is read.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reply_read_from_a_record_is_not_written_when_the_lease_ends_while_the_record_is_checked()
{
    use kr_protocol::ids::{ActorId, ConnectionId};

    for ends in [false, true] {
        let (_temp, controller, continuous, mut writer, mut reader) =
            connected_under_a_lease().await;
        let connection_id = ConnectionId::new(kr_ipc::new_uuid());
        let revision = controller.policy().authority_revision();
        controller.admitted_write().insert(
            connection_id,
            crate::service::AdmittedConnection::new(
                ActorId::new("owner").expect("a principal"),
                revision,
            ),
        );
        let (arrived, go) = controller.pause_before_the_last_fence_read();
        let writing = {
            let controller = Arc::clone(&controller);
            tokio::spawn(async move {
                let stood = controller
                    .write_answer(
                        &mut writer,
                        StreamKind::Control,
                        &result(),
                        Some(Method::PrivacySet),
                        REQUEST,
                        Some(crate::given::local_door::FromARecord::for_a_case(
                            connection_id,
                            revision,
                        )),
                    )
                    .await;
                drop(writer);
                stood
            })
        };
        // The lease was read live, and the record's check is at its last lock.
        tokio::task::spawn_blocking(move || {
            arrived.recv_timeout(std::time::Duration::from_secs(30))
        })
        .await
        .expect("the wait ends")
        .expect("the record's check is reached");
        if ends {
            continuous.advance(std::time::Duration::from_secs(16 * 60));
        }
        go.send(()).expect("the check goes on");
        let read = tokio::time::timeout(std::time::Duration::from_secs(30), reader.read_message())
            .await
            .expect("the daemon wrote or ended the connection");
        writing.await.expect("the write ends");
        if ends {
            let Ok(ControlFrame::Response(response)) = read else {
                panic!("the caller is told the outcome is unknown: {read:?}");
            };
            let Outcome::Error(told) = response.outcome else {
                panic!("the stored answer reached the caller after the lease ended");
            };
            assert_eq!(told.code, ErrorCode::OutcomeUnknown, "{told:?}");
        } else {
            assert_eq!(read.expect("the answer reads"), result(), "the control");
        }
    }
}

/// KR-REQ-17.54: the ask that stands behind a sign-in reads the owner's lease first and the fence
/// this host owes after it, and reading the fence takes its lock, so the lease's end that the first
/// reading returned is compared with the clock again after it. A lease that ends in that wait
/// stops the sign-in: nothing is kept. The control: where the lease still stands after the wait,
/// the ask passes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_sign_in_ask_whose_lease_ends_while_the_fence_is_read_is_refused() {
    for ends in [false, true] {
        let (_temp, controller, continuous, _writer, _reader) = connected_under_a_lease().await;
        let lasting = controller.sign_in_lasting(Method::AccountSignIn);
        let (arrived, go) = controller.pause_before_the_last_fence_read();
        let asking = tokio::task::spawn_blocking(move || lasting());
        // The lease was read live, and the ask is about to read the fence.
        tokio::task::spawn_blocking(move || {
            arrived.recv_timeout(std::time::Duration::from_secs(30))
        })
        .await
        .expect("the wait ends")
        .expect("the ask reaches its reading of the fence");
        if ends {
            continuous.advance(std::time::Duration::from_secs(16 * 60));
        }
        go.send(()).expect("the ask goes on");
        let asked = asking.await.expect("the ask ends");
        assert_eq!(
            asked.is_err(),
            ends,
            "a lease that ended in the wait: {ends}: {asked:?}"
        );
    }
}
