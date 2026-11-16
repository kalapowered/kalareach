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

use crate::given::local_door::WrittenUnder;
use crate::service::Controller;

/// The request the answer in these tests is to.
const REQUEST: RequestId = RequestId::new(7);

/// A daemon that is exclusively organisation-managed when `exclusive`, whose local owner has no
/// lease, and a local connection to it: the writer the daemon answers on and the reader its caller
/// reads from.
pub(super) async fn connected(
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
pub(super) async fn connected_under_a_lease() -> (
    kr_ipc::testing::TempHost,
    Arc<Controller>,
    kr_transport::clock::ManualClock,
    FrameWriter,
    FrameReader,
) {
    let (temp, controller, continuous, _presenter, writer, reader) =
        connected_under_a_lease_that_can_be_presented_again().await;
    (temp, controller, continuous, writer, reader)
}

/// What presents the local owner's lease of a daemon again, with other rights.
pub(super) struct Presenter {
    controller: Arc<Controller>,
    organisation: crate::grants::organisation::testing::TestOrganisation,
    key: kr_crypto::keys::AuthorisationKeyPair,
    wall: Arc<std::sync::atomic::AtomicU64>,
}

impl Presenter {
    /// Presents a lease for the same account and key that holds `rights` and no others, which a
    /// lease that held other rights is narrowed by: a run of the lease's bound that began under
    /// the earlier lease does not continue.
    pub(super) fn present(&self, rights: &[kr_protocol::rights::ActionRight]) {
        // Issued a second after the lease it narrows, so that it is the newest this host holds.
        let now = self
            .wall
            .fetch_add(1_000, std::sync::atomic::Ordering::SeqCst)
            + 1_000;
        let reading = crate::service::net::devices::ObservedUtc {
            now: kr_protocol::scalars::TimestampMs::new(now),
            behind_ms: 0,
        };
        let account = kr_protocol::ids::AccountId::new("ada").expect("an account");
        let lease = self
            .organisation
            .lease(&account, *self.key.public(), now, rights);
        self.controller
            .update_policy(|policy| {
                policy.install_lease(crate::grants::organisation::LeasePresentation {
                    lease: &lease,
                    device_id: self.controller.local_owner_device(),
                    proven_key: self.key.public(),
                    reading: Some(reading),
                    now: self.controller.clock.now(),
                    generation: self.controller.generation(),
                })
            })
            .expect("the lease is written down")
            .expect("the lease installs");
    }
}

/// As [`connected_under_a_lease`], with what presents the owner's lease again.
pub(super) async fn connected_under_a_lease_that_can_be_presented_again() -> (
    kr_ipc::testing::TempHost,
    Arc<Controller>,
    kr_transport::clock::ManualClock,
    Presenter,
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
    let presenter = Presenter {
        controller: Arc::clone(&controller),
        organisation,
        key,
        wall,
    };
    (temp, controller, continuous, presenter, writer, reader)
}

/// The answer the effect produced: a result.
fn result() -> ControlFrame {
    ControlFrame::Response(Response {
        request_id: REQUEST,
        outcome: Outcome::Ok(ParamsValue::empty()),
    })
}

/// A local registration of the owner at the revision in force, and the footing of a request that
/// arrived on it.
pub(super) fn registered(
    controller: &Controller,
) -> (
    kr_protocol::ids::ConnectionId,
    kr_protocol::ids::AuthorityRevision,
    crate::service::Footing,
) {
    use kr_protocol::ids::{ActorId, ConnectionId};

    let connection_id = ConnectionId::new(kr_ipc::new_uuid());
    let revision = controller.policy().authority_revision();
    controller.admitted_write().insert(
        connection_id,
        crate::service::AdmittedConnection::local(
            ActorId::new("owner").expect("a principal"),
            revision,
            kr_protocol::local::LocalClientKind::Cli,
        ),
    );
    (
        connection_id,
        revision,
        controller.footing_of_a_request(connection_id),
    )
}

/// Writes `answer` to the caller of `method` and returns what the caller reads.
async fn written_for(method: Method, exclusive: bool) -> ControlFrame {
    let (_temp, controller, mut writer, mut reader) = connected(exclusive).await;
    let (_, _, footing) = registered(&controller);
    assert!(
        controller
            .write_answer(
                &mut writer,
                StreamKind::Control,
                &result(),
                Some(method),
                REQUEST,
                &WrittenUnder::for_an_own_effect_case(footing, true),
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
    for (conflict, lands) in [false, true].into_iter().flat_map(|conflict| {
        [
            FenceLands::Never,
            FenceLands::Before,
            FenceLands::DuringTheWait,
        ]
        .map(|lands| (conflict, lands))
    }) {
        let (_temp, controller, mut writer, mut reader) = connected(false).await;
        let (_connection_id, _revision, footing) = registered(&controller);
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
                        &WrittenUnder::for_a_record_case(footing, conflict),
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
    for owed in [false, true] {
        let (_temp, controller, mut writer, mut reader) = connected(false).await;
        let (_connection_id, _revision, footing) = registered(&controller);
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
                        &WrittenUnder::for_a_record_case(footing, false),
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

    for owed in [false, true] {
        let (_temp, controller, mut writer, mut reader) = connected(false).await;
        let (_connection_id, _revision, footing) = registered(&controller);
        let conflict = ControlFrame::Response(Response {
            request_id: REQUEST,
            outcome: Outcome::Error(kr_protocol::error::ProtocolError::new(
                ErrorCode::IdConflict,
                "the identifier was used with another request",
            )),
        });
        let reply = told(
            Settled::of(Given::fresh(conflict.clone())),
            &Standing::new(&controller, footing, REQUEST),
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
        let read = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            reader.read_message::<ControlFrame>(),
        )
        .await
        .expect("the daemon wrote an answer")
        .expect("the answer reads");
        if owed {
            // The whole frame, in the words of the fence: another member's words are no answer.
            let refusal = crate::service::Lapse::FenceOwed.refusal();
            assert_eq!(
                read,
                super::error_reply(REQUEST, refusal.code(), refusal.to_string()),
                "the refusal of the fence"
            );
        } else {
            assert_eq!(read, conflict, "the control");
        }
    }
}

/// KR-REQ-17.54: a reply read from a record is written under a lease that is live when the write is
/// let go, not only when its reading began. The question the writer asks after the lease's reading
/// reads the bound of that lease without a lock, so a lease that ends between the reading and the
/// question stops the reply before the transport takes it: the stored answer is never written, and
/// the caller is told the outcome is unknown. The control: where the lease still stands after the
/// pause, the whole answer is read.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reply_read_from_a_record_is_not_written_when_the_lease_ends_after_it_is_read() {
    for ends in [false, true] {
        let (_temp, controller, continuous, mut writer, mut reader) =
            connected_under_a_lease().await;
        let (_connection_id, _revision, footing) = registered(&controller);
        let (arrived, go) = controller.pause_after_the_lease_is_read();
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
                        &WrittenUnder::for_a_record_case(footing, false),
                    )
                    .await;
                drop(writer);
                stood
            })
        };
        // The lease was read live, and the question is about to be asked.
        tokio::task::spawn_blocking(move || {
            arrived.recv_timeout(std::time::Duration::from_secs(30))
        })
        .await
        .expect("the wait ends")
        .expect("the lease is read for the reply");
        if ends {
            continuous.advance(std::time::Duration::from_secs(16 * 60));
        }
        go.send(()).expect("the question goes on");
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

/// KR-REQ-17.54: the ask that stands behind a sign-in reads the owner's lease first, and then asks
/// the footing's one question through its guard, which reads the fence this host owes and compares
/// the lease's end that the reading returned with the clock again. A lease that ends between the
/// reading and the question stops the sign-in: nothing is kept. The control: where the lease still
/// stands at the question, the ask passes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_sign_in_ask_whose_lease_ends_while_the_fence_is_read_is_refused() {
    for ends in [false, true] {
        let (_temp, controller, continuous, _writer, _reader) = connected_under_a_lease().await;
        let lasting = controller.sign_in_lasting(Method::AccountSignIn);
        let (arrived, go) = controller.pause_before_the_last_fence_read();
        let asking = tokio::task::spawn_blocking(move || lasting());
        // The lease was read live, and the question is about to be asked.
        tokio::task::spawn_blocking(move || {
            arrived.recv_timeout(std::time::Duration::from_secs(30))
        })
        .await
        .expect("the wait ends")
        .expect("the ask reaches its question");
        if ends {
            continuous.advance(std::time::Duration::from_secs(16 * 60));
        }
        go.send(()).expect("the ask goes on");
        let asked = asking.await.expect("the ask ends");
        if ends {
            let refused = asked.expect_err("a lease that ended in the wait stops the ask");
            assert_eq!(refused.code(), ErrorCode::PermissionDenied, "{refused:?}");
            assert_eq!(refused.to_string(), LEASE_NOT_LIVE, "{refused:?}");
        } else {
            asked.expect("the control passes");
        }
    }
}

/// KR-REQ-09.09: a fence this host comes to owe in the wait that follows the reading of the owner's
/// lease stops the sign-in's ask, which refuses in the fence's words, so nothing is kept. The
/// control: with no fence owed the ask passes and gives the host as its guard.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_sign_in_ask_whose_fence_comes_while_the_lease_is_read_is_refused() {
    for owed in [false, true] {
        let (_temp, controller, _continuous, _writer, _reader) = connected_under_a_lease().await;
        let lasting = controller.sign_in_lasting(Method::AccountSignIn);
        let (arrived, go) = controller.pause_before_the_last_fence_read();
        let asking = tokio::task::spawn_blocking(move || lasting());
        // The lease was read live, and the question is about to be asked.
        tokio::task::spawn_blocking(move || {
            arrived.recv_timeout(std::time::Duration::from_secs(30))
        })
        .await
        .expect("the wait ends")
        .expect("the ask reaches its question");
        controller.hold_fence(owed);
        go.send(()).expect("the ask goes on");
        let asked = asking.await.expect("the ask ends");
        controller.hold_fence(false);
        if owed {
            let refused = asked.expect_err("a fence owed in the wait stops the ask");
            assert_eq!(refused.code(), ErrorCode::PermissionDenied, "{refused:?}");
            assert_eq!(refused.to_string(), FENCE_OWED, "{refused:?}");
        } else {
            asked.expect("the control passes");
        }
    }
}

/// What a refusal of a request under a fence this host owes says, whole.
const FENCE_OWED: &str = "this host withdrew authority and the fence that withdrawal owes could \
     not be raised yet, so nothing admitted under it is dispatched; run kr doctor to see what \
     stopped it";

/// What a refusal of a held method says when the local owner's lease is not live, whole.
const LEASE_NOT_LIVE: &str = "this host is exclusively organisation-managed and its local owner's \
     membership lease is not live; present one with `kr organisation present`";

/// KR-REQ-17.54: the lease's bound that a sign-in's ask read can move to another lineage before the
/// question is asked: the lease was ended and established again. The question does not decide it:
/// the lease is read again and the question is asked with what the new reading found. Where the
/// new lineage has ended at the new reading, the ask is refused, as a lease that is not live is.
/// The control: where the new lineage is live, the ask passes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_sign_in_ask_whose_bound_moves_to_a_lineage_that_ended_at_the_new_reading_is_refused() {
    for ended in [false, true] {
        let (_temp, controller, continuous, presenter, _writer, _reader) =
            connected_under_a_lease_that_can_be_presented_again().await;
        let lasting = controller.sign_in_lasting(Method::AccountSignIn);
        let (arrived, go) = controller.pause_before_the_last_fence_read();
        let asking = tokio::task::spawn_blocking(move || lasting());
        // The lease was read live, and the question is about to be asked.
        tokio::task::spawn_blocking(move || {
            arrived.recv_timeout(std::time::Duration::from_secs(30))
        })
        .await
        .expect("the wait ends")
        .expect("the ask reaches its question");
        // A lease that holds other rights ends the run of the bound that was read and begins a new
        // one. Where `ended`, that lease has run out by the time the ask reads it again.
        presenter.present(&[kr_protocol::rights::ActionRight::FilesRead]);
        if ended {
            continuous.advance(std::time::Duration::from_secs(16 * 60));
        }
        go.send(()).expect("the ask goes on");
        let asked = asking.await.expect("the ask ends");
        if ended {
            let refused = asked.expect_err("a lineage that ended at the new reading stops the ask");
            assert_eq!(refused.code(), ErrorCode::PermissionDenied, "{refused:?}");
            assert_eq!(refused.to_string(), LEASE_NOT_LIVE, "{refused:?}");
        } else {
            asked.expect("the control passes with the new lineage");
        }
    }
}

/// KR-REQ-17.54: the guard that a sign-in's ask gives holds the host and the footing the question
/// was asked with, the lease's bound among them, until it is let go: the ask is made through it and
/// nothing it holds is let go of between the question and the write that follows. The footing is
/// counted through the host's copies that it holds, and the host through its own count.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_guard_of_a_sign_in_ask_holds_the_host_and_the_footing_it_asked_with() {
    let (_temp, controller, _continuous, _writer, _reader) = connected_under_a_lease().await;
    let lasting = controller.sign_in_lasting(Method::AccountSignIn);
    let host_before = Arc::strong_count(&controller);
    let copies_before = Arc::strong_count(&controller.copies);
    let guard = tokio::task::spawn_blocking(move || {
        let guard = lasting().expect("the ask passes");
        (lasting, guard)
    })
    .await
    .expect("the ask ends");
    let (lasting, guard) = guard;
    assert_eq!(
        Arc::strong_count(&controller),
        host_before + 1,
        "the guard holds the host"
    );
    assert_eq!(
        Arc::strong_count(&controller.copies),
        copies_before + 1,
        "the guard holds the footing the question was asked with"
    );
    drop(guard);
    assert_eq!(Arc::strong_count(&controller), host_before);
    assert_eq!(Arc::strong_count(&controller.copies), copies_before);
    drop(lasting);
}
