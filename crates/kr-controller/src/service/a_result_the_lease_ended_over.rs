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
    (temp, controller, writer, reader)
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
                REQUEST
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
