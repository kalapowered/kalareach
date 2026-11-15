//! What the door tells a paired device of an answer it reads from a record: the closure record a
//! session left, and the receipt a worker kept of an action it carried out or refused.
//!
//! A device whose registration is withdrawn, or to whom this host owes a fence, is not shown what
//! a record holds. The check is asked once the record is read, so a withdrawal that lands while the
//! door waits for the record, or for the worker that holds it, is what the answer meets: the device
//! is told that the outcome is not shown, and never that the action was refused or what it came to.
//! Each case is run with the fence owed and with none, which is the control: with none the device is
//! told what the record holds.

use std::sync::Arc;

use kr_protocol::envelope::{ControlFrame, MutationRequest, Outcome, ParamsValue, Response};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::ids::{ConnectionId, SessionId};
use kr_protocol::method::Method;
use kr_protocol::scalars::{CanonicalSet, Nullable};
use kr_protocol::session::{Durability, SessionCloseParams, SessionCloseResult, SessionState};

use super::a_copy_from_a_services_record::{EVERY_RIGHT, refusal_of};
use super::a_draft_a_device_writes::write_naming;
use super::decision::Answered;
use super::write_boundary::paired_connection;
use crate::service::a_close_a_worker_never_answers as fake;
use crate::service::a_read_that_meets_a_worker_on_its_way_out::closure_of;

/// How long a case waits for a request to reach the place it is stopped at.
const WAIT_BOUND: std::time::Duration = std::time::Duration::from_secs(30);

/// What a worker that answers from its receipt gives, once it knows the session it holds.
type Receipt = Arc<dyn Fn(SessionId) -> Outcome + Send + Sync>;

/// A daemon whose worker answers every mutation forwarded to it from a receipt it kept, which its
/// frame says, as a worker's does for a copy of an action it carried out or refused before.
async fn a_worker_that_answers_from_its_receipt(receipt: Receipt) -> fake::Silent {
    fake::fake_world(move |listener, identity, endpoint_text| {
        tokio::spawn(async move {
            loop {
                let Ok((connection, peer)) = listener.accept().await else {
                    return;
                };
                let identity = Arc::clone(&identity);
                let endpoint_text = endpoint_text.clone();
                let receipt = Arc::clone(&receipt);
                tokio::spawn(async move {
                    let (mut reader, mut writer) =
                        kr_ipc::framed::split(connection, kr_protocol::frame::StreamKind::Control);
                    let connection_id = ConnectionId::new(kr_ipc::new_uuid());
                    let stated: CanonicalSet<kr_protocol::ids::CapabilityId> =
                        std::iter::empty().collect();
                    while let Ok(frame) = reader.read_message::<ControlFrame>().await {
                        let replies = match fake::handshake(
                            &frame,
                            &identity,
                            &endpoint_text,
                            connection_id,
                            &peer,
                            &stated,
                        ) {
                            Some(replies) => replies,
                            None => match &frame {
                                ControlFrame::AuthorityRevision(notice) => {
                                    vec![ControlFrame::AuthorityRevisionAck(
                                        kr_protocol::worker::AuthorityRevisionAck {
                                            session_id: identity.session_id(),
                                            revision: notice.revision,
                                            fence: None,
                                        },
                                    )]
                                }
                                ControlFrame::Request(request)
                                    if request.method == Method::SessionRead.into() =>
                                {
                                    vec![ControlFrame::Response(Response {
                                        request_id: request.request_id,
                                        outcome: Outcome::Ok(
                                            ParamsValue::from_typed(&fake::read_result(
                                                identity.session_id(),
                                            ))
                                            .expect("encodes"),
                                        ),
                                    })]
                                }
                                ControlFrame::Forwarded(forwarded) => {
                                    vec![ControlFrame::RetainedResponse(Box::new(Response {
                                        request_id: forwarded.mutation.request_id,
                                        outcome: receipt(identity.session_id()),
                                    }))]
                                }
                                _ => Vec::new(),
                            },
                        };
                        for reply in replies {
                            if writer.write_message(&reply).await.is_err() {
                                return;
                            }
                        }
                    }
                });
            }
        })
    })
    .await
}

/// What the worker kept of a close it accepted: the session is closing.
fn the_acceptance_of_a_close(session_id: SessionId) -> Outcome {
    Outcome::Ok(
        ParamsValue::from_typed(&SessionCloseResult {
            session_id,
            state: SessionState::Closing,
            durability: Durability::Durable,
            closure: Nullable::null(),
            session: None,
        })
        .expect("encodes"),
    )
}

/// What the worker kept of an action it refused.
fn a_refusal_it_kept(_: SessionId) -> Outcome {
    Outcome::Error(ProtocolError::new(
        ErrorCode::PermissionDenied,
        "the authority this action stood on had been withdrawn",
    ))
}

/// A close of `session_id` on `connection`.
fn a_close_of(
    world: &fake::Silent,
    connection: &super::RemoteConnection,
    session_id: SessionId,
) -> MutationRequest {
    write_naming(
        world,
        connection,
        Method::SessionClose,
        7,
        &SessionCloseParams { session_id },
        Some(session_id),
    )
}

/// A prompt to the agent of `session_id` on `connection`, which a worker performs.
fn a_prompt_to(
    world: &fake::Silent,
    connection: &super::RemoteConnection,
    session_id: SessionId,
) -> MutationRequest {
    let params = kr_protocol::agent::AgentPromptParams {
        target: kr_protocol::agent::AgentMutationTarget {
            subject: kr_protocol::agent::AgentSubject {
                session_id,
                application_instance_id: kr_protocol::ids::ApplicationInstanceId::new(
                    kr_ipc::new_uuid(),
                ),
            },
            binding_revision: kr_protocol::ids::AgentBindingRevision::new(1),
        },
        draft_id: Nullable::null(),
        text: Nullable::some(kr_protocol::agent::PromptText::new("a prompt").expect("text")),
    };
    write_naming(
        world,
        connection,
        Method::AgentPromptSubmit,
        8,
        &params,
        Some(session_id),
    )
}

/// The place a case stops a request at, to owe the fence there.
#[derive(Clone, Copy)]
enum Pause {
    /// After the door's entry check, before the request's effect begins.
    BeforeTheEffect,
    /// After the worker has answered, before the answer is checked.
    AfterTheWorkerAnswered,
}

/// Serves `mutation` to `pause`, owes the fence there when `owed` says so, and returns what the
/// device is answered.
async fn answered_with_the_fence(
    world: &fake::Silent,
    connection: &super::RemoteConnection,
    mutation: MutationRequest,
    pause: Pause,
    owed: bool,
) -> Answered {
    let controller = &world.controller;
    let (arrived, go) = match pause {
        Pause::BeforeTheEffect => controller.before_the_effect.arm(),
        Pause::AfterTheWorkerAnswered => controller.pause_after_the_worker_answered(),
    };
    let (answered, ()) = tokio::join!(
        connection.answer_now(ControlFrame::Mutation(Box::new(mutation))),
        async {
            tokio::time::timeout(WAIT_BOUND, arrived)
                .await
                .expect("the request reaches the place it is stopped at")
                .expect("the pause is armed");
            controller.hold_fence(owed);
            go.send(()).expect("the request goes on");
        }
    );
    answered.expect("the request is answered")
}

/// What an answer holds when it is a result.
fn result_of<T: kr_protocol::wire::WireMessage>(answered: &Answered) -> T {
    let ControlFrame::Response(Response {
        outcome: Outcome::Ok(value),
        ..
    }) = answered.frame()
    else {
        panic!("a result was expected: {:?}", answered.frame());
    };
    value.to_typed().expect("the result of the method")
}

/// KR-REQ-09.09: a close of a session that no worker holds any more is answered from the closure
/// record, which the device is told only while this host owes no fence. The close names a session
/// whose closure is recorded; a fence is owed at the place before the close's effect; the device is
/// told the outcome is not shown, and not that the session closed. The control: with no fence owed
/// the device is told what the record holds.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_close_answered_from_the_closure_record_is_not_shown_when_a_fence_lands_after_the_read() {
    for owed in [false, true] {
        let world = fake::fake_worker(None).await;
        let (connection, _) = paired_connection(&world.controller, 41, EVERY_RIGHT);
        let session_id = SessionId::new(kr_ipc::new_uuid());
        world
            .controller
            .retire(&closure_of(session_id))
            .await
            .expect("the closure is recorded");

        let close = a_close_of(&world, &connection, session_id);
        let answered =
            answered_with_the_fence(&world, &connection, close, Pause::BeforeTheEffect, owed).await;
        if owed {
            let told = refusal_of(&answered);
            assert_eq!(told.code, ErrorCode::OutcomeUnknown, "{told:?}");
        } else {
            let closed: SessionCloseResult = result_of(&answered);
            assert_eq!(closed.state, SessionState::Closed);
        }
        world.serving.abort();
    }
}

/// KR-REQ-09.09: a close the worker answers from a receipt it kept, whether the receipt holds the
/// acceptance or a refusal, is told to the device only while this host owes no fence. The control:
/// with none owed the device is told what the receipt holds.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_close_the_worker_answers_from_its_receipt_is_not_shown_when_a_fence_lands_after_the_read()
 {
    let kept: [(&str, Receipt); 2] = [
        ("an acceptance", Arc::new(the_acceptance_of_a_close)),
        ("a refusal", Arc::new(a_refusal_it_kept)),
    ];
    for (what, receipt) in kept {
        for owed in [false, true] {
            let world = a_worker_that_answers_from_its_receipt(Arc::clone(&receipt)).await;
            let (connection, _) = paired_connection(&world.controller, 42, EVERY_RIGHT);
            let close = a_close_of(&world, &connection, world.session_id);
            let answered =
                answered_with_the_fence(&world, &connection, close, Pause::BeforeTheEffect, owed)
                    .await;
            let told = match answered.frame() {
                ControlFrame::Response(Response {
                    outcome: Outcome::Error(told),
                    ..
                }) => Some(told.code),
                _ => None,
            };
            match (what, owed) {
                (_, true) => assert_eq!(told, Some(ErrorCode::OutcomeUnknown), "{what}"),
                ("an acceptance", false) => {
                    let closed: SessionCloseResult = result_of(&answered);
                    assert_eq!(closed.state, SessionState::Closing);
                }
                (_, false) => assert_eq!(told, Some(ErrorCode::PermissionDenied), "{what}"),
            }
            world.serving.abort();
        }
    }
}

/// KR-REQ-09.09: a mutation the worker answers from a receipt it kept, whether the receipt holds
/// a result or a refusal, is told to the device only while this host owes no fence. The control:
/// with none owed the device is told what the receipt holds.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_mutation_the_worker_answers_from_its_receipt_is_not_shown_when_a_fence_lands_after_the_read()
 {
    let kept: [(&str, Receipt); 2] = [
        ("a result", Arc::new(|_| Outcome::Ok(ParamsValue::empty()))),
        ("a refusal", Arc::new(a_refusal_it_kept)),
    ];
    for (what, receipt) in kept {
        for owed in [false, true] {
            let world = a_worker_that_answers_from_its_receipt(Arc::clone(&receipt)).await;
            let (connection, _) = paired_connection(&world.controller, 43, EVERY_RIGHT);
            let prompt = a_prompt_to(&world, &connection, world.session_id);
            let answered = answered_with_the_fence(
                &world,
                &connection,
                prompt,
                Pause::AfterTheWorkerAnswered,
                owed,
            )
            .await;
            let told = match answered.frame() {
                ControlFrame::Response(Response {
                    outcome: Outcome::Error(told),
                    ..
                }) => Some(told.code),
                _ => None,
            };
            match (what, owed) {
                (_, true) => assert_eq!(told, Some(ErrorCode::OutcomeUnknown), "{what}"),
                ("a result", false) => assert_eq!(told, None, "{what}"),
                (_, false) => assert_eq!(told, Some(ErrorCode::PermissionDenied), "{what}"),
            }
            world.serving.abort();
        }
    }
}

/// KR-REQ-09.09: a mutation that names a session whose closure is recorded is refused from the
/// record, which the device is told only while this host owes no fence. A fence is owed at the place
/// before the mutation's effect; the device is told the outcome is not shown, and not that the
/// session closed. The control: with no fence owed the device is told the session closed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_mutation_refused_from_a_closure_record_is_not_shown_when_a_fence_lands_after_the_read() {
    for owed in [false, true] {
        let world = fake::fake_worker(None).await;
        let (connection, _) = paired_connection(&world.controller, 44, EVERY_RIGHT);
        let session_id = SessionId::new(kr_ipc::new_uuid());
        world
            .controller
            .retire(&closure_of(session_id))
            .await
            .expect("the closure is recorded");

        let prompt = a_prompt_to(&world, &connection, session_id);
        let answered =
            answered_with_the_fence(&world, &connection, prompt, Pause::BeforeTheEffect, owed)
                .await;
        let told = refusal_of(&answered);
        if owed {
            assert_eq!(told.code, ErrorCode::OutcomeUnknown, "{told:?}");
        } else {
            assert_eq!(told.code, ErrorCode::SessionClosed, "{told:?}");
        }
        world.serving.abort();
    }
}
