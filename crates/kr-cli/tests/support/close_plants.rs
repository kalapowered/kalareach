//! Earlier closes of a session as its worker's journal holds them.
//!
//! No `kr` suite can make a worker answer a close "whose outcome I cannot establish": the worker
//! says that only of a dispatch it never settled. So a test that needs one writes the earlier close
//! into the worker's journal itself, as a worker that was dispatching it when it stopped leaves it.

use kr_protocol::envelope::{ActionTarget, MutationRequest, ParamsValue};
use kr_protocol::ids::{
    ActionId, ActionWindowId, ActorId, EnvironmentId, RequestId, SessionEpoch, SessionId,
};
use kr_protocol::method::{Method, MethodVersion};
use kr_protocol::receipt::ReceiptState;
use kr_protocol::scalars::{Digest256, DurationMs, Nullable, TimestampMs};
use kr_worker::journal::{Journal, Submission};

/// The local owner at this machine, as a worker names the actor of a command's request.
pub fn the_local_owner() -> ActorId {
    ActorId::new(format!("local:{}", kr_ipc::paths::current_uid())).expect("a principal")
}

/// The subject of the close `kr close` composes for a session: its method, version and whole
/// target, which is what a close of that session has in common with every other.
pub fn the_subject_of_a_close(environment_id: EnvironmentId, session_id: SessionId) -> Digest256 {
    kr_protocol::action::subject_digest(&MutationRequest {
        request_id: RequestId::new(1),
        method: Method::SessionClose.into(),
        method_version: MethodVersion::V1,
        action_id: ActionId::new(kr_ipc::new_uuid()),
        grant_id: Nullable::null(),
        target: ActionTarget {
            environment_id,
            session_id: Nullable::some(session_id),
            session_epoch: Nullable::some(SessionEpoch::V1),
            application_instance_id: Nullable::null(),
            agent_binding_revision: Nullable::null(),
        },
        expected: ParamsValue::empty(),
        action_window_id: ActionWindowId::new("window-1").expect("a window identifier"),
        requested_ttl_ms: DurationMs::new(60_000),
        params: ParamsValue::from_typed(&kr_protocol::session::SessionCloseParams { session_id })
            .expect("encodes"),
    })
    .expect("a subject digest")
}

/// Writes into `journal` a request of the local owner's whose dispatch began, and settles it as
/// `settled` says; `None` leaves it dispatching, which a worker that opens the journal again settles
/// as an outcome it could not establish. Returns the revision the receipt stands at.
pub fn plant_a_dispatch(
    journal: &mut Journal,
    action: ActionId,
    method: Method,
    subject: Digest256,
    settled: Option<ReceiptState>,
) -> u64 {
    let actor = the_local_owner();
    let now = kr_ipc::now_ms();
    journal
        .accept(&Submission {
            actor_id: actor.clone(),
            action_id: action,
            method: method.into(),
            method_version: MethodVersion::V1,
            payload_digest: Digest256::from_bytes([50; 32]),
            subject_digest: subject,
            intent: vec![0xa0],
            accepted_deadline_ms: Some(TimestampMs::new(now.get() + 120_000)),
            now_ms: now,
        })
        .expect("the intent");
    journal
        .mark_dispatching(actor.clone(), action, now)
        .expect("a dispatch marker");
    if let Some(state) = settled {
        journal
            .settle(actor.clone(), action, state, None, None, now)
            .expect("a settled outcome");
    }
    journal
        .read(actor, action)
        .expect("readable")
        .expect("the receipt")
        .revision
        .get()
}
