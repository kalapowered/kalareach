//! A session closed by voice.
//!
//! A close the person asked for aloud, and confirmed on the unlocked screen of their paired device,
//! goes to the session's worker the way that device's own typed close does: as the device, over a
//! link opened for the close, with the rights of a close and nothing else. The voice grant is what
//! it travels under, so a worker can tell it from a close the device sent by hand, and withdrawing
//! that grant has to reach a worker that has not yet acted on it.

use std::sync::Arc;

use kr_protocol::actor::{ActorEnvelope, ActorIngress};
use kr_protocol::envelope::{ActionTarget, MutationRequest, ParamsValue};
use kr_protocol::ids::{ActionWindowId, RequestId, SessionEpoch};
use kr_protocol::method::{Method, MethodVersion};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{CanonicalSet, DurationMs, Nullable};
use kr_protocol::session::{SessionCloseParams, SessionCloseResult, SessionState};
use kr_transport::window::{AcceptedDeadline, DeadlineBound};
use kr_voice::seams::HostReceipt;

use crate::error::{ControllerError, Result};
use crate::grants::CloseHold;
use crate::service::net::lifetimes::Anchored;
use crate::service::net::proxy::Vouched;

use super::Controller;

impl Controller {
    /// Closes the session a voice proposal names, and reports what the worker answered.
    ///
    /// The proposal was admitted by the coordinator: the words were read by this host, the device
    /// signed the confirmation over this action's plan, and both grants carry the right to close
    /// this session. What is done here is what stays true between that decision and the worker:
    ///
    /// * The close is **held** against its voice grant before anything is read
    ///   ([`crate::grants::GrantDirectory::hold_close`]), then the revision and the authority are
    ///   read together, and only then is the close forwarded. A revocation of the voice grant is
    ///   wholly before the hold, so the read finds it and nothing is forwarded, or wholly after, so
    ///   it sees the hold and owes the fence that makes the worker refuse a close it has not yet
    ///   taken up.
    /// * The close travels under the action identifier of the delegation, with the deadline the
    ///   delegation was admitted under, shortened to the time the close is allowed and to the end
    ///   of the voice grant, so a worker that is slow to take it up cannot take it up late.
    /// * The close runs on a task of its own. A connection that goes away does not call it back;
    ///   the caller of this records what it came to under the delegation's claim, and a repeat of
    ///   the delegation is given that.
    ///
    /// A worker that refuses the close is the refusal this returns. One that does not answer inside
    /// the time allowed is [`ControllerError::Uncertain`]: the close may have happened, and it is
    /// not sent again.
    ///
    /// # Errors
    ///
    /// Returns the refusal of the admission, of the authority read, of the worker, or the
    /// uncertainty of a worker that did not answer.
    pub(super) async fn voice_close(
        self: &Arc<Self>,
        proposal: &kr_voice::Proposal,
        admission: &Arc<dyn kr_voice::Admission>,
    ) -> Result<HostReceipt> {
        let session_id = proposal.session_id.ok_or_else(|| {
            ControllerError::InvalidArgument("a close names the session it closes".to_owned())
        })?;
        admission
            .still_admitted()
            .map_err(|refusal| ControllerError::refused(&refusal))?;
        let connection_id = admission.connection().ok_or_else(|| {
            ControllerError::InvalidArgument(
                "a close arrives over the connection the delegation arrived on".to_owned(),
            )
        })?;

        // How long this close may take, and how long a worker may take it up.
        let now = self.clock.now();
        let mut allowed = self.voice_budgets().close;
        if let Some(left) = admission.time_left() {
            allowed = allowed.min(left);
        }
        let record = self
            .sharing
            .grants()
            .record(proposal.voice_grant_id)?
            .ok_or_else(|| ControllerError::PermissionDenied {
                detail: "the voice grant this action was admitted under has ended".to_owned(),
            })?;
        match self.lifetimes().stored(self.sharing.grants(), &record)? {
            Anchored::Unlimited => {}
            Anchored::Until(end) => allowed = allowed.min(end.saturating_duration_since(now)),
            Anchored::Over => {
                return Err(ControllerError::PermissionDenied {
                    detail: "the voice grant this action was admitted under has ended".to_owned(),
                });
            }
        }
        let deadline = now
            .checked_add(allowed)
            .filter(|_| !allowed.is_zero())
            .ok_or_else(|| ControllerError::WindowExpired {
                detail: "the time this close was allowed has passed".to_owned(),
            })?;

        let hold = self.sharing.grants().hold_close(proposal.voice_grant_id);
        #[cfg(test)]
        self.after_a_voice_close_is_held.wait().await;
        // The revision and the authority are read under the registry, which no barrier advances the
        // revision without: the revision this close is validated under is the one in force when its
        // authority was read. A worker that has installed a later one refuses it, and a revocation
        // of this grant that follows the read advances the revision past it.
        let (revision, narrowed) = {
            let registry = self.registry.lock().await;
            let revision = registry.authority_revision()?;
            (revision, self.voice_authority_now(proposal, session_id)?)
        };

        let mutation = close_of(proposal, session_id);
        let envelope = ActorEnvelope {
            actor_id: kr_transport::listener::device_principal(&proposal.device_id),
            ingress: ActorIngress::PairedDevice,
            device_id: Nullable::some(proposal.device_id),
            grant_id: Nullable::some(proposal.voice_grant_id),
            grant_revision: Nullable::some(revision),
            controller_generation: self.generation,
            connection_id,
        };
        let accepted = AcceptedDeadline {
            deadline,
            bound: DeadlineBound::AuthorityDeadline,
        };
        let (answer, answered) = tokio::sync::oneshot::channel();
        // Nothing holds the link for a delivery: the acceptance is taken as delivered at once.
        let (_, delivered) = tokio::sync::oneshot::channel();
        let daemon = Arc::clone(self);
        tokio::spawn(async move {
            let rights: CanonicalSet<ActionRight> =
                std::iter::once(ActionRight::SessionClose).collect();
            daemon
                .close_remote_session(
                    &mutation,
                    Vouched {
                        actor: &envelope,
                        grant_rights: &rights,
                        history: Some(&narrowed.history),
                        // A close is not an attach: no screen is drawn from it.
                        screen_basis: None,
                    },
                    accepted,
                    None,
                    answer,
                    delivered,
                )
                .await;
        });

        match tokio::time::timeout(allowed, answered).await {
            Ok(Ok(Ok(closed))) => {
                // The worker has answered, so nothing is left that could still run.
                drop(hold);
                Ok(self
                    .closed_by_voice(proposal, session_id, &closed.value)
                    .await)
            }
            Ok(Ok(Err(error))) => {
                lets_go_at(hold, deadline, &self.clock);
                Err(error)
            }
            Ok(Err(_)) | Err(_) => {
                lets_go_at(hold, deadline, &self.clock);
                Err(ControllerError::Uncertain {
                    detail: "this host could not tell whether the session closed: its worker did \
                             not answer in time, and the close is not sent again"
                        .to_owned(),
                })
            }
        }
    }

    /// The receipt for a close the worker accepted: the session is closing, or it already closed.
    async fn closed_by_voice(
        self: &Arc<Self>,
        proposal: &kr_voice::Proposal,
        session_id: kr_protocol::ids::SessionId,
        answer: &ParamsValue,
    ) -> HostReceipt {
        let number = self.voice_session_number(session_id).await.ok().flatten();
        let named = number.map_or_else(|| "the session".to_owned(), |n| format!("session {n}"));
        // A worker's retained answer to a close it had already taken may be its receipt and not a
        // close result; the close it answers happened either way.
        let state = answer
            .to_typed::<SessionCloseResult>()
            .ok()
            .map(|result| result.state);
        let summary = match state {
            Some(SessionState::Closed) => format!("{named} is closed"),
            Some(SessionState::Closing) | None => format!("{named} is closing"),
            Some(SessionState::Creating | SessionState::Live) => {
                format!("{named} was asked to close")
            }
        };
        HostReceipt {
            action_id: proposal.action_id,
            performed: true,
            summary,
        }
    }
}

/// The close a voice proposal is, as the worker is sent it.
///
/// Everything in it is fixed by the proposal, so the same proposal is always the same mutation:
/// the worker's journal answers an exact retry from the action it already took.
fn close_of(
    proposal: &kr_voice::Proposal,
    session_id: kr_protocol::ids::SessionId,
) -> MutationRequest {
    MutationRequest {
        // The link gives the frame its own request identity; the durable one is the action's.
        request_id: RequestId::new(0),
        method: Method::SessionClose.into(),
        method_version: MethodVersion::V1,
        action_id: proposal.action_id,
        grant_id: Nullable::some(proposal.voice_grant_id),
        target: ActionTarget {
            environment_id: proposal.environment_id,
            session_id: Nullable::some(session_id),
            session_epoch: Nullable::some(SessionEpoch::V1),
            application_instance_id: Nullable::null(),
            agent_binding_revision: Nullable::null(),
        },
        expected: ParamsValue::empty(),
        action_window_id: ActionWindowId::new("voice:delegation")
            .expect("a fixed window is an opaque identifier"),
        requested_ttl_ms: DurationMs::new(30_000),
        params: ParamsValue::from_typed(&SessionCloseParams { session_id })
            .expect("a session identifier encodes"),
    }
}

/// Keeps a close held against its grant until the deadline it was forwarded with has passed.
///
/// A worker that did not answer may still take the close up until that deadline, so a withdrawal of
/// the voice grant before then still owes the fence.
fn lets_go_at(
    hold: CloseHold,
    deadline: kr_transport::clock::ContinuousInstant,
    clock: &Arc<dyn kr_transport::clock::ContinuousClock>,
) {
    let left = deadline.saturating_duration_since(clock.now());
    tokio::spawn(async move {
        tokio::time::sleep(left).await;
        drop(hold);
    });
}
