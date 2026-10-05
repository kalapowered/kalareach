//! A prompt a caller at this machine sends to a session's agent, passed to the session's worker.
//!
//! A prompt that names a draft sends the draft's attachments to the session, and a submitted
//! attachment follows that session's retention instead of the seven-day window of an unused one.
//! The transfer service is this daemon's, so the record that says so is made here, before the
//! prompt is sent to the worker: nothing the worker then does, and nothing that happens to the
//! connection that hears its answer, decides whether a file this host was asked to hand to a
//! session is kept. A paired device's prompt is recorded as it arrives. This one is first put to
//! the worker with no lifetime, which the worker answers only from a receipt it holds, and is
//! recorded only when the worker says it holds none; any other answer is the caller's answer and
//! records nothing. The worker serves a prompt that names a draft only to this daemon, so no route
//! to the session's agent leaves a draft unrecorded.
//!
//! A prompt that carries its text inline names no draft and records nothing. A caller at this
//! machine may send it here or to the worker's own socket, and the worker answers it the same
//! either way.

use std::sync::Arc;

use kr_protocol::envelope::{MutationRequest, ParamsValue};
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::ConnectionId;
use kr_protocol::scalars::{CanonicalSet, U64};
use kr_transport::window::AcceptedDeadline;

use crate::error::{ControllerError, Result};

use super::admission::remaining_deadline;
use super::routes::local_actor;
use super::{Controller, parse};

/// The longest this daemon holds its link to a worker for the answer to one prompt when the prompt
/// brought no deadline of its own.
///
/// An exact repeat of a prompt carries the window its first attempt was admitted under, which this
/// connection does not hold, so it arrives with no deadline and is answered from the worker's
/// receipt. A worker that has stopped answering is let go of rather than held for whoever asks next.
const REPEAT_EXCHANGE: std::time::Duration = std::time::Duration::from_secs(30);

impl Controller {
    /// Passes a prompt a caller at this machine made to the worker that owns the session it names,
    /// after recording that the draft it names, if it names one, is sent to that session.
    ///
    /// The caller's envelope is forwarded, not replaced: the action identifier is the durable
    /// identity of the caller's action, and a repeat that reaches the worker by this route or by
    /// its own socket finds the same receipt. `accepted` is the deadline this daemon accepted for a
    /// first admission, and none for an exact repeat, which the worker answers from its record and
    /// which records nothing here: its first attempt did. A prompt that names a draft and still has
    /// its window is told from a repeat by the worker's own receipt before anything is recorded.
    ///
    /// # Errors
    ///
    /// Returns the refusal the worker gave, under its own code, the refusal the record met, an
    /// unknown session, or `OUTCOME_UNKNOWN` when the worker did not answer in time.
    pub(super) async fn local_prompt(
        self: &Arc<Self>,
        actor_id: &kr_protocol::ids::ActorId,
        mutation: &MutationRequest,
        connection_id: ConnectionId,
        accepted: Option<AcceptedDeadline>,
        carried: crate::authority::AdmittedMutation,
    ) -> Result<ParamsValue> {
        let params: kr_protocol::agent::AgentPromptParams = parse(&mutation.params)?;
        let session_id = params.target.subject.session_id;
        let worker = self.directory.lock().await.get(session_id).cloned().ok_or(
            ControllerError::UnknownSession {
                session: session_id.to_string(),
            },
        )?;
        // One budget for the whole exchange, started before the wait for the link: a worker that
        // stops answering while its link is opened, or a caller queued behind one that has, waits
        // exactly as long as one talking to a worker that answers slowly.
        let budget = tokio::time::Instant::now()
            + accepted.map_or(REPEAT_EXCHANGE, |accepted| {
                accepted
                    .deadline
                    .saturating_duration_since(self.clock.now())
            });
        let mut link = tokio::time::timeout_at(budget, self.worker_client(&worker))
            .await
            .map_err(|_| ControllerError::Uncertain {
                detail: "the connection to the worker that owns this session did not come free \
                         in the time this prompt was given, so nothing was sent"
                    .to_owned(),
            })??;
        // The admission is asked once the link is held, because holding it is where the wait was.
        // A deadline that ran out while this prompt queued is refused, and nothing is recorded or
        // sent for it. An exact repeat carries no deadline and goes on to the worker, which is
        // the only thing that knows whether it holds this action's receipt.
        let checked = async {
            let registry = self.registry.lock().await;
            match self.check_admission(&registry, &carried) {
                Ok(()) | Err(ControllerError::WindowExpired { .. }) if accepted.is_none() => Ok(()),
                other => other,
            }
        }
        .await;
        if let Err(error) = checked {
            link.give_back();
            return Err(error);
        }
        let deadline_boot_ms = match accepted {
            Some(accepted) => {
                let Some(deadline) =
                    remaining_deadline(&*self.shared_clock, &*self.clock, accepted.deadline, None)
                else {
                    link.give_back();
                    return Err(ControllerError::WindowExpired {
                        detail: "the deadline this prompt was admitted under has passed".to_owned(),
                    });
                };
                deadline
            }
            None => U64::new(0),
        };
        let actor = local_actor(actor_id.clone(), connection_id, self.generation);
        // The record is made for a first submission only, and before the worker is asked to take
        // the prompt. The worker is the only thing that knows whether it already holds a receipt
        // for this action, so it is asked first with the prompt itself and no lifetime. A prompt
        // with no lifetime cannot be admitted, so the worker answers only from a receipt it holds
        // (a result, or the receipt as it stands, or `ID_CONFLICT` for an identifier that was used
        // with another payload) or, finding none, with the refusal of a first admission that has
        // no lifetime, which keeps nothing. That refusal is the one answer that says it holds no
        // receipt, and only then is the draft recorded and the prompt sent. Any other answer is
        // the answer: a receipt is what the caller is owed and the draft was recorded when it was
        // first sent, and a refusal that leaves open whether the worker holds a receipt (its
        // journal cannot be read, a request it will not take) cannot be allowed to change what
        // is retained before the worker has said. A draft this caller does not hold has no
        // attachments for this host to retain, so naming one is not a failure, and a draft that is
        // for another session is refused before anything is sent.
        if accepted.is_some()
            && let Some(draft_id) = crate::transfer::prompted_draft(mutation)
        {
            let asked = tokio::time::timeout_at(
                budget,
                link.client()
                    .forward(mutation, &actor, &CanonicalSet::new(), U64::new(0)),
            )
            .await;
            match asked {
                Ok(Ok(Err(refusal))) if refusal.code == ErrorCode::PermissionDenied => {}
                Ok(Ok(answer)) => {
                    link.give_back();
                    return answer.map_err(|refusal| ControllerError::refused(&refusal));
                }
                // The link is retired in the two arms below, because its exchange was abandoned or
                // failed part way and its next caller would read this answer as its own.
                Ok(Err(error)) => return Err(error.into()),
                Err(_) => {
                    return Err(ControllerError::Uncertain {
                        detail:
                            "the worker that owns this session did not answer in the time this \
                                 prompt was given, so nothing was sent"
                                .to_owned(),
                    });
                }
            }
            if let Err(error) = self
                .transfer
                .record_submission(
                    actor_id,
                    draft_id,
                    session_id,
                    crate::transfer::TransferAdmission::new(Arc::clone(self), carried),
                )
                .await
            {
                link.give_back();
                return Err(ControllerError::refused(&error));
            }
        }
        let answered = tokio::time::timeout_at(
            budget,
            link.client().forward(
                mutation,
                &actor,
                // A local caller acts under the operating-system identity the listener
                // authenticated rather than under a grant, so there are no rights to narrow what
                // it asked for.
                &CanonicalSet::new(),
                deadline_boot_ms,
            ),
        )
        .await;
        match answered {
            Ok(Ok(result)) => {
                link.give_back();
                result.map_err(|refusal| ControllerError::refused(&refusal))
            }
            Ok(Err(error)) => Err(error.into()),
            // The prompt was written and no answer came back in the time it was given. The link is
            // retired rather than returned to the shared slot, because its exchange was abandoned
            // part way through and the next caller would read this answer as its own. Whether the
            // agent took the prompt is not known, which is what the caller is told.
            Err(_) => Err(ControllerError::Uncertain {
                detail: "the worker did not answer this prompt in the time it was given, so \
                         whether the agent took it is not known"
                    .to_owned(),
            }),
        }
    }
}
