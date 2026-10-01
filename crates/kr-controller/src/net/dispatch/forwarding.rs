//! Forwarding to the worker that owns a session, the action routes, receipts and relayed batches.

use std::sync::Arc;

use kr_protocol::authority::MethodEntry;
use kr_protocol::envelope::{
    ControlFrame, MutationRequest, Outcome, ParamsValue, Request, Response,
};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::ids::{AuthorityRevision, SessionId};
use kr_protocol::method::Method;
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::CanonicalSet;
use kr_transport::window::AcceptedDeadline;

use super::super::proxy::{Vouched, WorkerProxy};
use crate::error::{ControllerError, Result};
use crate::grants::policy::HeldBound;

use super::decision::{Asked, session_of};
use super::output::{RELAY_DECISIONS, RelayGrant, Relaying, Written};
use super::{RemoteConnection, failure, outcome_unknown};

/// Why a claim on an action's identity did not succeed.
///
/// The two are answered differently. A conflict is this host's answer about the action: section 9
/// makes a reused identifier carrying a different payload `ID_CONFLICT`, and nothing is dispatched
/// under it. Storage being unavailable says nothing about the action, and section 7 does not let a
/// storage failure stop an authorised stop, so a close goes on without its route while every other
/// mutation is refused.
pub(super) enum RouteRefusal {
    Conflict(ProtocolError),
    Unavailable(ProtocolError),
}

impl RouteRefusal {
    pub(super) fn into_error(self) -> ProtocolError {
        match self {
            Self::Conflict(error) | Self::Unavailable(error) => error,
        }
    }
}

impl RemoteConnection {
    /// Answers `action.read` for a catalogue action this device performed, where there is one.
    ///
    /// A catalogue action names no session: its receipt is kept by the catalogue, beside the
    /// state the action changed, under the actor that submitted it. It is read as this device,
    /// and it is disclosed only while this device's grant still carries `host.manage`, the right
    /// every catalogue action required. Owning an action identifier is not authority, and a device
    /// whose authority over the catalogue was withdrawn is not told what it did there.
    ///
    /// `None` is a request this does not answer: one that names a session, or an action the
    /// catalogue holds no receipt for, which the session route then answers.
    pub(super) async fn host_receipt(&self, request: &Request) -> Option<ControlFrame> {
        let params: kr_protocol::receipt::ActionReadParams = request.params.to_typed().ok()?;
        if params.session_id.is_some() {
            return None;
        }
        let actor_id = self.device.principal();
        let read = match self
            .controller
            .catalogue
            .action_read(&actor_id, params.action_id)
            .await
        {
            Ok(Some(read)) => read,
            Ok(None) => return None,
            Err(error) => return Some(failure(request.request_id, error)),
        };
        if !self.device.grant.permits(ActionRight::HostManage) {
            return Some(failure(
                request.request_id,
                ProtocolError::new(
                    ErrorCode::PermissionDenied,
                    "this device's grant no longer carries host.manage, which the catalogue \
                     action it names required",
                ),
            ));
        }
        Some(match ParamsValue::from_typed(&read) {
            Ok(value) => ControlFrame::Response(Response {
                request_id: request.request_id,
                outcome: Outcome::Ok(value),
            }),
            Err(error) => failure(
                request.request_id,
                ProtocolError::new(ErrorCode::StorageUnavailable, error.to_string()),
            ),
        })
    }

    /// Forwards one read to the worker that owns the session it names.
    pub(super) async fn proxied_read(
        &self,
        request: &Request,
        entry: &'static MethodEntry,
        validated: AuthorityRevision,
        asked: &Asked,
    ) -> ControlFrame {
        // A read that names its session goes to that session's worker. `action.read` names an
        // action rather than a session, and an action's receipt lives in the journal of whichever
        // session it was performed on, so the route this host recorded when it dispatched the
        // action is what says where to ask.
        let proxy = match session_of(&request.params, entry) {
            Ok(session_id) => self
                .proxy_for(session_id)
                .await
                .map_err(|error| error.to_protocol_error()),
            Err(_) if entry.method == Method::ActionRead => {
                self.receipt_owner(request, entry).await
            }
            Err(error) => return failure(request.request_id, error),
        };
        let proxy = match proxy {
            Ok(proxy) => proxy,
            Err(error) => return failure(request.request_id, error),
        };
        let envelope = self.envelope(validated);
        let authority = match self.authority_deadline(asked) {
            Ok(authority) => authority,
            Err(error) => return failure(request.request_id, error),
        };
        match proxy
            .forward_read(
                request,
                &envelope,
                authority,
                Some(&self.device.grant.history),
            )
            .await
        {
            Ok(response) => ControlFrame::Response(Response {
                request_id: request.request_id,
                outcome: response.outcome,
            }),
            Err(error) => failure(request.request_id, error.to_protocol_error()),
        }
    }

    /// Forwards one mutation to the worker that owns the session it names.
    ///
    /// Remote dispatch additionally needs a live lease from the current generation and revision,
    /// taken at the moment the dispatch runs rather than one that was valid when the request
    /// arrived, and the lease's own remaining time bounds the deadline the worker is given.
    pub(super) async fn proxied_mutation(
        &self,
        mutation: &MutationRequest,
        accepted: AcceptedDeadline,
        validated: AuthorityRevision,
        grant_rights: CanonicalSet<ActionRight>,
    ) -> ControlFrame {
        let Some(session_id) = mutation.target.session_id.as_ref().copied() else {
            return failure(
                mutation.request_id,
                ProtocolError::new(
                    ErrorCode::InvalidArgument,
                    "this mutation names the session it acts on",
                ),
            );
        };
        let proxy = match self.proxy_for(session_id).await {
            Ok(proxy) => proxy,
            Err(error) => return failure(mutation.request_id, error.to_protocol_error()),
        };
        if let Err(refusal) = self.claim_route(mutation, Some(session_id)) {
            return failure(mutation.request_id, refusal.into_error());
        }
        let envelope = self.envelope(validated);
        let deadline = match self
            .controller
            .forwarded_deadline(session_id, &envelope, accepted)
            .await
        {
            Ok(deadline) => deadline,
            Err(error) => {
                // The grant may have run out while this waited, and wherever that is observed it
                // is written down. What decides is the grant's own deadline: everything else this
                // failure can mean says nothing about the grant.
                self.expiry_observer().grant_expired();
                return failure(mutation.request_id, error.to_protocol_error());
            }
        };
        // The effect runs on a task that outlives this connection, for the same reason the
        // daemon's own effects do: the worker commits the intent before it answers, and a
        // cancellation here must not be what decides whether the outcome is recorded.
        let mutation = mutation.clone();
        let request_id = mutation.request_id;
        // The grant's history scope travels with it too, so what the worker shows of its answer,
        // now and when the action is read again, is held to what this device's grant reaches.
        let history = self.device.grant.history.clone();
        // The rights this request was decided with travel with the mutation: the grant as this
        // host's policy and its configured ceiling leave it. The worker admits an attachment and
        // holds no grants: section 8's intersection of requested capabilities with the actor's
        // rights is made where the attachment is admitted, out of what the host checked this
        // request against.
        let effect = tokio::spawn(async move {
            proxy
                .forward_mutation(
                    &mutation,
                    Vouched {
                        actor: &envelope,
                        grant_rights: &grant_rights,
                        history: Some(&history),
                    },
                    deadline,
                )
                .await
        });
        match effect.await {
            Ok(Ok(answered)) => {
                if answered.retained
                    && let Err(error) = self.may_read_receipts(Some(session_id))
                {
                    return failure(request_id, error);
                }
                ControlFrame::Response(Response {
                    request_id,
                    outcome: answered.response.outcome,
                })
            }
            Ok(Err(error)) => failure(request_id, error.to_protocol_error()),
            Err(_) => failure(request_id, outcome_unknown()),
        }
    }

    /// Returns whether this device may be told what one of its own actions produced.
    ///
    /// A retained answer is a read of a receipt, and section 23 has present view authority over
    /// the subject decide whether either half of a retained result is returned. The rights that
    /// decide it are `action.read`'s over the session the receipt belongs to, not the ones the
    /// mutation needed: a device that may act on a session it cannot observe does not learn what
    /// its action produced by submitting it twice.
    pub(super) fn may_read_receipts(
        &self,
        session_id: Option<SessionId>,
    ) -> std::result::Result<(), ProtocolError> {
        let entry = self.admit(
            Method::ActionRead.as_str(),
            Method::ActionRead.entry().version,
        )?;
        self.check_grant(session_id, entry, false).map(|_| ())
    }

    /// Returns this connection's link to one worker, opening it on first use.
    ///
    /// One link per connection, and one worker per link: a device attaches to one session at a
    /// time on one connection, and its attachment, its subscription and its input all have to
    /// belong to the same worker connection for the worker's own ownership rules to hold.
    async fn proxy_for(&self, session_id: SessionId) -> Result<Arc<WorkerProxy>> {
        let mut held = self.proxy.lock().await;
        if let Some(proxy) = held.as_ref() {
            if proxy.session_id() == session_id && proxy.is_open() {
                return Ok(Arc::clone(proxy));
            }
            if proxy.session_id() != session_id {
                return Err(ControllerError::InvalidArgument(
                    "this connection is already serving another session; open another connection"
                        .to_owned(),
                ));
            }
            // The link to this session has ended. A new one would be a new subscription and a new
            // attachment, which is a reconnection rather than something to do behind the caller's
            // back: section 8 has the client restore its state through cursors.
            return Err(ControllerError::supervision(
                "this connection's link to its session has ended; reconnect and subscribe again",
            ));
        }
        let proxy = self
            .controller
            .open_proxy(
                session_id,
                self.notifications.clone(),
                Arc::clone(&self.budget),
                Arc::clone(&self.lost),
            )
            .await?;
        *held = Some(Arc::clone(&proxy));
        Ok(proxy)
    }

    /// Claims this action's route before it is dispatched, and refuses a reused identifier.
    ///
    /// Where the action is going is written down before it goes. A receipt lives in the journal of
    /// the session the action was performed on, and a device whose connection ends before the
    /// answer arrives has nothing else left to say which session that was. An action whose route
    /// cannot be recorded is not dispatched: an unrecoverable result is worse than a refusal the
    /// device can submit again under the same identity.
    ///
    /// The claim is also this host's `(verified actor, action)` uniqueness check. Section 9 makes
    /// a reused identifier carrying a different payload `ID_CONFLICT`, and the digest the route
    /// holds is what a second submission is compared against.
    pub(super) fn claim_route(
        &self,
        mutation: &MutationRequest,
        session_id: Option<SessionId>,
    ) -> std::result::Result<(), RouteRefusal> {
        let actor_id = self.device.principal();
        let digest =
            kr_protocol::digest::mutation_digest(mutation, &actor_id).map_err(|error| {
                RouteRefusal::Conflict(ProtocolError::new(
                    ErrorCode::InvalidArgument,
                    error.to_string(),
                ))
            })?;
        let claimed = self
            .devices
            .claim_action_route(
                &actor_id,
                mutation.action_id,
                session_id,
                digest,
                kr_ipc::now_ms(),
            )
            .map_err(|error| RouteRefusal::Unavailable(error.to_protocol_error()))?;
        match claimed {
            super::super::devices::ActionRoute::Recorded => Ok(()),
            super::super::devices::ActionRoute::Existing(existing)
                if existing.payload_digest == Some(digest) && existing.session_id == session_id =>
            {
                Ok(())
            }
            super::super::devices::ActionRoute::Existing(_) => {
                Err(RouteRefusal::Conflict(ProtocolError::new(
                    ErrorCode::IdConflict,
                    format!(
                        "action {} was already used with a different request",
                        mutation.action_id
                    ),
                )))
            }
        }
    }

    /// Answers a resubmitted action from the receipt the worker that ran it still holds.
    ///
    /// Only an action this host has already dispatched is looked up, so an ordinary first
    /// submission costs nothing. A digest that does not match the route's is a reused identifier,
    /// which section 9 refuses; a matching digest is the same action, and the worker's own receipt
    /// is the answer. A worker that holds no receipt for it leaves the request to the ordinary
    /// first-admission path, where its window decides.
    pub(super) async fn retained_remotely(
        &self,
        mutation: &MutationRequest,
        validated: AuthorityRevision,
        asked: &Asked,
    ) -> std::result::Result<Option<ControlFrame>, RouteRefusal> {
        let actor_id = self.device.principal();
        let Some(routed) = self
            .devices
            .action_route(&actor_id, mutation.action_id)
            .map_err(|error| RouteRefusal::Unavailable(error.to_protocol_error()))?
        else {
            return Ok(None);
        };
        let digest =
            kr_protocol::digest::mutation_digest(mutation, &actor_id).map_err(|error| {
                RouteRefusal::Conflict(ProtocolError::new(
                    ErrorCode::InvalidArgument,
                    error.to_string(),
                ))
            })?;
        if routed.payload_digest != Some(digest) {
            return Err(RouteRefusal::Conflict(ProtocolError::new(
                ErrorCode::IdConflict,
                format!(
                    "action {} was already used with a different request",
                    mutation.action_id
                ),
            )));
        }
        // An action this host itself owns the receipt of is answered by the daemon or not at all.
        // Asking a worker about it would ask the wrong journal.
        let Some(session_id) = routed.session_id else {
            return Ok(None);
        };
        // A refusal here is the answer, not a reason to go on. This action has already been
        // dispatched, and forwarding it again would have the worker answer from the receipt this
        // device may not read.
        self.may_read_receipts(Some(session_id))
            .map_err(RouteRefusal::Conflict)?;
        // A link that cannot be opened is not an answer. The ordinary path decides what this
        // request gets, which for a session whose worker has gone is that session's own refusal
        // rather than a second dispatch.
        let Ok(proxy) = self.proxy_for(session_id).await else {
            return Ok(None);
        };
        let request = Request {
            request_id: mutation.request_id,
            method: Method::ActionRead.into(),
            method_version: Method::ActionRead.entry().version,
            params: ParamsValue::from_typed(&kr_protocol::receipt::ActionReadParams {
                action_id: mutation.action_id,
                // This request goes to the worker that owns the session, which serves the
                // receipts of the one session it has. Naming it would say nothing more.
                session_id: None,
            })
            .map_err(|error| {
                RouteRefusal::Conflict(ProtocolError::new(
                    ErrorCode::InvalidArgument,
                    error.to_string(),
                ))
            })?,
        };
        let envelope = self.envelope(validated);
        let authority = self
            .authority_deadline(asked)
            .map_err(RouteRefusal::Conflict)?;
        let Ok(response) = proxy
            .forward_read(
                &request,
                &envelope,
                authority,
                Some(&self.device.grant.history),
            )
            .await
        else {
            // The link failed, not the lookup. The ordinary path decides what happens next.
            return Ok(None);
        };
        let Outcome::Ok(value) = response.outcome else {
            // No receipt for it there, or the worker refused the read. Either way this is not an
            // answer, and the request goes on to be admitted or refused on its own terms.
            return Ok(None);
        };
        let Ok(read) = value.to_typed::<kr_protocol::receipt::ActionReadResult>() else {
            return Ok(None);
        };
        // The result when the action produced one, and the receipt when it has not: a caller that
        // resubmitted is told what became of its action, and nothing is dispatched again.
        Ok(Some(match read.result.0 {
            Some(result) => {
                // A close's result is settled as one given now is, and goes as it came.
                if mutation.method == Method::SessionClose.into()
                    && let Ok(answer) =
                        result.to_typed::<kr_protocol::session::SessionCloseResult>()
                {
                    let _ = self
                        .controller
                        .settle_close_answer(session_id, &answer)
                        .await;
                }
                ControlFrame::Response(Response {
                    request_id: mutation.request_id,
                    outcome: Outcome::Ok(result),
                })
            }
            None => ControlFrame::Receipt(Box::new(kr_protocol::receipt::ReceiptResponse {
                request_id: mutation.request_id,
                receipt: read.receipt,
            })),
        }))
    }

    /// Returns the link to the worker holding one action's receipt.
    ///
    /// The route is durable, so a device that lost its connection, or found this host restarted,
    /// can still ask for its own result. Owning an action identifier is not authority: the grant
    /// is checked again against the session the route names, because what the action was
    /// dispatched under may since have been narrowed.
    async fn receipt_owner(
        &self,
        request: &Request,
        entry: &'static MethodEntry,
    ) -> std::result::Result<Arc<WorkerProxy>, ProtocolError> {
        let params: kr_protocol::receipt::ActionReadParams = request
            .params
            .to_typed()
            .map_err(|error| ProtocolError::new(ErrorCode::InvalidArgument, error.to_string()))?;
        let routed = self
            .devices
            .action_route(&self.device.principal(), params.action_id)
            .map_err(|error| error.to_protocol_error())?;
        // A receipt lives in the journal of the session the action was performed on, and the
        // route says which. Two routes cannot be answered here, and they are answered differently
        // because they mean different things.
        let session_id = match routed {
            Some(routed) => match routed.session_id {
                Some(session_id) => session_id,
                // The route says this host owns whatever this identifier produced rather than a
                // session: a create, or a repository or workspace mutation. The route is claimed
                // before the action is admitted, so it says where an outcome would live rather
                // than that anything ran. Either way there is no receipt here to read, because
                // what such an action leaves is kept by the service that would have performed it
                // and not in the shape this method answers with. Submitting the action again
                // under the same identifier is what gives the caller its outcome, and the
                // sentence says so rather than leaving a caller to conclude that a recorded
                // action has gone missing.
                None => {
                    let detail = format!(
                        "action {} belongs to this host rather than to a session, and this host \
                         keeps no receipt for one; submit the action again under the same \
                         identifier to be given its outcome",
                        params.action_id
                    );
                    return Err(ProtocolError::new(ErrorCode::InvalidArgument, detail));
                }
            },
            // Nothing recorded it. An action nobody recorded is not an action this device can be
            // told about.
            None => {
                return Err(ProtocolError::new(
                    ErrorCode::InvalidArgument,
                    format!("no receipt for action {}", params.action_id),
                ));
            }
        };
        self.check_grant(Some(session_id), entry, false)?;
        self.proxy_for(session_id)
            .await
            .map_err(|error| error.to_protocol_error())
    }

    /// Writes one batch this connection's subscription carries, and returns whether it went.
    ///
    /// What a subscription carries is a read that goes on after it was answered, and a continued
    /// read still needs valid authority. So each batch is decided through the same intersection a
    /// request is, as a subscription to the session this connection is attached to: its grant,
    /// this host's policy and the configured ceiling as they stand at that moment. The batch is
    /// then written under that decision, which the write boundary holds it to until the last byte
    /// goes. A grant the decision finds expired is latched and written down, as a request's is.
    /// Any other refusal leaves the grant alone, because nothing about the grant has ended: a
    /// lapsed offline bound, for one, holds again once the authority feed synchronises, and the
    /// device is told why by the next request it makes. Either way the batch is not written, and
    /// the relay ends the connection.
    pub async fn relay(&self, frame: &ControlFrame) -> bool {
        let attached = self
            .proxy
            .lock()
            .await
            .as_ref()
            .map(|proxy| proxy.session_id());
        // Only a link relays anything, so a batch with none behind it is not one to write.
        let Some(session_id) = attached else {
            return false;
        };
        let redecide = || self.relay_grant(session_id).is_some();
        // A decision that stopped holding before the first byte went is taken again. A change that
        // lands on every attempt is not one this batch waits out.
        for _ in 0..RELAY_DECISIONS {
            let Some(grant) = self.relay_grant(session_id) else {
                break;
            };
            let relaying = Relaying {
                grant,
                redecide: &redecide,
            };
            match self.output.write(frame, &[], Some(relaying)).await {
                Written::Sent => return true,
                Written::Undecided => {}
                Written::Withdrawn => break,
            }
        }
        // However the batch was refused, a lapse the write boundary found on the way is owed its
        // record, and the boundary could not write it: this is the first step outside the poll
        // that can.
        self.controller.settle_floor();
        false
    }

    /// Decides whether this connection may be written what its subscription carries now, and
    /// returns the decision for the write boundary to hold the batch to.
    fn relay_grant(&self, session_id: SessionId) -> Option<RelayGrant> {
        // Read before the decision, so a change that lands while it is taken is one the write
        // sees. The time bounds are the decision's own: the offline bound as the host anchored it
        // on the continuous clock, which a decision taken again finds unchanged, and the moment in
        // UTC the decision stops holding.
        let epoch = self.controller.authority_epoch();
        let decision = self
            .check_grant(Some(session_id), Method::EventsSubscribe.entry(), false)
            .ok()?;
        Some(RelayGrant {
            epoch,
            until: decision
                .decided
                .permitted
                .offline
                .as_ref()
                .and_then(HeldBound::continuous_deadline),
            lapses_at_ms: decision.decided.lapses_at_ms,
            under: decision.bounds(),
        })
    }
}
