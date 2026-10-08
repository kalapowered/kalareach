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

use super::acting::Acting;
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

/// The refusal for a retained answer a worker of an earlier build gave whole.
///
/// Such a worker keeps an answer as it was produced and does not hold it to the grant a caller acts
/// under, so a device is not shown it. The refusal says what the host holds and does not do, never
/// that the action did not happen: it did, and the caller may well have caused it. For a close it
/// says how to stop the session, because the answer that would have told the caller whether it was
/// stopped is the one that is not shown.
pub(super) fn held_by_an_earlier_worker(method: Method) -> ProtocolError {
    let detail = if method == Method::SessionClose {
        "this host holds what this action produced and does not show it to this device, because \
         the session's worker is of an earlier build that cannot hold it to this device's grant; \
         a close under a new action identifier stops the session while this host still holds it"
    } else {
        "this host holds what this action produced and does not show it to this device, because \
         the session's worker is of an earlier build that cannot hold it to this device's grant"
    };
    ProtocolError::new(ErrorCode::UnsupportedCapability, detail)
}

impl RemoteConnection {
    /// Answers `action.read` for a catalogue action this device performed, where there is one.
    ///
    /// A catalogue action names no session: its receipt is kept by the catalogue, beside the
    /// state the action changed, under the actor that submitted it. It is read as this device, and
    /// it is shown only while the device is decided again under the right the action required:
    /// the entry of the method the receipt names, which for every catalogue action is
    /// `host.manage`, through the same intersection a request is, so a replacement lease or a
    /// rights ceiling that removes the right stops the answer where it is written. Owning an action
    /// identifier is not authority, and a device whose authority over the catalogue was withdrawn
    /// is not told what it did there.
    ///
    /// `None` is a request this does not answer: one that names a session, or an action the
    /// catalogue holds no receipt for, which the session route then answers.
    pub(super) async fn host_receipt(
        &self,
        request: &Request,
        asked: &mut Option<Asked>,
    ) -> Option<ControlFrame> {
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
        // The right the receipt's own method required, decided now. A method this build does not
        // name is not one it can say a device may read the receipt of.
        let Some(method) = read.receipt.method.method() else {
            return Some(failure(
                request.request_id,
                ProtocolError::new(
                    ErrorCode::PermissionDenied,
                    "the catalogue action this receipt belongs to is not one this host can say \
                     this device may read",
                ),
            ));
        };
        match self.ask(None, method.entry(), false) {
            Ok(decided) => {
                *asked = Some(decided.answering(Method::ActionRead));
            }
            Err(error) => {
                return Some(failure(
                    request.request_id,
                    ProtocolError::new(
                        ErrorCode::PermissionDenied,
                        format!(
                            "this device's grant no longer carries what the catalogue action it \
                             names required: {}",
                            error.message
                        ),
                    ),
                ));
            }
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

    /// Returns the session an `action.read` is about: the one it names, or the one this host
    /// recorded the action's route to.
    ///
    /// It is the subject the read is decided over. A read that names only an action is decided
    /// over the session the action was performed on, because present view authority over that
    /// session is what decides whether the receipt is shown, and a decision taken with no session
    /// would have none to check. `None` is an action this host keeps the receipt of itself, which
    /// the catalogue's route answers, or one it holds no route for, which is refused where the
    /// receipt is looked for.
    pub(super) fn receipt_session(&self, request: &Request) -> Option<SessionId> {
        let params: kr_protocol::receipt::ActionReadParams = request.params.to_typed().ok()?;
        if let Some(named) = params.session_id {
            return Some(named);
        }
        self.devices
            .action_route(&self.device.principal(), params.action_id)
            .ok()
            .flatten()?
            .session_id
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
                .proxy_for(session_id, &asked.acting)
                .await
                .map_err(|error| error.to_protocol_error()),
            Err(_) if entry.method == Method::ActionRead => {
                self.receipt_owner(request, entry, &asked.acting).await
            }
            Err(error) => return failure(request.request_id, error),
        };
        let proxy = match proxy {
            Ok(proxy) => proxy,
            Err(error) => return failure(request.request_id, error),
        };
        let envelope = self.envelope(asked.acting.grant.grant_id, validated);
        let authority = match self.authority_deadline(asked) {
            Ok(authority) => authority,
            Err(error) => return failure(request.request_id, error),
        };
        match proxy
            .forward_read(
                request,
                &envelope,
                authority,
                Some(&asked.acting.grant.history),
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
        acting: &Acting,
        asked: &mut Option<Asked>,
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
        let proxy = match self.proxy_for(session_id, acting).await {
            Ok(proxy) => proxy,
            Err(error) => return failure(mutation.request_id, error.to_protocol_error()),
        };
        if let Err(refusal) = self.claim_route(mutation, Some(session_id)) {
            return failure(mutation.request_id, refusal.into_error());
        }
        let envelope = self.envelope(acting.grant.grant_id, validated);
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
        // A prompt that names a draft puts the draft's attachments under the session's retention
        // from here, before it is sent. What a worker answers, and whether anyone is left to hear
        // it, cannot then decide whether a file this host was asked to hand to a session is kept:
        // a connection that ends while the worker answers, a worker that cannot be asked again, and
        // an answer that is not shown to the device all leave the record where it is. A draft is
        // sent to one session, and an attachment belongs to one, so a draft that is for another
        // session, or holds an attachment that belongs to one, is refused here and nothing is sent.
        // What the draft gets after this is the session's too, so the session's agent finds
        // nothing in it that is not held, whenever it reads it, and a repeat of the prompt has
        // nothing left to record. A prompt the worker refuses was still sent to that session, and
        // its attachments stay with it. If the record cannot be made the prompt is not sent.
        // The record is made under the admission this prompt arrived under, asked again where the
        // transfer service writes: a deadline that passed or a registration that was withdrawn
        // while the prompt waited for its worker's link records nothing and sends nothing.
        if let Some(draft_id) = crate::transfer::prompted_draft(mutation)
            && let Err(error) = self
                .controller
                .transfer
                .record_submission(
                    &self.device.principal(),
                    draft_id,
                    session_id,
                    crate::transfer::TransferAdmission::new(
                        Arc::clone(&self.controller),
                        crate::authority::AdmittedMutation {
                            connection_id: self.connection_id(),
                            admitted_revision: validated,
                            deadline: Some(accepted.deadline),
                        },
                    ),
                )
                .await
        {
            return failure(mutation.request_id, error);
        }
        // The effect runs on a task that outlives this connection, for the same reason the
        // daemon's own effects do: the worker commits the intent before it answers, and a
        // cancellation here must not be what decides whether the outcome is recorded.
        let answering = mutation.method.method().unwrap_or(Method::ActionRead);
        let mutation = mutation.clone();
        let request_id = mutation.request_id;
        // The grant's history scope travels with it too, so what the worker shows of its answer,
        // now and when the action is read again, is held to what this device's grant reaches.
        let history = acting.grant.history.clone();
        // A share's issuer was shown the screen as text, so an attach decided under one is drawn
        // that screen and no more. A pairing grant has no preview, and its attach is drawn the
        // live screen.
        let screen_basis = Some(match acting.held {
            super::acting::Held::Share => kr_protocol::local::ScreenBasis::Share,
            super::acting::Held::Pairing => kr_protocol::local::ScreenBasis::Pairing,
        });
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
                        screen_basis,
                    },
                    deadline,
                )
                .await
        });
        match effect.await {
            Ok(Ok(answered)) => {
                if answered.retained {
                    // A retained answer is a read of somebody's receipt. A worker that holds
                    // nothing to a scope gave it whole, so it is not shown; one that does gave
                    // what this device's grant reached, and it is written under present view
                    // authority over the session.
                    if !answered.holds_results_to_scopes {
                        return failure(request_id, held_by_an_earlier_worker(answering));
                    }
                    match self.may_read_receipts(Some(session_id), answering, acting) {
                        Ok(read) => *asked = Some(read),
                        Err(error) => return failure(request_id, error),
                    }
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

    /// Decides whether this device may be told what one of its own actions produced, and returns
    /// the decision the answer is to be written under.
    ///
    /// The read is made under the grant the action was decided under (`acting`): selecting one again
    /// could pick another grant than the one the action was performed under, and the answer would
    /// then be shown under authority the action never had.
    ///
    /// A retained answer is a read of a receipt, and section 23 has present view authority over the
    /// subject decide whether either half of a retained result is returned. The rights that
    /// decide it are `action.read`'s over the session the receipt belongs to, not the ones the
    /// mutation needed: a device that may act on a session it cannot observe does not learn what
    /// its action produced by submitting it twice. The decision is returned so the answer is
    /// written under it: a lease that drops `session.view` while the answer waits is refused at
    /// the write boundary, where it is decided again, and `answering` is the method the answer was
    /// kept for, which says how it is shown.
    pub(super) fn may_read_receipts(
        &self,
        session_id: Option<SessionId>,
        answering: Method,
        acting: &Acting,
    ) -> std::result::Result<Asked, ProtocolError> {
        let entry = self.admit(
            Method::ActionRead.as_str(),
            Method::ActionRead.entry().version,
        )?;
        Ok(self
            .ask_under(acting.clone(), session_id, entry, false)?
            .answering(answering))
    }

    /// Decides the read a retained answer of this daemon's own is written under, when it has one.
    ///
    /// Section 23 wants present view authority over the subject before either half of a retained
    /// result goes back, and the answer is written under that decision, so a lease that loses the
    /// right while it waits is refused where it is written. The subject is the session the request
    /// names (a rename's, a review's, a visit's) or, for a create, the session its answer names,
    /// which is in the answer rather than in the request.
    ///
    /// An owner confirmation's answer is a challenge. Its entry names only the owner's ceremony,
    /// which the confirmation service checks on a first request and cannot be asked again here, so
    /// it is decided under the right to read the challenges an owner can still answer, which is what
    /// `owner.confirmation.pending` requires. It acts on this host and names no session, and is
    /// decided so whatever its record's target says.
    ///
    /// Every other answer is about the environment, and what decides it is the right the mutation
    /// itself required, which the decision it was admitted under goes on checking where the answer
    /// is written: `None` leaves it there.
    ///
    /// # Errors
    ///
    /// Returns the refusal when this device's grant no longer admits the read.
    pub(super) fn read_of_retained(
        &self,
        method: Method,
        mutation: &MutationRequest,
        retained: &ControlFrame,
        acting: &Acting,
    ) -> std::result::Result<Option<Asked>, ProtocolError> {
        if matches!(
            method,
            Method::OwnerConfirmationRequest | Method::OwnerConfirmationComplete
        ) {
            return self
                .ask(None, Method::OwnerConfirmationPending.entry(), false)
                .map(|read| Some(read.answering(method)));
        }
        let subject = mutation
            .target
            .session_id
            .as_ref()
            .copied()
            .or_else(|| super::routes::answered_session(retained));
        if subject.is_some() {
            return self.may_read_receipts(subject, method, acting).map(Some);
        }
        Ok(None)
    }

    /// Returns this connection's link to one worker, opening it on first use.
    ///
    /// One link per connection, and one worker per link: a device attaches to one session at a
    /// time on one connection, and its attachment, its subscription and its input all have to
    /// belong to the same worker connection for the worker's own ownership rules to hold. The grant
    /// the link is opened under is the grant the connection acts under for that session from then
    /// on ([`Self::fix`]).
    async fn proxy_for(&self, session_id: SessionId, acting: &Acting) -> Result<Arc<WorkerProxy>> {
        let mut held = self.proxy.lock().await;
        // The grant this connection acts under for the session is the one its link was opened
        // under, and a request decided under another is refused here, where the link is.
        let fixed = |error: ProtocolError| ControllerError::PermissionDenied {
            detail: error.message,
        };
        if let Some(proxy) = held.as_ref() {
            if proxy.session_id() == session_id && proxy.is_open() {
                self.fix(session_id, acting).map_err(fixed)?;
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
        let proxy = match self
            .controller
            .open_proxy(
                session_id,
                self.notifications.clone(),
                Arc::clone(&self.budget),
                Arc::clone(&self.lost),
                super::super::proxy::Purpose::Attachment,
            )
            .await
        {
            Ok(proxy) => proxy,
            // A session with no worker is closed where its closure is recorded, and the record is
            // what says so.
            Err(error @ ControllerError::UnknownSession { .. }) => {
                return Err(self.controller.closed_or(session_id, error).await);
            }
            Err(error) => return Err(error),
        };
        self.fix(session_id, acting).map_err(fixed)?;
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
    ///
    /// The answer is returned with the decision it is to be written under: a read of the receipt
    /// over the session it belongs to ([`Self::may_read_receipts`]). A worker holds what it keeps to
    /// the history scope of this device's grant, which goes with the read. A worker of an earlier
    /// build holds nothing to a scope, so it is asked for the daemon's own use, which is to settle
    /// a close it kept the answer of, and the device is then refused by name rather than shown what
    /// was kept: the host holds it and does not show it.
    ///
    /// A caller that may not read this session's receipts is not told what its action produced,
    /// and for a close that is all it is not told: a close it may make is still made, because
    /// section 7 lets an authorised stop go ahead, and the answer a worker gives a retried close is
    /// checked again where it comes back.
    pub(super) async fn retained_remotely(
        &self,
        mutation: &MutationRequest,
        validated: AuthorityRevision,
        asked: &Asked,
    ) -> std::result::Result<Option<(ControlFrame, Asked)>, RouteRefusal> {
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
        let answering = mutation.method.method().unwrap_or(Method::ActionRead);
        // A refusal here is the answer, not a reason to go on. This action has already been
        // dispatched, and forwarding it again would have the worker answer from the receipt this
        // device may not read. A close is the one exception: it is made whether or not its
        // receipt may be read, and what a worker answers a retried one with is checked on its way
        // back.
        let read = match self.may_read_receipts(Some(session_id), answering, &asked.acting) {
            Ok(read) => read,
            Err(_) if answering == Method::SessionClose => return Ok(None),
            Err(error) => return Err(RouteRefusal::Conflict(error)),
        };
        // A link that cannot be opened is not an answer. The ordinary path decides what this
        // request gets, which for a session whose worker has gone is that session's own refusal
        // rather than a second dispatch.
        let Ok(proxy) = self.proxy_for(session_id, &asked.acting).await else {
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
        let envelope = self.envelope(asked.acting.grant.grant_id, validated);
        let authority = self
            .authority_deadline(asked)
            .map_err(RouteRefusal::Conflict)?;
        let holds = proxy.holds_results_to_scopes();
        let scope = holds.then_some(&asked.acting.grant.history);
        let Ok(response) = proxy
            .forward_read(&request, &envelope, authority, scope)
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
        let Ok(read_back) = value.to_typed::<kr_protocol::receipt::ActionReadResult>() else {
            return Ok(None);
        };
        // A close's result is settled as one given now is, and goes as it came: the daemon keeps
        // the worker's whole description for its own use, and what a device is shown of it is
        // decided where the answer is written.
        if mutation.method == Method::SessionClose.into()
            && let Some(result) = read_back.result.as_ref()
            && let Ok(answer) = result.to_typed::<kr_protocol::session::SessionCloseResult>()
        {
            let _ = self
                .controller
                .settle_close_answer(session_id, &answer)
                .await;
        }
        if !holds {
            return Err(RouteRefusal::Conflict(held_by_an_earlier_worker(answering)));
        }
        // The result when the action produced one, and the receipt when it has not: a caller that
        // resubmitted is told what became of its action, and nothing is dispatched again.
        let answered = match read_back.result.0 {
            Some(result) => ControlFrame::Response(Response {
                request_id: mutation.request_id,
                outcome: Outcome::Ok(result),
            }),
            None => ControlFrame::Receipt(Box::new(kr_protocol::receipt::ReceiptResponse {
                request_id: mutation.request_id,
                receipt: read_back.receipt,
            })),
        };
        Ok(Some((answered, read)))
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
        acting: &Acting,
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
        self.ask_under(acting.clone(), Some(session_id), entry, false)?;
        self.proxy_for(session_id, acting)
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
    /// goes. A pairing grant the decision finds expired is latched and written down, as a request's
    /// is; a share it finds expired ends the batch and the connection and writes nothing on the
    /// device's record. Any other refusal leaves the grant alone, because nothing about the grant
    /// has ended: a lapsed offline bound, for one, holds again once the authority feed
    /// synchronises, and the device is told why by the next request it makes. Either way the batch
    /// is not written, and the relay ends the connection.
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
        // A batch is relayed only on a link, and the link's grant is the one this connection
        // acts under for the session: no other is ever chosen for it.
        let acting = self.acting_for(Some(session_id), None).ok()?;
        let decision = self
            .check_grant(
                Some(session_id),
                Method::EventsSubscribe.entry(),
                false,
                &acting,
            )
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
