//! Forwarding to the worker that owns a session, the action routes, receipts and relayed batches.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use kr_protocol::authority::MethodEntry;
use kr_protocol::envelope::{
    ControlFrame, MutationRequest, Outcome, ParamsValue, Request, Response,
};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::ids::{AuthorityRevision, SessionId};
use kr_protocol::method::Method;
use kr_protocol::retained::CodecError;
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{CanonicalSet, Nullable};
use kr_transport::window::AcceptedDeadline;

use super::super::arrivals::{Arrival, Arrivals, Carried, request_of};
use super::super::proxy::{Vouched, WorkerProxy};
use crate::error::{ControllerError, Result};
use crate::given::{Recorded, network_door};
use crate::grants::policy::HeldBound;
use crate::service::FeedStanding;

use super::acting::Acting;
use super::decision::{Asked, session_of};
use super::output::{RELAY_DECISIONS, RelayGrant, Relaying, Written};
use super::{RemoteConnection, failure, outcome_not_shown, outcome_unknown};

/// Why a claim on an action's identity did not succeed, or why a repeat of one is not answered.
///
/// The two are answered differently. A conflict is this host's answer about the action: section 9
/// makes a reused identifier carrying a different payload `ID_CONFLICT`, and nothing is dispatched
/// under it. Storage being unavailable says nothing about the action, and section 7 does not let a
/// storage failure stop an authorised stop, so a close goes on without its route while every other
/// mutation is refused. A repeat whose route shows an earlier submission may have carried the action
/// out, and that this host does not answer, is a conflict that says so ([`Self::not_shown`]).
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

    /// The refusal of an action whose route shows it was dispatched before, when this host will
    /// not, or cannot, show what became of it.
    ///
    /// It says nothing of the action, which an earlier submission may have carried out, and is
    /// told as such ([`outcome_not_shown`]); `_refusal` is what stopped the answer.
    fn not_shown(_refusal: ProtocolError) -> Self {
        Self::Conflict(outcome_not_shown())
    }
}

/// Whether the call that serves a mutation made the claim on the route of its action itself.
///
/// A repeat is the device asking again after an answer it did not get, and the action may have been
/// carried out by the copy that went before. A refusal this host makes of a repeat on its own
/// account says nothing of that, so it is not told as a refusal of the action
/// ([`RemoteConnection::told_of_a_repeat`]). The route a call claims for itself does not make it a
/// repeat, so a first request refused after its own claim is refused as ever; this records that the
/// claim was the call's own. A route found otherwise was made by a copy of the request.
///
/// It also holds the call's entry among the calls that have not yet claimed the route of their
/// action ([`Arrivals`]), which it gives up when the route is claimed or found, and when the call
/// ends. A close whose route cannot be recorded goes on without one, and its work outlives the
/// call, so the entry is shared with that work ([`Self::shared_with_the_work`]) and leaves when both
/// are done with it.
pub(super) struct OwnClaim {
    made: AtomicBool,
    arrival: std::sync::Mutex<Option<Arc<Arrival>>>,
}

impl OwnClaim {
    /// A call that has claimed nothing and is not among the calls that have not yet claimed.
    pub(super) const fn none() -> Self {
        Self {
            made: AtomicBool::new(false),
            arrival: std::sync::Mutex::new(None),
        }
    }

    /// A call that has claimed nothing, and is entered among those that have not yet claimed.
    pub(super) fn arrived(arrival: Arrival) -> Self {
        Self {
            made: AtomicBool::new(false),
            arrival: std::sync::Mutex::new(Some(Arc::new(arrival))),
        }
    }

    /// Records that this call wrote the route of its action, and gives up its entry: the route is
    /// what a refusal reads from here on.
    fn made(&self) {
        self.made.store(true, Ordering::Release);
        self.leave();
    }

    fn is_made(&self) -> bool {
        self.made.load(Ordering::Acquire)
    }

    /// Gives up the entry among the calls that have not claimed, when the route has been found
    /// rather than written.
    fn leave(&self) {
        self.arrival
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
    }

    /// The call's entry, for the work that goes on after the call has ended, when the call has not
    /// claimed the route of its action. The entry stays among the calls that have not claimed until
    /// that work ends too, so a copy of the request that arrives while the work runs is a repeat of
    /// an action that is being carried out, and is told so.
    ///
    /// The work holds the same entry, with the same call number, so the call still does not count
    /// itself. [`Self::leave`] gives up the call's handle only: the entry leaves the set when the
    /// work lets go of it as well.
    pub(super) fn shared_with_the_work(&self) -> Option<Arc<Arrival>> {
        self.arrival
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Whether another call that carries `request` has not yet claimed its route.
    fn another_has_not_claimed(&self, arrivals: &Arrivals, request: &Carried) -> bool {
        let own = self
            .arrival
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        arrivals.another_carries(request, own.as_deref())
    }
}

/// What a device is told of a retained answer that does not read in the shape of the level its
/// worker is at.
///
/// What the worker kept is not shown to a device as it came, because the host cannot tell what the
/// worker held it to. The answer says what the host holds and does not do, never that the action
/// did not happen: it did, and the caller may well have caused it. The code is the one for an
/// outcome the host does not report, so a client keeps the action it sent.
fn unreadable_retained_answer() -> ProtocolError {
    ProtocolError::new(
        ErrorCode::OutcomeUnknown,
        "this host holds what this action produced and does not show it to this device, because \
         the session's worker answered in a form this host cannot read",
    )
}

/// The refusal for an `input.write` that cannot be written for the level its session's worker is
/// at.
///
/// A write the current type does not read is the caller's mistake, as it would be at a worker of
/// this level. Key records have no counterpart at a retained level, which is a lack of the
/// worker's and not of the write, so the code is the one that says a capability is missing and
/// nothing reaches the worker.
fn input_write_refusal(error: &CodecError) -> ProtocolError {
    match error {
        CodecError::NotInLevel { .. } => ProtocolError::new(
            ErrorCode::UnsupportedCapability,
            "this session's worker is of an earlier release and takes input as bytes only",
        ),
        _ => ProtocolError::new(
            ErrorCode::InvalidArgument,
            "the parameters of input.write are not the current ones",
        ),
    }
}

impl RemoteConnection {
    /// The entry of `mutation` among the calls that have not claimed the route of their action: the
    /// one the transport's reader made when it read the frame (`hold`), and otherwise a new one,
    /// for a frame that did not come through the reader. The call is entered once, when it was read.
    pub(super) fn arrival_of(
        &self,
        mutation: &MutationRequest,
        hold: Option<kr_transport::listener::FrameHold>,
    ) -> Option<Arrival> {
        let request = request_of(&self.device.principal(), mutation)?;
        let read = hold
            .and_then(|hold| hold.downcast::<Arrival>().ok())
            .map(|arrival| *arrival)
            .filter(|arrival| arrival.carries(&request));
        Some(read.unwrap_or_else(|| self.controller.arrivals().arrive(request)))
    }

    /// The standing work decided under `acting` takes with it: this connection's pairing grant,
    /// `acting`, and the shares it has decided a request under.
    pub(super) fn feed_standing(&self, acting: &kr_protocol::grant::Grant) -> FeedStanding {
        self.controller
            .feed_standing(self.connection_id, &self.device, acting)
    }

    /// Whether this host holds a route for the action a mutation carries, with the same request.
    ///
    /// A route this host cannot read leaves it unable to say whether it has seen the action, and it
    /// answers as it would for a repeat: a refusal then is not a word about an action that may have
    /// been carried out. The route is the device's own, keyed by the verified actor, so what a
    /// refusal that depends on it shows is a fact the device already holds.
    fn holds_a_route_for(&self, mutation: &MutationRequest) -> bool {
        let actor_id = self.device.principal();
        match self.devices.action_route(&actor_id, mutation.action_id) {
            Ok(None) => false,
            Ok(Some(routed)) => kr_protocol::digest::mutation_digest(mutation, &actor_id)
                .is_ok_and(|digest| routed.payload_digest == Some(digest)),
            Err(_) => true,
        }
    }

    /// What a device is told of a refusal this host made on its own account.
    ///
    /// A client takes a definite refusal for the host's word that nothing was done and drops the
    /// action. For a repeat the refusal is the host's own check failing (a window of another
    /// connection, a connection opened for something else, a worker that has ended, a registration
    /// withdrawn), and the host's route shows an earlier copy that may have been carried out, so the
    /// device is told the outcome is unknown. The host cannot show it was not: the route is
    /// claimed before dispatch and holds no record of whether a dispatch followed.
    ///
    /// The route is read now, when the refusal is worded, because a copy of the request can claim it
    /// at any point while this one waits. A route this call made itself does not count, so a first
    /// request refused after its own claim is refused as ever. A route that holds another request
    /// under the identifier does not either: the identifier is spent, this host dispatches nothing
    /// under it for this request, and the refusal keeps its code however many copies of this request
    /// are queued. Two kinds of mutation are the exception
    /// ([`Self::identifier_is_spent_on_another_request`]). A code that is already `OUTCOME_UNKNOWN`
    /// is told as it is.
    pub(super) fn told_of_a_repeat(
        &self,
        own_claim: &OwnClaim,
        mutation: &MutationRequest,
        error: ProtocolError,
    ) -> ProtocolError {
        if error.code == ErrorCode::OutcomeUnknown
            || own_claim.is_made()
            || self.identifier_is_spent_on_another_request(mutation)
            || !(self.another_copy_has_not_claimed(own_claim, mutation)
                || self.holds_a_route_for(mutation))
        {
            error
        } else {
            outcome_not_shown()
        }
    }

    /// Whether the route of the action a mutation carries holds another request, which makes the
    /// identifier a reused one that nothing is carried out under for this request.
    ///
    /// Two kinds of mutation are not always decided so. A close goes on without a route when
    /// storage cannot record one, because a stop is let through, so another request that holds the
    /// route by the time a copy is refused does not say the close was not carried out. A voice
    /// delegation's challenge gives its route back, so the identifier is free again for the request
    /// that is signed; only a route that names no session is given back, so a route that names one
    /// is spent for a voice delegation as for any request. A copy of either is told as a repeat's,
    /// as it is when it meets no conflict.
    fn identifier_is_spent_on_another_request(&self, mutation: &MutationRequest) -> bool {
        let method = mutation.method.method();
        if method == Some(Method::SessionClose) {
            return false;
        }
        let actor_id = self.device.principal();
        match self.devices.action_route(&actor_id, mutation.action_id) {
            Ok(Some(routed)) => {
                if method == Some(Method::VoiceDelegate) && routed.session_id.is_none() {
                    return false;
                }
                kr_protocol::digest::mutation_digest(mutation, &actor_id)
                    .is_ok_and(|digest| routed.payload_digest != Some(digest))
            }
            Ok(None) | Err(_) => false,
        }
    }

    /// Whether a copy of this request is being served that has not yet claimed the route of its
    /// action, and so has left no route to be read.
    ///
    /// Read before the route is: a call writes its route before it leaves the set, so a reader that
    /// finds the set without the copy finds the copy's route. A close whose route could not be
    /// recorded has neither once its work has ended ([`Arrivals`]).
    fn another_copy_has_not_claimed(
        &self,
        own_claim: &OwnClaim,
        mutation: &MutationRequest,
    ) -> bool {
        request_of(&self.device.principal(), mutation).is_some_and(|request| {
            own_claim.another_has_not_claimed(self.controller.arrivals(), &request)
        })
    }

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
                .map_err(|error| match error {
                    // A closed session has no worker to narrow its output to a grant, and this
                    // host serves a device nothing of it.
                    ControllerError::SessionClosed { .. }
                        if entry.method == Method::HistoryPage =>
                    {
                        ProtocolError::new(
                            ErrorCode::SessionClosed,
                            "this host does not serve a closed session's retained output to a \
                             paired device",
                        )
                    }
                    other => other.to_protocol_error(),
                }),
            Err(_) if entry.method == Method::ActionRead => {
                self.receipt_owner(request, entry, &asked.acting).await
            }
            Err(error) => return failure(request.request_id, error),
        };
        let proxy = match proxy {
            Ok(proxy) => proxy,
            Err(error) => return failure(request.request_id, error),
        };
        // A worker of an earlier release has no row for a read that is new in this one, and
        // refuses it as it refuses any method it does not serve, which reads as a missing right.
        // It states what it serves, so the read is not sent to one that does not state it.
        if let Some(capability) = worker_capability(entry.method)
            && !proxy.states(capability)
        {
            return failure(
                request.request_id,
                ProtocolError::new(
                    ErrorCode::UnsupportedCapability,
                    format!(
                        "this session's worker is of an earlier release and does not serve {}",
                        entry.name
                    ),
                ),
            );
        }
        // A write for a worker of a retained level is written in the shape that level reads, or
        // refused here when that level has no counterpart for it. A worker of this level gets the
        // request as it came, unread.
        let rewritten;
        let request = if entry.method == Method::InputWrite && !proxy.level().is_this() {
            match proxy.level().encode_input_write(&request.params) {
                Ok(params) => {
                    rewritten = Request {
                        params,
                        ..request.clone()
                    };
                    &rewritten
                }
                Err(error) => return failure(request.request_id, input_write_refusal(&error)),
            }
        } else {
            request
        };
        let envelope = self.envelope(asked.acting.grant.grant_id, validated);
        let authority = match self.authority_deadline(asked) {
            Ok(authority) => authority,
            Err(error) => return failure(request.request_id, error),
        };
        let standing = self.feed_standing(&asked.acting.grant);
        match proxy
            .forward_read(
                request,
                &envelope,
                authority,
                Some(&asked.acting.grant.history),
                &|| self.controller.refuse_while_the_feed_refuses(&standing),
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
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn proxied_mutation(
        &self,
        mutation: &MutationRequest,
        accepted: AcceptedDeadline,
        validated: AuthorityRevision,
        grant_rights: CanonicalSet<ActionRight>,
        acting: &Acting,
        asked: &mut Option<Asked>,
        own_claim: &OwnClaim,
    ) -> std::result::Result<ControlFrame, ProtocolError> {
        let Some(session_id) = mutation.target.session_id.as_ref().copied() else {
            return Err(ProtocolError::new(
                ErrorCode::InvalidArgument,
                "this mutation names the session it acts on",
            ));
        };
        let proxy = match self.proxy_for(session_id, acting).await {
            Ok(proxy) => proxy,
            Err(error) => return Err(error.to_protocol_error()),
        };
        if let Err(refusal) = self.claim_route(mutation, Some(session_id), own_claim) {
            return Err(refusal.into_error());
        }
        let envelope = self.envelope(acting.grant.grant_id, validated);
        let bound = match self
            .controller
            .forwarded_deadline(session_id, &envelope, accepted)
            .await
        {
            Ok(bound) => bound,
            Err(error) => {
                // The grant may have run out while this waited, and wherever that is observed it
                // is written down. What decides is the grant's own deadline: everything else this
                // failure can mean says nothing about the grant.
                self.expiry_observer().grant_expired();
                return Err(error.to_protocol_error());
            }
        };
        // A prompt that names a draft puts the draft's attachments under the session's retention
        // from here, before it is sent. What a worker answers, and whether anyone is left to hear
        // it, cannot then decide whether a file this host was asked to hand to a session is kept:
        // a connection that ends while the worker answers, a worker that cannot be asked again, and
        // an answer that is not shown to the device all leave the record where it is. A draft is
        // sent to one session, and an attachment belongs to one, so a draft that is for another
        // session, or holds an attachment that belongs to one, is refused here and nothing is sent.
        // A draft written for another application than the prompt's is refused the same way, as a
        // conflict: the person prepared it for a conversation that is not the one named.
        // What the draft gets after this is the session's too, so the session's agent finds
        // nothing in it that is not held, whenever it reads it, and a repeat of the prompt has
        // nothing left to record. A prompt the worker refuses was still sent to that session, and
        // its attachments stay with it. If the record cannot be made the prompt is not sent.
        // The record is made under the admission this prompt arrived under, asked again where the
        // transfer service writes: a deadline that passed or a registration that was withdrawn
        // while the prompt waited for its worker's link records nothing and sends nothing.
        if let Some(prompted) = crate::transfer::prompted_draft(mutation)
            && let Err(error) = self
                .controller
                .transfer
                .record_submission(
                    &self.device.principal(),
                    prompted,
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
            return Err(error);
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
        let controller = Arc::clone(&self.controller);
        // This task outlives the connection, so it takes the standing the feed's refusal is asked
        // of with it, and a connection that ends while the mutation waits for the writer does not
        // lift the refusal.
        let standing = self.feed_standing(&acting.grant);
        let effect = tokio::spawn(async move {
            proxy
                .forward_mutation(
                    &mutation,
                    Vouched {
                        actor: &envelope,
                        grant_rights: &grant_rights,
                        history: Some(&history),
                        screen_basis,
                        lease: bound.lease,
                    },
                    bound.deadline_boot_ms,
                    &|| controller.refuse_while_the_feed_refuses(&standing),
                )
                .await
        });
        match effect.await {
            Ok(Ok(answered)) => {
                #[cfg(feature = "testing")]
                self.controller.after_the_worker_answered.wait().await;
                if answered.retained {
                    // A retained answer is a read of somebody's receipt: the worker gave what
                    // this device's grant reached, and it is written under present view
                    // authority over the session. A device not given it is told neither that the
                    // action was refused nor what it came to: the worker answered from a receipt it
                    // already held.
                    match self.may_read_receipts(Some(session_id), answering, acting) {
                        Ok(read) => *asked = Some(read),
                        Err(_) => return Err(outcome_not_shown()),
                    }
                }
                // What an agent said in refusing what a device put to it is the agent's, not this
                // host's. It is held where the worker's answer arrives, so the daemon's own
                // refusals of the same call are told as they are written.
                let told = super::super::device_errors::upstream_words(
                    answering,
                    ControlFrame::Response(Response {
                        request_id,
                        outcome: answered.response.outcome,
                    }),
                );
                // A worker checks the authority a request stands on before it looks for the
                // receipt of an action it was sent before, and its envelope, limits, window and
                // deadline after a lookup that finds none. A lookup that finds none shows only
                // that the worker holds no receipt now: a dispatch of an earlier copy can still
                // be waiting in its queue. So a refusal it makes that is not read from a receipt
                // says nothing of an earlier copy. It is the host's word to give as
                // such, and a repeat is not told it.
                match told {
                    ControlFrame::Response(Response {
                        outcome: Outcome::Error(error),
                        ..
                    }) if !answered.retained => Err(error),
                    told => Ok(told),
                }
            }
            Ok(Err(error)) => Err(error.to_protocol_error()),
            Err(_) => Ok(failure(request_id, outcome_unknown())),
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
            .answering(answering)
            .kept())
    }

    /// Decides the read a retained answer of this daemon's own is written under, when it has one.
    ///
    /// Section 23 wants present view authority over the subject before either half of a retained
    /// result goes back, and the answer is written under that decision, so a lease that loses the
    /// right while it waits is refused where it is written. The subject is the session the request
    /// names (a rename's, a review's, a visit's) or, for a create, `reserved`, the session of the
    /// reservation the create left, which its answer does not name when the create failed.
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
        reserved: Option<SessionId>,
        acting: &Acting,
    ) -> std::result::Result<Option<Asked>, ProtocolError> {
        if matches!(
            method,
            Method::OwnerConfirmationRequest | Method::OwnerConfirmationComplete
        ) {
            return self
                .ask(None, Method::OwnerConfirmationPending.entry(), false)
                .map(|read| Some(read.answering(method).kept()));
        }
        let subject = mutation.target.session_id.as_ref().copied().or(reserved);
        if subject.is_some() {
            return self.may_read_receipts(subject, method, acting).map(Some);
        }
        Ok(None)
    }

    /// What a device is told of `kept`, the answer an earlier submission of its action left in a
    /// record this host reads: the daemon's own stores, which the door asks before it admits the
    /// action, and the service that performs it, which asks its own once it has. Both are the same
    /// answer to the device, so both pass through here.
    ///
    /// The answer is written under the decision of a read of the receipt it is, and a device that
    /// may not read it, or whose registration was withdrawn or replaced while the record was read,
    /// is told the outcome is unknown, whatever the answer was: that it was a refusal is not for a
    /// device that may not read it. `asked` is left holding the decision the answer is written
    /// under.
    pub(super) async fn kept_answer(
        &self,
        kept: Recorded<ControlFrame>,
        method: Method,
        mutation: &MutationRequest,
        validated: AuthorityRevision,
        decided: &Asked,
        asked: &mut Option<Asked>,
    ) -> std::result::Result<ControlFrame, ProtocolError> {
        // A reused identifier is this host's word about the identifier and names no result, so it
        // is no read of a record and is shown as it is, to whoever is still registered. It is
        // written under the decision of the request, not as an answer kept from an earlier
        // submission: a refusal to write a kept answer is told as an unknown outcome, and nothing
        // was carried out here.
        let reused = kept.names_a_reused_identifier();
        *asked = Some(if reused {
            decided.clone()
        } else {
            decided.clone().kept()
        });
        #[cfg(feature = "testing")]
        self.controller.after_the_retained_lookup.wait().await;
        // What this host holds is the outcome of an action. When it will not show the device
        // that outcome, it does not tell the device the action did not happen, or that it did.
        if self.admitted_to_answer(validated).is_err() {
            return Err(outcome_not_shown());
        }
        if reused {
            return Ok(network_door::kept(
                crate::service::net::AtTheNetworkDoor::here(),
                kept,
            ));
        }
        // The answer is a read of what an earlier submission produced, and is written under the
        // decision that read is ([`Self::read_of_retained`]). A create's answer is a read of the
        // reservation its token holds, whichever way the first attempt ended, and the session that
        // reservation holds is its subject.
        let reserved = if method == Method::SessionCreate {
            match network_door::kept(
                crate::service::net::AtTheNetworkDoor::here(),
                self.reserved_session(mutation).await,
            ) {
                Ok(reserved) => reserved,
                Err(()) => return Err(outcome_not_shown()),
            }
        } else {
            None
        };
        match self.read_of_retained(method, mutation, reserved, &decided.acting) {
            Ok(Some(read)) => *asked = Some(read),
            Ok(None) => {}
            Err(_) => return Err(outcome_not_shown()),
        }
        Ok(network_door::kept(
            crate::service::net::AtTheNetworkDoor::here(),
            kept,
        ))
    }

    /// [`Self::kept_answer`] for a copy a service gave when it performed the action, which it read
    /// from its own record.
    pub(super) async fn kept_copy(
        &self,
        copy: ControlFrame,
        method: Method,
        mutation: &MutationRequest,
        validated: AuthorityRevision,
        decided: &Asked,
        asked: &mut Option<Asked>,
    ) -> std::result::Result<ControlFrame, ProtocolError> {
        self.kept_answer(
            Recorded::read(copy),
            method,
            mutation,
            validated,
            decided,
            asked,
        )
        .await
    }

    /// What a device is told of a copy a service withheld: the service read the record of an
    /// earlier submission and refused to give it back under the authority this request arrived
    /// under.
    ///
    /// The service's own check found a fence this host owed, or a registration withdrawn or
    /// replaced. This door's check, asked next, can pass: the fence is gone by then. The service's
    /// refusal is no answer to the action, which an earlier submission may have carried out, and
    /// told as a kept answer it would say the action did not happen to a device that has authority
    /// now. So the device is told the outcome is not shown, as it is when this door's own check
    /// refuses. `asked` is left holding the decision the answer would have been written under.
    pub(super) fn withheld_answer(
        &self,
        decided: &Asked,
        asked: &mut Option<Asked>,
    ) -> ProtocolError {
        *asked = Some(decided.clone().kept());
        outcome_not_shown()
    }

    /// The session of the reservation under a create's action, when that reservation holds this
    /// request, which is what the create's answer is about when it is read from the reservation.
    ///
    /// `Ok(None)` is a token another request spent: the refusal that says so is this host's word
    /// about the identifier and names no result, so it is told as it is. `Err` is a reservation that
    /// cannot be read, which leaves open what the create came to.
    async fn reserved_session(
        &self,
        mutation: &MutationRequest,
    ) -> Recorded<std::result::Result<Option<SessionId>, ()>> {
        let actor_id = self.device.principal();
        let Ok(digest) = kr_protocol::digest::mutation_digest(mutation, &actor_id) else {
            return Recorded::read(Err(()));
        };
        let registry = self.controller.registry.lock().await;
        Recorded::read(
            match registry.reservation_for_token(&actor_id, mutation.action_id.get()) {
                Ok(Some(reservation)) => {
                    Ok((reservation.payload_digest == digest).then_some(reservation.session_id))
                }
                Ok(None) | Err(_) => Err(()),
            },
        )
    }

    /// Returns this connection's link to one worker, opening it on first use.
    ///
    /// One link per connection, and one worker per link: a device attaches to one session at a
    /// time on one connection, and its attachment, its subscription and its input all have to
    /// belong to the same worker connection for the worker's own ownership rules to hold. The grant
    /// the link is opened under is the grant the connection acts under for that session from then
    /// on ([`Self::fix`]).
    async fn proxy_for(&self, session_id: SessionId, acting: &Acting) -> Result<Arc<WorkerProxy>> {
        // Every route to a worker passes here, and a connection that serves the host alone has
        // none: a link would tie it to a session, and the session's own connection ends with its
        // share while this one must not.
        self.check_worker_route()
            .map_err(|error| ControllerError::InvalidArgument(error.message))?;
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
                self.output.receive(),
            )
            .await
        {
            Ok(proxy) => proxy,
            // A session with no worker is closed where its closure is recorded, and the record is
            // what says so.
            Err(error @ ControllerError::UnknownSession { .. }) => {
                return Err(network_door::kept(
                    crate::service::net::AtTheNetworkDoor::here(),
                    self.controller.closed_or(session_id, error).await,
                ));
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
        own_claim: &OwnClaim,
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
            super::super::devices::ActionRoute::Recorded => {
                own_claim.made();
                Ok(())
            }
            // A copy of this request claimed it first, perhaps while this one was arriving: the
            // route is theirs, and a refusal of this call is worded as that of a repeat.
            super::super::devices::ActionRoute::Existing(existing)
                if existing.payload_digest == Some(digest) && existing.session_id == session_id =>
            {
                own_claim.leave();
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
    /// is the answer. A worker that holds no receipt for it, or that cannot be asked, leaves the
    /// request to the ordinary path, where a refusal of it is told as an unknown outcome
    /// ([`Self::told_of_a_repeat`]) and not as a refusal of the action. A close whose session has
    /// closed is the exception: the closure record answers it ([`Self::closure_answer`]).
    ///
    /// The answer is returned with the decision it is to be written under: a read of the receipt
    /// over the session it belongs to ([`Self::may_read_receipts`]). A worker holds what it keeps to
    /// the history scope of this device's grant, which goes with the read, and its answer is read
    /// in the shape of its level: one that does not read there is not passed on, and the device is
    /// told what became of the action is unknown, after the daemon has used it to settle a close it
    /// kept the answer of.
    ///
    /// A caller that may not read this session's receipts is not told what its action produced,
    /// and not that it was refused: the route shows an earlier submission may have carried it out,
    /// so it is told the outcome is unknown ([`RouteRefusal::not_shown`]). For a close that is all
    /// it is not told: a close it may make is still made, because section 7 lets an authorised stop
    /// go ahead, and the answer a worker gives a retried close is checked again where it comes
    /// back.
    pub(super) async fn retained_remotely(
        &self,
        mutation: &MutationRequest,
        validated: AuthorityRevision,
        asked: &Asked,
    ) -> std::result::Result<Option<(Recorded<ControlFrame>, Asked)>, RouteRefusal> {
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
            Err(error) => return Err(RouteRefusal::not_shown(error)),
        };
        // A connection that serves the host alone has no route to a worker, and says so rather
        // than leaving the request to be refused for another reason further on.
        self.check_worker_route().map_err(RouteRefusal::not_shown)?;
        // A link that cannot be opened is not an answer. The ordinary path decides what this
        // request gets, except for a close whose session has closed, which the closure record
        // answers: a worker that has ended holds nothing more to ask.
        let Ok(proxy) = self.proxy_for(session_id, &asked.acting).await else {
            return Ok(self.closure_answer(mutation, session_id, read).await);
        };
        let request = Request {
            request_id: mutation.request_id,
            method: Method::ActionRead.into(),
            method_version: Method::ActionRead.entry().version,
            // Written as the worker's level reads them: the daemon makes this request itself.
            params: proxy
                .level()
                .encode_params(
                    Method::ActionRead,
                    &kr_protocol::receipt::ActionReadParams {
                        action_id: mutation.action_id,
                        // This request goes to the worker that owns the session, which serves the
                        // receipts of the one session it has. Naming it would say nothing more.
                        session_id: None,
                    },
                )
                .map_err(|error| {
                    RouteRefusal::not_shown(ProtocolError::new(
                        ErrorCode::UnsupportedCapability,
                        error.to_string(),
                    ))
                })?,
        };
        let envelope = self.envelope(asked.acting.grant.grant_id, validated);
        let authority = self
            .authority_deadline(asked)
            .map_err(RouteRefusal::not_shown)?;
        let standing = self.feed_standing(&asked.acting.grant);
        let Ok(response) = proxy
            .forward_read(
                &request,
                &envelope,
                authority,
                Some(&asked.acting.grant.history),
                &|| self.controller.refuse_while_the_feed_refuses(&standing),
            )
            .await
        else {
            // The link failed, not the lookup. The ordinary path decides what happens next.
            return Ok(self.closure_answer(mutation, session_id, read).await);
        };
        let Outcome::Ok(value) = response.outcome else {
            // No receipt for it there, or the worker refused the read. Either way this is not an
            // answer, and the request goes on to be admitted or refused on its own terms.
            return Ok(self.closure_answer(mutation, session_id, read).await);
        };
        // The answer is read in the shape of the worker's level. One that does not read there is
        // never passed on as it came: the worker held it to a scope in a way this host cannot see.
        let Ok(read_back) = proxy
            .level()
            .decode_value::<kr_protocol::receipt::ActionReadResult>(&value)
        else {
            return Err(RouteRefusal::Conflict(unreadable_retained_answer()));
        };
        // A close's result is read in the shape of the worker's level, like the answer around it,
        // and settled as one given now is. What goes on is the result in this release's shape: the
        // daemon keeps the worker's whole description for its own use, and what a device is shown
        // of it is decided where the answer is written. One that does not read is refused.
        let mut read_back = read_back;
        if mutation.method == Method::SessionClose.into()
            && let Some(result) = read_back.result.0.take()
        {
            let Ok(answer) = proxy
                .level()
                .decode_value::<kr_protocol::session::SessionCloseResult>(&result)
            else {
                return Err(RouteRefusal::Conflict(unreadable_retained_answer()));
            };
            let _ = self
                .controller
                .settle_close_answer(session_id, &answer)
                .await;
            let converted = ParamsValue::from_typed(&answer).map_err(|error| {
                RouteRefusal::not_shown(ProtocolError::new(
                    ErrorCode::InvalidArgument,
                    error.to_string(),
                ))
            })?;
            read_back.result = Nullable::some(converted);
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
        Ok(Some((Recorded::read(answered), read)))
    }

    /// Answers a repeated close of a session that has closed from the closure record, when the
    /// worker that owned the session cannot be asked.
    ///
    /// The record says the session is closed and how it ended, whatever closed it, which is what a
    /// close made after the closure is answered with (`Controller::answer_from_the_closure`). It
    /// is read from the registry and not inferred from the link that failed, which fails for other
    /// reasons while the session is open, and a repeat is told no more than the decision `read`
    /// allows. No record leaves the request to the ordinary path.
    async fn closure_answer(
        &self,
        mutation: &MutationRequest,
        session_id: SessionId,
        read: Asked,
    ) -> Option<(Recorded<ControlFrame>, Asked)> {
        if mutation.method != Method::SessionClose.into() {
            return None;
        }
        let closed = self
            .controller
            .answer_from_the_closure(session_id)
            .await
            .answered(mutation.request_id)?;
        Some((closed, read))
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
                         keeps no receipt for one; submit the same request again, exactly as it \
                         was sent, to be given its outcome when this host holds one",
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

/// The capability a worker states when it serves `method`, for a read that a worker of an earlier
/// release does not serve at all.
const fn worker_capability(method: Method) -> Option<&'static str> {
    match method {
        Method::ShellLaunchSurface => Some(kr_protocol::local::SHELL_LAUNCH_SURFACE_READ),
        _ => None,
    }
}
