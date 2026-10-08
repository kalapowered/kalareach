//! The voice coordinator's seams: its start, a session's facts and a voice change performed once.

use std::sync::Arc;

use kr_protocol::envelope::{MutationRequest, ParamsValue};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::ids::{ActorId, AuthorityRevision, SessionId};
use kr_protocol::method::Method;
use kr_protocol::service::GatewayOrigin;
use kr_protocol::session::{SessionReadParams, SessionReadResult};
use kr_protocol::voice::{VoiceDelegateParams, VoiceDelegateResult, VoiceDelegationOutcome};
use kr_voice::broker::ManagedVoiceService;

use crate::error::{ControllerError, Result};

use super::authority_changes::decoded;
use super::{Controller, parse};

impl Controller {
    /// Registers the voice coordinator beside the other services.
    ///
    /// After the daemon exists, because two of the coordinator's seams hold a weak reference back
    /// to it: a service built inside `Arc::new_cyclic` could not read a session or propose an
    /// effect, which is most of what those seams are for.
    ///
    /// The managed broker is attached when the configuration document names its origin, in the
    /// voice section this daemon read when it started. A host without one is a complete host: a
    /// person's own provider credential and the agent already running in the session both still
    /// work, and `voice.start` says so rather than failing obscurely.
    pub(super) fn start_voice(self: &Arc<Self>) {
        let authority = Arc::new(crate::voice::GrantAuthority::new(
            Arc::clone(&self.sharing),
            Arc::clone(&self.devices),
            self.sharing.host_device_id(),
            self.me.clone(),
        ));
        let provider = self.managed_voice_provider();
        let module = crate::voice::VoiceModule::new(
            Arc::new(crate::voice::ControllerFacts::new(self.me.clone())),
            authority,
            Arc::new(crate::voice::ControllerDispatch::new(self.me.clone())),
            provider,
            self.sharing.host_device_id(),
            self.paths.environment_id(),
            self.started
                .voice
                .broker_origin()
                .unwrap_or_default()
                .to_owned(),
        );
        let _ = self.voice.set(Arc::new(module));
    }

    /// The managed broker the configuration document names, reached over a transport of its own
    /// through the proxy that document selects, or none where it names none.
    ///
    /// A host that cannot reach the broker it names still starts: the transport is built on its
    /// first use and says why when it cannot be, and a broker the document names wrongly is a
    /// document the daemon refused before it got here. What is reported here is what leaves a
    /// device with no broker where the document names one.
    fn managed_voice_provider(&self) -> Option<Arc<dyn ManagedVoiceService>> {
        let origin = self.started.voice.broker_origin()?;
        let unavailable = |reason: &dyn std::fmt::Display| {
            eprintln!("kr-controller: managed voice is not attached: {reason}");
        };
        let origin_unusable = |error: &dyn std::fmt::Display| {
            unavailable(&format_args!(
                "voice.broker_origin in this host's configuration document is not usable: {error}"
            ));
        };
        let gateway = GatewayOrigin::new(origin)
            .inspect_err(|error| origin_unusable(error))
            .ok()?;
        // A proxy the document selects and this host cannot read is never gone around; the error
        // names `network.proxy_url` itself.
        let proxy = self
            .started_proxy()
            .inspect_err(|error| unavailable(error))
            .ok()?;
        let transport = Arc::new(crate::managed_transport::ManagedTransport::new(
            gateway,
            proxy,
            crate::managed_transport::VOICE_DEADLINES,
        ));
        crate::voice::VoiceModule::managed_provider(origin, transport, self.account.tokens())
            .inspect_err(|error| origin_unusable(error))
            .ok()
    }

    /// The environment's voice service.
    ///
    /// # Panics
    ///
    /// Panics when the daemon has not finished starting, which no request path can observe: the
    /// endpoint is served after startup returns.
    #[must_use]
    pub fn voice(&self) -> &Arc<crate::voice::VoiceModule> {
        self.voice.get().expect("the voice service is registered")
    }

    /// The device a paired actor acts as, when this host knows one.
    ///
    /// A voice method is reachable from a paired device and nothing else, so the actor has to
    /// resolve to a device record before the coordinator sees it. An actor that resolves to no
    /// live device reaches nothing.
    pub(crate) fn paired_device(&self, actor_id: &ActorId) -> Option<kr_protocol::ids::DeviceId> {
        self.devices
            .devices()
            .ok()?
            .into_iter()
            .find(|record| record.is_paired() && &record.principal() == actor_id)
            .map(|record| record.device_id)
    }

    /// The facts the voice coordinator may read about one session.
    ///
    /// Read through this daemon's ordinary session read, so voice sees what any other reader sees
    /// and nothing more. What this daemon does not hold — the worker's semantic history and its
    /// pending decisions — is reported as unavailable rather than left out silently.
    ///
    /// Every item carries the moment its content was produced, because that moment is what a
    /// grant's history lower bound is checked against. The shell a session runs and the directory
    /// it started in are fixed when the session is created, so the creation time is theirs; a fact
    /// this daemon cannot place in time is withheld rather than stamped with the moment it was
    /// read, which would let a retained summary of a session that closed long ago pass a bound
    /// written after it. What the description host holds of the session is read beside it: the
    /// directory and the program it observed, each with the moment it observed them, and what a
    /// model wrote, placed at the session's start ([`crate::voice::snapshot_with`]).
    ///
    /// # Errors
    ///
    /// Returns the refusal of the session read, and [`ControllerError::RegistryUnavailable`] when
    /// the description store cannot be read.
    pub async fn voice_session_snapshot(
        self: &Arc<Self>,
        session_id: SessionId,
    ) -> Result<crate::voice::SessionSnapshot> {
        let params = ParamsValue::from_typed(&SessionReadParams { session_id })
            .map_err(|error| ControllerError::InvalidArgument(error.to_string()))?;
        let read: SessionReadResult = parse(&self.session_read(&params).await?)?;
        let described = self.voice_description_of(&read.session).await?;
        Ok(crate::voice::snapshot_with(
            &read.session,
            session_id,
            &described,
        ))
    }

    /// What the description host holds of a session: the name a person pinned, what a model wrote
    /// and what the host observed, read under the privacy state as it stands.
    async fn voice_description_of(
        &self,
        session: &kr_protocol::session::SessionSummary,
    ) -> Result<crate::describe::VoiceDescription> {
        let descriptions = Arc::clone(&self.descriptions);
        let privacy = self.privacy.state();
        let facts = crate::describe::facts_of(session);
        let session_id = session.session_id;
        let started_ms = session.created_at_ms.get();
        tokio::task::spawn_blocking(move || {
            descriptions.voice_description(session_id, &facts, started_ms, &privacy)
        })
        .await
        .map_err(|_| ControllerError::RegistryUnavailable {
            detail: "the session's description could not be read".to_owned(),
        })?
    }

    /// Performs one voice proposal under the method the registry lists for its effect.
    ///
    /// The reads this daemon serves are performed here, as the device that asked and under the
    /// authority that admitted the proposal, checked again immediately before the effect and again
    /// before the answer is served. A proposal waits for the coordinator's own checks, for a
    /// confirmation and for this dispatch, and authority withdrawn inside any of those waits has
    /// to stop it: what the contract forbids is *serving* that state, not reading it.
    ///
    /// Everything else belongs to the worker's own dispatch, which this daemon does not forward,
    /// so it is **admitted and not performed**: section 15 ¶10 makes the receipt the authority, and
    /// reporting an effect this daemon did not cause would be the exact mistake that paragraph
    /// forbids.
    pub(crate) async fn voice_perform(
        self: &Arc<Self>,
        method: Method,
        proposal: &kr_voice::Proposal,
    ) -> Result<kr_voice::seams::HostReceipt> {
        let action_id = proposal.action_id;
        if method == Method::SessionRead {
            let session_id = proposal.session_id.ok_or_else(|| {
                ControllerError::InvalidArgument("that action names a session".to_owned())
            })?;
            let _ = self.voice_authority_now(proposal, session_id)?;
            let params = ParamsValue::from_typed(&SessionReadParams { session_id })
                .map_err(|error| ControllerError::InvalidArgument(error.to_string()))?;
            let read: SessionReadResult = parse(&self.session_read(&params).await?)?;
            // The session as the context names it, with the name a person pinned. What a model
            // wrote of it and what the description host observed are left out: a receipt leaves
            // this daemon with nothing that holds that text to the privacy state it was read
            // under, and it would carry it past the removal privacy mode makes.
            let described = self.voice_description_of(&read.session).await?.pin_only();
            let snapshot = crate::voice::snapshot_with(&read.session, session_id, &described);
            let narrowed = self.voice_authority_now(proposal, session_id)?;
            // The same bound the context path applies, and the answer is built from what it
            // admitted and from nothing else. A session's description carries its number and the
            // shell it runs, and both are facts from the moment it was created: naming them after
            // the filter had withheld them would be the way round the bound rather than an answer
            // under it. Whether a session that is still running is running is a fact about now,
            // so it travels with a description the bound admitted.
            let live = read.session.state != kr_protocol::session::SessionState::Closed;
            let state = read.session.state.as_str().to_owned();
            let filtered = crate::voice::filtered(snapshot, &narrowed);
            let summary = match (filtered.session_description, filtered.working_directory) {
                (None, _) => "this grant's history does not reach that session".to_owned(),
                (Some(description), directory) => {
                    let mut summary = description.text;
                    if live {
                        summary.push_str(" is ");
                        summary.push_str(&state);
                    }
                    match directory {
                        Some(directory) => {
                            summary.push_str(" in ");
                            summary.push_str(&directory.text);
                        }
                        None => {
                            summary.push_str("; where it runs is outside what this grant may see");
                        }
                    }
                    summary
                }
            };
            return Ok(kr_voice::seams::HostReceipt {
                action_id,
                performed: true,
                summary,
            });
        }
        Ok(kr_voice::seams::HostReceipt {
            action_id,
            performed: false,
            summary: format!(
                "{} belongs to the session's worker, which this host does not dispatch",
                method.as_str()
            ),
        })
    }

    /// Performs one voice mutation exactly once for its action identifier.
    ///
    /// Section 23 marks the four voice mutations action-deduplicated, and none of them is safe to
    /// repeat: a second `voice.grant` would replace the grant the first one wrote and end the calls
    /// started under it, a second `voice.stop` would find nothing, a second `voice.start` would be
    /// a second metered call, and a second delegation under one identifier would be a second
    /// action. The claim and the retained answer are the same ones this host already keeps for an
    /// authority change, because a voice grant is a grant in that same store.
    ///
    /// A delegation is claimed like the others, with one difference in what it asks of the claim.
    /// The answer to a first submission of an action that needs a confirmation is the challenge the
    /// device signs, and the signed delegation comes back under the same identifier carrying a
    /// different payload. That answer admits nothing, so its claim is given back rather than kept,
    /// and the same delegation then claims the identifier afresh. Every other answer is kept under
    /// the claim, and a repeat is answered from it.
    ///
    /// `carried` is the admission the mutation was accepted under: the connection it arrived on,
    /// the authority revision that connection was admitted at and the deadline this host accepted.
    /// It is asked again through the check every service asks from inside its work, before
    /// anything is claimed and wherever the coordinator and the grant store write.
    ///
    /// # Errors
    ///
    /// Returns the refusal the caller is given.
    pub(crate) async fn voice_mutation(
        self: &Arc<Self>,
        from: VoiceIngress<'_>,
        mutation: &MutationRequest,
        method: Method,
        authority_revision: AuthorityRevision,
        carried: crate::authority::AdmittedMutation,
    ) -> Result<ParamsValue> {
        let VoiceIngress {
            actor_id,
            actor,
            route,
        } = from;
        // The admission this mutation was accepted under, as a question the coordinator can ask
        // rather than a figure it has to convert. Everything after this waits — for the claim, for
        // the coordinator's own lock, for the store, for the broker — and the write at the end of
        // those waits is what has to stand on that admission, not merely the dispatch that began
        // it. The question is the one every service asks from inside its work: whether this host
        // owes a fence it could not raise, whether the connection's registration still stands
        // under the revision the mutation was admitted at, and whether the deadline has passed on
        // this daemon's own continuous clock.
        let admission = VoiceAdmission::new(Arc::clone(self), carried);
        // What this host already holds about this action, if anything. Answered before the claim,
        // so a retry of a completed change is its own result rather than a conflict, and one whose
        // first attempt is running or ended unrecorded is told so rather than performed.
        if let Some(answered) = self.voice_answered(actor_id, mutation).await? {
            return Ok(answered);
        }
        // A first admission is asked before anything is claimed or created. A start asks the
        // broker for a call before it writes the call's grant, and a call created for a start this
        // host then refuses is a metered call nobody can use. A stop is not asked. It takes
        // authority away rather than exercising it: section 15 ends a call's grant the moment the
        // call ends, and a fence this host owes is a reason to withdraw authority, never a reason
        // to keep a call's grant alive.
        if method != Method::VoiceStop {
            admission.check()?;
        }
        let hold = match self.claim_voice_action(actor_id, mutation)? {
            crate::grants::ActionClaim::Claimed { hold } => hold,
            crate::grants::ActionClaim::Recorded(record) => {
                return self.voice_recorded(actor_id, mutation, record).await;
            }
        };
        let outcome = self
            .voice()
            .answer(
                actor,
                mutation,
                method,
                authority_revision,
                self.settled_now_ms(),
                &admission,
            )
            .await;
        // The challenge a device signs admits nothing, so nothing is kept for it: the signed
        // delegation is the same action under the same identifier, and claims it afresh. The route
        // the ingress claimed goes back first, while this attempt still holds its claim: a request
        // under the identifier is refused as running until the claim is given back, so no other
        // attempt can have taken the route in the meantime, and one that comes after takes both
        // afresh. If the claim then cannot be given back, both stay spent.
        if method == Method::VoiceDelegate && is_a_challenge(&outcome) {
            if let Some(route) = route {
                route.give_back()?;
            }
            if let Err(error) = self.sharing.grants().release_claim(hold) {
                if let Some(route) = route {
                    route.take_again();
                }
                return Err(error);
            }
            return outcome;
        }
        // Recorded before the hold goes, so a retry finds the answer rather than a claim with
        // neither an answer nor an attempt behind it.
        self.settle_claim(&hold, &outcome)?;
        drop(hold);
        outcome
    }

    /// The digest one voice action is claimed and answered under.
    ///
    /// The mutation's own digest. A confirmed delegation is the same action as the one that asked
    /// for the confirmation and carries a different payload, which is why the challenge's claim is
    /// given back: a payload digest would otherwise refuse the signed resubmission.
    fn voice_action_digest(
        &self,
        actor_id: &ActorId,
        mutation: &MutationRequest,
    ) -> Result<kr_protocol::scalars::Digest256> {
        kr_protocol::digest::mutation_digest(mutation, actor_id)
            .map_err(|error| ControllerError::InvalidArgument(error.to_string()))
    }

    /// Claims one voice action for this attempt, or reports what an earlier attempt's claim is
    /// owed.
    ///
    /// [`crate::grants::ActionClaim::Claimed`] is this attempt's hold: it wrote the claim and is
    /// the one attempt that may perform the change. [`crate::grants::ActionClaim::Recorded`] is
    /// answered by [`Self::voice_recorded`], and nothing is performed.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::IdConflict`] when the identifier was used with another payload.
    fn claim_voice_action(
        &self,
        actor_id: &ActorId,
        mutation: &MutationRequest,
    ) -> Result<crate::grants::ActionClaim> {
        let digest = self.voice_action_digest(actor_id, mutation)?;
        self.sharing.grants().claim_action(
            actor_id,
            mutation.action_id,
            &digest,
            kr_ipc::now_ms().get(),
        )
    }

    /// What this host holds about one voice action, when an earlier attempt claimed it.
    ///
    /// Read, not claimed, so a retry whose freshness window has gone is still told what happened.
    /// An action identifier reused with another payload is refused here, which is how a second
    /// delegation under the first one's identifier never reaches the coordinator.
    pub(super) async fn voice_answered(
        self: &Arc<Self>,
        actor_id: &ActorId,
        mutation: &MutationRequest,
    ) -> Result<Option<ParamsValue>> {
        let digest = self.voice_action_digest(actor_id, mutation)?;
        match self
            .sharing
            .grants()
            .recorded_action(actor_id, mutation.action_id, &digest)?
        {
            Some(record) => self
                .voice_recorded(actor_id, mutation, record)
                .await
                .map(Some),
            None => Ok(None),
        }
    }

    /// The answer a voice change an earlier attempt claimed is owed.
    ///
    /// A delegation's is given back only under the authority it is owed under now
    /// ([`Self::delegation_again`]). The others name no session and carry no content about one:
    /// what each produced is the grant it wrote, the call it created or the call it ended.
    async fn voice_recorded(
        self: &Arc<Self>,
        actor_id: &ActorId,
        mutation: &MutationRequest,
        record: crate::grants::ActionRecord,
    ) -> Result<ParamsValue> {
        match record {
            crate::grants::ActionRecord::Answered { result }
                if mutation.method.method() == Some(Method::VoiceDelegate) =>
            {
                self.delegation_again(actor_id, mutation, &result).await
            }
            record => Self::recorded_voice_action(record),
        }
    }

    /// The answer a delegation this host already answered is owed when it is submitted again.
    ///
    /// Section 23 returns the retained receipt to a duplicate from a still-authorised actor, and the
    /// host checks current authority before it does, so that a revoked device cannot use an old
    /// action identifier to retrieve what it was told. The actor is a paired device, and it has to
    /// still be one. A receipt that carries nothing about a session goes back as it was kept. One
    /// that carries content read from a session does not go back from what it said then: the read
    /// is made again under every check a first submission passes, against the voice grant and the
    /// device's grant and history bound as they stand now, so a call that has ended, a grant that
    /// has gone or a bound that has narrowed gives the refusal and not the content.
    ///
    /// A receipt for an action that is not a read goes back as it was kept, whatever it says: an
    /// effect is never performed again for a repeat.
    async fn delegation_again(
        self: &Arc<Self>,
        actor_id: &ActorId,
        mutation: &MutationRequest,
        kept: &[u8],
    ) -> Result<ParamsValue> {
        let Some(device_id) = self.paired_device(actor_id) else {
            return Err(ControllerError::PermissionDenied {
                detail: "this device is no longer paired with this host".to_owned(),
            });
        };
        let answered = decoded(kept)?;
        let receipt: VoiceDelegateResult = parse(&answered)?;
        let params: VoiceDelegateParams = parse(&mutation.params)?;
        if !matches!(receipt.outcome, VoiceDelegationOutcome::Performed { .. })
            || crate::voice::method_for(params.action) != Some(Method::SessionRead)
        {
            return Ok(answered);
        }
        self.voice()
            .answer_again(device_id, mutation, self.settled_now_ms())
            .await
    }

    /// The answer a voice change an earlier attempt claimed is owed, as the claim holds it.
    ///
    /// As an authority change's ([`Self::recorded_authority_change`]), with one difference: none of
    /// the four leaves anything in this host's records that names the action. A voice grant takes a
    /// fresh identity, a voice session is held in memory, a started call is the broker's, and a
    /// delegation's effect is the worker's. So a change whose attempt ended without recording what
    /// it did is an outcome this host does not know, and it is never performed again: a second
    /// start would be a second metered call.
    fn recorded_voice_action(record: crate::grants::ActionRecord) -> Result<ParamsValue> {
        match record {
            crate::grants::ActionRecord::Answered { result } => decoded(&result),
            crate::grants::ActionRecord::Refused { code, detail } => {
                Err(ControllerError::Refused { code, detail })
            }
            crate::grants::ActionRecord::InFlight => Err(ControllerError::Refused {
                code: ErrorCode::ResourceUnavailable,
                detail: "that action is already running on this host".to_owned(),
            }),
            crate::grants::ActionRecord::Unfinished => Err(ControllerError::Uncertain {
                detail: "an earlier attempt at this voice change ended without recording what it \
                         did, so what it changed may exist; it is not performed again"
                    .to_owned(),
            }),
        }
    }

    /// Checks that the authority a voice proposal was admitted under still stands, now.
    ///
    /// Three things, on this host's one authority store: the device is still paired, the voice
    /// grant the coordinator admitted it under is still live and still reaches the session, and
    /// the device's own ordinary grant still carries what the action needs. The intersection is
    /// `kr_voice::permits`, which is the same rule the coordinator applied, so this is the same
    /// decision taken again rather than a second rule that could disagree with it.
    pub(super) fn voice_authority_now(
        &self,
        proposal: &kr_voice::Proposal,
        session_id: SessionId,
    ) -> Result<kr_protocol::grant::Grant> {
        use kr_voice::seams::VoiceAuthority as _;

        let denied = |detail: &str| ControllerError::PermissionDenied {
            detail: detail.to_owned(),
        };
        let paired = self
            .devices
            .record_for_device(proposal.device_id)?
            .is_some_and(|record| record.is_paired());
        if !paired {
            return Err(denied("this device is no longer paired with this host"));
        }
        let authority = crate::voice::GrantAuthority::new(
            Arc::clone(&self.sharing),
            Arc::clone(&self.devices),
            self.sharing.host_device_id(),
            self.me.clone(),
        );
        let store = |error: kr_voice::VoiceError| ControllerError::Refused {
            code: error.code(),
            detail: error.to_string(),
        };
        // Standing is the host's to decide, on its own clocks and its recorded floor: a grant
        // that has run out, or whose end is not on record yet, is not given back.
        let voice_grant = authority
            .grant(proposal.voice_grant_id)
            .map_err(store)?
            .ok_or_else(|| denied("the voice grant this action was admitted under has ended"))?;
        if !voice_grant.session_selector.admits(session_id) {
            return Err(denied(
                "the voice grant this action was admitted under no longer reaches that session",
            ));
        }
        let device_grant = authority
            .device_grant(proposal.device_id, Some(session_id))
            .map_err(store)?
            .ok_or_else(|| denied("this device's grant no longer covers that session"))?;
        if !kr_voice::permits(&voice_grant, &device_grant, proposal.action) {
            return Err(denied(
                "the authority this action was admitted under no longer carries it",
            ));
        }
        // The narrower of the two history scopes, which is what any content this effect answers
        // with is filtered under.
        Ok(kr_voice::narrower_history(&device_grant, &voice_grant))
    }
}

/// Who a voice mutation comes from, and what the ingress it came by holds for it.
pub(crate) struct VoiceIngress<'a> {
    /// The verified actor the action is de-duplicated under.
    pub(crate) actor_id: &'a ActorId,
    /// The device, or the owner at this machine, it acts as.
    pub(crate) actor: crate::voice::VoiceActor,
    /// The route a network ingress claimed for the action, which a challenge gives back. None for
    /// the local door, which claims none.
    pub(crate) route: Option<&'a dyn ClaimedRoute>,
}

/// The route a network ingress claimed for an action before it reached the voice service.
///
/// A route is the host's record that an identifier is one action whichever route it came by. The
/// voice service gives it back only for an answer that admitted nothing, and only while it still
/// holds the claim it took for the same action.
pub(crate) trait ClaimedRoute: Send + Sync {
    /// Gives the route back.
    ///
    /// # Errors
    ///
    /// Returns an error when the route cannot be given back, and it stays claimed.
    fn give_back(&self) -> Result<()>;

    /// Claims the route again after a give-back whose claim could not be returned, so that the
    /// identifier stays spent on every route.
    fn take_again(&self);
}

/// The route one action claimed in this host's device directory, which is what a network ingress
/// holds for a voice mutation.
pub(crate) struct DeviceRoute<'a> {
    /// The directory the route is recorded in.
    pub(crate) devices: &'a crate::service::net::devices::DeviceDirectory,
    /// The verified actor the action is claimed under.
    pub(crate) actor_id: &'a ActorId,
    /// The mutation the route was claimed for.
    pub(crate) mutation: &'a MutationRequest,
}

impl DeviceRoute<'_> {
    fn digest(&self) -> Result<kr_protocol::scalars::Digest256> {
        kr_protocol::digest::mutation_digest(self.mutation, self.actor_id)
            .map_err(|error| ControllerError::InvalidArgument(error.to_string()))
    }
}

impl ClaimedRoute for DeviceRoute<'_> {
    fn give_back(&self) -> Result<()> {
        self.devices
            .release_action_route(self.actor_id, self.mutation.action_id, self.digest()?)
    }

    fn take_again(&self) {
        // Nothing more to do if it cannot be taken: the claim that could not be given back is what
        // keeps the identifier spent for voice, and this is the same fault again.
        if let Ok(digest) = self.digest() {
            let _ = self.devices.claim_action_route(
                self.actor_id,
                self.mutation.action_id,
                None,
                digest,
                kr_ipc::now_ms(),
            );
        }
    }
}

/// The admission one voice mutation arrived under, as the coordinator and the grant store ask
/// about it.
///
/// Every answer is the check each service asks from inside the work a mutation has begun,
/// [`Controller::check_registration`]: a fence this host owes and could not raise, then the
/// connection's registration under the revision the mutation was admitted at, then the accepted
/// deadline on this daemon's own continuous clock. A voice change waits for the coordinator's
/// lock, for the store and for the broker; the coordinator asks once its lock and the broker have
/// answered, and the grant store's seam asks again immediately before it writes. A deadline alone
/// would let a change that waited write while a fence is owed, or after the authority it was
/// admitted under was replaced.
///
/// The refusal the check gave is what the seam answers with, so it is what the coordinator and the
/// store carry back to the caller, the same one the project service and the workflow journal give.
pub(super) struct VoiceAdmission {
    controller: Arc<Controller>,
    carried: crate::authority::AdmittedMutation,
}

impl VoiceAdmission {
    pub(super) fn new(
        controller: Arc<Controller>,
        carried: crate::authority::AdmittedMutation,
    ) -> Self {
        Self {
            controller,
            carried,
        }
    }

    /// Asks the check, and answers with its own refusal.
    fn check(&self) -> Result<()> {
        self.controller.check_registration(&self.carried)
    }
}

impl std::fmt::Debug for VoiceAdmission {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VoiceAdmission")
            .field("carried", &self.carried)
            .finish_non_exhaustive()
    }
}

impl kr_voice::Admission for VoiceAdmission {
    fn still_admitted(&self) -> std::result::Result<(), ProtocolError> {
        self.check().map_err(|refusal| refusal.to_protocol_error())
    }
}

/// Whether a delegation's answer is the challenge a device signs, which admits nothing.
fn is_a_challenge(outcome: &Result<ParamsValue>) -> bool {
    outcome
        .as_ref()
        .ok()
        .and_then(|answer| answer.to_typed::<VoiceDelegateResult>().ok())
        .is_some_and(|result| {
            matches!(
                result.outcome,
                VoiceDelegationOutcome::ConfirmationRequired { .. }
            )
        })
}
