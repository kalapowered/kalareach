//! The voice coordinator's seams: its start, a session's facts and a voice change performed once.

use std::sync::Arc;

use kr_protocol::envelope::{MutationRequest, ParamsValue};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::ids::{ActorId, AuthorityRevision, SessionId};
use kr_protocol::method::Method;
use kr_protocol::session::{SessionReadParams, SessionReadResult};

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
    /// The managed broker is configured only when the configuration document names its origin,
    /// in the voice section this daemon read when it started. A host without one is a complete
    /// host: a person's own provider credential and the agent already running in the session both
    /// still work, and `voice.start` says so rather than failing obscurely.
    pub(super) fn start_voice(self: &Arc<Self>) {
        let authority = Arc::new(crate::voice::GrantAuthority::new(
            Arc::clone(&self.sharing),
            Arc::clone(&self.devices),
            self.sharing.host_device_id(),
            self.me.clone(),
        ));
        // Reaching a managed service needs an HTTP exchange, which the client library leaves to
        // the embedder: a desktop build, a mobile build and a test each reach the network
        // differently. An embedder attaches its own with `VoiceModule::with_provider`, and a host
        // with none brokers no managed call.
        let provider = None;
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
        self.voice_snapshot_of(&read.session).await
    }

    /// What this host can say about a session it has already read, with what the description host
    /// holds of it: the second half of [`Self::voice_session_snapshot`], for a path that reads the
    /// session itself and says no more of it than the context does.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the description store cannot be read.
    async fn voice_snapshot_of(
        &self,
        session: &kr_protocol::session::SessionSummary,
    ) -> Result<crate::voice::SessionSnapshot> {
        let descriptions = Arc::clone(&self.descriptions);
        let privacy = self.privacy.state();
        let facts = crate::describe::facts_of(session);
        let session_id = session.session_id;
        let started_ms = session.created_at_ms.get();
        let described = tokio::task::spawn_blocking(move || {
            descriptions.voice_description(session_id, &facts, started_ms, &privacy)
        })
        .await
        .map_err(|_| ControllerError::RegistryUnavailable {
            detail: "the session's description could not be read".to_owned(),
        })??;
        Ok(crate::voice::snapshot_with(session, session_id, &described))
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
            // What the context says of the session, with the name a person pinned and where the
            // description host saw it run, so a receipt names the session as the context does. A
            // receipt says what was done and what the host observed, so what a model wrote of the
            // session is left out of it: nothing here holds that text to the privacy state it was
            // read under, and a receipt carries it past the removal privacy mode makes.
            let mut snapshot = self.voice_snapshot_of(&read.session).await?;
            snapshot.generated = None;
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
    /// Section 23 marks the four voice mutations action-deduplicated, and three of them are not
    /// safe to repeat: a second `voice.grant` would replace the grant the first one wrote and end
    /// the calls started under it, and a second `voice.stop` would find nothing. The claim and the
    /// retained answer are the same ones this host already keeps for an authority change, because
    /// a voice grant is a grant in that same store.
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
        actor_id: &ActorId,
        actor: crate::voice::VoiceActor,
        mutation: &MutationRequest,
        method: Method,
        authority_revision: AuthorityRevision,
        carried: crate::authority::AdmittedMutation,
    ) -> Result<ParamsValue> {
        // The admission this mutation was accepted under, as a question the coordinator can ask
        // rather than a figure it has to convert. Everything after this waits — for the claim, for
        // the coordinator's own lock, for the store, for the broker — and the write at the end of
        // those waits is what has to stand on that admission, not merely the dispatch that began
        // it. The question is the one every service asks from inside its work: whether this host
        // owes a fence it could not raise, whether the connection's registration still stands
        // under the revision the mutation was admitted at, and whether the deadline has passed on
        // this daemon's own continuous clock.
        let admission = VoiceAdmission::new(Arc::clone(self), carried);
        // A delegation does not go through this host's action store at all, and cannot yet: the
        // answer to a first submission of an action that needs a confirmation is the challenge, a
        // claim taken before that answer is held for longer than the confirmation itself lives,
        // and the store has no way to give a claim back. It is not read here either, because an
        // answer that store holds for a delegation is one an earlier build wrote and is content
        // whose authority nothing on this path re-checks. What makes one delegation one action is
        // the coordinator's own rule, taken under its lock before it waits for anything: a
        // delegation already submitted through any live call of that device is refused. Three
        // things that rule does not give. The `(actor, action)` key section 9 names is absent, so
        // two different delegations under one action identifier both reach the host; each is
        // separately authorised and each spends its own delegation, so within one live call
        // nothing happens twice. An exact resubmission whose reply was lost is told the delegation
        // has already been submitted rather than answered with the retained receipt section 23
        // wants. And stopping a call forgets its spent identifiers, so the same one submitted
        // through a later call is a new action decided on its own merits. Closing the first needs
        // a release call on the grant store's claim, so a challenge does not hold one, and then a
        // claim taken before dispatch like every other mutation's; the second needs that store
        // work and, before any of the answer's content goes back, present view authority and the
        // current history bound over the session it is about; the third needs spent identifiers
        // kept for the provider profile's replay window, across a call ending and across a host
        // restart.
        if method == Method::VoiceDelegate {
            // Nothing retains a delegation, so every one is a first admission, and it is asked
            // before the coordinator decides anything.
            admission.check()?;
            return self
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
        }
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
        let hold = match self.claim_voice_action(actor_id, mutation) {
            Ok(hold) => hold,
            Err(answer) => return answer,
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
        // Recorded before the hold goes, so a retry finds the answer rather than a claim with
        // neither an answer nor an attempt behind it.
        self.settle_claim(&hold, &outcome)?;
        drop(hold);
        outcome
    }

    /// The digest one voice action is claimed and answered under.
    ///
    /// The mutation's own digest. A delegation does not reach this: a confirmation is bound to the
    /// request that asked for it, so its signed resubmission is the same action carrying a
    /// different payload, which is what a payload digest refuses.
    fn voice_action_digest(
        &self,
        actor_id: &ActorId,
        mutation: &MutationRequest,
    ) -> Result<kr_protocol::scalars::Digest256> {
        kr_protocol::digest::mutation_digest(mutation, actor_id)
            .map_err(|error| ControllerError::InvalidArgument(error.to_string()))
    }

    /// Claims one voice action for this attempt, or gives the answer an earlier attempt's claim is
    /// owed.
    ///
    /// `Ok` is this attempt's hold: it wrote the claim and is the one attempt that may perform the
    /// change. `Err` is the answer to give instead ([`Self::recorded_voice_action`]), and nothing is
    /// performed.
    fn claim_voice_action(
        &self,
        actor_id: &ActorId,
        mutation: &MutationRequest,
    ) -> std::result::Result<crate::grants::ClaimHold, Result<ParamsValue>> {
        let digest = self.voice_action_digest(actor_id, mutation).map_err(Err)?;
        match self
            .sharing
            .grants()
            .claim_action(
                actor_id,
                mutation.action_id,
                &digest,
                kr_ipc::now_ms().get(),
            )
            .map_err(Err)?
        {
            crate::grants::ActionClaim::Claimed { hold } => Ok(hold),
            crate::grants::ActionClaim::Recorded(record) => {
                Err(Self::recorded_voice_action(record))
            }
        }
    }

    /// What one voice action already came to, when this host holds a claim on it.
    ///
    /// The three voice changes this answers for name no session and carry no content about one:
    /// what each produced is the grant it wrote, the call it created or the call it ended. A
    /// delegation does not reach this, because its answer can carry content about a session and
    /// nothing on this path re-checks the authority that content was found under.
    pub(super) async fn voice_answered(
        self: &Arc<Self>,
        actor_id: &ActorId,
        mutation: &MutationRequest,
    ) -> Result<Option<ParamsValue>> {
        let digest = self.voice_action_digest(actor_id, mutation)?;
        self.sharing
            .grants()
            .recorded_action(actor_id, mutation.action_id, &digest)?
            .map(Self::recorded_voice_action)
            .transpose()
    }

    /// The answer a voice change an earlier attempt claimed is owed.
    ///
    /// As an authority change's ([`Self::recorded_authority_change`]), with one difference: none of
    /// the three leaves anything in this host's records that names the action. A voice grant takes
    /// a fresh identity, a voice session is held in memory, and a started call is the broker's. So
    /// a change whose attempt ended without recording what it did is an outcome this host does not
    /// know, and it is never performed again: a second start would be a second metered call.
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
                         did, so a call or a grant it made may exist; it is not performed again"
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
