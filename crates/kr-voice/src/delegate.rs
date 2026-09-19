//! The coordinator: what a delegation becomes, and what it never becomes.
//!
//! Section 15 ¶7 gives this module its shape. A delegation arrives at the native app on the
//! provider's read-only data channel; the paired device submits it to the host over its own
//! authenticated connection; the actor is that device under its ordinary grant intersected with
//! the voice grant and the session binding; **the coordinator proposes and the worker validates
//! normally**. The delegation event supplies an identifier and a timeline offset, not task text,
//! so what the coordinator proposes comes from the host's own state and from the action the device
//! named — never from what the model said the person wants.
//!
//! # The order the checks run in
//!
//! 1. The voice session exists and belongs to this device.
//! 2. The delegation identifier belongs to this call's own timeline and has not been spent.
//! 3. The session named is one this voice session may reach.
//! 4. **The confirmation**, for the five classes of section 15 ¶13 that need one. It is checked
//!    before the grant deliberately: an action in one of those classes is refused for the missing
//!    confirmation whatever the grant says, so the refusal is the same sentence for everyone and
//!    tells a caller nothing about what this host's grants contain.
//! 5. The spoken destination, the verified approval details or the current turn identifier, for
//!    the three actions that need one.
//! 6. The authority: the voice grant and the device's ordinary grant, intersected now.
//! 7. The proposal goes to the host, which validates it the ordinary way.
//!
//! # What cannot happen here
//!
//! There is no path from speech interruption to task cancellation, because interruption is not in
//! this vocabulary at all: playback is the native client's and this crate never sees it. The only
//! way to cancel a coding task is [`VoiceAction::CancelTurn`] with the agent's current turn
//! identifier, which is the typed request section 15 ¶13 names.
//!
//! And nothing reads an admission as execution. A host that accepted a proposal without performing
//! it answers [`VoiceDelegationOutcome::Admitted`], never `Performed`.

use std::sync::{Arc, Mutex};

use kr_client::services::voice::{ManagedVoiceService, VoiceStart};
use kr_protocol::ids::{ActionId, DeviceId, EnvironmentId, SessionId, VoiceSessionId};
use kr_protocol::scalars::{CanonicalSet, Digest256, Nullable, TimestampMs, U64};
use kr_protocol::voice::{
    VOICE_ADMISSION_NOTE, VOICE_APPEND_BYTES, VOICE_DELEGATION_NOTE, VOICE_DISCLOSURE, VoiceAction,
    VoiceActionPlan, VoiceConfirmationRequest, VoiceDelegateParams, VoiceDelegateResult,
    VoiceDelegationId, VoiceDelegationOutcome, VoiceGrantParams, VoiceGrantResult,
    VoiceGrantStatement, VoiceRefusal, VoiceSessionDescriptor, VoiceStartOutcome, VoiceStartParams,
    VoiceStartResult, VoiceStopParams, VoiceStopResult,
};

use crate::confirm::{
    ConfirmationLedger, confirmation_required, issue_confirmation, verify_confirmation,
};
use crate::context::{SecretPatterns, select_context};
use crate::error::{Result, VoiceError};
use crate::grant::{GrantBinding, call_expiry, permits, permitted_actions, plan_voice_grant};
use crate::seams::{ActionSubmitter, ContextRequest, ContextSource, VoiceAuthority};
use crate::session::{NewVoiceSession, VoiceSessions};

/// What the coordinator asks the host to do.
///
/// It is a proposal and nothing more. The host resolves it to one of its own methods and runs
/// every check that method carries; a proposal that arrived by speech is checked exactly as one
/// that arrived by typing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proposal {
    /// The voice session proposing it.
    pub voice_session_id: VoiceSessionId,
    /// The paired device whose authority it runs under.
    pub device_id: DeviceId,
    /// The environment.
    pub environment_id: EnvironmentId,
    /// What to do.
    pub action: VoiceAction,
    /// The action identifier of the request that carried it.
    pub action_id: ActionId,
    /// The session it acts on, when it acts on one.
    pub session_id: Option<SessionId>,
    /// The delegation it was interpreted from.
    pub delegation_id: VoiceDelegationId,
    /// The plan the confirmation was bound to, so the host performs what was confirmed.
    pub plan: VoiceActionPlan,
    /// The approval being answered, when the action answers one.
    pub approval: Option<kr_protocol::voice::VerifiedApprovalAnswer>,
    /// The agent turn being cancelled, when the action cancels one.
    pub turn_id: Option<kr_protocol::ids::AgentTurnId>,
    /// The destination the speaker named, when the action submits a prompt.
    pub destination: Option<kr_protocol::voice::SpokenDestination>,
}

/// Everything the coordinator holds.
#[derive(Debug)]
pub struct Coordinator {
    context: Arc<dyn ContextSource>,
    authority: Arc<dyn VoiceAuthority>,
    submitter: Arc<dyn ActionSubmitter>,
    provider: Option<Arc<dyn ManagedVoiceService>>,
    host_device_id: DeviceId,
    environment_id: EnvironmentId,
    broker_origin: String,
    patterns: SecretPatterns,
    state: Mutex<State>,
}

#[derive(Debug, Default)]
struct State {
    sessions: VoiceSessions,
    ledger: ConfirmationLedger,
}

impl Coordinator {
    /// Builds a coordinator over the host's three seams and its provider.
    ///
    /// `provider` is `None` on a host with no managed voice service configured, which is a
    /// complete host: every other voice method still works against a call the person's own
    /// provider is carrying, and starting a managed one says so rather than failing obscurely.
    #[must_use]
    pub fn new(
        context: Arc<dyn ContextSource>,
        authority: Arc<dyn VoiceAuthority>,
        submitter: Arc<dyn ActionSubmitter>,
        provider: Option<Arc<dyn ManagedVoiceService>>,
        host_device_id: DeviceId,
        environment_id: EnvironmentId,
        broker_origin: impl Into<String>,
    ) -> Self {
        Self {
            context,
            authority,
            submitter,
            provider,
            host_device_id,
            environment_id,
            broker_origin: broker_origin.into(),
            patterns: SecretPatterns::default(),
            state: Mutex::new(State::default()),
        }
    }

    /// Replaces the provider this coordinator brokers through.
    ///
    /// The seam is filled by the managed broker, by a backend of the person's own, or by nothing
    /// at all. Nothing else in this crate changes with it.
    #[must_use]
    pub fn with_provider(mut self, provider: Option<Arc<dyn ManagedVoiceService>>) -> Self {
        self.provider = provider;
        self
    }

    /// Replaces the secret patterns this host strips as a secondary measure.
    #[must_use]
    pub fn with_secret_patterns(mut self, patterns: SecretPatterns) -> Self {
        self.patterns = patterns;
        self
    }

    /// How many voice sessions are live.
    ///
    /// # Panics
    ///
    /// Panics when a thread holding the coordinator's lock panicked, which would mean the
    /// coordinator's own state is no longer known.
    #[must_use]
    pub fn live_sessions(&self) -> usize {
        self.state
            .lock()
            .expect("the coordinator's state")
            .sessions
            .len()
    }

    /* ---------------------------------------------------------------- */
    /* voice.grant                                                       */
    /* ---------------------------------------------------------------- */

    /// Creates or replaces a device's standing voice grant.
    ///
    /// Section 15 ¶13: a person may broaden their own voice grant, and the change states which
    /// actions it permits. The statement comes back with the result rather than from a surface
    /// that might describe a different set from the one that was written.
    ///
    /// # Errors
    ///
    /// Returns an error when the device holds no ordinary grant, or the store refuses the write.
    ///
    /// # Panics
    ///
    /// Panics when a thread holding the coordinator's lock panicked.
    pub async fn grant(
        &self,
        params: &VoiceGrantParams,
        authority_revision: kr_protocol::ids::AuthorityRevision,
        now_ms: u64,
    ) -> Result<VoiceGrantResult> {
        let device_grant = self
            .authority
            .device_grant(params.device_id, None, now_ms)?
            .ok_or_else(|| {
                VoiceError::refused(
                    VoiceRefusal::OutsideDeviceGrant,
                    "this device holds no grant on this host, so it can hold no voice grant",
                )
            })?;
        let planned = plan_voice_grant(
            &device_grant,
            params.actions.0.as_ref(),
            &GrantBinding {
                parent_grant_id: None,
                issuer_device_id: self.host_device_id,
                environment_id: self.environment_id,
                session_ids: params.session_ids.clone(),
                expiry: device_grant.expiry,
                authority_revision,
            },
        )?;
        // The one this replaces goes first. A second standing grant beside the first would leave
        // the old scope authorising calls nobody can see in the new statement, and the store's
        // cascade is what ends the calls running under it.
        let replaced = self
            .authority
            .standing_voice_grant(params.device_id, now_ms)?;
        let mut ending: Vec<String> = Vec::new();
        if let Some(replaced) = replaced.as_ref() {
            self.authority.revoke(replaced.grant_id, now_ms)?;
            let mut state = self.state.lock().expect("the coordinator's state");
            for ended in state.sessions.stop_under(replaced.grant_id) {
                state.ledger.forget_session(ended.voice_session_id);
                if let Some(call_id) = ended.call_id {
                    ending.push(call_id);
                }
            }
        }
        // Outside the lock, and after the authority is already gone: a call whose grant this
        // change withdrew is finalised rather than left metering until its own deadline.
        if let Some(provider) = self.provider.clone() {
            for call_id in &ending {
                self.close_unbound(&provider, call_id).await;
            }
        }
        let written = self.authority.issue(&planned.plan)?;

        Ok(VoiceGrantResult {
            grant_id: written.grant_id,
            device_id: params.device_id,
            statement: VoiceGrantStatement::of(&planned.plan.actions),
            not_held_by_device: planned.not_held_by_device,
        })
    }

    /* ---------------------------------------------------------------- */
    /* voice.start                                                       */
    /* ---------------------------------------------------------------- */

    /// Starts a voice session for one paired device.
    ///
    /// The broker is asked first and the grant is written afterwards, so a creation that did not
    /// produce a call leaves no authority behind. The three outcomes are section 15 ¶4's, and
    /// `creation_unknown` is a state rather than an error: nothing here retries it.
    ///
    /// # Errors
    ///
    /// Returns an error when the device holds no voice grant, when the offer is not one the broker
    /// will carry, or when the store refuses the write.
    ///
    /// # Panics
    ///
    /// Panics when a thread holding the coordinator's lock panicked.
    pub async fn start(
        &self,
        device_id: DeviceId,
        params: &VoiceStartParams,
        authority_revision: kr_protocol::ids::AuthorityRevision,
        now_ms: u64,
    ) -> Result<VoiceStartResult> {
        let Some(provider) = self.provider.clone() else {
            return Err(VoiceError::NotConfigured(
                "this host has no voice service configured. A provider credential of your own, or \
                 the agent already running in the session, both still work."
                    .to_owned(),
            ));
        };
        let device_grant = self
            .authority
            .device_grant(device_id, None, now_ms)?
            .ok_or_else(|| {
                VoiceError::refused(
                    VoiceRefusal::OutsideDeviceGrant,
                    "this device holds no grant on this host",
                )
            })?;
        let standing = self
            .authority
            .standing_voice_grant(device_id, now_ms)?
            .ok_or_else(|| {
                VoiceError::refused(
                    VoiceRefusal::OutsideVoiceGrant,
                    "this device has no voice grant. Create one before starting a voice session.",
                )
            })?;

        let closes_at_ms = now_ms.saturating_add(u64::from(params.duration_seconds) * 1_000);
        // The call's grant expires on this host's own clock. A host that took its expiry from a
        // timestamp the service wrote would be letting the service decide how long its authority
        // lasts.
        let planned = plan_voice_grant(
            &device_grant,
            Some(&permitted_actions(&standing)),
            &GrantBinding {
                parent_grant_id: Some(standing.grant_id),
                issuer_device_id: self.host_device_id,
                environment_id: self.environment_id,
                session_ids: params.session_ids.clone(),
                expiry: call_expiry(closes_at_ms),
                authority_revision,
            },
        )?;

        let session_ids = match &planned.plan.session_selector {
            kr_protocol::grant::SessionSelector::These { session_ids } => session_ids.clone(),
            // A grant over every session reaches every session, and each request is decided again
            // against both grants. A grant over none reaches none, which is nothing to start.
            kr_protocol::grant::SessionSelector::Any => self.sessions_of(&device_grant),
            kr_protocol::grant::SessionSelector::None => CanonicalSet::from_iter([]),
        };
        if session_ids.is_empty() {
            // Checked before the provider is asked, so a call is never created for a voice session
            // that could reach nothing.
            return Err(VoiceError::refused(
                VoiceRefusal::OutsideDeviceGrant,
                "this device's grant covers no session, so a voice session would reach none",
            ));
        }

        let request = kr_client::services::voice::VoiceSessionRequest {
            offer_sdp: params.offer_sdp.clone(),
            host_id: self.environment_id.to_string(),
            duration_seconds: params.duration_seconds,
            reasoning_budget_minor: params.reasoning_budget_minor.0.map(U64::get),
            device_id: Some(device_id.to_string()),
        };
        let outcome = provider.start(&request).await?;

        let session = match outcome {
            VoiceStart::CreationUnknown {
                attempt_id,
                message,
            } => {
                return Ok(VoiceStartResult {
                    outcome: VoiceStartOutcome::CreationUnknown {
                        attempt_id: attempt_id.unwrap_or_default(),
                        message,
                    },
                });
            }
            VoiceStart::Refused(refusal) => {
                return Ok(VoiceStartResult {
                    outcome: VoiceStartOutcome::Unavailable {
                        reason: refusal.reason.as_str().to_owned(),
                        message: refusal.message.clone(),
                        alternatives: if refusal.alternatives.is_empty() {
                            vec![
                                "A provider credential of your own, which uses no managed credit."
                                    .to_owned(),
                                "The agent already running in the session, reached by typing."
                                    .to_owned(),
                            ]
                        } else {
                            refusal.alternatives.clone()
                        },
                    },
                });
            }
            VoiceStart::Started(session) => session,
        };

        if session.replayed {
            // The service answered with the call an earlier attempt already produced. Issuing a
            // second grant for it would leave two pieces of authority over one call, and stopping
            // either would leave the other standing. The caller is told to use the call it has.
            //
            // The call is closed only when nothing holds it. A call a live voice session is
            // running under is that session's, and closing it here would end a call this host has
            // just told the caller to go on using.
            if !self.holds_call(&session.call_id) {
                self.close_unbound(&provider, &session.call_id).await;
            }
            return Ok(VoiceStartResult {
                outcome: VoiceStartOutcome::Unavailable {
                    reason: "session_in_progress".to_owned(),
                    message: "A managed call for this account is already running. Use the call \
                              this device already holds, or stop it first."
                        .to_owned(),
                    alternatives: vec![
                        "Stop the call this device already holds and start a new one.".to_owned(),
                    ],
                },
            });
        }

        // Everything after this can fail, and a failure leaves a metered call running that no
        // grant covers. The call is closed on the way out rather than left for the deadline.
        let written = match self.authority.issue(&planned.plan) {
            Ok(written) => written,
            Err(error) => {
                self.close_unbound(&provider, &session.call_id).await;
                return Err(error);
            }
        };
        let voice_session_id = match new_identity() {
            Ok(identity) => VoiceSessionId::new(identity),
            Err(error) => {
                let _ = self.authority.revoke(written.grant_id, now_ms);
                self.close_unbound(&provider, &session.call_id).await;
                return Err(error);
            }
        };
        let mut state = self.state.lock().expect("the coordinator's state");
        state.sessions.start(NewVoiceSession {
            voice_session_id,
            device_id,
            grant_id: written.grant_id,
            parent_grant_id: standing.grant_id,
            session_ids: session_ids.clone(),
            call_id: Some(session.call_id.clone()),
            started_at_ms: now_ms,
            closes_at_ms,
        });

        Ok(VoiceStartResult {
            outcome: VoiceStartOutcome::Started {
                session: Box::new(VoiceSessionDescriptor {
                    voice_session_id,
                    grant_id: written.grant_id,
                    statement: VoiceGrantStatement::of(&planned.plan.actions),
                    session_ids,
                    call_id: session.call_id.clone(),
                    provider_session_id: session.provider_session_id.clone(),
                    answer_sdp: session.answer_sdp.clone(),
                    model: session.model.clone(),
                    control_path: session.control_path.clone(),
                    broker_origin: self.broker_origin.clone(),
                    heartbeat_seconds: session.heartbeat_seconds,
                    closes_at_ms: TimestampMs::new(closes_at_ms),
                    disclosure: if session.disclosure.is_empty() {
                        VOICE_DISCLOSURE
                            .iter()
                            .map(|line| (*line).to_owned())
                            .collect()
                    } else {
                        session.disclosure.clone()
                    },
                }),
            },
        })
    }

    /// Whether a live voice session is running under one broker call.
    ///
    /// # Panics
    ///
    /// Panics when a thread holding the coordinator's lock panicked.
    fn holds_call(&self, call_id: &str) -> bool {
        self.state
            .lock()
            .expect("the coordinator's state")
            .sessions
            .iter()
            .any(|record| record.call_id.as_deref() == Some(call_id))
    }

    /// Ends a call this host could not bind to a voice session.
    ///
    /// Told, not waited on, and a service that cannot be reached is not an error the caller sees:
    /// the caller's own answer is already decided, and the service's deadline closes the call in
    /// any case. Nothing here retries creation.
    async fn close_unbound(&self, provider: &Arc<dyn ManagedVoiceService>, call_id: &str) {
        let _ = provider.close(call_id).await;
    }

    /// The sessions a grant covers, when the grant names them.
    fn sessions_of(&self, grant: &kr_protocol::grant::Grant) -> CanonicalSet<SessionId> {
        match &grant.session_selector {
            kr_protocol::grant::SessionSelector::These { session_ids } => session_ids.clone(),
            kr_protocol::grant::SessionSelector::Any
            | kr_protocol::grant::SessionSelector::None => CanonicalSet::from_iter([]),
        }
    }

    /* ---------------------------------------------------------------- */
    /* voice.stop                                                        */
    /* ---------------------------------------------------------------- */

    /// Ends a voice session and revokes its grant immediately.
    ///
    /// Section 15 ¶8: the revocation is independent of provider billing finalisation. The grant
    /// goes first and the broker is told afterwards, so a broker that cannot be reached does not
    /// hold a revocation open. Section 15 ¶1: the terminal sessions it reached keep running, and
    /// they are named in the answer so nobody has to take that on trust.
    ///
    /// # Errors
    ///
    /// Returns an error when there is no such voice session for this device, or the store refuses
    /// the revocation.
    ///
    /// # Panics
    ///
    /// Panics when a thread holding the coordinator's lock panicked.
    pub async fn stop(
        &self,
        device_id: DeviceId,
        params: &VoiceStopParams,
        now_ms: u64,
    ) -> Result<VoiceStopResult> {
        let record = {
            let mut state = self.state.lock().expect("the coordinator's state");
            let record = state.sessions.stop(params.voice_session_id, device_id)?;
            state.ledger.forget_session(params.voice_session_id);
            record
        };
        let revoked_at_ms = self.authority.revoke(record.grant_id, now_ms)?;

        let mut broker_notified = false;
        if let (Some(provider), Some(call_id)) = (self.provider.as_ref(), record.call_id.as_ref()) {
            // Told, not waited on. The grant is already gone; what the service does about the
            // money is settled on its own schedule and `session.closed` is what finalises it.
            broker_notified = provider.close(call_id).await.is_ok();
        }

        Ok(VoiceStopResult {
            voice_session_id: params.voice_session_id,
            revoked_grant_id: record.grant_id,
            revoked_at_ms: TimestampMs::new(revoked_at_ms),
            broker_notified,
            sessions_left_running: record.session_ids,
        })
    }

    /* ---------------------------------------------------------------- */
    /* voice.context                                                     */
    /* ---------------------------------------------------------------- */

    /// Selects the bounded context for one session.
    ///
    /// The selection uses the requesting device's own grant and nothing wider, and what comes back
    /// goes to the paired client. The host does not send it anywhere: section 15 ¶9 routes context
    /// from the paired client to the broker, and this host has no route to the broker for content.
    ///
    /// # Errors
    ///
    /// Returns an error when there is no such voice session, when the session is not one it may
    /// reach, when the voice grant does not permit briefing, or when the host cannot read it.
    ///
    /// # Panics
    ///
    /// Panics when a thread holding the coordinator's lock panicked.
    pub async fn context(
        &self,
        device_id: DeviceId,
        params: &kr_protocol::voice::VoiceContextParams,
        now_ms: u64,
    ) -> Result<kr_protocol::voice::VoiceContextResult> {
        let (voice_grant_id, reaches) = {
            let state = self.state.lock().expect("the coordinator's state");
            let record = state
                .sessions
                .of_device(params.voice_session_id, device_id)?;
            (record.grant_id, record.reaches(params.session_id))
        };
        if !reaches {
            return Err(VoiceError::refused(
                VoiceRefusal::SessionOutsideVoiceSession,
                "this voice session does not reach that session",
            ));
        }
        let voice_grant = self.live_voice_grant(voice_grant_id, now_ms)?;
        let device_grant = self
            .authority
            .device_grant(device_id, Some(params.session_id), now_ms)?
            .ok_or_else(|| {
                VoiceError::refused(
                    VoiceRefusal::OutsideDeviceGrant,
                    "this device's grant does not cover that session",
                )
            })?;
        if !permits(&voice_grant, &device_grant, VoiceAction::Brief) {
            return Err(VoiceError::refused(
                VoiceRefusal::OutsideVoiceGrant,
                "this voice grant does not permit a briefing",
            ));
        }

        // The narrower of the two, which is what "intersected" means for history as well as for
        // rights. A device grant that later gained older history must not widen a voice grant that
        // was written against the narrower bound.
        let request = ContextRequest {
            session_id: params.session_id,
            grant: narrower_history(&device_grant, &voice_grant),
            selected: params.selected.clone(),
        };
        let gathered = self.context.gather(&request).await?;
        let selection = select_context(&gathered, &request.grant, &params.selected, &self.patterns);

        Ok(kr_protocol::voice::VoiceContextResult {
            voice_session_id: params.voice_session_id,
            session_id: params.session_id,
            selection: selection.selection,
            provenance: selection.provenance,
            withheld: selection.withheld,
            disclosure: selection.disclosure,
        })
    }

    /* ---------------------------------------------------------------- */
    /* voice.delegate                                                    */
    /* ---------------------------------------------------------------- */

    /// Records a delegation the provider announced to one call.
    ///
    /// The paired device is the only thing that sees the provider's data channel, so it is the
    /// only thing that can report one. An identifier is correlation data: recording it says the
    /// provider mentioned it, and says nothing about what anybody may do.
    ///
    /// # Errors
    ///
    /// Returns an error when there is no such voice session for this device, or the offset falls
    /// outside the call's own timeline.
    ///
    /// # Panics
    ///
    /// Panics when a thread holding the coordinator's lock panicked.
    pub fn announce(
        &self,
        device_id: DeviceId,
        voice_session_id: VoiceSessionId,
        delegation_id: &VoiceDelegationId,
        offset_ms: u64,
        now_ms: u64,
    ) -> Result<()> {
        let mut state = self.state.lock().expect("the coordinator's state");
        let record = state.sessions.of_device_mut(voice_session_id, device_id)?;
        let elapsed_ms = now_ms.saturating_sub(record.started_at_ms);
        // A delegation that happened before the call began, or after more time than the call has
        // run, is not this call's. The tolerance is one heartbeat interval, because the offset is
        // the provider's clock and the comparison is this host's.
        if offset_ms > elapsed_ms.saturating_add(TIMELINE_TOLERANCE_MS) {
            return Err(VoiceError::refused(
                VoiceRefusal::UnannouncedDelegation,
                "that delegation is not on this call's own timeline",
            ));
        }
        if record.announced(delegation_id) {
            return Err(VoiceError::refused(
                VoiceRefusal::UnannouncedDelegation,
                "that delegation has already been submitted; one delegation is one action",
            ));
        }
        record.announce(delegation_id.clone());
        Ok(())
    }

    /// Issues the confirmation challenge one action needs.
    ///
    /// The digest is over the plan, so the challenge the person answers names what will actually
    /// be performed rather than what a caller said it wanted.
    ///
    /// # Errors
    ///
    /// Returns an error when the plan cannot be encoded or the generator is unavailable.
    ///
    /// # Panics
    ///
    /// Panics when a thread holding the coordinator's lock panicked.
    pub fn confirmation_challenge(
        &self,
        device_id: DeviceId,
        plan: &VoiceActionPlan,
        action_id: ActionId,
        now_ms: u64,
    ) -> Result<VoiceConfirmationRequest> {
        let request = issue_confirmation(plan, action_id, self.host_device_id, device_id, now_ms)?;
        let mut state = self.state.lock().expect("the coordinator's state");
        state.ledger.sweep(now_ms);
        state.ledger.issue(&request);
        Ok(request)
    }

    /// Interprets one delegation and proposes what it means.
    ///
    /// # Errors
    ///
    /// Returns an error when the host could not be reached. Every rule that refuses the delegation
    /// answers [`VoiceDelegationOutcome::Refused`] instead, because a refusal is a decision rather
    /// than a failure and a caller that retried it would be retrying something settled.
    ///
    /// # Panics
    ///
    /// Panics when a thread holding the coordinator's lock panicked.
    pub async fn delegate(
        &self,
        device_id: DeviceId,
        action_id: ActionId,
        params: &VoiceDelegateParams,
        now_ms: u64,
    ) -> Result<VoiceDelegateResult> {
        match self.propose(device_id, action_id, params, now_ms).await {
            Ok(proposal) => {
                let receipt = self.submitter.submit(&proposal).await?;
                Ok(VoiceDelegateResult {
                    delegation_id: params.delegation_id.clone(),
                    outcome: if receipt.performed {
                        VoiceDelegationOutcome::Performed {
                            action_id: receipt.action_id,
                            summary: bounded(&receipt.summary),
                        }
                    } else {
                        // Admitted and not performed. Never reported as done: the receipt is the
                        // authority, and this says where to read it.
                        VoiceDelegationOutcome::Admitted {
                            action_id: receipt.action_id,
                            note: VOICE_ADMISSION_NOTE.to_owned(),
                        }
                    },
                })
            }
            Err(VoiceError::Refused { reason, detail }) => Ok(VoiceDelegateResult {
                delegation_id: params.delegation_id.clone(),
                outcome: VoiceDelegationOutcome::Refused {
                    reason,
                    message: detail,
                },
            }),
            Err(other) => Err(other),
        }
    }

    /// Runs every check and builds the proposal, or names the rule that refused.
    async fn propose(
        &self,
        device_id: DeviceId,
        action_id: ActionId,
        params: &VoiceDelegateParams,
        now_ms: u64,
    ) -> Result<Proposal> {
        // 1 and 2: the call is this device's, and the delegation is on its timeline and unspent.
        // `announce` does both, and spends the identifier, so a second submission of the same
        // delegation cannot become a second action.
        self.announce(
            device_id,
            params.voice_session_id,
            &params.delegation_id,
            params.offset_ms.get(),
            now_ms,
        )?;
        let (voice_grant_id, reaches) = {
            let state = self.state.lock().expect("the coordinator's state");
            let record = state
                .sessions
                .of_device(params.voice_session_id, device_id)?;
            (
                record.grant_id,
                params
                    .session_id
                    .0
                    .is_none_or(|session_id| record.reaches(session_id)),
            )
        };

        // 3: the session named is one this call may reach.
        if !reaches {
            return Err(VoiceError::refused(
                VoiceRefusal::SessionOutsideVoiceSession,
                "this voice session does not reach that session",
            ));
        }

        let plan = VoiceActionPlan {
            voice_session_id: params.voice_session_id,
            action: params.action,
            session_id: params.session_id,
            delegation_id: Nullable::some(params.delegation_id.clone()),
            payload_digest: payload_digest(params)?,
        };

        // 4: the confirmation, before the grant. An action in one of the five classes is refused
        // for the missing confirmation whatever this host's grants contain, so the refusal says
        // the same thing to everybody.
        if params.action.needs_unlocked_screen() {
            let Some(proof) = params.confirmation.0.as_ref() else {
                return Err(confirmation_required(params.action));
            };
            let signer = self
                .authority
                .device_identity_key(device_id)?
                .ok_or_else(|| {
                    VoiceError::refused(
                        VoiceRefusal::ConfirmationMismatch,
                        "this host holds no identity key for that device",
                    )
                })?;
            let mut state = self.state.lock().expect("the coordinator's state");
            verify_confirmation(
                &mut state.ledger,
                &plan,
                action_id,
                device_id,
                proof,
                &signer,
                now_ms,
            )?;
        }

        // 5: what the three remaining actions of section 15 ¶13 each need.
        if params.action.needs_spoken_destination() {
            let Some(destination) = params.spoken_destination.0.as_ref() else {
                return Err(VoiceError::refused(
                    VoiceRefusal::DestinationNotNamed,
                    "submitting a prompt needs a clear spoken confirmation that names the \
                     destination session",
                ));
            };
            if params.session_id.0 != Some(destination.session_id) {
                return Err(VoiceError::refused(
                    VoiceRefusal::DestinationNotNamed,
                    "the spoken confirmation named a different session from the one this \
                     delegation acts on",
                ));
            }
        }
        if params.action.needs_verified_request() {
            let Some(answer) = params.approval.0.as_ref() else {
                return Err(VoiceError::refused(
                    VoiceRefusal::ApprovalNotVerified,
                    "an approval decision needs the verified request's details and an explicit \
                     answer",
                ));
            };
            let Some(session_id) = params.session_id.0 else {
                return Err(VoiceError::refused(
                    VoiceRefusal::ApprovalNotVerified,
                    "an approval decision names the session the approval belongs to",
                ));
            };
            let held = self
                .context
                .approval_details(session_id, &answer.approval_request_id)
                .await?;
            if held != Some(answer.details_digest) {
                return Err(VoiceError::refused(
                    VoiceRefusal::ApprovalNotVerified,
                    "the details this answer was given for are not the ones this host holds for \
                     that approval",
                ));
            }
        }
        if params.action == VoiceAction::CancelTurn && params.turn_id.0.is_none() {
            return Err(VoiceError::refused(
                VoiceRefusal::TurnNotNamed,
                "cancelling an agent's work needs its typed request and the current turn \
                 identifier. Interrupting speech stops playback and nothing else.",
            ));
        }

        // 6: the authority, intersected now rather than when the grant was written.
        if params.action.required_right().is_none() {
            return Err(VoiceError::refused(
                VoiceRefusal::NoSuchEffect,
                "this host has no effect that does that, so no grant can carry it",
            ));
        }
        let voice_grant = self.live_voice_grant(voice_grant_id, now_ms)?;
        let device_grant = self
            .authority
            .device_grant(device_id, params.session_id.0, now_ms)?
            .ok_or_else(|| {
                VoiceError::refused(
                    VoiceRefusal::OutsideDeviceGrant,
                    "this device's grant does not cover that session",
                )
            })?;
        if !voice_grant.permits(kr_protocol::rights::ActionRight::VoiceUse)
            || !permitted_actions(&voice_grant).contains(&params.action)
        {
            return Err(VoiceError::refused(
                VoiceRefusal::OutsideVoiceGrant,
                format!(
                    "this voice grant does not permit {}. Broaden it in settings, where the \
                     change states which actions it permits.",
                    params.action.as_str()
                ),
            ));
        }
        if !permits(&voice_grant, &device_grant, params.action) {
            return Err(VoiceError::refused(
                VoiceRefusal::OutsideDeviceGrant,
                format!(
                    "this device's own grant does not carry what {} needs, and a voice grant \
                     narrows it rather than adding to it",
                    params.action.as_str()
                ),
            ));
        }

        Ok(Proposal {
            voice_session_id: params.voice_session_id,
            device_id,
            environment_id: self.environment_id,
            action: params.action,
            action_id,
            session_id: params.session_id.0,
            delegation_id: params.delegation_id.clone(),
            plan,
            approval: params.approval.0.clone(),
            turn_id: params.turn_id.0.clone(),
            destination: params.spoken_destination.0.clone(),
        })
    }

    /// The live grant behind one voice session, at the moment of the decision.
    ///
    /// Revoked and expired are both checked here, and expiry is checked against the clock the
    /// request carries rather than against what was true when the grant was written: a call that
    /// outlived its own deadline must stop authorising the request after it.
    fn live_voice_grant(
        &self,
        grant_id: kr_protocol::ids::GrantId,
        now_ms: u64,
    ) -> Result<kr_protocol::grant::Grant> {
        let grant = self.authority.grant(grant_id, now_ms)?.ok_or_else(|| {
            VoiceError::refused(
                VoiceRefusal::OutsideVoiceGrant,
                "this voice session's grant has been revoked",
            )
        })?;
        if !grant.expiry.is_valid_at(now_ms) {
            return Err(VoiceError::refused(
                VoiceRefusal::OutsideVoiceGrant,
                "this voice session's grant has run out",
            ));
        }
        Ok(grant)
    }

    /// The sentence carried with every delegation this host accepts.
    #[must_use]
    pub const fn delegation_note() -> &'static str {
        VOICE_DELEGATION_NOTE
    }
}

/// The device's grant with the narrower of the two history scopes.
///
/// Rights are intersected where each action is decided; history is intersected here, because the
/// selection is built from one scope and that scope has to be the narrower one. The lower bound
/// takes the later of the two, and a scope with no retained history at all wins outright.
fn narrower_history(
    device_grant: &kr_protocol::grant::Grant,
    voice_grant: &kr_protocol::grant::Grant,
) -> kr_protocol::grant::Grant {
    let mut narrowed = device_grant.clone();
    let device_bound = device_grant.history.lower_bound_ms.0.map(TimestampMs::get);
    let voice_bound = voice_grant.history.lower_bound_ms.0.map(TimestampMs::get);
    narrowed.history.lower_bound_ms = match (device_bound, voice_bound) {
        (Some(device), Some(voice)) => Nullable::some(TimestampMs::new(device.max(voice))),
        // Either scope seeing no retained history means the selection sees none.
        _ => Nullable::null(),
    };
    narrowed.history.include_live_screen =
        device_grant.history.include_live_screen && voice_grant.history.include_live_screen;
    narrowed
}

/// How far a provider's offset may fall outside this host's reading of the call's length.
///
/// One heartbeat interval. The offset is measured on the provider's clock and compared against
/// this host's, so a tolerance is needed; a tolerance longer than one heartbeat would admit an
/// identifier from a call that ended.
const TIMELINE_TOLERANCE_MS: u64 = 20_000;

/// The digest of the exact parameters a proposal will carry.
fn payload_digest(params: &VoiceDelegateParams) -> Result<Digest256> {
    // Everything the host will act on, and nothing the caller can vary afterwards. The
    // confirmation is not in it: a confirmation cannot be part of what it confirms.
    let material = VoiceDelegateParams {
        confirmation: Nullable::null(),
        ..params.clone()
    };
    Ok(Digest256::from_bytes(kr_cbor::sha256(&kr_cbor::encode(
        &kr_cbor::to_canonical_value(&material)?,
    ))))
}

/// Cuts a host result to what one bounded context request may carry.
///
/// Section 15 ¶9 bounds an append at 500 provider tokens, which the broker enforces as 500 UTF-8
/// bytes. A result the coordinator returns longer than that is a result the paired client could
/// not send, so it is cut here, on a character boundary, with the cut made visible.
fn bounded(summary: &str) -> String {
    if summary.len() <= VOICE_APPEND_BYTES {
        return summary.to_owned();
    }
    let ellipsis = '…';
    let room = VOICE_APPEND_BYTES - ellipsis.len_utf8();
    let mut end = room;
    while end > 0 && !summary.is_char_boundary(end) {
        end -= 1;
    }
    let mut cut = summary[..end].to_owned();
    cut.push(ellipsis);
    cut
}

/// A fresh 128-bit identity from the operating system's generator.
fn new_identity() -> Result<kr_protocol::scalars::Uuid> {
    let mut bytes = [0u8; 16];
    kr_crypto::random_bytes(&mut bytes)?;
    // Version 4, variant 1, as every identifier this product generates is.
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Ok(kr_protocol::scalars::Uuid::from_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_result_is_cut_to_what_one_context_request_carries() {
        let short = "applied the diff";
        assert_eq!(bounded(short), short);
        let long = "é".repeat(400);
        let cut = bounded(&long);
        assert!(cut.len() <= VOICE_APPEND_BYTES);
        assert!(cut.ends_with('…'));
    }

    #[test]
    fn a_generated_identity_is_a_version_four_identifier() {
        let identity = new_identity().expect("an identity");
        let bytes = identity.as_bytes();
        assert_eq!(bytes[6] & 0xf0, 0x40);
        assert_eq!(bytes[8] & 0xc0, 0x80);
    }
}
