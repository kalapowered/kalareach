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

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use kr_client::services::voice::{ManagedVoiceService, VoiceStart};
use kr_protocol::ids::{ActionId, DeviceId, EnvironmentId, GrantId, SessionId, VoiceSessionId};
use kr_protocol::scalars::{CanonicalSet, Digest256, Nullable, TimestampMs, U64};
use kr_protocol::voice::{
    VOICE_ADMISSION_NOTE, VOICE_APPEND_BYTES, VOICE_DELEGATION_NOTE, VOICE_DISCLOSURE, VoiceAction,
    VoiceActionPlan, VoiceConfirmationRequest, VoiceDelegateParams, VoiceDelegateResult,
    VoiceDelegationId, VoiceDelegationOutcome, VoiceGrantParams, VoiceGrantResult,
    VoiceGrantStatement, VoiceRefusal, VoiceSessionDescriptor, VoiceStartOutcome, VoiceStartParams,
    VoiceStartResult, VoiceStopParams, VoiceStopResult,
};

use crate::confirm::{ConfirmationLedger, issue_confirmation, verify_confirmation};
use crate::context::{SecretPatterns, select_context};
use crate::error::{Result, VoiceError};
use crate::grant::{GrantBinding, call_expiry, permits, permitted_actions, plan_voice_grant};
use crate::seams::{ActionSubmitter, Admission, ContextRequest, ContextSource, VoiceAuthority};
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
    /// The session-bound voice grant this proposal was admitted under.
    ///
    /// Carried so the host checks the same grant again at the moment of the effect. A proposal
    /// waits for the host between the check and the effect, and authority withdrawn inside that
    /// wait has to stop it.
    pub voice_grant_id: GrantId,
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

/// One call a change withdrew, with the provider that created it.
#[derive(Debug)]
struct Ending {
    call_id: String,
    provider: Option<Arc<dyn ManagedVoiceService>>,
}

/// What running every check produced.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Proposed {
    /// The checks passed, and this is what the host is asked to do.
    Ready(Box<Proposal>),
    /// The action needs a confirmation on the device's unlocked screen, and this is the challenge
    /// that ceremony signs. Nothing has been admitted, and the delegation has not been spent.
    NeedsConfirmation(Box<VoiceConfirmationRequest>),
}

/// Everything the coordinator holds.
#[derive(Debug)]
pub struct Coordinator {
    context: Arc<dyn ContextSource>,
    authority: Arc<dyn VoiceAuthority>,
    submitter: Arc<dyn ActionSubmitter>,
    /// The provider this coordinator brokers a managed call through, when one is configured.
    ///
    /// Replaceable while the coordinator runs, because the host that owns it has no way to reach
    /// a network of its own: the embedder brings the HTTP exchange and attaches the broker to the
    /// service the daemon has already registered.
    provider: Mutex<Option<Arc<dyn ManagedVoiceService>>>,
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
    /// Replayed calls this host could not close while another start was in flight.
    ///
    /// A call nobody holds is a call somebody is paying for, so it is closed rather than left to
    /// its own deadline; a call another start might be about to bind is left alone until that
    /// start has finished with it. Each is kept with the provider that created it, because the
    /// coordinator's own provider can be replaced in between.
    deferred: Vec<Ending>,
    /// The devices with a start in flight.
    ///
    /// A start asks the broker between reading a device's authority and recording what came back,
    /// and that wait is the window two starts can cross in. A device is in this set for the whole
    /// of its own start, so the second one is answered rather than run beside the first.
    starting: BTreeSet<DeviceId>,
}

/// One device's start, held for as long as it runs.
///
/// A guard rather than a pair of calls: every exit from `start` is a return, and a marker that a
/// failure path forgot to clear would stop that device starting a voice session again.
struct StartGate<'a> {
    state: &'a Mutex<State>,
    device_id: DeviceId,
}

impl Drop for StartGate<'_> {
    fn drop(&mut self) {
        if let Ok(mut state) = self.state.lock() {
            state.starting.remove(&self.device_id);
        }
    }
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
            provider: Mutex::new(provider),
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
        *self.provider.get_mut().expect("the coordinator's provider") = provider;
        self
    }

    /// Replaces the provider on a coordinator that is already running.
    ///
    /// The host registers its voice service while it starts, before anything that can reach a
    /// network exists; the embedder attaches the broker afterwards. A call already running keeps
    /// the provider it started on until it is stopped, because stopping it is what tells the
    /// provider the call has ended.
    ///
    /// # Panics
    ///
    /// Panics when a thread holding the coordinator's provider panicked.
    pub fn attach_provider(&self, provider: Option<Arc<dyn ManagedVoiceService>>) {
        *self.provider.lock().expect("the coordinator's provider") = provider;
    }

    /// The provider this coordinator brokers through, as it stands now.
    ///
    /// # Panics
    ///
    /// Panics when a thread holding the coordinator's provider panicked.
    fn provider(&self) -> Option<Arc<dyn ManagedVoiceService>> {
        self.provider
            .lock()
            .expect("the coordinator's provider")
            .clone()
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
        admission: &dyn Admission,
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
        // Reading the grant this replaces, withdrawing it and writing the new one happen together
        // or not at all. Every one of the three is a synchronous call on the host's store, so
        // holding this coordinator's own lock across them is what makes the replacement atomic:
        // two changes arriving at once cannot each read the same standing grant, withdraw it and
        // leave two replacements standing. The broker is told afterwards, outside the lock.
        let (written, ending) = {
            let mut state = self.state.lock().expect("the coordinator's state");
            // Inside the lock, and immediately before the write. Waiting for this lock is the last
            // thing this change does, and an authority change whose admitted lifetime ran out
            // while it waited is one nobody is still holding a window for.
            Self::still_admitted(admission)?;
            let replaced = self
                .authority
                .standing_voice_grant(params.device_id, now_ms)?;
            // Again, after the lookup: reading the store is itself a wait, on its own lock and on
            // the file underneath it, and the check that decides whether this change may happen
            // has to be the last thing before it does.
            Self::still_admitted(admission)?;
            let mut ending: Vec<Ending> = Vec::new();
            if let Some(replaced) = replaced.as_ref() {
                // The one this replaces goes first. A second standing grant beside the first would
                // leave the old scope authorising calls nobody can see in the new statement, and
                // the store's cascade is what ends the calls running under it.
                self.authority.revoke(replaced.grant_id, now_ms)?;
                for ended in state.sessions.stop_under(replaced.grant_id) {
                    state.ledger.forget_session(ended.voice_session_id);
                    if let Some(call_id) = ended.call_id {
                        ending.push(Ending {
                            call_id,
                            provider: ended.provider,
                        });
                    }
                }
            }
            // The write is kept rather than returned: its failure must not skip what follows. The
            // revocation has already happened by here, so a call it withdrew is a call nobody can
            // stop any more, and leaving it metering because the replacement could not be written
            // would be the worst of both.
            (self.authority.issue(&planned.plan), ending)
        };
        // Outside the lock, and after the authority is already gone: a call whose grant this
        // change withdrew is finalised rather than left metering until its own deadline. Each is
        // closed through the provider that created it.
        for ending in &ending {
            if let Some(provider) = ending.provider.as_ref() {
                self.close_unbound(provider, &ending.call_id).await;
            }
        }
        let written = written?;

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
        admission: &dyn Admission,
    ) -> Result<VoiceStartResult> {
        let answer = self
            .start_call(device_id, params, authority_revision, now_ms, admission)
            .await;
        // Whatever this start came to, and after its own gate is released: a replayed call this
        // host left open because a start might bind it is closed once no start is left that
        // could. A start that was refused defers nothing of its own and still drains what another
        // one left behind.
        self.close_deferred().await;
        answer
    }

    async fn start_call(
        &self,
        device_id: DeviceId,
        params: &VoiceStartParams,
        authority_revision: kr_protocol::ids::AuthorityRevision,
        now_ms: u64,
        admission: &dyn Admission,
    ) -> Result<VoiceStartResult> {
        let Some(provider) = self.provider() else {
            return Err(VoiceError::NotConfigured(
                "this host has no voice service configured. A provider credential of your own, or \
                 the agent already running in the session, both still work."
                    .to_owned(),
            ));
        };
        // One start at a time for one device. The broker call sits between reading this device's
        // authority and recording the call that came back, and two starts crossing in that window
        // can each decide about a call the other is about to bind. The second is told that one is
        // already running, which is what it would be told a moment later anyway.
        let Some(_gate) = self.begin_start(device_id) else {
            return Ok(VoiceStartResult {
                outcome: VoiceStartOutcome::Unavailable {
                    reason: "session_in_progress".to_owned(),
                    message: "a voice session is already starting for this device".to_owned(),
                    alternatives: vec![
                        "Wait for the call that is starting, and use it.".to_owned(),
                    ],
                },
            });
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
                // An empty request takes the standing voice grant's own sessions, not the wider
                // set the device's ordinary grant covers: the child narrows both, and the standing
                // grant is the narrower of the two by construction.
                session_ids: if params.session_ids.is_empty() {
                    match &standing.session_selector {
                        kr_protocol::grant::SessionSelector::These { session_ids } => {
                            session_ids.clone()
                        }
                        _ => CanonicalSet::from_iter([]),
                    }
                } else {
                    params.session_ids.clone()
                },
                expiry: call_expiry(closes_at_ms),
                authority_revision,
            },
        )?;

        let session_ids = match &planned.plan.session_selector {
            kr_protocol::grant::SessionSelector::These { session_ids } => session_ids.clone(),
            // A voice session names what it reaches. A grant over every session cannot be turned
            // into that list here, and answering with an empty one would be a call that reaches
            // nothing, so the caller is asked to name them.
            kr_protocol::grant::SessionSelector::Any => {
                return Err(VoiceError::refused(
                    VoiceRefusal::SessionOutsideVoiceSession,
                    "name the sessions this voice session may reach; a voice grant over every \
                     session is not one a call can be bound to",
                ));
            }
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
            // The call is closed only when nothing holds it and nothing is about to. A call a live
            // voice session is running under is that session's, and closing it here would end a
            // call this host has just told the caller to go on using; a call another start is
            // still waiting on is one that start will bind or close itself.
            if self.may_close_replayed(&session.call_id, &provider, device_id) {
                self.close_unbound(&provider, &session.call_id).await;
            } else {
                // Another start is still waiting on the broker and may be about to bind this
                // call. It is remembered rather than dropped, and closed once no start is left
                // that could hold it.
                let mut state = self.state.lock().expect("the coordinator's state");
                if !state.deferred.iter().any(|held| {
                    held.call_id == session.call_id
                        && held
                            .provider
                            .as_ref()
                            .is_some_and(|held| Arc::ptr_eq(held, &provider))
                }) {
                    state.deferred.push(Ending {
                        call_id: session.call_id.clone(),
                        provider: Some(Arc::clone(&provider)),
                    });
                }
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
        let voice_session_id = match new_identity() {
            Ok(identity) => VoiceSessionId::new(identity),
            Err(error) => {
                self.close_unbound(&provider, &session.call_id).await;
                return Err(error);
            }
        };
        // The child grant and the record of the call it belongs to are written together, under the
        // same lock a grant change takes, and against the standing grant this call was planned
        // for. Without that, a change that replaced the standing grant while the broker was
        // answering would revoke a child that had not been recorded yet and find no session to
        // stop, and this call would come back holding authority that was already withdrawn.
        let written = {
            let mut state = self.state.lock().expect("the coordinator's state");
            // The same check the grant change makes, at the same place: the broker's answer is the
            // longest wait this request has, and what is written after it has to be inside the
            // lifetime the host accepted.
            if let Err(error) = Self::still_admitted(admission) {
                drop(state);
                self.close_unbound(&provider, &session.call_id).await;
                return Err(error);
            }
            let current = self.authority.standing_voice_grant(device_id, now_ms);
            match current {
                Ok(Some(current)) if current.grant_id == standing.grant_id => {
                    // And again after that lookup, because reading the store waits too: on its
                    // own lock and on the file underneath it.
                    if let Err(error) = Self::still_admitted(admission) {
                        Err(error)
                    } else {
                        match self.authority.issue(&planned.plan) {
                            Ok(written) => {
                                state.sessions.start(NewVoiceSession {
                                    voice_session_id,
                                    device_id,
                                    grant_id: written.grant_id,
                                    parent_grant_id: standing.grant_id,
                                    session_ids: session_ids.clone(),
                                    call_id: Some(session.call_id.clone()),
                                    provider: Some(Arc::clone(&provider)),
                                    started_at_ms: now_ms,
                                    closes_at_ms,
                                });
                                Ok(Some(written))
                            }
                            Err(error) => Err(error),
                        }
                    }
                }
                Ok(_) => Ok(None),
                Err(error) => Err(error),
            }
        };
        let written = match written {
            Ok(Some(written)) => written,
            // The voice grant this call was planned under is not the one this device holds any
            // more. Nothing was written, so nothing has to be unwound but the call itself.
            Ok(None) => {
                self.close_unbound(&provider, &session.call_id).await;
                return Ok(VoiceStartResult {
                    outcome: VoiceStartOutcome::Unavailable {
                        reason: "voice_grant_changed".to_owned(),
                        message: "this device's voice grant changed while the call was being \
                                  created, so the call was not kept. Start it again."
                            .to_owned(),
                        alternatives: vec!["Start the voice session again.".to_owned()],
                    },
                });
            }
            Err(error) => {
                self.close_unbound(&provider, &session.call_id).await;
                return Err(error);
            }
        };

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

    /// Marks one device as starting, when it is not already.
    ///
    /// `None` means a start for that device is already running, which is the answer the second
    /// one gets: a device holds one managed call, and two starts would be two pieces of authority
    /// over it.
    ///
    /// # Panics
    ///
    /// Panics when a thread holding the coordinator's lock panicked.
    fn begin_start(&self, device_id: DeviceId) -> Option<StartGate<'_>> {
        let mut state = self.state.lock().expect("the coordinator's state");
        state.starting.insert(device_id).then(|| StartGate {
            state: &self.state,
            device_id,
        })
    }

    /// Refuses a change whose admitted lifetime ran out before it reached its write.
    ///
    /// Section 9 gives every mutation a deadline the host accepted it under, and an effect that
    /// happens after it is an effect nobody is holding a window for any more. The reading is this
    /// host's own clock at the moment of the check.
    fn still_admitted(admission: &dyn Admission) -> Result<()> {
        if !admission.still_admitted() {
            return Err(VoiceError::Host(kr_protocol::error::ProtocolError::new(
                kr_protocol::error::ErrorCode::PermissionDenied,
                "the deadline this action was admitted under passed before it could run".to_owned(),
            )));
        }
        Ok(())
    }

    /// Closes the replayed calls this host deferred, now that nothing may be about to bind them.
    ///
    /// # Panics
    ///
    /// Panics when a thread holding the coordinator's lock panicked.
    async fn close_deferred(&self) {
        let closing: Vec<Ending> = {
            let mut state = self.state.lock().expect("the coordinator's state");
            if !state.starting.is_empty() || state.deferred.is_empty() {
                Vec::new()
            } else {
                let held: Vec<(String, Option<Arc<dyn ManagedVoiceService>>)> = state
                    .sessions
                    .iter()
                    .filter_map(|record| {
                        record
                            .call_id
                            .clone()
                            .map(|call_id| (call_id, record.provider.clone()))
                    })
                    .collect();
                // Everything leaves the list: a call somebody bound after all is theirs to stop,
                // and everything else is closed here, each through the provider that created it.
                // A call is the pair of its identifier and that provider, because two providers
                // can name a call the same thing.
                std::mem::take(&mut state.deferred)
                    .into_iter()
                    .filter(|ending| {
                        !held.iter().any(|(call_id, provider)| {
                            call_id == &ending.call_id
                                && match (provider.as_ref(), ending.provider.as_ref()) {
                                    (Some(held), Some(theirs)) => Arc::ptr_eq(held, theirs),
                                    _ => false,
                                }
                        })
                    })
                    .collect()
            }
        };
        for ending in &closing {
            if let Some(provider) = ending.provider.as_ref() {
                self.close_unbound(provider, &ending.call_id).await;
            }
        }
    }

    /// Whether a replayed call is one this host may close.
    ///
    /// Both questions are answered in one critical section, because a start records its session
    /// under the same lock: a call is left alone when a live voice session holds it, and when
    /// another device's start is still in flight and may be about to hold it.
    ///
    /// # Panics
    ///
    /// Panics when a thread holding the coordinator's lock panicked.
    fn may_close_replayed(
        &self,
        call_id: &str,
        provider: &Arc<dyn ManagedVoiceService>,
        device_id: DeviceId,
    ) -> bool {
        let state = self.state.lock().expect("the coordinator's state");
        // A call belongs to the provider that created it. Two providers can name a call the same
        // thing, so an identifier on its own says nothing about who holds it.
        let held = state.sessions.iter().any(|record| {
            record.call_id.as_deref() == Some(call_id)
                && record
                    .provider
                    .as_ref()
                    .is_some_and(|held| Arc::ptr_eq(held, provider))
        });
        let others_starting = state.starting.iter().any(|starting| *starting != device_id);
        !held && !others_starting
    }

    /// Ends a call this host could not bind to a voice session.
    ///
    /// Told, not waited on, and a service that cannot be reached is not an error the caller sees:
    /// the caller's own answer is already decided, and the service's deadline closes the call in
    /// any case. Nothing here retries creation.
    async fn close_unbound(&self, provider: &Arc<dyn ManagedVoiceService>, call_id: &str) {
        let _ = provider.close(call_id).await;
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
        let revoked_at_ms = match self.authority.revoke(record.grant_id, now_ms) {
            Ok(revoked_at_ms) => revoked_at_ms,
            // The voice session is already out of the registry, so nothing can use it, and this
            // record is the only thing that still knows which call it held. The call is finalised
            // before the failure is reported, or nothing would be able to finalise it afterwards.
            Err(error) => {
                if let (Some(provider), Some(call_id)) =
                    (record.provider.as_ref(), record.call_id.as_ref())
                {
                    self.close_unbound(provider, call_id).await;
                }
                return Err(error);
            }
        };

        let mut broker_notified = false;
        // Through the provider that created it, not through whatever this coordinator brokers
        // now: a service told to close a call it never created leaves the real one metering.
        if let (Some(provider), Some(call_id)) = (record.provider.as_ref(), record.call_id.as_ref())
        {
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
        // Checked again, now the read has finished, and at the moment of the check rather than at
        // the moment the request arrived. A read waits for the host; a stop, a grant change or
        // the call's own deadline during that wait withdraws the authority it was admitted under,
        // and what must not happen is *serving* that content, not reading it.
        let now_ms = self.authority.now_ms().max(now_ms);
        {
            let state = self.state.lock().expect("the coordinator's state");
            let record = state
                .sessions
                .of_device(params.voice_session_id, device_id)?;
            if !record.reaches(params.session_id) {
                return Err(VoiceError::refused(
                    VoiceRefusal::SessionOutsideVoiceSession,
                    "this voice session does not reach that session",
                ));
            }
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
        // And the selection is built under the narrower of the two as they stand now, so a scope
        // that narrowed while the host was reading narrows what comes back.
        let narrowed = narrower_history(&device_grant, &voice_grant);
        let selection = select_context(&gathered, &narrowed, &params.selected, &self.patterns);

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
        action_id: ActionId,
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
        // One action identifier is one delegation. Section 23 makes a delegation
        // action-deduplicated and its payload cannot be the key, because a confirmation is bound
        // to the request that asked for it: the signed resubmission is the same identifier
        // carrying a different payload. So the identifier is bound to the delegation it was first
        // used for, here, in the same critical section that spends the delegation.
        if record
            .action_used_for(action_id)
            .is_some_and(|held| held != delegation_id)
        {
            return Err(VoiceError::refused(
                VoiceRefusal::UnannouncedDelegation,
                "that action identifier was used for another delegation on this call",
            ));
        }
        record.announce(delegation_id.clone(), action_id);
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
        let digest = plan.digest()?;
        let mut state = self.state.lock().expect("the coordinator's state");
        state.ledger.sweep(now_ms);
        // One action, one challenge. Asking again for the same action of the same request returns
        // the challenge already outstanding for it, so a caller that never signs cannot make this
        // host issue an unbounded number of them.
        if let Some(existing) = state
            .ledger
            .outstanding_for(digest, action_id, device_id, now_ms)
        {
            return Ok(existing.clone());
        }
        drop(state);
        let request = issue_confirmation(plan, action_id, self.host_device_id, device_id, now_ms)?;
        let mut state = self.state.lock().expect("the coordinator's state");
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
            Ok(Proposed::NeedsConfirmation(request)) => Ok(VoiceDelegateResult {
                delegation_id: params.delegation_id.clone(),
                outcome: VoiceDelegationOutcome::ConfirmationRequired {
                    request,
                    message: format!(
                        "{} needs a confirmation on the unlocked screen of the paired device, \
                         signed by that device. A statement in the conversation that you agreed \
                         is not one. Sign this challenge and submit the same delegation again.",
                        params.action.as_str()
                    ),
                },
            }),
            Ok(Proposed::Ready(proposal)) => {
                let proposal = *proposal;
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
    ) -> Result<Proposed> {
        // 1 and 2: the call is this device's, and the delegation is on its timeline and unspent.
        // `announce` does both, and spends the identifier, so a second submission of the same
        // delegation cannot become a second action.
        self.announce(
            device_id,
            params.voice_session_id,
            &params.delegation_id,
            action_id,
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
                // The device has no other way to obtain the challenge this action needs, so the
                // answer to a first submission is the challenge itself. The delegation goes back
                // into this call's unspent set with it: the same delegation returns carrying the
                // proof and becomes one action, rather than being spent on an answer that
                // admitted nothing.
                let request = self.confirmation_challenge(device_id, &plan, action_id, now_ms)?;
                let mut state = self.state.lock().expect("the coordinator's state");
                if let Ok(record) = state
                    .sessions
                    .of_device_mut(params.voice_session_id, device_id)
                {
                    record.forget(&params.delegation_id);
                }
                return Ok(Proposed::NeedsConfirmation(Box::new(request)));
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
            // And the words themselves. The identifier says which session was named; this says
            // that what was said was agreement. Without it an empty string, or "do not send
            // that", would submit a prompt as readily as "yes, send it".
            if !is_clear_affirmative(&destination.spoken_text) {
                return Err(VoiceError::refused(
                    VoiceRefusal::DestinationNotNamed,
                    "the words on that confirmation are not a clear agreement to send it. Say \
                     the destination session and that it should go.",
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

        Ok(Proposed::Ready(Box::new(Proposal {
            voice_session_id: params.voice_session_id,
            device_id,
            voice_grant_id: voice_grant.grant_id,
            environment_id: self.environment_id,
            action: params.action,
            action_id,
            session_id: params.session_id.0,
            delegation_id: params.delegation_id.clone(),
            plan,
            approval: params.approval.0.clone(),
            turn_id: params.turn_id.0.clone(),
            destination: params.spoken_destination.0.clone(),
        })))
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
///
/// Public because the host reads a session under this scope too: an effect that reads content
/// answers under the same bound the context path applies, or it becomes the way round it.
#[must_use]
pub fn narrower_history(
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

/// Whether a spoken confirmation is a clear agreement.
///
/// Section 15 ¶13 asks for a clear spoken confirmation naming the destination session. The
/// destination is checked by identifier against the session the delegation acts on, above; this is
/// the other half, the words.
///
/// The vocabulary is short and closed on purpose. A host that accepted any string would accept
/// silence and would accept a refusal, and a host that tried to interpret a sentence would be
/// putting a language model between a person and their own authority — which is the thing section
/// 15 ¶8 forbids in the case that matters most. So: an explicit refusal in the words is refused
/// outright, and something that agrees has to be there.
///
/// What this is not. The words reach this host from the paired device, which is what transcribed
/// them, so they are content and never authority: the grant is what permits the effect, this
/// confirmation is the extra thing section 15 ¶13 asks for on top of it, and a host that is given
/// an accumulated transcript of its own can check more than this one can.
fn is_clear_affirmative(spoken: &str) -> bool {
    /// Words that agree.
    const AGREEING: &[&str] = &[
        "yes",
        "yeah",
        "yep",
        "yup",
        "affirmative",
        "confirm",
        "confirmed",
        "confirming",
        "send",
        "submit",
        "go",
        "ok",
        "okay",
        "sure",
        "correct",
        "right",
        "proceed",
        "please",
    ];
    /// Words that refuse, whatever else is in the sentence.
    const REFUSING: &[&str] = &[
        "no",
        "not",
        "don't",
        "dont",
        "never",
        "cancel",
        "stop",
        "wait",
        "nope",
        "negative",
        "nevermind",
    ];

    let mut words = spoken
        .split(|character: char| !(character.is_alphanumeric() || character == '\''))
        .filter(|word| !word.is_empty())
        .map(str::to_lowercase)
        .peekable();
    if words.peek().is_none() {
        return false;
    }
    let mut agrees = false;
    for word in words {
        if REFUSING.contains(&word.as_str()) {
            return false;
        }
        if AGREEING.contains(&word.as_str()) {
            agrees = true;
        }
    }
    agrees
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

    /// KR-REQ-15.21: a spoken confirmation has to be words that agree, so silence and a refusal
    /// both stop a prompt rather than submitting one.
    #[test]
    fn a_spoken_confirmation_has_to_agree() {
        assert!(is_clear_affirmative("yes, send it to the build session"));
        assert!(is_clear_affirmative("Send it."));
        assert!(is_clear_affirmative("okay go ahead"));

        assert!(!is_clear_affirmative(""));
        assert!(!is_clear_affirmative("   \n  "));
        assert!(!is_clear_affirmative("the build session"));
        assert!(!is_clear_affirmative("do not send that"));
        assert!(!is_clear_affirmative("don't send it"));
        assert!(!is_clear_affirmative("no, cancel"));
    }

    #[test]
    fn a_generated_identity_is_a_version_four_identifier() {
        let identity = new_identity().expect("an identity");
        let bytes = identity.as_bytes();
        assert_eq!(bytes[6] & 0xf0, 0x40);
        assert_eq!(bytes[8] & 0xc0, 0x80);
    }
}
