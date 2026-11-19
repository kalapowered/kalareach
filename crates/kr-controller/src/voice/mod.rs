//! The host's voice service: the coordinator, its seams and the five methods.
//!
//! `kr-voice` holds the rules and this module holds the host. The division is deliberate: the
//! coordinator depends on the protocol, the client and the cryptography and never on this daemon,
//! so what reaches it is what this module passes in. That is what makes the data boundary in
//! `docs/voice/README.md` something a reader can check by reading three implementations rather
//! than the whole daemon. One rule is this module's own and sits beside the seams rather than in
//! one of them: [`VoiceModule::read_frame`] gives a context read only while privacy mode is in
//! the state the read began in, because the text a read carries from the description host leaves
//! with the answer and not with the read.
//!
//! | Seam | What this module gives it |
//! | --- | --- |
//! | `ContextSource` | Session facts, every item filtered at `Surface::VoiceContext` under a viewer scope built from the requesting device's grant |
//! | `VoiceAuthority` | The grant store this host already keeps, and the device record that holds the identity key a confirmation is checked against |
//! | `ActionSubmitter` | The host's own dispatch, which validates a spoken proposal exactly as a typed one |
//!
//! Nothing here reaches the managed broker with content. The broker client is used to read the terms
//! the service publishes, and to create and to end a call; selected context and host results go
//! back to the paired client, which is what sends them.

mod authority;
mod context;
mod credentials;
mod host;
mod host_call;
pub mod own_key_calls;
#[cfg(feature = "testing")]
pub mod own_key_hooks;
mod submit;
mod worker_half;

use std::sync::Arc;

use kr_protocol::envelope::{
    ControlFrame, MutationRequest, Outcome, ParamsValue, Request, Response,
};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::ids::{ActionId, AuthorityRevision, DeviceId, EnvironmentId};
use kr_protocol::method::Method;
use kr_voice::Coordinator;
use kr_voice::broker::{ManagedVoiceBroker, ServiceHttp, VoiceProviderService};

pub use authority::GrantAuthority;
pub use context::{
    FilteredContext, SessionFacts, SessionSnapshot, filtered, snapshot_of, snapshot_with,
};
pub use credentials::{OwnKey, VoiceCredentials};
pub use host::{ControllerDispatch, ControllerFacts};
pub use host_call::{
    ContextSelected, DelegationKind, DelegationRecord, FINAL_STATUS_KEEP_MS, FINAL_STATUS_RECORDS,
    FinalStatus, HostCall, HostCalls, NoteSupport, SendSupport, performed_words,
};
pub use submit::{HostDispatch, ProposalSubmitter, method_for};
pub use worker_half::{
    BEFORE_PRIVACY_CHANGE, MAX_HISTORY_PARTS, PRIVACY_ON, WorkerHalf, approval, decisions, message,
    messages, question,
};

use crate::error::{ControllerError, Result};

/// Who is asking, as this host resolved the actor.
///
/// Section 23 gives four of the five voice methods `PairedDevice` ingress and gives `voice.grant`
/// both: a device changes its own voice grant, and the person at this machine changes a device's.
/// The distinction is here rather than inside the coordinator, because it is a fact about the
/// connection the request arrived on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VoiceActor {
    /// A paired device, acting as itself over its own authenticated connection.
    Device(DeviceId),
    /// The person at this machine, on the host's own socket.
    Owner,
}

impl VoiceActor {
    /// The device this actor acts as, when it is one.
    #[must_use]
    pub const fn device(self) -> Option<DeviceId> {
        match self {
            Self::Device(device_id) => Some(device_id),
            Self::Owner => None,
        }
    }
}

/// How many times a read of a session's context is made when privacy mode changes while it is
/// made. The first read is the one that is given unless privacy mode moved; each read after it is
/// made under the state then in force.
const CONTEXT_READS: usize = 3;

/// The environment's voice service.
#[derive(Debug)]
pub struct VoiceModule {
    coordinator: Coordinator,
    /// Where the coordinator reads a session, which also says whether privacy mode moved while it
    /// did.
    facts: Arc<dyn SessionFacts>,
    /// The managed broker's origin the coordinator was built with, empty where there is none.
    ///
    /// Kept beside the coordinator so `kr doctor` reports the broker this service is actually
    /// naming to devices, rather than what some other record says it should be.
    broker_origin: String,
    /// The calls on the owner's own key that this host controls itself: the phone's heartbeats,
    /// its notes and the news it has not yet been told.
    host_calls: HostCalls,
    /// Whether the tick that watches those calls is running.
    ticking: std::sync::atomic::AtomicBool,
    /// The time the voice service's own tasks decide on. The daemon sets its settled clock.
    clock: Clock,
}

/// A source of the current time, in milliseconds since the epoch.
#[derive(Clone)]
pub struct Clock(Arc<dyn Fn() -> u64 + Send + Sync>);

impl Clock {
    /// A clock that reads `read`.
    pub fn new(read: impl Fn() -> u64 + Send + Sync + 'static) -> Self {
        Self(Arc::new(read))
    }

    /// The time now.
    #[must_use]
    pub fn now_ms(&self) -> u64 {
        (self.0)()
    }
}

impl std::fmt::Debug for Clock {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Clock")
    }
}

impl VoiceModule {
    /// Builds the service over this host's own stores and connections.
    ///
    /// `broker_origin` is the managed broker the configuration document's voice section names,
    /// which a started session's descriptor tells the device, and empty where it names none. It
    /// is a provider origin, so the daemon takes it from that document and never from the
    /// environment it inherited.
    #[must_use]
    pub fn new(
        facts: Arc<dyn SessionFacts>,
        authority: Arc<GrantAuthority>,
        dispatch: Arc<dyn HostDispatch>,
        provider: Option<Arc<dyn VoiceProviderService>>,
        host_device_id: DeviceId,
        environment_id: EnvironmentId,
        broker_origin: String,
    ) -> Self {
        let host_calls = HostCalls::new();
        let coordinator = Coordinator::new(
            Arc::new(FilteredContext::new(Arc::clone(&facts))),
            authority,
            Arc::new(ProposalSubmitter::new(dispatch)),
            provider,
            host_device_id,
            environment_id,
            broker_origin.clone(),
        );
        // A call that is ending is told to the call object before its grant goes, so a phone that
        // asks afterwards learns why it ended.
        let ending = host_calls.clone();
        coordinator.on_call_end(Arc::new(move |voice_session_id, reason, now_ms| {
            ending.end(voice_session_id, reason, now_ms);
        }));
        Self {
            facts,
            coordinator,
            broker_origin,
            host_calls,
            ticking: std::sync::atomic::AtomicBool::new(false),
            clock: Clock::new(|| kr_ipc::now_ms().get()),
        }
    }

    /// Replaces the clock the voice service's own tasks decide on.
    #[must_use]
    pub fn with_clock(mut self, clock: Clock) -> Self {
        self.clock = clock;
        self
    }

    /// Takes the one place for the tick that watches the calls the host controls itself. Says
    /// whether it was free; the caller that takes it runs the tick and gives the place back.
    pub fn claim_tick(&self) -> bool {
        self.ticking
            .compare_exchange(
                false,
                true,
                std::sync::atomic::Ordering::SeqCst,
                std::sync::atomic::Ordering::SeqCst,
            )
            .is_ok()
    }

    /// Gives the tick's place back.
    pub fn release_tick(&self) {
        self.ticking
            .store(false, std::sync::atomic::Ordering::SeqCst);
    }

    /// The calls on the owner's own key that this host controls itself.
    #[must_use]
    pub const fn host_calls(&self) -> &HostCalls {
        &self.host_calls
    }

    /// One pass of the voice service's own tick, at `now_ms`.
    ///
    /// While the host holds a call on the owner's own key it ends the calls that are over at their
    /// deadline, with or without an account, and begins the closure of each call whose phone has
    /// not been heard from for [`kr_protocol::voice_host::HOST_CLIENT_ABSENT_SECONDS`], as a stop
    /// would (the grant first, then the provider). A host with no such call does nothing.
    pub async fn tick(&self, now_ms: u64) {
        if self.host_calls.is_empty() {
            return;
        }
        for voice_session_id in self.host_calls.tick(now_ms).await {
            self.coordinator
                .end_call(
                    voice_session_id,
                    kr_protocol::voice_host::VoiceEndReason::Silence,
                    now_ms,
                )
                .await;
        }
        self.coordinator.end_calls_that_are_over(now_ms).await;
    }

    /// Ends every call the host controls itself, as a stop would (the grant first, then the
    /// provider), for `reason`.
    pub async fn end_host_calls(
        &self,
        reason: kr_protocol::voice_host::VoiceEndReason,
        now_ms: u64,
    ) {
        for voice_session_id in self.host_calls.voice_session_ids() {
            self.coordinator
                .end_call(voice_session_id, reason, now_ms)
                .await;
        }
    }

    /// The managed broker's origin this service names to a device whose voice session starts,
    /// or an empty string where it names none.
    #[must_use]
    pub fn broker_origin(&self) -> &str {
        &self.broker_origin
    }

    /// Builds the managed broker client for the origin the configuration document names,
    /// presenting the account token `tokens` holds for it.
    ///
    /// # Errors
    ///
    /// Returns why the broker client refuses the origin. The caller reports it and attaches no
    /// provider, so that the host still starts.
    pub fn managed_provider(
        origin: &str,
        http: Arc<dyn ServiceHttp>,
        tokens: Arc<dyn kr_client::services::AccountTokenSource>,
    ) -> std::result::Result<Arc<dyn VoiceProviderService>, kr_client::ClientError> {
        Ok(Arc::new(ManagedVoiceBroker::new(origin, http, tokens)?))
    }

    /// Replaces the provider this service brokers through.
    ///
    /// A caller with a provider of its own, a backend of the person's own or a stand-in, builds the
    /// service with it here. Nothing above the seam knows which one answered.
    #[must_use]
    pub fn with_provider(mut self, provider: Option<Arc<dyn VoiceProviderService>>) -> Self {
        self.coordinator = self.coordinator.with_provider(provider);
        self
    }

    /// Attaches a provider to the service this host has already registered.
    ///
    /// The daemon builds the managed broker itself when its configuration document names one, so
    /// this is for a provider that document cannot name: a backend of the person's own, or a
    /// stand-in. Until a provider is attached this host brokers no managed call, which is a
    /// complete host and says so.
    pub fn attach_provider(&self, provider: Option<Arc<dyn VoiceProviderService>>) {
        self.coordinator.attach_provider(provider);
    }

    /// The coordinator, for a caller that needs it directly.
    ///
    /// A context read made through it carries no hold against privacy mode being enabled while it
    /// is made: the daemon's own reads go through [`Self::read_frame`].
    #[must_use]
    pub const fn coordinator(&self) -> &Coordinator {
        &self.coordinator
    }

    /// Returns true when this service serves `method`.
    #[must_use]
    pub const fn serves(method: Method) -> bool {
        matches!(
            method,
            Method::VoiceStart
                | Method::VoiceStop
                | Method::VoiceGrant
                | Method::VoiceDelegate
                | Method::VoiceContext
                | Method::VoicePrepare
                | Method::VoiceControl
                | Method::VoiceContextSend
        )
    }

    /// Checks that a voice mutation's envelope and its parameters name the same subject.
    ///
    /// A voice session belongs to this host rather than to one terminal session, so a voice
    /// mutation names the environment. The session a delegation acts on is read by the coordinator
    /// from the words in the parameters, and checked against what the voice session may reach.
    ///
    /// # Errors
    ///
    /// Returns an error when the envelope names a session, or the parameters are not the shape the
    /// method declares.
    pub fn check_subject(method: Method, mutation: &MutationRequest) -> Result<()> {
        if mutation.target.session_id.as_ref().is_some() {
            return Err(ControllerError::InvalidArgument(
                "a voice session belongs to this host, not to one terminal session".to_owned(),
            ));
        }
        match method {
            Method::VoiceStart => {
                let _: kr_protocol::voice::VoiceStartParams = parse(&mutation.params)?;
            }
            Method::VoiceStop => {
                let _: kr_protocol::voice::VoiceStopParams = parse(&mutation.params)?;
            }
            Method::VoiceGrant => {
                let _: kr_protocol::voice::VoiceGrantParams = parse(&mutation.params)?;
            }
            Method::VoiceDelegate => {
                let _: kr_protocol::voice::VoiceDelegateParams = parse(&mutation.params)?;
            }
            Method::VoiceControl => {
                let _: kr_protocol::voice_host::VoiceControlParams = parse(&mutation.params)?;
            }
            Method::VoiceContextSend => {
                let _: kr_protocol::voice_host::VoiceContextSendParams = parse(&mutation.params)?;
            }
            _ => {
                return Err(ControllerError::InvalidArgument(format!(
                    "{} is not a voice mutation",
                    method.as_str()
                )));
            }
        }
        Ok(())
    }

    /// Answers one of the two voice reads.
    ///
    /// `voice.prepare` describes a call before one exists and creates nothing; `voice.context`
    /// selects what a running call may be told. Both are this device's, under its own grants.
    pub async fn read_frame(&self, device_id: DeviceId, request: &Request) -> ControlFrame {
        let outcome = async {
            match request.method.method() {
                Some(Method::VoicePrepare) => {
                    let params: kr_protocol::voice::VoicePrepareParams = parse(&request.params)?;
                    value(
                        &self
                            .coordinator
                            .prepare(device_id, &params)
                            .await
                            .map_err(voice_error)?,
                    )
                }
                Some(Method::VoiceContext) => {
                    let params: kr_protocol::voice::VoiceContextParams = parse(&request.params)?;
                    value(&self.context_unmoved(device_id, &params).await?)
                }
                _ => Err(ControllerError::InvalidArgument(format!(
                    "{} is not a voice read",
                    request.method.as_str()
                ))),
            }
        }
        .await;
        frame(request.request_id, outcome)
    }

    /// Reads what a running call may be told of a session, and answers only with a reading that
    /// privacy mode did not move under.
    ///
    /// The context carries what a model wrote of the session and what the description host
    /// observed, and privacy mode removes both when it is enabled. A reading is made after the
    /// state is noted, and it is given only if privacy mode is still in that state when it ends:
    /// otherwise it is made again, under the state now in force, which carries neither while
    /// privacy mode is on. A device's answer is checked once, when the read ends, and privacy mode
    /// can be enabled between that check and the write; an answer the privacy state keeps moving
    /// under is refused for the device to ask again.
    async fn context_unmoved(
        &self,
        device_id: DeviceId,
        params: &kr_protocol::voice::VoiceContextParams,
    ) -> Result<kr_protocol::voice::VoiceContextResult> {
        for _ in 0..CONTEXT_READS {
            let decided = self.facts.privacy();
            let read = self
                .coordinator
                .context(device_id, params)
                .await
                .map_err(voice_error)?;
            if self.facts.unmoved(decided) {
                return Ok(read);
            }
        }
        Err(ControllerError::Refused {
            code: ErrorCode::ResourceUnavailable,
            detail: "privacy mode changed while the context was read, so none was sent; ask again"
                .to_owned(),
        })
    }

    /// Answers one of the four voice mutations.
    ///
    /// # Errors
    ///
    /// Returns the refusal the caller is given. The caller of this is the one that claims a voice
    /// change and retains what it produced, so this performs the effect once for that claim. A
    /// delegation is claimed like the others, and the coordinator spends the delegation's own
    /// identifier as well, so the same delegation under another action is not a second action.
    pub async fn answer(
        self: &Arc<Self>,
        actor: VoiceActor,
        mutation: &MutationRequest,
        method: Method,
        authority_revision: AuthorityRevision,
        now_ms: u64,
        admission: &Arc<dyn kr_voice::Admission>,
    ) -> Result<ParamsValue> {
        self.dispatch(
            actor,
            mutation,
            method,
            authority_revision,
            now_ms,
            admission,
        )
        .await
    }

    /// Answers a delegation this host has already answered, once more, from what stands now.
    ///
    /// The caller has found the delegation's retained answer and decided that the action is a read
    /// of this host's own state, which can be read again ([`Coordinator::restate`]).
    ///
    /// # Errors
    ///
    /// Returns the refusal the checks give: the call has ended, or the authority it ran under no
    /// longer carries the action.
    pub async fn answer_again(
        &self,
        device_id: DeviceId,
        mutation: &MutationRequest,
        kept: &kr_protocol::voice::VoiceDelegateResult,
        now_ms: u64,
    ) -> Result<ParamsValue> {
        let params: kr_protocol::voice::VoiceDelegateParams = parse(&mutation.params)?;
        value(
            &self
                .coordinator
                .restate(device_id, mutation.action_id, &params, kept, now_ms)
                .await
                .map_err(voice_error)?,
        )
    }

    /// Takes a call the host controls itself into the registry that answers its heartbeats.
    fn hold_a_host_call(
        &self,
        device_id: DeviceId,
        started: &kr_protocol::voice::VoiceStartResult,
    ) {
        use kr_protocol::voice::{VoiceSessionControl, VoiceStartOutcome};
        let VoiceStartOutcome::Started { session } = &started.outcome else {
            return;
        };
        if !matches!(session.control, VoiceSessionControl::Host { .. }) {
            return;
        }
        // The coordinator refuses a start whose provider has no side channel for the call, so a
        // host call that was started has one.
        if let Ok(target) = self
            .coordinator
            .host_call_target(device_id, session.voice_session_id)
        {
            self.host_calls.register(
                session.voice_session_id,
                device_id,
                target.started_at_ms,
                target.closes_at_ms,
                target.control,
            );
        }
    }

    /// Answers `voice.control` for a call the host controls itself.
    async fn control(
        &self,
        device_id: DeviceId,
        action_id: ActionId,
        params: &kr_protocol::voice_host::VoiceControlParams,
        now_ms: u64,
    ) -> kr_protocol::voice_host::VoiceControlResult {
        use kr_protocol::voice_host::{VoiceControlArm, VoiceControlResult};
        let call = match self
            .host_calls
            .of_device(params.voice_session_id, device_id)
        {
            Ok(call) => call,
            // A call that ended answers a heartbeat from its final status; everything else about
            // it is over.
            Err(reason) => {
                return match params.arm {
                    VoiceControlArm::Heartbeat { after_seq } => self.host_calls.heartbeat(
                        params.voice_session_id,
                        device_id,
                        after_seq.get(),
                        now_ms,
                    ),
                    _ => VoiceControlResult::Refused { reason },
                };
            }
        };
        match &params.arm {
            VoiceControlArm::Heartbeat { after_seq } => {
                call.phone_is_back(now_ms).await;
                self.host_calls.heartbeat(
                    params.voice_session_id,
                    device_id,
                    after_seq.get(),
                    now_ms,
                )
            }
            VoiceControlArm::Mute { muted } => call.mute(action_id, *muted, now_ms).await,
            VoiceControlArm::Note {
                note,
                delegation_id,
            } => {
                let support = ReadAgain {
                    coordinator: &self.coordinator,
                    facts: &*self.facts,
                    decided: self.facts.privacy(),
                    device_id,
                    now_ms,
                };
                call.note(
                    action_id,
                    *note,
                    delegation_id.0.as_ref().map(|id| id.as_str()),
                    &support,
                    now_ms,
                )
                .await
            }
            VoiceControlArm::Heard { delegation_id } => {
                call.heard(delegation_id.as_str(), now_ms).await
            }
        }
    }

    /// Answers `voice.context.send`: the selection goes to the model in paced appends, by the call
    /// object's own sender.
    async fn context_send(
        self: &Arc<Self>,
        device_id: DeviceId,
        action_id: ActionId,
        params: &kr_protocol::voice_host::VoiceContextSendParams,
        now_ms: u64,
    ) -> kr_protocol::voice_host::VoiceContextSendResult {
        use kr_protocol::voice_host::VoiceContextSendResult;
        match self
            .host_calls
            .of_device(params.voice_session_id, device_id)
        {
            Ok(call) => {
                let support = Arc::new(ModuleSend {
                    module: Arc::clone(self),
                    device_id,
                });
                call.send_context(action_id, params.clone(), support, now_ms)
                    .await
            }
            Err(reason) => VoiceContextSendResult::Refused { reason },
        }
    }

    async fn dispatch(
        self: &Arc<Self>,
        actor: VoiceActor,
        mutation: &MutationRequest,
        method: Method,
        authority_revision: AuthorityRevision,
        now_ms: u64,
        admission: &Arc<dyn kr_voice::Admission>,
    ) -> Result<ParamsValue> {
        let action_id: ActionId = mutation.action_id;
        let device_of = |actor: VoiceActor| {
            actor
                .device()
                .ok_or_else(|| ControllerError::PermissionDenied {
                    detail: "this voice method is reachable from a paired device".to_owned(),
                })
        };
        match method {
            Method::VoiceGrant => {
                let params: kr_protocol::voice::VoiceGrantParams = parse(&mutation.params)?;
                // Three cases, which are the registry's own two conditions. A device changes its
                // own voice grant, which is the resource owner acting on its own subject. The
                // person at this machine changes any device's, which is what the host's own socket
                // is. A device changing another device's needs host management, and this host does
                // not yet resolve that right for a device, so it is refused rather than guessed
                // at.
                if let Some(device_id) = actor.device()
                    && params.device_id != device_id
                {
                    return Err(ControllerError::PermissionDenied {
                        detail: "a device changes its own voice grant; changing another device's \
                                 needs host-management authority"
                            .to_owned(),
                    });
                }
                value(
                    &self
                        .coordinator
                        .grant(&params, authority_revision, now_ms, &**admission)
                        .await
                        .map_err(voice_error)?,
                )
            }
            Method::VoiceStart => {
                let params: kr_protocol::voice::VoiceStartParams = parse(&mutation.params)?;
                let device_id = device_of(actor)?;
                let started = self
                    .coordinator
                    .start(
                        device_id,
                        mutation.action_id,
                        &params,
                        authority_revision,
                        now_ms,
                        &**admission,
                    )
                    .await
                    .map_err(voice_error)?;
                self.hold_a_host_call(device_id, &started);
                value(&started)
            }
            Method::VoiceStop => {
                let params: kr_protocol::voice::VoiceStopParams = parse(&mutation.params)?;
                value(
                    &self
                        .coordinator
                        .stop(device_of(actor)?, &params, now_ms)
                        .await
                        .map_err(stop_error)?,
                )
            }
            Method::VoiceDelegate => {
                let params: kr_protocol::voice::VoiceDelegateParams = parse(&mutation.params)?;
                let device_id = device_of(actor)?;
                // A call the host controls itself is one whose side channel heard what the model
                // said: an identifier it never heard is not a delegation of this call.
                if let Ok(call) = self
                    .host_calls
                    .of_device(params.voice_session_id, device_id)
                    && !call.announced(params.delegation_id.as_str()).await
                {
                    return Err(voice_error(kr_voice::VoiceError::refused(
                        kr_protocol::voice::VoiceRefusal::UnannouncedDelegation,
                        "the provider never announced that delegation to this call",
                    )));
                }
                let answered = self
                    .coordinator
                    .delegate(device_id, action_id, &params, now_ms, admission)
                    .await
                    .map_err(voice_error)?;
                // What a note about this delegation's outcome is checked against, for a call the
                // host controls itself.
                if let Ok(call) = self
                    .host_calls
                    .of_device(params.voice_session_id, device_id)
                {
                    call.record_delegation(
                        params.delegation_id.as_str(),
                        DelegationRecord {
                            delegate_action_id: action_id,
                            params: params.clone(),
                            kept: answered.clone(),
                        },
                    );
                }
                value(&answered)
            }
            Method::VoiceControl => {
                let params: kr_protocol::voice_host::VoiceControlParams = parse(&mutation.params)?;
                value(
                    &self
                        .control(device_of(actor)?, action_id, &params, now_ms)
                        .await,
                )
            }
            Method::VoiceContextSend => {
                let params: kr_protocol::voice_host::VoiceContextSendParams =
                    parse(&mutation.params)?;
                value(
                    &self
                        .context_send(device_of(actor)?, action_id, &params, now_ms)
                        .await,
                )
            }
            _ => Err(ControllerError::InvalidArgument(format!(
                "{} is not a voice mutation",
                method.as_str()
            ))),
        }
    }
}

/// What a note about a performed delegation reads again: the coordinator's own re-read, under the
/// grants, the history bound and privacy mode as they stand now.
struct ReadAgain<'a> {
    coordinator: &'a Coordinator,
    facts: &'a dyn SessionFacts,
    /// Privacy mode as it stood when the note's request began; a read that privacy mode moved under
    /// is not given.
    decided: crate::privacy::Published,
    device_id: DeviceId,
    now_ms: u64,
}

/// What the host tells a device when the read behind a note failed, by what failed: a grant or the
/// history bound that no longer allows it is `outside_grant`, and a host that could not say is
/// `not_ready`, which keeps the note owed.
fn refusal_of_the_read(error: &kr_voice::VoiceError) -> kr_protocol::voice_host::VoiceHostRefusal {
    use kr_protocol::voice_host::VoiceHostRefusal;
    match error {
        kr_voice::VoiceError::Refused { .. } => VoiceHostRefusal::OutsideGrant,
        _ => VoiceHostRefusal::NotReady,
    }
}

impl NoteSupport for ReadAgain<'_> {
    fn fresh_summary<'a>(
        &'a self,
        record: &'a DelegationRecord,
    ) -> kr_client::services::host_call::HostFuture<
        'a,
        std::result::Result<String, kr_protocol::voice_host::VoiceHostRefusal>,
    > {
        use kr_protocol::voice_host::VoiceHostRefusal;
        Box::pin(async move {
            let again = self
                .coordinator
                .restate(
                    self.device_id,
                    record.delegate_action_id,
                    &record.params,
                    &record.kept,
                    self.now_ms,
                )
                .await
                .map_err(|error| refusal_of_the_read(&error))?;
            // Privacy mode removes what a model wrote and what the host observed: a read it moved
            // under is not given.
            if !self.facts.unmoved(self.decided) {
                return Err(VoiceHostRefusal::Privacy);
            }
            match again.outcome {
                kr_protocol::voice::VoiceDelegationOutcome::Performed { summary, .. } => {
                    Ok(summary)
                }
                _ => Err(VoiceHostRefusal::OutsideGrant),
            }
        })
    }

    fn allowed_now<'a>(
        &'a self,
        record: &'a DelegationRecord,
    ) -> kr_client::services::host_call::HostFuture<
        'a,
        std::result::Result<(), kr_protocol::voice_host::VoiceHostRefusal>,
    > {
        use kr_protocol::voice_host::VoiceHostRefusal;
        Box::pin(async move {
            self.coordinator
                .allows_restate(
                    self.device_id,
                    record.delegate_action_id,
                    &record.params,
                    &record.kept,
                    self.now_ms,
                )
                .await
                .map_err(|error| refusal_of_the_read(&error))?;
            if self.facts.unmoved(self.decided) {
                Ok(())
            } else {
                Err(VoiceHostRefusal::Privacy)
            }
        })
    }
}

/// What a call's context sender reads of this host: the coordinator's selection and its checks, and
/// privacy mode, under the device that owns the call.
struct ModuleSend {
    module: Arc<VoiceModule>,
    device_id: DeviceId,
}

/// The stop a failed check of a running send is.
fn stop_of_the_check(error: &kr_voice::VoiceError) -> kr_protocol::voice_host::VoiceContextStop {
    use kr_protocol::voice::VoiceRefusal;
    use kr_protocol::voice_host::VoiceContextStop;
    match error.reason() {
        // The call is gone: what ended it is told as the call's own end.
        Some(VoiceRefusal::UnknownVoiceSession) => VoiceContextStop::Stop,
        _ => VoiceContextStop::Grant,
    }
}

impl SendSupport for ModuleSend {
    fn now_ms(&self) -> u64 {
        self.module.clock.now_ms()
    }

    fn select<'a>(
        &'a self,
        params: &'a kr_protocol::voice_host::VoiceContextSendParams,
    ) -> kr_client::services::host_call::HostFuture<
        'a,
        std::result::Result<ContextSelected, kr_protocol::voice_host::VoiceHostRefusal>,
    > {
        use kr_protocol::voice_host::VoiceHostRefusal;
        Box::pin(async move {
            let read = kr_protocol::voice::VoiceContextParams {
                voice_session_id: params.voice_session_id,
                session_id: params.session_id,
                selected: params.selected.clone(),
                delegation_id: params.delegation_id.clone(),
            };
            // The same rule as `voice.context`: a reading that privacy mode moved under is made
            // again, and given up on when it keeps moving.
            for _ in 0..CONTEXT_READS {
                let decided = self.module.facts.privacy();
                let lower_bound_ms = self
                    .module
                    .coordinator
                    .context_allowed(self.device_id, params.voice_session_id, params.session_id)
                    .map_err(|error| refusal_of_the_read(&error))?;
                let result = self
                    .module
                    .coordinator
                    .context(self.device_id, &read)
                    .await
                    .map_err(|error| refusal_of_the_read(&error))?;
                if self.module.facts.unmoved(decided) {
                    return Ok(ContextSelected {
                        selection: result.selection,
                        lower_bound_ms,
                        decided,
                    });
                }
            }
            Err(VoiceHostRefusal::Privacy)
        })
    }

    fn still_allowed<'a>(
        &'a self,
        params: &'a kr_protocol::voice_host::VoiceContextSendParams,
        selected: &'a ContextSelected,
    ) -> kr_client::services::host_call::HostFuture<
        'a,
        std::result::Result<(), kr_protocol::voice_host::VoiceContextStop>,
    > {
        use kr_protocol::voice_host::VoiceContextStop;
        Box::pin(async move {
            let bound = self
                .module
                .coordinator
                .context_allowed(self.device_id, params.voice_session_id, params.session_id)
                .map_err(|error| stop_of_the_check(&error))?;
            // A bound that moved later hides history the selection already holds.
            if bound.unwrap_or(0) > selected.lower_bound_ms.unwrap_or(0) {
                return Err(VoiceContextStop::History);
            }
            if !self.module.facts.unmoved(selected.decided) {
                return Err(VoiceContextStop::Privacy);
            }
            Ok(())
        })
    }
}

/// Reads one request's parameters.
fn parse<T: kr_protocol::wire::WireMessage>(params: &ParamsValue) -> Result<T> {
    params
        .to_typed()
        .map_err(|error| ControllerError::InvalidArgument(error.to_string()))
}

/// Writes one result.
fn value<T: serde::Serialize>(result: &T) -> Result<ParamsValue> {
    ParamsValue::from_typed(result)
        .map_err(|error| ControllerError::InvalidArgument(error.to_string()))
}

/// The daemon error one coordinator refusal becomes.
fn voice_error(error: kr_voice::VoiceError) -> ControllerError {
    let protocol = error.to_protocol_error();
    match protocol.code {
        ErrorCode::PermissionDenied => ControllerError::PermissionDenied {
            detail: protocol.message,
        },
        ErrorCode::InvalidArgument => ControllerError::InvalidArgument(protocol.message),
        ErrorCode::HostNotConfigured => ControllerError::NotConfigured(protocol.message),
        _ => ControllerError::Refused {
            code: protocol.code,
            detail: protocol.message,
        },
    }
}

/// The daemon error a refused stop becomes.
///
/// A voice session this host holds no record of (it ended, the host started again, or it is
/// another device's) is refused as an unknown session: a device that could not finish revoking its
/// call's grant asks again when it reaches this host, and that answer tells it there is nothing
/// left there to stop. It says nothing of a grant or of the fence this host owes its workers, which
/// this host keeps to itself. Every other refusal keeps its code, because none of them says the
/// grant is gone: the door answers `PERMISSION_DENIED` before it looks at the call.
fn stop_error(error: kr_voice::VoiceError) -> ControllerError {
    if error.reason() == Some(kr_protocol::voice::VoiceRefusal::UnknownVoiceSession) {
        return ControllerError::Refused {
            code: ErrorCode::UnknownSession,
            detail: error.to_protocol_error().message,
        };
    }
    voice_error(error)
}

/// The frame one answer becomes.
fn frame(request_id: kr_protocol::ids::RequestId, outcome: Result<ParamsValue>) -> ControlFrame {
    ControlFrame::Response(Response {
        request_id,
        outcome: match outcome {
            Ok(value) => Outcome::Ok(value),
            Err(error) => Outcome::Error(ProtocolError::new(error.code(), error.to_string())),
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_client::services::ServiceHeader;
    use kr_protocol::hostinfo::configuration::{self, ConfigurationDocument};
    use kr_protocol::scalars::Nullable;

    /// A performed note's re-read that failed is told by what failed: a refusal of a grant or of the
    /// history bound is `outside_grant`, and a host that could not say is `not_ready`, which keeps
    /// the note owed.
    #[test]
    fn a_re_read_that_failed_is_told_by_what_failed() {
        use kr_protocol::voice::VoiceRefusal;
        use kr_protocol::voice_host::VoiceHostRefusal;
        for reason in [
            VoiceRefusal::OutsideVoiceGrant,
            VoiceRefusal::OutsideDeviceGrant,
            VoiceRefusal::SessionOutsideVoiceSession,
            VoiceRefusal::UnknownVoiceSession,
        ] {
            assert_eq!(
                refusal_of_the_read(&kr_voice::VoiceError::refused(reason, "refused")),
                VoiceHostRefusal::OutsideGrant,
                "{reason:?}"
            );
        }
        for error in [
            kr_voice::VoiceError::InvalidArgument("only a read is answered again".to_owned()),
            kr_voice::VoiceError::NotConfigured("no voice service".to_owned()),
            kr_voice::VoiceError::Host(ProtocolError::new(
                ErrorCode::ResourceUnavailable,
                "the host could not say",
            )),
        ] {
            assert_eq!(
                refusal_of_the_read(&error),
                VoiceHostRefusal::NotReady,
                "{error}"
            );
        }
    }

    /// An exchange that is never made: building a broker client does not reach the network.
    #[derive(Debug)]
    struct NoExchange;

    impl ServiceHttp for NoExchange {
        fn post_json<'a>(
            &'a self,
            _url: &'a str,
            _body: &'a [u8],
            _headers: &'a [ServiceHeader<'a>],
        ) -> kr_client::services::ServiceFuture<'a, kr_voice::broker::ServiceHttpAnswer> {
            Box::pin(std::future::pending())
        }
    }

    /// A token source that is never asked: building a broker client presents no token.
    #[derive(Debug)]
    struct NoToken;

    impl kr_client::services::AccountTokenSource for NoToken {
        fn token<'a>(
            &'a self,
            _scope: &'a str,
        ) -> kr_client::services::ServiceFuture<'a, kr_client::services::AccountToken> {
            Box::pin(std::future::pending())
        }
    }

    /// KR-REQ-26.14: a broker origin the configuration document accepts is one the managed broker
    /// accepts, so a device is never handed an origin its own client would refuse.
    ///
    /// The origins the document refuses are here too, so a rule loosened on one side and not the
    /// other fails this.
    #[test]
    fn every_broker_origin_the_document_accepts_is_one_the_broker_accepts() {
        let corpus = [
            "https://voice.example.com",
            "https://voice.example.com:8443",
            "http://127.0.0.1:8080",
            "http://[::1]:8080",
            "https://[2001:db8::1]",
            "https://voice.example:0443",
            "http://127.1",
            "http://[0:0:0:0:0:0:0:1]",
            "https://a1.be",
            "https://Voice.example.com",
            "https://voice.example.com/",
            "https://xn--zz.example",
            "http://voice.example.com",
        ];
        let mut accepted = 0;
        for origin in corpus {
            let mut document = ConfigurationDocument::empty();
            document.voice.broker_origin = Nullable::some(origin.to_owned());
            if configuration::validate(&document).is_err() {
                continue;
            }
            accepted += 1;
            assert!(
                VoiceModule::managed_provider(origin, Arc::new(NoExchange), Arc::new(NoToken))
                    .is_ok(),
                "{origin} validated and the managed broker refused it"
            );
            assert!(
                kr_protocol::service::GatewayOrigin::new(origin).is_ok(),
                "{origin} validated and the transport that reaches it refused it"
            );
        }
        assert_eq!(
            accepted, 5,
            "the first five origins are the ones the schema accepts"
        );
    }
}
