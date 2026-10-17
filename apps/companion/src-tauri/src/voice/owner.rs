//! The task that owns one call from the moment it is asked for to the moment it is over.
//!
//! One task, so that nothing about a call is decided in two places: it reads the news native code
//! tells, the control's news, the person's commands and the clock, and it ends the call by one
//! procedure whatever the cause. The steps of a start run in it too, so a page that is loaded
//! again, a command that is dropped or a news item that arrives in the middle of a step changes
//! nothing about who ends the call.
//!
//! # What a start does, in order
//!
//! The account's token for the voice scope is checked before anything is created or asked. Native
//! code opens the call (the microphone question), makes the offer, and the host is asked to start
//! the call with it. **From the moment the host answers that a call exists, every way out goes
//! through the end procedure**, which stops the media, revokes the grant at the host and finalises
//! the call at the voice service. Then the answer is applied, the call is permitted, and the
//! control is opened at the service the account is signed in at.
//!
//! # What an end does, whatever the cause
//!
//! The media stops and the host is asked to revoke the call's grant, both at once and each with
//! its own bound: a native stop that does not return never holds a revocation, and a revocation
//! that is not answered never holds the media. The host's answer, a refusal and a silence are
//! kept apart in what the screen reads: only an answer says the grant is revoked. The voice
//! service is asked to finalise the call after that, by the control while it lives and by its HTTP
//! route when it does not, and the screen does not wait for it.

use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use companion_platform::call::{
    CallEvent, CallEvents, CallFailure, CallId, CallPlatform, CaptureState, ConnectionState,
    FailureKind, Heard, Held, Mute,
};
use kr_client::ClientError;
use kr_client::Session;
use kr_client::Settled;
use kr_client::services::AccountTokenSource;
use kr_client::services::account::{AccountStatus, SignedInAccount};
use kr_client::services::voice::{
    ManagedVoiceBroker, ManagedVoiceService, VOICE_SCOPE, VoiceCommand,
};
use kr_client::services::voice_control::{
    ControlEnd, ControlEvents, ControlNews, ControlTarget, VoiceControl,
};
use kr_client::session::ComposedMutation;
use kr_protocol::ids::{ActionId, VoiceSessionId};
use kr_protocol::method::Method;
use kr_protocol::scalars::{Nullable, U64};
use kr_protocol::voice::{
    VoiceContextParams, VoiceSessionDescriptor, VoiceStartOutcome, VoiceStartParams,
    VoiceStartResult,
};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::time::Instant;

use super::cause::Cause;
use super::host::{CallHost, HostReach, has_ended, revoke};
use super::view::{DelegationRow, EndedView, HostEnd, VoiceCallState};
use super::{Closed, Cmd, NoteKey, Shared, StartRequest, Started};
use crate::commands::{MUTATION_TTL, NoPreconditions};
use crate::error::{CommandError, Result};

/// What the model is told, once, as the call is attached: this version does not act on the host.
const HOST_ACTIONS_UNAVAILABLE: &str = "In this version the phone cannot act on the person's \
    computer. If the person asks for something to be done there, say that nothing can be done \
    from this call yet. Do not say or imply that anything was done.";

/// What the model is told of a delegation: nothing was done.
const NOTHING_WAS_DONE: &str = "Nothing was done on the person's computer: this version does not \
    act on spoken requests. Say so.";

/// What the model is told when the phone has lost the host.
const HOST_LOST: &str = "The phone has lost contact with the person's computer. The call goes on, \
    but nothing can be read from or done on the computer until it is back. Do not say or imply \
    that anything was done there.";

/// What the model is told when the host is back.
const HOST_BACK: &str = "The phone is in contact with the person's computer again. Nothing was \
    done there while it was away.";

/// The most delegation identifiers a call remembers having answered.
const ANSWERED: usize = 256;

/// What a task that the owner started tells it.
enum Internal {
    /// The answer to a sign of life.
    Alive(std::result::Result<Held, CallFailure>),
    /// What the host path came to: back on this connection, or what the host said.
    Probed(Probe),
    /// Whether the model was told a delegation was not acted on.
    Told { delegation_id: String, told: bool },
}

/// What the check of a host path that was lost came to.
enum Probe {
    /// The host answered on this connection.
    Back(Arc<Session>),
    /// The host answered with a refusal.
    Refused(Arc<Session>, String),
    /// The host could not be reached yet.
    Unreached,
}

/// What a call is started with.
pub(super) struct Launch {
    pub(super) id: u64,
    pub(super) request: StartRequest,
    pub(super) reach: Arc<dyn HostReach>,
    pub(super) tokens: Arc<SignedInAccount>,
    pub(super) inbox: mpsc::Receiver<Cmd>,
    pub(super) reply: oneshot::Sender<Result<Started>>,
}

/// Owns one call from its start to its end.
pub(super) async fn drive(shared: Arc<Shared>, launch: Launch) {
    let Launch {
        id,
        request,
        reach,
        tokens,
        inbox,
        reply,
    } = launch;
    let mut owner = Owner::new(id, shared, reach, tokens, inbox);
    match owner.start(request).await {
        Ok(Outcome::Live(started)) => {
            // A start whose asker is gone is a call nobody will hang up: it is ended.
            if reply.send(Ok(started)).is_err() {
                owner.end(Cause::Requested).await;
            } else {
                owner.running().await;
            }
        }
        Ok(Outcome::Over(started)) => {
            let _ = reply.send(Ok(started));
        }
        Err(error) => {
            let _ = reply.send(Err(error));
        }
    }
    owner.shared.release(owner.id);
    owner.shared.forget_emergency(owner.id);
}

/// What `start` came to.
pub(super) enum Outcome {
    /// A call runs.
    Live(Started),
    /// Nothing runs: the host declined, or could not say.
    Over(Started),
}

/// The task's whole state.
pub(super) struct Owner {
    id: u64,
    shared: Arc<Shared>,
    reach: Arc<dyn HostReach>,
    tokens: Arc<SignedInAccount>,
    inbox: mpsc::Receiver<Cmd>,
    account: watch::Receiver<AccountStatus>,
    internal_tx: mpsc::UnboundedSender<Internal>,
    internal: mpsc::UnboundedReceiver<Internal>,
    /// The grant generation the call started under.
    generation: Option<String>,
    host: Option<CallHost>,
    call: Option<CallId>,
    events: Option<CallEvents>,
    descriptor: Option<VoiceSessionDescriptor>,
    control: Option<VoiceControl>,
    control_events: Option<ControlEvents>,
    attached_before: bool,
    answered: VecDeque<String>,
    deadline: Pin<Box<tokio::time::Sleep>>,
    host_closed: Pin<Box<dyn Future<Output = ()> + Send + Sync>>,
    host_lost: bool,
    silent_signs: u32,
    stops: Vec<oneshot::Sender<Closed>>,
    /// Seconds of call the start asked for.
    requested: u32,
}

/// Waits for the next news of the call, or for ever when there is no call.
async fn next_heard(events: &mut Option<CallEvents>) -> Option<Heard> {
    match events {
        Some(events) => events.recv().await,
        None => std::future::pending().await,
    }
}

/// Waits for the control's next news, or for ever when there is no control.
async fn next_news(events: &mut Option<ControlEvents>) -> Option<ControlNews> {
    match events {
        Some(events) => events.next().await,
        None => std::future::pending().await,
    }
}

fn far_future() -> Pin<Box<tokio::time::Sleep>> {
    Box::pin(tokio::time::sleep_until(
        Instant::now() + Duration::from_secs(60 * 60 * 24 * 365),
    ))
}

/// The word the screen draws a capture state by.
fn capture_word(state: CaptureState) -> String {
    serde_json::to_value(state)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_else(|| "unavailable".to_owned())
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}

impl Owner {
    pub(super) fn new(
        id: u64,
        shared: Arc<Shared>,
        reach: Arc<dyn HostReach>,
        tokens: Arc<SignedInAccount>,
        inbox: mpsc::Receiver<Cmd>,
    ) -> Self {
        let (internal_tx, internal) = mpsc::unbounded_channel();
        let account = tokens.subscribe();
        Self {
            id,
            shared,
            reach,
            tokens,
            inbox,
            account,
            internal_tx,
            internal,
            generation: None,
            host: None,
            call: None,
            events: None,
            descriptor: None,
            control: None,
            control_events: None,
            attached_before: false,
            answered: VecDeque::new(),
            deadline: far_future(),
            host_closed: Box::pin(std::future::pending()),
            host_lost: false,
            silent_signs: 0,
            stops: Vec::new(),
            requested: 0,
        }
    }

    fn platform(&self) -> Arc<dyn CallPlatform> {
        Arc::clone(&self.shared.platform)
    }

    fn view(&self, change: impl FnOnce(&mut VoiceCallState)) {
        change(
            &mut self
                .shared
                .view
                .lock()
                .expect("the view lock is not poisoned"),
        );
    }

    /* ------------------------------------------------------------------------------------- */
    /* Waiting for a step while the call is watched                                          */
    /* ------------------------------------------------------------------------------------- */

    /// Runs `step`, and keeps hearing the person, native code and the account while it runs.
    /// Returns what the step came to, or why the call has to end instead.
    async fn wait<T>(&mut self, step: impl Future<Output = T>) -> std::result::Result<T, Cause> {
        tokio::pin!(step);
        loop {
            tokio::select! {
                out = &mut step => return Ok(out),
                cmd = self.inbox.recv() => {
                    if let Some(cause) = self.before_running(cmd) {
                        return Err(cause);
                    }
                }
                heard = next_heard(&mut self.events) => {
                    if let Some(cause) = self.on_heard(heard).await {
                        return Err(cause);
                    }
                }
                changed = self.account.changed() => {
                    if let Some(cause) = self.on_account(changed.is_ok()) {
                        return Err(cause);
                    }
                }
            }
        }
    }

    /// What a command means while the call is being set up: a stop gives it up, and nothing else
    /// can be done yet.
    fn before_running(&mut self, cmd: Option<Cmd>) -> Option<Cause> {
        match cmd {
            Some(Cmd::Stop(reply)) => {
                self.stops.push(reply);
                Some(Cause::Requested)
            }
            Some(Cmd::Mute { reply, .. }) => {
                let _ = reply.send(Err(CommandError::refused(
                    "this device is not holding a running voice call yet",
                )));
                None
            }
            None => Some(Cause::Requested),
        }
    }

    /// Looks at what the inbox holds without waiting for it.
    fn pending_cause(&mut self) -> Option<Cause> {
        while let Ok(cmd) = self.inbox.try_recv() {
            if let Some(cause) = self.before_running(Some(cmd)) {
                return Some(cause);
            }
        }
        None
    }

    /* ------------------------------------------------------------------------------------- */
    /* The start                                                                             */
    /* ------------------------------------------------------------------------------------- */

    pub(super) async fn start(&mut self, request: StartRequest) -> Result<Outcome> {
        self.view(|state| {
            *state = VoiceCallState::no_call();
            state.warning = None;
        });
        self.requested = request.duration_seconds;
        let host = self.reach.in_use()?;
        self.host = Some(host.clone());
        self.generation = Some(self.pre_check().await?);

        // The call is opened, which asks the person for the microphone.
        let platform = self.platform();
        let opened = match self.wait(async move { platform.open().await }).await {
            Ok(Ok(opened)) => opened,
            Ok(Err(failure)) => return Err(self.open_failed(failure).await),
            Err(cause) => return self.abandon(cause).await,
        };
        let call = opened.call.clone();
        self.call = Some(call.clone());
        self.events = Some(opened.events);
        self.shared
            .keep_for_emergency(self.id, Some(call.clone()), Some(&host), None, &self.reach);
        self.view(|state| state.running = false);

        let platform = self.platform();
        let offered = {
            let call = call.clone();
            self.wait(async move { platform.offer(&call).await }).await
        };
        let offer = match offered {
            Ok(Ok(offer)) => offer,
            Ok(Err(failure)) => {
                return self
                    .abandon(Cause::Step(format!(
                        "the offer could not be made ({failure})"
                    )))
                    .await;
            }
            Err(cause) => return self.abandon(cause).await,
        };
        if let Some(cause) = self.pending_cause() {
            return self.abandon(cause).await;
        }

        let params = VoiceStartParams {
            session_ids: request.session_ids.iter().copied().collect(),
            offer_sdp: offer,
            duration_seconds: request.duration_seconds,
            reasoning_budget_minor: Nullable::from(request.reasoning_budget_minor.map(U64::new)),
            prepared: request.prepared,
            expected_rate_version: Nullable::from(request.expected_rate_version.clone()),
        };
        let target = match request.subject.target(host.environment_id) {
            Ok(target) => target,
            Err(error) => {
                return self
                    .abandon_with(Cause::Step(error.message.clone()), error)
                    .await;
            }
        };
        let action_id = ActionId::new(kr_ipc::new_uuid());
        let composed = match host
            .session
            .compose(
                Method::VoiceStart,
                action_id,
                target,
                None,
                &NoPreconditions {},
                &params,
                MUTATION_TTL,
            )
            .await
        {
            Ok(composed) => composed,
            Err(error) => {
                return self
                    .abandon_with(
                        Cause::Step("the start could not be composed".to_owned()),
                        CommandError::from(error),
                    )
                    .await;
            }
        };

        // The send is not interrupted: a request the host has been given is answered or lost, and
        // a call it created has to be found, so nothing here drops it half way. A stop that comes
        // meanwhile waits in the inbox and is read as soon as the answer is.
        let sent = host.session.send(&composed).await;
        let created = match sent {
            Ok(Settled::Result(value)) => {
                host.session.settle(action_id).await;
                match value.to_typed::<VoiceStartResult>() {
                    Ok(result) => Reached::Result(result),
                    Err(error) => {
                        return self
                            .abandon_with(
                                Cause::Step("the host's answer could not be read".to_owned()),
                                CommandError::local_failure(error.to_string()),
                            )
                            .await;
                    }
                }
            }
            Ok(Settled::Receipt(receipt)) => {
                host.session.settle(action_id).await;
                Reached::Receipt(receipt)
            }
            Err(ClientError::SubmissionUncertain { .. } | ClientError::OutcomeUnknown { .. }) => {
                match self.reconcile(&composed, &host, action_id).await {
                    Ok(reached) => reached,
                    Err(cause) => return self.abandon(cause).await,
                }
            }
            Err(error) => {
                host.session.settle(action_id).await;
                self.stop_native().await;
                self.release();
                return Err(CommandError::from(error));
            }
        };

        let result = match created {
            Reached::Receipt(receipt) => {
                self.stop_native().await;
                self.release();
                return Ok(Outcome::Over(Started::Receipt(receipt)));
            }
            Reached::Unknown => {
                self.stop_native().await;
                self.release();
                return Ok(Outcome::Over(Started::Unknown { action_id }));
            }
            Reached::Result(result) => result,
        };
        let VoiceStartOutcome::Started { session } = &result.outcome else {
            self.stop_native().await;
            self.release();
            return Ok(Outcome::Over(Started::Result(result)));
        };
        let descriptor = (**session).clone();
        self.descriptor = Some(descriptor.clone());
        self.shared.keep_for_emergency(
            self.id,
            Some(call.clone()),
            self.host.as_ref(),
            Some(&descriptor),
            &self.reach,
        );
        if let Some(cause) = self.pending_cause() {
            return self.abandon(cause).await;
        }
        self.go_live(descriptor, result).await
    }

    /// The setup after the host created the call: every way out of here ends the call.
    async fn go_live(
        &mut self,
        descriptor: VoiceSessionDescriptor,
        result: VoiceStartResult,
    ) -> Result<Outcome> {
        let call = self.call.clone().expect("a call is held");
        let service = self.shared.service.clone();

        // The service the control is opened at is the one the account is signed in at, whatever
        // the host said.
        let target = match ControlTarget::at(
            &service.origin,
            &descriptor.broker_origin,
            &descriptor.control_path,
            &descriptor.call_id,
        ) {
            Ok(target) => target,
            Err(_) => return self.abandon(Cause::ForeignService).await,
        };
        // A call that closes at a moment the device did not ask for is not one it trusts native
        // code to hold to.
        let closes = descriptor.closes_at_ms.get();
        let latest = now_ms()
            .saturating_add(u64::from(self.requested) * 1000)
            .saturating_add(MAX_CLOCK_SKEW_MS);
        if closes <= now_ms() || closes > latest {
            return self
                .abandon(Cause::Step(
                    "the host gave the call a closing time that this device did not ask for"
                        .to_owned(),
                ))
                .await;
        }

        let platform = self.platform();
        let accepted = {
            let (call, sdp) = (call.clone(), descriptor.answer_sdp.clone());
            self.wait(async move { platform.accept(&call, &sdp).await })
                .await
        };
        match accepted {
            Ok(Ok(_)) => {}
            Ok(Err(failure)) => {
                return self
                    .abandon(Cause::Step(format!(
                        "the answer could not be applied ({failure})"
                    )))
                    .await;
            }
            Err(cause) => return self.abandon(cause).await,
        }

        let platform = self.platform();
        let permitted = {
            let (call, id) = (call.clone(), descriptor.voice_session_id.to_string());
            self.wait(async move { platform.permit(&call, &id, closes).await })
                .await
        };
        match permitted {
            Ok(Ok(true)) => {}
            Ok(Ok(false)) => {
                return self
                    .abandon(Cause::Step("the call could not be permitted".to_owned()))
                    .await;
            }
            Ok(Err(failure)) => {
                return self
                    .abandon(Cause::Step(format!(
                        "the call could not be permitted ({failure})"
                    )))
                    .await;
            }
            Err(cause) => return self.abandon(cause).await,
        }

        let (control, control_events) = VoiceControl::open(
            &service.connector,
            target,
            Arc::clone(&self.tokens) as Arc<dyn AccountTokenSource>,
        );
        self.control = Some(control);
        self.control_events = Some(control_events);
        let remaining = Duration::from_millis(closes.saturating_sub(now_ms()));
        self.deadline = Box::pin(tokio::time::sleep_until(Instant::now() + remaining));
        if let Some(host) = &self.host {
            let session = Arc::clone(&host.session);
            self.host_closed = Box::pin(async move { session.closed().await });
        }
        let mut shown = descriptor.clone();
        shown.answer_sdp = String::new();
        self.view(|state| {
            state.running = true;
            state.session = Some(shown);
            state.control = "none".to_owned();
            state.host = "reachable".to_owned();
            state.capture = "idle".to_owned();
        });
        // Whatever the page asked while the call was set up has been heard by now.
        if let Some(cause) = self.pending_cause() {
            return self.abandon(cause).await;
        }
        let mut answer = result;
        if let VoiceStartOutcome::Started { session } = &mut answer.outcome {
            session.answer_sdp = String::new();
        }
        Ok(Outcome::Live(Started::Result(answer)))
    }

    /// Checks that the account can give the voice token the control will present, before anything
    /// is created or asked, and returns which grant that is.
    async fn pre_check(&self) -> Result<String> {
        let tokens = Arc::clone(&self.tokens);
        // On a task of its own: a refresh that the caller going away interrupted could lose the
        // token it rotated.
        let asked = tokio::spawn(async move { tokens.token(VOICE_SCOPE).await.map(|_| ()) });
        match tokio::time::timeout(self.shared.timings.token_within, asked).await {
            Ok(Ok(Ok(()))) => {}
            Ok(Ok(Err(error))) => {
                return Err(
                    if error.code() == kr_protocol::error::ErrorCode::UpstreamUnavailable {
                        CommandError::unavailable(
                            "This device could not reach the account service, so it cannot tell \
                         whether it could control a call. No call was started.",
                        )
                    } else {
                        CommandError::refused(format!(
                            "This device has no account token for voice, so it could not control a \
                         call. No call was started. {error}"
                        ))
                    },
                );
            }
            Ok(Err(_)) | Err(_) => {
                return Err(CommandError::unavailable(
                    "This device could not get its account's voice token in time. No call was \
                     started.",
                ));
            }
        }
        match self.tokens.status() {
            Ok(AccountStatus::SignedIn { generation, .. }) => Ok(generation),
            _ => Err(CommandError::refused(
                "No account is signed in on this device, so no call was started.",
            )),
        }
    }

    /// What a call that native code would not open is told as, and whatever native code may have
    /// made after all is stopped.
    async fn open_failed(&mut self, failure: CallFailure) -> CommandError {
        let error = match failure.kind {
            FailureKind::MicrophoneRefused => CommandError::refused(
                "Kala Reach has no permission to use the microphone, so no call was started. \
                 Allow it in this device's settings.",
            ),
            FailureKind::AlreadyRunning => CommandError::refused(
                "This device already holds a voice call, so no other was started.",
            ),
            _ => CommandError::unavailable(format!(
                "The call could not be opened on this device ({failure})"
            )),
        };
        if matches!(failure.kind, FailureKind::Unavailable | FailureKind::Engine) {
            // Native code may yet make the call it was asked for: whatever it holds is stopped.
            if let Ok(held) = self.platform().held().await
                && let Some(call) = held.call
            {
                self.stop_media(&call).await;
            }
        }
        self.release();
        error
    }

    /// Ends the call for `cause` and says why to whoever started it.
    async fn abandon(&mut self, cause: Cause) -> Result<Outcome> {
        let error = match &cause {
            Cause::Requested => CommandError::unavailable("The call was given up before it began."),
            other => CommandError::unavailable(other.words()),
        };
        self.abandon_with(cause, error).await
    }

    async fn abandon_with(&mut self, cause: Cause, error: CommandError) -> Result<Outcome> {
        self.end(cause).await;
        Err(error)
    }

    /// Stops the call's media when nothing was created at the host.
    async fn stop_native(&mut self) {
        if let Some(call) = self.call.take() {
            self.stop_media(&call).await;
        }
        self.events = None;
        for reply in self.stops.drain(..) {
            let _ = reply.send(Closed {
                local: true,
                host: HostEnd::NotNeeded,
            });
        }
    }

    /// Learns what became of a start whose answer was lost, under the action it was sent under.
    ///
    /// A repeat is a question and not a second request: the host answers it from the record it
    /// kept of the action, on a connection other than the one that sent it, or does not answer
    /// it. What an answer other than a result says proves nothing about the original, which the
    /// host can still read until its window ends, so only a result settles a start; anything else
    /// leaves it unknown, and the person is told so.
    async fn reconcile(
        &mut self,
        composed: &ComposedMutation,
        host: &CallHost,
        action_id: ActionId,
    ) -> std::result::Result<Reached, Cause> {
        let delays = self.shared.timings.repeat_delays;
        let within = self.shared.timings.host_within;
        let mut reached = Reached::Unknown;
        'asking: for delay in delays {
            self.wait(tokio::time::sleep(delay)).await?;
            let reach = Arc::clone(&self.reach);
            let paired = host.paired.clone();
            let original = Arc::clone(&host.session);
            let session = match self
                .wait(async move { reach.session_to(&paired, Some(&original)).await })
                .await?
            {
                Ok(session) => session,
                Err(_) => continue,
            };
            let asking = session.repeat(composed);
            let answered = self
                .wait(async move { tokio::time::timeout(within, asking).await })
                .await?;
            match answered {
                Ok(Ok(Settled::Result(value))) => {
                    if let Ok(result) = value.to_typed::<VoiceStartResult>() {
                        // The call the host made goes on under the connection that heard of it.
                        if let Some(held) = self.host.as_mut() {
                            held.session = Arc::clone(&session);
                        }
                        session.settle(action_id).await;
                        reached = Reached::Result(result);
                        break 'asking;
                    }
                }
                Ok(Ok(Settled::Receipt(receipt))) => {
                    session.settle(action_id).await;
                    reached = Reached::Receipt(receipt);
                    break 'asking;
                }
                Ok(Err(_)) | Err(_) => {}
            }
            session.settle(action_id).await;
        }
        host.session.settle(action_id).await;
        Ok(reached)
    }

    /* ------------------------------------------------------------------------------------- */
    /* The running call                                                                      */
    /* ------------------------------------------------------------------------------------- */

    pub(super) async fn running(&mut self) {
        let mut tick = tokio::time::interval(self.shared.timings.tick);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        tick.tick().await;
        loop {
            let cause = tokio::select! {
                cmd = self.inbox.recv() => self.on_command(cmd),
                heard = next_heard(&mut self.events) => self.on_heard(heard).await,
                news = next_news(&mut self.control_events) => self.on_news(news),
                internal = self.internal.recv() => self.on_internal(internal),
                _ = tick.tick() => self.on_tick(),
                () = &mut self.deadline => Some(Cause::Deadline),
                changed = self.account.changed() => self.on_account(changed.is_ok()),
                () = &mut self.host_closed => self.on_host_closed(),
            };
            if let Some(cause) = cause {
                self.end(cause).await;
                return;
            }
        }
    }

    fn on_command(&mut self, cmd: Option<Cmd>) -> Option<Cause> {
        match cmd {
            Some(Cmd::Stop(reply)) => {
                self.stops.push(reply);
                Some(Cause::Requested)
            }
            Some(Cmd::Mute { what, muted, reply }) => {
                self.mute(what, muted, reply);
                None
            }
            None => Some(Cause::Requested),
        }
    }

    /// Silences the microphone or the model's voice on this device; the voice service is told of a
    /// microphone's mute as well, which is advice to the provider and not the mute itself.
    fn mute(&self, what: Mute, muted: bool, reply: oneshot::Sender<Result<VoiceCallState>>) {
        let Some(call) = self.call.clone() else {
            let _ = reply.send(Err(CommandError::refused(
                "this device is not holding a voice call",
            )));
            return;
        };
        let platform = self.platform();
        let shared = Arc::clone(&self.shared);
        let control = self.control.clone();
        tokio::spawn(async move {
            match platform.mute(&call, what, muted).await {
                Err(failure) => {
                    let _ = reply.send(Err(CommandError::unavailable(format!(
                        "that could not be done to the call ({failure})"
                    ))));
                }
                Ok(()) => {
                    if what == Mute::Microphone
                        && let Some(control) = control
                    {
                        let command = if muted {
                            VoiceCommand::Mute
                        } else {
                            VoiceCommand::Unmute
                        };
                        let _ = control.send(command, None, None).await;
                    }
                    if let Ok(held) = platform.held().await {
                        let mut view = shared.view.lock().expect("the view lock is not poisoned");
                        view.capture = capture_word(held.capture);
                        view.playing = held.playing;
                    }
                    let _ = reply.send(Ok(shared
                        .view
                        .lock()
                        .expect("the view lock is not poisoned")
                        .clone()));
                }
            }
        });
    }

    /// What native code's news says of the call, and whether it ends it.
    async fn on_heard(&mut self, heard: Option<Heard>) -> Option<Cause> {
        match heard {
            None | Some(Heard::Event(CallEvent::Ended)) => Some(Cause::NativeEnded),
            Some(Heard::Event(CallEvent::Connection { state })) => {
                if state == ConnectionState::Failed {
                    return Some(Cause::NativeFailed);
                }
                None
            }
            Some(Heard::Event(CallEvent::Capture { state })) => {
                self.view(|view| view.capture = capture_word(state));
                None
            }
            Some(Heard::Event(
                CallEvent::FirstAudio | CallEvent::ProviderEvent { .. } | CallEvent::Lost,
            )) => None,
            // News was lost, and what was lost can be the end of the call: ask native code what
            // it holds rather than carry on as if nothing had been missed.
            Some(Heard::Lost) => self.verify_native().await,
        }
    }

    async fn verify_native(&self) -> Option<Cause> {
        let call = self.call.clone()?;
        match self.platform().held().await {
            Ok(held) if held.call.as_ref() == Some(&call) => None,
            Ok(_) => Some(Cause::NativeGone),
            Err(failure)
                if matches!(failure.kind, FailureKind::Ended | FailureKind::NoSuchCall) =>
            {
                Some(Cause::NativeGone)
            }
            Err(_) => None,
        }
    }

    fn on_account(&mut self, open: bool) -> Option<Cause> {
        if !open {
            return None;
        }
        match self.tokens.status() {
            Ok(AccountStatus::SignedIn { generation, .. })
                if Some(&generation) == self.generation.as_ref() =>
            {
                None
            }
            _ => Some(Cause::AccountChanged),
        }
    }

    fn on_news(&mut self, news: Option<ControlNews>) -> Option<Cause> {
        match news {
            None => Some(Cause::Control(ControlEnd::Unreachable)),
            Some(ControlNews::Ended(end)) => Some(Cause::Control(end)),
            Some(ControlNews::Detached) => {
                self.view(|state| state.control = "unreachable".to_owned());
                None
            }
            Some(ControlNews::Attached { delegations, .. }) => {
                self.view(|state| state.control = "connected".to_owned());
                self.shared.clear_note();
                if !self.attached_before {
                    self.attached_before = true;
                    self.tell_model(VoiceCommand::Instructions, None, HOST_ACTIONS_UNAVAILABLE);
                }
                for delegation_id in delegations {
                    self.answer_delegation(delegation_id, None);
                }
                None
            }
            Some(ControlNews::Event(
                kr_client::services::voice::VoiceControlEvent::Delegation {
                    delegation_id,
                    offset_ms,
                },
            )) => {
                self.answer_delegation(delegation_id, Some(offset_ms));
                None
            }
            Some(ControlNews::Event(_)) => None,
        }
    }

    /// Says to the model, once for each delegation, that nothing was done about it, and keeps a
    /// row the screen shows.
    fn answer_delegation(&mut self, delegation_id: String, offset_ms: Option<u64>) {
        if self.answered.contains(&delegation_id) {
            return;
        }
        self.answered.push_back(delegation_id.clone());
        if self.answered.len() > ANSWERED {
            self.answered.pop_front();
        }
        self.view(|state| {
            state.delegations.push(DelegationRow {
                delegation_id: delegation_id.clone(),
                offset_ms: offset_ms.unwrap_or(0),
                state: "not_done".to_owned(),
                told: false,
            });
            if state.delegations.len() > ANSWERED {
                state.delegations.remove(0);
            }
        });
        let Some(control) = self.control.clone() else {
            return;
        };
        let internal = self.internal_tx.clone();
        tokio::spawn(async move {
            let told = control
                .send(
                    VoiceCommand::Commentary,
                    Some(&delegation_id),
                    Some(NOTHING_WAS_DONE),
                )
                .await
                .is_ok();
            let _ = internal.send(Internal::Told {
                delegation_id,
                told,
            });
        });
    }

    /// Tells the model a fixed sentence, on a task of its own so that nothing waits for it.
    fn tell_model(&self, command: VoiceCommand, delegation: Option<String>, text: &'static str) {
        let Some(control) = self.control.clone() else {
            return;
        };
        tokio::spawn(async move {
            let _ = control
                .send(command, delegation.as_deref(), Some(text))
                .await;
        });
    }

    fn on_internal(&mut self, message: Option<Internal>) -> Option<Cause> {
        match message? {
            Internal::Alive(Ok(held)) => {
                self.silent_signs = 0;
                if held.call.as_ref() != self.call.as_ref() {
                    return Some(Cause::NativeGone);
                }
                self.view(|state| {
                    state.capture = capture_word(held.capture);
                    state.playing = held.playing;
                });
                None
            }
            Internal::Alive(Err(failure)) => {
                if matches!(failure.kind, FailureKind::Ended | FailureKind::NoSuchCall) {
                    return Some(Cause::NativeGone);
                }
                self.silent_signs += 1;
                (self.silent_signs >= self.shared.timings.silent_signs)
                    .then_some(Cause::NativeSilent)
            }
            Internal::Told {
                delegation_id,
                told,
            } => {
                self.view(|state| {
                    if let Some(row) = state
                        .delegations
                        .iter_mut()
                        .find(|row| row.delegation_id == delegation_id)
                    {
                        row.told = told;
                    }
                });
                None
            }
            Internal::Probed(probe) => {
                match probe {
                    Probe::Back(session) => {
                        self.host_back(&session);
                    }
                    Probe::Refused(session, words) => {
                        self.host_back(&session);
                        self.view(|state| {
                            state.warning = Some(format!(
                                "The host answered but did not recognise this call: {words} \
                                 Hang up if you did not expect that."
                            ));
                        });
                    }
                    Probe::Unreached => {}
                }
                None
            }
        }
    }

    /// The host is reached again, on `session`.
    fn host_back(&mut self, session: &Arc<Session>) {
        if let Some(host) = self.host.as_mut() {
            host.session = Arc::clone(session);
        }
        let watched = Arc::clone(session);
        self.host_closed = Box::pin(async move { watched.closed().await });
        self.host_lost = false;
        self.view(|state| state.host = "reachable".to_owned());
        self.tell_model(VoiceCommand::Instructions, None, HOST_BACK);
    }

    fn on_host_closed(&mut self) -> Option<Cause> {
        self.host_closed = Box::pin(std::future::pending());
        if !self.host_lost {
            self.host_lost = true;
            self.view(|state| state.host = "lost".to_owned());
            self.tell_model(VoiceCommand::Instructions, None, HOST_LOST);
        }
        None
    }

    fn on_tick(&mut self) -> Option<Cause> {
        if let Some(host) = &self.host
            && !self.reach.still_paired(&host.paired)
        {
            return Some(Cause::HostForgotten);
        }
        if let Some(call) = self.call.clone() {
            let (platform, internal) = (self.platform(), self.internal_tx.clone());
            tokio::spawn(async move {
                let _ = internal.send(Internal::Alive(platform.alive(&call).await));
            });
        }
        if self.host_lost
            && let (Some(host), Some(descriptor)) = (self.host.clone(), self.descriptor.clone())
        {
            let (reach, internal) = (Arc::clone(&self.reach), self.internal_tx.clone());
            let within = self.shared.timings.host_within;
            tokio::spawn(async move {
                let probe = probe_host(reach, host, descriptor, within).await;
                let _ = internal.send(Internal::Probed(probe));
            });
        }
        None
    }

    /* ------------------------------------------------------------------------------------- */
    /* The end                                                                               */
    /* ------------------------------------------------------------------------------------- */

    /// Stops a call's media, and says whether native code returned from the stop in time.
    async fn stop_media(&self, call: &CallId) -> bool {
        let platform = self.platform();
        matches!(
            tokio::time::timeout(self.shared.timings.local_within, platform.stop(call)).await,
            Ok(Ok(()))
        )
    }

    /// Frees the slot, so another call can be started.
    fn release(&self) {
        self.shared.release(self.id);
    }

    /// Ends the call, whatever the cause.
    pub(super) async fn end(&mut self, cause: Cause) -> Closed {
        let timings = self.shared.timings;
        self.view(|state| state.running = false);
        // The control closes the call at the service while the media and the host are dealt with,
        // and its news is read meanwhile: a control that nobody reads stops reading its socket.
        let closing = match (&self.control, cause.service_closed()) {
            (Some(control), false) => {
                let control = control.clone();
                Some(tokio::spawn(async move { control.close().await }))
            }
            _ => None,
        };
        let draining = self.control_events.take().map(|mut events| {
            tokio::spawn(async move {
                let mut last = None;
                while let Some(news) = events.next().await {
                    if let ControlNews::Ended(end) = news {
                        last = Some(end);
                    }
                }
                last
            })
        });

        let platform = self.platform();
        let call = self.call.take();
        let local = async {
            match call {
                Some(call) => {
                    // Native code that does not return from a stop never holds the revocation.
                    matches!(
                        tokio::time::timeout(timings.local_within, platform.stop(&call)).await,
                        Ok(Ok(()))
                    )
                }
                None => false,
            }
        };
        let host = self.host.clone();
        let descriptor = self.descriptor.clone();
        let reach = Arc::clone(&self.reach);
        let toward_host = async {
            match (host, descriptor) {
                (Some(host), Some(descriptor)) => Some(
                    stop_at_host(
                        &reach,
                        &host,
                        descriptor.voice_session_id,
                        timings.host_within,
                    )
                    .await,
                ),
                _ => None,
            }
        };
        let (closed_locally, host_end) = tokio::join!(local, toward_host);
        self.events = None;
        let host_end = host_end.unwrap_or(HostEnd::NotNeeded);
        let closed = Closed {
            local: closed_locally,
            host: host_end.clone(),
        };

        let needs_broker = self.descriptor.is_some();
        let id = self.id;
        self.view(|state| {
            state.running = false;
            state.session = None;
            state.control = "none".to_owned();
            state.host = "none".to_owned();
            state.ended = Some(EndedView {
                owner: id,
                cause: cause.word().to_owned(),
                words: cause.words(),
                closed_locally,
                host: host_end.clone(),
                broker: if needs_broker {
                    "pending"
                } else {
                    "not_needed"
                }
                .to_owned(),
            });
        });
        if matches!(cause, Cause::Control(ControlEnd::NoSuchCall)) {
            self.shared.remember_no_such_call(self.note_key());
        }
        // Another call can be started from here; this one is only finalising at the service.
        self.release();
        for reply in self.stops.drain(..) {
            let _ = reply.send(closed.clone());
        }

        if needs_broker {
            let broker = self.finalise(&cause, closing, &host_end).await;
            self.view(|state| {
                if let Some(ended) = state.ended.as_mut().filter(|ended| ended.owner == id) {
                    ended.broker = broker.to_owned();
                }
            });
        }
        if let Some(control) = self.control.take() {
            control.stop();
        }
        if let Some(draining) = draining {
            draining.abort();
        }
        self.shared.forget_emergency(self.id);
        closed
    }

    fn note_key(&self) -> NoteKey {
        NoteKey {
            environment: self
                .host
                .as_ref()
                .map(|host| host.environment_id.to_string()),
            generation: self.generation.clone(),
            origin: self.shared.service.origin.clone(),
        }
    }

    /// Finalises the call at the voice service, and says how that went.
    async fn finalise(
        &mut self,
        cause: &Cause,
        closing: Option<
            tokio::task::JoinHandle<
                std::result::Result<
                    kr_client::services::voice_control::Closure,
                    kr_client::services::voice_control::SendError,
                >,
            >,
        >,
        host: &HostEnd,
    ) -> &'static str {
        if cause.service_closed() {
            return "closed_by_service";
        }
        if let Some(closing) = closing
            && matches!(closing.await, Ok(Ok(_)))
        {
            return "closed";
        }
        // The control could not close it. The host tells the service when it revokes, and when it
        // says it did there is nothing to add; otherwise the service's own route can close it.
        if matches!(
            host,
            HostEnd::Revoked {
                broker_notified: true,
                ..
            }
        ) {
            return "closed_by_host";
        }
        let Some(descriptor) = self.descriptor.as_ref() else {
            return "not_confirmed";
        };
        let service = &self.shared.service;
        let Ok(broker) = ManagedVoiceBroker::new(
            service.origin.clone(),
            Arc::clone(&service.http),
            Arc::clone(&self.tokens) as Arc<dyn AccountTokenSource>,
        ) else {
            return "not_confirmed";
        };
        if matches!(
            tokio::time::timeout(
                self.shared.timings.close_within,
                broker.close(&descriptor.call_id)
            )
            .await,
            Ok(Ok(_))
        ) {
            return "closed_over_http";
        }
        "not_confirmed"
    }
}

/// What a start learned.
enum Reached {
    /// The host's answer.
    Result(VoiceStartResult),
    /// The host answered with a receipt.
    Receipt(Box<kr_protocol::receipt::Receipt>),
    /// The host never said.
    Unknown,
}

/// How far from the clock this device's idea of the moment a call closes may be, in milliseconds.
const MAX_CLOCK_SKEW_MS: u64 = 120_000;

/// Asks `host` to revoke the call's grant, over a connection to that host.
pub(super) async fn stop_at_host(
    reach: &Arc<dyn HostReach>,
    host: &CallHost,
    voice_session_id: VoiceSessionId,
    within: Duration,
) -> HostEnd {
    let session = if has_ended(&host.session).await {
        match tokio::time::timeout(within, reach.session_to(&host.paired, Some(&host.session)))
            .await
        {
            Ok(Ok(session)) => session,
            Ok(Err(error)) => {
                return HostEnd::NotTold {
                    words: format!("The host could not be reached: {}", error.message),
                };
            }
            Err(_) => {
                return HostEnd::NotTold {
                    words: "The host could not be reached in time.".to_owned(),
                };
            }
        }
    } else {
        Arc::clone(&host.session)
    };
    revoke(&session, host.environment_id, voice_session_id, within).await
}

/// Reaches a host that was lost, and asks whether it still knows the call.
///
/// The read is the context of the call's first session, which the host answers only for a voice
/// session it holds: an answer is "the host is back", and a refusal is reported and ends nothing.
async fn probe_host(
    reach: Arc<dyn HostReach>,
    host: CallHost,
    descriptor: VoiceSessionDescriptor,
    within: Duration,
) -> Probe {
    let Ok(Ok(session)) = tokio::time::timeout(within, reach.session_to(&host.paired, None)).await
    else {
        return Probe::Unreached;
    };
    let Some(session_id) = descriptor.session_ids.iter().next().copied() else {
        return Probe::Back(session);
    };
    let params = VoiceContextParams {
        voice_session_id: descriptor.voice_session_id,
        session_id,
        selected: kr_protocol::scalars::CanonicalSet::new(),
        delegation_id: Nullable::null(),
    };
    match tokio::time::timeout(
        within,
        session.read::<_, kr_protocol::voice::VoiceContextResult>(Method::VoiceContext, &params),
    )
    .await
    {
        Ok(Ok(_)) => Probe::Back(session),
        Ok(Err(ClientError::Host(error))) => Probe::Refused(session, error.message),
        _ => Probe::Unreached,
    }
}
