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
//! kept apart in what the screen reads: only an answer says the grant is revoked, and a silence
//! leaves the revocation owed until the moment the call would have closed. The control is asked to
//! close the call at the voice service as the end begins, and its news is read meanwhile; the
//! service's own HTTP route is the fallback once the host has answered. The screen does not wait
//! for the service.

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
use kr_client::services::voice::{VOICE_SCOPE, VoiceCommand, same_origin};
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
use super::host::{CallHost, HostReach, Pairing, has_ended, revoke};
use super::view::{DelegationRow, EndedView, HostEnd, OwedView, VoiceCallState};
use super::{Closed, Cmd, NoteKey, Shared, StartRequest, Started, now_ms};
use crate::commands::{MUTATION_TTL, NoPreconditions};
use crate::error::{CommandError, Result};

/// What the model is told, once, as the call is attached: this version does not act on the host.
const HOST_ACTIONS_UNAVAILABLE: &str = "In this version the phone cannot act on the person's \
    computer. If the person asks for something to be done there, say that nothing can be done \
    from this call. Do not say or imply that anything was done.";

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
    Refused(String),
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
                owner
                    .end(Cause::Step(
                        "the page that asked for the call went away before it began".to_owned(),
                    ))
                    .await;
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
    // However the owner came to be done, nobody is left waiting on it: what is queued is answered,
    // and a command sent from now on is turned away at once.
    owner.close_inbox(&Closed {
        local: true,
        host: HostEnd::NotNeeded,
    });
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
    /// When the owner gives native code a sign while a step runs.
    signs: tokio::time::Interval,
    /// What would have ended the call while the host was still being asked what became of its
    /// start: the first of them, acted on when the host's answer is known.
    cancelled: Option<Cause>,
    /// Whether native code stopped the call's media before the end procedure ran.
    media_stopped: Option<bool>,
    /// Whether the inbox is closed: nothing more can be read from it.
    inbox_gone: bool,
    /// Whether a look at the host path is under way.
    probing: bool,
    /// Not before when the host path is looked at again, after the host refused to vouch.
    probe_after: Option<Instant>,
    /// What the host's refusal to vouch for the call said, while it stands.
    probe_warning: Option<String>,
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
        let timings = shared.timings;
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
            signs: {
                let mut signs = tokio::time::interval(timings.tick);
                signs.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                signs
            },
            cancelled: None,
            media_stopped: None,
            inbox_gone: false,
            probing: false,
            probe_after: None,
            probe_warning: None,
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
                // Native code ends a call whose owner gives no sign, and a setup can take long.
                _ = self.signs.tick() => self.give_a_sign(),
            }
        }
    }

    /// Runs `step` to its end while the person, native code and the account are still heard.
    ///
    /// What would end the call is acted on at once for what only this device can do, and the step
    /// goes on: the media stops and a stop is answered, and the first cause is kept for when the
    /// step is over. For a step that must be seen through whatever the person does, such as asking
    /// the host what became of a start.
    async fn wait_through<T>(&mut self, step: impl Future<Output = T>) -> T {
        tokio::pin!(step);
        loop {
            let cause = tokio::select! {
                out = &mut step => return out,
                cmd = self.inbox.recv(), if !self.inbox_gone => {
                    if cmd.is_none() {
                        self.inbox_gone = true;
                    }
                    self.before_running(cmd)
                }
                heard = next_heard(&mut self.events) => self.on_heard(heard).await,
                changed = self.account.changed() => self.on_account(changed.is_ok()),
                _ = self.signs.tick() => {
                    self.give_a_sign();
                    None
                }
            };
            if let Some(cause) = cause {
                self.give_up(cause).await;
            }
        }
    }

    /// Stops the media for a cause that arrived while the host was still being asked, answers the
    /// stops waiting for it, and keeps the cause.
    async fn give_up(&mut self, cause: Cause) {
        if self.cancelled.is_none() {
            self.cancelled = Some(cause);
        }
        self.stop_native(HostEnd::NotTold {
            words: "The host has not said whether it made the call. This device is still asking \
                    it, and ends the call if it did."
                .to_owned(),
        })
        .await;
    }

    /// Tells native code the owner is there, on a task of its own; what it answers is read when the
    /// call runs.
    fn give_a_sign(&self) {
        if let Some(call) = self.call.clone() {
            let platform = self.platform();
            tokio::spawn(async move {
                let _ = platform.alive(&call).await;
            });
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
        self.requested = request.duration_seconds;
        let host = self.reach.in_use()?;
        self.host = Some(host.clone());
        self.generation = Some(self.pre_check().await?);
        // A stop that came while the token was checked gives the call up before anything is made.
        if self.pending_cause().is_some() {
            self.stop_native(HostEnd::NotNeeded).await;
            self.release();
            return Err(CommandError::unavailable(
                "The call was given up before it began.",
            ));
        }

        // The call is opened, which asks the person for the microphone.
        // Not interrupted: native code makes the call it is asked for, and a call made after the
        // caller gave up would have no owner. A stop that comes meanwhile waits in the inbox.
        let opened = match self.platform().open().await {
            Ok(opened) => opened,
            Err(failure) => return Err(self.open_failed(failure).await),
        };
        let owner = self.id;
        self.view(|state| state.begin(owner));
        let call = opened.call.clone();
        self.call = Some(call.clone());
        self.events = Some(opened.events);
        self.shared.keep_for_emergency(
            self.id,
            Some(call.clone()),
            Some(&host),
            None,
            &self.reach,
            &self.tokens,
        );
        if let Some(cause) = self.pending_cause() {
            return self.abandon(cause).await;
        }

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

        // The send waits for the host for a bound of its own, after which its answer is taken as
        // lost and the host is asked what became of it. A stop that comes meanwhile waits in the
        // inbox and is read as soon as the answer is.
        let sent = match tokio::time::timeout(
            self.shared.timings.start_within,
            host.session.send(&composed),
        )
        .await
        {
            Ok(sent) => sent,
            Err(_) => Err(ClientError::SubmissionUncertain { action_id }),
        };
        let created = match sent {
            Ok(Settled::Result(value)) => {
                host.session.settle(action_id).await;
                match value.to_typed::<VoiceStartResult>() {
                    Ok(result) => Reached::Result(result),
                    Err(_) => Reached::Unknown,
                }
            }
            Ok(Settled::Receipt(receipt)) => {
                host.session.settle(action_id).await;
                Reached::Receipt(receipt)
            }
            Err(ClientError::SubmissionUncertain { .. } | ClientError::OutcomeUnknown { .. }) => {
                self.reconcile(&composed, &host, action_id).await
            }
            Err(error) => {
                host.session.settle(action_id).await;
                self.stop_native(HostEnd::NotNeeded).await;
                self.release();
                return Err(CommandError::from(error));
            }
        };

        let result = match created {
            Reached::Receipt(receipt) => {
                self.stop_native(HostEnd::NotNeeded).await;
                self.release();
                return Ok(Outcome::Over(Started::Receipt(receipt)));
            }
            Reached::Unknown => {
                let local = self
                    .stop_native(HostEnd::NotTold {
                        words: "The host never said whether it created the call, so a grant it \
                                made may still be open until the moment the call was to close."
                            .to_owned(),
                    })
                    .await;
                let owner = self.id;
                let until_ms = now_ms()
                    .saturating_add(u64::from(self.requested) * 1000)
                    .saturating_add(MAX_CLOCK_SKEW_MS);
                self.view(|state| {
                    state.running = false;
                    state.ended = Some(EndedView {
                        owner,
                        cause: "start_unknown".to_owned(),
                        words: if local {
                            "The host never said whether it created the call. Nothing is running \
                             on this device."
                                .to_owned()
                        } else {
                            "The host never said whether it created the call, and this device \
                             could not confirm that the call's media stopped."
                                .to_owned()
                        },
                        closed_locally: local,
                        host: HostEnd::NotTold {
                            words: "The host never said whether it created the call.".to_owned(),
                        },
                        broker: "not_needed".to_owned(),
                    });
                    state.owe(
                        now_ms(),
                        OwedView {
                            kind: "start_unknown".to_owned(),
                            words: "The host never said whether it created the call. If it did, \
                                    its grant ends by itself when the call was to close."
                                .to_owned(),
                            action_id: Some(action_id.to_string()),
                            voice_session_id: None,
                            until_ms,
                        },
                    );
                });
                self.release();
                return Ok(Outcome::Over(Started::Unknown { action_id }));
            }
            Reached::Result(result) => result,
        };
        let VoiceStartOutcome::Started { session } = &result.outcome else {
            self.stop_native(HostEnd::NotNeeded).await;
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
            &self.tokens,
        );
        // The call can be named from here on: a stop that names it reaches this owner.
        let mut shown = descriptor.clone();
        shown.answer_sdp = String::new();
        self.view(|state| state.session = Some(shown));
        if let Some(cause) = self.cancelled.take().or_else(|| self.pending_cause()) {
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
            Err(_) if !same_origin(&service.origin, &descriptor.broker_origin) => {
                return self.abandon(Cause::ForeignService).await;
            }
            Err(_) => {
                return self
                    .abandon(Cause::Step(
                        "the host named a control address that is not the voice service's for this \
                         call"
                            .to_owned(),
                    ))
                    .await;
            }
        };
        // The device holds the call to the time it asked for, with room for a clock that is not
        // its own: a later closing time than that is held to, and one that is long past is not a
        // call to carry.
        let Some(closes) = hold_until(descriptor.closes_at_ms.get(), self.requested, now_ms())
        else {
            return self
                .abandon(Cause::Step(
                    "the host gave the call a closing time that has already passed".to_owned(),
                ))
                .await;
        };

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

        // What came meanwhile is heard before native code is allowed to carry the person's voice.
        if let Some(cause) = self.pending_cause() {
            return self.abandon(cause).await;
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

    /// Stops the call's media before the end procedure has anything to revoke, and answers the
    /// stops waiting with `host` as what the host did. Says whether native code stopped the media:
    /// a stop it does not return from, or refuses, is not a stop. A call native code has already
    /// ended is stopped.
    async fn stop_native(&mut self, host: HostEnd) -> bool {
        let local = match self.call.take() {
            Some(call) => self.stop_media(&call).await,
            None => self.media_stopped.unwrap_or(true),
        };
        self.media_stopped = Some(local);
        self.events = None;
        let closed = Closed { local, host };
        for reply in self.stops.drain(..) {
            let _ = reply.send(closed.clone());
        }
        self.close_inbox(&closed);
        local
    }

    /// Closes the inbox, so that a command sent from now on is turned away at once and a sender
    /// waiting for room is let go, and answers what it holds: a stop gets what the end came to, and
    /// a mute is told there is no call.
    fn close_inbox(&mut self, closed: &Closed) {
        self.inbox_gone = true;
        answer_and_close(&mut self.inbox, closed);
    }

    /// Learns what became of a start whose answer was lost, under the action it was sent under.
    ///
    /// A repeat is a question and not a second request: the host answers it from the record it
    /// kept of the action, on a connection other than the one that sent it, or does not answer
    /// it. What an answer other than a result says proves nothing about the original, which the
    /// host can still read until its window ends, so only a result settles a start; anything else
    /// leaves it unknown, and the person is told so.
    ///
    /// The questions are asked through to the end whatever the person does meanwhile: a stop
    /// stops the media at once and is answered, and the question goes on, because the host may
    /// have made a call that only its answer can name.
    async fn reconcile(
        &mut self,
        composed: &ComposedMutation,
        host: &CallHost,
        action_id: ActionId,
    ) -> Reached {
        let delays = self.shared.timings.repeat_delays;
        let within = self.shared.timings.host_within;
        let mut reached = Reached::Unknown;
        'asking: for delay in delays {
            self.wait_through(tokio::time::sleep(delay)).await;
            let reach = Arc::clone(&self.reach);
            let paired = host.paired.clone();
            let original = Arc::clone(&host.session);
            let session = match self
                .wait_through(async move { reach.session_to(&paired, Some(&original)).await })
                .await
            {
                Ok(session) => session,
                Err(_) => continue,
            };
            let asking = session.repeat(composed);
            let answered = self
                .wait_through(async move { tokio::time::timeout(within, asking).await })
                .await;
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
                // A receipt is a lost answer again, and a refusal says nothing of the original.
                Ok(Ok(Settled::Receipt(_)) | Err(_)) | Err(_) => {}
            }
            session.settle(action_id).await;
        }
        host.session.settle(action_id).await;
        reached
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
                    // The service is told after the person has their answer: it is advice to the
                    // provider, and the mute does not wait for it.
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
            // A store that cannot be read says nothing of the account.
            Err(_) => None,
            Ok(_) => Some(Cause::AccountChanged),
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
                    // The host answered a refusal: it may not know the call, or may not let this
                    // device read what the probe reads. It is reached, and not known to be back.
                    Probe::Refused(words) => {
                        let warning = format!(
                            "The host answered but would not say the call is still its own: {words}"
                        );
                        self.probe_warning = Some(warning.clone());
                        self.probe_after =
                            Some(Instant::now() + self.shared.timings.tick * PROBE_PAUSE_TICKS);
                        self.view(|state| state.warning = Some(warning));
                    }
                    Probe::Unreached => {}
                }
                self.probing = false;
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
        self.probe_after = None;
        // The refusal that stood while the host was out of reach is over with it.
        let stale = self.probe_warning.take();
        self.view(|state| {
            state.host = "reachable".to_owned();
            if state.warning == stale {
                state.warning = None;
            }
        });
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
        if let Some(host) = &self.host {
            // A call belongs to the host that made it: it ends when this device forgets that host
            // and when the person chooses another.
            if self.reach.pairing(&host.paired) == Pairing::Gone {
                return Some(Cause::HostForgotten);
            }
            if self.reach.another_host_in_use(&host.paired) {
                return Some(Cause::HostChanged);
            }
        }
        if let Some(call) = self.call.clone() {
            let (platform, internal) = (self.platform(), self.internal_tx.clone());
            tokio::spawn(async move {
                let _ = internal.send(Internal::Alive(platform.alive(&call).await));
            });
        }
        let paused = self.probe_after.is_some_and(|after| Instant::now() < after);
        if self.host_lost
            && !self.probing
            && !paused
            && let (Some(host), Some(descriptor)) = (self.host.clone(), self.descriptor.clone())
        {
            self.probing = true;
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

    /// Stops a call's media, and says whether the media is stopped: native code returned from the
    /// stop in time, or answered that the call has ended already, as it does for a call it ended
    /// itself.
    async fn stop_media(&self, call: &CallId) -> bool {
        let platform = self.platform();
        match tokio::time::timeout(self.shared.timings.local_within, platform.stop(call)).await {
            Ok(Ok(())) => true,
            Ok(Err(failure)) => {
                matches!(failure.kind, FailureKind::Ended | FailureKind::NoSuchCall)
            }
            Err(_) => false,
        }
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

        let call = self.call.take();
        let already = self.media_stopped.unwrap_or(false);
        let this = &*self;
        let local = async {
            match call {
                // Native code that does not return from a stop never holds the revocation.
                Some(call) => this.stop_media(&call).await,
                None => already,
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
        self.media_stopped = Some(closed_locally);
        self.shared.host_was_told(self.id);
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
        if let (HostEnd::NotTold { words }, Some(descriptor)) = (&host_end, &self.descriptor) {
            // The grant may be live at the host until the moment the call was to close.
            let owed = OwedView {
                kind: "revocation".to_owned(),
                words: words.clone(),
                action_id: None,
                voice_session_id: Some(descriptor.voice_session_id.to_string()),
                until_ms: descriptor.closes_at_ms.get(),
            };
            self.view(|state| state.owe(now_ms(), owed));
        }
        if matches!(cause, Cause::Control(ControlEnd::NoSuchCall)) {
            self.shared.remember_no_such_call(self.note_key());
        }
        // Another call can be started from here; this one is only finalising at the service.
        self.release();
        for reply in self.stops.drain(..) {
            let _ = reply.send(closed.clone());
        }
        self.close_inbox(&closed);

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
        if self
            .shared
            .close_over_http(&self.tokens, &descriptor.call_id)
            .await
        {
            return "closed_over_http";
        }
        "not_confirmed"
    }
}

/// The moment this device holds a call to, in milliseconds since the epoch, or none when the call
/// is not one to carry.
///
/// The host says when the call closes. This device holds the call to that, and to no more than it
/// asked for, with room for a clock that is not its own: a closing time later than that is held
/// down to what was asked for, and one that is long past (further than the clock may differ) is
/// not a call to carry. A host whose clock is a little behind gives a time that is a little past,
/// which native code ends the call at.
fn hold_until(host_closes_ms: u64, requested_seconds: u32, now_ms: u64) -> Option<u64> {
    if host_closes_ms.saturating_add(MAX_CLOCK_SKEW_MS) <= now_ms {
        return None;
    }
    let latest = now_ms
        .saturating_add(u64::from(requested_seconds) * 1000)
        .saturating_add(MAX_CLOCK_SKEW_MS);
    Some(host_closes_ms.min(latest))
}

/// How many ticks the host path is left alone after the host refused to vouch for the call.
const PROBE_PAUSE_TICKS: u32 = 6;

/// Closes `inbox` and answers what it holds: a stop gets `closed`, and a mute is told there is no
/// call. A command sent afterwards fails at once, and a sender waiting for room is let go, so
/// nobody is left waiting on a task that is done.
fn answer_and_close(inbox: &mut mpsc::Receiver<Cmd>, closed: &Closed) {
    inbox.close();
    while let Ok(cmd) = inbox.try_recv() {
        match cmd {
            Cmd::Stop(reply) => {
                let _ = reply.send(closed.clone());
            }
            Cmd::Mute { reply, .. } => {
                let _ = reply.send(Err(CommandError::refused(
                    "this device is not holding a voice call",
                )));
            }
        }
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
        Ok(Err(ClientError::Host(error))) => Probe::Refused(error.message),
        _ => Probe::Unreached,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The closing time this device holds a call to is the host's, held down to what was asked
    /// for with room for a clock that is not its own, and a call that closed long ago is not
    /// carried.
    #[test]
    fn a_call_is_held_to_the_host_s_closing_time_within_what_was_asked_for() {
        const NOW: u64 = 1_000_000_000;
        // As asked: ten minutes.
        assert_eq!(hold_until(NOW + 600_000, 600, NOW), Some(NOW + 600_000));
        // A host whose clock is ahead gives a later time than was asked for: the call is held to
        // what was asked for, with the room for clocks, and not ended for it.
        assert_eq!(
            hold_until(NOW + 100_000_000, 600, NOW),
            Some(NOW + 600_000 + MAX_CLOCK_SKEW_MS)
        );
        // A host whose clock is a little behind gives a time a little past, and the call is
        // carried: native code ends it at that moment.
        assert_eq!(hold_until(NOW - 5_000, 600, NOW), Some(NOW - 5_000));
        // One that closed longer ago than clocks differ is not a call to carry.
        assert_eq!(hold_until(NOW - MAX_CLOCK_SKEW_MS, 600, NOW), None);
    }

    /// Nobody is left waiting on an owner that is done: what its inbox holds is answered, and a
    /// command sent afterwards is turned away at once instead of waiting for an answer that no one
    /// will give.
    #[tokio::test]
    async fn a_closed_inbox_answers_what_it_holds_and_turns_later_senders_away() {
        let (commands, mut inbox) = mpsc::channel(8);
        let (stop, stopped) = oneshot::channel();
        let (mute, muted) = oneshot::channel();
        commands.send(Cmd::Stop(stop)).await.expect("room");
        commands
            .send(Cmd::Mute {
                what: Mute::Microphone,
                muted: true,
                reply: mute,
            })
            .await
            .expect("room");

        answer_and_close(
            &mut inbox,
            &Closed {
                local: true,
                host: HostEnd::NotNeeded,
            },
        );

        assert!(stopped.await.expect("the stop is answered").local);
        muted
            .await
            .expect("the mute is answered")
            .expect_err("there is no call to mute");
        let (late, _) = oneshot::channel();
        assert!(
            commands.send(Cmd::Stop(late)).await.is_err(),
            "a command sent after the end is turned away"
        );
    }
}
