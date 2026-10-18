//! The voice call of a phone, owned by this process.
//!
//! Section 15 puts capture, playback and the media connection in native code, and everything else
//! about a call here: asking for it, finding out whether the host made it, applying the provider's
//! answer, permitting it, keeping the control socket to the voice service, and ending it by
//! whatever cause. The page asks and reads; it holds nothing a loaded page would lose.
//!
//! One call at a time, one task for each (`owner`). The screen reads the call from the record
//! that task keeps ([`VoiceCallState`]), so a screen that is loaded again finds the call it left,
//! and a call that ends while no screen is looking (the notification's stop, a failed connection,
//! the voice service closing it) is ended in full: the media, the host's grant and the call at the
//! service.
//!
//! This version acts on nothing a person says. Each delegation the provider announces is answered
//! to the model by a fixed sentence that nothing was done, and the screen is shown a row saying
//! so.

mod cause;
mod host;
mod kept;
mod owner;
mod view;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use companion_platform::call::{CallId, CallPlatform, Mute};
use kr_client::services::account::SignedInAccount;
use kr_client::services::voice::{ManagedVoiceBroker, ManagedVoiceService as _};
use kr_client::services::voice_control::ControlConnector;
use kr_client::services::{AccountTokenSource, ServiceHttp};
use kr_protocol::ids::{ActionId, SessionId, VoiceSessionId};
use kr_protocol::scalars::Digest256;
use kr_protocol::voice::VoiceStartResult;
use tokio::sync::{mpsc, oneshot};

pub use cause::Cause;
pub use host::{AppReach, CallHost, HostReach, Pairing, Reaching};
pub use kept::{Kept, KeptVoice};
pub use view::{DelegationRow, EndedView, HostEnd, OwedView, VoiceCallState};

use crate::error::{CommandError, Result};
use crate::target::Subject;

/// How long this process waits for each thing it has no better bound for.
#[derive(Clone, Copy, Debug)]
pub struct Timings {
    /// Between signs of life to native code, and between looks at the host path.
    pub tick: Duration,
    /// How many signs in a row native code may leave unanswered before the call is ended.
    pub silent_signs: u32,
    /// How long native code is given to stop a call before the host is asked without waiting for it.
    pub local_within: Duration,
    /// How long the host is given to answer a stop or a question.
    pub host_within: Duration,
    /// How long the host is given to answer a start before the answer is taken as lost.
    pub start_within: Duration,
    /// How long the account is given to produce its voice token.
    pub token_within: Duration,
    /// How long the voice service's own route is given to close a call.
    pub close_within: Duration,
    /// The waits before each repeat of a start whose answer was lost.
    pub repeat_delays: [Duration; 3],
}

impl Default for Timings {
    fn default() -> Self {
        Self {
            tick: Duration::from_secs(10),
            silent_signs: 3,
            local_within: Duration::from_secs(20),
            host_within: Duration::from_secs(20),
            start_within: Duration::from_secs(90),
            token_within: Duration::from_secs(20),
            close_within: Duration::from_secs(15),
            repeat_delays: [
                Duration::from_secs(2),
                Duration::from_secs(8),
                Duration::from_secs(30),
            ],
        }
    }
}

/// The voice service this device's account is signed in at.
#[derive(Clone)]
pub struct Service {
    /// Its origin, which is the only one the account's token is presented at.
    pub origin: String,
    /// How its HTTP routes are reached.
    pub http: Arc<dyn ServiceHttp>,
    /// How its control sockets are opened.
    pub connector: ControlConnector,
}

impl Service {
    /// The managed voice service, at the fixed origin the account is signed in at, reached the way
    /// the account service is.
    ///
    /// # Errors
    ///
    /// Returns why the transport or the platform's certificate verifier cannot be set up.
    pub fn managed() -> std::result::Result<Self, String> {
        use kr_client::services::account::ACCOUNT_ORIGIN;
        use kr_client::services::{HttpDeadlines, HttpService, managed_response_limits};

        let gateway = kr_protocol::service::GatewayOrigin::new(ACCOUNT_ORIGIN)
            .map_err(|error| error.to_string())?;
        let http = HttpService::with(gateway, HttpDeadlines::default(), managed_response_limits())
            .map_err(|error| error.to_string())?;
        let connector = ControlConnector::platform().map_err(|error| error.to_string())?;
        Ok(Self {
            origin: ACCOUNT_ORIGIN.to_owned(),
            http: Arc::new(http),
            connector,
        })
    }
}

/// What the page asks of a start.
pub struct StartRequest {
    /// The sessions the call may reach.
    pub session_ids: Vec<SessionId>,
    /// Seconds of call to ask the service to authorise.
    pub duration_seconds: u32,
    /// Minor units to hold for reasoning and tools.
    pub reasoning_budget_minor: Option<u64>,
    /// The preparation the person was shown.
    pub prepared: Digest256,
    /// The version of the rate the person was shown.
    pub expected_rate_version: Option<String>,
    /// What the start names.
    pub subject: Subject,
}

/// What a start came to.
pub enum Started {
    /// The host's answer: a call, or why there is none.
    Result(VoiceStartResult),
    /// The host answered with a receipt.
    Receipt(Box<kr_protocol::receipt::Receipt>),
    /// The host never said whether it made the call.
    Unknown {
        /// The action the start was sent under, which is what a later question about it names.
        action_id: ActionId,
    },
}

/// What ending a call did on this device and at the host.
#[derive(Clone, Debug)]
pub struct Closed {
    /// Whether the call's media was stopped here.
    pub local: bool,
    /// What the host did.
    pub host: HostEnd,
}

/// What a page or a command asks of the task that owns the call.
pub(crate) enum Cmd {
    /// End the call.
    Stop(oneshot::Sender<Closed>),
    /// Silence something, or end the silence.
    Mute {
        what: Mute,
        muted: bool,
        reply: oneshot::Sender<Result<VoiceCallState>>,
    },
}

/// What a remembered "no such call" is about: the same host, account grant and service.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct NoteKey {
    /// The host's environment.
    pub environment: Option<String>,
    /// The account's grant generation.
    pub generation: Option<String>,
    /// The voice service.
    pub origin: String,
}

/// What an owner that failed leaves for the supervisor to finish.
struct Emergency {
    call: Option<CallId>,
    host: Option<CallHost>,
    voice_session_id: Option<VoiceSessionId>,
    /// The call at the voice service, and the moment the host's grant for it ends by itself.
    service_call: Option<(String, u64)>,
    /// A start the host has not been heard to answer: the action it was sent under, and the
    /// moment a call it made would end by itself.
    pending_start: Option<(ActionId, u64)>,
    reach: Arc<dyn HostReach>,
    tokens: Arc<SignedInAccount>,
}

/// The time now, in milliseconds since the epoch.
pub(crate) fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}

/// What the owner and the commands share.
pub(crate) struct Shared {
    platform: Arc<dyn CallPlatform>,
    service: Service,
    timings: Timings,
    slot: Mutex<Option<(u64, mpsc::Sender<Cmd>)>>,
    next_owner: std::sync::atomic::AtomicU64,
    view: Mutex<VoiceCallState>,
    note: Mutex<Option<NoteKey>>,
    emergency: Mutex<Option<(u64, Emergency)>>,
    /// Where what outlives a launch is kept.
    kept: Kept,
    /// Held from the moment what is kept is copied until it is written, so that what is written
    /// last is what was copied last: a copy taken earlier never replaces a later one.
    keeping: Mutex<()>,
}

impl Shared {
    /// Frees the slot `owner` holds, so another call can be started. The slot of another owner is
    /// left as it is: an owner that is still finalising a call must not free the next one's.
    pub(crate) fn release(&self, owner: u64) {
        let mut slot = self.slot.lock().expect("the slot lock is not poisoned");
        if slot.as_ref().is_some_and(|(held, _)| *held == owner) {
            *slot = None;
        }
    }

    pub(crate) fn clear_note(&self) {
        let had = self
            .note
            .lock()
            .expect("the note lock is not poisoned")
            .take()
            .is_some();
        if had {
            self.keep();
        }
    }

    pub(crate) fn remember_no_such_call(&self, key: NoteKey) {
        *self.note.lock().expect("the note lock is not poisoned") = Some(key);
        self.keep();
    }

    /// Notes something owed, and keeps it for the next launch.
    pub(crate) fn owe(&self, owed: OwedView) {
        self.view
            .lock()
            .expect("the view lock is not poisoned")
            .owe(now_ms(), owed);
        self.keep();
    }

    /// Writes what outlives a launch: what is owed, and the note. A write that fails is logged and
    /// leaves the record in memory, which is what the screen reads: ending a call is never stopped
    /// by a file.
    pub(crate) fn keep(&self) {
        let _ordered = self
            .keeping
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let owed = self
            .view
            .lock()
            .expect("the view lock is not poisoned")
            .owed
            .clone();
        let note = self
            .note
            .lock()
            .expect("the note lock is not poisoned")
            .clone();
        if let Err(error) = self.kept.write(&KeptVoice { owed, note }) {
            tracing::warn!(%error, "what a voice call left owed could not be kept");
        }
    }

    /// Takes a revocation out of what is owed, because the host it is owed to has revoked the grant.
    /// Only an entry owed to that host and environment goes: another host's answer says nothing of
    /// what a different host holds.
    fn settled(
        &self,
        host: kr_protocol::ids::DeviceId,
        environment: kr_protocol::ids::EnvironmentId,
        voice_session_id: &str,
    ) {
        let removed = {
            let mut view = self.view.lock().expect("the view lock is not poisoned");
            let before = view.owed.len();
            view.owed.retain(|owed| {
                owed.kind != "revocation"
                    || owed.voice_session_id.as_deref() != Some(voice_session_id)
                    || owed.host != Some((host, environment))
            });
            view.owed.len() != before
        };
        if removed {
            self.keep();
        }
    }

    /// Keeps what the supervisor needs to end the call if its owner fails.
    pub(crate) fn keep_for_emergency(
        &self,
        owner: u64,
        call: Option<CallId>,
        host: Option<&CallHost>,
        descriptor: Option<&kr_protocol::voice::VoiceSessionDescriptor>,
        reach: &Arc<dyn HostReach>,
        tokens: &Arc<SignedInAccount>,
    ) {
        let mut kept = self
            .emergency
            .lock()
            .expect("the emergency lock is not poisoned");
        // A start that was not heard to be answered stays pending until the host names the call.
        let pending_start = match (&*kept, descriptor) {
            (Some((held, before)), None) if *held == owner => before.pending_start,
            _ => None,
        };
        *kept = Some((
            owner,
            Emergency {
                call,
                host: host.cloned(),
                voice_session_id: descriptor.map(|descriptor| descriptor.voice_session_id),
                service_call: descriptor.map(|descriptor| {
                    (
                        descriptor.call_id.clone(),
                        owner::owed_until(descriptor.closes_at_ms.get()),
                    )
                }),
                pending_start,
                reach: Arc::clone(reach),
                tokens: Arc::clone(tokens),
            },
        ));
    }

    /// Says that the host has been sent a start under `action_id` and not been heard to answer
    /// it, so a supervisor that finishes the call after a failure keeps the start as owed.
    pub(crate) fn keep_start_pending(&self, owner: u64, action_id: ActionId, until_ms: u64) {
        let mut kept = self
            .emergency
            .lock()
            .expect("the emergency lock is not poisoned");
        if let Some((held, kept)) = kept.as_mut()
            && *held == owner
        {
            kept.pending_start = Some((action_id, until_ms));
        }
    }

    /// Says that the host has answered the start, so it is no longer pending.
    pub(crate) fn start_was_answered(&self, owner: u64) {
        let mut kept = self
            .emergency
            .lock()
            .expect("the emergency lock is not poisoned");
        if let Some((held, kept)) = kept.as_mut()
            && *held == owner
        {
            kept.pending_start = None;
        }
    }

    /// Says that the owner has told the host to revoke the call's grant, so a supervisor that
    /// finishes the call after a failure does not ask the host again.
    pub(crate) fn host_was_told(&self, owner: u64) {
        let mut kept = self
            .emergency
            .lock()
            .expect("the emergency lock is not poisoned");
        if let Some((held, kept)) = kept.as_mut()
            && *held == owner
        {
            kept.host = None;
            kept.voice_session_id = None;
        }
    }

    /// Closes a call at the voice service over its own route, with the account's token, and says
    /// whether the service confirmed. The close runs on a task of its own: it takes the account's
    /// token, and a refresh that a wait gave up on half way could lose the token it rotated.
    pub(crate) async fn close_over_http(
        &self,
        tokens: &Arc<SignedInAccount>,
        call_id: &str,
    ) -> bool {
        let Ok(broker) = ManagedVoiceBroker::new(
            self.service.origin.clone(),
            Arc::clone(&self.service.http),
            Arc::clone(tokens) as Arc<dyn AccountTokenSource>,
        ) else {
            return false;
        };
        let call_id = call_id.to_owned();
        let closing = tokio::spawn(async move { broker.close(&call_id).await });
        matches!(
            tokio::time::timeout(self.timings.close_within, closing).await,
            Ok(Ok(Ok(_)))
        )
    }

    pub(crate) fn forget_emergency(&self, owner: u64) {
        let mut kept = self
            .emergency
            .lock()
            .expect("the emergency lock is not poisoned");
        if kept.as_ref().is_some_and(|(held, _)| *held == owner) {
            *kept = None;
        }
    }

    /// Stops a call's media, and says whether the media is stopped: native code returned from the
    /// stop in time, or answered that the call has ended already, as it does for a call it ended
    /// itself.
    pub(crate) async fn stop_media(&self, call: &CallId) -> bool {
        match tokio::time::timeout(self.timings.local_within, self.platform.stop(call)).await {
            Ok(Ok(())) => true,
            Ok(Err(failure)) => matches!(
                failure.kind,
                companion_platform::call::FailureKind::Ended
                    | companion_platform::call::FailureKind::NoSuchCall
            ),
            Err(_) => false,
        }
    }

    /// Ends a call whose owner failed: the media, then the host's grant.
    ///
    /// What the owner had already written of the end stands. It is the owner's account of what the
    /// host answered, and only what it left pending is settled here.
    async fn finish_failed_owner(&self, owner: u64) {
        let kept = {
            let mut kept = self
                .emergency
                .lock()
                .expect("the emergency lock is not poisoned");
            if kept.as_ref().is_some_and(|(held, _)| *held == owner) {
                kept.take().map(|(_, kept)| kept)
            } else {
                None
            }
        };
        let Some(kept) = kept else {
            // The owner failed before it kept anything to finish: no call was named to it, and it
            // wrote no end. This one says the call stopped working, and that nothing is known of
            // the media, before the slot is free for another.
            let mut view = self.view.lock().expect("the view lock is not poisoned");
            if view.owner == owner {
                view.running = false;
                view.session = None;
                view.control = "none".to_owned();
                view.host = "none".to_owned();
                if view.ended.as_ref().is_none_or(|ended| ended.owner != owner) {
                    view.ended = Some(EndedView {
                        owner,
                        cause: "owner_failed".to_owned(),
                        words: "This device's call stopped working, so the call was ended."
                            .to_owned(),
                        closed_locally: false,
                        host: HostEnd::NotNeeded,
                        broker: "not_needed".to_owned(),
                    });
                }
            }
            drop(view);
            self.release(owner);
            return;
        };
        let local = async {
            match &kept.call {
                Some(call) => self.stop_media(call).await,
                None => false,
            }
        };
        let toward_host = async {
            match (&kept.host, kept.voice_session_id) {
                (Some(host), Some(id)) => {
                    Some(owner::stop_at_host(&kept.reach, host, id, self.timings.host_within).await)
                }
                _ => None,
            }
        };
        {
            let mut view = self.view.lock().expect("the view lock is not poisoned");
            view.begin_ending(owner);
            // The call is being ended, not running, from here on.
            if view.owner <= owner {
                view.running = false;
            }
        }
        let (closed_locally, host_end) = tokio::join!(local, toward_host);
        let toward_host_asked = host_end.is_some();
        let mut owed = Vec::new();
        // A start the host was not heard to answer may have made a call, so it is not a host that
        // was never asked: it has said nothing.
        let host_end = host_end.unwrap_or_else(|| {
            if kept.pending_start.is_some() {
                HostEnd::NotTold {
                    words: "The host never said whether it created the call.".to_owned(),
                }
            } else {
                HostEnd::NotNeeded
            }
        });
        // What the owner wrote of the host's answer, when it got as far as writing it.
        let written = {
            let view = self.view.lock().expect("the view lock is not poisoned");
            view.ended
                .as_ref()
                .filter(|ended| ended.owner == owner)
                .map(|ended| ended.host.clone())
        };
        // The service is asked over its own route unless the host told it.
        let broker = match (&kept.service_call, written.as_ref().unwrap_or(&host_end)) {
            (
                _,
                HostEnd::Revoked {
                    broker_notified: true,
                    ..
                },
            ) => "closed_by_host",
            (Some((call_id, _)), _) => {
                if self.close_over_http(&kept.tokens, call_id).await {
                    "closed_over_http"
                } else {
                    "not_confirmed"
                }
            }
            // A start the host may have answered made a call this device cannot name.
            (None, _) if kept.pending_start.is_some() => "unknown",
            (None, _) => "not_needed",
        };
        {
            let mut view = self.view.lock().expect("the view lock is not poisoned");
            // A call that began after this one has its own record, which this does not touch.
            if view.owner <= owner {
                view.running = false;
                view.session = None;
                view.control = "none".to_owned();
                view.host = "none".to_owned();
                match view.ended.as_mut().filter(|ended| ended.owner == owner) {
                    Some(ended) => {
                        if ended.broker == "pending" {
                            ended.broker = broker.to_owned();
                        }
                    }
                    None => {
                        view.ended = Some(EndedView {
                            owner,
                            cause: "owner_failed".to_owned(),
                            words: "This device's call stopped working, so the call was ended."
                                .to_owned(),
                            closed_locally,
                            host: host_end.clone(),
                            broker: broker.to_owned(),
                        });
                    }
                }
            }
            if let (Some(words), Some((_, until_ms)), Some(id), Some(host), true) = (
                host_end.owed_reason(),
                &kept.service_call,
                kept.voice_session_id,
                &kept.host,
                toward_host_asked,
            ) {
                owed.push(OwedView::revocation(words, id, *until_ms, host));
            }
            if let (Some((action_id, until_ms)), Some(host)) = (kept.pending_start, &kept.host) {
                owed.push(OwedView::start_unknown(action_id, until_ms, host));
            }
        }
        for each in owed {
            self.owe(each);
        }
        self.release(owner);
    }
}

/// The voice calls of this application.
pub struct Calls {
    shared: Option<Arc<Shared>>,
}

impl Calls {
    /// The calls of an application that holds none: a desktop.
    #[must_use]
    pub const fn absent() -> Self {
        Self { shared: None }
    }

    /// The calls of a phone, made through `platform` and controlled at `service`, taking up what
    /// the calls before this launch left in `kept`: what is still owed, and the note.
    #[must_use]
    pub fn on_phone(
        platform: Arc<dyn CallPlatform>,
        service: Service,
        timings: Timings,
        kept: Kept,
    ) -> Self {
        let before = kept.read(now_ms());
        let mut view = VoiceCallState::no_call();
        view.owed = before.owed;
        Self {
            shared: Some(Arc::new(Shared {
                platform,
                service,
                timings,
                slot: Mutex::new(None),
                next_owner: std::sync::atomic::AtomicU64::new(1),
                view: Mutex::new(view),
                note: Mutex::new(before.note),
                emergency: Mutex::new(None),
                kept,
                keeping: Mutex::new(()),
            })),
        }
    }

    /// Says that the host a call left a grant at is reached, over `session`, so that what this
    /// device owes it is asked once more: each revocation owed to `host` in `environment` that has
    /// not lapsed goes to the host again. That the host revoked the grant settles it; a refusal, or
    /// no answer, leaves it owed until the grant lapses, because a refusal does not say the grant
    /// is gone. It runs on a task of its own and the screen does not wait for it.
    pub fn host_reached(
        &self,
        host: kr_protocol::ids::DeviceId,
        environment: kr_protocol::ids::EnvironmentId,
        session: Arc<kr_client::Session>,
    ) {
        let Some(shared) = self.shared.clone() else {
            return;
        };
        let owed: Vec<(VoiceSessionId, u64)> = shared
            .view
            .lock()
            .expect("the view lock is not poisoned")
            .owed
            .iter()
            .filter(|owed| owed.kind == "revocation" && owed.host == Some((host, environment)))
            .filter_map(|owed| {
                Some((
                    owed.voice_session_id.as_deref()?.parse().ok()?,
                    owed.until_ms,
                ))
            })
            .collect();
        if owed.is_empty() {
            return;
        }
        tokio::spawn(async move {
            for (voice_session_id, until_ms) in owed {
                // What has lapsed is not asked: the grant has ended by itself.
                if until_ms <= now_ms() {
                    continue;
                }
                let end = host::revoke(
                    &session,
                    environment,
                    voice_session_id,
                    shared.timings.host_within,
                )
                .await;
                // Only a revocation done settles it: a refusal may come from a host that did not
                // look at the session, and the grant is then still live.
                if matches!(end, HostEnd::Revoked { .. }) {
                    shared.settled(host, environment, &voice_session_id.to_string());
                }
            }
        });
    }

    /// What a remembered "no such call" would have to be about to apply to a call started now, or
    /// nothing on a device that holds no calls.
    #[must_use]
    pub fn note_key(
        &self,
        environment: Option<String>,
        generation: Option<String>,
    ) -> Option<NoteKey> {
        let shared = self.shared.as_ref()?;
        Some(NoteKey {
            environment,
            generation,
            origin: shared.service.origin.clone(),
        })
    }

    fn shared(&self) -> Result<&Arc<Shared>> {
        self.shared.as_ref().ok_or_else(|| {
            CommandError::unsupported("this application cannot open a voice call on this device")
        })
    }

    /// Starts a call and returns when it runs, when the host declined it, or when it could not be
    /// started.
    ///
    /// # Errors
    ///
    /// Returns why no call was started: this device cannot hold one, is holding one, has no
    /// account that could control it, or a step failed. A call the host created is ended before
    /// this returns.
    pub async fn start(
        &self,
        request: StartRequest,
        reach: Arc<dyn HostReach>,
        tokens: Arc<SignedInAccount>,
    ) -> Result<Started> {
        let shared = self.shared()?;
        let (commands, inbox) = mpsc::channel(8);
        let owner = shared
            .next_owner
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        {
            let mut slot = shared.slot.lock().expect("the slot lock is not poisoned");
            if slot.is_some() {
                return Err(CommandError::refused(
                    "this device is already holding a voice call, or is still ending one",
                ));
            }
            *slot = Some((owner, commands));
        }
        let (reply, answer) = oneshot::channel();
        let task = tokio::spawn(owner::drive(
            Arc::clone(shared),
            owner::Launch {
                id: owner,
                request,
                reach,
                tokens,
                inbox,
                reply,
            },
        ));
        let watched = Arc::clone(shared);
        tokio::spawn(async move {
            if let Err(error) = task.await
                && error.is_panic()
            {
                watched.finish_failed_owner(owner).await;
            }
        });
        answer
            .await
            .map_err(|_| CommandError::local_failure("the call's owner ended without answering"))?
    }

    /// Ends the call this device holds, or, when it holds none, asks the host to revoke the voice
    /// session `voice_session_id` names.
    ///
    /// # Errors
    ///
    /// Returns why nothing could be asked: no call is held and no voice session was named.
    pub async fn stop(
        &self,
        voice_session_id: Option<VoiceSessionId>,
        reach: &dyn HostReach,
    ) -> Result<Closed> {
        let shared = self.shared()?;
        let commands = shared
            .slot
            .lock()
            .expect("the slot lock is not poisoned")
            .as_ref()
            .map(|(_, commands)| commands.clone());
        let holding = commands.is_some();
        if let Some(commands) = commands {
            let held = shared
                .view
                .lock()
                .expect("the view lock is not poisoned")
                .session
                .as_ref()
                .map(|session| session.voice_session_id);
            // A page that names another call than the one held is stale: it ends nothing of the
            // held call's, and asks the host about what it named.
            if voice_session_id.is_none() || (held.is_some() && voice_session_id == held) {
                let (reply, answer) = oneshot::channel();
                if commands.send(Cmd::Stop(reply)).await.is_ok()
                    && let Ok(closed) = answer.await
                {
                    return Ok(closed);
                }
            }
        }
        let Some(voice_session_id) = voice_session_id else {
            return Err(CommandError::refused(if holding {
                "this device is already ending its call, and nothing more can be asked of it"
            } else {
                "this device is not holding a voice call"
            }));
        };
        let host = reach.in_use()?;
        let end = host::revoke(
            &host.session,
            host.environment_id,
            voice_session_id,
            shared.timings.host_within,
        )
        .await;
        // A host that revoked the grant settles what this device owed it for that call.
        if matches!(end, HostEnd::Revoked { .. }) {
            shared.settled(
                host.paired.host_device_id,
                host.environment_id,
                &voice_session_id.to_string(),
            );
        }
        Ok(Closed {
            local: false,
            host: end,
        })
    }

    /// Silences the microphone or the model's voice, or ends the silence.
    ///
    /// # Errors
    ///
    /// Returns why nothing was silenced: no call is running, or native code would not.
    pub async fn set_muted(&self, what: Mute, muted: bool) -> Result<VoiceCallState> {
        let shared = self.shared()?;
        let commands = shared
            .slot
            .lock()
            .expect("the slot lock is not poisoned")
            .as_ref()
            .map(|(_, commands)| commands.clone())
            .ok_or_else(|| CommandError::refused("this device is not holding a voice call"))?;
        let (reply, answer) = oneshot::channel();
        commands
            .send(Cmd::Mute { what, muted, reply })
            .await
            .map_err(|_| CommandError::refused("this device is not holding a voice call"))?;
        answer
            .await
            .map_err(|_| CommandError::refused("this device is not holding a voice call"))?
    }

    /// What the call is doing, and, when `note` is the host, account and service of a call that
    /// found no such call, the warning a person is shown before starting another.
    #[must_use]
    pub fn state(&self, note: Option<&NoteKey>) -> VoiceCallState {
        let Some(shared) = &self.shared else {
            return VoiceCallState::no_call();
        };
        // The slot is the one record of whether this device is busy with a call: a call that is
        // being made or given up holds it from the moment the start is taken until it is over,
        // before any descriptor exists to name it. It is read first: a call writes its end and
        // then frees the slot, so a read that finds the slot free finds the end too.
        let busy = shared
            .slot
            .lock()
            .expect("the slot lock is not poisoned")
            .is_some();
        let mut state = shared
            .view
            .lock()
            .expect("the view lock is not poisoned")
            .clone();
        state.setting_up = busy && !state.running;
        state.ending = state.setting_up && state.ending;
        let now = now_ms();
        state.owed.retain(|owed| owed.until_ms > now);
        let remembered = shared
            .note
            .lock()
            .expect("the note lock is not poisoned")
            .clone();
        if state.warning.is_none()
            && !state.running
            && remembered.as_ref().is_some_and(|kept| Some(kept) == note)
        {
            state.warning = Some(
                "The last call found that this voice service has no such call for this account. \
                 You can start another, and it may end the same way."
                    .to_owned(),
            );
        }
        state
    }
}
