//! The voice call of a phone, owned by this process.
//!
//! Section 15 puts capture, playback and the media connection in native code, and everything else
//! about a call here: asking for it, finding out whether the host made it, applying the provider's
//! answer, permitting it, keeping the control socket to the voice service, and ending it by
//! whatever cause. The page asks and reads; it holds nothing a loaded page would lose.
//!
//! One call at a time, one task for each ([`owner`]). The screen reads the call from the record
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
mod owner;
mod view;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use companion_platform::call::{CallId, CallPlatform, Mute};
use kr_client::services::ServiceHttp;
use kr_client::services::account::SignedInAccount;
use kr_client::services::voice_control::ControlConnector;
use kr_protocol::ids::{ActionId, SessionId, VoiceSessionId};
use kr_protocol::scalars::Digest256;
use kr_protocol::voice::VoiceStartResult;
use tokio::sync::{mpsc, oneshot};

pub use cause::Cause;
pub use host::{AppReach, CallHost, HostReach, Reaching};
pub use view::{DelegationRow, EndedView, HostEnd, VoiceCallState};

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
#[derive(Clone, Debug, PartialEq, Eq)]
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
    reach: Arc<dyn HostReach>,
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
        *self.note.lock().expect("the note lock is not poisoned") = None;
    }

    pub(crate) fn remember_no_such_call(&self, key: NoteKey) {
        *self.note.lock().expect("the note lock is not poisoned") = Some(key);
    }

    /// Keeps what the supervisor needs to end the call if its owner fails.
    pub(crate) fn keep_for_emergency(
        &self,
        owner: u64,
        call: Option<CallId>,
        host: Option<&CallHost>,
        descriptor: Option<&kr_protocol::voice::VoiceSessionDescriptor>,
        reach: &Arc<dyn HostReach>,
    ) {
        *self
            .emergency
            .lock()
            .expect("the emergency lock is not poisoned") = Some((
            owner,
            Emergency {
                call,
                host: host.cloned(),
                voice_session_id: descriptor.map(|descriptor| descriptor.voice_session_id),
                reach: Arc::clone(reach),
            },
        ));
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

    /// Ends a call whose owner failed: the media, then the host's grant.
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
            self.release(owner);
            return;
        };
        let local = async {
            if let Some(call) = &kept.call {
                let _ =
                    tokio::time::timeout(self.timings.local_within, self.platform.stop(call)).await;
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
        let (_, host_end) = tokio::join!(local, toward_host);
        let mut view = self.view.lock().expect("the view lock is not poisoned");
        view.running = false;
        view.session = None;
        view.ended = Some(EndedView {
            owner,
            cause: "owner_failed".to_owned(),
            words: "This device's call stopped working, so the call was ended.".to_owned(),
            closed_locally: kept.call.is_some(),
            host: host_end.unwrap_or(HostEnd::NotNeeded),
            broker: "not_confirmed".to_owned(),
        });
        drop(view);
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

    /// The calls of a phone, made through `platform` and controlled at `service`.
    #[must_use]
    pub fn on_phone(platform: Arc<dyn CallPlatform>, service: Service, timings: Timings) -> Self {
        Self {
            shared: Some(Arc::new(Shared {
                platform,
                service,
                timings,
                slot: Mutex::new(None),
                next_owner: std::sync::atomic::AtomicU64::new(1),
                view: Mutex::new(VoiceCallState::no_call()),
                note: Mutex::new(None),
                emergency: Mutex::new(None),
            })),
        }
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
            return Err(CommandError::refused(
                "this device is not holding a voice call",
            ));
        };
        let host = reach.in_use()?;
        let end = host::revoke(
            &host.session,
            host.environment_id,
            voice_session_id,
            shared.timings.host_within,
        )
        .await;
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
        let mut state = shared
            .view
            .lock()
            .expect("the view lock is not poisoned")
            .clone();
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
