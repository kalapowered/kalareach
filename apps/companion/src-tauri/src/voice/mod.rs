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

/// A call at the voice service, with what a notice that the service has not closed it is built from.
#[derive(Clone)]
pub(crate) struct ServiceCall {
    pub(crate) call_id: String,
    pub(crate) voice_session_id: VoiceSessionId,
    /// The moment the notice lapses: the call's own limit by the host's reading, and the clock
    /// allowance.
    pub(crate) until_ms: u64,
    pub(crate) host: CallHost,
}

/// What an owner that failed leaves for the supervisor to finish.
struct Emergency {
    call: Option<CallId>,
    host: Option<CallHost>,
    voice_session_id: Option<VoiceSessionId>,
    /// The call at the voice service, and what is owed if the service does not confirm it closed.
    service_call: Option<ServiceCall>,
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
    /// Whether what the launches before this one kept could not be read when it was tried, so that
    /// it is read again at the next use. A phone started before its first unlock cannot read its
    /// files, and a file it cannot read is not one that holds nothing: the view says nothing is
    /// owed only until the file can be read, and nothing is written over the file meanwhile.
    unread: std::sync::atomic::AtomicBool,
    /// Whether the note was remembered or forgotten since the read that failed, so that what is
    /// read later is older than the note and does not replace it.
    note_changed: std::sync::atomic::AtomicBool,
    /// Held from the moment what is kept is copied until it is written, so that what is written
    /// last is what was copied last: a copy taken earlier never replaces a later one.
    keeping: Mutex<()>,
    /// What this process owes the host for the call it holds, which nothing else records yet: it
    /// is kept in the file from the moment the host is asked to start the call, so that a process
    /// that ends during the call leaves it owed, and it is not in `view`, so that the host being
    /// reached while the call runs cannot ask to stop the call that is running. The end of the call
    /// replaces it with what the end owes, and it is cleared only by the owner that opened it.
    standing: Mutex<Option<(u64, OwedView)>>,
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
        self.read_again();
        let had = {
            let mut note = self.note.lock().expect("the note lock is not poisoned");
            self.note_changed
                .store(true, std::sync::atomic::Ordering::SeqCst);
            note.take().is_some()
        };
        if had {
            self.keep();
        }
    }

    pub(crate) fn remember_no_such_call(&self, key: NoteKey) {
        {
            let mut note = self.note.lock().expect("the note lock is not poisoned");
            self.note_changed
                .store(true, std::sync::atomic::Ordering::SeqCst);
            *note = Some(key);
        }
        self.keep();
    }

    /// Reads what the launches before this one kept again, when the first read was refused, and
    /// takes it up: what it holds comes before what was owed since, and a note remembered or
    /// forgotten since is newer than the file's and stands. It is written back whole when anything
    /// was owed or noted meanwhile, so that nothing owed in this launch waits for the next one.
    /// Every use of the record starts here.
    pub(crate) fn read_again(&self) {
        if !self.unread.load(std::sync::atomic::Ordering::SeqCst) {
            return;
        }
        let _ordered = self
            .keeping
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.take_up_unread() == Some(true) {
            self.write_kept();
        }
    }

    /// Takes up what the file holds, if it can be read now. `None` while it cannot, and otherwise
    /// whether anything was owed or noted since the read that failed. Called with `keeping` held.
    fn take_up_unread(&self) -> Option<bool> {
        use std::sync::atomic::Ordering::SeqCst;

        if !self.unread.load(SeqCst) {
            return Some(false);
        }
        let now = now_ms();
        let Ok(before) = self.kept.read(now) else {
            return None;
        };
        let mut changed = false;
        {
            let mut view = self.view.lock().expect("the view lock is not poisoned");
            let since = std::mem::take(&mut view.owed);
            changed |= !since.is_empty();
            view.owed = before.owed;
            for owed in since {
                view.owe(now, owed);
            }
        }
        {
            let mut note = self.note.lock().expect("the note lock is not poisoned");
            if self.note_changed.load(SeqCst) {
                changed = true;
            } else {
                *note = before.note;
            }
        }
        // What a call owes while it runs is kept in the file, and the file could not be read when
        // it was opened: it is written when the file can be.
        changed |= self
            .standing
            .lock()
            .expect("the standing lock is not poisoned")
            .is_some();
        self.unread.store(false, SeqCst);
        Some(changed)
    }

    /// Writes what outlives a launch: what is owed, and the note. A write that fails is logged and
    /// leaves the record in memory, which is what the screen reads: ending a call is never stopped
    /// by a file. A file that could not be read is not written over: it may hold what an earlier
    /// launch left owed, and the write waits until it has been read.
    pub(crate) fn keep(&self) {
        let _ordered = self
            .keeping
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.take_up_unread().is_none() {
            tracing::warn!(
                "what a voice call left owed was not kept: what an earlier launch kept cannot be read yet"
            );
            return;
        }
        self.write_kept();
    }

    /// Opens the entry this process owes the host for the call `owner` holds, in the file, replacing
    /// the one an earlier step of the same call opened.
    pub(crate) fn stand_open(&self, owner: u64, entry: OwedView) {
        *self
            .standing
            .lock()
            .expect("the standing lock is not poisoned") = Some((owner, entry));
        self.keep();
    }

    /// Says that the host has answered the start `owner` sent in a way that makes no grant
    /// (a refusal, a decline, a receipt), so nothing is owed for it: the start is no longer
    /// pending, and the entry opened for it is closed before native code is asked to stop.
    pub(crate) fn answered(&self, owner: u64) {
        self.start_was_answered(owner);
        self.record_end(owner, Vec::new());
    }

    /// Records how a call `owner` held ended, in one step: what the end owes is added to what is
    /// owed, the host is no longer to be asked again by the supervisor, the entry the call stood on
    /// is closed, and the file is written once. Recording and telling are one step, so an owner that
    /// fails never leaves the supervisor without the host to ask and nothing owed.
    ///
    /// The file is written when it can be read and something changed: the take-up of what an earlier
    /// launch kept, or an entry added or closed here. Whatever cannot be written is kept in memory
    /// and written with the next use.
    pub(crate) fn record_end(&self, owner: u64, entries: Vec<OwedView>) {
        let _ordered = self
            .keeping
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let took = self.take_up_unread();
        let mut changed = !entries.is_empty();
        {
            let now = now_ms();
            let mut view = self.view.lock().expect("the view lock is not poisoned");
            for each in entries {
                view.owe(now, each);
            }
        }
        {
            let mut standing = self
                .standing
                .lock()
                .expect("the standing lock is not poisoned");
            if standing.as_ref().is_some_and(|(held, _)| *held == owner) {
                *standing = None;
                changed = true;
            }
        }
        self.host_was_told(owner);
        self.persist(took, changed);
    }

    /// Writes by the one rule: when the file could be read, and the take-up changed something or
    /// the caller did. Called with `keeping` held.
    fn persist(&self, took: Option<bool>, changed: bool) {
        match took {
            None => tracing::warn!(
                "what a voice call left owed was not kept: what an earlier launch kept cannot be read yet"
            ),
            Some(took) => {
                if took || changed {
                    self.write_kept();
                }
            }
        }
    }

    /// Writes the record as it is in memory. Called with `keeping` held and nothing unread.
    fn write_kept(&self) {
        let mut owed = self
            .view
            .lock()
            .expect("the view lock is not poisoned")
            .owed
            .clone();
        if let Some((_, standing)) = self
            .standing
            .lock()
            .expect("the standing lock is not poisoned")
            .clone()
        {
            owed.push(standing);
        }
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
        self.read_again();
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
                service_call: descriptor.zip(host).map(|(descriptor, host)| ServiceCall {
                    call_id: descriptor.call_id.clone(),
                    voice_session_id: descriptor.voice_session_id,
                    until_ms: owner::owed_until(descriptor.closes_at_ms.get()),
                    host: host.clone(),
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
    fn host_was_told(&self, owner: u64) {
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
            (Some(service), _) => {
                if self.close_over_http(&kept.tokens, &service.call_id).await {
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
                // The voice service's part is recorded after the host's, with what it owes, by
                // `record_service`: it sets the word, so the entry exists before the word changes.
                if view.ended.as_ref().is_none_or(|ended| ended.owner != owner) {
                    view.ended = Some(EndedView {
                        owner,
                        cause: "owner_failed".to_owned(),
                        words: "This device's call stopped working, so the call was ended."
                            .to_owned(),
                        closed_locally,
                        host: host_end.clone(),
                        // A word that owes nothing is final at once; the one that owes a notice
                        // waits for `record_service`, which adds the notice and then sets it.
                        broker: if broker == "not_confirmed" {
                            "pending"
                        } else {
                            broker
                        }
                        .to_owned(),
                    });
                }
            }
            if let (Some(words), Some(service), Some(id), Some(host), true) = (
                host_end.owed_reason(),
                &kept.service_call,
                kept.voice_session_id,
                &kept.host,
                toward_host_asked,
            ) {
                owed.push(OwedView::revocation(words, id, service.until_ms, host));
            }
            if let (Some((action_id, until_ms)), Some(host)) = (kept.pending_start, &kept.host) {
                owed.push(OwedView::start_unknown(action_id, until_ms, host));
            }
        }
        self.record_end(owner, owed);
        self.record_service(owner, broker, kept.service_call.as_ref());
        self.release(owner);
    }

    /// Ends a call whose owner failed, and says that the owner has nothing more to say. The owner
    /// may have failed after it told the screen it was finalising, and nothing else will say it is
    /// done: this is the only place that ends a failed owner's call.
    async fn after_failed_owner(&self, owner: u64) {
        self.finish_failed_owner(owner).await;
        self.view
            .lock()
            .expect("the view lock is not poisoned")
            .finalising_owners
            .remove(&owner);
    }

    /// Records what the voice service did about the call `owner` ended, in one step: when it did
    /// not confirm that it closed the call, a notice that lasts until the call's own limit has
    /// passed is owed, and then the record's word changes, so that the notice is there before the
    /// screen reads the word. The owner is no longer finalising, and no longer needs the emergency
    /// record. The file is written by the one rule: when it can be read and something changed.
    pub(crate) fn record_service(
        &self,
        owner: u64,
        word: &'static str,
        service: Option<&ServiceCall>,
    ) {
        let _ordered = self
            .keeping
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let took = self.take_up_unread();
        let mut added = false;
        {
            let mut view = self.view.lock().expect("the view lock is not poisoned");
            if let (true, Some(service)) = (word == "not_confirmed", service) {
                view.owe(
                    now_ms(),
                    OwedView::service_close(
                        service.voice_session_id,
                        service.until_ms,
                        &service.host,
                    ),
                );
                added = true;
            }
            if let Some(ended) = view
                .ended
                .as_mut()
                .filter(|ended| ended.owner == owner && ended.broker == "pending")
            {
                ended.broker = word.to_owned();
            }
            view.finalising_owners.remove(&owner);
        }
        self.forget_emergency(owner);
        self.persist(took, added);
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
    /// the calls before this launch left in `kept`: what is still owed, and the note. A file the
    /// system refuses to read is read again at the next use of the record, and until then it says
    /// nothing is owed and is not written over.
    #[must_use]
    pub fn on_phone(
        platform: Arc<dyn CallPlatform>,
        service: Service,
        timings: Timings,
        kept: Kept,
    ) -> Self {
        let (before, unread) = match kept.read(now_ms()) {
            Ok(before) => (before, false),
            Err(error) => {
                tracing::warn!(
                    %error,
                    "what a voice call left owed could not be read, so it is read again before it is next used"
                );
                (KeptVoice::default(), true)
            }
        };
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
                unread: std::sync::atomic::AtomicBool::new(unread),
                note_changed: std::sync::atomic::AtomicBool::new(false),
                keeping: Mutex::new(()),
                standing: Mutex::new(None),
            })),
        }
    }

    /// Says that the host a call left a grant at is reached, over `session`, so that what this
    /// device owes it is asked once more: each revocation owed to `host` in `environment` that has
    /// not lapsed goes to the host again. That the host revoked the grant, or holds no such
    /// call, settles it; any other refusal, or no answer, leaves it owed until the grant lapses,
    /// because such a refusal does not say the grant is gone. It runs on a task of its own and the screen does not wait for it.
    pub fn host_reached(
        &self,
        host: kr_protocol::ids::DeviceId,
        environment: kr_protocol::ids::EnvironmentId,
        session: Arc<kr_client::Session>,
    ) {
        let Some(shared) = self.shared.clone() else {
            return;
        };
        // What an earlier launch left owed this host is asked once the file can be read, which is
        // each time the host is reached until it can.
        shared.read_again();
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
        // One question for each voice session: two entries for one call (a crash between two
        // writes can leave them) are one thing owed, and one answer settles both.
        let mut owed = owed;
        let mut asked = std::collections::BTreeSet::new();
        owed.retain(|(voice_session_id, _)| asked.insert(*voice_session_id));
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
                // Only a revocation done, or a host that holds no such call, settles it: another
                // refusal may come from a host that did not look at the session, and the grant is
                // then still live.
                if end.settles() {
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
                watched.after_failed_owner(owner).await;
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
        // A host that revoked the grant, or holds no such call, settles what this device owed it
        // for that call.
        if end.settles() {
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
        shared.read_again();
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

#[cfg(test)]
mod tests {
    use companion_platform::call::{Answered, CallFuture, Held, OpenedCall};

    use super::*;

    /// Native code that is never asked for anything.
    struct NoNativeCode;

    impl CallPlatform for NoNativeCode {
        fn open(&self) -> CallFuture<'_, OpenedCall> {
            Box::pin(async { unreachable!("no call is opened") })
        }

        fn offer<'a>(&'a self, _call: &'a CallId) -> CallFuture<'a, String> {
            Box::pin(async { unreachable!("no offer is made") })
        }

        fn accept<'a>(&'a self, _call: &'a CallId, _answer: &'a str) -> CallFuture<'a, Answered> {
            Box::pin(async { unreachable!("no answer is applied") })
        }

        fn permit<'a>(
            &'a self,
            _call: &'a CallId,
            _voice_session_id: &'a str,
            _closes_at_epoch_ms: u64,
        ) -> CallFuture<'a, bool> {
            Box::pin(async { unreachable!("no call is permitted") })
        }

        fn mute<'a>(&'a self, _call: &'a CallId, _what: Mute, _muted: bool) -> CallFuture<'a, ()> {
            Box::pin(async { unreachable!("nothing is muted") })
        }

        fn stop<'a>(&'a self, _call: &'a CallId) -> CallFuture<'a, ()> {
            Box::pin(async { unreachable!("no call is stopped") })
        }

        fn held(&self) -> CallFuture<'_, Held> {
            Box::pin(async { unreachable!("nothing is held") })
        }

        fn alive<'a>(&'a self, _call: &'a CallId) -> CallFuture<'a, Held> {
            Box::pin(async { unreachable!("no sign is given") })
        }
    }

    /// What the screen reads of the record: whether any owner is still to say what the voice
    /// service did.
    fn finalising_as_read(shared: &Shared) -> bool {
        let view = shared.view.lock().expect("the view lock");
        serde_json::to_value(&*view).expect("the record serialises")["finalising"]
            .as_bool()
            .expect("the screen reads a boolean")
    }

    fn calls_with_owner_nine_after_seven_ended() -> Calls {
        let calls = Calls::on_phone(
            Arc::new(NoNativeCode),
            Service::managed().expect("a service"),
            Timings::default(),
            Kept::nowhere(),
        );
        {
            let shared = calls.shared.as_ref().expect("a phone holds calls");
            let mut view = shared.view.lock().expect("the view lock");
            // Owner 9 began after owner 7 ended its call and was finalising it.
            view.begin(9);
            view.finalising_owners.insert(7);
        }
        calls
    }

    /// An owner that ended a call and was still finalising it when it failed is no longer
    /// finalising, whatever else has happened to the record since: a later call began and replaced
    /// the supervisor's emergency record, so the supervisor has nothing to end, and nothing else
    /// will say the owner is done. No integration test can make an owner fail between the moment it
    /// frees the slot and the moment it records the service's answer: the only awaits there run in
    /// tasks of their own.
    #[tokio::test]
    async fn a_failed_owner_that_was_finalising_is_not_finalising_once_its_supervisor_is_done() {
        let calls = calls_with_owner_nine_after_seven_ended();
        let shared = calls.shared.as_ref().expect("a phone holds calls");
        assert!(finalising_as_read(shared));

        shared.after_failed_owner(7).await;

        assert!(!finalising_as_read(shared));
        let view = shared.view.lock().expect("the view lock");
        assert_eq!(view.owner, 9, "the later call's record is left as it is");
        assert!(view.ended.is_none());
    }

    /// Another owner's finalisation is not the failed owner's to end.
    #[tokio::test]
    async fn a_failed_owner_leaves_another_owners_finalisation_standing() {
        let calls = calls_with_owner_nine_after_seven_ended();
        let shared = calls.shared.as_ref().expect("a phone holds calls");
        shared
            .view
            .lock()
            .expect("the view lock")
            .finalising_owners
            .insert(9);

        shared.after_failed_owner(7).await;

        assert!(finalising_as_read(shared));
    }
}
