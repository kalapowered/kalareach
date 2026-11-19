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

mod advice;
mod cause;
mod confirm;
mod delegation;
mod host;
mod kept;
mod owner;
mod provider;
mod view;
#[cfg(any(test, feature = "testing"))]
mod view_window;

/// Whether a spoken delegation the provider announces on its data channel may be handed to the
/// host. It is off: this version acts on nothing a person says, and each delegation is answered
/// to the model by a fixed sentence that nothing was done. A case, and the debug build's probe,
/// turn it on for one [`Calls`] through a setter that exists only in those builds, so a release
/// build holds this constant and nothing that can change it.
const ACCEPT_HOST_DELEGATIONS: bool = false;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use companion_platform::call::{CallId, CallPlatform, Mute};
use kr_client::pairing::owner::Ceremony;
use kr_client::services::account::SignedInAccount;
use kr_client::services::voice::{ManagedVoiceBroker, ManagedVoiceService};
use kr_client::services::voice_control::ControlConnector;
use kr_client::services::{AccountTokenSource, ServiceHttp};
use kr_protocol::ids::{ActionId, SessionId, VoiceSessionId};
use kr_protocol::scalars::Digest256;
use kr_protocol::voice::VoiceStartResult;
use tokio::sync::{mpsc, oneshot};

pub use cause::Cause;
pub use host::{AppReach, CallHost, HostReach, Pairing, Reaching};
pub use kept::{Kept, KeptVoice};
pub use view::{
    CallProblem, DelegationRow, EndedView, HostEnd, OwedView, ProblemKind, VoiceCallState,
};

use crate::error::{CommandError, Result};
use crate::target::Subject;

/// The call's view: the plain mutex in every shipped build; for cases, a lock whose release can open
/// a window for a read of the state.
#[cfg(not(any(test, feature = "testing")))]
type ViewMutex = Mutex<VoiceCallState>;
#[cfg(any(test, feature = "testing"))]
type ViewMutex = view_window::ViewLock;

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
    /// The waits before each repeat of a start whose answer was lost, or of a delegation's.
    pub repeat_delays: [Duration; 3],
    /// How long a delegation waits after the provider announced it for what was said before it to
    /// arrive. A parameter of the cases, not a safety bound.
    pub delegation_wait: Duration,
    /// How long native code's news is read for the marker of a capture proof before the set is
    /// refused as not drained.
    pub drain_within: Duration,
    /// How old a capture proof may be at the moment a delegation is written to the host. A
    /// parameter of the cases, not a safety bound.
    pub proof_age: Duration,
    /// How long the number of the session a confirmation is for is waited for, so the dialog can
    /// name it. Without the number nobody is asked, so this is also how long a person waits for the
    /// dialog. A parameter of the cases.
    pub session_name_within: Duration,
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
            delegation_wait: Duration::from_secs(3),
            drain_within: Duration::from_secs(5),
            proof_age: Duration::from_millis(500),
            session_name_within: Duration::from_secs(3),
        }
    }
}

/// The client of the voice service at an origin, reached over `http` and presenting the tokens of
/// an account: the managed inference client in the application's set of service clients.
pub type BrokerFor = dyn Fn(
        &str,
        Arc<dyn ServiceHttp>,
        Arc<dyn AccountTokenSource>,
    ) -> std::result::Result<Arc<dyn ManagedVoiceService>, String>
    + Send
    + Sync;

/// The managed voice broker, which is the client of the voice service the product uses.
#[must_use]
pub fn managed_brokers() -> Arc<BrokerFor> {
    Arc::new(|origin, http, tokens| {
        ManagedVoiceBroker::new(origin, http, tokens)
            .map(|broker| Arc::new(broker) as Arc<dyn ManagedVoiceService>)
            .map_err(|error| error.to_string())
    })
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
    /// How the client of its broker is got.
    pub brokers: Arc<BrokerFor>,
}

impl Service {
    /// A service at `origin`, whose broker is the managed one.
    #[must_use]
    pub fn new(origin: String, http: Arc<dyn ServiceHttp>, connector: ControlConnector) -> Self {
        Self {
            origin,
            http,
            connector,
            brokers: managed_brokers(),
        }
    }

    /// The same service, with another client of its broker.
    #[must_use]
    pub fn with_brokers(mut self, brokers: Arc<BrokerFor>) -> Self {
        self.brokers = brokers;
        self
    }

    /// The client of this service's broker, presenting the tokens of `tokens`.
    ///
    /// # Errors
    ///
    /// Returns why the broker's client cannot be made.
    pub fn broker(
        &self,
        tokens: Arc<dyn AccountTokenSource>,
    ) -> std::result::Result<Arc<dyn ManagedVoiceService>, String> {
        (self.brokers)(&self.origin, Arc::clone(&self.http), tokens)
    }

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
        Ok(Self::new(
            ACCOUNT_ORIGIN.to_owned(),
            Arc::new(http),
            connector,
        ))
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
    /// An earlier start of this device to this host that this start names, because the host holds
    /// it: the host then admits this start in its place.
    pub after: Option<ActionId>,
}

/// What a start came to.
pub enum Started {
    /// The host's answer: a call, or why there is none.
    Result(VoiceStartResult),
    /// The host answered with a receipt.
    Receipt(Box<kr_protocol::receipt::Receipt>),
    /// The host could not confirm whether the voice service created the call: its typed answer,
    /// and the action the start was sent under.
    Unconfirmed {
        /// The host's answer.
        result: VoiceStartResult,
        /// The action the start was sent under.
        action_id: ActionId,
    },
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
    /// A start the host has not been heard to answer: the action it was sent under.
    pending_start: Option<ActionId>,
    reach: Arc<dyn HostReach>,
    tokens: Arc<SignedInAccount>,
}

/// Whether `words` holds `id` as a whole token: bounded by the ends of the words or by a character
/// that is not a letter, a digit or a hyphen, so that a longer id that begins with it is not it.
fn names_token(words: &str, id: &str) -> bool {
    let is_id_char = |c: char| c.is_alphanumeric() || c == '-';
    words.match_indices(id).any(|(at, _)| {
        let before = words[..at].chars().next_back();
        let after = words[at + id.len()..].chars().next();
        !before.is_some_and(is_id_char) && !after.is_some_and(is_id_char)
    })
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
    /// The platform's ceremony, which asks the person to confirm what a spoken request needs
    /// confirmed on the unlocked screen.
    ceremony: Arc<dyn Ceremony>,
    service: Service,
    timings: Timings,
    slot: Mutex<Option<(u64, mpsc::Sender<Cmd>)>>,
    next_owner: std::sync::atomic::AtomicU64,
    view: ViewMutex,
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
    /// The hosts this device stopped pairing with, each with the first owner number that is NOT
    /// forgotten: a start that an earlier owner sent to such a host writes no entry when its answer
    /// comes, and an entry the file holds for it is not taken up. A start made after the host is
    /// paired again has a later number, so it is kept as any other.
    forgotten: Mutex<Vec<(kr_protocol::ids::DeviceId, u64)>>,
    /// Where the application says how this device is paired with a host. The removal of a pairing
    /// is written before an unpairing is reported, and a host paired again gives the device
    /// another identity, so what the pairings say outlives a launch whatever happened to this
    /// record: a start entry made under a pairing that is not the one held now is not shown and
    /// not kept, the first time it can be told, and a start made after the host is paired again
    /// stays.
    pairings: std::sync::OnceLock<Pairings>,
    /// Whether the start entries of the record were checked against the pairings once. Until they
    /// are, the start entries of a host that the pairings cannot tell about are neither shown nor
    /// named.
    pairings_applied: std::sync::atomic::AtomicBool,
    /// Whether spoken delegations are handed to the host: a case's choice, where a case can make one.
    #[cfg(any(test, feature = "testing", debug_assertions))]
    accept: std::sync::atomic::AtomicBool,
    /// What the owner has read and acted on, which a case waits for instead of a delay.
    #[cfg(any(test, feature = "testing"))]
    handled: Handled,
    /// A case's hold on what the host answered a delegation, kept from the owner until the case
    /// lets it go.
    #[cfg(any(test, feature = "testing"))]
    delivery: DeliveryHold,
    /// How far ahead of the time the system says this device's clock reads a confirmation's expiry,
    /// in milliseconds: a case's way of making the clock disagree with the host's.
    #[cfg(any(test, feature = "testing"))]
    clock_ahead_ms: std::sync::atomic::AtomicU64,
}

/// What the owner has read and acted on. A case that has to act after the owner did, and not after
/// a time, waits for it here: a build that is not made for cases records nothing.
#[cfg(any(test, feature = "testing"))]
#[derive(Default)]
struct Handled {
    /// The voice service's announcements of a delegation: its identifier, and its offset when the
    /// announcement said one.
    announcements: Mutex<Vec<(String, Option<u64>)>>,
    /// The delegations whose capture proof the owner has acted on.
    proofs: Mutex<Vec<String>>,
    /// The delegations whose confirmation asked for a capture proof after its ceremony and whose
    /// answer the owner has acted on.
    seals: Mutex<Vec<String>>,
    /// The delegations whose ceremony's answer the owner has read, acted on or dropped.
    ceremonies: Mutex<Vec<String>>,
}

/// Where a case's hold on the answer to a delegation stands.
#[cfg(any(test, feature = "testing"))]
#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum Delivery {
    /// Nothing is held and nothing is to be.
    #[default]
    Free,
    /// The next answer to a delegation handed to the host is to be held.
    Armed,
    /// An answer is held.
    Held,
}

/// A case's hold on the answer to the next delegation handed to the host, between the moment the
/// host has answered it and the moment the owner is told: what a case that needs the owner to read
/// something else first waits on, in place of a delay.
#[cfg(any(test, feature = "testing"))]
#[derive(Default)]
struct DeliveryHold {
    state: Mutex<Delivery>,
    changed: tokio::sync::Notify,
}

#[cfg(any(test, feature = "testing"))]
impl DeliveryHold {
    /// Holds the answer in hand when a hold is armed, until the case lets it go.
    async fn pass(&self) {
        {
            let mut state = self.state.lock().expect("the record is not poisoned");
            if *state != Delivery::Armed {
                return;
            }
            *state = Delivery::Held;
        }
        self.changed.notify_waiters();
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if *self.state.lock().expect("the record is not poisoned") != Delivery::Held {
                return;
            }
            changed.await;
        }
    }

    fn set(&self, to: Delivery) {
        *self.state.lock().expect("the record is not poisoned") = to;
        self.changed.notify_waiters();
    }

    fn is(&self, is: Delivery) -> bool {
        *self.state.lock().expect("the record is not poisoned") == is
    }
}

#[cfg(any(test, feature = "testing"))]
impl Handled {
    /// The owner read the voice service's announcement of the delegation `id`.
    fn announcement(&self, id: String, offset_ms: Option<u64>) {
        self.announcements
            .lock()
            .expect("the record is not poisoned")
            .push((id, offset_ms));
    }

    /// The owner acted on the answer to the proof the confirmation of the delegation `id` asked
    /// for after its ceremony.
    fn seal(&self, id: &str) {
        self.seals
            .lock()
            .expect("the record is not poisoned")
            .push(id.to_owned());
    }

    /// The owner read the answer of the ceremony the confirmation of the delegation `id` asked for.
    fn ceremony(&self, id: &str) {
        self.ceremonies
            .lock()
            .expect("the record is not poisoned")
            .push(id.to_owned());
    }

    /// The owner acted on the answer to the proof the delegation `id` asked for.
    fn proof(&self, id: &str) {
        self.proofs
            .lock()
            .expect("the record is not poisoned")
            .push(id.to_owned());
    }
}

impl Shared {
    /// The time this device reads a confirmation's expiry against, in milliseconds since the epoch:
    /// its own clock. The host's is the authority for whether a confirmation has run out; this one
    /// only stops the phone asking a person for, or signing, what its own clock says is over.
    pub(crate) fn confirmation_now_ms(&self) -> u64 {
        #[cfg(any(test, feature = "testing"))]
        {
            now_ms().saturating_add(
                self.clock_ahead_ms
                    .load(std::sync::atomic::Ordering::SeqCst),
            )
        }
        #[cfg(not(any(test, feature = "testing")))]
        {
            now_ms()
        }
    }

    /// Whether a spoken delegation may be handed to the host, read as a call begins.
    #[cfg(any(test, feature = "testing", debug_assertions))]
    pub(crate) fn accepts_host_delegations(&self) -> bool {
        self.accept.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Whether a spoken delegation may be handed to the host, read as a call begins.
    #[cfg(not(any(test, feature = "testing", debug_assertions)))]
    #[allow(clippy::unused_self)]
    pub(crate) const fn accepts_host_delegations(&self) -> bool {
        ACCEPT_HOST_DELEGATIONS
    }

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

    /// Notes, in memory, that the call found no such call at the voice service. Called by the end's
    /// own update, so that the end is never shown without it; the file is written after.
    pub(crate) fn note_no_such_call(&self, key: NoteKey) {
        let mut note = self.note.lock().expect("the note lock is not poisoned");
        self.note_changed
            .store(true, std::sync::atomic::Ordering::SeqCst);
        *note = Some(key);
    }

    /// Reads what the launches before this one kept again, when the first read was refused, and
    /// takes it up: what it holds comes before what was owed since, and a note remembered or
    /// forgotten since is newer than the file's and stands. It is written back whole when anything
    /// was owed or noted meanwhile, so that nothing owed in this launch waits for the next one.
    /// Every use of the record starts here.
    pub(crate) fn read_again(&self) {
        use std::sync::atomic::Ordering::SeqCst;

        let unchecked = self.pairings.get().is_some() && !self.pairings_applied.load(SeqCst);
        if !self.unread.load(SeqCst) && !unchecked {
            return;
        }
        let _ordered = self
            .keeping
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let took = self.take_up_unread();
        // What an unpairing left in the file is removed before anything is shown, and the removal
        // is written. The entries of a file that could not be read yet are checked as they are
        // taken up.
        let dropped = took.is_some() && self.drop_unpaired();
        if took == Some(true) || dropped {
            self.write_kept();
        }
    }

    /// Takes the start entries of hosts that this device no longer pairs with out of what is
    /// owed, and says whether any went. A host that the application cannot tell about yet keeps
    /// its entries, and the check is made again at the next use. Called with `keeping` held and
    /// nothing unread.
    fn drop_unpaired(&self) -> bool {
        let Some(paired) = self.pairings.get() else {
            return false;
        };
        let mut every_host_known = true;
        let dropped = {
            let mut view = self.view.lock().expect("the view lock is not poisoned");
            let held = view.owed.len();
            view.owed.retain(|each| {
                pairing_holds(paired, each).unwrap_or_else(|| {
                    every_host_known = false;
                    true
                })
            });
            view.owed.len() != held
        };
        if every_host_known {
            self.pairings_applied
                .store(true, std::sync::atomic::Ordering::SeqCst);
        }
        dropped
    }

    /// Whether the application says the pairing `entry` was made under is gone.
    fn pairing_gone(&self, entry: &OwedView) -> bool {
        self.pairings
            .get()
            .is_some_and(|paired| pairing_holds(paired, entry) == Some(false))
    }

    /// Whether the start entry `entry` is left out of what a person is shown and of what a refusal
    /// can name: the start entries of a host that the pairings cannot tell about wait until the
    /// check of the record is applied.
    fn awaits_the_pairing_check(&self, entry: &OwedView) -> bool {
        !self
            .pairings_applied
            .load(std::sync::atomic::Ordering::SeqCst)
            && self
                .pairings
                .get()
                .is_some_and(|paired| pairing_holds(paired, entry) != Some(true))
    }

    /// Takes out of `owed` what the page is never shown: what has lapsed, a start that is only
    /// kept, and a start whose pairing is not told yet.
    fn keep_what_is_shown(&self, owed: &mut Vec<OwedView>) {
        let now = now_ms();
        owed.retain(|each| {
            each.until_ms > now && !each.is_hidden_start() && !self.awaits_the_pairing_check(each)
        });
    }

    /// The call's state as a person is shown it: every reply that carries the record carries
    /// this.
    pub(crate) fn shown(&self, mut state: VoiceCallState) -> VoiceCallState {
        self.keep_what_is_shown(&mut state.owed);
        state
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
        let mut before = before;
        {
            // A host forgotten while the file could not be read, or a pairing this device no longer
            // holds: what the file holds for it goes.
            let forgotten = self
                .forgotten
                .lock()
                .expect("the forgotten lock is not poisoned");
            let held = before.owed.len();
            before.owed.retain(|each| {
                !(each.is_start()
                    && (each
                        .host
                        .is_some_and(|(id, _)| forgotten.iter().any(|(gone, _)| *gone == id))
                        || self.pairing_gone(each)))
            });
            changed |= before.owed.len() != held;
        }
        {
            // Nothing was owed since the read that failed: an entry is owed by the owner of a
            // start, and a start is not sent until the record has been read.
            self.view
                .lock()
                .expect("the view lock is not poisoned")
                .owed = before.owed;
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

    /// Opens the entry for a start this device is about to send, and says whether it is on disk.
    /// A start that the host may admit must leave a record that a crash does not lose, so a file
    /// that cannot be read, a write that fails and a device with no place to keep anything each
    /// say no, and the start is not sent.
    pub(crate) fn stand_open_durably(&self, owner: u64, entry: OwedView) -> bool {
        *self
            .standing
            .lock()
            .expect("the standing lock is not poisoned") = Some((owner, entry));
        let kept = {
            let _ordered = self
                .keeping
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            self.take_up_unread().is_some()
                && self.kept.stores()
                && self.write_kept_checked().is_ok()
        };
        if !kept {
            let mut standing = self
                .standing
                .lock()
                .expect("the standing lock is not poisoned");
            if standing.as_ref().is_some_and(|(held, _)| *held == owner) {
                *standing = None;
            }
        }
        kept
    }

    /// Whether this device keeps the earlier start `action_id` for `host`, so that a start can
    /// name it. The words say why not.
    pub(crate) fn earlier_start(
        &self,
        action_id: &str,
        host: (kr_protocol::ids::DeviceId, kr_protocol::ids::EnvironmentId),
    ) -> std::result::Result<(), &'static str> {
        self.read_again();
        let view = self.view.lock().expect("the view lock is not poisoned");
        match view.owed.iter().find(|each| {
            each.is_start()
                && each.action_id.as_deref() == Some(action_id)
                && !self.awaits_the_pairing_check(each)
        }) {
            None => Err(
                "Nothing was sent. This device no longer keeps that earlier start, so \
                         this start cannot name it.",
            ),
            Some(each) if each.host != Some(host) => Err("Nothing was sent. That earlier start \
                         was made to another host, so this start cannot name it."),
            Some(_) => Ok(()),
        }
    }

    /// The one earlier start of `host` that this device keeps and the host's words name: the
    /// action id of exactly one kept start appears in `words` as a whole token. The start that was
    /// refused and the one it named are not candidates. None, or two, is no candidate.
    pub(crate) fn start_named_in(
        &self,
        host: (kr_protocol::ids::DeviceId, kr_protocol::ids::EnvironmentId),
        words: &str,
        named: Option<String>,
    ) -> Option<String> {
        self.read_again();
        let view = self.view.lock().expect("the view lock is not poisoned");
        let mut found: Vec<&str> = Vec::new();
        for id in view
            .owed
            .iter()
            .filter(|each| {
                each.is_start() && each.host == Some(host) && !self.awaits_the_pairing_check(each)
            })
            .filter_map(|each| each.action_id.as_deref())
            .filter(|id| Some(*id) != named.as_deref())
        {
            if names_token(words, id) && !found.contains(&id) {
                found.push(id);
            }
        }
        match found.as_slice() {
            [only] => Some((*only).to_owned()),
            _ => None,
        }
    }

    /// Records what the host's answer to the start `owner` sent comes to, in one write: when the
    /// answer shows that the start passed the host's hold, the earlier starts to `passed` change as
    /// a pass changes them; `entry` is the start's own entry, when it keeps one; and `then` is what
    /// this process owes next, which replaces the entry opened for the send. A state that shows
    /// the proof without the changes, or the changes without the entry, is never written.
    pub(crate) fn settle_start(
        &self,
        owner: u64,
        passed: Option<(kr_protocol::ids::DeviceId, kr_protocol::ids::EnvironmentId)>,
        entry: Option<OwedView>,
        then: Option<OwedView>,
    ) {
        let has_next = then.is_some();
        let _ordered = self
            .keeping
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let took = self.take_up_unread();
        // An answer that comes after its host was forgotten leaves no entry of the start.
        let entry = entry.filter(|entry| !self.is_forgotten(owner, entry));
        {
            let now = now_ms();
            let mut view = self.view.lock().expect("the view lock is not poisoned");
            if let Some(host) = passed {
                view.start_passed(host);
            }
            if let Some(entry) = entry {
                view.owe(now, entry);
            }
        }
        {
            let mut standing = self
                .standing
                .lock()
                .expect("the standing lock is not poisoned");
            if standing.as_ref().is_some_and(|(held, _)| *held == owner) {
                *standing = then.map(|entry| (owner, entry));
            }
        }
        self.start_was_answered(owner);
        if !has_next {
            self.host_was_told(owner);
        }
        self.persist(took, true);
    }

    /// Changes what is owed and writes it, and says whether the change is saved: the change is
    /// made on a copy and replaces what is owed only when the write has succeeded, so a person is
    /// never shown a change that the next launch does not keep. `Ok(false)` when it changed
    /// nothing.
    pub(crate) fn change_owed_durably(
        &self,
        change: impl FnOnce(&mut VoiceCallState) -> bool,
    ) -> std::result::Result<bool, ()> {
        let _ordered = self
            .keeping
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.take_up_unread().is_none() {
            return Err(());
        }
        let mut after = self
            .view
            .lock()
            .expect("the view lock is not poisoned")
            .clone();
        if !change(&mut after) {
            return Ok(false);
        }
        let mut owed = after.owed.clone();
        owed.extend(self.standing_to_keep());
        let note = self
            .note
            .lock()
            .expect("the note lock is not poisoned")
            .clone();
        self.kept.write(&KeptVoice { owed, note }).map_err(|_| ())?;
        self.view
            .lock()
            .expect("the view lock is not poisoned")
            .owed = after.owed;
        Ok(true)
    }

    /// Says that the host has answered the start `owner` sent in a way that makes no grant
    /// (a refusal, a decline, a receipt), so nothing is owed for it: the start is no longer
    /// pending, and the entry opened for it is closed before native code is asked to stop.
    pub(crate) fn answered(&self, owner: u64) {
        self.start_was_answered(owner);
        self.record_end(owner, |_| {}, Vec::new());
    }

    /// Records how a call `owner` held ended, in one step: `end` shows the end and `entries`, what
    /// it owes, are added to what is owed in one update of the view, so that no state shows an end
    /// without the entry it owes. The host is no longer to be asked again by the supervisor, the
    /// entry the call stood on is closed, and the file is written once. Recording and telling are
    /// one step, so an owner that fails never leaves the supervisor without the host to ask and
    /// nothing owed.
    ///
    /// The file is written when it can be read and something changed: the take-up of what an earlier
    /// launch kept, or an entry added or closed here. Whatever cannot be written is kept in memory
    /// and written with the next use.
    pub(crate) fn record_end(
        &self,
        owner: u64,
        end: impl FnOnce(&mut VoiceCallState),
        entries: Vec<OwedView>,
    ) {
        let _ordered = self
            .keeping
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let took = self.take_up_unread();
        let entries: Vec<OwedView> = entries
            .into_iter()
            .filter(|entry| !self.is_forgotten(owner, entry))
            .collect();
        let mut changed = !entries.is_empty();
        {
            let now = now_ms();
            let mut view = self.view.lock().expect("the view lock is not poisoned");
            end(&mut view);
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
        if let Err(error) = self.write_kept_checked() {
            tracing::warn!(%error, "what a voice call left owed could not be kept");
        }
    }

    /// Writes the record as it is in memory and says why it could not. Called with `keeping` held
    /// and nothing unread.
    fn write_kept_checked(&self) -> std::io::Result<()> {
        let mut owed = self
            .view
            .lock()
            .expect("the view lock is not poisoned")
            .owed
            .clone();
        owed.extend(self.standing_to_keep());
        let note = self
            .note
            .lock()
            .expect("the note lock is not poisoned")
            .clone();
        self.kept.write(&KeptVoice { owed, note })
    }

    /// Whether the entry of a start that `owner` sent is for a host this device forgot after the
    /// owner was taken, so that the entry is not kept.
    fn is_forgotten(&self, owner: u64, entry: &OwedView) -> bool {
        entry.is_start()
            && entry.host.is_some_and(|(host, _)| {
                self.forgotten
                    .lock()
                    .expect("the forgotten lock is not poisoned")
                    .iter()
                    .any(|(gone, first_kept)| *gone == host && owner < *first_kept)
            })
    }

    /// What the process owes for the call it is making, unless that is the start of a host this
    /// device forgot.
    fn standing_to_keep(&self) -> Option<OwedView> {
        let (owner, entry) = self
            .standing
            .lock()
            .expect("the standing lock is not poisoned")
            .clone()?;
        (!self.is_forgotten(owner, &entry)).then_some(entry)
    }

    /// Forgets every start entry for `host`: the entries in memory, the start in flight, which is
    /// no longer kept in the file, an entry that comes with a late answer, and what a file that
    /// cannot be read yet holds. The save is whole and ordered with every other change.
    fn forget_starts_of(&self, host: kr_protocol::ids::DeviceId) {
        let _ordered = self
            .keeping
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        {
            let mut forgotten = self
                .forgotten
                .lock()
                .expect("the forgotten lock is not poisoned");
            forgotten.retain(|(each, _)| *each != host);
            forgotten.push((
                host,
                self.next_owner.load(std::sync::atomic::Ordering::SeqCst),
            ));
        }
        let took = self.take_up_unread();
        let removed = {
            let mut view = self.view.lock().expect("the view lock is not poisoned");
            let before = view.owed.len();
            view.forget_starts_of(host);
            view.owed.len() != before
        };
        let standing_start = self
            .standing
            .lock()
            .expect("the standing lock is not poisoned")
            .as_ref()
            .is_some_and(|(_, entry)| {
                entry.is_start() && entry.host.is_some_and(|(id, _)| id == host)
            });
        self.persist(took, removed || standing_start);
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
        let _ordered = self
            .keeping
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let took = self.take_up_unread();
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
        self.persist(took, removed);
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
    pub(crate) fn keep_start_pending(&self, owner: u64, action_id: ActionId) {
        let mut kept = self
            .emergency
            .lock()
            .expect("the emergency lock is not poisoned");
        if let Some((held, kept)) = kept.as_mut()
            && *held == owner
        {
            kept.pending_start = Some(action_id);
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
        let Ok(broker) = self
            .service
            .broker(Arc::clone(tokens) as Arc<dyn AccountTokenSource>)
        else {
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
        if let (Some(words), Some(service), Some(id), Some(host), true) = (
            host_end.owed_reason(),
            &kept.service_call,
            kept.voice_session_id,
            &kept.host,
            toward_host_asked,
        ) {
            owed.push(OwedView::revocation(words, id, service.until_ms, host));
        }
        if let (Some(action_id), Some(host)) = (kept.pending_start, &kept.host) {
            owed.push(OwedView::start_unknown(action_id, host));
        }
        // The end and what it owes are shown in one update.
        let accepts = self.accepts_host_delegations();
        self.record_end(
            owner,
            |view| {
                // A call that began after this one has its own record, which this does not touch.
                if view.owner <= owner {
                    view.running = false;
                    view.session = None;
                    view.control = "none".to_owned();
                    view.host = "none".to_owned();
                    // The voice service's part is recorded after the host's, with what it owes, by
                    // `record_service`: it sets the word, so the entry exists before the word
                    // changes.
                    if view.ended.as_ref().is_none_or(|ended| ended.owner != owner) {
                        view.ended = Some(EndedView {
                            owner,
                            cause: "owner_failed".to_owned(),
                            // A call that may have acted cannot say that nothing was done: what
                            // the owner had written to the host went with the owner.
                            words: if accepts {
                                format!(
                                    "This device's call stopped working, so the call was ended. {}",
                                    owner::REQUESTS_UNSETTLED
                                )
                            } else {
                                "This device's call stopped working, so the call was ended."
                                    .to_owned()
                            },
                            closed_locally,
                            host: host_end.clone(),
                            // A word that owes nothing is final at once; the one that owes a
                            // notice waits for `record_service`, which adds the notice and then
                            // sets it.
                            broker: if broker == "not_confirmed" {
                                "pending"
                            } else {
                                broker
                            }
                            .to_owned(),
                        });
                    }
                }
            },
            owed,
        );
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

/// What the application says of this device's pairing with a host.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PairedNow {
    /// The records of the pairings cannot be read.
    Unknown,
    /// This device holds no pairing with the host.
    Not,
    /// This device is paired with the host, as the device the host gave it this identity.
    As(kr_protocol::ids::DeviceId),
}

/// Says how this device is paired with a host.
pub type Pairings = Arc<dyn Fn(kr_protocol::ids::DeviceId) -> PairedNow + Send + Sync>;

/// Whether the pairing `entry` was made under is the one `paired` reports for its host now: `None`
/// while the records cannot say, and `Some(false)` for a start entry whose host was unpaired, or
/// paired again since, which gave the device another identity. Only a start entry is told: what
/// else is owed stands whatever the pairings are.
fn pairing_holds(paired: &Pairings, entry: &OwedView) -> Option<bool> {
    let Some((host, _)) = entry.host.filter(|_| entry.is_start()) else {
        return Some(true);
    };
    match paired(host) {
        PairedNow::Unknown => None,
        PairedNow::Not => Some(false),
        PairedNow::As(now) => Some(entry.pairing == Some(now)),
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

    /// The client of the voice service's broker, presenting the tokens of `tokens`, when this
    /// application makes calls and the broker factory can make one: its error is dropped.
    #[must_use]
    pub fn broker(
        &self,
        tokens: Arc<dyn AccountTokenSource>,
    ) -> Option<Arc<dyn ManagedVoiceService>> {
        self.shared.as_ref()?.service.broker(tokens).ok()
    }

    /// The calls of a phone, made through `platform` and controlled at `service`, taking up what
    /// the calls before this launch left in `kept`: what is still owed, and the note. A file the
    /// system refuses to read is read again at the next use of the record, and until then it says
    /// nothing is owed and is not written over.
    #[must_use]
    pub fn on_phone(
        platform: Arc<dyn CallPlatform>,
        ceremony: Arc<dyn Ceremony>,
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
                ceremony,
                service,
                timings,
                slot: Mutex::new(None),
                next_owner: std::sync::atomic::AtomicU64::new(1),
                view: ViewMutex::new(view),
                note: Mutex::new(before.note),
                emergency: Mutex::new(None),
                kept,
                unread: std::sync::atomic::AtomicBool::new(unread),
                note_changed: std::sync::atomic::AtomicBool::new(false),
                keeping: Mutex::new(()),
                standing: Mutex::new(None),
                forgotten: Mutex::new(Vec::new()),
                pairings: std::sync::OnceLock::new(),
                pairings_applied: std::sync::atomic::AtomicBool::new(false),
                #[cfg(any(test, feature = "testing", debug_assertions))]
                accept: std::sync::atomic::AtomicBool::new(ACCEPT_HOST_DELEGATIONS),
                #[cfg(any(test, feature = "testing"))]
                handled: Handled::default(),
                #[cfg(any(test, feature = "testing"))]
                delivery: DeliveryHold::default(),
                #[cfg(any(test, feature = "testing"))]
                clock_ahead_ms: std::sync::atomic::AtomicU64::new(0),
            })),
        }
    }

    /// Lets the calls this makes from now on hand spoken delegations to the host, or stops it. For
    /// cases and the debug build's probe only: a release build compiles no way to say so.
    #[cfg(any(test, feature = "testing", debug_assertions))]
    pub fn accept_host_delegations(&self, accept: bool) {
        if let Some(shared) = &self.shared {
            shared
                .accept
                .store(accept, std::sync::atomic::Ordering::SeqCst);
        }
    }

    /// Makes this device's clock read `ahead_ms` milliseconds ahead of the host's where a
    /// confirmation's expiry is concerned. For cases, which cannot wait out a confirmation's life.
    #[cfg(any(test, feature = "testing"))]
    pub fn run_the_confirmation_clock_ahead(&self, ahead_ms: u64) {
        if let Some(shared) = &self.shared {
            shared
                .clock_ahead_ms
                .store(ahead_ms, std::sync::atomic::Ordering::SeqCst);
        }
    }

    /// Whether the calls this makes hand spoken requests to the host: the constant every shipped
    /// build holds as false. What a person is asked to allow is only worth asking while it is true.
    #[must_use]
    pub fn hands_spoken_requests_to_the_host(&self) -> bool {
        self.shared
            .as_ref()
            .is_some_and(|shared| shared.accepts_host_delegations())
    }

    /// Whether an owner has read the voice service's announcement of the delegation `id` at
    /// `offset_ms`. For cases, which send the provider's delegation only once it has: they decide by
    /// that and not by a wait.
    #[cfg(any(test, feature = "testing"))]
    #[must_use]
    pub fn has_read_announcement(&self, id: &str, offset_ms: u64) -> bool {
        self.shared.as_ref().is_some_and(|shared| {
            shared
                .handled
                .announcements
                .lock()
                .expect("the record is not poisoned")
                .iter()
                .any(|(known, offset)| known == id && *offset == Some(offset_ms))
        })
    }

    /// Whether an owner has acted on the answer to the capture proof the confirmation of the
    /// delegation `id` asked for after its ceremony. For cases, which let the news behind that
    /// proof's marker through only once it has.
    #[cfg(any(test, feature = "testing"))]
    #[must_use]
    pub fn has_handled_seal(&self, id: &str) -> bool {
        self.shared.as_ref().is_some_and(|shared| {
            shared
                .handled
                .seals
                .lock()
                .expect("the record is not poisoned")
                .iter()
                .any(|known| known == id)
        })
    }

    /// Holds the host's answer to the next delegation an owner hands over, after the host has given
    /// it and before the owner is told, until [`Self::release_the_delivery`]. For cases that need
    /// the owner to read something else first.
    #[cfg(any(test, feature = "testing"))]
    pub fn hold_the_next_delivery(&self) {
        if let Some(shared) = self.shared.as_ref() {
            shared.delivery.set(Delivery::Armed);
        }
    }

    /// Waits until an answer is held by [`Self::hold_the_next_delivery`].
    #[cfg(any(test, feature = "testing"))]
    pub async fn until_a_delivery_is_held(&self) {
        let Some(shared) = self.shared.as_ref() else {
            return;
        };
        loop {
            let changed = shared.delivery.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if shared.delivery.is(Delivery::Held) {
                return;
            }
            changed.await;
        }
    }

    /// Lets the held answer go to the owner.
    #[cfg(any(test, feature = "testing"))]
    pub fn release_the_delivery(&self) {
        if let Some(shared) = self.shared.as_ref() {
            shared.delivery.set(Delivery::Free);
        }
    }

    /// Whether an owner has read the answer of the ceremony the confirmation of the delegation `id`
    /// asked for, and acted on it or dropped it as the answer of a confirmation that is over. For
    /// cases that say nothing was signed after a late answer.
    #[cfg(any(test, feature = "testing"))]
    #[must_use]
    pub fn has_handled_ceremony(&self, id: &str) -> bool {
        self.shared.as_ref().is_some_and(|shared| {
            shared
                .handled
                .ceremonies
                .lock()
                .expect("the record is not poisoned")
                .iter()
                .any(|known| known == id)
        })
    }

    /// Opens a window at the next end the call shows: the first hold of the view that shows an end
    /// the view does not show now opens it as the hold is released, wherever in the call's
    /// supervision that hold is. See [`Self::until_an_end_is_being_recorded`]. For cases that show
    /// no state has the end without what it owes.
    #[cfg(any(test, feature = "testing"))]
    pub fn open_a_window_at_the_next_end(&self) {
        if let Some(shared) = self.shared.as_ref() {
            shared.view.arm();
        }
    }

    /// Waits until the window is open: the view is free, and its writer waits for the case's read.
    /// The case then reads the state and calls [`Self::the_read_has_finished`], and asks
    /// [`Self::the_writer_gave_up`].
    #[cfg(any(test, feature = "testing"))]
    pub async fn until_an_end_is_being_recorded(&self) {
        if let Some(shared) = self.shared.as_ref() {
            shared.view.until_open().await;
        }
    }

    /// Says that the case's read of the state, in the window, has finished.
    #[cfg(any(test, feature = "testing"))]
    pub fn the_read_has_finished(&self) {
        if let Some(shared) = self.shared.as_ref() {
            shared.view.finish();
        }
    }

    /// Whether the writer stopped waiting in the window before the case's read had finished: a
    /// read that did not happen in the window shows nothing.
    #[cfg(any(test, feature = "testing"))]
    #[must_use]
    pub fn the_writer_gave_up(&self) -> bool {
        self.shared
            .as_ref()
            .is_some_and(|shared| shared.view.writer_gave_up())
    }

    /// Whether an owner has acted on the answer to the capture proof the delegation `id` asked for:
    /// what it holds of the proof is in, and the news behind the proof's marker may be told. For
    /// cases, which let that news through only once it has.
    #[cfg(any(test, feature = "testing"))]
    #[must_use]
    pub fn has_handled_proof(&self, id: &str) -> bool {
        self.shared.as_ref().is_some_and(|shared| {
            shared
                .handled
                .proofs
                .lock()
                .expect("the record is not poisoned")
                .iter()
                .any(|known| known == id)
        })
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

    /// Hides the notice of the start `action_id`: the person has read it. The entry stays, hidden,
    /// so a later refusal that names the start can still be matched; nothing is said to the host
    /// and no call is stopped. The change is shown only when it is saved.
    ///
    /// # Errors
    ///
    /// Returns an error when the change could not be saved: the notice stays.
    pub fn dismiss_start(&self, action_id: &str) -> Result<()> {
        let Some(shared) = &self.shared else {
            return Ok(());
        };
        shared
            .change_owed_durably(|state| state.dismiss_start(action_id))
            .map(|_| ())
            .map_err(|()| {
                CommandError::refused("This device could not save the dismissal. The notice stays.")
            })
    }

    /// Tells these calls where to ask how this device is paired with a host. The removal of a
    /// pairing is written before an unpairing is reported, and a host paired again gives the device
    /// another identity, so a start entry made under a pairing that is not the one held now goes
    /// the first time the record is used, even when the unpairing could not change the file and
    /// the process ended before it could. Said once; a second answer is ignored.
    pub fn know_pairings(
        &self,
        paired: impl Fn(kr_protocol::ids::DeviceId) -> PairedNow + Send + Sync + 'static,
    ) {
        if let Some(shared) = &self.shared {
            let _ = shared.pairings.set(Arc::new(paired));
        }
    }

    /// This device stops pairing with the host `host`: what it keeps of the starts it sent there
    /// goes. The host's own state is not touched, and nothing is said about whether a call ended.
    pub fn forget_starts_of(&self, host: kr_protocol::ids::DeviceId) {
        let Some(shared) = &self.shared else {
            return;
        };
        shared.forget_starts_of(host);
    }

    /// What the call is doing, and, when `note` is the host, account and service of a call that
    /// found no such call, the problem a person is shown before starting another.
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
        shared.keep_what_is_shown(&mut state.owed);
        let remembered = shared
            .note
            .lock()
            .expect("the note lock is not poisoned")
            .clone();
        if !state.running && remembered.as_ref().is_some_and(|kept| Some(kept) == note) {
            state.meet(
                ProblemKind::NoSuchCall,
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
    use companion_platform::call::{Answered, CallFuture, CaptureProof, Held, OpenedCall};

    use super::view::{NO_LAPSE_MS, START_KEPT, START_UNANSWERED, START_UNKNOWN};
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

        fn capture_proof<'a>(
            &'a self,
            _call: &'a CallId,
            _barrier: bool,
        ) -> CallFuture<'a, CaptureProof> {
            Box::pin(async { unreachable!("no proof is asked for") })
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
            Arc::new(crate::verify::NoCeremony),
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

    fn host(n: u8) -> (kr_protocol::ids::DeviceId, kr_protocol::ids::EnvironmentId) {
        (
            kr_protocol::ids::DeviceId::new(kr_protocol::scalars::Uuid::from_bytes([n; 16])),
            kr_protocol::ids::EnvironmentId::new(kr_protocol::scalars::Uuid::from_bytes([1; 16])),
        )
    }

    fn entry(
        kind: &str,
        action: &str,
        host: (kr_protocol::ids::DeviceId, kr_protocol::ids::EnvironmentId),
    ) -> OwedView {
        OwedView {
            kind: kind.to_owned(),
            words: String::new(),
            action_id: Some(action.to_owned()),
            voice_session_id: None,
            until_ms: NO_LAPSE_MS,
            host_reference: String::new(),
            host_name: "host".to_owned(),
            host: Some(host),
            // The first pairing with a host gave this device the host's own number as its identity.
            pairing: Some(host.0),
        }
    }

    /// The identity a host gave this device when it was paired with the host again.
    fn paired_again() -> kr_protocol::ids::DeviceId {
        kr_protocol::ids::DeviceId::new(kr_protocol::scalars::Uuid::from_bytes([9; 16]))
    }

    /// The pairings of a device that holds the first pairing of every host it paired with except
    /// `gone`, and holds a later pairing with that one.
    fn paired_again_with(
        gone: kr_protocol::ids::DeviceId,
    ) -> impl Fn(kr_protocol::ids::DeviceId) -> PairedNow + Send + Sync + 'static {
        move |paired| {
            if paired == gone {
                PairedNow::As(paired_again())
            } else {
                PairedNow::As(paired)
            }
        }
    }

    /// The pairings of a device that holds the first pairing of every host except `gone`.
    fn paired_except(
        gone: kr_protocol::ids::DeviceId,
    ) -> impl Fn(kr_protocol::ids::DeviceId) -> PairedNow + Send + Sync + 'static {
        move |paired| {
            if paired == gone {
                PairedNow::Not
            } else {
                PairedNow::As(paired)
            }
        }
    }

    fn calls_in(directory: &std::path::Path) -> Calls {
        Calls::on_phone(
            Arc::new(NoNativeCode),
            Arc::new(crate::verify::NoCeremony),
            Service::managed().expect("a service"),
            Timings::default(),
            Kept::at(directory),
        )
    }

    /// The kind and action of every entry the file holds.
    fn file_holds(directory: &std::path::Path) -> Vec<(String, String)> {
        Kept::at(directory)
            .read(0)
            .expect("the file is read")
            .owed
            .into_iter()
            .map(|each| (each.kind, each.action_id.unwrap_or_default()))
            .collect()
    }

    fn pair(kind: &str, action: &str) -> (String, String) {
        (kind.to_owned(), action.to_owned())
    }

    /// Unpairing a host removes its start in flight from the file, and neither the answer that
    /// comes after nor the unknown path puts the start back; a start made after the host is paired
    /// again is kept, and another host's entries are never touched.
    #[test]
    fn forgetting_a_host_drops_its_start_in_flight_and_a_late_answer_writes_no_entry() {
        let directory = tempfile::tempdir().expect("a folder");
        let calls = calls_in(directory.path());
        let shared = calls.shared.as_ref().expect("a phone holds calls");
        shared.settle_start(0, None, Some(entry(START_KEPT, "old-1", host(1))), None);
        shared.settle_start(0, None, Some(entry(START_KEPT, "old-2", host(2))), None);
        let owner = shared
            .next_owner
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        assert!(shared.stand_open_durably(owner, entry(START_UNKNOWN, "flight", host(1))));
        assert_eq!(file_holds(directory.path()).len(), 3);

        calls.forget_starts_of(host(1).0);
        assert_eq!(
            file_holds(directory.path()),
            vec![pair(START_KEPT, "old-2")],
            "the start in flight went from the file with the host's other entries"
        );

        // The answer that arrives after the host was forgotten, and the unknown path, write nothing.
        shared.settle_start(
            owner,
            Some(host(1)),
            Some(entry(START_KEPT, "flight", host(1))),
            None,
        );
        shared.record_end(owner, |_| {}, vec![entry(START_UNKNOWN, "flight", host(1))]);
        assert_eq!(
            file_holds(directory.path()),
            vec![pair(START_KEPT, "old-2")]
        );
        assert_eq!(
            calls_in(directory.path())
                .shared
                .as_ref()
                .expect("a phone holds calls")
                .view
                .lock()
                .expect("the view lock")
                .owed
                .len(),
            1,
            "a launch that reads the file finds nothing of the host"
        );

        let later = shared
            .next_owner
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        shared.settle_start(later, None, Some(entry(START_KEPT, "again", host(1))), None);
        assert_eq!(
            file_holds(directory.path()),
            vec![pair(START_KEPT, "old-2"), pair(START_KEPT, "again")],
            "a start made after the host is paired again is kept"
        );
    }

    /// Unpairing while the file cannot be read yet is not lost when it can: what the file holds for
    /// the host is not taken up.
    #[cfg(unix)]
    #[test]
    fn a_host_forgotten_while_the_file_cannot_be_read_stays_forgotten() {
        let directory = tempfile::tempdir().expect("a folder");
        Kept::at(directory.path())
            .write(&KeptVoice {
                owed: vec![
                    entry(START_KEPT, "one", host(1)),
                    entry(START_UNANSWERED, "two", host(2)),
                ],
                note: None,
            })
            .expect("the file is written");
        let file = directory.path().join("voice-kept.json");
        std::fs::rename(&file, directory.path().join("voice-kept.locked")).expect("put aside");
        std::os::unix::fs::symlink(&file, &file).expect("a link that cannot be opened");
        let calls = calls_in(directory.path());

        calls.forget_starts_of(host(1).0);
        assert!(
            std::fs::symlink_metadata(&file)
                .expect("the file is there")
                .file_type()
                .is_symlink(),
            "a file that could not be read was not written over"
        );

        std::fs::rename(directory.path().join("voice-kept.locked"), &file).expect("unlocked");
        calls
            .shared
            .as_ref()
            .expect("a phone holds calls")
            .read_again();
        assert_eq!(
            file_holds(directory.path()),
            vec![pair(START_UNANSWERED, "two")],
            "the host's entry is not back, and the file says so"
        );
    }

    /// The entries two hosts left in the file: one start each that the page shows.
    fn two_hosts_left_a_start_each(directory: &std::path::Path) {
        Kept::at(directory)
            .write(&KeptVoice {
                owed: vec![
                    entry(START_UNKNOWN, "one", host(1)),
                    entry(START_UNKNOWN, "two", host(2)),
                ],
                note: None,
            })
            .expect("the file is written");
    }

    /// The actions of the start entries the page is shown, after the use of the record that every
    /// reader starts with.
    fn actions_shown(calls: &Calls) -> Vec<String> {
        calls
            .state(None)
            .owed
            .into_iter()
            .filter_map(|each| each.action_id)
            .collect()
    }

    /// Unpairing while the file cannot be read, and a process that ends before any write can be
    /// made: the next launch finds the host unpaired, and the host's entry is neither shown nor
    /// kept. The removal of the pairing was written before the unpairing was reported, so it is
    /// what outlives the launch.
    #[cfg(unix)]
    #[test]
    fn a_host_forgotten_while_the_file_cannot_be_read_stays_forgotten_after_a_restart() {
        let directory = tempfile::tempdir().expect("a folder");
        two_hosts_left_a_start_each(directory.path());
        let file = directory.path().join("voice-kept.json");
        std::fs::rename(&file, directory.path().join("voice-kept.locked")).expect("put aside");
        std::os::unix::fs::symlink(&file, &file).expect("a link that cannot be opened");
        {
            let calls = calls_in(directory.path());
            calls.forget_starts_of(host(1).0);
            // The process ends here: nothing was written, and what was kept is not known.
        }
        std::fs::remove_file(&file).expect("the link goes");
        std::fs::rename(directory.path().join("voice-kept.locked"), &file).expect("unlocked");
        assert_eq!(
            file_holds(directory.path()),
            vec![pair(START_UNKNOWN, "one"), pair(START_UNKNOWN, "two")],
            "no write was made before the process ended"
        );

        let fresh = calls_in(directory.path());
        fresh.know_pairings(paired_except(host(1).0));
        assert_eq!(
            actions_shown(&fresh),
            vec!["two".to_owned()],
            "the unpaired host's entry is not shown by the launch that follows"
        );
        assert_eq!(
            file_holds(directory.path()),
            vec![pair(START_UNKNOWN, "two")],
            "and the removal is written"
        );
    }

    /// Unpairing while the cleanup cannot be written, and a process that ends before any write is
    /// made: the same.
    #[cfg(unix)]
    #[test]
    fn a_host_forgotten_while_the_cleanup_cannot_be_written_stays_forgotten_after_a_restart() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().expect("a folder");
        two_hosts_left_a_start_each(directory.path());
        {
            let calls = calls_in(directory.path());
            // The folder takes no new file, so the file cannot be replaced.
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o500))
                .expect("the folder is made read-only");
            let probe = directory.path().join("probe");
            if std::fs::File::create(&probe).is_ok() {
                let _ = std::fs::remove_file(&probe);
                std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
                    .expect("the folder is made writable again");
                eprintln!("the folder's mode does not bind this user: the write cannot fail");
                return;
            }
            calls.forget_starts_of(host(1).0);
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
                .expect("the folder is made writable again");
            // The process ends here.
        }
        assert_eq!(
            file_holds(directory.path()),
            vec![pair(START_UNKNOWN, "one"), pair(START_UNKNOWN, "two")],
            "the cleanup was not written"
        );

        let fresh = calls_in(directory.path());
        fresh.know_pairings(paired_except(host(1).0));
        assert_eq!(
            actions_shown(&fresh),
            vec!["two".to_owned()],
            "the unpaired host's entry is not shown by the launch that follows"
        );
        assert_eq!(
            file_holds(directory.path()),
            vec![pair(START_UNKNOWN, "two")],
            "and the removal is written"
        );
    }

    /// A launch that cannot tell how a host is paired keeps the host's entries in the file and
    /// shows and names none of them until it can; a host it can tell about is shown meanwhile, and
    /// the entries of a pairing that is gone are removed at the first use after every host can be
    /// told.
    #[test]
    fn a_launch_that_cannot_tell_how_a_host_is_paired_shows_no_entry_of_that_host_until_it_can() {
        let directory = tempfile::tempdir().expect("a folder");
        two_hosts_left_a_start_each(directory.path());
        let calls = calls_in(directory.path());
        let answer = Arc::new(std::sync::atomic::AtomicU8::new(0));
        calls.know_pairings({
            let answer = Arc::clone(&answer);
            move |paired| match (
                answer.load(std::sync::atomic::Ordering::SeqCst),
                paired == host(1).0,
            ) {
                (0, _) | (1, true) => PairedNow::Unknown,
                (1, false) => PairedNow::As(paired),
                (_, true) => PairedNow::Not,
                (_, false) => PairedNow::As(paired),
            }
        });
        let shared = calls.shared.as_ref().expect("a phone holds calls");
        assert_eq!(
            actions_shown(&calls),
            Vec::<String>::new(),
            "no host can be told about: nothing is shown"
        );
        assert_eq!(shared.start_named_in(host(1), "the start one", None), None);
        assert!(shared.earlier_start("one", host(1)).is_err());
        assert_eq!(
            file_holds(directory.path()),
            vec![pair(START_UNKNOWN, "one"), pair(START_UNKNOWN, "two")],
            "nothing was told, so nothing was removed"
        );

        answer.store(1, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(
            actions_shown(&calls),
            vec!["two".to_owned()],
            "a host that can be told about is shown while another cannot be"
        );
        assert_eq!(shared.start_named_in(host(1), "the start one", None), None);
        assert_eq!(
            shared.start_named_in(host(2), "the start two", None),
            Some("two".to_owned())
        );
        assert!(shared.earlier_start("one", host(1)).is_err());
        assert!(shared.earlier_start("two", host(2)).is_ok());

        answer.store(2, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(actions_shown(&calls), vec!["two".to_owned()]);
        assert_eq!(
            file_holds(directory.path()),
            vec![pair(START_UNKNOWN, "two")],
            "the pairing that is gone is removed once every host can be told"
        );
    }

    /// Records a start that these calls made under the pairing held after the host was paired again.
    fn a_start_under_the_new_pairing(calls: &Calls, action: &str) {
        let shared = calls.shared.as_ref().expect("a phone holds calls");
        shared.settle_start(
            0,
            None,
            Some(OwedView {
                pairing: Some(paired_again()),
                ..entry(START_UNKNOWN, action, host(1))
            }),
            None,
        );
    }

    /// The host is forgotten while the file cannot be read, the process ends before any write, and
    /// the device is paired with the host again before the next launch reads the file: the starts
    /// of the pairing that ended are removed before any is shown, and the next start of the new
    /// pairing stays.
    #[cfg(unix)]
    #[test]
    fn a_host_paired_again_after_a_forget_the_file_could_not_take_keeps_no_start_of_the_first_pairing()
     {
        let directory = tempfile::tempdir().expect("a folder");
        two_hosts_left_a_start_each(directory.path());
        let file = directory.path().join("voice-kept.json");
        std::fs::rename(&file, directory.path().join("voice-kept.locked")).expect("put aside");
        std::os::unix::fs::symlink(&file, &file).expect("a link that cannot be opened");
        {
            let calls = calls_in(directory.path());
            calls.forget_starts_of(host(1).0);
            // The process ends here: nothing was written.
        }
        std::fs::remove_file(&file).expect("the link goes");
        std::fs::rename(directory.path().join("voice-kept.locked"), &file).expect("unlocked");

        let fresh = calls_in(directory.path());
        fresh.know_pairings(paired_again_with(host(1).0));
        assert_eq!(
            actions_shown(&fresh),
            vec!["two".to_owned()],
            "the start of the first pairing is not shown after the host is paired again"
        );
        assert_eq!(
            file_holds(directory.path()),
            vec![pair(START_UNKNOWN, "two")],
            "and the removal is written"
        );
        a_start_under_the_new_pairing(&fresh, "three");
        assert_eq!(
            actions_shown(&fresh),
            vec!["two".to_owned(), "three".to_owned()],
            "the start of the new pairing stays"
        );

        let later = calls_in(directory.path());
        later.know_pairings(paired_again_with(host(1).0));
        assert_eq!(
            actions_shown(&later),
            vec!["two".to_owned(), "three".to_owned()],
            "and the launch after it finds it"
        );
    }

    /// The cleanup cannot be written, the process ends, the device is paired with the host again,
    /// and the next launch cannot write either: no start of the first pairing is shown, the file
    /// keeps them until a write can be made, and the starts of the new pairing stay.
    #[cfg(unix)]
    #[test]
    fn a_host_paired_again_after_a_cleanup_that_failed_keeps_no_start_of_the_first_pairing() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().expect("a folder");
        two_hosts_left_a_start_each(directory.path());
        let make_writable = || {
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
                .expect("the folder is made writable again");
        };
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o500))
            .expect("the folder is made read-only");
        let probe = directory.path().join("probe");
        if std::fs::File::create(&probe).is_ok() {
            let _ = std::fs::remove_file(&probe);
            make_writable();
            eprintln!("the folder's mode does not bind this user: the write cannot fail");
            return;
        }
        {
            let calls = calls_in(directory.path());
            calls.forget_starts_of(host(1).0);
            // The process ends here: the cleanup was not written.
        }
        {
            let fresh = calls_in(directory.path());
            fresh.know_pairings(paired_again_with(host(1).0));
            assert_eq!(
                actions_shown(&fresh),
                vec!["two".to_owned()],
                "the start of the first pairing is not shown, though the removal cannot be written"
            );
        }
        make_writable();
        assert_eq!(
            file_holds(directory.path()),
            vec![pair(START_UNKNOWN, "one"), pair(START_UNKNOWN, "two")],
            "the file keeps the start until a write can be made"
        );

        let later = calls_in(directory.path());
        later.know_pairings(paired_again_with(host(1).0));
        assert_eq!(actions_shown(&later), vec!["two".to_owned()]);
        assert_eq!(
            file_holds(directory.path()),
            vec![pair(START_UNKNOWN, "two")],
            "the removal is written at the first use after a write can be made"
        );
        a_start_under_the_new_pairing(&later, "three");
        let last = calls_in(directory.path());
        last.know_pairings(paired_again_with(host(1).0));
        assert_eq!(
            actions_shown(&last),
            vec!["two".to_owned(), "three".to_owned()],
            "the start of the new pairing stays"
        );
    }

    /// What a reply that carries the record shows: nothing that has lapsed, no start that is only
    /// kept, and no start whose pairing is not told.
    #[test]
    fn what_the_replies_show_leaves_out_hidden_lapsed_and_untold_starts() {
        let directory = tempfile::tempdir().expect("a folder");
        Kept::at(directory.path())
            .write(&KeptVoice {
                owed: vec![
                    entry(START_UNKNOWN, "shown", host(2)),
                    entry(START_KEPT, "kept", host(2)),
                    entry(START_UNANSWERED, "unanswered", host(2)),
                    entry(START_UNKNOWN, "untold", host(1)),
                ],
                note: None,
            })
            .expect("the file is written");
        let calls = calls_in(directory.path());
        calls.know_pairings(|paired| {
            if paired == host(1).0 {
                PairedNow::Unknown
            } else {
                PairedNow::As(paired)
            }
        });
        let shared = calls.shared.as_ref().expect("a phone holds calls");
        shared.read_again();
        let mut raw = shared
            .view
            .lock()
            .expect("the view lock is not poisoned")
            .clone();
        raw.owed.push(OwedView {
            until_ms: 5,
            ..entry("revocation", "lapsed", host(2))
        });
        assert_eq!(raw.owed.len(), 5, "the record holds all five");
        let shown: Vec<String> = shared
            .shown(raw)
            .owed
            .into_iter()
            .filter_map(|each| each.action_id)
            .collect();
        assert_eq!(shown, vec!["shown".to_owned()]);
    }

    /// A start's answer that passed the hold is recorded in one write of the whole file: the
    /// earlier starts the pass changed, the start's own entry and what is owed next are all in the
    /// file that write leaves, and no write leaves one of them without the others.
    #[test]
    fn a_start_that_passed_the_hold_is_recorded_in_one_write_of_the_whole_file() {
        let directory = tempfile::tempdir().expect("a folder");
        Kept::at(directory.path())
            .write(&KeptVoice {
                owed: vec![
                    entry(START_UNKNOWN, "old", host(1)),
                    entry(START_KEPT, "older", host(1)),
                    entry(START_UNKNOWN, "other", host(2)),
                ],
                note: None,
            })
            .expect("the file is written");
        let calls = calls_in(directory.path());
        let shared = calls.shared.as_ref().expect("a phone holds calls");
        let owner = shared
            .next_owner
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        assert!(shared.stand_open_durably(owner, entry(START_UNKNOWN, "new", host(1))));
        let before = shared.kept.writes();

        shared.settle_start(
            owner,
            Some(host(1)),
            Some(entry(START_KEPT, "new", host(1))),
            Some(entry("revocation", "rev", host(1))),
        );

        assert_eq!(
            shared.kept.writes() - before,
            1,
            "the pass, the entry and what is owed next are one write"
        );
        assert_eq!(
            file_holds(directory.path()),
            vec![
                pair(START_UNANSWERED, "old"),
                pair(START_UNKNOWN, "other"),
                pair(START_KEPT, "new"),
                pair("revocation", "rev"),
            ],
            "and that write is the whole change"
        );
    }

    /// The starts a launch kept, by the kinds of D-3731's table, are what the launch that follows
    /// finds and names: a fresh `Calls` over the file the first one wrote finds the older kept
    /// start and the start the host never answered as candidates, shows only the notices, and
    /// offers no hidden start to the page.
    #[test]
    fn a_fresh_calls_over_the_file_finds_the_kept_starts_the_refusal_names() {
        let directory = tempfile::tempdir().expect("a folder");
        {
            let calls = calls_in(directory.path());
            let shared = calls.shared.as_ref().expect("a phone holds calls");
            shared.settle_start(
                0,
                None,
                Some(entry(START_KEPT, "x-0001-aaaa", host(1))),
                None,
            );
            shared.settle_start(
                0,
                None,
                Some(entry(START_UNANSWERED, "y-0002-bbbb", host(1))),
                None,
            );
            shared.settle_start(
                0,
                None,
                Some(entry(START_UNKNOWN, "z-0003-cccc", host(1))),
                None,
            );
        }
        let fresh = calls_in(directory.path());
        let shared = fresh.shared.as_ref().expect("a phone holds calls");
        assert_eq!(
            actions_shown(&fresh),
            vec!["z-0003-cccc".to_owned()],
            "only the notice is shown after the restart"
        );
        assert_eq!(
            shared
                .start_named_in(host(1), "held under action x-0001-aaaa, begun", None)
                .as_deref(),
            Some("x-0001-aaaa"),
            "the older kept start is a candidate after the restart"
        );
        assert_eq!(
            shared
                .start_named_in(host(1), "held under y-0002-bbbb", None)
                .as_deref(),
            Some("y-0002-bbbb"),
            "the start the host never answered is a candidate after the restart"
        );
    }

    /// A directory flush that fails after the file was put in place is a write that failed: the
    /// start is not sent, and the launch that follows reads the file the rename left, which holds
    /// the entry of the start that was never sent, as a start the host did not answer.
    #[test]
    fn a_start_whose_record_could_not_be_flushed_is_not_sent_and_the_next_launch_reads_the_file() {
        let directory = tempfile::tempdir().expect("a folder");
        let calls = calls_in(directory.path());
        let shared = calls.shared.as_ref().expect("a phone holds calls");
        let owner = shared
            .next_owner
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let refused = kr_flush::testing::refuse_flushes_of(directory.path());
        let durable = shared.stand_open_durably(owner, entry(START_UNKNOWN, "flight", host(1)));
        drop(refused);
        assert!(
            !durable,
            "a record that could not be made durable does not let the start be sent"
        );
        // The rename had already put the file in place, so a fresh reader finds the entry.
        assert_eq!(
            file_holds(directory.path()),
            vec![pair(START_UNKNOWN, "flight")]
        );
        let fresh = calls_in(directory.path());
        assert_eq!(actions_shown(&fresh), vec!["flight".to_owned()]);
    }

    /// A revocation settled while a dismissal is being saved is not brought back by the dismissal:
    /// both take the same order as every other change of the record.
    #[test]
    fn a_removal_that_runs_during_a_dismissal_is_not_lost() {
        let directory = tempfile::tempdir().expect("a folder");
        let calls = calls_in(directory.path());
        let shared = Arc::clone(calls.shared.as_ref().expect("a phone holds calls"));
        let mut revocation = entry("revocation", "", host(1));
        revocation.action_id = None;
        revocation.voice_session_id = Some("v1".to_owned());
        shared.view.lock().expect("the view lock").owed =
            vec![revocation, entry(START_UNKNOWN, "n1", host(2))];

        let (started, wait_started) = std::sync::mpsc::channel();
        let (done, wait_done) = std::sync::mpsc::channel();
        let mut removing = None;
        let other = Arc::clone(&shared);
        let changed = shared.change_owed_durably(|state| {
            removing = Some(std::thread::spawn(move || {
                started.send(()).expect("the dismissal waits");
                other.settled(host(1).0, host(1).1, "v1");
                done.send(()).expect("the dismissal waits");
            }));
            wait_started.recv().expect("the removal started");
            // A removal that does not wait for this change finishes here, and the change then
            // replaces what it left with the copy it made before.
            let _ = wait_done.recv_timeout(std::time::Duration::from_millis(300));
            state.dismiss_start("n1")
        });
        assert_eq!(changed, Ok(true));
        removing.expect("the removal ran").join().expect("it ended");

        let kinds: Vec<String> = shared
            .view
            .lock()
            .expect("the view lock")
            .owed
            .iter()
            .map(|each| each.kind.clone())
            .collect();
        assert_eq!(kinds, vec![START_UNANSWERED.to_owned()]);
        assert_eq!(
            file_holds(directory.path()),
            vec![pair(START_UNANSWERED, "n1")]
        );
    }

    /// The one earlier start of a host that its refusal's words name is found, and only that one:
    /// the newest kept start is not the answer, two named starts are no candidate, the start the
    /// refused start itself named is passed over, a start the host never answered is a candidate,
    /// and another host's start is none.
    #[test]
    fn the_start_a_refusal_names_is_the_one_kept_start_its_words_hold() {
        let directory = tempfile::tempdir().expect("a folder");
        let calls = calls_in(directory.path());
        let shared = calls.shared.as_ref().expect("a phone holds calls");
        let (a, x, y) = ("a-0003-cccc", "x-0001-aaaa", "y-0002-bbbb");
        let owed = |entries: Vec<OwedView>| {
            shared.view.lock().expect("the view lock").owed = entries;
        };

        owed(vec![
            entry(START_KEPT, x, host(1)),
            entry(START_UNANSWERED, y, host(1)),
        ]);
        let older = shared.start_named_in(host(1), &format!("held under action {x}, begun"), None);
        assert_eq!(
            older.as_deref(),
            Some(x),
            "the older kept start, beside a newer hidden one"
        );
        let both = shared.start_named_in(host(1), &format!("actions {x} and {y}"), None);
        assert_eq!(both, None, "two named starts are no candidate");

        owed(vec![
            entry(START_UNANSWERED, a, host(1)),
            entry(START_KEPT, x, host(1)),
        ]);
        let misnamed = shared.start_named_in(
            host(1),
            &format!("held under {a}; you named {x}"),
            Some(x.to_owned()),
        );
        assert_eq!(
            misnamed.as_deref(),
            Some(a),
            "the start's own argument is passed over"
        );

        owed(vec![entry(START_UNANSWERED, a, host(1))]);
        let unanswered = shared.start_named_in(host(1), &format!("held under {a}"), None);
        assert_eq!(
            unanswered.as_deref(),
            Some(a),
            "a start the host never answered is a candidate"
        );

        owed(vec![entry(START_KEPT, x, host(2))]);
        let elsewhere = shared.start_named_in(host(1), &format!("held under {x}"), None);
        assert_eq!(elsewhere, None, "another host's start is none");
    }

    /// A start can name an earlier start only of the host it was made to: the same device in
    /// another environment is another host.
    #[test]
    fn an_earlier_start_is_named_only_for_the_host_it_was_made_to() {
        let directory = tempfile::tempdir().expect("a folder");
        let calls = calls_in(directory.path());
        let shared = calls.shared.as_ref().expect("a phone holds calls");
        shared.view.lock().expect("the view lock").owed = vec![entry(START_KEPT, "x", host(1))];
        let other_environment = (
            host(1).0,
            kr_protocol::ids::EnvironmentId::new(kr_protocol::scalars::Uuid::from_bytes([9; 16])),
        );

        assert_eq!(shared.earlier_start("x", host(1)), Ok(()));
        assert!(shared.earlier_start("x", other_environment).is_err());
        assert!(shared.earlier_start("x", host(2)).is_err());
        assert!(shared.earlier_start("nothing", host(1)).is_err());
    }
}

#[cfg(test)]
mod named_in_words {
    use super::names_token;

    /// An action id in a host's words is found only as a whole token: a longer id that begins with
    /// it, or one that ends with it, is not it.
    #[test]
    fn an_id_is_found_only_as_a_whole_token() {
        let id = "0f3c-4a";
        assert!(names_token("hold (action 0f3c-4a, begun", id));
        assert!(names_token("under action 0f3c-4a.", id));
        assert!(names_token("0f3c-4a", id));
        assert!(!names_token("under action 0f3c-4a1, begun", id));
        assert!(!names_token("under action x0f3c-4a, begun", id));
        assert!(!names_token("under action 0f3c-4a-9, begun", id));
        assert!(!names_token("no id here", id));
    }

    /// The sentences the host's cases read, with the ids a kept start has.
    const FIXTURE: &str =
        include_str!("../../../../../crates/kr-controller/tests/fixtures/voice_hold_refusals.txt");

    fn sentence(name: &str, standing: &str, named: &str) -> String {
        FIXTURE
            .lines()
            .find_map(|line| line.strip_prefix(&format!("{name}: ")))
            .expect("the fixture has the sentence")
            .replace("{A}", standing)
            .replace("{B}", named)
            .replace("{T0}", "2026-11-18 10:00:00 UTC")
            .replace("{T1}", "2026-11-18 10:11:50 UTC")
    }

    /// The host's refusal names the standing start once, however it is worded: the one kept id that
    /// the words hold as a whole token is found, a prefix of it is not, and the id the start named is
    /// not the one it finds.
    #[test]
    fn the_hosts_refusal_sentences_name_the_kept_start() {
        let standing = "7c1e0f3c-4a21-4b6e-9c11-0123456789ab";
        let named = "d2a9b1c4-5e66-4f70-8a12-ba9876543210";
        for words in [
            sentence("unnamed", standing, named),
            sentence("named", standing, named),
        ] {
            assert!(names_token(&words, standing), "{words}");
            assert!(
                !names_token(&words, &standing[..13]),
                "a prefix is not the id: {words}"
            );
            assert!(
                !names_token(&words, "00000000-0000-4000-8000-000000000000"),
                "{words}"
            );
        }
        // The sentence that says the start was not recorded names no action at all.
        let unrecorded = sentence("unrecorded", standing, named);
        assert!(!names_token(&unrecorded, standing), "{unrecorded}");
        // The sentence for a misnamed start holds both ids: the one the start named is the other
        // kept id, and a lookup that excludes it finds the standing one.
        let misnamed = sentence("named", standing, named);
        assert!(names_token(&misnamed, named), "{misnamed}");
    }
}
