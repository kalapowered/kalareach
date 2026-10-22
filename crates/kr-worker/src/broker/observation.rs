//! What the worker offers the components of its bindings to observe, and the queue it waits in.
//!
//! A binding whose package ships a component can be offered two streams: the connector's own
//! upstream frames (provenance `native_protocol`, the installation's `broker.semantic_events`) and
//! the session's terminal output (provenance `terminal_scrape`, `terminal.stream`). Neither is
//! offered from the place that produces it. The pseudo-terminal's read loop and the gateway's reader
//! push what they have onto the [`ObservationLane`] and carry on: the push is a short critical
//! section on a leaf lock, it never waits for a component, and it never makes a call. A task of the
//! plugin runtime's link (the pump, `crate::plugin_observation`) takes entries off the lane and makes
//! the calls. That is the structure section 11 asks for in "PTY draining, terminal-query responses
//! and presentation queues never wait for observation callbacks": nothing the producers hold is held
//! by anything that can wait on a component.
//!
//! # The lane
//!
//! The lane holds at most 4 MiB, the entry the pump is working on included. When an entry does not
//! fit, the oldest ordinary entries go until it does, each counted in the loss the lane keeps. An
//! authoritative entry, a native request the upstream is waiting on, is never evicted for room: when
//! only authoritative entries remain a new entry is refused and counted. The broker keeps the
//! request in its ledger and its source frames whatever the lane does; what a loss costs is the
//! component's view of it, and the loss says so.
//!
//! # The views
//!
//! Beside the entries the lane keeps one [`View`] for each binding, shared by the pump and the link.
//! A view says whether the binding may be offered anything yet, and what its component has missed:
//! each loss is numbered, a snapshot is requested for the number current when it is asked for and
//! discharges that number only, so a loss that arrives while a snapshot runs asks for another.
//!
//! The checkpoints the link holds for a binding are kept here too, so that privacy mode has one place
//! to remove them from.

use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use kr_plugin_sdk::limits::OBSERVATION_QUEUE_BYTES;
use kr_protocol::ids::{ApplicationInstanceId, BrokerBindingId, SourceEventHandle};
use tokio::time::Instant;

use super::{Broker, PackageIdentity};

/// What one entry costs beyond its bytes, so a lane of empty entries is still bounded.
pub const ENTRY_OVERHEAD_BYTES: u64 = 128;

/// The largest piece of terminal output one event carries.
pub const PIECE_BYTES: usize = 256 * 1024;

/// How long a binding is passed over after a call to its runtime ran out its deadline, the first
/// time. Each failure after doubles it, up to [`LONGEST_SILENCE`].
pub const SILENCE: Duration = Duration::from_secs(10);

/// The longest a binding is passed over for.
pub const LONGEST_SILENCE: Duration = Duration::from_secs(120);

/// How long a snapshot that could not be asked for is left before it is asked for again, the
/// first time. Each failure after doubles it, up to [`LONGEST_SNAPSHOT_RETRY`].
pub const SNAPSHOT_RETRY: Duration = Duration::from_secs(1);

/// The longest a snapshot is left for.
pub const LONGEST_SNAPSHOT_RETRY: Duration = Duration::from_secs(30);

/// How long a binding is quiet for before its state is taken.
pub const QUIET_BEFORE_CHECKPOINT: Duration = Duration::from_secs(2);

/// The longest a binding that is still being offered events goes between attempts to take its
/// state.
pub const CHECKPOINT_EVERY: Duration = Duration::from_secs(60);

/// The most checkpoint bytes the worker holds for all its bindings together.
pub const CHECKPOINT_BYTES: u64 = 8 * 1024 * 1024;

/// One upstream frame, offered as a native request or as news.
#[derive(Clone, Debug)]
pub struct NativeFrame {
    /// The instance whose connection read it.
    pub instance: ApplicationInstanceId,
    /// The package whose table read it. Only that package's bindings are offered it.
    pub package: PackageIdentity,
    /// The handle the broker retained the frame under, where it retained it (a request that
    /// expects a response); a frame nothing retains is given one when it is offered.
    pub handle: Option<SourceEventHandle>,
    /// The upstream's identifier for the request, where the frame is one the upstream is waiting
    /// on. Such an entry is authoritative.
    pub request_id: Option<String>,
    /// The frame's bytes, shared and never changed.
    pub bytes: Arc<[u8]>,
}

/// Where an entry came from.
#[derive(Clone, Debug)]
pub enum Source {
    /// An upstream frame on a connection a package's table reads.
    Native(NativeFrame),
    /// A span of the session's terminal output, as the owner's own terminal receives it.
    Terminal(Arc<Vec<u8>>),
}

/// Who may be offered an entry: the question [`Broker::observing`] answers.
#[derive(Clone, Copy, Debug)]
pub enum Audience<'a> {
    /// Bindings granted the terminal's output.
    Terminal,
    /// Bindings of one instance, and of one package where it is named, granted the connector's own
    /// upstream frames.
    Native {
        /// The instance.
        instance: ApplicationInstanceId,
        /// The package whose table read the frames, where one did.
        package: Option<&'a PackageIdentity>,
    },
}

/// One thing waiting to be offered.
#[derive(Clone, Debug)]
pub struct Entry {
    seq: u64,
    /// What it is.
    pub source: Source,
    /// When the worker had it, in milliseconds since the Unix epoch.
    pub at_ms: u64,
    /// Whether privacy mode was on when the worker had it, so that a component offered it later
    /// holds something made in privacy mode however privacy mode stands then.
    pub private: bool,
    cost: u64,
}

impl Entry {
    /// Returns the number this entry was pushed under: entries are offered in this order.
    #[must_use]
    pub const fn seq(&self) -> u64 {
        self.seq
    }

    /// Returns true when the upstream is waiting on this entry's request. Such an entry is never
    /// evicted to make room.
    #[must_use]
    pub fn is_authoritative(&self) -> bool {
        matches!(&self.source, Source::Native(frame) if frame.request_id.is_some())
    }

    /// Who may be offered it.
    #[must_use]
    pub fn audience(&self) -> Audience<'_> {
        match &self.source {
            Source::Native(frame) => Audience::Native {
                instance: frame.instance,
                package: Some(&frame.package),
            },
            Source::Terminal(_) => Audience::Terminal,
        }
    }
}

/// How many entries and bytes a loss took.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Tally {
    /// Entries.
    pub events: u64,
    /// Bytes.
    pub bytes: u64,
}

impl Tally {
    fn add(&mut self, bytes: u64) {
        self.events = self.events.saturating_add(1);
        self.bytes = self.bytes.saturating_add(bytes);
    }
}

/// What the lane lost of the upstream frames one package's table read on one instance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeLoss {
    /// The instance whose connection read them.
    pub instance: ApplicationInstanceId,
    /// The package whose table read them: only its bindings are owed a snapshot for them.
    pub package: PackageIdentity,
    /// How many, and how much.
    pub tally: Tally,
}

/// What the lane lost since the pump last looked, by who would have been offered it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LaneLoss {
    /// Terminal output.
    pub terminal: Tally,
    /// Upstream frames, by the instance and the package that read them.
    pub native: Vec<NativeLoss>,
}

impl LaneLoss {
    fn is_empty(&self) -> bool {
        self.terminal == Tally::default() && self.native.is_empty()
    }
}

/// What a push became.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pushed {
    /// The entry is waiting.
    Kept,
    /// The lane was full of authoritative entries (or the entry could not fit at all) and the entry
    /// was not taken. Counted in the loss.
    Refused,
}

/// The lane's account of what it has lost, since it began.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Account {
    /// Ordinary entries lost for want of room: pushed out by a newer one, or too late to fit.
    pub evicted: Tally,
    /// Entries the upstream is waiting on, and entries larger than the lane, that were not taken
    /// for want of room.
    pub refused: Tally,
}

/// What one binding's component has missed, and where the worker stands with it.
#[derive(Clone, Debug, Default)]
pub struct View {
    /// Whether the binding may be offered anything: registered, its checkpoint restored where there
    /// was one, and the snapshot after the restore answered.
    pub ready: bool,
    /// The number of the latest loss.
    pub lost_seq: u64,
    /// The loss number the latest answered snapshot was requested for.
    pub snapshot_through: u64,
    /// Not offered anything, and not asked for a snapshot, until this has passed.
    pub silent_until: Option<Instant>,
    /// How long the next silence is.
    pub silence: Option<Duration>,
    /// How long the next failed snapshot is left.
    pub snapshot_retry: Option<Duration>,
    /// How many events have been offered since the last attempt to take the binding's state.
    pub offered_since_checkpoint: u64,
    /// When an event was last offered.
    pub last_offer: Option<Instant>,
    /// When the binding's state was last asked for, answered or not.
    pub last_checkpoint_attempt: Option<Instant>,
    /// What the component last missed, in the words a person is told.
    pub loss_note: Option<String>,
    /// Whether the component was offered something made while privacy mode was on, so that its
    /// state may hold it. None is taken from it until it starts again.
    pub private_content: bool,
    /// The first entry the binding may be offered: those pushed before it was made ready are older
    /// than its view.
    pub ready_from: u64,
}

impl View {
    /// Returns the loss number a snapshot is owed for, where one is.
    #[must_use]
    pub const fn owes(&self) -> Option<u64> {
        if self.lost_seq > self.snapshot_through {
            Some(self.lost_seq)
        } else {
            None
        }
    }

    /// Returns true when nothing should be asked of this binding yet.
    #[must_use]
    pub fn is_silent(&self, now: Instant) -> bool {
        self.silent_until.is_some_and(|until| now < until)
    }
}

/// A binding's component state, held to be restored after the plugin runtime is lost.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Held {
    /// The package digest it was taken under.
    pub package_digest: kr_protocol::scalars::Digest256,
    /// The instance's source generation it was taken under: a new execution never restores an
    /// earlier one's state.
    pub generation: u64,
    /// The state, as the component returned it.
    pub state: Vec<u8>,
}

#[derive(Debug, Default)]
struct Inner {
    ordinary: VecDeque<Entry>,
    authoritative: VecDeque<Entry>,
    held: u64,
    in_flight_entries: u64,
    next_seq: u64,
    pending_loss: LaneLoss,
    account: Account,
    views: BTreeMap<BrokerBindingId, View>,
    checkpoints: BTreeMap<BrokerBindingId, Held>,
    checkpoint_order: VecDeque<BrokerBindingId>,
    checkpoint_bytes: u64,
}

impl Inner {
    fn lose(&mut self, entry: &Entry, refused: bool) {
        let bytes = entry.cost;
        match &entry.source {
            Source::Terminal(_) => self.pending_loss.terminal.add(bytes),
            Source::Native(frame) => {
                let losses = &mut self.pending_loss.native;
                let at = losses.iter().position(|loss| {
                    loss.instance == frame.instance && loss.package == frame.package
                });
                let loss = if let Some(at) = at {
                    &mut losses[at]
                } else {
                    losses.push(NativeLoss {
                        instance: frame.instance,
                        package: frame.package.clone(),
                        tally: Tally::default(),
                    });
                    let last = losses.len() - 1;
                    &mut losses[last]
                };
                loss.tally.add(bytes);
            }
        }
        if refused {
            self.account.refused.add(bytes);
        } else {
            self.account.evicted.add(bytes);
        }
    }
}

/// The queue of what the worker has to offer, the views of what each binding has missed, and the
/// state the link holds for each binding.
#[derive(Debug)]
pub struct ObservationLane {
    inner: Mutex<Inner>,
    wake: tokio::sync::Notify,
    /// Whether any binding takes upstream frames. A producer that finds it false pushes nothing.
    native_wanted: AtomicBool,
    /// Whether any binding takes terminal output.
    terminal_wanted: AtomicBool,
    /// Whether privacy mode is on: no component's state is taken or held.
    private: AtomicBool,
    /// Advances each time privacy mode is turned on or off, so that a state asked for before the
    /// change is not held after it.
    privacy_epoch: AtomicU64,
    /// Wakes the link when a binding that was owed nothing is offered something, so that the time
    /// its state falls due is worked out again.
    checkpoint_wake: tokio::sync::Notify,
    #[cfg(feature = "testing")]
    hold: Mutex<Option<Arc<HoldState>>>,
}

/// The two halves of a hold on the pump, for this host's own tests: a signal that the pump has
/// stopped at the hold, and the release.
#[cfg(feature = "testing")]
#[derive(Debug, Default)]
struct HoldState {
    parked: AtomicBool,
    released: AtomicBool,
}

/// A hold on the pump. While it is held the pump takes nothing off the lane. It is for this host's
/// own tests, the way a pause before a marker is.
#[cfg(feature = "testing")]
#[derive(Debug)]
pub struct PumpHold {
    state: Arc<HoldState>,
    lane: Arc<ObservationLane>,
}

#[cfg(feature = "testing")]
impl PumpHold {
    /// Returns true once the pump has reached the hold and is waiting at it.
    #[must_use]
    pub fn parked(&self) -> bool {
        self.state.parked.load(Ordering::Acquire)
    }

    /// Lets the pump go on.
    pub fn release(&self) {
        self.state.released.store(true, Ordering::Release);
        self.lane.nudge();
    }
}

impl Default for ObservationLane {
    fn default() -> Self {
        Self::new()
    }
}

impl ObservationLane {
    /// Builds an empty lane.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Inner::default()),
            wake: tokio::sync::Notify::new(),
            native_wanted: AtomicBool::new(false),
            terminal_wanted: AtomicBool::new(false),
            private: AtomicBool::new(false),
            privacy_epoch: AtomicU64::new(0),
            checkpoint_wake: tokio::sync::Notify::new(),
            #[cfg(feature = "testing")]
            hold: Mutex::new(None),
        }
    }

    fn inner(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    // -- producers ----------------------------------------------------------------------------

    /// Says which streams any binding takes now. A stream nobody takes costs a producer one load.
    pub fn set_wanted(&self, native: bool, terminal: bool) {
        self.native_wanted.store(native, Ordering::Release);
        self.terminal_wanted.store(terminal, Ordering::Release);
    }

    /// Returns true when some binding takes upstream frames.
    #[must_use]
    pub fn wants_native(&self) -> bool {
        self.native_wanted.load(Ordering::Acquire)
    }

    /// Returns true when some binding takes terminal output.
    #[must_use]
    pub fn wants_terminal(&self) -> bool {
        self.terminal_wanted.load(Ordering::Acquire)
    }

    /// Pushes one span of terminal output. Never waits, and copies nothing.
    pub fn push_terminal(&self, bytes: &Arc<Vec<u8>>, at_ms: u64) -> Option<Pushed> {
        if !self.wants_terminal() || bytes.is_empty() {
            return None;
        }
        Some(self.push(
            Source::Terminal(Arc::clone(bytes)),
            bytes.len() as u64,
            at_ms,
        ))
    }

    /// Pushes one upstream frame. Never waits.
    pub fn push_native(&self, frame: NativeFrame, at_ms: u64) -> Option<Pushed> {
        if !self.wants_native() {
            return None;
        }
        let bytes = frame.bytes.len() as u64;
        Some(self.push(Source::Native(frame), bytes, at_ms))
    }

    fn push(&self, source: Source, bytes: u64, at_ms: u64) -> Pushed {
        let cost = bytes.saturating_add(ENTRY_OVERHEAD_BYTES);
        let mut inner = self.inner();
        let seq = inner.next_seq;
        inner.next_seq = inner.next_seq.saturating_add(1);
        let entry = Entry {
            seq,
            source,
            at_ms,
            private: self.private.load(Ordering::Acquire),
            cost,
        };
        if cost > OBSERVATION_QUEUE_BYTES {
            inner.lose(&entry, true);
            drop(inner);
            self.wake.notify_one();
            return Pushed::Refused;
        }
        // The oldest ordinary entries go first, one at a time, until this one fits.
        while inner.held.saturating_add(cost) > OBSERVATION_QUEUE_BYTES {
            let Some(oldest) = inner.ordinary.pop_front() else {
                break;
            };
            inner.held = inner.held.saturating_sub(oldest.cost);
            inner.lose(&oldest, false);
        }
        if inner.held.saturating_add(cost) > OBSERVATION_QUEUE_BYTES {
            // Only authoritative entries are left (or the pump's own), and none is evicted.
            // An ordinary entry that does not fit is lost; an authoritative one is refused. Both
            // are counted, and the broker's own record of the request is what stays.
            let refused = entry.is_authoritative();
            inner.lose(&entry, refused);
            drop(inner);
            self.wake.notify_one();
            return Pushed::Refused;
        }
        inner.held = inner.held.saturating_add(cost);
        if entry.is_authoritative() {
            inner.authoritative.push_back(entry);
        } else {
            inner.ordinary.push_back(entry);
        }
        drop(inner);
        self.wake.notify_one();
        Pushed::Kept
    }

    // -- the pump -----------------------------------------------------------------------------

    /// Takes the oldest entry, in the order it was pushed. The lane goes on counting it against its
    /// bound until [`Self::finish`].
    pub fn take(&self) -> Option<Entry> {
        let mut inner = self.inner();
        // What the lane has lost is owed to the components before anything later is handed to them,
        // and it is the pump's to apply: while a loss waits, no entry is taken.
        if !inner.pending_loss.is_empty() {
            return None;
        }
        let from_authoritative = match (inner.ordinary.front(), inner.authoritative.front()) {
            (None, None) => return None,
            (Some(_), None) => false,
            (None, Some(_)) => true,
            (Some(ordinary), Some(authoritative)) => authoritative.seq < ordinary.seq,
        };
        let entry = if from_authoritative {
            inner.authoritative.pop_front()
        } else {
            inner.ordinary.pop_front()
        }?;
        inner.in_flight_entries = inner.in_flight_entries.saturating_add(1);
        Some(entry)
    }

    /// Says the pump has finished with the entry it took.
    pub fn finish(&self, entry: &Entry) {
        let mut inner = self.inner();
        inner.held = inner.held.saturating_sub(entry.cost);
        inner.in_flight_entries = inner.in_flight_entries.saturating_sub(1);
    }

    /// Returns true while the lane has lost something the pump has not yet applied.
    #[must_use]
    pub fn loss_pending(&self) -> bool {
        !self.inner().pending_loss.is_empty()
    }

    /// Waits until something may have been pushed, or a binding's silence or retry may be over.
    pub async fn idle(&self, at_most: Option<Duration>) {
        match at_most {
            Some(wait) => {
                let _elapsed = tokio::time::timeout(wait, self.wake.notified()).await;
            }
            None => self.wake.notified().await,
        }
    }

    /// Wakes the pump.
    pub fn nudge(&self) {
        self.wake.notify_one();
    }

    /// Takes what the lane has lost since this was last called.
    pub fn take_loss(&self) -> Option<LaneLoss> {
        let mut inner = self.inner();
        if inner.pending_loss.is_empty() {
            return None;
        }
        Some(std::mem::take(&mut inner.pending_loss))
    }

    /// Returns the lane's account of what it has lost, since it began.
    #[must_use]
    pub fn account(&self) -> Account {
        self.inner().account
    }

    /// Returns how many bytes the lane is counting against its bound.
    #[must_use]
    pub fn held_bytes(&self) -> u64 {
        self.inner().held
    }

    /// Returns how many entries are waiting, authoritative ones included.
    #[must_use]
    pub fn waiting(&self) -> usize {
        let inner = self.inner();
        inner.ordinary.len() + inner.authoritative.len()
    }

    // -- the views ----------------------------------------------------------------------------

    /// Says whether a binding may be offered anything.
    pub fn set_ready(&self, binding: BrokerBindingId, ready: bool) {
        let mut inner = self.inner();
        let next = inner.next_seq;
        let view = inner.views.entry(binding).or_default();
        view.ready = ready;
        view.silent_until = None;
        if ready {
            // A component made ready has been registered afresh, so it holds nothing it was offered
            // before, and nothing pushed before it is for it.
            view.private_content = false;
            view.silence = None;
            view.snapshot_retry = None;
            view.ready_from = next;
        }
        drop(inner);
        self.wake.notify_one();
    }

    /// Returns true when the binding may be offered something now.
    #[must_use]
    pub fn is_ready(&self, binding: BrokerBindingId) -> bool {
        self.inner()
            .views
            .get(&binding)
            .is_some_and(|view| view.ready)
    }

    /// Makes every binding not ready: the plugin runtime is gone.
    pub fn all_not_ready(&self) {
        for view in self.inner().views.values_mut() {
            view.ready = false;
            view.silent_until = None;
        }
    }

    /// Forgets a binding: its view, and the state held for it.
    pub fn forget(&self, binding: BrokerBindingId) {
        let mut inner = self.inner();
        inner.views.remove(&binding);
        drop_checkpoint(&mut inner, binding);
    }

    /// Forgets the view and the held state of every binding that is not in `wanted`: a binding that
    /// ended while the plugin runtime was lost is not unbound by anything else.
    pub fn forget_unwanted(&self, wanted: &std::collections::BTreeSet<BrokerBindingId>) {
        let mut inner = self.inner();
        let gone: Vec<BrokerBindingId> = inner
            .views
            .keys()
            .chain(inner.checkpoints.keys())
            .filter(|binding| !wanted.contains(binding))
            .copied()
            .collect();
        for binding in gone {
            inner.views.remove(&binding);
            drop_checkpoint(&mut inner, binding);
        }
    }

    /// Returns a copy of a binding's view.
    #[must_use]
    pub fn view(&self, binding: BrokerBindingId) -> Option<View> {
        self.inner().views.get(&binding).cloned()
    }

    /// Records a loss for a binding that is ready: the component has missed something and is owed a
    /// fresh snapshot. Returns the loss number.
    pub fn lose(&self, binding: BrokerBindingId, what: String) -> Option<u64> {
        let mut inner = self.inner();
        let view = inner.views.get_mut(&binding).filter(|view| view.ready)?;
        view.lost_seq = view.lost_seq.saturating_add(1);
        view.loss_note = Some(what);
        let seq = view.lost_seq;
        drop(inner);
        self.wake.notify_one();
        Some(seq)
    }

    /// Records a loss for a binding whether or not it is ready yet. A restore uses this: the
    /// observations between a checkpoint and the registration that follows it were not replayed.
    pub fn lose_unready(&self, binding: BrokerBindingId, what: String) -> u64 {
        let mut inner = self.inner();
        let view = inner.views.entry(binding).or_default();
        view.lost_seq = view.lost_seq.saturating_add(1);
        view.loss_note = Some(what);
        view.lost_seq
    }

    /// Records that a snapshot requested for loss number `through` has been answered, and returns
    /// what the component last missed, for the note a person reads.
    pub fn snapshot_answered(&self, binding: BrokerBindingId, through: u64) -> Option<String> {
        let mut inner = self.inner();
        let view = inner.views.get_mut(&binding)?;
        view.snapshot_through = view.snapshot_through.max(through);
        view.snapshot_retry = None;
        view.loss_note.clone()
    }

    /// Records that a snapshot could not be asked for, and leaves the binding alone for a while
    /// that grows with each failure.
    pub fn snapshot_failed(&self, binding: BrokerBindingId, now: Instant) {
        let mut inner = self.inner();
        if let Some(view) = inner.views.get_mut(&binding) {
            let wait = view.snapshot_retry.unwrap_or(SNAPSHOT_RETRY);
            view.silent_until = Some(now + wait);
            view.snapshot_retry = Some(wait.saturating_mul(2).min(LONGEST_SNAPSHOT_RETRY));
        }
    }

    /// Records that a call to the plugin runtime for this binding ran out its deadline, and
    /// passes the binding over for a while that grows with each failure.
    pub fn go_silent(&self, binding: BrokerBindingId, now: Instant) {
        let mut inner = self.inner();
        if let Some(view) = inner.views.get_mut(&binding) {
            let wait = view.silence.unwrap_or(SILENCE);
            view.silent_until = Some(now + wait);
            view.silence = Some(wait.saturating_mul(2).min(LONGEST_SILENCE));
        }
    }

    /// Records that something was offered to the binding, which is one more thing its state holds
    /// that has not been taken. `made_in_privacy` says whether privacy mode was on when the worker
    /// had it.
    pub fn offered(&self, binding: BrokerBindingId, now: Instant, made_in_privacy: bool) {
        let mut inner = self.inner();
        let Some(view) = inner.views.get_mut(&binding) else {
            return;
        };
        let first = view.offered_since_checkpoint == 0;
        view.offered_since_checkpoint = view.offered_since_checkpoint.saturating_add(1);
        view.last_offer = Some(now);
        if made_in_privacy || self.private.load(Ordering::Acquire) {
            view.private_content = true;
        }
        drop(inner);
        if first {
            self.checkpoint_wake.notify_one();
        }
    }

    /// Waits until a binding that had been offered nothing since its state was last asked for is
    /// offered something, which is when the time its state falls due changes.
    pub async fn until_state_is_owed(&self) {
        self.checkpoint_wake.notified().await;
    }

    /// Records that a call to the binding was answered, which ends a silence.
    pub fn answered(&self, binding: BrokerBindingId) {
        let mut inner = self.inner();
        if let Some(view) = inner.views.get_mut(&binding) {
            view.silence = None;
        }
    }

    /// Returns the bindings that are ready and owed a snapshot now, with the loss number each is
    /// owed it for.
    #[must_use]
    pub fn owing(&self, now: Instant) -> Vec<(BrokerBindingId, u64)> {
        self.inner()
            .views
            .iter()
            .filter(|(_, view)| view.ready && !view.is_silent(now))
            .filter_map(|(binding, view)| view.owes().map(|seq| (*binding, seq)))
            .collect()
    }

    /// Returns how long until the soonest ready binding that owes a snapshot, or is passed over for
    /// a time, may be asked again, where any is.
    #[must_use]
    pub fn next_due(&self, now: Instant) -> Option<Duration> {
        self.inner()
            .views
            .values()
            .filter(|view| view.ready)
            .filter_map(|view| view.silent_until)
            .filter(|until| *until > now)
            .map(|until| until.saturating_duration_since(now))
            .min()
    }

    // -- checkpoints --------------------------------------------------------------------------

    /// Returns the ready bindings whose state is due to be taken: events have been offered since the
    /// last attempt, and the binding has been quiet for [`QUIET_BEFORE_CHECKPOINT`] or the last
    /// attempt is [`CHECKPOINT_EVERY`] old.
    #[must_use]
    pub fn checkpoint_due(&self, now: Instant) -> Vec<BrokerBindingId> {
        if self.is_private() {
            return Vec::new();
        }
        self.inner()
            .views
            .iter()
            .filter(|(_, view)| view.ready && view.offered_since_checkpoint > 0)
            .filter(|(_, view)| !view.private_content)
            .filter(|(_, view)| {
                let quiet = view
                    .last_offer
                    .is_none_or(|at| now.saturating_duration_since(at) >= QUIET_BEFORE_CHECKPOINT);
                let old = view
                    .last_checkpoint_attempt
                    .is_none_or(|at| now.saturating_duration_since(at) >= CHECKPOINT_EVERY);
                quiet || old
            })
            .map(|(binding, _)| *binding)
            .collect()
    }

    /// Returns how long until some ready binding that has been offered events is due a checkpoint,
    /// where one is.
    #[must_use]
    pub fn next_checkpoint(&self, now: Instant) -> Option<Duration> {
        if self.is_private() {
            return None;
        }
        self.inner()
            .views
            .values()
            .filter(|view| view.ready && view.offered_since_checkpoint > 0)
            .filter(|view| !view.private_content)
            .map(|view| {
                let quiet_at = view.last_offer.map(|at| at + QUIET_BEFORE_CHECKPOINT);
                let old_at = view.last_checkpoint_attempt.map(|at| at + CHECKPOINT_EVERY);
                let due = match (quiet_at, old_at) {
                    (Some(quiet), Some(old)) => quiet.min(old),
                    (Some(at), None) | (None, Some(at)) => at,
                    (None, None) => now,
                };
                due.saturating_duration_since(now)
            })
            .min()
    }

    /// Records that this binding's state was asked for, whatever came of it.
    pub fn checkpoint_attempted(&self, binding: BrokerBindingId, now: Instant) {
        let mut inner = self.inner();
        if let Some(view) = inner.views.get_mut(&binding) {
            view.offered_since_checkpoint = 0;
            view.last_checkpoint_attempt = Some(now);
        }
    }

    /// Returns the number privacy mode's changes have reached: a state asked for under one number is
    /// held only under the same one.
    #[must_use]
    pub fn privacy_epoch(&self) -> u64 {
        self.privacy_epoch.load(Ordering::Acquire)
    }

    /// Holds a binding's state, asked for when privacy mode stood at `epoch`. Nothing is held under
    /// privacy mode, nothing asked for before a change of it, and nothing from a component that was
    /// offered something made in it; the oldest is dropped rather than the total passing
    /// [`CHECKPOINT_BYTES`].
    pub fn hold(&self, binding: BrokerBindingId, held: Held, epoch: u64) {
        let size = held.state.len() as u64;
        if size > CHECKPOINT_BYTES {
            return;
        }
        let mut inner = self.inner();
        // Read under the lock the fence takes, so that a fence is either before this or after it.
        if self.is_private()
            || self.privacy_epoch() != epoch
            || inner
                .views
                .get(&binding)
                .is_none_or(|view| view.private_content)
        {
            return;
        }
        drop_checkpoint(&mut inner, binding);
        while inner.checkpoint_bytes.saturating_add(size) > CHECKPOINT_BYTES {
            let Some(oldest) = inner.checkpoint_order.front().copied() else {
                break;
            };
            drop_checkpoint(&mut inner, oldest);
        }
        inner.checkpoint_bytes = inner.checkpoint_bytes.saturating_add(size);
        inner.checkpoint_order.push_back(binding);
        inner.checkpoints.insert(binding, held);
    }

    /// Takes the state held for a binding, if it was taken under this package and this
    /// generation.
    pub fn take_held(
        &self,
        binding: BrokerBindingId,
        package_digest: kr_protocol::scalars::Digest256,
        generation: u64,
    ) -> Option<Held> {
        let mut inner = self.inner();
        let matches = inner.checkpoints.get(&binding).is_some_and(|held| {
            held.package_digest == package_digest && held.generation == generation
        });
        if !matches {
            // Held under another package or another execution: it is not this binding's to
            // restore, and keeping it would only keep content nothing will use.
            drop_checkpoint(&mut inner, binding);
            return None;
        }
        let held = inner.checkpoints.get(&binding).cloned();
        drop_checkpoint(&mut inner, binding);
        held
    }

    /// Returns how many checkpoints are held, and their bytes.
    #[must_use]
    pub fn held_checkpoints(&self) -> (usize, u64) {
        let inner = self.inner();
        (inner.checkpoints.len(), inner.checkpoint_bytes)
    }

    /// Returns the state held for a binding, without taking it. For this host's own tests.
    #[cfg(feature = "testing")]
    #[must_use]
    pub fn held_state(&self, binding: BrokerBindingId) -> Option<Vec<u8>> {
        self.inner()
            .checkpoints
            .get(&binding)
            .map(|held| held.state.clone())
    }

    // -- privacy mode -------------------------------------------------------------------------

    /// Says whether privacy mode is on. Observation for live use goes on under it; what does not is
    /// anything derived from it that would outlive it: while it is on no checkpoint is taken or
    /// held, the ones held are dropped when it is turned on ([`Self::fence`]), and a component that
    /// was offered something while it was on is not asked for its state again, since the state may
    /// hold what it was offered, until it starts again.
    pub fn set_private(&self, private: bool) {
        // Under the lock a fence and a hold take, so that neither sees half of the change.
        let _inner = self.inner();
        if self.private.swap(private, Ordering::AcqRel) != private {
            self.privacy_epoch.fetch_add(1, Ordering::AcqRel);
        }
        if !private {
            self.checkpoint_wake.notify_one();
        }
    }

    /// Returns true while privacy mode is on.
    #[must_use]
    pub fn is_private(&self) -> bool {
        self.private.load(Ordering::Acquire)
    }

    /// Drops every checkpoint held, which is everything this lane holds that is derived from what a
    /// component was offered: the entries waiting are live observation, bounded in time by the
    /// pump and in size by the lane. Returns the checkpoints dropped and their bytes.
    pub fn fence(&self) -> Fenced {
        let mut inner = self.inner();
        self.privacy_epoch.fetch_add(1, Ordering::AcqRel);
        let records = inner.checkpoints.len();
        let bytes = inner.checkpoint_bytes;
        inner.checkpoints.clear();
        inner.checkpoint_order.clear();
        inner.checkpoint_bytes = 0;
        Fenced {
            checkpoints: records as u64,
            checkpoint_bytes: bytes,
        }
    }

    /// Returns how many entries the pump has taken and not finished with.
    #[must_use]
    pub fn in_flight(&self) -> u64 {
        self.inner().in_flight_entries
    }

    // -- the hold ------------------------------------------------------------------------------

    /// Holds the pump: until the returned hold is released it takes nothing off the lane. For this
    /// host's own tests.
    #[cfg(feature = "testing")]
    pub fn hold_pump(self: &Arc<Self>) -> PumpHold {
        let state = Arc::new(HoldState::default());
        *self
            .hold
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Arc::clone(&state));
        // The pump may be waiting for something to be pushed; it looks again and parks.
        self.nudge();
        PumpHold {
            state,
            lane: Arc::clone(self),
        }
    }

    /// Returns true while a test holds the pump, and records that the pump has reached the hold.
    #[cfg(feature = "testing")]
    pub fn held_by_a_test(&self) -> bool {
        let mut slot = self
            .hold
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(state) = slot.as_ref() else {
            return false;
        };
        if state.released.load(Ordering::Acquire) {
            *slot = None;
            return false;
        }
        state.parked.store(true, Ordering::Release);
        true
    }
}

/// The observation lane's part in privacy mode.
///
/// Observation for live use goes on under privacy mode, and nothing derived from it outlives it.
/// Turning privacy mode on stops any more of a component's state being taken and drops the state
/// held for each binding, so a component restored after that starts again from the live point; while
/// it is on, a component is never asked for its state ([`ObservationLane::checkpoint_due`]) and
/// nothing is held ([`ObservationLane::hold`]). A component that was offered something while it was
/// on keeps no state afterwards either, until it starts again, since what it holds may be what it
/// was offered.
#[derive(Clone, Debug)]
pub struct ObservationPrivacy {
    lane: Arc<ObservationLane>,
}

impl ObservationPrivacy {
    /// Builds the subsystem over a session's lane.
    #[must_use]
    pub const fn over(lane: Arc<ObservationLane>) -> Self {
        Self { lane }
    }
}

impl crate::privacy::PrivacySubsystem for ObservationPrivacy {
    fn name(&self) -> &'static str {
        "plugin_observation"
    }

    fn fence(
        &mut self,
        _generation: crate::privacy::PrivacyGeneration,
    ) -> Result<crate::privacy::Fenced, crate::privacy::Unavailable> {
        self.lane.set_private(true);
        Ok(crate::privacy::Fenced {
            queues: 1,
            items: 0,
        })
    }

    fn cancel_undispatched(
        &mut self,
        _generation: crate::privacy::PrivacyGeneration,
    ) -> Result<crate::privacy::Cancelled, crate::privacy::Unavailable> {
        Ok(crate::privacy::Cancelled::default())
    }

    fn remove_retained(
        &mut self,
        _generation: crate::privacy::PrivacyGeneration,
    ) -> Result<crate::privacy::Removed, crate::privacy::Unavailable> {
        let dropped = self.lane.fence();
        Ok(crate::privacy::Removed {
            bytes: dropped.checkpoint_bytes,
            records: dropped.checkpoints,
        })
    }

    fn outstanding(&self) -> Result<u64, crate::privacy::Unavailable> {
        // A checkpoint being taken when privacy mode is turned on is refused when it comes back:
        // nothing is held while it is on. So there is nothing in flight to wait for.
        Ok(0)
    }
}

/// What turning privacy mode on dropped from the lane.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Fenced {
    /// Checkpoints that were held.
    pub checkpoints: u64,
    /// The bytes those checkpoints held.
    pub checkpoint_bytes: u64,
}

fn drop_checkpoint(inner: &mut Inner, binding: BrokerBindingId) {
    if let Some(held) = inner.checkpoints.remove(&binding) {
        inner.checkpoint_bytes = inner
            .checkpoint_bytes
            .saturating_sub(held.state.len() as u64);
    }
    inner.checkpoint_order.retain(|queued| *queued != binding);
}

/// What is known of an upstream frame under the broker's lock, which is all the lock is needed
/// for: the frame itself is copied after it is dropped.
#[derive(Clone, Debug)]
pub(super) struct NativeTap {
    instance: ApplicationInstanceId,
    package: PackageIdentity,
    handle: Option<SourceEventHandle>,
    request_id: Option<String>,
}

impl super::BrokerState {
    /// Decides whether an upstream frame the broker has just recorded may be offered to a component,
    /// and under which names.
    ///
    /// Only a frame the connection's table lists, and does not class as carrying a credential or
    /// configuration, is offered: an unlisted method is presumed a mutation and not a credential, so
    /// it may carry one, and nothing a component is offered may. A frame goes with the package whose
    /// table read the connection, and a frame the upstream is waiting on goes under the handle the
    /// broker retained it under.
    pub(super) fn observation_tap(
        &self,
        connection: kr_protocol::ids::GatewayConnectionId,
        forwarded: &super::gateway::Forwarded,
        resource: Option<&kr_protocol::gateway::PendingResource>,
    ) -> Option<NativeTap> {
        if !forwarded.classification.declared || forwarded.classification.carries_credentials() {
            return None;
        }
        let instance = self.gateway.instance_of(connection)?;
        let package = self.connection_package(connection)?;
        let (handle, request_id) = match (&forwarded.request, forwarded.expects_response) {
            (Some(request), true) => (
                resource
                    .and_then(|resource| self.arbitration.source_of(resource.resource_id))
                    .cloned(),
                Some(request.upstream.as_str().to_owned()),
            ),
            _ => (None, None),
        };
        Some(NativeTap {
            instance,
            package,
            handle,
            request_id,
        })
    }
}

impl Broker {
    /// Offers an upstream frame to the components that may observe it. Called with the broker's lock
    /// dropped, and never waits: it copies the frame and pushes it onto the lane.
    pub(super) fn offer_upstream(
        &self,
        tap: Option<NativeTap>,
        frame: &[u8],
        now: kr_protocol::scalars::TimestampMs,
    ) {
        let Some(tap) = tap else {
            return;
        };
        let _pushed = self.observation.push_native(
            NativeFrame {
                instance: tap.instance,
                package: tap.package,
                handle: tap.handle,
                request_id: tap.request_id,
                bytes: Arc::from(frame),
            },
            now.get(),
        );
    }

    /// Returns the lane the worker's observations wait in. The pseudo-terminal's output and the
    /// gateway's frames are pushed onto it; the plugin runtime's link takes them off.
    #[must_use]
    pub fn observation(&self) -> Arc<ObservationLane> {
        Arc::clone(&self.observation)
    }

    /// Returns the bindings an entry may be offered to, read now.
    ///
    /// A binding is offered an entry only when its package ships a component the link has reported
    /// registered, it holds the `Observation` grant and the stream the entry needs, and it is neither
    /// rich-disabled nor ending. An upstream frame goes only to a binding of the instance whose
    /// package is the one whose table read the connection.
    #[must_use]
    pub fn observing(&self, audience: Audience<'_>) -> Vec<BrokerBindingId> {
        let state = self.state();
        state
            .bindings
            .values()
            .filter(|binding| binding.rich_disabled.is_none() && !binding.ending)
            .filter(|binding| {
                binding
                    .grants
                    .holds(kr_protocol::broker::BrokerGrant::Observation)
            })
            .filter(|binding| {
                binding
                    .component
                    .as_ref()
                    .is_some_and(|component| component.refusal.is_none())
            })
            .filter(|binding| {
                matches!(
                    state.component_states.get(&binding.binding_id),
                    Some((kr_protocol::admission::ComponentState::Registered, _))
                )
            })
            .filter(|binding| match audience {
                Audience::Terminal => binding.streams.terminal,
                Audience::Native { instance, package } => {
                    binding.streams.semantic
                        && binding.application_instance_id == instance
                        && package.is_none_or(|package| binding.package() == *package)
                }
            })
            .map(|binding| binding.binding_id)
            .collect()
    }
}
