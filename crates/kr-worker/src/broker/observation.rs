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
//! A loss is handed to the pump with the first entry that is newer than it, so that the pump applies
//! the loss, and takes the snapshot it owes, before it offers that entry and not after. The lane
//! loses ordinary entries before it loses a request, and refuses an entry larger than itself
//! whatever waits, so the order of losses and entries is one the pump cannot assume: something lost
//! after a request was pushed is newer than the request. Each waiting entry therefore carries what
//! was lost between it and the entry before it, an entry pushed out for room passes what it
//! carried, and itself, to the entry after it, and what is lost after the newest waiting entry
//! waits for the next entry, or for the pump to find none. That is one record for each waiting
//! entry, which the lane's own bound bounds.
//!
//! # The views
//!
//! Beside the entries the lane keeps one [`View`] for each binding, shared by the pump and the link.
//! A view says whether the binding may be offered anything yet, and what its component has missed:
//! each loss is numbered, a snapshot is requested for the number current when it is asked for and
//! discharges that number only, so a loss that arrives while a snapshot runs asks for another.

use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use kr_plugin_sdk::limits::OBSERVATION_QUEUE_BYTES;
use kr_protocol::ids::{
    ApplicationInstanceId, BrokerBindingId, PendingResourceId, SourceEventHandle, SourceGeneration,
};
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
    /// What the broker recorded the request as, where the frame is a request it recorded.
    pub recorded: Option<Recorded>,
    /// The frame's bytes, shared and never changed.
    pub bytes: Arc<[u8]>,
}

/// What the broker recorded a request as: where, under which identifier, and at which source
/// generation.
#[derive(Clone, Copy, Debug)]
pub struct Recorded {
    /// The place the broker recorded the request in ([`super::arbitration::Pending::recorded`]). A
    /// producer pushes the frame after the broker's lock is dropped, so the order of pushes is not
    /// the order of records: this is.
    pub place: u64,
    /// The request, which the broker is asked about again before the frame is offered.
    pub resource_id: PendingResourceId,
    /// The source generation the request was recorded under.
    pub generation: SourceGeneration,
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
    /// What the lane lost between the entry before this one and this one: older than it, and handed
    /// over with it.
    loss_before: LaneLoss,
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

/// What a binding's component did not see while the plugin runtime was away and it was started
/// again, counted from the moment the runtime was lost until its baseline has been given. Bytes are
/// the payload bytes, without the lane's own cost for an entry.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Outage {
    /// Upstream frames the worker took off the lane and passed over. A request is not one: the
    /// baseline gives it, if it is still pending.
    pub passed: Tally,
    /// Spans of terminal output the worker took off the lane and passed over.
    pub terminal: Tally,
    /// Observations the lane dropped for want of room.
    pub dropped: Tally,
    /// Pending requests queued to be decoded again when the component was registered.
    pub decode_queued: u64,
    /// Pending requests that could not be queued to be decoded again.
    pub decode_full: u64,
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

    /// Counts one lost entry.
    fn add(&mut self, entry: &Entry) {
        let bytes = entry.cost;
        match &entry.source {
            Source::Terminal(_) => self.terminal.add(bytes),
            Source::Native(frame) => {
                let at = self.native.iter().position(|loss| {
                    loss.instance == frame.instance && loss.package == frame.package
                });
                let loss = if let Some(at) = at {
                    &mut self.native[at]
                } else {
                    self.native.push(NativeLoss {
                        instance: frame.instance,
                        package: frame.package.clone(),
                        tally: Tally::default(),
                    });
                    let last = self.native.len() - 1;
                    &mut self.native[last]
                };
                loss.tally.add(bytes);
            }
        }
    }

    /// Counts everything `other` counts.
    fn absorb(&mut self, other: Self) {
        self.terminal.events = self.terminal.events.saturating_add(other.terminal.events);
        self.terminal.bytes = self.terminal.bytes.saturating_add(other.terminal.bytes);
        for theirs in other.native {
            let at = self.native.iter().position(|loss| {
                loss.instance == theirs.instance && loss.package == theirs.package
            });
            if let Some(at) = at {
                let tally = &mut self.native[at].tally;
                tally.events = tally.events.saturating_add(theirs.tally.events);
                tally.bytes = tally.bytes.saturating_add(theirs.tally.bytes);
            } else {
                self.native.push(theirs);
            }
        }
    }
}

/// What the pump took off the lane in one step.
#[derive(Debug)]
pub struct Taken {
    /// What the lane lost that is older than the entry, or all that it lost where no entry waits, to
    /// be applied before the entry is offered.
    pub loss: Option<LaneLoss>,
    /// The oldest entry, where the lane held one.
    pub entry: Option<Entry>,
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
    /// Whether the binding may be offered anything: registered, and made ready by the link. A
    /// binding may be ready while it owes a snapshot, and is offered nothing until the snapshot has
    /// been taken.
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
    /// What the component last missed, in the words a person is told.
    pub loss_note: Option<String>,
    /// The first entry the binding may be offered: those pushed before it was made ready are older
    /// than its view.
    pub ready_from: u64,
    /// Whether the component that started again is still owed the requests the broker holds for it
    /// (its baseline). Until it has them the binding is offered nothing and what is taken off the
    /// lane for it is counted in [`Self::outage`].
    pub rebuild_owed: bool,
    /// The place in the broker's recording at which the baseline was read
    /// ([`super::arbitration::Arbitration::next_recorded`]): a request recorded before it was
    /// given with the baseline or left out of it, and is never offered again.
    pub recorded_from: u64,
    /// The connection to the plugin runtime the binding was last made ready under.
    pub connection: u64,
    /// What the component has not seen since the plugin runtime was lost, until its baseline is
    /// given.
    pub outage: Outage,
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

#[derive(Debug, Default)]
struct Inner {
    ordinary: VecDeque<Entry>,
    authoritative: VecDeque<Entry>,
    held: u64,
    in_flight_entries: u64,
    next_seq: u64,
    /// What the lane lost after the newest entry that waits: newer than every entry that waits, so
    /// it goes with the next entry pushed, or is handed over alone where none waits.
    tail_loss: LaneLoss,
    account: Account,
    views: BTreeMap<BrokerBindingId, View>,
    /// Whether privacy mode has been on since the link made the connection it now holds.
    words_tainted: bool,
    /// How many connections to the plugin runtime the link has made: the one it holds now is this
    /// one. A component is registered on a connection and holds only what it was handed on it.
    connection: u64,
    /// The bindings whose component was handed something made in privacy mode, or while it stood,
    /// and the connection it was handed on. A mark belongs to the binding and the connection and not to a view: a binding that is
    /// unbound and registered again on the same connection can be reached by a call that was
    /// started before it was unbound, and that call finds the mark.
    marks: BTreeMap<BrokerBindingId, u64>,
}

impl Inner {
    /// Counts an entry that was never taken as lost: refused, or an ordinary entry that does not
    /// fit. It is the newest thing the lane has seen, so it is newer than everything that waits.
    fn lose_new(&mut self, entry: &Entry, refused: bool) {
        self.tail_loss.add(entry);
        if refused {
            self.account.refused.add(entry.cost);
        } else {
            self.account.evicted.add(entry.cost);
        }
    }

    /// Counts an entry that was waiting as lost, pushed out for room. It, and what had been lost
    /// before it, go with the first entry newer than it, or wait for one: that entry may be a
    /// request, which the lane keeps while it loses ordinary entries.
    fn lose_waiting(&mut self, mut lost: Entry) {
        let mut carried = std::mem::take(&mut lost.loss_before);
        carried.add(&lost);
        self.account.evicted.add(lost.cost);
        let request = self
            .authoritative
            .partition_point(|entry| entry.seq < lost.seq);
        let request_is_next = self.authoritative.get(request).is_some_and(|waiting| {
            self.ordinary
                .front()
                .is_none_or(|ordinary| waiting.seq < ordinary.seq)
        });
        let next = if request_is_next {
            self.authoritative.get_mut(request)
        } else {
            self.ordinary.front_mut()
        };
        match next {
            Some(next) => next.loss_before.absorb(carried),
            None => self.tail_loss.absorb(carried),
        }
    }
}

/// Where privacy mode stood at one moment: whether it was on, and how many times it had been turned
/// on or off by then ([`ObservationLane::privacy_mark`]).
///
/// A connection a hook made is marked when it is admitted. What the hook reports is read later,
/// and it is recorded as history only if privacy mode was off at the mark and has not changed
/// since ([`ObservationLane::unchanged_since`]): a report whose connection was admitted in
/// privacy mode, or before privacy mode was last turned on or off, is not what privacy mode lets
/// a worker keep. The default is where a lane that has never changed stands, off.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PrivacyMark {
    private: bool,
    epoch: u64,
}

/// The queue of what the worker has to offer, and the views of what each binding has missed.
#[derive(Debug)]
pub struct ObservationLane {
    inner: Mutex<Inner>,
    wake: tokio::sync::Notify,
    /// Whether any binding takes upstream frames. A producer that finds it false pushes nothing.
    native_wanted: AtomicBool,
    /// Whether any binding takes terminal output.
    terminal_wanted: AtomicBool,
    /// Whether privacy mode is on.
    private: AtomicBool,
    /// Advances each time privacy mode is turned on or off, so that what was taken in before a
    /// change can be told from what was taken in after it ([`Self::privacy_mark`]).
    privacy_epoch: AtomicU64,
    /// Wakes the task that tells the plugin runtime whether privacy mode is on when that changes.
    privacy_wake: tokio::sync::Notify,
    /// What the plugin runtime was last told and acknowledged on the connection the link holds:
    /// nought for nothing, one for off, two for on. For this host's own tests: nothing in the
    /// product reads it.
    #[cfg(feature = "testing")]
    runtime_told: std::sync::atomic::AtomicU8,
    /// The highest document number the link has read from the plugin runtime for each binding on
    /// the connection it holds, for this host's own tests: the worker reads a document and drops
    /// it, so nothing else says whether one arrived.
    #[cfg(feature = "testing")]
    documents_read: Mutex<BTreeMap<BrokerBindingId, u64>>,
    #[cfg(feature = "testing")]
    hold: Mutex<Option<Arc<HoldState>>>,
    #[cfg(feature = "testing")]
    pause: Mutex<Option<Arc<PauseState>>>,
}

/// The two halves of a hold on the pump, for this host's own tests: a signal that the pump has
/// stopped at the hold, and the release.
#[cfg(feature = "testing")]
#[derive(Debug, Default)]
struct HoldState {
    parked: AtomicBool,
    released: AtomicBool,
}

/// Where a test stops the pump in the middle of one of its calls. For this host's own tests.
#[cfg(feature = "testing")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pause {
    /// A baseline that has given this many requests, before it hands over the next or ends.
    BaselineGiven(u64),
    /// An entry that has been handed to this binding, before it is offered to the next one.
    OfferedTo(BrokerBindingId),
}

/// A pause a test set and the two halves of its hold: a signal that the pump has stopped there, and
/// the release.
#[cfg(feature = "testing")]
#[derive(Debug)]
struct PauseState {
    at: Pause,
    parked: AtomicBool,
    released: AtomicBool,
}

/// A hold on the pump at a [`Pause`]: the pump stops there until the hold is released. For this
/// host's own tests, the way a hold on the pump is.
#[cfg(feature = "testing")]
#[derive(Debug)]
pub struct PauseHold {
    state: Arc<PauseState>,
}

#[cfg(feature = "testing")]
impl PauseHold {
    /// Returns true once the pump has reached the pause and is waiting at it.
    #[must_use]
    pub fn parked(&self) -> bool {
        self.state.parked.load(Ordering::Acquire)
    }

    /// Lets the pump go on.
    pub fn release(&self) {
        self.state.released.store(true, Ordering::Release);
    }
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
            privacy_wake: tokio::sync::Notify::new(),
            #[cfg(feature = "testing")]
            runtime_told: std::sync::atomic::AtomicU8::new(0),
            #[cfg(feature = "testing")]
            documents_read: Mutex::new(BTreeMap::new()),
            #[cfg(feature = "testing")]
            hold: Mutex::new(None),
            #[cfg(feature = "testing")]
            pause: Mutex::new(None),
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
        let mut entry = Entry {
            seq,
            source,
            at_ms,
            private: self.private.load(Ordering::Acquire),
            cost,
            loss_before: LaneLoss::default(),
        };
        if cost > OBSERVATION_QUEUE_BYTES {
            inner.lose_new(&entry, true);
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
            inner.lose_waiting(oldest);
        }
        if inner.held.saturating_add(cost) > OBSERVATION_QUEUE_BYTES {
            // Only authoritative entries are left (or the pump's own), and none is evicted.
            // An ordinary entry that does not fit is lost; an authoritative one is refused. Both
            // are counted, and the broker's own record of the request is what stays.
            let refused = entry.is_authoritative();
            inner.lose_new(&entry, refused);
            drop(inner);
            self.wake.notify_one();
            return Pushed::Refused;
        }
        // What was lost since the newest entry that waits is older than this one.
        entry.loss_before = std::mem::take(&mut inner.tail_loss);
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

    /// Takes the oldest entry, in the order it was pushed, together with the losses older than it.
    /// The lane goes on counting the entry against its bound until [`Self::finish`].
    ///
    /// The loss and the entry are taken under one lock, so the loss is the pump's to apply before it
    /// offers the entry. Each loss goes with the first entry newer than it. The lane loses ordinary
    /// entries before it loses a request the upstream is waiting on, and refuses an entry larger
    /// than itself whatever waits, so something lost after a request was pushed is newer than the
    /// request: it is held back until the request has been taken, and comes with a later entry, or
    /// alone where none waits. What is lost after this call is newer than the entry taken.
    pub fn take(&self) -> Taken {
        let mut inner = self.inner();
        let from_request = match (inner.ordinary.front(), inner.authoritative.front()) {
            (None, None) => {
                let loss = std::mem::take(&mut inner.tail_loss);
                return Taken {
                    loss: (!loss.is_empty()).then_some(loss),
                    entry: None,
                };
            }
            (Some(_), None) => false,
            (None, Some(_)) => true,
            (Some(ordinary), Some(request)) => request.seq < ordinary.seq,
        };
        let mut entry = if from_request {
            inner.authoritative.pop_front()
        } else {
            inner.ordinary.pop_front()
        };
        let loss = entry
            .as_mut()
            .map(|entry| std::mem::take(&mut entry.loss_before))
            .filter(|loss| !loss.is_empty());
        if entry.is_some() {
            inner.in_flight_entries = inner.in_flight_entries.saturating_add(1);
        }
        Taken { loss, entry }
    }

    /// Says the pump has finished with the entry it took.
    pub fn finish(&self, entry: &Entry) {
        let mut inner = self.inner();
        inner.held = inner.held.saturating_sub(entry.cost);
        inner.in_flight_entries = inner.in_flight_entries.saturating_sub(1);
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

    /// Returns the connection to the plugin runtime that the link holds now, which a registration
    /// made on it is made ready under ([`Self::set_ready`]).
    #[must_use]
    pub fn connection(&self) -> u64 {
        self.inner().connection
    }

    /// Makes a binding ready to be offered anything, its component registered afresh on
    /// `connection`, which [`Self::connection`] returned before the registration began.
    ///
    /// A component registered on a connection holds only what it was handed on it, and a component
    /// handed something made in privacy mode is marked when it is handed it ([`Self::expose`]),
    /// before the registration has ended or after. So a mark made on an earlier connection goes,
    /// since the component it described went with that connection, and a mark made on this one
    /// stays, whenever in the registration it was made: the component may already hold what it was
    /// handed.
    pub fn set_ready(&self, binding: BrokerBindingId, connection: u64) {
        let mut inner = self.inner();
        let next = inner.next_seq;
        // A component registered afresh on a later connection holds nothing it was handed on an
        // earlier one.
        if inner
            .marks
            .get(&binding)
            .is_some_and(|made| *made < connection)
        {
            inner.marks.remove(&binding);
        }
        let view = inner.views.entry(binding).or_default();
        view.ready = true;
        view.connection = connection;
        view.silent_until = None;
        view.silence = None;
        view.snapshot_retry = None;
        view.ready_from = next;
        drop(inner);
        self.wake.notify_one();
    }

    /// Returns true when the binding has been ready before, so that a registration of it now is a
    /// component that starts again and not a first one. A view is made when a binding first becomes
    /// ready and kept, ready or not, until the lane forgets it ([`Self::forget`]).
    #[must_use]
    pub fn has_been_ready(&self, binding: BrokerBindingId) -> bool {
        self.inner().views.contains_key(&binding)
    }

    /// Makes a binding whose component started again ready, owed what the broker holds for it.
    ///
    /// The component holds nothing, so what the view says it has missed is not owed a snapshot: the
    /// loss and its note are cleared and the numbers met, and what is taken off the lane from now
    /// until the baseline is given is counted in the outage, not as a loss. The entries pushed
    /// before this call are older than the component's view and are passed over
    /// ([`Self::count_passed`]); the first entry at or after it waits for the baseline
    /// ([`Self::rebuilds_due`]). The outage the view holds is kept: it began when the runtime was
    /// lost. `decode_queued` and `decode_full` are how many pending requests were queued to be
    /// decoded again for the component, and how many could not be queued.
    pub fn set_ready_for_rebuild(
        &self,
        binding: BrokerBindingId,
        connection: u64,
        decode_queued: u64,
        decode_full: u64,
    ) {
        let mut inner = self.inner();
        if inner
            .marks
            .get(&binding)
            .is_some_and(|made| *made < connection)
        {
            inner.marks.remove(&binding);
        }
        let next = inner.next_seq;
        let view = inner.views.entry(binding).or_default();
        view.ready = true;
        view.rebuild_owed = true;
        view.connection = connection;
        view.silent_until = None;
        view.silence = None;
        view.snapshot_retry = None;
        view.ready_from = next;
        view.snapshot_through = view.lost_seq;
        view.loss_note = None;
        view.outage.decode_queued = decode_queued;
        view.outage.decode_full = decode_full;
        drop(inner);
        self.wake.notify_one();
    }

    /// Counts an entry the pump took off the lane for a binding whose component was not given it
    /// because the plugin runtime was away, or because its baseline is still owed. Returns true when
    /// it was counted. A request is not counted: the baseline gives it if it is still pending.
    pub fn count_passed(&self, binding: BrokerBindingId, entry: &Entry) -> bool {
        let is_request = entry.is_authoritative();
        if is_request {
            return false;
        }
        let mut inner = self.inner();
        let Some(view) = inner
            .views
            .get_mut(&binding)
            .filter(|view| !view.ready || view.rebuild_owed)
        else {
            return false;
        };
        let payload = entry.cost.saturating_sub(ENTRY_OVERHEAD_BYTES);
        match entry.source {
            Source::Native(_) => view.outage.passed.add(payload),
            Source::Terminal(_) => view.outage.terminal.add(payload),
        }
        true
    }

    /// Counts what the lane dropped for a binding whose component was not given it because the
    /// plugin runtime was away, or because its baseline is still owed. Returns true when it was
    /// counted, and false when the binding is to be told of it as a loss.
    pub fn count_dropped(&self, binding: BrokerBindingId, lost: Tally) -> bool {
        let mut inner = self.inner();
        let Some(view) = inner
            .views
            .get_mut(&binding)
            .filter(|view| !view.ready || view.rebuild_owed)
        else {
            return false;
        };
        let dropped = &mut view.outage.dropped;
        dropped.events = dropped.events.saturating_add(lost.events);
        dropped.bytes = dropped.bytes.saturating_add(
            lost.bytes
                .saturating_sub(lost.events.saturating_mul(ENTRY_OVERHEAD_BYTES)),
        );
        true
    }

    /// Returns the bindings that are ready, owed their baseline and not passed over for a while, each
    /// with the connection its registration was made on, when the pump holds `entry` (the sequence
    /// number of the entry it took, where it took one): a baseline is read only after every entry
    /// older than the component's view has been taken and counted, and before the first entry at or
    /// after it is offered.
    #[must_use]
    pub fn rebuilds_due(&self, entry: Option<u64>, now: Instant) -> Vec<(BrokerBindingId, u64)> {
        self.inner()
            .views
            .iter()
            .filter(|(_, view)| view.ready && view.rebuild_owed && !view.is_silent(now))
            .filter(|(_, view)| entry.is_none_or(|seq| seq >= view.ready_from))
            .map(|(binding, view)| (*binding, view.connection))
            .collect()
    }

    /// Returns true while a binding's baseline is owed to the registration made on `connection`: the
    /// binding is ready, still owed it, and has not been registered again since. A baseline that
    /// began on one registration is given to that registration's component and to no other.
    #[must_use]
    pub fn rebuild_owed_on(&self, binding: BrokerBindingId, connection: u64) -> bool {
        self.inner()
            .views
            .get(&binding)
            .is_some_and(|view| view.ready && view.rebuild_owed && view.connection == connection)
    }

    /// Ends a binding's baseline: it is offered what is recorded from `boundary` on, and the outage
    /// is handed back to be told. Returns nothing where the baseline is not owed to the registration
    /// made on `connection`: the component the baseline was given to is gone, and its replacement
    /// is still owed its own.
    pub fn finish_rebuild(
        &self,
        binding: BrokerBindingId,
        boundary: u64,
        connection: u64,
    ) -> Option<Outage> {
        let mut inner = self.inner();
        let view = inner
            .views
            .get_mut(&binding)
            .filter(|view| view.ready && view.rebuild_owed && view.connection == connection)?;
        view.rebuild_owed = false;
        view.recorded_from = boundary;
        Some(std::mem::take(&mut view.outage))
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

    /// Forgets a binding's view. Its mark stays: see [`Self::forget_unwanted`].
    pub fn forget(&self, binding: BrokerBindingId) {
        self.inner().views.remove(&binding);
    }

    /// Forgets the view of every binding that is not in `wanted`: a binding that ended while the plugin runtime was lost is not unbound by anything else.
    ///
    /// A mark made on an earlier connection of a binding that is not wanted goes with it. One made
    /// on this connection stays, for the binding may be registered again on it.
    pub fn forget_unwanted(&self, wanted: &std::collections::BTreeSet<BrokerBindingId>) {
        let mut inner = self.inner();
        let connection = inner.connection;
        inner
            .marks
            .retain(|binding, made| wanted.contains(binding) || *made >= connection);
        inner.views.retain(|binding, _| wanted.contains(binding));
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

    /// Marks that a component is about to be handed something made in privacy mode, or while it
    /// stood, before the hand-over, so that an answer that does not come back cannot leave the
    /// component holding it unmarked. The connection the component is on is marked too
    /// ([`Self::words_withheld`]): the pump may have read what it needed before the link made that
    /// connection, so that privacy mode having stood on it is not the only way it can be handed
    /// something made in privacy mode.
    ///
    /// The call writes only to the per-binding marks and gives the binding no view. The mark carries
    /// the connection the lane holds when it is made, so a caller that holds an older connection
    /// stamps the newer one. A hand-over that comes before the component is registered is marked
    /// too, and the mark stays when the binding's view is forgotten ([`Self::forget`]).
    pub fn expose(&self, binding: BrokerBindingId, made_in_privacy: bool) {
        if !(made_in_privacy || self.private.load(Ordering::Acquire)) {
            return;
        }
        let mut inner = self.inner();
        inner.words_tainted = true;
        let connection = inner.connection;
        inner.marks.insert(binding, connection);
    }

    /// Returns true when the binding's component was handed something made in privacy mode, or while
    /// it stood, on the connection it is registered on.
    #[must_use]
    pub fn is_marked(&self, binding: BrokerBindingId) -> bool {
        self.inner().marks.contains_key(&binding)
    }

    /// Returns the number privacy mode's changes have reached.
    #[must_use]
    pub fn privacy_epoch(&self) -> u64 {
        self.privacy_epoch.load(Ordering::Acquire)
    }

    /// Reads where privacy mode stands, to be put to [`Self::unchanged_since`] later.
    ///
    /// The number is read before the flag, so a change that lands between the two reads is seen
    /// by [`Self::unchanged_since`] as a change.
    #[must_use]
    pub fn privacy_mark(&self) -> PrivacyMark {
        let epoch = self.privacy_epoch();
        PrivacyMark {
            private: self.is_private(),
            epoch,
        }
    }

    /// Returns true when privacy mode was off at `mark` and has been neither turned on nor turned
    /// off since, so that something taken in at `mark` and recorded now was not made in privacy
    /// mode.
    #[must_use]
    pub fn unchanged_since(&self, mark: PrivacyMark) -> bool {
        !mark.private && self.privacy_epoch() == mark.epoch && !self.is_private()
    }

    // -- privacy mode -------------------------------------------------------------------------

    /// Says whether privacy mode is on. Observation for live use goes on under it, and the lane
    /// keeps nothing derived from it beyond the entries waiting, which the pump takes off in bounded
    /// time.
    pub fn set_private(&self, private: bool) {
        let mut inner = self.inner();
        if self.private.swap(private, Ordering::AcqRel) != private {
            self.privacy_epoch.fetch_add(1, Ordering::AcqRel);
            self.privacy_wake.notify_one();
        }
        if private {
            inner.words_tainted = true;
        }
    }

    /// Returns true while privacy mode is on.
    #[must_use]
    pub fn is_private(&self) -> bool {
        self.private.load(Ordering::Acquire)
    }

    /// Waits until privacy mode may have been turned on or off since the last wait returned.
    ///
    /// A change that comes first is kept until it is waited for.
    pub async fn privacy_changed(&self) {
        self.privacy_wake.notified().await;
    }

    /// Records what the plugin runtime has acknowledged being told about privacy mode on the
    /// connection the link holds, or that it has been told nothing. For this host's own tests.
    #[cfg(feature = "testing")]
    pub fn runtime_was_told(&self, private: Option<bool>) {
        self.runtime_told.store(
            private.map_or(0, |private| if private { 2 } else { 1 }),
            Ordering::Release,
        );
    }

    /// Returns what the plugin runtime has acknowledged being told about privacy mode on the
    /// connection the link holds, where it has acknowledged anything. For this host's own tests.
    #[cfg(feature = "testing")]
    #[must_use]
    pub fn runtime_told(&self) -> Option<bool> {
        match self.runtime_told.load(Ordering::Acquire) {
            0 => None,
            told => Some(told == 2),
        }
    }

    /// Says that the link has made a connection to the plugin runtime. Nothing a connection before
    /// it said can be read from this one, so the words the runtime gives on it are withheld only if
    /// privacy mode is on now ([`Self::words_withheld`]).
    pub fn began_connection(&self) {
        let mut inner = self.inner();
        inner.connection += 1;
        inner.words_tainted = self.private.load(Ordering::Acquire);
        #[cfg(feature = "testing")]
        self.documents_read
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
    }

    /// Records that the link read a document of a binding from the runtime. For this host's own
    /// tests.
    #[cfg(feature = "testing")]
    pub fn document_was_read(&self, binding: BrokerBindingId, document: u64) {
        let mut read = self
            .documents_read
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let highest = read.entry(binding).or_insert(0);
        *highest = (*highest).max(document);
    }

    /// Returns the highest document number the link has read for a binding on the connection it
    /// holds. For this host's own tests.
    #[cfg(feature = "testing")]
    #[must_use]
    pub fn highest_document_read(&self, binding: BrokerBindingId) -> Option<u64> {
        self.documents_read
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&binding)
            .copied()
    }

    /// Says whether the words the plugin runtime gives, in a fault and in the reason it disabled a
    /// component, must not be kept.
    ///
    /// They are withheld once privacy mode has been on at any time since the connection that carries
    /// them was made, or a component on it has been handed something made in privacy mode
    /// ([`Self::expose`]), and until the link makes another. What decides it is the connection and
    /// not the notice: any component on it may have been handed something while privacy mode stood, by
    /// an observation or an action, and the words can be made of what a component was
    /// handed. Every notice about every component on the connection is withheld, however many wait
    /// and however late each is read, and a notice of an earlier connection cannot be read from a
    /// later one.
    #[must_use]
    pub fn words_withheld(&self) -> bool {
        self.inner().words_tainted
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

    /// Stops the pump the next time it reaches `at`, and until the returned hold is released. For
    /// this host's own tests.
    #[cfg(feature = "testing")]
    pub fn pause_at(&self, at: Pause) -> PauseHold {
        let state = Arc::new(PauseState {
            at,
            parked: AtomicBool::new(false),
            released: AtomicBool::new(false),
        });
        *self
            .pause
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Arc::clone(&state));
        PauseHold { state }
    }

    /// Stops the pump at `at` where a test holds it there, until the hold is released.
    #[cfg(feature = "testing")]
    pub async fn paused_at(&self, at: Pause) {
        let state = self
            .pause
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
            .filter(|state| state.at == at);
        let Some(state) = state else {
            return;
        };
        while !state.released.load(Ordering::Acquire) {
            state.parked.store(true, Ordering::Release);
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }
}

/// The observation lane's part in privacy mode.
///
/// Observation for live use goes on under privacy mode, and the lane keeps nothing derived from it
/// beyond the entries waiting, which the pump takes off in bounded time. There is nothing to remove
/// when privacy mode is turned on, so the subsystem only records that it is on.
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
        Ok(crate::privacy::Removed::default())
    }

    fn outstanding(&self) -> Result<u64, crate::privacy::Unavailable> {
        // The lane takes nothing from a component, so there is nothing in flight to wait for.
        Ok(0)
    }
}

/// What is known of an upstream frame under the broker's lock, which is all the lock is needed
/// for: the frame itself is copied after it is dropped.
#[derive(Clone, Debug)]
pub(super) struct NativeTap {
    instance: ApplicationInstanceId,
    package: PackageIdentity,
    handle: Option<SourceEventHandle>,
    request_id: Option<String>,
    recorded: Option<Recorded>,
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
        let (handle, request_id, recorded) = match (&forwarded.request, forwarded.expects_response)
        {
            (Some(request), true) => (
                resource
                    .and_then(|resource| self.arbitration.source_of(resource.resource_id))
                    .cloned(),
                Some(request.upstream.as_str().to_owned()),
                resource
                    .and_then(|resource| self.arbitration.get(resource.resource_id))
                    .map(|pending| Recorded {
                        place: pending.recorded,
                        resource_id: pending.resource.resource_id,
                        generation: pending.resource.source_generation,
                    }),
            ),
            _ => (None, None, None),
        };
        Some(NativeTap {
            instance,
            package,
            handle,
            request_id,
            recorded,
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
                recorded: tap.recorded,
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
        self.bindings_of(audience, true)
    }

    /// Returns the bindings an entry would be offered to if their components were registered: the
    /// bindings whose components were lost with the plugin runtime and are waiting to start again
    /// are among them, and are counted what they were not offered.
    #[must_use]
    pub fn retaining(&self, audience: Audience<'_>) -> Vec<BrokerBindingId> {
        self.bindings_of(audience, false)
    }

    fn bindings_of(&self, audience: Audience<'_>, registered: bool) -> Vec<BrokerBindingId> {
        let state = self.state();
        state
            .bindings
            .values()
            .filter(|binding| state.retains(binding, audience, registered))
            .map(|binding| binding.binding_id)
            .collect()
    }
}

impl super::BrokerState {
    /// Returns true when a binding is offered the entries of an audience: it holds the
    /// `Observation` grant and the stream the audience needs, its package ships a component the
    /// package's own manifest agrees with, and it is neither rich-disabled nor ending. With
    /// `registered`, its component must also be one the link has reported registered.
    pub(super) fn retains(
        &self,
        binding: &super::Binding,
        audience: Audience<'_>,
        registered: bool,
    ) -> bool {
        binding.rich_disabled.is_none()
            && !binding.ending
            && binding
                .grants
                .holds(kr_protocol::broker::BrokerGrant::Observation)
            && binding
                .component
                .as_ref()
                .is_some_and(|component| component.refusal.is_none())
            && (!registered
                || matches!(
                    self.component_states.get(&binding.binding_id),
                    Some((kr_protocol::admission::ComponentState::Registered, _))
                ))
            && match audience {
                Audience::Terminal => binding.streams.terminal,
                Audience::Native { instance, package } => {
                    binding.streams.semantic
                        && binding.application_instance_id == instance
                        && package.is_none_or(|package| binding.package() == *package)
                }
            }
    }
}
