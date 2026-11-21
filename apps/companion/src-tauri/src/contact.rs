//! The one owner of every host's contact with this application.
//!
//! Which host the commands go to, the connection to it, how contact with each host stands, and
//! whether what the page read of a host is still valid are held here, under one mutex, and nowhere
//! else. Every accepted change that the page can see is one immutable revision, told to the page
//! once and in order by one publisher; the page checks the revision it applies.
//!
//! The mutex is a leaf lock: nothing is taken while it is held, and there is no `.await`, no file
//! or device call, no `emit`, and no drop of a connection, a session, a receiver or a task handle
//! under it. Every method that removes, replaces or rejects a resource returns it in a
//! [`Disposal`], which releases it when it is dropped, after the guard is gone.

#![deny(clippy::await_holding_lock, clippy::await_holding_invalid_type)]

use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use kr_client::Session;
use kr_protocol::attention_rule::HOST_CONTACT_ESCALATION_MS;
use kr_protocol::envelope::Notification;
use kr_protocol::ids::DeviceId;
use serde::Serialize;
use tauri::{AppHandle, Emitter as _, Manager as _, Runtime};
use tokio::sync::{Notify, broadcast, watch};

use crate::connection::{Asked, CONNECTION_EVENT, Connection, ConnectionState, Unopened};
use crate::error::CommandError;
use crate::state::AppState;

/// How many published changes are kept for a page that missed some, besides the ones not yet told.
const KEPT_REVISIONS: usize = 256;

/// How long a connection's first events wait for the state that announces them to be told: a bound
/// on a wait that exists for order, not an authority. The page holds an event until it has applied
/// the revision the event carries.
pub const STATE_FIRST_WITHIN: Duration = Duration::from_secs(5);

// ---------------------------------------------------------------------------------------------
// What the owner holds, and what it hands back.
// ---------------------------------------------------------------------------------------------

#[cfg(feature = "testing")]
thread_local! {
    /// How many owner guards this thread holds.
    static UNDER_GUARD: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
    /// How many resources this thread dropped while it held an owner guard.
    static DROPPED_UNDER_GUARD: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// A resource the owner stores. It is a newtype so that a drop under the owner's mutex can be seen
/// by a suite: under the `testing` feature a drop that happens while this thread holds the guard is
/// counted.
pub struct Held<T>(Option<T>);

impl<T> Held<T> {
    /// Holds `value`.
    pub const fn new(value: T) -> Self {
        Self(Some(value))
    }

    /// The resource.
    ///
    /// # Panics
    ///
    /// Never: the resource is present until [`Self::into_inner`] takes it.
    pub fn get(&self) -> &T {
        self.0.as_ref().expect("a held resource is present")
    }

    /// Takes the resource out, so that it is dropped (or kept) where the caller says.
    ///
    /// # Panics
    ///
    /// Never: see [`Self::get`].
    pub fn into_inner(mut self) -> T {
        self.0.take().expect("a held resource is present")
    }
}

#[cfg(feature = "testing")]
impl<T> Drop for Held<T> {
    fn drop(&mut self) {
        if self.0.is_some() && UNDER_GUARD.with(std::cell::Cell::get) > 0 {
            DROPPED_UNDER_GUARD.with(|count| count.set(count.get() + 1));
        }
    }
}

/// The owner's mutex, held. Under `testing` it marks the thread that holds it.
struct Guard<'a>(MutexGuard<'a, State>);

impl<'a> Guard<'a> {
    fn new(inner: MutexGuard<'a, State>) -> Self {
        #[cfg(feature = "testing")]
        UNDER_GUARD.with(|held| held.set(held.get() + 1));
        Self(inner)
    }
}

impl std::ops::Deref for Guard<'_> {
    type Target = State;

    fn deref(&self) -> &State {
        &self.0
    }
}

impl std::ops::DerefMut for Guard<'_> {
    fn deref_mut(&mut self) -> &mut State {
        &mut self.0
    }
}

#[cfg(feature = "testing")]
impl Drop for Guard<'_> {
    fn drop(&mut self) {
        UNDER_GUARD.with(|held| held.set(held.get() - 1));
    }
}

/// What a change removed, replaced, cleared or rejected, to be released outside the owner's mutex.
/// It releases itself when it is dropped: a dropped task handle only detaches its task, so the
/// task is aborted here, and a session is closed before it is dropped.
#[must_use = "what a change removed is released when this is dropped"]
#[derive(Default)]
pub struct Disposal {
    connections: Vec<Held<Connection>>,
    visits: Vec<Held<Arc<Connection>>>,
    sessions: Vec<Arc<Session>>,
    reads: Vec<Arc<StoredRead>>,
    receivers: Vec<Held<broadcast::Receiver<Notification>>>,
    adoptions: Vec<Adoption>,
    task: Option<Held<tauri::async_runtime::JoinHandle<()>>>,
}

impl Disposal {
    fn connection(&mut self, connection: Option<Held<Connection>>) {
        self.connections.extend(connection);
    }

    fn adoption(&mut self, adoption: Option<Adoption>) {
        self.adoptions.extend(adoption);
    }

    fn task(&mut self, task: Option<Held<tauri::async_runtime::JoinHandle<()>>>) {
        if let Some(task) = task {
            self.task = Some(task);
        }
    }

    /// What one record held that is not its facts.
    fn record(&mut self, record: Record) {
        self.reads.extend(record.read);
        self.visits.extend(record.visit);
    }
}

impl Drop for Disposal {
    fn drop(&mut self) {
        for session in self.sessions.drain(..) {
            session.close();
        }
        if let Some(task) = self.task.take() {
            task.into_inner().abort();
        }
    }
}

/// What a change answered, with what it removed and the revision the owner stands at once it is
/// applied.
#[must_use = "what a change removed is released when this is dropped"]
pub struct Applied<T> {
    /// The answer.
    pub value: T,
    /// The revision the owner stands at after the change: the one the change was published as when
    /// it changed what the page sees.
    pub revision: u64,
    /// What the change removed, released when this is dropped.
    pub disposal: Disposal,
}

/// A host's inbox as this device last read it, and the connection it was read over.
pub struct StoredRead {
    /// The order reads were made in, owner-wide.
    #[allow(dead_code, reason = "the visits that store a read write and check it")]
    serial: u64,
    /// The connection the read came from, kept for the check of the account it was opened under.
    #[allow(dead_code, reason = "the visits that store a read write and check it")]
    origin: Held<Arc<Connection>>,
}

/// A replacement connection the keeper has not taken up yet, and the receiver of its events that
/// was taken before it was installed.
struct Adoption {
    events: Held<broadcast::Receiver<Notification>>,
    /// The revision the replacement was published as.
    revision: u64,
}

// ---------------------------------------------------------------------------------------------
// What the page sees.
// ---------------------------------------------------------------------------------------------

/// A host the owner keeps a record of.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum HostKey {
    /// The host on this machine.
    Local,
    /// A host this device is paired with, by the identity the host has.
    Paired(DeviceId),
}

/// The host a choice is for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Target {
    /// The host on this machine.
    Local,
    /// A host this device is paired with.
    Paired {
        /// The identity the host has.
        host: DeviceId,
        /// The identity the host gave this device in the pairing this record belongs to.
        pairing: DeviceId,
        /// What the page names the host by.
        reference: String,
        /// What people call the host.
        name: String,
    },
}

impl Target {
    const fn key(&self) -> HostKey {
        match self {
            Self::Local => HostKey::Local,
            Self::Paired { host, .. } => HostKey::Paired(*host),
        }
    }

    const fn pairing(&self) -> Option<DeviceId> {
        match self {
            Self::Local => None,
            Self::Paired { pairing, .. } => Some(*pairing),
        }
    }
}

/// How contact with one host stands.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum HostContact {
    /// Nothing is known: no attempt has ended, or the host on this machine was never reached.
    Unknown,
    /// The host answered.
    InContact,
    /// The host answered and refused, or refused the connection itself.
    Refused {
        /// What the host said.
        refusal: CommandError,
        /// What it refused.
        request: Asked,
    },
    /// The host was not reached.
    OutOfContact {
        /// Since when, as this device's clock says.
        since_ms: u64,
        /// When the loss reaches the rule's next level.
        escalates_at_ms: u64,
    },
}

/// What one attempt to reach a host, or one end of a connection, came to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The host answered.
    InContact,
    /// The host refused.
    Refused {
        /// What the host said.
        refusal: CommandError,
        /// What it refused.
        request: Asked,
    },
    /// The host was not reached.
    Lost,
}

impl Outcome {
    /// The ONE classification of a failure to reach a host: a refusal is a refusal, and the host
    /// not being reached or not admitting the connection is a loss. A refusal this application
    /// makes itself (its own budget of connections) is a refusal of the connection.
    #[must_use]
    pub fn of(unopened: &Unopened) -> Self {
        match unopened {
            Unopened::Refused(asked, refusal) => Self::Refused {
                refusal: refusal.clone(),
                request: *asked,
            },
            Unopened::HostFull => Self::Refused {
                refusal: crate::places::host_full_error(),
                request: Asked::Connection,
            },
            Unopened::BudgetFull => Self::Refused {
                refusal: crate::places::full_error(),
                request: Asked::Connection,
            },
            Unopened::NotAdmitted(_) | Unopened::Unreached(_) => Self::Lost,
        }
    }
}

/// The host in use, as the page names it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum HostLabel {
    /// The host on this machine.
    Local,
    /// A host this device is paired with.
    Paired {
        /// What the page names the host by.
        reference: String,
        /// What people call the host.
        name: String,
    },
}

/// A host that is not the one in use, and holds an outcome.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Other {
    /// What the page names the host by.
    pub reference: String,
    /// What people call the host.
    pub name: String,
    /// How contact with it stands.
    pub contact: HostContact,
    /// The page may show an inbox of this host only under this epoch.
    pub inbox_epoch: u64,
}

/// What the page is shown of the owner at one moment.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Visible {
    /// The facts of the connection.
    #[serde(flatten)]
    pub connection: ConnectionState,
    /// The number of the installed connection, which a new connection or a replacement moves.
    pub link: u64,
    /// The host in use, when there is one.
    pub host: Option<HostLabel>,
    /// How contact with the host in use stands.
    pub contact: HostContact,
    /// What the page may show of the host in use is valid only under this epoch. It is 0 when no
    /// host is in use.
    pub inbox_epoch: u64,
    /// The other hosts that hold an outcome.
    pub others: Vec<Other>,
}

/// One accepted change of what the page sees, with its revision. It is never changed once made.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Publication {
    /// The revision: each accepted visible change takes the next.
    pub revision: u64,
    /// What the page sees from this revision.
    #[serde(flatten)]
    pub visible: Visible,
}

impl std::ops::Deref for Publication {
    type Target = Visible;

    fn deref(&self) -> &Visible {
        &self.visible
    }
}

impl std::ops::Deref for Visible {
    type Target = ConnectionState;

    fn deref(&self) -> &ConnectionState {
        &self.connection
    }
}

/// What the page missed since a revision.
#[derive(Clone, Debug, Serialize)]
pub struct Since {
    /// The revision the owner stands at.
    pub revision: u64,
    /// The changes above the revision asked from, in order; or, when `resync` is set, the current
    /// state alone.
    pub states: Vec<Publication>,
    /// Set when the page is further behind than the owner keeps, or ahead of it: the one state is
    /// the whole current state, to take as a new base.
    pub resync: bool,
}

// ---------------------------------------------------------------------------------------------
// The state.
// ---------------------------------------------------------------------------------------------

/// The wall clock, in milliseconds since the epoch.
pub type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

fn system_clock() -> Clock {
    Arc::new(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |since| {
                u64::try_from(since.as_millis()).unwrap_or(u64::MAX)
            })
    })
}

struct Record {
    /// Taken from the owner's counter: a new pairing with the same host is a new record.
    #[allow(dead_code, reason = "the active reads and the visits check it")]
    generation: u64,
    pairing: Option<DeviceId>,
    reference: Option<String>,
    name: String,
    contact: HostContact,
    inbox_epoch: u64,
    /// The last complete inbox of another host.
    read: Option<Arc<StoredRead>>,
    /// The connection the last visit kept.
    visit: Option<Held<Arc<Connection>>>,
}

struct State {
    choice: u64,
    task: Option<Held<tauri::async_runtime::JoinHandle<()>>>,
    in_use: Option<HostKey>,
    slot: Option<Held<Connection>>,
    link: u64,
    adoption: Option<Adoption>,
    reason: Option<String>,
    replaced: u64,
    hosts: BTreeMap<HostKey, Record>,
    /// The one source of generations and epochs.
    counter: u64,
    /// Every forget adds one, whether or not a record exists.
    fence: u64,
    ever_reached: bool,
    clock: Clock,
    log: VecDeque<Arc<Publication>>,
    revision: u64,
    /// The highest revision the publisher has taken.
    taken: u64,
    /// The highest revision the publisher has finished with: its emit was attempted.
    told: u64,
    last: Visible,
}

impl State {
    fn new(clock: Clock) -> Self {
        let mut state = Self {
            choice: 0,
            task: None,
            in_use: None,
            slot: None,
            link: 0,
            adoption: None,
            reason: Some("this application has not reached a host yet".to_owned()),
            replaced: 0,
            hosts: BTreeMap::new(),
            counter: 0,
            fence: 0,
            ever_reached: false,
            clock,
            log: VecDeque::new(),
            revision: 0,
            taken: 0,
            told: 0,
            last: Visible {
                connection: ConnectionState::unreachable(""),
                link: 0,
                host: None,
                contact: HostContact::Unknown,
                inbox_epoch: 0,
                others: Vec::new(),
            },
        };
        state.last = state.visible();
        state
    }

    fn next(&mut self) -> u64 {
        self.counter += 1;
        self.counter
    }

    fn record_of(target: &Target, generation: u64, epoch: u64) -> Record {
        let (reference, name) = match target {
            Target::Local => (None, String::new()),
            Target::Paired {
                reference, name, ..
            } => (Some(reference.clone()), name.clone()),
        };
        Record {
            generation,
            pairing: target.pairing(),
            reference,
            name,
            contact: HostContact::Unknown,
            inbox_epoch: epoch,
            read: None,
            visit: None,
        }
    }

    /// The page's projection of the state.
    fn visible(&self) -> Visible {
        let connection = match &self.slot {
            Some(held) => ConnectionState {
                replaced: self.replaced,
                ..ConnectionState::of(held.get())
            },
            None => ConnectionState {
                connected: false,
                environment_id: None,
                reason: self.reason.clone(),
                rights: None,
                paired: false,
                replaced: self.replaced,
            },
        };
        let in_use = self.in_use.and_then(|key| self.hosts.get(&key));
        let host = self.in_use.map(|key| match (key, in_use) {
            (HostKey::Paired(_), Some(record)) => HostLabel::Paired {
                reference: record.reference.clone().unwrap_or_default(),
                name: record.name.clone(),
            },
            _ => HostLabel::Local,
        });
        let others = self
            .hosts
            .iter()
            .filter(|(key, record)| {
                Some(**key) != self.in_use
                    && record.reference.is_some()
                    && (record.contact != HostContact::Unknown || record.read.is_some())
            })
            .map(|(_, record)| Other {
                reference: record.reference.clone().unwrap_or_default(),
                name: record.name.clone(),
                contact: record.contact.clone(),
                inbox_epoch: record.inbox_epoch,
            })
            .collect();
        Visible {
            connection,
            link: self.link,
            host,
            contact: in_use.map_or(HostContact::Unknown, |record| record.contact.clone()),
            inbox_epoch: in_use.map_or(0, |record| record.inbox_epoch),
            others,
        }
    }

    /// Makes a publication of the state when what the page sees has changed. Returns whether it
    /// did.
    fn publish(&mut self) -> bool {
        let visible = self.visible();
        if visible == self.last {
            return false;
        }
        self.revision += 1;
        self.log.push_back(Arc::new(Publication {
            revision: self.revision,
            visible: visible.clone(),
        }));
        self.last = visible;
        self.trim();
        true
    }

    /// Keeps the last [`KEPT_REVISIONS`] publications and every one the publisher has not finished
    /// with: a publication that was taken and not yet emitted is still one a page may miss.
    fn trim(&mut self) {
        while self.log.len() > KEPT_REVISIONS
            && self
                .log
                .front()
                .is_some_and(|oldest| oldest.revision <= self.told)
        {
            self.log.pop_front();
        }
    }

    fn free_for(&self, last: Option<&Arc<Session>>) -> bool {
        match (&self.slot, last) {
            (None, _) => true,
            (Some(held), Some(last)) => Arc::ptr_eq(&held.get().session(), last),
            (Some(_), None) => false,
        }
    }

    fn holds(&self, session: &Arc<Session>) -> bool {
        self.slot
            .as_ref()
            .is_some_and(|held| Arc::ptr_eq(&held.get().session(), session))
    }

    /// Applies what an attempt to reach the host in use came to.
    fn apply(&mut self, outcome: Outcome) {
        let Some(key) = self.in_use else {
            return;
        };
        let now = (self.clock)();
        let local = key == HostKey::Local;
        let ever_reached = self.ever_reached;
        let new_epoch = self.counter + 1;
        let Some(record) = self.hosts.get_mut(&key) else {
            return;
        };
        match outcome {
            Outcome::InContact => {
                record.contact = HostContact::InContact;
                self.ever_reached |= local;
            }
            Outcome::Refused { refusal, request } => {
                let refused = HostContact::Refused { refusal, request };
                if record.contact != refused {
                    record.inbox_epoch = new_epoch;
                    self.counter = new_epoch;
                    record.contact = refused;
                }
            }
            Outcome::Lost => match record.contact {
                HostContact::OutOfContact { .. } => {}
                _ if local && !ever_reached => record.contact = HostContact::Unknown,
                _ => {
                    record.contact = HostContact::OutOfContact {
                        since_ms: now,
                        escalates_at_ms: now + HOST_CONTACT_ESCALATION_MS,
                    };
                }
            },
        }
    }

    /// Takes the slot, the adoption and the task of the choice that ends.
    fn end_choice(&mut self, disposal: &mut Disposal) {
        self.choice += 1;
        disposal.connection(self.slot.take());
        disposal.adoption(self.adoption.take());
        disposal.task(self.task.take());
    }
}

// ---------------------------------------------------------------------------------------------
// The owner.
// ---------------------------------------------------------------------------------------------

/// What an attempt that reached a host came to.
pub enum Reach {
    /// The connection is the one held.
    Reached,
    /// Another host was chosen, or this one forgotten, since: the connection is given back.
    StaleChoice(Connection),
    /// A different connection is held: the connection is given back.
    SlotBusy(Connection),
}

/// What a write of a failed attempt, or of an end, came to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Wrote {
    /// The state was changed.
    Applied,
    /// Another host was chosen, or this one forgotten, since: nothing was written.
    StaleChoice,
    /// A different connection is held: nothing was written.
    SlotBusy,
}

/// What the keeper is given when the connection it supervised has ended.
pub enum Adopt {
    /// Another host was chosen, or this one forgotten: the keeper ends.
    Stale,
    /// No other connection is held: the keeper dials.
    None,
    /// A replacement is held. Whether it is alive is for the keeper to find out outside the owner:
    /// a replacement that has ended resolves at once.
    Candidate {
        /// The connection held.
        connection: Connection,
        /// The receiver of its events, taken before it was installed.
        events: broadcast::Receiver<Notification>,
        /// The revision its installation was published as.
        revision: u64,
    },
}

/// The choice in force and the connection held when they were read together.
pub struct Stand {
    /// The number of the choice.
    pub choice: u64,
    /// The connection held, when one is.
    pub held: Option<Connection>,
}

/// The owner. See the module's description.
pub struct ContactOwner {
    state: Mutex<State>,
    wake: Notify,
    emitted: watch::Sender<u64>,
    /// Where a suite has paused the owner's tasks.
    #[cfg(feature = "testing")]
    pauses: testing::Pauses,
}

impl std::fmt::Debug for ContactOwner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ContactOwner")
            .finish_non_exhaustive()
    }
}

impl Default for ContactOwner {
    fn default() -> Self {
        Self::with_clock(system_clock())
    }
}

impl ContactOwner {
    /// An owner that has not reached anything.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// An owner whose loss stamps come from `clock`.
    #[must_use]
    pub fn with_clock(clock: Clock) -> Self {
        Self {
            state: Mutex::new(State::new(clock)),
            wake: Notify::new(),
            emitted: watch::channel(0).0,
            #[cfg(feature = "testing")]
            pauses: testing::Pauses::default(),
        }
    }

    fn lock(&self) -> Guard<'_> {
        Guard::new(self.state.lock().unwrap_or_else(PoisonError::into_inner))
    }

    /// Applies one change under the mutex, publishes what the page sees of it, and returns what it
    /// answered with what it removed.
    fn commit<T>(&self, change: impl FnOnce(&mut State, &mut Disposal) -> T) -> Applied<T> {
        let mut disposal = Disposal::default();
        let (value, revision, told) = {
            let mut state = self.lock();
            let value = change(&mut state, &mut disposal);
            let told = state.publish();
            (value, state.revision, told)
        };
        if told {
            self.wake.notify_one();
        }
        Applied {
            value,
            revision,
            disposal,
        }
    }

    /// A choice of host: ends the choice before it and starts the one for `target`, whose number is
    /// the answer. The host left behind keeps only a loss; the host chosen keeps a loss it had.
    pub fn choose(&self, target: &Target, reason: &str) -> Applied<u64> {
        self.commit(|state, disposal| {
            state.end_choice(disposal);
            state.reason = Some(reason.to_owned());
            let left = state.in_use.replace(target.key());
            let key = target.key();
            // A record of another pairing is a new record: what the old one held goes with it.
            if state
                .hosts
                .get(&key)
                .is_some_and(|record| record.pairing != target.pairing())
                && let Some(old) = state.hosts.remove(&key)
            {
                disposal.record(old);
            }
            let (generation, epoch) = (state.next(), state.next());
            state
                .hosts
                .entry(key)
                .or_insert_with(|| State::record_of(target, generation, epoch));
            // Each host that changes role gets an epoch of its own and loses what was read of it.
            for each in [left, Some(key)].into_iter().flatten() {
                let epoch = state.next();
                if let Some(record) = state.hosts.get_mut(&each) {
                    record.inbox_epoch = epoch;
                    disposal.reads.extend(record.read.take());
                    disposal.visits.extend(record.visit.take());
                    // Only a loss is kept of a host.
                    if !matches!(record.contact, HostContact::OutOfContact { .. }) {
                        record.contact = HostContact::Unknown;
                    }
                }
            }
            if let (Target::Paired { name, .. }, Some(record)) = (target, state.hosts.get_mut(&key))
            {
                record.name.clone_from(name);
            }
            state.choice
        })
    }

    /// Keeps the task of `choice`, unless another choice has been made: then the handle is given
    /// back to be ended.
    pub fn set_task(&self, choice: u64, task: tauri::async_runtime::JoinHandle<()>) -> Disposal {
        self.commit(|state, disposal| {
            if state.choice == choice {
                disposal.task(state.task.replace(Held::new(task)));
            } else {
                disposal.task = Some(Held::new(task));
            }
        })
        .disposal
    }

    /// A host this device no longer holds a record of. The fence moves whether or not a record
    /// exists. When the host was in use its connection and choice end, and none is in use. The
    /// answer is whether it was.
    pub fn forget(&self, host: DeviceId, reason: &str) -> Applied<bool> {
        self.commit(|state, disposal| {
            state.fence += 1;
            let key = HostKey::Paired(host);
            if let Some(record) = state.hosts.remove(&key) {
                disposal.record(record);
            }
            let was_in_use = state.in_use == Some(key);
            if was_in_use {
                state.end_choice(disposal);
                state.in_use = None;
                state.reason = Some(reason.to_owned());
            }
            was_in_use
        })
    }

    /// A connection that reached the host, for `choice`. `last` is the session the keeper last
    /// supervised: the slot may hold it, or nothing.
    pub fn reached(
        &self,
        choice: u64,
        last: Option<&Arc<Session>>,
        connection: Connection,
    ) -> Applied<Reach> {
        self.commit(|state, disposal| {
            if state.choice != choice {
                return Reach::StaleChoice(connection);
            }
            if !state.free_for(last) {
                return Reach::SlotBusy(connection);
            }
            disposal.connection(state.slot.replace(Held::new(connection)));
            state.link += 1;
            state.reason = None;
            state.apply(Outcome::InContact);
            Reach::Reached
        })
    }

    /// An attempt for `choice` that did not reach the host.
    pub fn failed(
        &self,
        choice: u64,
        last: Option<&Arc<Session>>,
        outcome: Outcome,
        reason: &str,
    ) -> Applied<Wrote> {
        self.commit(|state, disposal| {
            if state.choice != choice {
                return Wrote::StaleChoice;
            }
            if !state.free_for(last) {
                return Wrote::SlotBusy;
            }
            disposal.connection(state.slot.take());
            state.reason = Some(reason.to_owned());
            state.apply(outcome);
            Wrote::Applied
        })
    }

    /// The lease kept for `session` stopped, for `choice`: the connection is removed and the
    /// outcome the stop is applied in one step. Nothing is written for another choice or another
    /// session.
    pub fn lease_stopped(
        &self,
        choice: u64,
        session: &Arc<Session>,
        outcome: Outcome,
        reason: &str,
    ) -> Applied<bool> {
        self.commit(|state, disposal| {
            if state.choice != choice || !state.holds(session) {
                return false;
            }
            disposal.connection(state.slot.take());
            state.reason = Some(reason.to_owned());
            state.apply(outcome);
            true
        })
    }

    /// The connection `session` ended. Nothing is written when another connection has taken its
    /// place.
    pub fn ended(&self, session: &Arc<Session>, outcome: Outcome, reason: &str) -> Applied<bool> {
        self.commit(|state, disposal| {
            if !state.holds(session) {
                return false;
            }
            disposal.connection(state.slot.take());
            state.reason = Some(reason.to_owned());
            state.apply(outcome);
            true
        })
    }

    /// `fresh` takes the place of the connection `withdrawn`, when that is the one held. `events`
    /// is the receiver of `fresh`'s events, taken before this call. The withdrawn session is closed
    /// when the answer is dropped. A replacement that is not wanted is given back in the disposal.
    pub fn replaced(
        &self,
        withdrawn: &Arc<Session>,
        fresh: Connection,
        events: broadcast::Receiver<Notification>,
    ) -> Applied<bool> {
        self.commit(|state, disposal| {
            if !state.holds(withdrawn) {
                disposal.connection(Some(Held::new(fresh)));
                disposal.receivers.push(Held::new(events));
                return false;
            }
            disposal.connection(state.slot.replace(Held::new(fresh)));
            disposal.sessions.push(Arc::clone(withdrawn));
            state.link += 1;
            state.replaced += 1;
            // The withdrawn connection's results are not valid on the new one.
            if let Some(key) = state.in_use {
                let epoch = state.next();
                if let Some(record) = state.hosts.get_mut(&key) {
                    record.inbox_epoch = epoch;
                    disposal.reads.extend(record.read.take());
                }
            }
            // This change is published as the next revision: link and the count both moved.
            let revision = state.revision + 1;
            disposal.adoption(state.adoption.replace(Adoption {
                events: Held::new(events),
                revision,
            }));
            true
        })
    }

    /// The session the keeper supervised has ended (or it has supervised none): what to do next.
    /// No liveness is tested here.
    pub fn adopt(&self, choice: u64, ended: Option<&Arc<Session>>) -> Adopt {
        let mut guard = self.lock();
        let state = &mut *guard;
        if state.choice != choice {
            return Adopt::Stale;
        }
        let Some(held) = state.slot.as_ref() else {
            return Adopt::None;
        };
        if ended.is_some_and(|ended| Arc::ptr_eq(&held.get().session(), ended)) {
            return Adopt::None;
        }
        let Some(adoption) = state.adoption.take() else {
            return Adopt::None;
        };
        Adopt::Candidate {
            connection: held.get().clone(),
            events: adoption.events.into_inner(),
            revision: adoption.revision,
        }
    }

    // The readers of the slot.

    /// The connection held.
    #[must_use]
    pub fn held(&self) -> Option<Connection> {
        self.lock().slot.as_ref().map(|held| held.get().clone())
    }

    /// The choice in force and the connection held, read together. A reader that must ask
    /// something else outside the owner takes this first and asks [`Self::stands_as`] afterwards.
    #[must_use]
    pub fn stand(&self) -> Stand {
        let state = self.lock();
        Stand {
            choice: state.choice,
            held: state.slot.as_ref().map(|held| held.get().clone()),
        }
    }

    /// Whether the choice in force and the connection held are still what `stand` read: the same
    /// choice number, and the same session or none.
    #[must_use]
    pub fn stands_as(&self, stand: &Stand) -> bool {
        let state = self.lock();
        state.choice == stand.choice
            && match (&state.slot, &stand.held) {
                (None, None) => true,
                (Some(now), Some(then)) => Arc::ptr_eq(&now.get().session(), &then.session()),
                _ => false,
            }
    }

    /// What the page sees now, as a publication.
    #[must_use]
    pub fn snapshot(&self) -> Publication {
        let state = self.lock();
        Publication {
            revision: state.revision,
            visible: state.last.clone(),
        }
    }

    /// The revision the owner stands at.
    #[must_use]
    pub fn revision(&self) -> u64 {
        self.lock().revision
    }

    /// What the page missed since the revision `after`.
    #[must_use]
    pub fn since(&self, after: u64) -> Since {
        let state = self.lock();
        let oldest = state
            .log
            .front()
            .map_or(state.revision + 1, |first| first.revision);
        if after > state.revision || after + 1 < oldest {
            return Since {
                revision: state.revision,
                states: vec![Publication {
                    revision: state.revision,
                    visible: state.last.clone(),
                }],
                resync: true,
            };
        }
        Since {
            revision: state.revision,
            states: state
                .log
                .iter()
                .filter(|published| published.revision > after)
                .map(|published| (**published).clone())
                .collect(),
            resync: false,
        }
    }

    /// Takes the next publication the publisher has not taken, in order. It stays in the log until
    /// [`Self::told`] is called for it.
    fn next_unemitted(&self) -> Option<Arc<Publication>> {
        let mut state = self.lock();
        let next = state.taken + 1;
        let found = state
            .log
            .iter()
            .find(|published| published.revision == next)
            .cloned()?;
        state.taken = next;
        Some(found)
    }

    /// The publisher has attempted the emit of `revision`, and a failed attempt counts: the
    /// publication may leave the log once it is beyond the kept ones, and whoever waits for it is let
    /// go.
    fn told(&self, revision: u64) {
        {
            let mut state = self.lock();
            state.told = revision;
            state.trim();
        }
        self.emitted.send_replace(revision);
    }

    /// Waits until the publisher has told `revision`, for at most `within`. Returns whether it was
    /// told. A revision that is never told does not hold the caller beyond the bound.
    pub async fn emitted_through(&self, revision: u64, within: Duration) -> bool {
        let mut told = self.emitted.subscribe();
        tokio::time::timeout(within, told.wait_for(|told| *told >= revision))
            .await
            .is_ok()
    }

    /// How long a connection's first events wait for the state that announces them.
    #[cfg(not(feature = "testing"))]
    #[allow(
        clippy::unused_self,
        reason = "the one form of the call; a suite sets its own under `testing`"
    )]
    pub(crate) const fn state_first_within(&self) -> Duration {
        STATE_FIRST_WITHIN
    }

    /// The seam of a suite: the owner's fence.
    #[cfg(feature = "testing")]
    #[must_use]
    pub fn fence(&self) -> u64 {
        self.lock().fence
    }
}

impl Drop for ContactOwner {
    fn drop(&mut self) {
        self.wake.notify_one();
    }
}

/// Tells the page one publication, and hands it to the suite's tap.
fn tell<R: Runtime>(app: &AppHandle<R>, published: &Publication) {
    #[cfg(feature = "testing")]
    crate::told::tap(app, CONNECTION_EVENT, published);
    let _ = app.emit(CONNECTION_EVENT, published);
}

/// Starts the one task that tells the page each publication, in order, once. It is started where
/// the state is managed, after the application is built.
pub fn serve<R: Runtime>(app: &AppHandle<R>) {
    let Some(state) = app.try_state::<AppState>() else {
        return;
    };
    let owner = Arc::clone(state.contact_owner());
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        loop {
            owner.wake.notified().await;
            while let Some(published) = owner.next_unemitted() {
                #[cfg(feature = "testing")]
                owner.before_telling().await;
                #[cfg(feature = "testing")]
                let lost = owner.loses_the_emit();
                #[cfg(not(feature = "testing"))]
                let lost = false;
                if !lost {
                    tell(&app, &published);
                }
                owner.told(published.revision);
            }
        }
    });
}

/// Seams the application's own suites act through.
#[cfg(feature = "testing")]
pub mod testing {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Mutex, PoisonError};
    use std::time::Duration;

    use kr_client::Session;
    use tokio::sync::{mpsc, oneshot};

    use super::{
        Adoption, Arc, Connection, ContactOwner, DROPPED_UNDER_GUARD, Held, HostKey, StoredRead,
    };

    /// How many resources the calling thread has dropped while it held the owner's mutex.
    #[must_use]
    pub fn dropped_under_the_guard() -> u64 {
        DROPPED_UNDER_GUARD.with(std::cell::Cell::get)
    }

    /// A pause a suite set at one place of the owner's tasks. The task that reaches the place waits
    /// until the hold is released or dropped.
    #[derive(Debug)]
    pub struct Hold {
        reached: oneshot::Receiver<()>,
        release: oneshot::Sender<()>,
    }

    impl Hold {
        /// Resolves once a task has reached the place and waits there.
        pub async fn reached(&mut self) {
            let _ = (&mut self.reached).await;
        }

        /// Lets the waiting task go on.
        pub fn release(self) {
            let _ = self.release.send(());
        }
    }

    /// One place a task can be paused at.
    #[derive(Debug, Default)]
    pub(super) struct Place(Mutex<Option<(oneshot::Sender<()>, oneshot::Receiver<()>)>>);

    impl Place {
        fn set(&self) -> Hold {
            let (reached, reached_by) = oneshot::channel();
            let (release, released) = oneshot::channel();
            *self.0.lock().unwrap_or_else(PoisonError::into_inner) = Some((reached, released));
            Hold {
                reached: reached_by,
                release,
            }
        }

        /// Waits here when a suite paused this place, once.
        pub(super) async fn wait(&self) {
            let held = self.0.lock().unwrap_or_else(PoisonError::into_inner).take();
            if let Some((reached, released)) = held {
                let _ = reached.send(());
                let _ = released.await;
            }
        }
    }

    /// A lease stop the keeper has reported and acted on, held at the keeper's checkpoint until it is
    /// released.
    #[derive(Debug)]
    pub struct Stop {
        /// The session the stop was for.
        pub session: Arc<Session>,
        release: oneshot::Sender<()>,
    }

    impl Stop {
        /// Lets the keeper go on.
        pub fn release(self) {
            let _ = self.release.send(());
        }
    }

    /// Every place a task of the owner can be paused at.
    #[derive(Debug, Default)]
    pub(super) struct Pauses {
        publisher: Place,
        adoption: Place,
        stops: Mutex<Option<mpsc::UnboundedSender<Stop>>>,
        state_wait: Mutex<Option<Duration>>,
        lose_emits: AtomicUsize,
    }

    impl ContactOwner {
        /// Pauses the publisher after it has taken its next publication and before it tells it.
        #[must_use]
        pub fn hold_the_publisher(&self) -> Hold {
            self.pauses.publisher.set()
        }

        pub(super) async fn before_telling(&self) {
            self.pauses.publisher.wait().await;
        }

        /// Pauses the keeper after the connection it supervised has ended and before it asks for a
        /// replacement to take up.
        #[must_use]
        pub fn hold_adoption(&self) -> Hold {
            self.pauses.adoption.set()
        }

        pub(crate) async fn before_adopting(&self) {
            self.pauses.adoption.wait().await;
        }

        /// Whether a replacement waits for the keeper to take it up.
        #[must_use]
        pub fn adoption_pending(&self) -> bool {
            self.lock().adoption.is_some()
        }

        /// Hands every lease stop the keeper acts on to the returned receiver, held at the
        /// keeper's checkpoint after the place where it closes the stopped session and before it
        /// waits for the connection to end, until the stop is released.
        #[must_use]
        pub fn watch_stops(&self) -> mpsc::UnboundedReceiver<Stop> {
            let (watching, stops) = mpsc::unbounded_channel();
            *self
                .pauses
                .stops
                .lock()
                .unwrap_or_else(PoisonError::into_inner) = Some(watching);
            stops
        }

        pub(crate) async fn at_the_stop(&self, session: &Arc<Session>) {
            let watching = self
                .pauses
                .stops
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone();
            if let Some(watching) = watching {
                let (release, released) = oneshot::channel();
                let sent = watching.send(Stop {
                    session: Arc::clone(session),
                    release,
                });
                if sent.is_ok() {
                    let _ = released.await;
                }
            }
        }

        /// Sets how long a connection's first events wait for the state that announces them, from
        /// now on: a bound on a wait that exists for order.
        pub fn wait_for_the_state_at_most(&self, within: Duration) {
            *self
                .pauses
                .state_wait
                .lock()
                .unwrap_or_else(PoisonError::into_inner) = Some(within);
        }

        pub(crate) fn state_first_within(&self) -> Duration {
            self.pauses
                .state_wait
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .unwrap_or(super::STATE_FIRST_WITHIN)
        }

        /// Makes the publisher's next emit fail: the page is told nothing of the publication it was
        /// to tell, and the publisher goes on with the next as it does after an emit that failed.
        pub fn lose_the_next_emit(&self) {
            self.pauses.lose_emits.fetch_add(1, Ordering::SeqCst);
        }

        pub(super) fn loses_the_emit(&self) -> bool {
            self.pauses
                .lose_emits
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |left| {
                    left.checked_sub(1)
                })
                .is_ok()
        }

        /// Plants a stored read and a retained visit connection in the record of the paired host
        /// `host`, which a choice or a forget then releases.
        pub fn plant(&self, host: kr_protocol::ids::DeviceId, read: Connection, visit: Connection) {
            let mut state = self.lock();
            if let Some(record) = state.hosts.get_mut(&HostKey::Paired(host)) {
                record.read = Some(Arc::new(StoredRead {
                    serial: 0,
                    origin: Held::new(Arc::new(read)),
                }));
                record.visit = Some(Held::new(Arc::new(visit)));
            }
        }

        /// Plants an adoption holding `events`, as a replacement leaves one.
        pub fn plant_adoption(
            &self,
            events: tokio::sync::broadcast::Receiver<kr_protocol::envelope::Notification>,
        ) {
            self.lock().adoption = Some(Adoption {
                events: Held::new(events),
                revision: 0,
            });
        }

        /// Installs `connection` as the one held, with no host in use.
        pub fn install(&self, connection: Connection) -> super::Disposal {
            self.commit(|state, disposal| {
                disposal.connection(state.slot.replace(Held::new(connection)));
                state.link += 1;
                state.reason = None;
            })
            .disposal
        }

        /// The generation of the record of `host`, when it has one.
        #[must_use]
        pub fn generation_of(&self, host: kr_protocol::ids::DeviceId) -> Option<u64> {
            self.lock()
                .hosts
                .get(&HostKey::Paired(host))
                .map(|record| record.generation)
        }

        /// Whether the record of `host` holds a read or a retained connection.
        #[must_use]
        pub fn holds_resources_of(&self, host: kr_protocol::ids::DeviceId) -> bool {
            self.lock()
                .hosts
                .get(&HostKey::Paired(host))
                .is_some_and(|record| record.read.is_some() || record.visit.is_some())
        }
    }
}

#[cfg(all(test, feature = "testing"))]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    use kr_client::error::Result as ClientResult;
    use kr_client::transport::{ControlTransport, TransportFuture};
    use kr_protocol::envelope::ControlFrame;
    use kr_protocol::hello::{ActionWindow, ReceiveLimits};
    use kr_protocol::ids::{ActionWindowId, BootEpoch, ConnectionId, EnvironmentId};
    use kr_protocol::scalars::{DurationMs, TimestampMs, Uuid};

    use super::*;
    use crate::connection::{HostWords, NotReached, Standing};

    /// A connection that takes every frame and never answers one, and says when it is closed. It
    /// sends one frame first when it is given one.
    #[derive(Debug)]
    struct Silent {
        id: ConnectionId,
        closed: Arc<AtomicBool>,
        first: std::sync::Mutex<Option<ControlFrame>>,
    }

    impl ControlTransport for Silent {
        fn host_states_placement_reading(&self) -> bool {
            false
        }

        fn connection_id(&self) -> ConnectionId {
            self.id
        }

        fn limits(&self) -> ReceiveLimits {
            ReceiveLimits::default()
        }

        fn initial_action_window(&self) -> ActionWindow {
            ActionWindow {
                action_window_id: ActionWindowId::new("window-1").expect("a window"),
                connection_id: self.id,
                boot_epoch: BootEpoch::new(1),
                issued_at_ms: TimestampMs::new(1),
                valid_for_ms: DurationMs::new(60_000),
            }
        }

        fn ended_by_this_device(&self) -> Option<kr_client::transport::DeviceEnd> {
            None
        }

        fn send<'a>(&'a self, _: &'a ControlFrame) -> TransportFuture<'a, ()> {
            Box::pin(async { Ok(()) })
        }

        fn claim_receiver(&self) -> ClientResult<()> {
            Ok(())
        }

        fn stream_opener(&self) -> Option<Arc<dyn kr_client::transport::StreamOpener>> {
            None
        }

        fn recv(&self) -> TransportFuture<'_, Option<ControlFrame>> {
            let first = self
                .first
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take();
            Box::pin(async move {
                match first {
                    Some(frame) => Ok(Some(frame)),
                    None => std::future::pending().await,
                }
            })
        }

        fn revoke_streams(&self) {}

        fn close(&self) {
            self.closed.store(true, Ordering::SeqCst);
        }
    }

    /// A connection of its own, and the flag that says its transport was closed.
    fn connection(byte: u8) -> (Connection, Arc<AtomicBool>) {
        let closed = Arc::new(AtomicBool::new(false));
        let session = Session::start(Arc::new(Silent {
            id: ConnectionId::new(Uuid::from_bytes([byte; 16])),
            closed: Arc::clone(&closed),
            first: std::sync::Mutex::new(None),
        }))
        .expect("a session");
        let connection = Connection::assembled(
            session,
            EnvironmentId::new(Uuid::from_bytes([9; 16])),
            Standing::Owner,
            None,
            None,
        );
        (connection, closed)
    }

    /// A session whose host refused the connection with `code`: the first error the host answered
    /// with request identifier zero, which the session keeps.
    async fn refused_session(code: kr_protocol::error::ErrorCode) -> Arc<Session> {
        let refusal = kr_protocol::error::ProtocolError::new(code, "the host will not have it");
        let session = Session::start(Arc::new(Silent {
            id: ConnectionId::new(Uuid::from_bytes([30; 16])),
            closed: Arc::new(AtomicBool::new(false)),
            first: std::sync::Mutex::new(Some(ControlFrame::Response(
                kr_protocol::envelope::Response {
                    request_id: kr_protocol::ids::RequestId::new(0),
                    outcome: kr_protocol::envelope::Outcome::Error(refusal),
                },
            ))),
        }))
        .expect("a session");
        // A host's refusal of the connection ends the session.
        tokio::time::timeout(Duration::from_secs(5), session.closed())
            .await
            .expect("the session ended with the host's refusal");
        Arc::new(session)
    }

    fn host(byte: u8) -> DeviceId {
        DeviceId::new(Uuid::from_bytes([byte; 16]))
    }

    /// The host `byte`, as this device is paired with it under the identity `pairing`.
    fn paired(byte: u8, pairing: u8) -> Target {
        Target::Paired {
            host: host(byte),
            pairing: host(pairing),
            reference: format!("reference-{byte}"),
            name: format!("host {byte}"),
        }
    }

    fn refusal(words: &str) -> Outcome {
        Outcome::Refused {
            refusal: CommandError::refused(words),
            request: Asked::HostInfo,
        }
    }

    fn owner_at(now: &Arc<AtomicU64>) -> ContactOwner {
        let now = Arc::clone(now);
        ContactOwner::with_clock(Arc::new(move || now.load(Ordering::SeqCst)))
    }

    /// Takes every publication and finishes with it, as the publisher does.
    fn told_all(owner: &ContactOwner) {
        while let Some(published) = owner.next_unemitted() {
            owner.told(published.revision);
        }
    }

    fn revisions(since: &Since) -> Vec<u64> {
        since.states.iter().map(|each| each.revision).collect()
    }

    /// An owner with the host on this machine chosen and reached over `connection(byte)`.
    fn reaching(owner: &ContactOwner, byte: u8) -> (u64, Arc<Session>, Arc<AtomicBool>) {
        let choice = owner.choose(&Target::Local, "reaching").value;
        let (held, closed) = connection(byte);
        let session = held.session();
        let reached = owner.reached(choice, None, held);
        assert!(matches!(reached.value, Reach::Reached));
        (choice, session, closed)
    }

    #[tokio::test]
    async fn an_accepted_change_takes_the_next_revision() {
        let owner = ContactOwner::new();
        assert_eq!(owner.revision(), 0);
        let chosen = owner.choose(&paired(1, 2), "reaching");
        assert_eq!(chosen.revision, 1);
        let (held, _) = connection(1);
        let reached = owner.reached(chosen.value, None, held);
        assert!(matches!(reached.value, Reach::Reached));
        assert_eq!(reached.revision, 2);
        assert_eq!(revisions(&owner.since(0)), [1, 2]);
        assert_eq!(owner.snapshot().revision, 2);
        assert!(owner.snapshot().connected);
    }

    #[tokio::test]
    async fn a_rejected_writer_makes_no_event() {
        let owner = ContactOwner::new();
        let (choice, session, _) = reaching(&owner, 1);
        let before = owner.revision();

        let (stale, _) = connection(2);
        let reached = owner.reached(choice + 1, None, stale);
        assert!(matches!(reached.value, Reach::StaleChoice(_)));
        let (busy, _) = connection(3);
        let reached = owner.reached(choice, None, busy);
        assert!(matches!(reached.value, Reach::SlotBusy(_)));
        assert_eq!(
            owner.failed(choice + 1, None, Outcome::Lost, "no").value,
            Wrote::StaleChoice
        );
        assert_eq!(
            owner.failed(choice, None, Outcome::Lost, "no").value,
            Wrote::SlotBusy
        );
        let (other, _) = connection(4);
        assert!(
            !owner
                .lease_stopped(choice, &other.session(), Outcome::Lost, "stopped")
                .value
        );
        assert!(
            !owner
                .lease_stopped(choice + 1, &session, Outcome::Lost, "stopped")
                .value
        );
        assert!(!owner.ended(&other.session(), Outcome::Lost, "ended").value);
        assert_eq!(
            owner.revision(),
            before,
            "no writer that was rejected made a revision"
        );
        assert!(owner.since(before).states.is_empty());
    }

    #[tokio::test]
    async fn an_unchanged_outcome_makes_no_event() {
        let owner = ContactOwner::new();
        let choice = owner.choose(&paired(1, 2), "reaching").value;
        let first = owner.failed(choice, None, Outcome::Lost, "no answer");
        assert_eq!(first.value, Wrote::Applied);
        let again = owner.failed(choice, None, Outcome::Lost, "no answer");
        assert_eq!(again.value, Wrote::Applied, "the write is accepted");
        assert_eq!(again.revision, first.revision, "and tells nothing new");
    }

    #[tokio::test]
    async fn an_identical_refusal_keeps_the_epoch_and_makes_no_event() {
        let owner = ContactOwner::new();
        let choice = owner.choose(&paired(1, 2), "reaching").value;
        drop(owner.failed(choice, None, refusal("not now"), "not now"));
        let told = owner.snapshot();
        drop(owner.failed(choice, None, refusal("not now"), "not now"));
        assert_eq!(owner.snapshot(), told, "the epoch and the revision stand");
    }

    #[tokio::test]
    async fn a_different_refusal_moves_it() {
        let owner = ContactOwner::new();
        let choice = owner.choose(&paired(1, 2), "reaching").value;
        drop(owner.failed(choice, None, refusal("not now"), "not now"));
        let told = owner.snapshot();
        drop(owner.failed(choice, None, refusal("not ever"), "not ever"));
        let now = owner.snapshot();
        assert_eq!(now.revision, told.revision + 1);
        assert!(now.inbox_epoch > told.inbox_epoch);
        // A recovery is no refusal: the epoch does not move for it.
        drop(owner.failed(choice, None, Outcome::InContact, "answered"));
        assert_eq!(owner.snapshot().inbox_epoch, now.inbox_epoch);
    }

    #[tokio::test]
    async fn a_replacement_moves_the_epoch() {
        let owner = ContactOwner::new();
        let (_, withdrawn, withdrawn_closed) = reaching(&owner, 1);
        let before = owner.snapshot();
        let (fresh, _) = connection(2);
        let events = fresh.session().events();
        let applied = owner.replaced(&withdrawn, fresh, events);
        assert!(applied.value);
        assert!(
            !withdrawn_closed.load(Ordering::SeqCst),
            "the withdrawn session is closed once the answer is dropped, outside the owner"
        );
        assert_eq!(applied.revision, before.revision + 1);
        drop(applied);
        assert!(withdrawn_closed.load(Ordering::SeqCst));
        let after = owner.snapshot();
        assert!(after.inbox_epoch > before.inbox_epoch);
        assert_eq!(after.link, before.link + 1);
        assert_eq!(after.connection.replaced, before.connection.replaced + 1);
    }

    #[tokio::test]
    async fn a_replacement_with_no_host_in_use_moves_link_and_replaced_and_no_epoch() {
        let owner = ContactOwner::new();
        let (held, _) = connection(1);
        let withdrawn = held.session();
        drop(owner.install(held));
        let before = owner.snapshot();
        assert_eq!(before.inbox_epoch, 0, "no host is in use");
        let (fresh, _) = connection(2);
        let events = fresh.session().events();
        assert!(owner.replaced(&withdrawn, fresh, events).value);
        let after = owner.snapshot();
        assert_eq!(after.inbox_epoch, 0);
        assert_eq!(after.link, before.link + 1);
        assert_eq!(after.connection.replaced, before.connection.replaced + 1);
        assert_eq!(after.host, None);
    }

    #[tokio::test]
    async fn inbox_epoch_is_zero_with_no_host_in_use() {
        let owner = ContactOwner::new();
        assert_eq!(owner.snapshot().inbox_epoch, 0);
        let choice = owner.choose(&paired(1, 2), "reaching").value;
        assert!(owner.snapshot().inbox_epoch > 0);
        assert!(owner.forget(host(1), "forgotten").value);
        assert_eq!(owner.snapshot().inbox_epoch, 0);
        assert_ne!(choice, 0);
    }

    #[tokio::test]
    async fn two_writers_on_two_threads_make_a_strictly_consecutive_log_of_whole_snapshots() {
        let owner = Arc::new(ContactOwner::new());
        let choice = owner.choose(&paired(1, 2), "reaching").value;
        let writers: Vec<_> = (0..2)
            .map(|writer| {
                let owner = Arc::clone(&owner);
                std::thread::spawn(move || {
                    for turn in 0..60 {
                        drop(owner.failed(
                            choice,
                            None,
                            Outcome::Lost,
                            &format!("writer {writer} turn {turn}"),
                        ));
                    }
                })
            })
            .collect();
        for writer in writers {
            writer.join().expect("a writer ends");
        }
        let since = owner.since(0);
        assert!(!since.resync);
        assert_eq!(
            revisions(&since),
            (1..=since.revision).collect::<Vec<_>>(),
            "one revision for each accepted change, with none missing"
        );
        assert_eq!(
            since.revision, 121,
            "the choice and every one of the 120 reasons"
        );
        for published in &since.states[1..] {
            // A whole snapshot: the reason and the loss belong to one accepted change.
            assert!(
                published
                    .connection
                    .reason
                    .as_deref()
                    .is_some_and(|reason| reason.starts_with("writer ")),
                "{published:?}"
            );
            assert!(matches!(
                published.contact,
                HostContact::OutOfContact { .. }
            ));
        }
    }

    #[tokio::test]
    async fn the_log_keeps_the_last_256_and_every_unemitted() {
        let owner = ContactOwner::new();
        let choice = owner.choose(&paired(1, 2), "reaching").value;
        for turn in 0..299 {
            drop(owner.failed(choice, None, Outcome::Lost, &format!("turn {turn}")));
        }
        assert_eq!(owner.revision(), 300);
        assert_eq!(
            owner.since(0).states.len(),
            300,
            "none is told, so none is dropped"
        );
        told_all(&owner);
        let kept = owner.since(44);
        assert_eq!(revisions(&kept).first(), Some(&45));
        assert_eq!(kept.states.len(), 256, "the last 256 stay");
    }

    #[tokio::test]
    async fn since_answers_the_missed_in_order_and_resyncs_behind_the_log() {
        let owner = ContactOwner::new();
        let choice = owner.choose(&paired(1, 2), "reaching").value;
        for turn in 0..299 {
            drop(owner.failed(choice, None, Outcome::Lost, &format!("turn {turn}")));
        }
        told_all(&owner);
        let missed = owner.since(295);
        assert!(!missed.resync);
        assert_eq!(revisions(&missed), [296, 297, 298, 299, 300]);
        let behind = owner.since(3);
        assert!(behind.resync);
        assert_eq!(revisions(&behind), [300], "the whole current state alone");
        let ahead = owner.since(9_999);
        assert!(
            ahead.resync,
            "a page ahead of this owner takes its state as a new base"
        );
    }

    #[tokio::test]
    async fn since_answers_resync_only_when_after_plus_one_is_below_the_oldest() {
        let owner = ContactOwner::new();
        let choice = owner.choose(&paired(1, 2), "reaching").value;
        for turn in 0..299 {
            drop(owner.failed(choice, None, Outcome::Lost, &format!("turn {turn}")));
        }
        told_all(&owner);
        // The oldest kept is 45.
        assert!(owner.since(43).resync);
        let exact = owner.since(44);
        assert!(!exact.resync);
        assert_eq!(revisions(&exact).first(), Some(&45));
    }

    #[tokio::test]
    async fn the_event_the_snapshot_and_the_replay_each_carry_the_revision_in_json() {
        let owner = ContactOwner::new();
        drop(owner.choose(&paired(1, 2), "reaching"));
        let told = owner
            .next_unemitted()
            .expect("the change is waiting to be told");
        let event = serde_json::to_value(&*told).expect("the event");
        let snapshot = serde_json::to_value(owner.snapshot()).expect("the snapshot");
        let replay = serde_json::to_value(owner.since(0)).expect("the replay");
        assert_eq!(event["revision"], 1, "{event}");
        assert_eq!(snapshot["revision"], 1, "{snapshot}");
        assert_eq!(replay["states"][0]["revision"], 1, "{replay}");
        assert_eq!(event["contact"]["state"], "unknown", "{event}");
        assert_eq!(event["host"]["kind"], "paired", "{event}");
        assert_eq!(event["connected"], false, "{event}");
    }

    #[tokio::test]
    async fn choose_keeps_a_loss_and_resets_the_rest_and_clears_the_read() {
        let now = Arc::new(AtomicU64::new(1_000));
        let owner = owner_at(&now);
        let first = owner.choose(&paired(1, 2), "reaching").value;
        drop(owner.failed(first, None, Outcome::Lost, "no answer"));
        let (read, _) = connection(10);
        let (visit, _) = connection(11);
        owner.plant(host(1), read, visit);
        assert!(owner.holds_resources_of(host(1)));
        let epoch = owner.snapshot().inbox_epoch;

        now.store(5_000, Ordering::SeqCst);
        drop(owner.choose(&paired(5, 6), "another"));
        let left_behind = owner.snapshot();
        assert!(
            !owner.holds_resources_of(host(1)),
            "the read goes at a role change"
        );
        assert_eq!(left_behind.others.len(), 1);
        assert_eq!(
            left_behind.others[0].contact,
            HostContact::OutOfContact {
                since_ms: 1_000,
                escalates_at_ms: 1_000 + HOST_CONTACT_ESCALATION_MS
            },
            "a host left behind keeps its loss and the loss's start"
        );
        assert!(left_behind.others[0].inbox_epoch > epoch);
        assert_eq!(left_behind.contact, HostContact::Unknown);

        // The host that held a loss, chosen again, reads out of contact at once.
        drop(owner.choose(&paired(1, 2), "back"));
        assert_eq!(
            owner.snapshot().contact,
            HostContact::OutOfContact {
                since_ms: 1_000,
                escalates_at_ms: 1_000 + HOST_CONTACT_ESCALATION_MS
            }
        );
    }

    #[tokio::test]
    async fn a_choice_and_a_forget_start_no_loss() {
        let owner = ContactOwner::new();
        let choice = owner.choose(&paired(1, 2), "reaching").value;
        assert_eq!(choice, 1);
        drop(owner.choose(&paired(5, 6), "another"));
        assert!(owner.forget(host(5), "forgotten").value);
        assert!(!owner.forget(host(1), "forgotten").value);
        for published in &owner.since(0).states {
            assert!(
                !matches!(published.contact, HostContact::OutOfContact { .. })
                    && published.others.is_empty(),
                "a choice and a forget are no loss: {published:?}"
            );
        }
    }

    #[tokio::test]
    async fn choose_with_another_pairing_makes_a_new_generation_and_disposes_the_old_resources() {
        let owner = ContactOwner::new();
        drop(owner.choose(&paired(1, 2), "reaching"));
        let generation = owner.generation_of(host(1)).expect("a record");
        let (read, read_session) = connection(10);
        let (visit, _) = connection(11);
        owner.plant(host(1), read, visit);
        drop(owner.choose(&paired(1, 2), "again"));
        assert_eq!(
            owner.generation_of(host(1)),
            Some(generation),
            "the same pairing"
        );
        owner.plant(host(1), connection(12).0, connection(13).0);
        let _ = read_session;
        drop(owner.choose(&paired(1, 3), "paired again"));
        assert!(owner.generation_of(host(1)).expect("a record") > generation);
        assert!(!owner.holds_resources_of(host(1)));
    }

    #[tokio::test]
    async fn forget_advances_the_fence_with_no_record() {
        let owner = ContactOwner::new();
        let before = owner.fence();
        let forgotten = owner.forget(host(7), "forgotten");
        assert!(!forgotten.value);
        assert_eq!(owner.fence(), before + 1);
        assert_eq!(forgotten.revision, 0, "nothing the page sees changed");
    }

    #[tokio::test]
    async fn epochs_stay_above_held_ones_across_forget_and_repair() {
        let owner = ContactOwner::new();
        drop(owner.choose(&paired(1, 2), "reaching"));
        let held = owner.snapshot().inbox_epoch;
        assert!(owner.forget(host(1), "forgotten").value);
        drop(owner.choose(&paired(1, 3), "paired again"));
        assert!(owner.snapshot().inbox_epoch > held);
    }

    #[tokio::test]
    async fn the_classifier_types_every_unopened() {
        let refused = Unopened::Refused(Asked::HostInfo, CommandError::refused("no"));
        assert!(matches!(
            Outcome::of(&refused),
            Outcome::Refused {
                request: Asked::HostInfo,
                ..
            }
        ));
        for unopened in [Unopened::HostFull, Unopened::BudgetFull] {
            assert!(
                matches!(Outcome::of(&unopened), Outcome::Refused { .. }),
                "{unopened:?}"
            );
        }
        for unopened in [
            Unopened::NotAdmitted(HostWords::said("not admitted")),
            Unopened::unreached(NotReached::NoAnswerInTime),
        ] {
            assert_eq!(Outcome::of(&unopened), Outcome::Lost, "{unopened:?}");
        }
    }

    #[tokio::test]
    async fn a_never_reached_local_loss_reads_unknown() {
        let now = Arc::new(AtomicU64::new(2_000));
        let owner = owner_at(&now);
        let choice = owner.choose(&Target::Local, "reaching").value;
        drop(owner.failed(choice, None, refusal("refused"), "refused"));
        assert!(matches!(
            owner.snapshot().contact,
            HostContact::Refused { .. }
        ));
        drop(owner.failed(choice, None, Outcome::Lost, "absent"));
        assert_eq!(
            owner.snapshot().contact,
            HostContact::Unknown,
            "a host never reached is not lost, and a loss clears a refusal"
        );
        let (held, _) = connection(1);
        let reached = owner.reached(choice, None, held);
        assert!(matches!(reached.value, Reach::Reached));
        assert_eq!(owner.snapshot().contact, HostContact::InContact);
        drop(reached);
        now.store(3_000, Ordering::SeqCst);
        let session = owner.held().expect("held").session();
        drop(owner.ended(&session, Outcome::Lost, "ended"));
        assert_eq!(
            owner.snapshot().contact,
            HostContact::OutOfContact {
                since_ms: 3_000,
                escalates_at_ms: 3_000 + HOST_CONTACT_ESCALATION_MS
            },
            "once reached, the end of the connection is a loss from that moment"
        );
    }

    #[tokio::test]
    async fn adopt_answers_a_candidate_without_testing_liveness() {
        let owner = ContactOwner::new();
        let (choice, withdrawn, _) = reaching(&owner, 1);
        let (fresh, _) = connection(2);
        // The replacement has ended before the keeper is asked.
        fresh.session().close();
        let events = fresh.session().events();
        let applied = owner.replaced(&withdrawn, fresh, events);
        let revision = applied.revision;
        drop(applied);
        match owner.adopt(choice, Some(&withdrawn)) {
            Adopt::Candidate {
                revision: adopted, ..
            } => assert_eq!(
                adopted, revision,
                "the revision the replacement was published as"
            ),
            Adopt::None | Adopt::Stale => panic!("an ended replacement is still a candidate"),
        }
        assert!(
            matches!(owner.adopt(choice, Some(&withdrawn)), Adopt::None),
            "an adoption is taken once"
        );
    }

    #[tokio::test]
    async fn adopt_answers_none_for_the_session_held_and_stale_for_another_choice() {
        let owner = ContactOwner::new();
        let (choice, held, _) = reaching(&owner, 1);
        assert!(matches!(owner.adopt(choice, Some(&held)), Adopt::None));
        assert!(matches!(owner.adopt(choice + 1, Some(&held)), Adopt::Stale));
        drop(owner.ended(&held, Outcome::Lost, "ended"));
        assert!(matches!(owner.adopt(choice, Some(&held)), Adopt::None));
    }

    #[tokio::test]
    async fn a_second_replacement_before_adoption_returns_the_old_adoption() {
        let owner = ContactOwner::new();
        let (choice, first, _) = reaching(&owner, 1);
        let (two, _) = connection(2);
        let (three, _) = connection(3);
        let second = two.session();
        let events = two.session().events();
        drop(owner.replaced(&first, two, events));
        let events = three.session().events();
        let applied = owner.replaced(&second, three, events);
        assert_eq!(
            applied.disposal.adoptions.len(),
            1,
            "the adoption the second replacement overwrote comes back to be released"
        );
        let revision = applied.revision;
        drop(applied);
        match owner.adopt(choice, Some(&second)) {
            Adopt::Candidate {
                revision: adopted, ..
            } => assert_eq!(adopted, revision),
            Adopt::None | Adopt::Stale => panic!("the second replacement is the candidate"),
        }
    }

    #[tokio::test]
    async fn a_task_started_by_a_choice_finds_its_choice_current() {
        let state = AppState::new();
        let owner = Arc::clone(state.contact_owner());
        let found = Arc::new(AtomicBool::new(false));
        let seen = Arc::clone(&found);
        state
            .choose_host("reaching", move || {
                Ok(crate::state::Started {
                    target: Target::Local,
                    spawn: Box::new(move |choice| {
                        // The task begins after the owner accepted the choice.
                        seen.store(
                            !matches!(owner.adopt(choice, None), Adopt::Stale),
                            Ordering::SeqCst,
                        );
                        tauri::async_runtime::spawn(async {})
                    }),
                })
            })
            .expect("the choice is made");
        assert!(found.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn a_choice_whose_start_fails_changes_nothing() {
        let state = AppState::new();
        let before = state.connection_state();
        let refused = state.choose_host("reaching", || {
            Err(CommandError::local_failure("the choice could not be kept"))
        });
        assert!(refused.is_err());
        assert_eq!(state.connection_state(), before);
        assert_eq!(state.contact_owner().revision(), before.revision);
    }

    #[tokio::test]
    async fn a_kept_not_admitted_lease_stop_reads_lost() {
        use kr_client::organisation::LeaseStop;
        use kr_protocol::error::ErrorCode;

        // The same stop of the lease, as it reads with no refusal kept and with one the host sent.
        let stopped = LeaseStop::SignIn;
        let plain = connection(40).0.session();
        assert!(
            matches!(
                crate::connection::lease_stop_outcome(&plain, &stopped),
                Outcome::Refused { .. }
            ),
            "a lease that could not be given is a refusal in its words"
        );
        let not_admitted = refused_session(ErrorCode::PermissionDenied).await;
        assert!(
            matches!(
                crate::connection::lease_stop_outcome(&not_admitted, &stopped),
                Outcome::Lost
            ),
            "a connection the host did not admit is a loss, whatever the lease says"
        );
        let full = refused_session(ErrorCode::ResourceUnavailable).await;
        let Outcome::Refused { refusal, request } =
            crate::connection::lease_stop_outcome(&full, &stopped)
        else {
            panic!("a host with no room is a refusal of the connection");
        };
        assert_eq!(request, Asked::Connection);
        assert_eq!(refusal.message, crate::places::host_full_error().message);
    }

    /// Sets a flag when it is dropped.
    struct EndedFlag(Arc<AtomicBool>);

    impl Drop for EndedFlag {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    /// A task that never ends by itself, and the flag that says it was ended.
    fn endless_task() -> (tauri::async_runtime::JoinHandle<()>, Arc<AtomicBool>) {
        let ended = Arc::new(AtomicBool::new(false));
        let flag = EndedFlag(Arc::clone(&ended));
        let task = tauri::async_runtime::spawn(async move {
            let _flag = flag;
            std::future::pending::<()>().await;
        });
        (task, ended)
    }

    /// Whether `ended` is set within five seconds.
    async fn ended_soon(ended: &AtomicBool) -> bool {
        for _ in 0..500 {
            if ended.load(Ordering::SeqCst) {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        ended.load(Ordering::SeqCst)
    }

    #[tokio::test]
    async fn a_second_task_for_one_choice_is_returned_to_be_ended() {
        let owner = ContactOwner::new();
        let choice = owner.choose(&Target::Local, "reaching").value;
        let (first, first_ended) = endless_task();
        drop(owner.set_task(choice, first));
        let (second, second_ended) = endless_task();
        let mut returned = None;
        let counted = dropped_under_the_guard(|| {
            returned = Some(owner.set_task(choice, second));
        });
        assert_eq!(
            counted, 0,
            "the replaced handle is not dropped under the guard"
        );
        drop(returned);
        assert!(
            ended_soon(&first_ended).await,
            "the first task is ended when what the second one replaced is released"
        );
        assert!(
            !second_ended.load(Ordering::SeqCst),
            "the second task is the choice's task and keeps running"
        );
        // The next choice ends it.
        drop(owner.choose(&paired(1, 2), "another"));
        assert!(
            ended_soon(&second_ended).await,
            "the next choice ends the task it replaces"
        );
    }

    #[tokio::test]
    async fn the_readers_answer_the_owners_slot() {
        let state = AppState::new();
        assert!(state.session().is_err());
        let (held, _) = connection(1);
        let session = held.session();
        state.connected(held);
        let Ok(found) = state.session() else {
            panic!("the connection installed is the one held");
        };
        assert!(Arc::ptr_eq(&found, &session));
        assert_eq!(
            state.connection().expect("a connection").environment_id(),
            state.environment_id().expect("an environment")
        );
        drop(
            state
                .contact_owner()
                .ended(&session, Outcome::Lost, "ended"),
        );
        let Err(refused) = state.session() else {
            panic!("nothing is held once the connection has ended");
        };
        assert_eq!(refused.message, CommandError::not_connected().message);
    }

    /// Runs `scenario` and counts what it dropped under the guard.
    fn dropped_under_the_guard(scenario: impl FnOnce()) -> u64 {
        let before = testing::dropped_under_the_guard();
        scenario();
        testing::dropped_under_the_guard() - before
    }

    #[tokio::test]
    async fn the_detector_counts_a_drop_under_the_guard() {
        let owner = ContactOwner::new();
        let counted = dropped_under_the_guard(|| {
            let guard = owner.lock();
            drop(Held::new(1_u8));
            drop(guard);
            drop(Held::new(2_u8));
        });
        assert_eq!(
            counted, 1,
            "the drop under the guard counts, the one after it does not"
        );
    }

    #[tokio::test]
    async fn every_removed_cleared_or_rejected_resource_is_dropped_after_the_guard_is_released() {
        // E1: the old slot, adoption, task and the host's read and retained connection.
        let counted = dropped_under_the_guard(|| {
            let owner = ContactOwner::new();
            drop(owner.choose(&paired(1, 2), "reaching"));
            owner.plant(host(1), connection(10).0, connection(11).0);
            owner.plant_adoption(connection(12).0.session().events());
            drop(owner.install(connection(13).0));
            let task = tauri::async_runtime::spawn(async {});
            drop(owner.set_task(1, task));
            drop(owner.choose(&paired(5, 6), "another"));
            owner.plant(host(5), connection(14).0, connection(15).0);
            // A record of another pairing is a new record, whose old read and visit are released.
            drop(owner.choose(&paired(5, 7), "paired again"));
        });
        assert_eq!(counted, 0, "E1");

        // E2: the slot, the task, the removed record's read and the adoption.
        let counted = dropped_under_the_guard(|| {
            let owner = ContactOwner::new();
            drop(owner.choose(&paired(1, 2), "reaching"));
            owner.plant(host(1), connection(10).0, connection(11).0);
            owner.plant_adoption(connection(12).0.session().events());
            drop(owner.install(connection(13).0));
            drop(owner.set_task(1, tauri::async_runtime::spawn(async {})));
            drop(owner.forget(host(1), "forgotten"));
        });
        assert_eq!(counted, 0, "E2");

        // E3 and E4: the replaced slot, and a rejected connection.
        let counted = dropped_under_the_guard(|| {
            let owner = ContactOwner::new();
            let (choice, session, _) = reaching(&owner, 1);
            drop(owner.reached(choice, Some(&session), connection(2).0));
            drop(owner.reached(choice + 1, None, connection(3).0));
            drop(owner.reached(choice, None, connection(4).0));
            drop(owner.failed(
                choice,
                owner.held().map(|each| each.session()).as_ref(),
                Outcome::Lost,
                "no",
            ));
        });
        assert_eq!(counted, 0, "E3 and E4");

        // E5 and E6: the removed slot.
        let counted = dropped_under_the_guard(|| {
            let owner = ContactOwner::new();
            let (choice, session, _) = reaching(&owner, 1);
            drop(owner.lease_stopped(choice, &session, Outcome::Lost, "stopped"));
            let (choice, session, _) = reaching(&owner, 2);
            let _ = choice;
            drop(owner.ended(&session, Outcome::Lost, "ended"));
        });
        assert_eq!(counted, 0, "E5 and E6");

        // E7: the complete old connection, the replaced adoption, and a rejected replacement.
        let counted = dropped_under_the_guard(|| {
            let owner = ContactOwner::new();
            let (_, first, _) = reaching(&owner, 1);
            owner.plant_adoption(connection(20).0.session().events());
            let (two, _) = connection(2);
            let second = two.session();
            let events = two.session().events();
            drop(owner.replaced(&first, two, events));
            let (three, _) = connection(3);
            let events = three.session().events();
            drop(owner.replaced(&second, three, events));
            // A replacement of a connection that is not held is rejected, and given back.
            let (four, _) = connection(4);
            let events = four.session().events();
            drop(owner.replaced(&first, four, events));
        });
        assert_eq!(counted, 0, "E7");

        // E7b: the adoption's receiver moves to the keeper.
        let counted = dropped_under_the_guard(|| {
            let owner = ContactOwner::new();
            let (choice, first, _) = reaching(&owner, 1);
            let (two, _) = connection(2);
            let events = two.session().events();
            drop(owner.replaced(&first, two, events));
            let adopted = owner.adopt(choice, Some(&first));
            assert!(matches!(adopted, Adopt::Candidate { .. }));
            drop(adopted);
        });
        assert_eq!(counted, 0, "E7b");
    }
}
