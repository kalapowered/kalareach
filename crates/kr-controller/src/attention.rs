//! The environment's attention store, hosted by the control daemon.
//!
//! One store holds the attention inbox, the review state and the visits of every session this
//! environment runs. It lives here because it has to outlive every session: completed work waiting
//! for review stays after the session that produced it has ended, and a paired device reads one
//! inbox rather than one per session. A session's own records stay in its journal. The store reads
//! them through a connection of its own to each live session's worker, declared for this purpose,
//! and from a closed session's journal once the session has ended.
//!
//! # Reading a session
//!
//! For every live session a link holds one request for the records past the store's cursors; the
//! worker answers it as soon as it commits a question transition, a host event or a privacy
//! transition, and after a bounded wait otherwise. A page that reached the head of both sources
//! certifies everything the session committed before the moment it was read, and a timer of that
//! session is decided only up to that moment: an answer on a page the store has not read never
//! becomes a reminder. A link that stops certifies nothing, and its session's timers wait.
//!
//! # A session that ends
//!
//! Once this daemon records a session's closure, the store reads what is left of its sources from
//! the journal and then ends the session's live conditions: a pending approval or question and its
//! reminder leave the inbox as ended, never as answered, and review work stays. A closure written
//! over a worker this host could not confirm had ended opens nothing: its sources are marked as
//! gaps with no known end and its items stay, uncertain.
//!
//! # The workflow journal's alerts
//!
//! The environment's own source is the workflow journal's attention records: a workflow revision or
//! a causal chain that one of its own limits paused, and a revision enabled again. The store reads
//! them as the journal's registered attention consumer. Each pass registers, reads the records past
//! the store's own cursor, commits what they raise or end, and only then tells the journal how far
//! the store has read, so a daemon that stops between the two neither loses a record nor counts one
//! twice. A journal that says the store has read further than the store's cursor holds is a store
//! that lost what it had written: what the journal still keeps of that range is read again and the
//! whole range is recorded as a gap, in one write.
//!
//! # Text
//!
//! The store keeps none of a session's text. A read that serves text asks the record's owner for
//! it when it serves the page: the live worker over its link, or the closed session's journal. A
//! paired device is served the host's own words and no session text.
//!
//! # The privacy fence
//!
//! Once a session commits a privacy generation that enables privacy mode, no text it answered with
//! under an earlier generation may leave this daemon, however long a read has been holding it.
//! Every live answer carries the generation it was decided under and the end of its release
//! lease, and a response carries a ticket of them. The text is released, one transport write at a
//! time, only while its session's latest statement says no transition is in progress, its
//! generation is the one recorded for the session, and its lease has the margin left; the check
//! runs before every write under a lock that applying a statement takes exclusively, so once a
//! statement raising a transition is acknowledged no release of that session's text is under way.
//! A worker that hears nothing back waits out its leases before it commits instead.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use kr_attention::host::{ActionKey, Answer as Answered, Mutation, Performed};
use kr_attention::{
    Attention, Claimant, Content, DeviceScope, EventCursor, EventKind, HostReading, Liveness,
    Origin, SourceEvent, Text, Viewer,
};
use kr_automation::store::{ATTENTION_CONSUMER, ATTENTION_EVENTS};
use kr_automation::{AttentionOutboxRecord, AttentionSubject, JournalEvent, WorkflowStore};
use kr_ipc::client::LocalClient;
use kr_ipc::framed::CheckedWrite;
use kr_protocol::attention::ChangeSummary;
use kr_protocol::attention::{
    AttentionAcknowledgeParams, AttentionAutomationSubject, AttentionBarrier,
    AttentionBarrierAcknowledged, AttentionHostRecord, AttentionQuestionRecord,
    AttentionQuietHoursParams, AttentionQuietHoursResult, AttentionReadParams, AttentionRecordRef,
    AttentionSource, AttentionSourcePage, AttentionSourcesRequest, AttentionTextRequest,
    MAX_ATTENTION_SOURCE_RECORDS, MAX_ATTENTION_SOURCE_WAIT_MS, MAX_ATTENTION_TEXT_RECORDS,
    MAX_LOG_VIEW_FILTER_LEN, MAX_LOG_VIEW_ID_LEN, MAX_RETAINED_LOG_VIEWS, ReviewAcknowledgeParams,
    ReviewReadParams, ReviewReadResult, ReviewSubject, VisitAcknowledgeParams, VisitChangedParams,
};
use kr_protocol::envelope::{
    ControlFrame, MutationRequest, Outcome, ParamsValue, Request, Response,
};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::ids::{ActorId, GrantId, RequestId, SessionId};
use kr_protocol::method::{Method, MethodGroup};
use kr_protocol::question::QuestionEventKind;
use kr_protocol::scalars::{Nullable, SecretBytes32, TimestampMs, U64};

use crate::directory::KnownWorker;
use crate::error::{ControllerError, Result};

/// What one answer of a method in this group is.
pub type Answer<T> = std::result::Result<T, ProtocolError>;

/// The longest a link waits for a page beyond the wait it asked the worker to hold.
const PAGE_GRACE: Duration = Duration::from_secs(15);

/// The longest a read waits for a live session's text.
///
/// It is headroom inside a text's release lease: a read that waited its whole bound normally still
/// holds its answers inside their release windows, though scheduling or a slow reader can use that
/// up, and the check before each write is what decides.
const TEXT_WAIT: Duration = Duration::from_secs(3);

/// How long before its lease ends a text stops being released: the time allowed between one
/// reading of the clock and the one transport write it admits.
const RELEASE_MARGIN_MS: u64 = 1_000;

/// The longest an acknowledgement of a worker's statement waits for the link's writer and its
/// write.
const ACKNOWLEDGEMENT_WAIT: Duration = Duration::from_secs(2);

/// The longest a connection to a worker takes to be made, verified and declared.
const CONNECT_WAIT: Duration = Duration::from_secs(10);

/// How soon a closed session the store could not finish is tried again.
const CLOSURE_RETRY: Duration = Duration::from_secs(5);

/// How often the records of expired actions are let go of.
const FORGET_EVERY_MS: u64 = 60 * 60 * 1_000;

/// The first wait before a link that failed is opened again, doubled up to [`MAX_RELINK`].
const FIRST_RELINK: Duration = Duration::from_millis(500);

/// The longest wait before a link that failed is opened again.
const MAX_RELINK: Duration = Duration::from_secs(30);

/// How often the store is looked at when no timer is due sooner.
const MAINTENANCE: Duration = Duration::from_secs(60);

/// How soon the maintenance loop reads the host's clock again while the host owes its record
/// something decided about it.
///
/// A reading writes what is owed before it answers, and without a request the next reading is the
/// loop's own: the first reading that finds a write owed wakes the loop, and while the host owes
/// anything it comes back this soon.
const CLOCK_WRITE_RETRY: Duration = Duration::from_secs(5);

/// How long the record of an action is kept, after which a repeat is a new request.
const ACTION_RETENTION_MS: u64 = 30 * 24 * 60 * 60 * 1_000;

/// The records one page asks for from each source.
const PAGE_RECORDS: u64 = MAX_ATTENTION_SOURCE_RECORDS;

/// A time-zone name a quiet-hours window records, in bytes.
const MAX_ZONE_LEN: usize = 128;

/// The largest number this store writes down exactly.
const MAX_STORED_COUNTER: u64 = i64::MAX as u64;

/// How often the workflow journal is read for its attention records.
///
/// The automation service wakes one waiter when a run stops, and that is its trigger dispatcher, so
/// the store reads on a cadence of its own, the same as the dispatcher's.
const AUTOMATION_EVERY: Duration = Duration::from_secs(2);

/// The workflow journal's attention records one read takes.
const AUTOMATION_PAGE: usize = 256;

/// Who is asking, in a form that can travel to a task of its own.
#[derive(Clone, Debug)]
pub enum Caller {
    /// The owner at this machine, on the daemon's own socket, who sees everything.
    Owner,
    /// A paired device, which sees what its grant admits.
    Device {
        /// The grant the device holds.
        grant_id: GrantId,
        /// Whether the grant carries `session.view`.
        session_view: bool,
        /// Whether the grant carries `automation.manage`.
        automation_manage: bool,
        /// Whether the grant carries `host.manage`.
        host_manage: bool,
        /// The sessions the grant's selector admits.
        sessions: kr_protocol::grant::SessionSelector,
        /// How far back the grant's history reaches: the moment it starts at, when it has one. A
        /// grant with no lower bound retains no history.
        history_lower_bound_ms: Option<TimestampMs>,
    },
}

impl Caller {
    /// Builds the caller a paired device's grant describes.
    #[must_use]
    pub fn device(grant: &kr_protocol::grant::Grant) -> Self {
        Self::Device {
            grant_id: grant.grant_id,
            session_view: grant.permits(kr_protocol::rights::ActionRight::SessionView),
            automation_manage: grant.permits(kr_protocol::rights::ActionRight::AutomationManage),
            host_manage: grant.permits(kr_protocol::rights::ActionRight::HostManage),
            sessions: grant.session_selector.clone(),
            history_lower_bound_ms: grant.history.lower_bound_ms.0,
        }
    }

    /// Whether this caller's authority reaches back to a moment in a session's history: the
    /// owner's always does, and a paired device's does when its grant's history starts at or before
    /// it. A grant with no lower bound retains no history and reaches none.
    ///
    /// A summary is written from every change in an interval and says things about all of them, so
    /// it is served only to a caller that reaches back to the earliest of them.
    #[must_use]
    pub fn reaches_back_to(&self, at_ms: u64) -> bool {
        match self {
            Self::Owner => true,
            Self::Device {
                history_lower_bound_ms,
                ..
            } => history_lower_bound_ms.is_some_and(|bound| bound.get() <= at_ms),
        }
    }

    /// How much of a session's content this caller is served.
    ///
    /// A paired device is served the host's own words and no session text: a grant's history
    /// scope is not yet something the store can narrow a record's text to.
    #[must_use]
    pub const fn content(&self) -> Content {
        match self {
            Self::Owner => Content::Whole,
            Self::Device { .. } => Content::Narrowed,
        }
    }

    /// Runs `with` with the store's view of this caller.
    fn view<T>(&self, with: impl FnOnce(&Viewer<'_>) -> T) -> T {
        match self {
            Self::Owner => with(&Viewer::Owner),
            Self::Device {
                grant_id,
                session_view,
                automation_manage,
                host_manage,
                sessions,
                history_lower_bound_ms: _,
            } => {
                let admits = |session_id: SessionId| sessions.admits(session_id);
                with(&Viewer::Device(DeviceScope {
                    grant_id: *grant_id,
                    session_view: *session_view,
                    automation_manage: *automation_manage,
                    host_manage: *host_manage,
                    admits_session: &admits,
                }))
            }
        }
    }
}

/// How the daemon reaches one session's worker for its attention link.
pub trait Reach: Send + Sync {
    /// Opens a connection to the worker, verified and declared for attention, speaking for this
    /// daemon's generation.
    fn connect<'a>(
        &'a self,
        worker: &'a KnownWorker,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<LocalClient>> + Send + 'a>>;

    /// Answers whether the closure this host recorded for a session leaves a worker it could not
    /// account for: one written over a death this host did not confirm. A closure it cannot read
    /// is answered the same way.
    fn unaccounted<'a>(
        &'a self,
        session_id: SessionId,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + 'a>>;

    /// Returns the journal of a closed session, brought to the schema this build reads, when it
    /// can be opened.
    fn closed_journal(&self, session_id: SessionId) -> Option<kr_worker::journal::Journal>;

    /// Returns the oldest output position a closed session's spool still retains, when it can be
    /// read.
    fn output_floor(&self, session_id: SessionId) -> Option<u64>;
}

/// The worker one session is reached at.
struct Watched {
    /// The latest worker the daemon added for the session.
    worker: KnownWorker,
    /// Counts the workers named for the session, so a connection made to an earlier one is known
    /// for what it is.
    revision: u64,
    /// Told when a newer worker is named, so a connection still being made to the one before it
    /// is given up.
    replaced: Arc<tokio::sync::Notify>,
}

/// What the module knows about each session it reads.
#[derive(Default)]
struct Origins {
    /// The live link to each session's worker.
    links: BTreeMap<SessionId, Arc<Link>>,
    /// The sessions a link is being kept open for.
    watched: BTreeSet<SessionId>,
    /// The worker each of those sessions is reached at.
    workers: BTreeMap<SessionId, Watched>,
    /// Each live session's latest certificate: the moment of its latest page that reached the
    /// head of both sources.
    certified: BTreeMap<SessionId, u64>,
    /// The environment's latest certificate: the moment of its latest read that reached the end of
    /// the workflow journal's attention records.
    environment_certified: Option<u64>,
    /// Each live session's oldest retained output position, from its latest page.
    output_floor: BTreeMap<SessionId, u64>,
    /// Sessions whose closure this daemon recorded and whose journals are being read to the end.
    closing: BTreeSet<SessionId>,
    /// Sessions closed over a worker this host could not confirm had ended.
    unaccounted: BTreeSet<SessionId>,
    /// Sessions whose closure this daemon has begun and not finished: from the moment their link
    /// is dropped, before anything is awaited, until the store has finished them.
    ended: BTreeSet<SessionId>,
    /// Closed sessions the store could not finish yet, which the maintenance loop tries again.
    unfinished: BTreeSet<SessionId>,
}

/// How far the store has read each origin, as a timer pass is told it: the moment up to which it
/// has read every record the origin committed.
#[derive(Clone, Debug, Default)]
struct Certificates {
    /// Each live session's.
    sessions: BTreeMap<SessionId, u64>,
    /// The environment's.
    environment: Option<u64>,
}

impl Certificates {
    fn of(origins: &Origins) -> Self {
        Self {
            sessions: origins.certified.clone(),
            environment: origins.environment_certified,
        }
    }

    fn at(&self, origin: &Origin) -> Option<u64> {
        match origin {
            Origin::Session(session_id) => self.sessions.get(session_id).copied(),
            Origin::Environment => self.environment,
        }
    }
}

/// What this daemon knows of one session's privacy fence.
#[derive(Clone, Copy, Debug, Default)]
struct SessionFence {
    /// The greatest privacy generation seen for the session, on a statement, a page or a text
    /// answer.
    recorded: Option<u64>,
    /// Whether the latest statement applied from the session's worker says a transition is in
    /// progress.
    barrier: bool,
    /// Whether the session was closed over a worker the host could not confirm had ended. Such a
    /// worker may still be running and changing its privacy state where this daemon cannot see
    /// it, so nothing it answered is released after the closure is recorded.
    unaccounted: bool,
}

/// What must still hold for a response's session text to be released.
///
/// One entry for each live answer the response holds text from. Text read from a finished
/// session's journal needs none: no transition can follow the closure. A response that carries
/// text a model wrote also holds the privacy state that text was decided under.
#[derive(Clone, Debug, Default)]
pub struct Ticket {
    entries: Vec<TicketEntry>,
    generated: Option<Generated>,
}

/// Text a model wrote that a response carries, and the privacy state it was read under.
///
/// Privacy mode removes what a model wrote of a session at the moment it is enabled, so the text is
/// released only while the state is the one it was read under: not private, and in the same
/// generation. The worker's own fence says nothing of it, since the daemon holds this text and
/// the worker did not answer it.
#[derive(Clone, Debug)]
pub(crate) struct Generated {
    state: crate::privacy::PrivacyState,
    decided: crate::privacy::Published,
}

impl Generated {
    /// Text a model wrote, read while `state` said `decided`.
    pub(crate) const fn read_under(
        state: crate::privacy::PrivacyState,
        decided: crate::privacy::Published,
    ) -> Self {
        Self { state, decided }
    }
}

/// The privacy state a response's generated text is released under, held for as long as a write
/// of it is made: privacy mode cannot be published in between.
struct Standing<'a> {
    _reading: Option<crate::privacy::Reading<'a>>,
}

#[derive(Clone, Copy, Debug)]
struct TicketEntry {
    session_id: SessionId,
    /// The generation the answer was decided under.
    generation: Option<u64>,
    /// When the answer's lease ends, on the machine's continuous clock.
    release_until: u64,
}

impl Ticket {
    /// Returns the privacy generation the text read from one session's worker was decided under:
    /// none when no text was read, and an error when a worker did not say which, or answered under
    /// more than one, so that nothing can be said of the text's generation.
    fn generation_of(
        &self,
        session_id: SessionId,
    ) -> std::result::Result<Option<kr_worker::privacy::PrivacyGeneration>, ()> {
        let mut found: Option<u64> = None;
        for entry in self
            .entries
            .iter()
            .filter(|entry| entry.session_id == session_id)
        {
            let generation = entry.generation.ok_or(())?;
            if found.is_some_and(|earlier| earlier != generation) {
                return Err(());
            }
            found = Some(generation);
        }
        Ok(found.map(kr_worker::privacy::PrivacyGeneration::new))
    }

    /// A ticket for a response whose only text is text a model wrote, read under `generated`.
    pub(crate) fn of_generated(generated: Generated) -> Self {
        Self {
            entries: Vec::new(),
            generated: Some(generated),
        }
    }

    /// Returns true when the ticket names no text that needs a check.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty() && self.generated.is_none()
    }

    /// Takes the privacy state the generated text was read under, and none when it has moved or is
    /// moving. It waits for nothing. A ticket with no generated text stands on nothing.
    fn standing(&self) -> Option<Standing<'_>> {
        let Some(generated) = &self.generated else {
            return Some(Standing { _reading: None });
        };
        generated
            .state
            .try_reading()
            .filter(|reading| reading.published() == generated.decided)
            .map(|reading| Standing {
                _reading: Some(reading),
            })
    }

    /// Answers whether everything the ticket names may be released at `now`: the privacy state its
    /// generated text was read under stands, and its session text may be released
    /// ([`Self::holds_text`]).
    fn holds(&self, fences: &BTreeMap<SessionId, SessionFence>, now: u64) -> bool {
        self.standing().is_some() && self.holds_text(fences, now)
    }

    /// Answers whether every session text the ticket names may be released at `now`: its session's
    /// barrier is lowered, the session was not closed over a worker the host could not account
    /// for, the generation its answer was decided under is the one recorded, and its lease has more
    /// than the margin left.
    fn holds_text(&self, fences: &BTreeMap<SessionId, SessionFence>, now: u64) -> bool {
        self.entries.iter().all(|entry| {
            let fence = fences.get(&entry.session_id).copied().unwrap_or_default();
            !fence.barrier
                && !fence.unaccounted
                && entry.generation.is_some()
                && fence.recorded == entry.generation
                && now.saturating_add(RELEASE_MARGIN_MS) < entry.release_until
        })
    }
}

/// One read of this group's answer, ready to be released to the reader who asked.
#[derive(Debug)]
pub struct Released {
    /// The answer, with the session text it carries.
    frame: ControlFrame,
    /// The same answer with all of that text withheld, when it carries any.
    withheld: Option<ControlFrame>,
    /// What must still hold for that text to be released.
    ticket: Ticket,
}

impl Released {
    /// The answer to the request `request_id` that a read came to, with what releasing it takes.
    pub(crate) fn of(request_id: RequestId, read: Answer<Read>) -> Self {
        match read {
            Ok(Read {
                value,
                text: Some((withheld, ticket)),
            }) => Self {
                frame: frame(request_id, Ok(value)),
                withheld: Some(frame(request_id, Ok(withheld))),
                ticket,
            },
            Ok(Read { value, text: None }) => Self {
                frame: frame(request_id, Ok(value)),
                withheld: None,
                ticket: Ticket::default(),
            },
            Err(error) => Self {
                frame: frame(request_id, Err(error)),
                withheld: None,
                ticket: Ticket::default(),
            },
        }
    }
}

/// A read's answer, with what it takes to release it.
pub(crate) struct Read {
    /// The answer, with any session text it carries.
    value: ParamsValue,
    /// When it carries live session text or text a model wrote: the same answer with that text
    /// withheld, and the ticket its release is bound by.
    text: Option<(ParamsValue, Ticket)>,
}

impl Read {
    /// An answer that carries no live session text.
    pub(crate) const fn plain(value: ParamsValue) -> Self {
        Self { value, text: None }
    }

    /// An answer whose live session text, if it carries any, is released under `ticket`.
    pub(crate) fn with(value: ParamsValue, withheld: ParamsValue, ticket: Ticket) -> Self {
        if ticket.is_empty() {
            return Self::plain(value);
        }
        Self {
            value,
            text: Some((withheld, ticket)),
        }
    }
}

/// A point in this module's work that a test can stop it at: the work says it has arrived and
/// waits there until the test lets it go. Armed once, it fires once.
#[cfg(any(test, feature = "testing"))]
#[derive(Debug, Default)]
pub(crate) struct Pause(
    std::sync::Mutex<
        Option<(
            std::sync::mpsc::SyncSender<()>,
            std::sync::mpsc::Receiver<()>,
        )>,
    >,
);

#[cfg(any(test, feature = "testing"))]
impl Pause {
    /// Arms the pause. Returns the end that says the work has arrived, and the end that lets it go.
    pub(crate) fn arm(
        &self,
    ) -> (
        std::sync::mpsc::Receiver<()>,
        std::sync::mpsc::SyncSender<()>,
    ) {
        let (arrived, watch) = std::sync::mpsc::sync_channel(1);
        let (release, go) = std::sync::mpsc::sync_channel(1);
        *self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some((arrived, go));
        (watch, release)
    }

    /// Waits here when the pause is armed.
    pub(crate) fn wait(&self) {
        let armed = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some((arrived, go)) = armed {
            let _ = arrived.send(());
            let _ = go.recv();
        }
    }
}

/// What the attention store asks of the host about its wall clock.
///
/// The host's one decision about the clock answers it, so the store withholds quiet hours and
/// forgets action records on the same clock every other collection of the host forgets on: a
/// rollback any of them finds is found for all, and one owner's retrust frees all.
pub(crate) trait HostClock: Send + Sync {
    /// One reading of the wall clock, and whether it proves what the store uses it for.
    /// `platform_qualified` is whether the platform's time service qualified at this reading.
    /// `None` when the host cannot answer, which the store reads as unproven.
    fn watch(&self, platform_qualified: bool) -> Option<crate::service::net::clock_trust::Watched>;

    /// Whether the host lets a record whose retention is counted from `reading_ms` be forgotten:
    /// the one check every collection passes.
    fn may_forget_at(&self, reading_ms: u64) -> bool;
}

/// The environment's attention store, as the daemon holds it.
pub struct AttentionModule {
    /// Each session's privacy fence, and the lock every release of session text is made under:
    /// held shared for one checked write, and exclusively to apply a statement or move a recorded
    /// generation. Its queue is fair, so an exclusive request stops new shared admissions and waits
    /// only for the holders admitted before it.
    release: tokio::sync::RwLock<BTreeMap<SessionId, SessionFence>>,
    store: std::sync::Mutex<Attention>,
    /// The host's one decision about its wall clock, which every reading of the store goes
    /// through, once the daemon has attached it. Until it has, the store reads the wall clock as
    /// unproven and forgets nothing.
    clock: std::sync::OnceLock<Arc<dyn HostClock>>,
    /// The platform's time service, read at each reading: whether it qualifies is evidence the
    /// host's decision takes from here.
    adapter: Arc<dyn kr_worker::action::adapter::TimeAdapter>,
    /// This host's boot, as the store tells one boot's readings from another's.
    boot: kr_attention::time::BootMark,
    /// Set by a reading that found a write owed to the host's record and cleared by one that did
    /// not, so only the first wakes the maintenance loop.
    clock_owed: AtomicBool,
    origins: std::sync::Mutex<Origins>,
    /// Wakes the maintenance loop when a timer may have moved.
    wake: Arc<tokio::sync::Notify>,
    /// Held for the whole of one pass over the workflow journal, so the store is that journal's one
    /// reader whoever asks for a pass.
    automation_pass: std::sync::Mutex<()>,
    /// Set once the workflow journal is being read, so it is read by one loop.
    automation_started: std::sync::OnceLock<()>,
    /// The privacy state every announcement the store decides is stamped with, once the daemon has
    /// attached it.
    privacy: std::sync::OnceLock<crate::privacy::PrivacyState>,
    /// The session names and descriptions module, which keeps the summaries a read of what
    /// changed asks for, once the daemon has attached it.
    descriptions: std::sync::OnceLock<Arc<crate::describe::DescribeModule>>,
    /// Whether the last pass over the workflow journal stopped short, so a failure that persists is
    /// reported once rather than at every pass.
    automation_failing: AtomicBool,
    /// Where this host's own tests stop an action once its admission has been asked and stood,
    /// before it takes the store. Compiled away in every shipped build.
    #[cfg(feature = "testing")]
    before_store: Pause,
    /// Where this module's own tests stop a forgetting pass once the host has answered that it may
    /// forget, before the pass takes the store.
    #[cfg(test)]
    after_the_clock_answer: Pause,
    /// How many times the maintenance loop has gone into its wait, which a test reads to know the
    /// loop is waiting.
    #[cfg(test)]
    maintenance_waits: AtomicU64,
    /// Where this host's own tests stop a pass that decides announcements once it holds the
    /// privacy state's read side, before it decides. Compiled away in every shipped build.
    #[cfg(any(test, feature = "testing"))]
    after_privacy_read: Pause,
    /// Where this module's own tests stop a read of what changed in a session once it has read
    /// its page, before it reads any text or asks for a summary.
    #[cfg(test)]
    after_page: Pause,
    /// The threads each pass that decided announcements ran on, which a test reads to see that no
    /// pass ran on a thread of the runtime that drives the exchanges privacy mode waits for.
    #[cfg(test)]
    decided_on: std::sync::Mutex<Vec<std::thread::ThreadId>>,
}

impl std::fmt::Debug for AttentionModule {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AttentionModule")
            .finish_non_exhaustive()
    }
}

/// The session a pending question or approval names, when it is not the one it was raised from.
///
/// A session's ending ends these by the session they name as well as by the origin they came
/// from, so an announcement about one waits for both to be read to their end.
fn named_by(item: &kr_attention::engine::Item) -> Option<SessionId> {
    use kr_protocol::attention::AttentionRule;
    matches!(
        item.rule,
        AttentionRule::PendingApproval
            | AttentionRule::PendingInput
            | AttentionRule::InputIdleReminder
    )
    .then_some(item.session_id)
    .flatten()
}

impl AttentionModule {
    /// Opens the environment's attention store in the daemon's state directory.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store cannot be opened: another
    /// live process holds it, or it cannot be read back or written.
    pub fn open(
        paths: &kr_ipc::paths::EnvironmentPaths,
        boot_identity: kr_protocol::identity::BootIdentity,
    ) -> Result<Self> {
        Self::open_over(
            paths,
            &boot_identity,
            Arc::new(kr_worker::action::adapter::PlatformTimeAdapter::new()),
        )
    }

    /// Opens the store as [`Self::open`] does, reading the platform's time service from `adapter`.
    fn open_over(
        paths: &kr_ipc::paths::EnvironmentPaths,
        boot_identity: &kr_protocol::identity::BootIdentity,
        adapter: Arc<dyn kr_worker::action::adapter::TimeAdapter>,
    ) -> Result<Self> {
        let boot = boot_mark(boot_identity);
        let identity = kr_ipc::identity::current_process_start_identity().map_err(|error| {
            ControllerError::RegistryUnavailable {
                detail: format!("this daemon's process cannot be identified: {error}"),
            }
        })?;
        let claimant = Claimant::new(identity, &liveness);
        let directory = paths.state_dir();
        std::fs::create_dir_all(directory).map_err(|error| {
            ControllerError::RegistryUnavailable {
                detail: format!("the attention store's directory cannot be made: {error}"),
            }
        })?;
        let store = Attention::open(
            directory.join("attention.sqlite3"),
            unproven_reading(boot),
            &claimant,
        )
        .map_err(|error| ControllerError::RegistryUnavailable {
            detail: format!("the attention store cannot be opened: {error}"),
        })?;
        Ok(Self {
            release: tokio::sync::RwLock::new(BTreeMap::new()),
            store: std::sync::Mutex::new(store),
            clock: std::sync::OnceLock::new(),
            adapter,
            boot,
            clock_owed: AtomicBool::new(false),
            origins: std::sync::Mutex::new(Origins::default()),
            wake: Arc::new(tokio::sync::Notify::new()),
            automation_pass: std::sync::Mutex::new(()),
            automation_started: std::sync::OnceLock::new(),
            privacy: std::sync::OnceLock::new(),
            descriptions: std::sync::OnceLock::new(),
            automation_failing: AtomicBool::new(false),
            #[cfg(feature = "testing")]
            before_store: Pause::default(),
            #[cfg(test)]
            after_the_clock_answer: Pause::default(),
            #[cfg(test)]
            maintenance_waits: AtomicU64::new(0),
            #[cfg(any(test, feature = "testing"))]
            after_privacy_read: Pause::default(),
            #[cfg(test)]
            after_page: Pause::default(),
            #[cfg(test)]
            decided_on: std::sync::Mutex::new(Vec::new()),
        })
    }

    /// Returns true when this module serves the method.
    #[must_use]
    pub fn serves(method: Method) -> bool {
        method.group() == MethodGroup::ReviewAndAttention
    }

    /// Checks that a mutation of this group names what its parameters name.
    ///
    /// An acknowledgement and a quiet-hours window belong to the environment, so a target naming a
    /// session is refused; a review or a visit acknowledgement belongs to the session its
    /// parameters name, and a target naming another is refused.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::InvalidArgument`] when the two disagree or the parameters do
    /// not parse.
    pub fn check_subject(method: Method, mutation: &MutationRequest) -> Result<()> {
        if mutation.target.application_instance_id.is_present() {
            return Err(ControllerError::InvalidArgument(format!(
                "{} acts on attention, not on an application",
                method.as_str()
            )));
        }
        let named = mutation.target.session_id.as_ref().copied();
        let carried = match method {
            Method::AttentionAcknowledge => {
                let _: AttentionAcknowledgeParams = parse(&mutation.params)?;
                None
            }
            Method::AttentionQuietHours => {
                let _: AttentionQuietHoursParams = parse(&mutation.params)?;
                None
            }
            Method::ReviewAcknowledge => {
                let params: ReviewAcknowledgeParams = parse(&mutation.params)?;
                if kr_attention::review::subject_session(&params.subject) != params.session_id {
                    return Err(ControllerError::InvalidArgument(
                        "the review subject belongs to another session than the one named"
                            .to_owned(),
                    ));
                }
                Some(params.session_id)
            }
            Method::VisitAcknowledge => {
                let params: VisitAcknowledgeParams = parse(&mutation.params)?;
                Some(params.session_id)
            }
            _ => {
                return Err(ControllerError::InvalidArgument(format!(
                    "{} is not a mutation of the review and attention group",
                    method.as_str()
                )));
            }
        };
        match (named, carried) {
            (Some(_), None) => Err(ControllerError::InvalidArgument(format!(
                "{} belongs to the environment, not to one session",
                method.as_str()
            ))),
            (Some(named), Some(carried)) if named != carried => {
                Err(ControllerError::InvalidArgument(
                    "the request's target and its parameters name different sessions".to_owned(),
                ))
            }
            _ => Ok(()),
        }
    }

    /// Hands the module the privacy state the daemon publishes, so that every announcement the
    /// store decides is stamped with the generation in force and whether privacy mode was on in
    /// it. Attached once, before the store decides anything; a second call changes nothing.
    pub fn attach_privacy(&self, state: crate::privacy::PrivacyState) {
        let _ = self.privacy.set(state);
    }

    /// Hands the module the descriptions module, which keeps the summaries a read of what changed
    /// since a visit is answered with and the host that writes them. Attached once; a second call
    /// changes nothing. Without it a read that asks for a summary is answered without one.
    pub(crate) fn attach_descriptions(&self, descriptions: Arc<crate::describe::DescribeModule>) {
        let _ = self.descriptions.set(descriptions);
    }

    /// Runs one pass that may decide announcements, under a reading that carries the privacy state
    /// in force.
    ///
    /// The state's read side is held for the whole pass, so a change of privacy mode is published
    /// wholly before the pass or wholly after it, and no decision is stamped with a state that was
    /// replaced while it was being made. It is taken before the store, never inside it, and the
    /// pass waits for the store while it holds it, so a change of privacy mode waits for as long as
    /// the store does.
    ///
    /// Taking it waits behind a change that is itself waiting for the sends admitted before it, and
    /// a send holds its admission across an exchange that needs the runtime's own threads. So this
    /// runs only on a thread that may wait, the blocking pool or one of its own, and a caller that
    /// runs on the runtime goes through [`Self::deciding_on_the_blocking_pool`]. Not held across an
    /// await.
    fn deciding<T>(&self, pass: impl FnOnce(HostReading) -> T) -> T {
        #[cfg(test)]
        self.decided_on
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(std::thread::current().id());
        let held = self
            .privacy
            .get()
            .map(crate::privacy::PrivacyState::reading);
        let mut reading = self.reading();
        if let Some(held) = &held {
            let published = held.published();
            reading = reading.under(kr_attention::PrivacyStamp {
                generation: published.generation.get(),
                private: published.private,
            });
        }
        #[cfg(any(test, feature = "testing"))]
        self.after_privacy_read.wait();
        pass(reading)
    }

    /// Runs one pass that may decide announcements on the blocking pool, under [`Self::deciding`],
    /// and waits for it without holding a thread of the runtime.
    ///
    /// Every caller that runs on the runtime decides through this, as every other taker of the
    /// privacy state's read side runs on the blocking pool. Answers `None` when the pool was shut
    /// down before the pass ran, which only a stopping runtime does.
    async fn deciding_on_the_blocking_pool<T: Send + 'static>(
        self: &Arc<Self>,
        pass: impl FnOnce(&Self, HostReading) -> T + Send + 'static,
    ) -> Option<T> {
        let module = Arc::clone(self);
        match tokio::task::spawn_blocking(move || module.deciding(|reading| pass(&module, reading)))
            .await
        {
            Ok(done) => Some(done),
            Err(error) if error.is_panic() => std::panic::resume_unwind(error.into_panic()),
            Err(_) => None,
        }
    }

    /// Returns what the host's clocks read now, in the form the store takes.
    ///
    /// The wall clock is read through the host's one decision about it, which notices a rollback
    /// before a reading is taken from the clock and says whether the reading is proven: the same
    /// answer every other part of the host that lets go of a record by the wall clock is given.
    /// The platform's time service is asked at each reading, and whether it qualifies is what the
    /// decision takes from it. Without the decision attached the wall clock is read as unproven.
    fn reading(&self) -> HostReading {
        self.reading_and_debt().0
    }

    /// As [`Self::reading`], and whether the host owes its record a write that the reading found
    /// or had left. A forgetting is not made while a write is owed: what the host knows of its
    /// clock is ahead of its record.
    fn reading_and_debt(&self) -> (HostReading, bool) {
        let qualified = self.adapter.read().is_qualified();
        let Some(watched) = self.clock.get().and_then(|clock| clock.watch(qualified)) else {
            return (unproven_reading(self.boot), false);
        };
        // The host owes its record a write: the first reading that finds so wakes the maintenance
        // loop, which may be in a wait it began while nothing was owed, and it comes back soon
        // after for as long as anything is.
        if watched.owed {
            if !self.clock_owed.swap(true, Ordering::Relaxed) {
                self.wake.notify_one();
            }
        } else {
            self.clock_owed.store(false, Ordering::Relaxed);
        }
        (
            HostReading::new(
                self.boot,
                kr_ipc::clock::boot_elapsed_ms(),
                watched.wall_ms,
                watched.proven,
            ),
            watched.owed,
        )
    }

    /// Attaches the host's decision about its wall clock, once the daemon exists.
    pub(crate) fn attach_clock(&self, clock: Arc<dyn HostClock>) {
        let _ = self.clock.set(clock);
    }

    fn store(&self) -> Answer<std::sync::MutexGuard<'_, Attention>> {
        self.store.lock().map_err(|_| {
            ProtocolError::new(
                ErrorCode::StorageUnavailable,
                "the attention store's lock is poisoned",
            )
        })
    }

    fn origins(&self) -> std::sync::MutexGuard<'_, Origins> {
        self.origins
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    // ----- Reads ---------------------------------------------------------------------------

    /// Serves one read of this group and returns the frame it answers with, its session text
    /// released now when its ticket holds and withheld otherwise.
    pub async fn read_frame(
        &self,
        reach: &dyn Reach,
        caller: &Caller,
        actor: &ActorId,
        request: &Request,
    ) -> ControlFrame {
        frame(
            request.request_id,
            self.read(reach, caller, actor, request).await,
        )
    }

    /// Serves one read of this group, its session text released now when its ticket holds and
    /// withheld otherwise.
    ///
    /// # Errors
    ///
    /// Returns the refusal the store decided.
    pub async fn read(
        &self,
        reach: &dyn Reach,
        caller: &Caller,
        actor: &ActorId,
        request: &Request,
    ) -> Answer<ParamsValue> {
        let read = self.read_texts(reach, caller, actor, request).await?;
        Ok(self.settled(read).await)
    }

    /// Decides now what a read is answered with: its text released when its ticket holds and
    /// withheld otherwise.
    pub(crate) async fn settled(&self, read: Read) -> ParamsValue {
        let Some((withheld, ticket)) = read.text else {
            return read.value;
        };
        let fences = self.release.read().await;
        if ticket.holds(&fences, kr_ipc::clock::boot_elapsed_ms()) {
            read.value
        } else {
            withheld
        }
    }

    /// Serves one read of this group for a reader's connection: the answer, and what
    /// [`Self::write_released`] needs to release the session text it carries.
    pub async fn read_released(
        &self,
        reach: &dyn Reach,
        caller: &Caller,
        actor: &ActorId,
        request: &Request,
    ) -> Released {
        Released::of(
            request.request_id,
            self.read_texts(reach, caller, actor, request).await,
        )
    }

    /// Writes a read's answer to the reader's connection, releasing its session text only while
    /// its ticket holds.
    ///
    /// Each write attempt, the first and every continuation, is one checked write made under the
    /// release lock held shared: the ticket is checked against the clock before every transport
    /// write it makes, and the wait for room happens with the lock let go. When the ticket stops
    /// holding, an answer none of which has gone is taken back and the same answer with its text
    /// withheld is written instead; one the reader has part of is not finished, and the caller
    /// ends the connection so the reader asks again.
    ///
    /// # Errors
    ///
    /// Returns the connection's failure, or a refusal to finish an answer the reader has part of.
    pub async fn write_released(
        &self,
        writer: &mut kr_ipc::framed::FrameWriter,
        kind: kr_protocol::frame::StreamKind,
        released: Released,
    ) -> kr_ipc::Result<()> {
        let Released {
            frame,
            withheld,
            ticket,
        } = released;
        let Some(withheld) = withheld.filter(|_| !ticket.is_empty()) else {
            return writer.write_message(&frame).await;
        };
        let bytes = kr_ipc::framed::FrameWriter::encode(kind, &frame)?;
        let mut begun = false;
        loop {
            let attempt = {
                let fences = self.release.read().await;
                // Held across the write itself, so privacy mode is published before the check or
                // after the write, and the generated text of an answer is never written under a
                // state that has gone.
                let standing = ticket.standing();
                let may_write = || {
                    standing.is_some()
                        && ticket.holds_text(&fences, kr_ipc::clock::boot_elapsed_ms())
                };
                if begun {
                    writer.resume_frame_checked(may_write)
                } else {
                    begun = true;
                    writer.begin_frame_checked(&bytes, may_write)
                }
            }?;
            match attempt {
                CheckedWrite::Complete => return Ok(()),
                CheckedWrite::Blocked => writer.writable().ready().await?,
                CheckedWrite::Refused => {
                    if writer.withdraw_unstarted() {
                        return writer.write_message(&withheld).await;
                    }
                    return Err(kr_ipc::IpcError::socket(
                        "write",
                        std::io::Error::other(
                            "the session text this answer carries may no longer be released, and \
                             part of the answer has gone",
                        ),
                    ));
                }
            }
        }
    }

    /// Hands the delivery consumer the store, to take the announcements the store has decided, and
    /// the offer that says which of them it may take now.
    ///
    /// The store is held for the whole call, so what the consumer takes, commits and settles is one
    /// step to every other reader and writer of the store. The consumer commits to its own journal
    /// before it settles, and settles with the store before it lets go.
    ///
    /// The offer holds back an announcement about a session that is neither one the store reads
    /// nor one whose records it has finished reading, and about one closed over a worker this host
    /// could not account for: a closing session's pending questions and approvals end when the
    /// store has read what is left of its journal, and an announcement taken before that is one
    /// about a condition that is about to end. A pending question or approval that names a session
    /// without having been raised from it is held back from the moment that session's closure
    /// begins until the store has finished it. What is held back is offered again.
    ///
    /// # Errors
    ///
    /// Returns the refusal when the store cannot be taken, and nothing is taken.
    pub fn take_for_delivery<T>(
        &self,
        consume: impl FnOnce(&mut Attention, &dyn Fn(&kr_attention::engine::Item) -> bool) -> T,
    ) -> Answer<T> {
        let mut store = self.store()?;
        // Two sets, because the two relationships are held back for different reasons. An item is
        // held with the session it was raised from until the store reads that session or has
        // finished reading it; a request that names a session it was not raised from is held
        // only while the session's closure is under way, because the environment can name a
        // session this host never held, and nothing would ever let that one go.
        let (held_by_origin, held_by_name): (BTreeSet<SessionId>, BTreeSet<SessionId>) = {
            let engine = store.engine().map_err(refusal)?;
            let origins = self.origins();
            let by_origin = engine
                .items()
                .filter_map(|item| item.origin.session())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .filter(|session_id| {
                    let reads = origins.links.contains_key(session_id)
                        || engine.is_finalised(&Origin::Session(*session_id));
                    !reads
                        || origins.closing.contains(session_id)
                        || origins.unaccounted.contains(session_id)
                })
                .collect();
            let by_name = engine
                .items()
                .filter_map(named_by)
                .filter(|session_id| origins.ended.contains(session_id))
                .collect();
            (by_origin, by_name)
        };
        let offer = |item: &kr_attention::engine::Item| {
            item.origin
                .session()
                .is_none_or(|session_id| !held_by_origin.contains(&session_id))
                && named_by(item).is_none_or(|session_id| !held_by_name.contains(&session_id))
        };
        Ok(consume(&mut store, &offer))
    }

    /// Resolves the text of records for a delivery send, with the ticket its release is bound by.
    ///
    /// The consumer sends the text only through [`Self::release_delivery`].
    pub async fn delivery_texts(
        &self,
        reach: &dyn Reach,
        records: &[EventCursor],
    ) -> (Vec<Option<String>>, Ticket) {
        let indexed: Vec<(usize, EventCursor)> = records.iter().copied().enumerate().collect();
        let (texts, ticket) = self.texts(reach, &indexed).await;
        let mut ordered = vec![None; records.len()];
        for (index, text) in texts {
            if let Some(slot) = ordered.get_mut(index) {
                *slot = text;
            }
        }
        (ordered, ticket)
    }

    /// Runs one transport write of a delivery send of session text, only while the text's ticket
    /// holds.
    ///
    /// `write` runs under the release lock held shared, right after the ticket is checked against
    /// the clock read then, and must make at most one transport write and never wait. The consumer
    /// waits for room outside, continues bytes its transport kept only through another call, and
    /// when this answers nothing drops the text and every byte of it not yet sent and ends a
    /// message partly sent. A transport that sends bytes it holds later on its own cannot carry
    /// session text.
    pub async fn release_delivery<T>(
        &self,
        ticket: &Ticket,
        write: impl FnOnce() -> T,
    ) -> Option<T> {
        let fences = self.release.read().await;
        ticket
            .holds(&fences, kr_ipc::clock::boot_elapsed_ms())
            .then(write)
    }

    /// Serves one read of this group, with the session text it carries and what releasing it
    /// takes.
    async fn read_texts(
        &self,
        reach: &dyn Reach,
        caller: &Caller,
        actor: &ActorId,
        request: &Request,
    ) -> Answer<Read> {
        let Some(method) = request.method.method() else {
            return Err(ProtocolError::new(
                ErrorCode::PermissionDenied,
                "the method is not in the registry",
            ));
        };
        match method {
            Method::AttentionRead => {
                let params: AttentionReadParams = typed(&request.params)?;
                let page = {
                    let store = self.store()?;
                    caller.view(|viewer| {
                        store.read(actor, viewer, &params, self.reading(), caller.content())
                    })
                }
                .map_err(refusal)?;
                let mut result = page.result;
                let withheld = encode(&result)?;
                let (texts, ticket) = self.texts(reach, &page.texts).await;
                for (index, text) in texts {
                    if let Some(item) = result.items.get_mut(index) {
                        item.summary = Nullable(text);
                    }
                }
                Ok(Read::with(encode(&result)?, withheld, ticket))
            }
            Method::ReviewRead => {
                let params: ReviewReadParams = typed(&request.params)?;
                let store = self.store()?;
                let (reviews, more) = match params.subject.as_ref() {
                    Some(subject) => (
                        caller
                            .view(|viewer| store.review_state(actor, viewer, subject))
                            .map_err(refusal)?
                            .filter(|_| {
                                params.session_id.0.is_none_or(|session_id| {
                                    session_id == kr_attention::review::subject_session(subject)
                                })
                            })
                            .into_iter()
                            .collect(),
                        false,
                    ),
                    None => caller
                        .view(|viewer| {
                            store.review_states(
                                actor,
                                viewer,
                                params.session_id.0,
                                params.after.as_ref(),
                                params.max_reviews.get(),
                            )
                        })
                        .map_err(refusal)?,
                };
                encode(&ReviewReadResult {
                    actor_id: actor.clone(),
                    reviews,
                    more,
                })
                .map(Read::plain)
            }
            Method::VisitChanged => {
                let params: VisitChangedParams = typed(&request.params)?;
                if !caller.view(|viewer| viewer.sees_session(params.session_id)) {
                    return Err(ProtocolError::new(
                        ErrorCode::PermissionDenied,
                        "this caller may not see that session",
                    ));
                }
                let floor = self.output_floor(reach, params.session_id);
                // The page and what a summary is written from are read under one hold of the
                // store, so the summary starts at the cursor the page does and ends at the head the
                // page was read at, whatever is recorded while the text is read.
                let (page, source) = {
                    let store = self.store()?;
                    let page = store
                        .changed(
                            actor,
                            params.session_id,
                            params.max_changes.get(),
                            floor,
                            caller.content(),
                        )
                        .map_err(refusal)?;
                    let source = if params.summarise {
                        Some(
                            store
                                .summary_source(actor, params.session_id)
                                .map_err(refusal)?,
                        )
                    } else {
                        None
                    };
                    (page, source)
                };
                #[cfg(test)]
                self.after_page.wait();
                let mut result = page.result;
                let withheld = encode(&result)?;
                let (texts, mut ticket) = self.texts(reach, &page.texts).await;
                for (index, text) in texts {
                    if let Some(change) = result.changes.get_mut(index) {
                        change.summary = Nullable(text);
                    }
                }
                // Beside the changes and never among them. The answer that withholds session
                // text carries no summary: one is generated text, written from it. It is released
                // only while the privacy state it was read under holds.
                if let Some(source) = &source
                    && let Some((summary, generated)) =
                        self.summary(reach, caller, params.session_id, source).await
                {
                    result.summary = Nullable::some(summary);
                    ticket.generated = Some(generated);
                }
                Ok(Read::with(encode(&result)?, withheld, ticket))
            }
            _ => Err(ProtocolError::new(
                ErrorCode::InvalidArgument,
                format!("{} is not a read this group serves", method.as_str()),
            )),
        }
    }

    /// Answers a read that asked for a summary of what changed since the actor's last visit: the
    /// newest one written for the interval `source` froze, from the cursor the actor had
    /// acknowledged when the page the answer carries it beside was read, and, when a newer one is
    /// wanted, the request for it.
    ///
    /// The answer does not wait for a model. It is the summary the description host has already
    /// written, held under the profile it selected and the privacy generation in force, to a
    /// caller whose grant reaches back to the earliest change in it, and nothing when there is none,
    /// when no model runs here and when privacy mode is on. A request for one that is wanted is
    /// made only for a caller whose grant reaches back to the earliest change in the interval now, so
    /// a grant that does not reach it starts nothing the answer to it could not show.
    async fn summary(
        &self,
        reach: &dyn Reach,
        caller: &Caller,
        session_id: SessionId,
        source: &kr_attention::visit::SummarySource,
    ) -> Option<(ChangeSummary, Generated)> {
        let (Some(descriptions), Some(privacy)) = (
            self.descriptions.get().map(Arc::clone),
            self.privacy.get().cloned(),
        ) else {
            return None;
        };
        let (earliest, _) = moments(&source.changes)?;
        if !caller.reaches_back_to(earliest) {
            return None;
        }
        let (first_cursor, head) = (source.from_cursor, source.head);
        let reading = {
            let descriptions = Arc::clone(&descriptions);
            let privacy = privacy.clone();
            // Decided under the privacy state's read side, which waits behind a change of privacy
            // mode, so on a thread that may wait.
            match tokio::task::spawn_blocking(move || {
                descriptions.summary_reading(session_id, first_cursor, head, &privacy)
            })
            .await
            {
                Ok(Ok(reading)) => reading,
                _ => return None,
            }
        };
        if reading.wanted {
            self.ask_for_summary(reach, &descriptions, session_id, source)
                .await;
        }
        reading
            .served
            .filter(|record| caller.reaches_back_to(record.from_ms))
            .map(|record| {
                (
                    ChangeSummary {
                        text: record.text.as_str().to_owned(),
                        from_cursor: U64::new(record.cursor.from),
                        to_cursor: U64::new(record.cursor.to),
                        from_ms: TimestampMs::new(record.from_ms),
                        to_ms: TimestampMs::new(record.to_ms),
                        model: format!("{}@{}", record.profile_id, record.profile_revision.get()),
                    },
                    Generated::read_under(privacy, reading.decided),
                )
            })
    }

    /// Asks the description host for a summary of the changes in a frozen interval.
    ///
    /// The text of the newest changes is read from its owner as a read of them is, and what is
    /// carried to the host is the generation that text was decided under: a host that finds
    /// privacy mode has moved since refuses the request. Nothing here is released to anybody.
    async fn ask_for_summary(
        &self,
        reach: &dyn Reach,
        descriptions: &crate::describe::DescribeModule,
        session_id: SessionId,
        source: &kr_attention::visit::SummarySource,
    ) {
        let newest = newest_changes(source);
        let records: Vec<(usize, EventCursor)> = newest
            .iter()
            .enumerate()
            .filter_map(|(index, change)| change.text.record().map(|record| (index, record)))
            .collect();
        let (texts, ticket) = self.texts(reach, &records).await;
        let Ok(generation) = ticket.generation_of(session_id) else {
            return;
        };
        let read: BTreeMap<usize, String> = texts
            .into_iter()
            .filter_map(|(index, text)| text.map(|text| (index, text)))
            .collect();
        if let Some(ask) = summary_ask(session_id, source, &read, generation) {
            descriptions.ask_summary(ask);
        }
    }

    /// Returns the oldest output position a session still retains, which a visit's log views are
    /// measured against.
    ///
    /// A live session's comes with each page. A finished session's spool is read, since retention
    /// goes on after the session has ended; floors only move forward, so the later of the two is
    /// the one that holds. A session with neither retains everything as far as this host knows.
    fn output_floor(&self, reach: &dyn Reach, session_id: SessionId) -> u64 {
        let (paged, linked) = {
            let origins = self.origins();
            (
                origins.output_floor.get(&session_id).copied(),
                origins.links.contains_key(&session_id),
            )
        };
        let finished = !linked
            && self
                .store()
                .ok()
                .and_then(|store| {
                    store
                        .engine()
                        .ok()
                        .map(|engine| engine.is_finalised(&Origin::Session(session_id)))
                })
                .unwrap_or(false);
        let archived = if finished {
            reach.output_floor(session_id)
        } else {
            None
        };
        paged.max(archived).unwrap_or_default()
    }

    /// Reads the text of each record a page names, from the record's owner, as it serves now.
    ///
    /// A live session's worker answers over its link and a closed session's journal is read; a
    /// session that is neither, or whose owner does not answer in time, serves none. Each request
    /// names at most as many records as a text request carries.
    ///
    /// What was read is looked at again once every owner has answered, under the same lock a
    /// closure is recorded under: a session found closed over a worker this host could not account
    /// for serves nothing it answered, and neither does a link that no longer speaks for its
    /// session unless the session has since ended with its journal read.
    ///
    /// Each live answer that carries text adds its generation and lease end to the ticket its
    /// release is bound by, and keeps it after its session closes; text read from a finished
    /// session's journal needs none.
    async fn texts(
        &self,
        reach: &dyn Reach,
        records: &[(usize, EventCursor)],
    ) -> (Vec<(usize, Option<String>)>, Ticket) {
        let mut by_session: BTreeMap<SessionId, Vec<(usize, EventCursor)>> = BTreeMap::new();
        for (index, record) in records {
            if let Some(session_id) = record.origin.session() {
                by_session
                    .entry(session_id)
                    .or_default()
                    .push((*index, *record));
            }
        }
        let batch = usize::try_from(MAX_ATTENTION_TEXT_RECORDS).unwrap_or(usize::MAX);
        // Every live session is asked at once, so a read waits for the slowest worker rather than
        // for each in turn.
        let mut read = Vec::new();
        for (session_id, wanted) in by_session {
            let owner = self.text_owner(session_id);
            let journal = if matches!(owner, TextOwner::Journal) {
                reach.closed_journal(session_id)
            } else {
                None
            };
            let recorded = match &owner {
                TextOwner::Link(_) => self.recorded_generation(session_id).await,
                TextOwner::Journal | TextOwner::Nobody => None,
            };
            for wanted in wanted.chunks(batch) {
                let request = AttentionTextRequest {
                    request_id: next_request(),
                    records: wanted
                        .iter()
                        .map(|(_, record)| AttentionRecordRef {
                            source: record.source,
                            sequence: U64::new(record.sequence),
                        })
                        .collect(),
                    recorded_generation: Nullable(recorded.map(U64::new)),
                };
                let answer = match &owner {
                    TextOwner::Link(link) => {
                        let link = Arc::clone(link);
                        TextAnswer::Asked(tokio::spawn(async move {
                            let request_id = request.request_id;
                            match link
                                .ask(ControlFrame::AttentionText(request), request_id, TEXT_WAIT)
                                .await
                            {
                                Some(ControlFrame::AttentionTextAnswer(answer)) => Some(Leased {
                                    generation: answer.privacy_generation.0.map(U64::get),
                                    release_until: answer.release_until_boot_ms.get(),
                                    texts: answer
                                        .texts
                                        .into_iter()
                                        .map(|text| text.text.0)
                                        .collect(),
                                }),
                                _ => None,
                            }
                        }))
                    }
                    TextOwner::Journal => TextAnswer::Read(journal.as_ref().and_then(|journal| {
                        kr_worker::attention_source::texts(journal, &request)
                            .ok()
                            .map(|answer| {
                                answer.texts.into_iter().map(|text| text.text.0).collect()
                            })
                    })),
                    TextOwner::Nobody => TextAnswer::Read(None),
                };
                read.push((session_id, owner.clone(), wanted.to_vec(), answer));
            }
        }
        let mut answered = Vec::with_capacity(read.len());
        for (session_id, owner, wanted, answer) in read {
            let (texts, lease) = match answer {
                TextAnswer::Asked(asking) => match asking.await.ok().flatten() {
                    Some(leased) => (
                        Some(leased.texts),
                        Some((leased.generation, leased.release_until)),
                    ),
                    None => (None, None),
                },
                TextAnswer::Read(texts) => (texts, None),
            };
            answered.push((session_id, owner, wanted, texts, lease));
        }
        let finalised: BTreeSet<SessionId> = self
            .store()
            .ok()
            .and_then(|store| {
                store.engine().ok().map(|engine| {
                    answered
                        .iter()
                        .map(|(session_id, ..)| *session_id)
                        .filter(|session_id| engine.is_finalised(&Origin::Session(*session_id)))
                        .collect()
                })
            })
            .unwrap_or_default();
        let origins = self.origins();
        let mut served = Vec::new();
        let mut ticket = Ticket::default();
        for (session_id, owner, wanted, texts, lease) in answered {
            let still = !origins.unaccounted.contains(&session_id)
                && match &owner {
                    TextOwner::Link(link) => {
                        origins
                            .links
                            .get(&session_id)
                            .is_some_and(|current| Arc::ptr_eq(current, link))
                            || origins.closing.contains(&session_id)
                            || finalised.contains(&session_id)
                    }
                    TextOwner::Journal => true,
                    TextOwner::Nobody => false,
                };
            let texts = texts.filter(|_| still);
            if let (Some(texts), Some((generation, release_until))) = (&texts, lease)
                && texts.iter().any(Option::is_some)
            {
                ticket.entries.push(TicketEntry {
                    session_id,
                    generation,
                    release_until,
                });
            }
            served.extend(serve(&wanted, texts));
        }
        (served, ticket)
    }

    /// Returns the privacy generation this daemon has recorded for a session.
    async fn recorded_generation(&self, session_id: SessionId) -> Option<u64> {
        self.release
            .read()
            .await
            .get(&session_id)
            .and_then(|fence| fence.recorded)
    }

    /// Records a privacy generation seen for a session on a page or a text answer, keeping the
    /// greatest.
    async fn record(&self, session_id: SessionId, generation: Option<u64>) {
        let Some(generation) = generation else {
            return;
        };
        if self
            .release
            .read()
            .await
            .get(&session_id)
            .is_some_and(|fence| fence.recorded >= Some(generation))
        {
            return;
        }
        let mut fences = self.release.write().await;
        let fence = fences.entry(session_id).or_default();
        fence.recorded = fence.recorded.max(Some(generation));
    }

    /// Applies a worker's statement of its privacy fence, when it came from the link that speaks
    /// for its session now and after the last statement applied from that link.
    ///
    /// The release lock is held exclusively, so no release of any session's text is in progress
    /// while the fence changes, and once this returns true no release of this session's text
    /// begins until a later statement lowers its barrier. Answers whether it was applied, which is
    /// when the statement is acknowledged.
    async fn apply_statement(&self, link: &Arc<Link>, statement: &AttentionBarrier) -> bool {
        let mut fences = self.release.write().await;
        let current = self
            .origins()
            .links
            .get(&link.session_id)
            .is_some_and(|linked| Arc::ptr_eq(linked, link));
        if !current {
            return false;
        }
        {
            let mut last = link
                .last_statement
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if last.is_some_and(|last| statement.sequence.get() <= last) {
                return false;
            }
            *last = Some(statement.sequence.get());
        }
        let fence = fences.entry(link.session_id).or_default();
        fence.recorded = fence.recorded.max(statement.generation.0.map(U64::get));
        // A statement that cannot name the session's generation cannot lower a barrier: lowering
        // one at a generation nobody named would release text decided under the one before.
        fence.barrier = statement.raised || statement.generation.0.is_none();
        true
    }

    /// Returns where one session's text is read from now.
    ///
    /// A live session's worker answers over its link, and a finished or closing session's journal
    /// is read; a session closed over a worker this host could not account for serves none, and
    /// so does one that is neither live nor closed.
    fn text_owner(&self, session_id: SessionId) -> TextOwner {
        {
            let origins = self.origins();
            if origins.unaccounted.contains(&session_id) {
                return TextOwner::Nobody;
            }
            if let Some(link) = origins.links.get(&session_id) {
                return TextOwner::Link(Arc::clone(link));
            }
            if origins.closing.contains(&session_id) {
                return TextOwner::Journal;
            }
        }
        if self.finalised(session_id) {
            TextOwner::Journal
        } else {
            TextOwner::Nobody
        }
    }

    /// Answers whether the store has finished a session.
    fn finalised(&self, session_id: SessionId) -> bool {
        self.store()
            .ok()
            .and_then(|store| {
                store
                    .engine()
                    .ok()
                    .map(|engine| engine.is_finalised(&Origin::Session(session_id)))
            })
            .unwrap_or(false)
    }

    /// Applies events this daemon observed of its own, as they happen.
    ///
    /// The environment's own producers feed the store through this, and so does a host that
    /// learns of a condition in a session by a route other than the session's own records.
    ///
    /// It decides under the privacy state's read side, which waits behind a change of privacy mode
    /// that is itself waiting for a send on the wire, so it is called from a thread that may wait,
    /// never from one of the runtime's own.
    ///
    /// # Errors
    ///
    /// Returns the store's refusal; nothing about the events is kept then.
    pub fn observe(&self, events: &[SourceEvent]) -> Answer<()> {
        self.deciding(|reading| -> Answer<()> {
            let mut store = self.store()?;
            for event in events {
                store.apply(event, reading).map_err(refusal)?;
            }
            Ok(())
        })?;
        self.wake.notify_one();
        Ok(())
    }

    // ----- Mutations -----------------------------------------------------------------------

    /// Answers an action this store has already performed for this caller, if it has.
    ///
    /// It runs before the freshness window is considered, like every other retained action.
    pub fn retained(
        &self,
        actor: &ActorId,
        mutation: &MutationRequest,
        method: Method,
    ) -> Option<ControlFrame> {
        let key = action_key(actor, mutation, method).ok()?;
        let record = match self.store().ok()?.answered(actor, &key.action_id) {
            Ok(Some(record)) => record,
            Ok(None) => return None,
            Err(error) => return Some(frame(mutation.request_id, Err(refusal(error)))),
        };
        if record.method != key.method || record.digest != key.digest {
            return Some(frame(
                mutation.request_id,
                Err(ProtocolError::new(
                    ErrorCode::IdConflict,
                    format!(
                        "action {} was already used for a different request",
                        key.action_id
                    ),
                )),
            ));
        }
        Some(frame(mutation.request_id, decode_answer(&record.answer)))
    }

    /// Checks, before an action is admitted, what the store can decide about it now.
    ///
    /// Section 9 makes a refusal the host can decide a rejection rather than an outcome nobody
    /// can establish, so a value the store could not write down as given, a window that is not
    /// minutes of a day, a view past its bounds and one more actor than the store admits are
    /// answered here.
    ///
    /// # Errors
    ///
    /// Returns the refusal.
    pub fn check_mutation(
        &self,
        caller: &Caller,
        actor: &ActorId,
        mutation: &MutationRequest,
        method: Method,
    ) -> Answer<()> {
        let store = self.store()?;
        store.check_actor(actor).map_err(refusal)?;
        match method {
            Method::AttentionAcknowledge => {
                let params: AttentionAcknowledgeParams = typed(&mutation.params)?;
                for item in &params.items {
                    storable(item.revision.get(), "an item revision")?;
                }
                caller
                    .view(|viewer| store.check_revisions(viewer, &params.items))
                    .map_err(refusal)
            }
            Method::AttentionQuietHours => {
                let params: AttentionQuietHoursParams = typed(&mutation.params)?;
                check_quiet_hours(&params)
            }
            Method::ReviewAcknowledge => {
                let params: ReviewAcknowledgeParams = typed(&mutation.params)?;
                storable(params.version.get(), "a review version")?;
                if kr_attention::review::subject_session(&params.subject) != params.session_id {
                    return Err(ProtocolError::new(
                        ErrorCode::InvalidArgument,
                        "the review subject belongs to another session than the one named",
                    ));
                }
                if !caller.view(|viewer| {
                    viewer.sees_session(kr_attention::review::subject_session(&params.subject))
                }) {
                    return Err(unknown_subject(&params.subject));
                }
                let state = store
                    .review_state(actor, &Viewer::Owner, &params.subject)
                    .map_err(refusal)?
                    .ok_or_else(|| unknown_subject(&params.subject))?;
                if params.version.get() > state.current_version.get() {
                    return Err(ProtocolError::new(
                        ErrorCode::DraftConflict,
                        format!(
                            "{} is at version {}, not {}",
                            kr_attention::review::subject_key(&params.subject),
                            state.current_version.get(),
                            params.version.get()
                        ),
                    ));
                }
                Ok(())
            }
            Method::VisitAcknowledge => {
                let params: VisitAcknowledgeParams = typed(&mutation.params)?;
                if !caller.view(|viewer| viewer.sees_session(params.session_id)) {
                    return Err(ProtocolError::new(
                        ErrorCode::PermissionDenied,
                        "this caller may not see that session",
                    ));
                }
                check_visit(&params)
            }
            _ => Err(ProtocolError::new(
                ErrorCode::InvalidArgument,
                format!("{} is not a mutation this group serves", method.as_str()),
            )),
        }
    }

    /// Performs one mutation of this group as the daemon's own action, in the write that records
    /// it, under the admission it carries.
    ///
    /// The admission is asked twice: by the daemon's guarded write before the store is reached,
    /// and again inside the store's transaction before its first write, so a deadline that passes
    /// while the write waits for the store refuses the action rather than letting it write.
    ///
    /// # Errors
    ///
    /// Returns the refusal the store or the admission decided.
    pub async fn write(
        &self,
        controller: &crate::service::Controller,
        caller: &Caller,
        actor: &ActorId,
        mutation: &MutationRequest,
        method: Method,
        carried: &crate::authority::AdmittedMutation,
    ) -> Answer<ParamsValue> {
        self.check_mutation(caller, actor, mutation, method)?;
        let key = action_key(actor, mutation, method)?;
        let reading = self.reading();
        let performed = controller
            .enter_admitted(carried, |registry| {
                let registry: &crate::registry::Registry = registry;
                #[cfg(feature = "testing")]
                self.before_store.wait();
                let mut store = self
                    .store()
                    .map_err(|refused| ControllerError::refused(&refused))?;
                // The admission's own refusal, when that is what stopped the store, is what the
                // caller is answered with.
                let lapsed: std::cell::RefCell<Option<ControllerError>> =
                    std::cell::RefCell::new(None);
                let admit = || {
                    controller
                        .check_admission(registry, carried)
                        .map_err(|error| {
                            let detail = error.to_string();
                            *lapsed.borrow_mut() = Some(error);
                            kr_attention::Error::StoreUnavailable {
                                kind: kr_attention::error::StoreFault::Other,
                                detail,
                            }
                        })
                };
                let encode = |answer: &Answered| encode_answer(answer, reading);
                let performed = caller.view(|viewer| {
                    let change = match method {
                        Method::AttentionAcknowledge => {
                            let params: AttentionAcknowledgeParams = typed(&mutation.params)
                                .map_err(|refused| {
                                    Unperformed::Refused(refusal_to_error(refused))
                                })?;
                            return store
                                .perform(
                                    &key,
                                    Mutation::Acknowledge {
                                        viewer,
                                        items: &params.items,
                                    },
                                    reading,
                                    admit,
                                    encode,
                                )
                                .map_err(Unperformed::Store);
                        }
                        Method::AttentionQuietHours => {
                            let params: AttentionQuietHoursParams = typed(&mutation.params)
                                .map_err(|refused| {
                                    Unperformed::Refused(refusal_to_error(refused))
                                })?;
                            Mutation::QuietHours(params.quiet_hours.0)
                        }
                        Method::ReviewAcknowledge => {
                            let params: ReviewAcknowledgeParams =
                                typed(&mutation.params).map_err(|refused| {
                                    Unperformed::Refused(refusal_to_error(refused))
                                })?;
                            return store
                                .perform(
                                    &key,
                                    Mutation::Review {
                                        viewer,
                                        subject: &params.subject,
                                        version: params.version.get(),
                                    },
                                    reading,
                                    admit,
                                    encode,
                                )
                                .map_err(Unperformed::Store);
                        }
                        Method::VisitAcknowledge => {
                            let params: VisitAcknowledgeParams =
                                typed(&mutation.params).map_err(|refused| {
                                    Unperformed::Refused(refusal_to_error(refused))
                                })?;
                            Mutation::Visit {
                                session_id: params.session_id,
                                cursor: params.acknowledged_cursor.get(),
                                views: params.views,
                            }
                        }
                        _ => {
                            return Err(Unperformed::Refused(ControllerError::InvalidArgument(
                                format!("{} is not a mutation this group serves", method.as_str()),
                            )));
                        }
                    };
                    store
                        .perform(&key, change, reading, admit, encode)
                        .map_err(Unperformed::Store)
                });
                performed.map_err(|unperformed| match unperformed {
                    Unperformed::Refused(error) => error,
                    Unperformed::Store(error) => lapsed
                        .borrow_mut()
                        .take()
                        .unwrap_or_else(|| store_error(error)),
                })
            })
            .await
            .map_err(|error| error.to_protocol_error())?;
        // A window change moves the next timer; the maintenance loop works it out again.
        self.wake.notify_one();
        match performed {
            Performed::Done(answer) => result_of(&answer, reading),
            Performed::Retained(record) => decode_answer(&record.answer),
        }
    }

    /// Stops the next action of this group once its admission has been asked and stood, before
    /// it takes the store, for this host's own tests.
    ///
    /// The action holds the daemon's registry there, as it does across its whole write. Returns
    /// the end that says the action has arrived, and the end that lets it go. The pause fires
    /// once.
    #[cfg(feature = "testing")]
    pub fn pause_before_store(
        &self,
    ) -> (
        std::sync::mpsc::Receiver<()>,
        std::sync::mpsc::SyncSender<()>,
    ) {
        self.before_store.arm()
    }

    /// Stops the next pass that decides announcements once it holds the privacy state's read side,
    /// before it decides, for this host's own tests.
    ///
    /// Returns the end that says the pass has arrived, and the end that lets it go. The pause
    /// fires once.
    #[cfg(feature = "testing")]
    pub fn pause_after_privacy_read(
        &self,
    ) -> (
        std::sync::mpsc::Receiver<()>,
        std::sync::mpsc::SyncSender<()>,
    ) {
        self.after_privacy_read.arm()
    }

    /// Performs one mutation of this group and returns the frame it answers with.
    pub async fn write_frame(
        &self,
        controller: &crate::service::Controller,
        caller: &Caller,
        actor: &ActorId,
        mutation: &MutationRequest,
        method: Method,
        carried: &crate::authority::AdmittedMutation,
    ) -> ControlFrame {
        frame(
            mutation.request_id,
            self.write(controller, caller, actor, mutation, method, carried)
                .await,
        )
    }

    // ----- Links ---------------------------------------------------------------------------

    /// Starts reading one live session's sources at the worker given.
    ///
    /// A session already being read is read from this worker from now on: a link to the one before
    /// it stops, a connection still being made to it is given up, and the next is made here.
    pub fn watch(self: &Arc<Self>, reach: Arc<dyn Reach>, worker: KnownWorker) {
        let session_id = worker.descriptor.session_id;
        {
            // With the store held, as a closure holds it: a page being taken from the link this
            // replaces is taken, certificate and all, before the link and its certificate go, and
            // one read after this finds its link gone.
            let _store = self
                .store
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut guard = self.origins();
            let origins = &mut *guard;
            origins.closing.remove(&session_id);
            match origins.workers.get_mut(&session_id) {
                Some(watched) if watched.worker == worker => {}
                Some(watched) => {
                    watched.worker = worker;
                    watched.revision = watched.revision.wrapping_add(1);
                    watched.replaced.notify_waiters();
                    if let Some(link) = origins.links.remove(&session_id) {
                        link.close();
                    }
                    origins.certified.remove(&session_id);
                }
                None => {
                    origins.workers.insert(
                        session_id,
                        Watched {
                            worker,
                            revision: 0,
                            replaced: Arc::new(tokio::sync::Notify::new()),
                        },
                    );
                }
            }
            if !origins.watched.insert(session_id) {
                return;
            }
        }
        let module = Arc::downgrade(self);
        tokio::spawn(async move {
            let mut pause = FIRST_RELINK;
            loop {
                let Some(held) = module.upgrade() else {
                    return;
                };
                let Some((revision, worker, replaced)) =
                    held.origins().workers.get(&session_id).map(|watched| {
                        (
                            watched.revision,
                            watched.worker.clone(),
                            Arc::clone(&watched.replaced),
                        )
                    })
                else {
                    return;
                };
                drop(held);
                // Taken before the connection is made, so a newer worker named while it is being
                // made gives it up at once. One named before this was taken shows as a revision
                // that no longer holds when the link would be put in place.
                let notified = replaced.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                let connected = tokio::select! {
                    biased;
                    () = &mut notified => {
                        pause = FIRST_RELINK;
                        continue;
                    }
                    connected = tokio::time::timeout(CONNECT_WAIT, reach.connect(&worker)) => {
                        connected.ok().and_then(std::result::Result::ok)
                    }
                };
                if let Some(client) = connected {
                    pause = FIRST_RELINK;
                    Self::serve_link(&module, session_id, revision, client).await;
                }
                tokio::time::sleep(pause).await;
                pause = (pause * 2).min(MAX_RELINK);
            }
        });
    }

    /// Reads one session's pages over an open connection until it fails, the session ends, or a
    /// newer worker is named for it.
    async fn serve_link(
        module: &std::sync::Weak<Self>,
        session_id: SessionId,
        revision: u64,
        client: LocalClient,
    ) {
        let (reader, writer, _acknowledgement) = client.into_halves();
        let link = Arc::new(Link::new(writer, session_id, module.clone()));
        // A session's notices are known by fingerprints under its key, and a link that cannot have
        // the key reads nothing until it can. A connection made to a worker the daemon has since
        // replaced is not put in place.
        let Some(fingerprint_key) = module.upgrade().and_then(|held| {
            let key = held.fingerprint_key(session_id).ok()?;
            let mut origins = held.origins();
            if origins
                .workers
                .get(&session_id)
                .is_none_or(|watched| watched.revision != revision)
            {
                return None;
            }
            origins.links.insert(session_id, Arc::clone(&link));
            Some(key)
        }) else {
            link.close();
            return;
        };
        // Read only once the link is in place: the worker's first frame states its privacy fence,
        // and a statement is applied only from the link that speaks for its session.
        let reading = tokio::spawn(Link::read_loop(Arc::clone(&link), reader));
        let mut behind = false;
        // The module is held for each step and let go of across the wait, so a module its owner
        // has let go of goes, with its store's claim, while a request is held.
        while let Some((questions_after, host_events_after, wait)) =
            module.upgrade().and_then(|held| {
                if !held.origins().watched.contains(&session_id) {
                    return None;
                }
                let (questions_after, host_events_after) = held.cursors(session_id).ok()?;
                let wait = if behind {
                    0
                } else {
                    held.page_wait(session_id)
                };
                Some((questions_after, host_events_after, wait))
            })
        {
            let Some(held) = module.upgrade() else {
                break;
            };
            let recorded = held.recorded_generation(session_id).await;
            drop(held);
            let request_id = next_request();
            let request = AttentionSourcesRequest {
                request_id,
                questions_after: U64::new(questions_after),
                host_events_after: U64::new(host_events_after),
                max_records: U64::new(PAGE_RECORDS),
                wait_ms: U64::new(wait),
                fingerprint_key: SecretBytes32::from_bytes(fingerprint_key),
                recorded_generation: Nullable(recorded.map(U64::new)),
            };
            let answered = link
                .ask(
                    ControlFrame::AttentionSources(request),
                    request_id,
                    Duration::from_millis(wait) + PAGE_GRACE,
                )
                .await;
            let Some(ControlFrame::AttentionSourcePage(page)) = answered else {
                break;
            };
            let Some(held) = module.upgrade() else {
                break;
            };
            match held
                .take_page(session_id, &link, questions_after, host_events_after, &page)
                .await
            {
                Ok(Taken::Complete) => behind = false,
                Ok(Taken::Partial) => behind = true,
                Ok(Taken::Stale) | Err(_) => break,
            }
        }
        if let Some(held) = module.upgrade() {
            let mut origins = held.origins();
            if origins
                .links
                .get(&session_id)
                .is_some_and(|linked| Arc::ptr_eq(linked, &link))
            {
                origins.links.remove(&session_id);
                // A link that stopped certifies nothing more, and this session's timers wait for
                // the next one.
                origins.certified.remove(&session_id);
            }
        }
        link.close();
        reading.abort();
    }

    /// Returns how long a live session's request may be held: until its next timer, and no
    /// longer than a worker holds one.
    fn page_wait(&self, session_id: SessionId) -> u64 {
        let reading = self.reading();
        let next = self.store().ok().and_then(|store| {
            store
                .next_deadline_of(&Origin::Session(session_id), reading)
                .ok()
                .flatten()
        });
        next.map_or(MAX_ATTENTION_SOURCE_WAIT_MS, |due| {
            due.saturating_sub(reading.continuous_ms)
                .min(MAX_ATTENTION_SOURCE_WAIT_MS)
        })
    }

    /// Returns where the store has read one session's two sources.
    fn cursors(&self, session_id: SessionId) -> Answer<(u64, u64)> {
        let store = self.store()?;
        let engine = store.engine().map_err(refusal)?;
        let origin = Origin::Session(session_id);
        Ok((
            engine
                .consumed(origin, AttentionSource::Questions)
                .unwrap_or_default(),
            engine
                .consumed(origin, AttentionSource::HostEvents)
                .unwrap_or_default(),
        ))
    }

    /// Returns the key one session's fingerprints are made under, derived from the store's own
    /// secret so it is the same for the session whenever it is asked for.
    fn fingerprint_key(&self, session_id: SessionId) -> Answer<[u8; 32]> {
        let store = self.store()?;
        let engine = store.engine().map_err(refusal)?;
        Ok(*engine
            .key_secret()
            .fingerprint(&format!("attention fingerprint key|{session_id}"))
            .as_bytes())
    }

    /// Feeds one page to the store and decides what it lets the store decide.
    ///
    /// The page is taken only from the link that speaks for the session now. The store is held from
    /// that look to the last write, and a closure or a replacement takes the store before it takes
    /// the link away, so a page read before either is applied before it, and one read after is not
    /// applied at all.
    async fn take_page(
        self: &Arc<Self>,
        session_id: SessionId,
        link: &Arc<Link>,
        questions_after: u64,
        host_events_after: u64,
        page: &AttentionSourcePage,
    ) -> Answer<Taken> {
        let events = events_of(session_id, page);
        let complete = complete(
            questions_after,
            page.questions.head.get(),
            page.questions
                .records
                .last()
                .map(|record| record.sequence.get()),
        ) && complete(
            host_events_after,
            page.host_events.head.get(),
            page.host_events
                .records
                .last()
                .map(|record| record.sequence.get()),
        );
        let built_at_boot_ms = page.built_at_boot_ms.get();
        let output_floor = page.output_floor.0.map(|floor| floor.get());
        let link = Arc::clone(link);
        let taken = self
            .deciding_on_the_blocking_pool(move |module, reading| -> Answer<Taken> {
                let mut store = module.store()?;
                if !module
                    .origins()
                    .links
                    .get(&session_id)
                    .is_some_and(|current| Arc::ptr_eq(current, &link))
                {
                    return Ok(Taken::Stale);
                }
                store.rebuild(&events, reading).map_err(refusal)?;
                let certified = {
                    let mut origins = module.origins();
                    if complete {
                        let certified = origins.certified.entry(session_id).or_insert(0);
                        *certified = (*certified).max(built_at_boot_ms);
                    }
                    if let Some(floor) = output_floor {
                        origins.output_floor.insert(session_id, floor);
                    }
                    Certificates::of(&origins)
                };
                store
                    .tick(reading, &|origin| certified.at(origin))
                    .map_err(refusal)?;
                Ok(if complete {
                    Taken::Complete
                } else {
                    Taken::Partial
                })
            })
            .await
            .ok_or_else(|| {
                ProtocolError::new(
                    ErrorCode::StorageUnavailable,
                    "the pass over a session's page was stopped",
                )
            })??;
        // A certificate that moved may let a timer be decided that the maintenance loop had put
        // aside.
        if !matches!(taken, Taken::Stale) {
            self.wake.notify_one();
        }
        Ok(taken)
    }

    fn certificates(&self) -> Certificates {
        Certificates::of(&self.origins())
    }

    // ----- Sessions that end -----------------------------------------------------------------

    /// Finishes a session whose closure this daemon has recorded.
    ///
    /// The link stops. A closure over a worker this host could not confirm had ended marks every
    /// source of the session as a gap with no known end and ends nothing. Otherwise the journal is
    /// read to the end and the session's live conditions end; a journal that cannot be read is a gap
    /// with no known end in every source, and then the session ends too. What the store cannot
    /// write now is kept and tried again by the maintenance loop; the session stays closing until
    /// it is finished.
    pub async fn session_closed(self: &Arc<Self>, reach: &dyn Reach, session_id: SessionId) {
        {
            // With the store held, so a page being applied finishes first and a page read after
            // this finds its link gone.
            let _store = self
                .store
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut origins = self.origins();
            origins.watched.remove(&session_id);
            origins.workers.remove(&session_id);
            origins.certified.remove(&session_id);
            // Under the store lock with the link, so no take sees the link gone and the closure not
            // begun: a request that names the session from elsewhere is held from here.
            origins.ended.insert(session_id);
            if let Some(link) = origins.links.remove(&session_id) {
                link.close();
            }
        }
        let unaccounted = reach.unaccounted(session_id).await;
        if unaccounted {
            // Under the release lock, so a response already put together for the session, and a
            // write already part way through, releases nothing more of its text from here on.
            self.release
                .write()
                .await
                .entry(session_id)
                .or_default()
                .unaccounted = true;
        }
        self.finish(reach, session_id, unaccounted);
    }

    /// Finishes a closed session as far as the store can now, and keeps it for the next pass when
    /// it cannot.
    fn finish(&self, reach: &dyn Reach, session_id: SessionId, unaccounted: bool) {
        if self.finalised(session_id) {
            let mut origins = self.origins();
            origins.closing.remove(&session_id);
            origins.ended.remove(&session_id);
            origins.unfinished.remove(&session_id);
            return;
        }
        let finished = if unaccounted {
            // Marked first, so no text is served for the session from here on.
            self.origins().unaccounted.insert(session_id);
            self.gaps_without_end(session_id)
        } else {
            // Only now is the journal the session's last word, and only now is its text read from
            // it.
            self.origins().closing.insert(session_id);
            let read = reach
                .closed_journal(session_id)
                .map_or(Err(Unfinished::Journal), |journal| {
                    self.read_to_the_end(session_id, &journal)
                });
            match read {
                Ok(()) => self.finalise(session_id),
                Err(Unfinished::Journal) => self
                    .gaps_without_end(session_id)
                    .and_then(|()| self.finalise(session_id)),
                Err(Unfinished::Store(error)) => Err(error),
            }
        };
        let changed = {
            let mut origins = self.origins();
            if finished.is_ok() {
                origins.unfinished.remove(&session_id);
                origins.closing.remove(&session_id);
                origins.ended.remove(&session_id);
                true
            } else {
                // A session newly left unfinished wakes the loop that retries it. One that failed
                // again is already on the loop's schedule, and waking the loop for it would retry
                // it at once, again and again, rather than after the pause a retry waits.
                origins.unfinished.insert(session_id)
            }
        };
        if changed {
            self.wake.notify_one();
        }
    }

    /// Tries again to finish every closed session the store could not finish before.
    async fn finish_again(&self, reach: &dyn Reach) {
        let unfinished: Vec<SessionId> = self.origins().unfinished.iter().copied().collect();
        for session_id in unfinished {
            let unaccounted = reach.unaccounted(session_id).await;
            self.finish(reach, session_id, unaccounted);
        }
    }

    /// Reads a closed session's journal from the store's cursors to the head of both sources.
    fn read_to_the_end(
        &self,
        session_id: SessionId,
        journal: &kr_worker::journal::Journal,
    ) -> std::result::Result<(), Unfinished> {
        let key = self
            .fingerprint_key(session_id)
            .map_err(Unfinished::Store)?;
        loop {
            let (questions_after, host_events_after) =
                self.cursors(session_id).map_err(Unfinished::Store)?;
            let request = AttentionSourcesRequest {
                request_id: RequestId::new(0),
                questions_after: U64::new(questions_after),
                host_events_after: U64::new(host_events_after),
                max_records: U64::new(PAGE_RECORDS),
                wait_ms: U64::ZERO,
                fingerprint_key: SecretBytes32::from_bytes(key),
                // A journal read after the closure: no worker is left to answer for a generation.
                recorded_generation: Nullable::null(),
            };
            let page = kr_worker::attention_source::page(journal, &request, 0, usize::MAX)
                .map_err(|_| Unfinished::Journal)?;
            let events = events_of(session_id, &page);
            let done = complete(
                questions_after,
                page.questions.head.get(),
                page.questions
                    .records
                    .last()
                    .map(|record| record.sequence.get()),
            ) && complete(
                host_events_after,
                page.host_events.head.get(),
                page.host_events
                    .records
                    .last()
                    .map(|record| record.sequence.get()),
            );
            let reading = self.reading();
            self.store()
                .map_err(Unfinished::Store)?
                .rebuild(&events, reading)
                .map_err(|error| Unfinished::Store(refusal(error)))?;
            if done {
                return Ok(());
            }
            // A page that moved neither cursor would be read again for ever. What the store will
            // not take from the journal is as good as what the journal cannot give.
            if self.cursors(session_id).map_err(Unfinished::Store)?
                == (questions_after, host_events_after)
            {
                return Err(Unfinished::Journal);
            }
        }
    }

    /// Marks every source of a session as a gap with no known end.
    ///
    /// Every source: the two a link reads, and any other the store holds records of for the
    /// session, so each of the session's unresolved items is uncertain afterwards.
    fn gaps_without_end(&self, session_id: SessionId) -> Answer<()> {
        let origin = Origin::Session(session_id);
        let mut store = self.store()?;
        let sources = {
            let engine = store.engine().map_err(refusal)?;
            let mut sources: BTreeMap<AttentionSource, u64> = [
                (AttentionSource::Questions, 0),
                (AttentionSource::HostEvents, 0),
            ]
            .into_iter()
            .collect();
            for ((of, source), consumed) in engine.all_consumed() {
                if *of == origin {
                    sources.insert(*source, *consumed);
                }
            }
            sources
        };
        for (source, consumed) in sources {
            store
                .note_gap(origin, source, consumed.saturating_add(1), None)
                .map_err(refusal)?;
        }
        Ok(())
    }

    /// Ends a closed session's live conditions in the store.
    fn finalise(&self, session_id: SessionId) -> Answer<()> {
        let reading = self.reading();
        self.store()?
            .finalise(session_id, reading)
            .map(|_| ())
            .map_err(refusal)
    }

    /// Returns every session the store holds anything of that has not ended.
    pub fn open_sessions(&self) -> Vec<SessionId> {
        let Ok(store) = self.store() else {
            return Vec::new();
        };
        let Ok(engine) = store.engine() else {
            return Vec::new();
        };
        let mut sessions: BTreeSet<SessionId> = engine
            .all_consumed()
            .keys()
            .filter_map(|(origin, _)| origin.session())
            .collect();
        sessions.extend(engine.items().filter_map(|item| item.origin.session()));
        sessions
            .into_iter()
            .filter(|session_id| !engine.is_finalised(&Origin::Session(*session_id)))
            .collect()
    }

    /// Whether the store is reading a session's sources at its worker. For this crate's own tests.
    #[cfg(test)]
    pub(crate) fn watching(&self, session_id: SessionId) -> bool {
        self.origins().watched.contains(&session_id)
    }

    /// Whether the store has finished with a closed session. For this crate's own tests.
    #[cfg(test)]
    pub(crate) fn finished_with(&self, session_id: SessionId) -> bool {
        self.finalised(session_id)
    }

    // ----- The workflow journal's alerts ----------------------------------------------------

    /// Reads the workflow journal's attention records for as long as the module is held: one pass
    /// now, and then one every `AUTOMATION_EVERY`.
    ///
    /// The first pass has run when this returns, so a daemon that waits for it at its start has put
    /// right whatever the last daemon left between the store and the journal before it serves
    /// anything. A second call starts nothing further.
    pub async fn consume_automation(self: &Arc<Self>, journal: Arc<WorkflowStore>) {
        if self.automation_started.set(()).is_err() {
            return;
        }
        let taken = self.take_automation(&journal).await;
        self.report_automation(taken);
        let module = Arc::downgrade(self);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(AUTOMATION_EVERY).await;
                // Held for one pass and let go of across the wait, so a module its owner has let
                // go of goes, with its store's claim.
                let Some(held) = module.upgrade() else {
                    return;
                };
                let taken = held.take_automation(&journal).await;
                held.report_automation(taken);
            }
        });
    }

    /// Makes one pass over the workflow journal's attention records.
    ///
    /// # Errors
    ///
    /// Returns why the pass stopped short: the journal or the store could not be read or written.
    /// The journal is not told the store has read anything the store has not committed, and the
    /// next pass starts again from the store's own cursor.
    pub async fn take_automation(self: &Arc<Self>, journal: &Arc<WorkflowStore>) -> Answer<()> {
        let module = Arc::clone(self);
        let journal = Arc::clone(journal);
        match tokio::task::spawn_blocking(move || module.automation_pass(&journal)).await {
            Ok(taken) => taken,
            Err(error) if error.is_panic() => std::panic::resume_unwind(error.into_panic()),
            Err(_) => Err(ProtocolError::new(
                ErrorCode::StorageUnavailable,
                "the pass over the workflow journal was stopped",
            )),
        }
    }

    /// Reports a pass that stopped short, once for as long as passes keep stopping.
    fn report_automation(&self, taken: Answer<()>) {
        match taken {
            Ok(()) => self.automation_failing.store(false, Ordering::Relaxed),
            Err(error) => {
                if !self.automation_failing.swap(true, Ordering::Relaxed) {
                    eprintln!(
                        "kr-controller: the attention store could not take the workflow journal's \
                         alerts: {error}"
                    );
                }
            }
        }
    }

    /// One pass: the registration, the recovery a journal ahead of the store owes, the records past
    /// the store's cursor, and then the journal told how far the store has read.
    fn automation_pass(&self, journal: &WorkflowStore) -> Answer<()> {
        let _one = self
            .automation_pass
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Registering is idempotent, and it answers how far the journal has recorded this store as
        // having read. A record of an attention type leaves the journal only once every consumer
        // registered for its type has passed it.
        let recorded = journal
            .register_consumer(ATTENTION_CONSUMER, ATTENTION_EVENTS, kr_ipc::now_ms().get())
            .map_err(journal_error)?;
        let mut cursor = self.automation_cursor()?;
        if recorded > cursor {
            self.recover_automation(journal, cursor, recorded)?;
            cursor = recorded;
        }
        loop {
            // Taken before the read, so every record the journal committed by then is on this read
            // or an earlier one.
            let before = self.reading().continuous_ms;
            let page = journal
                .events_after(cursor, ATTENTION_EVENTS, AUTOMATION_PAGE)
                .map_err(journal_error)?;
            if let Some(last) = page.last() {
                let events = page
                    .iter()
                    .map(|event| automation_event(journal, event))
                    .collect::<kr_automation::Result<Vec<_>>>()
                    .map_err(journal_error)?;
                let reading = self.reading();
                self.store()?.rebuild(&events, reading).map_err(refusal)?;
                cursor = last.sequence;
            }
            if page.len() < AUTOMATION_PAGE {
                self.certify_environment(before)?;
                break;
            }
        }
        // Only after the store's commit, and on every pass that finds the store past what the
        // journal recorded, whether or not this pass read anything: a daemon that stopped between
        // the commit and this has it done by the next pass, with no later record needed.
        let consumed = self.automation_cursor()?;
        if consumed > recorded {
            journal
                .acknowledge(ATTENTION_CONSUMER, consumed)
                .map_err(journal_error)?;
        }
        Ok(())
    }

    /// Returns how far the store has read the workflow journal's attention records.
    fn automation_cursor(&self) -> Answer<u64> {
        Ok(self
            .store()?
            .engine()
            .map_err(refusal)?
            .consumed(Origin::Environment, AttentionSource::Automation)
            .unwrap_or_default())
    }

    /// Reads again what the journal still keeps of a range the store has no record of reading, and
    /// feeds it with the whole range recorded as a gap and the cursor moved to its end, in one
    /// write.
    ///
    /// The journal records the store as having read through `through`, and the store's cursor
    /// stands at `from`: the store lost what it had written, or was put back to an earlier copy.
    /// Part of the range may have left the journal since, because a record every registered
    /// consumer has passed is not kept, so every unresolved automation item is uncertain afterwards.
    /// Nothing is written before the whole range has been read, so a pass that stops part way
    /// leaves the recovery to be done again, whole.
    fn recover_automation(&self, journal: &WorkflowStore, from: u64, through: u64) -> Answer<()> {
        let mut retained = Vec::new();
        let mut after = from;
        'reading: loop {
            let page = journal
                .events_after(after, ATTENTION_EVENTS, AUTOMATION_PAGE)
                .map_err(journal_error)?;
            for event in &page {
                if event.sequence > through {
                    break 'reading;
                }
                retained.push(automation_event(journal, event).map_err(journal_error)?);
                after = event.sequence;
            }
            if page.len() < AUTOMATION_PAGE {
                break;
            }
        }
        let reading = self.reading();
        self.store()?
            .recover_source(
                Origin::Environment,
                AttentionSource::Automation,
                &retained,
                through,
                reading,
            )
            .map_err(refusal)?;
        Ok(())
    }

    /// Records that the store has read every attention record the journal committed before `at`,
    /// and decides what the environment's items are owed when one of them has had nothing decided.
    ///
    /// A record read from the journal announces nothing by itself: the timer pass decides what an
    /// item it raised is owed, once a read has reached the end of the journal's records.
    fn certify_environment(&self, at: u64) -> Answer<()> {
        let ticked = self.deciding(|reading| -> Answer<bool> {
            let mut store = self.store()?;
            let certified = {
                let mut origins = self.origins();
                origins.environment_certified = Some(
                    origins
                        .environment_certified
                        .map_or(at, |earlier| earlier.max(at)),
                );
                Certificates::of(&origins)
            };
            let undecided =
                store.engine().map_err(refusal)?.items().any(|item| {
                    item.origin == Origin::Environment && item.since_notified.is_none()
                });
            if undecided {
                store
                    .tick(reading, &|origin| certified.at(origin))
                    .map_err(refusal)?;
            }
            Ok(undecided)
        })?;
        if ticked {
            self.wake.notify_one();
        }
        Ok(())
    }

    // ----- Maintenance -----------------------------------------------------------------------

    /// Runs the store's timers and its housekeeping for as long as the module is held, and finishes
    /// the closed sessions the store could not finish when they closed.
    pub fn maintain(self: &Arc<Self>, reach: Arc<dyn Reach>) {
        let module = Arc::downgrade(self);
        tokio::spawn(async move {
            let mut forgot_at = 0_u64;
            loop {
                let Some(held) = module.upgrade() else {
                    return;
                };
                held.finish_again(reach.as_ref()).await;
                let Some((reading, forgot)) = held.tick_and_forget(forgot_at).await else {
                    return;
                };
                forgot_at = forgot;
                let mut wait = held
                    .next_decidable_deadline(reading)
                    .map_or(MAINTENANCE, |due| {
                        Duration::from_millis(due.saturating_sub(reading.continuous_ms))
                            .clamp(Duration::from_millis(50), MAINTENANCE)
                    });
                if !held.origins().unfinished.is_empty() {
                    wait = wait.min(CLOSURE_RETRY);
                }
                if held.clock_owed.load(Ordering::Relaxed) {
                    wait = wait.min(CLOCK_WRITE_RETRY);
                }
                // The signal is taken before the module is let go of, so a change that wakes it
                // cannot fall between the look above and the wait; the module itself is not held
                // across the wait, so one its owner has let go of goes.
                let wake = Arc::clone(&held.wake);
                let notified = wake.notified();
                #[cfg(test)]
                held.maintenance_waits.fetch_add(1, Ordering::SeqCst);
                drop(held);
                let _ = tokio::time::timeout(wait, notified).await;
            }
        });
    }

    /// Runs the store's timers once, and lets go of the action records that have outlived their
    /// retention when that is due: `forgotten_at` is the wall reading the last cutoff was counted
    /// from, and a pass is due an hour after it or whenever the clock reads before it. Returns the
    /// reading the pass decided under and the marker to pass on next, or `None` when the pool was
    /// shut down before the pass ran.
    pub(crate) async fn tick_and_forget(
        self: &Arc<Self>,
        forgotten_at: u64,
    ) -> Option<(HostReading, u64)> {
        self.deciding_on_the_blocking_pool(move |module, reading| {
            let mut forgot = forgotten_at;
            // Expired records are let go of only on a wall clock this host can prove, so a
            // rollback cannot make a live record look expired. The host is asked about the
            // reading this pass decided under, before the store is taken and never under it, and
            // only when a forgetting is due and the reading itself is proven.
            let asked = reading.wall_ms.get();
            // Due an hour after the last forgetting, and at once when the clock reads before it:
            // a clock the owner established again after a correction is not waited for until it
            // catches up with a reading the correction took back.
            let due = asked < forgot || asked - forgot > FORGET_EVERY_MS;
            let permitted = due
                && reading.wall_proven
                && module
                    .clock
                    .get()
                    .is_some_and(|clock| clock.may_forget_at(asked));
            #[cfg(test)]
            module.after_the_clock_answer.wait();
            if let Ok(mut store) = module.store() {
                // Read with the store held: a closure and a replacement take the store before
                // they take a certificate away, so this tick never decides on one they took.
                let certified = module.certificates();
                let _ = store.tick(reading, &|origin| certified.at(origin));
                if permitted {
                    // The records go by a predicate over every row, so the final reading is taken
                    // with the store held and the store is held to the delete: no record can be
                    // stamped after a correction between the two, and the cutoff is counted from
                    // the earlier of the two readings, never later than the clock stands now.
                    let (held, owed) = module.reading_and_debt();
                    if held.wall_proven && !owed {
                        let counted = asked.min(held.wall_ms.get());
                        // The schedule moves to the reading the cutoff was counted from, and
                        // only once the records are gone.
                        if store
                            .forget_actions_before(counted.saturating_sub(ACTION_RETENTION_MS))
                            .is_ok()
                        {
                            forgot = counted;
                        }
                    }
                }
            }
            (reading, forgot)
        })
        .await
    }

    /// Returns the earliest timer the next tick could decide.
    ///
    /// A timer that has fallen due and whose origin has no certificate that reaches it waits for
    /// one, and a new certificate wakes the loop; counting it here would have the loop tick for
    /// nothing again and again.
    fn next_decidable_deadline(&self, reading: HostReading) -> Option<u64> {
        let store = self.store().ok()?;
        let certified = &self.certificates();
        let engine = store.engine().ok()?;
        let mut origins: BTreeSet<Origin> = engine
            .all_consumed()
            .keys()
            .map(|(origin, _)| *origin)
            .collect();
        origins.extend(engine.items().map(|item| item.origin));
        origins.insert(Origin::Environment);
        origins
            .into_iter()
            .filter_map(|origin| {
                let due = engine.next_deadline_of(&origin, reading)?;
                if due > reading.continuous_ms {
                    return Some(due);
                }
                let decidable = engine.is_finalised(&origin)
                    || certified.at(&origin).is_some_and(|at| at >= due);
                decidable.then_some(due)
            })
            .min()
    }
}

/// What became of a page the store was offered.
enum Taken {
    /// It reached the head of both sources.
    Complete,
    /// It stopped short of a head, and the next page follows at once.
    Partial,
    /// Its link no longer speaks for the session, and nothing of it was taken.
    Stale,
}

/// Why a closed session's journal was not read to its end.
enum Unfinished {
    /// The journal could not be read: its sources become gaps with no known end.
    Journal,
    /// The store could not take what was read: the session is tried again later.
    Store(ProtocolError),
}

// ----- The link --------------------------------------------------------------------------------

/// Where a session's text is read from.
#[derive(Clone)]
enum TextOwner {
    /// The live worker, over its link.
    Link(Arc<Link>),
    /// The session's journal, once it has ended.
    Journal,
    /// Nowhere: the session serves no text now.
    Nobody,
}

/// One text request's answer, as it is being read.
enum TextAnswer {
    /// Asked of a live worker, on a task of its own.
    Asked(tokio::task::JoinHandle<Option<Leased>>),
    /// Read already, from a finished session's journal.
    Read(Option<Vec<Option<String>>>),
}

/// A live worker's text answer: the texts, and what their release is bound by.
struct Leased {
    /// The generation the answer was decided under.
    generation: Option<u64>,
    /// When its lease ends.
    release_until: u64,
    texts: Vec<Option<String>>,
}

/// Pairs each record wanted with the text its owner answered, or none when it answered nothing.
fn serve(
    wanted: &[(usize, EventCursor)],
    answered: Option<Vec<Option<String>>>,
) -> Vec<(usize, Option<String>)> {
    let mut texts = answered.unwrap_or_default().into_iter();
    wanted
        .iter()
        .map(|(index, _)| (*index, texts.next().flatten()))
        .collect()
}

/// One connection to a session's worker, carrying the held page and the text requests beside it.
struct Link {
    /// The session the connection reads.
    session_id: SessionId,
    /// The module the worker's statements of its privacy fence are applied to.
    module: std::sync::Weak<AttentionModule>,
    writer: tokio::sync::Mutex<kr_ipc::framed::FrameWriter>,
    waiters: std::sync::Mutex<BTreeMap<u64, tokio::sync::oneshot::Sender<ControlFrame>>>,
    closed: std::sync::atomic::AtomicBool,
    /// The latest statement applied from this link, which a statement has to come after.
    last_statement: std::sync::Mutex<Option<u64>>,
}

impl Link {
    fn new(
        writer: kr_ipc::framed::FrameWriter,
        session_id: SessionId,
        module: std::sync::Weak<AttentionModule>,
    ) -> Self {
        Self {
            session_id,
            module,
            writer: tokio::sync::Mutex::new(writer),
            waiters: std::sync::Mutex::new(BTreeMap::new()),
            closed: std::sync::atomic::AtomicBool::new(false),
            last_statement: std::sync::Mutex::new(None),
        }
    }

    /// Writes one frame no answer follows, all within `within`.
    ///
    /// A frame given up part way through leaves the stream unusable, so the link is closed then.
    async fn send(&self, frame: &ControlFrame, within: Duration) -> bool {
        let writing = std::sync::atomic::AtomicBool::new(false);
        let sent = tokio::time::timeout(within, async {
            let mut writer = self.writer.lock().await;
            if self.closed.load(Ordering::SeqCst) {
                return false;
            }
            writing.store(true, Ordering::SeqCst);
            let written = writer.write_message(frame).await;
            writing.store(false, Ordering::SeqCst);
            if written.is_err() {
                self.close();
                return false;
            }
            true
        })
        .await;
        sent.unwrap_or_else(|_| {
            if writing.load(Ordering::SeqCst) {
                self.close();
            }
            false
        })
    }

    /// Applies a statement of the worker's privacy fence, and acknowledges it once it is applied.
    ///
    /// The acknowledgement is written from a task of its own, so the loop reading this link goes
    /// on handing answers over while the writer is busy with a request that may be waiting for one
    /// of them.
    async fn statement(self: &Arc<Self>, statement: &AttentionBarrier) {
        let Some(module) = self.module.upgrade() else {
            return;
        };
        let applied = module.apply_statement(self, statement).await;
        drop(module);
        if !applied {
            return;
        }
        let acknowledgement =
            ControlFrame::AttentionBarrierAcknowledged(AttentionBarrierAcknowledged {
                request_id: statement.request_id,
                sequence: statement.sequence,
            });
        let link = Arc::clone(self);
        tokio::spawn(async move {
            link.send(&acknowledgement, ACKNOWLEDGEMENT_WAIT).await;
        });
    }

    /// Records the privacy generation a page or a text answer was decided under.
    async fn record(&self, generation: Nullable<U64>) {
        if let Some(module) = self.module.upgrade() {
            module
                .record(self.session_id, generation.0.map(U64::get))
                .await;
        }
    }

    fn waiters(
        &self,
    ) -> std::sync::MutexGuard<'_, BTreeMap<u64, tokio::sync::oneshot::Sender<ControlFrame>>> {
        self.waiters
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Sends one request and waits for its answer, all within `within`.
    ///
    /// The bound covers the wait for the writer and the write as well as the answer, so a worker
    /// that stops reading cannot hold a read or a link for longer. A request given up part way
    /// through its frame leaves the stream unusable, so the link is closed then.
    async fn ask(
        &self,
        frame: ControlFrame,
        request_id: RequestId,
        within: Duration,
    ) -> Option<ControlFrame> {
        let (answer, answered) = tokio::sync::oneshot::channel();
        self.waiters().insert(request_id.get(), answer);
        // Looked at after the waiter is in place: a link that closes after this look clears the
        // waiter, so the wait ends at once rather than at its bound.
        if self.closed.load(Ordering::SeqCst) {
            self.waiters().remove(&request_id.get());
            return None;
        }
        let writing = std::sync::atomic::AtomicBool::new(false);
        let outcome = tokio::time::timeout(within, async {
            {
                let mut writer = self.writer.lock().await;
                // A link that closed while this waited for the writer sends nothing more.
                if self.closed.load(Ordering::SeqCst) {
                    return None;
                }
                writing.store(true, Ordering::SeqCst);
                let written = writer.write_message(&frame).await;
                writing.store(false, Ordering::SeqCst);
                if written.is_err() {
                    self.close();
                    return None;
                }
            }
            answered.await.ok()
        })
        .await;
        self.waiters().remove(&request_id.get());
        match outcome {
            Ok(answer) => answer,
            Err(_) => {
                if writing.load(Ordering::SeqCst) {
                    self.close();
                }
                None
            }
        }
    }

    /// Hands every answer to the request it answers, until the connection ends.
    ///
    /// Frames are handled in the order they arrive. A statement of the worker's privacy fence is
    /// applied before the next frame is read, and the generation an answer was decided under is
    /// recorded before the answer is handed on, so a new connection's first statement is in place
    /// before anything it carries is served.
    async fn read_loop(link: Arc<Self>, mut reader: kr_ipc::framed::FrameReader) {
        loop {
            let Ok(frame) = reader.read_message::<ControlFrame>().await else {
                break;
            };
            let request_id = match &frame {
                ControlFrame::AttentionBarrier(statement) => {
                    link.statement(statement).await;
                    continue;
                }
                ControlFrame::AttentionSourcePage(page) => {
                    link.record(page.privacy_generation).await;
                    page.request_id
                }
                ControlFrame::AttentionTextAnswer(answer) => {
                    link.record(answer.privacy_generation).await;
                    answer.request_id
                }
                ControlFrame::Response(response) => response.request_id,
                _ => continue,
            };
            if let Some(waiter) = link.waiters().remove(&request_id.get()) {
                let _ = waiter.send(frame);
            }
        }
        link.close();
    }

    fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        self.waiters().clear();
    }
}

// ----- Translation -----------------------------------------------------------------------------

/// The changes a summary job is built from: the newest the request may carry.
fn newest_changes(source: &kr_attention::visit::SummarySource) -> &[kr_attention::visit::Change] {
    let skipped = source
        .changes
        .len()
        .saturating_sub(kr_describe::summary::MAX_SUMMARY_CHANGES);
    &source.changes[skipped..]
}

/// The moments of the earliest and of the latest of `changes`, none when there are none.
///
/// A log holds changes in the order they were recorded, which is not the order they happened in: a
/// session's question records are read before its host's own events, so a change recorded later
/// can be older. What a summary says of the changes is held to the earliest of them, whichever
/// place that one has in the log.
fn moments(changes: &[kr_attention::visit::Change]) -> Option<(u64, u64)> {
    let at = || changes.iter().map(|change| change.at_ms.get());
    Some((at().min()?, at().max()?))
}

/// Builds the request for a summary of the changes in `source`.
///
/// The interval is the whole of what was frozen: from the cursor the actor had acknowledged to the
/// cursor the log had reached, and its moments are the earliest and the latest of every change the
/// log retains in it, so a grant is held to the earliest of them even when the newest are all the
/// job reads. Each of the newest changes carries the host's own words, or the text read for it
/// from its session; a change whose text was not read carries none. `read` is indexed by the
/// change's place among the newest.
fn summary_ask(
    session_id: SessionId,
    source: &kr_attention::visit::SummarySource,
    read: &BTreeMap<usize, String>,
    generation: Option<kr_worker::privacy::PrivacyGeneration>,
) -> Option<kr_describe::summary::SummaryAsk> {
    use kr_describe::context::{CursorInterval, ProjectText};
    use kr_describe::summary::{SummaryAsk, SummaryChange};

    let (from_ms, to_ms) = moments(&source.changes)?;
    let changes: Vec<SummaryChange> = newest_changes(source)
        .iter()
        .enumerate()
        .map(|(index, change)| SummaryChange {
            cursor: change.cursor,
            kind: change.kind.as_str(),
            at_ms: change.at_ms.get(),
            text: match &change.text {
                Text::Host(words) => ProjectText::new(words),
                Text::Record(_) => read.get(&index).and_then(|text| ProjectText::new(text)),
            },
        })
        .collect();
    SummaryAsk::new(
        session_id,
        CursorInterval::new(source.from_cursor, source.head),
        from_ms,
        to_ms,
        generation,
        changes,
    )
}

/// Turns one page's records into the typed events the store reads, in each source's order.
#[must_use]
pub fn events_of(session_id: SessionId, page: &AttentionSourcePage) -> Vec<SourceEvent> {
    let mut events: Vec<SourceEvent> = page
        .questions
        .records
        .iter()
        .map(|record| question_event(session_id, record))
        .collect();
    events.extend(
        page.host_events
            .records
            .iter()
            .map(|record| host_event(session_id, record)),
    );
    events
}

/// Turns one question transition into the event the store reads.
///
/// The event carries no text: the store keeps none, and reads the record's text from its owner
/// when it serves it.
#[must_use]
pub fn question_event(session_id: SessionId, record: &AttentionQuestionRecord) -> SourceEvent {
    let kind = match record.kind {
        QuestionEventKind::Created => EventKind::QuestionPending {
            question_id: record.question_id,
            session_id: record.session_id,
            verified: record.verified,
            pending_since_ms: record.pending_since_ms,
            pending_since_anchor: None,
            summary: String::new(),
        },
        QuestionEventKind::Answered => EventKind::QuestionResolved {
            question_id: record.question_id,
            session_id: record.session_id,
            answered: true,
        },
        QuestionEventKind::Cancelled | QuestionEventKind::Expired => EventKind::QuestionResolved {
            question_id: record.question_id,
            session_id: record.session_id,
            answered: false,
        },
    };
    SourceEvent::new(
        EventCursor::in_session(
            session_id,
            AttentionSource::Questions,
            record.sequence.get(),
        ),
        record.recorded_at_ms,
        kind,
    )
}

/// Turns one host event into the event the store reads.
///
/// Only a notification is a rule's condition, and one is known to the store by its fingerprint
/// rather than by what it said. Anything else moves the cursor and nothing more.
#[must_use]
pub fn host_event(session_id: SessionId, record: &AttentionHostRecord) -> SourceEvent {
    // A worker's notice about a plugin binding it holds is the trusted adapter rule's. Only the
    // worker writes the member, so an application's notification, which never carries it, cannot
    // raise or resolve one; the transition travels whether or not the text does.
    let kind = if let Some(notice) = record.adapter.0.as_ref() {
        match notice.transition {
            kr_protocol::attention::AdapterTransition::Revoked => EventKind::AdapterFailed {
                plugin_id: notice.plugin_id.clone(),
                session_id: Some(session_id),
                detail: record
                    .text
                    .0
                    .clone()
                    .unwrap_or_else(|| "revoked by its repository".to_owned()),
            },
            kr_protocol::attention::AdapterTransition::Cleared => EventKind::AdapterRecovered {
                plugin_id: notice.plugin_id.clone(),
            },
        }
    } else if record.notification {
        EventKind::ApplicationNotice {
            session_id,
            notice: kr_attention::event::ApplicationNotice {
                id: None,
                title: None,
                body: String::new(),
                lease_held: false,
                fingerprint: record.fingerprint.0.map(|fingerprint| {
                    kr_attention::event::Fingerprint::from_bytes(*fingerprint.as_bytes())
                }),
            },
        }
    } else {
        EventKind::Observed
    };
    SourceEvent::new(
        EventCursor::in_session(
            session_id,
            AttentionSource::HostEvents,
            record.sequence.get(),
        ),
        record.recorded_at_ms,
        kind,
    )
}

/// Turns one record of the workflow journal's stream into the event the store reads.
///
/// A record that raises an item carries the grant the paused revision or chain acts under, read
/// from the journal now: the grant the revision names, or the one the chain's root run acts under,
/// both facts that never change. An item whose grant the journal cannot name is left to the owner
/// at this machine alone.
fn automation_event(
    journal: &WorkflowStore,
    event: &JournalEvent,
) -> kr_automation::Result<SourceEvent> {
    let cursor = EventCursor::new(AttentionSource::Automation, event.sequence);
    let at = TimestampMs::new(event.recorded_at_ms);
    // The journal hands this reader only its own types, so every record is one; anything else
    // would move the cursor and raise nothing.
    let Some(record) = AttentionOutboxRecord::of(event) else {
        return Ok(SourceEvent::new(cursor, at, EventKind::Observed));
    };
    let subject = match record.subject {
        AttentionSubject::Workflow {
            workflow_id,
            revision,
        } => AttentionAutomationSubject::Workflow {
            workflow_id,
            revision: U64::new(revision),
        },
        AttentionSubject::CausalRoot(causal_root_id) => {
            AttentionAutomationSubject::CausalChain { causal_root_id }
        }
    };
    let kind = if record.ends_condition {
        EventKind::AutomationResumed { subject }
    } else {
        let grant_id = match record.subject {
            AttentionSubject::Workflow {
                workflow_id,
                revision,
            } => journal
                .get_definition(workflow_id, revision)?
                .map(|installed| installed.definition.grant_reference),
            AttentionSubject::CausalRoot(causal_root_id) => journal.chain_grant(causal_root_id)?,
        };
        EventKind::AutomationPaused {
            subject,
            reason: record.reason,
            grant_id,
        }
    };
    Ok(SourceEvent::new(cursor, at, kind))
}

/// The refusal a workflow journal that could not be read or written is reported with.
fn journal_error(error: kr_automation::AutomationError) -> ProtocolError {
    ProtocolError::new(
        ErrorCode::StorageUnavailable,
        format!("the workflow journal: {error}"),
    )
}

/// Whether one source's part of a page reached the source's head.
const fn complete(cursor: u64, head: u64, last: Option<u64>) -> bool {
    match last {
        Some(last) => last >= head,
        None => cursor >= head,
    }
}

// ----- Helpers ---------------------------------------------------------------------------------

/// Reduces a boot identity to what the store compares one boot's readings by.
fn boot_mark(identity: &kr_protocol::identity::BootIdentity) -> kr_attention::time::BootMark {
    let mut bytes = format!("{:?}", identity.source).into_bytes();
    bytes.push(b'|');
    bytes.extend_from_slice(identity.value.as_slice());
    kr_attention::time::BootMark::of(&bytes)
}

/// Returns the host's clocks now with the wall clock unproven: what the store reads before the
/// daemon has attached the host's decision about it, and when that decision cannot be read.
fn unproven_reading(boot: kr_attention::time::BootMark) -> HostReading {
    HostReading::new(
        boot,
        kr_ipc::clock::boot_elapsed_ms(),
        kr_ipc::now_ms().get(),
        false,
    )
}

/// Returns what the kernel says about the process a claim names.
fn liveness(held: &kr_protocol::identity::ProcessStartIdentity) -> Liveness {
    match kr_ipc::identity::process_state(held) {
        kr_ipc::identity::ProcessState::Running => Liveness::Running,
        kr_ipc::identity::ProcessState::Ended => Liveness::Ended,
        kr_ipc::identity::ProcessState::Unknown { .. } => Liveness::Unknown,
    }
}

fn next_request() -> RequestId {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    RequestId::new(NEXT.fetch_add(1, Ordering::Relaxed))
}

fn action_key(actor: &ActorId, mutation: &MutationRequest, method: Method) -> Answer<ActionKey> {
    let digest = kr_protocol::digest::mutation_digest(mutation, actor)
        .map_err(|error| ProtocolError::new(ErrorCode::InvalidArgument, error.to_string()))?;
    Ok(ActionKey {
        actor: actor.clone(),
        action_id: mutation.action_id.get().to_string(),
        method: method.as_str().to_owned(),
        digest: digest.as_bytes().to_vec(),
    })
}

/// Why a mutation was not performed: refused before the store was asked, or by the store.
enum Unperformed {
    Refused(ControllerError),
    Store(kr_attention::Error),
}

/// Returns the result a performed mutation answers with, first time and on every repeat.
///
/// A quiet-hours window's result is decided from the window the store committed and the reading
/// it committed under, so a repeat answers exactly what the first answer said.
fn result_of(answer: &Answered, reading: HostReading) -> Answer<ParamsValue> {
    match answer {
        Answered::Acknowledged(result) => encode(result),
        Answered::QuietHours(quiet) => encode(&quiet_result(quiet.clone(), reading)),
        Answered::Reviewed(result) => encode(result),
        Answered::Visited(result) => encode(result),
    }
}

/// The answer a quiet-hours window gives under one reading.
fn quiet_result(
    quiet: Option<kr_protocol::attention::QuietHours>,
    reading: HostReading,
) -> AttentionQuietHoursResult {
    let quiet_now = reading.wall_proven
        && quiet
            .as_ref()
            .is_some_and(|window| window.covers(reading.minute_of_day()));
    AttentionQuietHoursResult {
        quiet_hours: Nullable(quiet),
        quiet_now,
        quiet_hours_provable: reading.wall_proven,
    }
}

/// Returns what the record of a performed mutation keeps: the result it answered with.
fn encode_answer(answer: &Answered, reading: HostReading) -> Vec<u8> {
    result_of(answer, reading)
        .ok()
        .map(|value| kr_cbor::encode(value.as_value()))
        .unwrap_or_default()
}

fn decode_answer(bytes: &[u8]) -> Answer<ParamsValue> {
    kr_cbor::decode(bytes, &kr_cbor::Limits::DEFAULT)
        .map(ParamsValue::new)
        .map_err(|error| ProtocolError::new(ErrorCode::StorageUnavailable, error.to_string()))
}

fn frame(request_id: RequestId, answer: Answer<ParamsValue>) -> ControlFrame {
    ControlFrame::Response(Response {
        request_id,
        outcome: match answer {
            Ok(value) => Outcome::Ok(value),
            Err(error) => Outcome::Error(error),
        },
    })
}

fn typed<T: kr_protocol::wire::WireMessage>(params: &ParamsValue) -> Answer<T> {
    params
        .to_typed()
        .map_err(|error| ProtocolError::new(ErrorCode::InvalidArgument, error.to_string()))
}

fn parse<T: kr_protocol::wire::WireMessage>(params: &ParamsValue) -> Result<T> {
    params
        .to_typed()
        .map_err(|error| ControllerError::InvalidArgument(error.to_string()))
}

fn encode<T: serde::Serialize>(value: &T) -> Answer<ParamsValue> {
    ParamsValue::from_typed(value)
        .map_err(|error| ProtocolError::new(ErrorCode::InvalidArgument, error.to_string()))
}

fn storable(value: u64, what: &str) -> Answer<()> {
    if value > MAX_STORED_COUNTER {
        return Err(ProtocolError::new(
            ErrorCode::InvalidArgument,
            format!("{what} is at most {MAX_STORED_COUNTER}"),
        ));
    }
    Ok(())
}

fn unknown_subject(subject: &ReviewSubject) -> ProtocolError {
    ProtocolError::new(
        ErrorCode::InvalidArgument,
        format!(
            "this host holds no review subject {}",
            kr_attention::review::subject_key(subject)
        ),
    )
}

fn check_quiet_hours(params: &AttentionQuietHoursParams) -> Answer<()> {
    let Some(quiet) = params.quiet_hours.as_ref() else {
        return Ok(());
    };
    let day = kr_protocol::attention::MINUTES_IN_DAY;
    if quiet.start_minute.get() >= day || quiet.end_minute.get() >= day {
        return Err(ProtocolError::new(
            ErrorCode::InvalidArgument,
            format!("a quiet-hours bound is a minute of the UTC day, below {day}"),
        ));
    }
    if quiet
        .zone
        .as_ref()
        .is_some_and(|zone| zone.len() > MAX_ZONE_LEN)
    {
        return Err(ProtocolError::new(
            ErrorCode::InvalidArgument,
            format!("a time-zone name is at most {MAX_ZONE_LEN} bytes"),
        ));
    }
    Ok(())
}

fn check_visit(params: &VisitAcknowledgeParams) -> Answer<()> {
    storable(params.acknowledged_cursor.get(), "an acknowledged cursor")?;
    if params.views.len() > usize::try_from(MAX_RETAINED_LOG_VIEWS).unwrap_or(usize::MAX) {
        return Err(ProtocolError::new(
            ErrorCode::InvalidArgument,
            format!("an actor retains at most {MAX_RETAINED_LOG_VIEWS} log views"),
        ));
    }
    for view in &params.views {
        if view.view_id.is_empty() || view.view_id.len() > MAX_LOG_VIEW_ID_LEN {
            return Err(ProtocolError::new(
                ErrorCode::InvalidArgument,
                format!("a log view identifier is 1 to {MAX_LOG_VIEW_ID_LEN} bytes"),
            ));
        }
        if view.filter.len() > MAX_LOG_VIEW_FILTER_LEN {
            return Err(ProtocolError::new(
                ErrorCode::InvalidArgument,
                format!("a log view filter is at most {MAX_LOG_VIEW_FILTER_LEN} bytes"),
            ));
        }
        storable(view.source_offset.get(), "a log view offset")?;
    }
    Ok(())
}

/// Translates the store's refusal into the code a caller is given.
fn refusal(error: kr_attention::Error) -> ProtocolError {
    use kr_attention::Error;
    match error {
        Error::UnknownReviewSubject { subject } => ProtocolError::new(
            ErrorCode::InvalidArgument,
            format!("this host holds no review subject {subject}"),
        ),
        Error::UnknownReviewVersion {
            subject,
            version,
            current,
        } => ProtocolError::new(
            ErrorCode::DraftConflict,
            format!("{subject} is at version {current}, not {version}"),
        ),
        Error::UnknownContinuation { key } => ProtocolError::new(
            ErrorCode::DraftConflict,
            format!("this caller's view holds no {key}, so a page cannot continue after it"),
        ),
        Error::TooManyActors { bound } => ProtocolError::new(
            ErrorCode::QuotaExceeded,
            format!("the attention store holds {bound} actors, which is its bound"),
        ),
        Error::RevisionAhead {
            key,
            revision,
            current,
        } => ProtocolError::new(
            ErrorCode::DraftConflict,
            format!("{key} is at revision {current}, not {revision}"),
        ),
        Error::ActionConflict { action } => ProtocolError::new(
            ErrorCode::IdConflict,
            format!("action {action} was already used for a different request"),
        ),
        other => ProtocolError::new(ErrorCode::StorageUnavailable, other.to_string()),
    }
}

fn store_error(error: kr_attention::Error) -> ControllerError {
    ControllerError::refused(&refusal(error))
}

fn refusal_to_error(error: ProtocolError) -> ControllerError {
    ControllerError::refused(&error)
}

#[cfg(test)]
pub(crate) mod tests {
    use std::time::Instant;

    use kr_ipc::framed::{FrameReader, FrameWriter};
    use kr_protocol::attention::{
        AttentionHostSlice, AttentionQuestionSlice, AttentionReadResult, AttentionRecordText,
        AttentionTextAnswer, VisitChangedResult,
    };
    use kr_protocol::frame::StreamKind;
    use kr_protocol::ids::QuestionId;
    use kr_protocol::method::MethodVersion;
    use kr_protocol::scalars::TimestampMs;
    use kr_protocol::session::DisplayNumber;

    use super::*;

    /// A worker's adapter notice is the trusted adapter rule's, keyed on the package and carrying
    /// the session: `revoked` raises it with the text or, withheld, a line of this build's own,
    /// and `cleared` resolves it. An application's notification saying the same thing is an
    /// application notice and nothing else.
    #[test]
    fn an_adapter_notice_is_the_adapter_rule_and_a_notification_is_not() {
        let session = SessionId::new(kr_protocol::scalars::Uuid::from_bytes([7; 16]));
        let plugin = kr_protocol::ids::PluginId::new("kalareach/claude-code").expect("an id");
        let record =
            |text: Option<&str>,
             notification: bool,
             transition: Option<kr_protocol::attention::AdapterTransition>| {
                AttentionHostRecord {
                    sequence: U64::new(1),
                    notification,
                    recorded_at_ms: TimestampMs::new(0),
                    text: Nullable::from(text.map(str::to_owned)),
                    fingerprint: Nullable::null(),
                    adapter: Nullable::from(transition.map(|transition| {
                        kr_protocol::attention::AdapterNotice {
                            plugin_id: plugin.clone(),
                            transition,
                        }
                    })),
                }
            };
        let warning = "kalareach/claude-code 1.0.0 was revoked by its repository";
        let revoked = kr_protocol::attention::AdapterTransition::Revoked;
        let cleared = kr_protocol::attention::AdapterTransition::Cleared;
        assert_eq!(
            host_event(session, &record(Some(warning), false, Some(revoked))).kind,
            EventKind::AdapterFailed {
                plugin_id: plugin.clone(),
                session_id: Some(session),
                detail: warning.to_owned(),
            }
        );
        assert_eq!(
            host_event(session, &record(None, false, Some(revoked))).kind,
            EventKind::AdapterFailed {
                plugin_id: plugin.clone(),
                session_id: Some(session),
                detail: "revoked by its repository".to_owned(),
            }
        );
        assert_eq!(
            host_event(session, &record(None, false, Some(cleared))).kind,
            EventKind::AdapterRecovered {
                plugin_id: plugin.clone(),
            }
        );
        assert!(matches!(
            host_event(session, &record(Some(warning), true, None)).kind,
            EventKind::ApplicationNotice { .. }
        ));
    }

    /// KR-REQ-18.02: the request for a summary is for the whole interval that was frozen and reads
    /// the newest changes only. Its earliest and latest moments are those of every change the
    /// log retains in it, so a grant is held to the oldest even when the newest are all the job
    /// reads; each change carries the host's own words or the text read for it, and one whose
    /// text was not read carries none.
    #[test]
    fn a_summary_request_is_for_the_whole_interval_and_reads_the_newest_changes() {
        use kr_attention::visit::{Change, SummarySource};
        use kr_protocol::attention::SemanticChangeKind;

        let session = SessionId::new(kr_protocol::scalars::Uuid::from_bytes([7; 16]));
        let changes: Vec<Change> = (3..80_u64)
            .map(|cursor| Change {
                cursor,
                kind: SemanticChangeKind::CommandCompleted,
                session_id: session,
                text: if cursor % 2 == 0 {
                    Text::Host(format!("words {cursor}"))
                } else {
                    Text::Record(EventCursor::in_session(
                        session,
                        AttentionSource::HostEvents,
                        cursor,
                    ))
                },
                at_ms: TimestampMs::new(1_000 + cursor),
            })
            .collect();
        let source = SummarySource {
            from_cursor: 3,
            head: 80,
            changes,
        };
        let newest = newest_changes(&source);
        assert_eq!(newest.len(), kr_describe::summary::MAX_SUMMARY_CHANGES);
        assert_eq!(newest.last().map(|change| change.cursor), Some(79));
        // The text was read for the third newest record and for no other.
        let record_index = newest
            .iter()
            .position(|change| change.cursor == 77)
            .expect("a record among the newest");
        let read = BTreeMap::from([(record_index, "read from the worker".to_owned())]);
        let generation = Some(kr_worker::privacy::PrivacyGeneration::new(4));
        let ask = summary_ask(session, &source, &read, generation).expect("a request");

        assert_eq!(
            (ask.interval.from, ask.interval.to),
            (3, 80),
            "the whole of what was frozen"
        );
        assert_eq!(
            (ask.from_ms, ask.to_ms),
            (1_003, 1_079),
            "the earliest and latest moments of the retained changes, though the job reads the newest"
        );
        assert_eq!(ask.generation, generation);
        assert_eq!(ask.changes.len(), kr_describe::summary::MAX_SUMMARY_CHANGES);
        assert_eq!(
            ask.earlier,
            77 - kr_describe::summary::MAX_SUMMARY_CHANGES as u64,
            "the changes of the interval the request does not carry"
        );
        let text_of = |cursor: u64| {
            ask.changes
                .iter()
                .find(|change| change.cursor == cursor)
                .and_then(|change| change.text.as_ref().map(|text| text.as_str().to_owned()))
        };
        assert_eq!(
            text_of(78).as_deref(),
            Some("words 78"),
            "the host's own words"
        );
        assert_eq!(
            text_of(77).as_deref(),
            Some("read from the worker"),
            "the text read for the change"
        );
        assert_eq!(
            text_of(79),
            None,
            "a text that was not read is not guessed at"
        );
        assert_eq!(
            ask.changes
                .iter()
                .find(|change| change.cursor == 78)
                .map(|change| change.kind),
            Some("command_completed")
        );
        let empty = SummarySource {
            from_cursor: 3,
            head: 3,
            changes: Vec::new(),
        };
        assert!(summary_ask(session, &empty, &BTreeMap::new(), None).is_none());
    }

    /// KR-REQ-18.02: the order of a log is the order its changes were recorded in, and a session's
    /// question records are read before its host's own events, so it is not the order they
    /// happened in. The moments a request carries are the earliest and the latest of every change
    /// the log retains in the interval, whichever place they have in it.
    #[test]
    fn a_summary_request_carries_the_earliest_and_latest_moments_whatever_their_order_in_the_log() {
        use kr_attention::visit::{Change, SummarySource};
        use kr_protocol::attention::SemanticChangeKind;

        let session = SessionId::new(kr_protocol::scalars::Uuid::from_bytes([7; 16]));
        let change = |cursor: u64, at_ms: u64| Change {
            cursor,
            kind: SemanticChangeKind::AdapterState,
            session_id: session,
            text: Text::Host(format!("words {cursor}")),
            at_ms: TimestampMs::new(at_ms),
        };
        let source = SummarySource {
            from_cursor: 10,
            head: 13,
            changes: vec![change(10, 2_000), change(11, 1_000), change(12, 1_500)],
        };
        let ask = summary_ask(session, &source, &BTreeMap::new(), None).expect("a request");
        assert_eq!((ask.from_ms, ask.to_ms), (1_000, 2_000));
    }

    /// KR-REQ-18.02 and KR-REQ-24.11: what text was read for a summary is bound to the generation
    /// the worker decided it under, and a worker that did not say which, or answered under two,
    /// leaves nothing to bind it to: the request is not made.
    #[test]
    fn the_generation_text_was_read_under_is_one_the_worker_named() {
        let session = SessionId::new(kr_protocol::scalars::Uuid::from_bytes([7; 16]));
        let elsewhere = SessionId::new(kr_protocol::scalars::Uuid::from_bytes([8; 16]));
        let entry = |session_id: SessionId, generation: Option<u64>| TicketEntry {
            session_id,
            generation,
            release_until: 0,
        };
        let ticket = |entries: Vec<TicketEntry>| Ticket {
            entries,
            generated: None,
        };
        let named = |generation: u64| Some(kr_worker::privacy::PrivacyGeneration::new(generation));
        assert_eq!(ticket(Vec::new()).generation_of(session), Ok(None));
        assert_eq!(
            ticket(vec![entry(session, Some(4))]).generation_of(session),
            Ok(named(4))
        );
        assert_eq!(
            ticket(vec![entry(session, Some(4)), entry(session, Some(4))]).generation_of(session),
            Ok(named(4)),
            "two batches under one generation"
        );
        assert_eq!(
            ticket(vec![entry(session, Some(4)), entry(session, Some(5))]).generation_of(session),
            Err(())
        );
        assert_eq!(
            ticket(vec![entry(session, None)]).generation_of(session),
            Err(()),
            "an answer that does not say"
        );
        assert_eq!(
            ticket(vec![entry(elsewhere, None)]).generation_of(session),
            Ok(None),
            "another session's answers are its own"
        );
    }

    /// KR-REQ-18.02: a summary is written from every change in an interval, so it is served only to
    /// a caller whose authority reaches back to the earliest of them: the owner's always does, a
    /// paired device's when its grant's history starts at or before it, and a grant with no lower
    /// bound retains no history and reaches none.
    #[test]
    fn a_summary_is_for_a_caller_whose_history_reaches_the_earliest_change() {
        let device = |history_lower_bound_ms: Option<u64>| Caller::Device {
            grant_id: GrantId::new(kr_protocol::scalars::Uuid::from_bytes([1; 16])),
            session_view: true,
            automation_manage: false,
            host_manage: false,
            sessions: kr_protocol::grant::SessionSelector::Any,
            history_lower_bound_ms: history_lower_bound_ms.map(TimestampMs::new),
        };
        assert!(Caller::Owner.reaches_back_to(0));
        assert!(device(Some(1_000)).reaches_back_to(1_000), "at the moment");
        assert!(device(Some(900)).reaches_back_to(1_000), "before it");
        assert!(!device(Some(1_001)).reaches_back_to(1_000), "after it");
        assert!(!device(None).reaches_back_to(1_000), "no history at all");
    }

    /// A reach that connects to nothing and answers a closure as the test says.
    struct Stub {
        unaccounted: bool,
    }

    impl Reach for Stub {
        fn connect<'a>(
            &'a self,
            _worker: &'a KnownWorker,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<LocalClient>> + Send + 'a>>
        {
            Box::pin(async { Err(ControllerError::supervision("this test connects nothing")) })
        }

        fn unaccounted<'a>(
            &'a self,
            _session_id: SessionId,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + 'a>> {
            let unaccounted = self.unaccounted;
            Box::pin(async move { unaccounted })
        }

        fn closed_journal(&self, _session_id: SessionId) -> Option<kr_worker::journal::Journal> {
            None
        }

        fn output_floor(&self, _session_id: SessionId) -> Option<u64> {
            None
        }
    }

    fn module(temp: &kr_ipc::testing::TempHost) -> Arc<AttentionModule> {
        Arc::new(
            AttentionModule::open(
                &temp.environment(),
                kr_ipc::identity::boot_identity().expect("a boot identity"),
            )
            .expect("the store opens"),
        )
    }

    /// A link for one session of `module`, put in place as the session's, and the far end of its
    /// connection for the test to play the worker.
    async fn linked(
        temp: &kr_ipc::testing::TempHost,
        display: u64,
        module: &Arc<AttentionModule>,
        session_id: SessionId,
    ) -> (Arc<Link>, FrameReader, FrameWriter) {
        let endpoint = temp
            .environment()
            .worker_endpoint(DisplayNumber::new(display))
            .expect("an endpoint");
        let listener = kr_ipc::endpoint::Listener::bind(&endpoint).expect("binds");
        let accepting = tokio::spawn(async move { listener.accept().await.expect("accepts").0 });
        let near = kr_ipc::endpoint::Connection::connect(&endpoint)
            .await
            .expect("connects");
        let far = accepting.await.expect("accepted");
        let (near_reader, near_writer) = kr_ipc::framed::split(near, StreamKind::Control);
        let (far_reader, far_writer) = kr_ipc::framed::split(far, StreamKind::Control);
        let link = Arc::new(Link::new(near_writer, session_id, Arc::downgrade(module)));
        module.origins().links.insert(session_id, Arc::clone(&link));
        tokio::spawn(Link::read_loop(Arc::clone(&link), near_reader));
        (link, far_reader, far_writer)
    }

    /// The end of a lease a worker issues now.
    fn lease_from_now() -> U64 {
        U64::new(kr_ipc::clock::boot_elapsed_ms() + kr_protocol::attention::ATTENTION_TEXT_LEASE_MS)
    }

    /// A page carrying one question a verified source asked.
    fn question_page(session_id: SessionId) -> AttentionSourcePage {
        let now = TimestampMs::new(kr_ipc::now_ms().get());
        AttentionSourcePage {
            request_id: RequestId::new(1),
            built_at_boot_ms: U64::new(kr_ipc::clock::boot_elapsed_ms()),
            questions: AttentionQuestionSlice {
                head: U64::new(1),
                records: vec![AttentionQuestionRecord {
                    sequence: U64::new(1),
                    kind: QuestionEventKind::Created,
                    question_id: QuestionId::new(kr_ipc::new_uuid()),
                    session_id,
                    verified: true,
                    pending_since_ms: now,
                    recorded_at_ms: now,
                    text: Nullable::null(),
                }],
            },
            host_events: AttentionHostSlice {
                head: U64::ZERO,
                records: Vec::new(),
            },
            privacy_generation: Nullable::some(U64::ZERO),
            output_floor: Nullable::null(),
        }
    }

    fn inbox_request() -> Request {
        Request {
            request_id: RequestId::new(7),
            method: Method::AttentionRead.into(),
            method_version: MethodVersion::V1,
            params: ParamsValue::from_typed(&AttentionReadParams {
                session_id: Nullable::null(),
                include_acknowledged: true,
                max_items: U64::new(50),
                after: Nullable::null(),
            })
            .expect("encodes"),
        }
    }

    fn owner() -> ActorId {
        ActorId::new("local:501").expect("an actor")
    }

    /// A session whose changes a summary is asked for, over a module that a description module is
    /// attached to. The description module's host has selected a model profile and starts no
    /// process, so what it was asked for is what the test reads from it, and what has been written
    /// is what the test puts in the store.
    struct Summarised {
        temp: kr_ipc::testing::TempHost,
        module: Arc<AttentionModule>,
        descriptions: Arc<crate::describe::DescribeModule>,
        host: crate::describe::host::tests::ByHand,
        privacy: crate::privacy::PrivacyState,
        session_id: SessionId,
    }

    impl Summarised {
        fn start() -> Self {
            let temp = kr_ipc::testing::TempHost::create();
            let module = module(&temp);
            let descriptions = Arc::new(
                crate::describe::DescribeModule::open(temp.environment().state_dir())
                    .expect("the description store"),
            );
            let host = crate::describe::host::tests::ByHand::selecting();
            descriptions
                .set_host(host.handle())
                .expect("the first host");
            let privacy = crate::privacy::PrivacyState::default();
            module.attach_privacy(privacy.clone());
            module.attach_descriptions(Arc::clone(&descriptions));
            Self {
                temp,
                module,
                descriptions,
                host,
                privacy,
                session_id: SessionId::new(kr_ipc::new_uuid()),
            }
        }

        /// Puts in the description store a summary of the session's changes from the cursor `from`
        /// to the cursor `to`, as the host's profile wrote it in the generation in force.
        fn write_summary(&self, from: u64, to: u64, text: &str) {
            let handle = self.host.handle();
            let profile = handle.profile().expect("the host selected a profile");
            self.descriptions
                .store()
                .publish_summary(&kr_describe::summary::SummaryRecord {
                    session_id: self.session_id,
                    cursor: kr_describe::context::CursorInterval::new(from, to),
                    from_ms: 1_000,
                    to_ms: 1_010,
                    text: kr_describe::metadata::SummaryText::new(text).expect("a summary"),
                    profile_id: profile.profile_id().to_owned(),
                    profile_revision: profile.revision(),
                    generation: self.privacy.now().generation,
                    produced_at_ms: 1,
                })
                .expect("the summary is kept");
        }

        /// Records one command that completed in the session for each moment given, in the order
        /// given. The text of a change a session's own event gave is read from its worker; the
        /// text of one the host recorded is the host's own words.
        fn record_commands(&self, moments: &[u64], from_the_session: bool) {
            let events: Vec<kr_attention::SourceEvent> = moments
                .iter()
                .zip(1_u64..)
                .map(|(at_ms, sequence)| {
                    let cursor = if from_the_session {
                        EventCursor::in_session(
                            self.session_id,
                            AttentionSource::HostEvents,
                            sequence,
                        )
                    } else {
                        EventCursor::new(AttentionSource::Semantic, sequence)
                    };
                    kr_attention::SourceEvent::new(
                        cursor,
                        TimestampMs::new(*at_ms),
                        kr_attention::EventKind::CommandCompleted {
                            session_id: self.session_id,
                            command: "cargo test".to_owned(),
                            exit_code: 0,
                        },
                    )
                })
                .collect();
            self.module
                .observe(&events)
                .expect("the events are recorded");
        }

        /// A read of what changed in the session that asks for a summary.
        fn visit_changed(&self) -> Request {
            Request {
                request_id: RequestId::new(7),
                method: Method::VisitChanged.into(),
                method_version: MethodVersion::V1,
                params: ParamsValue::from_typed(&VisitChangedParams {
                    session_id: self.session_id,
                    max_changes: U64::new(50),
                    summarise: true,
                })
                .expect("encodes"),
            }
        }

        /// What `caller` is answered when it asks what changed and asks for a summary.
        async fn changed_for(&self, actor: &ActorId, caller: &Caller) -> VisitChangedResult {
            self.module
                .read(
                    &Stub { unaccounted: false },
                    caller,
                    actor,
                    &self.visit_changed(),
                )
                .await
                .expect("the changes are served")
                .to_typed()
                .expect("decodes")
        }

        /// The summaries the daemon has asked the description host for, in the order it asked.
        fn asked(&mut self) -> Vec<kr_describe::summary::SummaryAsk> {
            self.host.asked_summaries()
        }
    }

    /// A paired device whose grant's history starts at `bound`.
    fn device_from(bound: u64) -> Caller {
        Caller::Device {
            grant_id: GrantId::new(kr_protocol::scalars::Uuid::from_bytes([1; 16])),
            session_view: true,
            automation_manage: false,
            host_manage: false,
            sessions: kr_protocol::grant::SessionSelector::Any,
            history_lower_bound_ms: Some(TimestampMs::new(bound)),
        }
    }

    /// KR-REQ-18.02: a summary is asked for only by a caller whose history reaches back to the
    /// earliest of the changes it is written from, and the log holds them in the order they were
    /// recorded, not the order they happened in. A grant that starts after the earliest asks for
    /// nothing, though it starts before the first the log holds; one that starts at the earliest
    /// asks for the interval with the moments of its earliest and latest change.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_grant_that_starts_after_the_earliest_change_asks_for_no_summary() {
        let mut world = Summarised::start();
        world.record_commands(&[2_000, 1_000, 1_500], false);
        let reader = ActorId::new("test:device").expect("an actor");

        let late = world.changed_for(&reader, &device_from(1_500)).await;
        assert_eq!(late.changes.len(), 3);
        assert!(late.summary.0.is_none());
        assert_eq!(world.asked(), Vec::new(), "nothing is asked for");

        world.changed_for(&reader, &device_from(1_000)).await;
        let asked = world.asked();
        assert_eq!(asked.len(), 1, "{asked:?}");
        assert_eq!(
            (asked[0].interval.from, asked[0].interval.to),
            (0, 3),
            "the interval the log holds"
        );
        assert_eq!((asked[0].from_ms, asked[0].to_ms), (1_000, 2_000));
    }

    /// KR-REQ-18.02: a summary is asked for from the page the answer carries it beside. A visit
    /// that is recorded while the answer waits for session text moves the cursor the changes are
    /// read from, and the interval frozen with the page is the one the summary is asked for.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_summary_is_asked_for_over_the_interval_its_page_was_read_from() {
        let mut world = Summarised::start();
        world.record_commands(&[1_000, 1_010], false);
        let (arrived, go) = world.module.after_page.arm();
        let reading = {
            let module = Arc::clone(&world.module);
            let request = world.visit_changed();
            tokio::spawn(async move {
                module
                    .read(
                        &Stub { unaccounted: false },
                        &Caller::Owner,
                        &owner(),
                        &request,
                    )
                    .await
            })
        };
        tokio::task::spawn_blocking(move || arrived.recv())
            .await
            .expect("the wait ends")
            .expect("the read reached its page");
        // The person visits while the read waits: the first cursor of what changed moves on.
        world
            .module
            .store()
            .expect("the store")
            .acknowledge_visit(&owner(), world.session_id, 1, Vec::new())
            .expect("the visit is recorded");
        go.send(()).expect("the read goes on");
        let served: VisitChangedResult = reading
            .await
            .expect("the read finishes")
            .expect("the changes are served")
            .to_typed()
            .expect("decodes");

        assert_eq!(served.from_cursor, U64::new(0));
        let asked = world.asked();
        assert_eq!(asked.len(), 1, "{asked:?}");
        assert_eq!(
            (asked[0].interval.from, asked[0].interval.to),
            (0, 2),
            "the interval of the page, not of the visit that came after it"
        );
    }

    /// The summary an answer to a read of what changed carries, when it carries one.
    fn summary_in(frame: &ControlFrame) -> Option<kr_protocol::attention::ChangeSummary> {
        let ControlFrame::Response(response) = frame else {
            panic!("a response");
        };
        let Outcome::Ok(value) = &response.outcome else {
            panic!("the read was refused");
        };
        value
            .to_typed::<VisitChangedResult>()
            .expect("decodes")
            .summary
            .0
    }

    /// KR-REQ-18.02 and KR-REQ-24.11: an answer that carries a summary is written only while the
    /// privacy state it was decided under holds. One that is held while privacy mode is enabled is
    /// taken back, and the same answer without the summary is written instead, as it is for an
    /// answer that carries session text. The control is the same answer written while nothing has
    /// changed.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_answer_held_while_privacy_mode_is_enabled_carries_no_summary() {
        let world = Summarised::start();
        world.record_commands(&[1_000, 1_010], false);
        world.write_summary(0, 2, "Two commands ran");
        let read = || async {
            world
                .module
                .read_released(
                    &Stub { unaccounted: false },
                    &Caller::Owner,
                    &owner(),
                    &world.visit_changed(),
                )
                .await
        };

        let held = read().await;
        assert_eq!(
            summary_in(&held.frame).map(|summary| summary.text),
            Some("Two commands ran".to_owned()),
            "the answer carries the summary"
        );
        let (mut writer, mut reader) = owner_connection(&world.temp, 1).await;
        let unchanged = read().await;
        world
            .module
            .write_released(&mut writer, StreamKind::Control, unchanged)
            .await
            .expect("the answer is written");
        let written = reader.read_message::<ControlFrame>().await.expect("read");
        assert!(summary_in(&written).is_some(), "nothing changed");

        world.privacy.set(crate::privacy::Published {
            generation: kr_worker::privacy::PrivacyGeneration::new(1),
            private: true,
        });
        world
            .module
            .write_released(&mut writer, StreamKind::Control, held)
            .await
            .expect("the answer without the summary is written");
        let written = reader.read_message::<ControlFrame>().await.expect("read");
        assert_eq!(summary_in(&written), None, "privacy mode was enabled");
        let ControlFrame::Response(Response {
            outcome: Outcome::Ok(value),
            ..
        }) = written
        else {
            panic!("a response");
        };
        assert_eq!(
            value
                .to_typed::<VisitChangedResult>()
                .expect("decodes")
                .changes
                .len(),
            2,
            "the changes are what they were"
        );
    }

    /// A page that arrives after its session's closure is not taken: the closure holds the store
    /// while it takes the link away, and the page is taken only from the link that speaks for the
    /// session then. A page from a link that still does is taken.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_page_that_arrives_after_its_session_closed_is_not_taken() {
        let temp = kr_ipc::testing::TempHost::create();
        let module = module(&temp);
        let closed = SessionId::new(kr_ipc::new_uuid());
        let open = SessionId::new(kr_ipc::new_uuid());
        let (closed_link, _closed_reader, _closed_writer) = linked(&temp, 1, &module, closed).await;
        let (open_link, _open_reader, _open_writer) = linked(&temp, 2, &module, open).await;

        module
            .session_closed(&Stub { unaccounted: true }, closed)
            .await;
        let late = module
            .take_page(closed, &closed_link, 0, 0, &question_page(closed))
            .await
            .expect("the store answers");
        assert!(matches!(late, Taken::Stale));
        let current = module
            .take_page(open, &open_link, 0, 0, &question_page(open))
            .await
            .expect("the store answers");
        assert!(matches!(current, Taken::Complete));

        let items = module
            .store()
            .expect("the store")
            .inbox(&owner(), &Viewer::Owner, true)
            .expect("the inbox");
        assert_eq!(items.len(), 1, "{items:?}");
        assert_eq!(items[0].session_id, Nullable::some(open));
        assert!(!module.origins().certified.contains_key(&closed));
    }

    /// Text a worker answered is served only if its session still stands when every owner has
    /// answered: a session closed over a worker this host could not account for while the read
    /// waited for another session serves none of it, and a session that stands serves its own.
    #[tokio::test(flavor = "multi_thread")]
    async fn text_answered_before_an_unaccounted_closure_is_not_served_after_it() {
        let temp = kr_ipc::testing::TempHost::create();
        let module = module(&temp);
        let closing = SessionId::new(kr_ipc::new_uuid());
        let slow = SessionId::new(kr_ipc::new_uuid());
        let standing = SessionId::new(kr_ipc::new_uuid());
        let mut ends = BTreeMap::new();
        for (display, session_id) in [(1, closing), (2, slow), (3, standing)] {
            let (link, reader, writer) = linked(&temp, display, &module, session_id).await;
            module
                .take_page(session_id, &link, 0, 0, &question_page(session_id))
                .await
                .expect("the page is taken");
            ends.insert(session_id, (reader, writer));
        }

        let reading = {
            let module = Arc::clone(&module);
            tokio::spawn(async move {
                module
                    .read(
                        &Stub { unaccounted: true },
                        &Caller::Owner,
                        &owner(),
                        &inbox_request(),
                    )
                    .await
            })
        };
        // The two workers that answer do so at once; the slow one never does, so the read waits
        // for it until its bound.
        for session_id in [closing, standing] {
            let (reader, writer) = ends.get_mut(&session_id).expect("its end");
            let ControlFrame::AttentionText(request) = reader
                .read_message::<ControlFrame>()
                .await
                .expect("the text is asked for")
            else {
                panic!("a text request");
            };
            writer
                .write_message(&ControlFrame::AttentionTextAnswer(Box::new(
                    AttentionTextAnswer {
                        request_id: request.request_id,
                        privacy_generation: Nullable::some(U64::ZERO),
                        release_until_boot_ms: lease_from_now(),
                        texts: request
                            .records
                            .iter()
                            .map(|record| AttentionRecordText {
                                source: record.source,
                                sequence: record.sequence,
                                text: Nullable::some(format!("asked in {session_id}")),
                            })
                            .collect(),
                    },
                )))
                .await
                .expect("answers");
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
        module
            .session_closed(&Stub { unaccounted: true }, closing)
            .await;

        let started = Instant::now();
        let read: AttentionReadResult = reading
            .await
            .expect("the read finishes")
            .expect("the inbox reads")
            .to_typed()
            .expect("decodes");
        assert!(started.elapsed() < TEXT_WAIT + Duration::from_secs(5));
        let summary = |session_id: SessionId| {
            read.items
                .iter()
                .find(|item| item.session_id == Nullable::some(session_id))
                .expect("the item")
                .summary
                .0
                .clone()
        };
        assert_eq!(
            summary(closing),
            None,
            "its closure came before the text was served"
        );
        assert_eq!(summary(slow), None, "it never answered");
        assert_eq!(summary(standing), Some(format!("asked in {standing}")));
    }

    /// More records than one text request carries are asked for in requests that each carry no
    /// more, and every record is answered where it stood.
    #[tokio::test(flavor = "multi_thread")]
    async fn more_records_than_one_text_request_carries_are_asked_for_in_batches() {
        let temp = kr_ipc::testing::TempHost::create();
        let module = module(&temp);
        let session_id = SessionId::new(kr_ipc::new_uuid());
        let (_link, mut reader, mut writer) = linked(&temp, 1, &module, session_id).await;
        let records: Vec<(usize, EventCursor)> = (0..300_u64)
            .map(|sequence| {
                (
                    usize::try_from(sequence).expect("small"),
                    EventCursor::in_session(session_id, AttentionSource::HostEvents, sequence + 1),
                )
            })
            .collect();
        let asking = {
            let module = Arc::clone(&module);
            tokio::spawn(async move { module.texts(&Stub { unaccounted: false }, &records).await })
        };
        let mut sizes = Vec::new();
        for _ in 0..2 {
            let ControlFrame::AttentionText(request) = reader
                .read_message::<ControlFrame>()
                .await
                .expect("the text is asked for")
            else {
                panic!("a text request");
            };
            sizes.push(request.records.len());
            writer
                .write_message(&ControlFrame::AttentionTextAnswer(Box::new(
                    AttentionTextAnswer {
                        request_id: request.request_id,
                        privacy_generation: Nullable::some(U64::ZERO),
                        release_until_boot_ms: lease_from_now(),
                        texts: request
                            .records
                            .iter()
                            .map(|record| AttentionRecordText {
                                source: record.source,
                                sequence: record.sequence,
                                text: Nullable::some(format!("record {}", record.sequence.get())),
                            })
                            .collect(),
                    },
                )))
                .await
                .expect("answers");
        }
        sizes.sort_unstable();
        assert_eq!(sizes, vec![44, 256]);
        let (mut served, ticket) = asking.await.expect("the texts are read");
        assert_eq!(
            ticket.entries.len(),
            2,
            "each answer that carried text is on the ticket"
        );
        served.sort_by_key(|(index, _)| *index);
        assert_eq!(served.len(), 300);
        for (index, text) in served {
            assert_eq!(text, Some(format!("record {}", index + 1)));
        }
    }

    /// A worker's statement of its privacy fence.
    fn statement(sequence: u64, raised: bool, generation: Option<u64>) -> ControlFrame {
        ControlFrame::AttentionBarrier(AttentionBarrier {
            request_id: RequestId::new(sequence),
            sequence: U64::new(sequence),
            raised,
            generation: Nullable(generation.map(U64::new)),
        })
    }

    /// What the daemon knows of a session's fence now.
    async fn fence_of(module: &AttentionModule, session_id: SessionId) -> SessionFence {
        module
            .release
            .read()
            .await
            .get(&session_id)
            .copied()
            .unwrap_or_default()
    }

    /// Sets what the daemon knows of a session's fence, as statements and answers would.
    async fn set_fence(module: &AttentionModule, session_id: SessionId, fence: SessionFence) {
        module.release.write().await.insert(session_id, fence);
    }

    /// A ticket for text answered in each session under `generation`, released until `until`.
    fn ticket(sessions: &[SessionId], generation: u64, until: u64) -> Ticket {
        Ticket {
            entries: sessions
                .iter()
                .map(|session_id| TicketEntry {
                    session_id: *session_id,
                    generation: Some(generation),
                    release_until: until,
                })
                .collect(),
            generated: None,
        }
    }

    /// An answer carrying `bytes` bytes of text: more than a peer that stops reading takes whole.
    fn answer_of(bytes: usize) -> ControlFrame {
        frame(
            RequestId::new(7),
            Ok(ParamsValue::from_typed(&"t".repeat(bytes)).expect("encodes")),
        )
    }

    /// The same answer with its text withheld.
    fn withheld() -> ControlFrame {
        frame(
            RequestId::new(7),
            Ok(ParamsValue::from_typed(&String::new()).expect("encodes")),
        )
    }

    /// An owner's connection for the test to write an answer on, and its far end, which reads
    /// nothing until the test does.
    pub(crate) async fn owner_connection(
        temp: &kr_ipc::testing::TempHost,
        display: u64,
    ) -> (FrameWriter, FrameReader) {
        let endpoint = temp
            .environment()
            .worker_endpoint(DisplayNumber::new(display))
            .expect("an endpoint");
        let listener = kr_ipc::endpoint::Listener::bind(&endpoint).expect("binds");
        let accepting = tokio::spawn(async move { listener.accept().await.expect("accepts").0 });
        let near = kr_ipc::endpoint::Connection::connect(&endpoint)
            .await
            .expect("connects");
        let far = accepting.await.expect("accepted");
        let (_, writer) = kr_ipc::framed::split(near, StreamKind::Control);
        let (reader, _) = kr_ipc::framed::split(far, StreamKind::Control);
        (writer, reader)
    }

    /// KR-REQ-24.11: a statement is applied only from the link that speaks for its session and
    /// only after the last one applied from that link, and is acknowledged once applied; a page
    /// records its generation but lowers no barrier.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_statement_is_applied_only_from_the_session_s_link_and_after_the_last() {
        let temp = kr_ipc::testing::TempHost::create();
        let module = module(&temp);
        let session_id = SessionId::new(kr_ipc::new_uuid());
        let (_link, mut reader, mut writer) = linked(&temp, 1, &module, session_id).await;

        writer
            .write_message(&statement(5, true, Some(0)))
            .await
            .expect("states");
        let ControlFrame::AttentionBarrierAcknowledged(acknowledged) = reader
            .read_message::<ControlFrame>()
            .await
            .expect("acknowledged")
        else {
            panic!("an acknowledgement");
        };
        assert_eq!(acknowledged.sequence, U64::new(5));
        let fence = fence_of(&module, session_id).await;
        assert!(fence.barrier);
        assert_eq!(fence.recorded, Some(0));

        // An earlier statement that arrives late is neither applied nor acknowledged.
        writer
            .write_message(&statement(4, false, Some(0)))
            .await
            .expect("states");
        assert!(
            tokio::time::timeout(
                Duration::from_millis(300),
                reader.read_message::<ControlFrame>()
            )
            .await
            .is_err()
        );
        assert!(fence_of(&module, session_id).await.barrier);

        // A page records a later generation and lowers nothing.
        writer
            .write_message(&ControlFrame::AttentionSourcePage(Box::new(
                AttentionSourcePage {
                    privacy_generation: Nullable::some(U64::new(1)),
                    ..question_page(session_id)
                },
            )))
            .await
            .expect("pages");
        tokio::time::sleep(Duration::from_millis(200)).await;
        let fence = fence_of(&module, session_id).await;
        assert_eq!(fence.recorded, Some(1));
        assert!(fence.barrier, "only a statement lowers a barrier");

        // A link that no longer speaks for the session is not listened to; the one that does
        // starts an order of its own.
        let (_newer, mut newer_reader, mut newer_writer) =
            linked(&temp, 2, &module, session_id).await;
        writer
            .write_message(&statement(9, false, Some(1)))
            .await
            .expect("states");
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(fence_of(&module, session_id).await.barrier);
        newer_writer
            .write_message(&statement(1, false, Some(1)))
            .await
            .expect("states");
        let ControlFrame::AttentionBarrierAcknowledged(acknowledged) = newer_reader
            .read_message::<ControlFrame>()
            .await
            .expect("acknowledged")
        else {
            panic!("an acknowledgement");
        };
        assert_eq!(acknowledged.sequence, U64::new(1));
        let fence = fence_of(&module, session_id).await;
        assert!(!fence.barrier);
        assert_eq!(fence.recorded, Some(1));
    }

    /// KR-REQ-24.11: a statement that cannot name the session's generation lowers no barrier and
    /// moves no recorded generation, whatever it says about a transition.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_statement_that_names_no_generation_lowers_no_barrier() {
        let temp = kr_ipc::testing::TempHost::create();
        let module = module(&temp);
        let session_id = SessionId::new(kr_ipc::new_uuid());
        let (_link, mut reader, mut writer) = linked(&temp, 1, &module, session_id).await;
        for (sequence, raised, generation) in [(1, true, Some(0)), (2, false, None)] {
            writer
                .write_message(&statement(sequence, raised, generation))
                .await
                .expect("states");
            let _ = reader
                .read_message::<ControlFrame>()
                .await
                .expect("acknowledged");
        }
        let fence = fence_of(&module, session_id).await;
        assert!(fence.barrier, "the barrier stands");
        assert_eq!(fence.recorded, Some(0));
    }

    /// KR-REQ-24.11: a session closed over a worker the host could not account for releases
    /// nothing more of what its worker answered: not an answer already put together for a reader,
    /// not the rest of one part way to its reader, and not a delivery's text. A closure the host
    /// could account for leaves the answers its worker gave releasable.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_unaccounted_closure_stops_what_its_worker_answered() {
        let temp = kr_ipc::testing::TempHost::create();
        let module = module(&temp);
        let closing = SessionId::new(kr_ipc::new_uuid());
        let (link, mut reader, mut writer) = linked(&temp, 1, &module, closing).await;
        module
            .take_page(closing, &link, 0, 0, &question_page(closing))
            .await
            .expect("the page is taken");
        let assembling = {
            let module = Arc::clone(&module);
            tokio::spawn(async move {
                module
                    .read_released(
                        &Stub { unaccounted: true },
                        &Caller::Owner,
                        &owner(),
                        &inbox_request(),
                    )
                    .await
            })
        };
        let ControlFrame::AttentionText(request) =
            reader.read_message::<ControlFrame>().await.expect("asked")
        else {
            panic!("a text request");
        };
        writer
            .write_message(&ControlFrame::AttentionTextAnswer(Box::new(
                AttentionTextAnswer {
                    request_id: request.request_id,
                    privacy_generation: Nullable::some(U64::ZERO),
                    release_until_boot_ms: lease_from_now(),
                    texts: request
                        .records
                        .iter()
                        .map(|record| AttentionRecordText {
                            source: record.source,
                            sequence: record.sequence,
                            text: Nullable::some("which branch?".to_owned()),
                        })
                        .collect(),
                },
            )))
            .await
            .expect("answers");
        let assembled = assembling.await.expect("the read finishes");
        assert!(!assembled.ticket.is_empty(), "the answer carries live text");

        // A delivery's ticket and an answer part way to its reader, from the same session.
        let delivery = ticket(&[closing], 0, lease_from_now().get());
        assert_eq!(module.release_delivery(&delivery, || 1).await, Some(1));
        let (mut partway, mut partway_reader) = owner_connection(&temp, 2).await;
        let writing = {
            let module = Arc::clone(&module);
            let ticket = ticket(&[closing], 0, lease_from_now().get());
            tokio::spawn(async move {
                let written = module
                    .write_released(
                        &mut partway,
                        StreamKind::Control,
                        Released {
                            frame: answer_of(900 * 1024),
                            withheld: Some(withheld()),
                            ticket,
                        },
                    )
                    .await;
                drop(partway);
                written
            })
        };
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(!writing.is_finished());

        module
            .session_closed(&Stub { unaccounted: true }, closing)
            .await;
        let draining =
            tokio::spawn(async move { partway_reader.read_message::<ControlFrame>().await });
        assert!(
            tokio::time::timeout(Duration::from_secs(5), writing)
                .await
                .expect("the write stops")
                .expect("the write finishes")
                .is_err(),
            "the rest of the answer does not go"
        );
        let _ = draining.await;
        assert_eq!(module.release_delivery(&delivery, || 1).await, None);
        let (mut whole, mut whole_reader) = owner_connection(&temp, 3).await;
        module
            .write_released(&mut whole, StreamKind::Control, assembled)
            .await
            .expect("the withheld answer is written");
        let read = whole_reader
            .read_message::<ControlFrame>()
            .await
            .expect("the reader gets an answer");
        let ControlFrame::Response(response) = read else {
            panic!("a response");
        };
        let Outcome::Ok(value) = response.outcome else {
            panic!("the read was refused");
        };
        let inbox: AttentionReadResult = value.to_typed().expect("decodes");
        assert!(inbox.items.iter().all(|item| !item.summary.is_present()));

        // A closure the host could account for keeps what the worker answered releasable.
        let handed_over = SessionId::new(kr_ipc::new_uuid());
        set_fence(
            &module,
            handed_over,
            SessionFence {
                recorded: Some(0),
                ..SessionFence::default()
            },
        )
        .await;
        let kept = ticket(&[handed_over], 0, lease_from_now().get());
        module
            .session_closed(&Stub { unaccounted: false }, handed_over)
            .await;
        assert_eq!(module.release_delivery(&kept, || 1).await, Some(1));
    }

    /// KR-REQ-24.11: an owner's answer partly written when the barrier rises is not finished: the
    /// next transport write is refused, and the caller ends the connection, so the reader never
    /// holds the whole answer.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_owner_answer_partly_written_when_the_barrier_rises_is_cut() {
        let temp = kr_ipc::testing::TempHost::create();
        let module = module(&temp);
        let session_id = SessionId::new(kr_ipc::new_uuid());
        set_fence(
            &module,
            session_id,
            SessionFence {
                recorded: Some(0),
                ..SessionFence::default()
            },
        )
        .await;
        let (mut writer, mut reader) = owner_connection(&temp, 1).await;
        let released = Released {
            frame: answer_of(900 * 1024),
            withheld: Some(withheld()),
            ticket: ticket(&[session_id], 0, lease_from_now().get()),
        };
        let writing = {
            let module = Arc::clone(&module);
            tokio::spawn(async move {
                let written = module
                    .write_released(&mut writer, StreamKind::Control, released)
                    .await;
                drop(writer);
                written
            })
        };
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(!writing.is_finished(), "the reader has taken part of it");

        fence_raised(&module, session_id).await;
        let reading = tokio::spawn(async move { reader.read_message::<ControlFrame>().await });
        let written = tokio::time::timeout(Duration::from_secs(5), writing)
            .await
            .expect("the write stops")
            .expect("the write finishes");
        assert!(written.is_err(), "the answer is not finished");
        let read = tokio::time::timeout(Duration::from_secs(5), reading)
            .await
            .expect("the connection ends")
            .expect("the read finishes");
        assert!(read.is_err(), "the reader never holds the whole answer");
    }

    async fn fence_raised(module: &AttentionModule, session_id: SessionId) {
        module
            .release
            .write()
            .await
            .entry(session_id)
            .or_default()
            .barrier = true;
    }

    /// KR-REQ-24.11: an answer none of which has gone when its ticket stops holding is taken back,
    /// and the same answer with its text withheld goes instead; a read with text from two
    /// sessions is stopped by a transition in either.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_answer_none_of_which_went_is_answered_without_its_text() {
        let temp = kr_ipc::testing::TempHost::create();
        let module = module(&temp);
        let quiet = SessionId::new(kr_ipc::new_uuid());
        let moving = SessionId::new(kr_ipc::new_uuid());
        for session_id in [quiet, moving] {
            set_fence(
                &module,
                session_id,
                SessionFence {
                    recorded: Some(0),
                    ..SessionFence::default()
                },
            )
            .await;
        }
        fence_raised(&module, moving).await;
        let (mut writer, mut reader) = owner_connection(&temp, 1).await;
        module
            .write_released(
                &mut writer,
                StreamKind::Control,
                Released {
                    frame: answer_of(64),
                    withheld: Some(withheld()),
                    ticket: ticket(&[quiet, moving], 0, lease_from_now().get()),
                },
            )
            .await
            .expect("the withheld answer is written");
        let read = reader
            .read_message::<ControlFrame>()
            .await
            .expect("the reader gets an answer");
        assert_eq!(read, withheld());
    }

    /// KR-REQ-24.11: a lease that ends between two transport writes of one answer stops the
    /// second, and the answer is not finished.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_lease_that_ends_part_way_through_an_answer_stops_it() {
        let temp = kr_ipc::testing::TempHost::create();
        let module = module(&temp);
        let session_id = SessionId::new(kr_ipc::new_uuid());
        set_fence(
            &module,
            session_id,
            SessionFence {
                recorded: Some(0),
                ..SessionFence::default()
            },
        )
        .await;
        let (mut writer, mut reader) = owner_connection(&temp, 1).await;
        let until = kr_ipc::clock::boot_elapsed_ms() + RELEASE_MARGIN_MS + 400;
        let writing = {
            let module = Arc::clone(&module);
            tokio::spawn(async move {
                let written = module
                    .write_released(
                        &mut writer,
                        StreamKind::Control,
                        Released {
                            frame: answer_of(900 * 1024),
                            withheld: Some(withheld()),
                            ticket: ticket(&[session_id], 0, until),
                        },
                    )
                    .await;
                drop(writer);
                written
            })
        };
        tokio::time::sleep(Duration::from_millis(800)).await;
        // A writer the connection would not take more from waits for room where the platform parks
        // it, so the answer is still in hand once the lease has ended. Where a waiter polls, as it
        // does on Windows, it meets the lapse at its next poll and has already stopped.
        if cfg!(unix) {
            assert!(!writing.is_finished());
        }
        let reading = tokio::spawn(async move { reader.read_message::<ControlFrame>().await });
        let written = tokio::time::timeout(Duration::from_secs(5), writing)
            .await
            .expect("the write stops")
            .expect("the write finishes");
        // The refusal the write makes once part of the answer has gone and the lease no longer
        // holds, and not a failure of the connection or of the encoding before anything was sent.
        assert!(
            matches!(
                written,
                Err(kr_ipc::IpcError::Socket {
                    operation: "write",
                    ..
                })
            ),
            "no byte went after the lease ended: {written:?}"
        );
        assert!(
            tokio::time::timeout(Duration::from_secs(5), reading)
                .await
                .expect("the connection ends")
                .expect("the read finishes")
                .is_err()
        );
    }

    /// KR-REQ-24.11: a statement is applied while other sessions release text without pause: the
    /// release lock is fair, so an exclusive request stops new releases and waits only for the
    /// ones admitted before it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_statement_is_applied_while_other_sessions_release_without_pause() {
        let temp = kr_ipc::testing::TempHost::create();
        let module = module(&temp);
        let session_id = SessionId::new(kr_ipc::new_uuid());
        let (_link, mut reader, mut writer) = linked(&temp, 1, &module, session_id).await;
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut releasing = Vec::new();
        for _ in 0..3 {
            let module = Arc::clone(&module);
            let stop = Arc::clone(&stop);
            releasing.push(tokio::spawn(async move {
                while !stop.load(Ordering::SeqCst) {
                    let fences = module.release.read().await;
                    // One transport write's worth of holding it.
                    std::thread::sleep(Duration::from_millis(2));
                    drop(fences);
                    tokio::task::yield_now().await;
                }
            }));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        let started = Instant::now();
        writer
            .write_message(&statement(1, true, Some(0)))
            .await
            .expect("states");
        let acknowledged = tokio::time::timeout(
            Duration::from_secs(2),
            reader.read_message::<ControlFrame>(),
        )
        .await
        .expect("the statement is applied in time")
        .expect("acknowledged");
        assert!(matches!(
            acknowledged,
            ControlFrame::AttentionBarrierAcknowledged(_)
        ));
        assert!(started.elapsed() < Duration::from_secs(1));
        stop.store(true, Ordering::SeqCst);
        for task in releasing {
            task.await.expect("the release loop ends");
        }
    }

    /// KR-REQ-24.11: a delivery send is released one transport write at a time, and only while
    /// its text's ticket holds: not once the lease has ended, not while a transition is raised,
    /// and not once a later generation is recorded.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_delivery_send_is_released_only_while_its_ticket_holds() {
        let temp = kr_ipc::testing::TempHost::create();
        let module = module(&temp);
        let session_id = SessionId::new(kr_ipc::new_uuid());
        set_fence(
            &module,
            session_id,
            SessionFence {
                recorded: Some(0),
                ..SessionFence::default()
            },
        )
        .await;
        let short = ticket(
            &[session_id],
            0,
            kr_ipc::clock::boot_elapsed_ms() + RELEASE_MARGIN_MS + 300,
        );
        assert_eq!(module.release_delivery(&short, || 1).await, Some(1));
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(module.release_delivery(&short, || 1).await, None);

        let long = ticket(&[session_id], 0, lease_from_now().get());
        fence_raised(&module, session_id).await;
        assert_eq!(module.release_delivery(&long, || 1).await, None);
        set_fence(
            &module,
            session_id,
            SessionFence {
                recorded: Some(1),
                ..SessionFence::default()
            },
        )
        .await;
        assert_eq!(module.release_delivery(&long, || 1).await, None);
    }

    /// KR-REQ-24.11: text a worker answered before it raised a transition is withheld when the
    /// read that holds it releases after the raise, and a read with text from two sessions is
    /// stopped by the transition in one of them.
    #[tokio::test(flavor = "multi_thread")]
    async fn text_answered_before_a_raise_is_withheld_after_it() {
        let temp = kr_ipc::testing::TempHost::create();
        let module = module(&temp);
        let raising = SessionId::new(kr_ipc::new_uuid());
        let other = SessionId::new(kr_ipc::new_uuid());
        let mut ends = BTreeMap::new();
        for (display, session_id) in [(1, raising), (2, other)] {
            let (link, reader, writer) = linked(&temp, display, &module, session_id).await;
            module
                .take_page(session_id, &link, 0, 0, &question_page(session_id))
                .await
                .expect("the page is taken");
            ends.insert(session_id, (reader, writer));
        }
        let reading = {
            let module = Arc::clone(&module);
            tokio::spawn(async move {
                module
                    .read(
                        &Stub { unaccounted: false },
                        &Caller::Owner,
                        &owner(),
                        &inbox_request(),
                    )
                    .await
            })
        };
        let answer = |request: &AttentionTextRequest, session_id: SessionId| {
            ControlFrame::AttentionTextAnswer(Box::new(AttentionTextAnswer {
                request_id: request.request_id,
                privacy_generation: Nullable::some(U64::ZERO),
                release_until_boot_ms: lease_from_now(),
                texts: request
                    .records
                    .iter()
                    .map(|record| AttentionRecordText {
                        source: record.source,
                        sequence: record.sequence,
                        text: Nullable::some(format!("asked in {session_id}")),
                    })
                    .collect(),
            }))
        };
        // The raising session answers, then raises its transition before the other answers.
        {
            let (reader, writer) = ends.get_mut(&raising).expect("its end");
            let ControlFrame::AttentionText(request) =
                reader.read_message::<ControlFrame>().await.expect("asked")
            else {
                panic!("a text request");
            };
            writer
                .write_message(&answer(&request, raising))
                .await
                .expect("answers");
            writer
                .write_message(&statement(1, true, Some(0)))
                .await
                .expect("raises");
            let ControlFrame::AttentionBarrierAcknowledged(_) = reader
                .read_message::<ControlFrame>()
                .await
                .expect("acknowledged")
            else {
                panic!("an acknowledgement");
            };
        }
        {
            let (reader, writer) = ends.get_mut(&other).expect("its end");
            let ControlFrame::AttentionText(request) =
                reader.read_message::<ControlFrame>().await.expect("asked")
            else {
                panic!("a text request");
            };
            writer
                .write_message(&answer(&request, other))
                .await
                .expect("answers");
        }
        let read: AttentionReadResult = reading
            .await
            .expect("the read finishes")
            .expect("the inbox reads")
            .to_typed()
            .expect("decodes");
        assert_eq!(read.items.len(), 2);
        assert!(
            read.items.iter().all(|item| item.summary.0.is_none()),
            "the raise stops the whole answer: {:?}",
            read.items
        );
    }

    /// An answer the worker decided and sends on its way.
    fn text_answer(
        request: &AttentionTextRequest,
        generation: u64,
        release_until: u64,
    ) -> ControlFrame {
        ControlFrame::AttentionTextAnswer(Box::new(AttentionTextAnswer {
            request_id: request.request_id,
            privacy_generation: Nullable::some(U64::new(generation)),
            release_until_boot_ms: U64::new(release_until),
            texts: request
                .records
                .iter()
                .map(|record| AttentionRecordText {
                    source: record.source,
                    sequence: record.sequence,
                    text: Nullable::some("which branch?".to_owned()),
                })
                .collect(),
        }))
    }

    /// Reads the next text request the store sends a worker.
    async fn text_request(reader: &mut FrameReader) -> AttentionTextRequest {
        loop {
            match reader
                .read_message::<ControlFrame>()
                .await
                .expect("the store asks")
            {
                ControlFrame::AttentionText(request) => return request,
                ControlFrame::AttentionBarrierAcknowledged(_) => {}
                other => panic!("expected a text request, got {other:?}"),
            }
        }
    }

    /// KR-REQ-24.11: an answer that first reaches the daemon once its lease has ended, as one
    /// still on its way when the worker committed without an acknowledgement does, is withheld,
    /// though the daemon never heard of the transition and still records the answer's generation.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_answer_that_arrives_after_its_lease_is_withheld() {
        let temp = kr_ipc::testing::TempHost::create();
        let module = module(&temp);
        let session_id = SessionId::new(kr_ipc::new_uuid());
        let (link, mut reader, mut writer) = linked(&temp, 1, &module, session_id).await;
        module
            .take_page(session_id, &link, 0, 0, &question_page(session_id))
            .await
            .expect("the page is taken");
        let reading = {
            let module = Arc::clone(&module);
            tokio::spawn(async move {
                module
                    .read_released(
                        &Stub { unaccounted: false },
                        &Caller::Owner,
                        &owner(),
                        &inbox_request(),
                    )
                    .await
            })
        };
        let request = text_request(&mut reader).await;
        // Decided now with a lease past the margin, and delivered only once that lease has ended:
        // a worker without an acknowledgement commits no earlier than that.
        let until = kr_ipc::clock::boot_elapsed_ms() + RELEASE_MARGIN_MS + 300;
        while kr_ipc::clock::boot_elapsed_ms() < until {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        writer
            .write_message(&text_answer(&request, 0, until))
            .await
            .expect("answers");
        let released = reading.await.expect("the read finishes");
        // The answer reached the read in time: the response holds its text, bound by the
        // answer's own lease, and what withholds it is that lease, not a request left unanswered.
        let ControlFrame::Response(assembled) = &released.frame else {
            panic!("a response");
        };
        let Outcome::Ok(value) = &assembled.outcome else {
            panic!("the read was refused");
        };
        let assembled: AttentionReadResult = value.to_typed().expect("decodes");
        assert!(
            assembled.items.iter().any(|item| item.summary.is_present()),
            "the response was assembled with the answer's text"
        );
        assert!(released.withheld.is_some());
        assert!(!released.ticket.is_empty());
        assert!(
            released
                .ticket
                .entries
                .iter()
                .all(|entry| entry.release_until == until),
            "the ticket carries the answer's own lease"
        );
        let fence = fence_of(&module, session_id).await;
        assert!(!fence.barrier);
        assert_eq!(fence.recorded, Some(0));
        let (mut owner_writer, mut owner_reader) = owner_connection(&temp, 2).await;
        module
            .write_released(&mut owner_writer, StreamKind::Control, released)
            .await
            .expect("an answer is written");
        let ControlFrame::Response(response) = owner_reader
            .read_message::<ControlFrame>()
            .await
            .expect("the reader gets an answer")
        else {
            panic!("a response");
        };
        let Outcome::Ok(value) = response.outcome else {
            panic!("the read was refused");
        };
        let inbox: AttentionReadResult = value.to_typed().expect("decodes");
        assert!(inbox.items.iter().all(|item| !item.summary.is_present()));
    }

    /// KR-REQ-24.11: a raise the daemon learns only after the commit it announces holds back even
    /// text decided under the committed generation, until the statement that settles it.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_raise_that_arrives_after_its_commit_stands_until_it_is_settled() {
        let temp = kr_ipc::testing::TempHost::create();
        let module = module(&temp);
        let session_id = SessionId::new(kr_ipc::new_uuid());
        let (_link, mut reader, mut writer) = linked(&temp, 1, &module, session_id).await;
        // The commit reaches the daemon first, on a page, and the raise after it.
        writer
            .write_message(&ControlFrame::AttentionSourcePage(Box::new(
                AttentionSourcePage {
                    privacy_generation: Nullable::some(U64::new(1)),
                    ..question_page(session_id)
                },
            )))
            .await
            .expect("pages");
        writer
            .write_message(&statement(1, true, Some(0)))
            .await
            .expect("raises");
        let ControlFrame::AttentionBarrierAcknowledged(_) = reader
            .read_message::<ControlFrame>()
            .await
            .expect("acknowledged")
        else {
            panic!("an acknowledgement");
        };
        let current = ticket(&[session_id], 1, lease_from_now().get());
        let fence = fence_of(&module, session_id).await;
        assert_eq!(fence.recorded, Some(1));
        assert!(fence.barrier);
        assert_eq!(module.release_delivery(&current, || 1).await, None);
        writer
            .write_message(&statement(2, false, Some(1)))
            .await
            .expect("settles");
        let ControlFrame::AttentionBarrierAcknowledged(_) = reader
            .read_message::<ControlFrame>()
            .await
            .expect("acknowledged")
        else {
            panic!("an acknowledgement");
        };
        assert_eq!(module.release_delivery(&current, || 1).await, Some(1));
    }

    /// A timer that has fallen due for a session whose pages have not certified that moment is not
    /// a deadline the maintenance loop wakes for, and it is one once a certificate reaches it.
    #[tokio::test]
    async fn an_overdue_timer_without_a_certificate_is_not_a_deadline_to_wake_for() {
        let temp = kr_ipc::testing::TempHost::create();
        let module = module(&temp);
        let session_id = SessionId::new(kr_ipc::new_uuid());
        module
            .observe(&[SourceEvent::new(
                EventCursor::in_session(session_id, AttentionSource::Receipts, 1),
                kr_protocol::scalars::TimestampMs::new(kr_ipc::now_ms().get()),
                EventKind::ApprovalRequested {
                    request_id: kr_protocol::ids::ApprovalRequestId::new("req-1")
                        .expect("an identifier"),
                    session_id,
                    summary: String::new(),
                },
            )])
            .expect("the store records the approval");
        let later = module.reading().advanced(10 * 60_000);
        let due = module
            .store()
            .expect("the store")
            .next_deadline_of(&Origin::Session(session_id), later)
            .expect("the store answers")
            .expect("the reminder is due");
        assert!(due <= later.continuous_ms, "the reminder is overdue then");
        assert_eq!(
            module.next_decidable_deadline(later),
            None,
            "nothing certifies the moment it fell due"
        );
        module.origins().certified.insert(session_id, due);
        assert_eq!(module.next_decidable_deadline(later), Some(due));
    }

    /// A reach that connects to nothing, reads no journal, and counts how often it is asked about
    /// a closure.
    #[derive(Default)]
    struct Counting {
        asked: AtomicU64,
    }

    impl Reach for Counting {
        fn connect<'a>(
            &'a self,
            _worker: &'a KnownWorker,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<LocalClient>> + Send + 'a>>
        {
            Box::pin(async { Err(ControllerError::supervision("this test connects nothing")) })
        }

        fn unaccounted<'a>(
            &'a self,
            _session_id: SessionId,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + 'a>> {
            self.asked.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { false })
        }

        fn closed_journal(&self, _session_id: SessionId) -> Option<kr_worker::journal::Journal> {
            None
        }

        fn output_floor(&self, _session_id: SessionId) -> Option<u64> {
            None
        }
    }

    /// A worker for `session_id` as the directory knows it, published at `published_at_ms`.
    fn known(
        temp: &kr_ipc::testing::TempHost,
        session_id: SessionId,
        published_at_ms: u64,
    ) -> KnownWorker {
        let boot = kr_ipc::identity::boot_identity().expect("a boot identity");
        let process =
            kr_ipc::identity::current_process_start_identity().expect("a process identity");
        let identity = kr_ipc::verify::WorkerIdentity::generate(
            session_id,
            kr_protocol::ids::SessionEpoch::V1,
            boot.clone(),
            process.clone(),
            kr_protocol::hello::PROTOCOL_VERSION,
        )
        .expect("a session key");
        let endpoint = temp
            .environment()
            .worker_endpoint(DisplayNumber::new(5))
            .expect("an endpoint");
        KnownWorker {
            descriptor: kr_protocol::worker::WorkerDescriptor {
                session_id,
                session_epoch: kr_protocol::ids::SessionEpoch::V1,
                environment_id: temp.environment_id(),
                display_number: DisplayNumber::new(5),
                boot_identity: boot,
                process_start_identity: process,
                protocol_version: kr_protocol::hello::PROTOCOL_VERSION,
                endpoint: endpoint.as_text(),
                worker_public_key: *identity.public_key(),
                worker_profile: kr_protocol::identity::WorkerProfile::HeadlessUser,
                published_at_ms: TimestampMs::new(published_at_ms),
            },
            endpoint,
        }
    }

    /// A closed session the store cannot finish is tried again on the retry's own schedule: a
    /// retry that fails again does not wake the loop that made it.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_closure_the_store_cannot_finish_is_retried_on_its_own_schedule() {
        let temp = kr_ipc::testing::TempHost::create();
        let module = module(&temp);
        let session_id = SessionId::new(kr_ipc::new_uuid());
        // From here on the store answers nothing, as a store that cannot be written does.
        let poisoning = Arc::clone(&module);
        let _ = std::thread::spawn(move || {
            let _held = poisoning.store.lock();
            panic!("the store stops answering");
        })
        .join();
        let reach = Arc::new(Counting::default());
        module.session_closed(reach.as_ref(), session_id).await;
        assert!(module.origins().unfinished.contains(&session_id));
        let first = reach.asked.load(Ordering::SeqCst);
        module.maintain(Arc::clone(&reach) as Arc<dyn Reach>);
        tokio::time::sleep(Duration::from_millis(1_500)).await;
        let retried = reach.asked.load(Ordering::SeqCst) - first;
        assert!(retried >= 1, "the loop tries the closure again");
        assert!(
            retried <= 2,
            "retried {retried} times in a second and a half rather than after its pause"
        );
    }

    /// A replacement of a session's worker waits for a page being taken from the link it replaces,
    /// and no certificate of the old worker's outlives it.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_replacement_waits_for_a_page_being_taken_and_leaves_no_certificate() {
        let temp = kr_ipc::testing::TempHost::create();
        let module = module(&temp);
        let session_id = SessionId::new(kr_ipc::new_uuid());
        let (link, _reader, _writer) = linked(&temp, 1, &module, session_id).await;
        {
            let mut origins = module.origins();
            origins.watched.insert(session_id);
            origins.workers.insert(
                session_id,
                Watched {
                    worker: known(&temp, session_id, 1),
                    revision: 0,
                    replaced: Arc::new(tokio::sync::Notify::new()),
                },
            );
        }
        // A page being taken holds the store from its look at the link to its certificate.
        let taking = module.store.lock().expect("the store");
        let replacing = {
            let module = Arc::clone(&module);
            let worker = known(&temp, session_id, 2);
            std::thread::spawn(move || {
                module.watch(Arc::new(Stub { unaccounted: false }), worker);
            })
        };
        std::thread::sleep(Duration::from_millis(200));
        module
            .origins()
            .certified
            .insert(session_id, kr_ipc::clock::boot_elapsed_ms());
        drop(taking);
        replacing.join().expect("the replacement finishes");
        let origins = module.origins();
        assert!(
            !origins.certified.contains_key(&session_id),
            "no certificate of the old worker's outlives the replacement"
        );
        assert!(
            !origins
                .links
                .get(&session_id)
                .is_some_and(|current| Arc::ptr_eq(current, &link))
        );
    }

    /// What the platform's time service says, as a test states it.
    fn platform_reading(qualified: bool) -> kr_protocol::action::TimeAdapterReading {
        use kr_worker::action::adapter::{UnixTimex, classify_unix, unix_model};
        let (time_state, status, maxerror_us) = if qualified {
            (unix_model::TIME_OK, unix_model::STA_PLL, 62_192)
        } else {
            (
                unix_model::TIME_ERROR,
                unix_model::STA_PLL | unix_model::STA_UNSYNC,
                16_000_000,
            )
        };
        classify_unix(
            "macos",
            "ntp_adjtime(2)",
            UnixTimex {
                time_state,
                status,
                maxerror_us,
                esterror_us: 500_000,
            },
            TimestampMs::new(CLOCK_START),
        )
    }

    /// The platform's time service, as a test states it.
    fn platform(qualified: bool) -> kr_worker::action::adapter::RecordedTimeAdapter {
        kr_worker::action::adapter::RecordedTimeAdapter::new(platform_reading(qualified))
    }

    /// Where the test host's wall clock starts.
    const CLOCK_START: u64 = 1_700_000_000_000;

    /// The host's one decision about its wall clock, over a real device store and a wall clock the
    /// test moves by hand. The floor's own record is the daemon's, and is tested with it.
    struct TestClock {
        trust: crate::service::net::clock_trust::ClockTrust,
        devices: crate::service::net::devices::DeviceDirectory,
        wall: Arc<AtomicU64>,
        /// Whether the host refuses every forgetting, as it does on a clock whose continuity is
        /// lost or whose floor is owed its record.
        refuses_forgetting: AtomicBool,
    }

    impl TestClock {
        fn new() -> Arc<Self> {
            let wall = Arc::new(AtomicU64::new(CLOCK_START));
            let reading = Arc::clone(&wall);
            Arc::new(Self {
                trust: crate::service::net::clock_trust::ClockTrust::new(
                    crate::service::WallClock::from_fn(move || reading.load(Ordering::SeqCst)),
                    Arc::new(crate::grants::policy::UtcFloor::at(0)),
                    Arc::new(kr_transport::clock::ManualClock::new()),
                    Arc::new(kr_ipc::clock::ManualSharedClock::new()),
                    kr_ipc::identity::boot_identity().expect("a boot identity"),
                ),
                devices: crate::service::net::devices::DeviceDirectory::in_memory()
                    .expect("a device store"),
                wall,
                refuses_forgetting: AtomicBool::new(false),
            })
        }

        fn set_wall(&self, ms: u64) {
            self.wall.store(ms, Ordering::SeqCst);
        }
    }

    impl HostClock for TestClock {
        fn watch(
            &self,
            platform_qualified: bool,
        ) -> Option<crate::service::net::clock_trust::Watched> {
            self.trust.watch(&self.devices, platform_qualified).ok()
        }

        fn may_forget_at(&self, _reading_ms: u64) -> bool {
            !self.refuses_forgetting.load(Ordering::SeqCst)
                && self
                    .trust
                    .sample_for_forgetting(&self.devices)
                    .ok()
                    .flatten()
                    .is_some()
        }
    }

    /// A module over `adapter`, with `clock` attached when it is given.
    fn module_on(
        temp: &kr_ipc::testing::TempHost,
        adapter: &kr_worker::action::adapter::RecordedTimeAdapter,
        clock: Option<&Arc<TestClock>>,
    ) -> Arc<AttentionModule> {
        let module = Arc::new(
            AttentionModule::open_over(
                &temp.environment(),
                &kr_ipc::identity::boot_identity().expect("a boot identity"),
                Arc::new(adapter.clone()),
            )
            .expect("the store opens"),
        );
        if let Some(clock) = clock {
            module.attach_clock(Arc::clone(clock) as Arc<dyn HostClock>);
        }
        module
    }

    /// KR-REQ-09.18, KR-REQ-09.19: the store's readings of the wall clock come from the host's one decision about
    /// it. Detached, the wall clock is read as unproven. Attached, a reading carries the host's
    /// wall clock and says it is proven only when the host proves it: the platform's time service
    /// qualifies or the owner has confirmed the clock, nothing is held, and no rollback was found.
    #[test]
    fn a_reading_is_proven_when_the_host_proves_the_clock() {
        let temp = kr_ipc::testing::TempHost::create();
        let adapter = platform(true);
        let clock = TestClock::new();
        let detached = module_on(&temp, &adapter, None);
        assert!(
            !detached.reading().wall_proven,
            "detached it proves nothing"
        );
        drop(detached);

        let module = module_on(&temp, &adapter, Some(&clock));
        let reading = module.reading();
        assert!(reading.wall_proven);
        assert_eq!(
            reading.wall_ms.get(),
            CLOCK_START,
            "on the host's wall clock"
        );

        // The platform's service stops qualifying while the owner has not confirmed the clock: a
        // hold, which the service qualifying again does not lift.
        adapter.set(platform_reading(false));
        assert!(!module.reading().wall_proven);
        adapter.set(platform_reading(true));
        assert!(!module.reading().wall_proven);
        clock
            .trust
            .establish(&clock.devices)
            .expect("the owner establishes");
        adapter.set(platform_reading(false));
        assert!(
            module.reading().wall_proven,
            "the owner's confirmation stands where the platform has none to give"
        );

        clock.set_wall(CLOCK_START - 60_000);
        assert!(!module.reading().wall_proven, "a rollback proves nothing");
    }

    /// Waits for `condition`, which something else makes true, for as long as a loaded runner takes.
    async fn until(what: &str, condition: impl Fn() -> bool) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        while !condition() {
            assert!(tokio::time::Instant::now() < deadline, "never: {what}");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// KR-REQ-09.18: a decision the host owes its record is written by the maintenance loop's own
    /// reading, with no request to prompt it. The loop is in the long wait it began while nothing
    /// was owed when a reading finds a rollback and its write is refused. That reading wakes the
    /// loop, which reads again with the write still refused and then waits only the retry, not the
    /// long wait; once the store takes the write again the retry makes it. Without the wake the
    /// loop does not read again within the test's bound, and without the retry it does not write.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_maintenance_loop_wakes_and_retries_to_write_what_the_host_owes() {
        let temp = kr_ipc::testing::TempHost::create();
        let adapter = platform(true);
        let clock = TestClock::new();
        let module = module_on(&temp, &adapter, Some(&clock));
        assert!(module.reading().wall_proven);
        module.maintain(Arc::new(Counting::default()) as Arc<dyn Reach>);
        let waits = || module.maintenance_waits.load(Ordering::SeqCst);
        let passes = || {
            module
                .decided_on
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .len()
        };
        until("the loop is in its first wait", || waits() >= 1).await;
        let passes_before = passes();

        clock
            .devices
            .with(|connection| {
                connection.execute_batch(
                    "CREATE TRIGGER refuse_the_decision BEFORE UPDATE OF untrusted_at_ms
                     ON network_clock BEGIN SELECT RAISE(ABORT, 'the store is full'); END;",
                )
            })
            .expect("the store takes a trigger");
        clock.set_wall(CLOCK_START - 60_000);
        assert!(!module.reading().wall_proven);
        assert!(clock.trust.owes_a_write(), "the decision is owed");

        until("the woken loop reads again", || passes() > passes_before).await;
        until("and waits for its retry", || waits() >= 2).await;
        assert!(
            clock.trust.owes_a_write(),
            "the store still refused what the woken loop wrote"
        );
        clock
            .devices
            .with(|connection| connection.execute_batch("DROP TRIGGER refuse_the_decision;"))
            .expect("the trigger goes");

        until("the retry writes what is owed", || {
            !clock.trust.owes_a_write()
        })
        .await;
        assert!(
            clock
                .devices
                .clock_record()
                .expect("the record")
                .untrusted_at_ms
                .is_some()
        );
    }

    /// Puts an action record stamped at `recorded_at_ms` into the store of the module over `temp`.
    fn record_action(temp: &kr_ipc::testing::TempHost, id: &str, recorded_at_ms: u64) {
        let store =
            rusqlite::Connection::open(temp.environment().state_dir().join("attention.sqlite3"))
                .expect("opens the attention store");
        store
            .busy_timeout(Duration::from_secs(10))
            .expect("waits for the module's own use");
        store
            .execute(
                "INSERT INTO attention_actions
                     (actor, action_id, method, digest, answer, recorded_at_ms)
                 VALUES ('a', ?1, 'attention.acknowledge', x'00', x'00', ?2)",
                rusqlite::params![id, i64::try_from(recorded_at_ms).expect("a time")],
            )
            .expect("the attention store takes a record");
    }

    fn recorded_actions(temp: &kr_ipc::testing::TempHost) -> Vec<String> {
        let store =
            rusqlite::Connection::open(temp.environment().state_dir().join("attention.sqlite3"))
                .expect("opens the attention store");
        let mut statement = store
            .prepare("SELECT action_id FROM attention_actions ORDER BY action_id")
            .expect("prepares");
        statement
            .query_map([], |row| row.get(0))
            .expect("reads")
            .collect::<std::result::Result<_, _>>()
            .expect("the rows")
    }

    /// KR-REQ-09.14, KR-REQ-09.18: a reading from before the owner corrected a wrong clock never reaches a record
    /// stamped after the correction. The wall clock reads a late moment, the host answers that the
    /// store may forget, and the pass stops before it takes the store. The wall clock is corrected
    /// back by a hundred days and the owner establishes it; a record is stamped at the corrected
    /// moment. The pass counts its cutoff from the earlier of its two readings, so the record
    /// stamped after the correction is kept while the old one is forgotten.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_reading_from_before_a_correction_forgets_nothing_stamped_after_it() {
        let temp = kr_ipc::testing::TempHost::create();
        let adapter = platform(true);
        let clock = TestClock::new();
        let module = module_on(&temp, &adapter, Some(&clock));
        let late = CLOCK_START + 100 * 86_400_000;
        clock.set_wall(late);
        assert!(module.reading().wall_proven, "a step forward is accepted");
        record_action(&temp, "old", 1);

        let (arrived, go) = module.after_the_clock_answer.arm();
        let pass = tokio::spawn({
            let module = Arc::clone(&module);
            async move { module.tick_and_forget(0).await }
        });
        tokio::task::spawn_blocking(move || arrived.recv_timeout(Duration::from_secs(10)))
            .await
            .expect("joins")
            .expect("the pass reached the clock question");

        clock.set_wall(CLOCK_START);
        clock
            .trust
            .establish(&clock.devices)
            .expect("the owner establishes");
        record_action(&temp, "new", CLOCK_START);
        go.send(()).expect("the pass goes on");
        let (_, marker) = pass.await.expect("the pass ends").expect("the pass runs");

        assert_eq!(
            recorded_actions(&temp),
            vec!["new".to_owned()],
            "the record stamped after the correction is kept, and the old one is forgotten"
        );
        assert_eq!(
            marker, CLOCK_START,
            "the schedule moves to the reading the cutoff was counted from, not to the late one"
        );

        // The marker the pass returned is what the next pass is given, and it forgets what has
        // since outlived its retention.
        clock.set_wall(CLOCK_START + 31 * 86_400_000);
        module.tick_and_forget(marker).await.expect("the pass runs");
        assert!(recorded_actions(&temp).is_empty());
    }

    /// KR-REQ-09.14, KR-REQ-09.18: a forgetting is not made while the host owes its record a write
    /// that the final reading found. The host answers that the store may forget and the pass stops
    /// before it takes the store; the owner then establishes the clock back at the corrected
    /// moment, a record is stamped, the store refuses the anchor's write and the clock steps a
    /// month forward. The final reading owes its anchor, though it is proven and its cutoff would
    /// reach the record stamped after the correction: nothing is forgotten.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_final_reading_that_leaves_a_write_owed_forgets_nothing() {
        let temp = kr_ipc::testing::TempHost::create();
        let adapter = platform(true);
        let clock = TestClock::new();
        let module = module_on(&temp, &adapter, Some(&clock));
        clock.set_wall(CLOCK_START + 100 * 86_400_000);
        assert!(module.reading().wall_proven);
        record_action(&temp, "old", 1);

        let (arrived, go) = module.after_the_clock_answer.arm();
        let pass = tokio::spawn({
            let module = Arc::clone(&module);
            async move { module.tick_and_forget(0).await }
        });
        tokio::task::spawn_blocking(move || arrived.recv_timeout(Duration::from_secs(10)))
            .await
            .expect("joins")
            .expect("the pass reached the clock question");

        clock.set_wall(CLOCK_START);
        clock
            .trust
            .establish(&clock.devices)
            .expect("the owner establishes");
        record_action(&temp, "new", CLOCK_START);
        clock
            .devices
            .with(|connection| {
                connection.execute_batch(
                    "CREATE TRIGGER refuse_the_anchor BEFORE UPDATE OF anchor_wall_ms
                     ON network_clock BEGIN SELECT RAISE(ABORT, 'the store is full'); END;",
                )
            })
            .expect("the store takes a trigger");
        clock.set_wall(CLOCK_START + 31 * 86_400_000);
        go.send(()).expect("the pass goes on");
        pass.await.expect("the pass ends").expect("the pass runs");

        assert_eq!(
            recorded_actions(&temp),
            vec!["new".to_owned(), "old".to_owned()],
            "nothing is forgotten while the host owes its record the step"
        );
    }

    /// KR-REQ-09.14: a schedule that stands ahead of the clock is not waited for. The last
    /// forgetting was counted from a reading a correction has since taken back by a hundred days;
    /// once the owner has established the clock the next pass is due at once, not when the clock
    /// has caught up with that reading.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_schedule_ahead_of_the_clock_does_not_stall_forgetting() {
        let temp = kr_ipc::testing::TempHost::create();
        let adapter = platform(true);
        let clock = TestClock::new();
        let module = module_on(&temp, &adapter, Some(&clock));
        assert!(module.reading().wall_proven);
        record_action(&temp, "old", 1);
        clock.set_wall(CLOCK_START + 100 * 86_400_000);
        assert!(module.reading().wall_proven);

        let ahead = CLOCK_START + 200 * 86_400_000;
        module.tick_and_forget(ahead).await.expect("the pass runs");
        assert!(recorded_actions(&temp).is_empty());
    }

    /// KR-REQ-09.14: a forgetting the host refuses is not made, whatever the store's own reading
    /// says. The store's reading is proven and the records have outlived their retention; the host
    /// answers that it may not forget, as it does while this boot's clock continuity is lost or
    /// the floor is owed its record, and the records stay until it may.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_forgetting_the_host_refuses_is_not_made_on_a_proven_reading() {
        let temp = kr_ipc::testing::TempHost::create();
        let adapter = platform(true);
        let clock = TestClock::new();
        let module = module_on(&temp, &adapter, Some(&clock));
        assert!(module.reading().wall_proven);
        record_action(&temp, "old", 1);
        clock.set_wall(CLOCK_START + 100 * 86_400_000);
        assert!(module.reading().wall_proven, "the reading is proven");

        clock.refuses_forgetting.store(true, Ordering::SeqCst);
        module.tick_and_forget(0).await.expect("the pass runs");
        assert_eq!(recorded_actions(&temp), vec!["old".to_owned()]);
        clock.refuses_forgetting.store(false, Ordering::SeqCst);
        module.tick_and_forget(0).await.expect("the pass runs");
        assert!(recorded_actions(&temp).is_empty());
    }

    /// Nothing is forgotten while the host holds the clock against its own reading: a pass on a
    /// clock that went backwards keeps every record.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_pass_on_a_clock_that_went_backwards_forgets_nothing() {
        let temp = kr_ipc::testing::TempHost::create();
        let adapter = platform(true);
        let clock = TestClock::new();
        let module = module_on(&temp, &adapter, Some(&clock));
        assert!(module.reading().wall_proven);
        record_action(&temp, "old", 1);
        clock.set_wall(CLOCK_START - 60_000);
        assert!(!module.reading().wall_proven);
        clock.set_wall(CLOCK_START + 100 * 86_400_000);

        module.tick_and_forget(0).await.expect("the pass runs");
        assert_eq!(recorded_actions(&temp), vec!["old".to_owned()]);
        clock
            .trust
            .establish(&clock.devices)
            .expect("the owner establishes");
        module.tick_and_forget(0).await.expect("the pass runs");
        assert!(recorded_actions(&temp).is_empty());
    }

    /// A request's bound covers the wait for the connection's writer as well as the answer, so a
    /// worker that stops reading holds nothing past it.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_request_is_bounded_whole() {
        let temp = kr_ipc::testing::TempHost::create();
        let module = module(&temp);
        let (link, _reader, _writer) =
            linked(&temp, 1, &module, SessionId::new(kr_ipc::new_uuid())).await;
        let bound = Duration::from_millis(200);

        let started = Instant::now();
        let unanswered = link
            .ask(
                ControlFrame::AttentionText(AttentionTextRequest {
                    request_id: RequestId::new(1),
                    records: Vec::new(),
                    recorded_generation: Nullable::null(),
                }),
                RequestId::new(1),
                bound,
            )
            .await;
        assert!(unanswered.is_none());
        assert!(started.elapsed() < Duration::from_secs(2));
        assert!(
            !link.closed.load(Ordering::SeqCst),
            "a request written whole leaves the link usable"
        );

        let held = link.writer.lock().await;
        let started = Instant::now();
        let waited = link
            .ask(
                ControlFrame::AttentionText(AttentionTextRequest {
                    request_id: RequestId::new(2),
                    records: Vec::new(),
                    recorded_generation: Nullable::null(),
                }),
                RequestId::new(2),
                bound,
            )
            .await;
        assert!(waited.is_none());
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "the wait for the writer counts against the bound"
        );
        drop(held);
    }

    /// What the offer says of the one item the store holds, with the session in the state `label`
    /// names.
    fn offered_for(module: &AttentionModule, label: &str, expected: bool) {
        let offered = module
            .take_for_delivery(|store, offer| {
                store
                    .engine()
                    .expect("the store is this owner's")
                    .items()
                    .map(offer)
                    .collect::<Vec<_>>()
            })
            .expect("the store is taken");
        assert_eq!(offered.len(), 1, "{label}: the store holds the one item");
        assert_eq!(offered[0], expected, "{label}");
    }

    /// The delivery consumer is offered an announcement only while the store reads its session or
    /// has finished reading it: one about a session being closed, or neither read nor finished, ends
    /// with the session's own journal, so it is held back until the store lets it go. A session
    /// closed over a worker the host could not account for is held back after it is finished too.
    /// Each state is set against the one before it that lets the item through, so each held-back
    /// answer is that state's own. The control: an item of the environment itself is always
    /// offered.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_offer_holds_back_a_session_that_is_being_closed_and_one_that_is_not_read() {
        let temp = kr_ipc::testing::TempHost::create();
        let module = module(&temp);
        let session_id = SessionId::new(kr_ipc::new_uuid());
        // A failed command, which is an item that outlives its session, unlike a pending approval.
        let failed = |cursor: kr_attention::EventCursor| {
            SourceEvent::new(
                cursor,
                TimestampMs::new(kr_ipc::now_ms().get()),
                EventKind::CommandCompleted {
                    session_id,
                    command: "make".to_owned(),
                    exit_code: 2,
                },
            )
        };
        module
            .observe(&[failed(kr_attention::EventCursor::in_session(
                session_id,
                AttentionSource::Receipts,
                1,
            ))])
            .expect("the store records the failure");

        offered_for(&module, "neither read nor finished", false);

        let _worker = linked(&temp, 1, &module, session_id).await;
        offered_for(&module, "read", true);
        module.origins().closing.insert(session_id);
        offered_for(&module, "being closed", false);
        module.origins().closing.remove(&session_id);
        offered_for(&module, "read again", true);

        module.origins().links.remove(&session_id);
        module.finalise(session_id).expect("the session ends");
        offered_for(&module, "finished", true);
        module.origins().unaccounted.insert(session_id);
        offered_for(&module, "closed over a worker nobody accounts for", false);

        // The control: the environment's own item is not about any session.
        let temp = kr_ipc::testing::TempHost::create();
        let module = self::module(&temp);
        module
            .observe(&[failed(kr_attention::EventCursor::new(
                AttentionSource::Receipts,
                1,
            ))])
            .expect("the store records the failure");
        offered_for(&module, "an item of the environment", true);

        // A pending approval an environment record raises about a session ends with the session
        // as one of the session's own does, so it is held back while the session is being closed.
        // The controls: it is offered for a session the host has not read, which nothing would
        // ever let go of otherwise, and again once the closing is over.
        let temp = kr_ipc::testing::TempHost::create();
        let module = self::module(&temp);
        let named = SessionId::new(kr_ipc::new_uuid());
        module
            .observe(&[SourceEvent::new(
                kr_attention::EventCursor::new(AttentionSource::Receipts, 1),
                TimestampMs::new(kr_ipc::now_ms().get()),
                EventKind::ApprovalRequested {
                    request_id: kr_protocol::ids::ApprovalRequestId::new("req-1")
                        .expect("an identifier"),
                    session_id: named,
                    summary: String::new(),
                },
            )])
            .expect("the store records the approval");
        offered_for(&module, "an approval naming a session not read", true);
        module.origins().ended.insert(named);
        offered_for(&module, "an approval naming a session being closed", false);
        module.origins().ended.remove(&named);
        offered_for(
            &module,
            "an approval naming a session no longer closing",
            true,
        );
    }

    /// An announcement the store decides is stamped with the privacy state the daemon publishes at
    /// the moment it is decided, so that what is decided while privacy mode is on can be told from
    /// what is decided after by that state and not by a clock. The control: a module that was
    /// attached no privacy state stamps nothing.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_decision_is_stamped_with_the_privacy_state_the_daemon_publishes() {
        let failure = |session_id: SessionId| {
            SourceEvent::new(
                kr_attention::EventCursor::in_session(session_id, AttentionSource::Receipts, 1),
                TimestampMs::new(kr_ipc::now_ms().get()),
                EventKind::CommandCompleted {
                    session_id,
                    command: "make".to_owned(),
                    exit_code: 2,
                },
            )
        };
        let stamped = |module: &AttentionModule| {
            module
                .take_for_delivery(|store, _| {
                    store
                        .engine()
                        .expect("the store is this owner's")
                        .items()
                        .map(|item| item.decided_privacy)
                        .collect::<Vec<_>>()
                })
                .expect("the store is taken")
        };

        let temp = kr_ipc::testing::TempHost::create();
        let module = self::module(&temp);
        module.attach_privacy(crate::privacy::PrivacyState::at(
            crate::privacy::Published {
                generation: kr_worker::privacy::PrivacyGeneration::new(3),
                private: true,
            },
        ));
        module
            .observe(&[failure(SessionId::new(kr_ipc::new_uuid()))])
            .expect("the store records the failure");
        assert_eq!(
            stamped(&module),
            vec![Some(kr_attention::PrivacyStamp {
                generation: 3,
                private: true
            })]
        );

        let temp = kr_ipc::testing::TempHost::create();
        let module = self::module(&temp);
        module
            .observe(&[failure(SessionId::new(kr_ipc::new_uuid()))])
            .expect("the store records the failure");
        assert_eq!(stamped(&module), vec![None]);
    }

    /// A page is decided on the blocking pool and never on a thread of the runtime that read it. A
    /// pass that decides takes the privacy state's read side, which a change of privacy mode that is
    /// waiting for a send on the wire makes wait, and the send's exchange needs the runtime's own
    /// threads: a pass that waited on one would hold it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_page_is_decided_off_the_runtimes_threads() {
        let temp = kr_ipc::testing::TempHost::create();
        let module = self::module(&temp);
        let session_id = SessionId::new(kr_ipc::new_uuid());
        let (link, _reader, _writer) = linked(&temp, 1, &module, session_id).await;
        let polled_on = tokio::spawn({
            let module = Arc::clone(&module);
            let link = Arc::clone(&link);
            async move {
                let polled_on = std::thread::current().id();
                module
                    .take_page(session_id, &link, 0, 0, &question_page(session_id))
                    .await
                    .expect("the page is taken");
                polled_on
            }
        })
        .await
        .expect("the task ends");
        let decided = module.decided_on.lock().expect("not poisoned").clone();
        assert_eq!(decided.len(), 1, "one pass decided the page");
        assert_ne!(
            decided[0], polled_on,
            "the page was decided on the thread that read it"
        );
    }

    /// The maintenance tick is decided on the blocking pool too, and never on the runtime's own
    /// thread: the runtime here has the one, so a tick that waited on it would hold the whole
    /// runtime.
    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn the_maintenance_tick_is_decided_off_the_runtimes_threads() {
        let temp = kr_ipc::testing::TempHost::create();
        let module = self::module(&temp);
        let worker = tokio::spawn(async { std::thread::current().id() })
            .await
            .expect("the worker answers");
        module.maintain(Arc::new(Stub { unaccounted: false }) as Arc<dyn Reach>);
        let deadline = Instant::now() + Duration::from_secs(30);
        while module.decided_on.lock().expect("not poisoned").is_empty() {
            assert!(
                Instant::now() < deadline,
                "the maintenance loop never ticked"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let decided = module.decided_on.lock().expect("not poisoned").clone();
        assert!(
            decided.iter().all(|thread| *thread != worker),
            "the maintenance tick was decided on the runtime's thread"
        );
    }

    /// What each item of `module` was last decided at, and under which privacy state.
    fn decisions(
        module: &AttentionModule,
    ) -> Vec<(Option<TimestampMs>, Option<kr_attention::PrivacyStamp>)> {
        module
            .take_for_delivery(|store, _| {
                store
                    .engine()
                    .expect("the store is this owner's")
                    .items()
                    .map(|item| (item.last_notified_ms, item.decided_privacy))
                    .collect::<Vec<_>>()
            })
            .expect("the store is taken")
    }

    /// The privacy state the stamp tests publish: generation 3, on.
    fn private_in_generation_three() -> (crate::privacy::PrivacyState, kr_attention::PrivacyStamp) {
        (
            crate::privacy::PrivacyState::at(crate::privacy::Published {
                generation: kr_worker::privacy::PrivacyGeneration::new(3),
                private: true,
            }),
            kr_attention::PrivacyStamp {
                generation: 3,
                private: true,
            },
        )
    }

    /// A page that certifies its session decides what it raised under the privacy state the daemon
    /// publishes, and stamps it. The control: a module attached no state stamps nothing.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_page_stamps_what_it_decides_with_the_privacy_state() {
        for attached in [true, false] {
            let temp = kr_ipc::testing::TempHost::create();
            let module = self::module(&temp);
            let (state, stamp) = private_in_generation_three();
            if attached {
                module.attach_privacy(state);
            }
            let session_id = SessionId::new(kr_ipc::new_uuid());
            let (link, _reader, _writer) = linked(&temp, 1, &module, session_id).await;
            module
                .take_page(session_id, &link, 0, 0, &question_page(session_id))
                .await
                .expect("the page is taken");
            let decided = decisions(&module);
            assert_eq!(decided.len(), 1, "one item");
            assert!(decided[0].0.is_some(), "the page decided it");
            assert_eq!(
                decided[0].1,
                attached.then_some(stamp),
                "attached {attached}"
            );
        }
    }

    /// The maintenance tick decides what a certificate that arrived since the last pass lets be
    /// decided, under the privacy state the daemon publishes, and stamps it. The item is raised by a
    /// page that certifies nothing, so only the tick can decide it. The control: a module attached
    /// no state stamps nothing.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_maintenance_tick_stamps_what_it_decides_with_the_privacy_state() {
        for attached in [true, false] {
            let temp = kr_ipc::testing::TempHost::create();
            let module = self::module(&temp);
            let (state, stamp) = private_in_generation_three();
            if attached {
                module.attach_privacy(state);
            }
            let session_id = SessionId::new(kr_ipc::new_uuid());
            let (link, _reader, _writer) = linked(&temp, 1, &module, session_id).await;
            // A page that is not the end of what the session recorded: it raises the item and
            // certifies nothing, so nothing is decided yet.
            let mut partial = question_page(session_id);
            partial.questions.head = U64::new(2);
            let taken = module
                .take_page(session_id, &link, 0, 0, &partial)
                .await
                .expect("the page is taken");
            assert!(matches!(taken, Taken::Partial));
            let undecided = decisions(&module);
            assert_eq!(undecided.len(), 1, "one item");
            assert_eq!(undecided[0].0, None, "nothing decided it yet");

            module
                .origins()
                .certified
                .insert(session_id, kr_ipc::clock::boot_elapsed_ms());
            module.maintain(Arc::new(Stub { unaccounted: false }) as Arc<dyn Reach>);
            module.wake.notify_one();
            let deadline = Instant::now() + Duration::from_secs(30);
            while decisions(&module)[0].0.is_none() {
                assert!(
                    Instant::now() < deadline,
                    "the maintenance tick never decided the item"
                );
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            assert_eq!(
                decisions(&module)[0].1,
                attached.then_some(stamp),
                "attached {attached}"
            );
        }
    }

    /// The certification of the workflow journal's records decides what an environment item is owed
    /// under the privacy state the daemon publishes, and stamps it. The control: a module attached
    /// no state stamps nothing.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_environment_s_certification_stamps_what_it_decides_with_the_privacy_state() {
        for attached in [true, false] {
            let temp = kr_ipc::testing::TempHost::create();
            let module = self::module(&temp);
            let (state, stamp) = private_in_generation_three();
            if attached {
                module.attach_privacy(state);
            }
            let reading = module.reading();
            module
                .store()
                .expect("the store")
                .rebuild(
                    &[SourceEvent::new(
                        kr_attention::EventCursor::new(AttentionSource::Automation, 1),
                        TimestampMs::new(kr_ipc::now_ms().get()),
                        EventKind::AutomationPaused {
                            subject: kr_protocol::attention::AttentionAutomationSubject::Workflow {
                                workflow_id: kr_protocol::ids::WorkflowId::new(kr_ipc::new_uuid()),
                                revision: U64::new(1),
                            },
                            reason: "max_concurrent_runs".to_owned(),
                            grant_id: None,
                        },
                    )],
                    reading,
                )
                .expect("the store reads the record");
            let undecided = decisions(&module);
            assert_eq!(undecided.len(), 1, "one item");
            assert_eq!(undecided[0].0, None, "reading a record decides nothing");
            module
                .certify_environment(kr_ipc::clock::boot_elapsed_ms())
                .expect("the certification is recorded");
            let decided = decisions(&module);
            assert!(decided[0].0.is_some(), "the certification decided it");
            assert_eq!(
                decided[0].1,
                attached.then_some(stamp),
                "attached {attached}"
            );
        }
    }

    /// A reach whose answer to "was the closure unaccounted for" is held until the test lets it go,
    /// and which says when it was asked.
    struct Gated {
        asked: Arc<AtomicBool>,
        gate: Arc<tokio::sync::Notify>,
    }

    impl Reach for Gated {
        fn connect<'a>(
            &'a self,
            _worker: &'a KnownWorker,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<LocalClient>> + Send + 'a>>
        {
            Box::pin(async { Err(ControllerError::supervision("this test connects nothing")) })
        }

        fn unaccounted<'a>(
            &'a self,
            _session_id: SessionId,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + 'a>> {
            let (asked, gate) = (Arc::clone(&self.asked), Arc::clone(&self.gate));
            Box::pin(async move {
                asked.store(true, Ordering::SeqCst);
                gate.notified().await;
                false
            })
        }

        fn closed_journal(&self, _session_id: SessionId) -> Option<kr_worker::journal::Journal> {
            None
        }

        fn output_floor(&self, _session_id: SessionId) -> Option<u64> {
            None
        }
    }

    /// A request an environment record raises about a session is held from the moment the daemon
    /// drops the session's link, not from the moment the closure is recorded after the question
    /// whether it was accounted for has been answered, and it goes with the session once the
    /// session is finished. The control: the same request is offered before the closure begins.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_request_naming_a_session_is_held_while_the_closure_waits_to_be_accounted_for() {
        let temp = kr_ipc::testing::TempHost::create();
        let module = self::module(&temp);
        let named = SessionId::new(kr_ipc::new_uuid());
        module
            .observe(&[SourceEvent::new(
                kr_attention::EventCursor::new(AttentionSource::Receipts, 1),
                TimestampMs::new(kr_ipc::now_ms().get()),
                EventKind::ApprovalRequested {
                    request_id: kr_protocol::ids::ApprovalRequestId::new("req-1")
                        .expect("an identifier"),
                    session_id: named,
                    summary: String::new(),
                },
            )])
            .expect("the store records the approval");
        let _worker = linked(&temp, 3, &module, named).await;
        offered_for(&module, "before the closure begins", true);

        let asked = Arc::new(AtomicBool::new(false));
        let gate = Arc::new(tokio::sync::Notify::new());
        let reach = Arc::new(Gated {
            asked: Arc::clone(&asked),
            gate: Arc::clone(&gate),
        });
        let closing = {
            let (module, reach) = (Arc::clone(&module), Arc::clone(&reach));
            tokio::spawn(async move { module.session_closed(&*reach, named).await })
        };
        while !asked.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
        offered_for(
            &module,
            "while the closure waits to be accounted for",
            false,
        );
        gate.notify_one();
        closing.await.expect("the closure ends");
        let left = module
            .take_for_delivery(|store, _| {
                store
                    .engine()
                    .map(|engine| engine.items().count())
                    .expect("the store is this owner's")
            })
            .expect("the store is taken");
        assert_eq!(
            left, 0,
            "the session's ending ended the request, which is why it was held"
        );
    }

    /// A session an item was raised from and which the host does not read does not hold back a
    /// request that merely names it: the two are held for different reasons, so a request about a
    /// session this host never held is still offered while an item raised from that session waits.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_item_raised_from_an_unread_session_does_not_hold_back_a_request_naming_it() {
        use kr_protocol::attention::AttentionRule;

        let temp = kr_ipc::testing::TempHost::create();
        let module = self::module(&temp);
        let session_id = SessionId::new(kr_ipc::new_uuid());
        let observed = |origin: kr_attention::EventCursor, kind: EventKind| {
            SourceEvent::new(origin, TimestampMs::new(kr_ipc::now_ms().get()), kind)
        };
        module
            .observe(&[
                observed(
                    kr_attention::EventCursor::in_session(session_id, AttentionSource::Receipts, 1),
                    EventKind::CommandCompleted {
                        session_id,
                        command: "make".to_owned(),
                        exit_code: 2,
                    },
                ),
                observed(
                    kr_attention::EventCursor::new(AttentionSource::Receipts, 1),
                    EventKind::ApprovalRequested {
                        request_id: kr_protocol::ids::ApprovalRequestId::new("req-1")
                            .expect("an identifier"),
                        session_id,
                        summary: String::new(),
                    },
                ),
            ])
            .expect("the store records both");
        let offered = module
            .take_for_delivery(|store, offer| {
                store
                    .engine()
                    .expect("the store is this owner's")
                    .items()
                    .map(|item| (item.rule, offer(item)))
                    .collect::<Vec<_>>()
            })
            .expect("the store is taken");
        assert!(
            offered
                .iter()
                .any(|(rule, offered)| *rule == AttentionRule::PendingApproval && *offered),
            "the request naming the session is offered: {offered:?}"
        );
        assert!(
            offered
                .iter()
                .all(|(rule, offered)| *rule == AttentionRule::PendingApproval || !offered),
            "the item raised from the unread session is held back: {offered:?}"
        );
    }
}
