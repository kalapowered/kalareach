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
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use kr_attention::host::{ActionKey, Answer as Answered, Mutation, Performed};
use kr_attention::{
    Attention, Claimant, Content, DeviceScope, EventCursor, EventKind, HostReading, Liveness,
    Origin, SourceEvent, Viewer,
};
use kr_ipc::client::LocalClient;
use kr_ipc::framed::CheckedWrite;
use kr_protocol::attention::{
    AttentionAcknowledgeParams, AttentionBarrier, AttentionBarrierAcknowledged,
    AttentionHostRecord, AttentionQuestionRecord, AttentionQuietHoursParams,
    AttentionQuietHoursResult, AttentionReadParams, AttentionRecordRef, AttentionSource,
    AttentionSourcePage, AttentionSourcesRequest, AttentionTextRequest,
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
use kr_protocol::scalars::{Nullable, SecretBytes32, U64};

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

/// How long the record of an action is kept, after which a repeat is a new request.
const ACTION_RETENTION_MS: u64 = 30 * 24 * 60 * 60 * 1_000;

/// The records one page asks for from each source.
const PAGE_RECORDS: u64 = MAX_ATTENTION_SOURCE_RECORDS;

/// A time-zone name a quiet-hours window records, in bytes.
const MAX_ZONE_LEN: usize = 128;

/// The largest number this store writes down exactly.
const MAX_STORED_COUNTER: u64 = i64::MAX as u64;

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
    /// Each live session's oldest retained output position, from its latest page.
    output_floor: BTreeMap<SessionId, u64>,
    /// Sessions whose closure this daemon recorded and whose journals are being read to the end.
    closing: BTreeSet<SessionId>,
    /// Sessions closed over a worker this host could not confirm had ended.
    unaccounted: BTreeSet<SessionId>,
    /// Closed sessions the store could not finish yet, which the maintenance loop tries again.
    unfinished: BTreeSet<SessionId>,
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
/// session's journal needs none: no transition can follow the closure.
#[derive(Clone, Debug, Default)]
pub struct Ticket {
    entries: Vec<TicketEntry>,
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
    /// Returns true when the ticket names no text that needs a check.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Answers whether every text the ticket names may be released at `now`: its session's
    /// barrier is lowered, the session was not closed over a worker the host could not account
    /// for, the generation its answer was decided under is the one recorded, and its lease has more
    /// than the margin left.
    fn holds(&self, fences: &BTreeMap<SessionId, SessionFence>, now: u64) -> bool {
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

/// A read's answer, with what it takes to release it.
struct Read {
    /// The answer, with any session text it carries.
    value: ParamsValue,
    /// When it carries live session text: the same answer with that text withheld, and the ticket
    /// its release is bound by.
    text: Option<(ParamsValue, Ticket)>,
}

impl Read {
    /// An answer that carries no live session text.
    const fn plain(value: ParamsValue) -> Self {
        Self { value, text: None }
    }

    /// An answer whose live session text, if it carries any, is released under `ticket`.
    fn with(value: ParamsValue, withheld: ParamsValue, ticket: Ticket) -> Self {
        if ticket.is_empty() {
            return Self::plain(value);
        }
        Self {
            value,
            text: Some((withheld, ticket)),
        }
    }
}

/// The environment's attention store, as the daemon holds it.
pub struct AttentionModule {
    /// Each session's privacy fence, and the lock every release of session text is made under:
    /// held shared for one checked write, and exclusively to apply a statement or move a recorded
    /// generation. Its queue is fair, so an exclusive request stops new shared admissions and waits
    /// only for the holders admitted before it.
    release: tokio::sync::RwLock<BTreeMap<SessionId, SessionFence>>,
    store: std::sync::Mutex<Attention>,
    /// The host time contract the store's readings come from, observed at each reading and kept
    /// beside the store so a restart keeps what it knew about the wall clock.
    time: kr_worker::action::time::TimeContract,
    time_file: std::path::PathBuf,
    /// Held from reading what the time contract must keep to recording it as kept, so one save
    /// never replaces a newer one with an older state.
    time_saving: std::sync::Mutex<()>,
    origins: std::sync::Mutex<Origins>,
    /// Wakes the maintenance loop when a timer may have moved.
    wake: Arc<tokio::sync::Notify>,
}

impl std::fmt::Debug for AttentionModule {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AttentionModule")
            .finish_non_exhaustive()
    }
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
            boot_identity,
            kr_worker::action::time::TimeSources::system(),
        )
    }

    /// Opens the store as [`Self::open`] does, reading time from the clocks given.
    fn open_over(
        paths: &kr_ipc::paths::EnvironmentPaths,
        boot_identity: kr_protocol::identity::BootIdentity,
        sources: kr_worker::action::time::TimeSources,
    ) -> Result<Self> {
        let time_file = paths.state_dir().join("attention-time.cbor");
        let recorded = std::fs::read(&time_file).ok().and_then(|bytes| {
            kr_cbor::from_canonical_slice::<kr_protocol::action::HostTimeState>(
                &bytes,
                &kr_cbor::Limits::DEFAULT,
            )
            .ok()
        });
        let time =
            kr_worker::action::time::TimeContract::restore(boot_identity, "", sources, recorded);
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
            reading(&time),
            &claimant,
        )
        .map_err(|error| ControllerError::RegistryUnavailable {
            detail: format!("the attention store cannot be opened: {error}"),
        })?;
        let module = Self {
            release: tokio::sync::RwLock::new(BTreeMap::new()),
            store: std::sync::Mutex::new(store),
            time,
            time_file,
            time_saving: std::sync::Mutex::new(()),
            origins: std::sync::Mutex::new(Origins::default()),
            wake: Arc::new(tokio::sync::Notify::new()),
        };
        module.keep_time();
        Ok(module)
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

    /// Returns what the host's clocks read now, in the form the store takes.
    ///
    /// The time contract is observed first, so a rollback of the wall clock is noticed before a
    /// reading is taken from it, and what it learned is written down.
    fn reading(&self) -> HostReading {
        self.time.observe();
        self.keep_time();
        reading(&self.time)
    }

    /// Writes down what the time contract has to keep across a restart, when it has something new.
    ///
    /// One save at a time, from reading the state to recording it as kept: two saves that crossed
    /// could write an older state over a newer one and still record the newer as kept.
    fn keep_time(&self) {
        let _saving = self
            .time_saving
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !self.time.unsaved() {
            return;
        }
        let (state, generation) = self.time.durable_state();
        let Ok(bytes) = kr_cbor::to_canonical_vec(&state) else {
            return;
        };
        let partial = self.time_file.with_extension("cbor.partial");
        if std::fs::write(&partial, bytes).is_ok()
            && std::fs::rename(&partial, &self.time_file).is_ok()
        {
            self.time.note_saved(generation);
        }
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
        let Some((withheld, ticket)) = read.text else {
            return Ok(read.value);
        };
        let fences = self.release.read().await;
        Ok(if ticket.holds(&fences, kr_ipc::clock::boot_elapsed_ms()) {
            read.value
        } else {
            withheld
        })
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
        match self.read_texts(reach, caller, actor, request).await {
            Ok(Read {
                value,
                text: Some((withheld, ticket)),
            }) => Released {
                frame: frame(request.request_id, Ok(value)),
                withheld: Some(frame(request.request_id, Ok(withheld))),
                ticket,
            },
            Ok(Read { value, text: None }) => Released {
                frame: frame(request.request_id, Ok(value)),
                withheld: None,
                ticket: Ticket::default(),
            },
            Err(error) => Released {
                frame: frame(request.request_id, Err(error)),
                withheld: None,
                ticket: Ticket::default(),
            },
        }
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
                let may_write = || ticket.holds(&fences, kr_ipc::clock::boot_elapsed_ms());
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
                let page = self
                    .store()?
                    .changed(
                        actor,
                        params.session_id,
                        params.max_changes.get(),
                        floor,
                        caller.content(),
                    )
                    .map_err(refusal)?;
                let mut result = page.result;
                let withheld = encode(&result)?;
                let (texts, ticket) = self.texts(reach, &page.texts).await;
                for (index, text) in texts {
                    if let Some(change) = result.changes.get_mut(index) {
                        change.summary = Nullable(text);
                    }
                }
                Ok(Read::with(encode(&result)?, withheld, ticket))
            }
            _ => Err(ProtocolError::new(
                ErrorCode::InvalidArgument,
                format!("{} is not a read this group serves", method.as_str()),
            )),
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
    /// # Errors
    ///
    /// Returns the store's refusal; nothing about the events is kept then.
    pub fn observe(&self, events: &[SourceEvent]) -> Answer<()> {
        let reading = self.reading();
        let mut store = self.store()?;
        for event in events {
            store.apply(event, reading).map_err(refusal)?;
        }
        drop(store);
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
            match held.take_page(session_id, &link, questions_after, host_events_after, &page) {
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
    fn take_page(
        &self,
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
        let reading = self.reading();
        let mut store = self.store()?;
        if !self
            .origins()
            .links
            .get(&session_id)
            .is_some_and(|current| Arc::ptr_eq(current, link))
        {
            return Ok(Taken::Stale);
        }
        store.rebuild(&events, reading).map_err(refusal)?;
        let certified = {
            let mut origins = self.origins();
            if complete {
                let certified = origins.certified.entry(session_id).or_insert(0);
                *certified = (*certified).max(page.built_at_boot_ms.get());
            }
            if let Some(floor) = page.output_floor.0 {
                origins.output_floor.insert(session_id, floor.get());
            }
            origins.certified.clone()
        };
        store
            .tick(reading, &|origin| certified_at(&certified, origin))
            .map_err(refusal)?;
        drop(store);
        // A certificate that moved may let a timer be decided that the maintenance loop had put
        // aside.
        self.wake.notify_one();
        Ok(if complete {
            Taken::Complete
        } else {
            Taken::Partial
        })
    }

    fn certificates(&self) -> BTreeMap<SessionId, u64> {
        self.origins().certified.clone()
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
                let reading = held.reading();
                if let Ok(mut store) = held.store() {
                    // Read with the store held: a closure and a replacement take the store before
                    // they take a certificate away, so this tick never decides on one they took.
                    let certified = held.certificates();
                    let _ = store.tick(reading, &|origin| certified_at(&certified, origin));
                    // Expired records are let go of only on a wall clock this host can prove, so a
                    // rollback cannot make a live record look expired.
                    if held.time.may_collect_expired()
                        && reading.wall_ms.get().saturating_sub(forgot_at) > FORGET_EVERY_MS
                    {
                        forgot_at = reading.wall_ms.get();
                        let _ = store.forget_actions_before(
                            reading.wall_ms.get().saturating_sub(ACTION_RETENTION_MS),
                        );
                    }
                }
                let mut wait = held
                    .next_decidable_deadline(reading)
                    .map_or(MAINTENANCE, |due| {
                        Duration::from_millis(due.saturating_sub(reading.continuous_ms))
                            .clamp(Duration::from_millis(50), MAINTENANCE)
                    });
                if !held.origins().unfinished.is_empty() {
                    wait = wait.min(CLOSURE_RETRY);
                }
                // The signal is taken before the module is let go of, so a change that wakes it
                // cannot fall between the look above and the wait; the module itself is not held
                // across the wait, so one its owner has let go of goes.
                let wake = Arc::clone(&held.wake);
                let notified = wake.notified();
                drop(held);
                let _ = tokio::time::timeout(wait, notified).await;
            }
        });
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
                    || certified_at(certified, &origin).is_some_and(|at| at >= due);
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
    let kind = if record.notification {
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

/// Whether one source's part of a page reached the source's head.
const fn complete(cursor: u64, head: u64, last: Option<u64>) -> bool {
    match last {
        Some(last) => last >= head,
        None => cursor >= head,
    }
}

fn certified_at(certified: &BTreeMap<SessionId, u64>, origin: &Origin) -> Option<u64> {
    match origin {
        Origin::Session(session_id) => certified.get(session_id).copied(),
        // The environment has no source of its own yet, and so no certificate.
        Origin::Environment => None,
    }
}

// ----- Helpers ---------------------------------------------------------------------------------

/// Returns the host's clocks now, in the form the store takes.
fn reading(time: &kr_worker::action::time::TimeContract) -> HostReading {
    let identity = time.boot_identity();
    let mut bytes = format!("{:?}", identity.source).into_bytes();
    bytes.push(b'|');
    bytes.extend_from_slice(identity.value.as_slice());
    HostReading::new(
        kr_attention::time::BootMark::of(&bytes),
        kr_ipc::clock::boot_elapsed_ms(),
        kr_ipc::now_ms().get(),
        time.trust() == kr_protocol::action::WallClockTrust::Trusted,
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
mod tests {
    use std::time::Instant;

    use kr_ipc::framed::{FrameReader, FrameWriter};
    use kr_protocol::attention::{
        AttentionHostSlice, AttentionQuestionSlice, AttentionReadResult, AttentionRecordText,
        AttentionTextAnswer,
    };
    use kr_protocol::frame::StreamKind;
    use kr_protocol::ids::QuestionId;
    use kr_protocol::method::MethodVersion;
    use kr_protocol::scalars::TimestampMs;
    use kr_protocol::session::DisplayNumber;

    use super::*;

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
            .expect("the store answers");
        assert!(matches!(late, Taken::Stale));
        let current = module
            .take_page(open, &open_link, 0, 0, &question_page(open))
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
    async fn owner_connection(
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
        assert!(!writing.is_finished());
        let reading = tokio::spawn(async move { reader.read_message::<ControlFrame>().await });
        let written = tokio::time::timeout(Duration::from_secs(5), writing)
            .await
            .expect("the write stops")
            .expect("the write finishes");
        assert!(written.is_err(), "no byte went after the lease ended");
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

    /// A rollback of the wall clock the store's time contract saw is written beside the store,
    /// one save at a time however many readings save at once, and a store opened again reads it
    /// back.
    #[tokio::test(flavor = "multi_thread")]
    async fn what_the_time_contract_must_keep_is_written_beside_the_store() {
        use kr_worker::action::adapter::{
            RecordedTimeAdapter, UnixTimex, classify_unix, unix_model,
        };
        use kr_worker::action::time::{ManualActiveClock, ManualWallClock, TimeSources};

        const WALL: u64 = 1_700_000_000_000;
        let temp = kr_ipc::testing::TempHost::create();
        let continuous = kr_ipc::clock::ManualSharedClock::new();
        continuous.advance(Duration::from_secs(3_600));
        let active = ManualActiveClock::new();
        active.advance(Duration::from_secs(3_600));
        let wall = ManualWallClock::new(WALL);
        let adapter = RecordedTimeAdapter::new(classify_unix(
            "macos",
            "ntp_adjtime(2)",
            UnixTimex {
                time_state: unix_model::TIME_OK,
                status: unix_model::STA_PLL,
                maxerror_us: 62_192,
                esterror_us: 500_000,
            },
            TimestampMs::new(WALL),
        ));
        let sources = || TimeSources {
            continuous: Arc::new(continuous.clone()),
            active: Arc::new(active.clone()),
            wall: Arc::new(wall.clone()),
            adapter: Arc::new(adapter.clone()),
        };
        let boot = kr_ipc::identity::boot_identity().expect("a boot identity");
        let first = Arc::new(
            AttentionModule::open_over(&temp.environment(), boot.clone(), sources())
                .expect("the store opens"),
        );
        let _ = first.reading();
        assert_eq!(
            first.time.trust(),
            kr_protocol::action::WallClockTrust::Trusted
        );

        // The wall clock is set back a minute, and several readings observe it and save at once.
        wall.set(WALL - 60_000);
        let readers: Vec<_> = (0..8)
            .map(|_| {
                let first = Arc::clone(&first);
                std::thread::spawn(move || {
                    for _ in 0..20 {
                        let _ = first.reading();
                    }
                })
            })
            .collect();
        for reader in readers {
            reader.join().expect("the readings finish");
        }
        assert_eq!(
            first.time.trust(),
            kr_protocol::action::WallClockTrust::Unresolved
        );
        assert!(
            !first.time.unsaved(),
            "nothing it must keep is left unwritten"
        );
        let bytes = std::fs::read(&first.time_file).expect("the record is written");
        kr_cbor::from_canonical_slice::<kr_protocol::action::HostTimeState>(
            &bytes,
            &kr_cbor::Limits::DEFAULT,
        )
        .expect("what was written reads back");
        drop(first);
        let again = AttentionModule::open_over(&temp.environment(), boot, sources())
            .expect("the store opens again");
        assert_eq!(
            again.time.trust(),
            kr_protocol::action::WallClockTrust::Unresolved,
            "a restart keeps the rollback"
        );
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
}
