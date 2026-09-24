//! The broker's durable records.
//!
//! Section 11 requires the broker to retain a ledger of what a decoder did and what it was checked
//! against, and section 24 makes the worker's journal the authoritative store for "live receipts,
//! approvals, questions and gateway source bindings". This ledger lives in that same journal file,
//! beside the receipt tables and the question tables, with its own version row: neither migration
//! reads the other's, and a plugin-process failure cannot destroy any of them because none of them
//! is in the plugin process.
//!
//! What is kept, and why each row is here rather than in memory:
//!
//! * **Bindings** carry the three grants and the decoding-trust record. A restarted worker that
//!   forgot them would re-grant by default or refuse work the user had already permitted.
//! * **Decoder entries** name the package, its publisher, the original source and the request it
//!   produced. A person inspecting a pending approval has to be able to see whose interpretation
//!   it is, after the process that produced it has gone.
//! * **Consumed sources** are the non-reuse check. A decoder may offer a resource from a fresh
//!   source event handle once; the same handle offered twice is refused, and that has to survive a
//!   restart or the second offer would succeed after one.
//! * **Pending resources** are what reconnect reconciles against. Their durable state is what
//!   stops a second response from being emitted for an identifier the host may already have
//!   answered.
//! * **Launch profiles** record what was actually resolved and run.
//! * **Evidence gaps** record each spell of volatile operation, so the gap is committed when
//!   storage returns rather than quietly forgotten.
//! * **Adapter checkpoints** are the consumed semantic cursor a restart replays from.
//! * **Client intents** are the requests the native terminal made of its own upstream, recorded
//!   with their classification before their bytes go. A restart that found one of them unsettled
//!   knows an operation it did not classify may already have changed upstream state.
//! * **Transition events** are the outbox section 24 requires beside each state change: "commit
//!   state transitions and a small event/outbox record in the same local transaction". A crash
//!   between the two would lose the announcement of a change that happened, so there is no
//!   between: one transaction carries both, and the sequence the row is keyed by is the order
//!   every observer is told in.

use kr_protocol::broker::{BrokerGrants, DecoderLedgerEntry, DecodingTrust, LaunchProfile};
use kr_protocol::gateway::{
    EvidenceGap, NativeClassification, PendingKind, PendingResource, PendingState,
};
use kr_protocol::ids::{
    ApplicationInstanceId, BrokerBindingId, GatewayConnectionId, PendingResourceId,
    SourceEventHandle, StreamCursor, UpstreamMethod, UpstreamRequestId,
};
use kr_protocol::scalars::{TimestampMs, Uuid};
use kr_protocol::session::Durability;
use rusqlite::{Connection, OptionalExtension as _, params};

use crate::broker::error::{BrokerError, Result};
use crate::persistence::fault::JournalHealth;
use crate::persistence::stores::ContentClass;

/// The schema version this build reads.
pub const SCHEMA_VERSION: i64 = 5;

/// How long the ledger waits for another connection to finish writing, outside prompt mode.
pub const BUSY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// One binding, as the ledger holds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BindingRecord {
    /// The binding.
    pub binding_id: BrokerBindingId,
    /// The application instance it is bound to.
    pub application_instance_id: ApplicationInstanceId,
    /// The three grants, each held separately.
    pub grants: BrokerGrants,
    /// The decoding trust, where the binding has any.
    ///
    /// Absent is the default and the safe one: a component with no record here cannot create an
    /// approval resource whatever it reports.
    pub trust: Option<DecodingTrust>,
    /// When the binding was recorded.
    pub bound_at: TimestampMs,
}

/// One resource a restart found unresolved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnresolvedRecord {
    /// The resource as it was last written.
    pub resource: PendingResource,
    /// True when an answer had already left this host for it.
    ///
    /// This is the dispatch marker read back. A resource with it set is never answered again: the
    /// first answer may have been applied, and asking again would be the second.
    pub dispatched: bool,
    /// The binding whose decoder produced it, where one did.
    pub decoder: Option<BrokerBindingId>,
}

/// What became of one request the native client made of its upstream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientRequestOutcome {
    /// It is recorded and its bytes have not been written yet.
    Recorded,
    /// Every byte of it reached the upstream.
    Transmitted,
    /// Part of it reached the upstream, so whether the upstream read it cannot be established.
    Uncertain,
    /// None of it reached the upstream.
    Unsent,
}

impl ClientRequestOutcome {
    /// Returns the stable stored string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Recorded => "recorded",
            Self::Transmitted => "transmitted",
            Self::Uncertain => "uncertain",
            Self::Unsent => "unsent",
        }
    }
}

/// One request or notification the native client sent its own upstream.
///
/// It is recorded before its bytes go, with the classification the connection's own table gave it.
/// That is what makes an unclassified request something a restart can see: the row says a method
/// this host could not classify was forwarded, and whether it went.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientIntent {
    /// This host's own record of the request.
    pub intent_id: Uuid,
    /// The instance it was forwarded to.
    pub application_instance_id: ApplicationInstanceId,
    /// The connection it arrived on.
    pub connection: GatewayConnectionId,
    /// The identifier this host forwarded it under; absent for a notification.
    pub upstream_request_id: Option<UpstreamRequestId>,
    /// The method the client named.
    pub method: UpstreamMethod,
    /// How the connection's own pinned table classified it.
    pub classification: NativeClassification,
    /// The retained source frame the bytes were kept as.
    pub source: SourceEventHandle,
    /// What became of it.
    pub outcome: ClientRequestOutcome,
    /// When it was recorded.
    pub recorded_at: TimestampMs,
}

/// What caused one resource transition.
///
/// Section 24 asks an event to name the subsystem and actor it came from. Every one of these is
/// the broker's, so the subsystem is not a field; what differs is which of its paths decided, and
/// that is what tells a person's own answer from the upstream withdrawing its request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransitionCause {
    /// The request was recorded, which is where a resource begins.
    Recorded,
    /// A decoder's verified interpretation made it answerable.
    Interpreted,
    /// A rich client claimed it, or gave the claim back.
    RichClaim,
    /// An answer left this host for it.
    Dispatched,
    /// A rich client's answer settled it.
    RichAnswer,
    /// The native terminal's own answer settled it.
    NativeAnswer,
    /// This host's own answer to a request it performs itself settled it.
    HostAnswer,
    /// The upstream answered or withdrew its own request.
    Upstream,
    /// A reconciliation after a reconnection or a recovery settled it.
    Reconciliation,
}

/// Returns the class of content one resource's own content belongs to.
///
/// Section 24 asks every event to carry a content classification beside its identity and its
/// causal chain, and the classes are the worker's own
/// ([`crate::persistence::stores::ContentClass`]), not a second vocabulary. It is a different
/// question from [`NativeClassification`], which says what a method may *do*.
///
/// While `DecoderLedgerEntry` retains the source bytes and the verified projection, a native
/// request's raw bytes stay in the retained source frame they arrived in, and the resource itself
/// names that frame; this says what a consumer would be reading if it followed the name back, so
/// it is the widest class the content can be:
///
/// * a recorded native request, approval or reverse operation alike, is the connector's own
///   frame, and the widest thing a frame can quote is the application's own output, so it is
///   terminal content for as long as nothing has interpreted it;
/// * once a granted decoder's interpretation is verified, what the resource offers is the decoded
///   proposal a person is asked to answer, which is text an agent asked for;
/// * an action this host prepared carries what the person wrote.
#[must_use]
pub const fn content_class(resource: &PendingResource) -> ContentClass {
    match resource.kind {
        PendingKind::UpstreamAction => ContentClass::AuthoredContent,
        PendingKind::Approval | PendingKind::ReverseRpc => {
            if resource.interpretation_verified {
                ContentClass::AuthoredContent
            } else {
                ContentClass::TerminalContent
            }
        }
    }
}

impl TransitionCause {
    /// Every cause, in declaration order.
    pub const ALL: &'static [Self] = &[
        Self::Recorded,
        Self::Interpreted,
        Self::RichClaim,
        Self::Dispatched,
        Self::RichAnswer,
        Self::NativeAnswer,
        Self::HostAnswer,
        Self::Upstream,
        Self::Reconciliation,
    ];

    /// Returns the stable stored string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Recorded => "recorded",
            Self::Interpreted => "interpreted",
            Self::RichClaim => "rich_claim",
            Self::Dispatched => "dispatched",
            Self::RichAnswer => "rich_answer",
            Self::NativeAnswer => "native_answer",
            Self::HostAnswer => "host_answer",
            Self::Upstream => "upstream",
            Self::Reconciliation => "reconciliation",
        }
    }
}

/// One resource transition, as the outbox records it beside the transition itself.
///
/// Section 24: events carry an immutable identifier, a stream cursor, the subject and its binding
/// revision, the source subsystem and actor, a causal root and parent, and the content's
/// classification. The sequence is that cursor; the causal root is the upstream request the
/// resource belongs to, and the parent is the previous event about that same resource.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransitionEvent {
    /// The position of this event in the broker's own stream.
    pub sequence: u64,
    /// The event itself, which never changes and never repeats.
    ///
    /// It is the deduplication key. A sequence orders the events of one run; this identifies one
    /// event for the life of the record.
    pub event_id: Uuid,
    /// The instance the resource belongs to.
    pub application_instance_id: ApplicationInstanceId,
    /// The resource whose state changed.
    pub resource_id: PendingResourceId,
    /// The binding revision in force when it changed.
    pub binding_revision: kr_protocol::ids::AgentBindingRevision,
    /// What the resource became.
    pub state: PendingState,
    /// How the connection's own pinned table classified the method behind the resource.
    ///
    /// This is the method's effect class, which is what decides whether an unclassified request
    /// suspends rich mutations. Section 24's content classification is `content`, beside it.
    pub classification: NativeClassification,
    /// What class of content the resource holds, which is section 24's content classification.
    pub content: ContentClass,
    /// What the resource's own history is: durable, or lived through an evidence gap.
    pub durability: Durability,
    /// Which of the broker's paths decided this transition.
    pub cause: TransitionCause,
    /// The actor whose action caused it, where one did.
    pub actor_id: Option<kr_protocol::ids::ActorId>,
    /// The upstream request this resource belongs to, which is the root of its causal chain.
    pub causal_root: String,
    /// The previous event about this same resource, where there is one.
    pub parent_sequence: Option<u64>,
    /// When the transition happened.
    pub recorded_at: TimestampMs,
}

/// One bounded page of recorded transitions, and whether the backlog continues past it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EventPage {
    /// The events this page carries, in stream order.
    pub events: Vec<TransitionEvent>,
    /// Whether more events remain after the last one here.
    pub more: bool,
}

/// What one recovered event counts against a page's byte bound.
///
/// It measures the row rather than the frame the event is eventually encoded into: this bound is
/// on what a recovery allocates while it reads, and the queue the event then goes to has its own
/// bound on what it costs a subscriber. The fixed part covers the identifiers, the states and the
/// timestamps, which are the same size in every row; the variable part is the causal root, which
/// is the only field an upstream decides the length of.
fn event_bytes(event: &TransitionEvent) -> usize {
    /// Identifiers, revisions, states, classes, timestamps and the two sequences.
    const FIXED: usize = 192;
    FIXED
        .saturating_add(event.causal_root.len())
        .saturating_add(
            event
                .actor_id
                .as_ref()
                .map_or(0, |actor| actor.as_str().len()),
        )
}

/// Reads one stored classification back.
fn class_from(text: &str) -> Result<kr_protocol::gateway::NativeMethodClass> {
    kr_protocol::gateway::NativeMethodClass::ALL
        .iter()
        .copied()
        .find(|class| class.as_str() == text)
        .ok_or_else(|| BrokerError::ledger(format!("{text} is not a stored classification")))
}

/// Reads one stored content class back.
fn content_from(text: &str) -> Result<ContentClass> {
    ContentClass::from_stored(text)
        .ok_or_else(|| BrokerError::ledger(format!("{text} is not a stored content class")))
}

/// Reads one stored pending state back.
fn state_from(text: &str) -> Result<PendingState> {
    PendingState::ALL
        .iter()
        .copied()
        .find(|state| state.as_str() == text)
        .ok_or_else(|| BrokerError::ledger(format!("{text} is not a stored state")))
}

/// Writes one transition event inside the transaction that commits the transition.
fn write_event(
    faults: &Faults,
    transaction: &rusqlite::Transaction<'_>,
    event: &TransitionEvent,
) -> Result<()> {
    transaction
        .execute(
            "INSERT INTO broker_events
                 (sequence, event_id, application_instance_id, resource_id, binding_revision,
                  state, class, declared, content, durability, cause, actor_id, causal_root,
                  parent_sequence, recorded_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
            params![
                i64::try_from(event.sequence).unwrap_or(i64::MAX),
                event.event_id.as_bytes().as_slice(),
                event.application_instance_id.get().as_bytes().as_slice(),
                event.resource_id.get().as_bytes().as_slice(),
                i64::try_from(event.binding_revision.get()).unwrap_or(i64::MAX),
                event.state.as_str(),
                event.classification.class.as_str(),
                i64::from(event.classification.declared),
                event.content.as_str(),
                event.durability.as_str(),
                event.cause.as_str(),
                event
                    .actor_id
                    .as_ref()
                    .map(|actor| actor.as_str().to_owned()),
                event.causal_root.as_str(),
                event
                    .parent_sequence
                    .map(|sequence| i64::try_from(sequence).unwrap_or(i64::MAX)),
                i64::try_from(event.recorded_at.get()).unwrap_or(i64::MAX),
            ],
        )
        .map_err(|error| faults.of(error))?;
    Ok(())
}

/// Writes one pending resource's row, on a connection or inside a transaction.
fn put_pending_in(
    faults: &Faults,
    connection: &Connection,
    resource: &PendingResource,
    decoder: Option<BrokerBindingId>,
    dispatched: bool,
) -> Result<()> {
    let record = encode(resource)?;
    connection
        .execute(
            "INSERT INTO broker_pending
                 (resource_id, application_instance_id, connection_id, upstream_request_id,
                  state, durability, record, dispatched, decoder_binding_id, recorded_at_ms,
                  resolved_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, NULL)
             ON CONFLICT (resource_id) DO UPDATE SET
                 state = excluded.state,
                 durability = excluded.durability,
                 record = excluded.record,
                 dispatched = MAX(broker_pending.dispatched, excluded.dispatched)",
            params![
                resource.resource_id.get().as_bytes().as_slice(),
                resource.application_instance_id.get().as_bytes().as_slice(),
                i64::try_from(resource.request.connection.get()).unwrap_or(i64::MAX),
                resource.request.upstream.as_str(),
                resource.state.as_str(),
                resource.durability.as_str(),
                record,
                i64::from(dispatched),
                decoder.map(|binding| binding.get().as_bytes().to_vec()),
                i64::try_from(resource.recorded_at.get()).unwrap_or(i64::MAX),
            ],
        )
        .map_err(|error| faults.of(error))?;
    Ok(())
}

/// One event row, as it comes back out of the store.
struct StoredEvent {
    sequence: i64,
    event_id: Vec<u8>,
    instance: Vec<u8>,
    resource: Vec<u8>,
    revision: i64,
    state: String,
    class: String,
    declared: i64,
    content: String,
    durability: String,
    cause: String,
    actor_id: Option<String>,
    causal_root: String,
    parent_sequence: Option<i64>,
    recorded: i64,
}

/// Reads one stored cause back.
fn cause_from(text: &str) -> Result<TransitionCause> {
    TransitionCause::ALL
        .iter()
        .copied()
        .find(|cause| cause.as_str() == text)
        .ok_or_else(|| BrokerError::ledger(format!("{text} is not a stored cause")))
}

/// Reads one stored durability back.
fn durability_from(text: &str) -> Result<Durability> {
    [Durability::Durable, Durability::Volatile]
        .into_iter()
        .find(|durability| durability.as_str() == text)
        .ok_or_else(|| BrokerError::ledger(format!("{text} is not a stored durability")))
}

/// Reads one stored client-request outcome back.
fn outcome_from(text: &str) -> Result<ClientRequestOutcome> {
    [
        ClientRequestOutcome::Recorded,
        ClientRequestOutcome::Transmitted,
        ClientRequestOutcome::Uncertain,
        ClientRequestOutcome::Unsent,
    ]
    .into_iter()
    .find(|outcome| outcome.as_str() == text)
    .ok_or_else(|| BrokerError::ledger(format!("{text} is not a stored outcome")))
}

/// The broker's durable records, in the worker's own journal file.
///
/// It reports every failure of the store itself to the session's journal condition, where the
/// failure happens, exactly as the receipt journal does. That condition is the one fence the
/// receipt path and the broker both read, so a ledger that stops answering fences rich work
/// everywhere, and a receipt journal that stops answering fences it here.
#[derive(Debug)]
pub struct Ledger {
    connection: Connection,
    faults: Faults,
}

/// Where a failure of one ledger's store is reported, and how a busy store is read.
#[derive(Clone, Debug)]
struct Faults {
    health: std::sync::Arc<JournalHealth>,
    /// Set while this connection takes the store's lock without waiting for it.
    prompt: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl Faults {
    /// Turns one failure of the store into what it is.
    ///
    /// A store another connection is writing, met by a write that does not wait, is busy and not
    /// failing: nothing is reported, and the write is simply not made now. Everything else is a
    /// fault of the store, reported to the journal condition where it happened, which classifies
    /// the store's own result code, so a full store and a failing one are told apart by what the
    /// store said rather than by its message.
    fn of(&self, error: rusqlite::Error) -> BrokerError {
        let busy = matches!(
            &error,
            rusqlite::Error::SqliteFailure(failure, _)
                if matches!(
                    failure.code,
                    rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked
                )
        );
        if busy && self.prompt.load(std::sync::atomic::Ordering::Acquire) {
            return BrokerError::LedgerUnavailable {
                detail: format!(
                    "another writer holds the store, and this write does not wait: {error}"
                ),
            };
        }
        self.health.observe(&error, kr_ipc::now_ms().get());
        BrokerError::StoreFault {
            detail: error.to_string(),
        }
    }
}

/// Where the next wait for the store's lock is announced, for this host's own tests.
#[cfg(feature = "testing")]
static ANNOUNCED_WAIT: std::sync::Mutex<Option<std::sync::mpsc::SyncSender<()>>> =
    std::sync::Mutex::new(None);

/// Waits for the store's lock as patiently as the busy timeout, and announces the first wait.
#[cfg(feature = "testing")]
fn announce_the_wait(attempt: i32) -> bool {
    let waiting = ANNOUNCED_WAIT
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take();
    if let Some(waiting) = waiting {
        let _ = waiting.send(());
    }
    std::thread::sleep(std::time::Duration::from_millis(5));
    attempt < 1_000
}

impl Ledger {
    /// Opens the ledger beside the receipt journal, or in memory when there is no journal.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::LedgerUnavailable`] when the file cannot be opened or its schema
    /// cannot be created.
    pub fn open(
        path: Option<&std::path::Path>,
        health: std::sync::Arc<JournalHealth>,
    ) -> Result<Self> {
        let faults = Faults {
            health,
            prompt: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };
        let connection = match path {
            Some(path) => Connection::open(path),
            None => Connection::open_in_memory(),
        }
        .map_err(|error| faults.of(error))?;
        let ledger = Self { connection, faults };
        ledger.prepare()?;
        Ok(ledger)
    }

    /// Turns one failure of this ledger's store into what it is, reported where it happened.
    fn fault(&self, error: rusqlite::Error) -> BrokerError {
        self.faults.of(error)
    }

    /// Makes this connection take the store's lock without waiting for it, or wait again.
    ///
    /// While it does, a write that finds another connection holding the store answers at once
    /// with [`BrokerError::LedgerUnavailable`] rather than after the busy timeout, and that is not
    /// a fault of the store. It is for writes made under the broker's lock during a recovery,
    /// which must never hold native arbitration behind somebody else's write.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::StoreFault`] when the connection cannot be changed.
    pub fn set_prompt(&self, prompt: bool) -> Result<()> {
        if prompt {
            self.connection
                .busy_timeout(std::time::Duration::ZERO)
                .map_err(|error| self.fault(error))?;
            self.faults
                .prompt
                .store(true, std::sync::atomic::Ordering::Release);
        } else {
            self.faults
                .prompt
                .store(false, std::sync::atomic::Ordering::Release);
            self.connection
                .busy_timeout(BUSY_TIMEOUT)
                .map_err(|error| self.fault(error))?;
        }
        Ok(())
    }

    /// Announces, once, when this connection next waits for the store's lock, for this host's own
    /// tests.
    ///
    /// The wait itself is as patient as the busy timeout. It is compiled away in every shipped
    /// build.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::StoreFault`] when the connection cannot be changed.
    #[cfg(feature = "testing")]
    pub fn announce_the_next_wait(&self) -> Result<std::sync::mpsc::Receiver<()>> {
        let (waiting, announced) = std::sync::mpsc::sync_channel(1);
        *ANNOUNCED_WAIT
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(waiting);
        self.connection
            .busy_handler(Some(announce_the_wait))
            .map_err(|error| self.fault(error))?;
        Ok(announced)
    }

    /// Makes every later write to this ledger fail, or lets writes through again.
    ///
    /// The refusal is the store's own: in query-only mode SQLite answers every write with
    /// `SQLITE_READONLY`, which is what a store that has stopped taking writes says. It is how
    /// this host's own tests fault the ledger in the middle of live traffic without taking a disk
    /// away. It is compiled away in every shipped build.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::StoreFault`] when the setting cannot be applied.
    #[cfg(feature = "testing")]
    pub fn refuse_writes(&self, refuse: bool) -> Result<()> {
        self.connection
            .pragma_update(None, "query_only", refuse)
            .map_err(|error| self.fault(error))
    }

    fn prepare(&self) -> Result<()> {
        self.connection
            .busy_timeout(BUSY_TIMEOUT)
            .map_err(|error| self.fault(error))?;
        self.connection
            .pragma_update(None, "journal_mode", "WAL")
            .map_err(|error| self.fault(error))?;
        self.connection
            .pragma_update(None, "synchronous", "FULL")
            .map_err(|error| self.fault(error))?;
        self.connection
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS broker_schema (version INTEGER NOT NULL);
                 CREATE TABLE IF NOT EXISTS broker_bindings (
                     binding_id              BLOB PRIMARY KEY,
                     application_instance_id BLOB NOT NULL,
                     grants                  BLOB NOT NULL,
                     trust                   BLOB,
                     bound_at_ms             INTEGER NOT NULL
                 );
                 CREATE INDEX IF NOT EXISTS broker_bindings_by_instance
                     ON broker_bindings (application_instance_id);
                 CREATE TABLE IF NOT EXISTS broker_decoder_entries (
                     resource_id   BLOB PRIMARY KEY,
                     entry         BLOB NOT NULL,
                     recorded_at_ms INTEGER NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS broker_consumed_sources (
                     application_instance_id BLOB    NOT NULL,
                     source_handle           TEXT    NOT NULL,
                     source_generation       INTEGER NOT NULL,
                     source_digest           BLOB    NOT NULL,
                     binding_id              BLOB    NOT NULL,
                     consumed_at_ms          INTEGER NOT NULL,
                     PRIMARY KEY (application_instance_id, source_handle)
                 );
                 CREATE TABLE IF NOT EXISTS broker_pending (
                     resource_id             BLOB PRIMARY KEY,
                     application_instance_id BLOB NOT NULL,
                     connection_id           INTEGER NOT NULL,
                     upstream_request_id     TEXT NOT NULL,
                     state                   TEXT NOT NULL,
                     durability              TEXT NOT NULL,
                     record                  BLOB NOT NULL,
                     dispatched              INTEGER NOT NULL DEFAULT 0,
                     decoder_binding_id      BLOB,
                     recorded_at_ms          INTEGER NOT NULL,
                     resolved_at_ms          INTEGER
                 );
                 CREATE UNIQUE INDEX IF NOT EXISTS broker_pending_by_request
                     ON broker_pending (connection_id, upstream_request_id);
                 CREATE INDEX IF NOT EXISTS broker_pending_by_state ON broker_pending (state);
                 CREATE TABLE IF NOT EXISTS broker_profiles (
                     profile_id              TEXT PRIMARY KEY,
                     application_instance_id BLOB,
                     profile                 BLOB NOT NULL,
                     resolved_at_ms          INTEGER NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS broker_gaps (
                     sequence     INTEGER PRIMARY KEY AUTOINCREMENT,
                     opened_at_ms INTEGER NOT NULL,
                     closed_at_ms INTEGER,
                     reconciled   INTEGER NOT NULL DEFAULT 0,
                     record       BLOB NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS broker_checkpoints (
                     application_instance_id BLOB PRIMARY KEY,
                     consumed_cursor         INTEGER NOT NULL,
                     updated_at_ms           INTEGER NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS broker_stream (
                     id            INTEGER PRIMARY KEY CHECK (id = 0),
                     generation    INTEGER NOT NULL,
                     advanced_at_ms INTEGER NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS broker_client_requests (
                     intent_id               BLOB PRIMARY KEY,
                     application_instance_id BLOB NOT NULL,
                     connection_id           INTEGER NOT NULL,
                     upstream_request_id     TEXT,
                     method                  TEXT NOT NULL,
                     class                   TEXT NOT NULL,
                     declared                INTEGER NOT NULL,
                     source_handle           TEXT NOT NULL,
                     outcome                 TEXT NOT NULL,
                     recorded_at_ms          INTEGER NOT NULL
                 );
                 CREATE INDEX IF NOT EXISTS broker_client_requests_by_instance
                     ON broker_client_requests (application_instance_id);
                 CREATE TABLE IF NOT EXISTS broker_events (
                     sequence                INTEGER PRIMARY KEY,
                     event_id                BLOB NOT NULL UNIQUE,
                     application_instance_id BLOB NOT NULL,
                     resource_id             BLOB NOT NULL,
                     binding_revision        INTEGER NOT NULL,
                     state                   TEXT NOT NULL,
                     class                   TEXT NOT NULL,
                     declared                INTEGER NOT NULL,
                     content                 TEXT NOT NULL,
                     durability              TEXT NOT NULL,
                     cause                   TEXT NOT NULL,
                     actor_id                TEXT,
                     causal_root             TEXT NOT NULL,
                     parent_sequence         INTEGER,
                     recorded_at_ms          INTEGER NOT NULL
                 );
                 CREATE INDEX IF NOT EXISTS broker_events_by_resource
                     ON broker_events (resource_id, sequence);",
            )
            .map_err(|error| self.fault(error))?;
        let recorded: Option<i64> = self
            .connection
            .query_row("SELECT version FROM broker_schema", [], |row| row.get(0))
            .optional()
            .map_err(|error| self.fault(error))?;
        match recorded {
            None => {
                self.connection
                    .execute(
                        "INSERT INTO broker_schema (version) VALUES (?1)",
                        params![SCHEMA_VERSION],
                    )
                    .map_err(|error| self.fault(error))?;
            }
            Some(version) if version == SCHEMA_VERSION => {}
            // Not every change this build has made is one a `CREATE TABLE IF NOT EXISTS` brings
            // forward: a table that already exists keeps the columns it was made with. So an
            // older ledger is refused by name rather than relabelled into a shape it does not
            // have. Integration uses a fresh ledger; what happens to a retained one is a policy
            // decision, and the ledger-transition work is where it is made.
            Some(version) => {
                return Err(BrokerError::ledger(format!(
                    "this ledger is at schema version {version}; this build reads {SCHEMA_VERSION}"
                )));
            }
        }
        Ok(())
    }

    // -- bindings -----------------------------------------------------------------------------

    /// Writes or replaces one binding's grants and decoding trust.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::LedgerUnavailable`] when the write fails, and
    /// [`BrokerError::Trust`] when the trust record breaks section 11's rules, because a record
    /// the broker would not act on is not one to store.
    pub fn put_binding(&self, record: &BindingRecord) -> Result<()> {
        if let Some(trust) = record.trust.as_ref() {
            trust.validate()?;
        }
        self.connection
            .execute(
                "INSERT INTO broker_bindings
                     (binding_id, application_instance_id, grants, trust, bound_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT (binding_id) DO UPDATE SET
                     application_instance_id = excluded.application_instance_id,
                     grants = excluded.grants,
                     trust  = excluded.trust",
                params![
                    record.binding_id.get().as_bytes().as_slice(),
                    record.application_instance_id.get().as_bytes().as_slice(),
                    encode(&record.grants)?,
                    record.trust.as_ref().map(encode).transpose()?,
                    i64::try_from(record.bound_at.get()).unwrap_or(i64::MAX),
                ],
            )
            .map_err(|error| self.fault(error))?;
        Ok(())
    }

    /// Reads one binding.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::LedgerUnavailable`] when the read fails or a stored record cannot be
    /// decoded.
    pub fn binding(&self, binding_id: BrokerBindingId) -> Result<Option<BindingRecord>> {
        self.connection
            .query_row(
                "SELECT application_instance_id, grants, trust, bound_at_ms
                 FROM broker_bindings WHERE binding_id = ?1",
                params![binding_id.get().as_bytes().as_slice()],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Option<Vec<u8>>>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                },
            )
            .optional()
            .map_err(|error| self.fault(error))?
            .map(|(instance, grants, trust, bound_at)| {
                Ok(BindingRecord {
                    binding_id,
                    application_instance_id: ApplicationInstanceId::new(uuid_from(&instance)?),
                    grants: decode(&grants)?,
                    trust: trust.as_deref().map(decode).transpose()?,
                    bound_at: TimestampMs::new(u64::try_from(bound_at).unwrap_or(0)),
                })
            })
            .transpose()
    }

    /// Reads every binding of one application instance.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::LedgerUnavailable`] when the read fails.
    pub fn bindings_of(
        &self,
        application_instance_id: ApplicationInstanceId,
    ) -> Result<Vec<BindingRecord>> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT binding_id, grants, trust, bound_at_ms FROM broker_bindings
                 WHERE application_instance_id = ?1 ORDER BY bound_at_ms, binding_id",
            )
            .map_err(|error| self.fault(error))?;
        let rows = statement
            .query_map(
                params![application_instance_id.get().as_bytes().as_slice()],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Option<Vec<u8>>>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                },
            )
            .map_err(|error| self.fault(error))?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|error| self.fault(error))?;
        rows.into_iter()
            .map(|(binding, grants, trust, bound_at)| {
                Ok(BindingRecord {
                    binding_id: BrokerBindingId::new(uuid_from(&binding)?),
                    application_instance_id,
                    grants: decode(&grants)?,
                    trust: trust.as_deref().map(decode).transpose()?,
                    bound_at: TimestampMs::new(u64::try_from(bound_at).unwrap_or(0)),
                })
            })
            .collect()
    }

    /// Removes one binding and everything that hangs from it.
    ///
    /// The decoder entries stay: they are the record of what was already offered, and forgetting
    /// them because the binding ended would lose the provenance of a pending approval.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::LedgerUnavailable`] when the write fails.
    pub fn remove_binding(&self, binding_id: BrokerBindingId) -> Result<()> {
        self.connection
            .execute(
                "DELETE FROM broker_bindings WHERE binding_id = ?1",
                params![binding_id.get().as_bytes().as_slice()],
            )
            .map_err(|error| self.fault(error))?;
        Ok(())
    }

    // -- the decoder ledger -------------------------------------------------------------------

    /// Records what a decoder offered, against the resource it produced.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::LedgerUnavailable`] when the write fails.
    pub fn record_decoding(
        &self,
        resource_id: PendingResourceId,
        entry: &DecoderLedgerEntry,
    ) -> Result<()> {
        self.connection
            .execute(
                "INSERT OR REPLACE INTO broker_decoder_entries
                     (resource_id, entry, recorded_at_ms) VALUES (?1, ?2, ?3)",
                params![
                    resource_id.get().as_bytes().as_slice(),
                    encode(entry)?,
                    i64::try_from(entry.decoded_at.get()).unwrap_or(i64::MAX),
                ],
            )
            .map_err(|error| self.fault(error))?;
        Ok(())
    }

    /// Reads the decoder entry behind one pending resource.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::LedgerUnavailable`] when the read fails.
    pub fn decoding(&self, resource_id: PendingResourceId) -> Result<Option<DecoderLedgerEntry>> {
        self.connection
            .query_row(
                "SELECT entry FROM broker_decoder_entries WHERE resource_id = ?1",
                params![resource_id.get().as_bytes().as_slice()],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()
            .map_err(|error| self.fault(error))?
            .map(|bytes| decode(&bytes))
            .transpose()
    }

    /// Records one opaque native request before it is forwarded.
    ///
    /// Section 11: "The broker records opaque native requests before forwarding them and
    /// arbitrates responses by their IDs." It is not an approval yet; a decoder's interpretation
    /// makes it one, through [`Ledger::admit_resource`].
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::LedgerUnavailable`] when the write fails.
    pub fn record_opaque(&self, resource: &PendingResource, event: &TransitionEvent) -> Result<()> {
        let transaction = self
            .connection
            .unchecked_transaction()
            .map_err(|error| self.fault(error))?;
        put_pending_in(&self.faults, &transaction, resource, None, false)?;
        write_event(&self.faults, &transaction, event)?;
        transaction.commit().map_err(|error| self.fault(error))
    }

    /// Admits one decoded interpretation of a request this ledger already holds: consumes its
    /// source, records the decoder and makes the pending row actionable, all in one transaction.
    ///
    /// The three writes are one because a crash between them would leave a source permanently
    /// consumed with no interpretation to show for it, or a resource whose provenance nobody can
    /// read. The source is consumed by the broker's own event identity, so a second decoder cannot
    /// interpret the same event and two events with identical bytes are two events.
    ///
    /// Returns `false` without writing anything when the source has already been consumed.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::LedgerUnavailable`] when any part of the transaction fails; the
    /// whole of it goes back.
    pub fn admit_resource(
        &mut self,
        source_handle: &SourceEventHandle,
        binding_id: BrokerBindingId,
        entry: &DecoderLedgerEntry,
        resource: &PendingResource,
        now: TimestampMs,
        event: &TransitionEvent,
    ) -> Result<bool> {
        let faults = self.faults.clone();
        let transaction = self
            .connection
            .transaction()
            .map_err(|error| faults.of(error))?;
        let consumed = transaction
            .execute(
                "INSERT OR IGNORE INTO broker_consumed_sources
                     (application_instance_id, source_handle, source_generation, source_digest,
                      binding_id, consumed_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    resource.application_instance_id.get().as_bytes().as_slice(),
                    source_handle.as_str(),
                    i64::try_from(entry.source_generation.get()).unwrap_or(i64::MAX),
                    entry.source_digest.as_bytes().as_slice(),
                    binding_id.get().as_bytes().as_slice(),
                    i64::try_from(now.get()).unwrap_or(i64::MAX),
                ],
            )
            .map_err(|error| faults.of(error))?;
        if consumed != 1 {
            // Nothing was written, and the rollback makes that true of the whole transaction
            // rather than only of this statement.
            transaction.rollback().map_err(|error| faults.of(error))?;
            return Ok(false);
        }
        transaction
            .execute(
                "INSERT OR REPLACE INTO broker_decoder_entries
                     (resource_id, entry, recorded_at_ms) VALUES (?1, ?2, ?3)",
                params![
                    resource.resource_id.get().as_bytes().as_slice(),
                    encode(entry)?,
                    i64::try_from(entry.decoded_at.get()).unwrap_or(i64::MAX),
                ],
            )
            .map_err(|error| faults.of(error))?;
        let updated = transaction
            .execute(
                "UPDATE broker_pending
                 SET record = ?2, decoder_binding_id = ?3
                 WHERE resource_id = ?1 AND state = 'pending'",
                params![
                    resource.resource_id.get().as_bytes().as_slice(),
                    encode(resource)?,
                    binding_id.get().as_bytes().as_slice(),
                ],
            )
            .map_err(|error| faults.of(error))?;
        if updated != 1 {
            // The request this interpretation is about is not one this ledger holds as pending.
            // Consuming its source and recording a decoder against it would leave evidence about
            // nothing, so the whole transaction goes back.
            transaction.rollback().map_err(|error| faults.of(error))?;
            return Err(BrokerError::PreconditionFailed {
                detail: format!(
                    "pending resource {} is not a pending row this ledger holds",
                    resource.resource_id
                ),
            });
        }
        write_event(&self.faults, &transaction, event)?;
        transaction.commit().map_err(|error| faults.of(error))?;
        Ok(true)
    }

    // -- pending resources --------------------------------------------------------------------

    /// Writes the record of a resource that was admitted while the journal was faulted.
    ///
    /// Section 11 requires the gap to be committed after storage recovers, and this is what
    /// commits the resources that lived inside it. It is not a replay: the record says the
    /// resource was volatile, and its state is whatever it actually reached.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::LedgerUnavailable`] when the write fails.
    pub fn put_pending(
        &self,
        resource: &PendingResource,
        decoder: Option<BrokerBindingId>,
        dispatched: bool,
    ) -> Result<()> {
        put_pending_in(
            &self.faults,
            &self.connection,
            resource,
            decoder,
            dispatched,
        )
    }

    /// Moves one pending resource from the state it is in to the state it is going to.
    ///
    /// The update is conditional on `expected`, so a write built from a stale copy of the record
    /// cannot put a resolved resource back to pending. A row that does not match is reported
    /// rather than silently ignored, because the caller's memory and this ledger disagreeing is
    /// exactly the condition that must not be papered over.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::LedgerUnavailable`] when the row is not in the expected state or the
    /// write fails.
    pub fn settle_pending(
        &self,
        resource: &PendingResource,
        expected: PendingState,
        dispatched: bool,
        now: TimestampMs,
        event: &TransitionEvent,
    ) -> Result<()> {
        // One transaction for the change and for the record that announces it. Section 24 makes
        // those one write because a crash between two writes loses an event about a change that
        // did happen, and nothing later can tell that it did.
        let transaction = self
            .connection
            .unchecked_transaction()
            .map_err(|error| self.fault(error))?;
        let updated = transaction
            .execute(
                "UPDATE broker_pending
                 SET state = ?3, durability = ?4, record = ?5,
                     dispatched = MAX(dispatched, ?6),
                     resolved_at_ms = CASE WHEN ?7 THEN ?8 ELSE resolved_at_ms END
                 WHERE resource_id = ?1 AND state = ?2",
                params![
                    resource.resource_id.get().as_bytes().as_slice(),
                    expected.as_str(),
                    resource.state.as_str(),
                    resource.durability.as_str(),
                    encode(resource)?,
                    i64::from(dispatched),
                    resource.state.is_terminal(),
                    i64::try_from(now.get()).unwrap_or(i64::MAX),
                ],
            )
            .map_err(|error| self.fault(error))?;
        if updated != 1 {
            transaction.rollback().map_err(|error| self.fault(error))?;
            let held: Option<String> = self
                .connection
                .query_row(
                    "SELECT state FROM broker_pending WHERE resource_id = ?1",
                    params![resource.resource_id.get().as_bytes().as_slice()],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|error| self.fault(error))?;
            return Err(BrokerError::ledger(format!(
                "pending resource {} is {} in the ledger and the write expected {expected}",
                resource.resource_id,
                held.unwrap_or_else(|| "absent".to_owned())
            )));
        }
        write_event(&self.faults, &transaction, event)?;
        transaction.commit().map_err(|error| self.fault(error))
    }

    /// Returns the highest event sequence this ledger holds.
    ///
    /// A restarted worker numbers its own events above everything it has already written, so one
    /// stream of transitions runs across restarts rather than beginning again at the top.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::LedgerUnavailable`] when the read fails.
    pub fn highest_event(&self) -> Result<u64> {
        let highest: i64 = self
            .connection
            .query_row(
                "SELECT COALESCE(MAX(sequence), 0) FROM broker_events",
                [],
                |row| row.get(0),
            )
            .map_err(|error| self.fault(error))?;
        Ok(u64::try_from(highest).unwrap_or_default())
    }

    /// Reads the last event about each resource that has not reached a terminal state.
    ///
    /// This is what a restart needs to go on writing causal chains. Without it the first event
    /// after a restart would name no parent, and a consumer reading the outbox could not tell a
    /// resource that has just begun from one this host has been answering since before the
    /// restart. A resource whose last event is terminal is not here: nothing follows it.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::LedgerUnavailable`] when the read fails or a row is unreadable.
    pub fn latest_events(&self) -> Result<Vec<(PendingResourceId, u64)>> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT resource_id, sequence, state FROM broker_events
                 WHERE sequence IN (SELECT MAX(sequence) FROM broker_events GROUP BY resource_id)
                 ORDER BY sequence",
            )
            .map_err(|error| self.fault(error))?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })
            .map_err(|error| self.fault(error))?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|error| self.fault(error))?;
        let mut latest = Vec::new();
        for (resource, sequence, state) in rows {
            if state_from(&state)?.is_terminal() {
                continue;
            }
            latest.push((
                PendingResourceId::new(uuid_from(&resource)?),
                u64::try_from(sequence).unwrap_or_default(),
            ));
        }
        Ok(latest)
    }

    /// Reads one bounded page of the transitions recorded after one cursor, in order.
    ///
    /// A page is what one read allocates and one recovery carries, so it is bounded twice: by the
    /// number of events and by what they measure. A backlog larger than a page is read as several
    /// pages, and the caller continues from the cursor the page ends at, so neither the memory a
    /// recovery takes nor the time this holds the broker is a function of how far behind one
    /// observer fell.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::LedgerUnavailable`] when the read fails or a row is unreadable.
    pub fn events_after(
        &self,
        sequence: u64,
        max_events: usize,
        max_bytes: usize,
    ) -> Result<EventPage> {
        // One row over the page, so a full page is distinguished from a page that ends the
        // backlog without a second read.
        let wanted = max_events.saturating_add(1);
        let mut statement = self
            .connection
            .prepare(
                "SELECT sequence, event_id, application_instance_id, resource_id,
                        binding_revision, state, class, declared, content, durability, cause,
                        actor_id, causal_root, parent_sequence, recorded_at_ms
                 FROM broker_events WHERE sequence > ?1 ORDER BY sequence LIMIT ?2",
            )
            .map_err(|error| self.fault(error))?;
        let rows = statement
            .query_map(
                params![
                    i64::try_from(sequence).unwrap_or(i64::MAX),
                    i64::try_from(wanted).unwrap_or(i64::MAX)
                ],
                |row| {
                    Ok(StoredEvent {
                        sequence: row.get(0)?,
                        event_id: row.get(1)?,
                        instance: row.get(2)?,
                        resource: row.get(3)?,
                        revision: row.get(4)?,
                        state: row.get(5)?,
                        class: row.get(6)?,
                        declared: row.get(7)?,
                        content: row.get(8)?,
                        durability: row.get(9)?,
                        cause: row.get(10)?,
                        actor_id: row.get(11)?,
                        causal_root: row.get(12)?,
                        parent_sequence: row.get(13)?,
                        recorded: row.get(14)?,
                    })
                },
            )
            .map_err(|error| self.fault(error))?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|error| self.fault(error))?;
        let mut more = rows.len() > max_events;
        let mut events = Vec::with_capacity(rows.len().min(max_events));
        let mut measured = 0_usize;
        for row in rows.into_iter().take(max_events) {
            let event = Self::event_from(row)?;
            let cost = event_bytes(&event);
            // The first event of a page is carried whatever it measures: a page that refused it
            // would never advance, and an observer would wait for a recovery that cannot begin.
            if !events.is_empty() && measured.saturating_add(cost) > max_bytes {
                more = true;
                break;
            }
            measured = measured.saturating_add(cost);
            events.push(event);
        }
        Ok(EventPage { events, more })
    }

    /// Reads one stored event row back.
    fn event_from(row: StoredEvent) -> Result<TransitionEvent> {
        Ok(TransitionEvent {
            sequence: u64::try_from(row.sequence).unwrap_or_default(),
            event_id: uuid_from(&row.event_id)?,
            application_instance_id: ApplicationInstanceId::new(uuid_from(&row.instance)?),
            resource_id: PendingResourceId::new(uuid_from(&row.resource)?),
            binding_revision: kr_protocol::ids::AgentBindingRevision::new(
                u64::try_from(row.revision).unwrap_or_default(),
            ),
            state: state_from(&row.state)?,
            classification: NativeClassification {
                class: class_from(&row.class)?,
                declared: row.declared != 0,
            },
            content: content_from(&row.content)?,
            durability: durability_from(&row.durability)?,
            cause: cause_from(&row.cause)?,
            actor_id: row
                .actor_id
                .map(kr_protocol::ids::ActorId::new)
                .transpose()
                .map_err(|error| BrokerError::ledger(format!("a stored actor: {error}")))?,
            causal_root: row.causal_root,
            parent_sequence: row
                .parent_sequence
                .map(|sequence| u64::try_from(sequence).unwrap_or_default()),
            recorded_at: TimestampMs::new(u64::try_from(row.recorded).unwrap_or_default()),
        })
    }

    /// Records that an answer to one resource has left this host.
    ///
    /// This is the dispatch marker, and it is committed before the answer is written to the
    /// upstream. A crash after it leaves a record that says an answer may already have been sent,
    /// which is what stops a restart from sending a second one.
    ///
    /// The write is conditional on the state the resource is in and on the marker being unset, so
    /// it is the one write that can succeed for one resource. A rich answer is marked from
    /// `claimed`; the native client's own answer is marked from whatever state it beat, which is
    /// `pending` when nothing was encoding and `claimed` when something was.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::LedgerUnavailable`] when the write fails or the row is not in that
    /// state with its marker unset.
    pub fn mark_dispatched(
        &self,
        resource: &PendingResource,
        event: &TransitionEvent,
    ) -> Result<()> {
        let transaction = self
            .connection
            .unchecked_transaction()
            .map_err(|error| self.fault(error))?;
        let updated = transaction
            .execute(
                "UPDATE broker_pending SET dispatched = 1
                 WHERE resource_id = ?1 AND state = ?2 AND dispatched = 0",
                params![
                    resource.resource_id.get().as_bytes().as_slice(),
                    resource.state.as_str(),
                ],
            )
            .map_err(|error| self.fault(error))?;
        if updated != 1 {
            transaction.rollback().map_err(|error| self.fault(error))?;
            return Err(BrokerError::ledger(format!(
                "pending resource {} is not an undispatched {} row in the ledger",
                resource.resource_id, resource.state
            )));
        }
        write_event(&self.faults, &transaction, event)?;
        transaction.commit().map_err(|error| self.fault(error))
    }

    /// Commits an evidence gap and everything that happened inside it, in one transaction.
    ///
    /// Section 11 requires the gap to be committed after storage recovers. What is committed is
    /// the gap and the state each affected resource actually reached, in one transaction: a
    /// failure part way leaves the whole of it uncommitted, so the fence that follows is a fence
    /// over a ledger that has not half-recorded a recovery.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::LedgerUnavailable`] when any part of the transaction fails.
    /// Returns the gap's row, so the recovery that follows can mark that same row finished. A
    /// gap the fault itself could not write is inserted here and its new row returned; without
    /// that, a recovery nothing recorded the start of could never record its end either, and
    /// every later restart would come back fenced over a recovery that had already finished.
    pub fn commit_recovery(
        &mut self,
        records: &[(PendingResource, Option<BrokerBindingId>, bool)],
        gap: &EvidenceGap,
        row: Option<i64>,
    ) -> Result<i64> {
        let faults = self.faults.clone();
        let transaction = self
            .connection
            .transaction()
            .map_err(|error| faults.of(error))?;
        for (resource, decoder, dispatched) in records {
            transaction
                .execute(
                    "INSERT INTO broker_pending
                         (resource_id, application_instance_id, connection_id,
                          upstream_request_id, state, durability, record, dispatched,
                          decoder_binding_id, recorded_at_ms, resolved_at_ms)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, NULL)
                     ON CONFLICT (resource_id) DO UPDATE SET
                         state = excluded.state,
                         durability = excluded.durability,
                         record = excluded.record,
                         dispatched = MAX(broker_pending.dispatched, excluded.dispatched)",
                    params![
                        resource.resource_id.get().as_bytes().as_slice(),
                        resource.application_instance_id.get().as_bytes().as_slice(),
                        i64::try_from(resource.request.connection.get()).unwrap_or(i64::MAX),
                        resource.request.upstream.as_str(),
                        resource.state.as_str(),
                        resource.durability.as_str(),
                        encode(resource)?,
                        i64::from(*dispatched),
                        decoder.map(|binding| binding.get().as_bytes().to_vec()),
                        i64::try_from(resource.recorded_at.get()).unwrap_or(i64::MAX),
                    ],
                )
                .map_err(|error| faults.of(error))?;
        }
        let sequence = match row {
            Some(row) => {
                transaction
                    .execute(
                        "UPDATE broker_gaps SET closed_at_ms = ?2, record = ?3 WHERE sequence = ?1",
                        params![
                            row,
                            gap.closed_at
                                .as_ref()
                                .map(|at| i64::try_from(at.get()).unwrap_or(i64::MAX)),
                            encode(gap)?,
                        ],
                    )
                    .map_err(|error| faults.of(error))?;
                row
            }
            None => {
                transaction
                    .execute(
                        "INSERT INTO broker_gaps (opened_at_ms, closed_at_ms, record)
                         VALUES (?1, ?2, ?3)",
                        params![
                            i64::try_from(gap.opened_at.get()).unwrap_or(i64::MAX),
                            gap.closed_at
                                .as_ref()
                                .map(|at| i64::try_from(at.get()).unwrap_or(i64::MAX)),
                            encode(gap)?,
                        ],
                    )
                    .map_err(|error| faults.of(error))?;
                transaction.last_insert_rowid()
            }
        };
        transaction.commit().map_err(|error| faults.of(error))?;
        Ok(sequence)
    }

    /// Reads one pending resource.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::LedgerUnavailable`] when the read fails.
    pub fn pending(&self, resource_id: PendingResourceId) -> Result<Option<PendingResource>> {
        self.connection
            .query_row(
                "SELECT record FROM broker_pending WHERE resource_id = ?1",
                params![resource_id.get().as_bytes().as_slice()],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()
            .map_err(|error| self.fault(error))?
            .map(|bytes| decode(&bytes))
            .transpose()
    }

    /// Reads every resource that is still unresolved.
    ///
    /// This is what a restarted worker reconciles from: what it may already have answered, and
    /// what nobody has answered yet.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::LedgerUnavailable`] when the read fails.
    pub fn unresolved(&self) -> Result<Vec<UnresolvedRecord>> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT record, dispatched, decoder_binding_id FROM broker_pending
                 WHERE state IN ('pending', 'claimed') ORDER BY recorded_at_ms, resource_id",
            )
            .map_err(|error| self.fault(error))?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Option<Vec<u8>>>(2)?,
                ))
            })
            .map_err(|error| self.fault(error))?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|error| self.fault(error))?;
        rows.into_iter()
            .map(|(bytes, dispatched, decoder)| {
                Ok(UnresolvedRecord {
                    resource: decode(&bytes)?,
                    dispatched: dispatched != 0,
                    decoder: match decoder.as_deref() {
                        Some(bytes) => Some(BrokerBindingId::new(uuid_from(bytes)?)),
                        None => None,
                    },
                })
            })
            .collect()
    }

    // -- the native client's own requests -----------------------------------------------------

    /// Records one request of the native client's before its bytes go.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::LedgerUnavailable`] when the write fails.
    pub fn record_client_intent(&self, intent: &ClientIntent) -> Result<()> {
        self.connection
            .execute(
                "INSERT INTO broker_client_requests
                     (intent_id, application_instance_id, connection_id, upstream_request_id,
                      method, class, declared, source_handle, outcome, recorded_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    intent.intent_id.as_bytes().as_slice(),
                    intent.application_instance_id.get().as_bytes().as_slice(),
                    i64::try_from(intent.connection.get()).unwrap_or(i64::MAX),
                    intent
                        .upstream_request_id
                        .as_ref()
                        .map(|id| id.as_str().to_owned()),
                    intent.method.as_str(),
                    intent.classification.class.as_str(),
                    i64::from(intent.classification.declared),
                    intent.source.as_str(),
                    intent.outcome.as_str(),
                    i64::try_from(intent.recorded_at.get()).unwrap_or(i64::MAX),
                ],
            )
            .map_err(|error| self.fault(error))?;
        Ok(())
    }

    /// Records what became of one recorded client request.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::LedgerUnavailable`] when the write fails or the intent is not one
    /// this ledger holds.
    pub fn settle_client_intent(
        &self,
        intent_id: Uuid,
        outcome: ClientRequestOutcome,
    ) -> Result<()> {
        let updated = self
            .connection
            .execute(
                "UPDATE broker_client_requests SET outcome = ?2 WHERE intent_id = ?1",
                params![intent_id.as_bytes().as_slice(), outcome.as_str()],
            )
            .map_err(|error| self.fault(error))?;
        if updated == 1 {
            Ok(())
        } else {
            Err(BrokerError::ledger(format!(
                "client request {intent_id} is not one this ledger recorded"
            )))
        }
    }

    /// Reads every recorded client request, oldest first.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::LedgerUnavailable`] when the read fails or a row is unreadable.
    pub fn client_intents(&self) -> Result<Vec<ClientIntent>> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT intent_id, application_instance_id, connection_id, upstream_request_id,
                        method, class, declared, source_handle, outcome, recorded_at_ms
                 FROM broker_client_requests ORDER BY recorded_at_ms, rowid",
            )
            .map_err(|error| self.fault(error))?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, i64>(9)?,
                ))
            })
            .map_err(|error| self.fault(error))?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|error| self.fault(error))?;
        rows.into_iter()
            .map(
                |(
                    intent_id,
                    instance,
                    connection,
                    upstream,
                    method,
                    class,
                    declared,
                    source,
                    outcome,
                    recorded,
                )| {
                    Ok(ClientIntent {
                        intent_id: uuid_from(&intent_id)?,
                        application_instance_id: ApplicationInstanceId::new(uuid_from(&instance)?),
                        connection: GatewayConnectionId::new(
                            u64::try_from(connection).unwrap_or_default(),
                        ),
                        upstream_request_id: upstream
                            .map(UpstreamRequestId::new)
                            .transpose()
                            .map_err(|error| {
                                BrokerError::ledger(format!("a stored identifier: {error}"))
                            })?,
                        method: UpstreamMethod::new(method).map_err(|error| {
                            BrokerError::ledger(format!("a stored method: {error}"))
                        })?,
                        classification: NativeClassification {
                            class: class_from(&class)?,
                            declared: declared != 0,
                        },
                        source: SourceEventHandle::new(source).map_err(|error| {
                            BrokerError::ledger(format!("a stored source handle: {error}"))
                        })?,
                        outcome: outcome_from(&outcome)?,
                        recorded_at: TimestampMs::new(u64::try_from(recorded).unwrap_or_default()),
                    })
                },
            )
            .collect()
    }

    // -- launch profiles ----------------------------------------------------------------------

    /// Records one resolved launch profile.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::LedgerUnavailable`] when the write fails.
    pub fn put_profile(
        &self,
        profile: &LaunchProfile,
        application_instance_id: Option<ApplicationInstanceId>,
    ) -> Result<()> {
        self.connection
            .execute(
                "INSERT INTO broker_profiles
                     (profile_id, application_instance_id, profile, resolved_at_ms)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT (profile_id) DO UPDATE SET
                     application_instance_id = excluded.application_instance_id,
                     profile = excluded.profile",
                params![
                    profile.profile_id.as_str(),
                    application_instance_id.map(|id| id.get().as_bytes().to_vec()),
                    encode(profile)?,
                    i64::try_from(profile.resolved_at.get()).unwrap_or(i64::MAX),
                ],
            )
            .map_err(|error| self.fault(error))?;
        Ok(())
    }

    /// Reads every recorded launch profile, oldest first.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::LedgerUnavailable`] when the read fails.
    pub fn profiles(&self) -> Result<Vec<LaunchProfile>> {
        let mut statement = self
            .connection
            .prepare("SELECT profile FROM broker_profiles ORDER BY resolved_at_ms, profile_id")
            .map_err(|error| self.fault(error))?;
        let rows = statement
            .query_map([], |row| row.get::<_, Vec<u8>>(0))
            .map_err(|error| self.fault(error))?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|error| self.fault(error))?;
        rows.iter().map(|bytes| decode(bytes)).collect()
    }

    // -- evidence gaps ------------------------------------------------------------------------

    /// Commits a gap that has closed.
    ///
    /// What is committed is the gap itself: when it opened, why, what passed through it and how
    /// many claimed identifiers were carried across. The operations inside it are never replayed
    /// into durable history.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::LedgerUnavailable`] when the write fails.
    pub fn commit_gap(&self, row: i64, gap: &EvidenceGap) -> Result<()> {
        self.connection
            .execute(
                "UPDATE broker_gaps SET closed_at_ms = ?2, record = ?3 WHERE sequence = ?1",
                params![
                    row,
                    gap.closed_at
                        .as_ref()
                        .map(|at| i64::try_from(at.get()).unwrap_or(i64::MAX)),
                    encode(gap)?,
                ],
            )
            .map_err(|error| self.fault(error))?;
        Ok(())
    }

    /// Marks one gap's recovery as finished, because its upstreams have been reconciled.
    ///
    /// Committing a gap and finishing its recovery are two facts, and they are recorded
    /// separately because a crash between them must leave the fence in place: a resource this
    /// host may already have answered is not claimable again until an upstream has said what it
    /// still holds.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::LedgerUnavailable`] when the write fails.
    pub fn finish_recovery(&self, row: i64) -> Result<()> {
        self.connection
            .execute(
                "UPDATE broker_gaps SET reconciled = 1 WHERE sequence = ?1",
                params![row],
            )
            .map_err(|error| self.fault(error))?;
        Ok(())
    }

    /// Returns the gap whose recovery has not finished, when there is one.
    ///
    /// A restarted worker reads this and comes back fenced rather than normal, because what ends
    /// a recovery is the upstream, and the upstream has not spoken to this process yet.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::LedgerUnavailable`] when the read fails.
    pub fn unfinished_recovery(&self) -> Result<Option<(i64, EvidenceGap)>> {
        self.connection
            .query_row(
                "SELECT sequence, record FROM broker_gaps
                 WHERE reconciled = 0 ORDER BY sequence DESC LIMIT 1",
                [],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .optional()
            .map_err(|error| self.fault(error))?
            .map(|(row, bytes)| Ok((row, decode(&bytes)?)))
            .transpose()
    }

    /// Returns the highest gateway connection identifier this ledger has seen.
    ///
    /// A restarted worker numbers its connections above it. Reusing one would put a new
    /// connection's identifiers in an old connection's namespace, where a response could
    /// correlate to a request this host recorded before the restart.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::LedgerUnavailable`] when the read fails.
    pub fn highest_connection(&self) -> Result<u64> {
        let highest: Option<i64> = self
            .connection
            .query_row("SELECT MAX(connection_id) FROM broker_pending", [], |row| {
                row.get(0)
            })
            .optional()
            .map_err(|error| self.fault(error))?
            .flatten();
        Ok(highest.map_or(0, |value| u64::try_from(value).unwrap_or(0)))
    }

    /// Reads every recorded gap, oldest first.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::LedgerUnavailable`] when the read fails.
    pub fn gaps(&self) -> Result<Vec<EvidenceGap>> {
        let mut statement = self
            .connection
            .prepare("SELECT record FROM broker_gaps ORDER BY sequence")
            .map_err(|error| self.fault(error))?;
        let rows = statement
            .query_map([], |row| row.get::<_, Vec<u8>>(0))
            .map_err(|error| self.fault(error))?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|error| self.fault(error))?;
        rows.iter().map(|bytes| decode(bytes)).collect()
    }

    // -- adapter checkpoints ------------------------------------------------------------------

    /// Advances and returns the generation of this broker's stream of transitions.
    ///
    /// Sequence numbers are unique inside one generation and are not comparable across two. A
    /// stretch the journal could not take is announced and not recorded, so the numbers it spent
    /// are not in the outbox, and the next process resumes the numbering above what *was*
    /// recorded — which hands the same numbers to different events. The generation is what makes
    /// that safe to read: it advances once, here, each time the broker opens, so a cursor that
    /// names an earlier generation is known to belong to another sequence domain and is replayed
    /// from the start of the stream instead of being compared with numbers it does not share.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::LedgerUnavailable`] when the read or write fails.
    pub fn advance_stream_generation(&self) -> Result<u64> {
        let current: Option<i64> = self
            .connection
            .query_row(
                "SELECT generation FROM broker_stream WHERE id = 0",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| self.fault(error))?;
        let next = current.map_or(1, |generation| generation.saturating_add(1));
        self.connection
            .execute(
                "INSERT INTO broker_stream (id, generation, advanced_at_ms)
                 VALUES (0, ?1, ?2)
                 ON CONFLICT (id) DO UPDATE SET
                     generation = excluded.generation,
                     advanced_at_ms = excluded.advanced_at_ms",
                params![
                    next,
                    i64::try_from(kr_ipc::now_ms().get()).unwrap_or(i64::MAX)
                ],
            )
            .map_err(|error| self.fault(error))?;
        Ok(u64::try_from(next).unwrap_or(1))
    }

    /// Records the last semantic cursor one adapter consumed.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::LedgerUnavailable`] when the write fails.
    pub fn put_checkpoint(
        &self,
        application_instance_id: ApplicationInstanceId,
        cursor: StreamCursor,
        now: TimestampMs,
    ) -> Result<()> {
        self.connection
            .execute(
                "INSERT INTO broker_checkpoints
                     (application_instance_id, consumed_cursor, updated_at_ms)
                 VALUES (?1, ?2, ?3)
                 ON CONFLICT (application_instance_id) DO UPDATE SET
                     consumed_cursor = MAX(consumed_cursor, excluded.consumed_cursor),
                     updated_at_ms = excluded.updated_at_ms",
                params![
                    application_instance_id.get().as_bytes().as_slice(),
                    i64::try_from(cursor.get()).unwrap_or(i64::MAX),
                    i64::try_from(now.get()).unwrap_or(i64::MAX),
                ],
            )
            .map_err(|error| self.fault(error))?;
        Ok(())
    }

    /// Reads one adapter's consumed cursor.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::LedgerUnavailable`] when the read fails.
    pub fn checkpoint(
        &self,
        application_instance_id: ApplicationInstanceId,
    ) -> Result<Option<StreamCursor>> {
        Ok(self
            .connection
            .query_row(
                "SELECT consumed_cursor FROM broker_checkpoints WHERE application_instance_id = ?1",
                params![application_instance_id.get().as_bytes().as_slice()],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .map_err(|error| self.fault(error))?
            .map(|cursor| StreamCursor::new(u64::try_from(cursor).unwrap_or(0))))
    }

    /// Returns how many pending resources this ledger holds in a given durability.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::LedgerUnavailable`] when the read fails.
    pub fn count_pending(&self, durability: Durability, state: PendingState) -> Result<u64> {
        let count: i64 = self
            .connection
            .query_row(
                "SELECT COUNT(*) FROM broker_pending WHERE durability = ?1 AND state = ?2",
                params![durability.as_str(), state.as_str()],
                |row| row.get(0),
            )
            .map_err(|error| self.fault(error))?;
        Ok(u64::try_from(count).unwrap_or(0))
    }
}

fn encode<T: serde::Serialize>(value: &T) -> Result<Vec<u8>> {
    kr_cbor::to_canonical_vec(value).map_err(BrokerError::ledger)
}

fn decode<T: serde::de::DeserializeOwned + serde::Serialize>(bytes: &[u8]) -> Result<T> {
    kr_cbor::from_canonical_slice(bytes, &kr_cbor::Limits::DEFAULT)
        .map_err(|error| BrokerError::ledger(format!("a stored record could not be read: {error}")))
}

fn uuid_from(bytes: &[u8]) -> Result<Uuid> {
    let array: [u8; 16] = bytes
        .try_into()
        .map_err(|_| BrokerError::ledger("a stored identifier is not sixteen bytes"))?;
    Ok(Uuid::from_bytes(array))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::broker::process::{BrokerTransport, ManagedProcess, TransportHandle};
    use crate::broker::{Broker, Credential, MAX_REPLAY_BYTES, MAX_REPLAY_EVENTS};
    use kr_protocol::broker::{
        BrokerGrant, BrokerGrants, DecodedProjection, DecodingTrust, IntegrationMode,
        OfferedDecision,
    };
    use kr_protocol::gateway::{
        DeclarativeEntry, DeclarativeTable, DownstreamRequestId, NativeClassification,
        NativeFraming, NativeMethodClass, PendingKind, RichMethodEntry, RichMethodTable,
        RichOperation,
    };
    use kr_protocol::ids::{
        GatewayConnectionId, MethodTableVersion, PluginId, PublisherId, SessionId,
        SourceGeneration, UpstreamMethod, UpstreamRequestId,
    };
    use kr_protocol::rights::ActionRight;
    use kr_protocol::scalars::{Bytes, Digest256, Nullable, U64};

    /// A journal file of this test's own, on the internal disk.
    fn ledger_path() -> std::path::PathBuf {
        let directory = std::env::temp_dir().join(format!("kr-broker-{}", kr_ipc::new_uuid()));
        std::fs::create_dir_all(&directory).expect("the directory is created");
        directory.join("session.sqlite")
    }

    fn instance() -> ApplicationInstanceId {
        ApplicationInstanceId::new(Uuid::from_bytes([2; 16]))
    }

    fn binding() -> BrokerBindingId {
        BrokerBindingId::new(Uuid::from_bytes([9; 16]))
    }

    fn method() -> UpstreamMethod {
        UpstreamMethod::new("session/request_permission").expect("valid")
    }

    fn handle(name: &str) -> SourceEventHandle {
        SourceEventHandle::new(name).expect("valid")
    }

    fn test_declarative_table() -> DeclarativeTable {
        let mut table = DeclarativeTable {
            plugin_id: PluginId::new("kalareach.codex").expect("valid"),
            publisher_id: PublisherId::new("kalareach").expect("valid"),
            table_version: MethodTableVersion::new(1),
            upstream_protocol_version: "1".to_owned(),
            digest: Digest256::from_bytes([1; 32]),
            framing: NativeFraming::JsonLines,
            request_id_field: "id".to_owned(),
            response_id_field: "id".to_owned(),
            method_field: "method".to_owned(),
            params_field: "params".to_owned(),
            result_field: "result".to_owned(),
            error_field: "error".to_owned(),
            entries: vec![DeclarativeEntry {
                method: UpstreamMethod::new("session/request_permission").expect("valid"),
                class: NativeMethodClass::Mutation,
                expects_response: true,
                approval_option_field: Nullable::some("behavior".to_owned()),
                reverse: Nullable::null(),
            }],
        };
        table.digest = table.canonical_digest().expect("encodable");
        table
    }

    fn test_rich_table() -> RichMethodTable {
        RichMethodTable {
            table_version: MethodTableVersion::new(1),
            upstream_protocol_version: "1".to_owned(),
            entries: vec![RichMethodEntry {
                method: UpstreamMethod::new("session/answer").expect("valid"),
                class: NativeMethodClass::Mutation,
                required_right: ActionRight::AgentApprovalRespond,
                operation: Nullable::some(RichOperation::ApprovalRespond),
                provenance: kr_protocol::broker::ActionProvenance::UpstreamTypedRpc,
            }],
        }
    }

    fn test_managed_process() -> ManagedProcess {
        let running = kr_ipc::identity::current_process_start_identity().expect("process");
        ManagedProcess::new(
            instance(),
            running.clone(),
            TransportHandle {
                transport: BrokerTransport::PrivateSocket,
                application_instance_id: instance(),
                executable_digest: Digest256::from_bytes([3; 32]),
                process: running,
            },
            Credential::from_bytes([9; 32]),
            false,
            TimestampMs::new(1),
        )
    }

    fn trust() -> DecodingTrust {
        DecodingTrust {
            plugin_id: PluginId::new("kalareach.codex").expect("valid"),
            publisher_id: PublisherId::new("kalareach").expect("valid"),
            package_digest: Digest256::from_bytes([5; 32]),
            methods: [method()].into_iter().collect(),
            schema_versions: ["kr-approval/1".to_owned()].into_iter().collect(),
            max_decisions: U64::new(4),
            may_encode_response: true,
            granted_at: TimestampMs::new(1),
        }
    }

    fn projection() -> DecodedProjection {
        DecodedProjection {
            schema_version: "kr-approval/1".to_owned(),
            summary: "the agent wants to write a file".to_owned(),
            decisions: vec![
                OfferedDecision {
                    option_id: "allow".to_owned(),
                    label: "Allow".to_owned(),
                },
                OfferedDecision {
                    option_id: "deny".to_owned(),
                    label: "Deny".to_owned(),
                },
            ],
        }
    }

    fn entry(generation: u64) -> DecoderLedgerEntry {
        DecoderLedgerEntry {
            binding_id: binding(),
            plugin_id: PluginId::new("kalareach.codex").expect("valid"),
            publisher_id: PublisherId::new("kalareach").expect("valid"),
            package_digest: Digest256::from_bytes([5; 32]),
            method: method(),
            upstream_request_id: UpstreamRequestId::new("11").expect("valid"),
            source_generation: SourceGeneration::new(generation),
            source_digest: Digest256::from_bytes([6; 32]),
            source_bytes: Bytes::from(b"{\"id\":11}".to_vec()),
            projection: projection(),
            deadline_ms: Nullable::null(),
            decoded_at: TimestampMs::new(12),
        }
    }

    fn resource(byte: u8, request: &str, state: PendingState) -> PendingResource {
        PendingResource {
            resource_id: PendingResourceId::new(Uuid::from_bytes([byte; 16])),
            application_instance_id: instance(),
            request: DownstreamRequestId::new(
                GatewayConnectionId::new(1),
                UpstreamRequestId::new(request).expect("valid"),
            ),
            kind: PendingKind::Approval,
            method: method(),
            classification: NativeClassification::declared(NativeMethodClass::Mutation),
            source_generation: SourceGeneration::new(1),
            state,
            durability: Durability::Durable,
            deadline_ms: Nullable::null(),
            recorded_at: TimestampMs::new(10),
            interpretation_verified: true,
        }
    }

    #[test]
    fn a_binding_keeps_its_grants_and_its_trust_across_a_reopen() {
        let file = ledger_path();
        let record = BindingRecord {
            binding_id: binding(),
            application_instance_id: instance(),
            grants: BrokerGrants::granted([
                BrokerGrant::Observation,
                BrokerGrant::ApprovalInterpreter,
            ]),
            trust: Some(trust()),
            bound_at: TimestampMs::new(5),
        };
        {
            let ledger =
                Ledger::open(Some(&file), JournalHealth::shared()).expect("the ledger opens");
            ledger.put_binding(&record).expect("the binding is written");
        }
        let reopened =
            Ledger::open(Some(&file), JournalHealth::shared()).expect("the ledger reopens");
        let read = reopened
            .binding(record.binding_id)
            .expect("the read succeeds")
            .expect("the binding is still there");
        assert_eq!(read, record);
        assert!(read.grants.holds(BrokerGrant::ApprovalInterpreter));
        assert!(!read.grants.holds(BrokerGrant::UpstreamAction));
    }

    #[test]
    fn a_failure_part_way_through_admission_leaves_the_source_unconsumed() {
        let mut ledger = Ledger::open(None, JournalHealth::shared()).expect("the ledger opens");
        let recorded = resource(7, "11", PendingState::Pending);
        ledger
            .record_opaque(&recorded, &event(90, &recorded))
            .expect("the opaque request is recorded before it is forwarded");

        // An interpretation of a request this ledger does not hold. The source consumption is the
        // first statement of the transaction and succeeds; the update that follows finds no row,
        // and the whole transaction goes back.
        let absent = resource(8, "12", PendingState::Pending);
        let failed = ledger.admit_resource(
            &handle("src-1"),
            binding(),
            &entry(1),
            &absent,
            TimestampMs::new(12),
            &event(97, &absent),
        );
        assert!(failed.is_err());
        assert!(
            ledger
                .decoding(absent.resource_id)
                .expect("the read succeeds")
                .is_none(),
            "the decoder entry written before the failure went back"
        );

        // The source was not consumed, so the same event still interprets the request that is
        // really there.
        ledger
            .admit_resource(
                &handle("src-1"),
                binding(),
                &entry(1),
                &recorded,
                TimestampMs::new(13),
                &event(94, &recorded),
            )
            .expect("the retry succeeds because the transaction went back whole");
        assert!(
            ledger
                .decoding(recorded.resource_id)
                .expect("the read succeeds")
                .is_some()
        );
    }

    /// An event the outbox refuses takes its transition back with it.
    ///
    /// Section 24 commits the change and the event that announces it in one transaction, so the
    /// failure of either is the failure of both. A transition whose event cannot be written leaves
    /// the resource as it was, and the broker's parent map retains the event it would have
    /// followed, so the next event about that resource names the same parent it would have named
    /// before without the caller supplying it.
    /// A transition whose event the store will not take goes back whole in the ledger, and the
    /// failure raises the fence rather than losing what happened.
    ///
    /// The state change and its event are one transaction, so the ledger holds neither of them.
    /// What happened is still what happened: the upstream withdrew its request, so the broker
    /// keeps that in memory as a transition of the gap, behind the fence the failure raised, and
    /// the recovery that commits the gap commits it once the journal has written its own.
    #[test]
    fn a_transition_whose_event_cannot_be_written_goes_back_whole() {
        let path = ledger_path();
        let journal = crate::journal::Journal::open(path.with_extension("journal"))
            .expect("the receipt journal opens");
        let broker = Broker::open(
            Some(&path),
            SessionId::new(Uuid::from_bytes([1; 16])),
            std::sync::Arc::clone(journal.health()),
        )
        .expect("the broker opens");
        broker
            .register_instance(
                instance(),
                IntegrationMode::Gateway,
                None,
                Some(test_managed_process()),
            )
            .expect("instance registered");
        broker
            .pin_table(instance(), test_declarative_table(), test_rich_table())
            .expect("table pinned");
        let connection = broker
            .open_native_connection(
                instance(),
                &[9; 32],
                &kr_ipc::identity::current_process_start_identity().expect("process"),
                &PluginId::new("kalareach.codex").expect("valid"),
                "1",
            )
            .expect("connection opened");

        // The first request is admitted and recorded as sequence 1.
        let (forwarded, recorded) = broker
            .forward_native(
                connection,
                br#"{"id":71,"method":"session/request_permission","params":{}}"#,
                TimestampMs::new(10),
            )
            .expect("the request is forwarded");
        assert!(forwarded.request.is_some());
        let resource_id = recorded.expect("it expects a response").resource_id;
        assert_eq!(outbox_of(&broker).len(), 1);

        // The store refuses the next event, inside the transaction that would record the change.
        let injector = rusqlite::Connection::open(&path).expect("injector connection opens");
        injector
            .execute(
                "CREATE TRIGGER fail_seq_2 BEFORE INSERT ON broker_events WHEN new.sequence = 2 \
                 BEGIN SELECT RAISE(ABORT, 'injected failure'); END;",
                [],
            )
            .expect("trigger is installed");

        // The upstream withdraws its request. The ledger takes neither the change nor its event.
        let withdrawn = broker
            .upstream_response(
                connection,
                br#"{"id":71,"result":{"outcome":"deny"}}"#,
                TimestampMs::new(11),
            )
            .expect("what the upstream did is kept")
            .expect("it resolved a recorded request");
        assert_eq!(outbox_of(&broker).len(), 1, "no event was recorded for it");
        assert_eq!(
            broker
                .recorded(resource_id)
                .expect("the ledger reads")
                .expect("the row is there")
                .state,
            PendingState::Pending,
            "and the row went back whole"
        );
        // In memory it is what happened, marked as living through a gap, behind the fence the
        // failure raised in the same condition the receipt path reads.
        assert_eq!(withdrawn.state, PendingState::Cancelled);
        assert_eq!(withdrawn.durability, Durability::Volatile);
        assert_eq!(
            broker.mode(),
            kr_protocol::gateway::GatewayMode::NativeOnlyVolatile
        );
        assert!(!journal.health().is_healthy());

        // The store recovers: the journal writes its gap, the broker commits its own and what
        // lived in it, and with nothing left owed the recovery finishes.
        injector
            .execute("DROP TRIGGER fail_seq_2", [])
            .expect("trigger is removed");
        let mut journal = journal;
        journal
            .recover(TimestampMs::new(12))
            .expect("the journal writes its gap")
            .expect("a fault was open");
        broker
            .recover(TimestampMs::new(12))
            .expect("the broker commits its gap");
        assert!(
            broker.reconcile_connected(TimestampMs::new(13)).is_some(),
            "nothing unresolved was owed a reconciliation"
        );
        assert_eq!(broker.mode(), kr_protocol::gateway::GatewayMode::Normal);
        assert_eq!(
            broker
                .recorded(resource_id)
                .expect("the ledger reads")
                .expect("the row is there")
                .state,
            PendingState::Cancelled,
            "the gap committed what happened inside it"
        );

        drop(broker);
        drop(journal);
        let _ = std::fs::remove_dir_all(path.parent().expect("parent dir"));
    }

    /// Everything the outbox holds, read the way a recovery reads it.
    fn outbox_of(broker: &crate::broker::Broker) -> Vec<TransitionEvent> {
        let mut cursor = broker.stream_start();
        let mut recorded = Vec::new();
        loop {
            let replay = broker.replay_after(cursor).expect("the outbox reads");
            recorded.extend(replay.events);
            cursor = replay.cursor;
            if !replay.more {
                return recorded;
            }
        }
    }

    /// One transition event, as a settle writes beside the change it records.
    fn event(sequence: u64, resource: &PendingResource) -> TransitionEvent {
        TransitionEvent {
            sequence,
            event_id: Uuid::from_bytes([u8::try_from(sequence % 251).unwrap_or(0); 16]),
            application_instance_id: resource.application_instance_id,
            resource_id: resource.resource_id,
            binding_revision: kr_protocol::ids::AgentBindingRevision::new(1),
            state: resource.state,
            classification: resource.classification,
            content: content_class(resource),
            durability: resource.durability,
            cause: TransitionCause::Recorded,
            actor_id: None,
            causal_root: resource.request.to_string(),
            parent_sequence: None,
            recorded_at: resource.recorded_at,
        }
    }

    #[test]
    fn a_settle_built_from_a_stale_copy_is_refused() {
        let mut ledger = Ledger::open(None, JournalHealth::shared()).expect("the ledger opens");
        let pending = resource(7, "11", PendingState::Pending);
        ledger
            .record_opaque(&pending, &event(91, &pending))
            .expect("recorded");
        ledger
            .admit_resource(
                &handle("src-1"),
                binding(),
                &entry(1),
                &pending,
                TimestampMs::new(11),
                &event(95, &pending),
            )
            .expect("admitted");
        let claimed = resource(7, "11", PendingState::Claimed);
        ledger
            .settle_pending(
                &claimed,
                PendingState::Pending,
                false,
                TimestampMs::new(12),
                &event(1, &claimed),
            )
            .expect("the claim is written");
        let resolved = resource(7, "11", PendingState::Resolved);
        ledger
            .settle_pending(
                &resolved,
                PendingState::Claimed,
                true,
                TimestampMs::new(13),
                &event(2, &resolved),
            )
            .expect("the resolution is written");
        // A writer holding the older copy tries to put it back. The row has moved on, and the
        // write is refused rather than reversing a completed transition.
        let stale = ledger.settle_pending(
            &claimed,
            PendingState::Pending,
            false,
            TimestampMs::new(14),
            &event(3, &claimed),
        );
        assert!(stale.is_err());
        assert_eq!(
            ledger
                .events_after(0, MAX_REPLAY_EVENTS, MAX_REPLAY_BYTES)
                .expect("the outbox reads")
                .events
                .len(),
            4,
            "the record, the interpretation, the claim and the resolution, and nothing for the \
             refused settle"
        );
        assert_eq!(
            ledger
                .pending(pending.resource_id)
                .expect("the read succeeds")
                .expect("the record is there")
                .state,
            PendingState::Resolved
        );
    }

    #[test]
    fn the_dispatch_marker_survives_a_restart_and_is_what_recovery_reads() {
        let file = ledger_path();
        let claimed = resource(7, "11", PendingState::Claimed);
        {
            let mut ledger =
                Ledger::open(Some(&file), JournalHealth::shared()).expect("the ledger opens");
            let opaque = resource(7, "11", PendingState::Pending);
            ledger
                .record_opaque(&opaque, &event(92, &opaque))
                .expect("recorded");
            ledger
                .admit_resource(
                    &handle("src-1"),
                    binding(),
                    &entry(1),
                    &opaque,
                    TimestampMs::new(11),
                    &event(96, &opaque),
                )
                .expect("admitted");
            ledger
                .settle_pending(
                    &claimed,
                    PendingState::Pending,
                    false,
                    TimestampMs::new(12),
                    &event(1, &claimed),
                )
                .expect("claimed");
            let unresolved = ledger.unresolved().expect("the read succeeds");
            assert_eq!(unresolved.len(), 1);
            assert!(
                !unresolved[0].dispatched,
                "a claim on its own is not an answer that went"
            );
            ledger
                .mark_dispatched(&claimed, &event(93, &claimed))
                .expect("the marker is committed");
        }
        let reopened =
            Ledger::open(Some(&file), JournalHealth::shared()).expect("the ledger reopens");
        let unresolved = reopened.unresolved().expect("the read succeeds");
        assert_eq!(unresolved.len(), 1);
        assert!(unresolved[0].dispatched);
        assert_eq!(unresolved[0].decoder, Some(binding()));
        assert_eq!(unresolved[0].resource.state, PendingState::Claimed);
    }

    #[test]
    fn a_decoder_entry_outlives_the_binding_that_wrote_it() {
        let mut ledger = Ledger::open(None, JournalHealth::shared()).expect("the ledger opens");
        let pending = resource(7, "11", PendingState::Pending);
        ledger
            .record_opaque(&pending, &event(91, &pending))
            .expect("recorded");
        ledger
            .admit_resource(
                &handle("src-1"),
                binding(),
                &entry(1),
                &pending,
                TimestampMs::new(11),
                &event(95, &pending),
            )
            .expect("admitted");
        ledger
            .put_binding(&BindingRecord {
                binding_id: binding(),
                application_instance_id: instance(),
                grants: BrokerGrants::granted([BrokerGrant::ApprovalInterpreter]),
                trust: Some(trust()),
                bound_at: TimestampMs::new(5),
            })
            .expect("the binding is written");
        ledger.remove_binding(binding()).expect("the binding goes");
        assert_eq!(
            ledger
                .decoding(pending.resource_id)
                .expect("the read succeeds")
                .expect("the entry is still there"),
            entry(1)
        );
    }

    /// A gap that the fault itself stopped being written still has to record that its recovery
    /// finished. Otherwise every later restart comes back fenced over a recovery that ended.
    #[test]
    fn a_gap_first_written_during_recovery_can_still_be_finished() {
        let mut ledger = Ledger::open(None, JournalHealth::shared()).expect("the ledger opens");
        let mut gap = EvidenceGap::open("the journal faulted", TimestampMs::new(1), 0);
        gap.closed_at = Nullable::some(TimestampMs::new(2));
        let row = ledger
            .commit_recovery(&[], &gap, None)
            .expect("the gap is committed");
        assert!(
            ledger
                .unfinished_recovery()
                .expect("the read succeeds")
                .is_some(),
            "a committed gap is unfinished until its upstreams are reconciled"
        );
        ledger.finish_recovery(row).expect("the recovery finishes");
        assert!(
            ledger
                .unfinished_recovery()
                .expect("the read succeeds")
                .is_none(),
            "the row the commit returned is the row the completion marks"
        );
    }

    #[test]
    fn a_checkpoint_never_moves_backwards() {
        let ledger = Ledger::open(None, JournalHealth::shared()).expect("the ledger opens");
        ledger
            .put_checkpoint(instance(), StreamCursor::new(40), TimestampMs::new(1))
            .expect("the checkpoint is written");
        ledger
            .put_checkpoint(instance(), StreamCursor::new(20), TimestampMs::new(2))
            .expect("the older checkpoint is written");
        assert_eq!(
            ledger.checkpoint(instance()).expect("the read succeeds"),
            Some(StreamCursor::new(40))
        );
    }
}
