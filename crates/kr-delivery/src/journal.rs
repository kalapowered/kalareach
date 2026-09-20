//! The environment delivery journal.
//!
//! Section 24 names this store and what it is keyed by: *environment delivery journal, keyed by
//! underlying event, destination and attempt*, with *retry only under the delivery uncertainty
//! rules* and *queued content respecting privacy and revocation generations*. Those three
//! sentences are the schema.
//!
//! # The event comes first, and the foreign key is the proof
//!
//! Section 16 says the host writes the underlying event first and then sends a notification
//! produced from it. This store makes that the only thing it can do. A notification row names an
//! event row, the reference is a foreign key, and foreign keys are enforced on every connection
//! this module opens: a notification for an event nothing has taken is refused by SQLite before
//! any of it is written.
//!
//! Taking an event and producing a notification from it are **two** transactions, deliberately.
//! A host that stops between them has the event and no notification, which is the direction
//! section 16 asks for; one transaction would make the two simultaneous and there would be
//! nothing left to prove. Nothing here compares a timestamp to decide which came first: a clock
//! that went backwards would then reorder them, and this ordering is not the kind that may depend
//! on a clock.
//!
//! The event row carries the **notice** it was taken with, and a flag saying whether anything has
//! been produced from it yet. That is what makes the second transaction recoverable rather than
//! lost: a host that stops between the two comes back, finds the event unproduced, and produces
//! from the notice it committed. Without the notice the cursor would have moved past an event
//! nothing could rebuild.
//!
//! # One transaction per state transition
//!
//! [`DeliveryJournal::record_attempt`] writes the notification's new state, the attempt row that
//! produced it and the outbox row that follows from it in one immediate transaction, and
//! [`DeliveryJournal::produce`] writes every notification an event produced, its outbox rows, the
//! destination's spent allowance and the event's own completion in another. Splitting either would
//! let a crash leave an attempt with no state, a state with no outbox row, or an allowance spent
//! on a notification nothing admitted.
//!
//! # What is never written here
//!
//! A delivery credential. The gateway returns one once, the host presents it as a bearer token,
//! and it stays in memory behind [`crate::push::SenderCredentials`]. What this journal holds is
//! the destination's `sender_record_id`, which names the authorisation and proves nothing: a
//! secret in this file would be a secret in every backup of it and in everything that reads a
//! destination.

use std::collections::BTreeMap;
use std::path::Path;

use rusqlite::{Connection, OptionalExtension, params};

use kr_protocol::ids::{GrantId, InstallationId, NotificationId, PushSenderRecordId, SessionId};
use kr_protocol::push::{PushSuppression, PushSuppressionReason};
use kr_protocol::scalars::{NotificationPreviewKey, TimestampMs};

use crate::destination::{
    DeliveryRule, Destination, DestinationId, DestinationKind, DestinationRecord,
    ExternalDestination, Idempotency, PreviewKeys, PushDestination, RetiredPreviewKey,
};
use crate::error::{DeliveryError, Result};

/// The schema this build writes and reads.
const SCHEMA_VERSION: i64 = 1;

/// Every table a working journal has.
///
/// A store that has lost one of them is refused rather than recreated: an empty outbox and an
/// empty privacy row say the opposite of what is true about a host that had work queued or a fence
/// up.
const REQUIRED_TABLES: [&str; 11] = [
    "delivery_schema",
    "delivery_consumers",
    "delivery_events",
    "delivery_destinations",
    "delivery_notifications",
    "delivery_attempts",
    "delivery_outbox",
    "delivery_objects",
    "delivery_budget",
    "delivery_secret",
    "delivery_privacy",
];

/// How long a write waits for another connection to this file before it gives up.
const BUSY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// The consumer prefix attention announcements are taken under.
pub const ATTENTION_CONSUMER: &str = "kr-delivery/attention";

/// The consumer prefix a worker outbox is taken under.
///
/// It is what [`kr_worker::journal::Journal::note_outbox_consumed`] is registered with, because a
/// consumer that has not registered has no claim on what collection removes.
pub const OUTBOX_CONSUMER: &str = "kr-delivery/outbox";

/// Which retained source one taken event came from.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum EventSource {
    /// An attention announcement, taken through `Attention::take_announcements`.
    Attention,
    /// A worker outbox record, read through `Journal::outbox_after`.
    WorkerOutbox,
}

impl EventSource {
    /// Every source, in declaration order.
    pub const ALL: [Self; 2] = [Self::Attention, Self::WorkerOutbox];

    /// The stable name this source is stored under.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Attention => "attention",
            Self::WorkerOutbox => "worker_outbox",
        }
    }

    /// The consumer one store of this source is taken under.
    ///
    /// The scope is the store, not the source. Each session has its own journal and its own
    /// attention store, and a cursor is a position in one of them: a cursor of 100 in one worker's
    /// outbox says nothing about another worker's, whose records may start at one. One consumer
    /// name for every store of a kind would hand a new session's records to a cursor that had
    /// already passed them.
    #[must_use]
    pub fn consumer(self, scope: &str) -> String {
        let prefix = match self {
            Self::Attention => ATTENTION_CONSUMER,
            Self::WorkerOutbox => OUTBOX_CONSUMER,
        };
        format!("{prefix}/{scope}")
    }

    /// Reads a stored name back.
    #[must_use]
    pub fn from_stored(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|source| source.as_str() == value)
    }
}

/// The identity of one underlying event, in its own source's vocabulary.
///
/// It is the de-duplication record's key, so it has to be the identity the source will present
/// again if this host dies before it acknowledges the page. For the worker outbox that is the
/// event's immutable identifier. For attention it is the session, the item key and the
/// announcement's own never-reused number, which is exactly what T-037 says a consumer keys by.
#[derive(
    Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub struct EventKey {
    source: EventSource,
    identity: String,
}

impl EventKey {
    /// Names one worker outbox event.
    #[must_use]
    pub fn outbox(event_id: &kr_protocol::scalars::Uuid) -> Self {
        Self {
            source: EventSource::WorkerOutbox,
            identity: hex(event_id.as_bytes()),
        }
    }

    /// Names one attention announcement, by session, item and announcement number.
    #[must_use]
    pub fn announcement(session: Option<SessionId>, item: &str, number: u64) -> Self {
        let session = session.map_or_else(|| "-".to_owned(), |id| id.to_string());
        Self {
            source: EventSource::Attention,
            identity: format!("{session}/{number}/{item}"),
        }
    }

    /// Which source this event came from.
    #[must_use]
    pub const fn source(&self) -> EventSource {
        self.source
    }

    /// The stored form: the source and the identity, which is unique across both sources.
    #[must_use]
    pub fn stored(&self) -> String {
        format!("{}:{}", self.source.as_str(), self.identity)
    }
}

impl std::fmt::Display for EventKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.stored())
    }
}

/// One underlying event this journal has taken responsibility for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TakenEvent {
    /// Its identity in its own source.
    pub key: EventKey,
    /// The source's own cursor at the record.
    pub source_cursor: u64,
    /// The session it belongs to, when it belongs to one.
    pub session_id: Option<SessionId>,
    /// When the host recorded the underlying event, in UTC milliseconds.
    ///
    /// It is the source's figure, kept so that a person can see when the thing happened. Nothing
    /// in this store decides an ordering from it.
    pub recorded_at_ms: TimestampMs,
    /// What this journal has to know to produce from the event, encoded by its caller.
    ///
    /// It is committed with the cursor, so a host that stops before producing comes back to a
    /// notice it can still produce from. Without it the cursor would have moved past an event this
    /// journal could no longer rebuild, and the source would not offer it again.
    pub notice: Vec<u8>,
}

/// One event this journal took and has not produced anything from yet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingEvent {
    /// The event.
    pub key: EventKey,
    /// The notice it was taken with.
    pub notice: Vec<u8>,
    /// When the host recorded the underlying event, in UTC milliseconds.
    pub recorded_at_ms: TimestampMs,
}

/// Where one consumer has got to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsumerCursor {
    /// The consumer.
    pub consumer: String,
    /// The last cursor it took.
    pub cursor: u64,
    /// How many records it has applied.
    pub applied: u64,
    /// When it registered, in UTC milliseconds.
    pub registered_at_ms: TimestampMs,
}

/// Where one notification or external message stands.
///
/// `Accepted` means the provider or the destination took it for delivery. It does not mean
/// displayed, read or executed, and nothing in this crate treats it as though it did.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DeliveryState {
    /// Admitted to the outbox and not yet attempted.
    Admitted,
    /// An attempt is on the wire.
    InFlight,
    /// A transient failure; waiting for the next attempt.
    Retrying,
    /// The provider or the destination accepted it for delivery.
    Accepted,
    /// It collapsed into an attention update.
    Collapsed,
    /// This identifier was already handled; the earlier outcome stands.
    Duplicate,
    /// The destination token was rejected and disabled.
    TokenDisabled,
    /// The destination refused the message itself, and a retry cannot change that.
    Refused,
    /// The authorisation ended before the destination accepted it.
    Revoked,
    /// This host stopped trying before the expiry.
    Abandoned,
    /// The expiry passed first.
    Expired,
    /// Nobody knows whether it arrived.
    ///
    /// Section 23: `OUTCOME_UNKNOWN` is not retryable, so nothing picks this up automatically. A
    /// reconciliation pass asks the gateway what became of it, which is a read of a decision
    /// already recorded rather than a second send.
    OutcomeUnknown,
    /// It was delivered, and the destination cannot say whether it was a duplicate.
    ///
    /// Section 25's other half: a destination with no idempotent delivery identifier is not
    /// retried blindly, and the uncertainty is marked rather than resolved by guessing.
    DuplicateUncertain,
    /// Privacy mode took it back before it was dispatched.
    Cancelled,
}

impl DeliveryState {
    /// Every state, in declaration order.
    pub const ALL: [Self; 14] = [
        Self::Admitted,
        Self::InFlight,
        Self::Retrying,
        Self::Accepted,
        Self::Collapsed,
        Self::Duplicate,
        Self::TokenDisabled,
        Self::Refused,
        Self::Revoked,
        Self::Abandoned,
        Self::Expired,
        Self::OutcomeUnknown,
        Self::DuplicateUncertain,
        Self::Cancelled,
    ];

    /// The stable name this state is stored and reported under.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Admitted => "admitted",
            Self::InFlight => "in_flight",
            Self::Retrying => "retrying",
            Self::Accepted => "accepted",
            Self::Collapsed => "collapsed",
            Self::Duplicate => "duplicate",
            Self::TokenDisabled => "token_disabled",
            Self::Refused => "refused",
            Self::Revoked => "revoked",
            Self::Abandoned => "abandoned",
            Self::Expired => "expired",
            Self::OutcomeUnknown => "outcome_unknown",
            Self::DuplicateUncertain => "duplicate_uncertain",
            Self::Cancelled => "cancelled",
        }
    }

    /// Reads a stored name back.
    #[must_use]
    pub fn from_stored(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|state| state.as_str() == value)
    }

    /// Returns true when nothing will move this state again on its own.
    #[must_use]
    pub const fn is_settled(self) -> bool {
        !matches!(self, Self::Admitted | Self::InFlight | Self::Retrying)
    }

    /// Returns true when this host still holds work it has not accounted for.
    ///
    /// An attempt on the wire and an unknown outcome both count: privacy mode's reconciliation is
    /// not complete while either is true, because neither has been settled.
    #[must_use]
    pub const fn is_outstanding(self) -> bool {
        matches!(self, Self::InFlight | Self::OutcomeUnknown)
    }

    /// Returns true when the destination or its provider took the content.
    #[must_use]
    pub const fn has_left_this_host(self) -> bool {
        matches!(
            self,
            Self::Accepted | Self::DuplicateUncertain | Self::OutcomeUnknown
        )
    }
}

impl std::fmt::Display for DeliveryState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One notification or external message as the journal holds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeliveryRecord {
    /// The notification's identity. One identifier is one notification.
    pub notification_id: NotificationId,
    /// The underlying event it was produced from.
    pub event: EventKey,
    /// Where it is going.
    pub destination_id: DestinationId,
    /// Where it stands.
    pub state: DeliveryState,
    /// The privacy generation it was admitted under.
    pub privacy_generation: u64,
    /// The exact bytes that leave this host, until privacy mode or settlement removes them.
    ///
    /// `None` is content this journal no longer holds: removed by privacy mode, or never retained
    /// because the record settled before anything needed it again.
    pub content: Option<Vec<u8>>,
    /// The measured length of the built provider payload, in bytes.
    pub payload_bytes: u64,
    /// When it stops being worth delivering, in UTC milliseconds.
    pub expires_at_ms: TimestampMs,
    /// When it was admitted, in UTC milliseconds.
    pub admitted_at_ms: TimestampMs,
    /// How many attempts have been made.
    pub attempts: u64,
    /// What the destination said was suppressed, when it said anything.
    pub suppression: Option<PushSuppression>,
    /// One line saying what the last outcome was, for a person reading the journal.
    pub detail: Option<String>,
}

/// One attempt at one delivery.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttemptRecord {
    /// The delivery.
    pub notification_id: NotificationId,
    /// Which attempt, counting from one.
    pub attempt: u64,
    /// When it started, in UTC milliseconds.
    pub started_at_ms: TimestampMs,
    /// When it settled, when it has.
    pub settled_at_ms: Option<TimestampMs>,
    /// What it settled as.
    pub outcome: Option<DeliveryState>,
    /// One line about it.
    pub detail: Option<String>,
}

/// One state transition, with everything that is committed beside it.
///
/// It is one value rather than four calls because section 24 commits them together: a state with
/// no attempt behind it, or an outbox row that outlived the state that put it there, is a store
/// that cannot be recovered from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transition {
    /// The delivery this is about.
    pub notification_id: NotificationId,
    /// Which attempt produced it.
    pub attempt: u64,
    /// The state it moves to.
    pub state: DeliveryState,
    /// When the attempt started, in UTC milliseconds.
    pub started_at_ms: TimestampMs,
    /// When it settled, when it has.
    pub settled_at_ms: Option<TimestampMs>,
    /// When the next attempt is due, when there will be one.
    ///
    /// `None` on a settled state removes the outbox row: there is nothing left to do.
    pub next_attempt_at_ms: Option<TimestampMs>,
    /// One line about what happened.
    pub detail: Option<String>,
    /// What the destination said it suppressed, when it said anything.
    pub suppression: Option<PushSuppression>,
    /// Whether the content is kept after this transition.
    ///
    /// A settled delivery keeps nothing: the record of what happened stays, the bytes do not.
    pub keep_content: bool,
}

/// One delivery the outbox says is due.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DueDelivery {
    /// The delivery.
    pub notification_id: NotificationId,
    /// Where it is going.
    pub destination_id: DestinationId,
    /// How many attempts have already been made.
    pub attempts: u64,
    /// When it expires, in UTC milliseconds.
    pub expires_at_ms: TimestampMs,
    /// The privacy generation it was admitted under.
    pub privacy_generation: u64,
    /// The bytes to send.
    pub content: Vec<u8>,
}

/// Something that had already left this host.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExportedDelivery {
    /// What kind of copy it is.
    pub kind: String,
    /// The opaque reference a person is shown.
    pub reference: String,
    /// When it left, in UTC milliseconds.
    pub left_at_ms: TimestampMs,
    /// Whether this host holds a way to ask for its removal.
    pub deletable: bool,
}

/// The environment's delivery journal.
#[derive(Debug)]
pub struct DeliveryJournal {
    connection: Connection,
}

impl DeliveryJournal {
    /// Opens the journal at `path`, creating it when it is not there.
    ///
    /// # Errors
    ///
    /// Returns [`DeliveryError::JournalUnavailable`] when the file cannot be opened or the schema
    /// cannot be created, and [`DeliveryError::JournalUnreadable`] when the file holds a schema
    /// version this build does not write.
    pub fn open(path: &Path) -> Result<Self> {
        Self::prepare(Connection::open(path)?)
    }

    /// Opens a journal that lives only as long as it is held.
    ///
    /// # Errors
    ///
    /// Returns [`DeliveryError::JournalUnavailable`] when the schema cannot be created.
    pub fn in_memory() -> Result<Self> {
        Self::prepare(Connection::open_in_memory()?)
    }

    fn prepare(connection: Connection) -> Result<Self> {
        connection.busy_timeout(BUSY_TIMEOUT)?;
        // Foreign keys are what make "the event first" a property of the store. They are off by
        // default in SQLite, so turning them on is part of opening rather than a call somebody
        // remembers to make.
        connection.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=FULL;
             PRAGMA foreign_keys=ON;",
        )?;
        // A missing `delivery_schema` table is a store nothing has created. Any other failure is
        // a store this host could not read, which is not the same thing and must not be treated
        // as a new one: creating over it would answer every later read from an empty store.
        let recorded: Option<i64> = match connection
            .query_row("SELECT version FROM delivery_schema LIMIT 1", [], |row| {
                row.get(0)
            })
            .optional()
        {
            Ok(recorded) => recorded,
            Err(error) if is_missing_table(&error) => None,
            Err(error) => return Err(error.into()),
        };
        if recorded.is_none() && has_any_delivery_table(&connection)? {
            return Err(DeliveryError::JournalUnreadable(
                "the delivery journal has tables and no schema version, so this build cannot say                  what it holds",
            ));
        }
        match recorded {
            // A store this build wrote. It is checked rather than repaired: `CREATE TABLE IF NOT
            // EXISTS` over a store that has lost a table would answer every read from an empty one,
            // and an empty outbox and an empty privacy row say the opposite of what is true.
            Some(version) if version == SCHEMA_VERSION => {
                let journal = Self { connection };
                journal.check_schema()?;
                Ok(journal)
            }
            Some(_) => Err(DeliveryError::JournalUnreadable(
                "the delivery journal was written by another schema version",
            )),
            // A store with no version. It is created whole, in one transaction, so a store that
            // exists is a store with every table and the singleton rows in it.
            None => {
                let transaction = connection
                    .unchecked_transaction()
                    .map_err(DeliveryError::from)?;
                transaction.execute_batch(
                    "CREATE TABLE IF NOT EXISTS delivery_schema (version INTEGER NOT NULL);",
                )?;
                let present: Option<i64> = transaction
                    .query_row("SELECT version FROM delivery_schema LIMIT 1", [], |row| {
                        row.get(0)
                    })
                    .optional()?;
                if present.is_some() {
                    return Err(DeliveryError::JournalUnreadable(
                        "the delivery journal gained a schema version while it was being created",
                    ));
                }
                transaction.execute_batch(SCHEMA)?;
                transaction.execute(
                    "INSERT INTO delivery_privacy (id, generation, fenced) VALUES (0, 0, 0)",
                    [],
                )?;
                transaction.execute(
                    "INSERT INTO delivery_schema (version) VALUES (?1)",
                    params![SCHEMA_VERSION],
                )?;
                transaction.commit()?;
                let journal = Self { connection };
                journal.check_schema()?;
                Ok(journal)
            }
        }
    }

    /// Refuses a store that is missing a table or a singleton row this build depends on.
    fn check_schema(&self) -> Result<()> {
        for table in REQUIRED_TABLES {
            let found: Option<i64> = self
                .connection
                .query_row(
                    "SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = ?1",
                    params![table],
                    |row| row.get(0),
                )
                .optional()?;
            if found.is_none() {
                return Err(DeliveryError::JournalUnreadable(
                    "the delivery journal is missing a table this build depends on",
                ));
            }
        }
        let privacy: Option<i64> = self
            .connection
            .query_row("SELECT 1 FROM delivery_privacy WHERE id = 0", [], |row| {
                row.get(0)
            })
            .optional()?;
        if privacy.is_none() {
            return Err(DeliveryError::JournalUnreadable(
                "the delivery journal has no privacy row, so it cannot say whether it is fenced",
            ));
        }
        Ok(())
    }

    // ----- consumers ---------------------------------------------------------------------

    /// Registers a consumer before it relies on collection keeping anything for it.
    ///
    /// T-040's outbox contract: a consumer that has not registered has no claim on what collection
    /// removes. Registering is idempotent and never moves a cursor backwards, so a restart
    /// registers again and keeps its place.
    ///
    /// # Errors
    ///
    /// Returns [`DeliveryError::JournalUnavailable`] when the write fails.
    pub fn register_consumer(&mut self, consumer: &str, now_ms: u64) -> Result<()> {
        self.connection.execute(
            "INSERT INTO delivery_consumers (consumer, cursor, applied, registered_at_ms)
             VALUES (?1, 0, 0, ?2)
             ON CONFLICT (consumer) DO NOTHING",
            params![consumer, as_i64(now_ms)],
        )?;
        Ok(())
    }

    /// Returns whether a consumer has registered.
    ///
    /// # Errors
    ///
    /// Returns [`DeliveryError::JournalUnavailable`] when the read fails.
    pub fn is_registered(&self, consumer: &str) -> Result<bool> {
        Ok(self.consumer_cursor(consumer)?.is_some())
    }

    /// Returns where a consumer has got to, when it has registered.
    ///
    /// # Errors
    ///
    /// Returns [`DeliveryError::JournalUnavailable`] when the read fails.
    pub fn consumer_cursor(&self, consumer: &str) -> Result<Option<ConsumerCursor>> {
        let row: Option<(i64, i64, i64)> = self
            .connection
            .query_row(
                "SELECT cursor, applied, registered_at_ms FROM delivery_consumers
                 WHERE consumer = ?1",
                params![consumer],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        Ok(row.map(|(cursor, applied, registered)| ConsumerCursor {
            consumer: consumer.to_owned(),
            cursor: as_u64(cursor),
            applied: as_u64(applied),
            registered_at_ms: TimestampMs::new(as_u64(registered)),
        }))
    }

    /// Takes a page of underlying events, and records the cursor in the same transaction.
    ///
    /// This is the de-duplication record and the cursor together, which is the half of
    /// crash-safety a consumer owns: the upstream acknowledgement happens after this returns, so a
    /// host that dies in between is handed the same page again and the event keys absorb it.
    ///
    /// Returns how many events were new.
    ///
    /// # Errors
    ///
    /// Returns [`DeliveryError::NotAuthorised`] when the consumer has not registered, and
    /// [`DeliveryError::JournalUnavailable`] when the write fails.
    pub fn take_events(
        &mut self,
        consumer: &str,
        events: &[TakenEvent],
        cursor: u64,
    ) -> Result<usize> {
        if !self.is_registered(consumer)? {
            return Err(DeliveryError::NotAuthorised(format!(
                "{consumer} has not registered, so it has no claim on collection"
            )));
        }
        let transaction = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let mut taken = 0usize;
        for event in events {
            let changed = transaction.execute(
                "INSERT INTO delivery_events
                     (event_key, source, source_cursor, session_id, recorded_at_ms, taken_seq,
                      notice, produced)
                 VALUES (?1, ?2, ?3, ?4, ?5,
                         (SELECT COALESCE(MAX(taken_seq), 0) + 1 FROM delivery_events), ?6, 0)
                 ON CONFLICT (event_key) DO NOTHING",
                params![
                    event.key.stored(),
                    event.key.source().as_str(),
                    as_i64(event.source_cursor),
                    event.session_id.map(|id| id.to_string()),
                    as_i64(event.recorded_at_ms.get()),
                    event.notice.as_slice(),
                ],
            )?;
            taken += usize::from(changed > 0);
        }
        transaction.execute(
            "UPDATE delivery_consumers
                SET cursor = MAX(cursor, ?2), applied = applied + ?3
              WHERE consumer = ?1",
            params![consumer, as_i64(cursor), as_i64(taken as u64)],
        )?;
        transaction.commit()?;
        Ok(taken)
    }

    /// Returns whether this journal has taken one underlying event.
    ///
    /// # Errors
    ///
    /// Returns [`DeliveryError::JournalUnavailable`] when the read fails.
    pub fn has_event(&self, key: &EventKey) -> Result<bool> {
        let found: Option<i64> = self
            .connection
            .query_row(
                "SELECT 1 FROM delivery_events WHERE event_key = ?1",
                params![key.stored()],
                |row| row.get(0),
            )
            .optional()?;
        Ok(found.is_some())
    }

    /// Returns the events this journal has taken, oldest first.
    ///
    /// # Errors
    ///
    /// Returns [`DeliveryError::JournalUnavailable`] when the read fails, and
    /// [`DeliveryError::JournalUnreadable`] when a stored source is not one this build writes.
    pub fn events(&self) -> Result<Vec<TakenEvent>> {
        let mut statement = self.connection.prepare(
            "SELECT event_key, source, source_cursor, session_id, recorded_at_ms, notice
               FROM delivery_events ORDER BY taken_seq",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, Option<Vec<u8>>>(5)?,
            ))
        })?;
        let mut events = Vec::new();
        for row in rows {
            let (stored, source, cursor, session, recorded, notice) = row?;
            let source =
                EventSource::from_stored(&source).ok_or(DeliveryError::JournalUnreadable(
                    "a stored event source is not one this build writes",
                ))?;
            let identity = stored
                .split_once(':')
                .map(|(_, identity)| identity.to_owned())
                .ok_or(DeliveryError::JournalUnreadable(
                    "a stored event key is not one this build writes",
                ))?;
            events.push(TakenEvent {
                key: EventKey { source, identity },
                source_cursor: as_u64(cursor),
                session_id: session.as_deref().and_then(|id| id.parse().ok()),
                recorded_at_ms: TimestampMs::new(as_u64(recorded)),
                notice: notice.unwrap_or_default(),
            });
        }
        Ok(events)
    }

    // ----- destinations ------------------------------------------------------------------

    /// Writes down one configured destination and the rule that admits content to it.
    ///
    /// # Errors
    ///
    /// Returns [`DeliveryError::JournalUnavailable`] when the write fails.
    pub fn configure_destination(&mut self, record: &DestinationRecord) -> Result<()> {
        let (
            installation,
            sender_record,
            preview_key,
            preview_revision,
            previous_key,
            previous_revision,
            previous_until,
            previews_enabled,
            mailbox_key,
            endpoint,
            idempotency_field,
        ) = match &record.destination {
            Destination::Push(push) => (
                Some(push.installation_id.to_string()),
                Some(push.sender_record_id.to_string()),
                Some(push.preview_keys.current.as_bytes().to_vec()),
                Some(as_i64(push.preview_keys.revision)),
                push.preview_keys
                    .previous
                    .as_ref()
                    .map(|previous| previous.key.as_bytes().to_vec()),
                push.preview_keys
                    .previous
                    .as_ref()
                    .map(|previous| as_i64(previous.revision)),
                push.preview_keys
                    .previous
                    .as_ref()
                    .map(|previous| as_i64(previous.retired_until_ms.get())),
                i64::from(push.previews_enabled),
                push.mailbox_key.map(|key| key.as_bytes().to_vec()),
                None,
                None,
            ),
            Destination::External(external) => (
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                0,
                None,
                Some(external.endpoint.clone()),
                match &external.idempotency {
                    Idempotency::Supported { field } => Some(field.clone()),
                    Idempotency::Unsupported => None,
                },
            ),
        };
        self.connection.execute(
            "INSERT INTO delivery_destinations
                 (destination_id, kind, enabled, configured_at_ms, rule_name, grant_id,
                  installation_id, sender_record_id, preview_key, preview_revision,
                  previous_preview_key, previous_preview_revision, previous_preview_until_ms,
                  previews_enabled, mailbox_key, endpoint, idempotency_field)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)
             ON CONFLICT (destination_id) DO UPDATE SET
                 kind = excluded.kind,
                 enabled = excluded.enabled,
                 rule_name = excluded.rule_name,
                 grant_id = excluded.grant_id,
                 installation_id = excluded.installation_id,
                 sender_record_id = excluded.sender_record_id,
                 preview_key = excluded.preview_key,
                 preview_revision = excluded.preview_revision,
                 previous_preview_key = excluded.previous_preview_key,
                 previous_preview_revision = excluded.previous_preview_revision,
                 previous_preview_until_ms = excluded.previous_preview_until_ms,
                 previews_enabled = excluded.previews_enabled,
                 mailbox_key = excluded.mailbox_key,
                 endpoint = excluded.endpoint,
                 idempotency_field = excluded.idempotency_field",
            params![
                record.id.as_str(),
                record.destination.kind().as_str(),
                i64::from(record.enabled),
                as_i64(record.configured_at_ms.get()),
                record.rule.as_ref().map(|rule| rule.name.clone()),
                record
                    .rule
                    .as_ref()
                    .and_then(|rule| rule.grant_id.map(|id| id.to_string())),
                installation,
                sender_record,
                preview_key,
                preview_revision,
                previous_key,
                previous_revision,
                previous_until,
                previews_enabled,
                mailbox_key,
                endpoint,
                idempotency_field,
            ],
        )?;
        Ok(())
    }

    /// Returns one destination record.
    ///
    /// # Errors
    ///
    /// Returns [`DeliveryError::JournalUnavailable`] when the read fails, and
    /// [`DeliveryError::JournalUnreadable`] when the row cannot be decoded.
    pub fn destination(&self, id: &DestinationId) -> Result<Option<DestinationRecord>> {
        let mut statement = self
            .connection
            .prepare(&format!("{DESTINATION_COLUMNS} WHERE destination_id = ?1"))?;
        let record = statement
            .query_row(params![id.as_str()], decode_destination)
            .optional()?;
        record.transpose()
    }

    /// Returns one enabled destination record, or the refusal that names it.
    ///
    /// # Errors
    ///
    /// Returns [`DeliveryError::NoDestination`] when nothing enabled is configured under that
    /// name.
    pub fn enabled_destination(&self, id: &DestinationId) -> Result<DestinationRecord> {
        self.destination(id)?
            .filter(|record| record.enabled)
            .ok_or_else(|| DeliveryError::NoDestination(id.to_string()))
    }

    /// Returns every configured destination.
    ///
    /// # Errors
    ///
    /// Returns [`DeliveryError::JournalUnavailable`] when the read fails.
    pub fn destinations(&self) -> Result<Vec<DestinationRecord>> {
        let mut statement = self
            .connection
            .prepare(&format!("{DESTINATION_COLUMNS} ORDER BY destination_id"))?;
        let rows = statement.query_map([], decode_destination)?;
        let mut records = Vec::new();
        for row in rows {
            records.push(row??);
        }
        Ok(records)
    }

    // ----- admission and attempts --------------------------------------------------------

    /// Admits one produced notification to the outbox.
    ///
    /// The event reference is a foreign key, so an event this journal has not taken refuses the
    /// whole insert. That refusal is section 16's *the host writes the underlying event first*,
    /// enforced by the store rather than by an order somebody kept.
    ///
    /// # Errors
    ///
    /// Returns [`DeliveryError::NoUnderlyingEvent`] when the event has not been taken,
    /// [`DeliveryError::NoDestination`] when the destination is not configured, and
    /// [`DeliveryError::JournalUnavailable`] when the write fails.
    pub fn admit(&mut self, record: &DeliveryRecord) -> Result<()> {
        let transaction = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        admit_in(&transaction, record)?;
        transaction.commit()?;
        Ok(())
    }

    /// Writes every notification one event produced, its allowance and the event's completion.
    ///
    /// One transaction, because they are one fact: this event has been produced from, these are
    /// the notifications it produced, and this is what they spent. A crash before the commit
    /// leaves the event unproduced and the allowance unspent, so the recovery pass produces from
    /// it again and nothing is charged for a notification nobody admitted.
    ///
    /// It is idempotent by the event's own `produced` flag: an event this journal has already
    /// produced from writes nothing and returns `false`.
    ///
    /// # Errors
    ///
    /// Returns [`DeliveryError::Fenced`] when privacy mode has stopped this environment's outbox,
    /// [`DeliveryError::LateResult`] when a record names a generation that is not in force,
    /// [`DeliveryError::NoUnderlyingEvent`] when the event has not been taken, and
    /// [`DeliveryError::JournalUnavailable`] when the write fails.
    pub fn produce(
        &mut self,
        event: &EventKey,
        records: &[DeliveryRecord],
        spent: &[(DestinationId, StoredBudget)],
    ) -> Result<bool> {
        let transaction = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let taken: Option<i64> = transaction
            .query_row(
                "SELECT produced FROM delivery_events WHERE event_key = ?1",
                params![event.stored()],
                |row| row.get(0),
            )
            .optional()?;
        match taken {
            None => return Err(DeliveryError::NoUnderlyingEvent(event.stored())),
            Some(produced) if produced != 0 => return Ok(false),
            Some(_) => {}
        }
        for record in records {
            admit_in(&transaction, record)?;
        }
        for (destination, budget) in spent {
            record_budget_in(&transaction, destination, budget)?;
        }
        transaction.execute(
            "UPDATE delivery_events SET produced = 1 WHERE event_key = ?1",
            params![event.stored()],
        )?;
        transaction.commit()?;
        Ok(true)
    }

    /// Returns the events this journal took and has produced nothing from, oldest first.
    ///
    /// A restart finishes these before it reads a new page: the cursor has already moved past
    /// them, so nothing else will offer them again.
    ///
    /// # Errors
    ///
    /// Returns [`DeliveryError::JournalUnavailable`] when the read fails.
    pub fn pending_events(&self, limit: usize) -> Result<Vec<PendingEvent>> {
        let mut statement = self.connection.prepare(
            "SELECT event_key, source, notice, recorded_at_ms FROM delivery_events
              WHERE produced = 0 ORDER BY taken_seq LIMIT ?1",
        )?;
        let rows = statement.query_map(params![limit as i64], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<Vec<u8>>>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })?;
        let mut pending = Vec::new();
        for row in rows {
            let (stored, source, notice, recorded) = row?;
            let source =
                EventSource::from_stored(&source).ok_or(DeliveryError::JournalUnreadable(
                    "a stored event source is not one this build writes",
                ))?;
            let identity = stored
                .split_once(':')
                .map(|(_, identity)| identity.to_owned())
                .ok_or(DeliveryError::JournalUnreadable(
                    "a stored event key is not one this build writes",
                ))?;
            pending.push(PendingEvent {
                key: EventKey { source, identity },
                notice: notice.unwrap_or_default(),
                recorded_at_ms: TimestampMs::new(as_u64(recorded)),
            });
        }
        Ok(pending)
    }

    /// Drops a retired preview key whose outstanding notifications have all expired.
    ///
    /// Section 16 keeps a bounded previous preview key *only until outstanding notification
    /// expiry*, and a bound nothing enforces is not a bound. This is the enforcement, and a
    /// producer runs it on its own cadence.
    ///
    /// Returns how many destinations stopped holding one.
    ///
    /// # Errors
    ///
    /// Returns [`DeliveryError::JournalUnavailable`] when the write fails.
    pub fn forget_expired_preview_keys(&mut self, now_ms: u64) -> Result<u64> {
        let changed = self.connection.execute(
            "UPDATE delivery_destinations
                SET previous_preview_key = NULL,
                    previous_preview_revision = NULL,
                    previous_preview_until_ms = NULL
              WHERE previous_preview_until_ms IS NOT NULL
                AND previous_preview_until_ms <= ?1",
            params![as_i64(now_ms)],
        )?;
        Ok(changed as u64)
    }

    /// Records one state transition, its attempt row and its outbox row together.
    ///
    /// # Errors
    ///
    /// Returns [`DeliveryError::JournalUnavailable`] when the write fails.
    pub fn record_attempt(&mut self, transition: &Transition) -> Result<()> {
        let identifier = transition.notification_id.to_string();
        let transaction = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        transaction.execute(
            "INSERT INTO delivery_attempts
                 (notification_id, attempt, started_at_ms, settled_at_ms, outcome, detail)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT (notification_id, attempt) DO UPDATE SET
                 settled_at_ms = excluded.settled_at_ms,
                 outcome = excluded.outcome,
                 detail = excluded.detail",
            params![
                identifier,
                as_i64(transition.attempt),
                as_i64(transition.started_at_ms.get()),
                transition.settled_at_ms.map(|at| as_i64(at.get())),
                transition.settled_at_ms.map(|_| transition.state.as_str()),
                transition.detail.as_deref(),
            ],
        )?;
        let (reason, into, count, next) = suppression_columns(transition.suppression.as_ref());
        transaction.execute(
            "UPDATE delivery_notifications
                SET state = ?2,
                    attempts = MAX(attempts, ?3),
                    detail = COALESCE(?4, detail),
                    content = CASE WHEN ?5 = 1 THEN content ELSE NULL END,
                    suppression_reason = COALESCE(?6, suppression_reason),
                    suppression_into = COALESCE(?7, suppression_into),
                    suppression_count = COALESCE(?8, suppression_count),
                    suppression_next_ms = COALESCE(?9, suppression_next_ms)
              WHERE notification_id = ?1",
            params![
                identifier,
                transition.state.as_str(),
                as_i64(transition.attempt),
                transition.detail.as_deref(),
                i64::from(transition.keep_content),
                reason,
                into,
                count,
                next,
            ],
        )?;
        match transition.next_attempt_at_ms {
            Some(due) if !transition.state.is_settled() => {
                transaction.execute(
                    "INSERT INTO delivery_outbox (notification_id, due_at_ms, attempt)
                     VALUES (?1, ?2, ?3)
                     ON CONFLICT (notification_id) DO UPDATE SET
                         due_at_ms = excluded.due_at_ms,
                         attempt = excluded.attempt",
                    params![identifier, as_i64(due.get()), as_i64(transition.attempt)],
                )?;
            }
            _ => {
                transaction.execute(
                    "DELETE FROM delivery_outbox WHERE notification_id = ?1",
                    params![identifier],
                )?;
            }
        }
        transaction.commit()?;
        Ok(())
    }

    /// Returns the deliveries whose next attempt is due at `now_ms`, oldest first.
    ///
    /// A fenced outbox returns nothing: privacy mode stops the queue reaching anything outside
    /// this host at once, and that is expressed by the read rather than by every caller
    /// remembering to ask. Nor does a record admitted under an earlier generation, which is
    /// content privacy mode has already walked past, and nor does one whose own expiry has
    /// passed: section 16 stops retrying at expiry, and the read is where that is kept rather
    /// than every sender remembering it.
    ///
    /// # Errors
    ///
    /// Returns [`DeliveryError::JournalUnavailable`] when the read fails.
    pub fn due(&self, now_ms: u64, limit: usize) -> Result<Vec<DueDelivery>> {
        if self.is_fenced()? {
            return Ok(Vec::new());
        }
        let generation = self.generation()?;
        let mut statement = self.connection.prepare(
            "SELECT n.notification_id, n.destination_id, n.attempts, n.expires_at_ms,
                    n.privacy_generation, n.content
               FROM delivery_outbox o JOIN delivery_notifications n
                 ON n.notification_id = o.notification_id
              WHERE o.due_at_ms <= ?1 AND n.content IS NOT NULL
                AND n.expires_at_ms > ?1
                AND n.privacy_generation = ?3
              ORDER BY o.due_at_ms, n.admitted_at_ms
              LIMIT ?2",
        )?;
        let rows = statement.query_map(
            params![as_i64(now_ms), limit as i64, as_i64(generation)],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                ))
            },
        )?;
        let mut due = Vec::new();
        for row in rows {
            let (identifier, destination, attempts, expires, generation, content) = row?;
            due.push(DueDelivery {
                notification_id: parse_notification(&identifier)?,
                destination_id: DestinationId::new(destination)?,
                attempts: as_u64(attempts),
                expires_at_ms: TimestampMs::new(as_u64(expires)),
                privacy_generation: as_u64(generation),
                content,
            });
        }
        Ok(due)
    }

    /// Returns one delivery record.
    ///
    /// # Errors
    ///
    /// Returns [`DeliveryError::JournalUnavailable`] when the read fails.
    pub fn delivery(&self, notification_id: NotificationId) -> Result<Option<DeliveryRecord>> {
        let mut statement = self.connection.prepare(&format!(
            "{NOTIFICATION_COLUMNS} WHERE notification_id = ?1"
        ))?;
        let record = statement
            .query_row(params![notification_id.to_string()], decode_delivery)
            .optional()?;
        record.transpose()
    }

    /// Returns every delivery produced from one underlying event.
    ///
    /// # Errors
    ///
    /// Returns [`DeliveryError::JournalUnavailable`] when the read fails.
    pub fn deliveries_for(&self, event: &EventKey) -> Result<Vec<DeliveryRecord>> {
        let mut statement = self.connection.prepare(&format!(
            "{NOTIFICATION_COLUMNS} WHERE event_key = ?1 ORDER BY admitted_at_ms"
        ))?;
        let rows = statement.query_map(params![event.stored()], decode_delivery)?;
        let mut records = Vec::new();
        for row in rows {
            records.push(row??);
        }
        Ok(records)
    }

    /// Returns every delivery, oldest first. Every request this host made is retained.
    ///
    /// # Errors
    ///
    /// Returns [`DeliveryError::JournalUnavailable`] when the read fails.
    pub fn deliveries(&self) -> Result<Vec<DeliveryRecord>> {
        let mut statement = self
            .connection
            .prepare(&format!("{NOTIFICATION_COLUMNS} ORDER BY admitted_at_ms"))?;
        let rows = statement.query_map([], decode_delivery)?;
        let mut records = Vec::new();
        for row in rows {
            records.push(row??);
        }
        Ok(records)
    }

    /// Returns every attempt at one delivery, in order.
    ///
    /// # Errors
    ///
    /// Returns [`DeliveryError::JournalUnavailable`] when the read fails.
    pub fn attempts(&self, notification_id: NotificationId) -> Result<Vec<AttemptRecord>> {
        let mut statement = self.connection.prepare(
            "SELECT attempt, started_at_ms, settled_at_ms, outcome, detail
               FROM delivery_attempts WHERE notification_id = ?1 ORDER BY attempt",
        )?;
        let rows = statement.query_map(params![notification_id.to_string()], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, Option<i64>>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, Option<String>>(4)?,
            ))
        })?;
        let mut attempts = Vec::new();
        for row in rows {
            let (attempt, started, settled, outcome, detail) = row?;
            attempts.push(AttemptRecord {
                notification_id,
                attempt: as_u64(attempt),
                started_at_ms: TimestampMs::new(as_u64(started)),
                settled_at_ms: settled.map(|at| TimestampMs::new(as_u64(at))),
                outcome: outcome
                    .as_deref()
                    .map(|stored| {
                        DeliveryState::from_stored(stored).ok_or(DeliveryError::JournalUnreadable(
                            "a stored outcome is not one this build writes",
                        ))
                    })
                    .transpose()?,
                detail,
            });
        }
        Ok(attempts)
    }

    // ----- privacy -----------------------------------------------------------------------

    /// Stops every content-bearing queue at once and records the generation it was stopped at.
    ///
    /// Returns how many queues were stopped and how many items they were holding.
    ///
    /// # Errors
    ///
    /// Returns [`DeliveryError::JournalUnavailable`] when the write fails.
    pub fn fence(&mut self, generation: u64) -> Result<(u64, u64)> {
        let holding: i64 =
            self.connection
                .query_row("SELECT COUNT(*) FROM delivery_outbox", [], |row| row.get(0))?;
        self.connection.execute(
            "UPDATE delivery_privacy SET generation = ?1, fenced = 1 WHERE id = 0",
            params![as_i64(generation)],
        )?;
        Ok((1, as_u64(holding)))
    }

    /// Returns whether the outbox is fenced.
    ///
    /// # Errors
    ///
    /// Returns [`DeliveryError::JournalUnavailable`] when the read fails.
    pub fn is_fenced(&self) -> Result<bool> {
        let fenced: i64 = self.connection.query_row(
            "SELECT fenced FROM delivery_privacy WHERE id = 0",
            [],
            |row| row.get(0),
        )?;
        Ok(fenced != 0)
    }

    /// Returns the generation this journal last recorded.
    ///
    /// # Errors
    ///
    /// Returns [`DeliveryError::JournalUnavailable`] when the read fails.
    pub fn generation(&self) -> Result<u64> {
        let generation: i64 = self.connection.query_row(
            "SELECT generation FROM delivery_privacy WHERE id = 0",
            [],
            |row| row.get(0),
        )?;
        Ok(as_u64(generation))
    }

    /// Takes back everything admitted and not dispatched.
    ///
    /// Returns how many were taken back and how much had already left this host and cannot be.
    ///
    /// # Errors
    ///
    /// Returns [`DeliveryError::JournalUnavailable`] when the write fails.
    pub fn cancel_undispatched(&mut self, now_ms: u64) -> Result<(u64, u64)> {
        let transaction = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let in_flight: i64 = transaction.query_row(
            "SELECT COUNT(*) FROM delivery_notifications WHERE state IN ('in_flight',
             'outcome_unknown')",
            [],
            |row| row.get(0),
        )?;
        let cancelled = transaction.execute(
            "UPDATE delivery_notifications
                SET state = 'cancelled',
                    content = NULL,
                    detail = 'privacy mode took this back before it was dispatched'
              WHERE state IN ('admitted', 'retrying')",
            [],
        )?;
        transaction.execute(
            "DELETE FROM delivery_outbox WHERE notification_id IN
                 (SELECT notification_id FROM delivery_notifications WHERE state = 'cancelled')",
            [],
        )?;
        transaction.execute(
            "INSERT INTO delivery_attempts
                 (notification_id, attempt, started_at_ms, settled_at_ms, outcome, detail)
             SELECT notification_id, attempts + 1, ?1, ?1, 'cancelled',
                    'privacy mode took this back before it was dispatched'
               FROM delivery_notifications WHERE state = 'cancelled'
             ON CONFLICT (notification_id, attempt) DO NOTHING",
            params![as_i64(now_ms)],
        )?;
        transaction.commit()?;
        Ok((cancelled as u64, as_u64(in_flight)))
    }

    /// Removes the queued content and the preview material this journal holds.
    ///
    /// The records stay: what happened is not content, and a host that forgot its own attempts
    /// could not tell a person what the device did not see. The bytes go.
    ///
    /// Returns how many bytes and how many records were emptied.
    ///
    /// # Errors
    ///
    /// Returns [`DeliveryError::JournalUnavailable`] when the write fails.
    pub fn remove_retained(&mut self) -> Result<(u64, u64)> {
        let transaction = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let bytes: i64 = transaction.query_row(
            "SELECT COALESCE(SUM(LENGTH(content)), 0) FROM delivery_notifications
              WHERE content IS NOT NULL",
            [],
            |row| row.get(0),
        )?;
        let object_bytes: i64 = transaction.query_row(
            "SELECT COALESCE(SUM(LENGTH(sealed)), 0) FROM delivery_objects",
            [],
            |row| row.get(0),
        )?;
        let emptied = transaction.execute(
            "UPDATE delivery_notifications SET content = NULL WHERE content IS NOT NULL",
            [],
        )?;
        let objects = transaction.execute("DELETE FROM delivery_objects", [])?;
        transaction.commit()?;
        Ok((
            as_u64(bytes).saturating_add(as_u64(object_bytes)),
            (emptied + objects) as u64,
        ))
    }

    /// Returns how much work this journal still has outstanding.
    ///
    /// An attempt on the wire and an unknown outcome both count. Reconciliation is this reaching
    /// nought, and a journal that answered nought while a send was in flight would make privacy
    /// mode report complete before it was.
    ///
    /// # Errors
    ///
    /// Returns [`DeliveryError::JournalUnavailable`] when the read fails.
    pub fn outstanding(&self) -> Result<u64> {
        let outstanding: i64 = self.connection.query_row(
            "SELECT COUNT(*) FROM delivery_notifications
              WHERE state IN ('in_flight', 'outcome_unknown')",
            [],
            |row| row.get(0),
        )?;
        Ok(as_u64(outstanding))
    }

    /// Returns everything that has already left this host.
    ///
    /// Section 24: already-sent notifications and already-delivered external messages are not
    /// retroactively erased. They are shown as retained artifacts, with a separately authorised
    /// deletion action; `deletable` says whether this host holds a way to ask, not that asking
    /// will succeed and not that no other copy exists.
    ///
    /// # Errors
    ///
    /// Returns [`DeliveryError::JournalUnavailable`] when the read fails.
    pub fn exported(&self) -> Result<Vec<ExportedDelivery>> {
        let mut statement = self.connection.prepare(
            "SELECT n.notification_id, n.destination_id, d.kind, n.state,
                    COALESCE(MAX(a.settled_at_ms), n.admitted_at_ms)
               FROM delivery_notifications n
               JOIN delivery_destinations d ON d.destination_id = n.destination_id
               LEFT JOIN delivery_attempts a ON a.notification_id = n.notification_id
              WHERE n.state IN ('accepted', 'duplicate_uncertain', 'outcome_unknown')
              GROUP BY n.notification_id
              ORDER BY n.admitted_at_ms",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, i64>(4)?,
            ))
        })?;
        let mut exported = Vec::new();
        for row in rows {
            let (identifier, destination, kind, state, left_at) = row?;
            let kind =
                DestinationKind::from_stored(&kind).ok_or(DeliveryError::JournalUnreadable(
                    "a stored destination kind is not one this build writes",
                ))?;
            exported.push(ExportedDelivery {
                kind: match kind {
                    DestinationKind::Push => "notification".to_owned(),
                    other => format!("{other} message"),
                },
                reference: format!("{identifier} to {destination} ({state})"),
                left_at_ms: TimestampMs::new(as_u64(left_at)),
                // A notification a provider queued is on a device this host cannot reach, and an
                // external message is in somebody else's service. Neither has a removal this host
                // can perform, so neither claims one.
                deletable: false,
            });
        }
        Ok(exported)
    }

    /// Lifts the fence when privacy mode is turned off.
    ///
    /// # Errors
    ///
    /// Returns [`DeliveryError::JournalUnavailable`] when the write fails.
    pub fn lift_fence(&mut self, generation: u64) -> Result<()> {
        self.connection.execute(
            "UPDATE delivery_privacy SET generation = ?1, fenced = 0 WHERE id = 0",
            params![as_i64(generation)],
        )?;
        Ok(())
    }

    // ----- referenced encrypted objects --------------------------------------------------

    /// Keeps one encrypted object the excess details of a preview moved into.
    ///
    /// Section 16: larger details remain on the host or in an encrypted mailbox object. This is
    /// the host half; the mailbox half belongs to the mailbox service.
    ///
    /// # Errors
    ///
    /// Returns [`DeliveryError::JournalUnavailable`] when the write fails.
    pub fn keep_object(
        &mut self,
        envelope_id: kr_protocol::ids::EnvelopeId,
        destination_id: &DestinationId,
        sealed: &[u8],
        expires_at_ms: TimestampMs,
    ) -> Result<()> {
        self.connection.execute(
            "INSERT INTO delivery_objects (envelope_id, destination_id, sealed, expires_at_ms)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT (envelope_id) DO UPDATE SET
                 sealed = excluded.sealed, expires_at_ms = excluded.expires_at_ms",
            params![
                envelope_id.to_string(),
                destination_id.as_str(),
                sealed,
                as_i64(expires_at_ms.get())
            ],
        )?;
        Ok(())
    }

    /// Returns one kept object's sealed bytes.
    ///
    /// # Errors
    ///
    /// Returns [`DeliveryError::JournalUnavailable`] when the read fails.
    pub fn object(&self, envelope_id: kr_protocol::ids::EnvelopeId) -> Result<Option<Vec<u8>>> {
        Ok(self
            .connection
            .query_row(
                "SELECT sealed FROM delivery_objects WHERE envelope_id = ?1",
                params![envelope_id.to_string()],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?)
    }

    // ----- the host's own account --------------------------------------------------------

    /// Reads one destination's spent allowance back.
    ///
    /// # Errors
    ///
    /// Returns [`DeliveryError::JournalUnavailable`] when the read fails.
    pub fn budget(&self, destination_id: &DestinationId) -> Result<Option<StoredBudget>> {
        Ok(self
            .connection
            .query_row(
                "SELECT burst_scaled, sustained_scaled, refilled_at_ms, collapse_into,
                        collapse_opened_at_ms, collapse_count
                   FROM delivery_budget WHERE destination_id = ?1",
                params![destination_id.as_str()],
                |row| {
                    Ok(StoredBudget {
                        burst_scaled: as_u64(row.get::<_, i64>(0)?),
                        sustained_scaled: as_u64(row.get::<_, i64>(1)?),
                        refilled_at_ms: as_u64(row.get::<_, i64>(2)?),
                        collapse_into: row.get::<_, Option<String>>(3)?,
                        collapse_opened_at_ms: row.get::<_, Option<i64>>(4)?.map(as_u64),
                        collapse_count: as_u64(row.get::<_, i64>(5)?),
                    })
                },
            )
            .optional()?)
    }

    /// Writes one destination's spent allowance down.
    ///
    /// # Errors
    ///
    /// Returns [`DeliveryError::JournalUnavailable`] when the write fails.
    pub fn record_budget(
        &mut self,
        destination_id: &DestinationId,
        budget: &StoredBudget,
    ) -> Result<()> {
        self.connection.execute(
            BUDGET_UPSERT,
            rusqlite::params_from_iter(budget_params(destination_id, budget).iter()),
        )?;
        Ok(())
    }

    /// Returns the secret the collapse identifier is derived under, creating it once.
    ///
    /// It never leaves this store. A collapse identifier travels to a provider in the clear, so it
    /// is a keyed digest of what the host groups by rather than the thing itself: a provider that
    /// sees two equal values learns that they group, and nothing about what they group.
    ///
    /// # Errors
    ///
    /// Returns [`DeliveryError::JournalUnavailable`] when the read or the write fails.
    pub fn collapse_secret(&mut self) -> Result<[u8; 32]> {
        let stored: Option<Vec<u8>> = self
            .connection
            .query_row(
                "SELECT secret FROM delivery_secret WHERE id = 0",
                [],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(stored) = stored {
            return <[u8; 32]>::try_from(stored.as_slice()).map_err(|_| {
                DeliveryError::JournalUnreadable("the collapse secret is not 32 bytes")
            });
        }
        let mut secret = [0u8; 32];
        secret[..16].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
        secret[16..].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
        self.connection.execute(
            "INSERT INTO delivery_secret (id, secret) VALUES (0, ?1)",
            params![secret.as_slice()],
        )?;
        Ok(secret)
    }

    /// Returns the deliveries a restart has to reconcile, oldest first.
    ///
    /// An attempt that was on the wire when this host stopped has an outcome nobody knows. Section
    /// 24 resumes *only what is still authorised*, so the caller checks each one's destination and
    /// authorisation before it resumes anything; this read is the list, not the decision.
    ///
    /// # Errors
    ///
    /// Returns [`DeliveryError::JournalUnavailable`] when the read fails.
    pub fn unreconciled(&self) -> Result<Vec<DeliveryRecord>> {
        let mut statement = self.connection.prepare(&format!(
            "{NOTIFICATION_COLUMNS} WHERE state = 'in_flight' ORDER BY admitted_at_ms"
        ))?;
        let rows = statement.query_map([], decode_delivery)?;
        let mut records = Vec::new();
        for row in rows {
            records.push(row??);
        }
        Ok(records)
    }
}

/// One destination's spent allowance, as the journal holds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredBudget {
    /// The burst allowance spent, scaled.
    pub burst_scaled: u64,
    /// The sustained allowance spent, scaled.
    pub sustained_scaled: u64,
    /// When the bucket was last refilled, in UTC milliseconds.
    pub refilled_at_ms: u64,
    /// The attention update excess notifications are collapsing into.
    pub collapse_into: Option<String>,
    /// When that update's window opened, in UTC milliseconds.
    pub collapse_opened_at_ms: Option<u64>,
    /// How many notifications have collapsed into it.
    pub collapse_count: u64,
}

const DESTINATION_COLUMNS: &str = "SELECT destination_id, kind, enabled, configured_at_ms, \
     rule_name, grant_id, installation_id, sender_record_id, preview_key, preview_revision, \
     previous_preview_key, previous_preview_revision, previous_preview_until_ms, \
     previews_enabled, mailbox_key, endpoint, idempotency_field FROM delivery_destinations";

const NOTIFICATION_COLUMNS: &str = "SELECT notification_id, event_key, destination_id, state, \
     privacy_generation, content, payload_bytes, expires_at_ms, admitted_at_ms, attempts, \
     suppression_reason, suppression_into, suppression_count, suppression_next_ms, detail \
     FROM delivery_notifications";

type DestinationRow = (
    String,
    String,
    i64,
    i64,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<Vec<u8>>,
    Option<i64>,
    Option<Vec<u8>>,
    Option<i64>,
    Option<i64>,
    i64,
    Option<Vec<u8>>,
    Option<String>,
    Option<String>,
);

fn decode_destination(row: &rusqlite::Row<'_>) -> rusqlite::Result<Result<DestinationRecord>> {
    let columns: DestinationRow = (
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
        row.get(8)?,
        row.get(9)?,
        row.get(10)?,
        row.get(11)?,
        row.get(12)?,
        row.get(13)?,
        row.get(14)?,
        row.get(15)?,
        row.get(16)?,
    );
    Ok(build_destination(columns))
}

fn build_destination(columns: DestinationRow) -> Result<DestinationRecord> {
    let (
        id,
        kind,
        enabled,
        configured,
        rule_name,
        grant,
        installation,
        sender_record,
        preview_key,
        preview_revision,
        previous_key,
        previous_revision,
        previous_until,
        previews_enabled,
        mailbox_key,
        endpoint,
        idempotency_field,
    ) = columns;
    let kind = DestinationKind::from_stored(&kind).ok_or(DeliveryError::JournalUnreadable(
        "a stored destination kind is not one this build writes",
    ))?;
    let unreadable = |what: &'static str| DeliveryError::JournalUnreadable(what);
    let destination = if kind == DestinationKind::Push {
        let installation: InstallationId = installation
            .ok_or(unreadable("a push destination with no installation"))?
            .parse()
            .map_err(|_| unreadable("a stored installation identifier is not one"))?;
        let sender_record: PushSenderRecordId = sender_record
            .ok_or(unreadable("a push destination with no sender record"))?
            .parse()
            .map_err(|_| unreadable("a stored sender record identifier is not one"))?;
        let current = preview_key_from(preview_key.as_deref())?
            .ok_or(unreadable("a push destination with no preview key"))?;
        let previous = match (
            preview_key_from(previous_key.as_deref())?,
            previous_revision,
            previous_until,
        ) {
            (Some(key), Some(revision), Some(until)) => Some(RetiredPreviewKey {
                key,
                revision: as_u64(revision),
                retired_until_ms: TimestampMs::new(as_u64(until)),
            }),
            _ => None,
        };
        Destination::Push(Box::new(PushDestination {
            installation_id: installation,
            sender_record_id: sender_record,
            preview_keys: PreviewKeys {
                current,
                revision: as_u64(
                    preview_revision.ok_or(unreadable("a preview key with no revision"))?,
                ),
                previous,
            },
            previews_enabled: previews_enabled != 0,
            mailbox_key: mailbox_key
                .map(|bytes| {
                    <[u8; 32]>::try_from(bytes.as_slice())
                        .map(kr_protocol::scalars::StoredEnvelopeKey::from_bytes)
                        .map_err(|_| unreadable("a stored mailbox key is not 32 bytes"))
                })
                .transpose()?,
        }))
    } else {
        Destination::External(ExternalDestination {
            kind,
            endpoint: endpoint.ok_or(unreadable("an external destination with no endpoint"))?,
            idempotency: idempotency_field.map_or(Idempotency::Unsupported, |field| {
                Idempotency::Supported { field }
            }),
        })
    };
    let rule = rule_name.map(|name| {
        let grant_id = grant.as_deref().and_then(|id| id.parse::<GrantId>().ok());
        DeliveryRule { name, grant_id }
    });
    Ok(DestinationRecord {
        id: DestinationId::new(id)?,
        destination,
        rule,
        enabled: enabled != 0,
        configured_at_ms: TimestampMs::new(as_u64(configured)),
    })
}

fn preview_key_from(bytes: Option<&[u8]>) -> Result<Option<NotificationPreviewKey>> {
    bytes
        .map(|bytes| {
            <[u8; 32]>::try_from(bytes)
                .map(NotificationPreviewKey::from_bytes)
                .map_err(|_| {
                    DeliveryError::JournalUnreadable("a stored preview key is not 32 bytes")
                })
        })
        .transpose()
}

fn decode_delivery(row: &rusqlite::Row<'_>) -> rusqlite::Result<Result<DeliveryRecord>> {
    let identifier: String = row.get(0)?;
    let event: String = row.get(1)?;
    let destination: String = row.get(2)?;
    let state: String = row.get(3)?;
    let generation: i64 = row.get(4)?;
    let content: Option<Vec<u8>> = row.get(5)?;
    let payload_bytes: i64 = row.get(6)?;
    let expires: i64 = row.get(7)?;
    let admitted: i64 = row.get(8)?;
    let attempts: i64 = row.get(9)?;
    let reason: Option<String> = row.get(10)?;
    let into: Option<String> = row.get(11)?;
    let count: Option<i64> = row.get(12)?;
    let next: Option<i64> = row.get(13)?;
    let detail: Option<String> = row.get(14)?;
    Ok((|| {
        let source = event
            .split_once(':')
            .and_then(|(source, _)| EventSource::from_stored(source))
            .ok_or(DeliveryError::JournalUnreadable(
                "a stored event key is not one this build writes",
            ))?;
        let identity = event
            .split_once(':')
            .map(|(_, identity)| identity.to_owned())
            .unwrap_or_default();
        let suppression = match (reason, into, count, next) {
            (Some(reason), Some(into), Some(count), Some(next)) => Some(PushSuppression {
                collapsed_into: into.parse().map_err(|_| {
                    DeliveryError::JournalUnreadable(
                        "a stored collapse target is not an identifier",
                    )
                })?,
                next_update_at_ms: TimestampMs::new(as_u64(next)),
                reason: match reason.as_str() {
                    "burst" => PushSuppressionReason::Burst,
                    "sustained" => PushSuppressionReason::Sustained,
                    _ => {
                        return Err(DeliveryError::JournalUnreadable(
                            "a stored suppression reason is not one this build writes",
                        ));
                    }
                },
                suppressed_count: kr_protocol::scalars::U64::new(as_u64(count)),
            }),
            _ => None,
        };
        Ok(DeliveryRecord {
            notification_id: parse_notification(&identifier)?,
            event: EventKey { source, identity },
            destination_id: DestinationId::new(destination)?,
            state: DeliveryState::from_stored(&state).ok_or(DeliveryError::JournalUnreadable(
                "a stored delivery state is not one this build writes",
            ))?,
            privacy_generation: as_u64(generation),
            content,
            payload_bytes: as_u64(payload_bytes),
            expires_at_ms: TimestampMs::new(as_u64(expires)),
            admitted_at_ms: TimestampMs::new(as_u64(admitted)),
            attempts: as_u64(attempts),
            suppression,
            detail,
        })
    })())
}

/// Writes one admitted record and its outbox row inside a transaction the caller owns.
///
/// The fence and the generation are read **here**, inside that transaction, rather than by the
/// caller beforehand. A caller-side check has a window: privacy mode can fence between the check
/// and the insert, and what lands afterwards is content the cleanup has already walked past.
fn admit_in(transaction: &rusqlite::Transaction<'_>, record: &DeliveryRecord) -> Result<()> {
    let (generation, fenced): (i64, i64) = transaction.query_row(
        "SELECT generation, fenced FROM delivery_privacy WHERE id = 0",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    if fenced != 0 {
        return Err(DeliveryError::Fenced);
    }
    if record.privacy_generation != as_u64(generation) {
        return Err(DeliveryError::LateResult {
            produced_under: record.privacy_generation,
            in_force: as_u64(generation),
        });
    }
    let (reason, into, count, next) = suppression_columns(record.suppression.as_ref());
    let written = transaction.execute(
        "INSERT INTO delivery_notifications
             (notification_id, event_key, destination_id, state, privacy_generation,
              content, payload_bytes, expires_at_ms, admitted_at_ms, attempts,
              suppression_reason, suppression_into, suppression_count,
              suppression_next_ms, detail)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 0, ?11, ?12, ?13, ?14, ?10)",
        params![
            record.notification_id.to_string(),
            record.event.stored(),
            record.destination_id.as_str(),
            record.state.as_str(),
            as_i64(record.privacy_generation),
            record.content.as_deref(),
            as_i64(record.payload_bytes),
            as_i64(record.expires_at_ms.get()),
            as_i64(record.admitted_at_ms.get()),
            record.detail.as_deref(),
            reason,
            into,
            count,
            next,
        ],
    );
    match written {
        Ok(_) => {}
        Err(error) if is_foreign_key_violation(&error) => {
            // Two references, and the message says which is missing rather than making the caller
            // guess: the event that was never taken, or the destination nobody wrote.
            return Err(if transaction_has_event(transaction, &record.event)? {
                DeliveryError::NoDestination(record.destination_id.to_string())
            } else {
                DeliveryError::NoUnderlyingEvent(record.event.stored())
            });
        }
        Err(error) => return Err(error.into()),
    }
    if !record.state.is_settled() {
        transaction.execute(
            "INSERT INTO delivery_outbox (notification_id, due_at_ms, attempt)
             VALUES (?1, ?2, 0)",
            params![
                record.notification_id.to_string(),
                as_i64(record.admitted_at_ms.get())
            ],
        )?;
    }
    Ok(())
}

/// Writes one destination's spent allowance inside a transaction the caller owns.
fn record_budget_in(
    transaction: &rusqlite::Transaction<'_>,
    destination_id: &DestinationId,
    budget: &StoredBudget,
) -> Result<()> {
    transaction.execute(
        BUDGET_UPSERT,
        rusqlite::params_from_iter(budget_params(destination_id, budget).iter()),
    )?;
    Ok(())
}

/// The statement one destination's allowance is written with.
const BUDGET_UPSERT: &str = "INSERT INTO delivery_budget \
     (destination_id, burst_scaled, sustained_scaled, refilled_at_ms, \
      collapse_into, collapse_opened_at_ms, collapse_count) \
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7) \
     ON CONFLICT (destination_id) DO UPDATE SET \
         burst_scaled = excluded.burst_scaled, \
         sustained_scaled = excluded.sustained_scaled, \
         refilled_at_ms = excluded.refilled_at_ms, \
         collapse_into = excluded.collapse_into, \
         collapse_opened_at_ms = excluded.collapse_opened_at_ms, \
         collapse_count = excluded.collapse_count";

/// The values that statement takes.
fn budget_params(
    destination_id: &DestinationId,
    budget: &StoredBudget,
) -> [Box<dyn rusqlite::ToSql>; 7] {
    [
        Box::new(destination_id.as_str().to_owned()),
        Box::new(as_i64(budget.burst_scaled)),
        Box::new(as_i64(budget.sustained_scaled)),
        Box::new(as_i64(budget.refilled_at_ms)),
        Box::new(budget.collapse_into.clone()),
        Box::new(budget.collapse_opened_at_ms.map(as_i64)),
        Box::new(as_i64(budget.collapse_count)),
    ]
}

/// The four columns one suppression record is stored across.
fn suppression_columns(
    suppression: Option<&PushSuppression>,
) -> (
    Option<&'static str>,
    Option<String>,
    Option<i64>,
    Option<i64>,
) {
    match suppression {
        Some(suppression) => (
            Some(match suppression.reason {
                PushSuppressionReason::Burst => "burst",
                PushSuppressionReason::Sustained => "sustained",
            }),
            Some(suppression.collapsed_into.to_string()),
            Some(as_i64(suppression.suppressed_count.get())),
            Some(as_i64(suppression.next_update_at_ms.get())),
        ),
        None => (None, None, None, None),
    }
}

fn transaction_has_event(transaction: &rusqlite::Transaction<'_>, key: &EventKey) -> Result<bool> {
    let found: Option<i64> = transaction
        .query_row(
            "SELECT 1 FROM delivery_events WHERE event_key = ?1",
            params![key.stored()],
            |row| row.get(0),
        )
        .optional()?;
    Ok(found.is_some())
}

/// Returns true when the failure is SQLite saying the table is not there.
fn is_missing_table(error: &rusqlite::Error) -> bool {
    matches!(
        error,
        rusqlite::Error::SqliteFailure(failure, _) if failure.code == rusqlite::ErrorCode::Unknown
    ) || matches!(error, rusqlite::Error::SqliteFailure(_, Some(detail)) if detail.contains("no such table"))
}

/// Returns true when this file already holds one of the journal's tables.
fn has_any_delivery_table(connection: &Connection) -> Result<bool> {
    let found: Option<i64> = connection
        .query_row(
            "SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name LIKE 'delivery_%' LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()?;
    Ok(found.is_some())
}

fn is_foreign_key_violation(error: &rusqlite::Error) -> bool {
    matches!(
        error,
        rusqlite::Error::SqliteFailure(failure, _)
            if failure.code == rusqlite::ErrorCode::ConstraintViolation
                && failure.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_FOREIGNKEY
    )
}

fn parse_notification(value: &str) -> Result<NotificationId> {
    value.parse().map_err(|_| {
        DeliveryError::JournalUnreadable("a stored notification identifier is not one")
    })
}

fn hex(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push_str(&format!("{byte:02x}"));
    }
    text
}

/// Returns a bounded `i64` for a count this store holds as one.
fn as_i64(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

/// Returns a `u64` for a stored count, reading a negative as nought.
fn as_u64(value: i64) -> u64 {
    u64::try_from(value).unwrap_or(0)
}

/// A helper for callers that group records by destination.
#[must_use]
pub fn by_destination(records: &[DeliveryRecord]) -> BTreeMap<DestinationId, Vec<&DeliveryRecord>> {
    let mut grouped: BTreeMap<DestinationId, Vec<&DeliveryRecord>> = BTreeMap::new();
    for record in records {
        grouped
            .entry(record.destination_id.clone())
            .or_default()
            .push(record);
    }
    grouped
}

const SCHEMA: &str = "
    CREATE TABLE IF NOT EXISTS delivery_consumers (
        consumer TEXT PRIMARY KEY,
        cursor INTEGER NOT NULL,
        applied INTEGER NOT NULL,
        registered_at_ms INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS delivery_events (
        event_key TEXT PRIMARY KEY,
        source TEXT NOT NULL,
        source_cursor INTEGER NOT NULL,
        session_id TEXT,
        recorded_at_ms INTEGER NOT NULL,
        taken_seq INTEGER NOT NULL,
        notice BLOB,
        produced INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS delivery_destinations (
        destination_id TEXT PRIMARY KEY,
        kind TEXT NOT NULL,
        enabled INTEGER NOT NULL,
        configured_at_ms INTEGER NOT NULL,
        rule_name TEXT,
        grant_id TEXT,
        installation_id TEXT,
        sender_record_id TEXT,
        preview_key BLOB,
        preview_revision INTEGER,
        previous_preview_key BLOB,
        previous_preview_revision INTEGER,
        previous_preview_until_ms INTEGER,
        previews_enabled INTEGER NOT NULL,
        mailbox_key BLOB,
        endpoint TEXT,
        idempotency_field TEXT
    );
    CREATE TABLE IF NOT EXISTS delivery_notifications (
        notification_id TEXT PRIMARY KEY,
        event_key TEXT NOT NULL REFERENCES delivery_events(event_key),
        destination_id TEXT NOT NULL REFERENCES delivery_destinations(destination_id),
        state TEXT NOT NULL,
        privacy_generation INTEGER NOT NULL,
        content BLOB,
        payload_bytes INTEGER NOT NULL,
        expires_at_ms INTEGER NOT NULL,
        admitted_at_ms INTEGER NOT NULL,
        attempts INTEGER NOT NULL,
        suppression_reason TEXT,
        suppression_into TEXT,
        suppression_count INTEGER,
        suppression_next_ms INTEGER,
        detail TEXT,
        UNIQUE (event_key, destination_id)
    );
    CREATE TABLE IF NOT EXISTS delivery_attempts (
        notification_id TEXT NOT NULL
            REFERENCES delivery_notifications(notification_id) ON DELETE CASCADE,
        attempt INTEGER NOT NULL,
        started_at_ms INTEGER NOT NULL,
        settled_at_ms INTEGER,
        outcome TEXT,
        detail TEXT,
        PRIMARY KEY (notification_id, attempt)
    );
    CREATE TABLE IF NOT EXISTS delivery_outbox (
        notification_id TEXT PRIMARY KEY
            REFERENCES delivery_notifications(notification_id) ON DELETE CASCADE,
        due_at_ms INTEGER NOT NULL,
        attempt INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS delivery_objects (
        envelope_id TEXT PRIMARY KEY,
        destination_id TEXT NOT NULL REFERENCES delivery_destinations(destination_id),
        sealed BLOB NOT NULL,
        expires_at_ms INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS delivery_budget (
        destination_id TEXT PRIMARY KEY
            REFERENCES delivery_destinations(destination_id),
        burst_scaled INTEGER NOT NULL,
        sustained_scaled INTEGER NOT NULL,
        refilled_at_ms INTEGER NOT NULL,
        collapse_into TEXT,
        collapse_opened_at_ms INTEGER,
        collapse_count INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS delivery_secret (
        id INTEGER PRIMARY KEY CHECK (id = 0),
        secret BLOB NOT NULL
    );
    CREATE TABLE IF NOT EXISTS delivery_privacy (
        id INTEGER PRIMARY KEY CHECK (id = 0),
        generation INTEGER NOT NULL,
        fenced INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS delivery_outbox_due ON delivery_outbox (due_at_ms);
    CREATE INDEX IF NOT EXISTS delivery_notifications_state
        ON delivery_notifications (state);
    CREATE INDEX IF NOT EXISTS delivery_events_unproduced
        ON delivery_events (produced, taken_seq);
";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::destination::{Destination, ExternalDestination, PreviewKeys, PushDestination};

    fn uuid(byte: u8) -> kr_protocol::scalars::Uuid {
        kr_protocol::scalars::Uuid::from_bytes([byte; 16])
    }

    fn event(byte: u8) -> EventKey {
        EventKey::outbox(&uuid(byte))
    }

    fn taken(byte: u8, cursor: u64) -> TakenEvent {
        TakenEvent {
            key: event(byte),
            source_cursor: cursor,
            session_id: None,
            recorded_at_ms: TimestampMs::new(1_000),
            notice: b"a notice".to_vec(),
        }
    }

    fn consumer() -> String {
        EventSource::WorkerOutbox.consumer("session-1")
    }

    fn destination(id: &str) -> DestinationRecord {
        DestinationRecord {
            id: DestinationId::new(id).expect("an identifier"),
            destination: Destination::External(ExternalDestination {
                kind: DestinationKind::Webhook,
                endpoint: "https://example.invalid/hook".to_owned(),
                idempotency: Idempotency::Supported {
                    field: "Idempotency-Key".to_owned(),
                },
            }),
            rule: Some(DeliveryRule {
                name: "on failure".to_owned(),
                grant_id: None,
            }),
            enabled: true,
            configured_at_ms: TimestampMs::new(1),
        }
    }

    fn delivery(byte: u8, event: EventKey, destination: &str) -> DeliveryRecord {
        DeliveryRecord {
            notification_id: NotificationId::new(uuid(byte)),
            event,
            destination_id: DestinationId::new(destination).expect("an identifier"),
            state: DeliveryState::Admitted,
            privacy_generation: 0,
            content: Some(b"{}".to_vec()),
            payload_bytes: 2,
            expires_at_ms: TimestampMs::new(100_000),
            admitted_at_ms: TimestampMs::new(1_000),
            attempts: 0,
            suppression: None,
            detail: None,
        }
    }

    fn journal() -> DeliveryJournal {
        let mut journal = DeliveryJournal::in_memory().expect("a journal");
        journal
            .register_consumer(&consumer(), 1)
            .expect("registration");
        journal
            .configure_destination(&destination("hook"))
            .expect("a destination");
        journal
    }

    #[test]
    fn a_notification_cannot_be_produced_for_an_event_this_journal_has_not_taken() {
        let mut journal = journal();
        let error = journal
            .admit(&delivery(9, event(1), "hook"))
            .expect_err("the store refuses it");
        assert!(
            matches!(error, DeliveryError::NoUnderlyingEvent(key) if key == event(1).stored()),
            "the host writes the underlying event first, and the store is what proves it"
        );
    }

    #[test]
    fn taking_the_event_is_what_lets_a_notification_be_produced_from_it() {
        let mut journal = journal();
        journal
            .take_events(&consumer(), &[taken(1, 7)], 7)
            .expect("a page");
        journal
            .admit(&delivery(9, event(1), "hook"))
            .expect("admitted");
        let record = journal
            .delivery(NotificationId::new(uuid(9)))
            .expect("a read")
            .expect("the record");
        assert_eq!(record.event, event(1));
        assert_eq!(record.state, DeliveryState::Admitted);
    }

    #[test]
    fn a_consumer_that_has_not_registered_cannot_take_a_page() {
        let mut journal = DeliveryJournal::in_memory().expect("a journal");
        let error = journal
            .take_events(&consumer(), &[taken(1, 7)], 7)
            .expect_err("registration comes first");
        assert!(matches!(error, DeliveryError::NotAuthorised(_)));
    }

    #[test]
    fn a_replayed_page_adds_nothing_and_still_moves_the_cursor() {
        let mut journal = journal();
        assert_eq!(
            journal
                .take_events(&consumer(), &[taken(1, 5), taken(2, 6)], 6)
                .expect("a page"),
            2
        );
        assert_eq!(
            journal
                .take_events(&consumer(), &[taken(1, 5), taken(2, 6), taken(3, 7)], 7)
                .expect("a page"),
            1,
            "the de-duplication record absorbs what was already taken"
        );
        let cursor = journal
            .consumer_cursor(&consumer())
            .expect("a read")
            .expect("a registered consumer");
        assert_eq!(cursor.cursor, 7);
        assert_eq!(cursor.applied, 3);
    }

    #[test]
    fn a_cursor_never_goes_backwards() {
        let mut journal = journal();
        journal
            .take_events(&consumer(), &[taken(1, 9)], 9)
            .expect("a page");
        journal
            .take_events(&consumer(), &[taken(2, 3)], 3)
            .expect("a page");
        assert_eq!(
            journal
                .consumer_cursor(&consumer())
                .expect("a read")
                .expect("a consumer")
                .cursor,
            9
        );
    }

    #[test]
    fn a_transition_writes_the_state_the_attempt_and_the_outbox_row_together() {
        let mut journal = journal();
        journal
            .take_events(&consumer(), &[taken(1, 1)], 1)
            .expect("a page");
        journal
            .admit(&delivery(9, event(1), "hook"))
            .expect("admitted");
        journal
            .record_attempt(&Transition {
                notification_id: NotificationId::new(uuid(9)),
                attempt: 1,
                state: DeliveryState::Retrying,
                started_at_ms: TimestampMs::new(2_000),
                settled_at_ms: Some(TimestampMs::new(2_010)),
                next_attempt_at_ms: Some(TimestampMs::new(3_000)),
                detail: Some("the provider was busy".to_owned()),
                suppression: None,
                keep_content: true,
            })
            .expect("a transition");
        let record = journal
            .delivery(NotificationId::new(uuid(9)))
            .expect("a read")
            .expect("the record");
        assert_eq!(record.state, DeliveryState::Retrying);
        assert_eq!(record.attempts, 1);
        assert_eq!(
            journal
                .attempts(NotificationId::new(uuid(9)))
                .expect("attempts")
                .len(),
            1
        );
        assert!(journal.due(2_999, 10).expect("a read").is_empty());
        assert_eq!(journal.due(3_000, 10).expect("a read").len(), 1);
    }

    #[test]
    fn a_settled_transition_takes_the_delivery_out_of_the_outbox_and_keeps_the_record() {
        let mut journal = journal();
        journal
            .take_events(&consumer(), &[taken(1, 1)], 1)
            .expect("a page");
        journal
            .admit(&delivery(9, event(1), "hook"))
            .expect("admitted");
        journal
            .record_attempt(&Transition {
                notification_id: NotificationId::new(uuid(9)),
                attempt: 1,
                state: DeliveryState::Accepted,
                started_at_ms: TimestampMs::new(2_000),
                settled_at_ms: Some(TimestampMs::new(2_010)),
                next_attempt_at_ms: None,
                detail: Some("queued".to_owned()),
                suppression: None,
                keep_content: false,
            })
            .expect("a transition");
        assert!(journal.due(50_000, 10).expect("a read").is_empty());
        let record = journal
            .delivery(NotificationId::new(uuid(9)))
            .expect("a read")
            .expect("the record");
        assert_eq!(record.state, DeliveryState::Accepted);
        assert_eq!(record.content, None, "the bytes go, the record stays");
        assert_eq!(record.detail.as_deref(), Some("queued"));
    }

    #[test]
    fn one_event_produces_one_notification_per_destination_and_no_more() {
        let mut journal = journal();
        journal
            .configure_destination(&destination("second"))
            .expect("a destination");
        journal
            .take_events(&consumer(), &[taken(1, 1)], 1)
            .expect("a page");
        journal
            .admit(&delivery(9, event(1), "hook"))
            .expect("admitted");
        journal
            .admit(&delivery(8, event(1), "second"))
            .expect("admitted");
        let second = journal.admit(&delivery(7, event(1), "hook"));
        assert!(
            second.is_err(),
            "one underlying event and one destination is one notification"
        );
    }

    #[test]
    fn a_reopened_journal_keeps_its_budgets_and_its_state() {
        let directory = tempfile::tempdir().expect("a directory");
        let path = directory.path().join("delivery.sqlite3");
        let secret = {
            let mut journal = DeliveryJournal::open(&path).expect("a journal");
            journal
                .register_consumer(&consumer(), 1)
                .expect("registration");
            journal
                .configure_destination(&destination("hook"))
                .expect("a destination");
            journal
                .take_events(&consumer(), &[taken(1, 4)], 4)
                .expect("a page");
            journal
                .admit(&delivery(9, event(1), "hook"))
                .expect("admitted");
            journal
                .record_budget(
                    &DestinationId::new("hook").expect("an identifier"),
                    &StoredBudget {
                        burst_scaled: 17,
                        sustained_scaled: 42,
                        refilled_at_ms: 9_000,
                        collapse_into: None,
                        collapse_opened_at_ms: None,
                        collapse_count: 0,
                    },
                )
                .expect("a budget");
            journal.collapse_secret().expect("a secret")
        };
        let mut reopened = DeliveryJournal::open(&path).expect("a journal");
        assert_eq!(
            reopened
                .consumer_cursor(&consumer())
                .expect("a read")
                .expect("a consumer")
                .cursor,
            4
        );
        assert_eq!(reopened.due(50_000, 10).expect("a read").len(), 1);
        assert_eq!(
            reopened
                .budget(&DestinationId::new("hook").expect("an identifier"))
                .expect("a read")
                .expect("a budget")
                .burst_scaled,
            17
        );
        assert_eq!(
            reopened.collapse_secret().expect("a secret"),
            secret,
            "the collapse secret outlives the process that made it"
        );
    }

    #[test]
    fn an_event_carries_the_notice_it_was_taken_with_until_something_is_produced_from_it() {
        let mut journal = journal();
        journal
            .take_events(&consumer(), &[taken(1, 7)], 7)
            .expect("a page");
        let pending = journal.pending_events(10).expect("a read");
        assert_eq!(pending.len(), 1, "the event is waiting to be produced from");
        assert_eq!(pending[0].notice, b"a notice");
        journal
            .produce(&event(1), &[delivery(9, event(1), "hook")], &[])
            .expect("produced");
        assert!(
            journal.pending_events(10).expect("a read").is_empty(),
            "an event that has been produced from is no longer pending"
        );
    }

    #[test]
    fn producing_from_one_event_twice_writes_nothing_the_second_time() {
        let mut journal = journal();
        journal
            .take_events(&consumer(), &[taken(1, 7)], 7)
            .expect("a page");
        assert!(
            journal
                .produce(&event(1), &[delivery(9, event(1), "hook")], &[])
                .expect("produced")
        );
        assert!(
            !journal
                .produce(&event(1), &[delivery(8, event(1), "hook")], &[])
                .expect("a second pass"),
            "the event's own flag is what makes producing idempotent"
        );
        assert_eq!(journal.deliveries().expect("a read").len(), 1);
    }

    #[test]
    fn producing_writes_the_notifications_and_what_they_spent_together() {
        let mut journal = journal();
        journal
            .take_events(&consumer(), &[taken(1, 7)], 7)
            .expect("a page");
        let spent = StoredBudget {
            burst_scaled: 11,
            sustained_scaled: 22,
            refilled_at_ms: 1_000,
            collapse_into: None,
            collapse_opened_at_ms: None,
            collapse_count: 0,
        };
        journal
            .produce(
                &event(1),
                &[delivery(9, event(1), "hook")],
                &[(DestinationId::new("hook").expect("an identifier"), spent)],
            )
            .expect("produced");
        assert_eq!(
            journal
                .budget(&DestinationId::new("hook").expect("an identifier"))
                .expect("a read")
                .expect("an allowance")
                .burst_scaled,
            11
        );
    }

    #[test]
    fn a_refused_notification_leaves_the_allowance_unspent_and_the_event_unproduced() {
        let mut journal = journal();
        journal
            .take_events(&consumer(), &[taken(1, 7)], 7)
            .expect("a page");
        let mut unknown = delivery(9, event(1), "nowhere");
        unknown.destination_id = DestinationId::new("nowhere").expect("an identifier");
        let spent = StoredBudget {
            burst_scaled: 11,
            sustained_scaled: 22,
            refilled_at_ms: 1_000,
            collapse_into: None,
            collapse_opened_at_ms: None,
            collapse_count: 0,
        };
        assert!(
            journal
                .produce(
                    &event(1),
                    &[unknown],
                    &[(DestinationId::new("hook").expect("an identifier"), spent)]
                )
                .is_err()
        );
        assert_eq!(
            journal
                .budget(&DestinationId::new("hook").expect("an identifier"))
                .expect("a read"),
            None,
            "nothing was charged for a notification nobody admitted"
        );
        assert_eq!(
            journal.pending_events(10).expect("a read").len(),
            1,
            "the event is still waiting, so the recovery pass produces from it"
        );
    }

    #[test]
    fn nothing_is_admitted_while_the_outbox_is_fenced() {
        let mut journal = journal();
        journal
            .take_events(&consumer(), &[taken(1, 7)], 7)
            .expect("a page");
        journal.fence(1).expect("a fence");
        let mut record = delivery(9, event(1), "hook");
        record.privacy_generation = 1;
        assert!(
            matches!(journal.admit(&record), Err(DeliveryError::Fenced)),
            "the fence is read inside the admission transaction, not before it"
        );
    }

    #[test]
    fn a_record_from_an_earlier_generation_is_neither_admitted_nor_dispatched() {
        let mut journal = journal();
        journal
            .take_events(&consumer(), &[taken(1, 7), taken(2, 8)], 8)
            .expect("a page");
        journal
            .admit(&delivery(9, event(1), "hook"))
            .expect("admitted");
        // Privacy mode opens a generation and is then turned off again.
        journal.fence(1).expect("a fence");
        journal.lift_fence(1).expect("the fence lifts");
        assert!(
            journal.due(50_000, 10).expect("a read").is_empty(),
            "content admitted before the boundary is not offered after it"
        );
        assert!(
            matches!(
                journal.admit(&delivery(8, event(2), "hook")),
                Err(DeliveryError::LateResult {
                    produced_under: 0,
                    in_force: 1
                })
            ),
            "a producer that still holds the old generation is refused"
        );
    }

    #[test]
    fn two_stores_of_one_source_keep_separate_cursors() {
        let mut journal = journal();
        let first = EventSource::WorkerOutbox.consumer("session-1");
        let second = EventSource::WorkerOutbox.consumer("session-2");
        journal.register_consumer(&first, 1).expect("registration");
        journal.register_consumer(&second, 1).expect("registration");
        journal
            .take_events(&first, &[taken(1, 100)], 100)
            .expect("a page");
        assert_eq!(
            journal
                .consumer_cursor(&second)
                .expect("a read")
                .expect("a consumer")
                .cursor,
            0,
            "one worker's position is not another worker's"
        );
    }

    #[test]
    fn a_retired_preview_key_is_dropped_once_its_notifications_have_expired() {
        let mut journal = journal();
        let device = kr_crypto::keys::NotificationPreviewKeyPair::generate().expect("a keypair");
        let replaced = kr_crypto::keys::NotificationPreviewKeyPair::generate().expect("a keypair");
        let id = DestinationId::new("phone").expect("an identifier");
        journal
            .configure_destination(&DestinationRecord {
                id: id.clone(),
                destination: Destination::Push(Box::new(PushDestination {
                    installation_id: InstallationId::new(uuid(5)),
                    sender_record_id: PushSenderRecordId::new(uuid(6)),
                    preview_keys: PreviewKeys::only(*replaced.public(), 1).rotated(
                        *device.public(),
                        2,
                        Some(TimestampMs::new(9_000)),
                    ),
                    previews_enabled: true,
                    mailbox_key: None,
                })),
                rule: Some(DeliveryRule {
                    name: "anything".to_owned(),
                    grant_id: None,
                }),
                enabled: true,
                configured_at_ms: TimestampMs::new(1),
            })
            .expect("a destination");
        assert_eq!(
            journal.forget_expired_preview_keys(8_999).expect("a pass"),
            0
        );
        assert!(
            journal
                .destination(&id)
                .expect("a read")
                .expect("a record")
                .as_push()
                .expect("a push destination")
                .preview_keys
                .previous
                .is_some()
        );
        assert_eq!(
            journal.forget_expired_preview_keys(9_000).expect("a pass"),
            1
        );
        assert!(
            journal
                .destination(&id)
                .expect("a read")
                .expect("a record")
                .as_push()
                .expect("a push destination")
                .preview_keys
                .previous
                .is_none(),
            "the bound is enforced rather than trusted"
        );
    }

    #[test]
    fn a_store_that_has_lost_a_table_is_refused_rather_than_recreated() {
        let directory = tempfile::tempdir().expect("a directory");
        let path = directory.path().join("delivery.sqlite3");
        {
            let mut journal = DeliveryJournal::open(&path).expect("a journal");
            journal
                .register_consumer(&consumer(), 1)
                .expect("registration");
        }
        let connection = rusqlite::Connection::open(&path).expect("a connection");
        connection
            .execute_batch("DROP TABLE delivery_outbox;")
            .expect("a table goes missing");
        drop(connection);
        assert!(
            matches!(
                DeliveryJournal::open(&path),
                Err(DeliveryError::JournalUnreadable(_))
            ),
            "an empty outbox says the opposite of what is true"
        );
    }

    #[test]
    fn a_store_that_has_lost_its_privacy_row_is_refused() {
        let directory = tempfile::tempdir().expect("a directory");
        let path = directory.path().join("delivery.sqlite3");
        drop(DeliveryJournal::open(&path).expect("a journal"));
        let connection = rusqlite::Connection::open(&path).expect("a connection");
        connection
            .execute_batch("DELETE FROM delivery_privacy;")
            .expect("the row goes missing");
        drop(connection);
        assert!(matches!(
            DeliveryJournal::open(&path),
            Err(DeliveryError::JournalUnreadable(_))
        ));
    }

    #[test]
    fn a_fenced_outbox_offers_nothing_and_says_what_it_was_holding() {
        let mut journal = journal();
        journal
            .take_events(&consumer(), &[taken(1, 1)], 1)
            .expect("a page");
        journal
            .admit(&delivery(9, event(1), "hook"))
            .expect("admitted");
        let (queues, items) = journal.fence(1).expect("a fence");
        assert_eq!((queues, items), (1, 1));
        assert!(
            journal.due(50_000, 10).expect("a read").is_empty(),
            "the fence stops the queue rather than the caller remembering to ask"
        );
    }
}
