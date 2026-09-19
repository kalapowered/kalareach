//! The environment feature store.
//!
//! Section 24 gives attention, quiet hours, escalation, review and visit acknowledgements one
//! owner: an environment feature store with per-actor revisions and consumed event cursors, from
//! which the state is reconstructed idempotently. This is that store, a small table set of its own
//! beside the session's journal rather than inside it.
//!
//! Half of what it holds is a projection of the journal's events, and a replay rebuilds it. The
//! other half is not, and no replay restores it: the acknowledgements, the per-actor revisions,
//! the visits and their log views, the quiet-hours window, the identities already given to
//! announcements and the secret the keys are derived under are records in their own right, and
//! this is where they live.
//!
//! # Why the whole state is written at once
//!
//! Every write here replaces the stored state in one transaction. What keeps that affordable in
//! the ordinary case is that most of the state carries a bound where it is built:
//! [`kr_protocol::attention::MAX_RETAINED_ATTENTION_ITEMS`] items, each with a summary bounded by
//! [`kr_protocol::attention::MAX_ATTENTION_SUMMARY_LEN`];
//! [`crate::visit::MAX_RETAINED_CHANGES`] changes; [`crate::visit::MAX_OMITTED_RANGES`] omitted
//! ranges; [`kr_protocol::attention::MAX_RETAINED_SUMMARIES`] summaries; and
//! [`kr_protocol::attention::MAX_RETAINED_LOG_VIEWS`] views per actor.
//!
//! Two of those bounds hold back rather than forget, so the set they bound grows past its figure
//! rather than losing something authoritative: the inbox keeps a condition somebody is waiting on
//! and a decision that is still in flight, and the pending requests keep one whose reminder is
//! still owed. The review table has no retention at all, because outstanding review work and an
//! actor's record of what it read are both authoritative, and
//! [`crate::review::Reviews::states_page`] bounds the answer instead. What that costs is the
//! whole-state write growing with them, which is the price of not forgetting work the host was
//! asked to do or told about.
//!
//! Writing all of it buys two properties that matter more than the saving. There is no partial
//! write to reason about, so a crash leaves the store at the last complete state rather than at
//! half of two. And storing the state is then the same operation as reconstructing it, so a
//! rebuild from the retained events and an ordinary write cannot drift.
//!
//! # What is durable, and what is re-anchored
//!
//! Every interval the engine measures is measured on the boot-scoped continuous clock, which means
//! nothing after a restart. So the store records the wall-clock moments instead - when an item was
//! first seen, when it was last announced, when a request became pending - and, beside each one,
//! whether the clock that stamped it could be proved. [`crate::host::Attention::open`] re-anchors
//! each interval against the reading it opened at, and only where both ends were taken on a clock
//! somebody could vouch for: this reading, and the moment itself. Every other interval starts
//! again, which is the conservative answer rather than arithmetic across two clocks that were
//! never on one scale.
//!
//! # What a stored value may not do
//!
//! It may not come back as a different value. Every integer is written and read without clamping,
//! and a row this build cannot read exactly is [`Error::StoreUnreadable`] rather than a plausible
//! substitute: a current version that collapsed onto an acknowledged one would close review work
//! nobody had done.

use std::collections::{BTreeMap, VecDeque};
use std::path::Path;
use std::str::FromStr;

use kr_protocol::attention::{
    AttentionGap, AttentionKey, AttentionLevel, AttentionRouting, AttentionRule, AttentionSource,
    ChangeSummary, LogViewState, NotificationState, QuietHours, ReviewSubject, SemanticChange,
    SemanticChangeKind,
};
use kr_protocol::ids::{ActorId, AgentTurnId, ChangeSetId, QuestionId, SessionId};
use kr_protocol::scalars::{Nullable, TimestampMs, U64};
use rusqlite::{Connection, OptionalExtension, params};

use crate::engine::{Item, ItemAck, PendingInput};
use crate::error::{Error, Result};
use crate::review::{ReviewAck, Subject, subject_key};
use crate::time::{Elapsed, HostReading};
use crate::visit::{Omitted, Visit};

/// The schema this build writes and reads.
///
/// A store written under any other version is refused rather than read. Two things in here are
/// derived rather than stored on their own - an item's key, and the order a review page continues
/// by - so a row written under a different derivation would be read under a name that does not
/// describe it, which is worse than not reading it at all. Every row also has to say which of its
/// moments were taken on a clock somebody could prove, and a row that predates those columns
/// cannot answer.
pub const SCHEMA_VERSION: i64 = 4;

/// How long a write waits for another holder of the same file before it is refused.
pub const BUSY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Everything the feature store holds.
#[derive(Clone, Debug, Default)]
pub struct StoredState {
    /// The inbox.
    pub items: Vec<Item>,
    /// Each actor's acknowledgements of items.
    pub item_acks: BTreeMap<ActorId, BTreeMap<AttentionKey, ItemAck>>,
    /// Each actor's acknowledgement revision.
    pub revisions: BTreeMap<ActorId, u64>,
    /// The highest sequence consumed from each source.
    pub consumed: BTreeMap<AttentionSource, u64>,
    /// The ranges of retained events the host can no longer read.
    pub gaps: Vec<AttentionGap>,
    /// How many items the host has let go of to stay inside its bound.
    pub dropped: u64,
    /// The secret this store derives its item keys under.
    ///
    /// It is generated once, when a store first has state to write, and read back with the rest.
    /// A store that has never been written gives a fresh one, which is right: it has no keys.
    pub keys: crate::key::KeySecret,
    /// The highest identity this store has given an announcement.
    ///
    /// It only goes forward, and it outlives the item whose decision it named, so an identity a
    /// delivery consumer recorded never comes back attached to a later decision.
    pub next_announcement: u64,
    /// The questions waiting for an answer.
    pub pending_inputs: BTreeMap<QuestionId, PendingInput>,
    /// The configured quiet-hours window.
    pub quiet: Option<QuietHours>,
    /// Each review subject at the version the host holds.
    pub subjects: BTreeMap<String, Subject>,
    /// Each actor's review acknowledgements.
    pub review_acks: BTreeMap<ActorId, BTreeMap<String, ReviewAck>>,
    /// The retained semantic changes, oldest first.
    pub changes: VecDeque<SemanticChange>,
    /// The cursor the next change is recorded at.
    pub next_cursor: u64,
    /// The ranges that are missing from what a visit can be shown.
    pub omitted: Vec<Omitted>,
    /// The model summaries the host holds.
    pub summaries: Vec<ChangeSummary>,
    /// Each actor's visit and the views it had open.
    pub visits: BTreeMap<ActorId, Visit>,
}

/// The environment feature store.
#[derive(Debug)]
pub struct Store {
    connection: Connection,
}

const SCHEMA: &str = "
    CREATE TABLE IF NOT EXISTS attention_schema (version INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS attention_consumed (
        source TEXT PRIMARY KEY,
        sequence INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS attention_gaps (
        source TEXT NOT NULL,
        from_sequence INTEGER NOT NULL,
        to_sequence INTEGER NOT NULL,
        position INTEGER NOT NULL,
        PRIMARY KEY (source, from_sequence)
    );
    CREATE TABLE IF NOT EXISTS attention_items (
        key TEXT PRIMARY KEY,
        rule TEXT NOT NULL,
        source TEXT NOT NULL,
        session_id TEXT,
        summary TEXT NOT NULL,
        routing TEXT NOT NULL,
        level TEXT NOT NULL,
        steps_taken INTEGER NOT NULL,
        occurrences INTEGER NOT NULL,
        first_seen_ms INTEGER NOT NULL,
        last_seen_ms INTEGER NOT NULL,
        notification TEXT NOT NULL,
        last_notified_ms INTEGER,
        announced_proven INTEGER NOT NULL,
        anchor_proven INTEGER NOT NULL,
        announced_level TEXT,
        announcements INTEGER NOT NULL,
        pending_handoff INTEGER,
        uncertain INTEGER NOT NULL,
        deferred INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS attention_actors (
        actor TEXT PRIMARY KEY,
        revision INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS attention_dropped (
        id INTEGER PRIMARY KEY CHECK (id = 0),
        items INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS attention_key_secret (
        id INTEGER PRIMARY KEY CHECK (id = 0),
        secret BLOB NOT NULL
    );
    CREATE TABLE IF NOT EXISTS attention_announcements (
        id INTEGER PRIMARY KEY CHECK (id = 0),
        next INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS attention_item_acks (
        actor TEXT NOT NULL,
        key TEXT NOT NULL,
        occurrences INTEGER NOT NULL,
        at_ms INTEGER NOT NULL,
        PRIMARY KEY (actor, key)
    );
    CREATE TABLE IF NOT EXISTS attention_pending_inputs (
        question_id TEXT PRIMARY KEY,
        session_id TEXT NOT NULL,
        summary TEXT NOT NULL,
        pending_since_ms INTEGER NOT NULL,
        reminded INTEGER NOT NULL,
        anchor_proven INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS attention_quiet_hours (
        id INTEGER PRIMARY KEY CHECK (id = 0),
        start_minute INTEGER NOT NULL,
        end_minute INTEGER NOT NULL,
        zone TEXT
    );
    CREATE TABLE IF NOT EXISTS attention_review_subjects (
        key TEXT PRIMARY KEY,
        kind TEXT NOT NULL,
        session_id TEXT NOT NULL,
        object TEXT NOT NULL,
        version INTEGER NOT NULL,
        at_ms INTEGER NOT NULL,
        sequence INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS attention_review_acks (
        actor TEXT NOT NULL,
        subject TEXT NOT NULL,
        version INTEGER NOT NULL,
        at_ms INTEGER NOT NULL,
        PRIMARY KEY (actor, subject)
    );
    CREATE TABLE IF NOT EXISTS attention_changes (
        cursor INTEGER PRIMARY KEY,
        kind TEXT NOT NULL,
        session_id TEXT NOT NULL,
        summary TEXT,
        at_ms INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS attention_change_head (
        id INTEGER PRIMARY KEY CHECK (id = 0),
        next_cursor INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS attention_omitted (
        at_cursor INTEGER NOT NULL,
        source TEXT NOT NULL,
        from_sequence INTEGER NOT NULL,
        to_sequence INTEGER NOT NULL,
        position INTEGER NOT NULL,
        PRIMARY KEY (at_cursor, source, from_sequence)
    );
    CREATE TABLE IF NOT EXISTS attention_summaries (
        from_cursor INTEGER PRIMARY KEY,
        to_cursor INTEGER NOT NULL,
        from_ms INTEGER NOT NULL,
        to_ms INTEGER NOT NULL,
        model TEXT NOT NULL,
        text TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS attention_visits (
        actor TEXT PRIMARY KEY,
        cursor INTEGER NOT NULL,
        revision INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS attention_log_views (
        actor TEXT NOT NULL,
        view_id TEXT NOT NULL,
        source_offset INTEGER NOT NULL,
        filter TEXT NOT NULL,
        position INTEGER NOT NULL,
        PRIMARY KEY (actor, view_id)
    );
";

/// Every table the state lives in, which one write replaces together.
const TABLES: &[&str] = &[
    "attention_consumed",
    "attention_gaps",
    "attention_items",
    "attention_actors",
    "attention_dropped",
    "attention_announcements",
    "attention_key_secret",
    "attention_item_acks",
    "attention_pending_inputs",
    "attention_quiet_hours",
    "attention_review_subjects",
    "attention_review_acks",
    "attention_changes",
    "attention_change_head",
    "attention_omitted",
    "attention_summaries",
    "attention_visits",
    "attention_log_views",
];

fn unreadable(field: &'static str) -> Error {
    Error::StoreUnreadable { field }
}

/// Returns `value` as the integer SQLite stores, refusing one it cannot hold.
///
/// Clamping would be worse than refusing. A version, a cursor or an occurrence count that came
/// back as a different number would read as valid state, and a current version that collapsed onto
/// an acknowledged one would close review work nobody had done.
fn as_i64(value: u64, field: &'static str) -> Result<i64> {
    i64::try_from(value).map_err(|_| unreadable(field))
}

/// Returns a stored integer as the unsigned value it was written from, refusing a negative one.
fn as_u64(value: i64, field: &'static str) -> Result<u64> {
    u64::try_from(value).map_err(|_| unreadable(field))
}

fn as_index(value: usize, field: &'static str) -> Result<i64> {
    i64::try_from(value).map_err(|_| unreadable(field))
}

impl Store {
    /// Opens the store at `path`, creating it when it is not there.
    ///
    /// # Errors
    ///
    /// Returns [`Error::StoreUnavailable`] when the file cannot be opened or the schema cannot be
    /// created, and [`Error::StoreUnreadable`] when the file records a schema this build does not
    /// know.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let connection = Connection::open(path)?;
        Self::prepare(connection)
    }

    /// Opens the store inside the worker's private journal, or in memory when there is none.
    ///
    /// The journal opened the file first and owns its own schema version; these tables sit beside
    /// it under their own names and their own version row, so neither migration reads the other's.
    ///
    /// # Errors
    ///
    /// Returns [`Error::StoreUnavailable`] when the file cannot be opened or the schema cannot be
    /// created, and [`Error::StoreUnreadable`] when the file records a schema this build does not
    /// know.
    pub fn beside(path: Option<&Path>) -> Result<Self> {
        match path {
            Some(path) => Self::open(path),
            None => Self::in_memory(),
        }
    }

    /// Opens a store that lives only as long as it is held.
    ///
    /// # Errors
    ///
    /// Returns [`Error::StoreUnavailable`] when the schema cannot be created.
    pub fn in_memory() -> Result<Self> {
        let connection = Connection::open_in_memory()?;
        Self::prepare(connection)
    }

    fn prepare(connection: Connection) -> Result<Self> {
        // The store shares its file with the receipt journal and the question ledger, so a write
        // can find another of them holding it. The wait is bounded: past it the caller is told the
        // store is unavailable rather than left blocked.
        connection.busy_timeout(BUSY_TIMEOUT)?;
        connection.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=FULL;
             PRAGMA foreign_keys=ON;",
        )?;
        // The recorded version is read before anything is created, because a table that is already
        // there is left alone and would tell this build nothing about which build wrote it.
        connection.execute_batch(
            "CREATE TABLE IF NOT EXISTS attention_schema (version INTEGER NOT NULL);",
        )?;
        let recorded: Option<i64> = connection
            .query_row("SELECT version FROM attention_schema LIMIT 1", [], |row| {
                row.get(0)
            })
            .optional()?;
        match recorded {
            Some(version) if version == SCHEMA_VERSION => {}
            Some(_) => return Err(unreadable("schema version")),
            None => {
                connection.execute(
                    "INSERT INTO attention_schema (version) VALUES (?1)",
                    params![SCHEMA_VERSION],
                )?;
            }
        }
        connection.execute_batch(SCHEMA)?;
        Ok(Self { connection })
    }

    /// Reads the whole stored state back.
    ///
    /// # Errors
    ///
    /// Returns [`Error::StoreUnavailable`] when a read fails and [`Error::StoreUnreadable`] when a
    /// stored value is not one this build can read back exactly.
    pub fn load(&self) -> Result<StoredState> {
        let changes = self.load_changes()?;
        let head: Option<i64> = self
            .connection
            .query_row(
                "SELECT next_cursor FROM attention_change_head WHERE id = 0",
                [],
                |row| row.get(0),
            )
            .optional()?;
        let next_cursor = match head {
            Some(value) => as_u64(value, "change head")?,
            None => changes
                .back()
                .map_or(0, |change| change.cursor.get().saturating_add(1)),
        };
        let dropped: Option<i64> = self
            .connection
            .query_row(
                "SELECT items FROM attention_dropped WHERE id = 0",
                [],
                |row| row.get(0),
            )
            .optional()?;
        let secret: Option<Vec<u8>> = self
            .connection
            .query_row(
                "SELECT secret FROM attention_key_secret WHERE id = 0",
                [],
                |row| row.get(0),
            )
            .optional()?;
        // A store that has never been written has no secret and no state, and the fresh secret is
        // the one it starts with. A store that holds state and has lost its secret is a different
        // thing: every key in it was derived under one this build cannot reproduce, so a
        // resolution would look for an item under a name nothing there carries, and the condition
        // would stay outstanding for ever. That is refused rather than served.
        let keys = match secret {
            Some(bytes) => crate::key::KeySecret::from_bytes(
                <[u8; crate::key::SECRET_BYTES]>::try_from(bytes.as_slice())
                    .map_err(|_| unreadable("key secret"))?,
            ),
            None if self.is_empty()? => crate::key::KeySecret::fresh(),
            None => return Err(unreadable("key secret")),
        };
        let announcement: Option<i64> = self
            .connection
            .query_row(
                "SELECT next FROM attention_announcements WHERE id = 0",
                [],
                |row| row.get(0),
            )
            .optional()?;
        Ok(StoredState {
            items: self.load_items()?,
            item_acks: self.load_item_acks()?,
            revisions: self.load_revisions()?,
            consumed: self.load_consumed()?,
            gaps: self.load_gaps()?,
            dropped: match dropped {
                Some(value) => as_u64(value, "dropped count")?,
                None => 0,
            },
            keys,
            next_announcement: match announcement {
                Some(value) => as_u64(value, "announcement counter")?,
                None => 0,
            },
            pending_inputs: self.load_pending()?,
            quiet: self.load_quiet()?,
            subjects: self.load_subjects()?,
            review_acks: self.load_review_acks()?,
            changes,
            next_cursor,
            omitted: self.load_omitted()?,
            summaries: self.load_summaries()?,
            visits: self.load_visits()?,
        })
    }

    /// Returns whether this store holds no state at all.
    ///
    /// Every table one write replaces is asked, because a row in any of them was written under a
    /// secret, a key derivation and a schema this build has to be able to read back exactly. It
    /// answers about what is there now rather than about what was ever written: a store whose rows
    /// have all been removed is empty, and nothing in it needs a secret to name.
    fn is_empty(&self) -> Result<bool> {
        for table in TABLES {
            let held: i64 = self.connection.query_row(
                &format!("SELECT EXISTS(SELECT 1 FROM {table})"),
                [],
                |row| row.get(0),
            )?;
            if held != 0 {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Replaces the stored state with `state`, in one transaction.
    ///
    /// # Errors
    ///
    /// Returns [`Error::StoreUnavailable`] when the transaction cannot be committed and
    /// [`Error::StoreUnreadable`] when a value cannot be stored without changing it. Nothing is
    /// left half written: the store is either at the previous state or at this one.
    pub fn save(&mut self, state: &StoredState) -> Result<()> {
        let transaction = self.connection.transaction()?;
        for table in TABLES {
            transaction.execute(&format!("DELETE FROM {table}"), [])?;
        }
        for (source, sequence) in &state.consumed {
            transaction.execute(
                "INSERT INTO attention_consumed (source, sequence) VALUES (?1, ?2)",
                params![source.as_str(), as_i64(*sequence, "consumed cursor")?],
            )?;
        }
        for (position, gap) in state.gaps.iter().enumerate() {
            transaction.execute(
                "INSERT OR REPLACE INTO attention_gaps (source, from_sequence, to_sequence, position)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    gap.source.as_str(),
                    as_i64(gap.from_sequence.get(), "gap start")?,
                    as_i64(gap.to_sequence.get(), "gap end")?,
                    as_index(position, "gap position")?
                ],
            )?;
        }
        for item in &state.items {
            transaction.execute(
                "INSERT INTO attention_items (
                     key, rule, source, session_id, summary, routing, level, steps_taken,
                     occurrences, first_seen_ms, last_seen_ms, notification, last_notified_ms,
                     announced_proven, announced_level, announcements, pending_handoff, uncertain,
                     deferred, anchor_proven
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16,
                           ?17, ?18, ?19, ?20)",
                params![
                    item.key.as_str(),
                    item.rule.as_str(),
                    item.source.as_str(),
                    item.session_id.map(|session| session.to_string()),
                    item.summary,
                    item.routing.as_str(),
                    item.level.as_str(),
                    as_index(item.steps_taken, "escalation step")?,
                    as_i64(item.occurrences, "occurrence count")?,
                    as_i64(item.first_seen_ms.get(), "first seen")?,
                    as_i64(item.last_seen_ms.get(), "last seen")?,
                    item.notification.as_str(),
                    item.last_notified_ms
                        .map(|at| as_i64(at.get(), "last announced"))
                        .transpose()?,
                    i64::from(item.announced_wall_proven),
                    item.announced_level.map(AttentionLevel::as_str),
                    as_i64(item.announcements, "announcement count")?,
                    item.pending_handoff
                        .map(|number| as_i64(number, "announcement number"))
                        .transpose()?,
                    i64::from(item.uncertain),
                    i64::from(item.deferred),
                    i64::from(item.anchor_wall_proven),
                ],
            )?;
        }
        for (actor, revision) in &state.revisions {
            transaction.execute(
                "INSERT INTO attention_actors (actor, revision) VALUES (?1, ?2)",
                params![actor.as_str(), as_i64(*revision, "actor revision")?],
            )?;
        }
        transaction.execute(
            "INSERT INTO attention_dropped (id, items) VALUES (0, ?1)",
            params![as_i64(state.dropped, "dropped count")?],
        )?;
        transaction.execute(
            "INSERT INTO attention_key_secret (id, secret) VALUES (0, ?1)",
            params![state.keys.as_bytes().as_slice()],
        )?;
        transaction.execute(
            "INSERT INTO attention_announcements (id, next) VALUES (0, ?1)",
            params![as_i64(state.next_announcement, "announcement counter")?],
        )?;
        for (actor, acks) in &state.item_acks {
            for (key, ack) in acks {
                transaction.execute(
                    "INSERT INTO attention_item_acks (actor, key, occurrences, at_ms)
                     VALUES (?1, ?2, ?3, ?4)",
                    params![
                        actor.as_str(),
                        key.as_str(),
                        as_i64(ack.occurrences, "acknowledged occurrence")?,
                        as_i64(ack.at_ms.get(), "acknowledged at")?
                    ],
                )?;
            }
        }
        for (question_id, pending) in &state.pending_inputs {
            transaction.execute(
                "INSERT INTO attention_pending_inputs (
                     question_id, session_id, summary, pending_since_ms, reminded, anchor_proven
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    question_id.to_string(),
                    pending.session_id.to_string(),
                    pending.summary,
                    as_i64(pending.pending_since_ms.get(), "pending since")?,
                    i64::from(pending.reminded),
                    i64::from(pending.anchor_wall_proven)
                ],
            )?;
        }
        if let Some(quiet) = state.quiet.as_ref() {
            transaction.execute(
                "INSERT INTO attention_quiet_hours (id, start_minute, end_minute, zone)
                 VALUES (0, ?1, ?2, ?3)",
                params![
                    as_i64(quiet.start_minute.get(), "quiet start")?,
                    as_i64(quiet.end_minute.get(), "quiet end")?,
                    quiet.zone.as_ref()
                ],
            )?;
        }
        for (key, subject) in &state.subjects {
            let (kind, object) = match &subject.subject {
                ReviewSubject::CompletedTurn { turn_id, .. } => ("turn", turn_id.to_string()),
                ReviewSubject::ChangeSet { change_set_id, .. } => {
                    ("change_set", change_set_id.to_string())
                }
            };
            transaction.execute(
                "INSERT INTO attention_review_subjects
                     (key, kind, session_id, object, version, at_ms, sequence)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    key,
                    kind,
                    crate::review::subject_session(&subject.subject).to_string(),
                    object,
                    as_i64(subject.version, "review version")?,
                    as_i64(subject.at_ms.get(), "review recorded at")?,
                    as_i64(subject.sequence, "review order")?
                ],
            )?;
        }
        for (actor, acks) in &state.review_acks {
            for (subject, ack) in acks {
                transaction.execute(
                    "INSERT INTO attention_review_acks (actor, subject, version, at_ms)
                     VALUES (?1, ?2, ?3, ?4)",
                    params![
                        actor.as_str(),
                        subject,
                        as_i64(ack.version, "acknowledged version")?,
                        as_i64(ack.at_ms.get(), "acknowledged at")?
                    ],
                )?;
            }
        }
        for change in &state.changes {
            transaction.execute(
                "INSERT INTO attention_changes (cursor, kind, session_id, summary, at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    as_i64(change.cursor.get(), "change cursor")?,
                    change.kind.as_str(),
                    change.session_id.to_string(),
                    change.summary.as_ref(),
                    as_i64(change.at_ms.get(), "change recorded at")?
                ],
            )?;
        }
        transaction.execute(
            "INSERT INTO attention_change_head (id, next_cursor) VALUES (0, ?1)",
            params![as_i64(state.next_cursor, "change head")?],
        )?;
        for (position, omitted) in state.omitted.iter().enumerate() {
            transaction.execute(
                "INSERT OR REPLACE INTO attention_omitted (
                     at_cursor, source, from_sequence, to_sequence, position
                 ) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    as_i64(omitted.at_cursor, "omitted position")?,
                    omitted.gap.source.as_str(),
                    as_i64(omitted.gap.from_sequence.get(), "omitted start")?,
                    as_i64(omitted.gap.to_sequence.get(), "omitted end")?,
                    as_index(position, "omitted order")?
                ],
            )?;
        }
        for summary in &state.summaries {
            transaction.execute(
                "INSERT INTO attention_summaries (from_cursor, to_cursor, from_ms, to_ms, model, text)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    as_i64(summary.from_cursor.get(), "summary start")?,
                    as_i64(summary.to_cursor.get(), "summary end")?,
                    as_i64(summary.from_ms.get(), "summary from")?,
                    as_i64(summary.to_ms.get(), "summary to")?,
                    summary.model,
                    summary.text
                ],
            )?;
        }
        for (actor, visit) in &state.visits {
            transaction.execute(
                "INSERT INTO attention_visits (actor, cursor, revision) VALUES (?1, ?2, ?3)",
                params![
                    actor.as_str(),
                    as_i64(visit.cursor, "visit cursor")?,
                    as_i64(visit.revision, "visit revision")?
                ],
            )?;
            for (position, view) in visit.views.iter().enumerate() {
                transaction.execute(
                    "INSERT OR REPLACE INTO attention_log_views (
                         actor, view_id, source_offset, filter, position
                     ) VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![
                        actor.as_str(),
                        view.view_id,
                        as_i64(view.source_offset.get(), "view offset")?,
                        view.filter,
                        as_index(position, "view order")?
                    ],
                )?;
            }
        }
        transaction.commit()?;
        Ok(())
    }

    fn load_items(&self) -> Result<Vec<Item>> {
        let mut statement = self.connection.prepare(
            "SELECT key, rule, source, session_id, summary, routing, level, steps_taken,
                    occurrences, first_seen_ms, last_seen_ms, notification, last_notified_ms,
                    announced_proven, announced_level, announcements, pending_handoff, uncertain,
                    deferred, anchor_proven
             FROM attention_items ORDER BY first_seen_ms, key",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, i64>(7)?,
                row.get::<_, i64>(8)?,
                row.get::<_, i64>(9)?,
                row.get::<_, i64>(10)?,
                row.get::<_, String>(11)?,
                row.get::<_, Option<i64>>(12)?,
                row.get::<_, i64>(13)?,
                row.get::<_, Option<String>>(14)?,
                row.get::<_, i64>(15)?,
                row.get::<_, Option<i64>>(16)?,
                row.get::<_, i64>(17)?,
                row.get::<_, i64>(18)?,
                row.get::<_, i64>(19)?,
            ))
        })?;
        let unanchored = Elapsed::starting(HostReading::new(0, 0, false));
        let mut items = Vec::new();
        for row in rows {
            let row = row?;
            let session_id = match row.3 {
                Some(text) => Some(SessionId::from_str(&text).map_err(|_| unreadable("session"))?),
                None => None,
            };
            let last_notified_ms = row
                .12
                .map(|at| as_u64(at, "last announced").map(TimestampMs::new))
                .transpose()?;
            items.push(Item {
                key: AttentionKey::new(row.0).map_err(|_| unreadable("item key"))?,
                rule: AttentionRule::from_wire(&row.1).ok_or_else(|| unreadable("rule"))?,
                source: AttentionSource::from_wire(&row.2).ok_or_else(|| unreadable("source"))?,
                session_id,
                summary: row.4,
                routing: AttentionRouting::from_wire(&row.5)
                    .ok_or_else(|| unreadable("routing"))?,
                level: AttentionLevel::from_wire(&row.6).ok_or_else(|| unreadable("level"))?,
                steps_taken: usize::try_from(row.7).map_err(|_| unreadable("escalation step"))?,
                occurrences: as_u64(row.8, "occurrence count")?,
                first_seen_ms: TimestampMs::new(as_u64(row.9, "first seen")?),
                last_seen_ms: TimestampMs::new(as_u64(row.10, "last seen")?),
                notification: NotificationState::from_wire(&row.11)
                    .ok_or_else(|| unreadable("notification"))?,
                last_notified_ms,
                anchor_wall_proven: row.19 != 0,
                announced_wall_proven: row.13 != 0,
                announced_level: row
                    .14
                    .map(|level| {
                        AttentionLevel::from_wire(&level).ok_or_else(|| unreadable("level"))
                    })
                    .transpose()?,
                announcements: as_u64(row.15, "announcement count")?,
                pending_handoff: row
                    .16
                    .map(|number| as_u64(number, "announcement number"))
                    .transpose()?,
                uncertain: row.17 != 0,
                // Both intervals are re-anchored before anything reads them; the values here stand
                // only until `Attention::open` does that.
                age: unanchored,
                since_notified: last_notified_ms.map(|_| unanchored),
                deferred: row.18 != 0,
            });
        }
        Ok(items)
    }

    fn load_item_acks(&self) -> Result<BTreeMap<ActorId, BTreeMap<AttentionKey, ItemAck>>> {
        let mut statement = self
            .connection
            .prepare("SELECT actor, key, occurrences, at_ms FROM attention_item_acks")?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })?;
        let mut acks: BTreeMap<ActorId, BTreeMap<AttentionKey, ItemAck>> = BTreeMap::new();
        for row in rows {
            let (actor, key, occurrences, at_ms) = row?;
            let actor = ActorId::new(actor).map_err(|_| unreadable("actor"))?;
            let key = AttentionKey::new(key).map_err(|_| unreadable("item key"))?;
            acks.entry(actor).or_default().insert(
                key,
                ItemAck {
                    occurrences: as_u64(occurrences, "acknowledged occurrence")?,
                    at_ms: TimestampMs::new(as_u64(at_ms, "acknowledged at")?),
                },
            );
        }
        Ok(acks)
    }

    fn load_revisions(&self) -> Result<BTreeMap<ActorId, u64>> {
        let mut statement = self
            .connection
            .prepare("SELECT actor, revision FROM attention_actors")?;
        let rows = statement.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })?;
        let mut revisions = BTreeMap::new();
        for row in rows {
            let (actor, revision) = row?;
            revisions.insert(
                ActorId::new(actor).map_err(|_| unreadable("actor"))?,
                as_u64(revision, "actor revision")?,
            );
        }
        Ok(revisions)
    }

    fn load_consumed(&self) -> Result<BTreeMap<AttentionSource, u64>> {
        let mut statement = self
            .connection
            .prepare("SELECT source, sequence FROM attention_consumed")?;
        let rows = statement.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })?;
        let mut consumed = BTreeMap::new();
        for row in rows {
            let (source, sequence) = row?;
            let source = AttentionSource::from_wire(&source).ok_or_else(|| unreadable("source"))?;
            consumed.insert(source, as_u64(sequence, "consumed cursor")?);
        }
        Ok(consumed)
    }

    fn load_gaps(&self) -> Result<Vec<AttentionGap>> {
        let mut statement = self.connection.prepare(
            "SELECT source, from_sequence, to_sequence FROM attention_gaps ORDER BY position, from_sequence",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })?;
        let mut gaps = Vec::new();
        for row in rows {
            let (source, from, to) = row?;
            gaps.push(AttentionGap {
                source: AttentionSource::from_wire(&source).ok_or_else(|| unreadable("source"))?,
                from_sequence: U64::new(as_u64(from, "gap start")?),
                to_sequence: U64::new(as_u64(to, "gap end")?),
            });
        }
        Ok(gaps)
    }

    fn load_pending(&self) -> Result<BTreeMap<QuestionId, PendingInput>> {
        let mut statement = self.connection.prepare(
            "SELECT question_id, session_id, summary, pending_since_ms, reminded, anchor_proven
             FROM attention_pending_inputs",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, i64>(5)?,
            ))
        })?;
        let unanchored = Elapsed::starting(HostReading::new(0, 0, false));
        let mut pending = BTreeMap::new();
        for row in rows {
            let (question_id, session_id, summary, since, reminded, anchored) = row?;
            pending.insert(
                QuestionId::from_str(&question_id).map_err(|_| unreadable("question"))?,
                PendingInput {
                    session_id: SessionId::from_str(&session_id)
                        .map_err(|_| unreadable("session"))?,
                    summary,
                    pending_since_ms: TimestampMs::new(as_u64(since, "pending since")?),
                    waited: unanchored,
                    reminded: reminded != 0,
                    anchor_wall_proven: anchored != 0,
                },
            );
        }
        Ok(pending)
    }

    fn load_quiet(&self) -> Result<Option<QuietHours>> {
        let row: Option<(i64, i64, Option<String>)> = self
            .connection
            .query_row(
                "SELECT start_minute, end_minute, zone FROM attention_quiet_hours WHERE id = 0",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        row.map(|(start, end, zone)| {
            Ok(QuietHours {
                start_minute: U64::new(as_u64(start, "quiet start")?),
                end_minute: U64::new(as_u64(end, "quiet end")?),
                zone: Nullable(zone),
            })
        })
        .transpose()
    }

    fn load_subjects(&self) -> Result<BTreeMap<String, Subject>> {
        let mut statement = self.connection.prepare(
            "SELECT key, kind, session_id, object, version, at_ms, sequence
             FROM attention_review_subjects",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, i64>(6)?,
            ))
        })?;
        let mut subjects = BTreeMap::new();
        for row in rows {
            let (key, kind, session, object, version, at_ms, sequence) = row?;
            let session_id = SessionId::from_str(&session).map_err(|_| unreadable("session"))?;
            let subject = match kind.as_str() {
                "turn" => ReviewSubject::CompletedTurn {
                    session_id,
                    turn_id: AgentTurnId::new(object).map_err(|_| unreadable("turn"))?,
                },
                "change_set" => ReviewSubject::ChangeSet {
                    session_id,
                    change_set_id: ChangeSetId::from_str(&object)
                        .map_err(|_| unreadable("change set"))?,
                },
                _ => return Err(unreadable("review subject kind")),
            };
            // The stored key is checked against the one the subject derives, so a row whose key
            // and subject disagree is refused rather than serving review state under a name that
            // does not describe it.
            if subject_key(&subject) != key {
                return Err(unreadable("review subject key"));
            }
            subjects.insert(
                key,
                Subject {
                    subject,
                    version: as_u64(version, "review version")?,
                    at_ms: TimestampMs::new(as_u64(at_ms, "review recorded at")?),
                    sequence: as_u64(sequence, "review order")?,
                },
            );
        }
        Ok(subjects)
    }

    fn load_review_acks(&self) -> Result<BTreeMap<ActorId, BTreeMap<String, ReviewAck>>> {
        let mut statement = self
            .connection
            .prepare("SELECT actor, subject, version, at_ms FROM attention_review_acks")?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })?;
        let mut acks: BTreeMap<ActorId, BTreeMap<String, ReviewAck>> = BTreeMap::new();
        for row in rows {
            let (actor, subject, version, at_ms) = row?;
            acks.entry(ActorId::new(actor).map_err(|_| unreadable("actor"))?)
                .or_default()
                .insert(
                    subject,
                    ReviewAck {
                        version: as_u64(version, "acknowledged version")?,
                        at_ms: TimestampMs::new(as_u64(at_ms, "acknowledged at")?),
                    },
                );
        }
        Ok(acks)
    }

    fn load_changes(&self) -> Result<VecDeque<SemanticChange>> {
        let mut statement = self.connection.prepare(
            "SELECT cursor, kind, session_id, summary, at_ms FROM attention_changes ORDER BY cursor",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, i64>(4)?,
            ))
        })?;
        let mut changes = VecDeque::new();
        for row in rows {
            let (cursor, kind, session, summary, at_ms) = row?;
            changes.push_back(SemanticChange {
                cursor: U64::new(as_u64(cursor, "change cursor")?),
                kind: SemanticChangeKind::from_wire(&kind)
                    .ok_or_else(|| unreadable("change kind"))?,
                session_id: SessionId::from_str(&session).map_err(|_| unreadable("session"))?,
                summary: Nullable(summary),
                at_ms: TimestampMs::new(as_u64(at_ms, "change recorded at")?),
            });
        }
        Ok(changes)
    }

    fn load_omitted(&self) -> Result<Vec<Omitted>> {
        let mut statement = self.connection.prepare(
            "SELECT at_cursor, source, from_sequence, to_sequence FROM attention_omitted
             ORDER BY position, at_cursor, from_sequence",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })?;
        let mut omitted = Vec::new();
        for row in rows {
            let (at_cursor, source, from, to) = row?;
            omitted.push(Omitted {
                gap: AttentionGap {
                    source: AttentionSource::from_wire(&source)
                        .ok_or_else(|| unreadable("source"))?,
                    from_sequence: U64::new(as_u64(from, "omitted start")?),
                    to_sequence: U64::new(as_u64(to, "omitted end")?),
                },
                at_cursor: as_u64(at_cursor, "omitted position")?,
            });
        }
        Ok(omitted)
    }

    fn load_summaries(&self) -> Result<Vec<ChangeSummary>> {
        let mut statement = self.connection.prepare(
            "SELECT from_cursor, to_cursor, from_ms, to_ms, model, text
             FROM attention_summaries ORDER BY from_cursor",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
            ))
        })?;
        let mut summaries = Vec::new();
        for row in rows {
            let (from_cursor, to_cursor, from_ms, to_ms, model, text) = row?;
            summaries.push(ChangeSummary {
                from_cursor: U64::new(as_u64(from_cursor, "summary start")?),
                to_cursor: U64::new(as_u64(to_cursor, "summary end")?),
                from_ms: TimestampMs::new(as_u64(from_ms, "summary from")?),
                to_ms: TimestampMs::new(as_u64(to_ms, "summary to")?),
                model,
                text,
            });
        }
        Ok(summaries)
    }

    fn load_visits(&self) -> Result<BTreeMap<ActorId, Visit>> {
        let mut statement = self
            .connection
            .prepare("SELECT actor, cursor, revision FROM attention_visits")?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })?;
        let mut visits = BTreeMap::new();
        for row in rows {
            let (actor, cursor, revision) = row?;
            visits.insert(
                ActorId::new(actor).map_err(|_| unreadable("actor"))?,
                Visit {
                    cursor: as_u64(cursor, "visit cursor")?,
                    views: Vec::new(),
                    revision: as_u64(revision, "visit revision")?,
                },
            );
        }
        let mut statement = self.connection.prepare(
            "SELECT actor, view_id, source_offset, filter FROM attention_log_views ORDER BY position",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?,
            ))
        })?;
        for row in rows {
            let (actor, view_id, offset, filter) = row?;
            let actor = ActorId::new(actor).map_err(|_| unreadable("actor"))?;
            visits.entry(actor).or_default().views.push(LogViewState {
                view_id,
                source_offset: U64::new(as_u64(offset, "view offset")?),
                filter,
            });
        }
        Ok(visits)
    }
}
