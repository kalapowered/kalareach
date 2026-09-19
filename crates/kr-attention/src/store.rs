//! The environment feature store.
//!
//! Section 24 gives attention, quiet hours, escalation, review and visit acknowledgements one
//! owner: an environment feature store with per-actor revisions and consumed event cursors, from
//! which the state is reconstructed idempotently. This is that store, a small table set of its own
//! beside the session's journal rather than inside it, because what it holds is a projection of
//! the journal's events rather than a receipt.
//!
//! # Why the whole state is written at once
//!
//! Every write here replaces the stored state in one transaction. The state is bounded by design:
//! a few hundred items, at most a thousand retained changes, a bounded set of views per actor.
//! Writing all of it costs a few kilobytes and buys two properties that matter more than the
//! saving. There is no partial write to reason about, so a crash leaves the store at the last
//! complete state rather than at half of two. And storing the state is then the same operation as
//! reconstructing it, so a rebuild from the retained events and an ordinary write cannot drift.
//!
//! # What is durable, and what is re-anchored
//!
//! Every interval the engine measures is measured on the boot-scoped continuous clock, which means
//! nothing after a restart. So the store records the wall-clock moments instead - when an item was
//! first seen, when a request became pending - and [`crate::host::Attention::open`] re-anchors each
//! interval against the reading it opened at. A host that can prove its wall clock keeps an item's
//! escalation where it was; one that cannot starts the intervals again, which is the conservative
//! answer rather than a ladder climbed by arithmetic on a clock nobody can vouch for.

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
use crate::visit::Visit;

/// The schema this build writes and reads.
pub const SCHEMA_VERSION: i64 = 1;

/// Everything the feature store holds.
#[derive(Clone, Debug, Default)]
pub struct StoredState {
    /// The inbox.
    pub items: Vec<Item>,
    /// Each actor's acknowledgements of items.
    pub item_acks: BTreeMap<ActorId, BTreeMap<AttentionKey, ItemAck>>,
    /// The highest sequence consumed from each source.
    pub consumed: BTreeMap<AttentionSource, u64>,
    /// The ranges of retained events the host can no longer read.
    pub gaps: Vec<AttentionGap>,
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
    /// The ranges of semantic changes retention has taken.
    pub omitted: Vec<AttentionGap>,
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
    CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS consumed (
        source TEXT PRIMARY KEY,
        sequence INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS gaps (
        source TEXT NOT NULL,
        from_sequence INTEGER NOT NULL,
        to_sequence INTEGER NOT NULL,
        position INTEGER NOT NULL,
        PRIMARY KEY (source, from_sequence)
    );
    CREATE TABLE IF NOT EXISTS items (
        key TEXT PRIMARY KEY,
        rule TEXT NOT NULL,
        session_id TEXT,
        summary TEXT NOT NULL,
        routing TEXT NOT NULL,
        level TEXT NOT NULL,
        steps_taken INTEGER NOT NULL,
        occurrences INTEGER NOT NULL,
        first_seen_ms INTEGER NOT NULL,
        last_seen_ms INTEGER NOT NULL,
        notification TEXT NOT NULL,
        uncertain INTEGER NOT NULL,
        attended INTEGER NOT NULL,
        deferred INTEGER NOT NULL,
        notified INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS item_acks (
        actor TEXT NOT NULL,
        key TEXT NOT NULL,
        occurrences INTEGER NOT NULL,
        at_ms INTEGER NOT NULL,
        PRIMARY KEY (actor, key)
    );
    CREATE TABLE IF NOT EXISTS pending_inputs (
        question_id TEXT PRIMARY KEY,
        session_id TEXT NOT NULL,
        summary TEXT NOT NULL,
        pending_since_ms INTEGER NOT NULL,
        reminded INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS quiet_hours (
        id INTEGER PRIMARY KEY CHECK (id = 0),
        start_minute INTEGER NOT NULL,
        end_minute INTEGER NOT NULL,
        zone TEXT
    );
    CREATE TABLE IF NOT EXISTS review_subjects (
        key TEXT PRIMARY KEY,
        kind TEXT NOT NULL,
        session_id TEXT NOT NULL,
        object TEXT NOT NULL,
        version INTEGER NOT NULL,
        at_ms INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS review_acks (
        actor TEXT NOT NULL,
        subject TEXT NOT NULL,
        version INTEGER NOT NULL,
        at_ms INTEGER NOT NULL,
        PRIMARY KEY (actor, subject)
    );
    CREATE TABLE IF NOT EXISTS changes (
        cursor INTEGER PRIMARY KEY,
        kind TEXT NOT NULL,
        session_id TEXT NOT NULL,
        summary TEXT NOT NULL,
        at_ms INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS change_head (
        id INTEGER PRIMARY KEY CHECK (id = 0),
        next_cursor INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS omitted (
        from_cursor INTEGER PRIMARY KEY,
        to_cursor INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS summaries (
        from_cursor INTEGER PRIMARY KEY,
        to_cursor INTEGER NOT NULL,
        from_ms INTEGER NOT NULL,
        to_ms INTEGER NOT NULL,
        model TEXT NOT NULL,
        text TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS visits (
        actor TEXT PRIMARY KEY,
        cursor INTEGER NOT NULL,
        revision INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS log_views (
        actor TEXT NOT NULL,
        view_id TEXT NOT NULL,
        source_offset INTEGER NOT NULL,
        filter TEXT NOT NULL,
        position INTEGER NOT NULL,
        PRIMARY KEY (actor, view_id)
    );
";

fn unreadable(field: &'static str) -> Error {
    Error::StoreUnreadable { field }
}

fn as_i64(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn as_u64(value: i64) -> u64 {
    u64::try_from(value).unwrap_or_default()
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
        connection.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=FULL;
             PRAGMA foreign_keys=ON;",
        )?;
        connection.execute_batch(SCHEMA)?;
        let recorded: Option<i64> = connection
            .query_row("SELECT version FROM schema_version LIMIT 1", [], |row| {
                row.get(0)
            })
            .optional()?;
        match recorded {
            Some(version) if version == SCHEMA_VERSION => {}
            Some(_) => return Err(unreadable("schema version")),
            None => {
                connection.execute(
                    "INSERT INTO schema_version (version) VALUES (?1)",
                    params![SCHEMA_VERSION],
                )?;
            }
        }
        Ok(Self { connection })
    }

    /// Reads the whole stored state back.
    ///
    /// # Errors
    ///
    /// Returns [`Error::StoreUnavailable`] when a read fails and [`Error::StoreUnreadable`] when a
    /// stored value is not one this build can read back.
    pub fn load(&self) -> Result<StoredState> {
        let mut state = StoredState {
            items: self.load_items()?,
            item_acks: self.load_item_acks()?,
            consumed: self.load_consumed()?,
            gaps: self.load_gaps()?,
            pending_inputs: self.load_pending()?,
            quiet: self.load_quiet()?,
            subjects: self.load_subjects()?,
            review_acks: self.load_review_acks()?,
            changes: self.load_changes()?,
            next_cursor: 0,
            omitted: self.load_omitted()?,
            summaries: self.load_summaries()?,
            visits: self.load_visits()?,
        };
        let head: Option<i64> = self
            .connection
            .query_row(
                "SELECT next_cursor FROM change_head WHERE id = 0",
                [],
                |row| row.get(0),
            )
            .optional()?;
        state.next_cursor = head.map_or_else(
            || {
                state
                    .changes
                    .back()
                    .map_or(0, |change| change.cursor.get().saturating_add(1))
            },
            as_u64,
        );
        Ok(state)
    }

    /// Replaces the stored state with `state`, in one transaction.
    ///
    /// # Errors
    ///
    /// Returns [`Error::StoreUnavailable`] when the transaction cannot be committed. Nothing is
    /// left half written: the store is either at the previous state or at this one.
    pub fn save(&mut self, state: &StoredState) -> Result<()> {
        let transaction = self.connection.transaction()?;
        for table in [
            "consumed",
            "gaps",
            "items",
            "item_acks",
            "pending_inputs",
            "quiet_hours",
            "review_subjects",
            "review_acks",
            "changes",
            "change_head",
            "omitted",
            "summaries",
            "visits",
            "log_views",
        ] {
            transaction.execute(&format!("DELETE FROM {table}"), [])?;
        }
        for (source, sequence) in &state.consumed {
            transaction.execute(
                "INSERT INTO consumed (source, sequence) VALUES (?1, ?2)",
                params![source.as_str(), as_i64(*sequence)],
            )?;
        }
        for (position, gap) in state.gaps.iter().enumerate() {
            transaction.execute(
                "INSERT OR REPLACE INTO gaps (source, from_sequence, to_sequence, position)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    gap.source.as_str(),
                    as_i64(gap.from_sequence.get()),
                    as_i64(gap.to_sequence.get()),
                    as_i64(position as u64)
                ],
            )?;
        }
        for item in &state.items {
            transaction.execute(
                "INSERT INTO items (
                     key, rule, session_id, summary, routing, level, steps_taken, occurrences,
                     first_seen_ms, last_seen_ms, notification, uncertain, attended, deferred,
                     notified
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
                params![
                    item.key.as_str(),
                    item.rule.as_str(),
                    item.session_id.map(|session| session.to_string()),
                    item.summary,
                    item.routing.as_str(),
                    item.level.as_str(),
                    as_i64(item.steps_taken as u64),
                    as_i64(item.occurrences),
                    as_i64(item.first_seen_ms.get()),
                    as_i64(item.last_seen_ms.get()),
                    item.notification.as_str(),
                    i64::from(item.uncertain),
                    i64::from(item.attended),
                    i64::from(item.deferred_at.is_some()),
                    i64::from(item.last_notified_at.is_some()),
                ],
            )?;
        }
        for (actor, acks) in &state.item_acks {
            for (key, ack) in acks {
                transaction.execute(
                    "INSERT INTO item_acks (actor, key, occurrences, at_ms) VALUES (?1, ?2, ?3, ?4)",
                    params![
                        actor.as_str(),
                        key.as_str(),
                        as_i64(ack.occurrences),
                        as_i64(ack.at_ms.get())
                    ],
                )?;
            }
        }
        for (question_id, pending) in &state.pending_inputs {
            transaction.execute(
                "INSERT INTO pending_inputs (
                     question_id, session_id, summary, pending_since_ms, reminded
                 ) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    question_id.to_string(),
                    pending.session_id.to_string(),
                    pending.summary,
                    as_i64(pending.pending_since_ms.get()),
                    i64::from(pending.reminded)
                ],
            )?;
        }
        if let Some(quiet) = state.quiet.as_ref() {
            transaction.execute(
                "INSERT INTO quiet_hours (id, start_minute, end_minute, zone)
                 VALUES (0, ?1, ?2, ?3)",
                params![
                    as_i64(quiet.start_minute.get()),
                    as_i64(quiet.end_minute.get()),
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
                "INSERT INTO review_subjects (key, kind, session_id, object, version, at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    key,
                    kind,
                    crate::review::subject_session(&subject.subject).to_string(),
                    object,
                    as_i64(subject.version),
                    as_i64(subject.at_ms.get())
                ],
            )?;
        }
        for (actor, acks) in &state.review_acks {
            for (subject, ack) in acks {
                transaction.execute(
                    "INSERT INTO review_acks (actor, subject, version, at_ms)
                     VALUES (?1, ?2, ?3, ?4)",
                    params![
                        actor.as_str(),
                        subject,
                        as_i64(ack.version),
                        as_i64(ack.at_ms.get())
                    ],
                )?;
            }
        }
        for change in &state.changes {
            transaction.execute(
                "INSERT INTO changes (cursor, kind, session_id, summary, at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    as_i64(change.cursor.get()),
                    change.kind.as_str(),
                    change.session_id.to_string(),
                    change.summary,
                    as_i64(change.at_ms.get())
                ],
            )?;
        }
        transaction.execute(
            "INSERT INTO change_head (id, next_cursor) VALUES (0, ?1)",
            params![as_i64(state.next_cursor)],
        )?;
        for gap in &state.omitted {
            transaction.execute(
                "INSERT OR REPLACE INTO omitted (from_cursor, to_cursor) VALUES (?1, ?2)",
                params![
                    as_i64(gap.from_sequence.get()),
                    as_i64(gap.to_sequence.get())
                ],
            )?;
        }
        for summary in &state.summaries {
            transaction.execute(
                "INSERT INTO summaries (from_cursor, to_cursor, from_ms, to_ms, model, text)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    as_i64(summary.from_cursor.get()),
                    as_i64(summary.to_cursor.get()),
                    as_i64(summary.from_ms.get()),
                    as_i64(summary.to_ms.get()),
                    summary.model,
                    summary.text
                ],
            )?;
        }
        for (actor, visit) in &state.visits {
            transaction.execute(
                "INSERT INTO visits (actor, cursor, revision) VALUES (?1, ?2, ?3)",
                params![actor.as_str(), as_i64(visit.cursor), as_i64(visit.revision)],
            )?;
            for (position, view) in visit.views.iter().enumerate() {
                transaction.execute(
                    "INSERT OR REPLACE INTO log_views (
                         actor, view_id, source_offset, filter, position
                     ) VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![
                        actor.as_str(),
                        view.view_id,
                        as_i64(view.source_offset.get()),
                        view.filter,
                        as_i64(position as u64)
                    ],
                )?;
            }
        }
        transaction.commit()?;
        Ok(())
    }

    fn load_items(&self) -> Result<Vec<Item>> {
        let mut statement = self.connection.prepare(
            "SELECT key, rule, session_id, summary, routing, level, steps_taken, occurrences,
                    first_seen_ms, last_seen_ms, notification, uncertain, attended, deferred,
                    notified
             FROM items ORDER BY first_seen_ms, key",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, i64>(6)?,
                row.get::<_, i64>(7)?,
                row.get::<_, i64>(8)?,
                row.get::<_, i64>(9)?,
                row.get::<_, String>(10)?,
                row.get::<_, i64>(11)?,
                row.get::<_, i64>(12)?,
                row.get::<_, i64>(13)?,
                row.get::<_, i64>(14)?,
            ))
        })?;
        let mut items = Vec::new();
        for row in rows {
            let row = row?;
            let session_id = match row.2 {
                Some(text) => Some(SessionId::from_str(&text).map_err(|_| unreadable("session"))?),
                None => None,
            };
            items.push(Item {
                key: AttentionKey::new(row.0).map_err(|_| unreadable("item key"))?,
                rule: AttentionRule::from_wire(&row.1).ok_or_else(|| unreadable("rule"))?,
                session_id,
                summary: row.3,
                routing: AttentionRouting::from_wire(&row.4)
                    .ok_or_else(|| unreadable("routing"))?,
                level: AttentionLevel::from_wire(&row.5).ok_or_else(|| unreadable("level"))?,
                steps_taken: usize::try_from(row.6).unwrap_or_default(),
                occurrences: as_u64(row.7),
                first_seen_ms: TimestampMs::new(as_u64(row.8)),
                last_seen_ms: TimestampMs::new(as_u64(row.9)),
                notification: NotificationState::from_wire(&row.10)
                    .ok_or_else(|| unreadable("notification"))?,
                uncertain: row.11 != 0,
                attended: row.12 != 0,
                raised_at: 0,
                last_notified_at: (row.14 != 0).then_some(0),
                deferred_at: (row.13 != 0).then_some(0),
            });
        }
        Ok(items)
    }

    fn load_item_acks(&self) -> Result<BTreeMap<ActorId, BTreeMap<AttentionKey, ItemAck>>> {
        let mut statement = self
            .connection
            .prepare("SELECT actor, key, occurrences, at_ms FROM item_acks")?;
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
                    occurrences: as_u64(occurrences),
                    at_ms: TimestampMs::new(as_u64(at_ms)),
                },
            );
        }
        Ok(acks)
    }

    fn load_consumed(&self) -> Result<BTreeMap<AttentionSource, u64>> {
        let mut statement = self
            .connection
            .prepare("SELECT source, sequence FROM consumed")?;
        let rows = statement.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })?;
        let mut consumed = BTreeMap::new();
        for row in rows {
            let (source, sequence) = row?;
            let source = AttentionSource::from_wire(&source).ok_or_else(|| unreadable("source"))?;
            consumed.insert(source, as_u64(sequence));
        }
        Ok(consumed)
    }

    fn load_gaps(&self) -> Result<Vec<AttentionGap>> {
        let mut statement = self.connection.prepare(
            "SELECT source, from_sequence, to_sequence FROM gaps ORDER BY position, from_sequence",
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
                from_sequence: U64::new(as_u64(from)),
                to_sequence: U64::new(as_u64(to)),
            });
        }
        Ok(gaps)
    }

    fn load_pending(&self) -> Result<BTreeMap<QuestionId, PendingInput>> {
        let mut statement = self.connection.prepare(
            "SELECT question_id, session_id, summary, pending_since_ms, reminded
             FROM pending_inputs",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(4)?,
            ))
        })?;
        let mut pending = BTreeMap::new();
        for row in rows {
            let (question_id, session_id, summary, since, reminded) = row?;
            pending.insert(
                QuestionId::from_str(&question_id).map_err(|_| unreadable("question"))?,
                PendingInput {
                    session_id: SessionId::from_str(&session_id)
                        .map_err(|_| unreadable("session"))?,
                    summary,
                    pending_since_ms: TimestampMs::new(as_u64(since)),
                    pending_since: 0,
                    reminded: reminded != 0,
                },
            );
        }
        Ok(pending)
    }

    fn load_quiet(&self) -> Result<Option<QuietHours>> {
        let row: Option<(i64, i64, Option<String>)> = self
            .connection
            .query_row(
                "SELECT start_minute, end_minute, zone FROM quiet_hours WHERE id = 0",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        Ok(row.map(|(start, end, zone)| QuietHours {
            start_minute: U64::new(as_u64(start)),
            end_minute: U64::new(as_u64(end)),
            zone: Nullable(zone),
        }))
    }

    fn load_subjects(&self) -> Result<BTreeMap<String, Subject>> {
        let mut statement = self
            .connection
            .prepare("SELECT key, kind, session_id, object, version, at_ms FROM review_subjects")?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, i64>(5)?,
            ))
        })?;
        let mut subjects = BTreeMap::new();
        for row in rows {
            let (key, kind, session, object, version, at_ms) = row?;
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
                    version: as_u64(version),
                    at_ms: TimestampMs::new(as_u64(at_ms)),
                },
            );
        }
        Ok(subjects)
    }

    fn load_review_acks(&self) -> Result<BTreeMap<ActorId, BTreeMap<String, ReviewAck>>> {
        let mut statement = self
            .connection
            .prepare("SELECT actor, subject, version, at_ms FROM review_acks")?;
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
                        version: as_u64(version),
                        at_ms: TimestampMs::new(as_u64(at_ms)),
                    },
                );
        }
        Ok(acks)
    }

    fn load_changes(&self) -> Result<VecDeque<SemanticChange>> {
        let mut statement = self.connection.prepare(
            "SELECT cursor, kind, session_id, summary, at_ms FROM changes ORDER BY cursor",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, i64>(4)?,
            ))
        })?;
        let mut changes = VecDeque::new();
        for row in rows {
            let (cursor, kind, session, summary, at_ms) = row?;
            changes.push_back(SemanticChange {
                cursor: U64::new(as_u64(cursor)),
                kind: SemanticChangeKind::from_wire(&kind)
                    .ok_or_else(|| unreadable("change kind"))?,
                session_id: SessionId::from_str(&session).map_err(|_| unreadable("session"))?,
                summary,
                at_ms: TimestampMs::new(as_u64(at_ms)),
            });
        }
        Ok(changes)
    }

    fn load_omitted(&self) -> Result<Vec<AttentionGap>> {
        let mut statement = self
            .connection
            .prepare("SELECT from_cursor, to_cursor FROM omitted ORDER BY from_cursor")?;
        let rows =
            statement.query_map([], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)))?;
        let mut omitted = Vec::new();
        for row in rows {
            let (from, to) = row?;
            omitted.push(AttentionGap {
                source: AttentionSource::Semantic,
                from_sequence: U64::new(as_u64(from)),
                to_sequence: U64::new(as_u64(to)),
            });
        }
        Ok(omitted)
    }

    fn load_summaries(&self) -> Result<Vec<ChangeSummary>> {
        let mut statement = self.connection.prepare(
            "SELECT from_cursor, to_cursor, from_ms, to_ms, model, text
             FROM summaries ORDER BY from_cursor",
        )?;
        let rows = statement.query_map([], |row| {
            Ok(ChangeSummary {
                from_cursor: U64::new(as_u64(row.get::<_, i64>(0)?)),
                to_cursor: U64::new(as_u64(row.get::<_, i64>(1)?)),
                from_ms: TimestampMs::new(as_u64(row.get::<_, i64>(2)?)),
                to_ms: TimestampMs::new(as_u64(row.get::<_, i64>(3)?)),
                model: row.get::<_, String>(4)?,
                text: row.get::<_, String>(5)?,
            })
        })?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    fn load_visits(&self) -> Result<BTreeMap<ActorId, Visit>> {
        let mut statement = self
            .connection
            .prepare("SELECT actor, cursor, revision FROM visits")?;
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
                    cursor: as_u64(cursor),
                    views: Vec::new(),
                    revision: as_u64(revision),
                },
            );
        }
        let mut statement = self.connection.prepare(
            "SELECT actor, view_id, source_offset, filter FROM log_views ORDER BY position",
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
                source_offset: U64::new(as_u64(offset)),
                filter,
            });
        }
        Ok(visits)
    }
}
