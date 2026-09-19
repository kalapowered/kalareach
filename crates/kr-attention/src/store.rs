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
//! nothing outside its own boot. So the store records two things for each of them - when an item
//! was first seen, when it was last announced, when a request became pending - the wall-clock
//! moment, which says when it happened for a person reading the record, and the anchor: the
//! continuous reading at that moment and the boot it was taken in.
//! [`crate::host::Attention::open`] re-anchors each interval from that anchor when the boot is
//! still this one, which is exact, and starts it again when it is not. A row that carries half an
//! anchor is refused rather than half measured. No interval is worked out from the wall-clock
//! moments: a clock this host trusts is still a clock somebody can set forward, and two readings
//! it vouches for are not two readings on one scale.
//!
//! # One owner
//!
//! Every write here replaces the whole state, and it is made from the copy its owner has been
//! holding, so two owners of one store would each replace the other's work with a picture of the
//! world that predates it. There is one owner instead, and the claim is a **row in the store**:
//! opening it reads that row and writes its own under the same transaction that reads the state,
//! so every name for one database reaches one claim because there is nothing to key on but the
//! database. A claim from a boot that has ended, or one this boot has not refreshed within
//! [`OWNER_LEASE_MS`], is taken; anything else is a live owner and the second opener is told so
//! with [`Error::StoreHeld`]. Nothing here takes a second handle on the file: on the Unix family,
//! closing any descriptor for a file drops every lock the process holds on it, so a handle opened
//! beside SQLite's own would release the locks the receipt journal and the question ledger are
//! holding on the same file.
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
use crate::error::{Error, Result, StoreFault};
use crate::review::{ReviewAck, Subject, subject_key};
use crate::time::{Anchor, BootMark, Elapsed, HostReading};
use crate::visit::{Omitted, Visit};

/// The schema this build writes and reads.
///
/// A store written under any other version is refused rather than read. Two things in here are
/// derived rather than stored on their own - an item's key, and the order a review page continues
/// by - so a row written under a different derivation would be read under a name that does not
/// describe it, which is worse than not reading it at all. Every row also has to carry the anchor
/// each of its intervals is measured from, and a row that predates those columns carries none.
pub const SCHEMA_VERSION: i64 = 7;

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
    /// Who holds this store, when anybody does.
    pub owner: Option<Owner>,
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

/// What one process must say to own a store, and how long that claim stands unrefreshed.
///
/// The claim is a row in the store itself, so every name for one database reaches one claim by
/// construction: there is nothing to key on but the database. It carries the process that made it,
/// the boot that process is running in, and the continuous reading it was last refreshed at, which
/// is the only clock an interval may be measured on.
///
/// A claim from another boot is stale by definition: that boot has ended and so has its process. A
/// claim from this boot that has not been refreshed within the lease is stale too, because an
/// owner that is running refreshes it on every write, and the host's own maintenance writes at
/// least once a minute. Anything else is a live owner, and a second opener is told so.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Owner {
    /// What tells this claim apart from every other, including another in the same process.
    ///
    /// A process identifier cannot do it: two owners inside one process share one, and a process
    /// that died and whose number was given to another is not the owner that number names. This is
    /// random, and one value holds one of them for its life.
    pub claim: u64,
    /// The process that holds the store, for a person reading the refusal.
    pub process: u32,
    /// The boot that process is running in.
    pub boot: BootMark,
    /// The continuous reading the claim was last refreshed at, within that boot.
    pub refreshed_ms: u64,
}

/// How long a claim stands without being refreshed before another opener may take it.
///
/// Ten minutes against a maintenance loop that writes every minute: long enough that an owner
/// which is merely busy is never taken from, short enough that a process killed without unwinding
/// does not hold a session's store until the machine restarts.
pub const OWNER_LEASE_MS: u64 = 10 * 60_000;

impl Owner {
    /// Returns this process's claim at this reading.
    #[must_use]
    pub fn here(claim: u64, reading: HostReading) -> Self {
        Self {
            claim,
            process: std::process::id(),
            boot: reading.boot,
            refreshed_ms: reading.continuous_ms,
        }
    }

    /// Returns a claim no other owner holds.
    ///
    /// Sixty-three bits of it, because the store writes an integer it can read back exactly and a
    /// row it could not is refused rather than stored. Sixty-three bits is not a number two owners
    /// draw the same of.
    #[must_use]
    pub fn fresh_claim() -> u64 {
        let bytes = *uuid::Uuid::new_v4().as_bytes();
        let drawn = u64::from_be_bytes(bytes[..8].try_into().expect("eight of sixteen bytes"));
        drawn >> 1
    }

    /// Whether this claim still stands against `reading`, for an owner other than `claim`.
    ///
    /// A claim from a boot that has ended is not standing: that boot's processes are gone. One
    /// from this boot stands until its lease runs out, which an owner that is running refreshes on
    /// every write. **What this cannot ask** is whether a process on this boot is still alive, so
    /// an owner that was killed without unwinding holds its store until the lease does run out.
    #[must_use]
    pub fn stands_against(&self, claim: u64, reading: HostReading) -> bool {
        self.claim != claim
            && self.boot == reading.boot
            && reading.continuous_ms.saturating_sub(self.refreshed_ms) < OWNER_LEASE_MS
    }
}

/// How a store is opened: a file, never a URI.
///
/// SQLite reads a name beginning `file:` as a URI, and `:memory:` as a database of its own, so the
/// path is resolved before it is handed over and the flags leave URI interpretation out. Neither
/// is what names the owner - the row in the database is - but a string that opened a different
/// file would make a second database rather than a second owner of one.
const FILE_ONLY: rusqlite::OpenFlags = rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
    .union(rusqlite::OpenFlags::SQLITE_OPEN_CREATE)
    .union(rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX);

/// Returns a path SQLite can be given, resolved and absolute, for a file that may not exist yet.
fn resolve(path: &Path) -> Result<std::path::PathBuf> {
    let unavailable = |error: &dyn core::fmt::Display| Error::StoreUnavailable {
        kind: StoreFault::Other,
        detail: format!("{} cannot be resolved: {error}", path.display()),
    };
    if let Ok(resolved) = std::fs::canonicalize(path) {
        return Ok(resolved);
    }
    let name = path.file_name().ok_or_else(|| Error::StoreUnavailable {
        kind: StoreFault::Other,
        detail: format!("{} names no feature store", path.display()),
    })?;
    let directory = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    Ok(std::fs::canonicalize(directory)
        .map_err(|error| unavailable(&error))?
        .join(name))
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
        announced_boot TEXT,
        announced_continuous_ms INTEGER,
        anchor_boot TEXT,
        anchor_continuous_ms INTEGER,
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
    CREATE TABLE IF NOT EXISTS attention_owner (
        id INTEGER PRIMARY KEY CHECK (id = 0),
        claim INTEGER NOT NULL,
        process INTEGER NOT NULL,
        boot TEXT NOT NULL,
        refreshed_ms INTEGER NOT NULL
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
        anchor_boot TEXT,
        anchor_continuous_ms INTEGER
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
    "attention_owner",
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

/// Returns the anchor a pair of stored columns holds, or `None` when the row carries none.
///
/// A row with one half of an anchor is refused: an anchor is a continuous reading *and* the boot
/// it was taken in, and half of one would measure an interval against a clock that may have
/// restarted since.
fn anchor(
    boot: Option<&str>,
    continuous: Option<i64>,
    field: &'static str,
) -> Result<Option<Anchor>> {
    match (boot, continuous) {
        (None, None) => Ok(None),
        (Some(boot), Some(continuous)) => Ok(Some(Anchor::new(
            BootMark::from_hex(boot).ok_or_else(|| unreadable(field))?,
            as_u64(continuous, field)?,
        ))),
        _ => Err(unreadable(field)),
    }
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
    /// Returns [`Error::StoreHeld`] when another live owner already holds this store,
    /// [`Error::StoreUnavailable`] when the file cannot be opened or the schema cannot be created,
    /// and [`Error::StoreUnreadable`] when the file records a schema this build does not know.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        // The resolved path, never the name that reached here: SQLite reads a name beginning
        // `file:` as a URI and `:memory:` as a database of its own, and neither is the file this
        // store is meant to be. Who owns the store is a row inside it, not anything about a name.
        let connection = Connection::open_with_flags(resolve(path.as_ref())?, FILE_ONLY)?;
        Self::prepare(connection)
    }

    /// Opens the store inside the worker's private journal, or in memory when there is none.
    ///
    /// The journal opened the file first and owns its own schema version; these tables sit beside
    /// it under their own names and their own version row, so neither migration reads the other's.
    ///
    /// # Errors
    ///
    /// Returns [`Error::StoreHeld`] when another live owner already holds this store,
    /// [`Error::StoreUnavailable`] when the file cannot be opened or the schema cannot be created,
    /// and [`Error::StoreUnreadable`] when the file records a schema this build does not know.
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
        Self::load_from(&self.connection)
    }

    /// Reads the whole state through a connection the caller owns, which may be a transaction.
    fn load_from(connection: &Connection) -> Result<StoredState> {
        let changes = Self::load_changes(connection)?;
        let head: Option<i64> = connection
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
        let dropped: Option<i64> = connection
            .query_row(
                "SELECT items FROM attention_dropped WHERE id = 0",
                [],
                |row| row.get(0),
            )
            .optional()?;
        let secret: Option<Vec<u8>> = connection
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
            None if Self::is_empty(connection)? => crate::key::KeySecret::fresh(),
            None => return Err(unreadable("key secret")),
        };
        let owner: Option<(i64, i64, String, i64)> = connection
            .query_row(
                "SELECT claim, process, boot, refreshed_ms FROM attention_owner WHERE id = 0",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;
        let owner = match owner {
            Some((claim, process, boot, refreshed)) => Some(Owner {
                claim: as_u64(claim, "owner claim")?,
                process: u32::try_from(process).map_err(|_| unreadable("owner process"))?,
                boot: BootMark::from_hex(&boot).ok_or_else(|| unreadable("owner boot"))?,
                refreshed_ms: as_u64(refreshed, "owner lease")?,
            }),
            None => None,
        };
        let announcement: Option<i64> = connection
            .query_row(
                "SELECT next FROM attention_announcements WHERE id = 0",
                [],
                |row| row.get(0),
            )
            .optional()?;
        Ok(StoredState {
            items: Self::load_items(connection)?,
            item_acks: Self::load_item_acks(connection)?,
            revisions: Self::load_revisions(connection)?,
            consumed: Self::load_consumed(connection)?,
            gaps: Self::load_gaps(connection)?,
            dropped: match dropped {
                Some(value) => as_u64(value, "dropped count")?,
                None => 0,
            },
            keys,
            owner,
            next_announcement: match announcement {
                Some(value) => as_u64(value, "announcement counter")?,
                None => 0,
            },
            pending_inputs: Self::load_pending(connection)?,
            quiet: Self::load_quiet(connection)?,
            subjects: Self::load_subjects(connection)?,
            review_acks: Self::load_review_acks(connection)?,
            changes,
            next_cursor,
            omitted: Self::load_omitted(connection)?,
            summaries: Self::load_summaries(connection)?,
            visits: Self::load_visits(connection)?,
        })
    }

    /// Returns whether this store holds no state at all.
    ///
    /// Every table one write replaces is asked, because a row in any of them was written under a
    /// secret, a key derivation and a schema this build has to be able to read back exactly. It
    /// answers about what is there now rather than about what was ever written: a store whose rows
    /// have all been removed is empty, and nothing in it needs a secret to name.
    fn is_empty(connection: &Connection) -> Result<bool> {
        for table in TABLES {
            let held: i64 = connection.query_row(
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

    /// Reads the state back, hands it to `settle`, and writes what comes back, with nothing able
    /// to come between the three.
    ///
    /// This is what a session opening its store does. Re-anchoring an interval reads the state and
    /// writes it again, and a whole-state write replaces everything: another connection that
    /// committed between the read and the write would have its work replaced by the older state
    /// this one had read. So the write lock is taken before the read rather than at the write,
    /// which is the whole of the difference. It is held for one read and one write and then
    /// released, so the other owners of tables in the same file are not kept out.
    ///
    /// # Errors
    ///
    /// Returns whatever `settle` returns, [`Error::StoreUnavailable`] when the transaction cannot
    /// be taken or committed, and [`Error::StoreUnreadable`] for a value this build cannot read
    /// back or write down. Nothing is left half written.
    pub fn recover<T>(
        &mut self,
        settle: impl FnOnce(StoredState) -> Result<(StoredState, T)>,
    ) -> Result<T> {
        let transaction = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let stored = Self::load_from(&transaction)?;
        let (state, answer) = settle(stored)?;
        Self::save_into(&transaction, &state)?;
        transaction.commit()?;
        Ok(answer)
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
        Self::save_into(&transaction, state)?;
        transaction.commit()?;
        Ok(())
    }

    /// Writes the whole state through a transaction the caller owns.
    fn save_into(transaction: &Connection, state: &StoredState) -> Result<()> {
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
                     announced_boot, announced_continuous_ms, announced_level, announcements,
                     pending_handoff, uncertain, deferred, anchor_boot, anchor_continuous_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16,
                           ?17, ?18, ?19, ?20, ?21, ?22)",
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
                    item.announced_anchor.map(|anchor| anchor.boot.to_hex()),
                    item.announced_anchor
                        .map(|anchor| as_i64(anchor.continuous_ms, "announced anchor"))
                        .transpose()?,
                    item.announced_level.map(AttentionLevel::as_str),
                    as_i64(item.announcements, "announcement count")?,
                    item.pending_handoff
                        .map(|number| as_i64(number, "announcement number"))
                        .transpose()?,
                    i64::from(item.uncertain),
                    i64::from(item.deferred),
                    item.anchor.map(|anchor| anchor.boot.to_hex()),
                    item.anchor
                        .map(|anchor| as_i64(anchor.continuous_ms, "item anchor"))
                        .transpose()?,
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
        if let Some(owner) = state.owner {
            transaction.execute(
                "INSERT INTO attention_owner (id, claim, process, boot, refreshed_ms)
                 VALUES (0, ?1, ?2, ?3, ?4)",
                params![
                    as_i64(owner.claim, "owner claim")?,
                    i64::from(owner.process),
                    owner.boot.to_hex(),
                    as_i64(owner.refreshed_ms, "owner lease")?
                ],
            )?;
        }
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
                     question_id, session_id, summary, pending_since_ms, reminded, anchor_boot,
                     anchor_continuous_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    question_id.to_string(),
                    pending.session_id.to_string(),
                    pending.summary,
                    as_i64(pending.pending_since_ms.get(), "pending since")?,
                    i64::from(pending.reminded),
                    pending.anchor.map(|anchor| anchor.boot.to_hex()),
                    pending
                        .anchor
                        .map(|anchor| as_i64(anchor.continuous_ms, "pending anchor"))
                        .transpose()?
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
        Ok(())
    }

    fn load_items(connection: &Connection) -> Result<Vec<Item>> {
        let mut statement = connection.prepare(
            "SELECT key, rule, source, session_id, summary, routing, level, steps_taken,
                    occurrences, first_seen_ms, last_seen_ms, notification, last_notified_ms,
                    announced_boot, announced_continuous_ms, announced_level, announcements,
                    pending_handoff, uncertain, deferred, anchor_boot, anchor_continuous_ms
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
                row.get::<_, Option<String>>(13)?,
                row.get::<_, Option<i64>>(14)?,
                row.get::<_, Option<String>>(15)?,
                row.get::<_, i64>(16)?,
                row.get::<_, Option<i64>>(17)?,
                row.get::<_, i64>(18)?,
                row.get::<_, i64>(19)?,
                row.get::<_, Option<String>>(20)?,
                row.get::<_, Option<i64>>(21)?,
            ))
        })?;
        let unanchored = Elapsed::starting(HostReading::new(BootMark::default(), 0, 0, false));
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
                announced_anchor: anchor(row.13.as_deref(), row.14, "announced anchor")?,
                announced_level: row
                    .15
                    .map(|level| {
                        AttentionLevel::from_wire(&level).ok_or_else(|| unreadable("level"))
                    })
                    .transpose()?,
                announcements: as_u64(row.16, "announcement count")?,
                pending_handoff: row
                    .17
                    .map(|number| as_u64(number, "announcement number"))
                    .transpose()?,
                uncertain: row.18 != 0,
                anchor: anchor(row.20.as_deref(), row.21, "item anchor")?,
                // Both intervals are re-anchored before anything reads them; the values here stand
                // only until `Attention::open` does that.
                age: unanchored,
                since_notified: last_notified_ms.map(|_| unanchored),
                deferred: row.19 != 0,
            });
        }
        Ok(items)
    }

    fn load_item_acks(
        connection: &Connection,
    ) -> Result<BTreeMap<ActorId, BTreeMap<AttentionKey, ItemAck>>> {
        let mut statement =
            connection.prepare("SELECT actor, key, occurrences, at_ms FROM attention_item_acks")?;
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

    fn load_revisions(connection: &Connection) -> Result<BTreeMap<ActorId, u64>> {
        let mut statement = connection.prepare("SELECT actor, revision FROM attention_actors")?;
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

    fn load_consumed(connection: &Connection) -> Result<BTreeMap<AttentionSource, u64>> {
        let mut statement =
            connection.prepare("SELECT source, sequence FROM attention_consumed")?;
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

    fn load_gaps(connection: &Connection) -> Result<Vec<AttentionGap>> {
        let mut statement = connection.prepare(
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

    fn load_pending(connection: &Connection) -> Result<BTreeMap<QuestionId, PendingInput>> {
        let mut statement = connection.prepare(
            "SELECT question_id, session_id, summary, pending_since_ms, reminded, anchor_boot,
                    anchor_continuous_ms
             FROM attention_pending_inputs",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, Option<String>>(5)?,
                row.get::<_, Option<i64>>(6)?,
            ))
        })?;
        let unanchored = Elapsed::starting(HostReading::new(BootMark::default(), 0, 0, false));
        let mut pending = BTreeMap::new();
        for row in rows {
            let (question_id, session_id, summary, since, reminded, boot, continuous) = row?;
            pending.insert(
                QuestionId::from_str(&question_id).map_err(|_| unreadable("question"))?,
                PendingInput {
                    session_id: SessionId::from_str(&session_id)
                        .map_err(|_| unreadable("session"))?,
                    summary,
                    pending_since_ms: TimestampMs::new(as_u64(since, "pending since")?),
                    waited: unanchored,
                    reminded: reminded != 0,
                    anchor: anchor(boot.as_deref(), continuous, "pending anchor")?,
                },
            );
        }
        Ok(pending)
    }

    fn load_quiet(connection: &Connection) -> Result<Option<QuietHours>> {
        let row: Option<(i64, i64, Option<String>)> = connection
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

    fn load_subjects(connection: &Connection) -> Result<BTreeMap<String, Subject>> {
        let mut statement = connection.prepare(
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

    fn load_review_acks(
        connection: &Connection,
    ) -> Result<BTreeMap<ActorId, BTreeMap<String, ReviewAck>>> {
        let mut statement = connection
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

    fn load_changes(connection: &Connection) -> Result<VecDeque<SemanticChange>> {
        let mut statement = connection.prepare(
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

    fn load_omitted(connection: &Connection) -> Result<Vec<Omitted>> {
        let mut statement = connection.prepare(
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

    fn load_summaries(connection: &Connection) -> Result<Vec<ChangeSummary>> {
        let mut statement = connection.prepare(
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

    fn load_visits(connection: &Connection) -> Result<BTreeMap<ActorId, Visit>> {
        let mut statement =
            connection.prepare("SELECT actor, cursor, revision FROM attention_visits")?;
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
        let mut statement = connection.prepare(
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
