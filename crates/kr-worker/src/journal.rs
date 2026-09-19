//! The worker's private receipt journal.
//!
//! Section 9 makes this the durable identity of every mutation the session has seen, and section
//! 24 makes it crash-durable: SQLite in write-ahead-logging mode with full synchronisation, so an
//! acknowledgement and a dispatch marker are on disk before they are acted on.
//!
//! Three rules shape the whole design.
//!
//! * **The intent is committed before it is acknowledged.** A caller that receives `accepted` can
//!   rely on the host still knowing about the action after a crash.
//! * **The dispatch marker is committed before the external effect.** That is what makes a lost
//!   outcome recoverable: on restart a marker without an authoritative answer becomes `unknown`,
//!   and that identifier is never dispatched again. Redispatching would risk doing the thing
//!   twice, and there is no way to tell from here whether it already happened.
//! * **De-duplication is keyed by `(verified_actor_id, action_id)` with the payload digest.** The
//!   same actor retrying the same action gets the same receipt back; the same identifier carrying
//!   a different payload is an `ID_CONFLICT`, not a second action.

use kr_protocol::action::{
    ActionObservation, ObservationProvenance, ObservedResult, PossiblyExecutedAction,
};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::ids::{ActionId, ActorId, RequestId};
use kr_protocol::method::{MethodName, MethodVersion};
use kr_protocol::receipt::{Receipt, ReceiptState, RejectionReason};
use kr_protocol::scalars::{Digest256, Nullable, TimestampMs, U64, Uuid};
use rusqlite::{Connection, OptionalExtension as _, params};

use crate::error::{Result, WorkerError};

/// How long de-duplication records are retained, in milliseconds.
pub const RETENTION_MS: u64 = 30 * 24 * 60 * 60 * 1000;

/// The schema version this build reads.
///
/// It is [`crate::persistence::migration::CURRENT`], stated here because this is the store the
/// ladder brings forward and a reader of the journal should not have to go looking.
pub const SCHEMA_VERSION: i64 = crate::persistence::migration::CURRENT;

/// How often a live journal prunes records past the retention period.
///
/// Pruning at startup alone leaves a worker that has been up for longer than the retention period
/// holding records it should have forgotten. An hour is short against 30 days and long against
/// anything on the mutation path, so the cost falls on neither.
pub const PRUNE_INTERVAL_MS: u64 = 60 * 60 * 1000;

/// How many revocations may have names this journal still owes the daemon.
///
/// A revocation's names are kept until the daemon has taken them, whatever has been installed
/// since, because section 9 requires the actions a fence could not take back to be named in the
/// *result*. A daemon that stops asking would otherwise grow this journal one revocation at a
/// time, so this is where that stops: past it the oldest revocation's names go, and the count of
/// what went takes their place, so a page of them says how many are missing rather than carrying
/// nothing and reading as a fence that named nothing.
pub const MAX_HELD_REVOCATIONS: usize = 8;

/// One mutation being admitted.
#[derive(Clone, Debug)]
pub struct Submission {
    /// The host-verified actor. A caller never asserts its own provenance.
    pub actor_id: ActorId,
    /// The durable operation identity.
    pub action_id: ActionId,
    /// The method the digest covers.
    pub method: MethodName,
    /// The method version the digest covers.
    pub method_version: MethodVersion,
    /// The digest of everything the mutation names.
    pub payload_digest: Digest256,
    /// The digest of what the mutation asks for, without the identifier, window, lifetime or
    /// preconditions that differ between a first attempt and the later request that supersedes it.
    pub subject_digest: Digest256,
    /// The complete mutation envelope, canonically encoded.
    ///
    /// A digest proves an identifier was reused with a different payload. It cannot tell a
    /// recovering worker what the action was going to do, so the envelope itself is kept: the
    /// target, the preconditions, the window and the parameters, exactly as they arrived.
    pub intent: Vec<u8>,
    /// The deadline the host derived at acceptance. An exact retry never gets a new one.
    pub accepted_deadline_ms: Option<TimestampMs>,
    /// When the submission arrived.
    pub now_ms: TimestampMs,
}

/// What admitting a submission produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Admission {
    /// The receipt, new or retained.
    pub receipt: Receipt,
    /// True when an existing receipt was returned instead of a new one being committed.
    pub deduplicated: bool,
}

/// What fencing this session for a revocation could and could not take back.
///
/// The names live in the journal rather than in this value, because a revocation's result has to
/// survive what a worker's memory does not: a fence that failed part way, an acknowledgement lost
/// on the way back, a page of evidence whose exchange failed, and the worker's own restart. What
/// this carries is the counts one pass produced, which is what a caller needs to know whether the
/// pass finished.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Fenced {
    /// How many undispatched intents this pass rejected.
    pub rejected: u64,
    /// How many actions past their dispatch marker this pass named.
    pub possibly_executed: u64,
}

impl Fenced {
    /// How many names this pass produced.
    #[must_use]
    pub const fn named(&self) -> u64 {
        self.rejected.saturating_add(self.possibly_executed)
    }
}

/// One page of a revocation's fence evidence, as an acknowledgement carries it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EvidencePage {
    /// The names in this page, in the order the journal holds them.
    pub rejected: Vec<kr_protocol::action::FencedAction>,
    /// The actions past their dispatch marker in this page.
    pub possibly_executed: Vec<PossiblyExecutedAction>,
    /// How many names this journal holds that this page did not carry.
    pub remaining: u64,
    /// How many of this revocation's names this journal no longer holds.
    ///
    /// A revocation's names are kept until the daemon has taken them, and a bounded number of
    /// revocations are kept at once. Past that the oldest names go, and this is what takes their
    /// place: a page that carried nothing because there is nothing left says how much is missing
    /// rather than reading as a fence that named nothing.
    pub omitted: u64,
}

impl EvidencePage {
    /// Returns what this page says, as an acknowledgement carries it.
    #[must_use]
    pub fn evidence(&self) -> kr_protocol::action::FenceEvidence {
        kr_protocol::action::FenceEvidence {
            rejected_actions: self.rejected.clone(),
            possibly_executed: self.possibly_executed.clone(),
            remaining: U64::new(self.remaining),
            omitted: U64::new(self.omitted),
        }
    }
}

/// One transition a receipt is being advanced through.
///
/// The four travel together because they are one change: the state it reaches, why it reached it,
/// the error that explains it and when it happened.
struct Transition {
    state: ReceiptState,
    reason: Option<RejectionReason>,
    error: Option<ProtocolError>,
    now_ms: TimestampMs,
}

/// One recorded change to a receipt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceiptEvent {
    /// The position in the journal's event order.
    pub sequence: u64,
    /// The actor the receipt belongs to.
    pub actor_id: ActorId,
    /// The action.
    pub action_id: ActionId,
    /// The receipt revision this event records.
    pub revision: U64,
    /// The state the receipt reached.
    pub state: ReceiptState,
    /// When it was recorded.
    pub recorded_at_ms: TimestampMs,
}

/// The worker's private journal.
#[derive(Debug)]
pub struct Journal {
    connection: Connection,
    pruned_at_ms: u64,
    /// The condition this journal publishes, and what reads it decides.
    ///
    /// Section 24 makes a worker whose durable store has stopped answering refuse new durable
    /// mutations before dispatch while the terminal stays usable, so the condition has to be
    /// readable by everything that decides whether to start work. It is shared rather than
    /// returned, because a consumer needs to be woken when it changes as well as to ask now.
    health: std::sync::Arc<crate::persistence::fault::JournalHealth>,
    /// The boot this journal is being written in, recorded once.
    ///
    /// A record from another boot cannot have a live freshness window, because the windows a host
    /// issues live in its memory and the host has restarted. That is what lets retention treat
    /// this boot's records and an earlier boot's differently.
    boot: Option<Vec<u8>>,
}

/// The continuous reading below which a record this boot wrote is old enough to collect.
///
/// A freshness window lasts at most [`kr_protocol::limits::MAX_ACTION_WINDOW`] on the machine's
/// continuous clock, and no step of the wall clock shortens that. A record whose continuous
/// reading is above this floor therefore belongs to an action whose own window may still admit
/// the original request, which is exactly what its de-duplication record has to answer.
fn continuous_floor() -> i64 {
    i64::try_from(
        kr_ipc::clock::boot_elapsed_ms()
            .saturating_sub(kr_protocol::limits::MAX_ACTION_WINDOW.get()),
    )
    .unwrap_or(i64::MAX)
}

impl Journal {
    /// Opens a journal on disk.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::JournalUnavailable`] when the database cannot be opened or migrated.
    pub fn open(path: impl AsRef<std::path::Path>) -> Result<Self> {
        let connection = Connection::open(path.as_ref()).map_err(unavailable)?;
        Self::prepare(connection)
    }

    /// Opens a journal that exists only for the life of this process.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::JournalUnavailable`] when the database cannot be created.
    pub fn in_memory() -> Result<Self> {
        Self::prepare(Connection::open_in_memory().map_err(unavailable)?)
    }

    fn prepare(connection: Connection) -> Result<Self> {
        // Write-ahead logging with full synchronisation. Section 24 permits exactly this and
        // forbids weakening it to reach a latency number; nothing on the keystroke path writes
        // here, so the cost falls only on durable mutations.
        connection
            .pragma_update(None, "journal_mode", "WAL")
            .map_err(unavailable)?;
        connection
            .pragma_update(None, "synchronous", "FULL")
            .map_err(unavailable)?;
        connection
            .pragma_update(None, "foreign_keys", "ON")
            .map_err(unavailable)?;
        let journal = Self {
            connection,
            pruned_at_ms: 0,
            health: crate::persistence::fault::JournalHealth::shared(),
            boot: kr_ipc::identity::boot_identity()
                .ok()
                .map(|boot| boot.value.as_slice().to_vec()),
        };
        journal.migrate()?;
        Ok(journal)
    }

    /// Brings the database to the schema this build reads.
    ///
    /// The order is the contract, and it is the order a reader would not guess: the recorded
    /// version is read **before** anything is created. A `CREATE TABLE IF NOT EXISTS` does not add
    /// a column to a table that already exists, so creating this build's schema over an older one
    /// would leave the old shape in place and then fail on the first index that names a new
    /// column. The migrations run first, and only then does the current schema get created for a
    /// database that has none.
    fn migrate(&self) -> Result<()> {
        self.connection
            .execute_batch("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL);")
            .map_err(|error| faulted(&self.health, error))?;
        let recorded: Option<i64> = self
            .connection
            .query_row("SELECT version FROM schema_version", [], |row| row.get(0))
            .optional()
            .map_err(|error| faulted(&self.health, error))?;
        match recorded {
            None => {
                self.create_current_schema()?;
                self.connection
                    .execute(
                        "INSERT INTO schema_version (version) VALUES (?1)",
                        params![SCHEMA_VERSION],
                    )
                    .map_err(|error| faulted(&self.health, error))?;
            }
            Some(version) => {
                // The ladder decides which steps exist and in what order, and it refuses both
                // directions this build must not read: a store a newer build wrote, and one older
                // than the ladder starts from, which names the importer instead of being restored
                // in part.
                let steps = crate::persistence::migration::plan(version)
                    .map_err(|error| unavailable_detail_owned(error.to_string()))?;
                for step in steps {
                    match (step.from, step.to) {
                        (1, 2) => self.migrate_1_to_2()?,
                        (2, 3) => self.migrate_2_to_3()?,
                        (3, 4) => self.migrate_3_to_4()?,
                        _ => {
                            return Err(unavailable_detail_owned(format!(
                                "no migration is implemented from schema version {} to {}",
                                step.from, step.to
                            )));
                        }
                    }
                }
                // Every object of the current schema is created if it is absent, which is what
                // makes reopening a journal this build wrote cheap and idempotent.
                self.create_current_schema()?;
            }
        }
        Ok(())
    }

    /// Creates every object of the current schema that is not already there.
    fn create_current_schema(&self) -> Result<()> {
        self.connection
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS receipts (
                     actor_id             TEXT    NOT NULL,
                     action_id            BLOB    NOT NULL,
                     method               TEXT    NOT NULL,
                     method_version       INTEGER NOT NULL,
                     revision             INTEGER NOT NULL,
                     state                TEXT    NOT NULL,
                     reason               TEXT,
                     payload_digest       BLOB    NOT NULL,
                     subject_digest       BLOB,
                     intent               BLOB,
                     accepted_deadline_ms INTEGER,
                     created_boot         BLOB,
                     created_continuous_ms INTEGER,
                     error_code           TEXT,
                     error_message        TEXT,
                     created_at_ms        INTEGER NOT NULL,
                     updated_at_ms        INTEGER NOT NULL,
                     PRIMARY KEY (actor_id, action_id)
                 );
                 CREATE INDEX IF NOT EXISTS receipts_created_at ON receipts (created_at_ms);
                 CREATE INDEX IF NOT EXISTS receipts_subject
                     ON receipts (actor_id, subject_digest, state);
                 CREATE INDEX IF NOT EXISTS receipts_action ON receipts (action_id);
                 CREATE TABLE IF NOT EXISTS observations (
                     sequence          INTEGER PRIMARY KEY AUTOINCREMENT,
                     actor_id          TEXT    NOT NULL,
                     action_id         BLOB    NOT NULL,
                     provenance        TEXT    NOT NULL,
                     subject           TEXT    NOT NULL,
                     subject_revision  INTEGER,
                     source_cursor     INTEGER,
                     claimed_result    TEXT    NOT NULL,
                     observed_at_ms    INTEGER NOT NULL
                 );
                 CREATE INDEX IF NOT EXISTS observations_action
                     ON observations (actor_id, action_id, sequence);
                 CREATE TABLE IF NOT EXISTS results (
                     actor_id  TEXT NOT NULL,
                     action_id BLOB NOT NULL,
                     result    BLOB NOT NULL,
                     PRIMARY KEY (actor_id, action_id)
                 );
                 CREATE TABLE IF NOT EXISTS receipt_events (
                     sequence       INTEGER PRIMARY KEY AUTOINCREMENT,
                     actor_id       TEXT    NOT NULL,
                     action_id      BLOB    NOT NULL,
                     revision       INTEGER NOT NULL,
                     state          TEXT    NOT NULL,
                     recorded_at_ms INTEGER NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS closure (
                     session_id BLOB PRIMARY KEY,
                     record     BLOB NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS session (
                     session_id BLOB PRIMARY KEY,
                     summary    BLOB NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS host_events (
                     sequence       INTEGER PRIMARY KEY AUTOINCREMENT,
                     kind           TEXT    NOT NULL,
                     detail         TEXT    NOT NULL,
                     output_cursor  INTEGER NOT NULL,
                     recorded_at_ms INTEGER NOT NULL
                 );
                 CREATE INDEX IF NOT EXISTS host_events_recorded_at
                     ON host_events (recorded_at_ms);
                 CREATE TABLE IF NOT EXISTS host_time (
                     id    INTEGER PRIMARY KEY CHECK (id = 1),
                     state BLOB NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS fence_evidence (
                     revision  INTEGER NOT NULL,
                     position  INTEGER NOT NULL,
                     kind      TEXT    NOT NULL,
                     actor_id  TEXT    NOT NULL,
                     action_id BLOB    NOT NULL,
                     method    TEXT,
                     state     TEXT,
                     PRIMARY KEY (revision, position)
                 );
                 CREATE UNIQUE INDEX IF NOT EXISTS fence_evidence_named
                     ON fence_evidence (revision, kind, actor_id, action_id);
                 CREATE TABLE IF NOT EXISTS fence_state (
                     id             INTEGER PRIMARY KEY CHECK (id = 1),
                     since_sequence INTEGER NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS fence_delivery (
                     revision   INTEGER PRIMARY KEY,
                     named      INTEGER NOT NULL,
                     delivered  INTEGER NOT NULL,
                     generation INTEGER NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS fence_forgotten (
                     id              INTEGER PRIMARY KEY CHECK (id = 1),
                     before_revision INTEGER NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS outbox (
                     cursor           INTEGER PRIMARY KEY AUTOINCREMENT,
                     event_id         BLOB    NOT NULL UNIQUE,
                     stream           TEXT    NOT NULL,
                     source           TEXT    NOT NULL,
                     actor_id         TEXT,
                     action_id        BLOB,
                     subject_revision INTEGER NOT NULL,
                     causal_root      BLOB,
                     causal_parent    BLOB,
                     content          TEXT    NOT NULL,
                     detail           TEXT    NOT NULL,
                     recorded_at_ms   INTEGER NOT NULL
                 );
                 CREATE INDEX IF NOT EXISTS outbox_stream ON outbox (stream, cursor);
                 CREATE TABLE IF NOT EXISTS outbox_cursors (
                     consumer  TEXT PRIMARY KEY,
                     cursor    INTEGER NOT NULL,
                     delivered INTEGER NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS journal_gaps (
                     sequence        INTEGER PRIMARY KEY AUTOINCREMENT,
                     kind            TEXT    NOT NULL,
                     detail          TEXT    NOT NULL,
                     faulted_at_ms   INTEGER NOT NULL,
                     recovered_at_ms INTEGER NOT NULL,
                     durable_through INTEGER NOT NULL,
                     resumed_at      INTEGER NOT NULL
                 );",
            )
            .map_err(|error| faulted(&self.health, error))?;
        self.add_delivery_generation()?;
        Ok(())
    }

    /// Adds the outbox, its consumer cursors and the record of lost durability.
    ///
    /// One transaction, like every other step: a migration that failed part way would leave a
    /// store at a version describing neither the shape before it nor the shape after.
    fn migrate_3_to_4(&self) -> Result<()> {
        self.connection
            .execute_batch(
                "BEGIN IMMEDIATE;
                 CREATE TABLE IF NOT EXISTS outbox (
                     cursor           INTEGER PRIMARY KEY AUTOINCREMENT,
                     event_id         BLOB    NOT NULL UNIQUE,
                     stream           TEXT    NOT NULL,
                     source           TEXT    NOT NULL,
                     actor_id         TEXT,
                     action_id        BLOB,
                     subject_revision INTEGER NOT NULL,
                     causal_root      BLOB,
                     causal_parent    BLOB,
                     content          TEXT    NOT NULL,
                     detail           TEXT    NOT NULL,
                     recorded_at_ms   INTEGER NOT NULL
                 );
                 CREATE INDEX IF NOT EXISTS outbox_stream ON outbox (stream, cursor);
                 CREATE TABLE IF NOT EXISTS outbox_cursors (
                     consumer  TEXT PRIMARY KEY,
                     cursor    INTEGER NOT NULL,
                     delivered INTEGER NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS journal_gaps (
                     sequence        INTEGER PRIMARY KEY AUTOINCREMENT,
                     kind            TEXT    NOT NULL,
                     detail          TEXT    NOT NULL,
                     faulted_at_ms   INTEGER NOT NULL,
                     recovered_at_ms INTEGER NOT NULL,
                     durable_through INTEGER NOT NULL,
                     resumed_at      INTEGER NOT NULL
                 );
                 UPDATE schema_version SET version = 4;
                 COMMIT;",
            )
            .map_err(|error| {
                let _ = self.connection.execute_batch("ROLLBACK;");
                faulted(&self.health, error)
            })?;
        Ok(())
    }

    /// Gives an older delivery record the generation column it does not have.
    ///
    /// `CREATE TABLE IF NOT EXISTS` leaves a table that is already there alone, so a journal an
    /// earlier build of this schema version wrote keeps its three-column `fence_delivery`. Nought
    /// is the conservative value for what it holds: it matches no controller generation this host
    /// accepts, so nothing an earlier build recorded is read as delivered to the daemon asking now,
    /// and the names stay until that daemon says it has them.
    fn add_delivery_generation(&self) -> Result<()> {
        let mut statement = self
            .connection
            .prepare("SELECT name FROM pragma_table_info('fence_delivery')")
            .map_err(|error| faulted(&self.health, error))?;
        let columns = statement
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|error| faulted(&self.health, error))?;
        let mut present = false;
        for column in columns {
            if column.map_err(|error| faulted(&self.health, error))? == "generation" {
                present = true;
            }
        }
        drop(statement);
        if present {
            return Ok(());
        }
        self.connection
            .execute_batch(
                "ALTER TABLE fence_delivery ADD COLUMN generation INTEGER NOT NULL DEFAULT 0;",
            )
            .map_err(|error| faulted(&self.health, error))?;
        Ok(())
    }

    /// Brings a version 2 journal forward.
    ///
    /// Version 2 recorded the payload digest but not the subject digest, kept no observations, and
    /// wrote down nothing about the host's clocks.
    ///
    /// The subject digest is **derived** for every record whose retained intent can be decoded.
    /// Version 2 stored the complete mutation, so its subject is recoverable, and recovering it is
    /// what keeps section 23's rule working across an update: a record with no subject stands in
    /// nothing's way, so leaving the column empty would let a fresh identifier quietly take the
    /// place of an uncertain outcome admitted by the previous build. A record whose intent cannot
    /// be decoded keeps an empty subject, because there is nothing to derive one from, and that is
    /// recorded here rather than guessed at.
    ///
    /// This migration goes when there can no longer be a version 2 journal to read, which is the
    /// first release.
    fn migrate_2_to_3(&self) -> Result<()> {
        self.connection
            .execute_batch(
                "BEGIN;
                 ALTER TABLE receipts ADD COLUMN subject_digest BLOB;
                 ALTER TABLE receipts ADD COLUMN created_boot BLOB;
                 ALTER TABLE receipts ADD COLUMN created_continuous_ms INTEGER;
                 CREATE INDEX IF NOT EXISTS receipts_subject
                     ON receipts (actor_id, subject_digest, state);
                 CREATE INDEX IF NOT EXISTS receipts_action ON receipts (action_id);
                 CREATE TABLE IF NOT EXISTS observations (
                     sequence          INTEGER PRIMARY KEY AUTOINCREMENT,
                     actor_id          TEXT    NOT NULL,
                     action_id         BLOB    NOT NULL,
                     provenance        TEXT    NOT NULL,
                     subject           TEXT    NOT NULL,
                     subject_revision  INTEGER,
                     source_cursor     INTEGER,
                     claimed_result    TEXT    NOT NULL,
                     observed_at_ms    INTEGER NOT NULL
                 );
                 CREATE INDEX IF NOT EXISTS observations_action
                     ON observations (actor_id, action_id, sequence);
                 CREATE TABLE IF NOT EXISTS host_time (
                     id    INTEGER PRIMARY KEY CHECK (id = 1),
                     state BLOB NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS fence_evidence (
                     revision  INTEGER NOT NULL,
                     position  INTEGER NOT NULL,
                     kind      TEXT    NOT NULL,
                     actor_id  TEXT    NOT NULL,
                     action_id BLOB    NOT NULL,
                     method    TEXT,
                     state     TEXT,
                     PRIMARY KEY (revision, position)
                 );
                 CREATE UNIQUE INDEX IF NOT EXISTS fence_evidence_named
                     ON fence_evidence (revision, kind, actor_id, action_id);
                 CREATE TABLE IF NOT EXISTS fence_state (
                     id             INTEGER PRIMARY KEY CHECK (id = 1),
                     since_sequence INTEGER NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS fence_delivery (
                     revision   INTEGER PRIMARY KEY,
                     named      INTEGER NOT NULL,
                     delivered  INTEGER NOT NULL,
                     generation INTEGER NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS fence_forgotten (
                     id              INTEGER PRIMARY KEY CHECK (id = 1),
                     before_revision INTEGER NOT NULL
                 );",
            )
            .map_err(|error| faulted(&self.health, error))?;
        let backfilled = self.backfill_subjects();
        let finish = match backfilled {
            Ok(()) => self
                .connection
                .execute_batch("UPDATE schema_version SET version = 3;\n COMMIT;")
                .map_err(|error| faulted(&self.health, error)),
            // The whole migration goes back rather than leaving a half-derived column behind a
            // version number that claims this build wrote it.
            Err(error) => {
                let _ = self.connection.execute_batch("ROLLBACK;");
                return Err(error);
            }
        };
        finish?;
        Ok(())
    }

    /// Derives the subject digest of every migrated record whose retained intent decodes.
    fn backfill_subjects(&self) -> Result<()> {
        let rows: Vec<(String, Vec<u8>, Vec<u8>)> = {
            let mut statement = self
                .connection
                .prepare(
                    "SELECT actor_id, action_id, intent FROM receipts WHERE intent IS NOT NULL",
                )
                .map_err(|error| faulted(&self.health, error))?;
            statement
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                    ))
                })
                .map_err(|error| faulted(&self.health, error))?
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|error| faulted(&self.health, error))?
        };
        for (actor_id, action_id, intent) in rows {
            // A record this build cannot read is left alone. An intent that decodes but whose
            // subject cannot be computed is the same case: neither is a reason to fail an update,
            // and neither is a reason to write a subject that does not describe the record.
            let Ok(mutation) = kr_cbor::from_canonical_slice::<
                kr_protocol::envelope::MutationRequest,
            >(&intent, &kr_cbor::Limits::DEFAULT) else {
                continue;
            };
            let Ok(subject) = kr_protocol::action::subject_digest(&mutation) else {
                continue;
            };
            self.connection
                .execute(
                    "UPDATE receipts SET subject_digest = ?3
                     WHERE actor_id = ?1 AND action_id = ?2",
                    params![actor_id, action_id, subject.as_bytes().as_slice()],
                )
                .map_err(|error| faulted(&self.health, error))?;
        }
        Ok(())
    }

    fn migrate_1_to_2(&self) -> Result<()> {
        self.connection
            .execute_batch(
                "BEGIN;
                 ALTER TABLE receipts ADD COLUMN intent BLOB;
                 CREATE TABLE IF NOT EXISTS session (
                     session_id BLOB PRIMARY KEY,
                     summary    BLOB NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS host_events (
                     sequence       INTEGER PRIMARY KEY AUTOINCREMENT,
                     kind           TEXT    NOT NULL,
                     detail         TEXT    NOT NULL,
                     output_cursor  INTEGER NOT NULL,
                     recorded_at_ms INTEGER NOT NULL
                 );
                 UPDATE schema_version SET version = 2;
                 COMMIT;",
            )
            .map_err(|error| faulted(&self.health, error))?;
        Ok(())
    }

    /// Records a side effect that had no attachment to go to.
    ///
    /// Section 8 sends a side effect to exactly one destination: the attachment holding the input
    /// lease. When nothing holds it there is no destination, and the effect becomes a durable host
    /// event rather than something shown to whoever happens to be watching. What is kept is what
    /// the effect asked for and where in the stream it happened; a clipboard write's own content is
    /// deliberately not kept, because nothing has asked for it and a durable copy of it is a copy
    /// of somebody's data with no reader.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::JournalUnavailable`] when the write fails.
    pub fn record_host_event(
        &mut self,
        effect: &kr_term::sideeffect::SideEffect,
        now_ms: TimestampMs,
    ) -> Result<()> {
        let (kind, detail) = describe_effect(&effect.kind);
        self.connection
            .execute(
                "INSERT INTO host_events (kind, detail, output_cursor, recorded_at_ms)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    kind,
                    detail,
                    i64::try_from(effect.at).unwrap_or(i64::MAX),
                    i64::try_from(now_ms.get()).unwrap_or(i64::MAX)
                ],
            )
            .map_err(|error| faulted(&self.health, error))?;
        Ok(())
    }

    /// Returns the host events this session recorded, oldest first.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::JournalUnavailable`] when the read fails.
    pub fn host_events(&self) -> Result<Vec<HostEvent>> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT kind, detail, output_cursor, recorded_at_ms FROM host_events
                 ORDER BY sequence",
            )
            .map_err(|error| faulted(&self.health, error))?;
        let rows = statement
            .query_map([], |row| {
                Ok(HostEvent {
                    kind: row.get::<_, String>(0)?,
                    detail: row.get::<_, String>(1)?,
                    output_cursor: u64::try_from(row.get::<_, i64>(2)?).unwrap_or_default(),
                    recorded_at_ms: TimestampMs::new(
                        u64::try_from(row.get::<_, i64>(3)?).unwrap_or_default(),
                    ),
                })
            })
            .map_err(|error| faulted(&self.health, error))?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|error| faulted(&self.health, error))
    }

    /// Commits an intent, or returns the retained receipt for an exact duplicate.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::IdConflict`] when the identifier was used with a different payload,
    /// and [`WorkerError::JournalUnavailable`] when the write fails.
    pub fn accept(&mut self, submission: &Submission) -> Result<Admission> {
        if let Some(existing) = self.read(submission.actor_id.clone(), submission.action_id)? {
            if existing.payload_digest != submission.payload_digest {
                return Err(WorkerError::IdConflict {
                    action: submission.action_id.to_string(),
                });
            }
            // An exact retry returns the receipt as it stands, keeping its original deadline.
            return Ok(Admission {
                receipt: existing,
                deduplicated: true,
            });
        }
        let receipt = Receipt {
            action_id: submission.action_id,
            actor_id: submission.actor_id.clone(),
            method: submission.method.clone(),
            method_version: submission.method_version,
            revision: U64::new(1),
            state: ReceiptState::Accepted,
            reason: Nullable::null(),
            payload_digest: submission.payload_digest,
            accepted_deadline_ms: Nullable(submission.accepted_deadline_ms),
            error: Nullable::null(),
            updated_at_ms: submission.now_ms,
        };
        let transaction = self
            .connection
            .transaction()
            .map_err(|error| faulted(&self.health, error))?;
        transaction
            .execute(
                "INSERT INTO receipts (actor_id, action_id, method, method_version, revision,
                     state, reason, payload_digest, subject_digest, intent, accepted_deadline_ms,
                     created_boot, created_continuous_ms, error_code, error_message,
                     created_at_ms, updated_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, ?7, ?8, ?9, ?10, ?11, ?12, NULL, NULL,
                     ?13, ?13)",
                params![
                    receipt.actor_id.as_str(),
                    receipt.action_id.get().as_bytes().as_slice(),
                    receipt.method.as_str(),
                    i64::from(method_version_number(receipt.method_version)),
                    1_i64,
                    ReceiptState::Accepted.as_str(),
                    receipt.payload_digest.as_bytes().as_slice(),
                    submission.subject_digest.as_bytes().as_slice(),
                    submission.intent.as_slice(),
                    submission
                        .accepted_deadline_ms
                        .map(|deadline| i64::try_from(deadline.get()).unwrap_or(i64::MAX)),
                    self.boot.clone(),
                    i64::try_from(kr_ipc::clock::boot_elapsed_ms()).unwrap_or(i64::MAX),
                    i64::try_from(submission.now_ms.get()).unwrap_or(i64::MAX),
                ],
            )
            .map_err(|error| faulted(&self.health, error))?;
        append_event(&self.health, &transaction, &receipt)?;
        transaction
            .commit()
            .map_err(|error| faulted(&self.health, error))?;
        Ok(Admission {
            receipt,
            deduplicated: false,
        })
    }

    /// Reads the recoverable intent an action was accepted with.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::JournalUnavailable`] when the read fails.
    pub fn read_intent(&self, actor_id: &ActorId, action_id: ActionId) -> Result<Option<Vec<u8>>> {
        // Two absences, one answer: there is no such receipt, or it is one an earlier schema wrote
        // without recording what the action was. Neither is a failure to read the journal.
        Ok(self
            .connection
            .query_row(
                "SELECT intent FROM receipts WHERE actor_id = ?1 AND action_id = ?2",
                params![actor_id.as_str(), action_id.get().as_bytes().as_slice()],
                |row| row.get::<_, Option<Vec<u8>>>(0),
            )
            .optional()
            .map_err(|error| faulted(&self.health, error))?
            .flatten())
    }

    /// Cancels an intent that has not been dispatched.
    ///
    /// After a dispatch marker there is nothing to cancel here: the effect may already have
    /// happened, and section 9 makes cancelling it a separate upstream action with its own
    /// receipt. This refuses that case rather than pretending to undo it.
    ///
    /// # Errors
    ///
    /// Returns an error when there is no such receipt, or it already carries a dispatch marker.
    pub fn cancel(
        &mut self,
        actor_id: ActorId,
        action_id: ActionId,
        now_ms: TimestampMs,
    ) -> Result<Receipt> {
        let receipt = self
            .read(actor_id.clone(), action_id)?
            .ok_or_else(|| WorkerError::InvalidArgument(format!("no receipt for {action_id}")))?;
        if receipt.state.has_dispatch_marker() {
            return Err(WorkerError::InvalidArgument(format!(
                "action {action_id} is already {} and cannot be cancelled here",
                receipt.state
            )));
        }
        self.advance(
            actor_id,
            action_id,
            ReceiptState::Rejected,
            Some(RejectionReason::Cancelled),
            None,
            now_ms,
        )
    }

    /// Commits the result, the receipt revision and the event record in one transaction.
    ///
    /// The three describe one thing. Writing them separately is what lets a crash leave a receipt
    /// that says `applied` beside a result nobody can read, or an outcome nothing was notified of.
    ///
    /// # Errors
    ///
    /// Returns an error when the transition is not permitted or the write fails.
    pub fn settle(
        &mut self,
        actor_id: ActorId,
        action_id: ActionId,
        state: ReceiptState,
        result: Option<&[u8]>,
        error: Option<ProtocolError>,
        now_ms: TimestampMs,
    ) -> Result<Receipt> {
        let mut receipt = self
            .read(actor_id.clone(), action_id)?
            .ok_or_else(|| WorkerError::InvalidArgument(format!("no receipt for {action_id}")))?;
        let revision = U64::new(receipt.revision.get() + 1);
        receipt.advance(state, revision, None).map_err(|error| {
            WorkerError::InvalidArgument(format!("receipt transition refused: {error}"))
        })?;
        receipt.error = Nullable(error);
        receipt.updated_at_ms = now_ms;

        let transaction = self
            .connection
            .transaction()
            .map_err(|error| faulted(&self.health, error))?;
        if let Some(result) = result {
            transaction
                .execute(
                    "INSERT INTO results (actor_id, action_id, result) VALUES (?1, ?2, ?3)
                     ON CONFLICT (actor_id, action_id) DO UPDATE SET result = excluded.result",
                    params![
                        receipt.actor_id.as_str(),
                        receipt.action_id.get().as_bytes().as_slice(),
                        result
                    ],
                )
                .map_err(|error| faulted(&self.health, error))?;
        }
        transaction
            .execute(
                "UPDATE receipts SET revision = ?3, state = ?4, reason = ?5, error_code = ?6,
                     error_message = ?7, updated_at_ms = ?8
                 WHERE actor_id = ?1 AND action_id = ?2",
                params![
                    receipt.actor_id.as_str(),
                    receipt.action_id.get().as_bytes().as_slice(),
                    i64::try_from(receipt.revision.get()).unwrap_or(i64::MAX),
                    receipt.state.as_str(),
                    receipt.reason.as_ref().map(|reason| reason.as_str()),
                    receipt
                        .error
                        .as_ref()
                        .map(|error| error.code.as_str().to_owned()),
                    receipt.error.as_ref().map(|error| error.message.clone()),
                    i64::try_from(receipt.updated_at_ms.get()).unwrap_or(i64::MAX),
                ],
            )
            .map_err(|error| faulted(&self.health, error))?;
        append_event_at(&self.health, &transaction, &receipt, now_ms)?;
        transaction
            .commit()
            .map_err(|error| faulted(&self.health, error))?;
        Ok(receipt)
    }

    /// Returns the receipt revisions recorded after a sequence number.
    ///
    /// This is the transactional record every state change leaves behind, so a reader that
    /// reconnects learns what happened to an action while it was away instead of inferring it.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::JournalUnavailable`] when the read fails.
    pub fn events_after(&self, sequence: u64, limit: u64) -> Result<Vec<ReceiptEvent>> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT sequence, actor_id, action_id, revision, state, recorded_at_ms
                 FROM receipt_events WHERE sequence > ?1 ORDER BY sequence LIMIT ?2",
            )
            .map_err(|error| faulted(&self.health, error))?;
        let rows = statement
            .query_map(
                params![
                    i64::try_from(sequence).unwrap_or(i64::MAX),
                    i64::try_from(limit).unwrap_or(i64::MAX)
                ],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, i64>(5)?,
                    ))
                },
            )
            .map_err(|error| faulted(&self.health, error))?;
        let mut events = Vec::new();
        for row in rows {
            let (sequence, actor, action, revision, state, recorded) =
                row.map_err(|error| faulted(&self.health, error))?;
            let action = <[u8; 16]>::try_from(action.as_slice())
                .map_err(|_| unavailable_detail("a stored action identifier is not 16 bytes"))?;
            events.push(ReceiptEvent {
                sequence: u64::try_from(sequence).unwrap_or(0),
                actor_id: ActorId::new(actor)
                    .map_err(|_| unavailable_detail("a stored actor is not valid"))?,
                action_id: ActionId::new(Uuid::from_bytes(action)),
                revision: U64::new(u64::try_from(revision).unwrap_or(0)),
                state: parse_state(&state)?,
                recorded_at_ms: TimestampMs::new(u64::try_from(recorded).unwrap_or(0)),
            });
        }
        Ok(events)
    }
}

fn write_state(
    health: &crate::persistence::fault::JournalHealth,
    transaction: &rusqlite::Transaction<'_>,
    receipt: &Receipt,
) -> Result<()> {
    transaction
        .execute(
            "UPDATE receipts SET revision = ?3, state = ?4, reason = ?5, error_code = ?6,
                 error_message = ?7, updated_at_ms = ?8
             WHERE actor_id = ?1 AND action_id = ?2",
            params![
                receipt.actor_id.as_str(),
                receipt.action_id.get().as_bytes().as_slice(),
                i64::try_from(receipt.revision.get()).unwrap_or(i64::MAX),
                receipt.state.as_str(),
                receipt.reason.as_ref().map(|reason| reason.as_str()),
                receipt
                    .error
                    .as_ref()
                    .map(|error| error.code.as_str().to_owned()),
                receipt.error.as_ref().map(|error| error.message.clone()),
                i64::try_from(receipt.updated_at_ms.get()).unwrap_or(i64::MAX),
            ],
        )
        .map_err(|error| faulted(health, error))?;
    Ok(())
}

fn append_event(
    health: &crate::persistence::fault::JournalHealth,
    transaction: &rusqlite::Transaction<'_>,
    receipt: &Receipt,
) -> Result<()> {
    append_event_at(health, transaction, receipt, receipt.updated_at_ms)
}

/// Writes the transition's event record and its outbox row, inside the caller's transaction.
///
/// Section 24 asks an authoritative producer to commit the state transition and a small event
/// record in **the same local transaction**, and this is that record. The two rows go together
/// because they answer different readers - a subscriber pages `receipt_events` by sequence, and a
/// consumer with a cursor of its own takes the outbox - and because a crash between them would
/// leave a consumer that never hears about a state this host is already serving.
fn append_event_at(
    health: &crate::persistence::fault::JournalHealth,
    transaction: &rusqlite::Transaction<'_>,
    receipt: &Receipt,
    recorded_at_ms: TimestampMs,
) -> Result<()> {
    transaction
        .execute(
            "INSERT INTO receipt_events (actor_id, action_id, revision, state, recorded_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                receipt.actor_id.as_str(),
                receipt.action_id.get().as_bytes().as_slice(),
                i64::try_from(receipt.revision.get()).unwrap_or(i64::MAX),
                receipt.state.as_str(),
                i64::try_from(recorded_at_ms.get()).unwrap_or(i64::MAX),
            ],
        )
        .map_err(|error| faulted(health, error))?;
    // The event's own sequence is what a recovery gap is measured from, so the mark moves here,
    // inside the transaction that made it true, rather than when the caller gets its answer.
    let sequence = u64::try_from(transaction.last_insert_rowid()).unwrap_or(0);
    transaction
        .execute(
            "INSERT INTO outbox (
                 event_id, stream, source, actor_id, action_id, subject_revision,
                 causal_root, causal_parent, content, detail, recorded_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, NULL, ?7, ?8, ?9)",
            params![
                kr_ipc::new_uuid().as_bytes().as_slice(),
                kr_protocol::recovery::EventStream::Receipts.as_str(),
                crate::persistence::outbox::Subsystem::Receipts.as_str(),
                receipt.actor_id.as_str(),
                receipt.action_id.get().as_bytes().as_slice(),
                i64::try_from(receipt.revision.get()).unwrap_or(i64::MAX),
                "metadata",
                receipt.state.as_str(),
                i64::try_from(recorded_at_ms.get()).unwrap_or(i64::MAX),
            ],
        )
        .map_err(|error| faulted(health, error))?;
    health.note_durable_through(sequence);
    Ok(())
}

impl Journal {
    /// Commits the dispatch marker before the external effect.
    ///
    /// # Errors
    ///
    /// Returns an error when the receipt is missing, the transition is not permitted, or the write
    /// fails.
    pub fn mark_dispatching(
        &mut self,
        actor_id: ActorId,
        action_id: ActionId,
        now_ms: TimestampMs,
    ) -> Result<Receipt> {
        self.advance(
            actor_id,
            action_id,
            ReceiptState::Dispatching,
            None,
            None,
            now_ms,
        )
    }

    /// Records a rejection before dispatch.
    ///
    /// # Errors
    ///
    /// Returns an error when the transition is not permitted or the write fails.
    pub fn reject(
        &mut self,
        actor_id: ActorId,
        action_id: ActionId,
        reason: RejectionReason,
        error: Option<ProtocolError>,
        now_ms: TimestampMs,
    ) -> Result<Receipt> {
        self.advance(
            actor_id,
            action_id,
            ReceiptState::Rejected,
            Some(reason),
            error,
            now_ms,
        )
    }

    fn advance(
        &mut self,
        actor_id: ActorId,
        action_id: ActionId,
        state: ReceiptState,
        reason: Option<RejectionReason>,
        error: Option<ProtocolError>,
        now_ms: TimestampMs,
    ) -> Result<Receipt> {
        self.advance_and_name(
            actor_id,
            action_id,
            Transition {
                state,
                reason,
                error,
                now_ms,
            },
            None,
        )
        .map(|(receipt, _)| receipt)
    }

    /// Advances a receipt and, when `fenced_for` is given, names it in that revocation's evidence.
    ///
    /// One transaction, because the two are one fact: a rejection with no name is an action the
    /// revocation's result owes and cannot produce, and the next pass would not find it, because it
    /// selects intents that are still accepted. The boolean says whether the name was new.
    fn advance_and_name(
        &mut self,
        actor_id: ActorId,
        action_id: ActionId,
        transition: Transition,
        fenced_for: Option<u64>,
    ) -> Result<(Receipt, bool)> {
        let Transition {
            state,
            reason,
            error,
            now_ms,
        } = transition;
        let mut receipt = self
            .read(actor_id.clone(), action_id)?
            .ok_or_else(|| WorkerError::InvalidArgument(format!("no receipt for {action_id}")))?;
        let revision = U64::new(receipt.revision.get() + 1);
        receipt.advance(state, revision, reason).map_err(|error| {
            WorkerError::InvalidArgument(format!("receipt transition refused: {error}"))
        })?;
        receipt.error = Nullable(error);
        receipt.updated_at_ms = now_ms;
        let transaction = self
            .connection
            .transaction()
            .map_err(|error| faulted(&self.health, error))?;
        write_state(&self.health, &transaction, &receipt)?;
        append_event(&self.health, &transaction, &receipt)?;
        let named = match fenced_for {
            Some(revocation) => name_evidence(
                &self.health,
                &transaction,
                revocation,
                "rejected",
                &actor_id,
                action_id,
                None,
                None,
            )?,
            None => false,
        };
        transaction
            .commit()
            .map_err(|error| faulted(&self.health, error))?;
        Ok((receipt, named))
    }

    /// Fences this session for a revocation, and reports what it could and could not take back.
    ///
    /// An authority revision that removes the authority an intent was admitted under is what
    /// section 9 calls a revocation, and the acknowledgement it asks for is two statements rather
    /// than one: the undispatched intents this revision affects have been rejected, **and** the
    /// ones past their dispatch marker are named. The second list is defined by the race rather
    /// than by the outcome: every action whose dispatch transition won it is named, and its receipt
    /// state says how much is known about what it did.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::JournalUnavailable`] when the read or the write fails.
    pub fn fence_for_revocation(
        &mut self,
        revision: u64,
        error: Option<ProtocolError>,
        now_ms: TimestampMs,
        since_sequence: u64,
        generation: u64,
    ) -> (Fenced, Result<u64>) {
        let mut fenced = Fenced::default();
        // An older revocation's names go once the daemon has taken them, and not for being older.
        // "The daemon" is the controller generation this host answers to now, because a
        // replacement holds none of what its predecessor collected. This runs before the pass, so
        // a pass that fails part way leaves what it did name under the revision it ran for.
        if let Err(error) = self.forget_delivered_evidence(revision, generation) {
            return (fenced, Err(error));
        }
        // Read before anything is rejected, because everything this fence does appends events of
        // its own. The boundary the *next* fence starts from is where this journal stood when this
        // one began.
        let reached = match self.event_high_water() {
            Ok(reached) => reached,
            Err(error) => return (fenced, Err(error)),
        };
        let undispatched = match self.identities_in(&[ReceiptState::Accepted]) {
            Ok(found) => found,
            Err(error) => return (fenced, Err(error)),
        };
        // Every state that carries a dispatch marker, moved since the previous fence. Section 9
        // defines the set by the race rather than by the outcome: an action whose dispatch
        // transition already won it is named in the result, and its receipt state says how much is
        // known about what it did. An action that settled while the revocation was queued behind
        // it won that race as surely as one still inside the transition.
        //
        // `since_sequence` is what bounds the answer. Naming every dispatched action this journal
        // has ever retained would grow the report with the session's whole history, and eventually
        // past the frame that has to carry it; what this revocation covers is what happened since
        // the last one, measured on this journal's own event order rather than on a clock.
        let past_the_marker = match self.identities_since(
            &[
                ReceiptState::Dispatching,
                ReceiptState::Unknown,
                ReceiptState::Applied,
                ReceiptState::Refused,
            ],
            since_sequence,
        ) {
            Ok(found) => found,
            Err(error) => return (fenced, Err(error)),
        };

        // The rejections are committed one at a time, so a failure part way leaves some of them
        // done. What was done is reported either way: the acknowledgement is withheld, the daemon
        // announces again, and the second pass has to be able to name what the first rejected.
        for (actor_id, action_id) in undispatched {
            // The rejection, its event and its name in one transaction: a rejection this pass
            // committed without its name would be an action the result owes and cannot produce.
            match self.advance_and_name(
                actor_id,
                action_id,
                Transition {
                    state: ReceiptState::Rejected,
                    reason: Some(RejectionReason::Revoked),
                    error: error.clone(),
                    now_ms,
                },
                Some(revision),
            ) {
                Ok((_, named)) => {
                    fenced.rejected = fenced.rejected.saturating_add(u64::from(named));
                }
                Err(error) => return (fenced, Err(error)),
            }
        }

        for (actor_id, action_id) in past_the_marker {
            match self.read(actor_id.clone(), action_id) {
                Ok(Some(receipt)) => {
                    let named = self.name_possibly_executed(
                        revision,
                        &PossiblyExecutedAction {
                            action_id,
                            actor_id,
                            method: receipt.method,
                            state: receipt.state,
                        },
                    );
                    match named {
                        Ok(named) => {
                            fenced.possibly_executed =
                                fenced.possibly_executed.saturating_add(u64::from(named));
                        }
                        Err(error) => return (fenced, Err(error)),
                    }
                }
                Ok(None) => {}
                Err(error) => return (fenced, Err(error)),
            }
        }
        // Recorded only now, because everything above had to get through first. What it bounds is
        // where the next fence starts looking.
        if let Err(error) = self.record_fence_boundary(reached) {
            return (fenced, Err(error));
        }
        (fenced, Ok(reached))
    }

    /// Records one action past its dispatch marker, and says whether it was new.
    fn name_possibly_executed(
        &self,
        revision: u64,
        action: &PossiblyExecutedAction,
    ) -> Result<bool> {
        name_evidence(
            &self.health,
            &self.connection,
            revision,
            "possibly_executed",
            &action.actor_id,
            action.action_id,
            Some(action.method.as_str()),
            Some(action.state.as_str()),
        )
    }

    /// Returns the journal event position the last completed fence ran at.
    ///
    /// It is durable because what it bounds outlives a process: where the next fence starts
    /// looking. A boundary that reset to nothing on a restart would make the next fence name the
    /// session's whole history. Collection does not read it - what a revocation has already named
    /// is a `fence_evidence` row that outlives the receipt it refers to, and what no revocation
    /// has looked at is bounded by the retention period rather than by a fence.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::JournalUnavailable`] when the read fails.
    pub fn fence_boundary(&self) -> Result<u64> {
        let boundary: Option<i64> = self
            .connection
            .query_row(
                "SELECT since_sequence FROM fence_state WHERE id = 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| faulted(&self.health, error))?;
        Ok(boundary
            .and_then(|held| u64::try_from(held).ok())
            .unwrap_or(0))
    }

    /// Records the position a completed fence reached.
    fn record_fence_boundary(&self, reached: u64) -> Result<()> {
        self.connection
            .execute(
                "INSERT INTO fence_state (id, since_sequence) VALUES (1, ?1)
                 ON CONFLICT (id) DO UPDATE SET since_sequence = excluded.since_sequence",
                params![i64::try_from(reached).unwrap_or(i64::MAX)],
            )
            .map_err(|error| faulted(&self.health, error))?;
        Ok(())
    }

    /// Forgets the names of an older revocation the daemon has taken all of.
    ///
    /// A revision advancing is not what makes a revocation's names finished with. The daemon takes
    /// them a page at a time, and section 9 requires the actions a fence could not take back to be
    /// named in the *result*, so names it has not taken are still owed however many revisions have
    /// been installed since. What it has taken is a fact this journal has: an announcement says how
    /// many names the daemon already holds, and that is what is written down here.
    ///
    /// Keeping every revocation's names for a daemon that stopped asking would grow this journal a
    /// revocation at a time, so at most [`MAX_HELD_REVOCATIONS`] revocations have names here,
    /// counting the one this pass is about to name. Past that the oldest one's names go and the
    /// count takes their place, which is what a page of them then reports.
    ///
    /// `generation` is the controller generation this host answers to now. What a *previous*
    /// controller took is not something the current one holds, so a count another generation
    /// wrote does not finish anything: the names stay until the controller that has to name them
    /// says it has them.
    fn forget_delivered_evidence(&self, revision: u64, generation: u64) -> Result<()> {
        let current = i64::try_from(revision).unwrap_or(i64::MAX);
        let holder = i64::try_from(generation).unwrap_or(i64::MAX);
        let mut held: Vec<(i64, u64, u64)> = Vec::new();
        {
            let mut statement = self
                .connection
                .prepare(
                    "SELECT e.revision, COUNT(*),
                            COALESCE(MAX(CASE WHEN d.generation = ?1 THEN d.delivered END), 0)
                     FROM fence_evidence AS e
                     LEFT JOIN fence_delivery AS d ON d.revision = e.revision
                     GROUP BY e.revision
                     ORDER BY e.revision",
                )
                .map_err(|error| faulted(&self.health, error))?;
            let rows = statement
                .query_map(params![holder], |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                })
                .map_err(|error| faulted(&self.health, error))?;
            for row in rows {
                let (held_revision, named, delivered) =
                    row.map_err(|error| faulted(&self.health, error))?;
                held.push((
                    held_revision,
                    u64::try_from(named).unwrap_or(0),
                    u64::try_from(delivered).unwrap_or(0),
                ));
            }
        }
        // Superseded and taken. Nothing is owed about it, so nothing about it is kept: the names
        // go, and so does the record of them, because there is nothing left to say.
        let mut owed = Vec::new();
        for (held_revision, named, delivered) in held {
            if held_revision < current && delivered >= named {
                self.remove_evidence(held_revision)?;
                self.forget_delivery(held_revision)?;
            } else {
                owed.push(held_revision);
            }
        }
        // What is left is owed, and the bound is what stops it growing without end. The oldest
        // goes first, because the newest revocation is the one a person is waiting on. The
        // current revision is the newest of all, so it is never what goes. How many names went is
        // written down before they do, because after that nothing can count them.
        //
        // The pass that follows this one names the current revision, so its place is kept here
        // rather than taken afterwards: the bound is what this journal holds once the pass is
        // done, not what it held before it started.
        let keep = if owed.contains(&current) {
            MAX_HELD_REVOCATIONS
        } else {
            MAX_HELD_REVOCATIONS.saturating_sub(1)
        };
        while owed.len() > keep {
            let oldest = owed.remove(0);
            self.record_named(oldest, holder)?;
            self.remove_evidence(oldest)?;
        }
        self.bound_delivery_records(holder)?;
        Ok(())
    }

    /// Removes one revocation's names.
    fn remove_evidence(&self, revision: i64) -> Result<()> {
        self.connection
            .execute(
                "DELETE FROM fence_evidence WHERE revision = ?1",
                params![revision],
            )
            .map_err(|error| faulted(&self.health, error))?;
        Ok(())
    }

    /// Records how many names one revocation's fence has produced so far.
    ///
    /// The figure only rises: a second pass names what the first could not reach, and a count
    /// taken between them does not unsay the one before it. It is what a page reports as missing
    /// once the names themselves have gone.
    ///
    /// What was taken is settled against the controller this host answers to now, because that is
    /// the one the missing names are missing from. A count another generation made says nothing
    /// about what this one holds, so it becomes nought here: the names are gone, and the
    /// controller that has to name them never had them.
    fn record_named(&self, revision: i64, generation: i64) -> Result<()> {
        self.connection
            .execute(
                "INSERT INTO fence_delivery (revision, named, delivered, generation)
                 VALUES (?1, (SELECT COUNT(*) FROM fence_evidence WHERE revision = ?1), 0, ?2)
                 ON CONFLICT (revision) DO UPDATE
                     SET named = MAX(fence_delivery.named, excluded.named),
                         delivered = CASE
                             WHEN fence_delivery.generation = excluded.generation
                                 THEN fence_delivery.delivered
                             ELSE 0
                         END,
                         generation = excluded.generation",
                params![revision, generation],
            )
            .map_err(|error| faulted(&self.health, error))?;
        Ok(())
    }

    /// Forgets what was said about a revocation whose names are all accounted for.
    fn forget_delivery(&self, revision: i64) -> Result<()> {
        self.connection
            .execute(
                "DELETE FROM fence_delivery WHERE revision = ?1",
                params![revision],
            )
            .map_err(|error| faulted(&self.health, error))?;
        Ok(())
    }

    /// Keeps the delivery records that still have something to say, and bounds them.
    ///
    /// A record whose names the controller asking now has all taken says nothing, so it goes as
    /// soon as that is true. One that another generation took them is not that record: what a
    /// replacement holds is nothing, so the count is a loss to it and is kept as one. A record that says names went without reaching the daemon outlives the names it
    /// counts, and without a bound a host whose daemon stopped asking would keep one per
    /// revocation for good. So the newest [`MAX_HELD_REVOCATIONS`] of those are kept, and what
    /// goes past that is remembered as a boundary rather than as nothing: a page of a revocation
    /// below it says this journal cannot answer for that revocation, which is not the same
    /// statement as a fence that named nothing.
    fn bound_delivery_records(&self, generation: i64) -> Result<()> {
        let mut missing: Vec<i64> = Vec::new();
        {
            // What the controller asking now holds is nothing another generation took, so a count
            // one of those wrote is a loss to this one exactly as names that never arrived are.
            let mut statement = self
                .connection
                .prepare(
                    "SELECT revision FROM fence_delivery
                     WHERE named > CASE WHEN generation = ?1 THEN delivered ELSE 0 END
                       AND revision NOT IN (SELECT DISTINCT revision FROM fence_evidence)
                     ORDER BY revision",
                )
                .map_err(|error| faulted(&self.health, error))?;
            let rows = statement
                .query_map(params![generation], |row| row.get::<_, i64>(0))
                .map_err(|error| faulted(&self.health, error))?;
            for row in rows {
                missing.push(row.map_err(|error| faulted(&self.health, error))?);
            }
        }
        // Everything else is either still named here or completely taken by the controller asking
        // now, and neither needs a record once the names have gone.
        self.connection
            .execute(
                "DELETE FROM fence_delivery
                 WHERE named <= CASE WHEN generation = ?1 THEN delivered ELSE 0 END
                   AND revision NOT IN (SELECT DISTINCT revision FROM fence_evidence)",
                params![generation],
            )
            .map_err(|error| faulted(&self.health, error))?;
        while missing.len() > MAX_HELD_REVOCATIONS {
            let oldest = missing.remove(0);
            // The boundary first. A failure between these two leaves a count this journal can
            // still read and a boundary that covers it, which answers conservatively; the other
            // order would leave neither, and a revocation whose names went would read as one that
            // named nothing.
            self.record_forgotten(oldest)?;
            self.forget_delivery(oldest)?;
        }
        Ok(())
    }

    /// Records that this journal can no longer answer for revocations up to and including this one.
    fn record_forgotten(&self, revision: i64) -> Result<()> {
        self.connection
            .execute(
                "INSERT INTO fence_forgotten (id, before_revision) VALUES (1, ?1)
                 ON CONFLICT (id) DO UPDATE
                     SET before_revision = MAX(fence_forgotten.before_revision, excluded.before_revision)",
                params![revision],
            )
            .map_err(|error| faulted(&self.health, error))?;
        Ok(())
    }

    /// Returns whether this journal can still answer for one revocation.
    ///
    /// A page of names this journal never held and a page of names it has forgotten are different
    /// statements, and only the first one may read as a fence that named nothing. Section 9 makes
    /// the acknowledgement two statements; a worker that cannot make the second one says so by
    /// carrying no evidence at all, which is what a caller reads here.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::JournalUnavailable`] when the read fails.
    pub fn evidence_answerable(&self, revision: u64) -> Result<bool> {
        let revision = i64::try_from(revision).unwrap_or(i64::MAX);
        let held: i64 = self
            .connection
            .query_row(
                "SELECT COUNT(*) FROM fence_evidence WHERE revision = ?1",
                params![revision],
                |row| row.get(0),
            )
            .map_err(|error| faulted(&self.health, error))?;
        if held > 0 {
            return Ok(true);
        }
        let counted: i64 = self
            .connection
            .query_row(
                "SELECT COUNT(*) FROM fence_delivery WHERE revision = ?1",
                params![revision],
                |row| row.get(0),
            )
            .map_err(|error| faulted(&self.health, error))?;
        if counted > 0 {
            return Ok(true);
        }
        let forgotten: Option<i64> = self
            .connection
            .query_row(
                "SELECT before_revision FROM fence_forgotten WHERE id = 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| faulted(&self.health, error))?;
        Ok(forgotten.is_none_or(|before| revision > before))
    }

    /// Records how many of a revocation's names the controller of one generation holds.
    ///
    /// An announcement carries the count, and that is what makes it a statement rather than a
    /// guess: the daemon asks for the page after the names it already has. Within one generation
    /// the figure only rises, because an announcement that asked for less does not unsay the page
    /// before it.
    ///
    /// The generation is what the count belongs to. A controller keeps the names it has collected
    /// in its own memory, and a replacement starts with none of them, so what the previous one
    /// took is not something this journal may hold the new one to: a later generation's count
    /// *replaces* the figure rather than being compared with it.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::JournalUnavailable`] when the write fails.
    pub fn note_evidence_delivered(
        &self,
        revision: u64,
        delivered: u64,
        generation: u64,
    ) -> Result<()> {
        self.connection
            .execute(
                // Nothing is written for a revocation this journal has already said it cannot
                // answer for. A record made now would say the names were all taken, which is the
                // opposite of what happened to them.
                "INSERT INTO fence_delivery (revision, named, delivered, generation)
                 SELECT ?1, (SELECT COUNT(*) FROM fence_evidence WHERE revision = ?1), ?2, ?3
                 WHERE ?1 > COALESCE(
                         (SELECT before_revision FROM fence_forgotten WHERE id = 1), 0)
                    OR EXISTS (SELECT 1 FROM fence_evidence WHERE revision = ?1)
                    OR EXISTS (SELECT 1 FROM fence_delivery WHERE revision = ?1)
                 ON CONFLICT (revision) DO UPDATE
                     SET named = MAX(fence_delivery.named, excluded.named),
                         delivered = CASE
                             WHEN excluded.generation > fence_delivery.generation
                                 THEN excluded.delivered
                             ELSE MAX(fence_delivery.delivered, excluded.delivered)
                         END,
                         generation = MAX(fence_delivery.generation, excluded.generation)",
                params![
                    i64::try_from(revision).unwrap_or(i64::MAX),
                    i64::try_from(delivered).unwrap_or(i64::MAX),
                    i64::try_from(generation).unwrap_or(i64::MAX)
                ],
            )
            .map_err(|error| faulted(&self.health, error))?;
        Ok(())
    }

    /// Reads one page of a revocation's fence evidence.
    ///
    /// `from` is how many names the caller already has, so a page follows the one before it without
    /// the caller having to say where the journal put them. The page is at most
    /// [`kr_protocol::action::MAX_NAMED_FENCED_ACTIONS`] names, and `remaining` says how many are
    /// still to come: nought there is what says the evidence is complete.
    ///
    /// A revocation whose names this journal no longer holds is the one case where nought
    /// remaining does not mean complete, and `omitted` is what says so: it carries how many names
    /// went without reaching the daemon, so a page of nothing is not read as a fence that named
    /// nothing.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::JournalUnavailable`] when the read fails.
    pub fn evidence_page(&self, revision: u64, from: u64) -> Result<EvidencePage> {
        let revision = i64::try_from(revision).unwrap_or(i64::MAX);
        let held: i64 = self
            .connection
            .query_row(
                "SELECT COUNT(*) FROM fence_evidence WHERE revision = ?1",
                params![revision],
                |row| row.get(0),
            )
            .map_err(|error| faulted(&self.health, error))?;
        let held = u64::try_from(held).unwrap_or(0);
        let from = from.min(held);
        let page_size = u64::try_from(kr_protocol::action::MAX_NAMED_FENCED_ACTIONS).unwrap_or(256);
        let mut page = EvidencePage {
            remaining: held.saturating_sub(from.saturating_add(page_size)),
            omitted: self.evidence_omitted(revision, held)?,
            ..EvidencePage::default()
        };
        let mut statement = self
            .connection
            .prepare(
                "SELECT kind, actor_id, action_id, method, state FROM fence_evidence
                 WHERE revision = ?1
                 ORDER BY position
                 LIMIT ?2 OFFSET ?3",
            )
            .map_err(|error| faulted(&self.health, error))?;
        let rows = statement
            .query_map(
                params![
                    revision,
                    i64::try_from(page_size).unwrap_or(256),
                    i64::try_from(from).unwrap_or(0)
                ],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, Option<String>>(3)?,
                        row.get::<_, Option<String>>(4)?,
                    ))
                },
            )
            .map_err(|error| faulted(&self.health, error))?;
        for row in rows {
            let (kind, actor, action, method, state) =
                row.map_err(|error| faulted(&self.health, error))?;
            let actor_id = parse_actor(actor)?;
            let action_id = parse_action(&action)?;
            if kind == "rejected" {
                page.rejected.push(kr_protocol::action::FencedAction {
                    actor_id,
                    action_id,
                });
                continue;
            }
            // A named action whose method or state this journal cannot read is not a name this
            // host can report honestly, so it is skipped rather than given invented values. The
            // count above still says a name was there.
            let Some(method) = method else { continue };
            let Ok(state) = parse_state(state.as_deref().unwrap_or_default()) else {
                continue;
            };
            let Ok(method) = kr_protocol::method::MethodName::new(method) else {
                continue;
            };
            page.possibly_executed.push(PossiblyExecutedAction {
                action_id,
                actor_id,
                method,
                state,
            });
        }
        Ok(page)
    }

    /// Returns how many of a revocation's names this journal no longer holds.
    ///
    /// Nothing is missing while the names are here, because paging delivers all of them. Once they
    /// have gone, what is missing is what the fence named less what the daemon had already taken,
    /// and both figures are in the delivery record the names left behind.
    fn evidence_omitted(&self, revision: i64, held: u64) -> Result<u64> {
        if held > 0 {
            return Ok(0);
        }
        let counts: Option<(i64, i64)> = self
            .connection
            .query_row(
                "SELECT named, delivered FROM fence_delivery WHERE revision = ?1",
                params![revision],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|error| faulted(&self.health, error))?;
        let Some((named, delivered)) = counts else {
            return Ok(0);
        };
        let named = u64::try_from(named).unwrap_or(0);
        let delivered = u64::try_from(delivered).unwrap_or(0);
        Ok(named.saturating_sub(delivered))
    }

    /// Returns the actor and action of every receipt in one of these states.
    fn identities_in(&self, states: &[ReceiptState]) -> Result<Vec<(ActorId, ActionId)>> {
        self.identities_since(states, 0)
    }

    /// Returns the actor and action of every receipt in one of these states, changed since a time.
    /// Returns the actor and action of every receipt in one of these states that has changed
    /// since one position in this journal's own event order.
    ///
    /// The boundary is a recorded event position rather than a wall-clock reading. Every state
    /// change appends an event, and the sequence only increases, so "since the last fence" is a
    /// fact about this store rather than about a clock: a wall clock that moved backwards would
    /// otherwise put a receipt written after the previous fence *before* the boundary, and the
    /// next fence would not name it.
    fn identities_since(
        &self,
        states: &[ReceiptState],
        since_sequence: u64,
    ) -> Result<Vec<(ActorId, ActionId)>> {
        let since = i64::try_from(since_sequence).unwrap_or(i64::MAX);
        // From the beginning there is nothing to compare against, and a receipt can have no event
        // at all: a journal an earlier build wrote has rows and no event history, and requiring an
        // event would make recovery skip exactly those. Past the beginning the boundary is what
        // bounds the answer.
        let query = if since_sequence == 0 {
            "SELECT actor_id, action_id FROM receipts AS r
             WHERE r.state = ?1 AND ?2 = 0
             ORDER BY r.created_at_ms, r.action_id"
        } else {
            "SELECT actor_id, action_id FROM receipts AS r
             WHERE r.state = ?1
               AND EXISTS (SELECT 1 FROM receipt_events AS e
                           WHERE e.actor_id = r.actor_id
                             AND e.action_id = r.action_id
                             AND e.sequence > ?2)
             ORDER BY r.created_at_ms, r.action_id"
        };
        let mut found = Vec::new();
        for state in states {
            let mut statement = self
                .connection
                .prepare(query)
                .map_err(|error| faulted(&self.health, error))?;
            let rows = statement
                .query_map(params![state.as_str(), since], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
                })
                .map_err(|error| faulted(&self.health, error))?;
            for row in rows {
                let (actor, action) = row.map_err(|error| faulted(&self.health, error))?;
                found.push((parse_actor(actor)?, parse_action(&action)?));
            }
        }
        Ok(found)
    }

    /// Returns the furthest position this journal's event order has reached.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::JournalUnavailable`] when the read fails.
    pub fn event_high_water(&self) -> Result<u64> {
        let sequence: i64 = self
            .connection
            .query_row(
                "SELECT COALESCE(MAX(sequence), 0) FROM receipt_events",
                [],
                |row| row.get(0),
            )
            .map_err(|error| faulted(&self.health, error))?;
        Ok(u64::try_from(sequence).unwrap_or(0))
    }

    /// Returns how many of this actor's mutations are admitted and not yet settled.
    ///
    /// Both durable states before an outcome count: an accepted intent this host still owes a
    /// decision on, and one past its dispatch marker whose outcome has not been recorded.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::JournalUnavailable`] when the read fails.
    pub fn outstanding(&self, actor_id: &ActorId) -> Result<usize> {
        let count: i64 = self
            .connection
            .query_row(
                "SELECT COUNT(*) FROM receipts WHERE actor_id = ?1 AND state IN (?2, ?3)",
                params![
                    actor_id.as_str(),
                    ReceiptState::Accepted.as_str(),
                    ReceiptState::Dispatching.as_str()
                ],
                |row| row.get(0),
            )
            .map_err(|error| faulted(&self.health, error))?;
        Ok(usize::try_from(count).unwrap_or(usize::MAX))
    }

    /// Returns this actor's most recent uncertain outcome for a subject, if it has one.
    ///
    /// The subject rather than the action: section 23's rule is about a *new* identifier asking
    /// for the same thing, so what has to be found is the earlier ask rather than the earlier
    /// identifier.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::JournalUnavailable`] when the read fails.
    pub fn uncertain_for_subject(
        &self,
        actor_id: &ActorId,
        subject_digest: Digest256,
    ) -> Result<Option<(ActionId, u64)>> {
        let row: Option<(Vec<u8>, i64)> = self
            .connection
            .query_row(
                "SELECT action_id, revision FROM receipts
                 WHERE actor_id = ?1 AND subject_digest = ?2 AND state = ?3
                 ORDER BY updated_at_ms DESC, action_id DESC LIMIT 1",
                params![
                    actor_id.as_str(),
                    subject_digest.as_bytes().as_slice(),
                    ReceiptState::Unknown.as_str()
                ],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|error| faulted(&self.health, error))?;
        row.map(|(action, revision)| {
            Ok((
                parse_action(&action)?,
                u64::try_from(revision).unwrap_or_default(),
            ))
        })
        .transpose()
    }

    /// Finds the one action an identifier names, whichever actor submitted it.
    ///
    /// The de-duplication key is the actor **and** the action, so an identifier is not by itself a
    /// key: two actors may each have used the same one, and this journal holds both. This is the
    /// only lookup in the worker that is not keyed by the calling actor, and it exists for the host
    /// owner's cancellation; it therefore refuses an ambiguous identifier rather than choosing one
    /// of the rows, because cancelling the wrong actor's intent is worse than refusing.
    ///
    /// # Errors
    ///
    /// Returns an invalid-argument failure when more than one actor used the identifier, and
    /// [`WorkerError::JournalUnavailable`] when the read fails.
    pub fn find_any(&self, action_id: ActionId) -> Result<Option<(ActorId, Receipt)>> {
        let mut statement = self
            .connection
            .prepare("SELECT actor_id FROM receipts WHERE action_id = ?1 ORDER BY actor_id")
            .map_err(|error| faulted(&self.health, error))?;
        let rows = statement
            .query_map(params![action_id.get().as_bytes().as_slice()], |row| {
                row.get::<_, String>(0)
            })
            .map_err(|error| faulted(&self.health, error))?;
        let mut actors = Vec::new();
        for row in rows {
            actors.push(parse_actor(
                row.map_err(|error| faulted(&self.health, error))?,
            )?);
        }
        if actors.len() > 1 {
            return Err(WorkerError::InvalidArgument(format!(
                "action {action_id} names {} actors' actions, so it does not identify one; the \
                 de-duplication key is the actor and the action together",
                actors.len()
            )));
        }
        let Some(actor_id) = actors.pop() else {
            return Ok(None);
        };
        Ok(self
            .read(actor_id.clone(), action_id)?
            .map(|receipt| (actor_id, receipt)))
    }

    /// Records one observation beside an action, and reconciles the receipt when it may.
    ///
    /// An observation never creates a receipt: evidence about an action this journal never admitted
    /// is evidence about somebody else's action. It never moves a state the receipt contract has
    /// settled either; only an authoritative answer about an uncertain outcome moves anything, and
    /// [`crate::action::observation`] is where that is decided.
    ///
    /// # Errors
    ///
    /// Returns an invalid-argument failure when the action is not one this journal holds, and
    /// [`WorkerError::JournalUnavailable`] when the write fails.
    pub fn record_observation(
        &mut self,
        actor_id: &ActorId,
        observation: &ActionObservation,
    ) -> Result<Receipt> {
        let receipt = self
            .read(actor_id.clone(), observation.action_id)?
            .ok_or_else(|| {
                WorkerError::InvalidArgument(format!(
                    "no receipt for action {}, so there is nothing to observe",
                    observation.action_id
                ))
            })?;
        let effect = crate::action::observation::effect(observation, receipt.state);
        let transaction = self
            .connection
            .transaction()
            .map_err(|error| faulted(&self.health, error))?;
        transaction
            .execute(
                "INSERT INTO observations (actor_id, action_id, provenance, subject,
                     subject_revision, source_cursor, claimed_result, observed_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    actor_id.as_str(),
                    observation.action_id.get().as_bytes().as_slice(),
                    observation.provenance.as_str(),
                    observation.subject.as_str(),
                    observation
                        .subject_revision
                        .as_ref()
                        .map(|revision| i64::try_from(revision.get()).unwrap_or(i64::MAX)),
                    observation
                        .source_cursor
                        .as_ref()
                        .map(|cursor| i64::try_from(cursor.get()).unwrap_or(i64::MAX)),
                    observation.claimed_result.as_str(),
                    i64::try_from(observation.observed_at_ms.get()).unwrap_or(i64::MAX),
                ],
            )
            .map_err(|error| faulted(&self.health, error))?;
        let mut receipt = receipt;
        if let Some(state) = effect.reconciliation() {
            // The observation and the reconciliation are one commit. A crash between them would
            // leave a receipt claiming an outcome beside no record of what established it.
            let revision = U64::new(receipt.revision.get() + 1);
            receipt.advance(state, revision, None).map_err(|error| {
                WorkerError::InvalidArgument(format!("receipt transition refused: {error}"))
            })?;
            receipt.updated_at_ms = observation.observed_at_ms;
            write_state(&self.health, &transaction, &receipt)?;
            append_event(&self.health, &transaction, &receipt)?;
        }
        transaction
            .commit()
            .map_err(|error| faulted(&self.health, error))?;
        Ok(receipt)
    }

    /// Returns the observations recorded against one action, oldest first.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::JournalUnavailable`] when the read fails.
    pub fn observations(
        &self,
        actor_id: &ActorId,
        action_id: ActionId,
    ) -> Result<Vec<ActionObservation>> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT provenance, subject, subject_revision, source_cursor, claimed_result,
                        observed_at_ms
                 FROM observations WHERE actor_id = ?1 AND action_id = ?2 ORDER BY sequence",
            )
            .map_err(|error| faulted(&self.health, error))?;
        let rows = statement
            .query_map(
                params![actor_id.as_str(), action_id.get().as_bytes().as_slice()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<i64>>(2)?,
                        row.get::<_, Option<i64>>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, i64>(5)?,
                    ))
                },
            )
            .map_err(|error| faulted(&self.health, error))?;
        let mut observations = Vec::new();
        for row in rows {
            let (provenance, subject, revision, cursor, claimed, observed) =
                row.map_err(|error| faulted(&self.health, error))?;
            observations.push(ActionObservation {
                action_id,
                provenance: parse_provenance(&provenance)?,
                subject,
                subject_revision: Nullable(
                    revision.map(|value| U64::new(u64::try_from(value).unwrap_or_default())),
                ),
                source_cursor: Nullable(
                    cursor.map(|value| U64::new(u64::try_from(value).unwrap_or_default())),
                ),
                claimed_result: parse_claimed_result(&claimed)?,
                observed_at_ms: TimestampMs::new(u64::try_from(observed).unwrap_or_default()),
            });
        }
        Ok(observations)
    }

    /// Reads one receipt.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::JournalUnavailable`] when the read fails.
    pub fn read(&self, actor_id: ActorId, action_id: ActionId) -> Result<Option<Receipt>> {
        self.connection
            .query_row(
                "SELECT method, method_version, revision, state, reason, payload_digest,
                        accepted_deadline_ms, error_code, error_message, updated_at_ms
                 FROM receipts WHERE actor_id = ?1 AND action_id = ?2",
                params![actor_id.as_str(), action_id.get().as_bytes().as_slice()],
                |row| {
                    Ok(RawReceipt {
                        method: row.get(0)?,
                        method_version: row.get(1)?,
                        revision: row.get(2)?,
                        state: row.get(3)?,
                        reason: row.get(4)?,
                        payload_digest: row.get(5)?,
                        accepted_deadline_ms: row.get(6)?,
                        error_code: row.get(7)?,
                        error_message: row.get(8)?,
                        updated_at_ms: row.get(9)?,
                    })
                },
            )
            .optional()
            .map_err(|error| faulted(&self.health, error))?
            .map(|raw| raw.into_receipt(actor_id, action_id))
            .transpose()
    }

    /// Resolves every dispatch marker that has no authoritative outcome.
    ///
    /// This runs once at startup. A marker means the effect may already have happened, and nothing
    /// here can tell whether it did, so the receipt becomes `unknown` and that identifier is never
    /// dispatched again. Later authoritative reconciliation may still resolve it.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::JournalUnavailable`] when the write fails.
    pub fn resolve_unfinished_dispatches(&mut self, now_ms: TimestampMs) -> Result<usize> {
        let changed = self
            .connection
            .execute(
                "UPDATE receipts SET state = ?1, revision = revision + 1, updated_at_ms = ?2,
                        error_code = ?3, error_message = ?4
                 WHERE state = ?5",
                params![
                    ReceiptState::Unknown.as_str(),
                    i64::try_from(now_ms.get()).unwrap_or(i64::MAX),
                    ErrorCode::OutcomeUnknown.as_str(),
                    "the worker restarted after the dispatch marker and before an authoritative outcome",
                    ReceiptState::Dispatching.as_str(),
                ],
            )
            .map_err(|error| faulted(&self.health, error))?;
        Ok(changed)
    }

    /// Rejects every intent this journal accepted and never dispatched.
    ///
    /// This runs once at startup, beside [`Self::resolve_unfinished_dispatches`]. Section 9 permits
    /// an accepted intent with no dispatch marker to proceed after recovery **only if** the
    /// revalidation still passes, and otherwise requires a rejection. The freshness those intents
    /// were admitted under cannot be revalidated here: the deadline was decided on a continuous
    /// clock this process no longer has, and the connection and the window that admitted them are
    /// gone with the process that issued them. So every one of them is rejected as expired, which
    /// is the conservative direction and the one the contract names.
    ///
    /// It also releases the outstanding-mutation capacity those intents were holding, so an actor
    /// whose worker restarted mid-admission is not left unable to submit anything.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::JournalUnavailable`] when the write fails.
    pub fn reject_unrevalidated_intents(&mut self, now_ms: TimestampMs) -> Result<usize> {
        let pending = self.identities_in(&[ReceiptState::Accepted])?;
        let count = pending.len();
        for (actor_id, action_id) in pending {
            self.advance(
                actor_id,
                action_id,
                ReceiptState::Rejected,
                Some(RejectionReason::Expired),
                Some(ProtocolError::new(
                    ErrorCode::PermissionDenied,
                    "this intent was accepted before the worker restarted, and the freshness it \
                     was admitted under cannot be proved again",
                )),
                now_ms,
            )?;
        }
        Ok(count)
    }

    /// Deletes de-duplication records older than the retention period.
    ///
    /// Retention is a wall-clock period, and the wall clock is the thing that can move. A record
    /// this boot wrote is therefore kept while a freshness window that could admit its exact
    /// original request may still be live: a window lasts at most five minutes on the machine's
    /// continuous clock, and no step of the wall clock shortens that. Without the guard, a clock
    /// pushed thirty days forward inside those five minutes would delete the de-duplication record
    /// of an action whose own window still admitted it, and the original request would be admitted
    /// a second time.
    ///
    /// A record from an earlier boot needs no such guard. The windows a host issues live in its
    /// memory, so a host that has restarted can admit nothing through them.
    ///
    /// What retention does *not* promise is that a revocation can still name an action it has
    /// forgotten. Section 9 sets the period at thirty days and a revocation names what this host
    /// still retains; a name that a revocation owes is written into `fence_evidence` when the fence
    /// runs, and that row outlives the receipt it refers to.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::JournalUnavailable`] when the write fails.
    pub fn prune(&mut self, now_ms: TimestampMs) -> Result<usize> {
        let cutoff = i64::try_from(now_ms.get().saturating_sub(RETENTION_MS)).unwrap_or(i64::MAX);
        let continuous_floor = continuous_floor();
        let boot = self.boot.clone();
        // One selection, named once: the retained result, the event record and the observations
        // belong to the receipt, so they go when it goes. Leaving any of them behind would keep a
        // duplicate answerable after the receipt that authorises the answer had been forgotten.
        const SELECT: &str = "SELECT r.actor_id, r.action_id FROM receipts AS r
             WHERE r.created_at_ms < ?1
               AND (r.created_boot IS NULL OR ?2 IS NULL OR r.created_boot <> ?2
                    OR r.created_continuous_ms IS NULL OR r.created_continuous_ms < ?3)";
        let transaction = self
            .connection
            .transaction()
            .map_err(|error| faulted(&self.health, error))?;
        // The outbox rows of a receipt that is being forgotten go with it, and the consumer
        // cursors stay: a cursor past a record that no longer exists still says correctly that
        // the consumer has nothing to take, and resetting it would replay the whole journal.
        transaction
            .execute(
                &format!("DELETE FROM outbox WHERE (actor_id, action_id) IN ({SELECT})"),
                params![cutoff, boot, continuous_floor],
            )
            .map_err(|error| faulted(&self.health, error))?;
        for table in ["results", "receipt_events", "observations"] {
            transaction
                .execute(
                    &format!("DELETE FROM {table} WHERE (actor_id, action_id) IN ({SELECT})"),
                    params![cutoff, boot, continuous_floor],
                )
                .map_err(|error| faulted(&self.health, error))?;
        }
        let removed = transaction
            .execute(
                &format!("DELETE FROM receipts WHERE (actor_id, action_id) IN ({SELECT})"),
                params![cutoff, boot, continuous_floor],
            )
            .map_err(|error| faulted(&self.health, error))?;
        transaction
            .commit()
            .map_err(|error| faulted(&self.health, error))?;
        Ok(removed)
    }

    /// Prunes records past the retention period, at most once an interval.
    ///
    /// `permitted` is the host time contract's answer. Retention is expiry-based collection, and
    /// section 9 stops that while the wall clock cannot be proved: collecting against an unproved
    /// clock is how a rollback deletes something that had not expired. A host that cannot collect
    /// keeps its records and says nothing, which is the conservative direction.
    ///
    /// The schedule advances only when the prune succeeded, so a failure is retried rather than
    /// skipped for an hour. Nothing on the mutation path depends on the answer: retention is
    /// maintenance, and a maintenance failure must not decide what a caller is told about its own
    /// action.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::JournalUnavailable`] when the write fails.
    pub fn prune_if_due(&mut self, now_ms: TimestampMs, permitted: bool) -> Result<usize> {
        if !permitted || now_ms.get() < self.pruned_at_ms.saturating_add(PRUNE_INTERVAL_MS) {
            return Ok(0);
        }
        let removed = self.prune(now_ms)?;
        self.pruned_at_ms = now_ms.get();
        Ok(removed)
    }

    /// Reads the retained result of an action.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::JournalUnavailable`] when the read fails.
    pub fn read_result(&self, actor_id: &ActorId, action_id: ActionId) -> Result<Option<Vec<u8>>> {
        self.connection
            .query_row(
                "SELECT result FROM results WHERE actor_id = ?1 AND action_id = ?2",
                params![actor_id.as_str(), action_id.get().as_bytes().as_slice()],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()
            .map_err(|error| faulted(&self.health, error))
    }

    /// Opens a journal for reading only.
    ///
    /// A controller reads a closed session's journal to recover what the worker recorded: the
    /// closure it wrote, and the session it described. Opening read-only is what makes that safe
    /// to do beside a store the worker may still be finishing with.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::JournalUnavailable`] when the file cannot be opened or is not a
    /// journal this build reads.
    pub fn open_read_only(path: impl AsRef<std::path::Path>) -> Result<Self> {
        let connection = Connection::open_with_flags(
            path.as_ref(),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(unavailable)?;
        let recorded: i64 = connection
            .query_row("SELECT version FROM schema_version", [], |row| row.get(0))
            .map_err(unavailable)?;
        if recorded != SCHEMA_VERSION {
            return Err(unavailable_detail_owned(format!(
                "this journal is at schema version {recorded}; this build reads {SCHEMA_VERSION}"
            )));
        }
        Ok(Self {
            connection,
            pruned_at_ms: 0,
            health: crate::persistence::fault::JournalHealth::shared(),
            boot: None,
        })
    }

    /// Returns the condition this journal publishes.
    ///
    /// The handle is shared, so a consumer keeps it after the session's lock is released and is
    /// woken when the condition changes. It is the seam a volatile-native mode reads: while the
    /// condition is faulted, rich work is fenced and native terminal traffic continues.
    #[must_use]
    pub fn health(&self) -> &std::sync::Arc<crate::persistence::fault::JournalHealth> {
        &self.health
    }

    /// Tries to leave a fault, and writes down the interval it covered.
    ///
    /// The order is the contract. The gap is committed **first**, and the condition is cleared
    /// only once that commit has succeeded: a recovery whose gap could not be written is not a
    /// recovery, because the record would then read as continuous over an interval this host
    /// knows it did not write. A probe that fails leaves the fault exactly where it was.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::JournalUnavailable`] when the store is still failing.
    pub fn recover(
        &mut self,
        now_ms: TimestampMs,
    ) -> Result<Option<crate::persistence::fault::RecoveryGap>> {
        let Some(fault) = self.health.condition().fault().cloned() else {
            return Ok(None);
        };
        let resumed_at = self.event_high_water()?;
        let gap = crate::persistence::fault::RecoveryGap {
            kind: fault.kind,
            detail: fault.detail.clone(),
            faulted_at_ms: fault.observed_at_ms,
            recovered_at_ms: now_ms,
            durable_through: fault.durable_through,
            resumed_at,
        };
        self.connection
            .execute(
                "INSERT INTO journal_gaps (
                     kind, detail, faulted_at_ms, recovered_at_ms, durable_through, resumed_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    gap.kind.as_str(),
                    gap.detail.as_str(),
                    i64::try_from(gap.faulted_at_ms.get()).unwrap_or(i64::MAX),
                    i64::try_from(gap.recovered_at_ms.get()).unwrap_or(i64::MAX),
                    i64::try_from(gap.durable_through).unwrap_or(i64::MAX),
                    i64::try_from(gap.resumed_at).unwrap_or(i64::MAX),
                ],
            )
            .map_err(|error| faulted(&self.health, error))?;
        self.health.note_recovered();
        Ok(Some(gap))
    }

    /// Returns every interval durable writing was unavailable, oldest first.
    ///
    /// A reader of this journal sees them beside what it holds, so a run of receipts across one
    /// of these intervals is read as incomplete rather than as a quiet stretch.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::JournalUnavailable`] when the read fails.
    pub fn recovery_gaps(&self) -> Result<Vec<crate::persistence::fault::RecoveryGap>> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT kind, detail, faulted_at_ms, recovered_at_ms, durable_through, resumed_at
                 FROM journal_gaps ORDER BY sequence",
            )
            .map_err(|error| faulted(&self.health, error))?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            })
            .map_err(|error| faulted(&self.health, error))?;
        let mut gaps = Vec::new();
        for row in rows {
            let (kind, detail, faulted_at, recovered_at, durable_through, resumed_at) =
                row.map_err(unavailable)?;
            gaps.push(crate::persistence::fault::RecoveryGap {
                kind: crate::persistence::fault::FaultKind::from_str(&kind).ok_or_else(|| {
                    unavailable_detail("a stored fault kind is not one this build writes")
                })?,
                detail,
                faulted_at_ms: TimestampMs::new(u64::try_from(faulted_at).unwrap_or(0)),
                recovered_at_ms: TimestampMs::new(u64::try_from(recovered_at).unwrap_or(0)),
                durable_through: u64::try_from(durable_through).unwrap_or(0),
                resumed_at: u64::try_from(resumed_at).unwrap_or(0),
            });
        }
        Ok(gaps)
    }

    /// Returns one page of the outbox after a cursor.
    ///
    /// Delivery is at-least-once: this read takes nothing and moves nothing, so a consumer that
    /// dies before it records its cursor is handed the same page again. The immutable event
    /// identifier is what lets it apply each record once.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::JournalUnavailable`] when the read fails.
    pub fn outbox_after(
        &self,
        cursor: u64,
        limit: u64,
    ) -> Result<Vec<crate::persistence::outbox::OutboxRecord>> {
        use crate::persistence::outbox::{OutboxEvent, OutboxRecord, Subsystem};

        let mut statement = self
            .connection
            .prepare(
                "SELECT cursor, event_id, stream, source, actor_id, action_id, subject_revision,
                        content, detail, recorded_at_ms
                 FROM outbox WHERE cursor > ?1 ORDER BY cursor LIMIT ?2",
            )
            .map_err(|error| faulted(&self.health, error))?;
        let rows = statement
            .query_map(
                params![
                    i64::try_from(cursor).unwrap_or(i64::MAX),
                    i64::try_from(limit).unwrap_or(i64::MAX)
                ],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, Option<String>>(4)?,
                        row.get::<_, Option<Vec<u8>>>(5)?,
                        row.get::<_, i64>(6)?,
                        row.get::<_, String>(7)?,
                        row.get::<_, String>(8)?,
                        row.get::<_, i64>(9)?,
                    ))
                },
            )
            .map_err(|error| faulted(&self.health, error))?;
        let mut records = Vec::new();
        for row in rows {
            let (
                cursor,
                event_id,
                stream,
                source,
                actor_id,
                action_id,
                subject_revision,
                content,
                detail,
                recorded_at_ms,
            ) = row.map_err(unavailable)?;
            records.push(OutboxRecord {
                cursor: u64::try_from(cursor).unwrap_or(0),
                event: OutboxEvent {
                    event_id: uuid_from(&event_id)?,
                    stream: parse_stream(&stream)?,
                    source: Subsystem::from_str(&source).ok_or_else(|| {
                        unavailable_detail("a stored subsystem is not one this build writes")
                    })?,
                    actor_id: actor_id
                        .map(|actor| {
                            ActorId::new(actor)
                                .map_err(|_| unavailable_detail("a stored actor is not valid"))
                        })
                        .transpose()?,
                    action_id: action_id
                        .map(|bytes| uuid_from(&bytes).map(ActionId::new))
                        .transpose()?,
                    subject_revision: u64::try_from(subject_revision).unwrap_or(0),
                    causal_root: None,
                    causal_parent: None,
                    content: parse_content_class(&content)?,
                    detail,
                    recorded_at_ms: TimestampMs::new(u64::try_from(recorded_at_ms).unwrap_or(0)),
                },
            });
        }
        Ok(records)
    }

    /// Returns where one consumer has got to.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::JournalUnavailable`] when the read fails.
    pub fn outbox_cursor(
        &self,
        consumer: &str,
    ) -> Result<crate::persistence::outbox::OutboxCursor> {
        let row: Option<(i64, i64)> = self
            .connection
            .query_row(
                "SELECT cursor, delivered FROM outbox_cursors WHERE consumer = ?1",
                params![consumer],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|error| faulted(&self.health, error))?;
        let (cursor, delivered) = row.unwrap_or((0, 0));
        Ok(crate::persistence::outbox::OutboxCursor {
            consumer: consumer.to_owned(),
            cursor: u64::try_from(cursor).unwrap_or(0),
            delivered: u64::try_from(delivered).unwrap_or(0),
        })
    }

    /// Records that a consumer has taken everything up to a cursor.
    ///
    /// A cursor never goes backwards: a consumer that replays an older page and then records what
    /// it took would otherwise hand itself every record between twice.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::JournalUnavailable`] when the write fails.
    pub fn note_outbox_consumed(
        &mut self,
        consumer: &str,
        cursor: u64,
        applied: u64,
    ) -> Result<()> {
        self.connection
            .execute(
                "INSERT INTO outbox_cursors (consumer, cursor, delivered) VALUES (?1, ?2, ?3)
                 ON CONFLICT (consumer) DO UPDATE SET
                     cursor = MAX(outbox_cursors.cursor, excluded.cursor),
                     delivered = outbox_cursors.delivered + excluded.delivered",
                params![
                    consumer,
                    i64::try_from(cursor).unwrap_or(i64::MAX),
                    i64::try_from(applied).unwrap_or(i64::MAX),
                ],
            )
            .map_err(|error| faulted(&self.health, error))?;
        Ok(())
    }

    /// Writes down what the host's time contract has to survive a restart.
    ///
    /// One row, replaced each time. There is nothing to accumulate: the state is what the contract
    /// holds now, and an earlier copy of it says nothing a restarted host needs.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::JournalUnavailable`] when the write fails.
    pub fn record_host_time(&mut self, state: &kr_protocol::action::HostTimeState) -> Result<()> {
        let encoded = kr_cbor::to_canonical_vec(state)
            .map_err(|error| unavailable_detail_owned(error.to_string()))?;
        self.connection
            .execute(
                "INSERT INTO host_time (id, state) VALUES (1, ?1)
                 ON CONFLICT (id) DO UPDATE SET state = excluded.state",
                params![encoded],
            )
            .map_err(|error| faulted(&self.health, error))?;
        Ok(())
    }

    /// Reads back what the host wrote down about its clocks.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::JournalUnavailable`] when the row cannot be read or cannot be
    /// decoded. A caller that cannot read this must not fall back to "nothing was recorded":
    /// nothing recorded means a host with no history, and this is a host whose history is
    /// unreadable. The two lead to opposite conclusions about a clock.
    pub fn read_host_time(&self) -> Result<Option<kr_protocol::action::HostTimeState>> {
        let encoded: Option<Vec<u8>> = self
            .connection
            .query_row("SELECT state FROM host_time WHERE id = 1", [], |row| {
                row.get(0)
            })
            .optional()
            .map_err(|error| faulted(&self.health, error))?;
        encoded
            .map(|bytes| {
                kr_cbor::from_canonical_slice(&bytes, &kr_cbor::Limits::DEFAULT)
                    .map_err(|error| unavailable_detail_owned(error.to_string()))
            })
            .transpose()
    }

    /// Records what the session is, so a reader can describe it after the worker has gone.
    ///
    /// Without this the only thing left of a closed session is its closure record, and a summary
    /// rebuilt from that alone loses the shell it ran, the directory it ran in and when it started.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::JournalUnavailable`] when the write fails.
    pub fn record_session(&mut self, summary: &kr_protocol::session::SessionSummary) -> Result<()> {
        let encoded = kr_cbor::to_canonical_vec(summary)
            .map_err(|error| unavailable_detail_owned(error.to_string()))?;
        self.connection
            .execute(
                "INSERT INTO session (session_id, summary) VALUES (?1, ?2)
                 ON CONFLICT (session_id) DO UPDATE SET summary = excluded.summary",
                params![summary.session_id.get().as_bytes().as_slice(), encoded],
            )
            .map_err(|error| faulted(&self.health, error))?;
        Ok(())
    }

    /// Reads the session a journal describes.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::JournalUnavailable`] when the read fails.
    pub fn read_session(
        &self,
        session_id: kr_protocol::ids::SessionId,
    ) -> Result<Option<kr_protocol::session::SessionSummary>> {
        let encoded: Option<Vec<u8>> = self
            .connection
            .query_row(
                "SELECT summary FROM session WHERE session_id = ?1",
                params![session_id.get().as_bytes().as_slice()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| faulted(&self.health, error))?;
        encoded
            .map(|bytes| {
                kr_cbor::from_canonical_slice(&bytes, &kr_cbor::Limits::DEFAULT)
                    .map_err(|error| unavailable_detail_owned(error.to_string()))
            })
            .transpose()
    }

    /// Records the session's final closure.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::JournalUnavailable`] when the record cannot be written.
    pub fn record_closure(&mut self, record: &kr_protocol::session::ClosureRecord) -> Result<()> {
        let encoded = kr_cbor::to_canonical_vec(record)
            .map_err(|error| unavailable_detail_owned(error.to_string()))?;
        self.connection
            .execute(
                "INSERT INTO closure (session_id, record) VALUES (?1, ?2)
                 ON CONFLICT (session_id) DO UPDATE SET record = excluded.record",
                params![record.session_id.get().as_bytes().as_slice(), encoded],
            )
            .map_err(|error| faulted(&self.health, error))?;
        Ok(())
    }

    /// Reads a recorded closure.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::JournalUnavailable`] when the read fails.
    pub fn read_closure(
        &self,
        session_id: kr_protocol::ids::SessionId,
    ) -> Result<Option<kr_protocol::session::ClosureRecord>> {
        let encoded: Option<Vec<u8>> = self
            .connection
            .query_row(
                "SELECT record FROM closure WHERE session_id = ?1",
                params![session_id.get().as_bytes().as_slice()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| faulted(&self.health, error))?;
        encoded
            .map(|bytes| {
                kr_cbor::from_canonical_slice(&bytes, &kr_cbor::Limits::DEFAULT)
                    .map_err(|error| unavailable_detail_owned(error.to_string()))
            })
            .transpose()
    }

    /// Returns how many receipts the journal holds.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::JournalUnavailable`] when the read fails.
    pub fn len(&self) -> Result<u64> {
        let count: i64 = self
            .connection
            .query_row("SELECT COUNT(*) FROM receipts", [], |row| row.get(0))
            .map_err(|error| faulted(&self.health, error))?;
        Ok(u64::try_from(count).unwrap_or(0))
    }

    /// Returns true when the journal holds no receipts.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::JournalUnavailable`] when the read fails.
    pub fn is_empty(&self) -> Result<bool> {
        Ok(self.len()? == 0)
    }
}

struct RawReceipt {
    method: String,
    method_version: i64,
    revision: i64,
    state: String,
    reason: Option<String>,
    payload_digest: Vec<u8>,
    accepted_deadline_ms: Option<i64>,
    error_code: Option<String>,
    error_message: Option<String>,
    updated_at_ms: i64,
}

impl RawReceipt {
    fn into_receipt(self, actor_id: ActorId, action_id: ActionId) -> Result<Receipt> {
        let digest = <[u8; 32]>::try_from(self.payload_digest.as_slice())
            .map_err(|_| unavailable_detail("a stored payload digest is not 32 bytes"))?;
        let error = match (self.error_code, self.error_message) {
            (Some(code), Some(message)) => {
                let code = code.parse::<ErrorCode>().map_err(|_| {
                    unavailable_detail("a stored error code is not in the registry")
                })?;
                Some(ProtocolError::new(code, message))
            }
            _ => None,
        };
        Ok(Receipt {
            action_id,
            actor_id,
            method: MethodName::new(self.method)
                .map_err(|_| unavailable_detail("a stored method name is not valid"))?,
            method_version: method_version_from(self.method_version)?,
            revision: U64::new(u64::try_from(self.revision).unwrap_or(0)),
            state: parse_state(&self.state)?,
            reason: Nullable(self.reason.as_deref().and_then(parse_reason)),
            payload_digest: Digest256::from_bytes(digest),
            accepted_deadline_ms: Nullable(
                self.accepted_deadline_ms
                    .map(|deadline| TimestampMs::new(u64::try_from(deadline).unwrap_or(0))),
            ),
            error: Nullable(error),
            updated_at_ms: TimestampMs::new(u64::try_from(self.updated_at_ms).unwrap_or(0)),
        })
    }
}

/// Appends one name to a revocation's evidence, at the next position.
///
/// The position is what paging reads in order, and the key is the revision, the kind, the actor and
/// the action together: a second pass over the same revision names what it names again, and naming
/// it twice would deliver it twice. Two actors may each have used one identifier, which is why the
/// actor is part of the key rather than beside it.
///
/// It takes the connection rather than the journal so a caller can put it in a transaction with
/// whatever made the name true.
fn name_evidence(
    health: &crate::persistence::fault::JournalHealth,
    connection: &Connection,
    revision: u64,
    kind: &str,
    actor_id: &ActorId,
    action_id: ActionId,
    method: Option<&str>,
    state: Option<&str>,
) -> Result<bool> {
    let revision = i64::try_from(revision).unwrap_or(i64::MAX);
    let changed = connection
        .execute(
            "INSERT OR IGNORE INTO fence_evidence
                 (revision, position, kind, actor_id, action_id, method, state)
             VALUES (
                 ?1,
                 (SELECT COALESCE(MAX(position), 0) + 1 FROM fence_evidence WHERE revision = ?1),
                 ?2, ?3, ?4, ?5, ?6
             )",
            params![
                revision,
                kind,
                actor_id.as_str(),
                action_id.get().as_bytes().as_slice(),
                method,
                state
            ],
        )
        .map_err(|error| faulted(health, error))?;
    Ok(changed > 0)
}

fn parse_state(text: &str) -> Result<ReceiptState> {
    ReceiptState::ALL
        .iter()
        .copied()
        .find(|state| state.as_str() == text)
        .ok_or_else(|| unavailable_detail("a stored receipt state is not in the contract"))
}

fn parse_actor(value: String) -> Result<ActorId> {
    ActorId::new(value).map_err(|_| unavailable_detail("a stored actor is not valid"))
}

fn parse_action(value: &[u8]) -> Result<ActionId> {
    let bytes = <[u8; 16]>::try_from(value)
        .map_err(|_| unavailable_detail("a stored action identifier is not 16 bytes"))?;
    Ok(ActionId::new(Uuid::from_bytes(bytes)))
}

fn parse_provenance(text: &str) -> Result<ObservationProvenance> {
    ObservationProvenance::ALL
        .iter()
        .copied()
        .find(|provenance| provenance.as_str() == text)
        .ok_or_else(|| unavailable_detail("a stored observation provenance is not in the registry"))
}

fn parse_claimed_result(text: &str) -> Result<ObservedResult> {
    match text {
        "applied" => Ok(ObservedResult::Applied),
        "refused" => Ok(ObservedResult::Refused),
        "indeterminate" => Ok(ObservedResult::Indeterminate),
        _ => Err(unavailable_detail(
            "a stored observation result is not in the registry",
        )),
    }
}

fn parse_reason(text: &str) -> Option<RejectionReason> {
    [
        RejectionReason::AdmissionFailed,
        RejectionReason::Expired,
        RejectionReason::Cancelled,
        RejectionReason::Revoked,
        RejectionReason::StalePreconditions,
    ]
    .into_iter()
    .find(|reason| reason.as_str() == text)
}

const fn method_version_number(version: MethodVersion) -> u16 {
    version.0
}

fn method_version_from(value: i64) -> Result<MethodVersion> {
    u16::try_from(value)
        .map(MethodVersion)
        .map_err(|_| unavailable_detail("a stored method version is out of range"))
}

/// Builds an action identifier from a fresh random value.
#[must_use]
pub fn new_action_id() -> ActionId {
    ActionId::new(kr_ipc::new_uuid())
}

/// Builds a request identifier for a host-originated call.
#[must_use]
pub const fn request_id(value: u64) -> RequestId {
    RequestId::new(value)
}

/// Builds an action identifier from raw bytes, for tests and fixtures.
#[must_use]
pub const fn action_id_from(bytes: [u8; 16]) -> ActionId {
    ActionId::new(Uuid::from_bytes(bytes))
}

/// Turns one storage failure into a refusal, and reports it to the health seam.
///
/// Every durable path in this file goes through here, which is what makes the seam's condition a
/// fact about the store rather than a summary somebody remembered to update.
fn faulted(
    health: &crate::persistence::fault::JournalHealth,
    error: rusqlite::Error,
) -> WorkerError {
    health.observe(&error, kr_ipc::now_ms().get());
    WorkerError::JournalUnavailable {
        detail: error.to_string(),
    }
}

/// Turns one storage failure into a refusal without a seam to report it to.
///
/// Used where the failure is a decoding failure rather than the store refusing to answer: what a
/// stored row means is this build's business, and a value it cannot read is not the store saying
/// it has stopped working.
fn uuid_from(bytes: &[u8]) -> Result<Uuid> {
    let raw: [u8; 16] = bytes
        .try_into()
        .map_err(|_| unavailable_detail("a stored identifier is not sixteen bytes"))?;
    Ok(Uuid::from_bytes(raw))
}

fn parse_stream(value: &str) -> Result<kr_protocol::recovery::EventStream> {
    kr_protocol::recovery::EventStream::ALL
        .iter()
        .copied()
        .find(|stream| stream.as_str() == value)
        .ok_or_else(|| unavailable_detail("a stored stream is not one this build writes"))
}

fn parse_content_class(value: &str) -> Result<crate::persistence::stores::ContentClass> {
    use crate::persistence::stores::ContentClass;

    match value {
        "metadata" => Ok(ContentClass::Metadata),
        "terminal" => Ok(ContentClass::TerminalContent),
        "authored" => Ok(ContentClass::AuthoredContent),
        "secret" => Ok(ContentClass::Secret),
        _ => Err(unavailable_detail(
            "a stored content class is not one this build writes",
        )),
    }
}

fn unavailable(error: rusqlite::Error) -> WorkerError {
    WorkerError::JournalUnavailable {
        detail: error.to_string(),
    }
}

fn unavailable_detail(detail: &str) -> WorkerError {
    WorkerError::JournalUnavailable {
        detail: detail.to_owned(),
    }
}

fn unavailable_detail_owned(detail: String) -> WorkerError {
    WorkerError::JournalUnavailable { detail }
}

/// One side effect that had no attachment to go to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostEvent {
    /// What the application asked for.
    pub kind: String,
    /// What it said, with no content a person did not ask to keep.
    pub detail: String,
    /// Where in the output stream it happened.
    pub output_cursor: u64,
    /// When the host recorded it.
    pub recorded_at_ms: TimestampMs,
}

/// Returns the kind and the description one side effect is recorded under.
fn describe_effect(kind: &kr_term::sideeffect::SideEffectKind) -> (&'static str, String) {
    use kr_term::sideeffect::SideEffectKind;
    match kind {
        SideEffectKind::Bell => ("bell", String::new()),
        SideEffectKind::Notification {
            title,
            body,
            urgency,
            ..
        } => (
            "notification",
            match title {
                Some(title) => format!("{urgency:?}: {title} - {body}"),
                None => format!("{urgency:?}: {body}"),
            },
        ),
        SideEffectKind::Progress { progress } => ("progress", format!("{progress:?}")),
        // The content is not kept. Nothing has asked for it, and a durable copy of somebody's
        // clipboard with no reader is a copy nobody wanted.
        SideEffectKind::ClipboardWrite { selection, content } => (
            "clipboard_write",
            format!("{selection:?}, {} bytes", content.len()),
        ),
        SideEffectKind::ClipboardRead { selection } => ("clipboard_read", format!("{selection:?}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn actor() -> ActorId {
        ActorId::new("local:501").expect("an actor identifier")
    }

    fn submission(action: u8, digest: u8) -> Submission {
        Submission {
            actor_id: actor(),
            action_id: action_id_from([action; 16]),
            method: kr_protocol::method::Method::SessionClose.into(),
            method_version: MethodVersion::V1,
            payload_digest: Digest256::from_bytes([digest; 32]),
            subject_digest: Digest256::from_bytes([digest ^ 0xff; 32]),
            intent: vec![0xa0],
            accepted_deadline_ms: Some(TimestampMs::new(10_000)),
            now_ms: TimestampMs::new(1_000),
        }
    }

    #[test]
    fn an_accepted_intent_is_committed_before_it_is_acknowledged() {
        let mut journal = Journal::in_memory().expect("opens");
        let admission = journal.accept(&submission(1, 1)).expect("accepts");
        assert_eq!(admission.receipt.state, ReceiptState::Accepted);
        assert!(!admission.deduplicated);
        assert!(!admission.receipt.state.has_dispatch_marker());
        let stored = journal
            .read(actor(), action_id_from([1; 16]))
            .expect("reads")
            .expect("present");
        assert_eq!(stored, admission.receipt);
    }

    #[test]
    fn an_exact_retry_returns_the_retained_receipt_with_its_original_deadline() {
        let mut journal = Journal::in_memory().expect("opens");
        let first = journal.accept(&submission(2, 7)).expect("accepts");
        let mut retry = submission(2, 7);
        retry.now_ms = TimestampMs::new(9_000);
        retry.accepted_deadline_ms = Some(TimestampMs::new(99_000));
        let second = journal.accept(&retry).expect("deduplicates");
        assert!(second.deduplicated);
        assert_eq!(second.receipt, first.receipt);
        assert_eq!(
            second.receipt.accepted_deadline_ms.as_ref(),
            Some(&TimestampMs::new(10_000)),
            "a retry never receives a new deadline"
        );
    }

    #[test]
    fn a_reused_identifier_with_a_different_payload_is_a_conflict() {
        let mut journal = Journal::in_memory().expect("opens");
        journal.accept(&submission(3, 1)).expect("accepts");
        assert!(matches!(
            journal.accept(&submission(3, 2)),
            Err(WorkerError::IdConflict { .. })
        ));
    }

    #[test]
    fn a_dispatch_marker_cannot_become_a_rejection() {
        let mut journal = Journal::in_memory().expect("opens");
        journal.accept(&submission(4, 1)).expect("accepts");
        journal
            .mark_dispatching(actor(), action_id_from([4; 16]), TimestampMs::new(1_100))
            .expect("marks");
        assert!(matches!(
            journal.reject(
                actor(),
                action_id_from([4; 16]),
                RejectionReason::Cancelled,
                None,
                TimestampMs::new(1_200)
            ),
            Err(WorkerError::InvalidArgument(_))
        ));
    }

    #[test]
    fn a_marker_without_an_outcome_becomes_unknown_after_a_restart() {
        let mut journal = Journal::in_memory().expect("opens");
        journal.accept(&submission(5, 1)).expect("accepts");
        journal
            .mark_dispatching(actor(), action_id_from([5; 16]), TimestampMs::new(1_100))
            .expect("marks");
        let resolved = journal
            .resolve_unfinished_dispatches(TimestampMs::new(2_000))
            .expect("resolves");
        assert_eq!(resolved, 1);
        let receipt = journal
            .read(actor(), action_id_from([5; 16]))
            .expect("reads")
            .expect("present");
        assert_eq!(receipt.state, ReceiptState::Unknown);
        assert!(receipt.state.has_dispatch_marker());
        assert_eq!(
            receipt.error.as_ref().map(|error| error.code),
            Some(ErrorCode::OutcomeUnknown)
        );
    }

    #[test]
    fn an_unknown_outcome_can_still_be_reconciled_but_never_rejected() {
        let mut journal = Journal::in_memory().expect("opens");
        journal.accept(&submission(6, 1)).expect("accepts");
        journal
            .mark_dispatching(actor(), action_id_from([6; 16]), TimestampMs::new(1_100))
            .expect("marks");
        journal
            .resolve_unfinished_dispatches(TimestampMs::new(2_000))
            .expect("resolves");
        let reconciled = journal
            .settle(
                actor(),
                action_id_from([6; 16]),
                ReceiptState::Applied,
                None,
                None,
                TimestampMs::new(3_000),
            )
            .expect("reconciles");
        assert_eq!(reconciled.state, ReceiptState::Applied);
    }

    #[test]
    fn a_receipt_survives_reopening_the_journal() {
        let directory = std::env::temp_dir().join(format!("kr-journal-{}", kr_ipc::new_uuid()));
        std::fs::create_dir_all(&directory).expect("directory");
        let path = directory.join("session.sqlite");
        {
            let mut journal = Journal::open(&path).expect("opens");
            journal.accept(&submission(7, 3)).expect("accepts");
            journal
                .mark_dispatching(actor(), action_id_from([7; 16]), TimestampMs::new(1_100))
                .expect("marks");
        }
        let mut reopened = Journal::open(&path).expect("reopens");
        assert_eq!(
            reopened
                .resolve_unfinished_dispatches(TimestampMs::new(5_000))
                .expect("resolves"),
            1
        );
        let receipt = reopened
            .read(actor(), action_id_from([7; 16]))
            .expect("reads")
            .expect("present");
        assert_eq!(receipt.state, ReceiptState::Unknown);
        assert_eq!(receipt.revision.get(), 3);
        std::fs::remove_dir_all(&directory).ok();
    }

    #[test]
    fn records_older_than_the_retention_period_are_removed() {
        let mut journal = Journal::in_memory().expect("opens");
        journal.accept(&submission(8, 1)).expect("accepts");
        assert_eq!(journal.prune(TimestampMs::new(1_500)).expect("prunes"), 0);
        // Past the wall-clock period, and still kept: this boot wrote the record moments ago, so
        // a window that would admit its original request can still be live. A clock pushed thirty
        // days forward does not make a record from five seconds ago thirty days old.
        assert_eq!(
            journal
                .prune(TimestampMs::new(RETENTION_MS + 2_000))
                .expect("prunes"),
            0
        );
        assert!(!journal.is_empty().expect("counts"));
        // Once the record's continuous reading is older than the longest window this host issues,
        // no window can admit the original request any more and the wall-clock period decides.
        journal
            .connection
            .execute(
                "UPDATE receipts SET created_continuous_ms = ?1",
                params![continuous_floor() - 1],
            )
            .expect("ages the record");
        assert_eq!(journal.prune(TimestampMs::new(1_500)).expect("prunes"), 0);
        assert_eq!(
            journal
                .prune(TimestampMs::new(RETENTION_MS + 2_000))
                .expect("prunes"),
            1
        );
        assert!(journal.is_empty().expect("counts"));
    }

    #[test]
    fn a_record_from_an_earlier_boot_needs_no_window_guard() {
        let mut journal = Journal::in_memory().expect("opens");
        journal.accept(&submission(9, 1)).expect("accepts");
        // The windows a host issues live in its memory, so a host that has restarted can admit
        // nothing through them. The record's continuous reading belongs to a clock that is gone.
        journal
            .connection
            .execute("UPDATE receipts SET created_boot = 'an-earlier-boot'", [])
            .expect("moves the record to an earlier boot");
        assert_eq!(
            journal
                .prune(TimestampMs::new(RETENTION_MS + 2_000))
                .expect("prunes"),
            1
        );
    }
}
