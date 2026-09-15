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
pub const SCHEMA_VERSION: i64 = 2;

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
        let journal = Self { connection };
        journal.migrate()?;
        Ok(journal)
    }

    fn migrate(&self) -> Result<()> {
        // Forward-only migrations keyed by a schema version. The code reads one current schema
        // after migration; there is no second reader for an older shape.
        self.connection
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL);
                 CREATE TABLE IF NOT EXISTS receipts (
                     actor_id             TEXT    NOT NULL,
                     action_id            BLOB    NOT NULL,
                     method               TEXT    NOT NULL,
                     method_version       INTEGER NOT NULL,
                     revision             INTEGER NOT NULL,
                     state                TEXT    NOT NULL,
                     reason               TEXT,
                     payload_digest       BLOB    NOT NULL,
                     intent               BLOB    NOT NULL,
                     accepted_deadline_ms INTEGER,
                     error_code           TEXT,
                     error_message        TEXT,
                     created_at_ms        INTEGER NOT NULL,
                     updated_at_ms        INTEGER NOT NULL,
                     PRIMARY KEY (actor_id, action_id)
                 );
                 CREATE INDEX IF NOT EXISTS receipts_created_at ON receipts (created_at_ms);
                 CREATE TABLE IF NOT EXISTS results (
                     actor_id  TEXT NOT NULL,
                     action_id BLOB NOT NULL,
                     result    BLOB NOT NULL,
                     PRIMARY KEY (actor_id, action_id),
                     FOREIGN KEY (actor_id, action_id)
                         REFERENCES receipts (actor_id, action_id) ON DELETE CASCADE
                 );
                 CREATE TABLE IF NOT EXISTS receipt_events (
                     sequence      INTEGER PRIMARY KEY AUTOINCREMENT,
                     actor_id      TEXT    NOT NULL,
                     action_id     BLOB    NOT NULL,
                     revision      INTEGER NOT NULL,
                     state         TEXT    NOT NULL,
                     recorded_at_ms INTEGER NOT NULL,
                     FOREIGN KEY (actor_id, action_id)
                         REFERENCES receipts (actor_id, action_id) ON DELETE CASCADE
                 );
                 CREATE TABLE IF NOT EXISTS closure (
                     session_id BLOB PRIMARY KEY,
                     record     BLOB NOT NULL
                 );",
            )
            .map_err(unavailable)?;
        let recorded: Option<i64> = self
            .connection
            .query_row("SELECT version FROM schema_version", [], |row| row.get(0))
            .optional()
            .map_err(unavailable)?;
        match recorded {
            None => {
                self.connection
                    .execute(
                        "INSERT INTO schema_version (version) VALUES (?1)",
                        params![SCHEMA_VERSION],
                    )
                    .map_err(unavailable)?;
            }
            Some(version) if version == SCHEMA_VERSION => {}
            Some(version) => {
                // Migrations are forward-only and this build reads one schema. A journal written
                // by a later build is refused rather than read as though it were this one.
                return Err(unavailable_detail_owned(format!(
                    "this journal is at schema version {version}; this build reads {SCHEMA_VERSION}"
                )));
            }
        }
        Ok(())
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
        self.connection
            .execute(
                "INSERT INTO receipts (actor_id, action_id, method, method_version, revision,
                     state, reason, payload_digest, intent, accepted_deadline_ms, error_code,
                     error_message, created_at_ms, updated_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, ?7, ?8, ?9, NULL, NULL, ?10, ?10)",
                params![
                    receipt.actor_id.as_str(),
                    receipt.action_id.get().as_bytes().as_slice(),
                    receipt.method.as_str(),
                    i64::from(method_version_number(receipt.method_version)),
                    1_i64,
                    ReceiptState::Accepted.as_str(),
                    receipt.payload_digest.as_bytes().as_slice(),
                    submission.intent.as_slice(),
                    submission
                        .accepted_deadline_ms
                        .map(|deadline| i64::try_from(deadline.get()).unwrap_or(i64::MAX)),
                    i64::try_from(submission.now_ms.get()).unwrap_or(i64::MAX),
                ],
            )
            .map_err(unavailable)?;
        self.append_event(&receipt)?;
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
        self.connection
            .query_row(
                "SELECT intent FROM receipts WHERE actor_id = ?1 AND action_id = ?2",
                params![actor_id.as_str(), action_id.get().as_bytes().as_slice()],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()
            .map_err(unavailable)
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

        let transaction = self.connection.transaction().map_err(unavailable)?;
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
                .map_err(unavailable)?;
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
            .map_err(unavailable)?;
        transaction
            .execute(
                "INSERT INTO receipt_events (actor_id, action_id, revision, state, recorded_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    receipt.actor_id.as_str(),
                    receipt.action_id.get().as_bytes().as_slice(),
                    i64::try_from(receipt.revision.get()).unwrap_or(i64::MAX),
                    receipt.state.as_str(),
                    i64::try_from(now_ms.get()).unwrap_or(i64::MAX),
                ],
            )
            .map_err(unavailable)?;
        transaction.commit().map_err(unavailable)?;
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
            .map_err(unavailable)?;
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
            .map_err(unavailable)?;
        let mut events = Vec::new();
        for row in rows {
            let (sequence, actor, action, revision, state, recorded) = row.map_err(unavailable)?;
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

    fn append_event(&self, receipt: &Receipt) -> Result<()> {
        self.connection
            .execute(
                "INSERT INTO receipt_events (actor_id, action_id, revision, state, recorded_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    receipt.actor_id.as_str(),
                    receipt.action_id.get().as_bytes().as_slice(),
                    i64::try_from(receipt.revision.get()).unwrap_or(i64::MAX),
                    receipt.state.as_str(),
                    i64::try_from(receipt.updated_at_ms.get()).unwrap_or(i64::MAX),
                ],
            )
            .map_err(unavailable)?;
        Ok(())
    }

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

    /// Records the authoritative outcome of a dispatched action.
    ///
    /// # Errors
    ///
    /// Returns an error when the transition is not permitted or the write fails.
    pub fn complete(
        &mut self,
        actor_id: ActorId,
        action_id: ActionId,
        state: ReceiptState,
        error: Option<ProtocolError>,
        now_ms: TimestampMs,
    ) -> Result<Receipt> {
        self.advance(actor_id, action_id, state, None, error, now_ms)
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
        let mut receipt = self
            .read(actor_id.clone(), action_id)?
            .ok_or_else(|| WorkerError::InvalidArgument(format!("no receipt for {action_id}")))?;
        let revision = U64::new(receipt.revision.get() + 1);
        receipt.advance(state, revision, reason).map_err(|error| {
            WorkerError::InvalidArgument(format!("receipt transition refused: {error}"))
        })?;
        receipt.error = Nullable(error);
        receipt.updated_at_ms = now_ms;
        self.write_state(&receipt)?;
        self.append_event(&receipt)?;
        Ok(receipt)
    }

    fn write_state(&self, receipt: &Receipt) -> Result<()> {
        self.connection
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
            .map_err(unavailable)?;
        Ok(())
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
            .map_err(unavailable)?
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
            .map_err(unavailable)?;
        Ok(changed)
    }

    /// Deletes de-duplication records older than the retention period.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::JournalUnavailable`] when the write fails.
    pub fn prune(&mut self, now_ms: TimestampMs) -> Result<usize> {
        let cutoff = i64::try_from(now_ms.get().saturating_sub(RETENTION_MS)).unwrap_or(i64::MAX);
        // The retained result and the event record are the receipt's, so they go when it goes.
        // Leaving either behind would keep a duplicate answerable after the receipt that
        // authorises the answer had been forgotten.
        let transaction = self.connection.transaction().map_err(unavailable)?;
        transaction
            .execute(
                "DELETE FROM results WHERE (actor_id, action_id) IN
                     (SELECT actor_id, action_id FROM receipts WHERE created_at_ms < ?1)",
                params![cutoff],
            )
            .map_err(unavailable)?;
        transaction
            .execute(
                "DELETE FROM receipt_events WHERE (actor_id, action_id) IN
                     (SELECT actor_id, action_id FROM receipts WHERE created_at_ms < ?1)",
                params![cutoff],
            )
            .map_err(unavailable)?;
        let removed = transaction
            .execute(
                "DELETE FROM receipts WHERE created_at_ms < ?1",
                params![cutoff],
            )
            .map_err(unavailable)?;
        transaction.commit().map_err(unavailable)?;
        Ok(removed)
    }

    /// Stores the result a duplicate request must receive back.
    ///
    /// A retry of `session.attach` has to be given the attachment the first request allocated, not
    /// a second one. Keeping the result beside the receipt is what makes that possible.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::JournalUnavailable`] when the write fails.
    pub fn record_result(
        &mut self,
        actor_id: &ActorId,
        action_id: ActionId,
        result: &[u8],
    ) -> Result<()> {
        self.connection
            .execute(
                "INSERT INTO results (actor_id, action_id, result) VALUES (?1, ?2, ?3)
                 ON CONFLICT (actor_id, action_id) DO UPDATE SET result = excluded.result",
                params![
                    actor_id.as_str(),
                    action_id.get().as_bytes().as_slice(),
                    result
                ],
            )
            .map_err(unavailable)?;
        Ok(())
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
            .map_err(unavailable)
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
            .map_err(unavailable)?;
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
            .map_err(unavailable)?;
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
            .map_err(unavailable)?;
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

fn parse_state(text: &str) -> Result<ReceiptState> {
    ReceiptState::ALL
        .iter()
        .copied()
        .find(|state| state.as_str() == text)
        .ok_or_else(|| unavailable_detail("a stored receipt state is not in the contract"))
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
            .complete(
                actor(),
                action_id_from([6; 16]),
                ReceiptState::Applied,
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
        assert_eq!(
            journal
                .prune(TimestampMs::new(RETENTION_MS + 2_000))
                .expect("prunes"),
            1
        );
        assert!(journal.is_empty().expect("counts"));
    }
}
