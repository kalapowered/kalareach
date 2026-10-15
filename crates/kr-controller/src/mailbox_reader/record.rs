//! What the host remembers of the mailbox items it has accepted, kept where a restart finds it.
//!
//! Section 20 keeps a replay identifier until the item's expiry and a day more, so that an item the
//! service offers again, or one a restart would otherwise let back in, is accepted once. The rule
//! is [`kr_crypto::envelope::ReplayLedger`]'s; what is here is the part the crate leaves to the
//! controller, which owns the host's databases: the ledger on disk, written before the host acts on
//! an item and before it tells the service the item is safe to remove.
//!
//! The record belongs to the host's stored-envelope key and to no service: an identifier an item
//! authenticated is the same whichever service carried it, so a host pointed at another mailbox
//! service keeps what it has seen.

use std::path::Path;
use std::sync::{Mutex, PoisonError};

use kr_crypto::envelope::ReplayLedger;
use kr_protocol::ids::EnvelopeId;
use kr_protocol::scalars::Uuid;
use rusqlite::{Connection, OptionalExtension, params};

use crate::error::{ControllerError, Result};

/// The file the environment's record of accepted mailbox items lives in.
pub const MAILBOX_REPLAY_RECORD: &str = "mailbox-replay.sqlite3";

/// The schema version this build reads and writes.
pub const SCHEMA_VERSION: i64 = 1;

/// The oldest schema version this build opens: it reads no other.
pub const OLDEST_SCHEMA_VERSION: i64 = SCHEMA_VERSION;

/// The identifiers of the items the host accepted, and when each may be forgotten.
#[derive(Debug)]
pub struct Record {
    connection: Mutex<Connection>,
}

fn counter(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

impl Record {
    /// Opens the record in `state_dir`.
    ///
    /// A database that holds a schema this build does not read is refused before anything is
    /// written to it.
    ///
    /// # Errors
    ///
    /// Returns an error when the file cannot be opened, or holds a schema this build does not read.
    pub fn open(state_dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(state_dir).map_err(ControllerError::registry)?;
        let connection = Connection::open(state_dir.join(MAILBOX_REPLAY_RECORD))
            .map_err(ControllerError::registry)?;
        connection
            .busy_timeout(std::time::Duration::from_secs(5))
            .map_err(ControllerError::registry)?;
        // The version is read before anything is written, so a database of a newer build is left
        // exactly as it is.
        let has_version_table: bool = connection
            .query_row(
                "SELECT count(*) > 0 FROM sqlite_master
                 WHERE type = 'table' AND name = 'mailbox_replay_schema'",
                [],
                |row| row.get(0),
            )
            .map_err(ControllerError::registry)?;
        let version: Option<i64> = if has_version_table {
            connection
                .query_row("SELECT version FROM mailbox_replay_schema", [], |row| {
                    row.get(0)
                })
                .optional()
                .map_err(ControllerError::registry)?
        } else {
            None
        };
        if let Some(found) = version
            && found != SCHEMA_VERSION
        {
            return Err(ControllerError::registry(format!(
                "the mailbox replay record is at schema {found} and this build reads \
                 {SCHEMA_VERSION}"
            )));
        }
        // Every change is one transaction and is on the disk before it is reported: an identifier
        // the host acted on and did not write down is an item a restart would act on again.
        connection
            .execute_batch(
                "PRAGMA journal_mode = WAL;
                 PRAGMA synchronous = FULL;
                 CREATE TABLE IF NOT EXISTS mailbox_replay_schema (version INTEGER NOT NULL);
                 CREATE TABLE IF NOT EXISTS mailbox_replay (
                     envelope_id       TEXT PRIMARY KEY,
                     retained_until_ms INTEGER NOT NULL CHECK (retained_until_ms >= 0)
                 );",
            )
            .map_err(ControllerError::registry)?;
        if version.is_none() {
            connection
                .execute(
                    "INSERT INTO mailbox_replay_schema (version) VALUES (?1)",
                    params![SCHEMA_VERSION],
                )
                .map_err(ControllerError::registry)?;
        }
        Ok(Self {
            connection: Mutex::new(connection),
        })
    }

    fn with<T>(&self, body: impl FnOnce(&Connection) -> rusqlite::Result<T>) -> Result<T> {
        let connection = self
            .connection
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        body(&connection).map_err(ControllerError::registry)
    }

    /// The ledger of what the host has accepted, with every identifier whose retention has ended at
    /// `now_ms` forgotten first.
    ///
    /// # Errors
    ///
    /// Returns an error when the record cannot be read or an identifier in it cannot be.
    pub fn ledger(&self, now_ms: u64) -> Result<ReplayLedger> {
        let rows: Vec<(String, i64)> = self.with(|connection| {
            connection.execute(
                "DELETE FROM mailbox_replay WHERE retained_until_ms <= ?1",
                params![counter(now_ms)],
            )?;
            let mut statement =
                connection.prepare("SELECT envelope_id, retained_until_ms FROM mailbox_replay")?;
            statement
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
                .collect::<rusqlite::Result<Vec<_>>>()
        })?;
        let mut entries = Vec::with_capacity(rows.len());
        for (text, until) in rows {
            let id = text.parse::<Uuid>().map(EnvelopeId::new).map_err(|_| {
                ControllerError::registry(
                    "the mailbox replay record holds an identifier it cannot read",
                )
            })?;
            entries.push((id, u64::try_from(until).unwrap_or(0)));
        }
        Ok(ReplayLedger::restore(entries))
    }

    /// Writes down that the item `id` was accepted, and may be forgotten at `retained_until_ms`.
    ///
    /// # Errors
    ///
    /// Returns an error when the record cannot be written.
    pub fn remember(&self, id: EnvelopeId, retained_until_ms: u64) -> Result<()> {
        self.with(|connection| {
            connection.execute(
                "INSERT OR IGNORE INTO mailbox_replay (envelope_id, retained_until_ms)
                 VALUES (?1, ?2)",
                params![id.get().to_string(), counter(retained_until_ms)],
            )?;
            Ok(())
        })
    }

    /// How many identifiers the record holds. A test reads it; nothing else needs it.
    ///
    /// # Errors
    ///
    /// Returns an error when the record cannot be read.
    pub fn len(&self) -> Result<usize> {
        self.with(|connection| {
            connection
                .query_row("SELECT count(*) FROM mailbox_replay", [], |row| {
                    row.get::<_, i64>(0)
                })
                .map(|count| usize::try_from(count).unwrap_or(0))
        })
    }

    /// Whether the record holds no identifier.
    ///
    /// # Errors
    ///
    /// Returns an error when the record cannot be read.
    pub fn is_empty(&self) -> Result<bool> {
        self.len().map(|count| count == 0)
    }
}
