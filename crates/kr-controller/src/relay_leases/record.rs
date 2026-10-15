//! What the host has asked of the relay lease service, kept where a restart finds it.
//!
//! A lease the service issued is the service's to end, and only the host that asked can end it. A
//! host that forgot its leases in a restart could not end the lease of a device it unpaired in the
//! meantime, and a host that forgot a revocation it owed would leave the pair carried until the
//! lease ran out. So the record holds two things: the lease each paired device has, and the endings
//! the service has not yet answered.
//!
//! A row is written before every request that may create or revise its lease is sent, with the
//! time of that request. An answer that names a lease writes the row again with no time. An answer
//! that says the request issued nothing puts back the time the row held before it, because the
//! latest request that may have issued a lease is then the earlier one. A request that went
//! unanswered keeps its time, and so does one that followed a lease the host dropped without
//! ending. The service answers a request for a pair that already holds a lease with that lease, so
//! asking again after a restart is how the host learns the identifier a lost answer carried. A row
//! that holds the time of a request is kept until the longest a lease can live has passed since
//! then, because until then the pair may still hold a lease the host has not been told of.
//!
//! Everything in the record belongs to one service and one host key. The record names the scope it
//! was kept for, and a daemon started for another scope, or for none, discards what it holds: a
//! lease identifier is meaningful only to the service that issued it, and an ending can be answered
//! only for the key that asked for the lease. The leases left behind run out by themselves. A
//! daemon that cannot use its configuration document opens the record as it finds it, so a document
//! that is broken for a day does not cost the host an ending it owes. The file is made at every
//! start, whether or not a service is selected, so the environment's stored formats do not depend
//! on the configuration.

use std::path::Path;
use std::sync::{Mutex, PoisonError};

use kr_client::services::LeaseEndReason;
use kr_protocol::ids::RelayLeaseId;
use kr_protocol::scalars::{EndpointKey, Uuid};
use rusqlite::{Connection, OptionalExtension, params};

use crate::error::{ControllerError, Result};

/// The file the environment's relay lease record lives in.
pub const RELAY_LEASE_RECORD: &str = "relay-leases.sqlite3";

/// The schema version this build reads and writes.
pub const SCHEMA_VERSION: i64 = 1;

/// The oldest schema version this build opens: it reads no other.
pub const OLDEST_SCHEMA_VERSION: i64 = SCHEMA_VERSION;

/// What the record is kept for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kept<'a> {
    /// The service and host key named by this text. A record kept for another scope is emptied.
    For(&'a str),
    /// No service is selected. A record kept for a service is emptied.
    Nothing,
    /// The configuration could not be read, so what is selected is not known. The record is left as
    /// it is.
    AsFound,
}

/// What the host holds for one paired device.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Row {
    /// The host's own endpoint, the source of the pair.
    pub source: EndpointKey,
    /// The device's endpoint, the destination of the pair.
    pub destination: EndpointKey,
    /// The lease the service issued, or none while the host holds no answer that names one.
    pub lease_id: Option<RelayLeaseId>,
    /// The authorisation the lease was asked for under, or none when no account was named.
    pub payer: Option<String>,
    /// The cumulative bytes the reservation was asked for, or was granted.
    pub ceiling: u64,
    /// The bytes the relay had counted when the service last said.
    pub consumed: u64,
    /// When the lease stops being valid, in UTC milliseconds on the service's clock.
    pub expires_at_ms: u64,
    /// When the latest request whose answer the host has not seen was written down, in UTC
    /// milliseconds on this host's clock, or zero when every request has been answered. Until the
    /// longest a lease can live has passed since then, the pair may hold a lease the host does not
    /// know of, whether or not the row names one.
    pub written_at_ms: u64,
}

/// A lease the host owes the service an ending for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ending {
    /// The lease to end.
    pub lease_id: RelayLeaseId,
    /// Why it is ending.
    pub reason: LeaseEndReason,
}

/// The record of leases and endings.
#[derive(Debug)]
pub struct Record {
    connection: Mutex<Connection>,
}

/// The words an ending's reason is stored as, which the record matches stored text against.
pub const REASONS: [&str; 3] = [UNPAIRED, PAYER_WITHDREW, FINISHED];

const UNPAIRED: &str = "unpaired";
const PAYER_WITHDREW: &str = "payer_withdrew";
const FINISHED: &str = "finished";

fn text_of(reason: LeaseEndReason) -> &'static str {
    match reason {
        LeaseEndReason::Unpaired => UNPAIRED,
        LeaseEndReason::PayerWithdrew => PAYER_WITHDREW,
        LeaseEndReason::Finished => FINISHED,
    }
}

fn reason_of(text: &str) -> LeaseEndReason {
    match text {
        PAYER_WITHDREW => LeaseEndReason::PayerWithdrew,
        FINISHED => LeaseEndReason::Finished,
        _ => LeaseEndReason::Unpaired,
    }
}

fn lease_of(text: &str) -> Result<RelayLeaseId> {
    text.parse::<Uuid>().map(RelayLeaseId::new).map_err(|_| {
        ControllerError::registry("the relay lease record holds a lease identifier it cannot read")
    })
}

fn endpoint_of(bytes: Vec<u8>) -> rusqlite::Result<EndpointKey> {
    <[u8; 32]>::try_from(bytes)
        .map(EndpointKey::from_bytes)
        .map_err(|_| rusqlite::Error::InvalidQuery)
}

fn write_row(connection: &Connection, row: &Row) -> rusqlite::Result<()> {
    connection.execute(
        "INSERT OR REPLACE INTO relay_leases
             (destination, source, lease_id, payer, ceiling, consumed, expires_at_ms,
              written_at_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            row.destination.as_bytes().as_slice(),
            row.source.as_bytes().as_slice(),
            row.lease_id.map(|lease| lease.get().to_string()),
            row.payer,
            counter(row.ceiling),
            counter(row.consumed),
            counter(row.expires_at_ms),
            counter(row.written_at_ms),
        ],
    )?;
    Ok(())
}

fn counter(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn counter_of(value: i64) -> u64 {
    u64::try_from(value).unwrap_or(0)
}

impl Record {
    /// Opens the record in `state_dir`, kept for `kept`.
    ///
    /// A database that holds a schema this build does not read is refused before anything is
    /// written to it.
    ///
    /// # Errors
    ///
    /// Returns an error when the file cannot be opened, or holds a schema this build does not read.
    pub fn open(state_dir: &Path, kept: Kept<'_>) -> Result<Self> {
        std::fs::create_dir_all(state_dir).map_err(ControllerError::registry)?;
        let connection = Connection::open(state_dir.join(RELAY_LEASE_RECORD))
            .map_err(ControllerError::registry)?;
        connection
            .busy_timeout(std::time::Duration::from_secs(5))
            .map_err(ControllerError::registry)?;
        // The version is read before anything is written, so a database of a newer build is left
        // exactly as it is.
        let has_version_table: bool = connection
            .query_row(
                "SELECT count(*) > 0 FROM sqlite_master
                 WHERE type = 'table' AND name = 'relay_lease_schema'",
                [],
                |row| row.get(0),
            )
            .map_err(ControllerError::registry)?;
        let version: Option<i64> = if has_version_table {
            connection
                .query_row("SELECT version FROM relay_lease_schema", [], |row| {
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
                "the relay lease record is at schema {found} and this build reads {SCHEMA_VERSION}"
            )));
        }
        // Every change is one transaction and is on the disk before it is reported: a lease the
        // host asked for and did not write down is one it could not end.
        connection
            .execute_batch(
                "PRAGMA journal_mode = WAL;
                 PRAGMA synchronous = FULL;
                 CREATE TABLE IF NOT EXISTS relay_lease_schema (version INTEGER NOT NULL);
                 CREATE TABLE IF NOT EXISTS relay_lease_scope (
                     id    INTEGER PRIMARY KEY CHECK (id = 0),
                     scope TEXT
                 );
                 CREATE TABLE IF NOT EXISTS relay_leases (
                     destination   BLOB PRIMARY KEY CHECK (length(destination) = 32),
                     source        BLOB NOT NULL CHECK (length(source) = 32),
                     lease_id      TEXT,
                     payer         TEXT,
                     ceiling       INTEGER NOT NULL CHECK (ceiling >= 0),
                     consumed      INTEGER NOT NULL CHECK (consumed >= 0),
                     expires_at_ms INTEGER NOT NULL CHECK (expires_at_ms >= 0),
                     written_at_ms INTEGER NOT NULL CHECK (written_at_ms >= 0)
                 );
                 CREATE TABLE IF NOT EXISTS relay_endings (
                     lease_id TEXT PRIMARY KEY,
                     reason   TEXT NOT NULL
                 );",
            )
            .map_err(ControllerError::registry)?;
        if version.is_none() {
            connection
                .execute(
                    "INSERT INTO relay_lease_schema (version) VALUES (?1)",
                    params![SCHEMA_VERSION],
                )
                .map_err(ControllerError::registry)?;
        }
        let wanted: Option<&str> = match kept {
            Kept::For(scope) => Some(scope),
            Kept::Nothing => None,
            Kept::AsFound => {
                return Ok(Self {
                    connection: Mutex::new(connection),
                });
            }
        };
        let found: Option<Option<String>> = connection
            .query_row("SELECT scope FROM relay_lease_scope", [], |row| {
                row.get::<_, Option<String>>(0)
            })
            .optional()
            .map_err(ControllerError::registry)?;
        if found.as_ref().map(Option::as_deref) != Some(wanted) {
            let transaction = connection
                .unchecked_transaction()
                .map_err(ControllerError::registry)?;
            transaction
                .execute_batch("DELETE FROM relay_leases; DELETE FROM relay_endings;")
                .map_err(ControllerError::registry)?;
            transaction
                .execute(
                    "INSERT OR REPLACE INTO relay_lease_scope (id, scope) VALUES (0, ?1)",
                    params![wanted],
                )
                .map_err(ControllerError::registry)?;
            transaction.commit().map_err(ControllerError::registry)?;
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

    /// Every device the host holds or has asked for a lease for, in the order they were written.
    ///
    /// # Errors
    ///
    /// Returns an error when the record cannot be read.
    pub fn rows(&self) -> Result<Vec<Row>> {
        type Stored = (
            EndpointKey,
            EndpointKey,
            Option<String>,
            Option<String>,
            i64,
            i64,
            i64,
            i64,
        );
        let rows: Vec<Stored> = self.with(|connection| {
            let mut statement = connection.prepare(
                "SELECT source, destination, lease_id, payer, ceiling, consumed, expires_at_ms,
                        written_at_ms
                 FROM relay_leases ORDER BY rowid",
            )?;
            let rows = statement
                .query_map([], |row| {
                    Ok((
                        endpoint_of(row.get(0)?)?,
                        endpoint_of(row.get(1)?)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                        row.get(7)?,
                    ))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })?;
        rows.into_iter()
            .map(
                |(source, destination, lease, payer, ceiling, consumed, expires, written)| {
                    Ok(Row {
                        source,
                        destination,
                        lease_id: lease.as_deref().map(lease_of).transpose()?,
                        payer,
                        ceiling: counter_of(ceiling),
                        consumed: counter_of(consumed),
                        expires_at_ms: counter_of(expires),
                        written_at_ms: counter_of(written),
                    })
                },
            )
            .collect()
    }

    /// Writes what the host holds for one device, replacing what it held.
    ///
    /// # Errors
    ///
    /// Returns an error when the record cannot be written.
    pub fn save(&self, row: &Row) -> Result<()> {
        self.with(|connection| write_row(connection, row))
    }

    /// Forgets what the host held for one device, when it holds no lease the service could still
    /// be carrying.
    ///
    /// # Errors
    ///
    /// Returns an error when the record cannot be written.
    pub fn forget(&self, destination: &EndpointKey) -> Result<()> {
        self.with(|connection| {
            connection.execute(
                "DELETE FROM relay_leases WHERE destination = ?1",
                params![destination.as_bytes().as_slice()],
            )?;
            Ok(())
        })
    }

    /// Moves the lease a device holds to the endings the service is owed, in one step: a stop
    /// between the two leaves the lease where the host still knows to end it.
    ///
    /// # Errors
    ///
    /// Returns an error when the record cannot be written.
    pub fn end(
        &self,
        destination: &EndpointKey,
        lease: RelayLeaseId,
        reason: LeaseEndReason,
    ) -> Result<()> {
        self.end_keeping(destination, lease, reason, None)
    }

    /// As [`Self::end`], and puts `kept` in the place of the device's row in the same step, for a
    /// row that stands for a request whose answer the host has not seen. A stop, or a failed write,
    /// leaves the lease in its row and nothing owed, or the ending owed and the row kept: never the
    /// ending owed and the request forgotten.
    ///
    /// # Errors
    ///
    /// Returns an error when the record cannot be written.
    pub fn end_keeping(
        &self,
        destination: &EndpointKey,
        lease: RelayLeaseId,
        reason: LeaseEndReason,
        kept: Option<&Row>,
    ) -> Result<()> {
        self.with(|connection| {
            let transaction = connection.unchecked_transaction()?;
            transaction.execute(
                "INSERT OR IGNORE INTO relay_endings (lease_id, reason) VALUES (?1, ?2)",
                params![lease.get().to_string(), text_of(reason)],
            )?;
            match kept {
                Some(row) => write_row(&transaction, row)?,
                None => {
                    transaction.execute(
                        "DELETE FROM relay_leases WHERE destination = ?1",
                        params![destination.as_bytes().as_slice()],
                    )?;
                }
            }
            transaction.commit()
        })
    }

    /// The endings the service has not answered, in the order they were owed.
    ///
    /// # Errors
    ///
    /// Returns an error when the record cannot be read.
    pub fn endings(&self) -> Result<Vec<Ending>> {
        let owed = self.with(|connection| {
            let mut statement =
                connection.prepare("SELECT lease_id, reason FROM relay_endings ORDER BY rowid")?;
            let owed = statement
                .query_map([], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(owed)
        })?;
        owed.into_iter()
            .map(|(lease, reason)| {
                Ok(Ending {
                    lease_id: lease_of(&lease)?,
                    reason: reason_of(&reason),
                })
            })
            .collect()
    }

    /// Records that the service has answered an ending, so it is owed no more.
    ///
    /// # Errors
    ///
    /// Returns an error when the record cannot be written.
    pub fn settle(&self, lease: RelayLeaseId) -> Result<()> {
        self.with(|connection| {
            connection.execute(
                "DELETE FROM relay_endings WHERE lease_id = ?1",
                params![lease.get().to_string()],
            )?;
            Ok(())
        })
    }
}
