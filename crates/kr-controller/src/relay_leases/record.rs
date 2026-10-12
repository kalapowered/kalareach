//! What the host has asked of the relay lease service, kept where a restart finds it.
//!
//! A lease the service issued is the service's to end, and only the host that asked can end it. A
//! host that forgot its leases in a restart could not end the lease of a device it unpaired in the
//! meantime, and a host that forgot a revocation it owed would leave the pair carried until the
//! lease ran out. So the record holds two things: the lease each paired device has, and the endings
//! the service has not yet answered.
//!
//! A row is written before the request that may create its lease is sent, with no lease identifier
//! in it. The service answers a request for a pair that already holds a lease with that lease, so
//! asking again after a restart is how the host learns the identifier a lost answer carried.
//!
//! Everything in the record belongs to one service. The record names the origin it was kept for,
//! and a daemon started against another origin, or against none, discards what it holds: a lease
//! identifier is meaningful only to the service that issued it, and the leases left behind run out
//! by themselves. The file is made at every start, whether or not a service is selected, so the
//! environment's stored formats do not depend on the configuration.

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

fn text_of(reason: LeaseEndReason) -> &'static str {
    match reason {
        LeaseEndReason::Unpaired => "unpaired",
        LeaseEndReason::PayerWithdrew => "payer_withdrew",
        LeaseEndReason::Finished => "finished",
    }
}

fn reason_of(text: &str) -> LeaseEndReason {
    match text {
        "payer_withdrew" => LeaseEndReason::PayerWithdrew,
        "finished" => LeaseEndReason::Finished,
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

fn counter(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn counter_of(value: i64) -> u64 {
    u64::try_from(value).unwrap_or(0)
}

impl Record {
    /// Opens the record in `state_dir`, kept for the service at `origin`, when one is selected.
    ///
    /// A record kept for another origin, or for none, is emptied: nothing in it means anything to
    /// this one.
    ///
    /// # Errors
    ///
    /// Returns an error when the file cannot be opened, or holds a schema this build does not read.
    pub fn open(state_dir: &Path, origin: Option<&str>) -> Result<Self> {
        std::fs::create_dir_all(state_dir).map_err(ControllerError::registry)?;
        let connection = Connection::open(state_dir.join(RELAY_LEASE_RECORD))
            .map_err(ControllerError::registry)?;
        connection
            .busy_timeout(std::time::Duration::from_secs(5))
            .map_err(ControllerError::registry)?;
        // Every change is one transaction and is on the disk before it is reported: a lease the
        // host asked for and did not write down is one it could not end.
        connection
            .execute_batch(
                "PRAGMA journal_mode = WAL;
                 PRAGMA synchronous = FULL;
                 CREATE TABLE IF NOT EXISTS relay_lease_schema (version INTEGER NOT NULL);
                 CREATE TABLE IF NOT EXISTS relay_lease_service (
                     id     INTEGER PRIMARY KEY CHECK (id = 0),
                     origin TEXT
                 );
                 CREATE TABLE IF NOT EXISTS relay_leases (
                     destination   BLOB PRIMARY KEY CHECK (length(destination) = 32),
                     source        BLOB NOT NULL CHECK (length(source) = 32),
                     lease_id      TEXT,
                     payer         TEXT,
                     ceiling       INTEGER NOT NULL CHECK (ceiling >= 0),
                     consumed      INTEGER NOT NULL CHECK (consumed >= 0),
                     expires_at_ms INTEGER NOT NULL CHECK (expires_at_ms >= 0)
                 );
                 CREATE TABLE IF NOT EXISTS relay_endings (
                     lease_id TEXT PRIMARY KEY,
                     reason   TEXT NOT NULL
                 );",
            )
            .map_err(ControllerError::registry)?;
        let version: Option<i64> = connection
            .query_row("SELECT version FROM relay_lease_schema", [], |row| {
                row.get(0)
            })
            .optional()
            .map_err(ControllerError::registry)?;
        match version {
            None => {
                connection
                    .execute(
                        "INSERT INTO relay_lease_schema (version) VALUES (?1)",
                        params![SCHEMA_VERSION],
                    )
                    .map_err(ControllerError::registry)?;
            }
            Some(SCHEMA_VERSION) => {}
            Some(found) => {
                return Err(ControllerError::registry(format!(
                    "the relay lease record is at schema {found} and this build reads \
                     {SCHEMA_VERSION}"
                )));
            }
        }
        let kept_for: Option<Option<String>> = connection
            .query_row("SELECT origin FROM relay_lease_service", [], |row| {
                row.get::<_, Option<String>>(0)
            })
            .optional()
            .map_err(ControllerError::registry)?;
        if kept_for.as_ref().map(Option::as_deref) != Some(origin) {
            connection
                .execute_batch(
                    "BEGIN IMMEDIATE; DELETE FROM relay_leases; DELETE FROM relay_endings;",
                )
                .map_err(ControllerError::registry)?;
            connection
                .execute(
                    "INSERT OR REPLACE INTO relay_lease_service (id, origin) VALUES (0, ?1)",
                    params![origin],
                )
                .map_err(ControllerError::registry)?;
            connection
                .execute_batch("COMMIT;")
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

    /// Every device the host holds or has asked for a lease for, in the order they were written.
    ///
    /// # Errors
    ///
    /// Returns an error when the record cannot be read.
    pub fn rows(&self) -> Result<Vec<Row>> {
        let rows = self.with(|connection| {
            let mut statement = connection.prepare(
                "SELECT source, destination, lease_id, payer, ceiling, consumed, expires_at_ms
                 FROM relay_leases ORDER BY rowid",
            )?;
            let rows = statement
                .query_map([], |row| {
                    Ok((
                        endpoint_of(row.get(0)?)?,
                        endpoint_of(row.get(1)?)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, Option<String>>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, i64>(5)?,
                        row.get::<_, i64>(6)?,
                    ))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })?;
        rows.into_iter()
            .map(
                |(source, destination, lease, payer, ceiling, consumed, expires)| {
                    Ok(Row {
                        source,
                        destination,
                        lease_id: lease.as_deref().map(lease_of).transpose()?,
                        payer,
                        ceiling: counter_of(ceiling),
                        consumed: counter_of(consumed),
                        expires_at_ms: counter_of(expires),
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
        self.with(|connection| {
            connection.execute(
                "INSERT OR REPLACE INTO relay_leases
                     (destination, source, lease_id, payer, ceiling, consumed, expires_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    row.destination.as_bytes().as_slice(),
                    row.source.as_bytes().as_slice(),
                    row.lease_id.map(|lease| lease.get().to_string()),
                    row.payer,
                    counter(row.ceiling),
                    counter(row.consumed),
                    counter(row.expires_at_ms),
                ],
            )?;
            Ok(())
        })
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
        self.with(|connection| {
            connection.execute_batch("BEGIN IMMEDIATE;")?;
            let done = connection
                .execute(
                    "INSERT OR IGNORE INTO relay_endings (lease_id, reason) VALUES (?1, ?2)",
                    params![lease.get().to_string(), text_of(reason)],
                )
                .and_then(|_| {
                    connection.execute(
                        "DELETE FROM relay_leases WHERE destination = ?1",
                        params![destination.as_bytes().as_slice()],
                    )
                });
            match done {
                Ok(_) => connection.execute_batch("COMMIT;"),
                Err(error) => {
                    let _ = connection.execute_batch("ROLLBACK;");
                    Err(error)
                }
            }
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
