//! The verified device directory: which endpoints this host has paired, and under what grant.
//!
//! This is the durable half of the host's side of pairing. A device record survives a restart,
//! because a device that paired yesterday must still be paired today; an invitation does not,
//! because section 10 says a candidate's attempt state lives only in memory and a restart cancels
//! whatever was unfinished.
//!
//! The lookup key is the **endpoint identity**, never the device identity a peer claims. That is
//! what makes the handshake's record selection safe: a connection is authenticated by iroh as
//! coming from one endpoint, and the record that endpoint owns is the only one it can reach.
//!
//! Revocation is a state of the record rather than its absence. A revoked row stays, with the
//! moment it was revoked, so a host can say that a device *was* paired and is not any more; a row
//! that had simply been deleted would be indistinguishable from a device that never existed.
//!
//! The tables live in the daemon's own registry database, beside the reservations and the worker
//! rows, because a device record is environment state and section 24 puts environment state there.
//! The network module owns these two tables and nothing else in that file.

use std::path::Path;

use kr_crypto::connect::PairedPeer;
use kr_protocol::grant::Grant;
use kr_protocol::ids::{ActorId, DeviceId, DeviceKeyRevision, GrantId};
use kr_protocol::pairing::{DeviceName, DevicePlatform};
use kr_protocol::scalars::{AuthorisationKey, EndpointKey, TimestampMs, Uuid};
use kr_transport::handshake::PairedDirectory;
use rusqlite::{Connection, OptionalExtension as _, params};

use crate::error::{ControllerError, Result};

/// One paired device, as the host recorded it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceRecord {
    /// The device identity the host assigned when it committed the pairing.
    pub device_id: DeviceId,
    /// The device's iroh endpoint identity, which is what a connection is authenticated as.
    pub endpoint_id: EndpointKey,
    /// The revision of the device's purpose-separated keys.
    pub device_key_revision: DeviceKeyRevision,
    /// The authorisation key the `kr-connect/1` proof is checked against.
    pub authorisation: AuthorisationKey,
    /// What the device called itself. Display text, never authority.
    pub device_name: DeviceName,
    /// What the device said it runs on. Display text, never authority.
    pub platform: DevicePlatform,
    /// The grant the host issued it.
    pub grant: Grant,
    /// When the host committed the pairing, in UTC milliseconds.
    pub paired_at_ms: TimestampMs,
    /// When the host revoked it, in UTC milliseconds, while it still holds a grant.
    pub revoked_at_ms: Option<TimestampMs>,
    /// When the host first found its grant to have run out, in UTC milliseconds.
    ///
    /// Recorded so the decision survives a restart and a wall clock stepped backwards. A grant
    /// that has once run out never comes back.
    pub expired_at_ms: Option<TimestampMs>,
}

impl DeviceRecord {
    /// Returns true when this device may still open an authorised connection.
    #[must_use]
    pub const fn is_paired(&self) -> bool {
        self.revoked_at_ms.is_none() && self.expired_at_ms.is_none()
    }

    /// Returns the paired record the connection handshake checks a proof against.
    #[must_use]
    pub const fn as_paired_peer(&self) -> PairedPeer {
        PairedPeer {
            device_id: self.device_id,
            device_key_revision: self.device_key_revision,
            authorisation: self.authorisation,
            endpoint_id: self.endpoint_id,
        }
    }

    /// Returns the principal this device acts under on this host.
    ///
    /// It is derived from the device identity the host assigned, so a device cannot choose it and
    /// `(actor_id, action_id)` names one device's action for as long as the record exists.
    #[must_use]
    pub fn principal(&self) -> ActorId {
        kr_transport::listener::device_principal(&self.device_id)
    }
}

/// Every device this host has paired.
#[derive(Debug)]
pub struct DeviceDirectory {
    connection: std::sync::Mutex<Connection>,
}

impl DeviceDirectory {
    /// Opens the directory in the daemon's registry database, creating its tables.
    ///
    /// # Errors
    ///
    /// Returns an error when the database cannot be opened or migrated.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let connection = Connection::open(path.as_ref()).map_err(ControllerError::registry)?;
        Self::prepare(connection)
    }

    /// Opens an in-memory directory, which is what a test uses.
    ///
    /// # Errors
    ///
    /// Returns an error when the tables cannot be created.
    pub fn in_memory() -> Result<Self> {
        Self::prepare(Connection::open_in_memory().map_err(ControllerError::registry)?)
    }

    fn prepare(connection: Connection) -> Result<Self> {
        // The same durability the rest of the daemon's state uses: write-ahead logging with full
        // synchronisation. A device record that a crash lost would leave a paired device unable to
        // connect and no record of why.
        connection
            .pragma_update(None, "journal_mode", "WAL")
            .map_err(ControllerError::registry)?;
        connection
            .pragma_update(None, "synchronous", "FULL")
            .map_err(ControllerError::registry)?;
        connection
            .pragma_update(None, "foreign_keys", "ON")
            .map_err(ControllerError::registry)?;
        // The daemon's own registry opens this file too, so a write may find the other connection
        // holding the lock. Waiting is the answer; failing would turn an ordinary overlap into a
        // refused pairing.
        connection
            .busy_timeout(std::time::Duration::from_secs(5))
            .map_err(ControllerError::registry)?;
        let directory = Self {
            connection: std::sync::Mutex::new(connection),
        };
        directory.migrate()?;
        Ok(directory)
    }

    fn migrate(&self) -> Result<()> {
        self.with(|connection| {
            connection.execute_batch(
                "CREATE TABLE IF NOT EXISTS network_devices (
                     device_id BLOB PRIMARY KEY NOT NULL,
                     endpoint_id BLOB NOT NULL UNIQUE,
                     device_key_revision INTEGER NOT NULL,
                     authorisation_key BLOB NOT NULL,
                     device_name TEXT NOT NULL,
                     platform TEXT NOT NULL,
                     grant_id BLOB NOT NULL,
                     grant BLOB NOT NULL,
                     paired_at_ms INTEGER NOT NULL,
                     revoked_at_ms INTEGER,
                     expired_at_ms INTEGER
                 );
                 CREATE INDEX IF NOT EXISTS network_devices_endpoint
                     ON network_devices (endpoint_id);",
            )
        })
    }

    fn with<T>(&self, body: impl FnOnce(&Connection) -> rusqlite::Result<T>) -> Result<T> {
        let connection = self
            .connection
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        body(&connection).map_err(ControllerError::registry)
    }

    /// Records a completed pairing.
    ///
    /// The device record and the grant are one row, written in one statement: section 10 commits
    /// them together, and a row that held one without the other would be a device with no rights
    /// or rights with no device.
    ///
    /// # Errors
    ///
    /// Returns an error when the row cannot be written, including when this endpoint already has a
    /// record: an endpoint identity belongs to one device.
    pub fn commit(&self, record: &DeviceRecord) -> Result<()> {
        let grant = kr_cbor::to_canonical_vec(&record.grant)
            .map_err(|error| ControllerError::InvalidArgument(error.to_string()))?;
        let platform = platform_text(record.platform)?;
        self.with(|connection| {
            connection
                .execute(
                    "INSERT INTO network_devices (
                         device_id, endpoint_id, device_key_revision, authorisation_key,
                         device_name, platform, grant_id, grant, paired_at_ms, revoked_at_ms,
                         expired_at_ms
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, NULL, NULL)",
                    params![
                        record.device_id.get().as_bytes().as_slice(),
                        record.endpoint_id.as_bytes().as_slice(),
                        i64::try_from(record.device_key_revision.get()).unwrap_or(i64::MAX),
                        record.authorisation.as_bytes().as_slice(),
                        record.device_name.as_str(),
                        platform,
                        record.grant.grant_id.get().as_bytes().as_slice(),
                        grant,
                        i64::try_from(record.paired_at_ms.get()).unwrap_or(i64::MAX),
                    ],
                )
                .map(|_| ())
        })
    }

    /// Returns the record of one endpoint, paired or revoked.
    ///
    /// # Errors
    ///
    /// Returns an error when the row cannot be read.
    pub fn record_for_endpoint(&self, endpoint_id: &EndpointKey) -> Result<Option<DeviceRecord>> {
        let bytes = endpoint_id.as_bytes().to_vec();
        self.with(|connection| {
            connection
                .query_row(
                    "SELECT device_id, endpoint_id, device_key_revision, authorisation_key,
                            device_name, platform, grant, paired_at_ms, revoked_at_ms,
                            expired_at_ms
                     FROM network_devices WHERE endpoint_id = ?1",
                    params![bytes],
                    |row| Ok(read_record(row)),
                )
                .optional()
        })?
        .transpose()
    }

    /// Returns the record of one device, paired or revoked.
    ///
    /// # Errors
    ///
    /// Returns an error when the row cannot be read.
    pub fn record_for_device(&self, device_id: DeviceId) -> Result<Option<DeviceRecord>> {
        let bytes = device_id.get().as_bytes().to_vec();
        self.with(|connection| {
            connection
                .query_row(
                    "SELECT device_id, endpoint_id, device_key_revision, authorisation_key,
                            device_name, platform, grant, paired_at_ms, revoked_at_ms,
                            expired_at_ms
                     FROM network_devices WHERE device_id = ?1",
                    params![bytes],
                    |row| Ok(read_record(row)),
                )
                .optional()
        })?
        .transpose()
    }

    /// Returns every device, in pairing order.
    ///
    /// # Errors
    ///
    /// Returns an error when the rows cannot be read.
    pub fn devices(&self) -> Result<Vec<DeviceRecord>> {
        self.with(|connection| {
            let mut statement = connection.prepare(
                "SELECT device_id, endpoint_id, device_key_revision, authorisation_key,
                        device_name, platform, grant, paired_at_ms, revoked_at_ms, expired_at_ms
                 FROM network_devices ORDER BY paired_at_ms, device_id",
            )?;
            let rows = statement
                .query_map([], |row| Ok(read_record(row)))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })?
        .into_iter()
        .collect()
    }

    /// Records that one device's grant has run out.
    ///
    /// It is written so the decision survives a restart. An absolute expiry is read against the
    /// wall clock, and a wall clock can be stepped backwards; a grant that has once been found to
    /// have run out never comes back, whatever the clock says afterwards.
    ///
    /// # Errors
    ///
    /// Returns an error when the row cannot be written.
    pub fn record_expiry(&self, device_id: DeviceId, now_ms: TimestampMs) -> Result<()> {
        let bytes = device_id.get().as_bytes().to_vec();
        self.with(|connection| {
            connection.execute(
                "UPDATE network_devices SET expired_at_ms = ?2
                 WHERE device_id = ?1 AND expired_at_ms IS NULL",
                params![bytes, i64::try_from(now_ms.get()).unwrap_or(i64::MAX)],
            )
        })?;
        Ok(())
    }

    /// Marks one device as revoked, and reports whether this call was the one that did it.
    ///
    /// Revoking twice is not an error: the second call finds the row already revoked and says so,
    /// which is what lets a caller report a revocation as complete without having to decide who
    /// got there first.
    ///
    /// # Errors
    ///
    /// Returns an error when the row cannot be written.
    pub fn revoke(&self, device_id: DeviceId, now_ms: TimestampMs) -> Result<bool> {
        let bytes = device_id.get().as_bytes().to_vec();
        let changed = self.with(|connection| {
            connection.execute(
                "UPDATE network_devices SET revoked_at_ms = ?2
                 WHERE device_id = ?1 AND revoked_at_ms IS NULL",
                params![bytes, i64::try_from(now_ms.get()).unwrap_or(i64::MAX)],
            )
        })?;
        Ok(changed > 0)
    }
}

/// Only a paired record answers a lookup.
///
/// A revoked device is not an unpaired candidate that may pair again through the same endpoint: it
/// reaches the pre-authorisation surface, where pairing's own rules decide, and it reaches nothing
/// else. What matters here is that it can never be *authorised*, and the handshake asks this
/// exactly once for that purpose.
impl PairedDirectory for DeviceDirectory {
    fn paired_peer(&self, endpoint_id: &EndpointKey) -> Option<PairedPeer> {
        self.record_for_endpoint(endpoint_id)
            .ok()
            .flatten()
            .filter(DeviceRecord::is_paired)
            .map(|record| record.as_paired_peer())
    }
}

fn read_record(row: &rusqlite::Row<'_>) -> Result<DeviceRecord> {
    let device_id: Vec<u8> = row.get(0).map_err(ControllerError::registry)?;
    let endpoint_id: Vec<u8> = row.get(1).map_err(ControllerError::registry)?;
    let device_key_revision: i64 = row.get(2).map_err(ControllerError::registry)?;
    let authorisation: Vec<u8> = row.get(3).map_err(ControllerError::registry)?;
    let device_name: String = row.get(4).map_err(ControllerError::registry)?;
    let platform: String = row.get(5).map_err(ControllerError::registry)?;
    let grant: Vec<u8> = row.get(6).map_err(ControllerError::registry)?;
    let paired_at_ms: i64 = row.get(7).map_err(ControllerError::registry)?;
    let revoked_at_ms: Option<i64> = row.get(8).map_err(ControllerError::registry)?;
    let expired_at_ms: Option<i64> = row.get(9).map_err(ControllerError::registry)?;
    Ok(DeviceRecord {
        device_id: DeviceId::new(uuid(&device_id)?),
        endpoint_id: EndpointKey::from_bytes(key(&endpoint_id)?),
        device_key_revision: DeviceKeyRevision::new(
            u64::try_from(device_key_revision).unwrap_or_default(),
        ),
        authorisation: AuthorisationKey::from_bytes(key(&authorisation)?),
        device_name: DeviceName::new(device_name)
            .map_err(|error| ControllerError::registry(error.to_string()))?,
        platform: platform_from(&platform)?,
        grant: kr_cbor::from_canonical_slice(&grant, &kr_cbor::Limits::DEFAULT)
            .map_err(|error| ControllerError::registry(error.to_string()))?,
        paired_at_ms: TimestampMs::new(u64::try_from(paired_at_ms).unwrap_or_default()),
        revoked_at_ms: revoked_at_ms
            .map(|at| TimestampMs::new(u64::try_from(at).unwrap_or_default())),
        expired_at_ms: expired_at_ms
            .map(|at| TimestampMs::new(u64::try_from(at).unwrap_or_default())),
    })
}

/// Returns the grant identity a row records, for a caller that wants it without the grant.
#[must_use]
pub fn grant_id_of(record: &DeviceRecord) -> GrantId {
    record.grant.grant_id
}

fn uuid(bytes: &[u8]) -> Result<Uuid> {
    <[u8; 16]>::try_from(bytes)
        .map(Uuid::from_bytes)
        .map_err(|_| {
            ControllerError::registry(format!("an identifier is 16 bytes, not {}", bytes.len()))
        })
}

fn key(bytes: &[u8]) -> Result<[u8; 32]> {
    <[u8; 32]>::try_from(bytes)
        .map_err(|_| ControllerError::registry(format!("a key is 32 bytes, not {}", bytes.len())))
}

/// Returns the stable name a platform is stored under.
///
/// It is the protocol's own name for the value rather than a second spelling invented here, so a
/// row written by one build reads back the same in the next.
fn platform_text(platform: DevicePlatform) -> Result<String> {
    serde_json::to_string(&platform)
        .map(|quoted| quoted.trim_matches('"').to_owned())
        .map_err(ControllerError::registry)
}

fn platform_from(text: &str) -> Result<DevicePlatform> {
    serde_json::from_str(&format!("\"{text}\""))
        .map_err(|_| ControllerError::registry(format!("{text} is not a device platform")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_protocol::grant::{EnvironmentSelector, GrantExpiry, HistoryScope, SessionSelector};
    use kr_protocol::ids::AuthorityRevision;
    use kr_protocol::rights::ActionRight;
    use kr_protocol::scalars::{CanonicalSet, Nullable};

    fn record(byte: u8) -> DeviceRecord {
        DeviceRecord {
            device_id: DeviceId::new(Uuid::from_bytes([byte; 16])),
            endpoint_id: EndpointKey::from_bytes([byte; 32]),
            device_key_revision: DeviceKeyRevision::new(1),
            authorisation: AuthorisationKey::from_bytes([byte ^ 0xff; 32]),
            device_name: DeviceName::new("A phone").expect("a name"),
            platform: DevicePlatform::Android,
            grant: Grant {
                grant_id: GrantId::new(Uuid::from_bytes([byte; 16])),
                parent_grant_id: Nullable::null(),
                issuer_device_id: DeviceId::new(Uuid::from_bytes([0; 16])),
                recipient_device_id: DeviceId::new(Uuid::from_bytes([byte; 16])),
                authority_revision: AuthorityRevision::new(1),
                environment_selector: EnvironmentSelector::Any,
                session_selector: SessionSelector::Any,
                actions: [ActionRight::SessionView].into_iter().collect(),
                history: HistoryScope {
                    lower_bound_ms: Nullable::null(),
                    include_live_screen: true,
                    named_questions: CanonicalSet::new(),
                    named_approvals: CanonicalSet::new(),
                },
                expiry: GrantExpiry::Never,
                organisation: Nullable::null(),
            },
            paired_at_ms: TimestampMs::new(1_764_003_600_000),
            revoked_at_ms: None,
            expired_at_ms: None,
        }
    }

    #[test]
    fn a_committed_device_is_found_by_its_endpoint_and_nothing_else() {
        let directory = DeviceDirectory::in_memory().expect("a directory");
        let device = record(7);
        directory.commit(&device).expect("the row is written");

        assert_eq!(
            directory
                .record_for_endpoint(&device.endpoint_id)
                .expect("a read"),
            Some(device.clone())
        );
        assert_eq!(
            directory
                .paired_peer(&device.endpoint_id)
                .expect("a paired record"),
            device.as_paired_peer()
        );
        assert!(
            directory
                .paired_peer(&EndpointKey::from_bytes([9; 32]))
                .is_none(),
            "an endpoint with no record is an unpaired candidate"
        );
    }

    #[test]
    fn a_revoked_device_keeps_its_record_and_authorises_nothing() {
        let directory = DeviceDirectory::in_memory().expect("a directory");
        let device = record(3);
        directory.commit(&device).expect("the row is written");

        let now = TimestampMs::new(1_764_003_700_000);
        assert!(
            directory.revoke(device.device_id, now).expect("a write"),
            "the first revocation is the one that changed the row"
        );
        assert!(
            !directory.revoke(device.device_id, now).expect("a write"),
            "revoking again finds it already revoked"
        );

        assert!(directory.paired_peer(&device.endpoint_id).is_none());
        let stored = directory
            .record_for_device(device.device_id)
            .expect("a read")
            .expect("the row is still there");
        assert_eq!(stored.revoked_at_ms, Some(now));
        assert!(!stored.is_paired());
        assert_eq!(grant_id_of(&stored), device.grant.grant_id);
    }

    #[test]
    fn one_endpoint_identity_belongs_to_one_device() {
        let directory = DeviceDirectory::in_memory().expect("a directory");
        let first = record(1);
        directory.commit(&first).expect("the row is written");
        let mut second = record(2);
        second.endpoint_id = first.endpoint_id;
        assert!(
            directory.commit(&second).is_err(),
            "a second device cannot claim an endpoint that already has a record"
        );
    }
}
