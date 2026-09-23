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
use std::sync::Arc;

use kr_crypto::connect::PairedPeer;
use kr_protocol::grant::Grant;
use kr_protocol::identity::BootIdentity;
use kr_protocol::ids::{ActorId, DeviceId, DeviceKeyRevision, GrantId};
use kr_protocol::pairing::{DeviceName, DevicePlatform, DevicePublicKeys};
use kr_protocol::scalars::{
    AuthorisationKey, Digest256, EndpointKey, NotificationPreviewKey, StoredEnvelopeKey,
    TimestampMs, Uuid,
};
use kr_transport::handshake::PairedDirectory;
use rusqlite::{Connection, OptionalExtension as _, params};

use crate::error::{ControllerError, Result};

/// The durable records a connection reads and writes, and the boundaries they move behind.
///
/// One handle, because a connection needs all three and none of them belongs to it: the directory
/// it was admitted from, what the host owes that directory, and the decision about the clock those
/// records are dated by. Each outlives the connection, which is why they are the host's and not
/// the connection's.
#[derive(Clone, Debug)]
pub struct HostRecords {
    /// Every device this host has paired, and where each remote action went.
    pub devices: Arc<DeviceDirectory>,
    /// The expiry records this host owes that directory.
    pub pending: Arc<PendingExpiry>,
    /// Whether this host may decide an expiry from its own wall clock.
    pub clock: Arc<ClockTrust>,
}

/// Whether this host may decide an expiry from its own wall clock, and the transitions of that.
///
/// Four things move together: sampling the clock, moving the mark, setting or clearing the
/// decision, and writing it down. Each of them reads what the others wrote, so they share one
/// boundary: without it an observation taken before an owner established the clock could land
/// after it, and a decision cleared between an observation and its write would be lost.
#[derive(Debug, Default)]
pub struct ClockTrust {
    /// Held for the whole of every transition below.
    ///
    /// `true` once this host has found its clock going backwards, cleared only by an owner's
    /// approval. The durable record is what a later run reads; this is what holds the decision
    /// while a write is failing.
    distrusted: std::sync::Mutex<bool>,
}

impl ClockTrust {
    /// Samples the wall clock and says whether this host may decide against what it read.
    ///
    /// One operation, because the two halves are one decision: the clock is read, a rollback
    /// becomes distrust, and the answer says whether the reading may be used. Anything that read
    /// the clock and then asked separately could be answered about a clock an owner established in
    /// between, and would then measure a grant from the reading it took before that.
    ///
    /// The clock is read *inside* the boundary too, so a caller that paused before it got here
    /// cannot contribute a stale reading.
    ///
    /// # Errors
    ///
    /// Returns an error when the mark or the decision cannot be read or written. A host that
    /// cannot tell decides nothing.
    pub fn sample(&self, devices: &DeviceDirectory) -> Result<Option<ObservedUtc>> {
        let mut distrusted = self.held();
        let observed = devices.utc_at_least(kr_ipc::now_ms())?;
        if observed.behind_ms > CLOCK_TOLERANCE_MS {
            *distrusted = true;
            // The decision is in memory before anything is written, and the write is attempted
            // here and retried by whoever calls [`Self::settle`] until it lands.
            let _ = devices.note_clock_untrusted(observed.now);
        }
        if *distrusted || devices.clock_untrusted()? {
            return Ok(None);
        }
        Ok(Some(observed))
    }

    /// Records the moment this host is at, for a caller that needs the reading rather than a
    /// decision from it.
    ///
    /// A tombstone is written at the moment it was observed, and a rollback observed while doing
    /// it is the same fact as one observed anywhere else: it becomes distrust here too.
    ///
    /// # Errors
    ///
    /// Returns an error when the mark cannot be read or written.
    pub fn observe(&self, devices: &DeviceDirectory) -> Result<TimestampMs> {
        let mut distrusted = self.held();
        let observed = devices.utc_at_least(kr_ipc::now_ms())?;
        if observed.behind_ms > CLOCK_TOLERANCE_MS {
            *distrusted = true;
            let _ = devices.note_clock_untrusted(observed.now);
        }
        Ok(observed.now)
    }

    /// Writes down a decision this host is holding, until the write lands.
    ///
    /// # Errors
    ///
    /// Returns an error when the record cannot be read or written.
    pub fn settle(&self, devices: &DeviceDirectory) -> Result<()> {
        let distrusted = self.held();
        if *distrusted && !devices.clock_untrusted()? {
            devices.note_clock_untrusted(kr_ipc::now_ms())?;
        }
        Ok(())
    }

    /// Establishes the clock again, at the moment an owner authenticated.
    ///
    /// The mark moves to that moment and the decision is cleared, in one transition: an
    /// observation taken against the old mark cannot land after it, because it would have to take
    /// this boundary to be recorded at all.
    ///
    /// # Errors
    ///
    /// Returns an error when the record cannot be written. The decision stands if it cannot.
    pub fn establish(&self, devices: &DeviceDirectory) -> Result<()> {
        let mut distrusted = self.held();
        // Read inside the boundary, like every other reading of this clock: the moment the owner
        // established is the moment this host is at now, not one sampled before it got here.
        devices.trust_clock(kr_ipc::now_ms())?;
        *distrusted = false;
        Ok(())
    }

    fn held(&self) -> std::sync::MutexGuard<'_, bool> {
        self.distrusted
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// How far behind its own recorded mark this host's wall clock may be and still decide an expiry.
///
/// A small step is ordinary: a clock corrected by a time service, or two reads either side of a
/// write. A larger one says the wall clock is not currently a clock this host can measure a grant
/// against, and section 9 does not let it guess in the device's favour.
pub const CLOCK_TOLERANCE_MS: u64 = 5_000;

/// Expiry records this host owes its own directory.
///
/// A grant's expiry is written down where it is observed, and a write can fail: a full disk, a
/// database another process is holding. The connection that observed it then ends, and the record
/// is still owed, so it is kept here and written by the host's own task. Section 9 does not let
/// withdrawn authority come back, and a tombstone that was never written is how it would.
#[derive(Debug, Default)]
pub struct PendingExpiry {
    owed: std::sync::Mutex<std::collections::BTreeMap<DeviceId, TimestampMs>>,
}

impl PendingExpiry {
    /// Records that one device's grant was found to have run out.
    ///
    /// The first moment observed for a device stays: a later observation of the same expiry is the
    /// same fact, and the earliest reading is the one closest to when it actually happened.
    pub fn owe(&self, device_id: DeviceId, now_ms: TimestampMs) {
        self.owed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entry(device_id)
            .or_insert(now_ms);
    }

    /// Writes down what is owed, and keeps whatever could not be written.
    pub fn settle(&self, devices: &DeviceDirectory) {
        let owed: Vec<(DeviceId, TimestampMs)> = self
            .owed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .map(|(device, at)| (*device, *at))
            .collect();
        for (device_id, at) in owed {
            match devices.record_expiry(device_id, at) {
                Ok(()) => {
                    self.owed
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .remove(&device_id);
                }
                Err(error) => eprintln!(
                    "kr-controller: could not record that device {device_id} has run out of \
                     grant: {error}"
                ),
            }
        }
    }

    /// Returns how many records are still owed. A test reads it; nothing else needs it.
    #[must_use]
    pub fn owed(&self) -> usize {
        self.owed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }
}

/// What this host makes of the wall clock, against the latest moment it has recorded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObservedUtc {
    /// The moment to decide against: the wall clock, or the recorded mark when that is later.
    pub now: TimestampMs,
    /// How far the wall clock is behind the mark. Zero when it is not behind it.
    pub behind_ms: u64,
}

/// Where one action went, as this host recorded it before dispatching it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RoutedAction {
    /// The session the action was dispatched to, absent when this host itself holds the receipt.
    pub session_id: Option<kr_protocol::ids::SessionId>,
    /// The digest of the payload dispatched under this identifier.
    ///
    /// Absent for a row written before this host recorded digests. Such an identifier is spent:
    /// nothing here can say whether a second submission carries the same payload, and section 9
    /// does not let a host guess.
    pub payload_digest: Option<Digest256>,
}

/// What claiming one action's route found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActionRoute {
    /// This host had no record of the action, and now holds this one.
    Recorded,
    /// This host had already dispatched the action, as recorded here.
    Existing(RoutedAction),
}

/// What recording a device's notification-preview key came to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PreviewKeyOutcome {
    /// The key and its revision are now the device's.
    Recorded,
    /// The device already held exactly this key at exactly this revision.
    AlreadyRecorded,
    /// The revision offered does not follow the one recorded, which is carried here.
    RevisionBehind(DeviceKeyRevision),
    /// No paired device answers to that identity.
    NotPaired,
}

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
    /// The device's stored-envelope key, which another device seals to.
    ///
    /// Recorded at pairing from the keys the owner-approved exchange bound. A device paired before
    /// this host kept it has none until it declares its keys through `device.keys.complete`.
    pub stored_envelope: Option<StoredEnvelopeKey>,
    /// The device's notification-preview key: recorded at pairing on the same terms, replaced at a
    /// new key revision by each `device.preview_key.update`, and declared through
    /// `device.keys.complete` by a device whose record has none.
    pub notification_preview: Option<NotificationPreviewKey>,
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
    /// The invitation this pairing was committed from, where the record says.
    ///
    /// A candidate asks about an invitation, and the answer has to be about that invitation: a
    /// device that paired through one has no committed result to be told about another. A row
    /// written before this host recorded it has none, and that device stays paired: what it loses
    /// is the ability to be told about an invitation, not its authority.
    pub committed_invitation_id: Option<kr_protocol::ids::InvitationId>,
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

    /// Returns the device's four public keys, when this host holds all four.
    #[must_use]
    pub fn public_keys(&self) -> Option<DevicePublicKeys> {
        Some(DevicePublicKeys {
            transport: self.endpoint_id,
            authorisation: self.authorisation,
            stored_envelope: self.stored_envelope?,
            notification_preview: self.notification_preview?,
        })
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
                     ON network_devices (endpoint_id);
                 CREATE TABLE IF NOT EXISTS network_actions (
                     actor_id TEXT NOT NULL,
                     action_id BLOB NOT NULL,
                     session_id BLOB,
                     payload_digest BLOB,
                     recorded_at_ms INTEGER NOT NULL,
                     PRIMARY KEY (actor_id, action_id)
                 );
                 CREATE TABLE IF NOT EXISTS network_grant_deadlines (
                     device_id BLOB PRIMARY KEY NOT NULL,
                     boot_value BLOB NOT NULL,
                     deadline_boot_ms INTEGER NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS network_clock (
                     id INTEGER PRIMARY KEY NOT NULL CHECK (id = 0),
                     observed_ms INTEGER NOT NULL,
                     untrusted_at_ms INTEGER
                 );",
            )
        })?;
        // Forward-only, and applied to a table that already exists: `CREATE TABLE IF NOT EXISTS`
        // leaves an older table exactly as it was, and every read below names these columns. A
        // host upgraded in place would otherwise find its own paired devices unreadable.
        for column in [
            "expired_at_ms INTEGER",
            "committed_invitation_id BLOB",
            "notification_preview BLOB",
            "stored_envelope_key BLOB",
        ] {
            self.add_column("network_devices", column)?;
        }
        self.add_column("network_clock", "untrusted_at_ms INTEGER")?;
        self.rebuild_actions()?;
        Ok(())
    }

    /// Brings an older action table up to the shape every read below names.
    ///
    /// The columns changed twice: a payload digest was added, and the session became optional for
    /// an action this host itself owns the receipt of. Neither can be done with `ADD COLUMN`
    /// alone, because one of them relaxes a constraint, so the table is rebuilt and its rows are
    /// carried across. What they cannot carry is a digest nothing recorded: those identifiers keep
    /// their route and are spent, which refuses a second submission rather than dispatching one.
    fn rebuild_actions(&self) -> Result<()> {
        let columns: Vec<(String, i32)> = self.with(|connection| {
            let mut statement = connection.prepare("PRAGMA table_info(network_actions)")?;
            let rows = statement.query_map([], |row| Ok((row.get(1)?, row.get(3)?)))?;
            rows.collect()
        })?;
        let has_digest = columns.iter().any(|(name, _)| name == "payload_digest");
        let owner_optional = columns
            .iter()
            .any(|(name, notnull)| name == "session_id" && *notnull == 0);
        if has_digest && owner_optional {
            return Ok(());
        }
        // The digest is carried across when the old table had one. A row loses it only when
        // nothing ever recorded it, because a digest is what identifies an exact duplicate: a
        // row that arrived with one and left without it would turn a caller's own retry into a
        // reused identifier.
        let digest = if has_digest { "payload_digest" } else { "NULL" };
        let batch = format!(
            "BEGIN IMMEDIATE;
             ALTER TABLE network_actions RENAME TO network_actions_superseded;
             CREATE TABLE network_actions (
                 actor_id TEXT NOT NULL,
                 action_id BLOB NOT NULL,
                 session_id BLOB,
                 payload_digest BLOB,
                 recorded_at_ms INTEGER NOT NULL,
                 PRIMARY KEY (actor_id, action_id)
             );
             INSERT INTO network_actions
                 (actor_id, action_id, session_id, payload_digest, recorded_at_ms)
                 SELECT actor_id, action_id, session_id, {digest}, recorded_at_ms
                 FROM network_actions_superseded;
             DROP TABLE network_actions_superseded;
             COMMIT;"
        );
        self.with(|connection| connection.execute_batch(&batch))?;
        Ok(())
    }

    /// Adds one column to the device table, unless it is already there.
    ///
    /// SQLite has no conditional `ADD COLUMN`, and a duplicate is the ordinary case on every start
    /// after the first, so that one failure is the success case and anything else is not.
    fn add_column(&self, table: &str, definition: &str) -> Result<()> {
        let statement = format!("ALTER TABLE {table} ADD COLUMN {definition}");
        let outcome = self.with(|connection| connection.execute(&statement, []));
        match outcome {
            Ok(_) => Ok(()),
            Err(error) if error.to_string().contains("duplicate column name") => Ok(()),
            Err(error) => Err(error),
        }
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
                         expired_at_ms, committed_invitation_id, notification_preview,
                         stored_envelope_key
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, NULL, NULL, ?10, ?11, ?12)",
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
                        record
                            .committed_invitation_id
                            .map(|invitation| invitation.get().as_bytes().to_vec()),
                        record
                            .notification_preview
                            .map(|key| key.as_bytes().to_vec()),
                        record.stored_envelope.map(|key| key.as_bytes().to_vec()),
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
                            expired_at_ms, committed_invitation_id, notification_preview,
                            stored_envelope_key
                     FROM network_devices WHERE endpoint_id = ?1",
                    params![bytes],
                    |row| Ok(read_record(row)),
                )
                .optional()
        })?
        .transpose()
    }

    /// Records the two keys a device paired before this host kept them declares, and nothing more.
    ///
    /// The row is written only while it holds no stored-envelope key and either no preview key or
    /// the one declared, which a preview-key update may have recorded first. So a declaration
    /// completes a record and never replaces a key: a second declaration, of the same keys or of
    /// others, changes nothing.
    /// Returns the record as it stands afterwards, which the caller compares with what was declared.
    ///
    /// # Errors
    ///
    /// Returns an error when the row cannot be written or read back.
    pub fn complete_keys(
        &self,
        device_id: DeviceId,
        stored_envelope: &StoredEnvelopeKey,
        notification_preview: &NotificationPreviewKey,
    ) -> Result<Option<DeviceRecord>> {
        self.with(|connection| {
            connection
                .execute(
                    "UPDATE network_devices
                        SET stored_envelope_key = ?2, notification_preview = ?3
                      WHERE device_id = ?1
                        AND stored_envelope_key IS NULL
                        AND (notification_preview IS NULL OR notification_preview = ?3)",
                    params![
                        device_id.get().as_bytes().as_slice(),
                        stored_envelope.as_bytes().as_slice(),
                        notification_preview.as_bytes().as_slice(),
                    ],
                )
                .map(|_| ())
        })?;
        self.record_for_device(device_id)
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
                            expired_at_ms, committed_invitation_id, notification_preview,
                            stored_envelope_key
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
                        device_name, platform, grant, paired_at_ms, revoked_at_ms,
                        expired_at_ms, committed_invitation_id, notification_preview,
                        stored_envelope_key
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

    /// Claims the route of one remote action, before it is dispatched.
    ///
    /// A receipt lives in the journal of the session the action was performed on, and a device
    /// that reconnects to ask for its own result has nothing left to say where that was. The route
    /// is durable, so a reconnection, and a restart, can still find the receipt's owner. It is
    /// written before the dispatch, because an action whose route was recorded afterwards would be
    /// unfindable in exactly the case that needs it: the connection ended before the answer
    /// arrived.
    ///
    /// The claim is what makes `(actor_id, action_id)` one durable operation on this host. The
    /// first route for an action stays, and a second submission is told what the first one was:
    /// section 9 answers an exact duplicate from the receipt the first produced and refuses a
    /// reused identifier carrying a different payload. Reading and writing are one statement pair
    /// inside one immediate transaction, so two submissions of the same identifier cannot both be
    /// told they are the first.
    ///
    /// # Errors
    ///
    /// Returns an error when the row cannot be read or written.
    pub fn claim_action_route(
        &self,
        actor_id: &ActorId,
        action_id: kr_protocol::ids::ActionId,
        session_id: Option<kr_protocol::ids::SessionId>,
        payload_digest: Digest256,
        now_ms: TimestampMs,
    ) -> Result<ActionRoute> {
        self.with(|connection| {
            // Immediate, not deferred. A deferred transaction takes its read snapshot first, and
            // the daemon's own connection on this file can commit between that snapshot and this
            // insert, which SQLite answers by refusing the write rather than by serialising it.
            let transaction = rusqlite::Transaction::new_unchecked(
                connection,
                rusqlite::TransactionBehavior::Immediate,
            )?;
            let existing = read_route(&transaction, actor_id, action_id)?;
            if let Some(existing) = existing {
                transaction.commit()?;
                return Ok::<ActionRoute, rusqlite::Error>(ActionRoute::Existing(existing));
            }
            transaction.execute(
                "INSERT INTO network_actions
                     (actor_id, action_id, session_id, payload_digest, recorded_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    actor_id.as_str(),
                    action_id.get().as_bytes().as_slice(),
                    session_id.map(|session| session.get().as_bytes().to_vec()),
                    payload_digest.as_bytes().as_slice(),
                    i64::try_from(now_ms.get()).unwrap_or(i64::MAX),
                ],
            )?;
            transaction.commit()?;
            Ok(ActionRoute::Recorded)
        })
    }

    /// Returns where one actor's action went, and what payload it carried.
    ///
    /// # Errors
    ///
    /// Returns an error when the table cannot be read.
    pub fn action_route(
        &self,
        actor_id: &ActorId,
        action_id: kr_protocol::ids::ActionId,
    ) -> Result<Option<RoutedAction>> {
        self.with(|connection| read_route(connection, actor_id, action_id))
    }

    /// Returns the current UTC millisecond, never earlier than the latest this host has seen.
    ///
    /// Every decision about a grant's lifetime is made against this rather than the wall clock
    /// directly. A grant's expiry is a UTC moment, and a wall clock stepped backwards would put
    /// that moment in the future again: a device whose grant ran out yesterday would be current
    /// once more, which section 9 forbids. The highest moment this host has observed is durable,
    /// so the answer never goes backwards, across a restart included.
    ///
    /// # Errors
    ///
    /// Returns an error when the mark cannot be read or written.
    pub fn utc_at_least(&self, now_ms: TimestampMs) -> Result<ObservedUtc> {
        let now = i64::try_from(now_ms.get()).unwrap_or(i64::MAX);
        let observed: i64 = self.with(|connection| {
            connection.query_row(
                "INSERT INTO network_clock (id, observed_ms) VALUES (0, ?1)
                 ON CONFLICT (id) DO UPDATE SET observed_ms = MAX(observed_ms, ?1)
                 RETURNING observed_ms",
                params![now],
                |row| row.get(0),
            )
        })?;
        let observed = TimestampMs::new(u64::try_from(observed).unwrap_or_else(|_| now_ms.get()));
        let behind = observed.get().saturating_sub(now_ms.get());
        Ok(ObservedUtc {
            now: observed,
            behind_ms: behind,
        })
    }

    /// Records when one device's grant runs out, on the machine's own continuous clock.
    ///
    /// The deadline is bound to the boot it was derived in, because that is the clock it is
    /// measured on: milliseconds since this boot mean nothing after the next one. Within a boot it
    /// is the answer, restart of this daemon included, which is what stops an idle connection's
    /// expiry being re-derived from a wall clock that has since been stepped backwards.
    ///
    /// # Errors
    ///
    /// Returns an error when the row cannot be written.
    pub fn record_grant_deadline(
        &self,
        device_id: DeviceId,
        boot: &BootIdentity,
        deadline_boot_ms: u64,
    ) -> Result<()> {
        self.with(|connection| {
            connection.execute(
                "INSERT INTO network_grant_deadlines (device_id, boot_value, deadline_boot_ms)
                 VALUES (?1, ?2, ?3)
                 ON CONFLICT (device_id) DO UPDATE
                     SET boot_value = ?2, deadline_boot_ms = ?3",
                params![
                    device_id.get().as_bytes().as_slice(),
                    boot.value.as_slice(),
                    i64::try_from(deadline_boot_ms).unwrap_or(i64::MAX),
                ],
            )
        })?;
        Ok(())
    }

    /// Returns the deadline this host derived for one device in the boot it is running in.
    ///
    /// A deadline from an earlier boot is not returned: the clock it was measured on has gone with
    /// that boot, and a number of milliseconds since a boot that has ended says nothing about this
    /// one.
    ///
    /// # Errors
    ///
    /// Returns an error when the table cannot be read.
    pub fn grant_deadline_in(
        &self,
        device_id: DeviceId,
        boot: &BootIdentity,
    ) -> Result<Option<u64>> {
        let row: Option<(Vec<u8>, i64)> = self.with(|connection| {
            connection
                .query_row(
                    "SELECT boot_value, deadline_boot_ms FROM network_grant_deadlines
                     WHERE device_id = ?1",
                    params![device_id.get().as_bytes().as_slice()],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
        })?;
        let Some((recorded, deadline)) = row else {
            return Ok(None);
        };
        if recorded.as_slice() != boot.value.as_slice() {
            return Ok(None);
        }
        Ok(Some(u64::try_from(deadline).unwrap_or_default()))
    }

    /// Records that this host's wall clock could not be trusted to decide an expiry.
    ///
    /// It is durable because the decision has to outlive the connection that found it and the run
    /// that was serving it: a clock that went backwards once, and then reads plausibly again,
    /// would otherwise let the next connection decide a grant's life against it. What clears it is
    /// [`Self::trust_clock`], and only a clock that has caught up with everything this host has
    /// already recorded reaches that.
    ///
    /// # Errors
    ///
    /// Returns an error when the row cannot be written.
    pub fn note_clock_untrusted(&self, now_ms: TimestampMs) -> Result<()> {
        self.with(|connection| {
            connection.execute(
                "INSERT INTO network_clock (id, observed_ms, untrusted_at_ms)
                 VALUES (0, ?1, ?1)
                 ON CONFLICT (id) DO UPDATE
                     SET untrusted_at_ms = COALESCE(untrusted_at_ms, ?1)",
                params![i64::try_from(now_ms.get()).unwrap_or(i64::MAX)],
            )
        })?;
        Ok(())
    }

    /// Returns whether this host has recorded its wall clock as untrustworthy.
    ///
    /// # Errors
    ///
    /// Returns an error when the row cannot be read.
    pub fn clock_untrusted(&self) -> Result<bool> {
        let recorded: Option<Option<i64>> = self.with(|connection| {
            connection
                .query_row(
                    "SELECT untrusted_at_ms FROM network_clock WHERE id = 0",
                    [],
                    |row| row.get(0),
                )
                .optional()
        })?;
        Ok(recorded.flatten().is_some())
    }

    /// Clears the record above, and marks the moment the clock was established at.
    ///
    /// The mark moves with it, to `now_ms`. It has to: the mark is what a rollback is measured
    /// against, and a host whose clock had been running *ahead* would otherwise be told it had
    /// gone backwards by the very correction the owner just authenticated. What does not move is
    /// anything already decided - the expiry tombstones, and the deadlines this boot holds - so a
    /// grant this host has already found to be over stays over.
    ///
    /// # Errors
    ///
    /// Returns an error when the row cannot be written.
    pub fn trust_clock(&self, now_ms: TimestampMs) -> Result<()> {
        self.with(|connection| {
            connection.execute(
                "INSERT INTO network_clock (id, observed_ms, untrusted_at_ms)
                 VALUES (0, ?1, NULL)
                 ON CONFLICT (id) DO UPDATE SET observed_ms = ?1, untrusted_at_ms = NULL",
                params![i64::try_from(now_ms.get()).unwrap_or(i64::MAX)],
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

    /// Updates the notification-preview public key and key revision for a device.
    ///
    /// The revision only moves forward. A registration is a key and the number the device gave it,
    /// and a number that does not follow the one recorded belongs to a registration this host has
    /// already replaced: writing it would put a retired key back into service, and the same
    /// revision is also what a connection is authenticated against. The condition is part of the
    /// write rather than a read before it, so two registrations racing cannot both pass it.
    ///
    /// A repeat of the registration already recorded is not a move backwards and is not refused:
    /// an answer lost on the way to the device is resubmitted, and the store it reaches says the
    /// same thing it said the first time.
    ///
    /// # Errors
    ///
    /// Returns an error when the row cannot be written.
    pub fn update_preview_key(
        &self,
        device_id: DeviceId,
        preview_key: NotificationPreviewKey,
        revision: DeviceKeyRevision,
    ) -> Result<PreviewKeyOutcome> {
        let Some(record) = self.record_for_device(device_id)? else {
            return Ok(PreviewKeyOutcome::NotPaired);
        };
        if record.revoked_at_ms.is_some() {
            return Ok(PreviewKeyOutcome::NotPaired);
        }
        if record.device_key_revision == revision
            && record.notification_preview == Some(preview_key)
        {
            return Ok(PreviewKeyOutcome::AlreadyRecorded);
        }
        let bytes = device_id.get().as_bytes().to_vec();
        let changed = self.with(|connection| {
            connection.execute(
                "UPDATE network_devices
                 SET notification_preview = ?2,
                     device_key_revision = ?3
                 WHERE device_id = ?1 AND revoked_at_ms IS NULL
                   AND device_key_revision < ?3",
                params![
                    bytes,
                    preview_key.as_bytes().as_slice(),
                    i64::try_from(revision.get()).unwrap_or(i64::MAX),
                ],
            )
        })?;
        if changed > 0 {
            return Ok(PreviewKeyOutcome::Recorded);
        }
        Ok(PreviewKeyOutcome::RevisionBehind(
            record.device_key_revision,
        ))
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
    let invitation: Option<Vec<u8>> = row.get(10).map_err(ControllerError::registry)?;
    let notification_preview: Option<Vec<u8>> = row.get(11).map_err(ControllerError::registry)?;
    let stored_envelope: Option<Vec<u8>> = row.get(12).map_err(ControllerError::registry)?;
    Ok(DeviceRecord {
        device_id: DeviceId::new(uuid(&device_id)?),
        endpoint_id: EndpointKey::from_bytes(key(&endpoint_id)?),
        device_key_revision: DeviceKeyRevision::new(
            u64::try_from(device_key_revision).unwrap_or_default(),
        ),
        authorisation: AuthorisationKey::from_bytes(key(&authorisation)?),
        stored_envelope: stored_envelope
            .as_deref()
            .map(|bytes| key(bytes).map(StoredEnvelopeKey::from_bytes))
            .transpose()?,
        notification_preview: notification_preview
            .as_deref()
            .map(|bytes| key(bytes).map(NotificationPreviewKey::from_bytes))
            .transpose()?,
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
        committed_invitation_id: invitation
            .as_deref()
            .map(|bytes| uuid(bytes).map(kr_protocol::ids::InvitationId::new))
            .transpose()?,
    })
}

/// Returns the grant identity a row records, for a caller that wants it without the grant.
#[must_use]
pub fn grant_id_of(record: &DeviceRecord) -> GrantId {
    record.grant.grant_id
}

/// Reads one action's route on a connection the caller already holds.
fn read_route(
    connection: &Connection,
    actor_id: &ActorId,
    action_id: kr_protocol::ids::ActionId,
) -> rusqlite::Result<Option<RoutedAction>> {
    /// The two nullable columns of one route row, as SQLite hands them over.
    type Row = (Option<Vec<u8>>, Option<Vec<u8>>);

    let row: Option<Row> = connection
        .query_row(
            "SELECT session_id, payload_digest FROM network_actions
             WHERE actor_id = ?1 AND action_id = ?2",
            params![actor_id.as_str(), action_id.get().as_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let Some((session, digest)) = row else {
        return Ok(None);
    };
    // A session is sixteen bytes and a digest is thirty-two. Anything else is a value nothing here
    // wrote, and it is read as absent rather than guessed at: an unknown owner and an unknown
    // payload both refuse a second submission.
    Ok(Some(RoutedAction {
        session_id: session
            .and_then(|bytes| <[u8; 16]>::try_from(bytes).ok())
            .map(|bytes| kr_protocol::ids::SessionId::new(Uuid::from_bytes(bytes))),
        payload_digest: digest
            .and_then(|bytes| key(&bytes).ok())
            .map(Digest256::from_bytes),
    }))
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
            stored_envelope: Some(StoredEnvelopeKey::from_bytes([byte ^ 0x0f; 32])),
            notification_preview: Some(NotificationPreviewKey::from_bytes([byte ^ 0xf0; 32])),
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
            committed_invitation_id: Some(kr_protocol::ids::InvitationId::new(Uuid::from_bytes(
                [byte ^ 0x0f; 16],
            ))),
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

    #[test]
    fn a_preview_key_is_updated_on_the_device_record() {
        let directory = DeviceDirectory::in_memory().expect("a directory");
        let device = record(1);
        directory.commit(&device).expect("the row is written");

        let preview_key = NotificationPreviewKey::from_bytes([42; 32]);
        let revision = DeviceKeyRevision::new(2);
        let updated = directory
            .update_preview_key(device.device_id, preview_key, revision)
            .expect("update succeeds");
        assert_eq!(updated, PreviewKeyOutcome::Recorded);

        let stored = directory
            .record_for_device(device.device_id)
            .expect("read")
            .expect("found");
        assert_eq!(stored.notification_preview, Some(preview_key));
        assert_eq!(stored.device_key_revision, revision);

        let missing = DeviceId::new(Uuid::from_bytes([99; 16]));
        let not_found = directory
            .update_preview_key(missing, preview_key, revision)
            .expect("update succeeds");
        assert_eq!(not_found, PreviewKeyOutcome::NotPaired);
    }

    /// A revision that does not follow the one recorded belongs to a registration this host has
    /// already replaced, and the same registration again is not a move backwards.
    #[test]
    fn a_preview_key_revision_only_moves_forward_in_the_directory() {
        let directory = DeviceDirectory::in_memory().expect("a directory");
        let device = record(1);
        directory.commit(&device).expect("the row is written");
        let third = NotificationPreviewKey::from_bytes([3; 32]);
        assert_eq!(
            directory
                .update_preview_key(device.device_id, third, DeviceKeyRevision::new(3))
                .expect("a write"),
            PreviewKeyOutcome::Recorded
        );
        for behind in [0, 2, 3] {
            let outcome = directory
                .update_preview_key(
                    device.device_id,
                    NotificationPreviewKey::from_bytes([9; 32]),
                    DeviceKeyRevision::new(behind),
                )
                .expect("a write");
            assert_eq!(
                outcome,
                PreviewKeyOutcome::RevisionBehind(DeviceKeyRevision::new(3)),
                "revision {behind} does not follow 3"
            );
        }
        assert_eq!(
            directory
                .update_preview_key(device.device_id, third, DeviceKeyRevision::new(3))
                .expect("a write"),
            PreviewKeyOutcome::AlreadyRecorded,
            "the same registration again is the registration this host already holds"
        );
        let stored = directory
            .record_for_device(device.device_id)
            .expect("a read")
            .expect("the record");
        assert_eq!(stored.notification_preview, Some(third));
        assert_eq!(stored.device_key_revision, DeviceKeyRevision::new(3));
    }

    #[test]
    fn a_pairing_keeps_all_four_keys_and_an_earlier_one_completes_them_once() {
        let directory = DeviceDirectory::in_memory().expect("a directory");
        let complete = record(1);
        directory.commit(&complete).expect("committed");
        let read = directory
            .record_for_device(complete.device_id)
            .expect("read")
            .expect("present");
        assert!(read.public_keys().is_some());
        assert_eq!(read.public_keys(), complete.public_keys());

        // A device paired before this host kept every key has two of them.
        let mut earlier = record(2);
        earlier.stored_envelope = None;
        earlier.notification_preview = None;
        directory.commit(&earlier).expect("committed");
        let before = directory
            .record_for_device(earlier.device_id)
            .expect("read")
            .expect("present");
        assert!(before.public_keys().is_none());

        let stored = StoredEnvelopeKey::from_bytes([0x21; 32]);
        let preview = NotificationPreviewKey::from_bytes([0x22; 32]);
        let completed = directory
            .complete_keys(earlier.device_id, &stored, &preview)
            .expect("written")
            .expect("present");
        assert_eq!(completed.stored_envelope, Some(stored));
        assert_eq!(completed.notification_preview, Some(preview));

        // A second declaration changes nothing, whatever it declares: a declaration completes a
        // record and never replaces a key.
        let again = directory
            .complete_keys(
                earlier.device_id,
                &StoredEnvelopeKey::from_bytes([0x31; 32]),
                &NotificationPreviewKey::from_bytes([0x32; 32]),
            )
            .expect("written")
            .expect("present");
        assert_eq!(again.stored_envelope, Some(stored));
        assert_eq!(again.notification_preview, Some(preview));
    }
}
