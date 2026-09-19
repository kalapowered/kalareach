//! Where the host keeps its grants, and how revoking one revokes its descendants.
//!
//! The durable shape is one row per grant: the grant itself as canonical bytes, its parent, the
//! session it shares, when it was issued and, once it is revoked, when and because of which
//! ancestor. The parent column is what makes section 10's cascade a property of the store rather
//! than a loop somebody has to remember to write: "Each grant names its parent; revoking a parent
//! revokes descendants."
//!
//! Two things the cascade has to get right, and both are tested:
//!
//! * **It reaches the whole subtree, not the children.** A grant delegated from a delegation is
//!   still a descendant.
//! * **It terminates.** A row whose parent is itself, or a pair that name each other, cannot be
//!   written through [`GrantDirectory::issue`] because a parent must already exist and a grant's
//!   identity is new. The walk still carries a visited set, because a store is a file and a file
//!   can be edited by something that is not this code, and an authority store that could be made
//!   to spin by a hand-written row would be a way to stop revocations working.
//!
//! The directory opens the daemon's own registry database, the way the device directory does, so
//! a grant and the device that holds it are in one file and one backup.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::Path;

use rusqlite::{Connection, OptionalExtension, params};

use kr_protocol::grant::Grant;
use kr_protocol::ids::{DeviceId, GrantId, SessionId};
use kr_protocol::scalars::{Nullable, TimestampMs};
use kr_protocol::sharing::{GrantState, GrantSummary};

use crate::error::{ControllerError, Result};

/// One grant as the store holds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrantRecord {
    /// The grant itself.
    pub grant: Grant,
    /// The session it shares, when it shares one.
    pub session_id: Option<SessionId>,
    /// When it was issued, in UTC milliseconds.
    pub issued_at_ms: u64,
    /// When it was revoked, when it has been.
    pub revoked_at_ms: Option<u64>,
    /// The ancestor whose revocation revoked it, when it was revoked as a descendant.
    pub revoked_by_parent: Option<GrantId>,
}

impl GrantRecord {
    /// Where this grant stands at `now_ms`.
    #[must_use]
    pub fn state(&self, now_ms: u64) -> GrantState {
        if self.revoked_at_ms.is_some() {
            GrantState::Revoked
        } else if self.grant.expiry.is_valid_at(now_ms) {
            GrantState::Active
        } else {
            GrantState::Expired
        }
    }

    /// The wire summary of this record.
    #[must_use]
    pub fn summary(&self, now_ms: u64) -> GrantSummary {
        GrantSummary {
            grant: self.grant.clone(),
            state: self.state(now_ms),
            revoked_at_ms: Nullable(self.revoked_at_ms.map(TimestampMs::new)),
            revoked_by_parent: Nullable(self.revoked_by_parent),
        }
    }
}

/// What one revocation did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrantRevocation {
    /// The grant that was named.
    pub grant_id: GrantId,
    /// Every grant this revocation revoked: the named one and its descendants, in order.
    pub revoked: Vec<GrantId>,
    /// The devices that held them, which is what a revocation has to fence.
    pub devices: BTreeSet<DeviceId>,
    /// The sessions those grants covered, which is what a revocation has to close subscriptions
    /// for. Empty when a revoked grant covered every session.
    pub sessions: BTreeSet<SessionId>,
    /// True when one of the revoked grants covered every session, so the fence is not narrowed by
    /// the session list.
    pub covers_every_session: bool,
}

impl GrantRevocation {
    /// Returns true when this revocation affects `session_id`.
    #[must_use]
    pub fn affects_session(&self, session_id: SessionId) -> bool {
        self.covers_every_session || self.sessions.contains(&session_id)
    }
}

/// The host's grants.
#[derive(Debug)]
pub struct GrantDirectory {
    connection: std::sync::Mutex<Connection>,
}

impl GrantDirectory {
    /// Opens the directory in the daemon's registry database, creating its table.
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
    /// Returns an error when the table cannot be created.
    pub fn in_memory() -> Result<Self> {
        Self::prepare(Connection::open_in_memory().map_err(ControllerError::registry)?)
    }

    fn prepare(connection: Connection) -> Result<Self> {
        // The durability the rest of the daemon's state uses. A grant a crash lost would be a
        // device that cannot connect and no record of why; a revocation a crash lost would be
        // worse.
        connection
            .pragma_update(None, "journal_mode", "WAL")
            .map_err(ControllerError::registry)?;
        connection
            .pragma_update(None, "synchronous", "FULL")
            .map_err(ControllerError::registry)?;
        connection
            .busy_timeout(std::time::Duration::from_secs(5))
            .map_err(ControllerError::registry)?;
        connection
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS grants (
                     grant_id          BLOB PRIMARY KEY NOT NULL,
                     parent_grant_id   BLOB,
                     recipient_device_id BLOB NOT NULL,
                     session_id        BLOB,
                     grant             BLOB NOT NULL,
                     issued_at_ms      INTEGER NOT NULL,
                     revoked_at_ms     INTEGER,
                     revoked_by_parent BLOB
                 );
                 CREATE INDEX IF NOT EXISTS grants_by_parent ON grants (parent_grant_id);
                 CREATE INDEX IF NOT EXISTS grants_by_device ON grants (recipient_device_id);",
            )
            .map_err(ControllerError::registry)?;
        Ok(Self {
            connection: std::sync::Mutex::new(connection),
        })
    }

    fn with<T>(&self, body: impl FnOnce(&Connection) -> rusqlite::Result<T>) -> Result<T> {
        let connection = self
            .connection
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        body(&connection).map_err(ControllerError::registry)
    }

    /// Writes a grant.
    ///
    /// A grant that names a parent is checked against that parent here, not only where it was
    /// composed: the parent has to exist, has to be live, and the child has to narrow it. Section
    /// 10 allows delegation to narrow and never to extend, and section 19 says delegation cannot
    /// grant rights the delegating actor lacks. Both are the same check, and this is where it is
    /// unavoidable.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::InvalidArgument`] when the identity is already in use, and
    /// [`ControllerError::PermissionDenied`] when the parent is missing, revoked, expired, or is
    /// not narrowed by the child.
    pub fn issue(&self, record: &GrantRecord) -> Result<()> {
        if let Some(parent_grant_id) = record.grant.parent_grant_id.as_ref().copied() {
            let parent =
                self.record(parent_grant_id)?
                    .ok_or_else(|| ControllerError::PermissionDenied {
                        detail: "this grant names a parent this host does not hold".to_owned(),
                    })?;
            if parent.revoked_at_ms.is_some() {
                return Err(ControllerError::PermissionDenied {
                    detail: "the grant this one delegates from has been revoked".to_owned(),
                });
            }
            if !parent.grant.expiry.is_valid_at(record.issued_at_ms) {
                return Err(ControllerError::PermissionDenied {
                    detail: "the grant this one delegates from has expired".to_owned(),
                });
            }
            if !record.grant.narrows(&parent.grant) {
                return Err(ControllerError::PermissionDenied {
                    detail: "a delegated grant narrows its parent; it never extends one".to_owned(),
                });
            }
        }
        let encoded = kr_cbor::to_canonical_vec(&record.grant)
            .map_err(|error| ControllerError::InvalidArgument(error.to_string()))?;
        let written = self.with(|connection| {
            connection.execute(
                "INSERT OR IGNORE INTO grants (
                     grant_id, parent_grant_id, recipient_device_id, session_id, grant,
                     issued_at_ms, revoked_at_ms, revoked_by_parent
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, NULL)",
                params![
                    record.grant.grant_id.get().as_bytes().as_slice(),
                    record
                        .grant
                        .parent_grant_id
                        .as_ref()
                        .map(|parent| parent.get().as_bytes().to_vec()),
                    record.grant.recipient_device_id.get().as_bytes().as_slice(),
                    record
                        .session_id
                        .map(|session| session.get().as_bytes().to_vec()),
                    encoded,
                    i64::try_from(record.issued_at_ms).unwrap_or(i64::MAX),
                ],
            )
        })?;
        if written == 0 {
            return Err(ControllerError::InvalidArgument(
                "that grant identity is already in use".to_owned(),
            ));
        }
        Ok(())
    }

    /// Returns one grant's record, revoked or not.
    ///
    /// # Errors
    ///
    /// Returns an error when the row cannot be read.
    pub fn record(&self, grant_id: GrantId) -> Result<Option<GrantRecord>> {
        let key = grant_id.get().as_bytes().to_vec();
        let row: Option<Row> = self.with(|connection| {
            connection
                .query_row(
                    "SELECT grant, session_id, issued_at_ms, revoked_at_ms, revoked_by_parent
                     FROM grants WHERE grant_id = ?1",
                    params![key],
                    |row| Ok(read_row(row)),
                )
                .optional()
        })?;
        row.transpose()
    }

    /// Returns every grant, in identity order.
    ///
    /// # Errors
    ///
    /// Returns an error when the rows cannot be read.
    pub fn records(&self) -> Result<Vec<GrantRecord>> {
        let rows: Vec<Row> = self.with(|connection| {
            let mut statement = connection.prepare(
                "SELECT grant, session_id, issued_at_ms, revoked_at_ms, revoked_by_parent
                 FROM grants ORDER BY grant_id",
            )?;
            let rows = statement
                .query_map([], |row| Ok(read_row(row)))?
                .collect::<rusqlite::Result<Vec<Row>>>()?;
            Ok(rows)
        })?;
        rows.into_iter().collect()
    }

    /// Returns every grant one device holds.
    ///
    /// # Errors
    ///
    /// Returns an error when the rows cannot be read.
    pub fn records_for_device(&self, device_id: DeviceId) -> Result<Vec<GrantRecord>> {
        let key = device_id.get().as_bytes().to_vec();
        let rows: Vec<Row> = self.with(|connection| {
            let mut statement = connection.prepare(
                "SELECT grant, session_id, issued_at_ms, revoked_at_ms, revoked_by_parent
                 FROM grants WHERE recipient_device_id = ?1 ORDER BY grant_id",
            )?;
            let rows = statement
                .query_map(params![key], |row| Ok(read_row(row)))?
                .collect::<rusqlite::Result<Vec<Row>>>()?;
            Ok(rows)
        })?;
        rows.into_iter().collect()
    }

    /// Revokes a grant and every grant delegated from it, however deep.
    ///
    /// Idempotent: a grant already revoked keeps the moment and the ancestor it was first revoked
    /// under, so a repeated revocation cannot rewrite the record of the first one. A descendant
    /// that was already revoked on its own is left as it was, for the same reason.
    ///
    /// # Errors
    ///
    /// Returns an error when the rows cannot be read or written, and
    /// [`ControllerError::InvalidArgument`] when this host holds no such grant.
    pub fn revoke(&self, grant_id: GrantId, now_ms: u64) -> Result<GrantRevocation> {
        let subtree = self.subtree(grant_id)?;
        if subtree.is_empty() {
            return Err(ControllerError::InvalidArgument(
                "this host holds no such grant".to_owned(),
            ));
        }
        let mut revoked = Vec::new();
        let mut devices = BTreeSet::new();
        let mut sessions = BTreeSet::new();
        let mut covers_every_session = false;
        for record in &subtree {
            devices.insert(record.grant.recipient_device_id);
            match &record.grant.session_selector {
                kr_protocol::grant::SessionSelector::Any => covers_every_session = true,
                kr_protocol::grant::SessionSelector::These { session_ids } => {
                    sessions.extend(session_ids.iter().copied());
                }
                kr_protocol::grant::SessionSelector::None => {}
            }
            if let Some(session_id) = record.session_id {
                sessions.insert(session_id);
            }
            revoked.push(record.grant.grant_id);
        }
        let moment = i64::try_from(now_ms).unwrap_or(i64::MAX);
        self.with(|connection| {
            for record in &subtree {
                let is_the_named_one = record.grant.grant_id == grant_id;
                connection.execute(
                    "UPDATE grants
                        SET revoked_at_ms = ?2,
                            revoked_by_parent = CASE WHEN ?3 THEN NULL ELSE ?4 END
                      WHERE grant_id = ?1 AND revoked_at_ms IS NULL",
                    params![
                        record.grant.grant_id.get().as_bytes().as_slice(),
                        moment,
                        is_the_named_one,
                        grant_id.get().as_bytes().as_slice(),
                    ],
                )?;
            }
            Ok(())
        })?;
        Ok(GrantRevocation {
            grant_id,
            revoked,
            devices,
            sessions,
            covers_every_session,
        })
    }

    /// Revokes every grant one device holds, and their descendants.
    ///
    /// # Errors
    ///
    /// Returns an error when the rows cannot be read or written.
    pub fn revoke_device(&self, device_id: DeviceId, now_ms: u64) -> Result<GrantRevocation> {
        let held = self.records_for_device(device_id)?;
        let mut merged = GrantRevocation {
            grant_id: held.first().map_or_else(
                || GrantId::new(kr_protocol::scalars::Uuid::NIL),
                |record| record.grant.grant_id,
            ),
            revoked: Vec::new(),
            devices: BTreeSet::new(),
            sessions: BTreeSet::new(),
            covers_every_session: false,
        };
        merged.devices.insert(device_id);
        for record in held {
            if record.revoked_at_ms.is_some() {
                continue;
            }
            let one = self.revoke(record.grant.grant_id, now_ms)?;
            merged.revoked.extend(one.revoked);
            merged.devices.extend(one.devices);
            merged.sessions.extend(one.sessions);
            merged.covers_every_session |= one.covers_every_session;
        }
        Ok(merged)
    }

    /// The grant and every grant delegated from it, breadth first.
    ///
    /// The visited set is not defensive clutter. This store is a file, and a row that named itself
    /// as its parent would otherwise make every revocation of that subtree run for ever, which is
    /// a way to stop revocations working rather than a tidy internal invariant.
    fn subtree(&self, grant_id: GrantId) -> Result<Vec<GrantRecord>> {
        let Some(root) = self.record(grant_id)? else {
            return Ok(Vec::new());
        };
        let children = self.children_by_parent()?;
        let mut seen: BTreeSet<GrantId> = BTreeSet::new();
        let mut queue: VecDeque<GrantRecord> = VecDeque::new();
        let mut found = Vec::new();
        seen.insert(root.grant.grant_id);
        queue.push_back(root);
        while let Some(record) = queue.pop_front() {
            if let Some(next) = children.get(&record.grant.grant_id) {
                for child in next {
                    if seen.insert(child.grant.grant_id) {
                        queue.push_back(child.clone());
                    }
                }
            }
            found.push(record);
        }
        Ok(found)
    }

    fn children_by_parent(&self) -> Result<BTreeMap<GrantId, Vec<GrantRecord>>> {
        let mut children: BTreeMap<GrantId, Vec<GrantRecord>> = BTreeMap::new();
        for record in self.records()? {
            if let Some(parent) = record.grant.parent_grant_id.as_ref().copied() {
                children.entry(parent).or_default().push(record);
            }
        }
        Ok(children)
    }
}

type Row = Result<GrantRecord>;

fn read_row(row: &rusqlite::Row<'_>) -> Row {
    let encoded: Vec<u8> = row.get(0).map_err(ControllerError::registry)?;
    let grant: Grant = kr_cbor::from_canonical_slice(&encoded, &kr_cbor::Limits::DEFAULT)
        .map_err(|error| ControllerError::InvalidArgument(error.to_string()))?;
    let session: Option<Vec<u8>> = row.get(1).map_err(ControllerError::registry)?;
    let issued: i64 = row.get(2).map_err(ControllerError::registry)?;
    let revoked: Option<i64> = row.get(3).map_err(ControllerError::registry)?;
    let by_parent: Option<Vec<u8>> = row.get(4).map_err(ControllerError::registry)?;
    Ok(GrantRecord {
        grant,
        session_id: session.as_deref().and_then(uuid_of).map(SessionId::new),
        issued_at_ms: u64::try_from(issued).unwrap_or_default(),
        revoked_at_ms: revoked.map(|moment| u64::try_from(moment).unwrap_or_default()),
        revoked_by_parent: by_parent.as_deref().and_then(uuid_of).map(GrantId::new),
    })
}

fn uuid_of(bytes: &[u8]) -> Option<kr_protocol::scalars::Uuid> {
    <[u8; 16]>::try_from(bytes)
        .ok()
        .map(kr_protocol::scalars::Uuid::from_bytes)
}
