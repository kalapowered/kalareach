//! Where the host keeps its grants, and how revoking one revokes its descendants.
//!
//! The durable shape is one row per grant: the grant itself as canonical bytes, its parent, the
//! session it shares, when it was issued and, once it is revoked, when and because of which
//! ancestor. The parent column is what makes section 10's cascade a property of the store rather
//! than a loop somebody has to remember to write: "Each grant names its parent; revoking a parent
//! revokes descendants."
//!
//! Everything that reads and then writes does both inside one immediate transaction, under the
//! store's own lock. One daemon owns an environment, but a daemon runs many tasks: without the
//! transaction a child grant could be written between a revocation reading its subtree and
//! updating it, and escape the cascade entirely. The lock alone is not enough either, because a
//! crash part way through the update loop would leave a subtree half revoked.
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
use kr_protocol::ids::InvitationId;
use kr_protocol::ids::{ActionId, ActorId, DeviceId, GrantId, SessionId};
use kr_protocol::scalars::{Digest256, Nullable, TimestampMs};
use kr_protocol::sharing::{GrantState, GrantSummary, InvitationPreview, InvitationState};

use crate::sharing::invitation::{InvitationRecord, state_of};

use super::durable::{StoredFeed, StoredPolicy};

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
    /// When its invitation was redeemed, when it has been.
    ///
    /// A grant with no activation is a **proposal**: it is written down, its issuer's authority has
    /// been checked against it, and it authorises nothing until the device it names redeems the
    /// invitation that carries it. Section 25's "invitations are single-use" is that redemption, and
    /// a grant that was live before anybody redeemed it would make the word meaningless.
    pub activated_at_ms: Option<u64>,
    /// When it was revoked, when it has been.
    pub revoked_at_ms: Option<u64>,
    /// The ancestor whose revocation revoked it, when it was revoked as a descendant.
    pub revoked_by_parent: Option<GrantId>,
}

impl GrantRecord {
    /// Returns true when this grant's invitation has been redeemed.
    #[must_use]
    pub const fn is_active(&self) -> bool {
        self.activated_at_ms.is_some()
    }

    /// Where this grant stands at `now_ms`.
    ///
    /// A proposal nobody has redeemed reads as `Pending`: it is not active, and calling it expired
    /// or revoked would be saying something untrue about why it authorises nothing.
    #[must_use]
    pub fn state(&self, now_ms: u64) -> GrantState {
        if self.revoked_at_ms.is_some() {
            GrantState::Revoked
        } else if !self.grant.expiry.is_valid_at(now_ms) {
            // Expiry comes before pending. A proposal whose deadline has passed is finished, and
            // reporting it as still waiting for somebody would be an invitation list that never
            // shrinks.
            GrantState::Expired
        } else if self.is_active() {
            GrantState::Active
        } else {
            GrantState::Pending
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

/// What a claim on one action found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ActionClaim {
    /// This caller now holds the claim, from the moment it was made.
    Claimed {
        /// When the claim was made. The effect builds its proposal from this, so a retry asks for
        /// the same thing rather than one with a later deadline.
        claimed_at_ms: u64,
    },
    /// Somebody else holds the claim and has not finished.
    ///
    /// Two requests under one action identifier must not both reach the effect. The second is told
    /// the work is under way rather than performing it again, because two `grant.revoke` calls
    /// that both ran would advance the revision twice and fence the host twice for one withdrawal.
    InFlight,
    /// This action already happened, and here is what it produced.
    Answered {
        /// The encoded result.
        result: Vec<u8>,
    },
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
                     activated_at_ms   INTEGER,
                     revoked_at_ms     INTEGER,
                     revoked_by_parent BLOB
                 );
                 CREATE INDEX IF NOT EXISTS grants_by_parent ON grants (parent_grant_id);
                 CREATE INDEX IF NOT EXISTS grants_by_device ON grants (recipient_device_id);
                 CREATE TABLE IF NOT EXISTS authority_receipts (
                     actor_id       TEXT NOT NULL,
                     action_id      BLOB NOT NULL,
                     payload_digest BLOB NOT NULL,
                     claimed_at_ms  INTEGER NOT NULL,
                     leased_at_ms   INTEGER NOT NULL,
                     result         BLOB,
                     recorded_at_ms INTEGER,
                     PRIMARY KEY (actor_id, action_id)
                 );
                 CREATE TABLE IF NOT EXISTS host_authority (
                     key   TEXT PRIMARY KEY NOT NULL,
                     value BLOB NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS session_invitations (
                     invitation_id       BLOB PRIMARY KEY NOT NULL,
                     issuer_device_id    BLOB NOT NULL,
                     grant_id            BLOB NOT NULL,
                     recipient_device_id BLOB NOT NULL,
                     preview             BLOB NOT NULL,
                     state               TEXT NOT NULL,
                     redeemed_by         BLOB,
                     issued_at_ms        INTEGER NOT NULL,
                     expires_at_ms       INTEGER NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS fence_debt (
                     grant_id      BLOB PRIMARY KEY NOT NULL,
                     recorded_at_ms INTEGER NOT NULL
                 );",
            )
            .map_err(ControllerError::registry)?;
        // A store written by an earlier build has the receipts table without its lease column.
        // `CREATE TABLE IF NOT EXISTS` leaves that table alone, so the column is added here and
        // every existing claim's lease starts from the moment it was claimed. Without this a host
        // that upgraded would fail on its first authority change, reading a column that is not
        // there.
        let has_lease = connection
            .prepare("SELECT leased_at_ms FROM authority_receipts LIMIT 1")
            .is_ok();
        if !has_lease {
            // One transaction, because the two statements are one change. An interruption between
            // them would leave the column there and every existing lease at zero, and the next
            // start would find the column and never run the backfill: every pending claim would
            // read as stale for ever after.
            connection
                .execute_batch(
                    "BEGIN IMMEDIATE;
                     ALTER TABLE authority_receipts
                         ADD COLUMN leased_at_ms INTEGER NOT NULL DEFAULT 0;
                     UPDATE authority_receipts SET leased_at_ms = claimed_at_ms
                      WHERE leased_at_ms = 0;
                     COMMIT;",
                )
                .map_err(ControllerError::registry)?;
        }
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

    /// Runs one read-then-write sequence as a single immediate transaction.
    ///
    /// `Immediate` rather than the default deferred begin, so the write lock is taken before the
    /// first read rather than when the first write happens: a deferred transaction that read a
    /// subtree and then failed to upgrade would have to be retried, and retrying an authority
    /// change is exactly where a caller stops paying attention.
    ///
    /// The transaction rolls back when it is dropped, which covers the three ways a closure can
    /// end without committing: it returned an error, the commit itself failed, or it panicked.
    /// A connection left inside a transaction would hold this database's writer lock, and the
    /// registry and the device directory write to the same file.
    fn in_transaction<T>(&self, body: impl FnOnce(&Connection) -> Result<T>) -> Result<T> {
        let connection = self
            .connection
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let transaction = rusqlite::Transaction::new_unchecked(
            &connection,
            rusqlite::TransactionBehavior::Immediate,
        )
        .map_err(ControllerError::registry)?;
        let value = body(&transaction)?;
        transaction.commit().map_err(ControllerError::registry)?;
        Ok(value)
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
        let encoded = kr_cbor::to_canonical_vec(&record.grant)
            .map_err(|error| ControllerError::InvalidArgument(error.to_string()))?;
        // The parent check and the write are one transaction. Checking first and writing after
        // would prove the parent stood before the write rather than at it, and a revocation that
        // landed in between would leave a live child of a revoked parent.
        self.in_transaction(|connection| {
            check_parent(connection, record)?;
            write_grant(connection, record, &encoded)
        })
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
                    "SELECT grant, session_id, issued_at_ms, revoked_at_ms, revoked_by_parent,
             activated_at_ms,
                            activated_at_ms
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
                "SELECT grant, session_id, issued_at_ms, revoked_at_ms, revoked_by_parent,
             activated_at_ms,
                            activated_at_ms
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
                "SELECT grant, session_id, issued_at_ms, revoked_at_ms, revoked_by_parent,
             activated_at_ms,
                            activated_at_ms
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
        // The subtree is read and updated inside one transaction. A child written between the read
        // and the update would otherwise escape the cascade entirely, and a crash part way through
        // the loop would leave a subtree half revoked.
        self.in_transaction(|connection| Self::revoke_within(connection, grant_id, now_ms))
    }

    /// Revokes every grant one device holds, and their descendants.
    ///
    /// One transaction for the whole set, for the same reason one revocation is: a grant issued to
    /// that device between two of these would survive its own device's revocation.
    ///
    /// # Errors
    ///
    /// Returns an error when the rows cannot be read or written.
    pub fn revoke_device(&self, device_id: DeviceId, now_ms: u64) -> Result<GrantRevocation> {
        self.in_transaction(|connection| {
            let held = read_for_device(connection, device_id)?;
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
                let one = Self::revoke_within(connection, record.grant.grant_id, now_ms)?;
                merged.revoked.extend(one.revoked);
                merged.devices.extend(one.devices);
                merged.sessions.extend(one.sessions);
                merged.covers_every_session |= one.covers_every_session;
            }
            Ok(merged)
        })
    }

    /// One revocation, inside a transaction the caller is already holding.
    ///
    /// [`GrantRevocation::revoked`] names only what **this** call revoked. A repeat finds the
    /// subtree already revoked and names nothing, which is what lets a caller tell a revocation
    /// that did something from one that found the work done: advancing the authority revision for
    /// a repeat would make a retry look like a new withdrawal of authority.
    fn revoke_within(
        connection: &Connection,
        grant_id: GrantId,
        now_ms: u64,
    ) -> Result<GrantRevocation> {
        let subtree = subtree_within(connection, grant_id)?;
        if subtree.is_empty() {
            return Err(ControllerError::InvalidArgument(
                "this host holds no such grant".to_owned(),
            ));
        }
        let mut revoked = Vec::new();
        let mut devices = BTreeSet::new();
        let mut sessions = BTreeSet::new();
        let mut covers_every_session = false;
        let moment = i64::try_from(now_ms).unwrap_or(i64::MAX);
        for record in &subtree {
            let is_the_named_one = record.grant.grant_id == grant_id;
            let changed = connection
                .execute(
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
                )
                .map_err(ControllerError::registry)?;
            if changed == 0 {
                // Already revoked, on its own or under an earlier ancestor. Its first revocation's
                // moment and ancestor stand, and this call did not withdraw anything.
                continue;
            }
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
            if record.is_active() {
                // Debt only for authority that was live. Withdrawing a proposal nobody redeemed
                // takes nothing away from anybody, so there is nothing to fence, and recording it
                // would make an ordinary cancellation fence the host later.
                connection
                    .execute(
                        "INSERT OR IGNORE INTO fence_debt (grant_id, recorded_at_ms)
                         VALUES (?1, ?2)",
                        params![record.grant.grant_id.get().as_bytes().as_slice(), moment],
                    )
                    .map_err(ControllerError::registry)?;
            }
            revoked.push(record.grant.grant_id);
        }
        Ok(GrantRevocation {
            grant_id,
            revoked,
            devices,
            sessions,
            covers_every_session,
        })
    }

    /// Writes a proposal and the invitation that carries it, in one transaction.
    ///
    /// One commit, because an invitation and the grant it carries are one thing. Two commits would
    /// leave either a grant nobody previewed or an invitation nobody can redeem, and neither is a
    /// state this host should be able to reach.
    ///
    /// The grant is written **unactivated**: it authorises nothing until [`Self::redeem`] runs.
    ///
    /// # Errors
    ///
    /// As [`Self::issue`], plus [`ControllerError::InvalidArgument`] when the preview promises
    /// historical attachment keys, is not single use, has already expired, or names an identity
    /// already in use.
    pub fn issue_shared(
        &self,
        record: &GrantRecord,
        preview: &InvitationPreview,
        issuer_device_id: DeviceId,
        now_ms: u64,
    ) -> Result<()> {
        if preview.historical_attachment_keys {
            return Err(ControllerError::InvalidArgument(
                "a new recipient does not receive historical attachment keys".to_owned(),
            ));
        }
        if !preview.single_use {
            return Err(ControllerError::InvalidArgument(
                "a session invitation is redeemed once".to_owned(),
            ));
        }
        if preview.expires_at_ms.get() <= now_ms {
            return Err(ControllerError::InvalidArgument(
                "a session invitation expires in the future".to_owned(),
            ));
        }
        if record.activated_at_ms.is_some() {
            return Err(ControllerError::InvalidArgument(
                "a grant an invitation carries is not active until that invitation is redeemed"
                    .to_owned(),
            ));
        }
        let encoded_grant = kr_cbor::to_canonical_vec(&record.grant)
            .map_err(|error| ControllerError::InvalidArgument(error.to_string()))?;
        let encoded_preview = kr_cbor::to_canonical_vec(preview)
            .map_err(|error| ControllerError::InvalidArgument(error.to_string()))?;
        let recipient = record.grant.recipient_device_id;
        self.in_transaction(|connection| {
            check_parent(connection, record)?;
            write_grant(connection, record, &encoded_grant)?;
            let written = connection
                .execute(
                    "INSERT OR IGNORE INTO session_invitations (
                         invitation_id, issuer_device_id, grant_id, recipient_device_id, preview,
                         state, redeemed_by, issued_at_ms, expires_at_ms
                     ) VALUES (?1, ?2, ?3, ?4, ?5, 'open', NULL, ?6, ?7)",
                    params![
                        preview.invitation_id.get().as_bytes().as_slice(),
                        issuer_device_id.get().as_bytes().as_slice(),
                        record.grant.grant_id.get().as_bytes().as_slice(),
                        recipient.get().as_bytes().as_slice(),
                        encoded_preview,
                        i64::try_from(now_ms).unwrap_or(i64::MAX),
                        i64::try_from(preview.expires_at_ms.get()).unwrap_or(i64::MAX),
                    ],
                )
                .map_err(ControllerError::registry)?;
            if written == 0 {
                return Err(ControllerError::InvalidArgument(
                    "that invitation identity is already in use".to_owned(),
                ));
            }
            Ok(())
        })
    }

    /// Returns one invitation's record.
    ///
    /// # Errors
    ///
    /// Returns an error when the row cannot be read.
    pub fn invitation(&self, invitation_id: InvitationId) -> Result<Option<InvitationRecord>> {
        let key = invitation_id.get().as_bytes().to_vec();
        let row: Option<Result<InvitationRecord>> = self.with(|connection| {
            connection
                .query_row(
                    "SELECT preview, issuer_device_id, state, redeemed_by, issued_at_ms,
                            grant_id, recipient_device_id
                     FROM session_invitations WHERE invitation_id = ?1",
                    params![key],
                    |row| Ok(read_invitation(row)),
                )
                .optional()
        })?;
        row.transpose()
    }

    /// Redeems an invitation and activates the grant it carries, once, in one transaction.
    ///
    /// The two changes are one commit, so a crash cannot consume an invitation without activating
    /// its grant. The precondition travels in the `WHERE` clauses, so two devices racing the same
    /// invitation produce one activation and one refusal.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::InvalidArgument`] when this host holds no such invitation, and
    /// [`ControllerError::PermissionDenied`] when it names another device, was withdrawn, has
    /// expired, has already been redeemed, or carries a grant that is revoked or expired.
    pub fn redeem(
        &self,
        invitation_id: InvitationId,
        device_id: DeviceId,
        now_ms: u64,
    ) -> Result<Grant> {
        // The refusal travels out of the transaction as a *value*, so the transaction commits and
        // the refusal is raised afterwards. An error would roll the transaction back, and one of
        // the things it writes is that the invitation expired: rolling that back would let a
        // later call with an earlier clock reading redeem an invitation this host has already
        // refused as expired.
        self.in_transaction(|connection| {
            let Some(invitation) = read_invitation_within(connection, invitation_id)? else {
                return Ok(Err(ControllerError::InvalidArgument(
                    "this host holds no such invitation".to_owned(),
                )));
            };
            if invitation.recipient_device_id != device_id {
                return Ok(Err(refusal("that invitation was issued to another device")));
            }
            match invitation.state_at(now_ms) {
                InvitationState::Open => {}
                InvitationState::Redeemed => {
                    return Ok(Err(refusal("this invitation has already been redeemed")));
                }
                InvitationState::Cancelled => {
                    return Ok(Err(refusal("this invitation was withdrawn")));
                }
                InvitationState::Expired => {
                    settle_invitation(connection, invitation_id, InvitationState::Expired)?;
                    return Ok(Err(refusal("this invitation has expired")));
                }
            }
            let record = read_one(connection, invitation.grant_id)?.ok_or_else(|| {
                ControllerError::InvalidArgument("this host holds no such grant".to_owned())
            })?;
            if record.revoked_at_ms.is_some() {
                return Ok(Err(refusal("that invitation's grant has been revoked")));
            }
            if !record.grant.expiry.is_valid_at(now_ms) {
                settle_invitation(connection, invitation_id, InvitationState::Expired)?;
                return Ok(Err(refusal("that invitation has expired")));
            }
            let activated = connection
                .execute(
                    "UPDATE grants SET activated_at_ms = ?2
                      WHERE grant_id = ?1 AND activated_at_ms IS NULL AND revoked_at_ms IS NULL",
                    params![
                        invitation.grant_id.get().as_bytes().as_slice(),
                        i64::try_from(now_ms).unwrap_or(i64::MAX),
                    ],
                )
                .map_err(ControllerError::registry)?;
            let consumed = connection
                .execute(
                    "UPDATE session_invitations SET state = 'redeemed', redeemed_by = ?2
                      WHERE invitation_id = ?1 AND state = 'open'",
                    params![
                        invitation_id.get().as_bytes().as_slice(),
                        device_id.get().as_bytes().as_slice(),
                    ],
                )
                .map_err(ControllerError::registry)?;
            if activated == 0 || consumed == 0 {
                // One of the two changed and the other did not, which is a state neither of them
                // should be able to reach. An outer error rolls the whole thing back rather than
                // committing half of a redemption.
                return Err(ControllerError::InvalidArgument(
                    "this invitation and the grant it carries disagree about their state"
                        .to_owned(),
                ));
            }
            Ok(Ok(record.grant))
        })?
    }

    /// Withdraws an invitation and the proposal it carries, in one transaction.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::InvalidArgument`] when this host holds no such invitation, and
    /// [`ControllerError::PermissionDenied`] when it is no longer open.
    pub fn cancel_invitation(
        &self,
        invitation_id: InvitationId,
        now_ms: u64,
    ) -> Result<GrantRevocation> {
        self.in_transaction(|connection| {
            let Some(invitation) = read_invitation_within(connection, invitation_id)? else {
                return Err(ControllerError::InvalidArgument(
                    "this host holds no such invitation".to_owned(),
                ));
            };
            let changed = connection
                .execute(
                    "UPDATE session_invitations SET state = 'cancelled'
                      WHERE invitation_id = ?1 AND state = 'open'",
                    params![invitation_id.get().as_bytes().as_slice()],
                )
                .map_err(ControllerError::registry)?;
            if changed == 0 {
                return Err(ControllerError::PermissionDenied {
                    detail: "this invitation is no longer open".to_owned(),
                });
            }
            // The proposal goes with it. It was never active, so this leaves nothing to fence.
            Self::revoke_within(connection, invitation.grant_id, now_ms)
        })
    }

    /// Transfers control: issues the replacement authority and revokes the source, in one
    /// transaction.
    ///
    /// One commit, because a transfer that issued without revoking would leave two devices in
    /// control and one that revoked without issuing would leave none. The source is re-read inside
    /// the transaction, so two transfers of the same grant produce one replacement and one
    /// refusal.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::PermissionDenied`] when the source is not this host's to
    /// transfer at the moment the transaction reads it.
    pub fn transfer(
        &self,
        source_grant_id: GrantId,
        replacement: &GrantRecord,
        now_ms: u64,
        check: impl FnOnce(&GrantRecord) -> Result<()>,
    ) -> Result<GrantRevocation> {
        let encoded = kr_cbor::to_canonical_vec(&replacement.grant)
            .map_err(|error| ControllerError::InvalidArgument(error.to_string()))?;
        self.in_transaction(|connection| {
            let source = read_one(connection, source_grant_id)?.ok_or_else(|| {
                ControllerError::PermissionDenied {
                    detail: "this host holds no such grant".to_owned(),
                }
            })?;
            if !source.is_active() {
                return Err(ControllerError::PermissionDenied {
                    detail: "a grant nobody has redeemed carries no control to transfer".to_owned(),
                });
            }
            if source.revoked_at_ms.is_some() || !source.grant.expiry.is_valid_at(now_ms) {
                return Err(ControllerError::PermissionDenied {
                    detail: "that grant is no longer valid, so there is no control to transfer"
                        .to_owned(),
                });
            }
            check(&source)?;
            write_grant(connection, replacement, &encoded)?;
            Self::revoke_within(connection, source_grant_id, now_ms)
        })
    }

    // --- Fence debt -------------------------------------------------------------------------

    /// Records that a revocation needs a fence that has not happened yet.
    ///
    /// A revocation is two halves: the rows change here, and the daemon then advances the
    /// authority revision and fences what was admitted under it. If the second half fails, a retry
    /// would find nothing *newly* revoked and read the work as done. So the first half writes the
    /// debt down, by grant, and only a completed fence clears it. A timestamp would not do: two
    /// revocations in the same millisecond, or one while the host's time floor is holding the
    /// reading constant, are indistinguishable by time and distinguishable by identity.
    ///
    /// A device revocation that touched no grant row still owes a fence, so it records the device's
    /// identity in the same table under its own key.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the rows cannot be written.
    pub fn owe_fence(
        &self,
        keys: impl IntoIterator<Item = GrantId>,
        now_ms: u64,
    ) -> Result<Vec<GrantId>> {
        let keys: Vec<GrantId> = keys.into_iter().collect();
        if keys.is_empty() {
            return Ok(Vec::new());
        }
        self.in_transaction(|connection| {
            let mut written = Vec::new();
            for key in keys {
                let rows = connection
                    .execute(
                        "INSERT OR IGNORE INTO fence_debt (grant_id, recorded_at_ms)
                         VALUES (?1, ?2)",
                        params![
                            key.get().as_bytes().as_slice(),
                            i64::try_from(now_ms).unwrap_or(i64::MAX),
                        ],
                    )
                    .map_err(ControllerError::registry)?;
                if rows > 0 {
                    written.push(key);
                }
            }
            // What *this* call wrote. A caller that finds its work already done clears only its
            // own intent: debt that was already there belongs to an attempt that has not been
            // fenced, and erasing it would leave that withdrawal unfenced for ever.
            Ok(written)
        })
    }

    /// Returns the revocations still owed a fence.
    ///
    /// The caller takes this list, fences, and hands the same list back to
    /// [`Self::fence_completed`]. Reading and clearing the whole table instead would let one fence
    /// retire debt a revocation recorded while that fence was waiting on a worker.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the rows cannot be read.
    pub fn fence_owed(&self) -> Result<Vec<GrantId>> {
        let rows: Vec<Option<Vec<u8>>> = self.with(|connection| {
            let mut statement =
                connection.prepare("SELECT grant_id FROM fence_debt ORDER BY grant_id")?;
            let rows = statement
                .query_map([], |row| row.get(0))?
                .collect::<rusqlite::Result<Vec<Option<Vec<u8>>>>>()?;
            Ok(rows)
        })?;
        Ok(rows
            .into_iter()
            .filter_map(|bytes| bytes.as_deref().and_then(uuid_of).map(GrantId::new))
            .collect())
    }

    /// Clears exactly the debt a completed fence covered.
    ///
    /// Called only after the revision advanced and the connections were fenced, and only for the
    /// rows that fence was started for. Clearing the table would retire a revocation that arrived
    /// while this fence was waiting, and that one has had no fence of its own.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the rows cannot be written.
    pub fn fence_completed(&self, covered: &[GrantId]) -> Result<()> {
        if covered.is_empty() {
            return Ok(());
        }
        self.in_transaction(|connection| {
            for key in covered {
                connection
                    .execute(
                        "DELETE FROM fence_debt WHERE grant_id = ?1",
                        params![key.get().as_bytes().as_slice()],
                    )
                    .map_err(ControllerError::registry)?;
            }
            Ok(())
        })
    }

    // --- Retained results -------------------------------------------------------------------

    /// Returns the result this host already recorded for one actor's action, if it has one.
    ///
    /// A read, with no claim. It answers a retry from what happened rather than performing
    /// anything, which is what lets a retry whose freshness window has gone still be told its
    /// outcome.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::IdConflict`] when the identifier was reused with a different
    /// payload, and a storage error when the row cannot be read.
    pub fn answered_action(
        &self,
        actor_id: &ActorId,
        action_id: ActionId,
        payload_digest: &Digest256,
    ) -> Result<Option<Vec<u8>>> {
        let held: Option<(Vec<u8>, Option<Vec<u8>>)> = self.with(|connection| {
            connection
                .query_row(
                    "SELECT payload_digest, result FROM authority_receipts
                      WHERE actor_id = ?1 AND action_id = ?2",
                    params![actor_id.as_str(), action_id.get().as_bytes().as_slice()],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
        })?;
        let Some((digest, result)) = held else {
            return Ok(None);
        };
        if digest.as_slice() != payload_digest.as_bytes() {
            return Err(ControllerError::IdConflict {
                token: action_id.to_string(),
            });
        }
        Ok(result)
    }

    /// Claims one actor's action before its effect, or reports what already happened under it.
    ///
    /// Section 9's de-duplication key is the actor and the action together, and the payload digest
    /// decides whether it is the same action or a reused identifier. The claim is written **first**,
    /// in one statement whose `WHERE` clause carries the whole precondition, because a host that
    /// recorded only afterwards would let two concurrent requests under one identifier both reach
    /// their effects before either noticed the other.
    ///
    /// The claim carries the moment it was made. A retry rebuilds its proposal from that moment
    /// rather than from the clock, so the grant it asks for a second time is the grant it asked for
    /// the first time rather than one with a later deadline.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::IdConflict`] when the identifier was reused with a different
    /// payload, and a storage error when the row cannot be read or written.
    pub fn claim_action(
        &self,
        actor_id: &ActorId,
        action_id: ActionId,
        payload_digest: &Digest256,
        now_ms: u64,
    ) -> Result<ActionClaim> {
        self.in_transaction(|connection| {
            let held: Option<HeldClaim> = connection
                .query_row(
                    "SELECT payload_digest, claimed_at_ms, leased_at_ms, result
                       FROM authority_receipts
                      WHERE actor_id = ?1 AND action_id = ?2",
                    params![actor_id.as_str(), action_id.get().as_bytes().as_slice()],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .optional()
                .map_err(ControllerError::registry)?;
            if let Some((digest, claimed_at_ms, leased_at_ms, result)) = held {
                if digest.as_slice() != payload_digest.as_bytes() {
                    return Err(ControllerError::IdConflict {
                        token: action_id.to_string(),
                    });
                }
                if let Some(result) = result {
                    return Ok(ActionClaim::Answered { result });
                }
                // A claim with no result is somebody inside the effect. It is not a claim for
                // ever: a lease older than the longest lifetime a mutation may be admitted for
                // belongs to an attempt that is no longer being awaited, and this caller takes it
                // over rather than finding the identifier wedged. What the lease does **not**
                // establish is that the earlier holder stopped running; an executor that woke up
                // afterwards could still reach its effect, and the record it would write is
                // refused because a completed receipt is never replaced.
                let claimed = u64::try_from(claimed_at_ms).unwrap_or_default();
                let leased = u64::try_from(leased_at_ms).unwrap_or_default();
                let stale =
                    now_ms >= leased.saturating_add(kr_protocol::limits::MAX_MUTATION_TTL.get());
                if !stale {
                    return Ok(ActionClaim::InFlight);
                }
                // The lease is renewed; the moment the *proposal* was made is not. A takeover that
                // moved it would make each retry ask for a grant with a later deadline than the
                // one before it, which is the opposite of what a retry is for.
                connection
                    .execute(
                        "UPDATE authority_receipts SET leased_at_ms = ?3
                          WHERE actor_id = ?1 AND action_id = ?2 AND result IS NULL",
                        params![
                            actor_id.as_str(),
                            action_id.get().as_bytes().as_slice(),
                            i64::try_from(now_ms).unwrap_or(i64::MAX),
                        ],
                    )
                    .map_err(ControllerError::registry)?;
                return Ok(ActionClaim::Claimed {
                    claimed_at_ms: claimed,
                });
            }
            connection
                .execute(
                    "INSERT INTO authority_receipts
                         (actor_id, action_id, payload_digest, claimed_at_ms, leased_at_ms,
                          result, recorded_at_ms)
                     VALUES (?1, ?2, ?3, ?4, ?4, NULL, NULL)",
                    params![
                        actor_id.as_str(),
                        action_id.get().as_bytes().as_slice(),
                        payload_digest.as_bytes().as_slice(),
                        i64::try_from(now_ms).unwrap_or(i64::MAX),
                    ],
                )
                .map_err(ControllerError::registry)?;
            Ok(ActionClaim::Claimed {
                claimed_at_ms: now_ms,
            })
        })
    }

    /// Records the result of a claimed action, once.
    ///
    /// A completed receipt is immutable: the `WHERE` clause writes only into a row that has no
    /// result yet, so a second answer to one action cannot replace the first one a caller was
    /// given.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the row cannot be written.
    pub fn retain_result(
        &self,
        actor_id: &ActorId,
        action_id: ActionId,
        result: &[u8],
        now_ms: u64,
    ) -> Result<()> {
        self.with(|connection| {
            connection
                .execute(
                    "UPDATE authority_receipts SET result = ?3, recorded_at_ms = ?4
                      WHERE actor_id = ?1 AND action_id = ?2 AND result IS NULL",
                    params![
                        actor_id.as_str(),
                        action_id.get().as_bytes().as_slice(),
                        result,
                        i64::try_from(now_ms).unwrap_or(i64::MAX),
                    ],
                )
                .map(|_| ())
        })
    }

    // --- Durable authority state ------------------------------------------------------------

    /// Reads this host's stored policy, if it has one.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the row cannot be read or does not decode.
    pub fn stored_policy(&self) -> Result<Option<StoredPolicy>> {
        self.stored("policy")
    }

    /// Writes this host's policy.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the row cannot be written.
    pub fn store_policy(&self, policy: &StoredPolicy) -> Result<()> {
        self.store("policy", policy)
    }

    /// Reads this host's stored authority-feed state, if it has one.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the row cannot be read or does not decode.
    pub fn stored_feed(&self) -> Result<Option<StoredFeed>> {
        self.stored("feed")
    }

    /// Writes this host's authority-feed state.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the row cannot be written.
    pub fn store_feed(&self, feed: &StoredFeed) -> Result<()> {
        self.store("feed", feed)
    }

    fn stored<T: serde::de::DeserializeOwned + serde::Serialize>(
        &self,
        key: &str,
    ) -> Result<Option<T>> {
        let held: Option<Vec<u8>> = self.with(|connection| {
            connection
                .query_row(
                    "SELECT value FROM host_authority WHERE key = ?1",
                    params![key],
                    |row| row.get(0),
                )
                .optional()
        })?;
        held.map(|bytes| {
            kr_cbor::from_canonical_slice(&bytes, &kr_cbor::Limits::DEFAULT)
                .map_err(|error| ControllerError::InvalidArgument(error.to_string()))
        })
        .transpose()
    }

    fn store<T: serde::Serialize>(&self, key: &str, value: &T) -> Result<()> {
        let encoded = kr_cbor::to_canonical_vec(value)
            .map_err(|error| ControllerError::InvalidArgument(error.to_string()))?;
        self.with(|connection| {
            connection
                .execute(
                    "INSERT OR REPLACE INTO host_authority (key, value) VALUES (?1, ?2)",
                    params![key, encoded],
                )
                .map(|_| ())
        })
    }
}

type Row = Result<GrantRecord>;

/// Checks a grant's parent inside a transaction the caller is already holding.
///
/// The parent has to exist, be **active**, be live, and be narrowed by the child. Active matters:
/// a proposal nobody has redeemed authorises nothing, so delegating from one would turn authority
/// that does not exist yet into authority that does.
fn check_parent(connection: &Connection, record: &GrantRecord) -> Result<()> {
    let Some(parent_grant_id) = record.grant.parent_grant_id.as_ref().copied() else {
        return Ok(());
    };
    let parent = read_one(connection, parent_grant_id)?.ok_or_else(|| {
        ControllerError::PermissionDenied {
            detail: "this grant names a parent this host does not hold".to_owned(),
        }
    })?;
    if !parent.is_active() {
        return Err(ControllerError::PermissionDenied {
            detail: "the grant this one delegates from has not been redeemed, so it carries \
                     nothing to delegate"
                .to_owned(),
        });
    }
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
    Ok(())
}

/// Writes one grant row inside a transaction the caller is already holding.
fn write_grant(connection: &Connection, record: &GrantRecord, encoded: &[u8]) -> Result<()> {
    let written = connection
        .execute(
            "INSERT OR IGNORE INTO grants (
                 grant_id, parent_grant_id, recipient_device_id, session_id, grant,
                 issued_at_ms, activated_at_ms, revoked_at_ms, revoked_by_parent
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, NULL, NULL)",
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
                record
                    .activated_at_ms
                    .map(|at| i64::try_from(at).unwrap_or(i64::MAX)),
            ],
        )
        .map_err(ControllerError::registry)?;
    if written == 0 {
        return Err(ControllerError::InvalidArgument(
            "that grant identity is already in use".to_owned(),
        ));
    }
    Ok(())
}

/// One invitation's record, on a connection the caller is already holding.
fn read_invitation_within(
    connection: &Connection,
    invitation_id: InvitationId,
) -> Result<Option<InvitationRecord>> {
    let row: Option<Result<InvitationRecord>> = connection
        .query_row(
            "SELECT preview, issuer_device_id, state, redeemed_by, issued_at_ms,
                    grant_id, recipient_device_id
             FROM session_invitations WHERE invitation_id = ?1",
            params![invitation_id.get().as_bytes().as_slice()],
            |row| Ok(read_invitation(row)),
        )
        .optional()
        .map_err(ControllerError::registry)?;
    row.transpose()
}

/// Settles an invitation's state inside a transaction the caller is already holding.
fn settle_invitation(
    connection: &Connection,
    invitation_id: InvitationId,
    state: InvitationState,
) -> Result<()> {
    connection
        .execute(
            "UPDATE session_invitations SET state = ?2 WHERE invitation_id = ?1 AND state = 'open'",
            params![invitation_id.get().as_bytes().as_slice(), state.as_str()],
        )
        .map(|_| ())
        .map_err(ControllerError::registry)
}

/// One claim row, as the store reads it back: the digest, when the proposal was made, when the
/// lease was last renewed, and the result once there is one.
type HeldClaim = (Vec<u8>, i64, i64, Option<Vec<u8>>);

/// A refusal a transaction returns as a value, so its own writes still commit.
fn refusal(detail: &str) -> ControllerError {
    ControllerError::PermissionDenied {
        detail: detail.to_owned(),
    }
}

fn read_invitation(row: &rusqlite::Row<'_>) -> Result<InvitationRecord> {
    let encoded: Vec<u8> = row.get(0).map_err(ControllerError::registry)?;
    let preview: InvitationPreview =
        kr_cbor::from_canonical_slice(&encoded, &kr_cbor::Limits::DEFAULT)
            .map_err(|error| ControllerError::InvalidArgument(error.to_string()))?;
    let issuer: Vec<u8> = row.get(1).map_err(ControllerError::registry)?;
    let state: String = row.get(2).map_err(ControllerError::registry)?;
    let redeemed: Option<Vec<u8>> = row.get(3).map_err(ControllerError::registry)?;
    let issued: i64 = row.get(4).map_err(ControllerError::registry)?;
    let grant: Vec<u8> = row.get(5).map_err(ControllerError::registry)?;
    let recipient: Vec<u8> = row.get(6).map_err(ControllerError::registry)?;
    Ok(InvitationRecord {
        preview,
        issuer_device_id: DeviceId::new(uuid_of(&issuer).ok_or_else(|| {
            ControllerError::InvalidArgument("a stored issuer identity is malformed".to_owned())
        })?),
        state: state_of(&state).ok_or_else(|| {
            ControllerError::InvalidArgument("a stored invitation state is malformed".to_owned())
        })?,
        redeemed_by: redeemed.as_deref().and_then(uuid_of).map(DeviceId::new),
        issued_at_ms: u64::try_from(issued).unwrap_or_default(),
        grant_id: GrantId::new(uuid_of(&grant).ok_or_else(|| {
            ControllerError::InvalidArgument("a stored grant identity is malformed".to_owned())
        })?),
        recipient_device_id: DeviceId::new(uuid_of(&recipient).ok_or_else(|| {
            ControllerError::InvalidArgument("a stored recipient identity is malformed".to_owned())
        })?),
    })
}

/// One grant's record, on a connection the caller is already holding.
fn read_one(connection: &Connection, grant_id: GrantId) -> Result<Option<GrantRecord>> {
    let row: Option<Row> = connection
        .query_row(
            "SELECT grant, session_id, issued_at_ms, revoked_at_ms, revoked_by_parent,
             activated_at_ms,
                            activated_at_ms
             FROM grants WHERE grant_id = ?1",
            params![grant_id.get().as_bytes().as_slice()],
            |row| Ok(read_row(row)),
        )
        .optional()
        .map_err(ControllerError::registry)?;
    row.transpose()
}

/// Every grant, on a connection the caller is already holding.
fn read_all(connection: &Connection) -> Result<Vec<GrantRecord>> {
    let mut statement = connection
        .prepare(
            "SELECT grant, session_id, issued_at_ms, revoked_at_ms, revoked_by_parent,
             activated_at_ms,
                            activated_at_ms
             FROM grants ORDER BY grant_id",
        )
        .map_err(ControllerError::registry)?;
    let rows: Vec<Row> = statement
        .query_map([], |row| Ok(read_row(row)))
        .map_err(ControllerError::registry)?
        .collect::<rusqlite::Result<Vec<Row>>>()
        .map_err(ControllerError::registry)?;
    rows.into_iter().collect()
}

/// Every grant one device holds, on a connection the caller is already holding.
fn read_for_device(connection: &Connection, device_id: DeviceId) -> Result<Vec<GrantRecord>> {
    let mut statement = connection
        .prepare(
            "SELECT grant, session_id, issued_at_ms, revoked_at_ms, revoked_by_parent,
             activated_at_ms,
                            activated_at_ms
             FROM grants WHERE recipient_device_id = ?1 ORDER BY grant_id",
        )
        .map_err(ControllerError::registry)?;
    let rows: Vec<Row> = statement
        .query_map(params![device_id.get().as_bytes().as_slice()], |row| {
            Ok(read_row(row))
        })
        .map_err(ControllerError::registry)?
        .collect::<rusqlite::Result<Vec<Row>>>()
        .map_err(ControllerError::registry)?;
    rows.into_iter().collect()
}

/// The grant and every grant delegated from it, breadth first, inside one transaction.
///
/// The visited set is not defensive clutter. This store is a file, and a row that named itself as
/// its parent would otherwise make every revocation of that subtree run for ever, which is a way to
/// stop revocations working rather than a tidy internal invariant.
fn subtree_within(connection: &Connection, grant_id: GrantId) -> Result<Vec<GrantRecord>> {
    let Some(root) = read_one(connection, grant_id)? else {
        return Ok(Vec::new());
    };
    let mut children: BTreeMap<GrantId, Vec<GrantRecord>> = BTreeMap::new();
    for record in read_all(connection)? {
        if let Some(parent) = record.grant.parent_grant_id.as_ref().copied() {
            children.entry(parent).or_default().push(record);
        }
    }
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

fn read_row(row: &rusqlite::Row<'_>) -> Row {
    let encoded: Vec<u8> = row.get(0).map_err(ControllerError::registry)?;
    let grant: Grant = kr_cbor::from_canonical_slice(&encoded, &kr_cbor::Limits::DEFAULT)
        .map_err(|error| ControllerError::InvalidArgument(error.to_string()))?;
    let session: Option<Vec<u8>> = row.get(1).map_err(ControllerError::registry)?;
    let issued: i64 = row.get(2).map_err(ControllerError::registry)?;
    let revoked: Option<i64> = row.get(3).map_err(ControllerError::registry)?;
    let by_parent: Option<Vec<u8>> = row.get(4).map_err(ControllerError::registry)?;
    let activated: Option<i64> = row.get(5).map_err(ControllerError::registry)?;
    Ok(GrantRecord {
        grant,
        session_id: session.as_deref().and_then(uuid_of).map(SessionId::new),
        issued_at_ms: u64::try_from(issued).unwrap_or_default(),
        activated_at_ms: activated.map(|moment| u64::try_from(moment).unwrap_or_default()),
        revoked_at_ms: revoked.map(|moment| u64::try_from(moment).unwrap_or_default()),
        revoked_by_parent: by_parent.as_deref().and_then(uuid_of).map(GrantId::new),
    })
}

fn uuid_of(bytes: &[u8]) -> Option<kr_protocol::scalars::Uuid> {
    <[u8; 16]>::try_from(bytes)
        .ok()
        .map(kr_protocol::scalars::Uuid::from_bytes)
}
