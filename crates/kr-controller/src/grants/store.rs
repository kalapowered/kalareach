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
use std::sync::Arc;

use rusqlite::{Connection, OptionalExtension, params};

use kr_protocol::error::ErrorCode;
use kr_protocol::grant::{Grant, GrantExpiry};
use kr_protocol::ids::InvitationId;
use kr_protocol::ids::{ActionId, ActorId, DeviceId, GrantId, SessionId};
use kr_protocol::scalars::{Digest256, Nullable, TimestampMs};
use kr_protocol::sharing::{GrantState, GrantSummary, InvitationPreview, InvitationState};

use crate::sharing::invitation::{InvitationRecord, state_of};

use super::durable::{StoredFeed, StoredPolicy};
use super::policy::{Bound, UtcFloor};

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
///
/// The attempt that writes an action's claim is the one attempt that may ever perform it. Section
/// 9 never dispatches an identifier again because its receipt is incomplete, so no later attempt
/// takes a claim over, however old it is: an attempt that is still running is not known to have
/// stopped, and one that did stop may already have reached its effect.
#[derive(Debug)]
pub enum ActionClaim {
    /// This attempt wrote the claim, and holds it for as long as `hold` lives.
    Claimed {
        /// This attempt's hold, which the result is recorded under.
        hold: ClaimHold,
    },
    /// Another attempt wrote it first, and this is what the store holds about the action.
    Recorded(ActionRecord),
}

/// What this host holds about one action whose claim an attempt wrote.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ActionRecord {
    /// The attempt that claimed it is still running in this daemon.
    ///
    /// A second request under the identifier is told so rather than performing the action again:
    /// two `grant.revoke` calls that both ran would advance the revision twice and fence the host
    /// twice for one withdrawal, and two voice starts would be two metered calls.
    InFlight,
    /// The action happened, and this is what it produced.
    Answered {
        /// The encoded result.
        result: Vec<u8>,
    },
    /// The action was refused, and this is the refusal it was given.
    Refused {
        /// The refusal's code.
        code: ErrorCode,
        /// What the refusal said.
        detail: String,
    },
    /// The attempt that claimed it ended without recording what it did: this daemon stopped, or
    /// the attempt's task ended, in between.
    ///
    /// It is never performed again. What it did is whatever this host's own records prove, and
    /// otherwise not known.
    Unfinished,
}

/// One claim's key: the actor, and the action as its sixteen bytes.
type ClaimKey = (String, [u8; 16]);

/// The claims whose attempts are running in this daemon.
///
/// In memory, because it describes this process: a claim written by a daemon that has since
/// stopped belongs to an attempt that stopped with it.
#[derive(Debug, Default)]
struct LiveClaims(std::sync::Mutex<BTreeSet<ClaimKey>>);

impl LiveClaims {
    fn held(&self) -> std::sync::MutexGuard<'_, BTreeSet<ClaimKey>> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// An attempt's hold on the claim it wrote, for as long as the attempt runs.
///
/// The hold is what tells a retry that the attempt is still running rather than ended, and it is
/// released when it is dropped, however the attempt ends: it returned, it failed, its task was
/// dropped part way through, or it panicked. Its result is recorded under it, so only the attempt
/// that claimed an action records what the action did. Record before dropping it: a retry that
/// finds neither a hold nor a result reads the action as unfinished.
#[derive(Debug)]
#[must_use = "a claim is released when its hold is dropped"]
pub struct ClaimHold {
    live: Arc<LiveClaims>,
    key: ClaimKey,
}

impl Drop for ClaimHold {
    fn drop(&mut self) {
        self.live.held().remove(&self.key);
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
    /// The action claims whose attempts are running in this daemon.
    live: Arc<LiveClaims>,
    /// This host's clock floor, once the daemon has bound it ([`Self::bind_host_clock`]).
    host_clock: std::sync::OnceLock<Arc<UtcFloor>>,
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
                     result         BLOB,
                     recorded_at_ms INTEGER,
                     refusal_code   TEXT,
                     refusal_detail TEXT,
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
        migrate_receipts(&connection)?;
        Ok(Self {
            connection: std::sync::Mutex::new(connection),
            live: Arc::new(LiveClaims::default()),
            host_clock: std::sync::OnceLock::new(),
        })
    }

    /// Whether `expiry` has passed, for a caller that read the clock at `admitted_ms`, or the
    /// refusal when that cannot be answered now.
    ///
    /// Decided the way an effect in this store decides it ([`Self::bind_host_clock`]): at the later
    /// of the caller's reading and this host's clock now, under its floor, once the daemon has
    /// bound it. A lapse the floor on disk does not cover yet, and any bound that can pass while
    /// the floor is owed its record, is refused as unrecorded rather than answered.
    ///
    /// # Errors
    ///
    /// Returns a `STORAGE_UNAVAILABLE` refusal when the bound cannot be answered now.
    pub fn bound_passed(&self, expiry: GrantExpiry, admitted_ms: u64) -> Result<bool> {
        let bound = self.bound_at_effect(expiry, admitted_ms);
        if bound.answerable() {
            Ok(bound.passed)
        } else {
            Err(self.unanswerable(&bound))
        }
    }

    /// The refusal of an effect whose time bound `bound` could not be answered.
    ///
    /// A lapse the floor on disk does not cover yet is owed its record from here, so the daemon
    /// writes the floor it stood on before its next decision, and an effect asked for again once
    /// that record is down is refused as expired.
    fn unanswerable(&self, bound: &Bound) -> ControllerError {
        if let Some(floor) = self.host_clock.get()
            && !bound.recorded
        {
            floor.owe(bound.at_ms);
        }
        unrecorded()
    }

    /// Binds this host's clock floor, so a grant's time bound is decided at the moment of the
    /// effect that depends on it.
    ///
    /// Until then a bound is decided at the reading its caller took, which is what a caller that
    /// keeps its own time wants: a test, or a tool reading a copy of the store. The daemon binds
    /// its floor as it starts. From then on a delegation, a redemption and a transfer read this
    /// host's wall clock inside the transaction that writes them, under that floor: a grant that
    /// expires while the effect waits for the store's lock is found expired there, and nothing
    /// that can expire is decided while the floor is owed its record
    /// ([`UtcFloor::bound`]). A second binding is ignored.
    pub fn bind_host_clock(&self, floor: Arc<UtcFloor>) {
        let _ = self.host_clock.set(floor);
    }

    /// What `expiry` comes to at the effect, for a caller that decided it at `admitted_ms`.
    ///
    /// The later of the caller's reading and this host's clock now, under its floor, once the
    /// daemon has bound it; the caller's reading alone until then.
    fn bound_at_effect(&self, expiry: GrantExpiry, admitted_ms: u64) -> Bound {
        match self.host_clock.get() {
            Some(floor) => floor.bound(expiry, admitted_ms.max(kr_ipc::now_ms().get())),
            None => Bound {
                at_ms: admitted_ms,
                passed: !expiry.is_valid_at(admitted_ms),
                recorded: true,
                owed: false,
            },
        }
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
    /// `still_admitted` is as [`Self::revoke`]: run inside the transaction, once this call holds the
    /// store's lock and has checked the parent, immediately before the grant is written. A caller
    /// with nothing to re-check passes `|| Ok(())`.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::InvalidArgument`] when the identity is already in use,
    /// [`ControllerError::PermissionDenied`] when the parent is missing, revoked, expired, or is
    /// not narrowed by the child, and whatever `still_admitted` refuses with.
    pub fn issue(
        &self,
        record: &GrantRecord,
        still_admitted: impl FnOnce() -> Result<()>,
    ) -> Result<()> {
        let encoded = kr_cbor::to_canonical_vec(&record.grant)
            .map_err(|error| ControllerError::InvalidArgument(error.to_string()))?;
        // The parent check and the write are one transaction. Checking first and writing after
        // would prove the parent stood before the write rather than at it, and a revocation that
        // landed in between would leave a live child of a revoked parent. The caller's admission
        // is asked in the same place, for the same reason: the wait for the store's lock and the
        // parent read can each outlast it.
        self.in_transaction(|connection| {
            check_parent(connection, record, |expiry, at| {
                self.bound_passed(expiry, at)
            })?;
            still_admitted()?;
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

    /// Returns what the revocation that withdrew a grant withdrew with it, as the rows record it.
    ///
    /// A revocation writes the grant it names with no ancestor, and each descendant it withdraws
    /// with that grant as the ancestor that took it; a withdrawn row is never written again. So a
    /// grant a revocation named reads back with the descendants withdrawn under it, which is what
    /// that revocation withdrew. A grant that went with an ancestor reads back with nothing,
    /// because a revocation naming it afterwards withdraws nothing. `None` is a grant this host
    /// does not hold or that still stands. A revocation whose record was never written is answered
    /// from this.
    ///
    /// # Errors
    ///
    /// Returns an error when the rows cannot be read.
    pub fn withdrawn_with(&self, grant_id: GrantId) -> Result<Option<Vec<GrantId>>> {
        let connection = self
            .connection
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let subtree = subtree_within(&connection, grant_id)?;
        let Some(named) = subtree.first() else {
            return Ok(None);
        };
        if named.revoked_at_ms.is_none() {
            return Ok(None);
        }
        if named.revoked_by_parent.is_some() {
            return Ok(Some(Vec::new()));
        }
        Ok(Some(
            subtree
                .iter()
                .filter(|record| {
                    record.grant.grant_id == grant_id || record.revoked_by_parent == Some(grant_id)
                })
                .map(|record| record.grant.grant_id)
                .collect(),
        ))
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
    /// `still_admitted` is run inside the transaction, once this call holds the store's lock and
    /// once it has read what it is about to withdraw, immediately before the first write. A
    /// request is admitted with a deadline, and the wait for that lock and the read that follows
    /// it can both outlast it, so a check made before either says only what was true before them.
    /// A caller with nothing to re-check passes `|| Ok(())`.
    ///
    /// # Errors
    ///
    /// Returns an error when the rows cannot be read or written, when `still_admitted` refuses,
    /// and [`ControllerError::InvalidArgument`] when this host holds no such grant.
    pub fn revoke(
        &self,
        grant_id: GrantId,
        now_ms: u64,
        still_admitted: impl FnOnce() -> Result<()>,
    ) -> Result<GrantRevocation> {
        // The subtree is read and updated inside one transaction. A child written between the read
        // and the update would otherwise escape the cascade entirely, and a crash part way through
        // the loop would leave a subtree half revoked.
        self.in_transaction(|connection| {
            // Read first, check second, write third. Reading a subtree walks every grant this host
            // holds, so a check made before it is a check with a read still to come.
            let subtree = Self::subtree_to_revoke(connection, grant_id)?;
            still_admitted()?;
            Self::revoke_subtree(connection, grant_id, &subtree, now_ms)
        })
    }

    /// Revokes every grant one device holds, and their descendants.
    ///
    /// One transaction for the whole set, for the same reason one revocation is: a grant issued to
    /// that device between two of these would survive its own device's revocation.
    ///
    /// `still_admitted` is as [`Self::revoke`]: run inside the transaction, after every subtree
    /// this would withdraw has been read and before the first of them is withdrawn.
    ///
    /// # Errors
    ///
    /// Returns an error when the rows cannot be read or written, or when `still_admitted` refuses.
    pub fn revoke_device(
        &self,
        device_id: DeviceId,
        now_ms: u64,
        still_admitted: impl FnOnce() -> Result<()>,
    ) -> Result<GrantRevocation> {
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
            // Every subtree is read before any of them is written, so the check below is the last
            // thing between this call and the first withdrawal rather than the first of several
            // reads. Revoking a grant changes no parent link, so a subtree read now is the same
            // subtree the writes act on.
            //
            // A grant reached from two of this device's roots is kept once, under the first root
            // that reaches it, which is the root its record would have named anyway: the write
            // below takes each row only while it is still live, so a second root never revoked it
            // twice. Keeping every copy would hold a whole chain of grants once per grant.
            let mut claimed: BTreeSet<GrantId> = BTreeSet::new();
            let mut subtrees = Vec::new();
            for record in held {
                if record.revoked_at_ms.is_some() {
                    continue;
                }
                let grant_id = record.grant.grant_id;
                // Collected into a boxed slice: filtering a vector in place keeps the capacity it
                // was read with, and a chain of grants read once per grant would hold that
                // capacity once per grant even with nothing left in it.
                let subtree: Box<[GrantRecord]> = Self::subtree_to_revoke(connection, grant_id)?
                    .into_iter()
                    .filter(|record| claimed.insert(record.grant.grant_id))
                    .collect();
                subtrees.push((grant_id, subtree));
            }
            still_admitted()?;
            for (grant_id, subtree) in &subtrees {
                let one = Self::revoke_subtree(connection, *grant_id, subtree, now_ms)?;
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
        let subtree = Self::subtree_to_revoke(connection, grant_id)?;
        Self::revoke_subtree(connection, grant_id, &subtree, now_ms)
    }

    /// The grants one revocation would withdraw: the named one and everything below it.
    ///
    /// Separate from the writing half so a caller can do its reading first and check, immediately
    /// before the first write, whatever it has to be sure of at that moment.
    fn subtree_to_revoke(connection: &Connection, grant_id: GrantId) -> Result<Vec<GrantRecord>> {
        let subtree = subtree_within(connection, grant_id)?;
        if subtree.is_empty() {
            return Err(ControllerError::InvalidArgument(
                "this host holds no such grant".to_owned(),
            ));
        }
        Ok(subtree)
    }

    /// Withdraws a subtree [`Self::subtree_to_revoke`] read, inside the caller's transaction.
    fn revoke_subtree(
        connection: &Connection,
        grant_id: GrantId,
        subtree: &[GrantRecord],
        now_ms: u64,
    ) -> Result<GrantRevocation> {
        let mut revoked = Vec::new();
        let mut devices = BTreeSet::new();
        let mut sessions = BTreeSet::new();
        let mut covers_every_session = false;
        let moment = i64::try_from(now_ms).unwrap_or(i64::MAX);
        for record in subtree {
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
    /// `still_admitted` is as [`Self::revoke`]: run inside the transaction, after the parent is
    /// checked and before the grant and its invitation are written.
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
        still_admitted: impl FnOnce() -> Result<()>,
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
            check_parent(connection, record, |expiry, at| {
                self.bound_passed(expiry, at)
            })?;
            still_admitted()?;
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
            // Both deadlines are decided at the moment of the redemption. A lapse found here is
            // written down with the invitation, in this commit, so it needs no clock floor to
            // outlive a restart; anything else that reads the clock waits for the floor's record.
            let invitation_bound = self.bound_at_effect(
                GrantExpiry::At {
                    expires_at_ms: invitation.preview.expires_at_ms,
                },
                now_ms,
            );
            match invitation.state {
                InvitationState::Open if invitation_bound.passed => {
                    settle_invitation(connection, invitation_id, InvitationState::Expired)?;
                    return Ok(Err(refusal("this invitation has expired")));
                }
                InvitationState::Open if invitation_bound.owed => {
                    return Ok(Err(unrecorded()));
                }
                InvitationState::Open => {}
                InvitationState::Redeemed => {
                    return Ok(Err(refusal("this invitation has already been redeemed")));
                }
                InvitationState::Cancelled => {
                    return Ok(Err(refusal("this invitation was withdrawn")));
                }
                InvitationState::Expired => {
                    return Ok(Err(refusal("this invitation has expired")));
                }
            }
            let record = read_one(connection, invitation.grant_id)?.ok_or_else(|| {
                ControllerError::InvalidArgument("this host holds no such grant".to_owned())
            })?;
            if record.revoked_at_ms.is_some() {
                return Ok(Err(refusal("that invitation's grant has been revoked")));
            }
            let grant_bound = self.bound_at_effect(record.grant.expiry, now_ms);
            if grant_bound.passed {
                settle_invitation(connection, invitation_id, InvitationState::Expired)?;
                return Ok(Err(refusal("that invitation has expired")));
            }
            if grant_bound.owed {
                return Ok(Err(unrecorded()));
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
            // Its expiry at the moment of the transfer, not at the moment it was asked for.
            if source.revoked_at_ms.is_some() || self.bound_passed(source.grant.expiry, now_ms)? {
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

    /// Returns what this host holds about one actor's action, if it holds anything.
    ///
    /// A read, with no claim. It answers a retry from what happened rather than performing
    /// anything, which is what lets a retry whose freshness window has gone still be told its
    /// outcome.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::IdConflict`] when the identifier was reused with a different
    /// payload, and a storage error when the row cannot be read.
    pub fn recorded_action(
        &self,
        actor_id: &ActorId,
        action_id: ActionId,
        payload_digest: &Digest256,
    ) -> Result<Option<ActionRecord>> {
        let connection = self
            .connection
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Read and asked about under the store's own lock, which the attempt's result is written
        // under too. The attempt records its result before it releases its hold, so a reader that
        // found no result here and then no hold would otherwise read an action that had just been
        // answered as unfinished.
        let key = claim_key(actor_id, action_id);
        read_claim(&connection, &key, payload_digest, &self.live)
    }

    /// Claims one actor's action before its effect, or reports what this host holds about it.
    ///
    /// Section 9's de-duplication key is the actor and the action together, and the payload digest
    /// decides whether it is the same action or a reused identifier. The claim is written **first**,
    /// in one transaction that reads the key and writes it, because a host that recorded only
    /// afterwards would let two concurrent requests under one identifier both reach their effects
    /// before either noticed the other.
    ///
    /// Only the attempt that writes the claim may perform the action. A later request under the
    /// identifier is answered from the record whatever has happened to the first attempt, and is
    /// never given the claim: see [`ActionClaim`].
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
        let key = claim_key(actor_id, action_id);
        self.in_transaction(|connection| {
            if let Some(record) = read_claim(connection, &key, payload_digest, &self.live)? {
                return Ok(ActionClaim::Recorded(record));
            }
            connection
                .execute(
                    "INSERT INTO authority_receipts
                         (actor_id, action_id, payload_digest, claimed_at_ms, result,
                          recorded_at_ms, refusal_code, refusal_detail)
                     VALUES (?1, ?2, ?3, ?4, NULL, NULL, NULL, NULL)",
                    params![
                        key.0,
                        key.1.as_slice(),
                        payload_digest.as_bytes().as_slice(),
                        i64::try_from(now_ms).unwrap_or(i64::MAX),
                    ],
                )
                .map_err(ControllerError::registry)?;
            // Registered inside the transaction, which holds the store's lock: nothing can read
            // the new row before its hold is there. A commit that then fails drops the hold with
            // the claim it was returned in.
            self.live.held().insert(key.clone());
            Ok(ActionClaim::Claimed {
                hold: ClaimHold {
                    live: Arc::clone(&self.live),
                    key: key.clone(),
                },
            })
        })
    }

    /// Records what the action `hold` claimed produced, once.
    ///
    /// A completed receipt is immutable: the `WHERE` clause writes only into a row that has no
    /// outcome yet, so a second answer to one action cannot replace the first one a caller was
    /// given.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the row cannot be written.
    pub fn retain_result(&self, hold: &ClaimHold, result: &[u8], now_ms: u64) -> Result<()> {
        self.with(|connection| {
            connection
                .execute(
                    "UPDATE authority_receipts SET result = ?3, recorded_at_ms = ?4
                      WHERE actor_id = ?1 AND action_id = ?2
                        AND result IS NULL AND refusal_code IS NULL",
                    params![
                        hold.key.0,
                        hold.key.1.as_slice(),
                        result,
                        i64::try_from(now_ms).unwrap_or(i64::MAX),
                    ],
                )
                .map(|_| ())
        })
    }

    /// Records the refusal the action `hold` claimed was given, once.
    ///
    /// Immutable in the same way as a result, and for the same reason.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the row cannot be written.
    pub fn retain_refusal(
        &self,
        hold: &ClaimHold,
        code: ErrorCode,
        detail: &str,
        now_ms: u64,
    ) -> Result<()> {
        self.with(|connection| {
            connection
                .execute(
                    "UPDATE authority_receipts
                        SET refusal_code = ?3, refusal_detail = ?4, recorded_at_ms = ?5
                      WHERE actor_id = ?1 AND action_id = ?2
                        AND result IS NULL AND refusal_code IS NULL",
                    params![
                        hold.key.0,
                        hold.key.1.as_slice(),
                        code.as_str(),
                        detail,
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
/// that does not exist yet into authority that does. Live is decided at the effect
/// (`bound_at_effect`), not only at the moment the child was proposed: a parent that expired while
/// the delegation waited for this transaction delegates nothing.
fn check_parent(
    connection: &Connection,
    record: &GrantRecord,
    bound_passed: impl FnOnce(GrantExpiry, u64) -> Result<bool>,
) -> Result<()> {
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
    if bound_passed(parent.grant.expiry, record.issued_at_ms)? {
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

/// The key one actor's action is claimed under.
fn claim_key(actor_id: &ActorId, action_id: ActionId) -> ClaimKey {
    (actor_id.as_str().to_owned(), *action_id.get().as_bytes())
}

/// One claim row, as the store reads it back: the digest, the result once there is one, and the
/// refusal's code and words once there is one of those.
type ClaimRow = (Vec<u8>, Option<Vec<u8>>, Option<String>, Option<String>);

/// What the store holds about one claimed action, on a connection the caller holds.
///
/// `live` is asked while the connection is held, which is the lock a result is recorded under, so
/// an attempt that recorded its result and then released its hold is read as answered.
fn read_claim(
    connection: &Connection,
    key: &ClaimKey,
    payload_digest: &Digest256,
    live: &LiveClaims,
) -> Result<Option<ActionRecord>> {
    let held: Option<ClaimRow> = connection
        .query_row(
            "SELECT payload_digest, result, refusal_code, refusal_detail
               FROM authority_receipts
              WHERE actor_id = ?1 AND action_id = ?2",
            params![key.0, key.1.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .map_err(ControllerError::registry)?;
    let Some((digest, result, refusal_code, refusal_detail)) = held else {
        return Ok(None);
    };
    if digest.as_slice() != payload_digest.as_bytes() {
        return Err(ControllerError::IdConflict {
            token: ActionId::new(kr_protocol::scalars::Uuid::from_bytes(key.1)).to_string(),
        });
    }
    if let Some(result) = result {
        return Ok(Some(ActionRecord::Answered { result }));
    }
    if let Some(code) = refusal_code {
        let code = ErrorCode::from_wire(&code).ok_or_else(|| {
            ControllerError::InvalidArgument("a stored refusal's code is malformed".to_owned())
        })?;
        return Ok(Some(ActionRecord::Refused {
            code,
            detail: refusal_detail.unwrap_or_default(),
        }));
    }
    if live.held().contains(key) {
        return Ok(Some(ActionRecord::InFlight));
    }
    Ok(Some(ActionRecord::Unfinished))
}

/// Brings a receipts table an earlier build wrote to the shape this one reads, once.
///
/// Two earlier shapes exist. One carried a lease column, from when a later attempt could take over
/// a claim whose lease had run out; that column goes, and nothing reads it. Both lacked the columns
/// a refusal is kept in, which are added empty. The rows stay as they were: a claim with no result
/// in either shape belongs to an attempt that ended with the daemon that wrote it, which is what a
/// row with no result and no hold reads as.
///
/// One immediate transaction, which reads the shape inside it, so two processes opening one store
/// at once change it once.
fn migrate_receipts(connection: &Connection) -> Result<()> {
    let transaction =
        rusqlite::Transaction::new_unchecked(connection, rusqlite::TransactionBehavior::Immediate)
            .map_err(ControllerError::registry)?;
    let columns: BTreeSet<String> = transaction
        .prepare("SELECT name FROM pragma_table_info('authority_receipts')")
        .and_then(|mut statement| {
            statement
                .query_map([], |row| row.get(0))?
                .collect::<rusqlite::Result<BTreeSet<String>>>()
        })
        .map_err(ControllerError::registry)?;
    if columns.contains("leased_at_ms") {
        transaction
            .execute_batch("ALTER TABLE authority_receipts DROP COLUMN leased_at_ms;")
            .map_err(ControllerError::registry)?;
    }
    if !columns.contains("refusal_code") {
        transaction
            .execute_batch(
                "ALTER TABLE authority_receipts ADD COLUMN refusal_code TEXT;
                 ALTER TABLE authority_receipts ADD COLUMN refusal_detail TEXT;",
            )
            .map_err(ControllerError::registry)?;
    }
    transaction.commit().map_err(ControllerError::registry)
}

/// The refusal of an effect whose time bound this host cannot decide now, because the clock floor
/// it would stand on is owed its record ([`UtcFloor::bound`]). It passes once the floor is written.
fn unrecorded() -> ControllerError {
    ControllerError::Refused {
        code: ErrorCode::StorageUnavailable,
        detail: super::FLOOR_UNRECORDED.to_owned(),
    }
}

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
