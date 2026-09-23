//! The catalogue's records, and the one place they change.
//!
//! One SQLite database beside the repositories owns everything the catalogue must still know after
//! a restart: the enrolments with their roots and budgets, which generation each is on, the
//! installations with what each may do, the administrator's disable policy, and the receipt of
//! every catalogue action the daemon performed. It runs with a write-ahead log and full
//! synchronisation, so a change is on disk before the call that made it returns.
//!
//! Three rules follow from there being one owner.
//!
//! * **Every change reads what it changes inside its own transaction.** A second catalogue on the
//!   same directory, or a second request on this one, changes rows rather than rewriting a copy of
//!   everything it read earlier, so neither can lose the other's work.
//! * **A change to the catalogue's state needs a [`Permit`].** [`Pending::run`] takes one, and a
//!   permit exists only inside the admitting authority's commit, so no state reaches disk without
//!   the admission standing at that moment. The write lock is taken first, by [`Db::begin`], so no
//!   wait for another writer comes between the authority's answer and the change.
//! * **An action's effect and its receipt commit together.** The transaction that changes the
//!   state also records the result the action answered with, so no crash can leave an effect
//!   without its receipt or a receipt without its effect.
//!
//! The large objects are not in here. Verified index documents, payloads and package trees are
//! files named by their digests, written before a row names them and useless until one does.
//!
//! This is also where section 24's durable plugin and catalogue installation state lives
//! (KR-REQ-24.01): every enrolment and installation this host holds is a row here, committed with
//! full durability before anything is acknowledged.

use std::path::{Path, PathBuf};

use kr_plugin_sdk::capability::{CapabilityRequest, PluginCapability};
use kr_plugin_sdk::digest::PayloadDigest;
use kr_plugin_sdk::ids::{PluginId, PluginName, PublisherId};
use kr_plugin_sdk::version::PackageVersion;
use kr_protocol::error::ProtocolError;
use kr_protocol::ids::{EnvironmentId, RepositoryGeneration};
use kr_protocol::receipt::ReceiptState;
use rusqlite::{Connection, OptionalExtension as _, TransactionBehavior, params};

use crate::catalogue::authority::{Failure, Permit};
use crate::catalogue::ceiling::{InstallationGrant, capability_from_str};
use crate::catalogue::error::{CatalogueError, CatalogueResult};
use crate::catalogue::install::{DisablePolicy, Installation};
use crate::catalogue::repository::{
    CapabilityCeiling, Enrolment, EnrolmentKey, RepositoryId, RepositoryKind,
};
use crate::catalogue::trust::{AcceptedTarget, MetadataVersions, TargetRecord};

/// The database file, beside the repositories' directories.
pub const DATABASE_FILE: &str = "catalogue.sqlite3";

/// How long a writer waits for another writer's transaction before it reports the store busy.
const BUSY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Which generation a repository is on, and what that generation is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ActiveGeneration {
    /// The generation number.
    pub generation: u64,
    /// The digest of the index's canonical rendering.
    ///
    /// A generation number names one immutable index. Holding the digest beside the number is what
    /// lets a later sync refuse different bytes under a number this host already accepted.
    pub index_digest: PayloadDigest,
    /// The exact length of the index document held.
    pub index_bytes: u64,
    /// How many entries the index carries.
    pub entries: u64,
    /// The metadata versions this generation was accepted at.
    pub versions: MetadataVersions,
}

/// One enrolment as the catalogue holds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Enrolled {
    /// This host's identity for the enrolment.
    pub key: EnrolmentKey,
    /// What was enrolled.
    pub enrolment: Enrolment,
    /// Which generation it is on, where it has one.
    pub active: Option<ActiveGeneration>,
}

/// The identity of one action's receipt: the verified actor and its action identifier.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ReceiptKey {
    actor: String,
    action: String,
}

impl ReceiptKey {
    /// Names one action of one actor.
    #[must_use]
    pub fn new(actor: impl Into<String>, action: impl Into<String>) -> Self {
        Self {
            actor: actor.into(),
            action: action.into(),
        }
    }

    /// Returns the actor.
    #[must_use]
    pub fn actor(&self) -> &str {
        &self.actor
    }

    /// Returns the action identifier.
    #[must_use]
    pub fn action(&self) -> &str {
        &self.action
    }
}

/// What a caller claims before it performs an action.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceiptClaim {
    /// Whose action, and which.
    pub key: ReceiptKey,
    /// The digest of what was submitted, so a reused identifier is told apart from a retry.
    pub digest: Vec<u8>,
    /// The method the action named.
    pub method: String,
    /// The method version the digest covers.
    pub method_version: u16,
    /// The deadline the action was accepted under, where it has one.
    pub deadline_ms: Option<u64>,
}

/// One action's receipt as the catalogue retains it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceiptRecord {
    /// What was claimed.
    pub claim: ReceiptClaim,
    /// Where the action stands.
    pub state: ReceiptState,
    /// A revision that increases with every change to this receipt.
    pub revision: u64,
    /// The result the action answered with, where it applied.
    pub result: Option<Vec<u8>>,
    /// The refusal, or what made the outcome unknown.
    pub error: Option<ProtocolError>,
    /// When this revision was written.
    pub updated_at_ms: u64,
}

/// What a claim found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Claimed {
    /// Nothing held this action yet; the claim is now durable and the action may be performed.
    Fresh,
    /// This action was claimed before, and this is its receipt.
    Retained(Box<ReceiptRecord>),
}

/// The durability settings the store runs under.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Durability {
    /// The journal mode, which is `wal`.
    pub journal_mode: String,
    /// The synchronisation level, where 2 is full.
    pub synchronous: i64,
}

/// The catalogue's database, and the only thing that holds a connection to it.
#[derive(Debug)]
pub struct Db {
    connection: Connection,
    path: PathBuf,
}

impl Db {
    /// Opens the catalogue's database under `root`, creating it where there is none.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::StorageUnavailable`] when it cannot be opened or its tables
    /// cannot be created.
    pub(crate) fn open(root: &Path) -> CatalogueResult<Self> {
        let path = root.join(DATABASE_FILE);
        let connection = Connection::open(&path).map_err(|source| failed(&path, &source))?;
        let db = Self { connection, path };
        db.connection
            .busy_timeout(BUSY_TIMEOUT)
            .map_err(|source| db.failure(&source))?;
        db.connection
            .pragma_update(None, "journal_mode", "WAL")
            .map_err(|source| db.failure(&source))?;
        db.connection
            .pragma_update(None, "synchronous", "FULL")
            .map_err(|source| db.failure(&source))?;
        db.connection
            .execute_batch(SCHEMA)
            .map_err(|source| db.failure(&source))?;
        Ok(db)
    }

    /// Returns the durability settings this connection runs under.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::StorageUnavailable`] when they cannot be read.
    pub(crate) fn durability(&self) -> CatalogueResult<Durability> {
        let journal_mode: String = self
            .connection
            .pragma_query_value(None, "journal_mode", |row| row.get(0))
            .map_err(|source| self.failure(&source))?;
        let synchronous: i64 = self
            .connection
            .pragma_query_value(None, "synchronous", |row| row.get(0))
            .map_err(|source| self.failure(&source))?;
        Ok(Durability {
            journal_mode,
            synchronous,
        })
    }

    /// Reads several records as one consistent view.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::StorageUnavailable`] when the store cannot be read, and whatever
    /// `read` returns.
    pub(crate) fn read<T>(
        &self,
        read: impl FnOnce(&Records<'_>) -> CatalogueResult<T>,
    ) -> CatalogueResult<T> {
        let transaction = self
            .connection
            .unchecked_transaction()
            .map_err(|source| self.failure(&source))?;
        let value = read(&Records {
            transaction: &transaction,
            path: &self.path,
        })?;
        transaction
            .finish()
            .map_err(|source| self.failure(&source))?;
        Ok(value)
    }

    /// Begins one change to the catalogue's state, taking the database's write lock now.
    ///
    /// The lock is taken before the admitting authority is asked for the last time, so no wait for
    /// another writer can come between that answer and the change: whatever wait there is happens
    /// here, first, and the authority is asked after it, inside [`Pending::run`]'s caller. What the
    /// change then reads is what it changes. Dropping the returned change without running it
    /// changes nothing.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::StorageUnavailable`] when the write lock cannot be taken.
    pub(crate) fn begin(&mut self) -> CatalogueResult<Pending<'_>> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|source| failed(&self.path, &source))?;
        Ok(Pending {
            transaction,
            path: &self.path,
        })
    }

    /// Records what happened to an action, without changing the catalogue's state.
    ///
    /// A claim, a refusal and the recovery of an interrupted action are records about an action,
    /// not the change the action asked for, so they need no permit: a refusal is recorded even
    /// when the refusal is that the admission lapsed.
    ///
    /// # Errors
    ///
    /// Returns what `record` returns, and [`CatalogueError::StorageUnavailable`] when the record
    /// cannot be committed.
    pub(crate) fn receipts<T>(
        &mut self,
        record: impl FnOnce(&ReceiptChanges<'_>) -> CatalogueResult<T>,
    ) -> CatalogueResult<T> {
        let path = self.path.clone();
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|source| failed(&path, &source))?;
        let value = record(&ReceiptChanges(Records {
            transaction: &transaction,
            path: &path,
        }))?;
        transaction
            .commit()
            .map_err(|source| failed(&path, &source))?;
        Ok(value)
    }

    fn failure(&self, source: &rusqlite::Error) -> CatalogueError {
        failed(&self.path, source)
    }
}

/// One change to the catalogue's state, holding the write lock, not yet made.
pub(crate) struct Pending<'a> {
    transaction: rusqlite::Transaction<'a>,
    path: &'a Path,
}

impl Pending<'_> {
    /// Reads records under the write lock this change holds, before any change is made.
    ///
    /// What is read here cannot move before the change commits or is dropped: another writer
    /// waits for the lock. A reclaim reads what it protects this way, so a pin that commits
    /// elsewhere lands wholly before the read or wholly after the removal.
    ///
    /// # Errors
    ///
    /// Returns whatever `read` returns.
    pub(crate) fn read<T>(
        &self,
        read: impl FnOnce(&Records<'_>) -> CatalogueResult<T>,
    ) -> CatalogueResult<T> {
        read(&Records {
            transaction: &self.transaction,
            path: self.path,
        })
    }

    /// Makes the change under the admitting authority's permit and commits it.
    ///
    /// An error from `change` leaves nothing changed. A failure of the commit itself is
    /// [`CatalogueError::PublicationUncertain`]: SQLite may have written the change before it
    /// could confirm it, and a restart may find it applied.
    ///
    /// # Errors
    ///
    /// Returns what `change` returns, and [`CatalogueError::PublicationUncertain`] when the commit
    /// cannot be confirmed.
    pub(crate) fn run<T>(
        self,
        _permit: &Permit,
        change: impl FnOnce(&Changes<'_>) -> CatalogueResult<T>,
    ) -> CatalogueResult<T> {
        let value = change(&Changes(Records {
            transaction: &self.transaction,
            path: self.path,
        }))?;
        let path = self.path;
        self.transaction
            .commit()
            .map_err(|source| CatalogueError::PublicationUncertain {
                detail: format!(
                    "{} did not confirm the change it was given: {source}",
                    path.display()
                ),
            })?;
        Ok(value)
    }
}

/// The tables. There is no earlier shape of them to migrate from.
const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS enrolments (
    enrolment_key      TEXT PRIMARY KEY,
    repository_id      TEXT NOT NULL UNIQUE,
    kind               TEXT NOT NULL,
    metadata_url       TEXT NOT NULL,
    targets_url        TEXT NOT NULL,
    root               BLOB NOT NULL,
    budgets            TEXT NOT NULL,
    ceiling            TEXT NOT NULL,
    pinned_generation  INTEGER,
    active_generation  INTEGER,
    trust_reset        INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS accepted_generations (
    enrolment_key  TEXT NOT NULL REFERENCES enrolments(enrolment_key) ON DELETE CASCADE,
    generation     INTEGER NOT NULL,
    index_digest   TEXT NOT NULL,
    index_bytes    INTEGER NOT NULL,
    entries        INTEGER NOT NULL,
    versions       TEXT NOT NULL,
    PRIMARY KEY (enrolment_key, generation)
);
CREATE TABLE IF NOT EXISTS accepted_targets (
    enrolment_key  TEXT NOT NULL,
    generation     INTEGER NOT NULL,
    target         TEXT NOT NULL,
    digest         TEXT NOT NULL,
    length         INTEGER NOT NULL,
    location       TEXT NOT NULL,
    PRIMARY KEY (enrolment_key, generation, target),
    FOREIGN KEY (enrolment_key, generation)
        REFERENCES accepted_generations(enrolment_key, generation) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS installations (
    environment_id  TEXT NOT NULL,
    plugin_id       TEXT NOT NULL,
    enrolment_key   TEXT NOT NULL,
    repository_id   TEXT NOT NULL,
    publisher_id    TEXT NOT NULL,
    plugin_name     TEXT NOT NULL,
    version         TEXT NOT NULL,
    package_digest  TEXT NOT NULL,
    enabled         INTEGER NOT NULL,
    pinned          INTEGER NOT NULL,
    granted         TEXT NOT NULL,
    requested       TEXT NOT NULL,
    payloads        TEXT NOT NULL,
    ceiling         TEXT NOT NULL,
    PRIMARY KEY (environment_id, plugin_id)
);
CREATE TABLE IF NOT EXISTS settings (
    name   TEXT PRIMARY KEY,
    value  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS receipts (
    actor           TEXT NOT NULL,
    action          TEXT NOT NULL,
    digest          BLOB NOT NULL,
    method          TEXT NOT NULL,
    method_version  INTEGER NOT NULL,
    deadline_ms     INTEGER,
    state           TEXT NOT NULL,
    revision        INTEGER NOT NULL,
    result          BLOB,
    error           TEXT,
    updated_at_ms   INTEGER NOT NULL,
    PRIMARY KEY (actor, action)
);
PRAGMA foreign_keys = ON;
";

/// The records, read inside one transaction.
pub struct Records<'a> {
    transaction: &'a rusqlite::Transaction<'a>,
    path: &'a Path,
}

impl Records<'_> {
    fn failure(&self, source: &rusqlite::Error) -> CatalogueError {
        failed(self.path, source)
    }

    /// Returns every enrolment, in the order of their names.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::StorageUnavailable`] when a record cannot be read.
    pub fn enrolments(&self) -> CatalogueResult<Vec<Enrolled>> {
        let mut statement = self
            .transaction
            .prepare(ENROLMENT_SELECT_ALL)
            .map_err(|source| self.failure(&source))?;
        let rows = statement
            .query_map([], EnrolmentRow::read)
            .map_err(|source| self.failure(&source))?;
        let mut enrolled = Vec::new();
        for row in rows {
            let row = row.map_err(|source| self.failure(&source))?;
            enrolled.push(row.into_enrolled()?);
        }
        Ok(enrolled)
    }

    /// Returns the enrolment of one repository, where it is enrolled.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::StorageUnavailable`] when the record cannot be read.
    pub fn enrolment(&self, id: &RepositoryId) -> CatalogueResult<Option<Enrolled>> {
        self.transaction
            .query_row(
                ENROLMENT_SELECT_BY_NAME,
                params![id.as_str()],
                EnrolmentRow::read,
            )
            .optional()
            .map_err(|source| self.failure(&source))?
            .map(EnrolmentRow::into_enrolled)
            .transpose()
    }

    /// Returns true when a kept root advance changed the timestamp or snapshot keys and no verified
    /// checkpoint has been published since.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::StorageUnavailable`] when the record cannot be read.
    pub fn trust_reset(&self, key: &EnrolmentKey) -> CatalogueResult<bool> {
        self.transaction
            .query_row(
                "SELECT trust_reset FROM enrolments WHERE enrolment_key = ?1",
                params![key.as_str()],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .map_err(|source| self.failure(&source))
            .map(|value| value.is_some_and(|reset| reset != 0))
    }

    /// Returns one target of one accepted generation, as it was accepted.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::StorageUnavailable`] when the record cannot be read.
    pub fn accepted_target(
        &self,
        key: &EnrolmentKey,
        generation: u64,
        name: &str,
    ) -> CatalogueResult<Option<AcceptedTarget>> {
        let row: Option<(String, i64, String)> = self
            .transaction
            .query_row(
                "SELECT digest, length, location FROM accepted_targets
                  WHERE enrolment_key = ?1 AND generation = ?2 AND target = ?3",
                params![key.as_str(), number(generation)?, name],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(|source| self.failure(&source))?;
        row.map(|(digest, length, found_at)| {
            Ok(AcceptedTarget {
                name: name.to_owned(),
                record: TargetRecord {
                    digest: PayloadDigest::parse(&digest).map_err(unreadable)?,
                    length: unsigned(length)?,
                },
                location: location(&found_at)?,
            })
        })
        .transpose()
    }

    /// Returns one enrolment by its key, where it is still enrolled.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::StorageUnavailable`] when the record cannot be read.
    pub fn enrolment_by_key(&self, key: &EnrolmentKey) -> CatalogueResult<Option<Enrolled>> {
        self.transaction
            .query_row(
                ENROLMENT_SELECT_BY_KEY,
                params![key.as_str()],
                EnrolmentRow::read,
            )
            .optional()
            .map_err(|source| self.failure(&source))?
            .map(EnrolmentRow::into_enrolled)
            .transpose()
    }

    /// Returns every installation, in a stable order.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::StorageUnavailable`] when a record cannot be read.
    pub fn installations(&self) -> CatalogueResult<Vec<Installation>> {
        let mut statement = self
            .transaction
            .prepare(INSTALLATION_SELECT_ALL)
            .map_err(|source| self.failure(&source))?;
        let rows = statement
            .query_map([], InstallationRow::read)
            .map_err(|source| self.failure(&source))?;
        let mut installations = Vec::new();
        for row in rows {
            let row = row.map_err(|source| self.failure(&source))?;
            installations.push(row.into_installation()?);
        }
        Ok(installations)
    }

    /// Returns one package's installation in one environment.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::StorageUnavailable`] when the record cannot be read.
    pub fn installation(
        &self,
        environment_id: EnvironmentId,
        plugin_id: &PluginId,
    ) -> CatalogueResult<Option<Installation>> {
        self.transaction
            .query_row(
                INSTALLATION_SELECT_ONE,
                params![environment_id.to_string(), plugin_id.as_str()],
                InstallationRow::read,
            )
            .optional()
            .map_err(|source| self.failure(&source))?
            .map(InstallationRow::into_installation)
            .transpose()
    }

    /// Returns the administrator's disable policy.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::StorageUnavailable`] when the setting cannot be read or is not
    /// one this build knows.
    pub fn disable_policy(&self) -> CatalogueResult<DisablePolicy> {
        let value: Option<String> = self
            .transaction
            .query_row(
                "SELECT value FROM settings WHERE name = 'disable_policy'",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|source| self.failure(&source))?;
        match value.as_deref() {
            None => Ok(DisablePolicy::default()),
            Some(text) => DisablePolicy::parse(text).ok_or_else(|| unreadable(text)),
        }
    }

    /// Returns one action's receipt.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::StorageUnavailable`] when the record cannot be read.
    pub fn receipt(&self, key: &ReceiptKey) -> CatalogueResult<Option<ReceiptRecord>> {
        self.transaction
            .query_row(
                "SELECT actor, action, digest, method, method_version, deadline_ms, state,
                        revision, result, error, updated_at_ms
                   FROM receipts WHERE actor = ?1 AND action = ?2",
                params![key.actor, key.action],
                ReceiptRow::read,
            )
            .optional()
            .map_err(|source| self.failure(&source))?
            .map(ReceiptRow::into_record)
            .transpose()
    }
}

/// The records, inside a transaction that changes the catalogue's state.
pub struct Changes<'a>(Records<'a>);

impl<'a> core::ops::Deref for Changes<'a> {
    type Target = Records<'a>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Changes<'_> {
    fn execute(&self, sql: &str, parameters: impl rusqlite::Params) -> CatalogueResult<usize> {
        self.0
            .transaction
            .execute(sql, parameters)
            .map_err(|source| self.0.failure(&source))
    }

    /// Records a new enrolment.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::InvalidArgument`] when a repository of that name is already
    /// enrolled, and [`CatalogueError::StorageUnavailable`] when it cannot be written.
    pub fn enrol(&self, key: &EnrolmentKey, enrolment: &Enrolment) -> CatalogueResult<()> {
        if self.enrolment(&enrolment.id)?.is_some() {
            return Err(CatalogueError::InvalidArgument {
                detail: format!("{} is already enrolled", enrolment.id),
            });
        }
        self.execute(
            "INSERT INTO enrolments (enrolment_key, repository_id, kind, metadata_url, targets_url,
                                     root, budgets, ceiling, pinned_generation, active_generation)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, NULL)",
            params![
                key.as_str(),
                enrolment.id.as_str(),
                enrolment.kind.as_str(),
                enrolment.metadata_url.as_str(),
                enrolment.targets_url.as_str(),
                enrolment.root,
                json(&enrolment.budgets)?,
                json(&ceiling_names(&enrolment.ceiling))?,
                enrolment
                    .pinned_generation
                    .map(|pin| number(pin.get()))
                    .transpose()?,
            ],
        )?;
        Ok(())
    }

    /// Replaces what one enrolment says, keeping its identity and its generation.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::NotFound`] when the enrolment is gone, and
    /// [`CatalogueError::StorageUnavailable`] when it cannot be written.
    pub fn update_enrolment(
        &self,
        key: &EnrolmentKey,
        enrolment: &Enrolment,
    ) -> CatalogueResult<()> {
        let changed = self.execute(
            "UPDATE enrolments
                SET kind = ?2, metadata_url = ?3, targets_url = ?4, root = ?5, budgets = ?6,
                    ceiling = ?7, pinned_generation = ?8
              WHERE enrolment_key = ?1",
            params![
                key.as_str(),
                enrolment.kind.as_str(),
                enrolment.metadata_url.as_str(),
                enrolment.targets_url.as_str(),
                enrolment.root,
                json(&enrolment.budgets)?,
                json(&ceiling_names(&enrolment.ceiling))?,
                enrolment
                    .pinned_generation
                    .map(|pin| number(pin.get()))
                    .transpose()?,
            ],
        )?;
        if changed == 0 {
            return Err(CatalogueError::NotFound {
                detail: format!("{} is no longer enrolled", enrolment.id),
            });
        }
        Ok(())
    }

    /// Records the root verification arrived at, which is the one the next load starts from.
    ///
    /// An enrolment removed while it synchronised is not recreated: there is then nothing to keep
    /// the root for.
    ///
    /// `reset` records that the new root signs timestamps or snapshots with other keys than the
    /// root it replaces, so the next verification starts without the old floors for those roles.
    /// The record stays until a verified checkpoint is published; a later root that does not
    /// change those keys does not clear it.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::StorageUnavailable`] when it cannot be written.
    pub fn set_root(&self, key: &EnrolmentKey, root: &[u8], reset: bool) -> CatalogueResult<()> {
        self.execute(
            "UPDATE enrolments SET root = ?2, trust_reset = MAX(trust_reset, ?3)
              WHERE enrolment_key = ?1",
            params![key.as_str(), root, i64::from(reset)],
        )?;
        Ok(())
    }

    /// Records that a verified trust checkpoint was published, so no reset is pending any more.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::StorageUnavailable`] when it cannot be written.
    pub fn clear_trust_reset(&self, key: &EnrolmentKey) -> CatalogueResult<()> {
        self.execute(
            "UPDATE enrolments SET trust_reset = 0 WHERE enrolment_key = ?1",
            params![key.as_str()],
        )?;
        Ok(())
    }

    /// Removes one enrolment and the generations it accepted.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::StorageUnavailable`] when it cannot be written.
    pub fn remove_enrolment(&self, key: &EnrolmentKey) -> CatalogueResult<()> {
        self.execute(
            "DELETE FROM accepted_generations WHERE enrolment_key = ?1",
            params![key.as_str()],
        )?;
        self.execute(
            "DELETE FROM enrolments WHERE enrolment_key = ?1",
            params![key.as_str()],
        )?;
        Ok(())
    }

    /// Records a generation as accepted and makes it the one the repository is on.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::StorageUnavailable`] when it cannot be written.
    pub fn activate(
        &self,
        key: &EnrolmentKey,
        active: &ActiveGeneration,
        targets: &[AcceptedTarget],
    ) -> CatalogueResult<()> {
        self.execute(
            "INSERT INTO accepted_generations
                 (enrolment_key, generation, index_digest, index_bytes, entries, versions)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT (enrolment_key, generation) DO NOTHING",
            params![
                key.as_str(),
                number(active.generation)?,
                active.index_digest.to_string(),
                number(active.index_bytes)?,
                number(active.entries)?,
                json(&active.versions)?,
            ],
        )?;
        // What the generation pinned is kept with it, so its exact bytes stay fetchable after the
        // repository publishes something newer. A generation accepted again is the same
        // generation, pinning the same things.
        let mut insert = self
            .transaction
            .prepare_cached(
                "INSERT INTO accepted_targets
                     (enrolment_key, generation, target, digest, length, location)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT (enrolment_key, generation, target) DO NOTHING",
            )
            .map_err(|source| self.failure(&source))?;
        for target in targets {
            insert
                .execute(params![
                    key.as_str(),
                    number(active.generation)?,
                    target.name,
                    target.record.digest.to_string(),
                    number(target.record.length)?,
                    target.location.as_str(),
                ])
                .map_err(|source| self.failure(&source))?;
        }
        self.execute(
            "UPDATE enrolments SET active_generation = ?2 WHERE enrolment_key = ?1",
            params![key.as_str(), number(active.generation)?],
        )?;
        Ok(())
    }

    /// Records an installation, replacing the one of the same package in the same environment.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::StorageUnavailable`] when it cannot be written.
    pub fn install(&self, installation: &Installation) -> CatalogueResult<()> {
        self.execute(
            "INSERT INTO installations
                 (environment_id, plugin_id, enrolment_key, repository_id, publisher_id,
                  plugin_name, version, package_digest, enabled, pinned, granted, requested,
                  payloads, ceiling)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)
             ON CONFLICT (environment_id, plugin_id) DO UPDATE SET
                 enrolment_key = excluded.enrolment_key,
                 repository_id = excluded.repository_id,
                 publisher_id = excluded.publisher_id,
                 plugin_name = excluded.plugin_name,
                 version = excluded.version,
                 package_digest = excluded.package_digest,
                 enabled = excluded.enabled,
                 pinned = excluded.pinned,
                 granted = excluded.granted,
                 requested = excluded.requested,
                 payloads = excluded.payloads,
                 ceiling = excluded.ceiling",
            params![
                installation.environment_id.to_string(),
                installation.plugin_id.as_str(),
                installation.enrolment.as_str(),
                installation.repository.as_str(),
                installation.publisher_id.as_str(),
                installation.plugin_name.as_str(),
                installation.version.to_string(),
                installation.package_digest.to_string(),
                installation.enabled,
                installation.pinned,
                json(&capability_names(installation.grant.capabilities()))?,
                json(&installation.requested)?,
                json(
                    &installation
                        .payloads
                        .iter()
                        .map(PayloadDigest::to_string)
                        .collect::<Vec<_>>()
                )?,
                json(&ceiling_names(&installation.ceiling))?,
            ],
        )?;
        Ok(())
    }

    /// Removes one installation.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::StorageUnavailable`] when it cannot be written.
    pub fn uninstall(
        &self,
        environment_id: EnvironmentId,
        plugin_id: &PluginId,
    ) -> CatalogueResult<()> {
        self.execute(
            "DELETE FROM installations WHERE environment_id = ?1 AND plugin_id = ?2",
            params![environment_id.to_string(), plugin_id.as_str()],
        )?;
        Ok(())
    }

    /// Records the administrator's disable policy.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::StorageUnavailable`] when it cannot be written.
    pub fn set_disable_policy(&self, policy: DisablePolicy) -> CatalogueResult<()> {
        self.execute(
            "INSERT INTO settings (name, value) VALUES ('disable_policy', ?1)
             ON CONFLICT (name) DO UPDATE SET value = excluded.value",
            params![policy.as_str()],
        )?;
        Ok(())
    }

    /// Settles a claimed action as applied, with the result it answered with.
    ///
    /// This runs in the transaction that makes the action's change, which is what makes the
    /// effect and its receipt one commit.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::StorageUnavailable`] when the claim is not there to settle, or it
    /// cannot be written.
    pub fn settle_applied(
        &self,
        key: &ReceiptKey,
        result: &[u8],
        now_ms: u64,
    ) -> CatalogueResult<()> {
        let changed = self.execute(
            "UPDATE receipts
                SET state = ?3, revision = revision + 1, result = ?4, error = NULL,
                    updated_at_ms = ?5
              WHERE actor = ?1 AND action = ?2 AND state = ?6",
            params![
                key.actor,
                key.action,
                ReceiptState::Applied.as_str(),
                result,
                number(now_ms)?,
                ReceiptState::Dispatching.as_str(),
            ],
        )?;
        if changed == 0 {
            return Err(CatalogueError::StorageUnavailable {
                detail: format!(
                    "action {} of {} has no claim waiting to be settled",
                    key.action, key.actor
                ),
            });
        }
        Ok(())
    }
}

/// The records, inside a transaction that only records what happened to an action.
pub struct ReceiptChanges<'a>(Records<'a>);

impl<'a> core::ops::Deref for ReceiptChanges<'a> {
    type Target = Records<'a>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl ReceiptChanges<'_> {
    /// Claims an action before it is performed, or returns the receipt it already has.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::StorageUnavailable`] when the claim cannot be recorded.
    pub fn claim(&self, claim: &ReceiptClaim, now_ms: u64) -> CatalogueResult<Claimed> {
        if let Some(existing) = self.receipt(&claim.key)? {
            return Ok(Claimed::Retained(Box::new(existing)));
        }
        self.0
            .transaction
            .execute(
                "INSERT INTO receipts (actor, action, digest, method, method_version, deadline_ms,
                                       state, revision, result, error, updated_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 1, NULL, NULL, ?8)",
                params![
                    claim.key.actor,
                    claim.key.action,
                    claim.digest,
                    claim.method,
                    i64::from(claim.method_version),
                    claim.deadline_ms.map(number).transpose()?,
                    ReceiptState::Dispatching.as_str(),
                    number(now_ms)?,
                ],
            )
            .map_err(|source| self.0.failure(&source))?;
        Ok(Claimed::Fresh)
    }

    /// Settles a claimed action that stopped, as its [`Failure`] says.
    ///
    /// The state is refused only for an action that committed nothing, and unknown for anything
    /// else; the failure was made from what the action committed, not from what its caller
    /// believes. A receipt that is no longer dispatching is left as it is: an action whose last
    /// commit could not be confirmed may have settled itself as applied in that same commit, and
    /// that is the answer a later reader is owed.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::StorageUnavailable`] when it cannot be written.
    pub fn settle_failure(
        &self,
        key: &ReceiptKey,
        failure: &Failure,
        now_ms: u64,
    ) -> CatalogueResult<()> {
        let state = failure.state();
        let error = failure.answer();
        self.0
            .transaction
            .execute(
                "UPDATE receipts
                    SET state = ?3, revision = revision + 1, result = NULL, error = ?4,
                        updated_at_ms = ?5
                  WHERE actor = ?1 AND action = ?2 AND state = ?6",
                params![
                    key.actor,
                    key.action,
                    state.as_str(),
                    json(error)?,
                    number(now_ms)?,
                    ReceiptState::Dispatching.as_str(),
                ],
            )
            .map_err(|source| self.0.failure(&source))?;
        Ok(())
    }

    /// Settles every action a previous daemon left mid-dispatch as unknown.
    ///
    /// A claim still dispatching when the store is opened belongs to a process that stopped part
    /// way. Its change may have been made, so it is never dispatched again and never reported as
    /// refused; unknown is the only answer this host can stand behind.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::StorageUnavailable`] when it cannot be written.
    pub fn recover_interrupted(&self, now_ms: u64) -> CatalogueResult<usize> {
        let error = ProtocolError::new(
            kr_protocol::error::ErrorCode::OutcomeUnknown,
            "the daemon stopped while this action was being performed; it is not performed again",
        );
        self.0
            .transaction
            .execute(
                "UPDATE receipts
                    SET state = ?1, revision = revision + 1, error = ?2, updated_at_ms = ?3
                  WHERE state = ?4",
                params![
                    ReceiptState::Unknown.as_str(),
                    json(&error)?,
                    number(now_ms)?,
                    ReceiptState::Dispatching.as_str(),
                ],
            )
            .map_err(|source| self.0.failure(&source))
    }
}

/// Selects enrolments with the generation each is on, followed by `$rest`.
macro_rules! select_enrolments {
    ($rest:literal) => {
        concat!(
            "SELECT e.enrolment_key, e.repository_id, e.kind, e.metadata_url, e.targets_url,
                    e.root, e.budgets, e.ceiling, e.pinned_generation, a.generation,
                    a.index_digest, a.index_bytes, a.entries, a.versions
               FROM enrolments e LEFT JOIN accepted_generations a
                 ON a.enrolment_key = e.enrolment_key AND a.generation = e.active_generation ",
            $rest
        )
    };
}

/// Selects installations, followed by `$rest`.
macro_rules! select_installations {
    ($rest:literal) => {
        concat!(
            "SELECT environment_id, plugin_id, enrolment_key, repository_id, publisher_id,
                    plugin_name, version, package_digest, enabled, pinned, granted, requested,
                    payloads, ceiling
               FROM installations ",
            $rest
        )
    };
}

const ENROLMENT_SELECT_ALL: &str = select_enrolments!("ORDER BY e.repository_id");
const ENROLMENT_SELECT_BY_NAME: &str = select_enrolments!("WHERE e.repository_id = ?1");
const ENROLMENT_SELECT_BY_KEY: &str = select_enrolments!("WHERE e.enrolment_key = ?1");
const INSTALLATION_SELECT_ALL: &str = select_installations!("ORDER BY environment_id, plugin_id");
const INSTALLATION_SELECT_ONE: &str =
    select_installations!("WHERE environment_id = ?1 AND plugin_id = ?2");

/// One enrolment row as SQLite returns it.
struct EnrolmentRow {
    key: String,
    repository_id: String,
    kind: String,
    metadata_url: String,
    targets_url: String,
    root: Vec<u8>,
    budgets: String,
    ceiling: String,
    pinned_generation: Option<i64>,
    active_generation: Option<i64>,
    index_digest: Option<String>,
    index_bytes: Option<i64>,
    entries: Option<i64>,
    versions: Option<String>,
}

impl EnrolmentRow {
    fn read(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            key: row.get(0)?,
            repository_id: row.get(1)?,
            kind: row.get(2)?,
            metadata_url: row.get(3)?,
            targets_url: row.get(4)?,
            root: row.get(5)?,
            budgets: row.get(6)?,
            ceiling: row.get(7)?,
            pinned_generation: row.get(8)?,
            active_generation: row.get(9)?,
            index_digest: row.get(10)?,
            index_bytes: row.get(11)?,
            entries: row.get(12)?,
            versions: row.get(13)?,
        })
    }

    fn into_enrolled(self) -> CatalogueResult<Enrolled> {
        let kind = match self.kind.as_str() {
            "official" => RepositoryKind::Official,
            "vendor" => RepositoryKind::Vendor,
            "community" => RepositoryKind::Community,
            "local" => RepositoryKind::Local,
            "mirror" => RepositoryKind::Mirror,
            other => return Err(unreadable(other)),
        };
        // Built from its fields rather than through `Enrolment::new`: what enrolment checks, the
        // location and the root's size against the budgets, was checked when this row was
        // written, and a budget the owner has since narrowed below the root is for the next sync
        // to refuse, not a record this host cannot read.
        let enrolment = Enrolment {
            id: RepositoryId::new(self.repository_id).map_err(unreadable)?,
            kind,
            metadata_url: location(&self.metadata_url)?,
            targets_url: location(&self.targets_url)?,
            root: self.root,
            budgets: from_json(&self.budgets)?,
            ceiling: CapabilityCeiling::with(capabilities_from(&self.ceiling)?),
            pinned_generation: self
                .pinned_generation
                .map(|pin| unsigned(pin).map(RepositoryGeneration::new))
                .transpose()?,
        };
        let active = match (
            self.active_generation,
            self.index_digest,
            self.index_bytes,
            self.entries,
            self.versions,
        ) {
            (Some(generation), Some(digest), Some(bytes), Some(entries), Some(versions)) => {
                Some(ActiveGeneration {
                    generation: unsigned(generation)?,
                    index_digest: PayloadDigest::parse(&digest).map_err(unreadable)?,
                    index_bytes: unsigned(bytes)?,
                    entries: unsigned(entries)?,
                    versions: from_json(&versions)?,
                })
            }
            (None, ..) => None,
            _ => {
                return Err(unreadable(
                    "an enrolment names an active generation it has no record of",
                ));
            }
        };
        Ok(Enrolled {
            key: EnrolmentKey::parse(&self.key)?,
            enrolment,
            active,
        })
    }
}

/// One installation row as SQLite returns it.
struct InstallationRow {
    environment_id: String,
    plugin_id: String,
    enrolment_key: String,
    repository_id: String,
    publisher_id: String,
    plugin_name: String,
    version: String,
    package_digest: String,
    enabled: bool,
    pinned: bool,
    granted: String,
    requested: String,
    payloads: String,
    ceiling: String,
}

impl InstallationRow {
    fn read(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            environment_id: row.get(0)?,
            plugin_id: row.get(1)?,
            enrolment_key: row.get(2)?,
            repository_id: row.get(3)?,
            publisher_id: row.get(4)?,
            plugin_name: row.get(5)?,
            version: row.get(6)?,
            package_digest: row.get(7)?,
            enabled: row.get(8)?,
            pinned: row.get(9)?,
            granted: row.get(10)?,
            requested: row.get(11)?,
            payloads: row.get(12)?,
            ceiling: row.get(13)?,
        })
    }

    fn into_installation(self) -> CatalogueResult<Installation> {
        let payload_names: Vec<String> = from_json(&self.payloads)?;
        let mut payloads = Vec::with_capacity(payload_names.len());
        for name in payload_names {
            payloads.push(PayloadDigest::parse(&name).map_err(unreadable)?);
        }
        let requested: Vec<CapabilityRequest> = from_json(&self.requested)?;
        Ok(Installation {
            plugin_id: PluginId::new(self.plugin_id).map_err(unreadable)?,
            publisher_id: PublisherId::new(self.publisher_id).map_err(unreadable)?,
            plugin_name: PluginName::new(self.plugin_name).map_err(unreadable)?,
            version: PackageVersion::parse(&self.version).map_err(unreadable)?,
            package_digest: PayloadDigest::parse(&self.package_digest).map_err(unreadable)?,
            enrolment: EnrolmentKey::parse(&self.enrolment_key)?,
            repository: RepositoryId::new(self.repository_id).map_err(unreadable)?,
            environment_id: environment(&self.environment_id)?,
            enabled: self.enabled,
            pinned: self.pinned,
            grant: InstallationGrant::with(capabilities_from(&self.granted)?),
            requested,
            payloads,
            ceiling: CapabilityCeiling::with(capabilities_from(&self.ceiling)?),
        })
    }
}

/// One receipt row as SQLite returns it.
struct ReceiptRow {
    actor: String,
    action: String,
    digest: Vec<u8>,
    method: String,
    method_version: i64,
    deadline_ms: Option<i64>,
    state: String,
    revision: i64,
    result: Option<Vec<u8>>,
    error: Option<String>,
    updated_at_ms: i64,
}

impl ReceiptRow {
    fn read(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            actor: row.get(0)?,
            action: row.get(1)?,
            digest: row.get(2)?,
            method: row.get(3)?,
            method_version: row.get(4)?,
            deadline_ms: row.get(5)?,
            state: row.get(6)?,
            revision: row.get(7)?,
            result: row.get(8)?,
            error: row.get(9)?,
            updated_at_ms: row.get(10)?,
        })
    }

    fn into_record(self) -> CatalogueResult<ReceiptRecord> {
        let state = ReceiptState::ALL
            .iter()
            .copied()
            .find(|state| state.as_str() == self.state)
            .ok_or_else(|| unreadable(&self.state))?;
        Ok(ReceiptRecord {
            claim: ReceiptClaim {
                key: ReceiptKey::new(self.actor, self.action),
                digest: self.digest,
                method: self.method,
                method_version: u16::try_from(self.method_version)
                    .map_err(|_| unreadable(self.method_version))?,
                deadline_ms: self.deadline_ms.map(unsigned).transpose()?,
            },
            state,
            revision: unsigned(self.revision)?,
            result: self.result,
            error: self.error.as_deref().map(from_json).transpose()?,
            updated_at_ms: unsigned(self.updated_at_ms)?,
        })
    }
}

fn failed(path: &Path, source: &rusqlite::Error) -> CatalogueError {
    CatalogueError::StorageUnavailable {
        detail: format!("{}: {source}", path.display()),
    }
}

fn unreadable(detail: impl core::fmt::Display) -> CatalogueError {
    CatalogueError::StorageUnavailable {
        detail: format!("the catalogue holds a record this build cannot read: {detail}"),
    }
}

fn json<T: serde::Serialize + ?Sized>(value: &T) -> CatalogueResult<String> {
    serde_json::to_string(value).map_err(|source| CatalogueError::StorageUnavailable {
        detail: format!("a catalogue record could not be written: {source}"),
    })
}

fn from_json<T: serde::de::DeserializeOwned>(text: &str) -> CatalogueResult<T> {
    serde_json::from_str(text).map_err(unreadable)
}

fn number(value: u64) -> CatalogueResult<i64> {
    i64::try_from(value).map_err(|_| CatalogueError::InvalidArgument {
        detail: format!("{value} is past what the catalogue records"),
    })
}

fn unsigned(value: i64) -> CatalogueResult<u64> {
    u64::try_from(value).map_err(|_| unreadable(value))
}

fn location(text: &str) -> CatalogueResult<url::Url> {
    url::Url::parse(text).map_err(unreadable)
}

fn environment(text: &str) -> CatalogueResult<EnvironmentId> {
    let uuid: kr_protocol::scalars::Uuid =
        serde_json::from_value(serde_json::Value::String(text.to_owned())).map_err(unreadable)?;
    Ok(EnvironmentId::new(uuid))
}

fn ceiling_names(ceiling: &CapabilityCeiling) -> Vec<&'static str> {
    capability_names(ceiling.capabilities())
}

fn capability_names(capabilities: Vec<PluginCapability>) -> Vec<&'static str> {
    capabilities
        .into_iter()
        .map(PluginCapability::as_str)
        .collect()
}

fn capabilities_from(text: &str) -> CatalogueResult<Vec<PluginCapability>> {
    let names: Vec<String> = from_json(text)?;
    names
        .iter()
        .map(|name| capability_from_str(name).map_err(unreadable))
        .collect()
}
