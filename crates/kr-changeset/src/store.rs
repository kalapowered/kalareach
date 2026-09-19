//! `changesets.sqlite`: the versions, their manifests, the materialisations, the results, the
//! evidence and the applies.
//!
//! Three rules shape it.
//!
//! * **A version is written once.** There is no statement in this module that updates a version
//!   row, and the manifest is stored beside it as canonical bytes. New edits produce a new version
//!   rather than changing the subject of an earlier test or review.
//! * **An apply's progress is written before the write it describes, and replaced after it.** A
//!   path is `planned` before anything is attempted and its outcome replaces that row once this
//!   host has established one. A daemon that dies between the two leaves `planned`, which says
//!   this host did not establish what became of that path — not that nothing happened to it.
//! * **An outcome class is recorded only when it is true.** An apply is `applied` once every path
//!   it planned has been confirmed. A crash before that leaves the apply open, and recovery
//!   settles it as an interrupted apply with exactly the paths whose state is known.

use std::path::Path;

use kr_protocol::changeset::{
    ApplyOutcomeClass, DestinationClass, EvidenceKind, MaterialisationPurpose, PathProgressState,
    SourceConsistency, TestedSource,
};
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::{
    ActionId, ActorId, ChangeSetId, ChangeSetVersion, EnvironmentId, MaterialisationId,
    ProjectRepositoryId, WorkspaceId,
};
use kr_protocol::scalars::{Digest256, TimestampMs, Uuid};
use rusqlite::{Connection, OptionalExtension as _, Transaction, params};

use crate::error::{ChangeSetError, Result};

/// The schema version this build reads.
pub const SCHEMA_VERSION: i64 = 1;

/// The directory, under the environment's state directory, that this service owns.
pub const CHANGESETS_DIRECTORY: &str = "changesets";

/// The store's filename inside that directory.
pub const STORE_FILE_NAME: &str = "changesets.sqlite";

/// One change set: the series a version belongs to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChangeSetRow {
    /// Its identity.
    pub change_set_id: ChangeSetId,
    /// The environment that owns it.
    pub environment_id: EnvironmentId,
    /// The repository every version of it was captured from.
    pub project_repository_id: ProjectRepositoryId,
    /// The workspace every version of it was captured from.
    pub workspace_id: WorkspaceId,
    /// The label the caller gave it.
    pub label: String,
    /// When it was started.
    pub created_at_ms: TimestampMs,
}

/// One immutable version, as the store holds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VersionRow {
    /// The change set it belongs to.
    pub change_set_id: ChangeSetId,
    /// Which version it is.
    pub version: ChangeSetVersion,
    /// The digest that identifies it exactly.
    pub content_digest: Digest256,
    /// How consistent its source was.
    pub consistency: SourceConsistency,
    /// The revision it is against.
    pub base_revision: String,
    /// The version it is derived from, when it is derived.
    pub derived_from: Option<ChangeSetVersion>,
    /// The record a caller receives, as canonical bytes.
    pub record: Vec<u8>,
    /// The whole manifest, as canonical bytes.
    pub manifest: Vec<u8>,
    /// When it was captured.
    pub captured_at_ms: TimestampMs,
}

/// One materialisation, as the store holds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MaterialisationRow {
    /// Its identity.
    pub materialisation_id: MaterialisationId,
    /// The change set it holds a version of.
    pub change_set_id: ChangeSetId,
    /// Which version.
    pub version: ChangeSetVersion,
    /// What it is for.
    pub purpose: MaterialisationPurpose,
    /// The record a caller receives, as canonical bytes.
    pub record: Vec<u8>,
    /// The single-component directory name it lives under.
    pub directory_name: String,
    /// Its directory's stable filesystem identity.
    pub identity: kr_transfer::ObjectIdentity,
    /// When it was made.
    pub created_at_ms: TimestampMs,
    /// When it was released, once it has been.
    pub released_at_ms: Option<TimestampMs>,
}

/// One result recorded against a materialisation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResultRow {
    /// The materialisation it ran against.
    pub materialisation_id: MaterialisationId,
    /// The change set whose version was materialised.
    pub input_change_set_id: ChangeSetId,
    /// The version that was materialised.
    pub input_version: ChangeSetVersion,
    /// What was actually tested.
    pub tested_source: TestedSource,
    /// The version it attests, when it attests one.
    pub tested_version: Option<(ChangeSetId, ChangeSetVersion)>,
    /// The record a caller receives, as canonical bytes.
    pub record: Vec<u8>,
    /// When it was recorded.
    pub recorded_at_ms: TimestampMs,
}

/// One thing that names a version and has to be accounted for before it is deleted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvidenceRow {
    /// The change set.
    pub change_set_id: ChangeSetId,
    /// The version.
    pub version: ChangeSetVersion,
    /// What kind of evidence it is.
    pub kind: EvidenceKind,
    /// What it is, in this host's own words.
    pub detail: String,
    /// When it was recorded.
    pub recorded_at_ms: TimestampMs,
}

/// One apply, as the store holds it while it runs and after it has been decided.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApplyRow {
    /// The action it is performed under.
    pub action_id: ActionId,
    /// The change set whose content it carries.
    pub change_set_id: ChangeSetId,
    /// Which version.
    pub version: ChangeSetVersion,
    /// The workspace it writes to, when it writes to one.
    pub workspace_id: Option<WorkspaceId>,
    /// Where it writes.
    pub destination: DestinationClass,
    /// Which of the five classes it came to, once this host has established one.
    pub outcome: Option<ApplyOutcomeClass>,
    /// The immutable version of the destination before it ran.
    pub before_version: Option<(ChangeSetId, ChangeSetVersion)>,
    /// The immutable version of the destination after it ran.
    pub after_version: Option<(ChangeSetId, ChangeSetVersion)>,
    /// The staging directory the validated content went through.
    pub staged_name: Option<String>,
    /// Why it came to what it came to.
    pub detail: String,
    /// When it started.
    pub started_at_ms: TimestampMs,
    /// When it was decided, once it has been.
    pub decided_at_ms: Option<TimestampMs>,
}

/// One path's progress inside one apply.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProgressRow {
    /// The path.
    pub path: String,
    /// What became of it.
    pub state: PathProgressState,
    /// The digest of what was there before, when this host read it.
    pub before_digest: Option<Digest256>,
    /// The digest of what is there now, when this host read it.
    pub after_digest: Option<Digest256>,
    /// What this host can say about it.
    pub detail: String,
}

/// What one action's row holds: its method, its payload digest, and its outcome.
type StoredAction = (String, Vec<u8>, Option<Vec<u8>>, Option<String>, Option<String>);

/// One action's retained outcome.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RetainedOutcome {
    /// The canonical encoding of the typed result the first attempt returned.
    Ok(Vec<u8>),
    /// The refusal it returned, under the code it decided.
    Error {
        /// The code.
        code: ErrorCode,
        /// The protected sentence.
        detail: String,
    },
}

/// The change-set journal of one environment.
#[derive(Debug)]
pub struct Store {
    connection: Connection,
    environment_id: EnvironmentId,
}

impl Store {
    /// Opens the store at a path, creating and migrating it.
    ///
    /// # Errors
    ///
    /// Returns [`ChangeSetError::StoreUnavailable`] when it cannot be opened or migrated.
    pub fn open(path: impl AsRef<Path>, environment_id: EnvironmentId) -> Result<Self> {
        let connection = Connection::open(path.as_ref()).map_err(ChangeSetError::store)?;
        Self::prepare(connection, environment_id)
    }

    /// Opens a store that exists only for the life of this process.
    ///
    /// # Errors
    ///
    /// Returns [`ChangeSetError::StoreUnavailable`] when it cannot be created.
    pub fn in_memory(environment_id: EnvironmentId) -> Result<Self> {
        Self::prepare(
            Connection::open_in_memory().map_err(ChangeSetError::store)?,
            environment_id,
        )
    }

    fn prepare(connection: Connection, environment_id: EnvironmentId) -> Result<Self> {
        connection
            .pragma_update(None, "journal_mode", "WAL")
            .map_err(ChangeSetError::store)?;
        connection
            .pragma_update(None, "synchronous", "FULL")
            .map_err(ChangeSetError::store)?;
        connection
            .pragma_update(None, "foreign_keys", "ON")
            .map_err(ChangeSetError::store)?;
        let mut store = Self {
            connection,
            environment_id,
        };
        store.migrate()?;
        Ok(store)
    }

    /// Returns the environment this store belongs to.
    #[must_use]
    pub const fn environment_id(&self) -> EnvironmentId {
        self.environment_id
    }

    fn migrate(&mut self) -> Result<()> {
        // One transaction for the whole upgrade. A store is never left saying it is at a version
        // whose shape it does not have, and a store this build refuses is left as it was found.
        let transaction = self
            .connection
            .transaction()
            .map_err(ChangeSetError::store)?;
        transaction
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL);
                 CREATE TABLE IF NOT EXISTS change_sets (
                     change_set_id         BLOB PRIMARY KEY,
                     environment_id        BLOB NOT NULL,
                     project_repository_id BLOB NOT NULL,
                     workspace_id          BLOB NOT NULL,
                     label                 TEXT NOT NULL,
                     -- The next version number this change set hands out. It only ever goes up,
                     -- so a number a deleted version used is never handed out again and two
                     -- captures of one change set never choose the same one.
                     next_version          INTEGER NOT NULL DEFAULT 1,
                     created_at_ms         INTEGER NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS versions (
                     change_set_id   BLOB NOT NULL REFERENCES change_sets(change_set_id),
                     version         INTEGER NOT NULL,
                     content_digest  BLOB NOT NULL,
                     consistency     TEXT NOT NULL,
                     base_revision   TEXT NOT NULL,
                     derived_from    INTEGER,
                     record          BLOB NOT NULL,
                     manifest        BLOB NOT NULL,
                     captured_at_ms  INTEGER NOT NULL,
                     PRIMARY KEY (change_set_id, version)
                 );
                 CREATE TABLE IF NOT EXISTS version_objects (
                     change_set_id BLOB NOT NULL,
                     version       INTEGER NOT NULL,
                     object_digest BLOB NOT NULL,
                     PRIMARY KEY (change_set_id, version, object_digest)
                 );
                 CREATE TABLE IF NOT EXISTS materialisations (
                     materialisation_id BLOB PRIMARY KEY,
                     change_set_id      BLOB NOT NULL,
                     version            INTEGER NOT NULL,
                     purpose            TEXT NOT NULL,
                     record             BLOB NOT NULL,
                     directory_name     TEXT NOT NULL,
                     identity_device    INTEGER NOT NULL,
                     identity_file_id   INTEGER NOT NULL,
                     created_at_ms      INTEGER NOT NULL,
                     released_at_ms     INTEGER
                 );
                 CREATE TABLE IF NOT EXISTS results (
                     result_id             BLOB PRIMARY KEY,
                     materialisation_id    BLOB NOT NULL,
                     tested_source         TEXT NOT NULL,
                     tested_change_set_id  BLOB,
                     tested_version        INTEGER,
                     record                BLOB NOT NULL,
                     recorded_at_ms        INTEGER NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS evidence (
                     change_set_id  BLOB NOT NULL,
                     version        INTEGER NOT NULL,
                     kind           TEXT NOT NULL,
                     detail         TEXT NOT NULL,
                     recorded_at_ms INTEGER NOT NULL,
                     PRIMARY KEY (change_set_id, version, kind, detail)
                 );
                 CREATE TABLE IF NOT EXISTS applies (
                     action_id               BLOB PRIMARY KEY,
                     change_set_id           BLOB NOT NULL,
                     version                 INTEGER NOT NULL,
                     workspace_id            BLOB,
                     destination             TEXT NOT NULL,
                     outcome                 TEXT,
                     before_change_set_id    BLOB,
                     before_version          INTEGER,
                     after_change_set_id     BLOB,
                     after_version           INTEGER,
                     staged_name             TEXT,
                     detail                  TEXT NOT NULL,
                     started_at_ms           INTEGER NOT NULL,
                     decided_at_ms           INTEGER
                 );
                 CREATE TABLE IF NOT EXISTS actions (
                     actor_id       TEXT NOT NULL,
                     action_id      BLOB NOT NULL,
                     method         TEXT NOT NULL,
                     payload_digest BLOB NOT NULL,
                     result         BLOB,
                     error_code     TEXT,
                     error_detail   TEXT,
                     recorded_at_ms INTEGER NOT NULL,
                     PRIMARY KEY (actor_id, action_id)
                 );
                 CREATE TABLE IF NOT EXISTS apply_progress (
                     action_id     BLOB NOT NULL,
                     path          TEXT NOT NULL,
                     state         TEXT NOT NULL,
                     before_digest BLOB,
                     after_digest  BLOB,
                     detail        TEXT NOT NULL,
                     PRIMARY KEY (action_id, path)
                 );",
            )
            .map_err(ChangeSetError::store)?;
        let recorded: Option<i64> = transaction
            .query_row("SELECT version FROM schema_version LIMIT 1", [], |row| {
                row.get(0)
            })
            .optional()
            .map_err(ChangeSetError::store)?;
        match recorded {
            Some(version) if version > SCHEMA_VERSION => {
                // A store a later build wrote is refused rather than half read, because this build
                // cannot know what a column it does not have holds.
                return Err(ChangeSetError::StoreUnavailable {
                    detail: format!(
                        "this change-set store was written at schema version {version} and this \
                         build reads {SCHEMA_VERSION}"
                    )
                    .into(),
                });
            }
            Some(_) => {
                transaction
                    .execute(
                        "UPDATE schema_version SET version = ?1",
                        params![SCHEMA_VERSION],
                    )
                    .map_err(ChangeSetError::store)?;
            }
            None => {
                transaction
                    .execute(
                        "INSERT INTO schema_version (version) VALUES (?1)",
                        params![SCHEMA_VERSION],
                    )
                    .map_err(ChangeSetError::store)?;
            }
        }
        transaction.commit().map_err(ChangeSetError::store)
    }

    // ----- change sets and versions ------------------------------------------------------------

    /// Records a new change set.
    ///
    /// # Errors
    ///
    /// Returns [`ChangeSetError::StoreUnavailable`] when the write fails.
    pub fn insert_change_set(&self, row: &ChangeSetRow) -> Result<()> {
        self.connection
            .execute(
                "INSERT INTO change_sets
                   (change_set_id, environment_id, project_repository_id, workspace_id, label,
                    next_version, created_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, 1, ?6)",
                params![
                    uuid_bytes(row.change_set_id.get()),
                    uuid_bytes(row.environment_id.get()),
                    uuid_bytes(row.project_repository_id.get()),
                    uuid_bytes(row.workspace_id.get()),
                    row.label,
                    row.created_at_ms.get() as i64,
                ],
            )
            .map_err(ChangeSetError::store)?;
        Ok(())
    }

    /// Returns one change set.
    ///
    /// # Errors
    ///
    /// Returns [`ChangeSetError::StoreUnavailable`] when the read fails.
    pub fn change_set(&self, change_set_id: ChangeSetId) -> Result<Option<ChangeSetRow>> {
        self.connection
            .query_row(
                "SELECT environment_id, project_repository_id, workspace_id, label, created_at_ms
                   FROM change_sets WHERE change_set_id = ?1",
                params![uuid_bytes(change_set_id.get())],
                |row| {
                    Ok(ChangeSetRow {
                        change_set_id,
                        environment_id: EnvironmentId::new(uuid_column(row, 0)?),
                        project_repository_id: ProjectRepositoryId::new(uuid_column(row, 1)?),
                        workspace_id: WorkspaceId::new(uuid_column(row, 2)?),
                        label: row.get(3)?,
                        created_at_ms: TimestampMs::new(row.get::<_, i64>(4)? as u64),
                    })
                },
            )
            .optional()
            .map_err(ChangeSetError::store)
    }

    /// Records one version and the objects it references, in one transaction.
    ///
    /// The version and its object references commit together, so a version whose row exists always
    /// has the references that keep its blobs from being collected.
    ///
    /// # Errors
    ///
    /// Returns [`ChangeSetError::StoreUnavailable`] when the write fails.
    pub fn insert_version(&mut self, row: &VersionRow, objects: &[Digest256]) -> Result<()> {
        let transaction = self
            .connection
            .transaction()
            .map_err(ChangeSetError::store)?;
        transaction
            .execute(
                "INSERT INTO versions
                   (change_set_id, version, content_digest, consistency, base_revision,
                    derived_from, record, manifest, captured_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    uuid_bytes(row.change_set_id.get()),
                    row.version.get() as i64,
                    row.content_digest.as_bytes().to_vec(),
                    consistency_text(row.consistency),
                    row.base_revision,
                    row.derived_from.map(|version| version.get() as i64),
                    row.record,
                    row.manifest,
                    row.captured_at_ms.get() as i64,
                ],
            )
            .map_err(ChangeSetError::store)?;
        for digest in objects {
            transaction
                .execute(
                    "INSERT OR IGNORE INTO version_objects (change_set_id, version, object_digest)
                     VALUES (?1, ?2, ?3)",
                    params![
                        uuid_bytes(row.change_set_id.get()),
                        row.version.get() as i64,
                        digest.as_bytes().to_vec(),
                    ],
                )
                .map_err(ChangeSetError::store)?;
        }
        transaction.commit().map_err(ChangeSetError::store)
    }

    /// Returns the highest version number one change set has, or nothing when it has none.
    ///
    /// # Errors
    ///
    /// Returns [`ChangeSetError::StoreUnavailable`] when the read fails.
    pub fn latest_version(&self, change_set_id: ChangeSetId) -> Result<Option<ChangeSetVersion>> {
        let highest: Option<i64> = self
            .connection
            .query_row(
                "SELECT MAX(version) FROM versions WHERE change_set_id = ?1",
                params![uuid_bytes(change_set_id.get())],
                |row| row.get(0),
            )
            .optional()
            .map_err(ChangeSetError::store)?
            .flatten();
        Ok(highest.map(|value| ChangeSetVersion::new(value as u64)))
    }

    /// Takes the next version number one change set hands out, and moves it on.
    ///
    /// Durable and monotonic: the number is written before the version that uses it exists, so a
    /// capture that then fails leaves a gap rather than a number a later capture reuses, and two
    /// captures of one change set never choose the same one. A version reference therefore names
    /// one piece of work for as long as the change set exists, which is what an immutable
    /// identified version means.
    ///
    /// # Errors
    ///
    /// Returns [`ChangeSetError::UnknownVersion`] when there is no such change set, and
    /// [`ChangeSetError::StoreUnavailable`] when the write fails or the counter would overflow.
    pub fn reserve_version(&mut self, change_set_id: ChangeSetId) -> Result<ChangeSetVersion> {
        let transaction = self
            .connection
            .transaction()
            .map_err(ChangeSetError::store)?;
        let current: i64 = transaction
            .query_row(
                "SELECT next_version FROM change_sets WHERE change_set_id = ?1",
                params![uuid_bytes(change_set_id.get())],
                |row| row.get(0),
            )
            .optional()
            .map_err(ChangeSetError::store)?
            .ok_or_else(|| ChangeSetError::UnknownVersion {
                detail: format!("no change set {change_set_id}").into(),
            })?;
        let next = current
            .checked_add(1)
            .ok_or_else(|| ChangeSetError::StoreUnavailable {
                detail: "this change set has handed out every version number there is".into(),
            })?;
        transaction
            .execute(
                "UPDATE change_sets SET next_version = ?2 WHERE change_set_id = ?1",
                params![uuid_bytes(change_set_id.get()), next],
            )
            .map_err(ChangeSetError::store)?;
        transaction.commit().map_err(ChangeSetError::store)?;
        Ok(ChangeSetVersion::new(
            u64::try_from(current).map_err(ChangeSetError::store)?,
        ))
    }

    /// Returns one version.
    ///
    /// # Errors
    ///
    /// Returns [`ChangeSetError::StoreUnavailable`] when the read fails.
    pub fn version(
        &self,
        change_set_id: ChangeSetId,
        version: ChangeSetVersion,
    ) -> Result<Option<VersionRow>> {
        self.connection
            .query_row(
                "SELECT content_digest, consistency, base_revision, derived_from, record, manifest,
                        captured_at_ms
                   FROM versions WHERE change_set_id = ?1 AND version = ?2",
                params![uuid_bytes(change_set_id.get()), version.get() as i64],
                |row| {
                    Ok(VersionRow {
                        change_set_id,
                        version,
                        content_digest: digest_column(row, 0)?,
                        consistency: consistency_of(&row.get::<_, String>(1)?)
                            .ok_or_else(|| unknown(1, "a consistency class"))?,
                        base_revision: row.get(2)?,
                        derived_from: row
                            .get::<_, Option<i64>>(3)?
                            .map(|value| ChangeSetVersion::new(value as u64)),
                        record: row.get(4)?,
                        manifest: row.get(5)?,
                        captured_at_ms: TimestampMs::new(row.get::<_, i64>(6)? as u64),
                    })
                },
            )
            .optional()
            .map_err(ChangeSetError::store)
    }

    /// Returns every version of one change set, oldest first.
    ///
    /// # Errors
    ///
    /// Returns [`ChangeSetError::StoreUnavailable`] when the read fails.
    pub fn versions(&self, change_set_id: ChangeSetId) -> Result<Vec<VersionRow>> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT version, content_digest, consistency, base_revision, derived_from, record,
                        manifest, captured_at_ms
                   FROM versions WHERE change_set_id = ?1 ORDER BY version",
            )
            .map_err(ChangeSetError::store)?;
        let rows = statement
            .query_map(params![uuid_bytes(change_set_id.get())], |row| {
                Ok(VersionRow {
                    change_set_id,
                    version: ChangeSetVersion::new(row.get::<_, i64>(0)? as u64),
                    content_digest: digest_column(row, 1)?,
                    consistency: consistency_of(&row.get::<_, String>(2)?)
                        .ok_or_else(|| unknown(2, "a consistency class"))?,
                    base_revision: row.get(3)?,
                    derived_from: row
                        .get::<_, Option<i64>>(4)?
                        .map(|value| ChangeSetVersion::new(value as u64)),
                    record: row.get(5)?,
                    manifest: row.get(6)?,
                    captured_at_ms: TimestampMs::new(row.get::<_, i64>(7)? as u64),
                })
            })
            .map_err(ChangeSetError::store)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(ChangeSetError::store)?;
        Ok(rows)
    }

    /// Returns everything inside this store that names one version.
    ///
    /// Every count runs inside the caller's own transaction, so nothing can be recorded between
    /// the counting and a removal that depends on it.
    fn held_by(
        transaction: &Transaction<'_>,
        change_set_id: ChangeSetId,
        version: ChangeSetVersion,
    ) -> Result<Vec<String>> {
        let set = uuid_bytes(change_set_id.get());
        let number = version.get() as i64;
        let mut held = Vec::new();
        for (statement, what) in [
            (
                "SELECT COUNT(*) FROM materialisations
                  WHERE change_set_id = ?1 AND version = ?2 AND released_at_ms IS NULL",
                "materialisation(s) that have not been released",
            ),
            (
                "SELECT COUNT(*) FROM evidence WHERE change_set_id = ?1 AND version = ?2
                   AND kind <> 'materialisation'",
                "evidence reference(s)",
            ),
            (
                "SELECT COUNT(*) FROM versions WHERE change_set_id = ?1 AND derived_from = ?2",
                "later version(s) derived from this one",
            ),
            (
                "SELECT COUNT(*) FROM results r
                   JOIN materialisations m ON m.materialisation_id = r.materialisation_id
                  WHERE (m.change_set_id = ?1 AND m.version = ?2)
                     OR (r.tested_change_set_id = ?1 AND r.tested_version = ?2)",
                "recorded result(s)",
            ),
            (
                "SELECT COUNT(*) FROM applies
                  WHERE (change_set_id = ?1 AND version = ?2)
                     OR (before_change_set_id = ?1 AND before_version = ?2)
                     OR (after_change_set_id = ?1 AND after_version = ?2)",
                "apply record(s) that name it",
            ),
        ] {
            let count: i64 = transaction
                .query_row(statement, params![set, number], |row| row.get(0))
                .map_err(ChangeSetError::store)?;
            if count > 0 {
                held.push(format!("{count} {what}"));
            }
        }
        Ok(held)
    }

    /// Returns everything inside this store that names one version, for a caller that shows it.
    ///
    /// # Errors
    ///
    /// Returns [`ChangeSetError::StoreUnavailable`] when the read fails.
    pub fn held_by_anything(
        &mut self,
        change_set_id: ChangeSetId,
        version: ChangeSetVersion,
    ) -> Result<Vec<String>> {
        let transaction = self
            .connection
            .transaction()
            .map_err(ChangeSetError::store)?;
        let held = Self::held_by(&transaction, change_set_id, version)?;
        transaction.commit().map_err(ChangeSetError::store)?;
        Ok(held)
    }

    /// Removes one version, once nothing inside this store names it.
    ///
    /// The counting and the removal are **one transaction**, so nothing can record a
    /// materialisation, a result, an apply or a piece of evidence between them. What this cannot
    /// cover is the project service's own pin, which lives in another store; the service checks
    /// that first and the reference says so.
    ///
    /// # Errors
    ///
    /// Returns [`ChangeSetError::WrongState`] naming everything that still holds it, and
    /// [`ChangeSetError::StoreUnavailable`] when the write fails.
    pub fn delete_version_if_unheld(
        &mut self,
        change_set_id: ChangeSetId,
        version: ChangeSetVersion,
    ) -> Result<()> {
        let transaction = self
            .connection
            .transaction()
            .map_err(ChangeSetError::store)?;
        let held = Self::held_by(&transaction, change_set_id, version)?;
        if !held.is_empty() {
            return Err(ChangeSetError::WrongState {
                detail: format!(
                    "this version is still held, so it is not deleted: {}",
                    held.join("; ")
                )
                .into(),
            });
        }
        let key = params![uuid_bytes(change_set_id.get()), version.get() as i64];
        for statement in [
            "DELETE FROM version_objects WHERE change_set_id = ?1 AND version = ?2",
            "DELETE FROM evidence WHERE change_set_id = ?1 AND version = ?2",
            "DELETE FROM versions WHERE change_set_id = ?1 AND version = ?2",
        ] {
            transaction
                .execute(statement, key)
                .map_err(ChangeSetError::store)?;
        }
        transaction.commit().map_err(ChangeSetError::store)
    }

    // ----- materialisations and results ---------------------------------------------------------

    /// Records one materialisation, with the evidence reference that accounts for it.
    ///
    /// The two commit together, so a materialisation that exists is always one a deletion has to
    /// account for.
    ///
    /// # Errors
    ///
    /// Returns [`ChangeSetError::StoreUnavailable`] when the write fails.
    pub fn insert_materialisation(&mut self, row: &MaterialisationRow) -> Result<()> {
        let transaction = self
            .connection
            .transaction()
            .map_err(ChangeSetError::store)?;
        transaction
            .execute(
                "INSERT INTO materialisations
                   (materialisation_id, change_set_id, version, purpose, record, directory_name,
                    identity_device, identity_file_id, created_at_ms, released_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, NULL)",
                params![
                    uuid_bytes(row.materialisation_id.get()),
                    uuid_bytes(row.change_set_id.get()),
                    row.version.get() as i64,
                    purpose_text(row.purpose),
                    row.record,
                    row.directory_name,
                    row.identity.device as i64,
                    row.identity.file_id as i64,
                    row.created_at_ms.get() as i64,
                ],
            )
            .map_err(ChangeSetError::store)?;
        transaction
            .execute(
                "INSERT OR REPLACE INTO evidence
                   (change_set_id, version, kind, detail, recorded_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    uuid_bytes(row.change_set_id.get()),
                    row.version.get() as i64,
                    evidence_text(EvidenceKind::Materialisation),
                    format!("materialisation {}", row.materialisation_id),
                    row.created_at_ms.get() as i64,
                ],
            )
            .map_err(ChangeSetError::store)?;
        transaction.commit().map_err(ChangeSetError::store)
    }

    /// Returns one materialisation.
    ///
    /// # Errors
    ///
    /// Returns [`ChangeSetError::StoreUnavailable`] when the read fails.
    pub fn materialisation(
        &self,
        materialisation_id: MaterialisationId,
    ) -> Result<Option<MaterialisationRow>> {
        self.connection
            .query_row(
                "SELECT change_set_id, version, purpose, record, directory_name, identity_device,
                        identity_file_id, created_at_ms, released_at_ms
                   FROM materialisations WHERE materialisation_id = ?1",
                params![uuid_bytes(materialisation_id.get())],
                |row| {
                    Ok(MaterialisationRow {
                        materialisation_id,
                        change_set_id: ChangeSetId::new(uuid_column(row, 0)?),
                        version: ChangeSetVersion::new(row.get::<_, i64>(1)? as u64),
                        purpose: purpose_of(&row.get::<_, String>(2)?)
                            .ok_or_else(|| unknown(2, "a materialisation purpose"))?,
                        record: row.get(3)?,
                        directory_name: row.get(4)?,
                        identity: kr_transfer::ObjectIdentity {
                            device: row.get::<_, i64>(5)? as u64,
                            file_id: row.get::<_, i64>(6)? as u64,
                        },
                        created_at_ms: TimestampMs::new(row.get::<_, i64>(7)? as u64),
                        released_at_ms: row
                            .get::<_, Option<i64>>(8)?
                            .map(|value| TimestampMs::new(value as u64)),
                    })
                },
            )
            .optional()
            .map_err(ChangeSetError::store)
    }

    /// Returns every materialisation of one version that has not been released.
    ///
    /// # Errors
    ///
    /// Returns [`ChangeSetError::StoreUnavailable`] when the read fails.
    pub fn materialisations(
        &self,
        change_set_id: ChangeSetId,
        version: ChangeSetVersion,
        include_released: bool,
    ) -> Result<Vec<MaterialisationRow>> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT materialisation_id, purpose, record, directory_name, identity_device,
                        identity_file_id, created_at_ms, released_at_ms
                   FROM materialisations
                  WHERE change_set_id = ?1 AND version = ?2
                    AND (?3 OR released_at_ms IS NULL)
                  ORDER BY created_at_ms",
            )
            .map_err(ChangeSetError::store)?;
        let rows = statement
            .query_map(
                params![
                    uuid_bytes(change_set_id.get()),
                    version.get() as i64,
                    include_released
                ],
                |row| {
                    Ok(MaterialisationRow {
                        materialisation_id: MaterialisationId::new(uuid_column(row, 0)?),
                        change_set_id,
                        version,
                        purpose: purpose_of(&row.get::<_, String>(1)?)
                            .ok_or_else(|| unknown(1, "a materialisation purpose"))?,
                        record: row.get(2)?,
                        directory_name: row.get(3)?,
                        identity: kr_transfer::ObjectIdentity {
                            device: row.get::<_, i64>(4)? as u64,
                            file_id: row.get::<_, i64>(5)? as u64,
                        },
                        created_at_ms: TimestampMs::new(row.get::<_, i64>(6)? as u64),
                        released_at_ms: row
                            .get::<_, Option<i64>>(7)?
                            .map(|value| TimestampMs::new(value as u64)),
                    })
                },
            )
            .map_err(ChangeSetError::store)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(ChangeSetError::store)?;
        Ok(rows)
    }

    /// Marks one materialisation released and replaces the record a caller reads.
    ///
    /// # Errors
    ///
    /// Returns [`ChangeSetError::StoreUnavailable`] when the write fails.
    pub fn release_materialisation(
        &self,
        materialisation_id: MaterialisationId,
        record: &[u8],
        at_ms: TimestampMs,
    ) -> Result<()> {
        self.connection
            .execute(
                "UPDATE materialisations SET released_at_ms = ?2, record = ?3
                  WHERE materialisation_id = ?1",
                params![
                    uuid_bytes(materialisation_id.get()),
                    at_ms.get() as i64,
                    record
                ],
            )
            .map_err(ChangeSetError::store)?;
        Ok(())
    }

    /// Records one result, with the evidence reference that accounts for it.
    ///
    /// # Errors
    ///
    /// Returns [`ChangeSetError::StoreUnavailable`] when the write fails.
    pub fn insert_result(&mut self, row: &ResultRow) -> Result<()> {
        let transaction = self
            .connection
            .transaction()
            .map_err(ChangeSetError::store)?;
        transaction
            .execute(
                "INSERT INTO results
                   (result_id, materialisation_id, tested_source, tested_change_set_id,
                    tested_version, record, recorded_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    uuid_bytes(kr_ipc::new_uuid()),
                    uuid_bytes(row.materialisation_id.get()),
                    tested_text(row.tested_source),
                    row.tested_version.map(|(set, _)| uuid_bytes(set.get())),
                    row.tested_version.map(|(_, version)| version.get() as i64),
                    row.record,
                    row.recorded_at_ms.get() as i64,
                ],
            )
            .map_err(ChangeSetError::store)?;
        // A result is evidence about the version it ran against and about the version it
        // attests, which are the same version only when the materialisation was unmodified.
        // Both are written here, in the same transaction as the result itself: an indeterminate
        // result is exactly what a person has to see before the version it ran against goes.
        let mut named = vec![(row.input_change_set_id, row.input_version)];
        if let Some((set, version)) = row.tested_version
            && (set, version) != (row.input_change_set_id, row.input_version)
        {
            named.push((set, version));
        }
        for (set, version) in named {
            transaction
                .execute(
                    "INSERT OR REPLACE INTO evidence
                       (change_set_id, version, kind, detail, recorded_at_ms)
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![
                        uuid_bytes(set.get()),
                        version.get() as i64,
                        evidence_text(EvidenceKind::TestResult),
                        format!(
                            "a result against materialisation {}",
                            row.materialisation_id
                        ),
                        row.recorded_at_ms.get() as i64,
                    ],
                )
                .map_err(ChangeSetError::store)?;
        }
        transaction.commit().map_err(ChangeSetError::store)
    }

    /// Returns every result recorded against the materialisations of one version.
    ///
    /// # Errors
    ///
    /// Returns [`ChangeSetError::StoreUnavailable`] when the read fails.
    pub fn results(
        &self,
        change_set_id: ChangeSetId,
        version: ChangeSetVersion,
    ) -> Result<Vec<ResultRow>> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT r.materialisation_id, r.tested_source, r.tested_change_set_id,
                        r.tested_version, r.record, r.recorded_at_ms
                   FROM results r
                   JOIN materialisations m ON m.materialisation_id = r.materialisation_id
                  WHERE m.change_set_id = ?1 AND m.version = ?2
                  ORDER BY r.recorded_at_ms",
            )
            .map_err(ChangeSetError::store)?;
        let rows = statement
            .query_map(
                params![uuid_bytes(change_set_id.get()), version.get() as i64],
                |row| {
                    let set: Option<Vec<u8>> = row.get(2)?;
                    let number: Option<i64> = row.get(3)?;
                    Ok(ResultRow {
                        materialisation_id: MaterialisationId::new(uuid_column(row, 0)?),
                        input_change_set_id: change_set_id,
                        input_version: version,
                        tested_source: tested_of(&row.get::<_, String>(1)?)
                            .ok_or_else(|| unknown(1, "a tested-source class"))?,
                        tested_version: pair(set, number)?,
                        record: row.get(4)?,
                        recorded_at_ms: TimestampMs::new(row.get::<_, i64>(5)? as u64),
                    })
                },
            )
            .map_err(ChangeSetError::store)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(ChangeSetError::store)?;
        Ok(rows)
    }

    // ----- evidence ------------------------------------------------------------------------------

    /// Records one piece of evidence against a version.
    ///
    /// # Errors
    ///
    /// Returns [`ChangeSetError::StoreUnavailable`] when the write fails.
    pub fn record_evidence(&self, row: &EvidenceRow) -> Result<()> {
        self.connection
            .execute(
                "INSERT OR REPLACE INTO evidence
                   (change_set_id, version, kind, detail, recorded_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    uuid_bytes(row.change_set_id.get()),
                    row.version.get() as i64,
                    evidence_text(row.kind),
                    kr_project::git::redact(&row.detail),
                    row.recorded_at_ms.get() as i64,
                ],
            )
            .map_err(ChangeSetError::store)?;
        Ok(())
    }

    /// Returns every piece of evidence that names one version.
    ///
    /// # Errors
    ///
    /// Returns [`ChangeSetError::StoreUnavailable`] when the read fails.
    pub fn evidence(
        &self,
        change_set_id: ChangeSetId,
        version: ChangeSetVersion,
    ) -> Result<Vec<EvidenceRow>> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT kind, detail, recorded_at_ms FROM evidence
                  WHERE change_set_id = ?1 AND version = ?2
                  ORDER BY recorded_at_ms, kind, detail",
            )
            .map_err(ChangeSetError::store)?;
        let rows = statement
            .query_map(
                params![uuid_bytes(change_set_id.get()), version.get() as i64],
                |row| {
                    Ok(EvidenceRow {
                        change_set_id,
                        version,
                        kind: evidence_of(&row.get::<_, String>(0)?)
                            .ok_or_else(|| unknown(0, "an evidence kind"))?,
                        // The rule applies where a column is read as well as where it is written,
                        // because a store an earlier build wrote holds what that build composed.
                        detail: kr_project::git::redact(&row.get::<_, String>(1)?),
                        recorded_at_ms: TimestampMs::new(row.get::<_, i64>(2)? as u64),
                    })
                },
            )
            .map_err(ChangeSetError::store)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(ChangeSetError::store)?;
        Ok(rows)
    }

    // ----- actions ---------------------------------------------------------------------------

    /// Returns one action's retained outcome, when this service has one.
    ///
    /// A successful answer is kept whole and carries free text of its own, so it comes back
    /// through the rule: this is the last place this host can reach what an earlier build recorded
    /// before a repeat of the action returns it.
    ///
    /// # Errors
    ///
    /// Returns [`ChangeSetError::IdConflict`] when the identifier was used for a different
    /// request, and [`ChangeSetError::StoreUnavailable`] when the read fails.
    pub fn retained_action(
        &self,
        actor_id: &ActorId,
        action_id: Uuid,
        method: &str,
        payload_digest: Digest256,
    ) -> Result<Option<RetainedOutcome>> {
        let row: Option<StoredAction> = self
            .connection
            .query_row(
                "SELECT method, payload_digest, result, error_code, error_detail
                   FROM actions WHERE actor_id = ?1 AND action_id = ?2",
                params![actor_id.as_str(), action_id.as_bytes().to_vec()],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .optional()
            .map_err(ChangeSetError::store)?;
        let Some((stored_method, stored_digest, result, code, detail)) = row else {
            return Ok(None);
        };
        if stored_method != method || digest_of_slice(&stored_digest) != Some(payload_digest) {
            return Err(ChangeSetError::IdConflict {
                action: action_id.to_string().into(),
                method: stored_method.into(),
            });
        }
        // A claim with no outcome is not an answer: the request reaches the service, which
        // finishes what its claim started rather than telling the caller the outcome is unknown
        // for ever.
        match (result, code) {
            (Some(result), _) => Ok(Some(RetainedOutcome::Ok(
                crate::answer::protect_stored_result(method, &result)?,
            ))),
            (None, Some(code)) => Ok(Some(RetainedOutcome::Error {
                code: ErrorCode::from_wire(&code).unwrap_or(ErrorCode::OutcomeUnknown),
                detail: kr_project::git::redact(&detail.unwrap_or_default()),
            })),
            (None, None) => Ok(None),
        }
    }

    /// Records one action's outcome, leaving an existing row alone.
    ///
    /// Returns the record that was already there, when another copy of the action recorded first.
    /// That record is the answer both callers get: one action, one receipt.
    ///
    /// # Errors
    ///
    /// Returns [`ChangeSetError::IdConflict`] when the identifier was used for a different
    /// request, and [`ChangeSetError::StoreUnavailable`] when the write fails.
    pub fn record_action(
        &self,
        actor_id: &ActorId,
        action_id: Uuid,
        method: &str,
        payload_digest: Digest256,
        outcome: &RetainedOutcome,
    ) -> Result<Option<RetainedOutcome>> {
        let (result, code, detail) = match outcome {
            RetainedOutcome::Ok(result) => (Some(result.clone()), None, None),
            RetainedOutcome::Error { code, detail } => (
                None,
                Some(code.as_str().to_owned()),
                // A retained failure is read back by whoever repeats the action, and it is kept,
                // so the rule is applied here as well as where the message was composed.
                Some(kr_project::git::redact(detail)),
            ),
        };
        let inserted = self
            .connection
            .execute(
                "INSERT INTO actions (actor_id, action_id, method, payload_digest, result,
                                      error_code, error_detail, recorded_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                 ON CONFLICT (actor_id, action_id) DO NOTHING",
                params![
                    actor_id.as_str(),
                    action_id.as_bytes().to_vec(),
                    method,
                    payload_digest.as_bytes().to_vec(),
                    result,
                    code,
                    detail,
                    kr_ipc::now_ms().get() as i64,
                ],
            )
            .map_err(ChangeSetError::store)?;
        if inserted == 1 {
            return Ok(None);
        }
        self.retained_action(actor_id, action_id, method, payload_digest)
    }

    // ----- applies --------------------------------------------------------------------------------

    /// Begins one apply, before anything is written anywhere.
    ///
    /// # Errors
    ///
    /// Returns [`ChangeSetError::StoreUnavailable`] when the write fails.
    pub fn begin_apply(&self, row: &ApplyRow) -> Result<()> {
        self.connection
            .execute(
                "INSERT INTO applies
                   (action_id, change_set_id, version, workspace_id, destination, outcome,
                    before_change_set_id, before_version, after_change_set_id, after_version,
                    staged_name, detail, started_at_ms, decided_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, NULL, ?6, ?7, NULL, NULL, ?8, ?9, ?10, NULL)",
                params![
                    uuid_bytes(row.action_id.get()),
                    uuid_bytes(row.change_set_id.get()),
                    row.version.get() as i64,
                    row.workspace_id.map(|id| uuid_bytes(id.get())),
                    destination_text(row.destination),
                    row.before_version.map(|(set, _)| uuid_bytes(set.get())),
                    row.before_version.map(|(_, version)| version.get() as i64),
                    row.staged_name,
                    kr_project::git::redact(&row.detail),
                    row.started_at_ms.get() as i64,
                ],
            )
            .map_err(ChangeSetError::store)?;
        Ok(())
    }

    /// Records one path as planned, before anything is attempted for it.
    ///
    /// # Errors
    ///
    /// Returns [`ChangeSetError::StoreUnavailable`] when the write fails.
    pub fn plan_path(&self, action_id: ActionId, path: &str) -> Result<()> {
        self.connection
            .execute(
                "INSERT OR REPLACE INTO apply_progress
                   (action_id, path, state, before_digest, after_digest, detail)
                 VALUES (?1, ?2, ?3, NULL, NULL, ?4)",
                params![
                    uuid_bytes(action_id.get()),
                    path,
                    progress_text(PathProgressState::Planned),
                    "this host recorded that it was going to write this path",
                ],
            )
            .map_err(ChangeSetError::store)?;
        Ok(())
    }

    /// Replaces one path's progress with the outcome this host established.
    ///
    /// # Errors
    ///
    /// Returns [`ChangeSetError::StoreUnavailable`] when the write fails.
    pub fn settle_path(&self, action_id: ActionId, row: &ProgressRow) -> Result<()> {
        self.connection
            .execute(
                "INSERT OR REPLACE INTO apply_progress
                   (action_id, path, state, before_digest, after_digest, detail)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    uuid_bytes(action_id.get()),
                    row.path,
                    progress_text(row.state),
                    row.before_digest.map(|d| d.as_bytes().to_vec()),
                    row.after_digest.map(|d| d.as_bytes().to_vec()),
                    kr_project::git::redact(&row.detail),
                ],
            )
            .map_err(ChangeSetError::store)?;
        Ok(())
    }

    /// Returns every path's progress inside one apply, in path order.
    ///
    /// # Errors
    ///
    /// Returns [`ChangeSetError::StoreUnavailable`] when the read fails.
    pub fn progress(&self, action_id: ActionId) -> Result<Vec<ProgressRow>> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT path, state, before_digest, after_digest, detail FROM apply_progress
                  WHERE action_id = ?1 ORDER BY path",
            )
            .map_err(ChangeSetError::store)?;
        let rows = statement
            .query_map(params![uuid_bytes(action_id.get())], |row| {
                let before: Option<Vec<u8>> = row.get(2)?;
                let after: Option<Vec<u8>> = row.get(3)?;
                Ok(ProgressRow {
                    path: row.get(0)?,
                    state: progress_of(&row.get::<_, String>(1)?)
                        .ok_or_else(|| unknown(1, "a path progress state"))?,
                    before_digest: before.as_deref().and_then(digest_of_slice),
                    after_digest: after.as_deref().and_then(digest_of_slice),
                    detail: kr_project::git::redact(&row.get::<_, String>(4)?),
                })
            })
            .map_err(ChangeSetError::store)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(ChangeSetError::store)?;
        Ok(rows)
    }

    /// Records the class one apply came to, and what it left to recover from.
    ///
    /// # Errors
    ///
    /// Returns [`ChangeSetError::StoreUnavailable`] when the write fails.
    pub fn settle_apply(
        &self,
        action_id: ActionId,
        outcome: ApplyOutcomeClass,
        after: Option<(ChangeSetId, ChangeSetVersion)>,
        detail: &str,
        at_ms: TimestampMs,
    ) -> Result<()> {
        self.connection
            .execute(
                "UPDATE applies
                    SET outcome = ?2, after_change_set_id = ?3, after_version = ?4, detail = ?5,
                        decided_at_ms = ?6
                  WHERE action_id = ?1",
                params![
                    uuid_bytes(action_id.get()),
                    outcome_text(outcome),
                    after.map(|(set, _)| uuid_bytes(set.get())),
                    after.map(|(_, version)| version.get() as i64),
                    kr_project::git::redact(detail),
                    at_ms.get() as i64,
                ],
            )
            .map_err(ChangeSetError::store)?;
        Ok(())
    }

    /// Records the staging directory one apply's validated content went through.
    ///
    /// # Errors
    ///
    /// Returns [`ChangeSetError::StoreUnavailable`] when the write fails.
    pub fn set_staged_name(&self, action_id: ActionId, name: Option<&str>) -> Result<()> {
        self.connection
            .execute(
                "UPDATE applies SET staged_name = ?2 WHERE action_id = ?1",
                params![uuid_bytes(action_id.get()), name],
            )
            .map_err(ChangeSetError::store)?;
        Ok(())
    }

    /// Returns one apply.
    ///
    /// # Errors
    ///
    /// Returns [`ChangeSetError::StoreUnavailable`] when the read fails.
    pub fn apply(&self, action_id: ActionId) -> Result<Option<ApplyRow>> {
        self.connection
            .query_row(
                "SELECT change_set_id, version, workspace_id, destination, outcome,
                        before_change_set_id, before_version, after_change_set_id, after_version,
                        staged_name, detail, started_at_ms, decided_at_ms
                   FROM applies WHERE action_id = ?1",
                params![uuid_bytes(action_id.get())],
                |row| apply_row(action_id, row),
            )
            .optional()
            .map_err(ChangeSetError::store)
    }

    /// Returns every apply this host has not decided.
    ///
    /// These are what recovery settles: an apply with no outcome is one a daemon died inside.
    ///
    /// # Errors
    ///
    /// Returns [`ChangeSetError::StoreUnavailable`] when the read fails.
    pub fn undecided_applies(&self) -> Result<Vec<ApplyRow>> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT action_id, change_set_id, version, workspace_id, destination, outcome,
                        before_change_set_id, before_version, after_change_set_id, after_version,
                        staged_name, detail, started_at_ms, decided_at_ms
                   FROM applies WHERE outcome IS NULL ORDER BY started_at_ms",
            )
            .map_err(ChangeSetError::store)?;
        let rows = statement
            .query_map([], |row| {
                let action_id = ActionId::new(uuid_column(row, 0)?);
                apply_row_offset(action_id, row, 1)
            })
            .map_err(ChangeSetError::store)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(ChangeSetError::store)?;
        Ok(rows)
    }
}

fn apply_row(action_id: ActionId, row: &rusqlite::Row<'_>) -> rusqlite::Result<ApplyRow> {
    apply_row_offset(action_id, row, 0)
}

fn apply_row_offset(
    action_id: ActionId,
    row: &rusqlite::Row<'_>,
    offset: usize,
) -> rusqlite::Result<ApplyRow> {
    let workspace: Option<Vec<u8>> = row.get(offset + 2)?;
    let outcome: Option<String> = row.get(offset + 4)?;
    let before_set: Option<Vec<u8>> = row.get(offset + 5)?;
    let before_version: Option<i64> = row.get(offset + 6)?;
    let after_set: Option<Vec<u8>> = row.get(offset + 7)?;
    let after_version: Option<i64> = row.get(offset + 8)?;
    Ok(ApplyRow {
        action_id,
        change_set_id: ChangeSetId::new(uuid_column(row, offset)?),
        version: ChangeSetVersion::new(row.get::<_, i64>(offset + 1)? as u64),
        workspace_id: workspace
            .as_deref()
            .map(|bytes| uuid_of(bytes, offset + 2).map(WorkspaceId::new))
            .transpose()?,
        destination: destination_of(&row.get::<_, String>(offset + 3)?)
            .ok_or_else(|| unknown(offset + 3, "a destination class"))?,
        outcome: outcome
            .as_deref()
            .map(|text| outcome_of(text).ok_or_else(|| unknown(offset + 4, "an outcome class")))
            .transpose()?,
        before_version: pair(before_set, before_version)?,
        after_version: pair(after_set, after_version)?,
        staged_name: row.get(offset + 9)?,
        detail: kr_project::git::redact(&row.get::<_, String>(offset + 10)?),
        started_at_ms: TimestampMs::new(row.get::<_, i64>(offset + 11)? as u64),
        decided_at_ms: row
            .get::<_, Option<i64>>(offset + 12)?
            .map(|value| TimestampMs::new(value as u64)),
    })
}

fn pair(
    set: Option<Vec<u8>>,
    version: Option<i64>,
) -> rusqlite::Result<Option<(ChangeSetId, ChangeSetVersion)>> {
    Ok(match (set, version) {
        (Some(set), Some(version)) => Some((
            ChangeSetId::new(uuid_of(&set, 0)?),
            ChangeSetVersion::new(version as u64),
        )),
        _ => None,
    })
}

fn uuid_bytes(value: Uuid) -> Vec<u8> {
    value.as_bytes().to_vec()
}

/// Refuses a stored value this build cannot read.
///
/// One unreadable row is one row a reader is refused. The store still opens and every other row
/// still reads: what this prevents is a damaged or later-written value becoming a plausible
/// identifier, digest or class for something the store does not actually say.
fn unreadable(index: usize, kind: rusqlite::types::Type, what: &str) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        index,
        kind,
        Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            what.to_owned(),
        )),
    )
}

/// Refuses a stored name this build does not write.
fn unknown(index: usize, what: &str) -> rusqlite::Error {
    unreadable(
        index,
        rusqlite::types::Type::Text,
        &format!("{what} this store holds is not one this build writes"),
    )
}

/// Decodes one stored identifier, refusing anything that is not one.
///
/// Padding a short value or truncating a long one would turn a damaged row into a plausible
/// identifier for something else, and a reader would then be told about a version that is not the
/// one the row is about.
fn uuid_of(bytes: &[u8], index: usize) -> rusqlite::Result<Uuid> {
    <[u8; 16]>::try_from(bytes)
        .map(Uuid::from_bytes)
        .map_err(|_| {
            unreadable(
                index,
                rusqlite::types::Type::Blob,
                "an identifier this store holds is not sixteen bytes",
            )
        })
}

fn uuid_column(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<Uuid> {
    let bytes: Vec<u8> = row.get(index)?;
    uuid_of(&bytes, index)
}

/// Decodes one stored digest, refusing anything that is not one.
fn digest_column(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<Digest256> {
    let bytes: Vec<u8> = row.get(index)?;
    digest_of_slice(&bytes).ok_or_else(|| {
        unreadable(
            index,
            rusqlite::types::Type::Blob,
            "a digest this store holds is not thirty-two bytes",
        )
    })
}

fn digest_of_slice(bytes: &[u8]) -> Option<Digest256> {
    <[u8; 32]>::try_from(bytes).ok().map(Digest256::from_bytes)
}

/// Declares the two directions of one stored vocabulary, so a name and its member cannot drift.
macro_rules! vocabulary {
    ($to:ident, $from:ident, $type:ty, $($member:ident => $name:literal),+ $(,)?) => {
        /// Returns the stored name of one member.
        #[must_use]
        pub const fn $to(value: $type) -> &'static str {
            match value {
                $(<$type>::$member => $name),+
            }
        }

        /// Returns the member one stored name stands for, or nothing when this build does not
        /// know it.
        ///
        /// A name this build does not write is a row this build cannot read, and a plausible enum
        /// member in its place would tell a reader something the store does not say. The row is
        /// refused; the store still opens and every other row still reads.
        #[must_use]
        pub fn $from(text: &str) -> Option<$type> {
            match text {
                $($name => Some(<$type>::$member),)+
                _ => None,
            }
        }
    };
}

vocabulary!(
    consistency_text,
    consistency_of,
    SourceConsistency,
    AtomicSnapshot => "atomic_snapshot",
    QuiescedCapture => "quiesced_capture",
    PerFileCapture => "per_file_capture",
);

vocabulary!(
    purpose_text,
    purpose_of,
    MaterialisationPurpose,
    Test => "test",
    Review => "review",
    Inspection => "inspection",
);

vocabulary!(
    tested_text,
    tested_of,
    TestedSource,
    UnmodifiedVersion => "unmodified_version",
    DerivedVersion => "derived_version",
    Indeterminate => "indeterminate",
);

vocabulary!(
    evidence_text,
    evidence_of,
    EvidenceKind,
    ReviewAcknowledgement => "review_acknowledgement",
    TestResult => "test_result",
    Materialisation => "materialisation",
    AppliedChange => "applied_change",
);

vocabulary!(
    destination_text,
    destination_of,
    DestinationClass,
    Proposal => "proposal",
    VersionedReference => "versioned_reference",
    SharedExisting => "shared_existing",
);

vocabulary!(
    outcome_text,
    outcome_of,
    ApplyOutcomeClass,
    PreflightConflict => "preflight_conflict",
    Applied => "applied",
    ConflictAfterPartialWrites => "conflict_after_partial_writes",
    InterruptedApply => "interrupted_apply",
    UncertainOutcome => "uncertain_outcome",
);

vocabulary!(
    progress_text,
    progress_of,
    PathProgressState,
    Planned => "planned",
    Written => "written",
    Conflicted => "conflicted",
    Unresolved => "unresolved",
    Skipped => "skipped",
);

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> Store {
        Store::in_memory(EnvironmentId::new(kr_ipc::new_uuid())).expect("an in-memory store")
    }

    fn change_set(store: &Store) -> ChangeSetId {
        let change_set_id = ChangeSetId::new(kr_ipc::new_uuid());
        store
            .insert_change_set(&ChangeSetRow {
                change_set_id,
                environment_id: store.environment_id(),
                project_repository_id: ProjectRepositoryId::new(kr_ipc::new_uuid()),
                workspace_id: WorkspaceId::new(kr_ipc::new_uuid()),
                label: "a change set".to_owned(),
                created_at_ms: TimestampMs::new(1),
            })
            .expect("the change set is recorded");
        change_set_id
    }

    fn version_row(change_set_id: ChangeSetId, version: u64) -> VersionRow {
        VersionRow {
            change_set_id,
            version: ChangeSetVersion::new(version),
            content_digest: crate::objects::digest_of(format!("version {version}").as_bytes()),
            consistency: SourceConsistency::PerFileCapture,
            base_revision: "abc123".to_owned(),
            derived_from: None,
            record: vec![1, 2, 3],
            manifest: vec![4, 5, 6],
            captured_at_ms: TimestampMs::new(10 + version),
        }
    }

    #[test]
    fn versions_append_and_an_earlier_one_stays_exactly_as_it_was() {
        // Section 14: new edits produce a different version; they do not mutate the subject of an
        // earlier test or review. There is no statement in this module that updates a version.
        let mut store = store();
        let change_set_id = change_set(&store);
        assert_eq!(store.latest_version(change_set_id).expect("a read"), None);
        let first = version_row(change_set_id, 1);
        store
            .insert_version(&first, &[first.content_digest])
            .expect("the first version");
        let second = version_row(change_set_id, 2);
        store
            .insert_version(&second, &[second.content_digest])
            .expect("the second version");
        assert_eq!(
            store.latest_version(change_set_id).expect("a read"),
            Some(ChangeSetVersion::new(2))
        );
        let read = store
            .version(change_set_id, ChangeSetVersion::new(1))
            .expect("a read")
            .expect("version one is still there");
        assert_eq!(read, first, "version one is exactly what it was");
        assert_eq!(store.versions(change_set_id).expect("a read").len(), 2);
    }

    #[test]
    fn a_version_number_cannot_be_written_twice() {
        let mut store = store();
        let change_set_id = change_set(&store);
        let row = version_row(change_set_id, 1);
        store
            .insert_version(&row, &[])
            .expect("the first write succeeds");
        assert!(
            store.insert_version(&row, &[]).is_err(),
            "a second write of the same version is refused by the key"
        );
    }

    #[test]
    fn a_planned_path_survives_until_its_outcome_replaces_it() {
        // The whole of residual "planned is not unwritten": a row written before the attempt and
        // replaced after it, so a daemon that dies between the two leaves `planned`.
        let store = store();
        let action_id = ActionId::new(kr_ipc::new_uuid());
        let change_set_id = change_set(&store);
        store
            .begin_apply(&ApplyRow {
                action_id,
                change_set_id,
                version: ChangeSetVersion::new(1),
                workspace_id: None,
                destination: DestinationClass::SharedExisting,
                outcome: None,
                before_version: None,
                after_version: None,
                staged_name: None,
                detail: "beginning".to_owned(),
                started_at_ms: TimestampMs::new(1),
                decided_at_ms: None,
            })
            .expect("the apply begins");
        store.plan_path(action_id, "a.txt").expect("a plan");
        store.plan_path(action_id, "b.txt").expect("a plan");
        let progress = store.progress(action_id).expect("a read");
        assert_eq!(progress.len(), 2);
        assert!(
            progress
                .iter()
                .all(|row| row.state == PathProgressState::Planned)
        );
        store
            .settle_path(
                action_id,
                &ProgressRow {
                    path: "a.txt".to_owned(),
                    state: PathProgressState::Written,
                    before_digest: Some(crate::objects::digest_of(b"before")),
                    after_digest: Some(crate::objects::digest_of(b"after")),
                    detail: "written".to_owned(),
                },
            )
            .expect("an outcome");
        let progress = store.progress(action_id).expect("a read");
        assert_eq!(progress[0].state, PathProgressState::Written);
        assert_eq!(progress[1].state, PathProgressState::Planned);
        // The apply is still undecided, which is what recovery finds.
        assert_eq!(store.undecided_applies().expect("a read").len(), 1);
        store
            .settle_apply(
                action_id,
                ApplyOutcomeClass::InterruptedApply,
                None,
                "stopped",
                TimestampMs::new(2),
            )
            .expect("the apply is settled");
        assert!(store.undecided_applies().expect("a read").is_empty());
        assert_eq!(
            store
                .apply(action_id)
                .expect("a read")
                .expect("the apply is there")
                .outcome,
            Some(ApplyOutcomeClass::InterruptedApply)
        );
    }

    #[test]
    fn a_materialisation_is_its_own_evidence() {
        // Retention has to account for every materialisation before a version is deleted, so the
        // materialisation and the evidence reference that names it commit together.
        let mut store = store();
        let change_set_id = change_set(&store);
        let row = version_row(change_set_id, 1);
        store.insert_version(&row, &[]).expect("a version");
        let materialisation_id = MaterialisationId::new(kr_ipc::new_uuid());
        store
            .insert_materialisation(&MaterialisationRow {
                materialisation_id,
                change_set_id,
                version: ChangeSetVersion::new(1),
                purpose: MaterialisationPurpose::Test,
                record: vec![7],
                directory_name: "m-1".to_owned(),
                identity: kr_transfer::ObjectIdentity {
                    device: 1,
                    file_id: 2,
                },
                created_at_ms: TimestampMs::new(11),
                released_at_ms: None,
            })
            .expect("a materialisation");
        let evidence = store
            .evidence(change_set_id, ChangeSetVersion::new(1))
            .expect("a read");
        assert_eq!(evidence.len(), 1);
        assert_eq!(evidence[0].kind, EvidenceKind::Materialisation);
        assert_eq!(
            store
                .materialisations(change_set_id, ChangeSetVersion::new(1), false)
                .expect("a read")
                .len(),
            1
        );
        store
            .release_materialisation(materialisation_id, &[8], TimestampMs::new(12))
            .expect("the release");
        assert!(
            store
                .materialisations(change_set_id, ChangeSetVersion::new(1), false)
                .expect("a read")
                .is_empty(),
            "a released materialisation is not one that still holds the version"
        );
    }

    #[test]
    fn a_store_a_later_build_wrote_is_refused_rather_than_half_read() {
        let temporary = tempfile::TempDir::new().expect("a directory on the internal disk");
        let path = temporary.path().join("changesets.sqlite");
        let environment_id = EnvironmentId::new(kr_ipc::new_uuid());
        {
            let store = Store::open(&path, environment_id).expect("a store");
            drop(store);
        }
        let connection = Connection::open(&path).expect("the fixture opens the store");
        connection
            .execute(
                "UPDATE schema_version SET version = ?1",
                params![SCHEMA_VERSION + 1],
            )
            .expect("the fixture moves it forward");
        drop(connection);
        let failure = Store::open(&path, environment_id).expect_err("a later store is refused");
        assert!(
            failure.to_string().contains("schema version"),
            "the refusal says why: {failure}"
        );
    }

    #[test]
    fn a_stored_name_this_build_does_not_know_refuses_the_row_rather_than_standing_in_for_one() {
        // A plausible enum member in place of a name this build does not write would tell a reader
        // something the store does not say. The row is refused; the store still opens.
        assert_eq!(consistency_of("something a later build wrote"), None);
        assert_eq!(outcome_of("something a later build wrote"), None);
        assert_eq!(progress_of("something a later build wrote"), None);
        assert_eq!(evidence_of("something a later build wrote"), None);
        // And every name this build writes round-trips.
        for class in SourceConsistency::EVERY {
            assert_eq!(consistency_of(consistency_text(*class)), Some(*class));
        }
        for class in ApplyOutcomeClass::EVERY {
            assert_eq!(outcome_of(outcome_text(*class)), Some(*class));
        }
    }
}
