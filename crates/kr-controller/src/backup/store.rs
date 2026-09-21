//! `backup.sqlite`: the generations this host has produced, their objects, their upload state and
//! the outbox that carries them to the service.
//!
//! # One transaction per state transition
//!
//! Every write here changes the state *and* whatever follows from it in the same transaction. A
//! generation admitted writes its object rows and its first outbox entry with it; an object that
//! finished uploading writes the publish entry with it when it was the last one; a publication
//! settles the generation and its outbox entry together. There is no point at which this host has
//! recorded half of a step, so nothing has to guess what the other half was.
//!
//! # Nothing plaintext, nothing reusable
//!
//! The store holds identities, hashes, sizes, states and the paths of staged ciphertext. It holds
//! no object key, no plaintext and no filename: those live inside the encrypted manifest, which is
//! the producer's, not this store's.
//!
//! # The store owns what privacy mode is owed
//!
//! Privacy mode does not hand this host a count to remember. It hands it a *request*, which is
//! written down before anything is attempted, and the fence it raises writes down every piece of
//! cleanup that fence implies, as one row each, in the same transaction. From then on a piece of
//! cleanup ends exactly one way: the effect and the row that discharges it commit together. There
//! is no in-memory tally, no string key and no path by which a count can be lost, because there is
//! no count: what is owed is the set of rows in [`Obligation`] form, and what is complete is the
//! absence of them.

use std::path::{Path, PathBuf};

use kr_protocol::ids::{ArchiveId, BackupGeneration, BackupObjectId};
use kr_protocol::scalars::{Digest256, KeyId, TimestampMs};
use rusqlite::{Connection, OptionalExtension, params};

use crate::error::{ControllerError, Result};

/// The schema version this build reads and writes.
pub const SCHEMA_VERSION: i64 = 2;

/// Where one generation has got to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum GenerationState {
    /// Admitted and staged on this host. Nothing has left it.
    Staging,
    /// Its objects are being uploaded.
    Uploading,
    /// Its descriptor was published and the service accepted it.
    Published,
    /// It was cancelled before anything of it was dispatched.
    Cancelled,
    /// It was dispatched and this host cannot establish what became of it.
    ///
    /// Section 23's `OUTCOME_UNKNOWN`, recorded rather than guessed at: a generation whose upload
    /// was in flight when this host stopped may or may not be at the service, and a host that
    /// wrote either answer would be writing something it does not know.
    Unknown,
}

impl GenerationState {
    /// Returns the stable name this is stored and reported under.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Staging => "staging",
            Self::Uploading => "uploading",
            Self::Published => "published",
            Self::Cancelled => "cancelled",
            Self::Unknown => "unknown",
        }
    }

    /// Returns true when nothing more will happen to this generation.
    #[must_use]
    pub const fn is_settled(self) -> bool {
        matches!(self, Self::Published | Self::Cancelled | Self::Unknown)
    }

    fn parse(text: &str) -> Result<Self> {
        match text {
            "staging" => Ok(Self::Staging),
            "uploading" => Ok(Self::Uploading),
            "published" => Ok(Self::Published),
            "cancelled" => Ok(Self::Cancelled),
            "unknown" => Ok(Self::Unknown),
            other => Err(ControllerError::registry(format!(
                "a backup generation is in state {other}, which this build does not read"
            ))),
        }
    }
}

/// Where one object has got to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ObjectState {
    /// Its ciphertext is on this host and nothing has left it.
    Staged,
    /// Its bytes are being sent.
    Uploading,
    /// The service holds it.
    Uploaded,
    /// This host cannot establish whether the service holds it.
    Unknown,
    /// Its staged ciphertext has been removed from this host.
    Removed,
}

impl ObjectState {
    /// Returns the stable name this is stored under.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Staged => "staged",
            Self::Uploading => "uploading",
            Self::Uploaded => "uploaded",
            Self::Unknown => "unknown",
            Self::Removed => "removed",
        }
    }

    fn parse(text: &str) -> Result<Self> {
        match text {
            "staged" => Ok(Self::Staged),
            "uploading" => Ok(Self::Uploading),
            "uploaded" => Ok(Self::Uploaded),
            "unknown" => Ok(Self::Unknown),
            "removed" => Ok(Self::Removed),
            other => Err(ControllerError::registry(format!(
                "a backup object is in state {other}, which this build does not read"
            ))),
        }
    }
}

/// What one outbox entry asks for next.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Step {
    /// Send one generation's objects.
    Upload,
    /// Publish its descriptor, once every object is at the service.
    Publish,
}

impl Step {
    /// Returns the stable name this is stored under.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Upload => "upload",
            Self::Publish => "publish",
        }
    }

    fn parse(text: &str) -> Result<Self> {
        match text {
            "upload" => Ok(Self::Upload),
            "publish" => Ok(Self::Publish),
            other => Err(ControllerError::registry(format!(
                "a backup outbox entry asks for {other}, which this build does not read"
            ))),
        }
    }
}

/// One piece of cleanup a privacy fence implies, by kind.
///
/// The kind and its target are the identity. A failure writes a diagnostic beside the row and
/// never changes either, so a retry finds the same obligation rather than a second one, and a
/// message this host could not write is never the thing that decides whether cleanup is complete.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ObligationKind {
    /// Raise the fence this request asked for, and write down everything it implies.
    ///
    /// It exists from the moment the request is accepted, which is before the activation is
    /// attempted. An activation that fails therefore leaves the request and this row behind, and
    /// nothing else on this host can clear it.
    ActivateFence,
    /// Take back one outbox entry that was admitted and never dispatched.
    CancelEntry,
    /// Remove one staged ciphertext file.
    UnlinkObject,
    /// Establish what became of one upload attempt that had already left this host.
    ResolveUpload,
    /// Establish what became of one publication attempt that had already left this host.
    ResolvePublication,
    /// Finish one generation's bookkeeping, once its removals and attempts are done.
    FinishGeneration,
    /// Walk this store's staging directory for ciphertext no object row names.
    ScanStaging,
}

impl ObligationKind {
    /// Returns the stable name this is stored under.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ActivateFence => "activate_fence",
            Self::CancelEntry => "cancel_entry",
            Self::UnlinkObject => "unlink_object",
            Self::ResolveUpload => "resolve_upload",
            Self::ResolvePublication => "resolve_publication",
            Self::FinishGeneration => "finish_generation",
            Self::ScanStaging => "scan_staging",
        }
    }

    fn parse(text: &str) -> Result<Self> {
        match text {
            "activate_fence" => Ok(Self::ActivateFence),
            "cancel_entry" => Ok(Self::CancelEntry),
            "unlink_object" => Ok(Self::UnlinkObject),
            "resolve_upload" => Ok(Self::ResolveUpload),
            "resolve_publication" => Ok(Self::ResolvePublication),
            "finish_generation" => Ok(Self::FinishGeneration),
            "scan_staging" => Ok(Self::ScanStaging),
            other => Err(ControllerError::registry(format!(
                "a backup cleanup obligation is of kind {other}, which this build does not read"
            ))),
        }
    }
}

/// One outstanding piece of cleanup, as the store holds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Obligation {
    /// Its row identity, which is what a discharge names.
    pub id: i64,
    /// The privacy generation whose fence this cleanup belongs to.
    pub privacy_generation: u64,
    /// What has to be done.
    pub kind: ObligationKind,
    /// The exact thing it has to be done to, as a stable key.
    pub target_key: String,
    /// The archive, where the kind has one.
    pub archive_id: Option<ArchiveId>,
    /// The backup generation, where the kind has one.
    pub backup_generation: Option<BackupGeneration>,
    /// The object, where the kind has one.
    pub object_id: Option<BackupObjectId>,
    /// The file to remove, where the kind has one. Relative paths are under the staging root.
    pub staged_path: Option<PathBuf>,
    /// The outbox entry whose attempt this is about, where the kind has one.
    pub entry_sequence: Option<u64>,
    /// When it was recorded.
    pub recorded_at_ms: TimestampMs,
    /// How many times this host has tried.
    pub attempt_count: u64,
    /// What went wrong last time, which is diagnostic and never the clearance condition.
    pub last_error: Option<String>,
}

impl Obligation {
    /// Returns a line naming what is owed, for a report a person reads.
    #[must_use]
    pub fn describe(&self) -> String {
        match self.last_error.as_deref() {
            Some(error) => format!(
                "{} {} (privacy generation {}, {} attempts, last error: {error})",
                self.kind.as_str(),
                self.target_key,
                self.privacy_generation,
                self.attempt_count
            ),
            None => format!(
                "{} {} (privacy generation {})",
                self.kind.as_str(),
                self.target_key,
                self.privacy_generation
            ),
        }
    }
}

/// Where this host stands with privacy mode, as the store holds it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PrivacyStatus {
    /// The privacy generation in force.
    pub current_generation: u64,
    /// Whether privacy mode is on.
    pub enabled: bool,
    /// The oldest accepted request whose fence has not been raised, if there is one.
    pub pending_activation: Option<u64>,
    /// The oldest fence that has not been released, if there is one.
    pub unreleased_fence: Option<u64>,
    /// How many pieces of cleanup are outstanding across every fence.
    pub obligations: u64,
}

impl PrivacyStatus {
    /// Returns the privacy generation backup production is stopped at, if it is stopped.
    ///
    /// A request whose fence has not gone up stops production as firmly as a fence that has: this
    /// host has been told to stop, and work admitted in between would be work inside a cleanup
    /// scope nothing had written down yet.
    #[must_use]
    pub fn inhibited_at(&self) -> Option<u64> {
        match (self.pending_activation, self.unreleased_fence) {
            (Some(request), Some(fence)) => Some(request.min(fence)),
            (Some(generation), None) | (None, Some(generation)) => Some(generation),
            (None, None) => None,
        }
    }

    /// Returns true when every fence this host raised has been cleaned up and released.
    #[must_use]
    pub fn is_settled(&self) -> bool {
        self.pending_activation.is_none()
            && self.unreleased_fence.is_none()
            && self.obligations == 0
    }
}

/// What accepting one privacy request did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrivacyRequest {
    /// The generation that was asked for.
    pub privacy_generation: u64,
    /// When this host first accepted it.
    pub requested_at_ms: TimestampMs,
    /// When its fence was raised, if it has been.
    pub applied_at_ms: Option<TimestampMs>,
}

impl PrivacyRequest {
    /// Returns true when the fence this request asked for has been raised.
    #[must_use]
    pub const fn is_applied(&self) -> bool {
        self.applied_at_ms.is_some()
    }
}

/// What releasing one fence did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FenceRelease {
    /// The fence is released and production resumes under the generation that was named.
    Released,
    /// The fence stands, because this is what is still owed under it.
    Pending {
        /// How many pieces of cleanup are outstanding under that fence.
        obligations: u64,
    },
    /// There is no unreleased fence at that generation to release.
    NotHeld,
}

/// One generation, as the store holds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GenerationRecord {
    /// The archive.
    pub archive_id: ArchiveId,
    /// The generation.
    pub backup_generation: BackupGeneration,
    /// Where it has got to.
    pub state: GenerationState,
    /// The writer whose signature its manifest and publication carry.
    pub writer_key_id: KeyId,
    /// The privacy generation it was admitted under.
    ///
    /// A result that comes back carrying another one belongs to work privacy mode has already
    /// drawn a line under, and is not published.
    pub privacy_generation: u64,
    /// The canonical descriptor bytes, once the generation has been sealed.
    pub descriptor: Option<Vec<u8>>,
    /// When it was admitted.
    pub created_at_ms: TimestampMs,
    /// When it settled, if it has.
    pub settled_at_ms: Option<TimestampMs>,
    /// What this host can say about it beyond its state.
    pub detail: Option<String>,
}

/// One object of one generation, as the store holds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectRecord {
    /// The archive.
    pub archive_id: ArchiveId,
    /// The generation.
    pub backup_generation: BackupGeneration,
    /// The object.
    pub object_id: BackupObjectId,
    /// The SHA-256 of its ciphertext.
    pub encrypted_object_hash: Digest256,
    /// The size of its ciphertext.
    pub encrypted_len: u64,
    /// Where its ciphertext is staged on this host.
    pub staged_path: PathBuf,
    /// How many bytes the service has acknowledged, so a resume knows where to continue.
    pub uploaded_bytes: u64,
    /// Where it has got to.
    pub state: ObjectState,
}

/// One outbox entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutboxEntry {
    /// Its position in the outbox.
    pub sequence: u64,
    /// The archive.
    pub archive_id: ArchiveId,
    /// The generation.
    pub backup_generation: BackupGeneration,
    /// What it asks for.
    pub step: Step,
    /// The privacy generation the work was admitted under.
    pub privacy_generation: u64,
    /// Whether it has been handed to the service.
    pub dispatched: bool,
}

/// The backup store of one environment.
#[derive(Debug)]
pub struct BackupStore {
    connection: Connection,
    staging_root: PathBuf,
}

impl BackupStore {
    /// Opens the store beside `state_dir`, creating it and its staging directory on first use.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the database cannot be opened or
    /// migrated, or the staging directory cannot be made.
    pub fn open(state_dir: &Path) -> Result<Self> {
        let staging_root = state_dir.join("backup");
        std::fs::create_dir_all(&staging_root).map_err(ControllerError::registry)?;
        let connection =
            Connection::open(state_dir.join("backup.sqlite")).map_err(ControllerError::registry)?;
        Self::prepare(connection, staging_root)
    }

    /// Opens a store that exists only for the life of this process.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the database cannot be created.
    pub fn in_memory(staging_root: &Path) -> Result<Self> {
        std::fs::create_dir_all(staging_root).map_err(ControllerError::registry)?;
        Self::prepare(
            Connection::open_in_memory().map_err(ControllerError::registry)?,
            staging_root.to_path_buf(),
        )
    }

    fn prepare(connection: Connection, staging_root: PathBuf) -> Result<Self> {
        // The staging root is held absolute, whatever the caller passed. Every object row names an
        // absolute path under it, and cleanup joins the root only to what the staging walk found,
        // which is relative to it. A relative root would make a registered path look relative too,
        // and cleanup would go looking for it underneath itself, find nothing, and take the
        // absence for a removal it had performed.
        let staging_root = if staging_root.is_absolute() {
            staging_root
        } else {
            std::env::current_dir()
                .map_err(ControllerError::registry)?
                .join(staging_root)
        };
        connection
            .pragma_update(None, "journal_mode", "WAL")
            .map_err(ControllerError::registry)?;
        connection
            .pragma_update(None, "synchronous", "FULL")
            .map_err(ControllerError::registry)?;
        connection
            .pragma_update(None, "foreign_keys", "ON")
            .map_err(ControllerError::registry)?;
        let store = Self {
            connection,
            staging_root,
        };
        store.migrate()?;
        Ok(store)
    }

    fn migrate(&self) -> Result<()> {
        // A store that records a version already has its tables. Creating a missing one would turn
        // a lost fence or a lost set of cleanup obligations into an empty table, which reads as
        // "nothing was fenced" and "nothing is owed": the two answers a host must never guess.
        let existing: Option<i64> = self
            .connection
            .query_row("SELECT version FROM schema_version", [], |row| row.get(0))
            .optional()
            .unwrap_or(None);
        if let Some(version) = existing {
            if version != SCHEMA_VERSION {
                return Err(ControllerError::RegistryUnavailable {
                    detail: format!(
                        "this backup store is at schema version {version}; this build reads \
                         {SCHEMA_VERSION}"
                    ),
                });
            }
            for table in [
                "generations",
                "objects",
                "outbox",
                "writers",
                "privacy_state",
                "privacy_requests",
                "privacy_fences",
                "privacy_obligations",
            ] {
                let present: i64 = self
                    .connection
                    .query_row(
                        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
                        params![table],
                        |row| row.get(0),
                    )
                    .map_err(ControllerError::registry)?;
                if present == 0 {
                    return Err(ControllerError::RegistryUnavailable {
                        detail: format!(
                            "this backup store is missing its {table} table, so what it recorded \
                             cannot be established"
                        ),
                    });
                }
            }
            return Ok(());
        }
        self.connection
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL);
                 CREATE TABLE IF NOT EXISTS generations (
                     archive_id         BLOB NOT NULL,
                     backup_generation  INTEGER NOT NULL,
                     state              TEXT NOT NULL,
                     writer_key_id      BLOB NOT NULL,
                     privacy_generation INTEGER NOT NULL,
                     descriptor         BLOB,
                     created_at_ms      INTEGER NOT NULL,
                     settled_at_ms      INTEGER,
                     detail             TEXT,
                     PRIMARY KEY (archive_id, backup_generation)
                 );
                 CREATE TABLE IF NOT EXISTS objects (
                     archive_id        BLOB NOT NULL,
                     backup_generation INTEGER NOT NULL,
                     object_id         BLOB NOT NULL,
                     encrypted_hash    BLOB NOT NULL,
                     encrypted_len     INTEGER NOT NULL,
                     staged_path       TEXT NOT NULL,
                     uploaded_bytes    INTEGER NOT NULL DEFAULT 0,
                     state             TEXT NOT NULL,
                     PRIMARY KEY (archive_id, backup_generation, object_id),
                     FOREIGN KEY (archive_id, backup_generation)
                         REFERENCES generations (archive_id, backup_generation)
                         ON DELETE CASCADE
                 );
                 CREATE TABLE IF NOT EXISTS outbox (
                     sequence           INTEGER PRIMARY KEY AUTOINCREMENT,
                     archive_id         BLOB NOT NULL,
                     backup_generation  INTEGER NOT NULL,
                     step               TEXT NOT NULL,
                     privacy_generation INTEGER NOT NULL,
                     dispatched         INTEGER NOT NULL DEFAULT 0,
                     enqueued_at_ms     INTEGER NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS writers (
                     archive_id     BLOB NOT NULL,
                     writer_key_id  BLOB NOT NULL,
                     enrolled_at_ms INTEGER NOT NULL,
                     retired_at_ms  INTEGER,
                     PRIMARY KEY (archive_id, writer_key_id)
                 );
                 CREATE TABLE IF NOT EXISTS privacy_state (
                     id                 INTEGER PRIMARY KEY CHECK (id = 0),
                     current_generation INTEGER NOT NULL,
                     enabled            INTEGER NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS privacy_requests (
                     privacy_generation INTEGER PRIMARY KEY,
                     requested_at_ms    INTEGER NOT NULL,
                     applied_at_ms      INTEGER
                 );
                 CREATE TABLE IF NOT EXISTS privacy_fences (
                     privacy_generation INTEGER PRIMARY KEY
                         REFERENCES privacy_requests (privacy_generation),
                     raised_at_ms       INTEGER NOT NULL,
                     released_at_ms     INTEGER
                 );
                 CREATE TABLE IF NOT EXISTS privacy_obligations (
                     id                 INTEGER PRIMARY KEY AUTOINCREMENT,
                     privacy_generation INTEGER NOT NULL
                         REFERENCES privacy_requests (privacy_generation),
                     kind               TEXT NOT NULL,
                     target_key         TEXT NOT NULL,
                     archive_id         BLOB,
                     backup_generation  INTEGER,
                     object_id          BLOB,
                     staged_path        TEXT,
                     entry_sequence     INTEGER,
                     recorded_at_ms     INTEGER NOT NULL,
                     attempt_count      INTEGER NOT NULL DEFAULT 0,
                     last_error_code    TEXT,
                     last_error_at_ms   INTEGER,
                     UNIQUE (privacy_generation, kind, target_key),
                     CHECK (kind IN ('activate_fence', 'cancel_entry', 'unlink_object',
                                     'resolve_upload', 'resolve_publication',
                                     'finish_generation', 'scan_staging')),
                     CHECK (kind <> 'activate_fence'
                            OR (archive_id IS NULL AND backup_generation IS NULL
                                AND object_id IS NULL AND staged_path IS NULL
                                AND entry_sequence IS NULL)),
                     CHECK (kind <> 'cancel_entry'
                            OR (entry_sequence IS NOT NULL AND archive_id IS NOT NULL
                                AND backup_generation IS NOT NULL)),
                     CHECK (kind <> 'unlink_object' OR staged_path IS NOT NULL),
                     CHECK (kind NOT IN ('resolve_upload', 'resolve_publication')
                            OR (entry_sequence IS NOT NULL AND archive_id IS NOT NULL
                                AND backup_generation IS NOT NULL)),
                     CHECK (kind <> 'finish_generation'
                            OR (archive_id IS NOT NULL AND backup_generation IS NOT NULL
                                AND staged_path IS NULL AND entry_sequence IS NULL)),
                     CHECK (kind <> 'scan_staging'
                            OR (archive_id IS NULL AND backup_generation IS NULL
                                AND object_id IS NULL AND entry_sequence IS NULL))
                 );
                 CREATE TRIGGER IF NOT EXISTS a_released_fence_takes_no_obligation
                 BEFORE INSERT ON privacy_obligations
                 WHEN EXISTS (SELECT 1 FROM privacy_fences
                               WHERE privacy_generation = NEW.privacy_generation
                                 AND released_at_ms IS NOT NULL)
                 BEGIN
                     SELECT RAISE(ABORT, 'that privacy fence is released and takes no further \
                                          cleanup');
                 END;
                 CREATE TRIGGER IF NOT EXISTS a_fence_keeps_its_obligations
                 BEFORE UPDATE OF released_at_ms ON privacy_fences
                 WHEN NEW.released_at_ms IS NOT NULL AND OLD.released_at_ms IS NULL
                  AND EXISTS (SELECT 1 FROM privacy_obligations
                               WHERE privacy_generation = OLD.privacy_generation)
                 BEGIN
                     SELECT RAISE(ABORT, 'that privacy fence still has cleanup outstanding');
                 END;
                 CREATE TRIGGER IF NOT EXISTS a_fence_with_obligations_is_not_deleted
                 BEFORE DELETE ON privacy_fences
                 WHEN EXISTS (SELECT 1 FROM privacy_obligations
                               WHERE privacy_generation = OLD.privacy_generation)
                 BEGIN
                     SELECT RAISE(ABORT, 'that privacy fence still has cleanup outstanding');
                 END;
                 CREATE TRIGGER IF NOT EXISTS a_fence_is_not_replaced_while_it_is_owed
                 BEFORE INSERT ON privacy_fences
                 WHEN EXISTS (SELECT 1 FROM privacy_obligations
                               WHERE privacy_generation = NEW.privacy_generation
                                 AND kind <> 'activate_fence')
                 BEGIN
                     SELECT RAISE(ABORT, 'that privacy fence still has cleanup outstanding');
                 END;
                 CREATE TRIGGER IF NOT EXISTS a_fence_keeps_the_generation_it_was_raised_at
                 BEFORE UPDATE OF privacy_generation ON privacy_fences
                 WHEN NEW.privacy_generation <> OLD.privacy_generation
                 BEGIN
                     SELECT RAISE(ABORT, 'a privacy fence keeps the generation it was raised at');
                 END;
                 CREATE TRIGGER IF NOT EXISTS an_obligation_keeps_the_fence_it_was_written_under
                 BEFORE UPDATE OF privacy_generation ON privacy_obligations
                 WHEN NEW.privacy_generation <> OLD.privacy_generation
                 BEGIN
                     SELECT RAISE(ABORT, 'cleanup keeps the fence it was written under');
                 END;
                 INSERT INTO privacy_state (id, current_generation, enabled) VALUES (0, 0, 0);",
            )
            .map_err(ControllerError::registry)?;
        self.connection
            .execute(
                "INSERT INTO schema_version (version) VALUES (?1)",
                params![SCHEMA_VERSION],
            )
            .map_err(ControllerError::registry)?;
        Ok(())
    }

    /// Returns the directory staged ciphertext lives in.
    #[must_use]
    pub fn staging_root(&self) -> &Path {
        &self.staging_root
    }

    /// Returns where one object's ciphertext is staged.
    #[must_use]
    pub fn staged_path(
        &self,
        archive_id: ArchiveId,
        backup_generation: BackupGeneration,
        object_id: BackupObjectId,
    ) -> PathBuf {
        self.staging_root
            .join(format!("{}-{}", archive_id, backup_generation.get()))
            .join(format!("{object_id}.krb"))
    }

    /// Admits one generation: its record, its object rows and its first outbox entry, together.
    ///
    /// Together is the point. A generation recorded without its outbox entry would be work this
    /// host had taken on and would never do; an outbox entry without its generation would be work
    /// with no account of what it was for.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store refuses the write.
    pub fn admit(
        &mut self,
        record: &GenerationRecord,
        objects: &[ObjectRecord],
        now_ms: TimestampMs,
    ) -> Result<u64> {
        let transaction = self
            .connection
            .transaction()
            .map_err(ControllerError::registry)?;
        transaction
            .execute(
                "INSERT INTO generations
                     (archive_id, backup_generation, state, writer_key_id, privacy_generation,
                      descriptor, created_at_ms, settled_at_ms, detail)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, NULL, NULL)",
                params![
                    record.archive_id.get().as_bytes().as_slice(),
                    i64::try_from(record.backup_generation.get()).unwrap_or(i64::MAX),
                    record.state.as_str(),
                    record.writer_key_id.as_bytes().as_slice(),
                    i64::try_from(record.privacy_generation).unwrap_or(i64::MAX),
                    record.descriptor.as_deref(),
                    millis(record.created_at_ms),
                ],
            )
            .map_err(ControllerError::registry)?;
        for object in objects {
            transaction
                .execute(
                    "INSERT INTO objects
                         (archive_id, backup_generation, object_id, encrypted_hash, encrypted_len,
                          staged_path, uploaded_bytes, state)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                    params![
                        object.archive_id.get().as_bytes().as_slice(),
                        i64::try_from(object.backup_generation.get()).unwrap_or(i64::MAX),
                        object.object_id.get().as_bytes().as_slice(),
                        object.encrypted_object_hash.as_bytes().as_slice(),
                        i64::try_from(object.encrypted_len).unwrap_or(i64::MAX),
                        object.staged_path.to_string_lossy().as_ref(),
                        i64::try_from(object.uploaded_bytes).unwrap_or(i64::MAX),
                        object.state.as_str(),
                    ],
                )
                .map_err(ControllerError::registry)?;
        }
        let sequence = enqueue(
            &transaction,
            record.archive_id,
            record.backup_generation,
            Step::Upload,
            record.privacy_generation,
            now_ms,
        )?;
        transaction.commit().map_err(ControllerError::registry)?;
        Ok(sequence)
    }

    /// Records that one object's bytes reached the service.
    ///
    /// Returns true when the generation has no object left to arrive. That is a fact about the
    /// object rows and not about the call, so an acknowledgement repeated after the upload
    /// finished returns true again, whatever became of the generation afterwards.
    ///
    /// What happens in the same transaction depends on what the generation is still allowed to do.
    /// Ordinarily the publish step is enqueued, because a host that wrote the last object and then
    /// died would otherwise have a complete upload nothing publishes. A generation privacy mode
    /// cancelled, or one finishing while production is fenced, gets no publication: its upload
    /// step is taken out of the outbox instead, so the cleanup it owed is finished rather than
    /// turned into a late result.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store refuses the write.
    pub fn note_object_uploaded(
        &mut self,
        archive_id: ArchiveId,
        backup_generation: BackupGeneration,
        object_id: BackupObjectId,
        now_ms: TimestampMs,
    ) -> Result<bool> {
        let transaction = self
            .connection
            .transaction()
            .map_err(ControllerError::registry)?;
        let uploaded_len: Option<i64> = transaction
            .query_row(
                "SELECT encrypted_len FROM objects
                 WHERE archive_id = ?1 AND backup_generation = ?2 AND object_id = ?3",
                params![
                    archive_id.get().as_bytes().as_slice(),
                    i64::try_from(backup_generation.get()).unwrap_or(i64::MAX),
                    object_id.get().as_bytes().as_slice(),
                ],
                |row| row.get(0),
            )
            .optional()
            .map_err(ControllerError::registry)?;
        let Some(uploaded_len) = uploaded_len else {
            return Err(ControllerError::registry(
                "that object is not one this host staged",
            ));
        };
        // What the service has is written down whatever else is true of the object. Where its
        // ciphertext is, is a separate fact, and an acknowledgement does not put a file back: an
        // object privacy mode has already removed stays removed, and saying it was staged here
        // again would be a record that named a file this host does not hold.
        transaction
            .execute(
                "UPDATE objects SET uploaded_bytes = ?4
                 WHERE archive_id = ?1 AND backup_generation = ?2 AND object_id = ?3",
                params![
                    archive_id.get().as_bytes().as_slice(),
                    i64::try_from(backup_generation.get()).unwrap_or(i64::MAX),
                    object_id.get().as_bytes().as_slice(),
                    uploaded_len,
                ],
            )
            .map_err(ControllerError::registry)?;
        transaction
            .execute(
                "UPDATE objects SET state = ?4
                 WHERE archive_id = ?1 AND backup_generation = ?2 AND object_id = ?3
                   AND state <> ?5",
                params![
                    archive_id.get().as_bytes().as_slice(),
                    i64::try_from(backup_generation.get()).unwrap_or(i64::MAX),
                    object_id.get().as_bytes().as_slice(),
                    ObjectState::Uploaded.as_str(),
                    ObjectState::Removed.as_str(),
                ],
            )
            .map_err(ControllerError::registry)?;
        transaction
            .execute(
                "UPDATE generations SET state = ?3
                 WHERE archive_id = ?1 AND backup_generation = ?2 AND state = ?4",
                params![
                    archive_id.get().as_bytes().as_slice(),
                    i64::try_from(backup_generation.get()).unwrap_or(i64::MAX),
                    GenerationState::Uploading.as_str(),
                    GenerationState::Staging.as_str(),
                ],
            )
            .map_err(ControllerError::registry)?;

        // What is left to arrive. An object whose staged copy privacy mode has since removed still
        // counts as arrived when the service had acknowledged all of its bytes first: the state
        // then says where the ciphertext is and `uploaded_bytes` says what the service has, and
        // reading the removal as an object still to come would leave a generation whose transfers
        // had all finished waiting on one of them for ever.
        let outstanding: i64 = transaction
            .query_row(
                "SELECT COUNT(*) FROM objects
                 WHERE archive_id = ?1 AND backup_generation = ?2
                   AND state <> ?3
                   AND NOT (state = ?4 AND uploaded_bytes >= encrypted_len)",
                params![
                    archive_id.get().as_bytes().as_slice(),
                    i64::try_from(backup_generation.get()).unwrap_or(i64::MAX),
                    ObjectState::Uploaded.as_str(),
                    ObjectState::Removed.as_str(),
                ],
                |row| row.get(0),
            )
            .map_err(ControllerError::registry)?;
        // A generation that has settled takes no more transitions. Its outbox is empty by
        // definition, and an acknowledgement arriving afterwards must not put work back into it.
        let state: String = transaction
            .query_row(
                "SELECT state FROM generations WHERE archive_id = ?1 AND backup_generation = ?2",
                params![
                    archive_id.get().as_bytes().as_slice(),
                    i64::try_from(backup_generation.get()).unwrap_or(i64::MAX),
                ],
                |row| row.get(0),
            )
            .map_err(ControllerError::registry)?;
        let gen_state = GenerationState::parse(&state)?;
        let complete = outstanding == 0;
        if complete && gen_state.is_settled() {
            // A settled generation takes no more transitions, and nothing is enqueued for it. What
            // is left to do is end the wait its outbox may still hold: a generation privacy mode
            // cancelled while its upload was in flight keeps that entry until the transfer ends,
            // and this acknowledgement is the end of it. A publication that had already left stays,
            // because its answer has not. A published generation and one whose outcome is unknown
            // have empty outboxes already, so this does nothing to them.
            clear_unfinished_work(&transaction, archive_id, backup_generation)?;
            try_finish_generation(&transaction, archive_id, backup_generation)?;
            transaction.commit().map_err(ControllerError::registry)?;
            return Ok(true);
        }
        if complete {
            let fenced_at = inhibited_at(&transaction)?;
            if let Some(fenced_at) = fenced_at {
                // A fence enqueues no publication. The upload step goes rather than being left for
                // a dispatch after the fence is released, and the generation settles as cancelled.
                //
                // Unless a publication left this host before the fence: that one is still owed an
                // answer, so its entry stays and the record stays unsettled until the answer says
                // what became of it. Publishing it is not what that allows; the late-result rule
                // in `note_published` is what decides that, and it refuses a result produced under
                // a privacy generation the fence has moved past.
                let publication_owed =
                    clear_unfinished_work(&transaction, archive_id, backup_generation)?;
                if !publication_owed {
                    transaction
                        .execute(
                            "UPDATE generations SET state = ?3, settled_at_ms = ?4, detail = ?5
                             WHERE archive_id = ?1 AND backup_generation = ?2",
                            params![
                                archive_id.get().as_bytes().as_slice(),
                                i64::try_from(backup_generation.get()).unwrap_or(i64::MAX),
                                GenerationState::Cancelled.as_str(),
                                millis(now_ms),
                                format!(
                                    "privacy mode fenced backup production at privacy generation {fenced_at} before publication was enqueued"
                                ),
                            ],
                        )
                        .map_err(ControllerError::registry)?;
                }
                try_finish_generation(&transaction, archive_id, backup_generation)?;
                transaction.commit().map_err(ControllerError::registry)?;
                return Ok(true);
            }

            // Exactly one publish entry, and the upload entry goes with it. A second
            // acknowledgement of an object that had already arrived would otherwise enqueue a
            // second publication, and reconciliation would resume an upload that had finished.
            let already: i64 = transaction
                .query_row(
                    "SELECT COUNT(*) FROM outbox
                     WHERE archive_id = ?1 AND backup_generation = ?2 AND step = ?3",
                    params![
                        archive_id.get().as_bytes().as_slice(),
                        i64::try_from(backup_generation.get()).unwrap_or(i64::MAX),
                        Step::Publish.as_str(),
                    ],
                    |row| row.get(0),
                )
                .map_err(ControllerError::registry)?;
            if already == 0 {
                let privacy_generation: i64 = transaction
                    .query_row(
                        "SELECT privacy_generation FROM generations
                         WHERE archive_id = ?1 AND backup_generation = ?2",
                        params![
                            archive_id.get().as_bytes().as_slice(),
                            i64::try_from(backup_generation.get()).unwrap_or(i64::MAX),
                        ],
                        |row| row.get(0),
                    )
                    .map_err(ControllerError::registry)?;
                transaction
                    .execute(
                        "DELETE FROM outbox
                         WHERE archive_id = ?1 AND backup_generation = ?2 AND step = ?3",
                        params![
                            archive_id.get().as_bytes().as_slice(),
                            i64::try_from(backup_generation.get()).unwrap_or(i64::MAX),
                            Step::Upload.as_str(),
                        ],
                    )
                    .map_err(ControllerError::registry)?;
                enqueue(
                    &transaction,
                    archive_id,
                    backup_generation,
                    Step::Publish,
                    u64::try_from(privacy_generation).unwrap_or(0),
                    now_ms,
                )?;
            }
        }
        transaction.commit().map_err(ControllerError::registry)?;
        Ok(complete)
    }

    /// Records that one outbox entry has been handed to the service.
    ///
    /// From here on the outcome is not this host's to decide. A dispatched entry whose answer
    /// never arrives is what [`Self::reconcile`] records as unknown.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store refuses the write.
    pub fn note_dispatched(&mut self, sequence: u64) -> Result<()> {
        // Exactly one undispatched entry, claimed. A row that is already dispatched, or gone
        // because its generation settled, is not something this host may dispatch again: the first
        // would be a second send of work already out there, and the second would be work nothing
        // accounts for.
        let claimed = self
            .connection
            .execute(
                "UPDATE outbox SET dispatched = 1 WHERE sequence = ?1 AND dispatched = 0",
                params![i64::try_from(sequence).unwrap_or(i64::MAX)],
            )
            .map_err(ControllerError::registry)?;
        if claimed == 1 {
            Ok(())
        } else {
            Err(ControllerError::registry(
                "that outbox entry is not one this host holds undispatched",
            ))
        }
    }

    /// Records where one generation ended up, and drops the work it had not yet started.
    ///
    /// An entry this host still holds is this host's to drop. An attempt that had already left is
    /// **not**: it keeps its row and whatever obligation names it, because a record written here
    /// says nothing about what became of it. [`Self::settle_ended_attempts`] is the call for a
    /// caller that has actually established the end of one.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store refuses the write.
    pub fn settle(
        &mut self,
        archive_id: ArchiveId,
        backup_generation: BackupGeneration,
        state: GenerationState,
        detail: Option<&str>,
        now_ms: TimestampMs,
    ) -> Result<()> {
        self.record_settlement(archive_id, backup_generation, state, detail, now_ms, false)
    }

    /// Records where one generation ended up, and ends every attempt of it that had left.
    ///
    /// The caller is stating that those attempts are over: the service answered, or the transfer
    /// stopped and no answer will come. Their rows and the obligations that name them go together
    /// with the settlement, in one transaction.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store refuses the write.
    pub fn settle_ended_attempts(
        &mut self,
        archive_id: ArchiveId,
        backup_generation: BackupGeneration,
        state: GenerationState,
        detail: Option<&str>,
        now_ms: TimestampMs,
    ) -> Result<()> {
        self.record_settlement(archive_id, backup_generation, state, detail, now_ms, true)
    }

    fn record_settlement(
        &mut self,
        archive_id: ArchiveId,
        backup_generation: BackupGeneration,
        state: GenerationState,
        detail: Option<&str>,
        now_ms: TimestampMs,
        attempts_ended: bool,
    ) -> Result<()> {
        let transaction = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(ControllerError::registry)?;
        apply_settlement(
            &transaction,
            archive_id,
            backup_generation,
            state,
            detail,
            now_ms,
            attempts_ended,
        )?;
        transaction.commit().map_err(ControllerError::registry)
    }

    /// Records that the service accepted one generation's publication.
    ///
    /// Every condition is read inside the transaction that records the result, and every one of
    /// them is this store's rather than the caller's. The caller says which privacy generation the
    /// work it is reporting on was produced under; the store says which generation it admitted the
    /// work under and which is in force, and a caller cannot relabel work privacy mode has already
    /// drawn a line under by naming a different one.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::Refused`] when the result belongs to another privacy generation
    /// or a fence stands, and [`ControllerError::RegistryUnavailable`] when the store refuses the
    /// write.
    pub fn note_published(
        &mut self,
        archive_id: ArchiveId,
        backup_generation: BackupGeneration,
        produced_under: u64,
        now_ms: TimestampMs,
    ) -> Result<()> {
        let archive = archive_id.get().as_bytes().to_vec();
        let generation = i64::try_from(backup_generation.get()).unwrap_or(i64::MAX);
        let transaction = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(ControllerError::registry)?;
        let admitted_under: Option<i64> = transaction
            .query_row(
                "SELECT privacy_generation FROM generations
                  WHERE archive_id = ?1 AND backup_generation = ?2",
                params![archive, generation],
                |row| row.get(0),
            )
            .optional()
            .map_err(ControllerError::registry)?;
        let Some(admitted_under) = admitted_under else {
            return Err(ControllerError::registry(
                "that backup generation is not one this host admitted",
            ));
        };
        let admitted_under = u64::try_from(admitted_under).unwrap_or(0);
        if admitted_under != produced_under {
            return Err(ControllerError::Refused {
                code: kr_protocol::error::ErrorCode::PermissionDenied,
                detail: format!(
                    "that backup result claims privacy generation {produced_under}, and this \
                     host admitted the work under {admitted_under}"
                ),
            });
        }
        if let Some(fenced_at) = inhibited_at(&transaction)? {
            return Err(ControllerError::Refused {
                code: kr_protocol::error::ErrorCode::PermissionDenied,
                detail: format!(
                    "backup production is fenced at privacy generation {fenced_at}, so no \
                     publication is recorded"
                ),
            });
        }
        let current: i64 = transaction
            .query_row(
                "SELECT current_generation FROM privacy_state WHERE id = 0",
                [],
                |row| row.get(0),
            )
            .map_err(ControllerError::registry)?;
        let current = u64::try_from(current).unwrap_or(0);
        if admitted_under != current {
            return Err(ControllerError::Refused {
                code: kr_protocol::error::ErrorCode::PermissionDenied,
                detail: format!(
                    "that backup result was produced under privacy generation \
                     {admitted_under}, and this host is at {current}"
                ),
            });
        }
        apply_settlement(
            &transaction,
            archive_id,
            backup_generation,
            GenerationState::Published,
            None,
            now_ms,
            // The service answered, so that publication attempt is over: its row and whatever
            // obligation named it end with the settlement.
            true,
        )?;
        transaction.commit().map_err(ControllerError::registry)
    }

    /// Records the descriptor a generation was sealed with.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store refuses the write.
    pub fn record_descriptor(
        &mut self,
        archive_id: ArchiveId,
        backup_generation: BackupGeneration,
        descriptor: &[u8],
    ) -> Result<()> {
        self.connection
            .execute(
                "UPDATE generations SET descriptor = ?3
                 WHERE archive_id = ?1 AND backup_generation = ?2",
                params![
                    archive_id.get().as_bytes().as_slice(),
                    i64::try_from(backup_generation.get()).unwrap_or(i64::MAX),
                    descriptor,
                ],
            )
            .map_err(ControllerError::registry)?;
        Ok(())
    }

    /// Returns one generation's record.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store cannot be read.
    pub fn generation(
        &self,
        archive_id: ArchiveId,
        backup_generation: BackupGeneration,
    ) -> Result<Option<GenerationRecord>> {
        self.connection
            .query_row(
                "SELECT archive_id, backup_generation, state, writer_key_id, privacy_generation,
                        descriptor, created_at_ms, settled_at_ms, detail
                 FROM generations WHERE archive_id = ?1 AND backup_generation = ?2",
                params![
                    archive_id.get().as_bytes().as_slice(),
                    i64::try_from(backup_generation.get()).unwrap_or(i64::MAX),
                ],
                read_generation,
            )
            .optional()
            .map_err(ControllerError::registry)?
            .transpose()
    }

    /// Returns every generation, oldest first.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store cannot be read.
    pub fn generations(&self) -> Result<Vec<GenerationRecord>> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT archive_id, backup_generation, state, writer_key_id, privacy_generation,
                        descriptor, created_at_ms, settled_at_ms, detail
                 FROM generations ORDER BY created_at_ms, backup_generation",
            )
            .map_err(ControllerError::registry)?;
        let rows = statement
            .query_map([], read_generation)
            .map_err(ControllerError::registry)?;
        let mut records = Vec::new();
        for row in rows {
            records.push(row.map_err(ControllerError::registry)??);
        }
        Ok(records)
    }

    /// Returns one generation's objects.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store cannot be read.
    pub fn objects(
        &self,
        archive_id: ArchiveId,
        backup_generation: BackupGeneration,
    ) -> Result<Vec<ObjectRecord>> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT archive_id, backup_generation, object_id, encrypted_hash, encrypted_len,
                        staged_path, uploaded_bytes, state
                 FROM objects WHERE archive_id = ?1 AND backup_generation = ?2
                 ORDER BY object_id",
            )
            .map_err(ControllerError::registry)?;
        let rows = statement
            .query_map(
                params![
                    archive_id.get().as_bytes().as_slice(),
                    i64::try_from(backup_generation.get()).unwrap_or(i64::MAX),
                ],
                read_object,
            )
            .map_err(ControllerError::registry)?;
        let mut records = Vec::new();
        for row in rows {
            records.push(row.map_err(ControllerError::registry)??);
        }
        Ok(records)
    }

    /// Returns the outbox, oldest first.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store cannot be read.
    pub fn outbox(&self) -> Result<Vec<OutboxEntry>> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT sequence, archive_id, backup_generation, step, privacy_generation,
                        dispatched
                 FROM outbox ORDER BY sequence",
            )
            .map_err(ControllerError::registry)?;
        let rows = statement
            .query_map([], read_outbox)
            .map_err(ControllerError::registry)?;
        let mut entries = Vec::new();
        for row in rows {
            entries.push(row.map_err(ControllerError::registry)??);
        }
        Ok(entries)
    }

    /// Enrols one backup writer for one archive, which is what makes its work authorised.
    ///
    /// Reconciliation after a restart reads this table: a generation whose writer is not enrolled
    /// here any more is work this host may no longer do, whatever state it was left in.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store refuses the write.
    pub fn enrol_writer(
        &mut self,
        writer_key_id: KeyId,
        archive_id: ArchiveId,
        now_ms: TimestampMs,
    ) -> Result<()> {
        self.connection
            .execute(
                "INSERT INTO writers (writer_key_id, archive_id, enrolled_at_ms, retired_at_ms)
                 VALUES (?1, ?2, ?3, NULL)
                 ON CONFLICT (archive_id, writer_key_id) DO UPDATE
                     SET enrolled_at_ms = ?3, retired_at_ms = NULL",
                params![
                    writer_key_id.as_bytes().as_slice(),
                    archive_id.get().as_bytes().as_slice(),
                    millis(now_ms),
                ],
            )
            .map_err(ControllerError::registry)?;
        Ok(())
    }

    /// Retires one backup writer for one archive. Its unfinished generations there stop being
    /// authorised, and its enrolments for other collections are untouched.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store refuses the write.
    pub fn retire_writer(
        &mut self,
        archive_id: ArchiveId,
        writer_key_id: KeyId,
        now_ms: TimestampMs,
    ) -> Result<()> {
        self.connection
            .execute(
                "UPDATE writers SET retired_at_ms = ?3
                 WHERE archive_id = ?1 AND writer_key_id = ?2",
                params![
                    archive_id.get().as_bytes().as_slice(),
                    writer_key_id.as_bytes().as_slice(),
                    millis(now_ms),
                ],
            )
            .map_err(ControllerError::registry)?;
        Ok(())
    }

    /// Returns every writer this host may still publish under, with the archive it may publish.
    ///
    /// The pair rather than the key, because an enrolment is for one collection: a writer enrolled
    /// for archive A does not authorise unfinished work for archive B, and returning only key
    /// identifiers would say that it did.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store cannot be read.
    pub fn authorised_writers(&self) -> Result<Vec<(ArchiveId, KeyId)>> {
        let mut statement = self
            .connection
            .prepare("SELECT archive_id, writer_key_id FROM writers WHERE retired_at_ms IS NULL")
            .map_err(ControllerError::registry)?;
        let rows = statement
            .query_map([], |row| {
                let archive: Vec<u8> = row.get(0)?;
                let writer: Vec<u8> = row.get(1)?;
                Ok((|| -> Result<(ArchiveId, KeyId)> {
                    Ok((
                        ArchiveId::new(uuid(&archive, "an archive identifier")?),
                        key_id(&writer)?,
                    ))
                })())
            })
            .map_err(ControllerError::registry)?;
        let mut writers = Vec::new();
        for row in rows {
            writers.push(row.map_err(ControllerError::registry)??);
        }
        Ok(writers)
    }

    /// Returns true when this host holds an enrolment of that writer for that archive.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store cannot be read.
    pub fn authorises(&self, archive_id: ArchiveId, writer_key_id: KeyId) -> Result<bool> {
        Ok(self
            .authorised_writers()?
            .into_iter()
            .any(|(archive, writer)| archive == archive_id && writer == writer_key_id))
    }

    /// Puts one object back to staged, so a resumed upload continues from where it reached.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store refuses the write.
    pub fn note_object_resumable(
        &mut self,
        archive_id: ArchiveId,
        backup_generation: BackupGeneration,
    ) -> Result<()> {
        self.connection
            .execute(
                "UPDATE objects SET state = ?3
                 WHERE archive_id = ?1 AND backup_generation = ?2 AND state = ?4",
                params![
                    archive_id.get().as_bytes().as_slice(),
                    i64::try_from(backup_generation.get()).unwrap_or(i64::MAX),
                    ObjectState::Staged.as_str(),
                    ObjectState::Uploading.as_str(),
                ],
            )
            .map_err(ControllerError::registry)?;
        Ok(())
    }

    /// Puts one dispatched outbox entry back, so its step is taken again.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store refuses the write.
    pub fn note_undispatched(&mut self, sequence: u64) -> Result<()> {
        self.connection
            .execute(
                "UPDATE outbox SET dispatched = 0 WHERE sequence = ?1",
                params![i64::try_from(sequence).unwrap_or(i64::MAX)],
            )
            .map_err(ControllerError::registry)?;
        Ok(())
    }

    /// Accepts one privacy request, before its fence is attempted.
    ///
    /// This is the first durable thing that happens when privacy mode is turned on, and it happens
    /// on its own so that an activation which then fails cannot take the request with it. The
    /// request row and the [`ObligationKind::ActivateFence`] obligation commit together; from that
    /// moment this host is inhibited, counts one thing outstanding, and cannot report the fence as
    /// raised. Nothing but the activation's own success discharges it.
    ///
    /// Accepting the same generation twice reads the record back rather than writing a second one,
    /// so a repeated request cannot recreate cleanup that has already finished.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::InvalidArgument`] when the generation is older than the one in
    /// force, and [`ControllerError::RegistryUnavailable`] when the store refuses the write. A
    /// store that cannot commit this cannot hold the request at all: the caller keeps it and
    /// replays it, and backup work stays inhibited until it does.
    pub fn accept_privacy_request(
        &mut self,
        privacy_generation: u64,
        now_ms: TimestampMs,
    ) -> Result<PrivacyRequest> {
        let generation = i64::try_from(privacy_generation).unwrap_or(i64::MAX);
        let transaction = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(ControllerError::registry)?;
        let existing = read_request(&transaction, generation)?;
        if let Some(request) = existing {
            transaction.commit().map_err(ControllerError::registry)?;
            return Ok(request);
        }
        let current: i64 = transaction
            .query_row(
                "SELECT current_generation FROM privacy_state WHERE id = 0",
                [],
                |row| row.get(0),
            )
            .map_err(ControllerError::registry)?;
        if generation < current {
            return Err(ControllerError::InvalidArgument(format!(
                "privacy generation {privacy_generation} is older than the {current} this host is \
                 at, and a fence is never moved backwards"
            )));
        }
        transaction
            .execute(
                "INSERT INTO privacy_requests (privacy_generation, requested_at_ms, applied_at_ms)
                 VALUES (?1, ?2, NULL)",
                params![generation, millis(now_ms)],
            )
            .map_err(ControllerError::registry)?;
        insert_obligation(
            &transaction,
            &ObligationTarget {
                privacy_generation: generation,
                kind: Some(ObligationKind::ActivateFence),
                target_key: format!("request:{privacy_generation}"),
                ..ObligationTarget::default()
            },
            now_ms,
        )?;
        transaction
            .execute("UPDATE privacy_state SET enabled = 1 WHERE id = 0", [])
            .map_err(ControllerError::registry)?;
        transaction.commit().map_err(ControllerError::registry)?;
        Ok(PrivacyRequest {
            privacy_generation,
            requested_at_ms: now_ms,
            applied_at_ms: None,
        })
    }

    /// Raises the fence one accepted request asked for.
    ///
    /// One transaction, and it is the only one that raises a fence. It records the fence, advances
    /// the generation in force without letting it move backwards, marks the request applied and
    /// discharges that request's activation obligation. A failure anywhere inside rolls all of it
    /// back and leaves the request and its obligation exactly as they were, which is why the
    /// request is accepted first.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::InvalidArgument`] when no request at that generation has been
    /// accepted, and [`ControllerError::RegistryUnavailable`] when the store refuses the write.
    pub fn activate_fence(
        &mut self,
        privacy_generation: u64,
        now_ms: TimestampMs,
    ) -> Result<PrivacyRequest> {
        let generation = i64::try_from(privacy_generation).unwrap_or(i64::MAX);
        let transaction = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(ControllerError::registry)?;
        let Some(request) = read_request(&transaction, generation)? else {
            return Err(ControllerError::InvalidArgument(format!(
                "no privacy request at generation {privacy_generation} has been accepted on this \
                 host, and a fence is raised only over one that has"
            )));
        };
        if request.is_applied() {
            // The fence is up already. Raising it again would write a second cleanup scope over
            // targets the first scope may have finished with.
            transaction.commit().map_err(ControllerError::registry)?;
            return Ok(request);
        }
        transaction
            .execute(
                "INSERT INTO privacy_fences (privacy_generation, raised_at_ms, released_at_ms)
                 SELECT ?1, ?2, NULL WHERE NOT EXISTS
                     (SELECT 1 FROM privacy_fences WHERE privacy_generation = ?1)",
                params![generation, millis(now_ms)],
            )
            .map_err(ControllerError::registry)?;
        transaction
            .execute(
                "UPDATE privacy_state SET current_generation = ?1, enabled = 1
                 WHERE id = 0 AND current_generation < ?1",
                params![generation],
            )
            .map_err(ControllerError::registry)?;
        write_cleanup_scope(&transaction, generation, now_ms)?;
        transaction
            .execute(
                "UPDATE privacy_requests SET applied_at_ms = ?2 WHERE privacy_generation = ?1",
                params![generation, millis(now_ms)],
            )
            .map_err(ControllerError::registry)?;
        discharge_obligation(
            &transaction,
            generation,
            ObligationKind::ActivateFence,
            &format!("request:{privacy_generation}"),
        )?;
        transaction.commit().map_err(ControllerError::registry)?;
        Ok(PrivacyRequest {
            privacy_generation,
            requested_at_ms: request.requested_at_ms,
            applied_at_ms: Some(now_ms),
        })
    }

    #[doc(hidden)]
    pub fn set_query_only(&mut self, query_only: bool) -> Result<()> {
        self.connection
            .pragma_update(None, "query_only", if query_only { "ON" } else { "OFF" })
            .map_err(ControllerError::registry)
    }

    /// Returns every piece of cleanup this host still owes, oldest first.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store cannot be read. A read that
    /// fails is reported rather than answered with an empty list: "nothing is owed" and "this host
    /// cannot say what it owes" are not the same answer.
    pub fn obligations(&self) -> Result<Vec<Obligation>> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT id, privacy_generation, kind, target_key, archive_id, backup_generation,
                        object_id, staged_path, entry_sequence, recorded_at_ms, attempt_count,
                        last_error_code
                 FROM privacy_obligations ORDER BY id",
            )
            .map_err(ControllerError::registry)?;
        let rows = statement
            .query_map([], read_obligation)
            .map_err(ControllerError::registry)?;
        let mut outstanding = Vec::new();
        for row in rows {
            outstanding.push(row.map_err(ControllerError::registry)??);
        }
        Ok(outstanding)
    }

    /// Records that one attempt at an obligation failed, without ending it.
    ///
    /// The counter and the message are diagnostics beside the row. They are written in their own
    /// statement precisely so that failing to write them changes nothing: the obligation is still
    /// there, with its identity intact, and the next attempt finds it.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store refuses the write.
    pub fn note_obligation_failed(
        &mut self,
        id: i64,
        error: &str,
        now_ms: TimestampMs,
    ) -> Result<()> {
        self.connection
            .execute(
                "UPDATE privacy_obligations
                    SET attempt_count = attempt_count + 1,
                        last_error_code = ?2,
                        last_error_at_ms = ?3
                  WHERE id = ?1",
                params![id, error, millis(now_ms)],
            )
            .map_err(ControllerError::registry)?;
        Ok(())
    }

    /// Releases one fence, naming both the fence and the generation production resumes under.
    ///
    /// Both, explicitly. A release that took no fence generation could clear a fence raised after
    /// the caller decided to release, and one that took no resumed generation could move the
    /// generation in force backwards. The statement is guarded on the fence still being unreleased
    /// *and* having nothing outstanding, and the row count is read: nought rows is a fence that
    /// stands, never a release reported because nothing came back.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::InvalidArgument`] when the resumed generation is not newer than
    /// the fence, and [`ControllerError::RegistryUnavailable`] when the store refuses the write.
    pub fn release_fence(
        &mut self,
        fence_generation: u64,
        resumed_generation: u64,
        now_ms: TimestampMs,
    ) -> Result<FenceRelease> {
        if resumed_generation <= fence_generation {
            return Err(ControllerError::InvalidArgument(format!(
                "backup production resumes under a generation newer than the fence, and {resumed_generation} is not newer than {fence_generation}"
            )));
        }
        let fence = i64::try_from(fence_generation).unwrap_or(i64::MAX);
        let resumed = i64::try_from(resumed_generation).unwrap_or(i64::MAX);
        let transaction = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(ControllerError::registry)?;
        let released: Option<i64> = transaction
            .query_row(
                "UPDATE privacy_fences
                    SET released_at_ms = ?2
                  WHERE privacy_generation = ?1
                    AND released_at_ms IS NULL
                    AND NOT EXISTS (SELECT 1 FROM privacy_obligations
                                     WHERE privacy_generation = ?1)
                RETURNING privacy_generation",
                params![fence, millis(now_ms)],
                |row| row.get(0),
            )
            .optional()
            .map_err(ControllerError::registry)?;
        if released.is_none() {
            let outstanding: i64 = transaction
                .query_row(
                    "SELECT COUNT(*) FROM privacy_obligations WHERE privacy_generation = ?1",
                    params![fence],
                    |row| row.get(0),
                )
                .map_err(ControllerError::registry)?;
            let held: i64 = transaction
                .query_row(
                    "SELECT COUNT(*) FROM privacy_fences
                      WHERE privacy_generation = ?1 AND released_at_ms IS NULL",
                    params![fence],
                    |row| row.get(0),
                )
                .map_err(ControllerError::registry)?;
            transaction.commit().map_err(ControllerError::registry)?;
            return Ok(if held == 0 {
                FenceRelease::NotHeld
            } else {
                FenceRelease::Pending {
                    obligations: u64::try_from(outstanding).unwrap_or(0),
                }
            });
        }
        // The generation in force moves forward with the release, and only forward. Whether
        // privacy mode is still on is a fact about what is left: another fence that has not been
        // released, or a request whose fence has not gone up, keeps it on.
        transaction
            .execute(
                "UPDATE privacy_state SET current_generation = ?1
                  WHERE id = 0 AND current_generation < ?1",
                params![resumed],
            )
            .map_err(ControllerError::registry)?;
        let remaining: i64 = transaction
            .query_row(
                "SELECT (SELECT COUNT(*) FROM privacy_fences WHERE released_at_ms IS NULL)
                      + (SELECT COUNT(*) FROM privacy_requests WHERE applied_at_ms IS NULL)",
                [],
                |row| row.get(0),
            )
            .map_err(ControllerError::registry)?;
        if remaining == 0 {
            transaction
                .execute("UPDATE privacy_state SET enabled = 0 WHERE id = 0", [])
                .map_err(ControllerError::registry)?;
        }
        transaction.commit().map_err(ControllerError::registry)?;
        Ok(FenceRelease::Released)
    }

    /// Returns where this host stands with privacy mode.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store cannot be read.
    pub fn privacy_status(&self) -> Result<PrivacyStatus> {
        let (current, enabled): (i64, i64) = self
            .connection
            .query_row(
                "SELECT current_generation, enabled FROM privacy_state WHERE id = 0",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(ControllerError::registry)?;
        let pending: Option<i64> = self
            .connection
            .query_row(
                "SELECT MIN(privacy_generation) FROM privacy_requests WHERE applied_at_ms IS NULL",
                [],
                |row| row.get(0),
            )
            .map_err(ControllerError::registry)?;
        let unreleased: Option<i64> = self
            .connection
            .query_row(
                "SELECT MIN(privacy_generation) FROM privacy_fences WHERE released_at_ms IS NULL",
                [],
                |row| row.get(0),
            )
            .map_err(ControllerError::registry)?;
        let obligations: i64 = self
            .connection
            .query_row("SELECT COUNT(*) FROM privacy_obligations", [], |row| {
                row.get(0)
            })
            .map_err(ControllerError::registry)?;
        Ok(PrivacyStatus {
            current_generation: u64::try_from(current).unwrap_or(0),
            enabled: enabled != 0,
            pending_activation: pending.map(|value| u64::try_from(value).unwrap_or(0)),
            unreleased_fence: unreleased.map(|value| u64::try_from(value).unwrap_or(0)),
            obligations: u64::try_from(obligations).unwrap_or(0),
        })
    }

    /// Returns one privacy request, if this host accepted it.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store cannot be read.
    pub fn privacy_request(&self, privacy_generation: u64) -> Result<Option<PrivacyRequest>> {
        read_request(
            &self.connection,
            i64::try_from(privacy_generation).unwrap_or(i64::MAX),
        )
    }

    /// Returns the privacy generation backup production is stopped at, if it is stopped.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store cannot be read.
    pub fn fenced_at(&self) -> Result<Option<u64>> {
        Ok(self.privacy_status()?.inhibited_at())
    }

    /// Records that one staged copy is gone, and ends the obligation that named it, together.
    ///
    /// The caller has already unlinked the file, or found it absent. Both halves commit here in
    /// one transaction, so a stop between them leaves the obligation rather than a store that says
    /// the cleanup finished. An `UPDATE` that names no object row is correct and expected: an
    /// obligation the staging walk wrote covers a file no row ever claimed.
    ///
    /// Returns how many rows the generation's bookkeeping removed, which is nought unless this was
    /// the last thing that bookkeeping was waiting on.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store refuses the write.
    pub fn note_object_unlinked(&mut self, obligation: &Obligation) -> Result<u64> {
        let transaction = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(ControllerError::registry)?;
        // The stored row decides, never the caller's copy of it. `Obligation`'s fields are public
        // so a report can read them, and a caller that relabelled one could otherwise discharge a
        // row of an entirely different kind by asking for this handler.
        expect_stored_kind(&transaction, obligation.id, ObligationKind::UnlinkObject)?;
        let (stored_archive, stored_generation, stored_object): (
            Option<Vec<u8>>,
            Option<i64>,
            Option<Vec<u8>>,
        ) = transaction
            .query_row(
                "SELECT archive_id, backup_generation, object_id FROM privacy_obligations
                  WHERE id = ?1",
                params![obligation.id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .map_err(ControllerError::registry)?;
        let target = match (stored_archive, stored_generation, stored_object) {
            (Some(archive), Some(generation), Some(object)) => Some((
                ArchiveId::new(uuid(&archive, "an archive identifier")?),
                BackupGeneration::new(u64::try_from(generation).unwrap_or(0)),
                BackupObjectId::new(uuid(&object, "an object identifier")?),
            )),
            _ => None,
        };
        if let Some((archive_id, backup_generation, object_id)) = target {
            // Where the ciphertext is, and nothing else. What the service acknowledged stays where
            // it is: an object that had arrived before its staged copy went is still an object
            // that arrived.
            transaction
                .execute(
                    "UPDATE objects SET state = ?4
                      WHERE archive_id = ?1 AND backup_generation = ?2 AND object_id = ?3",
                    params![
                        archive_id.get().as_bytes().as_slice(),
                        i64::try_from(backup_generation.get()).unwrap_or(i64::MAX),
                        object_id.get().as_bytes().as_slice(),
                        ObjectState::Removed.as_str(),
                    ],
                )
                .map_err(ControllerError::registry)?;
        }
        transaction
            .execute(
                "DELETE FROM privacy_obligations WHERE id = ?1",
                params![obligation.id],
            )
            .map_err(ControllerError::registry)?;
        let finished = match target {
            Some((archive_id, backup_generation, _)) => {
                try_finish_generation(&transaction, archive_id, backup_generation)?
            }
            None => 0,
        };
        transaction.commit().map_err(ControllerError::registry)?;
        Ok(finished)
    }

    /// Records what a walk of the staging directory found, and ends the walk, together.
    ///
    /// Returns how many rows the bookkeeping this walk released removed, which is nought unless
    /// the walk was the last thing a generation was waiting on.
    ///
    /// Every file the caller found that no object row names gets its own removal obligation before
    /// the walk is discharged. A walk that could not read the directory is not discharged at all:
    /// the caller returns the error and the obligation stays.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store refuses the write.
    pub fn record_staging_scan(
        &mut self,
        obligation: &Obligation,
        unregistered: &[PathBuf],
        now_ms: TimestampMs,
    ) -> Result<u64> {
        let transaction = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(ControllerError::registry)?;
        expect_stored_kind(&transaction, obligation.id, ObligationKind::ScanStaging)?;
        let privacy_generation: i64 = transaction
            .query_row(
                "SELECT privacy_generation FROM privacy_obligations WHERE id = ?1",
                params![obligation.id],
                |row| row.get(0),
            )
            .map_err(ControllerError::registry)?;
        for path in unregistered {
            let text = path.to_string_lossy().into_owned();
            insert_obligation(
                &transaction,
                &ObligationTarget {
                    privacy_generation,
                    kind: Some(ObligationKind::UnlinkObject),
                    target_key: format!("path:{text}"),
                    staged_path: Some(text),
                    ..ObligationTarget::default()
                },
                now_ms,
            )?;
        }
        transaction
            .execute(
                "DELETE FROM privacy_obligations WHERE id = ?1",
                params![obligation.id],
            )
            .map_err(ControllerError::registry)?;
        // The walk was the last thing every generation's bookkeeping waited on, so each one that
        // is now ready is finished in the same transaction.
        let ready: Vec<(Vec<u8>, i64)> = {
            let mut statement = transaction
                .prepare(
                    "SELECT archive_id, backup_generation FROM privacy_obligations
                      WHERE kind = 'finish_generation' AND privacy_generation = ?1",
                )
                .map_err(ControllerError::registry)?;
            let rows = statement
                .query_map(params![privacy_generation], |row| {
                    Ok((row.get(0)?, row.get(1)?))
                })
                .map_err(ControllerError::registry)?;
            let mut collected = Vec::new();
            for row in rows {
                collected.push(row.map_err(ControllerError::registry)?);
            }
            collected
        };
        let mut finished = 0u64;
        for (archive, generation) in ready {
            finished = finished.saturating_add(try_finish_generation(
                &transaction,
                ArchiveId::new(uuid(&archive, "an archive identifier")?),
                BackupGeneration::new(u64::try_from(generation).unwrap_or(0)),
            )?);
        }
        transaction.commit().map_err(ControllerError::registry)?;
        Ok(finished)
    }

    /// Finishes one generation's bookkeeping, if everything it waits on is done.
    ///
    /// Returns how many rows it removed, which is nought while anything is still outstanding and
    /// nought for a generation whose record is kept as a retained artifact.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store refuses the write.
    pub fn finish_generation(&mut self, obligation: &Obligation) -> Result<u64> {
        let transaction = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(ControllerError::registry)?;
        expect_stored_kind(
            &transaction,
            obligation.id,
            ObligationKind::FinishGeneration,
        )?;
        let (archive, generation): (Vec<u8>, i64) = transaction
            .query_row(
                "SELECT archive_id, backup_generation FROM privacy_obligations WHERE id = ?1",
                params![obligation.id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(ControllerError::registry)?;
        let archive_id = ArchiveId::new(uuid(&archive, "an archive identifier")?);
        let backup_generation = BackupGeneration::new(u64::try_from(generation).unwrap_or(0));
        let finished = try_finish_generation(&transaction, archive_id, backup_generation)?;
        transaction.commit().map_err(ControllerError::registry)?;
        Ok(finished)
    }

    /// Returns every path an object row names as staged on this host.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store cannot be read.
    pub fn registered_staged_paths(&self) -> Result<Vec<PathBuf>> {
        let mut statement = self
            .connection
            .prepare("SELECT staged_path FROM objects")
            .map_err(ControllerError::registry)?;
        let rows = statement
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(ControllerError::registry)?;
        let mut paths = Vec::new();
        for row in rows {
            paths.push(PathBuf::from(row.map_err(ControllerError::registry)?));
        }
        Ok(paths)
    }

    /// Takes back exactly the entries this fence wrote a cancellation down for.
    ///
    /// Returns how many were taken back and how many had already left this host. The second figure
    /// is what reconciliation waits on: dispatched work cannot be taken back, only followed, so it
    /// keeps its own obligation until evidence for that exact attempt arrives.
    ///
    /// Each entry and its obligation go in one statement pair inside one transaction, so a stop
    /// part way through leaves the rest of the cancellations owed rather than lost.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store refuses the write.
    pub fn cancel_undispatched(
        &mut self,
        _now_ms: TimestampMs,
        _detail: &str,
    ) -> Result<(u64, u64)> {
        let owed = self.obligations()?;
        let in_flight = owed
            .iter()
            .filter(|obligation| {
                matches!(
                    obligation.kind,
                    ObligationKind::ResolveUpload | ObligationKind::ResolvePublication
                )
            })
            .count() as u64;
        let transaction = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(ControllerError::registry)?;
        let mut taken_back = 0u64;
        for obligation in owed
            .iter()
            .filter(|obligation| obligation.kind == ObligationKind::CancelEntry)
        {
            let Some(sequence) = obligation.entry_sequence else {
                continue;
            };
            let sequence = i64::try_from(sequence).unwrap_or(i64::MAX);
            // The exact entry, and only while it is still this host's to take back. An entry that
            // had been dispatched in between is not a cancellation any more, so its obligation
            // stays and the attempt is followed instead.
            let queued: i64 = transaction
                .query_row(
                    "SELECT COUNT(*) FROM outbox WHERE sequence = ?1 AND dispatched = 1",
                    params![sequence],
                    |row| row.get(0),
                )
                .map_err(ControllerError::registry)?;
            if queued > 0 {
                continue;
            }
            let removed = transaction
                .execute(
                    "DELETE FROM outbox WHERE sequence = ?1 AND dispatched = 0",
                    params![sequence],
                )
                .map_err(ControllerError::registry)?;
            transaction
                .execute(
                    "DELETE FROM privacy_obligations WHERE id = ?1",
                    params![obligation.id],
                )
                .map_err(ControllerError::registry)?;
            taken_back = taken_back.saturating_add(u64::try_from(removed).unwrap_or(0));
            if let (Some(archive_id), Some(backup_generation)) =
                (obligation.archive_id, obligation.backup_generation)
            {
                try_finish_generation(&transaction, archive_id, backup_generation)?;
            }
        }
        transaction.commit().map_err(ControllerError::registry)?;
        Ok((taken_back, in_flight))
    }
}

/// Takes a generation's unfinished work out of the outbox, and says whether a publication that
/// already left this host is still owed an answer.
///
/// The upload is over either way: it has either finished or been cancelled, and its entry asks for
/// nothing more. An undispatched publication is work this host has not started, so it goes with
/// it. A *dispatched* publication is neither: its answer is what decides whether the service holds
/// the generation, and an entry deleted here would be a cleanup reported complete over work that
/// is still out there.
fn clear_unfinished_work(
    transaction: &rusqlite::Transaction<'_>,
    archive_id: ArchiveId,
    backup_generation: BackupGeneration,
) -> Result<bool> {
    let ended: Vec<i64> = {
        let mut statement = transaction
            .prepare(
                "SELECT sequence FROM outbox
                  WHERE archive_id = ?1 AND backup_generation = ?2
                    AND (step = ?3 OR dispatched = 0)",
            )
            .map_err(ControllerError::registry)?;
        let rows = statement
            .query_map(
                params![
                    archive_id.get().as_bytes().as_slice(),
                    i64::try_from(backup_generation.get()).unwrap_or(i64::MAX),
                    Step::Upload.as_str(),
                ],
                |row| row.get(0),
            )
            .map_err(ControllerError::registry)?;
        let mut collected = Vec::new();
        for row in rows {
            collected.push(row.map_err(ControllerError::registry)?);
        }
        collected
    };
    // Each entry and whatever obligation named it, together. The upload is over either way: it has
    // finished or it has been cancelled, and that is evidence for that exact attempt.
    for sequence in ended {
        settle_attempt(transaction, sequence)?;
    }
    let owed: i64 = transaction
        .query_row(
            "SELECT COUNT(*) FROM outbox WHERE archive_id = ?1 AND backup_generation = ?2",
            params![
                archive_id.get().as_bytes().as_slice(),
                i64::try_from(backup_generation.get()).unwrap_or(i64::MAX),
            ],
            |row| row.get(0),
        )
        .map_err(ControllerError::registry)?;
    Ok(owed > 0)
}

/// Writes down everything one fence implies, inside the transaction that raises it.
///
/// One row per target, from the rows that exist at this moment: every staged copy this host still
/// holds, every queued entry it has not sent, every attempt that has left and not been answered,
/// the bookkeeping each generation still needs, and one walk of the staging directory for
/// ciphertext no row names. Production is prohibited for everything still producing in the same
/// breath, so nothing can be admitted into a scope that has just been written.
///
/// It does not consult an outbox, a settled flag or any other summary. A generation that is
/// staging, uploading, cancelled, published or of unknown outcome is covered the same way: if its
/// ciphertext is here, its removal is written down.
fn write_cleanup_scope(
    transaction: &rusqlite::Transaction<'_>,
    privacy_generation: i64,
    now_ms: TimestampMs,
) -> Result<()> {
    let now = millis(now_ms);
    // Every staged copy still on this host, by its own path.
    transaction
        .execute(
            "INSERT INTO privacy_obligations
                 (privacy_generation, kind, target_key, archive_id, backup_generation, object_id,
                  staged_path, recorded_at_ms, attempt_count)
             SELECT ?1, 'unlink_object',
                    'object:' || hex(archive_id) || ':' || backup_generation || ':'
                              || hex(object_id),
                    archive_id, backup_generation, object_id, staged_path, ?2, 0
               FROM objects WHERE state <> ?3
             ON CONFLICT (privacy_generation, kind, target_key) DO NOTHING",
            params![privacy_generation, now, ObjectState::Removed.as_str()],
        )
        .map_err(ControllerError::registry)?;
    // Every piece of work admitted and never sent.
    transaction
        .execute(
            "INSERT INTO privacy_obligations
                 (privacy_generation, kind, target_key, archive_id, backup_generation,
                  entry_sequence, recorded_at_ms, attempt_count)
             SELECT ?1, 'cancel_entry', 'entry:' || sequence,
                    archive_id, backup_generation, sequence, ?2, 0
               FROM outbox WHERE dispatched = 0
             ON CONFLICT (privacy_generation, kind, target_key) DO NOTHING",
            params![privacy_generation, now],
        )
        .map_err(ControllerError::registry)?;
    // Every attempt that has already left this host. It cannot be taken back, only followed, and
    // the obligation says so until evidence for that exact attempt arrives.
    transaction
        .execute(
            "INSERT INTO privacy_obligations
                 (privacy_generation, kind, target_key, archive_id, backup_generation,
                  entry_sequence, recorded_at_ms, attempt_count)
             SELECT ?1,
                    CASE step WHEN 'upload' THEN 'resolve_upload'
                              ELSE 'resolve_publication' END,
                    CASE step WHEN 'upload' THEN 'upload:' ELSE 'publication:' END || sequence,
                    archive_id, backup_generation, sequence, ?2, 0
               FROM outbox WHERE dispatched = 1
             ON CONFLICT (privacy_generation, kind, target_key) DO NOTHING",
            params![privacy_generation, now],
        )
        .map_err(ControllerError::registry)?;
    // The bookkeeping each generation still needs once its removals and attempts are done.
    transaction
        .execute(
            "INSERT INTO privacy_obligations
                 (privacy_generation, kind, target_key, archive_id, backup_generation,
                  recorded_at_ms, attempt_count)
             SELECT ?1, 'finish_generation',
                    'generation:' || hex(archive_id) || ':' || backup_generation,
                    archive_id, backup_generation, ?2, 0
               FROM generations WHERE TRUE
             ON CONFLICT (privacy_generation, kind, target_key) DO NOTHING",
            params![privacy_generation, now],
        )
        .map_err(ControllerError::registry)?;
    // And one walk of the staging directory. Ciphertext is written before the row that names it,
    // so a stop in between leaves a file no row accounts for; this is what finds it.
    insert_obligation(
        transaction,
        &ObligationTarget {
            privacy_generation,
            kind: Some(ObligationKind::ScanStaging),
            target_key: "staging".to_owned(),
            ..ObligationTarget::default()
        },
        now_ms,
    )?;
    // Production stops here, permanently, for everything that was still producing. A generation
    // cancelled by a fence is never resumed: what is admitted after the fence is released is
    // admitted under the generation that released it.
    transaction
        .execute(
            "UPDATE generations SET state = ?1, settled_at_ms = ?2, detail = ?3
              WHERE state IN (?4, ?5)",
            params![
                GenerationState::Cancelled.as_str(),
                now,
                format!(
                    "privacy mode fenced backup production at privacy generation \
                     {privacy_generation}"
                ),
                GenerationState::Staging.as_str(),
                GenerationState::Uploading.as_str(),
            ],
        )
        .map_err(ControllerError::registry)?;
    Ok(())
}

/// Ends one attempt: its outbox row and every obligation that names it, together.
///
/// The two are one fact. An attempt whose row went while its obligation stayed would be cleanup
/// nothing could ever discharge; an obligation that went while the row stayed would be work
/// reported finished with the row still asking for it.
fn settle_attempt(transaction: &rusqlite::Transaction<'_>, sequence: i64) -> Result<()> {
    transaction
        .execute(
            "DELETE FROM privacy_obligations WHERE entry_sequence = ?1",
            params![sequence],
        )
        .map_err(ControllerError::registry)?;
    transaction
        .execute("DELETE FROM outbox WHERE sequence = ?1", params![sequence])
        .map_err(ControllerError::registry)?;
    Ok(())
}

/// Writes where one generation ended up, inside a transaction the caller owns.
///
/// `attempts_ended` says whether the caller has established that work which had already left this
/// host is over. When it has not, such an attempt keeps its row and whatever obligation names it:
/// a record written here says nothing about what a service did.
fn apply_settlement(
    transaction: &rusqlite::Transaction<'_>,
    archive_id: ArchiveId,
    backup_generation: BackupGeneration,
    state: GenerationState,
    detail: Option<&str>,
    now_ms: TimestampMs,
    attempts_ended: bool,
) -> Result<()> {
    let archive = archive_id.get().as_bytes().to_vec();
    let generation = i64::try_from(backup_generation.get()).unwrap_or(i64::MAX);
    transaction
        .execute(
            "UPDATE generations SET state = ?3, settled_at_ms = ?4, detail = ?5
             WHERE archive_id = ?1 AND backup_generation = ?2",
            params![archive, generation, state.as_str(), millis(now_ms), detail],
        )
        .map_err(ControllerError::registry)?;
    let sequences: Vec<i64> = {
        let mut statement = transaction
            .prepare(
                "SELECT sequence FROM outbox
                  WHERE archive_id = ?1 AND backup_generation = ?2
                    AND (?3 = 1 OR dispatched = 0)",
            )
            .map_err(ControllerError::registry)?;
        let rows = statement
            .query_map(
                params![archive, generation, i64::from(attempts_ended)],
                |row| row.get(0),
            )
            .map_err(ControllerError::registry)?;
        let mut collected = Vec::new();
        for row in rows {
            collected.push(row.map_err(ControllerError::registry)?);
        }
        collected
    };
    for sequence in sequences {
        settle_attempt(transaction, sequence)?;
    }
    try_finish_generation(transaction, archive_id, backup_generation)?;
    Ok(())
}

/// Finishes one generation's bookkeeping, if everything that obligation waits on is done.
///
/// Called from inside whichever transaction makes the last condition true, so completion is a fact
/// the store derives rather than a step somebody has to remember to take. Until then the
/// `finish_generation` row is simply there, and cleanup is not complete.
///
/// Returns how many rows this actually deleted, which is nought whenever the conditions do not
/// hold yet and nought for a generation whose record is kept as a retained artifact.
fn try_finish_generation(
    transaction: &rusqlite::Transaction<'_>,
    archive_id: ArchiveId,
    backup_generation: BackupGeneration,
) -> Result<u64> {
    let archive = archive_id.get().as_bytes().to_vec();
    let generation = i64::try_from(backup_generation.get()).unwrap_or(i64::MAX);
    let mut finished = 0u64;
    let pending: Vec<(i64, i64)> = {
        let mut statement = transaction
            .prepare(
                "SELECT id, privacy_generation FROM privacy_obligations
                  WHERE kind = 'finish_generation' AND archive_id = ?1 AND backup_generation = ?2",
            )
            .map_err(ControllerError::registry)?;
        let rows = statement
            .query_map(params![archive, generation], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .map_err(ControllerError::registry)?;
        let mut collected = Vec::new();
        for row in rows {
            collected.push(row.map_err(ControllerError::registry)?);
        }
        collected
    };
    for (id, privacy_generation) in pending {
        // A staging walk that has not happened could still find ciphertext of this generation, so
        // the bookkeeping waits for it too.
        let blocking: i64 = transaction
            .query_row(
                "SELECT COUNT(*) FROM privacy_obligations
                  WHERE privacy_generation = ?1
                    AND id <> ?2
                    AND (kind = 'scan_staging'
                         OR (archive_id = ?3 AND backup_generation = ?4))",
                params![privacy_generation, id, archive, generation],
                |row| row.get(0),
            )
            .map_err(ControllerError::registry)?;
        if blocking > 0 {
            continue;
        }
        // And every staged copy of it is really gone from this host.
        let present: i64 = transaction
            .query_row(
                "SELECT COUNT(*) FROM objects
                  WHERE archive_id = ?1 AND backup_generation = ?2 AND state <> ?3",
                params![archive, generation, ObjectState::Removed.as_str()],
                |row| row.get(0),
            )
            .map_err(ControllerError::registry)?;
        if present > 0 {
            continue;
        }
        let state: Option<String> = transaction
            .query_row(
                "SELECT state FROM generations WHERE archive_id = ?1 AND backup_generation = ?2",
                params![archive, generation],
                |row| row.get(0),
            )
            .optional()
            .map_err(ControllerError::registry)?;
        let keep = match state.as_deref() {
            // A copy that has already left this host is shown rather than pretended away, and a
            // copy this host cannot account for is still a copy.
            Some(text) => matches!(
                GenerationState::parse(text)?,
                GenerationState::Published | GenerationState::Unknown
            ),
            None => false,
        };
        if !keep {
            let objects: i64 = transaction
                .query_row(
                    "SELECT COUNT(*) FROM objects WHERE archive_id = ?1 AND backup_generation = ?2",
                    params![archive, generation],
                    |row| row.get(0),
                )
                .map_err(ControllerError::registry)?;
            transaction
                .execute(
                    "DELETE FROM objects WHERE archive_id = ?1 AND backup_generation = ?2",
                    params![archive, generation],
                )
                .map_err(ControllerError::registry)?;
            let generations = transaction
                .execute(
                    "DELETE FROM generations WHERE archive_id = ?1 AND backup_generation = ?2",
                    params![archive, generation],
                )
                .map_err(ControllerError::registry)?;
            finished = finished.saturating_add(u64::try_from(objects).unwrap_or(0));
            finished = finished.saturating_add(u64::try_from(generations).unwrap_or(0));
        }
        transaction
            .execute("DELETE FROM privacy_obligations WHERE id = ?1", params![id])
            .map_err(ControllerError::registry)?;
    }
    Ok(finished)
}

/// Everything one obligation row names, so an insert cannot leave a target column out by accident.
#[derive(Clone, Debug, Default)]
struct ObligationTarget {
    privacy_generation: i64,
    kind: Option<ObligationKind>,
    target_key: String,
    archive_id: Option<ArchiveId>,
    backup_generation: Option<BackupGeneration>,
    object_id: Option<BackupObjectId>,
    staged_path: Option<String>,
    entry_sequence: Option<i64>,
}

impl ObligationTarget {
    fn kind(&self) -> Result<ObligationKind> {
        self.kind
            .ok_or_else(|| ControllerError::registry("a cleanup obligation has no kind"))
    }
}

/// Writes one obligation, before the thing it is owed for is attempted.
///
/// `ON CONFLICT DO NOTHING` over `(privacy_generation, kind, target_key)`, so writing the same
/// obligation twice writes it once: a second fence activation over a target the first already
/// recorded adds nothing, and a target that has been discharged is not recreated by a repeat of
/// the transaction that recorded it.
fn insert_obligation(
    transaction: &rusqlite::Transaction<'_>,
    target: &ObligationTarget,
    now_ms: TimestampMs,
) -> Result<()> {
    transaction
        .execute(
            "INSERT INTO privacy_obligations
                 (privacy_generation, kind, target_key, archive_id, backup_generation, object_id,
                  staged_path, entry_sequence, recorded_at_ms, attempt_count)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 0)
             ON CONFLICT (privacy_generation, kind, target_key) DO NOTHING",
            params![
                target.privacy_generation,
                target.kind()?.as_str(),
                target.target_key,
                target.archive_id.map(|id| id.get().as_bytes().to_vec()),
                target
                    .backup_generation
                    .map(|value| i64::try_from(value.get()).unwrap_or(i64::MAX)),
                target.object_id.map(|id| id.get().as_bytes().to_vec()),
                target.staged_path,
                target.entry_sequence,
                millis(now_ms),
            ],
        )
        .map_err(ControllerError::registry)?;
    Ok(())
}

/// Ends one obligation, inside the transaction that records the evidence for it.
///
/// Private, and it stays private. There is no call anywhere that clears an obligation on its own:
/// the only way a row goes is together with the result that earns it, so a cleanup this host did
/// not perform has no route to being reported as done.
fn discharge_obligation(
    transaction: &rusqlite::Transaction<'_>,
    privacy_generation: i64,
    kind: ObligationKind,
    target_key: &str,
) -> Result<()> {
    transaction
        .execute(
            "DELETE FROM privacy_obligations
              WHERE privacy_generation = ?1 AND kind = ?2 AND target_key = ?3",
            params![privacy_generation, kind.as_str(), target_key],
        )
        .map_err(ControllerError::registry)?;
    Ok(())
}

/// Returns the privacy generation backup production is stopped at, read inside a transaction.
///
/// A request whose fence has not gone up counts as firmly as a fence that has: this host has been
/// told to stop, and the scope of what it has to clean up is not written down yet.
fn inhibited_at(connection: &Connection) -> Result<Option<i64>> {
    connection
        .query_row(
            "SELECT MIN(privacy_generation) FROM (
                 SELECT privacy_generation FROM privacy_fences WHERE released_at_ms IS NULL
                 UNION ALL
                 SELECT privacy_generation FROM privacy_requests WHERE applied_at_ms IS NULL
             )",
            [],
            |row| row.get(0),
        )
        .map_err(ControllerError::registry)
}

/// Refuses a discharge whose stored row is not the kind the handler is for.
///
/// The row in the database is the authority. An [`Obligation`] value is a copy a caller may hold,
/// change and hand back, so a handler that trusted its `kind` could be asked to end a row of
/// another kind entirely.
fn expect_stored_kind(
    transaction: &rusqlite::Transaction<'_>,
    id: i64,
    expected: ObligationKind,
) -> Result<()> {
    let stored: Option<String> = transaction
        .query_row(
            "SELECT kind FROM privacy_obligations WHERE id = ?1",
            params![id],
            |row| row.get(0),
        )
        .optional()
        .map_err(ControllerError::registry)?;
    let Some(stored) = stored else {
        return Err(ControllerError::registry(
            "that cleanup obligation is not one this host holds",
        ));
    };
    if ObligationKind::parse(&stored)? != expected {
        return Err(ControllerError::registry(format!(
            "that cleanup obligation is a {stored}, not a {}",
            expected.as_str()
        )));
    }
    Ok(())
}

fn read_request(
    connection: &Connection,
    privacy_generation: i64,
) -> Result<Option<PrivacyRequest>> {
    connection
        .query_row(
            "SELECT privacy_generation, requested_at_ms, applied_at_ms FROM privacy_requests
              WHERE privacy_generation = ?1",
            params![privacy_generation],
            |row| {
                let generation: i64 = row.get(0)?;
                let requested: i64 = row.get(1)?;
                let applied: Option<i64> = row.get(2)?;
                Ok(PrivacyRequest {
                    privacy_generation: u64::try_from(generation).unwrap_or(0),
                    requested_at_ms: TimestampMs::new(u64::try_from(requested).unwrap_or(0)),
                    applied_at_ms: applied
                        .map(|value| TimestampMs::new(u64::try_from(value).unwrap_or(0))),
                })
            },
        )
        .optional()
        .map_err(ControllerError::registry)
}

fn read_obligation(row: &rusqlite::Row<'_>) -> rusqlite::Result<Result<Obligation>> {
    let id: i64 = row.get(0)?;
    let privacy: i64 = row.get(1)?;
    let kind: String = row.get(2)?;
    let target_key: String = row.get(3)?;
    let archive: Option<Vec<u8>> = row.get(4)?;
    let generation: Option<i64> = row.get(5)?;
    let object: Option<Vec<u8>> = row.get(6)?;
    let staged_path: Option<String> = row.get(7)?;
    let entry_sequence: Option<i64> = row.get(8)?;
    let recorded: i64 = row.get(9)?;
    let attempts: i64 = row.get(10)?;
    let last_error: Option<String> = row.get(11)?;
    Ok((|| {
        Ok(Obligation {
            id,
            privacy_generation: u64::try_from(privacy).unwrap_or(0),
            kind: ObligationKind::parse(&kind)?,
            target_key,
            archive_id: archive
                .map(|bytes| uuid(&bytes, "an archive identifier").map(ArchiveId::new))
                .transpose()?,
            backup_generation: generation
                .map(|value| BackupGeneration::new(u64::try_from(value).unwrap_or(0))),
            object_id: object
                .map(|bytes| uuid(&bytes, "an object identifier").map(BackupObjectId::new))
                .transpose()?,
            staged_path: staged_path.map(PathBuf::from),
            entry_sequence: entry_sequence.map(|value| u64::try_from(value).unwrap_or(0)),
            recorded_at_ms: TimestampMs::new(u64::try_from(recorded).unwrap_or(0)),
            attempt_count: u64::try_from(attempts).unwrap_or(0),
            last_error,
        })
    })())
}

fn enqueue(
    transaction: &rusqlite::Transaction<'_>,
    archive_id: ArchiveId,
    backup_generation: BackupGeneration,
    step: Step,
    privacy_generation: u64,
    now_ms: TimestampMs,
) -> Result<u64> {
    transaction
        .execute(
            "INSERT INTO outbox
                 (archive_id, backup_generation, step, privacy_generation, dispatched,
                  enqueued_at_ms)
             VALUES (?1, ?2, ?3, ?4, 0, ?5)",
            params![
                archive_id.get().as_bytes().as_slice(),
                i64::try_from(backup_generation.get()).unwrap_or(i64::MAX),
                step.as_str(),
                i64::try_from(privacy_generation).unwrap_or(i64::MAX),
                millis(now_ms),
            ],
        )
        .map_err(ControllerError::registry)?;
    Ok(u64::try_from(transaction.last_insert_rowid()).unwrap_or(0))
}

fn read_generation(row: &rusqlite::Row<'_>) -> rusqlite::Result<Result<GenerationRecord>> {
    let archive: Vec<u8> = row.get(0)?;
    let generation: i64 = row.get(1)?;
    let state: String = row.get(2)?;
    let writer: Vec<u8> = row.get(3)?;
    let privacy: i64 = row.get(4)?;
    let descriptor: Option<Vec<u8>> = row.get(5)?;
    let created: i64 = row.get(6)?;
    let settled: Option<i64> = row.get(7)?;
    let detail: Option<String> = row.get(8)?;
    Ok((|| {
        Ok(GenerationRecord {
            archive_id: ArchiveId::new(uuid(&archive, "an archive identifier")?),
            backup_generation: BackupGeneration::new(u64::try_from(generation).unwrap_or(0)),
            state: GenerationState::parse(&state)?,
            writer_key_id: key_id(&writer)?,
            privacy_generation: u64::try_from(privacy).unwrap_or(0),
            descriptor,
            created_at_ms: TimestampMs::new(u64::try_from(created).unwrap_or(0)),
            settled_at_ms: settled.map(|value| TimestampMs::new(u64::try_from(value).unwrap_or(0))),
            detail,
        })
    })())
}

fn read_object(row: &rusqlite::Row<'_>) -> rusqlite::Result<Result<ObjectRecord>> {
    let archive: Vec<u8> = row.get(0)?;
    let generation: i64 = row.get(1)?;
    let object: Vec<u8> = row.get(2)?;
    let hash: Vec<u8> = row.get(3)?;
    let len: i64 = row.get(4)?;
    let path: String = row.get(5)?;
    let uploaded: i64 = row.get(6)?;
    let state: String = row.get(7)?;
    Ok((|| {
        Ok(ObjectRecord {
            archive_id: ArchiveId::new(uuid(&archive, "an archive identifier")?),
            backup_generation: BackupGeneration::new(u64::try_from(generation).unwrap_or(0)),
            object_id: BackupObjectId::new(uuid(&object, "an object identifier")?),
            encrypted_object_hash: Digest256::from_bytes(
                <[u8; 32]>::try_from(hash.as_slice()).map_err(|_| {
                    ControllerError::registry("a stored encrypted-object hash is not 32 bytes")
                })?,
            ),
            encrypted_len: u64::try_from(len).unwrap_or(0),
            staged_path: PathBuf::from(path),
            uploaded_bytes: u64::try_from(uploaded).unwrap_or(0),
            state: ObjectState::parse(&state)?,
        })
    })())
}

fn read_outbox(row: &rusqlite::Row<'_>) -> rusqlite::Result<Result<OutboxEntry>> {
    let sequence: i64 = row.get(0)?;
    let archive: Vec<u8> = row.get(1)?;
    let generation: i64 = row.get(2)?;
    let step: String = row.get(3)?;
    let privacy: i64 = row.get(4)?;
    let dispatched: i64 = row.get(5)?;
    Ok((|| {
        Ok(OutboxEntry {
            sequence: u64::try_from(sequence).unwrap_or(0),
            archive_id: ArchiveId::new(uuid(&archive, "an archive identifier")?),
            backup_generation: BackupGeneration::new(u64::try_from(generation).unwrap_or(0)),
            step: Step::parse(&step)?,
            privacy_generation: u64::try_from(privacy).unwrap_or(0),
            dispatched: dispatched != 0,
        })
    })())
}

/// Returns a timestamp as the signed integer SQLite stores.
///
/// Milliseconds since the epoch fit a signed 64-bit integer until the year 292 277 026 596, so the
/// saturation below never happens; it is here because a conversion that could not fail is still a
/// conversion, and the alternative is a cast that wraps.
fn millis(value: TimestampMs) -> i64 {
    i64::try_from(value.get()).unwrap_or(i64::MAX)
}

fn uuid(bytes: &[u8], what: &'static str) -> Result<kr_protocol::scalars::Uuid> {
    <[u8; 16]>::try_from(bytes)
        .map(kr_protocol::scalars::Uuid::from_bytes)
        .map_err(|_| ControllerError::registry(format!("{what} is not sixteen bytes")))
}

fn key_id(bytes: &[u8]) -> Result<KeyId> {
    <[u8; 32]>::try_from(bytes)
        .map(KeyId::from_bytes)
        .map_err(|_| ControllerError::registry("a stored key identifier is not 32 bytes"))
}
