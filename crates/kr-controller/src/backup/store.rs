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

use std::path::{Path, PathBuf};

use kr_protocol::ids::{ArchiveId, BackupGeneration, BackupObjectId};
use kr_protocol::scalars::{Digest256, KeyId, TimestampMs};
use rusqlite::{Connection, OptionalExtension, params};

use crate::error::{ControllerError, Result};

/// The schema version this build reads and writes.
pub const SCHEMA_VERSION: i64 = 1;

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
                "fence",
                "obligations",
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
                 CREATE TABLE IF NOT EXISTS fence (
                     id                 INTEGER PRIMARY KEY CHECK (id = 0),
                     privacy_generation INTEGER NOT NULL,
                     fenced_at_ms       INTEGER NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS obligations (
                     id           INTEGER PRIMARY KEY AUTOINCREMENT,
                     what         TEXT NOT NULL UNIQUE,
                     recorded_at_ms INTEGER NOT NULL
                 );",
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
    /// Returns true when this acknowledgement finished the generation's upload, which is decided
    /// by the object rows and not by how often the caller says so: an acknowledgement repeated
    /// after the upload finished returns true again.
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
        transaction
            .execute(
                "UPDATE objects SET state = ?4, uploaded_bytes = ?5
                 WHERE archive_id = ?1 AND backup_generation = ?2 AND object_id = ?3",
                params![
                    archive_id.get().as_bytes().as_slice(),
                    i64::try_from(backup_generation.get()).unwrap_or(i64::MAX),
                    object_id.get().as_bytes().as_slice(),
                    ObjectState::Uploaded.as_str(),
                    uploaded_len,
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
        if gen_state == GenerationState::Cancelled && outstanding == 0 {
            // A generation privacy mode cancelled while its upload was already in flight keeps
            // that entry until the transfer ends, which is what says the cleanup is not finished.
            // This acknowledgement is the end of it, so the entry goes and nothing is enqueued in
            // its place. A publication that had already left stays, because its answer has not.
            clear_unfinished_work(&transaction, archive_id, backup_generation)?;
            transaction.commit().map_err(ControllerError::registry)?;
            return Ok(true);
        }
        let complete = outstanding == 0 && !gen_state.is_settled();
        if complete {
            let fenced_at: Option<i64> = transaction
                .query_row(
                    "SELECT privacy_generation FROM fence WHERE id = 0",
                    [],
                    |row| row.get(0),
                )
                .optional()
                .map_err(ControllerError::registry)?;
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

    /// Settles one generation and its outbox entries in one transaction.
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
        let transaction = self
            .connection
            .transaction()
            .map_err(ControllerError::registry)?;
        transaction
            .execute(
                "UPDATE generations SET state = ?3, settled_at_ms = ?4, detail = ?5
                 WHERE archive_id = ?1 AND backup_generation = ?2",
                params![
                    archive_id.get().as_bytes().as_slice(),
                    i64::try_from(backup_generation.get()).unwrap_or(i64::MAX),
                    state.as_str(),
                    millis(now_ms),
                    detail,
                ],
            )
            .map_err(ControllerError::registry)?;
        transaction
            .execute(
                "DELETE FROM outbox WHERE archive_id = ?1 AND backup_generation = ?2",
                params![
                    archive_id.get().as_bytes().as_slice(),
                    i64::try_from(backup_generation.get()).unwrap_or(i64::MAX),
                ],
            )
            .map_err(ControllerError::registry)?;
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

    /// Records the privacy generation this host is fenced at.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store refuses the write.
    pub fn record_fence(&mut self, privacy_generation: u64, now_ms: TimestampMs) -> Result<()> {
        self.connection
            .execute(
                "INSERT INTO fence (id, privacy_generation, fenced_at_ms) VALUES (0, ?1, ?2)
                 ON CONFLICT (id) DO UPDATE SET privacy_generation = ?1, fenced_at_ms = ?2",
                params![
                    i64::try_from(privacy_generation).unwrap_or(i64::MAX),
                    millis(now_ms),
                ],
            )
            .map_err(ControllerError::registry)?;
        Ok(())
    }

    /// Records something privacy mode asked for and this host could not do.
    ///
    /// It is durable because a fault that lived in memory would be gone after a restart, and the
    /// content it describes would not: privacy mode would then report complete over ciphertext
    /// still on the disk. The text is the key, so recording the same failure twice records it
    /// once.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store refuses the write.
    pub fn record_obligation(&mut self, what: &str, now_ms: TimestampMs) -> Result<()> {
        self.connection
            .execute(
                "INSERT INTO obligations (what, recorded_at_ms) VALUES (?1, ?2)
                 ON CONFLICT (what) DO NOTHING",
                params![what, millis(now_ms)],
            )
            .map_err(ControllerError::registry)?;
        Ok(())
    }

    /// Clears one obligation, which only its own success does.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store refuses the write.
    pub fn clear_obligation(&mut self, what: &str) -> Result<()> {
        self.connection
            .execute("DELETE FROM obligations WHERE what = ?1", params![what])
            .map_err(ControllerError::registry)?;
        Ok(())
    }

    #[doc(hidden)]
    pub fn set_query_only(&mut self, query_only: bool) -> Result<()> {
        self.connection
            .pragma_update(None, "query_only", if query_only { "ON" } else { "OFF" })
            .map_err(ControllerError::registry)
    }

    /// Returns everything privacy mode asked for that this host has not done.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store cannot be read.
    pub fn obligations(&self) -> Result<Vec<String>> {
        let mut statement = self
            .connection
            .prepare("SELECT what FROM obligations ORDER BY id")
            .map_err(ControllerError::registry)?;
        let rows = statement
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(ControllerError::registry)?;
        let mut outstanding = Vec::new();
        for row in rows {
            outstanding.push(row.map_err(ControllerError::registry)?);
        }
        Ok(outstanding)
    }

    /// Releases the fence, so backup production is admitted again from this moment.
    ///
    /// It is the durable half of turning privacy mode off. Nothing it releases is reconstructed:
    /// the work the fence cancelled stays cancelled, and what is admitted afterwards is admitted
    /// under the new generation.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store refuses the write.
    pub fn release_fence(&mut self) -> Result<()> {
        self.connection
            .execute("DELETE FROM fence WHERE id = 0", [])
            .map_err(ControllerError::registry)?;
        Ok(())
    }

    /// Returns the privacy generation this host recorded a fence at, if it has.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store cannot be read.
    pub fn fenced_at(&self) -> Result<Option<u64>> {
        let recorded: Option<i64> = self
            .connection
            .query_row(
                "SELECT privacy_generation FROM fence WHERE id = 0",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(ControllerError::registry)?;
        Ok(recorded.map(|value| u64::try_from(value).unwrap_or(0)))
    }

    /// Removes one generation's rows and returns its staged paths.
    ///
    /// The caller unlinks the files. The rows go in one transaction, so a generation is never half
    /// forgotten; the files are the caller's because a removal this host could not perform must
    /// not be reported as one it did.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store refuses the write.
    pub fn forget(
        &mut self,
        archive_id: ArchiveId,
        backup_generation: BackupGeneration,
    ) -> Result<Vec<ObjectRecord>> {
        let objects = self.objects(archive_id, backup_generation)?;
        let transaction = self
            .connection
            .transaction()
            .map_err(ControllerError::registry)?;
        transaction
            .execute(
                "DELETE FROM outbox WHERE archive_id = ?1 AND backup_generation = ?2",
                params![
                    archive_id.get().as_bytes().as_slice(),
                    i64::try_from(backup_generation.get()).unwrap_or(i64::MAX),
                ],
            )
            .map_err(ControllerError::registry)?;
        transaction
            .execute(
                "DELETE FROM objects WHERE archive_id = ?1 AND backup_generation = ?2",
                params![
                    archive_id.get().as_bytes().as_slice(),
                    i64::try_from(backup_generation.get()).unwrap_or(i64::MAX),
                ],
            )
            .map_err(ControllerError::registry)?;
        transaction
            .execute(
                "DELETE FROM generations WHERE archive_id = ?1 AND backup_generation = ?2",
                params![
                    archive_id.get().as_bytes().as_slice(),
                    i64::try_from(backup_generation.get()).unwrap_or(i64::MAX),
                ],
            )
            .map_err(ControllerError::registry)?;
        transaction.commit().map_err(ControllerError::registry)?;
        Ok(objects)
    }

    /// Marks one generation's objects as no longer staged on this host.
    ///
    /// The state says where the ciphertext is, and after this it is nowhere here. What the service
    /// acknowledged is not written over: `uploaded_bytes` keeps it, so an object that had arrived
    /// before its staged copy was removed is still an object that arrived.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store refuses the write.
    pub fn note_objects_removed(
        &mut self,
        archive_id: ArchiveId,
        backup_generation: BackupGeneration,
    ) -> Result<()> {
        self.connection
            .execute(
                "UPDATE objects SET state = ?3
                 WHERE archive_id = ?1 AND backup_generation = ?2",
                params![
                    archive_id.get().as_bytes().as_slice(),
                    i64::try_from(backup_generation.get()).unwrap_or(i64::MAX),
                    ObjectState::Removed.as_str(),
                ],
            )
            .map_err(ControllerError::registry)?;
        Ok(())
    }

    /// Cancels every undispatched outbox entry and settles every generation still producing, in
    /// one transaction.
    ///
    /// Returns how many entries were taken back and how many were already dispatched. The second
    /// figure is what reconciliation waits on: dispatched work has left this host and cannot be
    /// taken back, only followed. Its entry therefore stays, which is the one place in this store
    /// where a settled generation has an outbox that is not yet empty; [`Self::settle`] and the
    /// completion paths of [`Self::note_object_uploaded`] are what empty it.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store refuses the write.
    pub fn cancel_undispatched(&mut self, now_ms: TimestampMs, detail: &str) -> Result<(u64, u64)> {
        let entries = self.outbox()?;
        let dispatched = entries.iter().filter(|entry| entry.dispatched).count() as u64;
        let taken_back: Vec<&OutboxEntry> =
            entries.iter().filter(|entry| !entry.dispatched).collect();
        let transaction = self
            .connection
            .transaction()
            .map_err(ControllerError::registry)?;
        for entry in &taken_back {
            transaction
                .execute(
                    "DELETE FROM outbox WHERE sequence = ?1",
                    params![i64::try_from(entry.sequence).unwrap_or(i64::MAX)],
                )
                .map_err(ControllerError::registry)?;
        }
        // Every generation still producing is cancelled, whether or not any of it had been
        // dispatched. A generation with work already in flight keeps that entry, so the cleanup it
        // owes stays visible until the transfer ends, but the record settles now: an upload that
        // finishes afterwards must find a generation nothing may be published for, and a fence
        // that is released in between must not turn that upload into a late publication.
        //
        // Two statements because the two say different things. The first runs before the second
        // takes the rest, so each generation is described by what was actually true of it.
        transaction
            .execute(
                "UPDATE generations SET state = ?1, settled_at_ms = ?2, detail = ?3
                 WHERE state IN (?4, ?5)
                   AND EXISTS (SELECT 1 FROM outbox
                               WHERE outbox.archive_id = generations.archive_id
                                 AND outbox.backup_generation = generations.backup_generation
                                 AND outbox.dispatched = 1)",
                params![
                    GenerationState::Cancelled.as_str(),
                    millis(now_ms),
                    format!(
                        "{detail}, and what had already left this host is followed to its answer"
                    ),
                    GenerationState::Staging.as_str(),
                    GenerationState::Uploading.as_str(),
                ],
            )
            .map_err(ControllerError::registry)?;
        transaction
            .execute(
                "UPDATE generations SET state = ?1, settled_at_ms = ?2, detail = ?3
                 WHERE state IN (?4, ?5)",
                params![
                    GenerationState::Cancelled.as_str(),
                    millis(now_ms),
                    detail,
                    GenerationState::Staging.as_str(),
                    GenerationState::Uploading.as_str(),
                ],
            )
            .map_err(ControllerError::registry)?;
        transaction.commit().map_err(ControllerError::registry)?;
        Ok((taken_back.len() as u64, dispatched))
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
    transaction
        .execute(
            "DELETE FROM outbox
             WHERE archive_id = ?1 AND backup_generation = ?2 AND (step = ?3 OR dispatched = 0)",
            params![
                archive_id.get().as_bytes().as_slice(),
                i64::try_from(backup_generation.get()).unwrap_or(i64::MAX),
                Step::Upload.as_str(),
            ],
        )
        .map_err(ControllerError::registry)?;
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
