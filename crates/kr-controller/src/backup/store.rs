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
///
/// The rules a store enforces are part of its schema: a database written when one of them was
/// weaker is a database this build cannot vouch for, and it is refused by version rather than
/// opened and quietly held to the weaker rule. Every rule change therefore moves this number.
pub const SCHEMA_VERSION: i64 = 4;

/// Whether this host may go on producing for one generation.
///
/// This is permission, and nothing else. What a service holds is [`Remote`], recorded beside it:
/// a generation privacy mode cancelled while its publication was already out there carries both
/// facts at once, and neither one overwrites the other.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Production {
    /// This host may still stage, enqueue and dispatch for it.
    Producing,
    /// Production is prohibited, permanently, for the reason in `detail`.
    ///
    /// Privacy mode fencing this host, or a writer this host no longer holds an enrolment for.
    /// Nothing turns it back into [`Self::Producing`]: what is admitted after a fence is released
    /// is admitted afresh, under the generation that released it.
    Cancelled,
    /// Production finished: the service accepted this generation's descriptor.
    Complete,
}

impl Production {
    /// Returns the stable name this is stored and reported under.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Producing => "producing",
            Self::Cancelled => "cancelled",
            Self::Complete => "complete",
        }
    }

    /// Returns true when this host will produce nothing more for this generation.
    #[must_use]
    pub const fn is_over(self) -> bool {
        matches!(self, Self::Cancelled | Self::Complete)
    }

    fn parse(text: &str) -> Result<Self> {
        match text {
            "producing" => Ok(Self::Producing),
            "cancelled" => Ok(Self::Cancelled),
            "complete" => Ok(Self::Complete),
            other => Err(ControllerError::registry(format!(
                "a backup generation's production is {other}, which this build does not read"
            ))),
        }
    }
}

/// What this host can establish about what a service holds of one generation.
///
/// It only ever moves away from [`Self::Nothing`]. Evidence that ciphertext reached a service is
/// not withdrawn by anything this host does afterwards, which is what keeps a cancelled
/// generation's artifacts visible instead of tidied away with its production bookkeeping.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Remote {
    /// Nothing of it has been acknowledged and nothing of it has left unanswered.
    Nothing,
    /// A service acknowledged ciphertext of it, and no descriptor was published.
    Objects,
    /// A service accepted its descriptor.
    Published,
    /// Something of it left this host and this host cannot establish what became of it.
    ///
    /// Section 23's `OUTCOME_UNKNOWN`, recorded rather than guessed at: a host that wrote either
    /// answer would be writing something it does not know.
    Unknown,
}

impl Remote {
    /// Returns the stable name this is stored and reported under.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Nothing => "none",
            Self::Objects => "objects",
            Self::Published => "published",
            Self::Unknown => "unknown",
        }
    }

    /// Returns true when a service may hold something of this generation.
    #[must_use]
    pub const fn is_artifact(self) -> bool {
        !matches!(self, Self::Nothing)
    }

    fn parse(text: &str) -> Result<Self> {
        match text {
            "none" => Ok(Self::Nothing),
            "objects" => Ok(Self::Objects),
            "published" => Ok(Self::Published),
            "unknown" => Ok(Self::Unknown),
            other => Err(ControllerError::registry(format!(
                "a backup generation's remote outcome is {other}, which this build does not read"
            ))),
        }
    }
}

/// Where one object's ciphertext is on this host.
///
/// Local presence, and nothing else. What a service acknowledged is
/// [`ObjectRecord::acknowledged_bytes`], a separate column: an acknowledgement never puts a file
/// back, and a removal never unsays an acknowledgement.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LocalState {
    /// Its ciphertext is staged on this host.
    Present,
    /// Its ciphertext has been removed from this host.
    Absent,
}

impl LocalState {
    /// Returns the stable name this is stored under.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Present => "present",
            Self::Absent => "absent",
        }
    }

    fn parse(text: &str) -> Result<Self> {
        match text {
            "present" => Ok(Self::Present),
            "absent" => Ok(Self::Absent),
            other => Err(ControllerError::registry(format!(
                "a backup object's staged copy is {other}, which this build does not read"
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

/// Where one dispatch attempt has got to.
///
/// It moves one way. `queued` becomes `dispatched` when this host hands the attempt over, and
/// either becomes `terminal` when something establishes how that exact attempt ended. Nothing
/// turns a dispatched attempt back into a queued one: work that has left this host cannot be taken
/// back, and a row relabelled as though it had never gone would be a cancellation standing in for
/// an answer nobody ever got. A resumed step is a *new* attempt beside the old one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AttemptStatus {
    /// Admitted on this host and never handed over.
    Queued,
    /// Handed to the executor named beside it, with no answer yet.
    Dispatched,
    /// Over, with the outcome recorded beside it.
    Terminal,
}

impl AttemptStatus {
    /// Returns the stable name this is stored under.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Dispatched => "dispatched",
            Self::Terminal => "terminal",
        }
    }

    /// Returns true when this host is still owed an answer about the attempt.
    #[must_use]
    pub const fn is_open(self) -> bool {
        matches!(self, Self::Queued | Self::Dispatched)
    }

    fn parse(text: &str) -> Result<Self> {
        match text {
            "queued" => Ok(Self::Queued),
            "dispatched" => Ok(Self::Dispatched),
            "terminal" => Ok(Self::Terminal),
            other => Err(ControllerError::registry(format!(
                "a backup dispatch attempt is {other}, which this build does not read"
            ))),
        }
    }
}

/// How one dispatch attempt ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AttemptOutcome {
    /// The service took what this attempt carried.
    Accepted,
    /// It never left this host, and it never will.
    Cancelled,
    /// It left this host, the transfer stopped, and no answer arrived.
    Stopped,
}

impl AttemptOutcome {
    /// Returns the stable name this is stored under.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Cancelled => "cancelled",
            Self::Stopped => "stopped",
        }
    }

    fn parse(text: &str) -> Result<Self> {
        match text {
            "accepted" => Ok(Self::Accepted),
            "cancelled" => Ok(Self::Cancelled),
            "stopped" => Ok(Self::Stopped),
            other => Err(ControllerError::registry(format!(
                "a backup dispatch attempt ended as {other}, which this build does not read"
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
    /// Whether this host may go on producing for it.
    pub production: Production,
    /// What this host can establish about what a service holds of it.
    pub remote: Remote,
    /// The writer whose signature its manifest and publication carry.
    pub writer_key_id: KeyId,
    /// The privacy generation this host admitted it under.
    ///
    /// The store stamps it from its own durable state when the work is admitted, and nothing
    /// changes it afterwards. A result that comes back carrying another one belongs to work
    /// privacy mode has already drawn a line under.
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
    /// Whether that ciphertext is still here.
    pub local_state: LocalState,
    /// How many bytes a service has acknowledged, so a resume knows where to continue.
    ///
    /// It never decreases, and it is never touched by a removal: what a service holds and where
    /// the ciphertext is are two facts, and each is recorded on its own terms.
    pub acknowledged_bytes: u64,
}

impl ObjectRecord {
    /// Returns true when a service has acknowledged the whole object.
    #[must_use]
    pub const fn is_acknowledged(&self) -> bool {
        self.acknowledged_bytes >= self.encrypted_len
    }
}

/// One dispatch attempt: a step this host took, or is taking, for one generation.
///
/// The `sequence` is its identity and never changes. Neither do the archive, the generation, the
/// step or the privacy generation it was admitted under, so an attempt is always the same piece of
/// work, and the answer that ends it can only ever end that one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attempt {
    /// Its identity, from the moment it was enqueued.
    pub sequence: u64,
    /// The archive.
    pub archive_id: ArchiveId,
    /// The generation.
    pub backup_generation: BackupGeneration,
    /// What it carries.
    pub step: Step,
    /// The privacy generation the work was admitted under.
    pub privacy_generation: u64,
    /// Where it has got to.
    pub status: AttemptStatus,
    /// How it ended, once it has.
    pub outcome: Option<AttemptOutcome>,
    /// Who holds it, once it has left this host.
    pub executor: Option<String>,
}

/// One generation offered for admission.
///
/// It carries what the producer knows and nothing else. Where production has got to, what a
/// service holds and which privacy generation the work belongs to are the store's to decide, so
/// there is nowhere in this type for a caller to put a generation it read earlier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewGeneration {
    /// The archive.
    pub archive_id: ArchiveId,
    /// The generation.
    pub backup_generation: BackupGeneration,
    /// The writer whose signature its manifest carries.
    pub writer_key_id: KeyId,
    /// The canonical descriptor bytes this generation was sealed with.
    pub descriptor: Vec<u8>,
    /// When it was produced.
    pub created_at_ms: TimestampMs,
}

/// One object offered with a generation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewObject {
    /// The object.
    pub object_id: BackupObjectId,
    /// The SHA-256 of its ciphertext.
    pub encrypted_object_hash: Digest256,
    /// The size of its ciphertext.
    pub encrypted_len: u64,
    /// Where that ciphertext is staged on this host.
    pub staged_path: PathBuf,
}

/// What admitting one generation wrote down.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Admission {
    /// The upload attempt that will carry it.
    pub sequence: u64,
    /// The privacy generation the store admitted it under, read from its own durable state.
    pub privacy_generation: u64,
}

/// What recording one accepted publication did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Publication {
    /// It is this host's archive for that generation, and production of it is complete.
    Recorded,
    /// A service accepted work privacy mode had already drawn a line under.
    ///
    /// The artifact is written down and the attempt that carried it is over. No descriptor of this
    /// host's becomes current, no local content comes back, and production stays prohibited.
    RetainedArtifact {
        /// The privacy generation the work was admitted under.
        privacy_generation: u64,
    },
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
        // No statement this store executes resolves a conflict by deleting the row it collided
        // with: there is no `REPLACE` clause anywhere in it, and an insert that would repeat an
        // obligation asks whether it is already there instead. Recursive triggers make that hold
        // twice over. A delete performed as conflict resolution runs the delete triggers only with
        // this on, so a statement that reached this store by any other route still meets the rules
        // that guard a delete rather than slipping under them.
        connection
            .pragma_update(None, "recursive_triggers", "ON")
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
                     production         TEXT NOT NULL,
                     remote             TEXT NOT NULL,
                     writer_key_id      BLOB NOT NULL,
                     privacy_generation INTEGER NOT NULL,
                     descriptor         BLOB,
                     created_at_ms      INTEGER NOT NULL,
                     settled_at_ms      INTEGER,
                     detail             TEXT,
                     PRIMARY KEY (archive_id, backup_generation),
                     CHECK (production IN ('producing', 'cancelled', 'complete')),
                     CHECK (remote IN ('none', 'objects', 'published', 'unknown'))
                 );
                 CREATE TABLE IF NOT EXISTS objects (
                     archive_id         BLOB NOT NULL,
                     backup_generation  INTEGER NOT NULL,
                     object_id          BLOB NOT NULL,
                     encrypted_hash     BLOB NOT NULL,
                     encrypted_len      INTEGER NOT NULL,
                     staged_path        TEXT NOT NULL,
                     local_state        TEXT NOT NULL,
                     acknowledged_bytes INTEGER NOT NULL DEFAULT 0,
                     PRIMARY KEY (archive_id, backup_generation, object_id),
                     FOREIGN KEY (archive_id, backup_generation)
                         REFERENCES generations (archive_id, backup_generation),
                     CHECK (local_state IN ('present', 'absent'))
                 );
                 CREATE TABLE IF NOT EXISTS outbox (
                     sequence           INTEGER PRIMARY KEY AUTOINCREMENT,
                     archive_id         BLOB NOT NULL,
                     backup_generation  INTEGER NOT NULL,
                     step               TEXT NOT NULL,
                     privacy_generation INTEGER NOT NULL,
                     status             TEXT NOT NULL,
                     outcome            TEXT,
                     executor           TEXT,
                     enqueued_at_ms     INTEGER NOT NULL,
                     dispatched_at_ms   INTEGER,
                     settled_at_ms      INTEGER,
                     FOREIGN KEY (archive_id, backup_generation)
                         REFERENCES generations (archive_id, backup_generation),
                     CHECK (step IN ('upload', 'publish')),
                     CHECK (status IN ('queued', 'dispatched', 'terminal')),
                     CHECK (outcome IS NULL
                            OR outcome IN ('accepted', 'cancelled', 'stopped')),
                     CHECK ((status = 'terminal') = (outcome IS NOT NULL)),
                     CHECK (status <> 'dispatched' OR executor IS NOT NULL)
                 );
                 CREATE UNIQUE INDEX IF NOT EXISTS one_publication_per_generation
                     ON outbox (archive_id, backup_generation)
                  WHERE step = 'publish'
                    AND (status <> 'terminal' OR outcome = 'accepted');
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
                     entry_sequence     INTEGER REFERENCES outbox (sequence),
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
                 CREATE TRIGGER IF NOT EXISTS a_generation_is_never_replaced
                 BEFORE INSERT ON generations
                 WHEN EXISTS (SELECT 1 FROM generations
                               WHERE archive_id = NEW.archive_id
                                 AND backup_generation = NEW.backup_generation)
                 BEGIN
                     SELECT RAISE(ABORT, 'that backup generation is already admitted on this host');
                 END;
                 CREATE TRIGGER IF NOT EXISTS an_object_is_never_replaced
                 BEFORE INSERT ON objects
                 WHEN EXISTS (SELECT 1 FROM objects
                               WHERE archive_id = NEW.archive_id
                                 AND backup_generation = NEW.backup_generation
                                 AND object_id = NEW.object_id)
                 BEGIN
                     SELECT RAISE(ABORT, 'that backup object is already recorded on this host');
                 END;
                 CREATE TRIGGER IF NOT EXISTS an_attempt_is_never_replaced
                 BEFORE INSERT ON outbox
                 WHEN EXISTS (SELECT 1 FROM outbox WHERE sequence = NEW.sequence)
                   OR (NEW.step = 'publish'
                       AND (NEW.status <> 'terminal' OR NEW.outcome = 'accepted')
                       AND EXISTS (SELECT 1 FROM outbox
                                    WHERE archive_id = NEW.archive_id
                                      AND backup_generation = NEW.backup_generation
                                      AND step = 'publish'
                                      AND (status <> 'terminal' OR outcome = 'accepted')))
                 BEGIN
                     SELECT RAISE(ABORT, 'a backup dispatch attempt keeps its own identity');
                 END;
                 CREATE TRIGGER IF NOT EXISTS a_generation_keeps_what_it_was_admitted_under
                 BEFORE UPDATE OF privacy_generation ON generations
                 WHEN NEW.privacy_generation <> OLD.privacy_generation
                 BEGIN
                     SELECT RAISE(ABORT, 'a backup generation keeps the privacy generation it was \
                                          admitted under');
                 END;
                 CREATE TRIGGER IF NOT EXISTS a_generation_keeps_the_archive_it_is_of
                 BEFORE UPDATE ON generations
                 WHEN NEW.archive_id <> OLD.archive_id
                   OR NEW.backup_generation <> OLD.backup_generation
                 BEGIN
                     SELECT RAISE(ABORT, 'a backup generation keeps the archive it is of');
                 END;
                 CREATE TRIGGER IF NOT EXISTS an_object_keeps_what_it_is
                 BEFORE UPDATE ON objects
                 WHEN NEW.archive_id <> OLD.archive_id
                   OR NEW.backup_generation <> OLD.backup_generation
                   OR NEW.object_id <> OLD.object_id
                   OR NEW.encrypted_hash <> OLD.encrypted_hash
                   OR NEW.encrypted_len <> OLD.encrypted_len
                   OR NEW.staged_path <> OLD.staged_path
                 BEGIN
                     SELECT RAISE(ABORT, 'a backup object keeps its identity, its ciphertext hash \
                                          and where it was staged');
                 END;
                 CREATE TRIGGER IF NOT EXISTS the_privacy_generation_never_moves_backwards
                 BEFORE UPDATE OF current_generation ON privacy_state
                 WHEN NEW.current_generation < OLD.current_generation
                 BEGIN
                     SELECT RAISE(ABORT, 'the privacy generation in force never moves backwards');
                 END;
                 CREATE TRIGGER IF NOT EXISTS production_never_resumes
                 BEFORE UPDATE OF production ON generations
                 WHEN OLD.production <> 'producing' AND NEW.production <> OLD.production
                 BEGIN
                     SELECT RAISE(ABORT, 'backup production that has ended is never resumed');
                 END;
                 CREATE TRIGGER IF NOT EXISTS remote_evidence_is_never_withdrawn
                 BEFORE UPDATE OF remote ON generations
                 WHEN (NEW.remote = 'none' AND OLD.remote <> 'none')
                   OR (OLD.remote = 'published' AND NEW.remote <> 'published')
                 BEGIN
                     SELECT RAISE(ABORT, 'what a service holds of a backup generation is never \
                                          unsaid');
                 END;
                 CREATE TRIGGER IF NOT EXISTS a_removed_staged_copy_never_returns
                 BEFORE UPDATE OF local_state ON objects
                 WHEN OLD.local_state = 'absent' AND NEW.local_state <> 'absent'
                 BEGIN
                     SELECT RAISE(ABORT, 'a staged copy this host removed is never recorded as \
                                          present again');
                 END;
                 CREATE TRIGGER IF NOT EXISTS an_acknowledgement_is_never_withdrawn
                 BEFORE UPDATE OF acknowledged_bytes ON objects
                 WHEN NEW.acknowledged_bytes < OLD.acknowledged_bytes
                 BEGIN
                     SELECT RAISE(ABORT, 'what a service acknowledged of a backup object is never \
                                          unsaid');
                 END;
                 CREATE TRIGGER IF NOT EXISTS an_attempt_keeps_what_it_is
                 BEFORE UPDATE ON outbox
                 WHEN NEW.sequence <> OLD.sequence
                   OR NEW.archive_id <> OLD.archive_id
                   OR NEW.backup_generation <> OLD.backup_generation
                   OR NEW.step <> OLD.step
                   OR NEW.privacy_generation <> OLD.privacy_generation
                 BEGIN
                     SELECT RAISE(ABORT, 'a backup dispatch attempt keeps its identity, the work \
                                          it carries and the privacy generation it was enqueued \
                                          for');
                 END;
                 CREATE TRIGGER IF NOT EXISTS an_attempt_never_goes_back_in_hand
                 BEFORE UPDATE OF status ON outbox
                 WHEN NEW.status <> OLD.status
                  AND NOT (OLD.status = 'queued' AND NEW.status IN ('dispatched', 'terminal'))
                  AND NOT (OLD.status = 'dispatched' AND NEW.status = 'terminal')
                 BEGIN
                     SELECT RAISE(ABORT, 'a backup dispatch attempt never returns to an earlier \
                                          state');
                 END;
                 CREATE TRIGGER IF NOT EXISTS an_attempt_ends_as_what_it_was
                 BEFORE UPDATE OF status ON outbox
                 WHEN NEW.status = 'terminal'
                  AND ((OLD.status = 'dispatched' AND NEW.outcome = 'cancelled')
                    OR (OLD.status = 'queued' AND NEW.outcome <> 'cancelled'))
                 BEGIN
                     SELECT RAISE(ABORT, 'an attempt that left this host is never cancelled, and \
                                          one that never left is never answered');
                 END;
                 CREATE TRIGGER IF NOT EXISTS an_upload_is_written_accepted_only_once_its_objects_are_held
                 BEFORE INSERT ON outbox
                 WHEN NEW.status = 'terminal' AND NEW.outcome = 'accepted'
                  AND NEW.step = 'upload'
                  AND EXISTS (SELECT 1 FROM objects
                               WHERE archive_id = NEW.archive_id
                                 AND backup_generation = NEW.backup_generation
                                 AND acknowledged_bytes < encrypted_len)
                 BEGIN
                     SELECT RAISE(ABORT, 'a backup upload ends as accepted only once a service \
                                          holds every object of its generation');
                 END;
                 CREATE TRIGGER IF NOT EXISTS a_publication_is_written_accepted_only_once_it_is_held
                 BEFORE INSERT ON outbox
                 WHEN NEW.status = 'terminal' AND NEW.outcome = 'accepted'
                  AND NEW.step = 'publish'
                  AND NOT EXISTS (SELECT 1 FROM generations
                                   WHERE archive_id = NEW.archive_id
                                     AND backup_generation = NEW.backup_generation
                                     AND remote = 'published')
                 BEGIN
                     SELECT RAISE(ABORT, 'a backup publication ends as accepted only once this \
                                          host has written down that a service holds it');
                 END;
                 CREATE TRIGGER IF NOT EXISTS an_upload_ends_as_accepted_only_once_its_objects_are_held
                 BEFORE UPDATE OF status ON outbox
                 WHEN NEW.status = 'terminal' AND NEW.outcome = 'accepted'
                  AND OLD.step = 'upload'
                  AND EXISTS (SELECT 1 FROM objects
                               WHERE archive_id = OLD.archive_id
                                 AND backup_generation = OLD.backup_generation
                                 AND acknowledged_bytes < encrypted_len)
                 BEGIN
                     SELECT RAISE(ABORT, 'a backup upload ends as accepted only once a service \
                                          holds every object of its generation');
                 END;
                 CREATE TRIGGER IF NOT EXISTS a_publication_ends_as_accepted_only_once_it_is_held
                 BEFORE UPDATE OF status ON outbox
                 WHEN NEW.status = 'terminal' AND NEW.outcome = 'accepted'
                  AND OLD.step = 'publish'
                  AND NOT EXISTS (SELECT 1 FROM generations
                                   WHERE archive_id = OLD.archive_id
                                     AND backup_generation = OLD.backup_generation
                                     AND remote = 'published')
                 BEGIN
                     SELECT RAISE(ABORT, 'a backup publication ends as accepted only once this \
                                          host has written down that a service holds it');
                 END;
                 CREATE TRIGGER IF NOT EXISTS an_attempt_ends_as_stopped_only_once_that_is_written_down
                 BEFORE UPDATE OF status ON outbox
                 WHEN NEW.status = 'terminal' AND NEW.outcome = 'stopped'
                  AND NOT EXISTS (SELECT 1 FROM generations
                                   WHERE archive_id = OLD.archive_id
                                     AND backup_generation = OLD.backup_generation
                                     AND remote <> 'none')
                 BEGIN
                     SELECT RAISE(ABORT, 'an attempt ends as stopped only once this host has \
                                          written down what a service may hold of its generation');
                 END;
                 CREATE TRIGGER IF NOT EXISTS an_attempt_is_written_stopped_only_once_that_is_written_down
                 BEFORE INSERT ON outbox
                 WHEN NEW.status = 'terminal' AND NEW.outcome = 'stopped'
                  AND NOT EXISTS (SELECT 1 FROM generations
                                   WHERE archive_id = NEW.archive_id
                                     AND backup_generation = NEW.backup_generation
                                     AND remote <> 'none')
                 BEGIN
                     SELECT RAISE(ABORT, 'an attempt ends as stopped only once this host has \
                                          written down what a service may hold of its generation');
                 END;
                 CREATE TRIGGER IF NOT EXISTS an_attempt_still_owed_an_answer_is_not_deleted
                 BEFORE DELETE ON outbox
                 WHEN OLD.status <> 'terminal'
                 BEGIN
                     SELECT RAISE(ABORT, 'a backup dispatch attempt this host is still owed an \
                                          answer for is not deleted');
                 END;
                 CREATE TRIGGER IF NOT EXISTS cleanup_naming_an_open_attempt_is_not_deleted
                 BEFORE DELETE ON privacy_obligations
                 WHEN OLD.entry_sequence IS NOT NULL
                  AND EXISTS (SELECT 1 FROM outbox
                               WHERE sequence = OLD.entry_sequence
                                 AND status <> 'terminal')
                 BEGIN
                     SELECT RAISE(ABORT, 'cleanup for an attempt this host is still owed an \
                                          answer for is not discharged');
                 END;
                 CREATE TRIGGER IF NOT EXISTS an_attempt_keeps_the_executor_it_left_with
                 BEFORE UPDATE OF executor ON outbox
                 WHEN OLD.executor IS NOT NULL
                  AND (NEW.executor IS NULL OR NEW.executor <> OLD.executor)
                 BEGIN
                     SELECT RAISE(ABORT, 'a backup dispatch attempt keeps the executor it was \
                                          handed to');
                 END;
                 CREATE TRIGGER IF NOT EXISTS a_finished_attempt_keeps_its_outcome
                 BEFORE UPDATE OF outcome ON outbox
                 WHEN OLD.outcome IS NOT NULL AND NEW.outcome <> OLD.outcome
                 BEGIN
                     SELECT RAISE(ABORT, 'a backup dispatch attempt that ended keeps how it ended');
                 END;
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
                 CREATE TRIGGER IF NOT EXISTS an_obligation_keeps_what_it_is_owed_for
                 BEFORE UPDATE ON privacy_obligations
                 WHEN NEW.id IS NOT OLD.id
                   OR NEW.kind IS NOT OLD.kind
                   OR NEW.target_key IS NOT OLD.target_key
                   OR NEW.archive_id IS NOT OLD.archive_id
                   OR NEW.backup_generation IS NOT OLD.backup_generation
                   OR NEW.object_id IS NOT OLD.object_id
                   OR NEW.staged_path IS NOT OLD.staged_path
                   OR NEW.entry_sequence IS NOT OLD.entry_sequence
                   OR NEW.recorded_at_ms IS NOT OLD.recorded_at_ms
                 BEGIN
                     SELECT RAISE(ABORT, 'cleanup keeps what it is owed for and when it was \
                                          written down; only how often it has been tried and why \
                                          it failed ever change');
                 END;
                 CREATE TRIGGER IF NOT EXISTS an_obligation_is_never_replaced
                 BEFORE INSERT ON privacy_obligations
                 WHEN EXISTS (SELECT 1 FROM privacy_obligations WHERE id = NEW.id)
                   OR EXISTS (SELECT 1 FROM privacy_obligations
                               WHERE privacy_generation = NEW.privacy_generation
                                 AND kind = NEW.kind
                                 AND target_key = NEW.target_key)
                 BEGIN
                     SELECT RAISE(ABORT, 'cleanup this host already owes is never written over');
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

    /// Admits one generation: its record, its object rows and its first upload attempt, together.
    ///
    /// Together is the point. A generation recorded without its attempt would be work this host
    /// had taken on and would never do; an attempt without its generation would be work with no
    /// account of what it was for.
    ///
    /// The privacy generation is read from this store's own durable state inside this transaction
    /// and stamped on the row, and a caller has no way to supply one. That is what makes admission
    /// after a fence released into a newer generation impossible rather than merely unlikely: work
    /// carrying a generation somebody read earlier cannot be admitted, because nothing carries one.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::Refused`] when backup production is inhibited, and
    /// [`ControllerError::RegistryUnavailable`] when the store refuses the write.
    pub fn admit(
        &mut self,
        offered: &NewGeneration,
        objects: &[NewObject],
        now_ms: TimestampMs,
    ) -> Result<Admission> {
        let archive = offered.archive_id.get().as_bytes().to_vec();
        let generation = i64::try_from(offered.backup_generation.get()).unwrap_or(i64::MAX);
        let transaction = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(ControllerError::registry)?;
        if let Some(inhibited_at) = inhibited_at(&transaction)? {
            return Err(ControllerError::Refused {
                code: kr_protocol::error::ErrorCode::PermissionDenied,
                detail: format!("backup production is fenced at privacy generation {inhibited_at}"),
            });
        }
        let privacy_generation = current_generation(&transaction)?;
        transaction
            .execute(
                "INSERT INTO generations
                     (archive_id, backup_generation, production, remote, writer_key_id,
                      privacy_generation, descriptor, created_at_ms, settled_at_ms, detail)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, NULL, NULL)",
                params![
                    archive,
                    generation,
                    Production::Producing.as_str(),
                    Remote::Nothing.as_str(),
                    offered.writer_key_id.as_bytes().as_slice(),
                    privacy_generation,
                    offered.descriptor.as_slice(),
                    millis(offered.created_at_ms),
                ],
            )
            .map_err(ControllerError::registry)?;
        for object in objects {
            transaction
                .execute(
                    "INSERT INTO objects
                         (archive_id, backup_generation, object_id, encrypted_hash, encrypted_len,
                          staged_path, local_state, acknowledged_bytes)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0)",
                    params![
                        archive,
                        generation,
                        object.object_id.get().as_bytes().as_slice(),
                        object.encrypted_object_hash.as_bytes().as_slice(),
                        i64::try_from(object.encrypted_len).unwrap_or(i64::MAX),
                        object.staged_path.to_string_lossy().as_ref(),
                        LocalState::Present.as_str(),
                    ],
                )
                .map_err(ControllerError::registry)?;
        }
        let sequence = enqueue(
            &transaction,
            offered.archive_id,
            offered.backup_generation,
            Step::Upload,
            now_ms,
        )?;
        transaction.commit().map_err(ControllerError::registry)?;
        Ok(Admission {
            sequence,
            privacy_generation: u64::try_from(privacy_generation).unwrap_or(0),
        })
    }

    /// Records that one object's ciphertext reached a service, as the attempt that carried it.
    ///
    /// Returns true when the generation has no object left to arrive. That is a fact about the
    /// object rows and not about the call, so an acknowledgement repeated after the upload
    /// finished returns true again, whatever became of the generation afterwards.
    ///
    /// The acknowledgement changes what a service holds and nothing else. Where the ciphertext is
    /// stays exactly as it was: an object privacy mode has already removed stays removed, and this
    /// never puts a file back.
    ///
    /// **No attempt ends here**, not even the one that delivered this object. One object arriving
    /// is not the end of a transfer, and a generation with nothing left outstanding is a fact
    /// about its objects rather than about any executor: an attempt that has sent every object it
    /// was asked for may still be sending, and the acknowledgements that completed the generation
    /// may have come from a different attempt altogether. Only the executor holding an attempt can
    /// say that it finished, through [`Self::note_attempt_accepted`].
    ///
    /// Completion still decides what this host does next, because that part needs no evidence
    /// about a transfer: the publication is enqueued, or, where the production rule refuses,
    /// undispatched work is taken back and production is cancelled.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::InvalidArgument`] when the attempt is not an upload attempt of
    /// that generation that left this host, and [`ControllerError::RegistryUnavailable`] when the
    /// store refuses the write.
    pub fn note_object_uploaded(
        &mut self,
        attempt: u64,
        archive_id: ArchiveId,
        backup_generation: BackupGeneration,
        object_id: BackupObjectId,
        now_ms: TimestampMs,
    ) -> Result<bool> {
        let archive = archive_id.get().as_bytes().to_vec();
        let generation = i64::try_from(backup_generation.get()).unwrap_or(i64::MAX);
        let attempt = i64::try_from(attempt).unwrap_or(i64::MAX);
        let transaction = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(ControllerError::registry)?;
        // The attempt that carried it, checked against the work it was enqueued for. An
        // acknowledgement is evidence about one transfer, so it has to name the transfer it came
        // from; one that named another generation's attempt could end a wait nobody had answered.
        let carrier: Option<String> = transaction
            .query_row(
                "SELECT status FROM outbox
                  WHERE sequence = ?1 AND archive_id = ?2 AND backup_generation = ?3
                    AND step = ?4 AND status <> 'queued'",
                params![attempt, archive, generation, Step::Upload.as_str()],
                |row| row.get(0),
            )
            .optional()
            .map_err(ControllerError::registry)?;
        if carrier.is_none() {
            return Err(ControllerError::InvalidArgument(
                "that is not an upload attempt of that backup generation that left this host"
                    .to_owned(),
            ));
        }
        let encrypted_len: Option<i64> = transaction
            .query_row(
                "SELECT encrypted_len FROM objects
                 WHERE archive_id = ?1 AND backup_generation = ?2 AND object_id = ?3",
                params![archive, generation, object_id.get().as_bytes().as_slice()],
                |row| row.get(0),
            )
            .optional()
            .map_err(ControllerError::registry)?;
        let Some(encrypted_len) = encrypted_len else {
            return Err(ControllerError::registry(
                "that object is not one this host staged",
            ));
        };
        // What a service holds, written down on its own terms. `MAX` because an acknowledgement is
        // never withdrawn: a repeat that named fewer bytes would be a service unsaying something
        // it had already said, which the store does not record and a trigger refuses.
        transaction
            .execute(
                "UPDATE objects SET acknowledged_bytes = MAX(acknowledged_bytes, ?4)
                 WHERE archive_id = ?1 AND backup_generation = ?2 AND object_id = ?3",
                params![
                    archive,
                    generation,
                    object_id.get().as_bytes().as_slice(),
                    encrypted_len
                ],
            )
            .map_err(ControllerError::registry)?;
        // The generation now has an artifact somewhere other than this host, whatever becomes of
        // its production. That is the fact a cancelled generation keeps.
        note_remote(&transaction, archive_id, backup_generation, Remote::Objects)?;

        let outstanding: i64 = transaction
            .query_row(
                "SELECT COUNT(*) FROM objects
                 WHERE archive_id = ?1 AND backup_generation = ?2
                   AND acknowledged_bytes < encrypted_len",
                params![archive, generation],
                |row| row.get(0),
            )
            .map_err(ControllerError::registry)?;
        let complete = outstanding == 0;
        if complete {
            // Every object of the generation is at a service. No attempt ends on that: this one
            // may still be sending what another attempt had already delivered, and an attempt that
            // had left keeps its row and whatever cleanup names it until its own executor or a
            // caller says what became of it.
            match production_refusal(&transaction, archive_id, backup_generation)? {
                None => {
                    // Exactly one publication, ever. A second acknowledgement of an object that had
                    // already arrived would otherwise enqueue a second descriptor for the same
                    // generation.
                    let already: i64 = transaction
                        .query_row(
                            "SELECT COUNT(*) FROM outbox
                              WHERE archive_id = ?1 AND backup_generation = ?2 AND step = ?3
                                AND (status <> 'terminal' OR outcome = 'accepted')",
                            params![archive, generation, Step::Publish.as_str()],
                            |row| row.get(0),
                        )
                        .map_err(ControllerError::registry)?;
                    if already == 0 {
                        enqueue(
                            &transaction,
                            archive_id,
                            backup_generation,
                            Step::Publish,
                            now_ms,
                        )?;
                    }
                }
                Some(reason) => {
                    // No publication, and no queued work left over for a dispatch after the fence
                    // comes down. An attempt that had already left this host keeps its row and
                    // whatever cleanup names it: only its own answer ends that.
                    cancel_queued_attempts(&transaction, archive_id, backup_generation, now_ms)?;
                    cancel_production(
                        &transaction,
                        archive_id,
                        backup_generation,
                        &reason,
                        now_ms,
                    )?;
                }
            }
            try_finish_generation(&transaction, archive_id, backup_generation)?;
        }
        transaction.commit().map_err(ControllerError::registry)?;
        Ok(complete)
    }

    /// Records that one upload attempt finished and a service took what it carried.
    ///
    /// This is the executor speaking about its own transfer, which is the only thing that can end
    /// one. It names the attempt, and it ends that attempt and the cleanup that names it, in one
    /// transaction. No other attempt is touched.
    ///
    /// A publication is not accepted here. Its acceptance is also the statement that a service
    /// holds the archive, and the two are written down together by [`Self::note_published`]; an
    /// acceptance recorded without that would end the attempt and lose the only evidence that a
    /// copy is somewhere else.
    ///
    /// Repeating it for an attempt already accepted changes nothing and succeeds, because a
    /// transport that delivers the same answer twice has still told this host the truth.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::InvalidArgument`] when that attempt is not an upload attempt
    /// that left this host and is either unanswered or already accepted, and
    /// [`ControllerError::RegistryUnavailable`] when the store refuses the write.
    pub fn note_attempt_accepted(&mut self, attempt: u64, now_ms: TimestampMs) -> Result<()> {
        let sequence = i64::try_from(attempt).unwrap_or(i64::MAX);
        let transaction = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(ControllerError::registry)?;
        let Some(attempt) = claim_attempt(&transaction, sequence)? else {
            return Err(ControllerError::InvalidArgument(
                "that backup dispatch attempt is not one this host holds".to_owned(),
            ));
        };
        if attempt.step != Step::Upload {
            return Err(ControllerError::InvalidArgument(
                "a publication is answered through the call that records what a service holds"
                    .to_owned(),
            ));
        }
        match (attempt.status, attempt.outcome) {
            (AttemptStatus::Dispatched, _) => {}
            // The same answer again. It is already written down, so nothing here changes.
            (AttemptStatus::Terminal, Some(AttemptOutcome::Accepted)) => {
                transaction.commit().map_err(ControllerError::registry)?;
                return Ok(());
            }
            _ => {
                return Err(ControllerError::InvalidArgument(
                    "that backup upload attempt is not one that left this host and is still \
                     unanswered"
                        .to_owned(),
                ));
            }
        }
        answer_attempt(&transaction, &attempt, Answer::Accepted, now_ms)?;
        try_finish_generation(&transaction, attempt.archive_id, attempt.backup_generation)?;
        transaction.commit().map_err(ControllerError::registry)
    }

    /// Claims one queued attempt for dispatch, and records who holds it.
    ///
    /// The claim is the gate. Everything it decides on is read inside this one transaction: the
    /// attempt is still queued, nothing inhibits production, this host has not moved past the
    /// privacy generation the work was admitted under, and that generation may still produce. A
    /// caller cannot supply any of those, so an entry admitted before a fence cannot be let go
    /// after it by a caller working from what it read earlier.
    ///
    /// From here on the outcome is not this host's to decide. The attempt keeps its identity and
    /// its executor, and only evidence about that exact attempt ends it.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::Refused`] when production is inhibited or the attempt belongs to
    /// a privacy generation this host has moved past, [`ControllerError::InvalidArgument`] when it
    /// is not a queued attempt, and [`ControllerError::RegistryUnavailable`] when the store
    /// refuses the write.
    pub fn note_dispatched(
        &mut self,
        sequence: u64,
        executor: &str,
        now_ms: TimestampMs,
    ) -> Result<()> {
        let sequence = i64::try_from(sequence).unwrap_or(i64::MAX);
        let transaction = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(ControllerError::registry)?;
        let attempt: Option<(Vec<u8>, i64, String, i64)> = transaction
            .query_row(
                "SELECT archive_id, backup_generation, status, privacy_generation FROM outbox
                  WHERE sequence = ?1",
                params![sequence],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()
            .map_err(ControllerError::registry)?;
        let Some((archive, generation, status, admitted_under)) = attempt else {
            return Err(ControllerError::InvalidArgument(
                "that backup dispatch attempt is not one this host holds".to_owned(),
            ));
        };
        if AttemptStatus::parse(&status)? != AttemptStatus::Queued {
            return Err(ControllerError::InvalidArgument(format!(
                "that backup dispatch attempt is {status}, and only a queued one is dispatched"
            )));
        }
        let archive_id = ArchiveId::new(uuid(&archive, "an archive identifier")?);
        let backup_generation = BackupGeneration::new(u64::try_from(generation).unwrap_or(0));
        if let Some(reason) = production_refusal(&transaction, archive_id, backup_generation)? {
            return Err(ControllerError::Refused {
                code: kr_protocol::error::ErrorCode::PermissionDenied,
                detail: reason,
            });
        }
        // The attempt's own stamp, checked against the durable generation in the same breath. It
        // agrees with its generation's by construction; checking it here keeps the whole rule in
        // the transaction that lets the work go.
        let current = current_generation(&transaction)?;
        if admitted_under != current {
            return Err(ControllerError::Refused {
                code: kr_protocol::error::ErrorCode::PermissionDenied,
                detail: format!(
                    "that backup work was admitted under privacy generation {admitted_under}, and \
                     this host is at {current}"
                ),
            });
        }
        let claimed = transaction
            .execute(
                "UPDATE outbox SET status = ?2, executor = ?3, dispatched_at_ms = ?4
                  WHERE sequence = ?1 AND status = 'queued'",
                params![
                    sequence,
                    AttemptStatus::Dispatched.as_str(),
                    executor,
                    millis(now_ms)
                ],
            )
            .map_err(ControllerError::registry)?;
        if claimed != 1 {
            return Err(ControllerError::registry(
                "that backup dispatch attempt is not one this host holds queued",
            ));
        }
        transaction.commit().map_err(ControllerError::registry)
    }

    /// Prohibits further production of one generation, and takes back what it never sent.
    ///
    /// An attempt this host still holds queued is this host's to take back. An attempt that had
    /// already left is **not**: it keeps its row and whatever obligation names it, because a
    /// record written here says nothing about what became of it.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store refuses the write.
    pub fn cancel_production(
        &mut self,
        archive_id: ArchiveId,
        backup_generation: BackupGeneration,
        detail: &str,
        now_ms: TimestampMs,
    ) -> Result<()> {
        let transaction = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(ControllerError::registry)?;
        cancel_queued_attempts(&transaction, archive_id, backup_generation, now_ms)?;
        cancel_production(&transaction, archive_id, backup_generation, detail, now_ms)?;
        try_finish_generation(&transaction, archive_id, backup_generation)?;
        transaction.commit().map_err(ControllerError::registry)
    }

    /// Records that something of one generation left this host and was never answered.
    ///
    /// Two facts, written down as two: production of it is over, and a service may hold it. The
    /// attempt that left keeps its row, its identity and whatever cleanup names it, because a
    /// restart is not evidence about what a service did. [`Self::note_attempt_stopped`] is the
    /// call for a caller that has actually established the end of one.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store refuses the write.
    pub fn note_dispatch_unanswered(
        &mut self,
        archive_id: ArchiveId,
        backup_generation: BackupGeneration,
        detail: &str,
        now_ms: TimestampMs,
    ) -> Result<()> {
        let transaction = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(ControllerError::registry)?;
        note_remote(&transaction, archive_id, backup_generation, Remote::Unknown)?;
        cancel_queued_attempts(&transaction, archive_id, backup_generation, now_ms)?;
        cancel_production(&transaction, archive_id, backup_generation, detail, now_ms)?;
        try_finish_generation(&transaction, archive_id, backup_generation)?;
        transaction.commit().map_err(ControllerError::registry)
    }

    /// Records that one exact attempt stopped without an answer.
    ///
    /// The caller is stating two things about **that attempt**, and makes the call only when both
    /// hold: the transfer has ended, and no answer arrived. It ends as stopped and the obligations
    /// that name it end with it, in one transaction. No other attempt is touched, because nothing
    /// here is evidence about any other transfer. What a service may hold is written down and
    /// stays written down.
    ///
    /// A **publication** that ends this way ends production with it. Whether a service holds that
    /// descriptor is not something this host can establish, and section 23 never retries an
    /// unknown outcome: sending a second descriptor would be this host publishing again on the
    /// strength of not knowing. An **upload** is different, because the objects say for themselves
    /// what has arrived, so production continues and the objects still owed are sent again.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::InvalidArgument`] when that attempt is not one that left this
    /// host, and [`ControllerError::RegistryUnavailable`] when the store refuses the write.
    pub fn note_attempt_stopped(&mut self, attempt: u64, now_ms: TimestampMs) -> Result<()> {
        let sequence = i64::try_from(attempt).unwrap_or(i64::MAX);
        let transaction = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(ControllerError::registry)?;
        let claimed = claim_attempt(&transaction, sequence)?
            .filter(|attempt| attempt.status == AttemptStatus::Dispatched);
        let Some(attempt) = claimed else {
            return Err(ControllerError::InvalidArgument(
                "that backup dispatch attempt is not one that left this host and is still \
                 unanswered"
                    .to_owned(),
            ));
        };
        // It left, and nothing here knows what became of it. That is a fact about the generation
        // this attempt carried, and it stays written down.
        note_remote(
            &transaction,
            attempt.archive_id,
            attempt.backup_generation,
            Remote::Unknown,
        )?;
        answer_attempt(&transaction, &attempt, Answer::Stopped, now_ms)?;
        if attempt.step == Step::Publish {
            // Production of it is over. An outcome this host cannot establish is not retried, so
            // nothing of this generation is enqueued again and whatever it still holds queued is
            // taken back.
            cancel_queued_attempts(
                &transaction,
                attempt.archive_id,
                attempt.backup_generation,
                now_ms,
            )?;
            cancel_production(
                &transaction,
                attempt.archive_id,
                attempt.backup_generation,
                "its publication left this host and was never answered, so whether a service holds \
                 it is not something this host can say",
                now_ms,
            )?;
        }
        try_finish_generation(&transaction, attempt.archive_id, attempt.backup_generation)?;
        transaction.commit().map_err(ControllerError::registry)
    }

    /// Records that a service accepted the publication one attempt carried.
    ///
    /// `attempt` is the publication attempt the answer is about, and the archive and generation
    /// come from its row rather than from the caller. An answer is evidence about one transfer, so
    /// it ends that one and no other: a publication this host had written off and replaced cannot
    /// have its replacement ended by an answer that was never about it.
    ///
    /// Every term of the decision except the caller's claim about which privacy generation the
    /// work was produced under is read inside the transaction that records the result. The claim
    /// is checked against the generation this host admitted the work under, so a caller cannot
    /// relabel work privacy mode has drawn a line under by naming a different one.
    ///
    /// An answer that arrives after that line is still an answer, and it is recorded as one: the
    /// artifact is written down, the publication attempt that carried it ends, and the result is
    /// [`Publication::RetainedArtifact`]. No descriptor of this host's becomes current, no local
    /// content comes back, and production stays prohibited. Refusing instead would leave the
    /// attempt owed an answer it had already been given.
    ///
    /// An answer for an attempt this host had already reported stopped is recorded too. What a
    /// service holds is the stronger fact and replaces the uncertainty, and the attempt keeps the
    /// outcome it was given: it ended once, on the evidence there was at the time.
    ///
    /// `withheld` is the caller's own reason for refusing to let production complete, which the
    /// store has no row for: a process that was told to stop and could not is in exactly that
    /// position. It can only withhold. Nothing a caller passes can make a publication current that
    /// this store's own rules would not.
    ///
    /// The upload attempts of that generation are **not** ended here. An accepted descriptor says
    /// a service holds the archive; it says nothing about whether some executor is still pushing
    /// bytes for a second attempt at the same upload.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::InvalidArgument`] when the attempt is not a publication attempt
    /// that left this host, [`ControllerError::Refused`] when the result claims a privacy
    /// generation other than the one this host admitted the work under, and
    /// [`ControllerError::RegistryUnavailable`] when the store refuses the write.
    pub fn note_published(
        &mut self,
        attempt: u64,
        produced_under: u64,
        withheld: Option<&str>,
        now_ms: TimestampMs,
    ) -> Result<Publication> {
        let sequence = i64::try_from(attempt).unwrap_or(i64::MAX);
        let transaction = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(ControllerError::registry)?;
        let Some(attempt) = claim_attempt(&transaction, sequence)? else {
            return Err(ControllerError::InvalidArgument(
                "that backup dispatch attempt is not one this host holds".to_owned(),
            ));
        };
        if attempt.step != Step::Publish {
            return Err(ControllerError::InvalidArgument(
                "that backup dispatch attempt carries a generation's objects and not its \
                 descriptor"
                    .to_owned(),
            ));
        }
        // Nothing of a queued or cancelled attempt ever went anywhere, so no service can be
        // answering for it. Recording one would be this host writing down a transfer that never
        // happened.
        if matches!(
            (attempt.status, attempt.outcome),
            (AttemptStatus::Queued, _) | (AttemptStatus::Terminal, Some(AttemptOutcome::Cancelled))
        ) {
            return Err(ControllerError::InvalidArgument(
                "that backup publication attempt never left this host".to_owned(),
            ));
        }
        let archive_id = attempt.archive_id;
        let backup_generation = attempt.backup_generation;
        let archive = archive_id.get().as_bytes().to_vec();
        let generation = i64::try_from(backup_generation.get()).unwrap_or(i64::MAX);
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
        // The service holds the descriptor. That is true whatever privacy mode has since done, so
        // it is written down first and stays written down. It is also what the database requires
        // before any publication attempt may end as accepted.
        note_remote(
            &transaction,
            archive_id,
            backup_generation,
            Remote::Published,
        )?;
        // The attempt the answer is about, and only that one. An attempt already terminal keeps
        // the outcome it was given: this statement leaves it alone rather than ending a transfer
        // twice or ending some other attempt in its place.
        answer_attempt(&transaction, &attempt, Answer::Accepted, now_ms)?;
        let refusal = production_refusal(&transaction, archive_id, backup_generation)?
            .or_else(|| withheld.map(ToOwned::to_owned));
        let outcome = match refusal {
            None => {
                transaction
                    .execute(
                        "UPDATE generations SET production = ?3, settled_at_ms = ?4, detail = NULL
                          WHERE archive_id = ?1 AND backup_generation = ?2
                            AND production = ?5",
                        params![
                            archive,
                            generation,
                            Production::Complete.as_str(),
                            millis(now_ms),
                            Production::Producing.as_str(),
                        ],
                    )
                    .map_err(ControllerError::registry)?;
                // The archive is at a service, so anything of this generation this host still
                // holds queued is work it will never do. Taking back its own undispatched entries
                // is not an answer about them; it is what stops a replacement enqueued while the
                // outcome was unknown sitting queued for ever behind a gate that now refuses it.
                cancel_queued_attempts(&transaction, archive_id, backup_generation, now_ms)?;
                Publication::Recorded
            }
            Some(_) => Publication::RetainedArtifact {
                privacy_generation: admitted_under,
            },
        };
        try_finish_generation(&transaction, archive_id, backup_generation)?;
        transaction.commit().map_err(ControllerError::registry)?;
        Ok(outcome)
    }

    /// Completes the production of a generation whose descriptor a service has accepted.
    ///
    /// An accepted descriptor is the end of production, and the transaction that recorded it is
    /// not always able to say so: a host that was told to stop and could not withholds completion,
    /// and the answer is not delivered again. Reconciliation closes that here, rather than leaving
    /// a generation producing with nothing left to carry it.
    ///
    /// It is the store's own state that decides, inside the transaction: a service holds the
    /// descriptor, the generation is still producing, and nothing inhibits it. Work this host
    /// still holds queued for a generation that is finished is taken back with it.
    ///
    /// Returns true when this is what finished it.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store refuses the write.
    pub fn finish_accepted_production(
        &mut self,
        archive_id: ArchiveId,
        backup_generation: BackupGeneration,
        now_ms: TimestampMs,
    ) -> Result<bool> {
        let archive = archive_id.get().as_bytes().to_vec();
        let generation = i64::try_from(backup_generation.get()).unwrap_or(i64::MAX);
        let transaction = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(ControllerError::registry)?;
        if production_refusal(&transaction, archive_id, backup_generation)?.is_some() {
            return Ok(false);
        }
        let finished = transaction
            .execute(
                "UPDATE generations SET production = ?3, settled_at_ms = ?4, detail = NULL
                  WHERE archive_id = ?1 AND backup_generation = ?2
                    AND production = ?5 AND remote = ?6",
                params![
                    archive,
                    generation,
                    Production::Complete.as_str(),
                    millis(now_ms),
                    Production::Producing.as_str(),
                    Remote::Published.as_str(),
                ],
            )
            .map_err(ControllerError::registry)?;
        if finished == 0 {
            return Ok(false);
        }
        cancel_queued_attempts(&transaction, archive_id, backup_generation, now_ms)?;
        try_finish_generation(&transaction, archive_id, backup_generation)?;
        transaction.commit().map_err(ControllerError::registry)?;
        Ok(true)
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
                "SELECT archive_id, backup_generation, production, remote, writer_key_id,
                        privacy_generation, descriptor, created_at_ms, settled_at_ms, detail
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
                "SELECT archive_id, backup_generation, production, remote, writer_key_id,
                        privacy_generation, descriptor, created_at_ms, settled_at_ms, detail
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
                        staged_path, local_state, acknowledged_bytes
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

    /// Returns every attempt this host is still owed an answer about, oldest first.
    ///
    /// Queued and dispatched, which together are the work that has not ended. An attempt that has
    /// ended keeps its row with the outcome that ended it; [`Self::attempts`] returns those too.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store cannot be read.
    pub fn outbox(&self) -> Result<Vec<Attempt>> {
        self.read_attempts(
            "SELECT sequence, archive_id, backup_generation, step, privacy_generation,
                    status, outcome, executor
               FROM outbox WHERE status <> 'terminal' ORDER BY sequence",
        )
    }

    /// Returns every attempt this host has made or is making, oldest first.
    ///
    /// An attempt that ended is still here, with its outcome and its executor. That is what lets
    /// this host recognise an answer it has already had, and say what a service may be holding
    /// even when the production it belonged to was cancelled.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store cannot be read.
    pub fn attempts(&self) -> Result<Vec<Attempt>> {
        self.read_attempts(
            "SELECT sequence, archive_id, backup_generation, step, privacy_generation,
                    status, outcome, executor
               FROM outbox ORDER BY sequence",
        )
    }

    /// Reads attempts with one of the two statements above, each written out in full.
    ///
    /// Neither is assembled from pieces. A statement this store executes is a statement somebody
    /// can read in this file, which is what lets the rule that none of them replaces a row it
    /// collided with be checked against the source rather than against a habit.
    fn read_attempts(&self, statement: &'static str) -> Result<Vec<Attempt>> {
        let mut statement = self
            .connection
            .prepare(statement)
            .map_err(ControllerError::registry)?;
        let rows = statement
            .query_map([], read_attempt)
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

    /// Gives one generation that may still produce an attempt at whatever it needs next.
    ///
    /// The step is the store's to decide, from the object rows: an object a service has not
    /// acknowledged means another upload, and a complete set means the descriptor. A resumed step
    /// is a *new* attempt, never an old row put back in hand. The attempt that left this host
    /// keeps its identity and its unanswered status until something establishes how it ended, so a
    /// fence that arrives later writes down what it really is: an attempt to follow, not a queued
    /// entry to cancel. Cancelling it would end the only record that anything of this generation
    /// had gone anywhere.
    ///
    /// Returns the new attempt's identity, or nothing when this host already holds one it has not
    /// handed over. It is the answer to a generation whose last attempt stopped without one: work
    /// nothing is carrying gets something to carry it, rather than waiting for a fence to clean it
    /// up.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::Refused`] when production of that generation is inhibited or
    /// belongs to a privacy generation this host has moved past, and
    /// [`ControllerError::RegistryUnavailable`] when the store refuses the write.
    pub fn ensure_open_attempt(
        &mut self,
        archive_id: ArchiveId,
        backup_generation: BackupGeneration,
        now_ms: TimestampMs,
    ) -> Result<Option<u64>> {
        let archive = archive_id.get().as_bytes().to_vec();
        let generation = i64::try_from(backup_generation.get()).unwrap_or(i64::MAX);
        let transaction = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(ControllerError::registry)?;
        let outstanding: i64 = transaction
            .query_row(
                "SELECT COUNT(*) FROM objects
                  WHERE archive_id = ?1 AND backup_generation = ?2
                    AND acknowledged_bytes < encrypted_len",
                params![archive, generation],
                |row| row.get(0),
            )
            .map_err(ControllerError::registry)?;
        let step = if outstanding > 0 {
            Step::Upload
        } else {
            Step::Publish
        };
        // Already in hand, or already answered. A publication a service accepted is not enqueued
        // again whatever else happens; an upload this host still holds is the attempt it would
        // otherwise make.
        let held: i64 = transaction
            .query_row(
                "SELECT COUNT(*) FROM outbox
                  WHERE archive_id = ?1 AND backup_generation = ?2 AND step = ?3
                    AND (status = 'queued' OR outcome = 'accepted')",
                params![archive, generation, step.as_str()],
                |row| row.get(0),
            )
            .map_err(ControllerError::registry)?;
        if held > 0 {
            transaction.commit().map_err(ControllerError::registry)?;
            return Ok(None);
        }
        let sequence = enqueue(&transaction, archive_id, backup_generation, step, now_ms)?;
        transaction.commit().map_err(ControllerError::registry)?;
        Ok(Some(sequence))
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
                    "UPDATE objects SET local_state = ?4
                      WHERE archive_id = ?1 AND backup_generation = ?2 AND object_id = ?3",
                    params![
                        archive_id.get().as_bytes().as_slice(),
                        i64::try_from(backup_generation.get()).unwrap_or(i64::MAX),
                        object_id.get().as_bytes().as_slice(),
                        LocalState::Absent.as_str(),
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
    pub fn cancel_undispatched(&mut self, now_ms: TimestampMs) -> Result<(u64, u64)> {
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
            // The exact attempt, and only while it is still this host's to take back. One that had
            // been dispatched in between is not a cancellation any more, so its obligation stays
            // and the attempt is followed instead.
            //
            // The cancellation goes through the one settlement path, which ends the attempt and
            // every obligation naming it together. Two fences over the same queued attempt each
            // write a cancellation for it; one cancellation answers both, and a handler that
            // discharged only the row it was looking at would leave the other owed for ever and
            // block both generations' bookkeeping.
            let cancelled = cancel_attempt(&transaction, sequence, now_ms)?;
            if cancelled == 0 {
                continue;
            }
            taken_back = taken_back.saturating_add(cancelled);
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
               FROM objects
              WHERE local_state <> ?3
                AND NOT EXISTS (SELECT 1 FROM privacy_obligations
                                 WHERE privacy_generation = ?1
                                   AND kind = 'unlink_object'
                                   AND target_key = 'object:' || hex(objects.archive_id) || ':'
                                                 || objects.backup_generation || ':'
                                                 || hex(objects.object_id))",
            params![privacy_generation, now, LocalState::Absent.as_str()],
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
               FROM outbox
              WHERE status = 'queued'
                AND NOT EXISTS (SELECT 1 FROM privacy_obligations
                                 WHERE privacy_generation = ?1
                                   AND kind = 'cancel_entry'
                                   AND target_key = 'entry:' || outbox.sequence)",
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
               FROM outbox
              WHERE status = 'dispatched'
                AND NOT EXISTS (SELECT 1 FROM privacy_obligations
                                 WHERE privacy_generation = ?1
                                   AND kind = CASE outbox.step WHEN 'upload' THEN 'resolve_upload'
                                                               ELSE 'resolve_publication' END
                                   AND target_key = CASE outbox.step WHEN 'upload' THEN 'upload:'
                                                                     ELSE 'publication:' END
                                                 || outbox.sequence)",
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
               FROM generations
              WHERE NOT EXISTS (SELECT 1 FROM privacy_obligations
                                 WHERE privacy_generation = ?1
                                   AND kind = 'finish_generation'
                                   AND target_key = 'generation:'
                                                 || hex(generations.archive_id) || ':'
                                                 || generations.backup_generation)",
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
            "UPDATE generations SET production = ?1, settled_at_ms = ?2, detail = ?3
              WHERE production = ?4",
            params![
                Production::Cancelled.as_str(),
                now,
                format!(
                    "privacy mode fenced backup production at privacy generation \
                     {privacy_generation}"
                ),
                Production::Producing.as_str(),
            ],
        )
        .map_err(ControllerError::registry)?;
    Ok(())
}

/// One dispatch attempt, read by the sequence a caller named.
///
/// This value is how an attempt's identity reaches the settlement path, and [`claim_attempt`] is
/// the only thing that makes one. Its sole identity argument is the sequence, so a caller has to
/// have named the attempt for one to exist at all: no count of objects, no state of a generation
/// and no answer about a different transfer can produce one.
#[derive(Clone, Copy)]
struct NamedAttempt {
    sequence: i64,
    archive_id: ArchiveId,
    backup_generation: BackupGeneration,
    step: Step,
    status: AttemptStatus,
    outcome: Option<AttemptOutcome>,
}

/// How an attempt that left this host ended.
///
/// Cancellation is not one of these. It is what this host does to work it never handed over, and
/// it is not an answer about a transfer.
#[derive(Clone, Copy)]
enum Answer {
    /// The service took what the attempt carried.
    Accepted,
    /// The transfer ended and no answer arrived.
    Stopped,
}

impl Answer {
    const fn outcome(self) -> AttemptOutcome {
        match self {
            Self::Accepted => AttemptOutcome::Accepted,
            Self::Stopped => AttemptOutcome::Stopped,
        }
    }
}

/// Reads the attempt a caller named, inside the transaction that would act on it.
///
/// What the attempt is for is read from its own row rather than taken from the caller, so an
/// answer cannot be applied to the work the caller believed it was about while the row says
/// otherwise.
fn claim_attempt(
    transaction: &rusqlite::Transaction<'_>,
    sequence: i64,
) -> Result<Option<NamedAttempt>> {
    /// One attempt's stored columns, as they come back: archive, generation, step, status and
    /// outcome.
    type Row = (Vec<u8>, i64, String, String, Option<String>);
    let row: Option<Row> = transaction
        .query_row(
            "SELECT archive_id, backup_generation, step, status, outcome FROM outbox
              WHERE sequence = ?1",
            params![sequence],
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
        .map_err(ControllerError::registry)?;
    let Some((archive, generation, step, status, outcome)) = row else {
        return Ok(None);
    };
    Ok(Some(NamedAttempt {
        sequence,
        archive_id: ArchiveId::new(uuid(&archive, "an archive identifier")?),
        backup_generation: BackupGeneration::new(u64::try_from(generation).unwrap_or(0)),
        step: Step::parse(&step)?,
        status: AttemptStatus::parse(&status)?,
        outcome: outcome.as_deref().map(AttemptOutcome::parse).transpose()?,
    }))
}

/// Ends the attempt a caller named, on evidence about that attempt.
///
/// Only an attempt that left this host is answered, and only the one whose identity the caller
/// supplied. Nothing else in this file ends a dispatched attempt, so evidence one transfer
/// delivered cannot end another: the [`NamedAttempt`] this takes has no other source.
fn answer_attempt(
    transaction: &rusqlite::Transaction<'_>,
    attempt: &NamedAttempt,
    answer: Answer,
    now_ms: TimestampMs,
) -> Result<u64> {
    end_attempt(
        transaction,
        attempt.sequence,
        AttemptStatus::Dispatched,
        answer.outcome(),
        now_ms,
    )
}

/// Takes back one attempt this host still holds and has never handed over.
///
/// Nothing of it went anywhere, so this needs no evidence about a transfer: it is this host
/// withdrawing its own work.
fn cancel_attempt(
    transaction: &rusqlite::Transaction<'_>,
    sequence: i64,
    now_ms: TimestampMs,
) -> Result<u64> {
    end_attempt(
        transaction,
        sequence,
        AttemptStatus::Queued,
        AttemptOutcome::Cancelled,
        now_ms,
    )
}

/// Ends one attempt: its outcome and every obligation that named it, together.
///
/// The two are one fact. An attempt marked over while its obligation stayed would be cleanup
/// nothing could ever discharge; an obligation cleared while the attempt stayed open would be work
/// reported finished with the attempt still owed an answer.
///
/// The statement is guarded on the state the outcome implies, so an attempt in any other state
/// changes nothing rather than recording a transfer that never happened.
///
/// The row itself remains, with how it ended and who held it. That is what lets this host know an
/// answer it has already had, and keeps a record that something of a cancelled generation went to
/// a service.
fn end_attempt(
    transaction: &rusqlite::Transaction<'_>,
    sequence: i64,
    from: AttemptStatus,
    outcome: AttemptOutcome,
    now_ms: TimestampMs,
) -> Result<u64> {
    let ended = transaction
        .execute(
            "UPDATE outbox SET status = ?2, outcome = ?3, settled_at_ms = ?4
              WHERE sequence = ?1 AND status = ?5",
            params![
                sequence,
                AttemptStatus::Terminal.as_str(),
                outcome.as_str(),
                millis(now_ms),
                from.as_str(),
            ],
        )
        .map_err(ControllerError::registry)?;
    if ended == 0 {
        return Ok(0);
    }
    transaction
        .execute(
            "DELETE FROM privacy_obligations WHERE entry_sequence = ?1",
            params![sequence],
        )
        .map_err(ControllerError::registry)?;
    Ok(u64::try_from(ended).unwrap_or(0))
}

/// Takes back every attempt of one generation this host still holds and has never handed over.
///
/// A dispatched attempt is never one of them, and this names a generation rather than an attempt
/// for exactly that reason: what it ends is work that never left, which no service can be
/// answering for.
fn cancel_queued_attempts(
    transaction: &rusqlite::Transaction<'_>,
    archive_id: ArchiveId,
    backup_generation: BackupGeneration,
    now_ms: TimestampMs,
) -> Result<u64> {
    let queued = open_attempts(
        transaction,
        archive_id,
        backup_generation,
        None,
        Some(AttemptStatus::Queued),
    )?;
    let mut ended = 0u64;
    for sequence in queued {
        ended = ended.saturating_add(cancel_attempt(transaction, sequence, now_ms)?);
    }
    Ok(ended)
}

/// Returns the open attempts of one generation, narrowed by step and status where asked.
fn open_attempts(
    transaction: &rusqlite::Transaction<'_>,
    archive_id: ArchiveId,
    backup_generation: BackupGeneration,
    step: Option<Step>,
    status: Option<AttemptStatus>,
) -> Result<Vec<i64>> {
    let mut statement = transaction
        .prepare(
            "SELECT sequence FROM outbox
              WHERE archive_id = ?1 AND backup_generation = ?2
                AND status <> 'terminal'
                AND (?3 IS NULL OR step = ?3)
                AND (?4 IS NULL OR status = ?4)
              ORDER BY sequence",
        )
        .map_err(ControllerError::registry)?;
    let rows = statement
        .query_map(
            params![
                archive_id.get().as_bytes().as_slice(),
                i64::try_from(backup_generation.get()).unwrap_or(i64::MAX),
                step.map(Step::as_str),
                status.map(AttemptStatus::as_str),
            ],
            |row| row.get(0),
        )
        .map_err(ControllerError::registry)?;
    let mut collected = Vec::new();
    for row in rows {
        collected.push(row.map_err(ControllerError::registry)?);
    }
    Ok(collected)
}

/// Prohibits further production of one generation, inside a transaction the caller owns.
///
/// Only a generation that is still producing takes the reason. One already cancelled keeps the
/// reason it was cancelled for, and one that completed stays complete: production ends once.
fn cancel_production(
    transaction: &rusqlite::Transaction<'_>,
    archive_id: ArchiveId,
    backup_generation: BackupGeneration,
    detail: &str,
    now_ms: TimestampMs,
) -> Result<()> {
    transaction
        .execute(
            "UPDATE generations SET production = ?3, settled_at_ms = ?4, detail = ?5
              WHERE archive_id = ?1 AND backup_generation = ?2 AND production = ?6",
            params![
                archive_id.get().as_bytes().as_slice(),
                i64::try_from(backup_generation.get()).unwrap_or(i64::MAX),
                Production::Cancelled.as_str(),
                millis(now_ms),
                detail,
                Production::Producing.as_str(),
            ],
        )
        .map_err(ControllerError::registry)?;
    Ok(())
}

/// Writes down what a service holds of one generation, inside a transaction the caller owns.
///
/// It only ever moves away from [`Remote::Nothing`], and an accepted descriptor is the last word.
/// Evidence that ciphertext reached a service is not withdrawn by anything that happens here
/// afterwards, which is what keeps a cancelled generation's artifacts visible.
fn note_remote(
    transaction: &rusqlite::Transaction<'_>,
    archive_id: ArchiveId,
    backup_generation: BackupGeneration,
    remote: Remote,
) -> Result<()> {
    transaction
        .execute(
            "UPDATE generations SET remote = ?3
              WHERE archive_id = ?1 AND backup_generation = ?2
                AND remote <> ?3 AND remote <> ?4",
            params![
                archive_id.get().as_bytes().as_slice(),
                i64::try_from(backup_generation.get()).unwrap_or(i64::MAX),
                remote.as_str(),
                Remote::Published.as_str(),
            ],
        )
        .map_err(ControllerError::registry)?;
    Ok(())
}

/// Returns why this host may not enqueue or dispatch more work for one generation, if it may not.
///
/// One rule, read from this store's own durable state, and the only one: nothing inhibits
/// production, this host has not moved past the privacy generation the work was admitted under,
/// and that generation may still produce. Admission, publication enqueue and the dispatch claim
/// each ask it inside the transaction that would change state, so none of them can act on a
/// generation somebody read earlier.
fn production_refusal(
    transaction: &rusqlite::Transaction<'_>,
    archive_id: ArchiveId,
    backup_generation: BackupGeneration,
) -> Result<Option<String>> {
    if let Some(inhibited_at) = inhibited_at(transaction)? {
        return Ok(Some(format!(
            "backup production is fenced at privacy generation {inhibited_at}"
        )));
    }
    let row: Option<(String, i64)> = transaction
        .query_row(
            "SELECT production, privacy_generation FROM generations
              WHERE archive_id = ?1 AND backup_generation = ?2",
            params![
                archive_id.get().as_bytes().as_slice(),
                i64::try_from(backup_generation.get()).unwrap_or(i64::MAX),
            ],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(ControllerError::registry)?;
    let Some((production, admitted_under)) = row else {
        return Ok(Some(
            "that backup generation is not one this host admitted".to_owned(),
        ));
    };
    if Production::parse(&production)? != Production::Producing {
        return Ok(Some(format!(
            "that backup generation's production is {production}"
        )));
    }
    let current = current_generation(transaction)?;
    if admitted_under != current {
        return Ok(Some(format!(
            "that backup work was admitted under privacy generation {admitted_under}, and this \
             host is at {current}"
        )));
    }
    Ok(None)
}

/// Returns the privacy generation in force, read inside a transaction.
fn current_generation(connection: &Connection) -> Result<i64> {
    connection
        .query_row(
            "SELECT current_generation FROM privacy_state WHERE id = 0",
            [],
            |row| row.get(0),
        )
        .map_err(ControllerError::registry)
}

/// Finishes one generation's bookkeeping, if everything that obligation waits on is done.
///
/// Called from inside whichever transaction makes the last condition true, so completion is a fact
/// the store derives rather than a step somebody has to remember to take. Until then the
/// `finish_generation` row is simply there, and cleanup is not complete.
///
/// What it removes is production bookkeeping, and only that. A generation a service may hold
/// something of keeps its record, its object rows and its attempts, because those are the evidence
/// that ciphertext of it is somewhere else. Production being cancelled is not a reason to forget
/// that: privacy mode shows such a generation as a retained artifact, and a host that had deleted
/// the acknowledgements would show nothing at all.
///
/// Returns how many rows this actually deleted, which is nought whenever the conditions do not
/// hold yet and nought for a generation whose record is kept.
fn try_finish_generation(
    transaction: &rusqlite::Transaction<'_>,
    archive_id: ArchiveId,
    backup_generation: BackupGeneration,
) -> Result<u64> {
    let archive = archive_id.get().as_bytes().to_vec();
    let generation = i64::try_from(backup_generation.get()).unwrap_or(i64::MAX);
    let owed: i64 = transaction
        .query_row(
            "SELECT COUNT(*) FROM privacy_obligations
              WHERE kind = 'finish_generation' AND archive_id = ?1 AND backup_generation = ?2",
            params![archive, generation],
            |row| row.get(0),
        )
        .map_err(ControllerError::registry)?;
    if owed == 0 {
        return Ok(0);
    }
    // Anything any fence still owes about this generation, and any staging walk that has not
    // happened: a walk could still find ciphertext of it, so the bookkeeping waits for that too.
    // Another fence's `finish_generation` row for the same target is not a blocker; it is
    // discharged by the same evidence, below.
    let blocking: i64 = transaction
        .query_row(
            "SELECT COUNT(*) FROM privacy_obligations
              WHERE kind <> 'finish_generation'
                AND (kind = 'scan_staging'
                     OR (archive_id = ?1 AND backup_generation = ?2))",
            params![archive, generation],
            |row| row.get(0),
        )
        .map_err(ControllerError::registry)?;
    if blocking > 0 {
        return Ok(0);
    }
    // And every staged copy of it is really gone from this host.
    let present: i64 = transaction
        .query_row(
            "SELECT COUNT(*) FROM objects
              WHERE archive_id = ?1 AND backup_generation = ?2 AND local_state <> ?3",
            params![archive, generation, LocalState::Absent.as_str()],
            |row| row.get(0),
        )
        .map_err(ControllerError::registry)?;
    if present > 0 {
        return Ok(0);
    }
    let remote: Option<String> = transaction
        .query_row(
            "SELECT remote FROM generations WHERE archive_id = ?1 AND backup_generation = ?2",
            params![archive, generation],
            |row| row.get(0),
        )
        .optional()
        .map_err(ControllerError::registry)?;
    // A generation a service may hold something of is shown rather than pretended away. That is
    // true of a published archive, of one whose outcome this host cannot establish, and equally of
    // one whose production privacy mode cancelled after its ciphertext had already been
    // acknowledged.
    let keep = match remote.as_deref() {
        Some(text) => Remote::parse(text)?.is_artifact(),
        None => false,
    };
    let mut finished = 0u64;
    if !keep {
        let counted: i64 = transaction
            .query_row(
                "SELECT (SELECT COUNT(*) FROM objects
                          WHERE archive_id = ?1 AND backup_generation = ?2)
                      + (SELECT COUNT(*) FROM outbox
                          WHERE archive_id = ?1 AND backup_generation = ?2)",
                params![archive, generation],
                |row| row.get(0),
            )
            .map_err(ControllerError::registry)?;
        for statement in [
            "DELETE FROM outbox WHERE archive_id = ?1 AND backup_generation = ?2",
            "DELETE FROM objects WHERE archive_id = ?1 AND backup_generation = ?2",
        ] {
            transaction
                .execute(statement, params![archive, generation])
                .map_err(ControllerError::registry)?;
        }
        let generations = transaction
            .execute(
                "DELETE FROM generations WHERE archive_id = ?1 AND backup_generation = ?2",
                params![archive, generation],
            )
            .map_err(ControllerError::registry)?;
        finished = finished.saturating_add(u64::try_from(counted).unwrap_or(0));
        finished = finished.saturating_add(u64::try_from(generations).unwrap_or(0));
    }
    transaction
        .execute(
            "DELETE FROM privacy_obligations
              WHERE kind = 'finish_generation' AND archive_id = ?1 AND backup_generation = ?2",
            params![archive, generation],
        )
        .map_err(ControllerError::registry)?;
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
/// The insert asks whether that `(privacy_generation, kind, target_key)` is already owed and writes
/// nothing when it is, so writing the same obligation twice writes it once: a second fence
/// activation over a target the first already recorded adds nothing. It asks rather than leaving it
/// to conflict resolution because the row that is already there is never touched: the database
/// refuses an insert carrying an obligation's identity or its target outright, and an upsert would
/// be refused with it.
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
             SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 0
              WHERE NOT EXISTS (SELECT 1 FROM privacy_obligations
                                 WHERE privacy_generation = ?1 AND kind = ?2
                                   AND target_key = ?3)",
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

/// Enqueues one attempt, and refuses one the production rule does not permit.
///
/// Every insert into the outbox comes through here, so there is one place that decides whether
/// work may be enqueued at all, and it decides inside the caller's transaction. The privacy
/// generation stamped on the attempt is this store's own, never a caller's.
fn enqueue(
    transaction: &rusqlite::Transaction<'_>,
    archive_id: ArchiveId,
    backup_generation: BackupGeneration,
    step: Step,
    now_ms: TimestampMs,
) -> Result<u64> {
    if let Some(reason) = production_refusal(transaction, archive_id, backup_generation)? {
        return Err(ControllerError::Refused {
            code: kr_protocol::error::ErrorCode::PermissionDenied,
            detail: reason,
        });
    }
    transaction
        .execute(
            "INSERT INTO outbox
                 (archive_id, backup_generation, step, privacy_generation, status, outcome,
                  executor, enqueued_at_ms)
             SELECT ?1, ?2, ?3, current_generation, ?4, NULL, NULL, ?5
               FROM privacy_state WHERE id = 0",
            params![
                archive_id.get().as_bytes().as_slice(),
                i64::try_from(backup_generation.get()).unwrap_or(i64::MAX),
                step.as_str(),
                AttemptStatus::Queued.as_str(),
                millis(now_ms),
            ],
        )
        .map_err(ControllerError::registry)?;
    Ok(u64::try_from(transaction.last_insert_rowid()).unwrap_or(0))
}

fn read_generation(row: &rusqlite::Row<'_>) -> rusqlite::Result<Result<GenerationRecord>> {
    let archive: Vec<u8> = row.get(0)?;
    let generation: i64 = row.get(1)?;
    let production: String = row.get(2)?;
    let remote: String = row.get(3)?;
    let writer: Vec<u8> = row.get(4)?;
    let privacy: i64 = row.get(5)?;
    let descriptor: Option<Vec<u8>> = row.get(6)?;
    let created: i64 = row.get(7)?;
    let settled: Option<i64> = row.get(8)?;
    let detail: Option<String> = row.get(9)?;
    Ok((|| {
        Ok(GenerationRecord {
            archive_id: ArchiveId::new(uuid(&archive, "an archive identifier")?),
            backup_generation: BackupGeneration::new(u64::try_from(generation).unwrap_or(0)),
            production: Production::parse(&production)?,
            remote: Remote::parse(&remote)?,
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
    let local_state: String = row.get(6)?;
    let acknowledged: i64 = row.get(7)?;
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
            local_state: LocalState::parse(&local_state)?,
            acknowledged_bytes: u64::try_from(acknowledged).unwrap_or(0),
        })
    })())
}

fn read_attempt(row: &rusqlite::Row<'_>) -> rusqlite::Result<Result<Attempt>> {
    let sequence: i64 = row.get(0)?;
    let archive: Vec<u8> = row.get(1)?;
    let generation: i64 = row.get(2)?;
    let step: String = row.get(3)?;
    let privacy: i64 = row.get(4)?;
    let status: String = row.get(5)?;
    let outcome: Option<String> = row.get(6)?;
    let executor: Option<String> = row.get(7)?;
    Ok((|| {
        Ok(Attempt {
            sequence: u64::try_from(sequence).unwrap_or(0),
            archive_id: ArchiveId::new(uuid(&archive, "an archive identifier")?),
            backup_generation: BackupGeneration::new(u64::try_from(generation).unwrap_or(0)),
            step: Step::parse(&step)?,
            privacy_generation: u64::try_from(privacy).unwrap_or(0),
            status: AttemptStatus::parse(&status)?,
            outcome: outcome.as_deref().map(AttemptOutcome::parse).transpose()?,
            executor,
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

#[cfg(test)]
mod tests {
    use super::BackupStore;

    /// SQLite runs the delete rules for a delete that conflict resolution causes only when
    /// recursive triggers are on. Nothing here resolves a conflict that way, and this is what makes
    /// that a rule of the database rather than a habit of the code that writes it.
    #[test]
    fn a_store_holds_a_delete_a_conflict_causes_to_the_rules_that_guard_a_delete() {
        let root = tempfile::tempdir().expect("a disposable directory on the internal disk");
        let store = BackupStore::in_memory(&root.path().join("backup")).expect("a backup store");
        let recursive: i64 = store
            .connection
            .query_row("PRAGMA recursive_triggers", [], |row| row.get(0))
            .expect("a read of the setting");
        assert_eq!(recursive, 1, "recursive triggers are on for this store");
    }
}
