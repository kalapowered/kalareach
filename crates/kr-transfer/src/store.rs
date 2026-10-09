//! `transfers.sqlite`: the transfer journal.
//!
//! Write-ahead logging with full synchronisation, forward-only migrations, and every state change
//! committed together with the outbox row that announces it. The order the rows are written in is
//! what makes an interrupted transfer resumable:
//!
//! * An **upload** row exists before a single byte is accepted, with its declared size already
//!   charged against the environment's budget.
//! * A **chunk** row is written *after* its bytes are on disk and flushed. A row with no bytes
//!   behind it would let a later verification trust a hole; bytes with no row are simply sent
//!   again, which costs a chunk and nothing else.
//! * Publication is two commits with a recoverable state between them. The row moves to
//!   `publishing` naming both the incomplete and the published name, then the file is renamed, then
//!   the row moves to `published`. A daemon that dies in the middle finds the `publishing` row and
//!   resolves it from whichever name exists, so there is never a published handle without a file or
//!   a verified file nothing can reach.
//! * A **snapshot** row records the source's identity, size and modification time as they were
//!   when the copy was taken, so a source that changed underneath it fails explicitly instead of
//!   mixing two versions.
//! * An **action** row retains the result of a completed mutation, keyed by actor and action
//!   identifier, so a lost reply is answered rather than performed twice.

use kr_protocol::ids::TransferId;
use kr_protocol::ids::{
    ActorId, ApplicationInstanceId, DeviceId, DraftId, DraftRevision, EnvironmentId, GrantId,
    SessionId,
};
use kr_protocol::scalars::{Digest256, TimestampMs, U64, Uuid};
use kr_protocol::transfer::{
    ChunkDescriptor, DownloadImmutability, DraftState, InsertionMethod, InsertionState, UploadState,
};
use rusqlite::{Connection, OptionalExtension as _, Transaction, params};

use crate::authority::ObjectIdentity;
use crate::error::{Result, TransferError};
use crate::filesystem::{FilesystemId, RecordedIdentity, Settled};

/// The schema version this build reads, and the one a journal holds nothing of the sessions of
/// earlier builds at ([`Noting`]). A journal at it has the table of ended sessions and the columns
/// that say which offer a binding was claimed for.
pub const SCHEMA_VERSION: i64 = 5;

/// The version before the columns that record who claimed a binding: a journal at it has the table
/// of ended sessions and holds no claim. The step to [`SCHEMA_VERSION`] adds the columns and moves
/// the version; a build that cannot read a claim then refuses the journal.
///
/// Remove this, with the step from it, once no supported upgrade can start from a journal at this
/// version.
const UNCLAIMED_VERSION: i64 = 4;

/// The version of a journal that holds nothing of the sessions of earlier builds and may have no
/// table of ended sessions: one that the build before that table made or settled. A journal that
/// this build added the table to while it was at [`UNSETTLED_VERSION`], and that a build before that
/// table then settled, has the table. The step to [`SCHEMA_VERSION`] adds the table where it is
/// missing and moves the version in one transaction.
///
/// Remove this, with the step from it, once no supported upgrade can start from a journal at this
/// version.
const SETTLED_VERSION: i64 = 3;

/// The version a journal that an earlier build wrote is at until the sessions of earlier builds in
/// it are settled ([`Store::settle_unseen_prompt_sessions`]), which moves it to [`SCHEMA_VERSION`].
///
/// A journal can stay at this version for as long as a session of an earlier build runs, so a later
/// schema step has to read it, or refuse it by name, and not carry it past settling. The step to
/// [`SCHEMA_VERSION`] reads it: it adds its table and leaves the version, so settling still moves
/// the journal. Remove this, with the noting, once no supported upgrade can start from a journal at
/// this version, and have the build that removes it refuse such a journal.
const UNSETTLED_VERSION: i64 = 2;

/// Where a journal stands with the sessions of earlier builds, whose agents may have been sent a
/// prompt that names a draft without this host being told.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Noting {
    /// Nothing is noted and nothing is owed: the journal was made by this build or a later one, or
    /// its noted sessions were settled.
    Done,
    /// An earlier build wrote the journal and its sessions have not been noted.
    Owed,
    /// The sessions are noted and held until none of them can run a worker.
    Held,
}

/// The configurable resource limits of one environment.
///
/// Section 14 calls these configurable resource limits rather than subscription restrictions. A
/// self-hosted owner changes them; nothing in the protocol depends on the defaults.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Largest single file, in bytes.
    pub max_file_len: u64,
    /// Largest total staged bytes for this environment, uploads and snapshots together.
    pub max_staged_len: u64,
    /// Concurrent transfers one device may hold.
    pub max_concurrent_transfers: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_file_len: kr_protocol::limits::DEFAULT_MAX_UPLOAD_FILE_LEN,
            max_staged_len: kr_protocol::limits::DEFAULT_MAX_STAGED_UPLOAD_LEN,
            max_concurrent_transfers: kr_protocol::limits::DEFAULT_MAX_CONCURRENT_TRANSFERS as u64,
        }
    }
}

/// One recorded upload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UploadRow {
    /// The upload's identity, shared with the attachment it publishes.
    pub transfer_id: TransferId,
    /// The environment that owns it.
    pub environment_id: EnvironmentId,
    /// The session it is bound to, when it has one.
    pub session_id: Option<SessionId>,
    /// The device its concurrency is counted against.
    pub device_id: Option<DeviceId>,
    /// The actor that began it. Only that actor may continue it.
    pub actor_id: ActorId,
    /// The declared size.
    pub declared_byte_len: u64,
    /// The declared whole-file digest.
    pub declared_digest: Digest256,
    /// The declared media type.
    pub declared_media_type: String,
    /// The original filename, metadata only.
    pub original_file_name: String,
    /// The host-chosen storage stem and extension, as a published name.
    pub stored_name: String,
    /// Its state.
    pub state: UploadState,
    /// Why it was invalidated, when it was.
    pub invalid_reason: Option<String>,
    /// Bytes charged against the environment's budget while this upload occupies it.
    pub reserved_byte_len: u64,
    /// The verified whole-file digest, once verification has happened.
    pub content_digest: Option<Digest256>,
    /// The stable identity of the payload file the verification was made against.
    ///
    /// A rename preserves it, so the object in the completed area has to be the object that was
    /// verified. A replacement of equal length does not.
    pub payload_identity: Option<ObjectIdentity>,
    /// True while a payload this upload no longer needs is still on disk.
    ///
    /// The bytes stay charged against the environment until the file is gone, and recovery retries
    /// the removal, so a failed delete cannot leave an uncharged file nothing looks at again.
    pub cleanup_pending: bool,
    /// The encoded preview, once one has been produced.
    pub preview: Option<Vec<u8>>,
    /// Why no preview was produced, when none was.
    pub preview_unavailable: Option<String>,
    /// When it was recorded.
    pub created_at_ms: TimestampMs,
    /// When it expires.
    pub expires_at_ms: TimestampMs,
    /// When it was published.
    pub published_at_ms: Option<TimestampMs>,
    /// When a draft holding it was submitted. Retention follows the session from then on.
    pub submitted_at_ms: Option<TimestampMs>,
}

/// One recorded download snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnapshotRow {
    /// The transfer's identity, which a resume addresses.
    pub transfer_id: TransferId,
    /// The environment that owns it.
    pub environment_id: EnvironmentId,
    /// The actor that opened it. Only that actor may read it.
    pub actor_id: ActorId,
    /// The device its concurrency is counted against.
    pub device_id: Option<DeviceId>,
    /// The read scope the source came from, for a staged snapshot.
    pub scope_id: Option<GrantId>,
    /// The attachment the source was, for an immutable source.
    pub source_transfer_id: Option<TransferId>,
    /// How the bytes were made immutable.
    pub immutability: DownloadImmutability,
    /// The source, as text, for diagnostics.
    pub source_label: String,
    /// The name the snapshot is stored under, for a staged snapshot.
    pub stored_name: Option<String>,
    /// The size.
    pub byte_len: u64,
    /// The whole-file digest.
    pub content_digest: Digest256,
    /// Bytes charged against the environment's budget.
    pub reserved_byte_len: u64,
    /// Its state.
    pub state: SnapshotState,
    /// True while a payload this snapshot no longer needs is still on disk.
    pub cleanup_pending: bool,
    /// Why it failed, when it did.
    pub failure_reason: Option<String>,
    /// The source object's identity when the snapshot was taken.
    pub source_identity: Option<ObjectIdentity>,
    /// The source's modification time when the snapshot was taken, in milliseconds.
    pub source_modified_ms: Option<i64>,
    /// When it was created.
    pub created_at_ms: TimestampMs,
    /// When it expires.
    pub expires_at_ms: TimestampMs,
}

/// What state a download snapshot is in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SnapshotState {
    /// Its bytes are reserved and its payload is being written.
    ///
    /// The row exists before the copy starts, so the reservation is atomic against every other
    /// admission and an interrupted construction is a row recovery can find.
    Reserving,
    /// It can serve chunks.
    Open,
    /// The source changed while it was being staged, or its bytes stopped verifying.
    Failed,
    /// It outlived its expiry and its bytes are gone.
    Expired,
    /// The client finished with it and its bytes are gone.
    Released,
}

impl SnapshotState {
    /// Returns the stable stored string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Reserving => "reserving",
            Self::Open => "open",
            Self::Failed => "failed",
            Self::Expired => "expired",
            Self::Released => "released",
        }
    }

    fn parse(text: &str) -> Option<Self> {
        match text {
            "reserving" => Some(Self::Reserving),
            "open" => Some(Self::Open),
            "failed" => Some(Self::Failed),
            "expired" => Some(Self::Expired),
            "released" => Some(Self::Released),
            _ => None,
        }
    }

    /// Returns true when this state still holds a payload and a reservation.
    #[must_use]
    pub const fn holds_bytes(self) -> bool {
        matches!(self, Self::Reserving | Self::Open)
    }
}

/// One registered authorised read scope.
///
/// A scope is an opened directory handle the host holds, plus the stable identity it had when it
/// was registered. Reopening it after a restart and finding a different object refuses the scope:
/// a rename, a case alias or a linked worktree does not extend the grant to another tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScopeRow {
    /// The scope's identity.
    pub scope_id: GrantId,
    /// The environment it is valid in.
    pub environment_id: EnvironmentId,
    /// The path it was opened from, for diagnostics and for reopening.
    pub root_path: String,
    /// The identity the opened directory had when it was registered.
    pub root: RecordedIdentity,
    /// What the scope is for.
    pub purpose: String,
    /// True once the scope is revoked. A revoked scope stops further bytes at once.
    pub revoked: bool,
}

/// One durable draft.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DraftRow {
    /// The draft's identity.
    pub draft_id: DraftId,
    /// The environment that owns it.
    pub environment_id: EnvironmentId,
    /// The actor that owns it.
    pub actor_id: ActorId,
    /// The device that owns it.
    pub device_id: Option<DeviceId>,
    /// The session it targets.
    pub session_id: Option<SessionId>,
    /// The application it targets.
    pub application_instance_id: Option<ApplicationInstanceId>,
    /// Its revision.
    pub revision: DraftRevision,
    /// Its state.
    pub state: DraftState,
    /// Its text.
    pub text: String,
    /// When it was created.
    pub created_at_ms: TimestampMs,
    /// When it was last updated.
    pub updated_at_ms: TimestampMs,
}

/// One attachment bound to a draft.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BindingRow {
    /// The draft.
    pub draft_id: DraftId,
    /// The attachment.
    pub transfer_id: TransferId,
    /// How it was offered.
    pub insertion_method: InsertionMethod,
    /// What became of the offer.
    pub state: InsertionState,
    /// The upstream evidence, which is the only thing that makes it accepted.
    pub upstream_evidence: Option<String>,
    /// Why it failed, when it did.
    pub failure_detail: Option<String>,
    /// The read grant issued for it, when its method needed one.
    pub grant_id: Option<GrantId>,
    /// Where the operation declared the bytes leave for, when it declared one.
    pub external_destination: Option<String>,
    /// When it was bound.
    pub bound_at_ms: TimestampMs,
    /// The order it was bound in. A binding bound again is a new attempt, so this is the attempt
    /// an offer is claimed for.
    pub ordinal: i64,
    /// The offer that claimed the binding, as its owner names it: the actor and the action the
    /// offer is made for. Absent until a claim, and kept after the offer is reported, so a repeat
    /// of the report is recognised.
    pub claimed_by: Option<String>,
    /// The read grant the claim issued for the one file. It is not the binding's `grant_id`: a
    /// draft's reply shows the latter and never the former.
    pub claim_grant: Option<GrantId>,
}

/// One narrow read grant over one attachment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrantRow {
    /// The grant's identity.
    pub grant_id: GrantId,
    /// The environment it is valid in.
    pub environment_id: EnvironmentId,
    /// The attachment it covers.
    pub transfer_id: TransferId,
    /// The insertion method it was issued for.
    pub insertion_method: InsertionMethod,
    /// The path it names.
    pub host_path: String,
    /// When it expires.
    pub expires_at_ms: TimestampMs,
    /// True once it is revoked.
    pub revoked: bool,
}

/// One action's identity, its payload and the result it produced.
///
/// A mutation whose idempotency is the action identifier commits this row in the same transaction
/// as the state it changed. That is what makes a repeat answerable: a daemon that dies between the
/// two would otherwise leave a mutation nothing could recognise as already performed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetainedAction {
    /// The actor that performed it.
    pub actor_id: ActorId,
    /// The action identifier.
    pub action_id: Uuid,
    /// The method.
    pub method: String,
    /// The digest of the payload it was performed with.
    pub payload_digest: Digest256,
    /// The transfer this action acts on, where it acts on one.
    ///
    /// A claim recorded without a result is resolvable only if something says which object it was
    /// for. This is that.
    pub subject: Option<TransferId>,
    /// The canonically encoded result, where the effect produces one in the same transaction.
    ///
    /// A publication is two commits, and the claim belongs to the first of them: there is no
    /// handle to record yet. Such a claim carries no result, which is what makes a repeat of it
    /// `OUTCOME_UNKNOWN` until the second commit fills it in.
    pub result: Option<Vec<u8>>,
    /// The refusal the effect ended in, where it ended in one in the same transaction.
    ///
    /// An effect that invalidates what it acts on is refused and leaves nothing to answer a repeat
    /// from but this: a repeat is owed the refusal the first copy was given, under the same code.
    pub failure: Option<ActionFailure>,
    /// When it was recorded.
    pub recorded_at_ms: TimestampMs,
}

/// The refusal an action is retained as.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActionFailure {
    /// The protocol code the refusal was given under.
    pub code: String,
    /// What it said.
    pub detail: String,
}

/// What a transaction that carried an action found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActionOutcome {
    /// The action was recorded and the state it changed was committed with it.
    Committed,
    /// This actor had already performed this action. Nothing was changed.
    AlreadyPerformed,
}

/// What a publication records before the payload file moves.
///
/// The four facts that make an interrupted publish resolvable: what the verification computed, the
/// object it computed it from, and the preview it produced or the reason it did not.
#[derive(Clone, Copy, Debug)]
pub struct Publication<'bytes> {
    /// The whole-file digest the verification computed.
    pub content_digest: Digest256,
    /// The filesystem identity of the object that was verified.
    pub payload_identity: ObjectIdentity,
    /// The encoded preview, where one was produced.
    pub preview: Option<&'bytes [u8]>,
    /// Why no preview was produced, where none was.
    pub preview_unavailable: Option<&'bytes str>,
}

/// One action claim whose outcome is not recorded yet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenClaim {
    /// The actor that claimed it.
    pub actor_id: ActorId,
    /// The action identifier.
    pub action_id: Uuid,
    /// The method it was claimed for.
    pub method: String,
    /// The digest of the payload it was claimed with.
    pub payload_digest: Digest256,
    /// The transfer it acts on, where it names one.
    pub transfer: Option<TransferId>,
}

/// A retained mutation result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActionRecord {
    /// The method that was performed.
    pub method: String,
    /// The digest of the payload it was performed with.
    pub payload_digest: Digest256,
    /// The canonically encoded result, for a mutation that succeeded.
    pub result: Option<Vec<u8>>,
    /// The error code, for one that failed.
    pub error_code: Option<String>,
    /// The error message, for one that failed.
    pub error_detail: Option<String>,
    /// When it was recorded.
    pub recorded_at_ms: TimestampMs,
}

/// One outbox row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventRow {
    /// Its position in this store's stream.
    pub sequence: u64,
    /// What happened.
    pub kind: String,
    /// The transfer or draft it happened to.
    pub subject: String,
    /// When it happened.
    pub recorded_at_ms: TimestampMs,
}

/// The transfer journal of one environment.
#[derive(Debug)]
pub struct Store {
    connection: Connection,
    environment_id: EnvironmentId,
}

impl Store {
    /// Opens the store for an environment, creating it on first use.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::StoreUnavailable`] when the database cannot be opened or migrated.
    pub fn open(path: impl AsRef<std::path::Path>, environment_id: EnvironmentId) -> Result<Self> {
        let connection = Connection::open(path.as_ref()).map_err(TransferError::store)?;
        Self::prepare(connection, environment_id)
    }

    /// Opens a store that exists only for the life of this process.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::StoreUnavailable`] when the database cannot be created.
    pub fn in_memory(environment_id: EnvironmentId) -> Result<Self> {
        Self::prepare(
            Connection::open_in_memory().map_err(TransferError::store)?,
            environment_id,
        )
    }

    fn prepare(connection: Connection, environment_id: EnvironmentId) -> Result<Self> {
        connection
            .pragma_update(None, "journal_mode", "WAL")
            .map_err(TransferError::store)?;
        connection
            .pragma_update(None, "synchronous", "FULL")
            .map_err(TransferError::store)?;
        connection
            .pragma_update(None, "foreign_keys", "ON")
            .map_err(TransferError::store)?;
        let store = Self {
            connection,
            environment_id,
        };
        store.migrate()?;
        Ok(store)
    }

    fn migrate(&self) -> Result<()> {
        self.connection
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL);
                 CREATE TABLE IF NOT EXISTS environment (
                     environment_id  BLOB PRIMARY KEY,
                     staging_name    TEXT NOT NULL,
                     staging_device  INTEGER,
                     staging_file_id INTEGER,
                     staging_fs      BLOB,
                     max_file_len    INTEGER NOT NULL,
                     max_staged_len  INTEGER NOT NULL,
                     max_concurrent  INTEGER NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS uploads (
                     transfer_id         BLOB PRIMARY KEY,
                     environment_id      BLOB NOT NULL,
                     session_id          BLOB,
                     device_id           BLOB,
                     actor_id            TEXT NOT NULL,
                     declared_byte_len   INTEGER NOT NULL,
                     declared_digest     BLOB NOT NULL,
                     declared_media_type TEXT NOT NULL,
                     original_file_name  TEXT NOT NULL,
                     stored_name         TEXT NOT NULL,
                     state               TEXT NOT NULL,
                     invalid_reason      TEXT,
                     reserved_byte_len   INTEGER NOT NULL,
                     content_digest      BLOB,
                     payload_device      INTEGER,
                     payload_file_id     INTEGER,
                     cleanup_pending     INTEGER NOT NULL DEFAULT 0,
                     preview             BLOB,
                     preview_unavailable TEXT,
                     created_at_ms       INTEGER NOT NULL,
                     expires_at_ms       INTEGER NOT NULL,
                     published_at_ms     INTEGER,
                     submitted_at_ms     INTEGER
                 );
                 CREATE INDEX IF NOT EXISTS uploads_needing_cleanup
                     ON uploads (cleanup_pending);
                 CREATE INDEX IF NOT EXISTS uploads_by_state ON uploads (state, expires_at_ms);
                 CREATE TABLE IF NOT EXISTS chunks (
                     transfer_id BLOB NOT NULL
                         REFERENCES uploads (transfer_id) ON DELETE CASCADE,
                     idx           INTEGER NOT NULL,
                     byte_len      INTEGER NOT NULL,
                     digest        BLOB NOT NULL,
                     written_at_ms INTEGER NOT NULL,
                     PRIMARY KEY (transfer_id, idx)
                 );
                 CREATE TABLE IF NOT EXISTS snapshots (
                     transfer_id        BLOB PRIMARY KEY,
                     environment_id     BLOB NOT NULL,
                     actor_id           TEXT NOT NULL,
                     device_id          BLOB,
                     scope_id           BLOB,
                     source_transfer_id BLOB,
                     immutability       TEXT NOT NULL,
                     source_label       TEXT NOT NULL,
                     stored_name        TEXT,
                     byte_len           INTEGER NOT NULL,
                     content_digest     BLOB NOT NULL,
                     reserved_byte_len  INTEGER NOT NULL,
                     state              TEXT NOT NULL,
                     cleanup_pending    INTEGER NOT NULL DEFAULT 0,
                     failure_reason     TEXT,
                     source_device      INTEGER,
                     source_file_id     INTEGER,
                     source_modified_ms INTEGER,
                     created_at_ms      INTEGER NOT NULL,
                     expires_at_ms      INTEGER NOT NULL
                 );
                 CREATE INDEX IF NOT EXISTS snapshots_by_state
                     ON snapshots (state, expires_at_ms);
                 CREATE TABLE IF NOT EXISTS snapshot_chunks (
                     transfer_id BLOB NOT NULL
                         REFERENCES snapshots (transfer_id) ON DELETE CASCADE,
                     idx      INTEGER NOT NULL,
                     byte_len INTEGER NOT NULL,
                     digest   BLOB NOT NULL,
                     PRIMARY KEY (transfer_id, idx)
                 );
                 CREATE TABLE IF NOT EXISTS scopes (
                     scope_id       BLOB PRIMARY KEY,
                     environment_id BLOB NOT NULL,
                     root_path      TEXT NOT NULL,
                     root_device    INTEGER NOT NULL,
                     root_file_id   INTEGER NOT NULL,
                     root_fs        BLOB,
                     purpose        TEXT NOT NULL,
                     revoked        INTEGER NOT NULL DEFAULT 0
                 );
                 CREATE TABLE IF NOT EXISTS drafts (
                     draft_id                BLOB PRIMARY KEY,
                     environment_id          BLOB NOT NULL,
                     actor_id                TEXT NOT NULL,
                     device_id               BLOB,
                     session_id              BLOB,
                     application_instance_id BLOB,
                     revision                INTEGER NOT NULL,
                     state                   TEXT NOT NULL,
                     text                    TEXT NOT NULL,
                     created_at_ms           INTEGER NOT NULL,
                     updated_at_ms           INTEGER NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS draft_attachments (
                     draft_id          BLOB NOT NULL
                         REFERENCES drafts (draft_id) ON DELETE CASCADE,
                     transfer_id       BLOB NOT NULL,
                     insertion_method  TEXT NOT NULL,
                     state             TEXT NOT NULL,
                     upstream_evidence TEXT,
                     failure_detail    TEXT,
                     grant_id          BLOB,
                     external_destination TEXT,
                     bound_at_ms       INTEGER NOT NULL,
                     ordinal           INTEGER NOT NULL,
                     claimed_by        TEXT,
                     claim_grant       BLOB,
                     PRIMARY KEY (draft_id, transfer_id)
                 );
                 CREATE TABLE IF NOT EXISTS grants (
                     grant_id         BLOB PRIMARY KEY,
                     environment_id   BLOB NOT NULL,
                     transfer_id      BLOB NOT NULL,
                     insertion_method TEXT NOT NULL,
                     host_path        TEXT NOT NULL,
                     expires_at_ms    INTEGER NOT NULL,
                     revoked          INTEGER NOT NULL DEFAULT 0
                 );
                 CREATE TABLE IF NOT EXISTS actions (
                     actor_id       TEXT NOT NULL,
                     action_id      BLOB NOT NULL,
                     method         TEXT NOT NULL,
                     payload_digest BLOB NOT NULL,
                     subject        BLOB,
                     result         BLOB,
                     error_code     TEXT,
                     error_detail   TEXT,
                     recorded_at_ms INTEGER NOT NULL,
                     PRIMARY KEY (actor_id, action_id)
                 );
                 CREATE TABLE IF NOT EXISTS events (
                     sequence       INTEGER PRIMARY KEY AUTOINCREMENT,
                     kind           TEXT NOT NULL,
                     subject        TEXT NOT NULL,
                     recorded_at_ms INTEGER NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS cursors (
                     consumer TEXT PRIMARY KEY,
                     sequence INTEGER NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS draft_prompts (
                     draft_id   BLOB PRIMARY KEY
                         REFERENCES drafts (draft_id) ON DELETE CASCADE,
                     session_id BLOB NOT NULL,
                     sent_at_ms INTEGER NOT NULL
                 );",
            )
            .map_err(TransferError::store)?;
        let recorded: Option<i64> = self
            .connection
            .query_row("SELECT version FROM schema_version", [], |row| row.get(0))
            .optional()
            .map_err(TransferError::store)?;
        // Forward-only, and each step leaves the journal readable by the version it moves to.
        // `CREATE TABLE IF NOT EXISTS` above does nothing to a table that already exists, so a
        // column that a later version of the schema added is added here, and a table that a later
        // version added is made in one transaction with the move of the version, where the step
        // moves it.
        //
        // Version 1 is what a build before the action subject was recorded wrote. The column and
        // the version are written by two statements, not one transaction, and a start that
        // stopped between them repeats the step safely, because the column is added only when it
        // is absent. Remove this step, with `add_action_subject`, once no supported upgrade
        // starts from a version 1 store.
        let mut version = recorded;
        if version == Some(1) {
            self.add_action_subject()?;
            self.connection
                .execute(
                    "UPDATE schema_version SET version = ?1",
                    params![UNSETTLED_VERSION],
                )
                .map_err(TransferError::store)?;
            version = Some(UNSETTLED_VERSION);
        }
        // A store written before directory identities carried a filesystem has no column for it.
        // The columns are added here, empty, and each record's first successful check fills its
        // own (`Settled::Revised`): the check decides such a record as every record was decided
        // before, by its device number and inode, and records the filesystem it found. Remove this
        // step and the handling of a record without a filesystem in `filesystem::settle` once no
        // supported upgrade starts from a store written before filesystems were recorded; a record
        // that no use has settled by then is refused, and registered again.
        self.add_column_if_absent("environment", "staging_fs", "BLOB")?;
        self.add_column_if_absent("scopes", "root_fs", "BLOB")?;
        // The offer a binding was claimed for, and the read grant that claim issued. A journal at
        // any version below the current one gets them here, empty, so that a journal the
        // sessions of earlier builds keep at its version has them as well. Remove this once no
        // supported upgrade can start from a store written before a binding could be claimed.
        self.add_column_if_absent("draft_attachments", "claimed_by", "TEXT")?;
        self.add_column_if_absent("draft_attachments", "claim_grant", "BLOB")?;
        match version {
            // A journal this build makes has no earlier build's session to note, and comes to the
            // current version with its table in one step.
            None => self.add_ended_sessions(None)?,
            // The sessions of earlier builds are still owed their settling, which alone moves the
            // version, so the table is added and the version is left.
            Some(UNSETTLED_VERSION) => self.add_ended_sessions(Some(UNSETTLED_VERSION))?,
            Some(SETTLED_VERSION) => self.add_ended_sessions(Some(SETTLED_VERSION))?,
            // The table is there and the columns have just been added: the version is all that
            // is left to move.
            Some(UNCLAIMED_VERSION) => {
                self.connection
                    .execute(
                        "UPDATE schema_version SET version = ?1",
                        params![SCHEMA_VERSION],
                    )
                    .map_err(TransferError::store)?;
            }
            Some(SCHEMA_VERSION) => {}
            Some(version) => {
                return Err(TransferError::StoreUnavailable {
                    detail: format!(
                        "this transfer store is at schema version {version}; this build reads \
                         {SCHEMA_VERSION}"
                    ),
                });
            }
        }
        Ok(())
    }

    /// Adds a column to a table that an earlier build created without it.
    fn add_column_if_absent(&self, table: &str, column: &str, kind: &str) -> Result<()> {
        let present: i64 = self
            .connection
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info(?1) WHERE name = ?2",
                params![table, column],
                |row| row.get(0),
            )
            .map_err(TransferError::store)?;
        if present == 0 {
            self.connection
                .execute(
                    &format!("ALTER TABLE {table} ADD COLUMN {column} {kind}"),
                    [],
                )
                .map_err(TransferError::store)?;
        }
        Ok(())
    }

    /// The step to version 4: the table that records which sessions have ended, so that a binding or
    /// a prompt for a draft of one is refused ([`Store::end_sessions`]).
    ///
    /// The table and the version are written in one transaction: a journal is never at version 3
    /// with the table half made, and never at version 4 without it. `from` is the version the
    /// journal is at, or `None` for one this build creates. A journal still at
    /// [`UNSETTLED_VERSION`] gets the table and keeps its version, because the settling of the
    /// sessions of earlier builds moves it. Once no supported upgrade starts from a journal at
    /// [`SETTLED_VERSION`] or below, the table moves into the batch above, this step goes, and the
    /// arm for a new journal writes the version row itself.
    fn add_ended_sessions(&self, from: Option<i64>) -> Result<()> {
        let transaction = self
            .connection
            .unchecked_transaction()
            .map_err(TransferError::store)?;
        transaction
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS ended_sessions (
                     session_id  BLOB PRIMARY KEY,
                     ended_at_ms INTEGER NOT NULL
                 );",
            )
            .map_err(TransferError::store)?;
        match from {
            None => transaction.execute(
                "INSERT INTO schema_version (version) VALUES (?1)",
                params![SCHEMA_VERSION],
            ),
            Some(UNSETTLED_VERSION) => Ok(0),
            Some(_) => transaction.execute(
                "UPDATE schema_version SET version = ?1",
                params![SCHEMA_VERSION],
            ),
        }
        .map_err(TransferError::store)?;
        transaction.commit().map_err(TransferError::store)
    }

    /// Adds the column that says which transfer an action claim acts on.
    ///
    /// Version 1 recorded an action's result or its failure and nothing else, because a claim
    /// always carried its result. A two-commit effect claims first and records later, and a claim
    /// with no result is resolvable only from the object it was for.
    fn add_action_subject(&self) -> Result<()> {
        let present: i64 = self
            .connection
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('actions') WHERE name = 'subject'",
                [],
                |row| row.get(0),
            )
            .map_err(TransferError::store)?;
        if present == 0 {
            self.connection
                .execute("ALTER TABLE actions ADD COLUMN subject BLOB", [])
                .map_err(TransferError::store)?;
        }
        Ok(())
    }

    /// Returns the environment this store belongs to.
    #[must_use]
    pub const fn environment_id(&self) -> EnvironmentId {
        self.environment_id
    }

    /// Returns the environment's staging-directory name, recording `proposed` on first use.
    ///
    /// The name is chosen once and kept. A second start that generated a new one would leave every
    /// published attachment in a directory nothing reaches.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::StoreUnavailable`] when the row cannot be read or written.
    pub fn staging_name(&self, proposed: &str, limits: Limits) -> Result<String> {
        self.connection
            .execute(
                "INSERT OR IGNORE INTO environment
                     (environment_id, staging_name, max_file_len, max_staged_len, max_concurrent)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    uuid_sql(self.environment_id.get()),
                    proposed,
                    as_i64(limits.max_file_len),
                    as_i64(limits.max_staged_len),
                    as_i64(limits.max_concurrent_transfers),
                ],
            )
            .map_err(TransferError::store)?;
        self.connection
            .query_row(
                "SELECT staging_name FROM environment WHERE environment_id = ?1",
                params![uuid_sql(self.environment_id.get())],
                |row| row.get(0),
            )
            .map_err(TransferError::store)
    }

    /// Returns the environment's configured limits.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::StoreUnavailable`] when the row cannot be read.
    pub fn limits(&self) -> Result<Limits> {
        self.connection
            .query_row(
                "SELECT max_file_len, max_staged_len, max_concurrent
                 FROM environment WHERE environment_id = ?1",
                params![uuid_sql(self.environment_id.get())],
                |row| {
                    Ok(Limits {
                        max_file_len: from_i64(row.get(0)?),
                        max_staged_len: from_i64(row.get(1)?),
                        max_concurrent_transfers: from_i64(row.get(2)?),
                    })
                },
            )
            .optional()
            .map_err(TransferError::store)
            .map(Option::unwrap_or_default)
    }

    /// Replaces the environment's configured limits.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::StoreUnavailable`] when the row cannot be written.
    pub fn set_limits(&self, limits: Limits) -> Result<()> {
        self.connection
            .execute(
                "UPDATE environment
                 SET max_file_len = ?2, max_staged_len = ?3, max_concurrent = ?4
                 WHERE environment_id = ?1",
                params![
                    uuid_sql(self.environment_id.get()),
                    as_i64(limits.max_file_len),
                    as_i64(limits.max_staged_len),
                    as_i64(limits.max_concurrent_transfers),
                ],
            )
            .map_err(TransferError::store)?;
        Ok(())
    }

    /// Returns the identity recorded for this environment's staging directory, if one is.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::StoreUnavailable`] when the row cannot be read.
    pub fn staging_identity(&self) -> Result<Option<RecordedIdentity>> {
        self.connection
            .query_row(
                "SELECT staging_device, staging_file_id, staging_fs FROM environment
                 WHERE environment_id = ?1",
                params![uuid_sql(self.environment_id.get())],
                |row| {
                    let device: Option<i64> = row.get(0)?;
                    let file_id: Option<i64> = row.get(1)?;
                    let filesystem: Option<FilesystemId> = row.get(2)?;
                    Ok(device.zip(file_id).map(|(device, file_id)| {
                        RecordedIdentity::from_parts(
                            identity_from_sql(device),
                            identity_from_sql(file_id),
                            filesystem,
                        )
                    }))
                },
            )
            .optional()
            .map_err(TransferError::store)
            .map(Option::flatten)
    }

    /// Records the identity of this environment's staging directory.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::StoreUnavailable`] when the row cannot be written.
    pub fn set_staging_identity(&self, identity: RecordedIdentity) -> Result<()> {
        self.connection
            .execute(
                "UPDATE environment SET staging_device = ?2, staging_file_id = ?3, staging_fs = ?4
                 WHERE environment_id = ?1",
                params![
                    uuid_sql(self.environment_id.get()),
                    identity_sql(identity.object.device),
                    identity_sql(identity.object.file_id),
                    identity.filesystem,
                ],
            )
            .map_err(TransferError::store)?;
        Ok(())
    }

    /// Replaces the identity recorded for the staging directory by what the directory has now,
    /// and moves every payload recorded on the same filesystem to its new number.
    ///
    /// A device number names one mounting of a filesystem, so a filesystem mounted again can come
    /// back under another one. The objects are the same and keep their numbers within it. The
    /// directory's identity and every payload's change in one transaction, so a start never finds
    /// some under each number, and only while the directory's row still carries the whole of what
    /// it is replacing. A row another settlement already replaced by `now` is as it should be; a
    /// row that is neither is refused, and no payload moves with it.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::StoreUnavailable`] when the rows cannot be written, or when the
    /// directory's record is neither what it replaces nor what it becomes.
    pub fn settle_staging(&mut self, settled: &Settled) -> Result<()> {
        let Some((was, now)) = settled.revision() else {
            return Ok(());
        };
        let environment = uuid_sql(self.environment_id.get());
        let transaction = self.begin()?;
        let changed = transaction
            .execute(
                "UPDATE environment SET staging_device = ?3, staging_fs = ?5
                 WHERE environment_id = ?1 AND staging_device = ?2 AND staging_file_id = ?6
                   AND staging_fs IS ?4",
                params![
                    environment,
                    identity_sql(was.object.device),
                    identity_sql(now.object.device),
                    was.filesystem,
                    now.filesystem,
                    identity_sql(was.object.file_id),
                ],
            )
            .map_err(TransferError::store)?;
        if changed == 0 {
            let already: i64 = transaction
                .query_row(
                    "SELECT COUNT(*) FROM environment
                     WHERE environment_id = ?1 AND staging_device = ?2 AND staging_file_id = ?3
                       AND staging_fs IS ?4",
                    params![
                        environment,
                        identity_sql(now.object.device),
                        identity_sql(now.object.file_id),
                        now.filesystem,
                    ],
                    |row| row.get(0),
                )
                .map_err(TransferError::store)?;
            return if already == 1 {
                Ok(())
            } else {
                Err(TransferError::store(
                    "the staging directory's record changed while it was being checked",
                ))
            };
        }
        if was.object.device != now.object.device {
            transaction
                .execute(
                    "UPDATE uploads SET payload_device = ?2 WHERE payload_device = ?1",
                    params![
                        identity_sql(was.object.device),
                        identity_sql(now.object.device)
                    ],
                )
                .map_err(TransferError::store)?;
        }
        transaction.commit().map_err(TransferError::store)
    }

    /// Returns how many bytes this environment has staged.
    ///
    /// Receiving uploads, published attachments that still exist and open snapshots share one
    /// budget, which is what section 14 asks of a snapshot: it is storage this environment spent.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::StoreUnavailable`] when the sums cannot be read.
    pub fn staged_byte_len(&self) -> Result<u64> {
        let uploads: i64 = self
            .connection
            .query_row(
                // The charge follows the file, not the state: a closed upload whose payload is
                // still on disk is still spending this environment's bytes.
                "SELECT COALESCE(SUM(reserved_byte_len), 0) FROM uploads
                 WHERE state IN ('receiving', 'publishing', 'published')
                    OR cleanup_pending = 1",
                [],
                |row| row.get(0),
            )
            .map_err(TransferError::store)?;
        let snapshots: i64 = self
            .connection
            .query_row(
                "SELECT COALESCE(SUM(reserved_byte_len), 0) FROM snapshots
                 WHERE state IN ('reserving', 'open') OR cleanup_pending = 1",
                [],
                |row| row.get(0),
            )
            .map_err(TransferError::store)?;
        Ok(from_i64(uploads).saturating_add(from_i64(snapshots)))
    }

    /// Returns how many transfers one principal holds open.
    ///
    /// Section 14 counts the ceiling per device, and the authenticated principal is what identifies
    /// a device to this host: a paired device's actor is that device, and a local caller's actor is
    /// the operating-system user. The `device_id` a request carries is a label the host records and
    /// takes no authority from, because a caller could otherwise send a new one per request and
    /// give itself another allowance.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::StoreUnavailable`] when the counts cannot be read.
    pub fn open_transfers(&self, actor_id: &ActorId) -> Result<u64> {
        let uploads = self.count(
            "SELECT COUNT(*) FROM uploads
             WHERE state IN ('receiving', 'publishing') AND actor_id = ?1",
            params![actor_id.as_str()],
        )?;
        let snapshots = self.count(
            "SELECT COUNT(*) FROM snapshots
             WHERE state IN ('reserving', 'open') AND actor_id = ?1",
            params![actor_id.as_str()],
        )?;
        Ok(uploads.saturating_add(snapshots))
    }

    fn count(&self, sql: &str, parameters: impl rusqlite::Params) -> Result<u64> {
        let count: i64 = self
            .connection
            .query_row(sql, parameters, |row| row.get(0))
            .map_err(TransferError::store)?;
        Ok(from_i64(count))
    }

    /// Records a new upload, its action and the event that announces it, in one transaction.
    ///
    /// Returns [`ActionOutcome::AlreadyPerformed`] when this actor had already performed this
    /// action, in which case nothing was written.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::StoreUnavailable`] when the write fails.
    pub fn insert_upload(
        &mut self,
        row: &UploadRow,
        action: Option<&RetainedAction>,
    ) -> Result<ActionOutcome> {
        let transaction = self.begin()?;
        if claim_action(&transaction, action)? == ActionOutcome::AlreadyPerformed {
            return Ok(ActionOutcome::AlreadyPerformed);
        }
        transaction
            .execute(
                "INSERT INTO uploads
                     (transfer_id, environment_id, session_id, device_id, actor_id,
                      declared_byte_len, declared_digest, declared_media_type, original_file_name,
                      stored_name, state, invalid_reason, reserved_byte_len, content_digest,
                      payload_device, payload_file_id, cleanup_pending, preview,
                      preview_unavailable, created_at_ms, expires_at_ms, published_at_ms,
                      submitted_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, NULL, ?12, NULL, ?13, ?14,
                         1, NULL, NULL, ?15, ?16, NULL, NULL)",
                params![
                    uuid_sql(row.transfer_id.get()),
                    uuid_sql(row.environment_id.get()),
                    row.session_id.map(|value| uuid_sql(value.get())),
                    row.device_id.map(|value| uuid_sql(value.get())),
                    row.actor_id.as_str(),
                    as_i64(row.declared_byte_len),
                    row.declared_digest.as_bytes().as_slice(),
                    row.declared_media_type,
                    row.original_file_name,
                    row.stored_name,
                    row.state.as_str(),
                    as_i64(row.reserved_byte_len),
                    row.payload_identity
                        .map(|identity| identity_sql(identity.device)),
                    row.payload_identity
                        .map(|identity| identity_sql(identity.file_id)),
                    as_i64(row.created_at_ms.get()),
                    as_i64(row.expires_at_ms.get()),
                ],
            )
            .map_err(TransferError::store)?;
        record_event(
            &transaction,
            "upload.begun",
            &row.transfer_id.to_string(),
            row.created_at_ms,
        )?;
        transaction.commit().map_err(TransferError::store)?;
        Ok(ActionOutcome::Committed)
    }

    /// Returns one upload.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::StoreUnavailable`] when the read fails.
    pub fn upload(&self, transfer_id: TransferId) -> Result<Option<UploadRow>> {
        self.connection
            .query_row(
                "SELECT transfer_id, environment_id, session_id, device_id, actor_id,
                        declared_byte_len, declared_digest, declared_media_type,
                        original_file_name, stored_name, state, invalid_reason, reserved_byte_len,
                        content_digest, payload_device, payload_file_id, cleanup_pending, preview,
                        preview_unavailable, created_at_ms, expires_at_ms, published_at_ms,
                        submitted_at_ms
                 FROM uploads WHERE transfer_id = ?1",
                params![uuid_sql(transfer_id.get())],
                read_upload,
            )
            .optional()
            .map_err(TransferError::store)?
            .transpose()
    }

    /// Records one verified chunk, after its bytes are on disk.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::StoreUnavailable`] when the write fails.
    pub fn record_chunk(
        &mut self,
        transfer_id: TransferId,
        chunk: ChunkDescriptor,
        at_ms: TimestampMs,
        action: Option<&RetainedAction>,
    ) -> Result<ActionOutcome> {
        let transaction = self.begin()?;
        if claim_action(&transaction, action)? == ActionOutcome::AlreadyPerformed {
            return Ok(ActionOutcome::AlreadyPerformed);
        }
        transaction
            .execute(
                "INSERT OR REPLACE INTO chunks (transfer_id, idx, byte_len, digest, written_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    uuid_sql(transfer_id.get()),
                    as_i64(chunk.index.get()),
                    as_i64(chunk.byte_len.get()),
                    chunk.digest.as_bytes().as_slice(),
                    as_i64(at_ms.get()),
                ],
            )
            .map_err(TransferError::store)?;
        transaction.commit().map_err(TransferError::store)?;
        Ok(ActionOutcome::Committed)
    }

    /// Returns one recorded chunk.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::StoreUnavailable`] when the read fails.
    pub fn chunk(&self, transfer_id: TransferId, index: u64) -> Result<Option<ChunkDescriptor>> {
        self.connection
            .query_row(
                "SELECT idx, byte_len, digest FROM chunks WHERE transfer_id = ?1 AND idx = ?2",
                params![uuid_sql(transfer_id.get()), as_i64(index)],
                read_chunk,
            )
            .optional()
            .map_err(TransferError::store)?
            .transpose()
    }

    /// Returns every recorded chunk of one upload, in index order.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::StoreUnavailable`] when the read fails.
    pub fn chunks(&self, transfer_id: TransferId) -> Result<Vec<ChunkDescriptor>> {
        let mut statement = self
            .connection
            .prepare("SELECT idx, byte_len, digest FROM chunks WHERE transfer_id = ?1 ORDER BY idx")
            .map_err(TransferError::store)?;
        let rows = statement
            .query_map(params![uuid_sql(transfer_id.get())], read_chunk)
            .map_err(TransferError::store)?;
        let mut chunks = Vec::new();
        for row in rows {
            chunks.push(row.map_err(TransferError::store)??);
        }
        Ok(chunks)
    }

    /// Moves an upload to a terminal state and announces it.
    ///
    /// The reservation is **not** released here. Its bytes stay charged against the environment
    /// until the payload is actually gone, which [`Self::release_payload`] records; a daemon that
    /// died between the two would otherwise leave a file no sweep looks at again.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::StoreUnavailable`] when the write fails.
    pub fn close_upload(
        &mut self,
        transfer_id: TransferId,
        state: UploadState,
        reason: Option<&str>,
        at_ms: TimestampMs,
        action: Option<&RetainedAction>,
    ) -> Result<ActionOutcome> {
        let transaction = self.begin()?;
        if claim_action(&transaction, action)? == ActionOutcome::AlreadyPerformed {
            return Ok(ActionOutcome::AlreadyPerformed);
        }
        transaction
            .execute(
                "UPDATE uploads
                 SET state = ?2, invalid_reason = ?3, cleanup_pending = 1
                 WHERE transfer_id = ?1",
                params![uuid_sql(transfer_id.get()), state.as_str(), reason],
            )
            .map_err(TransferError::store)?;
        record_event(
            &transaction,
            &format!("upload.{}", state.as_str()),
            &transfer_id.to_string(),
            at_ms,
        )?;
        transaction.commit().map_err(TransferError::store)?;
        Ok(ActionOutcome::Committed)
    }

    /// Moves an upload out of `from` to a terminal state, only while it is still in `from`.
    ///
    /// Returns false when the row had already moved, which is what a sweep needs: its list of
    /// candidates was read before the lock it now holds, and a finish or a cancellation may have
    /// landed in between.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::StoreUnavailable`] when the write fails.
    pub fn close_upload_from(
        &mut self,
        transfer_id: TransferId,
        from: UploadState,
        state: UploadState,
        reason: Option<&str>,
        at_ms: TimestampMs,
    ) -> Result<bool> {
        let transaction = self.begin()?;
        let changed = transaction
            .execute(
                "UPDATE uploads
                 SET state = ?3, invalid_reason = ?4, cleanup_pending = 1
                 WHERE transfer_id = ?1 AND state = ?2",
                params![
                    uuid_sql(transfer_id.get()),
                    from.as_str(),
                    state.as_str(),
                    reason,
                ],
            )
            .map_err(TransferError::store)?;
        if changed == 0 {
            return Ok(false);
        }
        record_event(
            &transaction,
            &format!("upload.{}", state.as_str()),
            &transfer_id.to_string(),
            at_ms,
        )?;
        transaction.commit().map_err(TransferError::store)?;
        Ok(true)
    }

    /// Records that a closed upload's payload is gone, which releases its reservation.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::StoreUnavailable`] when the write fails.
    pub fn release_payload(&self, transfer_id: TransferId) -> Result<()> {
        self.connection
            .execute(
                "UPDATE uploads SET reserved_byte_len = 0, cleanup_pending = 0
                 WHERE transfer_id = ?1",
                params![uuid_sql(transfer_id.get())],
            )
            .map_err(TransferError::store)?;
        Ok(())
    }

    /// Returns every upload whose payload still has to be removed.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::StoreUnavailable`] when the read fails.
    pub fn uploads_needing_cleanup(&self) -> Result<Vec<UploadRow>> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT transfer_id, environment_id, session_id, device_id, actor_id,
                        declared_byte_len, declared_digest, declared_media_type,
                        original_file_name, stored_name, state, invalid_reason, reserved_byte_len,
                        content_digest, payload_device, payload_file_id, cleanup_pending, preview,
                        preview_unavailable, created_at_ms, expires_at_ms, published_at_ms,
                        submitted_at_ms
                 FROM uploads
                 WHERE cleanup_pending = 1
                   AND state IN ('cancelled', 'invalidated', 'expired')
                 ORDER BY created_at_ms",
            )
            .map_err(TransferError::store)?;
        let rows = statement
            .query_map([], read_upload)
            .map_err(TransferError::store)?;
        let mut found = Vec::new();
        for row in rows {
            found.push(row.map_err(TransferError::store)??);
        }
        Ok(found)
    }

    /// Records the intent to publish, before the payload file is moved.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::StoreUnavailable`] when the write fails.
    pub fn begin_publish(
        &mut self,
        transfer_id: TransferId,
        publication: &Publication<'_>,
        at_ms: TimestampMs,
        action: Option<&RetainedAction>,
    ) -> Result<ActionOutcome> {
        let transaction = self.begin()?;
        if claim_action(&transaction, action)? == ActionOutcome::AlreadyPerformed {
            return Ok(ActionOutcome::AlreadyPerformed);
        }
        transaction
            .execute(
                "UPDATE uploads
                 SET state = ?2, content_digest = ?3, preview = ?4, preview_unavailable = ?5,
                     payload_device = ?6, payload_file_id = ?7
                 WHERE transfer_id = ?1",
                params![
                    uuid_sql(transfer_id.get()),
                    UploadState::Publishing.as_str(),
                    publication.content_digest.as_bytes().as_slice(),
                    publication.preview,
                    publication.preview_unavailable,
                    identity_sql(publication.payload_identity.device),
                    identity_sql(publication.payload_identity.file_id),
                ],
            )
            .map_err(TransferError::store)?;
        record_event(
            &transaction,
            "upload.verified",
            &transfer_id.to_string(),
            at_ms,
        )?;
        transaction.commit().map_err(TransferError::store)?;
        Ok(ActionOutcome::Committed)
    }

    /// Records the published handle, after the payload file has been moved.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::StoreUnavailable`] when the write fails.
    pub fn complete_publish(
        &mut self,
        transfer_id: TransferId,
        published_at_ms: TimestampMs,
        expires_at_ms: TimestampMs,
    ) -> Result<bool> {
        let transaction = self.begin()?;
        // Conditional on the row still being the one that was verified. A cancellation that landed
        // while the file was being moved must not be overwritten by the publish it cancelled.
        let changed = transaction
            .execute(
                "UPDATE uploads
                 SET state = ?2, published_at_ms = ?3, expires_at_ms = ?4, cleanup_pending = 0
                 WHERE transfer_id = ?1 AND state = ?5",
                params![
                    uuid_sql(transfer_id.get()),
                    UploadState::Published.as_str(),
                    as_i64(published_at_ms.get()),
                    as_i64(expires_at_ms.get()),
                    UploadState::Publishing.as_str(),
                ],
            )
            .map_err(TransferError::store)?;
        if changed == 0 {
            return Ok(false);
        }
        record_event(
            &transaction,
            "upload.published",
            &transfer_id.to_string(),
            published_at_ms,
        )?;
        transaction.commit().map_err(TransferError::store)?;
        Ok(true)
    }

    /// Records that a draft is sent to a session, and puts the attachments the draft holds under
    /// that session's retention.
    ///
    /// A draft is sent to one session, as an attachment belongs to one: once it is recorded, an
    /// attachment bound to the draft later is the session's as well ([`Self::bind_attachment`]), so
    /// what the draft carries to the session's agent is held whenever the agent reads it. An
    /// attachment already submitted keeps its submission, and one without a session takes the
    /// session the draft was sent to. Recording the same draft for the same session again changes
    /// nothing.
    ///
    /// A draft that targets another session, a draft already sent to another session, and a draft
    /// that holds an attachment belonging to another session are each refused, and the refusal
    /// writes nothing.
    ///
    /// Returns how many attachments the draft holds.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::InvalidArgument`] for each refusal above,
    /// [`TransferError::SessionEnded`] when the session has ended, and
    /// [`TransferError::StoreUnavailable`] when the write fails.
    pub fn record_prompt(
        &mut self,
        draft_id: DraftId,
        session_id: SessionId,
        at_ms: TimestampMs,
    ) -> Result<usize> {
        let draft = self
            .draft(draft_id)?
            .ok_or_else(|| TransferError::UnknownDraft {
                draft: draft_id.to_string(),
            })?;
        if draft.session_id.is_some_and(|target| target != session_id) {
            return Err(TransferError::invalid(
                "this draft targets another session, so it cannot be sent to this one",
            ));
        }
        let transaction = self.begin()?;
        let sent_to: Option<Uuid> = transaction
            .query_row(
                "SELECT session_id FROM draft_prompts WHERE draft_id = ?1",
                params![uuid_sql(draft_id.get())],
                |row| uuid_column(row, 0),
            )
            .optional()
            .map_err(TransferError::store)?;
        if sent_to.is_some_and(|sent_to| sent_to != session_id.get()) {
            return Err(TransferError::invalid(
                "this draft was sent to another session, so it cannot be sent to this one",
            ));
        }
        refuse_ended_session(&transaction, draft_id, None, Some(session_id))?;
        // A prompt sends the draft as it stands, and an attachment being offered to the agent is
        // not yet one the draft can be sent with: the offer would be answered for a draft that has
        // already gone.
        let being_offered: bool = transaction
            .query_row(
                "SELECT EXISTS (SELECT 1 FROM draft_attachments
                                 WHERE draft_id = ?1 AND state = 'inserting')",
                params![uuid_sql(draft_id.get())],
                |row| row.get(0),
            )
            .map_err(TransferError::store)?;
        if being_offered {
            return Err(TransferError::DraftConflict {
                detail: "an attachment of this draft is being offered to the agent, so the draft \
                         cannot be sent until the offer is reported"
                    .to_owned(),
            });
        }
        let held: Vec<(Uuid, Option<Uuid>, bool)> = {
            let mut statement = transaction
                .prepare(
                    "SELECT binding.transfer_id, upload.session_id,
                            upload.submitted_at_ms IS NOT NULL
                     FROM draft_attachments AS binding
                     JOIN uploads AS upload ON upload.transfer_id = binding.transfer_id
                     WHERE binding.draft_id = ?1",
                )
                .map_err(TransferError::store)?;
            let rows = statement
                .query_map(params![uuid_sql(draft_id.get())], |row| {
                    Ok((uuid_column(row, 0)?, optional_uuid(row, 1)?, row.get(2)?))
                })
                .map_err(TransferError::store)?;
            rows.collect::<std::result::Result<_, _>>()
                .map_err(TransferError::store)?
        };
        if held
            .iter()
            .any(|(_, owner, _)| owner.is_some_and(|owner| owner != session_id.get()))
        {
            return Err(TransferError::invalid(
                "an attachment of this draft belongs to another session, and an attachment is \
                 held by one session",
            ));
        }
        transaction
            .execute(
                "INSERT OR IGNORE INTO draft_prompts (draft_id, session_id, sent_at_ms)
                 VALUES (?1, ?2, ?3)",
                params![
                    uuid_sql(draft_id.get()),
                    uuid_sql(session_id.get()),
                    as_i64(at_ms.get())
                ],
            )
            .map_err(TransferError::store)?;
        for (transfer, _, submitted) in &held {
            if *submitted {
                continue;
            }
            // The session is recorded only where the upload had none: an attachment bound to a
            // session keeps that one.
            transaction
                .execute(
                    "UPDATE uploads
                     SET submitted_at_ms = ?2, session_id = COALESCE(session_id, ?3)
                     WHERE transfer_id = ?1 AND submitted_at_ms IS NULL",
                    params![
                        uuid_sql(*transfer),
                        as_i64(at_ms.get()),
                        uuid_sql(session_id.get())
                    ],
                )
                .map_err(TransferError::store)?;
            record_event(
                &transaction,
                "upload.submitted",
                &TransferId::new(*transfer).to_string(),
                at_ms,
            )?;
        }
        transaction.commit().map_err(TransferError::store)?;
        Ok(held.len())
    }

    /// Returns where this journal stands with the sessions an earlier build's worker may have been
    /// sent a prompt that names a draft, without this host being told.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::StoreUnavailable`] when the read fails.
    pub fn noting(&self) -> Result<Noting> {
        let marked: i64 = self
            .connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master
                 WHERE type = 'table' AND name = 'unseen_prompts_noted'",
                [],
                |row| row.get(0),
            )
            .map_err(TransferError::store)?;
        if marked > 0 {
            let noted: i64 = self
                .connection
                .query_row("SELECT COUNT(*) FROM unseen_prompts_noted", [], |row| {
                    row.get(0)
                })
                .map_err(TransferError::store)?;
            if noted > 0 {
                return Ok(Noting::Held);
            }
        }
        let version: i64 = self
            .connection
            .query_row("SELECT version FROM schema_version", [], |row| row.get(0))
            .map_err(TransferError::store)?;
        Ok(if version == SCHEMA_VERSION {
            Noting::Done
        } else {
            Noting::Owed
        })
    }

    /// Notes `sessions` as sessions whose agents may have been sent a prompt that names a draft
    /// without this host being told, and that the noting is done, in one transaction: a store that
    /// holds the mark holds every session that was named with it.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::StoreUnavailable`] when the write fails, and writes nothing.
    pub fn note_unseen_prompt_sessions(
        &mut self,
        sessions: &std::collections::BTreeSet<SessionId>,
        at_ms: TimestampMs,
    ) -> Result<()> {
        let transaction = self.begin()?;
        transaction
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS unseen_prompt_sessions (
                     session_id  BLOB PRIMARY KEY,
                     noted_at_ms INTEGER NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS unseen_prompts_noted (
                     id          INTEGER PRIMARY KEY CHECK (id = 1),
                     noted_at_ms INTEGER NOT NULL
                 );",
            )
            .map_err(TransferError::store)?;
        for session_id in sessions {
            transaction
                .execute(
                    "INSERT OR IGNORE INTO unseen_prompt_sessions (session_id, noted_at_ms)
                     VALUES (?1, ?2)",
                    params![uuid_sql(session_id.get()), as_i64(at_ms.get())],
                )
                .map_err(TransferError::store)?;
        }
        transaction
            .execute(
                "INSERT OR IGNORE INTO unseen_prompts_noted (id, noted_at_ms) VALUES (1, ?1)",
                params![as_i64(at_ms.get())],
            )
            .map_err(TransferError::store)?;
        transaction.commit().map_err(TransferError::store)
    }

    /// Returns the sessions noted as ones whose agents may have been sent a prompt that names a
    /// draft without this host being told.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::StoreUnavailable`] when the read fails.
    pub fn unseen_prompt_sessions(&self) -> Result<std::collections::BTreeSet<SessionId>> {
        noted_sessions(&self.connection)
    }

    /// Puts what the noted sessions name under those sessions' retention, once, and forgets the
    /// sessions, in one transaction: a journal that has lost the sessions holds what they named as
    /// submitted. Returns how many attachments were put under a session.
    ///
    /// A published attachment that no prompt this host knows of has submitted, and that a noted
    /// session names ([`Self::sessions_shielding`]), becomes submitted, to the session it belongs to
    /// or, where it belongs to none, to the first session that names it by identifier. Every
    /// assignment is read before any is written, so the order of the rows decides nothing. One
    /// session holds the attachment from then on, so the sweep reads no table to keep it, and it
    /// follows that session's retention alone and can be bound to no draft for another session. An
    /// attachment already submitted keeps its own session, and one that names no noted session is
    /// not touched.
    ///
    /// Both tables go, and the journal moves to the schema version that holds nothing noted, which is
    /// what tells the next start that there is nothing to note.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::StoreUnavailable`] when the write fails, and writes nothing.
    pub fn settle_unseen_prompt_sessions(&mut self, at_ms: TimestampMs) -> Result<usize> {
        let transaction = self.begin()?;
        let noted = noted_sessions(&transaction)?;
        let mut settled = 0;
        if !noted.is_empty() {
            let unsubmitted: Vec<Uuid> = {
                let mut statement = transaction
                    .prepare(
                        "SELECT transfer_id FROM uploads
                         WHERE state = ?1 AND submitted_at_ms IS NULL",
                    )
                    .map_err(TransferError::store)?;
                let rows = statement
                    .query_map(params![UploadState::Published.as_str()], |row| {
                        uuid_column(row, 0)
                    })
                    .map_err(TransferError::store)?;
                rows.collect::<std::result::Result<_, _>>()
                    .map_err(TransferError::store)?
            };
            // Every assignment is read before any is written: an attachment given a session
            // changes what names a session for the others that share a draft with it, and the
            // result must not depend on the order the rows come in.
            let mut assignments = Vec::new();
            for transfer in unsubmitted {
                let shielding =
                    shielding_sessions(&transaction, TransferId::new(transfer), &noted)?;
                if let Some(session_id) = shielding.first() {
                    assignments.push((transfer, *session_id));
                }
            }
            for (transfer, session_id) in assignments {
                transaction
                    .execute(
                        "UPDATE uploads
                         SET submitted_at_ms = ?2, session_id = COALESCE(session_id, ?3)
                         WHERE transfer_id = ?1 AND submitted_at_ms IS NULL",
                        params![
                            uuid_sql(transfer),
                            as_i64(at_ms.get()),
                            uuid_sql(session_id.get())
                        ],
                    )
                    .map_err(TransferError::store)?;
                record_event(
                    &transaction,
                    "upload.submitted",
                    &TransferId::new(transfer).to_string(),
                    at_ms,
                )?;
                settled += 1;
            }
        }
        transaction
            .execute_batch(
                "DROP TABLE IF EXISTS unseen_prompt_sessions;
                 DROP TABLE IF EXISTS unseen_prompts_noted;",
            )
            .map_err(TransferError::store)?;
        transaction
            .execute(
                "UPDATE schema_version SET version = ?1",
                params![SCHEMA_VERSION],
            )
            .map_err(TransferError::store)?;
        transaction.commit().map_err(TransferError::store)?;
        Ok(settled)
    }

    /// Returns those of `unseen` that an attachment belongs to, or that a draft holding the
    /// attachment names: by the session the draft targets, or by the session of another attachment
    /// the draft holds. A draft the attachment is held by may be sent to such a session by a route
    /// this host is not told of, and the whole draft goes with it.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::StoreUnavailable`] when the read fails.
    pub fn sessions_shielding(
        &self,
        transfer_id: TransferId,
        unseen: &std::collections::BTreeSet<SessionId>,
    ) -> Result<std::collections::BTreeSet<SessionId>> {
        shielding_sessions(&self.connection, transfer_id, unseen)
    }

    /// Returns true when a session the draft targets, was sent to, or whose upload one of its
    /// bindings holds has ended.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::StoreUnavailable`] when the read fails.
    pub fn session_has_ended(&self, draft_id: DraftId, transfer_id: TransferId) -> Result<bool> {
        session_has_ended(&self.connection, draft_id, Some(transfer_id), None)
    }

    /// Returns the session a draft was sent to, when it was sent to one.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::StoreUnavailable`] when the read fails.
    pub fn draft_sent_to(&self, draft_id: DraftId) -> Result<Option<SessionId>> {
        self.connection
            .query_row(
                "SELECT session_id FROM draft_prompts WHERE draft_id = ?1",
                params![uuid_sql(draft_id.get())],
                |row| uuid_column(row, 0),
            )
            .optional()
            .map(|session| session.map(SessionId::new))
            .map_err(TransferError::store)
    }

    /// Returns every upload in one of the given states, oldest first.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::StoreUnavailable`] when the read fails.
    pub fn uploads_in(&self, states: &[UploadState]) -> Result<Vec<UploadRow>> {
        let mut rows = Vec::new();
        for state in states {
            let mut statement = self
                .connection
                .prepare(
                    "SELECT transfer_id, environment_id, session_id, device_id, actor_id,
                            declared_byte_len, declared_digest, declared_media_type,
                            original_file_name, stored_name, state, invalid_reason,
                            reserved_byte_len, content_digest, payload_device, payload_file_id,
                            cleanup_pending, preview, preview_unavailable, created_at_ms,
                            expires_at_ms, published_at_ms, submitted_at_ms
                     FROM uploads WHERE state = ?1 ORDER BY created_at_ms",
                )
                .map_err(TransferError::store)?;
            let found = statement
                .query_map(params![state.as_str()], read_upload)
                .map_err(TransferError::store)?;
            for row in found {
                rows.push(row.map_err(TransferError::store)??);
            }
        }
        Ok(rows)
    }

    /// Records a new snapshot, its chunk layout and the event that announces it, in one
    /// transaction.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::StoreUnavailable`] when the write fails.
    pub fn insert_snapshot(&mut self, row: &SnapshotRow, chunks: &[ChunkDescriptor]) -> Result<()> {
        let transaction = self.begin()?;
        transaction
            .execute(
                "INSERT INTO snapshots
                     (transfer_id, environment_id, actor_id, device_id, scope_id,
                      source_transfer_id, immutability, source_label, stored_name, byte_len,
                      content_digest, reserved_byte_len, state, cleanup_pending, failure_reason,
                      source_device, source_file_id, source_modified_ms, created_at_ms,
                      expires_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, NULL, ?15,
                         ?16, ?17, ?18, ?19)",
                params![
                    uuid_sql(row.transfer_id.get()),
                    uuid_sql(row.environment_id.get()),
                    row.actor_id.as_str(),
                    row.device_id.map(|value| uuid_sql(value.get())),
                    row.scope_id.map(|value| uuid_sql(value.get())),
                    row.source_transfer_id.map(|value| uuid_sql(value.get())),
                    row.immutability.as_str(),
                    row.source_label,
                    row.stored_name,
                    as_i64(row.byte_len),
                    row.content_digest.as_bytes().as_slice(),
                    as_i64(row.reserved_byte_len),
                    row.state.as_str(),
                    i64::from(row.cleanup_pending),
                    row.source_identity
                        .map(|identity| identity_sql(identity.device)),
                    row.source_identity
                        .map(|identity| identity_sql(identity.file_id)),
                    row.source_modified_ms,
                    as_i64(row.created_at_ms.get()),
                    as_i64(row.expires_at_ms.get()),
                ],
            )
            .map_err(TransferError::store)?;
        for chunk in chunks {
            transaction
                .execute(
                    "INSERT INTO snapshot_chunks (transfer_id, idx, byte_len, digest)
                     VALUES (?1, ?2, ?3, ?4)",
                    params![
                        uuid_sql(row.transfer_id.get()),
                        as_i64(chunk.index.get()),
                        as_i64(chunk.byte_len.get()),
                        chunk.digest.as_bytes().as_slice(),
                    ],
                )
                .map_err(TransferError::store)?;
        }
        record_event(
            &transaction,
            "download.opened",
            &row.transfer_id.to_string(),
            row.created_at_ms,
        )?;
        transaction.commit().map_err(TransferError::store)
    }

    /// Returns one snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::StoreUnavailable`] when the read fails.
    pub fn snapshot(&self, transfer_id: TransferId) -> Result<Option<SnapshotRow>> {
        self.connection
            .query_row(
                "SELECT transfer_id, environment_id, actor_id, device_id, scope_id,
                        source_transfer_id, immutability, source_label, stored_name, byte_len,
                        content_digest, reserved_byte_len, state, cleanup_pending, failure_reason,
                        source_device, source_file_id, source_modified_ms, created_at_ms,
                        expires_at_ms
                 FROM snapshots WHERE transfer_id = ?1",
                params![uuid_sql(transfer_id.get())],
                read_snapshot,
            )
            .optional()
            .map_err(TransferError::store)?
            .transpose()
    }

    /// Returns one snapshot chunk.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::StoreUnavailable`] when the read fails.
    pub fn snapshot_chunk(
        &self,
        transfer_id: TransferId,
        index: u64,
    ) -> Result<Option<ChunkDescriptor>> {
        self.connection
            .query_row(
                "SELECT idx, byte_len, digest FROM snapshot_chunks
                 WHERE transfer_id = ?1 AND idx = ?2",
                params![uuid_sql(transfer_id.get()), as_i64(index)],
                read_chunk,
            )
            .optional()
            .map_err(TransferError::store)?
            .transpose()
    }

    /// Returns every chunk of one snapshot, in index order.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::StoreUnavailable`] when the read fails.
    pub fn snapshot_chunks(&self, transfer_id: TransferId) -> Result<Vec<ChunkDescriptor>> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT idx, byte_len, digest FROM snapshot_chunks
                 WHERE transfer_id = ?1 ORDER BY idx",
            )
            .map_err(TransferError::store)?;
        let rows = statement
            .query_map(params![uuid_sql(transfer_id.get())], read_chunk)
            .map_err(TransferError::store)?;
        let mut chunks = Vec::new();
        for row in rows {
            chunks.push(row.map_err(TransferError::store)??);
        }
        Ok(chunks)
    }

    /// Moves a snapshot to a terminal state, releasing its reservation, and announces it.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::StoreUnavailable`] when the write fails.
    pub fn close_snapshot(
        &mut self,
        transfer_id: TransferId,
        state: SnapshotState,
        reason: Option<&str>,
        at_ms: TimestampMs,
    ) -> Result<bool> {
        let transaction = self.begin()?;
        // Conditional, and the reservation stays. A snapshot's bytes are charged until its payload
        // is gone, exactly as an upload's are.
        let changed = transaction
            .execute(
                "UPDATE snapshots
                 SET state = ?2, failure_reason = ?3, cleanup_pending = 1
                 WHERE transfer_id = ?1 AND state IN ('reserving', 'open')",
                params![uuid_sql(transfer_id.get()), state.as_str(), reason],
            )
            .map_err(TransferError::store)?;
        if changed == 0 {
            return Ok(false);
        }
        record_event(
            &transaction,
            &format!("download.{}", state.as_str()),
            &transfer_id.to_string(),
            at_ms,
        )?;
        transaction.commit().map_err(TransferError::store)?;
        Ok(true)
    }

    /// Moves a snapshot under construction to serving, only while it is still reserving.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::StoreUnavailable`] when the write fails.
    pub fn open_snapshot_row(
        &mut self,
        transfer_id: TransferId,
        content_digest: Digest256,
        chunks: &[ChunkDescriptor],
        at_ms: TimestampMs,
    ) -> Result<bool> {
        let transaction = self.begin()?;
        let changed = transaction
            .execute(
                "UPDATE snapshots SET state = 'open', content_digest = ?2
                 WHERE transfer_id = ?1 AND state = 'reserving'",
                params![
                    uuid_sql(transfer_id.get()),
                    content_digest.as_bytes().as_slice(),
                ],
            )
            .map_err(TransferError::store)?;
        if changed == 0 {
            return Ok(false);
        }
        for chunk in chunks {
            transaction
                .execute(
                    "INSERT OR REPLACE INTO snapshot_chunks (transfer_id, idx, byte_len, digest)
                     VALUES (?1, ?2, ?3, ?4)",
                    params![
                        uuid_sql(transfer_id.get()),
                        as_i64(chunk.index.get()),
                        as_i64(chunk.byte_len.get()),
                        chunk.digest.as_bytes().as_slice(),
                    ],
                )
                .map_err(TransferError::store)?;
        }
        record_event(
            &transaction,
            "download.opened",
            &transfer_id.to_string(),
            at_ms,
        )?;
        transaction.commit().map_err(TransferError::store)?;
        Ok(true)
    }

    /// Records which mechanism produced a snapshot's bytes.
    ///
    /// A clone and a byte copy are different guarantees, and the row says which one this snapshot
    /// has, because a resume answers from the row rather than from the call that created it.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::StoreUnavailable`] when the write fails.
    pub fn set_snapshot_immutability(
        &self,
        transfer_id: TransferId,
        immutability: DownloadImmutability,
    ) -> Result<()> {
        self.connection
            .execute(
                "UPDATE snapshots SET immutability = ?2 WHERE transfer_id = ?1",
                params![uuid_sql(transfer_id.get()), immutability.as_str()],
            )
            .map_err(TransferError::store)?;
        Ok(())
    }

    /// Records that a closed snapshot's payload is gone, which releases its reservation.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::StoreUnavailable`] when the write fails.
    pub fn release_snapshot_payload(&self, transfer_id: TransferId) -> Result<()> {
        self.connection
            .execute(
                "UPDATE snapshots SET reserved_byte_len = 0, cleanup_pending = 0
                 WHERE transfer_id = ?1",
                params![uuid_sql(transfer_id.get())],
            )
            .map_err(TransferError::store)?;
        Ok(())
    }

    /// Returns every snapshot whose payload still has to be removed.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::StoreUnavailable`] when the read fails.
    pub fn snapshots_needing_cleanup(&self) -> Result<Vec<SnapshotRow>> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT transfer_id, environment_id, actor_id, device_id, scope_id,
                        source_transfer_id, immutability, source_label, stored_name, byte_len,
                        content_digest, reserved_byte_len, state, cleanup_pending, failure_reason,
                        source_device, source_file_id, source_modified_ms, created_at_ms,
                        expires_at_ms
                 FROM snapshots WHERE cleanup_pending = 1 ORDER BY created_at_ms",
            )
            .map_err(TransferError::store)?;
        let rows = statement
            .query_map([], read_snapshot)
            .map_err(TransferError::store)?;
        let mut found = Vec::new();
        for row in rows {
            found.push(row.map_err(TransferError::store)??);
        }
        Ok(found)
    }

    /// Returns every snapshot in one state, oldest first.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::StoreUnavailable`] when the read fails.
    pub fn snapshots_in(&self, state: SnapshotState) -> Result<Vec<SnapshotRow>> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT transfer_id, environment_id, actor_id, device_id, scope_id,
                        source_transfer_id, immutability, source_label, stored_name, byte_len,
                        content_digest, reserved_byte_len, state, cleanup_pending, failure_reason,
                        source_device, source_file_id, source_modified_ms, created_at_ms,
                        expires_at_ms
                 FROM snapshots WHERE state = ?1 ORDER BY created_at_ms",
            )
            .map_err(TransferError::store)?;
        let rows = statement
            .query_map(params![state.as_str()], read_snapshot)
            .map_err(TransferError::store)?;
        let mut found = Vec::new();
        for row in rows {
            found.push(row.map_err(TransferError::store)??);
        }
        Ok(found)
    }

    /// Records an authorised read scope.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::StoreUnavailable`] when the write fails.
    pub fn register_scope(&self, row: &ScopeRow) -> Result<()> {
        self.connection
            .execute(
                "INSERT OR REPLACE INTO scopes
                     (scope_id, environment_id, root_path, root_device, root_file_id, root_fs,
                      purpose, revoked)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    uuid_sql(row.scope_id.get()),
                    uuid_sql(row.environment_id.get()),
                    row.root_path,
                    identity_sql(row.root.object.device),
                    identity_sql(row.root.object.file_id),
                    row.root.filesystem,
                    row.purpose,
                    i64::from(row.revoked),
                ],
            )
            .map_err(TransferError::store)?;
        Ok(())
    }

    /// Returns one read scope.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::StoreUnavailable`] when the read fails.
    pub fn scope(&self, scope_id: GrantId) -> Result<Option<ScopeRow>> {
        self.connection
            .query_row(
                "SELECT scope_id, environment_id, root_path, root_device, root_file_id, root_fs,
                        purpose, revoked
                 FROM scopes WHERE scope_id = ?1",
                params![uuid_sql(scope_id.get())],
                |row| {
                    Ok(ScopeRow {
                        scope_id: GrantId::new(uuid_column(row, 0)?),
                        environment_id: EnvironmentId::new(uuid_column(row, 1)?),
                        root_path: row.get(2)?,
                        root: RecordedIdentity::from_parts(
                            identity_from_sql(row.get(3)?),
                            identity_from_sql(row.get(4)?),
                            row.get(5)?,
                        ),
                        purpose: row.get(6)?,
                        revoked: row.get::<_, i64>(7)? != 0,
                    })
                },
            )
            .optional()
            .map_err(TransferError::store)
    }

    /// Replaces the identity one scope's root was recorded under by what the directory has now.
    ///
    /// Only that scope's row changes, and only while it still carries the whole of what it
    /// replaces. The same filesystem can hold other scopes, and each is checked against its own
    /// directory when it is next used. A row another settlement already replaced by `now` is as it
    /// should be; a row that is neither, because the scope was registered again, is refused.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::StoreUnavailable`] when the write fails, or when the scope's
    /// record is neither what it replaces nor what it becomes.
    pub fn settle_scope(&self, scope_id: GrantId, settled: &Settled) -> Result<()> {
        let Some((was, now)) = settled.revision() else {
            return Ok(());
        };
        let changed = self
            .connection
            .execute(
                "UPDATE scopes SET root_device = ?3, root_fs = ?5
                 WHERE scope_id = ?1 AND root_device = ?2 AND root_file_id = ?6 AND root_fs IS ?4",
                params![
                    uuid_sql(scope_id.get()),
                    identity_sql(was.object.device),
                    identity_sql(now.object.device),
                    was.filesystem,
                    now.filesystem,
                    identity_sql(was.object.file_id),
                ],
            )
            .map_err(TransferError::store)?;
        if changed == 1 {
            return Ok(());
        }
        let already: i64 = self
            .connection
            .query_row(
                "SELECT COUNT(*) FROM scopes
                 WHERE scope_id = ?1 AND root_device = ?2 AND root_file_id = ?3 AND root_fs IS ?4",
                params![
                    uuid_sql(scope_id.get()),
                    identity_sql(now.object.device),
                    identity_sql(now.object.file_id),
                    now.filesystem,
                ],
                |row| row.get(0),
            )
            .map_err(TransferError::store)?;
        if already == 1 {
            Ok(())
        } else {
            Err(TransferError::store(
                "the scope's record changed while it was being checked",
            ))
        }
    }

    /// Revokes a read scope, which stops further bytes from every transfer that came from it.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::StoreUnavailable`] when the write fails.
    pub fn revoke_scope(&self, scope_id: GrantId) -> Result<()> {
        self.connection
            .execute(
                "UPDATE scopes SET revoked = 1 WHERE scope_id = ?1",
                params![uuid_sql(scope_id.get())],
            )
            .map_err(TransferError::store)?;
        Ok(())
    }

    /// Records a new draft and the event that announces it, in one transaction.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::SessionEnded`] when the draft targets a session that has ended, and
    /// [`TransferError::StoreUnavailable`] when the write fails.
    pub fn insert_draft(
        &mut self,
        row: &DraftRow,
        action: Option<&RetainedAction>,
    ) -> Result<ActionOutcome> {
        let transaction = self.begin()?;
        if claim_action(&transaction, action)? == ActionOutcome::AlreadyPerformed {
            return Ok(ActionOutcome::AlreadyPerformed);
        }
        transaction
            .execute(
                "INSERT INTO drafts
                     (draft_id, environment_id, actor_id, device_id, session_id,
                      application_instance_id, revision, state, text, created_at_ms,
                      updated_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                params![
                    uuid_sql(row.draft_id.get()),
                    uuid_sql(row.environment_id.get()),
                    row.actor_id.as_str(),
                    row.device_id.map(|value| uuid_sql(value.get())),
                    row.session_id.map(|value| uuid_sql(value.get())),
                    row.application_instance_id
                        .map(|value| uuid_sql(value.get())),
                    as_i64(row.revision.get()),
                    row.state.as_str(),
                    row.text,
                    as_i64(row.created_at_ms.get()),
                    as_i64(row.updated_at_ms.get()),
                ],
            )
            .map_err(TransferError::store)?;
        // A draft that targets a session which has already ended would be orphaned by the next pass
        // over the ended sessions, and nothing can be offered from it: it is not made.
        refuse_ended_session(&transaction, row.draft_id, None, None)?;
        record_event(
            &transaction,
            "draft.created",
            &row.draft_id.to_string(),
            row.created_at_ms,
        )?;
        transaction.commit().map_err(TransferError::store)?;
        Ok(ActionOutcome::Committed)
    }

    /// Returns one draft.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::StoreUnavailable`] when the read fails.
    pub fn draft(&self, draft_id: DraftId) -> Result<Option<DraftRow>> {
        self.connection
            .query_row(
                "SELECT draft_id, environment_id, actor_id, device_id, session_id,
                        application_instance_id, revision, state, text, created_at_ms,
                        updated_at_ms
                 FROM drafts WHERE draft_id = ?1",
                params![uuid_sql(draft_id.get())],
                |row| {
                    Ok(DraftRow {
                        draft_id: DraftId::new(uuid_column(row, 0)?),
                        environment_id: EnvironmentId::new(uuid_column(row, 1)?),
                        actor_id: actor_column(row, 2)?,
                        device_id: optional_uuid(row, 3)?.map(DeviceId::new),
                        session_id: optional_uuid(row, 4)?.map(SessionId::new),
                        application_instance_id: optional_uuid(row, 5)?
                            .map(ApplicationInstanceId::new),
                        revision: DraftRevision::new(from_i64(row.get(6)?)),
                        state: text_column(row, 7, DraftState::parse)?,
                        text: row.get(8)?,
                        created_at_ms: timestamp(row.get(9)?),
                        updated_at_ms: timestamp(row.get(10)?),
                    })
                },
            )
            .optional()
            .map_err(TransferError::store)
    }

    /// Replaces a draft's text at its exact revision, advancing it, and announces the update.
    ///
    /// Returns the new revision, or `None` when the expected revision was not current.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::StoreUnavailable`] when the write fails.
    pub fn update_draft(
        &mut self,
        draft_id: DraftId,
        expected: DraftRevision,
        text: &str,
        at_ms: TimestampMs,
        action: Option<&RetainedAction>,
    ) -> Result<Option<DraftRevision>> {
        let transaction = self.begin()?;
        if claim_action(&transaction, action)? == ActionOutcome::AlreadyPerformed {
            return Ok(None);
        }
        let changed = transaction
            .execute(
                "UPDATE drafts SET text = ?3, revision = revision + 1, updated_at_ms = ?4
                 WHERE draft_id = ?1 AND revision = ?2",
                params![
                    uuid_sql(draft_id.get()),
                    as_i64(expected.get()),
                    text,
                    as_i64(at_ms.get()),
                ],
            )
            .map_err(TransferError::store)?;
        if changed == 0 {
            return Ok(None);
        }
        record_event(&transaction, "draft.updated", &draft_id.to_string(), at_ms)?;
        transaction.commit().map_err(TransferError::store)?;
        Ok(Some(DraftRevision::new(expected.get().saturating_add(1))))
    }

    /// Advances a draft's revision without changing its text.
    ///
    /// Binding an attachment is a change to the draft, so it takes a revision like any other.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::SessionEnded`] when the session of the draft, or of the upload,
    /// has ended, and [`TransferError::StoreUnavailable`] when the write fails.
    pub fn bind_attachment(
        &mut self,
        binding: &BindingRow,
        expected: DraftRevision,
        grant: Option<&GrantRow>,
        action: Option<&RetainedAction>,
        session_id: Option<SessionId>,
        submitted_at: Option<TimestampMs>,
    ) -> Result<Option<DraftRevision>> {
        let transaction = self.begin()?;
        if claim_action(&transaction, action)? == ActionOutcome::AlreadyPerformed {
            return Ok(None);
        }
        refuse_ended_session(
            &transaction,
            binding.draft_id,
            Some(binding.transfer_id),
            session_id,
        )?;
        // An attachment uploaded without a session becomes that session's when it is bound to a
        // draft for one, in the same transaction as the binding. Recorded here rather than at
        // submission, so a second draft for another session finds the session already set and is
        // refused instead of quietly sharing the attachment.
        if let Some(session_id) = session_id {
            transaction
                .execute(
                    "UPDATE uploads SET session_id = ?2
                     WHERE transfer_id = ?1 AND session_id IS NULL",
                    params![
                        uuid_sql(binding.transfer_id.get()),
                        uuid_sql(session_id.get()),
                    ],
                )
                .map_err(TransferError::store)?;
        }
        // An attachment bound to a draft that was sent to a session is held by that session from
        // here, as the draft's other attachments are: the session's agent reads the draft when it
        // does, and what it finds there is kept for as long as the session is.
        if let Some(submitted_at) = submitted_at {
            let submitted = transaction
                .execute(
                    "UPDATE uploads SET submitted_at_ms = ?2
                     WHERE transfer_id = ?1 AND submitted_at_ms IS NULL",
                    params![
                        uuid_sql(binding.transfer_id.get()),
                        as_i64(submitted_at.get())
                    ],
                )
                .map_err(TransferError::store)?;
            if submitted == 1 {
                record_event(
                    &transaction,
                    "upload.submitted",
                    &binding.transfer_id.to_string(),
                    submitted_at,
                )?;
            }
        }
        let changed = transaction
            .execute(
                "UPDATE drafts SET revision = revision + 1, updated_at_ms = ?3
                 WHERE draft_id = ?1 AND revision = ?2",
                params![
                    uuid_sql(binding.draft_id.get()),
                    as_i64(expected.get()),
                    as_i64(binding.bound_at_ms.get()),
                ],
            )
            .map_err(TransferError::store)?;
        if changed == 0 {
            return Ok(None);
        }
        // An offer that is no longer being made has no use for the read grant its claim issued.
        if binding.state != InsertionState::Inserting
            && let Some(claim_grant) = binding.claim_grant
        {
            transaction
                .execute(
                    "UPDATE grants SET revoked = 1 WHERE grant_id = ?1",
                    params![uuid_sql(claim_grant.get())],
                )
                .map_err(TransferError::store)?;
        }
        transaction
            .execute(
                "INSERT OR REPLACE INTO draft_attachments
                     (draft_id, transfer_id, insertion_method, state, upstream_evidence,
                      failure_detail, grant_id, external_destination, bound_at_ms, ordinal,
                      claimed_by, claim_grant)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                params![
                    uuid_sql(binding.draft_id.get()),
                    uuid_sql(binding.transfer_id.get()),
                    binding.insertion_method.as_str(),
                    binding.state.as_str(),
                    binding.upstream_evidence,
                    binding.failure_detail,
                    binding.grant_id.map(|value| uuid_sql(value.get())),
                    binding.external_destination,
                    as_i64(binding.bound_at_ms.get()),
                    binding.ordinal,
                    binding.claimed_by,
                    binding.claim_grant.map(|value| uuid_sql(value.get())),
                ],
            )
            .map_err(TransferError::store)?;
        if let Some(grant) = grant {
            // The grant exists only if the binding it was issued for does. Committing it first
            // would leave a readable path behind a binding that never happened.
            transaction
                .execute(
                    "INSERT OR REPLACE INTO grants
                         (grant_id, environment_id, transfer_id, insertion_method, host_path,
                          expires_at_ms, revoked)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![
                        uuid_sql(grant.grant_id.get()),
                        uuid_sql(grant.environment_id.get()),
                        uuid_sql(grant.transfer_id.get()),
                        grant.insertion_method.as_str(),
                        grant.host_path,
                        as_i64(grant.expires_at_ms.get()),
                        i64::from(grant.revoked),
                    ],
                )
                .map_err(TransferError::store)?;
        }
        record_event(
            &transaction,
            &format!("draft.attachment.{}", binding.state.as_str()),
            &binding.draft_id.to_string(),
            binding.bound_at_ms,
        )?;
        transaction.commit().map_err(TransferError::store)?;
        Ok(Some(DraftRevision::new(expected.get().saturating_add(1))))
    }

    /// Records `sessions` as ended and fails, in the same transaction, every insertion that no
    /// upstream evidence confirmed and that belongs to one of them: its draft targets the session
    /// or was sent to it, or its upload is the session's. Each draft that has one takes a
    /// revision. Returns how many bindings it failed.
    ///
    /// A failed binding carries no reason text: the session's end is the reason, and a reason is
    /// bytes added to a reply that may already be at its budget. The state word alone is shorter
    /// than the one it replaces, so a draft that could be read can still be read.
    ///
    /// From the moment the transaction commits, a binding or a prompt for a draft of an ended
    /// session is refused ([`TransferError::SessionEnded`]), so a binding that races the end is
    /// either failed here or refused: the store's one lock orders them.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::StoreUnavailable`] when the write fails, and writes nothing.
    pub fn end_sessions(
        &mut self,
        sessions: &std::collections::BTreeSet<SessionId>,
        at_ms: TimestampMs,
    ) -> Result<usize> {
        let transaction = self.begin()?;
        for session_id in sessions {
            transaction
                .execute(
                    "INSERT OR IGNORE INTO ended_sessions (session_id, ended_at_ms) VALUES (?1, ?2)",
                    params![uuid_sql(session_id.get()), as_i64(at_ms.get())],
                )
                .map_err(TransferError::store)?;
        }
        // The insertions no upstream evidence confirmed are few however many sessions have ended,
        // so they are read once and matched against the set here. A binding a worker was claiming
        // is among them: the worker that claimed it is gone, and nothing will report the offer.
        type Held = (
            Uuid,
            Uuid,
            Option<Uuid>,
            Option<Uuid>,
            Option<Uuid>,
            Option<Uuid>,
        );
        let held: Vec<Held> = {
            let mut statement = transaction
                .prepare(
                    "SELECT binding.draft_id, binding.transfer_id, draft.session_id,
                            prompt.session_id, upload.session_id, binding.claim_grant
                       FROM draft_attachments AS binding
                       JOIN drafts AS draft ON draft.draft_id = binding.draft_id
                       LEFT JOIN draft_prompts AS prompt ON prompt.draft_id = binding.draft_id
                       LEFT JOIN uploads AS upload ON upload.transfer_id = binding.transfer_id
                      WHERE binding.state IN ('recorded', 'inserting')",
                )
                .map_err(TransferError::store)?;
            let rows = statement
                .query_map([], |row| {
                    Ok((
                        uuid_column(row, 0)?,
                        uuid_column(row, 1)?,
                        optional_uuid(row, 2)?,
                        optional_uuid(row, 3)?,
                        optional_uuid(row, 4)?,
                        optional_uuid(row, 5)?,
                    ))
                })
                .map_err(TransferError::store)?;
            rows.collect::<std::result::Result<_, _>>()
                .map_err(TransferError::store)?
        };
        let mut failed = 0;
        let mut drafts: Vec<Uuid> = Vec::new();
        for (draft, transfer, targeted, sent, uploaded, claim_grant) in held {
            let ended = [targeted, sent, uploaded]
                .into_iter()
                .flatten()
                .any(|session| sessions.contains(&SessionId::new(session)));
            if !ended {
                continue;
            }
            let changed = transaction
                .execute(
                    "UPDATE draft_attachments
                        SET state = 'failed', failure_detail = NULL, bound_at_ms = ?3
                      WHERE draft_id = ?1 AND transfer_id = ?2
                        AND state IN ('recorded', 'inserting')",
                    params![uuid_sql(draft), uuid_sql(transfer), as_i64(at_ms.get())],
                )
                .map_err(TransferError::store)?;
            failed += changed;
            if changed > 0 {
                if let Some(grant) = claim_grant {
                    transaction
                        .execute(
                            "UPDATE grants SET revoked = 1 WHERE grant_id = ?1",
                            params![uuid_sql(grant)],
                        )
                        .map_err(TransferError::store)?;
                }
                if !drafts.contains(&draft) {
                    drafts.push(draft);
                }
            }
        }
        // A draft whose target is gone is orphaned: kept, unbound, for explicit retargeting. A draft
        // that was only sent to a session, or holds an upload of one, has its insertions failed above
        // and is not orphaned, because it never targeted it.
        let targeting: Vec<Uuid> = {
            let mut statement = transaction
                .prepare(
                    "SELECT draft_id, session_id FROM drafts
                      WHERE session_id IS NOT NULL AND state <> 'orphaned'",
                )
                .map_err(TransferError::store)?;
            let rows = statement
                .query_map([], |row| Ok((uuid_column(row, 0)?, uuid_column(row, 1)?)))
                .map_err(TransferError::store)?;
            let mut targeting = Vec::new();
            for row in rows {
                let (draft, session) = row.map_err(TransferError::store)?;
                if sessions.contains(&SessionId::new(session)) {
                    targeting.push(draft);
                }
            }
            targeting
        };
        for draft in &targeting {
            if !drafts.contains(draft) {
                drafts.push(*draft);
            }
        }
        for draft in drafts {
            let orphaned = targeting.contains(&draft);
            transaction
                .execute(
                    "UPDATE drafts SET revision = revision + 1, updated_at_ms = ?2,
                            state = CASE WHEN ?3 THEN 'orphaned' ELSE state END
                      WHERE draft_id = ?1",
                    params![uuid_sql(draft), as_i64(at_ms.get()), orphaned],
                )
                .map_err(TransferError::store)?;
            record_event(
                &transaction,
                if orphaned {
                    "draft.orphaned"
                } else {
                    "draft.attachment.failed"
                },
                &DraftId::new(draft).to_string(),
                at_ms,
            )?;
        }
        transaction.commit().map_err(TransferError::store)?;
        Ok(failed)
    }

    /// Returns every attachment bound to a draft, in binding order.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::StoreUnavailable`] when the read fails.
    pub fn bindings(&self, draft_id: DraftId) -> Result<Vec<BindingRow>> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT draft_id, transfer_id, insertion_method, state, upstream_evidence,
                        failure_detail, grant_id, external_destination, bound_at_ms, ordinal,
                        claimed_by, claim_grant
                 FROM draft_attachments WHERE draft_id = ?1 ORDER BY ordinal",
            )
            .map_err(TransferError::store)?;
        let rows = statement
            .query_map(params![uuid_sql(draft_id.get())], |row| {
                Ok(BindingRow {
                    draft_id: DraftId::new(uuid_column(row, 0)?),
                    transfer_id: TransferId::new(uuid_column(row, 1)?),
                    insertion_method: text_column(row, 2, InsertionMethod::parse)?,
                    state: text_column(row, 3, InsertionState::parse)?,
                    upstream_evidence: row.get(4)?,
                    failure_detail: row.get(5)?,
                    grant_id: optional_uuid(row, 6)?.map(GrantId::new),
                    external_destination: row.get(7)?,
                    bound_at_ms: timestamp(row.get(8)?),
                    ordinal: row.get(9)?,
                    claimed_by: row.get(10)?,
                    claim_grant: optional_uuid(row, 11)?.map(GrantId::new),
                })
            })
            .map_err(TransferError::store)?;
        let mut bindings = Vec::new();
        for row in rows {
            bindings.push(row.map_err(TransferError::store)?);
        }
        Ok(bindings)
    }

    /// Records a narrow read grant.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::StoreUnavailable`] when the write fails.
    pub fn issue_grant(&self, row: &GrantRow) -> Result<()> {
        self.connection
            .execute(
                "INSERT OR REPLACE INTO grants
                     (grant_id, environment_id, transfer_id, insertion_method, host_path,
                      expires_at_ms, revoked)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    uuid_sql(row.grant_id.get()),
                    uuid_sql(row.environment_id.get()),
                    uuid_sql(row.transfer_id.get()),
                    row.insertion_method.as_str(),
                    row.host_path,
                    as_i64(row.expires_at_ms.get()),
                    i64::from(row.revoked),
                ],
            )
            .map_err(TransferError::store)?;
        Ok(())
    }

    /// Returns one read grant.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::StoreUnavailable`] when the read fails.
    pub fn grant(&self, grant_id: GrantId) -> Result<Option<GrantRow>> {
        self.connection
            .query_row(
                "SELECT grant_id, environment_id, transfer_id, insertion_method, host_path,
                        expires_at_ms, revoked
                 FROM grants WHERE grant_id = ?1",
                params![uuid_sql(grant_id.get())],
                |row| {
                    Ok(GrantRow {
                        grant_id: GrantId::new(uuid_column(row, 0)?),
                        environment_id: EnvironmentId::new(uuid_column(row, 1)?),
                        transfer_id: TransferId::new(uuid_column(row, 2)?),
                        insertion_method: text_column(row, 3, InsertionMethod::parse)?,
                        host_path: row.get(4)?,
                        expires_at_ms: timestamp(row.get(5)?),
                        revoked: row.get::<_, i64>(6)? != 0,
                    })
                },
            )
            .optional()
            .map_err(TransferError::store)
    }

    /// Revokes every grant over one attachment.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::StoreUnavailable`] when the write fails.
    pub fn revoke_grants_for(&self, transfer_id: TransferId) -> Result<()> {
        self.connection
            .execute(
                "UPDATE grants SET revoked = 1 WHERE transfer_id = ?1",
                params![uuid_sql(transfer_id.get())],
            )
            .map_err(TransferError::store)?;
        Ok(())
    }

    /// Returns a retained mutation result, when the same actor performed the same action before.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::StoreUnavailable`] when the read fails.
    pub fn retained_action(
        &self,
        actor_id: &ActorId,
        action_id: Uuid,
    ) -> Result<Option<ActionRecord>> {
        self.connection
            .query_row(
                "SELECT method, payload_digest, result, error_code, error_detail, recorded_at_ms
                 FROM actions WHERE actor_id = ?1 AND action_id = ?2",
                params![actor_id.as_str(), uuid_sql(action_id)],
                |row| {
                    Ok(ActionRecord {
                        method: row.get(0)?,
                        payload_digest: digest_column(row, 1)?,
                        result: row.get(2)?,
                        error_code: row.get(3)?,
                        error_detail: row.get(4)?,
                        recorded_at_ms: timestamp(row.get(5)?),
                    })
                },
            )
            .optional()
            .map_err(TransferError::store)
    }

    /// Retains one mutation result.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::StoreUnavailable`] when the write fails.
    pub fn record_action(
        &self,
        actor_id: &ActorId,
        action_id: Uuid,
        record: &ActionRecord,
    ) -> Result<bool> {
        // The first outcome recorded for an identifier is the one that stands. A later call with
        // the same identifier must not replace it, because the caller that is retrying is entitled
        // to the answer its action actually produced. The return says which call this was: true
        // when this outcome is the retained one, false when one was already there.
        let changed = self
            .connection
            .execute(
                "INSERT INTO actions
                     (actor_id, action_id, method, payload_digest, result, error_code,
                      error_detail, recorded_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                 ON CONFLICT (actor_id, action_id) DO NOTHING",
                params![
                    actor_id.as_str(),
                    uuid_sql(action_id),
                    record.method,
                    record.payload_digest.as_bytes().as_slice(),
                    record.result,
                    record.error_code,
                    record.error_detail,
                    as_i64(record.recorded_at_ms.get()),
                ],
            )
            .map_err(TransferError::store)?;
        Ok(changed == 1)
    }

    /// Returns every claim that has neither a result nor a failure recorded.
    ///
    /// These are two-commit effects that were interrupted between their commits. Each names the
    /// transfer it acts on, which is what makes it resolvable from that transfer's state.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::StoreUnavailable`] when the read fails.
    pub fn unfinished_claims(&self) -> Result<Vec<OpenClaim>> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT actor_id, action_id, method, payload_digest, subject FROM actions
                 WHERE result IS NULL AND error_code IS NULL",
            )
            .map_err(TransferError::store)?;
        let rows = statement
            .query_map([], |row| {
                Ok(OpenClaim {
                    actor_id: ActorId::new(row.get::<_, String>(0)?).unwrap_or_else(|_| {
                        ActorId::new("local").expect("a valid fallback principal")
                    }),
                    action_id: uuid_column(row, 1)?,
                    method: row.get(2)?,
                    payload_digest: digest_column(row, 3)?,
                    transfer: optional_uuid(row, 4)?.map(TransferId::new),
                })
            })
            .map_err(TransferError::store)?;
        let mut claims = Vec::new();
        for row in rows {
            claims.push(row.map_err(TransferError::store)?);
        }
        Ok(claims)
    }

    /// Fills in the result of an action that was claimed without one.
    ///
    /// The claim happens in the transaction that makes the effect durable; for a two-commit effect
    /// the result exists only after the second. Nothing replaces a result that is already there.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::StoreUnavailable`] when the write fails.
    pub fn complete_action(
        &self,
        actor_id: &ActorId,
        action_id: Uuid,
        method: &str,
        payload_digest: Digest256,
        result: &[u8],
    ) -> Result<bool> {
        // The method and the payload are part of the condition, not just the identifier. An
        // identifier can be claimed by a different request between a caller reading the record and
        // completing it, and that claim's result is not this caller's to write.
        let changed = self
            .connection
            .execute(
                "UPDATE actions SET result = ?5
                 WHERE actor_id = ?1 AND action_id = ?2 AND method = ?3 AND payload_digest = ?4
                   AND result IS NULL AND error_code IS NULL",
                params![
                    actor_id.as_str(),
                    uuid_sql(action_id),
                    method,
                    payload_digest.as_bytes().as_slice(),
                    result,
                ],
            )
            .map_err(TransferError::store)?;
        Ok(changed == 1)
    }

    /// Records the failure of an action that was claimed and never finished.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::StoreUnavailable`] when the write fails.
    pub fn fail_action(
        &self,
        actor_id: &ActorId,
        action_id: Uuid,
        method: &str,
        payload_digest: Digest256,
        code: &str,
        detail: &str,
    ) -> Result<bool> {
        // The method and the payload are part of the condition here for the same reason they are
        // part of completing one: an identifier can be claimed by a different request between a
        // caller reading the record and writing to it, and that claim's answer is not this
        // caller's to write.
        let changed = self
            .connection
            .execute(
                "UPDATE actions SET error_code = ?5, error_detail = ?6
                 WHERE actor_id = ?1 AND action_id = ?2 AND method = ?3 AND payload_digest = ?4
                   AND result IS NULL AND error_code IS NULL",
                params![
                    actor_id.as_str(),
                    uuid_sql(action_id),
                    method,
                    payload_digest.as_bytes().as_slice(),
                    code,
                    detail,
                ],
            )
            .map_err(TransferError::store)?;
        Ok(changed == 1)
    }

    /// Removes de-duplication records older than the protocol's retention.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::StoreUnavailable`] when the write fails.
    pub fn forget_actions_before(&self, at_ms: TimestampMs) -> Result<usize> {
        self.connection
            .execute(
                "DELETE FROM actions WHERE recorded_at_ms < ?1",
                params![as_i64(at_ms.get())],
            )
            .map_err(TransferError::store)
    }

    /// Returns whether any de-duplication record was written before `at_ms`.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::StoreUnavailable`] when the read fails.
    pub fn has_actions_before(&self, at_ms: TimestampMs) -> Result<bool> {
        self.connection
            .query_row(
                "SELECT EXISTS (SELECT 1 FROM actions WHERE recorded_at_ms < ?1)",
                params![as_i64(at_ms.get())],
                |row| row.get(0),
            )
            .map_err(TransferError::store)
    }

    /// Returns outbox rows after a cursor, oldest first.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::StoreUnavailable`] when the read fails.
    pub fn events_after(&self, sequence: u64, limit: u32) -> Result<Vec<EventRow>> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT sequence, kind, subject, recorded_at_ms FROM events
                 WHERE sequence > ?1 ORDER BY sequence LIMIT ?2",
            )
            .map_err(TransferError::store)?;
        let rows = statement
            .query_map(params![as_i64(sequence), i64::from(limit)], |row| {
                Ok(EventRow {
                    sequence: from_i64(row.get(0)?),
                    kind: row.get(1)?,
                    subject: row.get(2)?,
                    recorded_at_ms: timestamp(row.get(3)?),
                })
            })
            .map_err(TransferError::store)?;
        let mut events = Vec::new();
        for row in rows {
            events.push(row.map_err(TransferError::store)?);
        }
        Ok(events)
    }

    /// Records a consumer's position in the outbox.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::StoreUnavailable`] when the write fails.
    pub fn set_cursor(&self, consumer: &str, sequence: u64) -> Result<()> {
        self.connection
            .execute(
                "INSERT INTO cursors (consumer, sequence) VALUES (?1, ?2)
                 ON CONFLICT (consumer) DO UPDATE SET sequence = ?2",
                params![consumer, as_i64(sequence)],
            )
            .map_err(TransferError::store)?;
        Ok(())
    }

    /// Returns a consumer's recorded position.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::StoreUnavailable`] when the read fails.
    pub fn cursor(&self, consumer: &str) -> Result<u64> {
        let sequence: Option<i64> = self
            .connection
            .query_row(
                "SELECT sequence FROM cursors WHERE consumer = ?1",
                params![consumer],
                |row| row.get(0),
            )
            .optional()
            .map_err(TransferError::store)?;
        Ok(sequence.map(from_i64).unwrap_or_default())
    }

    fn begin(&mut self) -> Result<Transaction<'_>> {
        self.connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(TransferError::store)
    }
}

/// Writes an action's row inside the caller's transaction.
///
/// `ON CONFLICT DO NOTHING` is what makes this a claim: the first commit wins, and a second
/// transaction carrying the same identifier finds nothing to do and changes no state either. Two
/// callers racing the same action therefore produce one mutation and one retained result.
fn claim_action(
    transaction: &Transaction<'_>,
    action: Option<&RetainedAction>,
) -> Result<ActionOutcome> {
    let Some(action) = action else {
        return Ok(ActionOutcome::Committed);
    };
    let changed = transaction
        .execute(
            "INSERT INTO actions
                 (actor_id, action_id, method, payload_digest, subject, result, error_code,
                  error_detail, recorded_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?7, ?5, ?8, ?9, ?6)
             ON CONFLICT (actor_id, action_id) DO NOTHING",
            params![
                action.actor_id.as_str(),
                uuid_sql(action.action_id),
                action.method,
                action.payload_digest.as_bytes().as_slice(),
                action.result,
                as_i64(action.recorded_at_ms.get()),
                action.subject.map(|subject| uuid_sql(subject.get())),
                action.failure.as_ref().map(|failure| failure.code.as_str()),
                action
                    .failure
                    .as_ref()
                    .map(|failure| failure.detail.as_str()),
            ],
        )
        .map_err(TransferError::store)?;
    if changed == 0 {
        Ok(ActionOutcome::AlreadyPerformed)
    } else {
        Ok(ActionOutcome::Committed)
    }
}

/// Refuses a write for a draft whose session has ended, whether the draft targets it, was sent to
/// it or holds an upload that belongs to it, or for a session the write is about to bind.
fn refuse_ended_session(
    transaction: &Transaction<'_>,
    draft_id: DraftId,
    transfer_id: Option<TransferId>,
    also: Option<SessionId>,
) -> Result<()> {
    if session_has_ended(transaction, draft_id, transfer_id, also)? {
        Err(TransferError::SessionEnded)
    } else {
        Ok(())
    }
}

/// Whether a session a draft targets, was sent to, or whose upload it holds has ended.
fn session_has_ended(
    connection: &Connection,
    draft_id: DraftId,
    transfer_id: Option<TransferId>,
    also: Option<SessionId>,
) -> Result<bool> {
    connection
        .query_row(
            "SELECT EXISTS (
                 SELECT 1 FROM ended_sessions
                  WHERE session_id IN (
                        SELECT session_id FROM drafts
                         WHERE draft_id = ?1 AND session_id IS NOT NULL
                        UNION
                        SELECT session_id FROM draft_prompts WHERE draft_id = ?1
                        UNION
                        SELECT session_id FROM uploads
                         WHERE transfer_id = ?2 AND session_id IS NOT NULL
                        UNION
                        SELECT ?3 WHERE ?3 IS NOT NULL))",
            params![
                uuid_sql(draft_id.get()),
                transfer_id.map(|transfer| uuid_sql(transfer.get())),
                also.map(|session| uuid_sql(session.get()))
            ],
            |row| row.get(0),
        )
        .map_err(TransferError::store)
}

fn record_event(
    transaction: &Transaction<'_>,
    kind: &str,
    subject: &str,
    at_ms: TimestampMs,
) -> Result<()> {
    transaction
        .execute(
            "INSERT INTO events (kind, subject, recorded_at_ms) VALUES (?1, ?2, ?3)",
            params![kind, subject, as_i64(at_ms.get())],
        )
        .map_err(TransferError::store)?;
    Ok(())
}

type RowResult<T> = std::result::Result<Result<T>, rusqlite::Error>;

fn read_upload(row: &rusqlite::Row<'_>) -> RowResult<UploadRow> {
    let state = match UploadState::parse(&row.get::<_, String>(10)?) {
        Some(state) => state,
        None => {
            return Ok(Err(TransferError::store(
                "an upload row holds a state this build does not read",
            )));
        }
    };
    Ok(Ok(UploadRow {
        transfer_id: TransferId::new(uuid_column(row, 0)?),
        environment_id: EnvironmentId::new(uuid_column(row, 1)?),
        session_id: optional_uuid(row, 2)?.map(SessionId::new),
        device_id: optional_uuid(row, 3)?.map(DeviceId::new),
        actor_id: match ActorId::new(row.get::<_, String>(4)?) {
            Ok(actor) => actor,
            Err(_) => {
                return Ok(Err(TransferError::store(
                    "an upload row holds a principal this build does not read",
                )));
            }
        },
        declared_byte_len: from_i64(row.get(5)?),
        declared_digest: digest_column(row, 6)?,
        declared_media_type: row.get(7)?,
        original_file_name: row.get(8)?,
        stored_name: row.get(9)?,
        state,
        invalid_reason: row.get(11)?,
        reserved_byte_len: from_i64(row.get(12)?),
        content_digest: optional_digest(row, 13)?,
        payload_identity: row
            .get::<_, Option<i64>>(14)?
            .zip(row.get::<_, Option<i64>>(15)?)
            .map(|(device, file_id)| ObjectIdentity {
                device: identity_from_sql(device),
                file_id: identity_from_sql(file_id),
            }),
        cleanup_pending: row.get::<_, i64>(16)? != 0,
        preview: row.get(17)?,
        preview_unavailable: row.get(18)?,
        created_at_ms: timestamp(row.get(19)?),
        expires_at_ms: timestamp(row.get(20)?),
        published_at_ms: row.get::<_, Option<i64>>(21)?.map(timestamp),
        submitted_at_ms: row.get::<_, Option<i64>>(22)?.map(timestamp),
    }))
}

fn read_snapshot(row: &rusqlite::Row<'_>) -> RowResult<SnapshotRow> {
    let immutability = match DownloadImmutability::parse(&row.get::<_, String>(6)?) {
        Some(value) => value,
        None => {
            return Ok(Err(TransferError::store(
                "a snapshot row holds an immutability this build does not read",
            )));
        }
    };
    let state = match SnapshotState::parse(&row.get::<_, String>(12)?) {
        Some(state) => state,
        None => {
            return Ok(Err(TransferError::store(
                "a snapshot row holds a state this build does not read",
            )));
        }
    };
    let device: Option<i64> = row.get(15)?;
    let file_id: Option<i64> = row.get(16)?;
    Ok(Ok(SnapshotRow {
        transfer_id: TransferId::new(uuid_column(row, 0)?),
        environment_id: EnvironmentId::new(uuid_column(row, 1)?),
        actor_id: match ActorId::new(row.get::<_, String>(2)?) {
            Ok(actor) => actor,
            Err(_) => {
                return Ok(Err(TransferError::store(
                    "a snapshot row holds a principal this build does not read",
                )));
            }
        },
        device_id: optional_uuid(row, 3)?.map(DeviceId::new),
        scope_id: optional_uuid(row, 4)?.map(GrantId::new),
        source_transfer_id: optional_uuid(row, 5)?.map(TransferId::new),
        immutability,
        source_label: row.get(7)?,
        stored_name: row.get(8)?,
        byte_len: from_i64(row.get(9)?),
        content_digest: digest_column(row, 10)?,
        reserved_byte_len: from_i64(row.get(11)?),
        state,
        cleanup_pending: row.get::<_, i64>(13)? != 0,
        failure_reason: row.get(14)?,
        source_identity: device.zip(file_id).map(|(device, file_id)| ObjectIdentity {
            device: identity_from_sql(device),
            file_id: identity_from_sql(file_id),
        }),
        source_modified_ms: row.get(17)?,
        created_at_ms: timestamp(row.get(18)?),
        expires_at_ms: timestamp(row.get(19)?),
    }))
}

fn read_chunk(row: &rusqlite::Row<'_>) -> RowResult<ChunkDescriptor> {
    Ok(Ok(ChunkDescriptor {
        index: U64::new(from_i64(row.get(0)?)),
        byte_len: U64::new(from_i64(row.get(1)?)),
        digest: digest_column(row, 2)?,
    }))
}

fn text_column<T>(
    row: &rusqlite::Row<'_>,
    index: usize,
    parse: impl Fn(&str) -> Option<T>,
) -> std::result::Result<T, rusqlite::Error> {
    let text: String = row.get(index)?;
    parse(&text).ok_or_else(|| {
        rusqlite::Error::FromSqlConversionFailure(
            index,
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("{text} is not a value this build reads"),
            )),
        )
    })
}

fn actor_column(
    row: &rusqlite::Row<'_>,
    index: usize,
) -> std::result::Result<ActorId, rusqlite::Error> {
    let text: String = row.get(index)?;
    ActorId::new(text).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            index,
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                error.to_string(),
            )),
        )
    })
}

/// The sessions noted as ones whose agents may have been sent a prompt that names a draft without
/// this host being told. A journal that holds none has no table for them.
fn noted_sessions(connection: &Connection) -> Result<std::collections::BTreeSet<SessionId>> {
    let present: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master
             WHERE type = 'table' AND name = 'unseen_prompt_sessions'",
            [],
            |row| row.get(0),
        )
        .map_err(TransferError::store)?;
    if present == 0 {
        return Ok(std::collections::BTreeSet::new());
    }
    let mut statement = connection
        .prepare("SELECT session_id FROM unseen_prompt_sessions")
        .map_err(TransferError::store)?;
    let rows = statement
        .query_map([], |row| uuid_column(row, 0))
        .map_err(TransferError::store)?;
    rows.map(|row| row.map(SessionId::new).map_err(TransferError::store))
        .collect()
}

/// Those of `unseen` that an attachment belongs to, or that a draft holding the attachment names:
/// by the session the draft targets, or by the session of another attachment the draft holds.
fn shielding_sessions(
    connection: &Connection,
    transfer_id: TransferId,
    unseen: &std::collections::BTreeSet<SessionId>,
) -> Result<std::collections::BTreeSet<SessionId>> {
    let mut statement = connection
        .prepare(
            "SELECT session_id FROM uploads
                 WHERE transfer_id = ?1 AND session_id IS NOT NULL
             UNION
             SELECT draft.session_id
                 FROM draft_attachments AS binding
                 JOIN drafts AS draft ON draft.draft_id = binding.draft_id
                 WHERE binding.transfer_id = ?1 AND draft.session_id IS NOT NULL
             UNION
             SELECT upload.session_id
                 FROM draft_attachments AS binding
                 JOIN draft_attachments AS other ON other.draft_id = binding.draft_id
                 JOIN uploads AS upload ON upload.transfer_id = other.transfer_id
                 WHERE binding.transfer_id = ?1 AND upload.session_id IS NOT NULL",
        )
        .map_err(TransferError::store)?;
    let rows = statement
        .query_map(params![uuid_sql(transfer_id.get())], |row| {
            uuid_column(row, 0)
        })
        .map_err(TransferError::store)?;
    let mut shielding = std::collections::BTreeSet::new();
    for row in rows {
        let session_id = SessionId::new(row.map_err(TransferError::store)?);
        if unseen.contains(&session_id) {
            shielding.insert(session_id);
        }
    }
    Ok(shielding)
}

fn uuid_sql(value: Uuid) -> Vec<u8> {
    value.as_bytes().to_vec()
}

fn uuid_column(
    row: &rusqlite::Row<'_>,
    index: usize,
) -> std::result::Result<Uuid, rusqlite::Error> {
    let bytes: Vec<u8> = row.get(index)?;
    let bytes: [u8; 16] = bytes.try_into().map_err(|_| {
        rusqlite::Error::FromSqlConversionFailure(
            index,
            rusqlite::types::Type::Blob,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "an identifier column is not sixteen bytes",
            )),
        )
    })?;
    Ok(Uuid::from_bytes(bytes))
}

fn optional_uuid(
    row: &rusqlite::Row<'_>,
    index: usize,
) -> std::result::Result<Option<Uuid>, rusqlite::Error> {
    let bytes: Option<Vec<u8>> = row.get(index)?;
    match bytes {
        None => Ok(None),
        Some(bytes) => {
            let bytes: [u8; 16] = bytes.try_into().map_err(|_| {
                rusqlite::Error::FromSqlConversionFailure(
                    index,
                    rusqlite::types::Type::Blob,
                    Box::new(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "an identifier column is not sixteen bytes",
                    )),
                )
            })?;
            Ok(Some(Uuid::from_bytes(bytes)))
        }
    }
}

fn digest_column(
    row: &rusqlite::Row<'_>,
    index: usize,
) -> std::result::Result<Digest256, rusqlite::Error> {
    let bytes: Vec<u8> = row.get(index)?;
    let bytes: [u8; 32] = bytes.try_into().map_err(|_| {
        rusqlite::Error::FromSqlConversionFailure(
            index,
            rusqlite::types::Type::Blob,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "a digest column is not thirty-two bytes",
            )),
        )
    })?;
    Ok(Digest256::from_bytes(bytes))
}

fn optional_digest(
    row: &rusqlite::Row<'_>,
    index: usize,
) -> std::result::Result<Option<Digest256>, rusqlite::Error> {
    let bytes: Option<Vec<u8>> = row.get(index)?;
    match bytes {
        None => Ok(None),
        Some(bytes) => {
            let bytes: [u8; 32] = bytes.try_into().map_err(|_| {
                rusqlite::Error::FromSqlConversionFailure(
                    index,
                    rusqlite::types::Type::Blob,
                    Box::new(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "a digest column is not thirty-two bytes",
                    )),
                )
            })?;
            Ok(Some(Digest256::from_bytes(bytes)))
        }
    }
}

/// Stores a count as a signed integer, which is the widest SQLite has.
///
/// Every count this store holds is a byte length or a millisecond bounded well below the signed
/// maximum. Saturating keeps a nonsensical value from wrapping into a negative one that would then
/// read back as an enormous quota.
const fn as_i64(value: u64) -> i64 {
    if value > i64::MAX as u64 {
        i64::MAX
    } else {
        value as i64
    }
}

const fn from_i64(value: i64) -> u64 {
    if value < 0 { 0 } else { value as u64 }
}

/// Stores a filesystem identity as a signed integer without losing a bit.
///
/// A device number or an inode uses the whole `u64` range, so the saturating conversion counts use
/// for byte lengths would turn a valid identity into `i64::MAX` and make it compare unequal after a
/// restart. The reinterpretation round-trips exactly.
const fn identity_sql(value: u64) -> i64 {
    value as i64
}

const fn identity_from_sql(value: i64) -> u64 {
    value as u64
}

const fn timestamp(value: i64) -> TimestampMs {
    TimestampMs::new(from_i64(value))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn environment() -> EnvironmentId {
        EnvironmentId::new(Uuid::from_bytes([1; 16]))
    }

    fn actor() -> ActorId {
        ActorId::new("local:501").expect("a valid principal")
    }

    fn transfer(byte: u8) -> TransferId {
        TransferId::new(Uuid::from_bytes([byte; 16]))
    }

    fn upload(byte: u8, declared: u64) -> UploadRow {
        UploadRow {
            transfer_id: transfer(byte),
            environment_id: environment(),
            session_id: None,
            device_id: None,
            actor_id: actor(),
            declared_byte_len: declared,
            declared_digest: Digest256::from_bytes([byte; 32]),
            declared_media_type: "image/png".to_owned(),
            original_file_name: "photo.png".to_owned(),
            stored_name: format!("{byte:032x}.png"),
            state: UploadState::Receiving,
            invalid_reason: None,
            reserved_byte_len: declared,
            content_digest: None,
            payload_identity: None,
            cleanup_pending: false,
            preview: None,
            preview_unavailable: None,
            created_at_ms: TimestampMs::new(1000),
            expires_at_ms: TimestampMs::new(1000 + 24 * 60 * 60 * 1000),
            published_at_ms: None,
            submitted_at_ms: None,
        }
    }

    #[test]
    fn a_version_one_journal_gains_the_column_a_claim_needs() {
        // A journal written by the version that retained only finished actions: the same table
        // without `subject`, and the version row that says so.
        let connection = rusqlite::Connection::open_in_memory().expect("opens");
        connection
            .execute_batch(
                "CREATE TABLE schema_version (version INTEGER NOT NULL);
                 INSERT INTO schema_version (version) VALUES (1);
                 CREATE TABLE actions (
                     actor_id       TEXT NOT NULL,
                     action_id      BLOB NOT NULL,
                     method         TEXT NOT NULL,
                     payload_digest BLOB NOT NULL,
                     result         BLOB,
                     error_code     TEXT,
                     error_detail   TEXT,
                     recorded_at_ms INTEGER NOT NULL,
                     PRIMARY KEY (actor_id, action_id)
                 );",
            )
            .expect("writes a version-one journal");
        let store = Store::prepare(connection, environment()).expect("migrates and opens");

        // The version moved, the column is there, and the reader that needs it works. The journal
        // is one an earlier build wrote, so the sessions of earlier builds are still owed their
        // noting.
        let version: i64 = store
            .connection
            .query_row("SELECT version FROM schema_version", [], |row| row.get(0))
            .expect("reads the version");
        assert_eq!(version, UNSETTLED_VERSION);
        assert_eq!(store.noting().expect("reads the noting"), Noting::Owed);
        assert!(
            store
                .unfinished_claims()
                .expect("reads the claims")
                .is_empty()
        );
    }

    /// A journal at `version`, as a build before the record of ended sessions wrote it, with
    /// `extra` run after the version row is written.
    fn write_a_journal_at(path: &std::path::Path, version: i64, extra: &str) {
        let connection = rusqlite::Connection::open(path).expect("opens");
        connection
            .execute_batch(&format!(
                "CREATE TABLE schema_version (version INTEGER NOT NULL);
                 INSERT INTO schema_version (version) VALUES ({version});
                 {extra}"
            ))
            .expect("writes the journal");
    }

    /// The table of bindings as a build before a binding could be claimed made it.
    const BINDINGS_BEFORE_CLAIMS: &str = "CREATE TABLE draft_attachments (
        draft_id BLOB NOT NULL, transfer_id BLOB NOT NULL, insertion_method TEXT NOT NULL,
        state TEXT NOT NULL, upstream_evidence TEXT, failure_detail TEXT, grant_id BLOB,
        external_destination TEXT, bound_at_ms INTEGER NOT NULL, ordinal INTEGER NOT NULL,
        PRIMARY KEY (draft_id, transfer_id));";

    fn has_the_column(path: &std::path::Path, column: &str) -> bool {
        rusqlite::Connection::open(path)
            .expect("opens")
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('draft_attachments') WHERE name = ?1",
                [column],
                |row| row.get::<_, i64>(0),
            )
            .expect("reads the schema")
            == 1
    }

    fn recorded_version(path: &std::path::Path) -> i64 {
        rusqlite::Connection::open(path)
            .expect("opens")
            .query_row("SELECT version FROM schema_version", [], |row| row.get(0))
            .expect("reads the version")
    }

    fn has_the_table_of_ended_sessions(path: &std::path::Path) -> bool {
        rusqlite::Connection::open(path)
            .expect("opens")
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master
                  WHERE type = 'table' AND name = 'ended_sessions'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .expect("reads the schema")
            == 1
    }

    fn end_a_session(store: &mut Store) {
        let session = SessionId::new(Uuid::from_bytes([7; 16]));
        store
            .end_sessions(
                &std::collections::BTreeSet::from([session]),
                TimestampMs::new(1000),
            )
            .expect("records the session as ended in the table the step made");
    }

    #[test]
    fn a_journal_this_build_makes_is_at_the_current_version_with_the_table_of_ended_sessions() {
        let directory = tempfile::tempdir().expect("a temporary directory");
        let path = directory.path().join("transfers.sqlite");

        let mut store = Store::open(&path, environment()).expect("creates and opens");
        assert_eq!(SCHEMA_VERSION, 5);
        assert_eq!(recorded_version(&path), SCHEMA_VERSION);
        assert!(has_the_table_of_ended_sessions(&path));
        assert_eq!(store.noting().expect("reads the noting"), Noting::Done);
        end_a_session(&mut store);
    }

    #[test]
    fn a_version_two_journal_gains_the_table_of_ended_sessions_and_keeps_its_version_until_settled()
    {
        // An earlier build's journal: its sessions are owed their noting, and only the settling of
        // them moves the journal on, so the step for the table leaves the version at 2.
        let directory = tempfile::tempdir().expect("a temporary directory");
        let path = directory.path().join("transfers.sqlite");
        write_a_journal_at(&path, UNSETTLED_VERSION, "");
        assert!(!has_the_table_of_ended_sessions(&path));

        let mut store = Store::open(&path, environment()).expect("migrates and opens");
        assert_eq!(recorded_version(&path), UNSETTLED_VERSION);
        assert!(has_the_table_of_ended_sessions(&path));
        assert_eq!(store.noting().expect("reads the noting"), Noting::Owed);
        end_a_session(&mut store);

        // Settling moves it to the current version and leaves the table with its row.
        store
            .settle_unseen_prompt_sessions(TimestampMs::new(2000))
            .expect("settles");
        assert_eq!(recorded_version(&path), SCHEMA_VERSION);
        assert!(has_the_table_of_ended_sessions(&path));
        let ended: i64 = store
            .connection
            .query_row("SELECT COUNT(*) FROM ended_sessions", [], |row| row.get(0))
            .expect("counts the ended sessions");
        assert_eq!(ended, 1, "settling keeps the session that was ended");
        assert_eq!(store.noting().expect("reads the noting"), Noting::Done);
        drop(store);

        // A start after it reads the journal as it is.
        let reopened = Store::open(&path, environment()).expect("opens again");
        assert_eq!(reopened.noting().expect("reads the noting"), Noting::Done);
        assert_eq!(recorded_version(&path), SCHEMA_VERSION);
    }

    #[test]
    fn a_version_four_journal_gains_the_columns_that_record_a_claim_and_moves_to_version_five() {
        let directory = tempfile::tempdir().expect("a temporary directory");
        let path = directory.path().join("transfers.sqlite");
        write_a_journal_at(
            &path,
            UNCLAIMED_VERSION,
            &format!(
                "CREATE TABLE ended_sessions (session_id BLOB PRIMARY KEY, ended_at_ms INTEGER NOT NULL);
                 {BINDINGS_BEFORE_CLAIMS}"
            ),
        );
        assert!(!has_the_column(&path, "claimed_by"));
        assert!(!has_the_column(&path, "claim_grant"));

        let store = Store::open(&path, environment()).expect("migrates and opens");
        assert_eq!(recorded_version(&path), SCHEMA_VERSION);
        assert!(has_the_column(&path, "claimed_by"));
        assert!(has_the_column(&path, "claim_grant"));
        assert_eq!(store.noting().expect("reads the noting"), Noting::Done);
    }

    #[test]
    fn a_journal_that_is_unsettled_gains_the_columns_and_keeps_its_version() {
        // A journal of an earlier build's sessions: it stays at its version until they are settled,
        // and it has the columns all the same, so a claim could be recorded in it. Claims are
        // refused while it is unsettled.
        let directory = tempfile::tempdir().expect("a temporary directory");
        let path = directory.path().join("transfers.sqlite");
        write_a_journal_at(&path, UNSETTLED_VERSION, BINDINGS_BEFORE_CLAIMS);

        let store = Store::open(&path, environment()).expect("migrates and opens");
        assert_eq!(recorded_version(&path), UNSETTLED_VERSION);
        assert!(has_the_column(&path, "claimed_by"));
        assert!(has_the_column(&path, "claim_grant"));
        assert_eq!(store.noting().expect("reads the noting"), Noting::Owed);
    }

    #[test]
    fn a_version_three_journal_gains_the_table_of_ended_sessions_and_moves_to_version_four() {
        // A journal whose sessions of earlier builds were settled: nothing is owed, so the one
        // step adds the table and moves the version.
        let directory = tempfile::tempdir().expect("a temporary directory");
        let path = directory.path().join("transfers.sqlite");
        write_a_journal_at(&path, SETTLED_VERSION, "");
        assert!(!has_the_table_of_ended_sessions(&path));

        let mut store = Store::open(&path, environment()).expect("migrates and opens");
        assert_eq!(recorded_version(&path), SCHEMA_VERSION);
        assert!(has_the_table_of_ended_sessions(&path));
        assert_eq!(store.noting().expect("reads the noting"), Noting::Done);
        end_a_session(&mut store);
    }

    #[test]
    fn a_step_that_cannot_write_the_version_leaves_a_version_three_journal_without_the_table() {
        let directory = tempfile::tempdir().expect("a temporary directory");
        let path = directory.path().join("transfers.sqlite");
        write_a_journal_at(
            &path,
            SETTLED_VERSION,
            "CREATE TRIGGER refuse_the_version BEFORE UPDATE ON schema_version
             BEGIN SELECT RAISE(ABORT, 'the version cannot be written'); END;",
        );

        let refusal = Store::open(&path, environment()).expect_err("the version cannot be written");
        assert!(
            format!("{refusal:?}").contains("the version cannot be written"),
            "the open failed at the version write: {refusal:?}"
        );
        // The table and the version are one step: neither is there.
        assert_eq!(recorded_version(&path), SETTLED_VERSION);
        assert!(!has_the_table_of_ended_sessions(&path));
    }

    #[test]
    fn a_filesystem_identity_survives_the_whole_range_of_the_journal() {
        let mut store = Store::in_memory(environment()).expect("opens");
        // A device number and a file identifier are unsigned and use the whole range. SQLite
        // stores signed integers, so the conversion has to be a reinterpretation rather than a
        // clamp: an identifier with its high bit set must come back as itself.
        let extreme = crate::authority::ObjectIdentity {
            device: u64::MAX,
            file_id: u64::MAX - 1,
        };
        let mut row = upload(9, 64);
        row.payload_identity = Some(extreme);
        store.insert_upload(&row, None).expect("records the upload");

        let read = store
            .upload(transfer(9))
            .expect("reads it back")
            .expect("the row exists");

        assert_eq!(read.payload_identity, Some(extreme));
    }

    #[test]
    fn a_new_store_reads_the_default_limits() {
        let store = Store::in_memory(environment()).expect("opens");
        let name = store
            .staging_name("0123456789abcdef0123456789abcdef", Limits::default())
            .expect("records a name");
        assert_eq!(name, "0123456789abcdef0123456789abcdef");
        assert_eq!(store.limits().expect("reads"), Limits::default());
    }

    #[test]
    fn a_recorded_staging_name_is_never_replaced() {
        let store = Store::in_memory(environment()).expect("opens");
        let first = store
            .staging_name("aaaa", Limits::default())
            .expect("records");
        let second = store
            .staging_name("bbbb", Limits::default())
            .expect("reads the first");
        assert_eq!(first, second);
    }

    #[test]
    fn limits_are_configurable_and_persist() {
        let store = Store::in_memory(environment()).expect("opens");
        store
            .staging_name("aaaa", Limits::default())
            .expect("records");
        let changed = Limits {
            max_file_len: 1024,
            max_staged_len: 4096,
            max_concurrent_transfers: 1,
        };
        store.set_limits(changed).expect("writes");
        assert_eq!(store.limits().expect("reads"), changed);
    }

    #[test]
    fn a_reservation_counts_against_the_environment_until_it_is_released() {
        let mut store = Store::in_memory(environment()).expect("opens");
        store
            .staging_name("aaaa", Limits::default())
            .expect("records");
        store.insert_upload(&upload(1, 4096), None).expect("writes");
        store.insert_upload(&upload(2, 2048), None).expect("writes");
        assert_eq!(store.staged_byte_len().expect("reads"), 6144);
        store
            .close_upload(
                transfer(2),
                UploadState::Cancelled,
                None,
                TimestampMs::new(2000),
                None,
            )
            .expect("writes");
        // Closing the row does not release the bytes; removing the payload does.
        assert_eq!(store.staged_byte_len().expect("reads"), 6144);
        store.release_payload(transfer(2)).expect("writes");
        assert_eq!(store.staged_byte_len().expect("reads"), 4096);
    }

    #[test]
    fn a_published_attachment_still_occupies_the_budget() {
        let mut store = Store::in_memory(environment()).expect("opens");
        store
            .staging_name("aaaa", Limits::default())
            .expect("records");
        store.insert_upload(&upload(1, 4096), None).expect("writes");
        store
            .begin_publish(
                transfer(1),
                &Publication {
                    content_digest: Digest256::from_bytes([1; 32]),
                    payload_identity: ObjectIdentity {
                        device: 1,
                        file_id: 2,
                    },
                    preview: None,
                    preview_unavailable: None,
                },
                TimestampMs::new(2000),
                None,
            )
            .expect("writes");
        store
            .complete_publish(transfer(1), TimestampMs::new(2000), TimestampMs::new(9000))
            .expect("writes");
        assert_eq!(store.staged_byte_len().expect("reads"), 4096);
        let row = store.upload(transfer(1)).expect("reads").expect("exists");
        assert_eq!(row.state, UploadState::Published);
        assert_eq!(row.expires_at_ms, TimestampMs::new(9000));
    }

    #[test]
    fn open_transfers_are_counted_for_the_authenticated_principal() {
        let mut store = Store::in_memory(environment()).expect("opens");
        store
            .staging_name("aaaa", Limits::default())
            .expect("records");
        // The device identifier a request carries is metadata. Changing it per request must not
        // give the same principal another allowance, so the count is per principal.
        let device = DeviceId::new(Uuid::from_bytes([7; 16]));
        let mut first = upload(1, 16);
        first.device_id = Some(device);
        let mut second = upload(2, 16);
        second.device_id = Some(DeviceId::new(Uuid::from_bytes([8; 16])));
        let mut third = upload(3, 16);
        third.device_id = None;
        store.insert_upload(&first, None).expect("writes");
        store.insert_upload(&second, None).expect("writes");
        store.insert_upload(&third, None).expect("writes");
        assert_eq!(store.open_transfers(&actor()).expect("reads"), 3);
        let other = ActorId::new("local:502").expect("a valid principal");
        assert_eq!(store.open_transfers(&other).expect("reads"), 0);
    }

    #[test]
    fn a_chunk_journal_reads_back_in_index_order() {
        let mut store = Store::in_memory(environment()).expect("opens");
        store
            .staging_name("aaaa", Limits::default())
            .expect("records");
        store.insert_upload(&upload(1, 3), None).expect("writes");
        for index in [2_u64, 0, 1] {
            store
                .record_chunk(
                    transfer(1),
                    ChunkDescriptor {
                        index: U64::new(index),
                        byte_len: U64::new(1),
                        digest: Digest256::from_bytes([index as u8; 32]),
                    },
                    TimestampMs::new(1000 + index),
                    None,
                )
                .expect("writes");
        }
        let chunks = store.chunks(transfer(1)).expect("reads");
        assert_eq!(chunks.len(), 3);
        assert_eq!(
            chunks
                .iter()
                .map(|chunk| chunk.index.get())
                .collect::<Vec<_>>(),
            vec![0, 1, 2]
        );
        assert_eq!(
            store
                .chunk(transfer(1), 1)
                .expect("reads")
                .expect("exists")
                .digest,
            Digest256::from_bytes([1; 32])
        );
        assert!(store.chunk(transfer(1), 9).expect("reads").is_none());
    }

    #[test]
    fn every_state_change_writes_an_outbox_row_in_the_same_transaction() {
        let mut store = Store::in_memory(environment()).expect("opens");
        store
            .staging_name("aaaa", Limits::default())
            .expect("records");
        store.insert_upload(&upload(1, 16), None).expect("writes");
        store
            .close_upload(
                transfer(1),
                UploadState::Invalidated,
                Some("a conflicting duplicate"),
                TimestampMs::new(2000),
                None,
            )
            .expect("writes");
        let events = store.events_after(0, 100).expect("reads");
        assert_eq!(
            events
                .iter()
                .map(|event| event.kind.as_str())
                .collect::<Vec<_>>(),
            vec!["upload.begun", "upload.invalidated"]
        );
        assert!(
            events
                .iter()
                .all(|event| event.subject == transfer(1).to_string())
        );
        store
            .set_cursor("attention", events[0].sequence)
            .expect("writes");
        assert_eq!(
            store.cursor("attention").expect("reads"),
            events[0].sequence
        );
        assert_eq!(
            store
                .events_after(events[0].sequence, 100)
                .expect("reads")
                .len(),
            1
        );
    }

    #[test]
    fn an_invalidated_upload_records_why() {
        let mut store = Store::in_memory(environment()).expect("opens");
        store
            .staging_name("aaaa", Limits::default())
            .expect("records");
        store.insert_upload(&upload(1, 16), None).expect("writes");
        store
            .close_upload(
                transfer(1),
                UploadState::Invalidated,
                Some("chunk 3 arrived twice with different digests"),
                TimestampMs::new(2000),
                None,
            )
            .expect("writes");
        let row = store.upload(transfer(1)).expect("reads").expect("exists");
        assert_eq!(row.state, UploadState::Invalidated);
        assert_eq!(
            row.invalid_reason.as_deref(),
            Some("chunk 3 arrived twice with different digests")
        );
        // The bytes stay charged until the payload is gone, which is what stops a failed removal
        // from leaving a file nothing accounts for.
        assert!(row.cleanup_pending);
        assert_eq!(row.reserved_byte_len, 16);
        assert_eq!(
            store
                .uploads_needing_cleanup()
                .expect("reads")
                .iter()
                .map(|row| row.transfer_id)
                .collect::<Vec<_>>(),
            vec![transfer(1)]
        );
        store.release_payload(transfer(1)).expect("writes");
        let row = store.upload(transfer(1)).expect("reads").expect("exists");
        assert!(!row.cleanup_pending);
        assert_eq!(row.reserved_byte_len, 0);
        assert!(store.uploads_needing_cleanup().expect("reads").is_empty());
    }

    #[test]
    fn a_draft_advances_only_at_its_exact_revision() {
        let mut store = Store::in_memory(environment()).expect("opens");
        let draft_id = DraftId::new(Uuid::from_bytes([3; 16]));
        store
            .insert_draft(
                &DraftRow {
                    draft_id,
                    environment_id: environment(),
                    actor_id: actor(),
                    device_id: None,
                    session_id: None,
                    application_instance_id: None,
                    revision: DraftRevision::new(1),
                    state: DraftState::Open,
                    text: "first".to_owned(),
                    created_at_ms: TimestampMs::new(1000),
                    updated_at_ms: TimestampMs::new(1000),
                },
                None,
            )
            .expect("writes");
        assert_eq!(
            store
                .update_draft(
                    draft_id,
                    DraftRevision::new(9),
                    "second",
                    TimestampMs::new(2000),
                    None,
                )
                .expect("reads"),
            None
        );
        assert_eq!(
            store
                .update_draft(
                    draft_id,
                    DraftRevision::new(1),
                    "second",
                    TimestampMs::new(2000),
                    None,
                )
                .expect("writes"),
            Some(DraftRevision::new(2))
        );
        let row = store.draft(draft_id).expect("reads").expect("exists");
        assert_eq!(row.text, "second");
        assert_eq!(row.revision, DraftRevision::new(2));
    }

    #[test]
    fn a_retained_action_is_returned_to_the_same_actor_and_forgotten_on_schedule() {
        let store = Store::in_memory(environment()).expect("opens");
        let action_id = Uuid::from_bytes([4; 16]);
        let record = ActionRecord {
            method: "upload.finish".to_owned(),
            payload_digest: Digest256::from_bytes([5; 32]),
            result: Some(vec![1, 2, 3]),
            error_code: None,
            error_detail: None,
            recorded_at_ms: TimestampMs::new(1000),
        };
        store
            .record_action(&actor(), action_id, &record)
            .expect("writes");
        assert_eq!(
            store
                .retained_action(&actor(), action_id)
                .expect("reads")
                .expect("exists"),
            record
        );
        let other = ActorId::new("local:502").expect("a valid principal");
        assert!(
            store
                .retained_action(&other, action_id)
                .expect("reads")
                .is_none()
        );
        assert_eq!(
            store
                .forget_actions_before(TimestampMs::new(2000))
                .expect("writes"),
            1
        );
        assert!(
            store
                .retained_action(&actor(), action_id)
                .expect("reads")
                .is_none()
        );
    }

    #[test]
    fn a_failure_names_the_claim_it_fails() {
        let store = Store::in_memory(environment()).expect("opens");
        let action_id = Uuid::from_bytes([9; 16]);
        let claimed = Digest256::from_bytes([1; 32]);
        store
            .record_action(
                &actor(),
                action_id,
                &ActionRecord {
                    method: "upload.finish".to_owned(),
                    payload_digest: claimed,
                    result: None,
                    error_code: None,
                    error_detail: None,
                    recorded_at_ms: TimestampMs::new(1000),
                },
            )
            .expect("writes the claim");

        // Another request's refusal, under the same identifier and method but a different payload.
        // That claim is not this refusal's to answer, any more than its result would be.
        assert!(
            !store
                .fail_action(
                    &actor(),
                    action_id,
                    "upload.finish",
                    Digest256::from_bytes([2; 32]),
                    "ATTACHMENT_INTEGRITY",
                    "another request's refusal",
                )
                .expect("writes"),
        );
        assert!(
            !store
                .fail_action(
                    &actor(),
                    action_id,
                    "upload.cancel",
                    claimed,
                    "ATTACHMENT_INTEGRITY",
                    "another method's refusal",
                )
                .expect("writes"),
        );
        let other = ActorId::new("local:502").expect("a valid principal");
        assert!(
            !store
                .fail_action(
                    &other,
                    action_id,
                    "upload.finish",
                    claimed,
                    "ATTACHMENT_INTEGRITY",
                    "another actor's refusal",
                )
                .expect("writes"),
        );
        assert_eq!(
            store
                .retained_action(&actor(), action_id)
                .expect("reads")
                .expect("exists")
                .error_code,
            None,
            "the claim is still open"
        );

        // Its own refusal fills it, and nothing replaces what is recorded afterwards.
        assert!(
            store
                .fail_action(
                    &actor(),
                    action_id,
                    "upload.finish",
                    claimed,
                    "ATTACHMENT_INTEGRITY",
                    "these are not the bytes that were verified",
                )
                .expect("writes"),
        );
        let record = store
            .retained_action(&actor(), action_id)
            .expect("reads")
            .expect("exists");
        assert_eq!(record.error_code.as_deref(), Some("ATTACHMENT_INTEGRITY"));
        assert_eq!(
            record.error_detail.as_deref(),
            Some("these are not the bytes that were verified")
        );
        assert!(
            !store
                .fail_action(
                    &actor(),
                    action_id,
                    "upload.finish",
                    claimed,
                    "RESOURCE_UNAVAILABLE",
                    "a later refusal",
                )
                .expect("writes"),
        );
        assert!(
            !store
                .complete_action(&actor(), action_id, "upload.finish", claimed, &[7])
                .expect("writes"),
        );
    }

    #[test]
    fn a_scope_records_the_identity_its_grant_was_made_for() {
        let store = Store::in_memory(environment()).expect("opens");
        let scope_id = GrantId::new(Uuid::from_bytes([6; 16]));
        let row = ScopeRow {
            scope_id,
            environment_id: environment(),
            root_path: "/work/project".to_owned(),
            root: RecordedIdentity::from_parts(17, 4242, Some(FilesystemId::from_u64(99))),
            purpose: "diff review".to_owned(),
            revoked: false,
        };
        store.register_scope(&row).expect("writes");
        assert_eq!(store.scope(scope_id).expect("reads").expect("exists"), row);
        store.revoke_scope(scope_id).expect("writes");
        assert!(
            store
                .scope(scope_id)
                .expect("reads")
                .expect("exists")
                .revoked
        );
    }

    #[test]
    fn a_snapshot_records_its_chunk_layout_with_it() {
        let mut store = Store::in_memory(environment()).expect("opens");
        store
            .staging_name("aaaa", Limits::default())
            .expect("records");
        let chunks = vec![ChunkDescriptor {
            index: U64::new(0),
            byte_len: U64::new(8),
            digest: Digest256::from_bytes([8; 32]),
        }];
        let row = SnapshotRow {
            transfer_id: transfer(5),
            environment_id: environment(),
            actor_id: actor(),
            device_id: None,
            scope_id: Some(GrantId::new(Uuid::from_bytes([6; 16]))),
            source_transfer_id: None,
            immutability: DownloadImmutability::StagedSnapshot,
            source_label: "notes.txt".to_owned(),
            stored_name: Some("0505.txt".to_owned()),
            byte_len: 8,
            content_digest: Digest256::from_bytes([9; 32]),
            reserved_byte_len: 8,
            state: SnapshotState::Open,
            cleanup_pending: false,
            failure_reason: None,
            source_identity: Some(ObjectIdentity {
                device: 3,
                file_id: 9,
            }),
            source_modified_ms: Some(1234),
            created_at_ms: TimestampMs::new(1000),
            expires_at_ms: TimestampMs::new(2000),
        };
        store.insert_snapshot(&row, &chunks).expect("writes");
        assert_eq!(
            store.snapshot(transfer(5)).expect("reads").expect("exists"),
            row
        );
        assert_eq!(store.snapshot_chunks(transfer(5)).expect("reads"), chunks);
        assert_eq!(store.staged_byte_len().expect("reads"), 8);
        assert!(
            store
                .close_snapshot(
                    transfer(5),
                    SnapshotState::Failed,
                    Some("the source changed while it was staged"),
                    TimestampMs::new(3000),
                )
                .expect("writes")
        );
        // Closing keeps the charge; removing the payload releases it, exactly as an upload does.
        assert_eq!(store.staged_byte_len().expect("reads"), 8);
        assert_eq!(
            store
                .snapshots_needing_cleanup()
                .expect("reads")
                .iter()
                .map(|row| row.transfer_id)
                .collect::<Vec<_>>(),
            vec![transfer(5)]
        );
        store.release_snapshot_payload(transfer(5)).expect("writes");
        assert_eq!(store.staged_byte_len().expect("reads"), 0);
        assert!(store.snapshots_needing_cleanup().expect("reads").is_empty());
        // A second close finds nothing to change.
        assert!(
            !store
                .close_snapshot(
                    transfer(5),
                    SnapshotState::Released,
                    None,
                    TimestampMs::new(4000),
                )
                .expect("writes")
        );
        assert_eq!(
            store
                .snapshot(transfer(5))
                .expect("reads")
                .expect("exists")
                .state,
            SnapshotState::Failed
        );
    }

    #[test]
    fn a_store_from_a_later_schema_is_refused_rather_than_read() {
        let directory = tempfile::tempdir().expect("a temporary directory");
        let path = directory.path().join("transfers.sqlite");
        {
            let store = Store::open(&path, environment()).expect("opens");
            store
                .connection
                .execute("UPDATE schema_version SET version = ?1", params![99])
                .expect("writes");
        }
        assert!(Store::open(&path, environment()).is_err());
    }
}
