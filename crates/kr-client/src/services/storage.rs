//! Managed storage's client: backup ciphertext into an account's storage and back out of it, over
//! the signed call.
//!
//! Section 17: managed uploads are bounded parts the service mediates. The declared maximum is
//! reserved against the allowance, and one object key, one upload identity and an immutable part
//! table are allocated, before any content is accepted. Every part is 8 MiB but the last, the
//! service reads at most its declared length and refuses a wrong length or hash before it writes,
//! and completion is the service's: it checks every part and the total, settles the reservation as
//! stored bytes, and answers a completion asked for again with the result it already gave. No
//! storage address ever reaches this client, so every byte goes through the service in both
//! directions. [`ManagedStorageService`] is how a device or a host reaches it: the
//! [`StorageService`] this crate carries, over [`SignedService`].
//!
//! It seals nothing and opens nothing. What it uploads is ciphertext a producer made, which the
//! service holds under a key nobody outside it knows, and what it reads back is the same bytes.
//!
//! # Two proofs on every request
//!
//! Backup storage belongs to an account, not to the key that asks for it: an installation's free
//! entitlement holds none. So every request here carries two proofs, the signature of the key that
//! asks and the account token for `backup.write` beside it, and the body names the installation
//! that key derives, which is what binds the two proofs to one caller. A client given no account
//! sends nothing at all, because without one there is no storage for a request to reach.
//!
//! # The part table is the service's, and a resume follows it
//!
//! The service answers a created upload with its part table: the total, the part size, the count
//! and the length of the last part. This client holds the table to its own arithmetic, one total
//! and one part size give one table, and refuses one that disagrees, because every part it sends
//! afterwards is cut by that table. [`UploadProgress`] is where one upload has got to, which a
//! caller keeps, and [`upload_parts`] sends the parts after it in order, telling the caller of each
//! acknowledgement before the next part leaves. So a transfer that stopped goes on at the part
//! after the last one acknowledged, and no acknowledged part is sent again.
//!
//! # Refusals that are answers
//!
//! Two refusals say something about the work rather than about the request, and a caller acts on
//! them: [`ArchiveAnswer::CollectionDeleted`], a backup collection its owner deleted from the
//! account console, which takes nothing more, so backing up again means enrolling a new
//! collection; and [`ArchiveAnswer::UploadGone`], an upload that takes nothing more, because it
//! expired, was closed, or is not one the service holds for this caller, so the object is uploaded
//! again under a new one. Every other refusal is the error the service named, with what a person
//! does about it.
//!
//! # What is never rendered
//!
//! A part carries ciphertext and a read answers with it, so the types that hold either write their
//! own [`std::fmt::Debug`]: the part's number and length, or the range's length, and never a byte.

use std::fmt;
use std::ops::Range;
use std::sync::Arc;

use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::ids::{ArchiveId, BackupGeneration, BackupObjectId, InstallationId};
use kr_protocol::method::Method;
use kr_protocol::scalars::{Digest256, Nullable, U64, Uuid};
use kr_protocol::service::GatewayOrigin;
use serde::{Deserialize, Serialize};

use super::account::{AccountTokenSource, BACKUP_WRITE_SCOPE};
use super::relay::{ServiceHttp, ServiceSigner};
use super::signed::{
    AccountAuthorisation, Answer, Carriage, Content, SignedService, Unanswered, malformed,
    unreadable_answer,
};
use super::{ServiceFuture, StorageService};
use crate::error::{ClientError, Result};

/// The route every managed storage method is served under.
pub const STORAGE_ROUTE_PREFIX: &str = "/api/storage";

/// Where the storage a principal holds is reported.
pub const STORAGE_STATUS_PATH: &str = "/api/storage/status";

/// Where backup storage is turned on or off.
pub const STORAGE_RETENTION_PATH: &str = "/api/storage/retention";

/// Where an upload is created.
pub const STORAGE_UPLOAD_CREATE_PATH: &str = "/api/storage/upload/create";

/// Where one part is sent.
pub const STORAGE_UPLOAD_PART_PATH: &str = "/api/storage/upload/part";

/// Where an upload is completed.
pub const STORAGE_UPLOAD_COMPLETE_PATH: &str = "/api/storage/upload/complete";

/// Where an upload is abandoned.
pub const STORAGE_UPLOAD_ABORT_PATH: &str = "/api/storage/upload/abort";

/// Where a range of a stored object is read.
pub const STORAGE_READ_PATH: &str = "/api/storage/object/read";

/// Where a stored object is deleted.
pub const STORAGE_DELETE_PATH: &str = "/api/storage/object/delete";

/// The header a part carries its signed request in, lower-cased.
pub const STORAGE_REQUEST_HEADER: &str = "kr-service-request";

/// The most bytes one signed storage request may be.
///
/// Every request but a part is a small document of identifiers and counters, and a part's signed
/// request describes its content rather than holding it.
pub const MAX_STORAGE_REQUEST_BYTES: usize = 8 * 1024;

/// The bytes one part is, except the last part of an object, which is shorter.
pub const STORAGE_PART_SIZE_BYTES: u64 = 8 * 1024 * 1024;

/// The most bytes one stored object may be.
pub const MAX_STORAGE_OBJECT_BYTES: u64 = 1024 * 1024 * 1024;

/// The most bytes one read may ask for.
pub const MAX_STORAGE_READ_BYTES: u64 = 8 * 1024 * 1024;

/// How many bytes of a read's answer this client reads: the most a read may ask for, and room for
/// the refusal a read can be answered with instead.
pub const STORAGE_READ_ANSWER_LIMIT_BYTES: u64 = MAX_STORAGE_READ_BYTES + 64 * 1024;

/// The most daily snapshots the service keeps for an archive, which is also its default.
pub const MAX_DAILY_SNAPSHOTS: u32 = 30;

/// The longest upload identity this client carries.
const MAX_UPLOAD_ID_BYTES: usize = 256;

/* -------------------------------------------------------------------------- */
/* What a caller hands over                                                    */
/* -------------------------------------------------------------------------- */

/// Whether managed backup storage is on for a principal.
///
/// It is off until the person turns it on: section 20 keeps cloud history backup off until it is
/// enabled, so a plan that includes storage is capacity available rather than storage in use.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackupState {
    /// Uploads are taken.
    On,
    /// No upload is taken, and nothing already stored is deleted.
    Off,
}

/// A change of whether backup storage is on, decided against the revision it was read at.
///
/// A change is a compare and swap, so a request replayed after a later change landed is refused
/// rather than undoing it: an old "on" cannot reverse a newer "off".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetentionChange {
    /// Whether backup storage is to be on.
    pub backup: BackupState,
    /// The daily snapshots to keep, from one to [`MAX_DAILY_SNAPSHOTS`], or none to leave the
    /// figure as it is.
    pub daily_snapshots: Option<u32>,
    /// The revision this change was decided against, which a status read or the answer to the last
    /// change names, and nought for a principal that has never changed it.
    pub expected_revision: u64,
}

/// One object's upload, as its caller declares it before any content is accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NewUpload {
    /// The archive the object belongs to.
    pub archive_id: ArchiveId,
    /// The object, as the archive's manifest names it.
    pub object_id: BackupObjectId,
    /// The generation it is uploaded for.
    pub backup_generation: BackupGeneration,
    /// The most bytes the object will be, which is what the service reserves.
    pub declared_max_bytes: u64,
    /// The bytes the object is, exactly, which fixes its part table.
    pub total_bytes: u64,
    /// The SHA-256 of the whole encrypted object, which a restoring device checks the assembled
    /// ciphertext against.
    pub encrypted_object_hash: Digest256,
}

/// The identity the service gave one upload, in the answer that created it and nowhere else.
///
/// Opaque: this client carries it back and never reads anything out of it.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct UploadId(String);

impl UploadId {
    /// Wraps an identity the service named.
    ///
    /// # Errors
    ///
    /// Returns an error when it is empty, longer than this client carries, or holds anything but
    /// printable ASCII with no space.
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_UPLOAD_ID_BYTES
            || !value.bytes().all(|byte| byte.is_ascii_graphic())
        {
            return Err(malformed(crate::shown!(
                "an upload identity is 1 to {} printable characters with no space",
                MAX_UPLOAD_ID_BYTES
            )));
        }
        Ok(Self(value))
    }

    /// The identity as the service named it.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for UploadId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for UploadId {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(|_| {
            serde::de::Error::custom("an upload identity is printable text of bounded length")
        })
    }
}

/// One object's part table: its total, and the parts that total cuts into.
///
/// Arithmetic rather than a list. Every part is [`STORAGE_PART_SIZE_BYTES`] but the last, which is
/// shorter and not empty, so one total gives exactly one table, and this is how a caller finds the
/// bytes of any part.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PartTable {
    total_bytes: u64,
    part_count: u32,
}

impl PartTable {
    /// The table an object of `total_bytes` has, or none when no table could produce that total.
    #[must_use]
    pub fn for_total(total_bytes: u64) -> Option<Self> {
        if total_bytes == 0 || total_bytes > MAX_STORAGE_OBJECT_BYTES {
            return None;
        }
        let part_count = u32::try_from(total_bytes.div_ceil(STORAGE_PART_SIZE_BYTES)).ok()?;
        Some(Self {
            total_bytes,
            part_count,
        })
    }

    /// The bytes the object is.
    #[must_use]
    pub const fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    /// How many parts it has.
    #[must_use]
    pub const fn part_count(&self) -> u32 {
        self.part_count
    }

    /// The bytes of the last part.
    #[must_use]
    pub const fn final_part_bytes(&self) -> u64 {
        self.total_bytes - (self.part_count as u64 - 1) * STORAGE_PART_SIZE_BYTES
    }

    /// Where part `number` lies in the object, or none when there is no such part.
    #[must_use]
    pub fn part(&self, number: u32) -> Option<Range<u64>> {
        if number == 0 || number > self.part_count {
            return None;
        }
        let start = u64::from(number - 1) * STORAGE_PART_SIZE_BYTES;
        let end = (start + STORAGE_PART_SIZE_BYTES).min(self.total_bytes);
        Some(start..end)
    }
}

/// One part, as its caller hands it over: its number and its ciphertext.
#[derive(Clone, Copy)]
pub struct UploadPart<'a> {
    /// Which part it is, from one.
    pub number: u32,
    /// Its ciphertext: the object's bytes that part covers.
    pub bytes: &'a [u8],
}

impl fmt::Debug for UploadPart<'_> {
    /// Its number and its length. Never its ciphertext.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UploadPart")
            .field("number", &self.number)
            .field("length", &self.bytes.len())
            .finish()
    }
}

/// Where one object's upload has got to, as far as the service has acknowledged it.
///
/// It is what a caller keeps across a transfer that stops, so the transfer goes on at the next
/// part: the service names an upload only in the answer that created it, and the parts it holds
/// only in the answer to each.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UploadProgress {
    /// The upload.
    pub upload_id: UploadId,
    /// Its part table, which the service fixed when it created it.
    pub table: PartTable,
    /// How many of its parts the service has acknowledged: parts one to this, sent in order.
    pub parts_acknowledged: u32,
}

impl UploadProgress {
    /// Whether the service has acknowledged every part, so what is left is the completion.
    #[must_use]
    pub const fn every_part_acknowledged(&self) -> bool {
        self.parts_acknowledged >= self.table.part_count
    }
}

/* -------------------------------------------------------------------------- */
/* What the service answers                                                    */
/* -------------------------------------------------------------------------- */

/// What a write into an archive was answered, where the answer is about the work rather than about
/// the request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ArchiveAnswer<T> {
    /// The service did what was asked, or had already done it.
    Done(T),
    /// The archive's collection was deleted from the account console.
    ///
    /// It takes no upload and no publication again, whoever sends them. Backing up again means
    /// enrolling a new collection under a new archive, which is a change of configuration and
    /// never an update of this client. An upload creation, a completion and a publication can meet
    /// it.
    CollectionDeleted,
    /// The upload takes nothing more.
    ///
    /// It expired, it was closed, the service holds no such upload, or it belongs to another pair
    /// of proofs than this client's. What it held is the service's to clean up, and the object is
    /// uploaded again under a new one. A part, a completion and an abandonment can meet it.
    UploadGone,
}

impl<T> ArchiveAnswer<T> {
    /// The answer, or the error a caller that cannot act on the other two reports.
    ///
    /// # Errors
    ///
    /// Returns a refusal that says what the answer was, with what a person does about it.
    pub fn done(self) -> Result<T> {
        match self {
            Self::Done(answer) => Ok(answer),
            Self::CollectionDeleted => Err(collection_deleted()),
            Self::UploadGone => Err(ClientError::Host(ProtocolError::new(
                ErrorCode::StaleSession,
                "that upload takes nothing more; upload the object again".to_owned(),
            ))),
        }
    }
}

/// What a caller is told about a collection deleted from the account console.
///
/// The words a host shows: the collection was deleted, and backing up again means enrolling a new
/// one.
#[must_use]
pub fn collection_deleted() -> ClientError {
    ClientError::Refused {
        error: ProtocolError::new(
            ErrorCode::PermissionDenied,
            "that backup collection was deleted from the account console; to back up again, \
             enrol a new collection"
                .to_owned(),
        ),
        retry_after_seconds: None,
        action: crate::retry::UserAction::FixConfiguration,
    }
}

/// Who the bytes are charged to, as the service named it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StoragePrincipal {
    /// An account, under the identifier the service gives it.
    Account(String),
    /// An installation, which holds no backup storage of its own.
    Installation(InstallationId),
}

impl<'de> Deserialize<'de> for StoragePrincipal {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let named = String::deserialize(deserializer)?;
        let refused = || serde::de::Error::custom("a principal is an account or an installation");
        match named.split_once(':') {
            Some(("account", account)) if !account.is_empty() => {
                Ok(Self::Account(account.to_owned()))
            }
            Some(("installation", installation)) => installation
                .parse::<Uuid>()
                .map(|identity| Self::Installation(InstallationId::new(identity)))
                .map_err(|_| refused()),
            _ => Err(refused()),
        }
    }
}

/// The retention the service publishes and applies.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
pub struct RetentionPolicy {
    /// Daily snapshots kept for an archive.
    pub daily_snapshots: u32,
    /// Days a deleted object is a tombstone before its ciphertext is removed.
    pub tombstone_days: u32,
    /// The published upper bound on the provider's own recovery window after a deletion.
    pub provider_recovery_days: u32,
}

/// How many objects one class holds, and how many bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StorageUsage {
    /// How many objects.
    pub objects: u64,
    /// How many bytes of ciphertext.
    pub bytes: u64,
}

/// What managed storage a principal holds, as a status read answers it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StorageStatus {
    /// Who the storage is charged to.
    pub principal: StoragePrincipal,
    /// Whether backup storage is on.
    pub backup: BackupState,
    /// The revision the next retention change names.
    pub retention_revision: u64,
    /// The retention the service applies.
    pub retention: RetentionPolicy,
    /// Objects readable now.
    pub stored: StorageUsage,
    /// Objects deleted and not yet removed, which are still charged.
    pub tombstoned: StorageUsage,
    /// When the next tombstoned object is removed, as the service wrote it, if one is waiting.
    pub next_purge: Option<String>,
    /// Uploads open now.
    pub uploading: StorageUsage,
    /// The bytes open uploads hold reserved.
    pub reserved_bytes: u64,
    /// The storage allowance the ledger states for the principal, when the service could read it.
    pub allowance_bytes: Option<u64>,
    /// The figures the deployment pins.
    pub limits: StorageLimits,
}

/// The figures a deployment pins, as a status read reports them.
///
/// Reported rather than adopted. The part size is the protocol's and a created upload's part table
/// is held to it; the rest bound what the service takes, and a request past one is the service's to
/// refuse.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StorageLimits {
    /// The bytes of every part but the last.
    pub part_size_bytes: u64,
    /// The most bytes one object may be.
    pub max_object_bytes: u64,
    /// The most parts one upload may hold.
    pub max_parts: u32,
    /// The most bytes one read may ask for.
    pub max_read_bytes: u64,
    /// How long one upload stays open, in seconds.
    pub upload_lifetime_seconds: u64,
    /// How many uploads one principal may hold open at once.
    pub outstanding_uploads: u32,
}

/// What a retention change answered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetentionSet {
    /// Whether the change was made, or asked for what was already so.
    pub changed: bool,
    /// Whether backup storage is on now.
    pub backup: BackupState,
    /// The retention the service applies now.
    pub retention: RetentionPolicy,
    /// The revision the record is at now, which the next change names.
    pub revision: u64,
}

/// What creating an upload answered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UploadCreated {
    /// The upload, as the service named it.
    pub upload_id: UploadId,
    /// Its part table, which every part is checked against.
    pub table: PartTable,
    /// The bytes the service reserved for it.
    pub reserved_bytes: u64,
    /// When the upload stops taking parts, as the service wrote it.
    pub expires_at: String,
    /// Who it is charged to.
    pub principal: StoragePrincipal,
}

impl UploadCreated {
    /// The progress of an upload that has just been created: nothing acknowledged yet.
    #[must_use]
    pub fn progress(&self) -> UploadProgress {
        UploadProgress {
            upload_id: self.upload_id.clone(),
            table: self.table,
            parts_acknowledged: 0,
        }
    }
}

/// What one part answered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PartStored {
    /// Whether this part was written now, or had already been.
    pub duplicate: bool,
    /// How many parts of the upload the service holds.
    pub parts_stored: u32,
    /// How many bytes of it the service holds.
    pub bytes_stored: u64,
}

/// One stored object, as the archive's manifest names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StoredObject {
    /// The object.
    pub object_id: BackupObjectId,
    /// The SHA-256 of its ciphertext, as its uploader declared it.
    pub encrypted_object_hash: Digest256,
    /// The bytes of ciphertext stored.
    pub encrypted_len: u64,
}

/// What completing an upload answered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UploadCompleted {
    /// Whether this completion stored the object now, or had already been answered.
    pub duplicate: bool,
    /// The archive the object belongs to.
    pub archive_id: ArchiveId,
    /// The generation it was uploaded for.
    pub backup_generation: BackupGeneration,
    /// The object, as the archive's manifest names it.
    pub object: StoredObject,
    /// The bytes the reservation settled at, which is the stored ciphertext.
    pub committed_bytes: u64,
    /// When the service stored it, as it wrote it.
    pub stored_at: String,
}

/// What abandoning an upload answered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UploadAborted {
    /// Whether the service has confirmed the removal and given the hold back, or will come back to
    /// work dispatched before the upload was fenced.
    pub cleaned: bool,
    /// The bytes given back, or none while the removal is unconfirmed.
    pub released_bytes: Option<u64>,
}

/// A range of one stored object's ciphertext.
#[derive(Clone, PartialEq, Eq)]
pub struct ObjectRange {
    /// Where the range starts in the object.
    pub offset: u64,
    /// The ciphertext, as the service served it.
    pub bytes: Vec<u8>,
}

impl fmt::Debug for ObjectRange {
    /// Where it starts and how long it is. Never the ciphertext.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ObjectRange")
            .field("offset", &self.offset)
            .field("length", &self.bytes.len())
            .finish()
    }
}

/// What deleting an object answered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectDeleted {
    /// Whether this deletion made the tombstone, or found the one it had made.
    pub already: bool,
    /// When it was deleted, as the service wrote it.
    pub deleted_at: String,
    /// When its ciphertext is removed, after which the bytes stop being charged.
    pub purge_after: String,
    /// The bytes still charged until then.
    pub retained_bytes: u64,
    /// The retention the service applies.
    pub retention: RetentionPolicy,
}

/* -------------------------------------------------------------------------- */
/* On the wire                                                                 */
/* -------------------------------------------------------------------------- */

/// Ask what managed storage this principal holds.
#[derive(Serialize)]
struct StatusBody {
    installation_id: InstallationId,
}

/// Turn backup storage on or off.
#[derive(Serialize)]
struct RetentionBody {
    installation_id: InstallationId,
    backup: BackupState,
    #[serde(skip_serializing_if = "Option::is_none")]
    daily_snapshots: Option<u32>,
    expected_revision: U64,
}

/// Create one upload.
#[derive(Serialize)]
struct CreateBody {
    installation_id: InstallationId,
    archive_id: ArchiveId,
    object_id: BackupObjectId,
    backup_generation: BackupGeneration,
    declared_max_bytes: U64,
    total_bytes: U64,
    encrypted_object_hash: Digest256,
}

/// What a part's signed request describes: its upload, its number, its length and its hash.
#[derive(Serialize)]
struct PartBody<'a> {
    installation_id: InstallationId,
    upload_id: &'a UploadId,
    part_number: u32,
    length_bytes: U64,
    sha256: Digest256,
}

/// Complete one upload.
#[derive(Serialize)]
struct CompleteBody<'a> {
    installation_id: InstallationId,
    upload_id: &'a UploadId,
    total_bytes: U64,
    part_count: u32,
}

/// Abandon one upload.
#[derive(Serialize)]
struct AbortBody<'a> {
    installation_id: InstallationId,
    upload_id: &'a UploadId,
}

/// Read one range of a stored object.
#[derive(Serialize)]
struct ReadBody {
    installation_id: InstallationId,
    archive_id: ArchiveId,
    object_id: BackupObjectId,
    offset: U64,
    length: U64,
}

/// Delete one stored object.
#[derive(Serialize)]
struct DeleteBody {
    installation_id: InstallationId,
    archive_id: ArchiveId,
    object_id: BackupObjectId,
}

/// Objects and bytes of one class, as the service writes them.
#[derive(Deserialize)]
struct UsageAnswer {
    objects: u64,
    bytes: U64,
}

/// Tombstoned objects, and when the next is removed.
#[derive(Deserialize)]
struct TombstonedAnswer {
    objects: u64,
    bytes: U64,
    next_purge: Nullable<String>,
}

/// Uploads open now, and what they hold reserved.
#[derive(Deserialize)]
struct UploadingAnswer {
    objects: u64,
    bytes: U64,
    reserved_bytes: U64,
}

/// The figures a deployment pins, as the service writes them.
#[derive(Deserialize)]
struct LimitsAnswer {
    part_size_bytes: U64,
    max_object_bytes: U64,
    max_parts: u32,
    max_read_bytes: U64,
    upload_lifetime_seconds: u64,
    outstanding_uploads: u32,
}

/// What `storage.status` answers.
#[derive(Deserialize)]
struct StatusAnswer {
    principal: StoragePrincipal,
    backup: BackupState,
    retention_revision: U64,
    retention: RetentionPolicy,
    stored: UsageAnswer,
    tombstoned: TombstonedAnswer,
    uploading: UploadingAnswer,
    allowance_bytes: Nullable<U64>,
    limits: LimitsAnswer,
}

/// Whether a change was made.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum SetState {
    Set,
    Unchanged,
}

/// What `storage.retention.set` answers.
#[derive(Deserialize)]
struct RetentionAnswer {
    state: SetState,
    backup: BackupState,
    retention: RetentionPolicy,
    revision: u64,
}

/// A created upload's state, which is always `created`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum CreatedState {
    Created,
}

/// A part table, as the service writes one.
#[derive(Deserialize)]
struct LayoutAnswer {
    total_bytes: U64,
    part_size_bytes: U64,
    part_count: u32,
    final_part_bytes: U64,
}

/// What `storage.upload.create` answers.
#[derive(Deserialize)]
struct CreateAnswer {
    #[expect(dead_code, reason = "held to its schema and never read")]
    state: CreatedState,
    layout: LayoutAnswer,
    upload_id: UploadId,
    principal: StoragePrincipal,
    reserved_bytes: U64,
    expires_at: String,
}

/// Whether something was stored now or had been.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum StoredState {
    Stored,
    Duplicate,
}

/// What `storage.upload.part` answers.
#[derive(Deserialize)]
struct PartAnswer {
    state: StoredState,
    part_number: u32,
    length_bytes: U64,
    parts_stored: u32,
    bytes_stored: U64,
}

/// The reference the archive's manifest carries for one stored object.
#[derive(Deserialize)]
struct ObjectRefAnswer {
    object_id: BackupObjectId,
    encrypted_object_hash: Digest256,
    encrypted_len: U64,
}

/// What `storage.upload.complete` answers.
#[derive(Deserialize)]
struct CompleteAnswer {
    state: StoredState,
    archive_id: ArchiveId,
    backup_generation: BackupGeneration,
    object: ObjectRefAnswer,
    #[expect(dead_code, reason = "held to its schema and never read")]
    size_bucket_bytes: U64,
    stored_at: String,
    committed_bytes: U64,
    #[expect(dead_code, reason = "held to its schema and never read")]
    principal: StoragePrincipal,
}

/// Whether an abandonment is confirmed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum AbortState {
    Cleaned,
    Cleaning,
}

/// What `storage.upload.abort` answers.
#[derive(Deserialize)]
struct AbortAnswer {
    state: AbortState,
    released_bytes: Nullable<U64>,
}

/// Whether a deletion made its tombstone now.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum DeletedState {
    Tombstoned,
    AlreadyTombstoned,
}

/// What `storage.object.delete` answers.
#[derive(Deserialize)]
struct DeleteAnswer {
    state: DeletedState,
    deleted_at: String,
    purge_after: String,
    retained_bytes: U64,
    retention: RetentionPolicy,
}

/* -------------------------------------------------------------------------- */
/* The client                                                                  */
/* -------------------------------------------------------------------------- */

/// Managed storage's client, over the signed call.
#[derive(Clone, Debug)]
pub struct ManagedStorageService {
    call: SignedService,
    /// The installation the signing key derives, which every body names.
    installation: InstallationId,
    /// The account token every request carries beside its signature, when this client was given
    /// an account.
    account: Option<AccountAuthorisation>,
}

impl ManagedStorageService {
    /// Builds a client against one gateway, signing as the key `signer` holds.
    ///
    /// It sends nothing until it is given an account with [`Self::presenting`], because an
    /// installation alone holds no backup storage.
    #[must_use]
    pub fn new(
        origin: GatewayOrigin,
        http: Arc<dyn ServiceHttp>,
        signer: Arc<dyn ServiceSigner>,
    ) -> Self {
        let installation = kr_protocol::service::installation_id(&signer.public_key());
        Self {
            call: SignedService::new(origin, http, signer),
            installation,
            account: None,
        }
    }

    /// The same client, presenting the account token `tokens` holds for `backup.write` beside the
    /// signature of every request.
    #[must_use]
    pub fn presenting(mut self, tokens: Arc<dyn AccountTokenSource>) -> Self {
        self.account = Some(AccountAuthorisation::new(tokens, BACKUP_WRITE_SCOPE));
        self
    }

    /// The gateway this client addresses.
    #[must_use]
    pub const fn origin(&self) -> &GatewayOrigin {
        self.call.origin()
    }

    /// The installation every request names: the one the signing key derives.
    #[must_use]
    pub const fn installation(&self) -> InstallationId {
        self.installation
    }

    /// The account this client presents, or the refusal of a request it cannot send without one.
    fn account(&self) -> std::result::Result<&AccountAuthorisation, Unanswered> {
        self.account.as_ref().ok_or_else(|| {
            Unanswered::NotSent(ClientError::Host(ProtocolError::new(
                ErrorCode::HostNotConfigured,
                "managed storage is reached with an account token for backup.write, and this \
                 client presents no account"
                    .to_owned(),
            )))
        })
    }

    /// Sends one request whose answer is a document, with the account token beside it.
    async fn ask<B: Serialize>(&self, path: &str, method: Method, body: &B) -> Result<Answer> {
        let account = self.account()?;
        Ok(self
            .call
            .dispatch(
                path,
                method,
                body,
                MAX_STORAGE_REQUEST_BYTES,
                None,
                Some(account),
            )
            .await?)
    }

    async fn status(&self) -> Result<StorageStatus> {
        let body = StatusBody {
            installation_id: self.installation,
        };
        let answer: StatusAnswer = read(
            self.ask(STORAGE_STATUS_PATH, Method::StorageStatus, &body)
                .await?
                .data()?,
            "what a storage status read answered",
        )?;
        Ok(StorageStatus {
            principal: answer.principal,
            backup: answer.backup,
            retention_revision: answer.retention_revision.get(),
            retention: answer.retention,
            stored: StorageUsage {
                objects: answer.stored.objects,
                bytes: answer.stored.bytes.get(),
            },
            tombstoned: StorageUsage {
                objects: answer.tombstoned.objects,
                bytes: answer.tombstoned.bytes.get(),
            },
            next_purge: answer.tombstoned.next_purge.0,
            uploading: StorageUsage {
                objects: answer.uploading.objects,
                bytes: answer.uploading.bytes.get(),
            },
            reserved_bytes: answer.uploading.reserved_bytes.get(),
            allowance_bytes: answer.allowance_bytes.0.map(U64::get),
            limits: StorageLimits {
                part_size_bytes: answer.limits.part_size_bytes.get(),
                max_object_bytes: answer.limits.max_object_bytes.get(),
                max_parts: answer.limits.max_parts,
                max_read_bytes: answer.limits.max_read_bytes.get(),
                upload_lifetime_seconds: answer.limits.upload_lifetime_seconds,
                outstanding_uploads: answer.limits.outstanding_uploads,
            },
        })
    }

    async fn set_retention(&self, change: &RetentionChange) -> Result<RetentionSet> {
        if let Some(snapshots) = change.daily_snapshots
            && !(1..=MAX_DAILY_SNAPSHOTS).contains(&snapshots)
        {
            return Err(malformed(crate::shown!(
                "daily snapshots kept is between one and {}",
                MAX_DAILY_SNAPSHOTS
            )));
        }
        let body = RetentionBody {
            installation_id: self.installation,
            backup: change.backup,
            daily_snapshots: change.daily_snapshots,
            expected_revision: counter("a retention revision", change.expected_revision)?,
        };
        let answer: RetentionAnswer = read(
            self.ask(STORAGE_RETENTION_PATH, Method::StorageRetentionSet, &body)
                .await?
                .data()?,
            "what a retention change answered",
        )?;
        Ok(RetentionSet {
            changed: answer.state == SetState::Set,
            backup: answer.backup,
            retention: answer.retention,
            revision: answer.revision,
        })
    }

    async fn create_upload(&self, upload: &NewUpload) -> Result<ArchiveAnswer<UploadCreated>> {
        let table = PartTable::for_total(upload.total_bytes).ok_or_else(|| {
            malformed(crate::shown!(
                "an object is between one byte and {} bytes",
                MAX_STORAGE_OBJECT_BYTES
            ))
        })?;
        if upload.declared_max_bytes < upload.total_bytes
            || upload.declared_max_bytes > MAX_STORAGE_OBJECT_BYTES
        {
            return Err(malformed(
                "an upload declares at most the largest object and no less than the object it is",
            ));
        }
        if upload.backup_generation.get() == 0 {
            return Err(malformed("a backup generation is a counter from one"));
        }
        let body = CreateBody {
            installation_id: self.installation,
            archive_id: upload.archive_id,
            object_id: upload.object_id,
            backup_generation: upload.backup_generation,
            declared_max_bytes: counter("a declared maximum", upload.declared_max_bytes)?,
            total_bytes: counter("a total", upload.total_bytes)?,
            encrypted_object_hash: upload.encrypted_object_hash,
        };
        let data = match self
            .ask(
                STORAGE_UPLOAD_CREATE_PATH,
                Method::StorageUploadCreate,
                &body,
            )
            .await?
        {
            Answer::Data(data) => data,
            Answer::Refused(refusal) if refusal.code() == "COLLECTION_DELETED" => {
                return Ok(ArchiveAnswer::CollectionDeleted);
            }
            Answer::Refused(refusal) => return Err(refusal.into_error()),
        };
        let answer: CreateAnswer = read(data, "what an upload creation answered")?;
        // The table every part is then checked against, held to this client's own arithmetic for
        // the total it declared: a service that cut the object otherwise would refuse every part
        // this client sends.
        let layout = &answer.layout;
        if layout.total_bytes.get() != table.total_bytes()
            || layout.part_size_bytes.get() != STORAGE_PART_SIZE_BYTES
            || layout.part_count != table.part_count()
            || layout.final_part_bytes.get() != table.final_part_bytes()
        {
            return Err(contrary(
                "a part table other than the one the declared total gives",
            ));
        }
        if answer.reserved_bytes.get() < upload.total_bytes {
            return Err(contrary(
                "an upload that reserved less than the object it is",
            ));
        }
        Ok(ArchiveAnswer::Done(UploadCreated {
            upload_id: answer.upload_id,
            table,
            reserved_bytes: answer.reserved_bytes.get(),
            expires_at: answer.expires_at,
            principal: answer.principal,
        }))
    }

    async fn upload_part(
        &self,
        upload_id: &UploadId,
        part: UploadPart<'_>,
    ) -> Result<ArchiveAnswer<PartStored>> {
        let length = part.bytes.len() as u64;
        if part.number == 0 || length == 0 || length > STORAGE_PART_SIZE_BYTES {
            return Err(malformed(crate::shown!(
                "a part is numbered from one and is between one byte and {} bytes",
                STORAGE_PART_SIZE_BYTES
            )));
        }
        let account = self.account()?;
        let body = PartBody {
            installation_id: self.installation,
            upload_id,
            part_number: part.number,
            length_bytes: U64::new(length),
            sha256: Digest256::from_bytes(kr_cbor::sha256(part.bytes)),
        };
        let answer = self
            .call
            .dispatch_carried(
                STORAGE_UPLOAD_PART_PATH,
                Method::StorageUploadPart,
                &body,
                MAX_STORAGE_REQUEST_BYTES,
                Some(account),
                Carriage::Header {
                    header: STORAGE_REQUEST_HEADER,
                    content: part.bytes,
                },
            )
            .await?;
        let data = match upload_answer(answer)? {
            ArchiveAnswer::Done(data) => data,
            ArchiveAnswer::CollectionDeleted => return Ok(ArchiveAnswer::CollectionDeleted),
            ArchiveAnswer::UploadGone => return Ok(ArchiveAnswer::UploadGone),
        };
        let answer: PartAnswer = read(data, "what a part answered")?;
        if answer.part_number != part.number || answer.length_bytes.get() != length {
            return Err(contrary("a part other than the one that was sent"));
        }
        Ok(ArchiveAnswer::Done(PartStored {
            duplicate: answer.state == StoredState::Duplicate,
            parts_stored: answer.parts_stored,
            bytes_stored: answer.bytes_stored.get(),
        }))
    }

    async fn complete_upload(
        &self,
        upload_id: &UploadId,
        table: &PartTable,
    ) -> Result<ArchiveAnswer<UploadCompleted>> {
        let body = CompleteBody {
            installation_id: self.installation,
            upload_id,
            total_bytes: counter("a total", table.total_bytes())?,
            part_count: table.part_count(),
        };
        let answer = self
            .ask(
                STORAGE_UPLOAD_COMPLETE_PATH,
                Method::StorageUploadComplete,
                &body,
            )
            .await?;
        let data = match upload_answer(answer)? {
            ArchiveAnswer::Done(data) => data,
            ArchiveAnswer::CollectionDeleted => return Ok(ArchiveAnswer::CollectionDeleted),
            ArchiveAnswer::UploadGone => return Ok(ArchiveAnswer::UploadGone),
        };
        let answer: CompleteAnswer = read(data, "what an upload completion answered")?;
        if answer.object.encrypted_len.get() != table.total_bytes()
            || answer.committed_bytes.get() != table.total_bytes()
        {
            return Err(contrary(
                "a completion of another length than the upload declared",
            ));
        }
        Ok(ArchiveAnswer::Done(UploadCompleted {
            duplicate: answer.state == StoredState::Duplicate,
            archive_id: answer.archive_id,
            backup_generation: answer.backup_generation,
            object: StoredObject {
                object_id: answer.object.object_id,
                encrypted_object_hash: answer.object.encrypted_object_hash,
                encrypted_len: answer.object.encrypted_len.get(),
            },
            committed_bytes: answer.committed_bytes.get(),
            stored_at: answer.stored_at,
        }))
    }

    async fn abort_upload(&self, upload_id: &UploadId) -> Result<ArchiveAnswer<UploadAborted>> {
        let body = AbortBody {
            installation_id: self.installation,
            upload_id,
        };
        let answer = self
            .ask(STORAGE_UPLOAD_ABORT_PATH, Method::StorageUploadAbort, &body)
            .await?;
        let data = match upload_answer(answer)? {
            ArchiveAnswer::Done(data) => data,
            ArchiveAnswer::CollectionDeleted => return Ok(ArchiveAnswer::CollectionDeleted),
            ArchiveAnswer::UploadGone => return Ok(ArchiveAnswer::UploadGone),
        };
        let answer: AbortAnswer = read(data, "what an upload abandonment answered")?;
        Ok(ArchiveAnswer::Done(UploadAborted {
            cleaned: answer.state == AbortState::Cleaned,
            released_bytes: answer.released_bytes.0.map(U64::get),
        }))
    }

    async fn read_object(
        &self,
        archive_id: ArchiveId,
        object_id: BackupObjectId,
        offset: u64,
        length: u64,
    ) -> Result<ObjectRange> {
        if length == 0 || length > MAX_STORAGE_READ_BYTES {
            return Err(malformed(crate::shown!(
                "a read asks for between one byte and {}",
                MAX_STORAGE_READ_BYTES
            )));
        }
        let account = self.account()?;
        let body = ReadBody {
            installation_id: self.installation,
            archive_id,
            object_id,
            offset: counter("an offset", offset)?,
            length: U64::new(length),
        };
        let answer = self
            .call
            .dispatch_for_content(
                STORAGE_READ_PATH,
                Method::StorageObjectRead,
                &body,
                MAX_STORAGE_REQUEST_BYTES,
                Some(account),
            )
            .await?;
        match answer {
            // A range is at most what was asked for, and shorter only at the end of the object.
            Content::Bytes(bytes) if bytes.is_empty() || bytes.len() as u64 > length => {
                Err(contrary("a range other than the one that was asked for"))
            }
            Content::Bytes(bytes) => Ok(ObjectRange { offset, bytes }),
            // A tombstoned object reads the same as one that never existed.
            Content::Refused(refusal) if refusal.code() == "NOT_FOUND" => Err(not_held()),
            Content::Refused(refusal) => Err(refusal.into_error()),
        }
    }

    async fn delete_object(
        &self,
        archive_id: ArchiveId,
        object_id: BackupObjectId,
    ) -> Result<ObjectDeleted> {
        let body = DeleteBody {
            installation_id: self.installation,
            archive_id,
            object_id,
        };
        let data = match self
            .ask(STORAGE_DELETE_PATH, Method::StorageObjectDelete, &body)
            .await?
        {
            Answer::Data(data) => data,
            Answer::Refused(refusal) if refusal.code() == "NOT_FOUND" => return Err(not_held()),
            Answer::Refused(refusal) => return Err(refusal.into_error()),
        };
        let answer: DeleteAnswer = read(data, "what an object deletion answered")?;
        Ok(ObjectDeleted {
            already: answer.state == DeletedState::AlreadyTombstoned,
            deleted_at: answer.deleted_at,
            purge_after: answer.purge_after,
            retained_bytes: answer.retained_bytes.get(),
            retention: answer.retention,
        })
    }
}

impl StorageService for ManagedStorageService {
    fn status(&self) -> ServiceFuture<'_, StorageStatus> {
        Box::pin(self.status())
    }

    fn set_retention<'a>(&'a self, change: &'a RetentionChange) -> ServiceFuture<'a, RetentionSet> {
        Box::pin(self.set_retention(change))
    }

    fn create_upload<'a>(
        &'a self,
        upload: &'a NewUpload,
    ) -> ServiceFuture<'a, ArchiveAnswer<UploadCreated>> {
        Box::pin(self.create_upload(upload))
    }

    fn upload_part<'a>(
        &'a self,
        upload_id: &'a UploadId,
        part: UploadPart<'a>,
    ) -> ServiceFuture<'a, ArchiveAnswer<PartStored>> {
        Box::pin(self.upload_part(upload_id, part))
    }

    fn complete_upload<'a>(
        &'a self,
        upload_id: &'a UploadId,
        table: &'a PartTable,
    ) -> ServiceFuture<'a, ArchiveAnswer<UploadCompleted>> {
        Box::pin(self.complete_upload(upload_id, table))
    }

    fn abort_upload<'a>(
        &'a self,
        upload_id: &'a UploadId,
    ) -> ServiceFuture<'a, ArchiveAnswer<UploadAborted>> {
        Box::pin(self.abort_upload(upload_id))
    }

    fn read_object(
        &self,
        archive_id: ArchiveId,
        object_id: BackupObjectId,
        offset: u64,
        length: u64,
    ) -> ServiceFuture<'_, ObjectRange> {
        Box::pin(self.read_object(archive_id, object_id, offset, length))
    }

    fn delete_object(
        &self,
        archive_id: ArchiveId,
        object_id: BackupObjectId,
    ) -> ServiceFuture<'_, ObjectDeleted> {
        Box::pin(self.delete_object(archive_id, object_id))
    }
}

/* -------------------------------------------------------------------------- */
/* An upload, part by part                                                     */
/* -------------------------------------------------------------------------- */

/// Sends the parts of one object the service has not acknowledged, in order, from the part after
/// the last one `progress` records.
///
/// `ciphertext` is the whole object, which the part table cuts. After each part is acknowledged,
/// `progress` moves on and `acknowledged` is told, before the next part leaves: a caller that keeps
/// what it is told goes on from there after a transfer stops, and sends no acknowledged part again.
/// An `acknowledged` that fails stops the upload there, since a caller that could not keep where
/// it got to would send a part again after a restart. A part asked for again that the service
/// already held is answered as one, and counts as acknowledged all the same.
///
/// # Errors
///
/// Returns an error when the ciphertext is not the length the table was cut for, when a part is
/// refused or unanswered, and whatever `acknowledged` returns. [`ArchiveAnswer::UploadGone`] and
/// [`ArchiveAnswer::CollectionDeleted`] come back as answers, with `progress` where it had got to.
pub async fn upload_parts(
    storage: &dyn StorageService,
    progress: &mut UploadProgress,
    ciphertext: &[u8],
    acknowledged: &mut (dyn FnMut(&UploadProgress) -> Result<()> + Send),
) -> Result<ArchiveAnswer<()>> {
    if ciphertext.len() as u64 != progress.table.total_bytes() {
        return Err(malformed(
            "the ciphertext is not the length its upload's part table was cut for",
        ));
    }
    while !progress.every_part_acknowledged() {
        let number = progress.parts_acknowledged + 1;
        let range = progress
            .table
            .part(number)
            .ok_or_else(|| malformed("a part the table does not have"))?;
        let bytes = usize::try_from(range.start)
            .ok()
            .zip(usize::try_from(range.end).ok())
            .and_then(|(start, end)| ciphertext.get(start..end))
            .ok_or_else(|| malformed("a part past the end of the ciphertext"))?;
        match storage
            .upload_part(&progress.upload_id, UploadPart { number, bytes })
            .await?
        {
            ArchiveAnswer::Done(_) => {}
            ArchiveAnswer::CollectionDeleted => return Ok(ArchiveAnswer::CollectionDeleted),
            ArchiveAnswer::UploadGone => return Ok(ArchiveAnswer::UploadGone),
        }
        progress.parts_acknowledged = number;
        acknowledged(progress)?;
    }
    Ok(ArchiveAnswer::Done(()))
}

/* -------------------------------------------------------------------------- */
/* Answers                                                                     */
/* -------------------------------------------------------------------------- */

/// Reads the answer to a request about one upload, taking the refusals that are answers as answers.
///
/// An upload that is closed, expired, being cleaned up or already stored is refused `FORBIDDEN`
/// for anything but a completion asked for again, and so is one created under another pair of
/// proofs; one the service never made is `NOT_FOUND`. Either way it takes nothing more from this
/// caller, which is [`ArchiveAnswer::UploadGone`].
fn upload_answer(answer: Answer) -> Result<ArchiveAnswer<serde_json::Value>> {
    match answer {
        Answer::Data(data) => Ok(ArchiveAnswer::Done(data)),
        Answer::Refused(refusal) => match refusal.code() {
            "COLLECTION_DELETED" => Ok(ArchiveAnswer::CollectionDeleted),
            "FORBIDDEN" | "NOT_FOUND" => Ok(ArchiveAnswer::UploadGone),
            _ => Err(refusal.into_error()),
        },
    }
}

/// Reads one answer as the shape the contract gives it.
fn read<T: for<'de> Deserialize<'de>>(data: serde_json::Value, what: &'static str) -> Result<T> {
    serde_json::from_value(data).map_err(|error| unreadable_answer(what, &error))
}

/// A counter the service compares exactly, or the refusal of one it would not.
fn counter(what: &'static str, value: u64) -> Result<U64> {
    if value > MAX_SAFE_COUNTER {
        return Err(malformed(crate::shown!(
            "{} is at most {}, the largest counter the service compares exactly",
            what,
            MAX_SAFE_COUNTER
        )));
    }
    Ok(U64::new(value))
}

/// The largest counter the service's own arithmetic carries exactly.
const MAX_SAFE_COUNTER: u64 = (1 << 53) - 1;

/// What a caller is told about an object the service holds none of.
///
/// A tombstoned object reads the same as one that never existed, so this says neither.
fn not_held() -> ClientError {
    ClientError::Host(ProtocolError::new(
        ErrorCode::UnknownSession,
        "the service holds no stored object under that identity".to_owned(),
    ))
}

/// An answer that was read and says something the service's contract does not allow.
///
/// The service answered, so whatever it did is done; what this client lacks is an answer it can
/// act on, which is an unknown outcome like any other answer it could not read.
fn contrary(what: &str) -> ClientError {
    ClientError::Host(ProtocolError::new(
        ErrorCode::OutcomeUnknown,
        format!("the service answered {what}"),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::rendering::{NEVER_RENDERED, renders_only};

    #[test]
    fn a_rendering_of_a_part_or_a_range_carries_its_length_and_never_its_ciphertext() {
        renders_only(
            &UploadPart {
                number: 3,
                bytes: NEVER_RENDERED.as_bytes(),
            },
            &format!("UploadPart{{number:3,length:{}}}", NEVER_RENDERED.len()),
        );
        renders_only(
            &ObjectRange {
                offset: 8,
                bytes: NEVER_RENDERED.as_bytes().to_vec(),
            },
            &format!("ObjectRange{{offset:8,length:{}}}", NEVER_RENDERED.len()),
        );
    }

    /// A part table is the protocol's arithmetic: every part the part size but the last, which is
    /// shorter and not empty, and one table for one total.
    #[test]
    fn a_total_cuts_into_one_part_table() {
        let size = STORAGE_PART_SIZE_BYTES;
        for (total, count, last) in [
            (1, 1, 1),
            (size, 1, size),
            (size + 1, 2, 1),
            (2 * size, 2, size),
            (2 * size + 7, 3, 7),
            (MAX_STORAGE_OBJECT_BYTES, 128, size),
        ] {
            let table = PartTable::for_total(total).expect("a table");
            assert_eq!(table.part_count(), count, "{total}");
            assert_eq!(table.final_part_bytes(), last, "{total}");
            assert_eq!(
                table.part(count).expect("the last part"),
                (total - last)..total
            );
            assert_eq!(table.part(1).expect("the first part").start, 0);
            assert!(table.part(0).is_none());
            assert!(table.part(count + 1).is_none());
        }
        assert!(PartTable::for_total(0).is_none());
        assert!(PartTable::for_total(MAX_STORAGE_OBJECT_BYTES + 1).is_none());
    }

    #[test]
    fn an_upload_identity_is_bounded_printable_text() {
        assert!(UploadId::new("bXL7_q-2").is_ok());
        for refused in [
            String::new(),
            "has space".to_owned(),
            "line\nbreak".to_owned(),
            "é".to_owned(),
            "a".repeat(MAX_UPLOAD_ID_BYTES + 1),
        ] {
            assert!(UploadId::new(refused.clone()).is_err(), "{refused:?}");
        }
    }
}
