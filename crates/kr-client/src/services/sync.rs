//! Settings sync's client: the compare-and-exchange service, over the signed call.
//!
//! Section 20: an object is encrypted before it is stored, written by compare and swap against a
//! per-object revision, and a write that loses the comparison is kept for the person to choose
//! from. [`ManagedSyncService`] is how a device reaches the service that does that: the
//! [`SyncBackupService`] this crate carries, over [`SignedService`].
//!
//! It seals nothing and opens nothing. The bytes it carries are a [`SealedSyncObject`] in
//! canonical KR-CBOR-1, which is what [`crate::sync::CollectionSealer`] produces and opens: this
//! reads them, holds them to the rules a service checks without a key, and carries the object they
//! describe.
//!
//! # One route, eight members
//!
//! `sync.compare_exchange` is one signed method at one path, and a request asks for exactly one of
//! eight things: an exchange, a comparison, a resolution, the status of a request identity, a fence
//! of one, a read of a collection's key records, the offer of the record that follows its newest,
//! or the list of shared collections whose newest record names this installation. Each is signed
//! under the same credential.
//!
//! # Which collection a call reaches
//!
//! This crate keeps one object per collection and names the collection for the object's kind and
//! identity: [`crate::sync::sync_collection`] for settings and a client's position, and
//! [`crate::drafts::draft_collection`] for a draft. The service names a collection with an
//! identifier of its own, scoped to the key that signs, and holds each object under its identity
//! with its kind beside it. So a name is read back into those three, and the service's collection
//! is named by the object's own identity: one object, one collection, on both sides. A name neither
//! function produced is refused before anything is sent.
//!
//! Such a collection belongs to the installation whose key signs for it, because the service
//! derives it from that key, and it is what [`SyncBackupService`] addresses.
//!
//! A collection two or more devices share is named by a [`CollectionRef`] instead: it lives in the
//! namespace of the installation that started it, its home, and holds several objects, each named
//! inside it by the same per-object name. Every request about it names the home, every write names
//! the key epoch its object is sealed under, and the service admits only the devices its newest key
//! record lists. The `_shared` calls address one: [`ManagedSyncService::exchange_shared`],
//! [`ManagedSyncService::status_shared`], [`ManagedSyncService::fence_shared`],
//! [`ManagedSyncService::compare_shared`] and [`ManagedSyncService::resolve_shared`]. A shared
//! comparison follows the service's pages of objects until nothing it names is missing.
//! [`ManagedSyncService::inventory`] reads what one holds, each with the epoch it is sealed under,
//! under a budget of pages its caller continues from, and [`ManagedSyncService::memberships`] lists
//! the shared collections whose newest record names this installation. Its key records are this
//! client's [`KeyRecordService`].
//!
//! # Two refusals that are answers
//!
//! In a shared collection the service answers two things with refusals a caller acts on rather
//! than reports. `COLLECTION_ABSENT` is a collection that does not exist or whose newest record
//! does not list this installation, one answer for both. `KEY_EPOCH_RETIRED` is a write sealed
//! under an epoch the collection has retired: nothing was stored or held, the refusal names the
//! collection's epoch and revision, and it is the request's receipt. A shared write, its status
//! query and its fence return both as [`Keyed`] answers; a shared comparison, a resolution and an
//! inventory answer nothing for a collection that does not list this installation, and the
//! key-record reads return that as [`KeyRecords::Absent`] and [`RecordAt::Absent`]. A collection
//! only its home writes answers neither, so for it both stay errors.
//!
//! Every request but a membership listing can meet a third. `SIGNED_BEFORE_CUTOFF` refuses a
//! request signed before the collection's cutoff, which a service keeps so that a request whose
//! receipt it has swept is never run as a first admission: nothing ran and nothing was recorded,
//! and no attempt signed then ever runs. An exchange returns it as
//! [`SyncExchanged::SignedBeforeCutoff`], an answer that ends the attempt, and a caller never
//! presents the identity again, signed now or otherwise. Every other request is signed at the
//! instant it is sent, or, for a key-record offer, at the instant its caller recorded, which is
//! sent only while it is fresh. The service checks freshness first, so for them the refusal says
//! that the collection's cutoff runs ahead of the clocks. They are told `CLOCK_UNTRUSTED`, with
//! the action to wait and a message that nothing ran and nothing was recorded, and nothing sends
//! or signs them again by itself.
//!
//! # What it keeps
//!
//! Nothing. Every ordering fact is the service's: the position an exchange answers, what a receipt
//! recorded, whether a fenced request ever ran. This passes each of them through as the service
//! stated it, and an answer that does not state one is an error rather than a guess. A write is
//! signed at the instant its caller recorded, never at a reading taken here, and a request's bytes
//! are a function of what the caller passed and nothing else, so the same attempt made twice is the
//! same document twice: the service answers a retry from its receipt only when nothing its digest
//! covers has changed. The digest covers the key epoch a write names, so a retry names the epoch
//! the first attempt named.
//!
//! # What an answer may carry
//!
//! Every member of an answer this client reads is required, and read as the type the contract
//! gives it: an answer missing one is an error rather than a default. A member it does not read is
//! let through. The service and this client are deployed on their own schedules, so the service can
//! add a member before this client knows of it, and refusing a whole answer over that would leave
//! a write the service had applied unsettled until this client caught up. A sealed object and a key
//! record are the exceptions and stay closed schemas, because what is stored has to be exactly what
//! was sealed or signed.
//!
//! # What is never rendered
//!
//! An exchange carries a sealed object and a comparison answers with them. Under this module's
//! rule the types that hold one write their own [`std::fmt::Debug`]: what the object is, its
//! declared size and where it stands, and nothing sealed. A key record renders its collection,
//! epoch, revision and how many members it names, and nothing else.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::num::NonZeroUsize;
use std::sync::Arc;

use kr_protocol::collection_keys::CollectionKeyRecord;
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::ids::{DraftId, InstallationId, SyncCollectionId, SyncConflictId, SyncObjectId};
use kr_protocol::method::Method;
use kr_protocol::scalars::{Nullable, U64, Uuid};
use kr_protocol::service::GatewayOrigin;
use kr_protocol::sync::{SealedSyncObject, SyncObjectKind};
use serde::{Deserialize, Serialize};

use super::relay::{ServiceHttp, ServiceSigner};
use super::signed::{Answer, Refusal, SignedService, malformed, unreadable_answer};
use super::{
    KeyHead, Keyed, ServiceFuture, SyncBackupService, SyncExchanged, SyncFetched, SyncPosition,
    SyncRecoveryId, SyncRequestFence, SyncRequestStatus, SyncRevision,
};
use crate::error::{ClientError, Result};
use crate::sync::membership::{
    CollectionRef, KeyRecordService, KeyRecords, MembershipStatus, RecordAt, RekeyAnswer,
    RekeyFence, RekeyStatus,
};

/// Where every settings-sync member is served.
pub const SYNC_EXCHANGE_PATH: &str = "/api/sync/exchange";

/// The most bytes one signed settings-sync request may be.
///
/// It is what the service admits for the whole request, credential included. An exchange is what
/// reaches it: one object is at most [`kr_protocol::sync::MAX_SYNC_OBJECT_PLAINTEXT_BYTES`] padded and sealed, and it
/// travels as base64, which costs a third on top. This client refuses a request past the bound
/// rather than sending one the service stops reading part way through.
pub const MAX_SYNC_REQUEST_BYTES: usize = 256 * 1024;

/// The most objects, and separately the most copies, one comparison answers with.
///
/// The service's own page. It is stated here because the bound an answer is read under has to
/// cover it.
pub const SYNC_ANSWER_PAGE: u64 = 64;

/// How many bytes of a settings-sync answer this client reads.
///
/// A comparison is the largest answer: a page of objects and a page of copies, each carrying one
/// sealed object of at most [`kr_protocol::sync::MAX_SYNC_OBJECT_PLAINTEXT_BYTES`] and the seal's overhead, as base64,
/// with the record around it. Eight kibibytes an entry covers that record, which is a closed schema
/// of identifiers, positions and two timestamps, and
/// `the_bound_an_answer_is_read_under_covers_the_largest_comparison` holds this constant to that
/// arithmetic. It is far above [`super::http::DEFAULT_RESPONSE_LIMIT_BYTES`], which is why a
/// transport that carries this client states it for this path.
pub const SYNC_ANSWER_LIMIT_BYTES: u64 = 16 * 1024 * 1024;

/// The largest counter the service compares exactly.
///
/// Every instant and position on this surface is stored and compared by the service as a number
/// its arithmetic carries exactly, and one past this is refused rather than rounded. This client
/// refuses one first, so a caller that carried a figure from somewhere else is told which rule it
/// broke rather than being refused by the service.
pub const MAX_SYNC_COUNTER: u64 = (1 << 53) - 1;

/// The most key records one read follows, across every page the service answers it with.
///
/// Every revision of a collection's records is kept for the collection's life, and a device that
/// joins reads them all from the first. One revision is one change of who holds the key, so a
/// collection reaches this only after thousands of them; a read past it is refused as an answer
/// this client will not hold, rather than one that grows without bound.
pub const MAX_KEY_RECORDS_READ: usize = 4096;

/// The most shared collections one listing follows, across every page the service answers it with.
pub const MAX_MEMBERSHIPS_READ: usize = 4096;

/// The most objects a reader may name as held in one comparison, which is what the service reads.
pub const MAX_KNOWN_REVISIONS: usize = 8 * 64;

/// The most pages one shared comparison follows to bring every object the reader lacks.
///
/// A collection holds at most [`kr_protocol::sync::MAX_SYNC_OBJECTS_PER_COLLECTION`] objects and
/// a page carries [`SYNC_ANSWER_PAGE`] of them, so four pages bring them all; the rest allows for
/// objects written again while the pages are read.
pub const MAX_COMPARISON_PAGES: usize = 16;

/* -------------------------------------------------------------------------- */
/* Which collection a call reaches                                             */
/* -------------------------------------------------------------------------- */

/// One synchronised object's collection, as the service names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Collection {
    /// The service's name for the collection, which is the object's own identity.
    id: SyncCollectionId,
    /// What kind of object it holds.
    kind: SyncObjectKind,
    /// The object it holds.
    object_id: SyncObjectId,
}

impl Collection {
    /// Reads one of the names this crate gives a synchronised object's collection.
    ///
    /// The name is checked by making it again. A name is accepted only when the function that
    /// names that kind of collection produces exactly it, so this reads the names this crate writes
    /// and nothing else, and the two cannot drift apart.
    fn named(collection: &str) -> Result<Self> {
        let refused = || {
            malformed(
                "that collection is not one settings sync names: settings, a client's position or a draft",
            )
        };
        let (_, identity) = collection.split_once('/').ok_or_else(refused)?;
        let identity = identity.parse::<Uuid>().map_err(|_| refused())?;
        let object_id = SyncObjectId::new(identity);
        let kind = if collection == crate::drafts::draft_collection(DraftId::new(identity)) {
            SyncObjectKind::Draft
        } else {
            [SyncObjectKind::Settings, SyncObjectKind::ClientSelection]
                .into_iter()
                .find(|kind| collection == crate::sync::sync_collection(*kind, object_id))
                .ok_or_else(refused)?
        };
        Ok(Self {
            id: SyncCollectionId::new(identity),
            kind,
            object_id,
        })
    }
}

/// Where one request goes: the service's collection, and the namespace it lives in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Address {
    /// The service's name for the collection.
    collection_id: SyncCollectionId,
    /// The installation whose namespace it lives in, or nothing for the signer's own.
    ///
    /// Left out of the request when it is nothing, so a request about a collection only its home
    /// writes is the document it always was.
    home: Option<InstallationId>,
}

impl Address {
    /// The collection one object lives in, in the signer's own namespace.
    const fn own(collection: Collection) -> Self {
        Self {
            collection_id: collection.id,
            home: None,
        }
    }

    /// A collection two or more devices share, in its home's namespace.
    const fn shared(collection: &CollectionRef) -> Self {
        Self {
            collection_id: collection.collection_id,
            home: Some(collection.home),
        }
    }
}

/* -------------------------------------------------------------------------- */
/* What a client sends                                                         */
/* -------------------------------------------------------------------------- */

/// One settings-sync request: exactly one member.
#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
enum SyncRequest<'a> {
    Exchange(ExchangeBody<'a>),
    Compare(CompareBody),
    Resolve(ResolveBody),
    Status(StatusBody),
    Fence(FenceBody),
    Keys(KeysBody),
    Rekey(RekeyBody<'a>),
    Memberships(MembershipsBody),
}

/// Write one object, if the service still holds the revision the writer expects.
#[derive(Serialize)]
struct ExchangeBody<'a> {
    request_id: Uuid,
    collection_id: SyncCollectionId,
    #[serde(skip_serializing_if = "Option::is_none")]
    home: Option<InstallationId>,
    /// The epoch of the key the object is sealed under, in a collection a key record has claimed.
    #[serde(skip_serializing_if = "Option::is_none")]
    key_epoch: Option<U64>,
    kind: SyncObjectKind,
    object_id: SyncObjectId,
    /// The revision this write replaces, or null when it names no object.
    ///
    /// Present and null rather than absent, which is the shape the service's contract declares.
    expected_revision: Option<SyncRevision>,
    object: &'a SealedSyncObject,
}

impl fmt::Debug for ExchangeBody<'_> {
    /// What the object is, how large it declares itself, whether the write names a revision and
    /// which epoch it names. Never the ciphertext or the nonce.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExchangeBody")
            .field("kind", &self.kind)
            .field("size_bucket_bytes", &self.object.size_bucket_bytes)
            .field("expects_an_object", &self.expected_revision.is_some())
            .field("key_epoch", &self.key_epoch)
            .finish_non_exhaustive()
    }
}

/// Read what the collection holds, and its copies when they are asked for.
#[derive(Debug, Serialize)]
struct CompareBody {
    collection_id: SyncCollectionId,
    #[serde(skip_serializing_if = "Option::is_none")]
    home: Option<InstallationId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    kind: Option<SyncObjectKind>,
    /// The objects the reader already holds at the revision named, which the answer leaves out.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    known: Vec<KnownRevision>,
    with_conflicts: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    conflicts_after_sequence: Option<U64>,
}

/// One object a reader already holds, at the revision it holds it at, which a comparison leaves
/// out.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct KnownRevision {
    /// The object.
    pub object_id: SyncObjectId,
    /// The revision the reader holds.
    pub revision: SyncRevision,
}

/// Drop copies the person has chosen about.
#[derive(Debug, Serialize)]
struct ResolveBody {
    collection_id: SyncCollectionId,
    #[serde(skip_serializing_if = "Option::is_none")]
    home: Option<InstallationId>,
    conflict_ids: Vec<SyncConflictId>,
}

/// Ask what the service recorded about one request identity.
#[derive(Debug, Serialize)]
struct StatusBody {
    collection_id: SyncCollectionId,
    #[serde(skip_serializing_if = "Option::is_none")]
    home: Option<InstallationId>,
    request_id: Uuid,
}

/// End one request identity, naming the instants its attempts were signed at.
#[derive(Debug, Serialize)]
struct FenceBody {
    collection_id: SyncCollectionId,
    #[serde(skip_serializing_if = "Option::is_none")]
    home: Option<InstallationId>,
    request_id: Uuid,
    first_signed_at_ms: U64,
    last_signed_at_ms: U64,
}

/// Read a collection's key records after a revision.
#[derive(Debug, Serialize)]
struct KeysBody {
    collection_id: SyncCollectionId,
    #[serde(skip_serializing_if = "Option::is_none")]
    home: Option<InstallationId>,
    after_revision: U64,
}

/// Offer the key record that follows the collection's newest, under a request identity.
#[derive(Debug, Serialize)]
struct RekeyBody<'a> {
    request_id: Uuid,
    collection_id: SyncCollectionId,
    #[serde(skip_serializing_if = "Option::is_none")]
    home: Option<InstallationId>,
    /// Its `Debug` names the collection, epoch, revision and member count, and nothing else.
    record: &'a CollectionKeyRecord,
}

/// List the shared collections whose newest record lists the signer.
#[derive(Debug, Serialize)]
struct MembershipsBody {
    #[serde(skip_serializing_if = "Option::is_none")]
    after: Option<String>,
}

/* -------------------------------------------------------------------------- */
/* What the service answers                                                    */
/* -------------------------------------------------------------------------- */

/// What one collection holds, and what the allowance leaves.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
pub struct SyncUsage {
    /// How many objects the collection holds.
    pub objects: U64,
    /// How many copies are waiting for a choice.
    pub conflicts: U64,
    /// How many bytes they occupy.
    pub bytes: U64,
    /// The most objects the collection holds.
    pub object_limit: U64,
    /// The settings-sync allowance the signing principal holds, in bytes, where the service read
    /// it for this answer. Only a comparison reads it.
    pub allowance_bytes: Nullable<U64>,
}

/// What became of one exchange.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ExchangeState {
    Written,
    Removed,
    Conflict,
}

/// One stored object, without its content, as an exchange answers it.
#[derive(Deserialize)]
#[expect(dead_code, reason = "held to its schema and never read")]
struct ObjectSummary {
    kind: SyncObjectKind,
    object_id: SyncObjectId,
    revision: SyncRevision,
    write_sequence: U64,
    updated_at: String,
    bytes: U64,
}

/// The copy a refusal kept, without its content.
#[derive(Deserialize)]
struct ConflictSummary {
    #[expect(dead_code, reason = "held to its schema and never read")]
    sequence: U64,
    conflict_id: SyncConflictId,
    object_id: SyncObjectId,
    #[expect(dead_code, reason = "held to its schema and never read")]
    expected_revision: Nullable<SyncRevision>,
    /// The revision the object held, or empty text when it held none.
    #[expect(dead_code, reason = "held to its schema and never read")]
    current_revision: String,
    #[expect(dead_code, reason = "held to its schema and never read")]
    current_write_sequence: U64,
    #[expect(dead_code, reason = "held to its schema and never read")]
    recorded_at: String,
}

/// What `sync.compare_exchange` answers for an exchange.
#[derive(Deserialize)]
struct ExchangeAnswer {
    state: ExchangeState,
    #[expect(dead_code, reason = "held to its schema and never read")]
    record: Nullable<ObjectSummary>,
    current_revision: Nullable<SyncRevision>,
    current_write_sequence: U64,
    conflict: Nullable<ConflictSummary>,
    /// The collection's epoch, in a collection a key record has claimed.
    #[serde(default)]
    key_epoch: Option<U64>,
    /// The revision of the collection's newest key record, beside the epoch.
    #[serde(default)]
    key_revision: Option<U64>,
    /// The history every place in this answer is in, as the collection stands when it answers.
    recovery_id: Nullable<SyncRecoveryId>,
    #[expect(dead_code, reason = "held to its schema and never read")]
    stored: SyncUsage,
}

/// What `sync.compare_exchange` answers for a resolution.
#[derive(Deserialize)]
struct ResolveAnswer {
    resolved: U64,
    #[expect(dead_code, reason = "held to its schema and never read")]
    stored: SyncUsage,
}

/// Where a status query or a fence found one request identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum StatusState {
    Applied,
    Refused,
    Fenced,
    Retired,
    Unknown,
}

/// What a receipt recorded.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ReceiptOutcome {
    Written,
    Removed,
    Conflict,
    Retired,
    Rekeyed,
    RekeyRefused,
    Fenced,
}

impl ReceiptOutcome {
    /// The state a status query and a fence answer this outcome as, which is the service's rule.
    const fn state(self) -> StatusState {
        match self {
            Self::Written | Self::Removed | Self::Rekeyed => StatusState::Applied,
            Self::Conflict | Self::RekeyRefused => StatusState::Refused,
            Self::Retired => StatusState::Retired,
            Self::Fenced => StatusState::Fenced,
        }
    }
}

/// What a status query and a fence answer.
///
/// `never_ran` is required on every answer, so an answer that does not state it is not one this
/// client reads: whether a request ever ran is the service's to say, and a default here would be
/// this client saying it instead.
#[derive(Deserialize)]
struct StatusAnswer {
    request_id: Uuid,
    state: StatusState,
    never_ran: bool,
    outcome: Nullable<ReceiptOutcome>,
    #[expect(dead_code, reason = "held to its schema and never read")]
    record: Nullable<ObjectSummary>,
    current_revision: Nullable<SyncRevision>,
    current_write_sequence: Nullable<U64>,
    conflict_id: Nullable<SyncConflictId>,
    /// The epoch the recorded answer named, when it named one.
    #[serde(default)]
    key_epoch: Option<U64>,
    /// The key record revision the recorded answer named, beside the epoch.
    #[serde(default)]
    key_revision: Option<U64>,
    /// The history the collection answers from now, which is the one every place the receipt
    /// recorded is read in: a restored collection's history begins with what the archive held.
    recovery_id: Nullable<SyncRecoveryId>,
    #[expect(dead_code, reason = "held to its schema and never read")]
    recorded_at: Nullable<String>,
}

/// One stored object, with its content, as a comparison answers it.
#[derive(Deserialize)]
struct ObjectRecord {
    kind: SyncObjectKind,
    object_id: SyncObjectId,
    revision: SyncRevision,
    write_sequence: U64,
    #[serde(default)]
    key_epoch: Option<U64>,
    object: SealedSyncObject,
    #[expect(dead_code, reason = "held to its schema and never read")]
    updated_at: String,
}

/// One object a reader named that the collection no longer holds.
#[derive(Deserialize)]
struct RemovedObject {
    object_id: SyncObjectId,
    write_sequence: U64,
}

/// Where one object stands.
#[derive(Deserialize)]
struct ObjectPosition {
    object_id: SyncObjectId,
    revision: SyncRevision,
    write_sequence: U64,
    #[serde(default)]
    key_epoch: Option<U64>,
}

/// One copy, with its content, as a comparison answers it.
#[derive(Deserialize)]
struct ConflictRecord {
    sequence: U64,
    conflict_id: SyncConflictId,
    kind: SyncObjectKind,
    object_id: SyncObjectId,
    expected_revision: Nullable<SyncRevision>,
    /// The revision the object held when the write was refused, or empty text when it held none.
    current_revision: String,
    current_write_sequence: U64,
    #[serde(default)]
    key_epoch: Option<U64>,
    object: SealedSyncObject,
    #[expect(dead_code, reason = "held to its schema and never read")]
    recorded_at: String,
}

/// What `sync.compare_exchange` answers for a comparison.
#[derive(Deserialize)]
struct CompareAnswer {
    changed: Vec<ObjectRecord>,
    removed: Vec<RemovedObject>,
    revisions: Vec<ObjectPosition>,
    conflicts: Vec<ConflictRecord>,
    next_conflicts_after_sequence: U64,
    more_conflicts: bool,
    #[serde(default)]
    key_epoch: Option<U64>,
    #[serde(default)]
    key_revision: Option<U64>,
    /// The history every place in this answer is in.
    recovery_id: Nullable<SyncRecoveryId>,
    stored: SyncUsage,
}

/// What `sync.compare_exchange` answers for a read of key records.
#[derive(Deserialize)]
struct KeysAnswer {
    records: Vec<CollectionKeyRecord>,
    more: bool,
    #[expect(dead_code, reason = "held to its schema and never read")]
    key_revision: U64,
    #[expect(dead_code, reason = "held to its schema and never read")]
    key_epoch: Nullable<U64>,
    /// The history every revision in this answer is in.
    recovery_id: Nullable<SyncRecoveryId>,
}

/// What a `rekey` did.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RekeyState {
    Applied,
    Refused,
}

/// What `sync.compare_exchange` answers for the offer of a key record.
#[derive(Deserialize)]
struct RekeyResult {
    state: RekeyState,
    key_revision: U64,
    #[expect(dead_code, reason = "held to its schema and never read")]
    key_epoch: Nullable<U64>,
    /// The history that revision is in, as the collection stands when it answers.
    recovery_id: Nullable<SyncRecoveryId>,
}

/// One shared collection a membership listing names.
#[derive(Deserialize)]
struct MembershipEntry {
    home: InstallationId,
    collection_id: SyncCollectionId,
    key_revision: U64,
    key_epoch: U64,
    /// The history the collection stated with that revision.
    recovery_id: Nullable<SyncRecoveryId>,
}

/// What `sync.compare_exchange` answers for a membership listing.
#[derive(Deserialize)]
struct MembershipsAnswer {
    memberships: Vec<MembershipEntry>,
    more: bool,
    next_after: Nullable<String>,
}

/// One object a collection holds, as a comparison read it.
#[derive(Clone, PartialEq, Eq)]
pub struct SyncHeldObject {
    /// The object.
    pub object_id: SyncObjectId,
    /// What kind of object the service holds it as.
    pub kind: SyncObjectKind,
    /// Where it stands: the write that put it there, and that write's place in the order.
    pub position: SyncPosition,
    /// The epoch of the key it is sealed under, in a collection a key record has claimed.
    pub epoch: Option<u64>,
    /// The sealed object, in canonical KR-CBOR-1, which is what a sealer opens.
    pub ciphertext: Vec<u8>,
}

impl fmt::Debug for SyncHeldObject {
    /// What the object is, where it stands and its epoch. Never the sealed object.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SyncHeldObject")
            .field("object_id", &self.object_id)
            .field("kind", &self.kind)
            .field("position", &self.position)
            .field("epoch", &self.epoch)
            .finish_non_exhaustive()
    }
}

/// One copy the service kept of a refused write, as a comparison read it.
#[derive(Clone, PartialEq, Eq)]
pub struct SyncHeldCopy {
    /// Its place in the order the collection recorded its copies, which is what a cursor names.
    pub sequence: u64,
    /// The copy, which is what a resolution names.
    pub conflict_id: SyncConflictId,
    /// The object the refused write was about.
    pub object_id: SyncObjectId,
    /// What kind of object the refused write carried.
    pub kind: SyncObjectKind,
    /// The revision the refused write expected, or null when it expected no object.
    pub expected_revision: Nullable<SyncRevision>,
    /// Where the object stood when the write was refused: the write that beat it, or the place a
    /// removal took when the object held none. Nothing when the collection had never held it.
    pub current: Option<SyncPosition>,
    /// The epoch of the key the refused content is sealed under, in a collection a key record has
    /// claimed.
    pub epoch: Option<u64>,
    /// The refused write's sealed object, in canonical KR-CBOR-1, which is what a sealer opens.
    pub ciphertext: Vec<u8>,
}

impl fmt::Debug for SyncHeldCopy {
    /// Which copy it is, what it is about, where the object stood and its epoch. Never the sealed
    /// object.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SyncHeldCopy")
            .field("sequence", &self.sequence)
            .field("conflict_id", &self.conflict_id)
            .field("object_id", &self.object_id)
            .field("kind", &self.kind)
            .field("current", &self.current)
            .field("epoch", &self.epoch)
            .finish_non_exhaustive()
    }
}

/// One object a reader named that the collection no longer holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SyncRemoved {
    /// The object.
    pub object_id: SyncObjectId,
    /// Where its removal came in its order of writes, or nothing when the collection never held it.
    pub position: Option<SyncPosition>,
}

/// What one comparison found in a collection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyncComparison {
    /// The objects the collection holds that the reader did not hold at the revision it holds them
    /// at.
    pub objects: Vec<SyncHeldObject>,
    /// The objects the reader named that the collection no longer holds.
    pub removed: Vec<SyncRemoved>,
    /// The copies waiting for a choice, when they were asked for, in the order they were kept.
    pub copies: Vec<SyncHeldCopy>,
    /// Whether more copies were waiting than this page carried.
    pub more_copies: bool,
    /// The cursor to read the next page of copies from.
    pub next_copies_after: u64,
    /// Where the collection's key records stood, in a collection a key record has claimed.
    pub head: Option<KeyHead>,
    /// The history every place in this comparison is in: the recovery the service named, or none
    /// for a service never put back. It is stated even when the comparison names no place at all.
    pub recovery: Option<SyncRecoveryId>,
    /// How the collection stands.
    pub stored: SyncUsage,
}

/// Where one object a shared collection holds stands, and the epoch it is sealed under.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InventoryObject {
    /// The object.
    pub object_id: SyncObjectId,
    /// Where it stands.
    pub position: SyncPosition,
    /// The epoch of the key it is sealed under, in a collection a key record has claimed.
    pub epoch: Option<u64>,
}

/// One copy a shared collection keeps of a refused write, and the epoch it is sealed under.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InventoryCopy {
    /// Its place in the order the collection recorded its copies.
    pub sequence: u64,
    /// The copy.
    pub conflict_id: SyncConflictId,
    /// The object the refused write was about.
    pub object_id: SyncObjectId,
    /// What kind of object the refused write carried.
    pub kind: SyncObjectKind,
    /// The epoch of the key the refused content is sealed under, in a collection a key record has
    /// claimed.
    pub epoch: Option<u64>,
}

/// What a shared collection holds, each with the epoch it is sealed under: every object, and every
/// copy the read reached.
///
/// It is what a member reads before it forgets an epoch's key: the key goes only once a read that
/// reached the end found nothing sealed under it. Objects are as the last page found them, which
/// is the newest account of each; copies are every one the pages reached, in the order they were
/// kept.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Inventory {
    /// Where the collection's key records stood when the last page was read.
    pub head: Option<KeyHead>,
    /// The history every page was read in: the recovery the first page named. A read continued
    /// from here takes pages from that history only, because a collection put back between two
    /// pages holds copies the earlier pages never saw and has lost some they did.
    pub recovery: Option<SyncRecoveryId>,
    /// Every object.
    pub objects: Vec<InventoryObject>,
    /// Every copy the read reached.
    pub copies: Vec<InventoryCopy>,
    /// The cursor the copies continue from when the read stopped at its budget before the end, or
    /// nothing when it reached the end.
    pub resume_after: Option<u64>,
}

impl Inventory {
    /// Whether the read reached the end of the copies.
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.resume_after.is_none()
    }

    /// Every epoch something the read found is sealed under.
    #[must_use]
    pub fn epochs(&self) -> BTreeSet<u64> {
        self.objects
            .iter()
            .filter_map(|object| object.epoch)
            .chain(self.copies.iter().filter_map(|copy| copy.epoch))
            .collect()
    }

    /// Whether the collection may hold something sealed under this epoch: it does when the read
    /// found something, and it may whenever the read stopped before the end, because what it did
    /// not reach cannot be shown not to be.
    #[must_use]
    pub fn may_hold_epoch(&self, epoch: u64) -> bool {
        !self.is_complete() || self.epochs().contains(&epoch)
    }
}

/// One shared collection whose newest key record listed this installation when the service's
/// index last heard of it.
///
/// The index can be behind the collection, and it admits nobody: a device reads the records
/// themselves before it trusts any of them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MembershipListing {
    /// The collection.
    pub collection: CollectionRef,
    /// The epoch and revision of the record the index last heard of, and the history they are in.
    pub head: KeyHead,
}

impl MembershipListing {
    /// Whether this entry says something the membership this device holds does not know: for the
    /// same collection, another history than the one its records were read in, whatever revision
    /// the entry names, since the revision held belongs to a history the collection no longer
    /// has; or, in the same history, a later revision than its head.
    ///
    /// It is a reason to refresh and nothing more. The index admits nobody, so nothing in an entry
    /// changes what this device holds: only the records the collection itself answers do.
    #[must_use]
    pub fn names_news(&self, held: &MembershipStatus) -> bool {
        self.collection == held.collection
            && (self.head.recovery != held.recovery || self.head.revision > held.head)
    }
}

/// A shared comparison read over several pages, folded into one answer.
///
/// Every page is read whole: the objects it brought, the objects it says the collection no longer
/// holds, and the listing of every object the collection holds. One rule merges them: what a later
/// page says of an object replaces what an earlier page said, because a later page is a later
/// reading. Every request is built from the fold's own state, so what it names stays within what
/// the service reads: one revision an object, and after the first page only the objects the
/// collection lists.
#[derive(Debug, Default)]
struct ObjectFold {
    /// What the reader holds, one revision an object.
    known: BTreeMap<SyncObjectId, SyncRevision>,
    /// What the pages said of each object, the latest word kept.
    said: BTreeMap<SyncObjectId, Said>,
    /// The objects the latest page listed, at the revisions it listed them at, or nothing before
    /// the first page.
    listed: Option<BTreeMap<SyncObjectId, SyncRevision>>,
}

/// What one page said of one object.
#[derive(Debug)]
enum Said {
    /// Its content, at a revision.
    Held(SyncHeldObject),
    /// That the collection no longer holds it.
    Removed(SyncRemoved),
}

impl ObjectFold {
    /// A fold over what the reader holds, each object once at the last revision named for it, as
    /// the service reads a list.
    fn holding(known: &[KnownRevision]) -> Self {
        Self {
            known: known
                .iter()
                .map(|held| (held.object_id, held.revision))
                .collect(),
            ..Self::default()
        }
    }

    /// What the next request names as held: everything before the first page, and after it only
    /// the objects the collection lists, which is at most what one collection holds.
    fn held(&self) -> Vec<KnownRevision> {
        self.known
            .iter()
            .filter(|(object_id, _)| {
                self.listed
                    .as_ref()
                    .is_none_or(|listed| listed.contains_key(object_id))
            })
            .map(|(object_id, revision)| KnownRevision {
                object_id: *object_id,
                revision: *revision,
            })
            .collect()
    }

    /// Takes one page, and says whether it brought any object.
    fn absorb(
        &mut self,
        page: &SyncComparison,
        listed: BTreeMap<SyncObjectId, SyncRevision>,
    ) -> Result<bool> {
        for object in &page.objects {
            let revision =
                object.position.revision.0.ok_or_else(|| {
                    contrary("an object a comparison carries without its revision")
                })?;
            self.known.insert(object.object_id, revision);
            self.said
                .insert(object.object_id, Said::Held(object.clone()));
        }
        for removed in &page.removed {
            self.known.remove(&removed.object_id);
            self.said.insert(removed.object_id, Said::Removed(*removed));
        }
        self.listed = Some(listed);
        Ok(!page.objects.is_empty())
    }

    /// Whether the latest page lists an object the reader does not hold at the revision listed.
    fn missing(&self) -> bool {
        self.listed.as_ref().is_some_and(|listed| {
            listed
                .iter()
                .any(|(object_id, revision)| self.known.get(object_id) != Some(revision))
        })
    }

    /// The objects and the removals the pages brought, the latest word on each. An object the
    /// pages brought that the latest listing leaves out, with no page saying it went, is an answer
    /// this client does not follow.
    fn answer(self) -> Result<(Vec<SyncHeldObject>, Vec<SyncRemoved>)> {
        let listed = self.listed.unwrap_or_default();
        let mut objects = Vec::new();
        let mut removed = Vec::new();
        for (object_id, said) in self.said {
            match said {
                Said::Held(object) if listed.contains_key(&object_id) => objects.push(object),
                Said::Held(_) => {
                    return Err(contrary(
                        "an object a comparison brought that its listing leaves out",
                    ));
                }
                Said::Removed(gone) => removed.push(gone),
            }
        }
        Ok((objects, removed))
    }
}

/// What the service answered one request, read before it is read as one contract or another.
enum Reply<T> {
    /// The answer's `data`.
    Data(T),
    /// A write sealed under a retired epoch; the refusal named the collection's head.
    Retired(KeyHead),
    /// The collection does not exist, or does not list the signer.
    Absent,
}

/* -------------------------------------------------------------------------- */
/* The client                                                                  */
/* -------------------------------------------------------------------------- */

/// Settings sync's client, over the signed call.
#[derive(Clone, Debug)]
pub struct ManagedSyncService {
    call: SignedService,
}

impl ManagedSyncService {
    /// Builds a client against one gateway.
    ///
    /// The key `signer` holds is the installation the collections belong to: the service derives
    /// every collection a request reaches from the key that signed it, and in a shared collection
    /// admits it by that key.
    #[must_use]
    pub fn new(
        origin: GatewayOrigin,
        http: Arc<dyn ServiceHttp>,
        signer: Arc<dyn ServiceSigner>,
    ) -> Self {
        Self {
            call: SignedService::new(origin, http, signer),
        }
    }

    /// The gateway this client addresses.
    #[must_use]
    pub const fn origin(&self) -> &GatewayOrigin {
        self.call.origin()
    }

    /// Reads what one collection holds, and the copies its refusals kept when `with_copies` asks.
    ///
    /// Every object and copy comes back with where it stands, stated by the service, and with its
    /// sealed object in the encoding a sealer opens. Copies come a page at a time from `after`, the
    /// cursor the previous page ended at, so a copy beyond the first page is reached by asking for
    /// it rather than by resolving the ones in front of it.
    ///
    /// # Errors
    ///
    /// Returns an error when the collection is not one settings sync names, when the service
    /// refuses the comparison, and when the exchange or the answer failed.
    pub async fn compare(
        &self,
        collection: &str,
        with_copies: bool,
        after: Option<u64>,
    ) -> Result<SyncComparison> {
        let named = Collection::named(collection)?;
        let data = self
            .ask(
                &self.compare_body(Address::own(named), None, with_copies, after, Vec::new())?,
                None,
            )
            .await?
            .data()?;
        comparison(read(data, "what a comparison answered")?)
    }

    /// Reads every object a shared collection holds that the reader does not hold at the revision
    /// the collection holds it at, every object the reader holds that the collection no longer
    /// does, and a page of the copies its refusals kept when `with_copies` asks, from the cursor
    /// `after`.
    ///
    /// `known` is what the reader holds: each object at the revision it holds it at, which the
    /// service leaves out. The service answers a page of objects at a time and names every object
    /// the collection holds, so this folds the pages into one answer: each page read whole,
    /// what a later page says of an object replacing what an earlier one said, and each request
    /// built from what the pages have brought. It follows them until nothing the collection names
    /// is missing. A page that brings nothing while something is missing is an answer this client
    /// does not follow, and so is a collection still moving after [`MAX_COMPARISON_PAGES`] pages.
    ///
    /// Every object and copy names the epoch it is sealed under, and the comparison names where the
    /// collection's key records stood at its last page.
    ///
    /// # Errors
    ///
    /// As [`Self::compare`], and a reader that names more than [`MAX_KNOWN_REVISIONS`] objects is
    /// refused before anything is sent. A collection that does not list this installation is
    /// `None`.
    pub async fn compare_shared(
        &self,
        collection: &CollectionRef,
        known: &[KnownRevision],
        with_copies: bool,
        after: Option<u64>,
    ) -> Result<Option<SyncComparison>> {
        if known.len() > MAX_KNOWN_REVISIONS {
            return Err(malformed(format!(
                "a comparison names at most {MAX_KNOWN_REVISIONS} objects the reader holds"
            )));
        }
        let mut fold = ObjectFold::holding(known);
        // The copies are the first page's: it is the one request that asks for them.
        let mut first: Option<SyncComparison> = None;
        // The history the first page was read in, which every later page is held to.
        let mut history: Option<Option<SyncRecoveryId>> = None;
        for page in 0..MAX_COMPARISON_PAGES {
            let request = if page == 0 {
                self.compare_body(
                    Address::shared(collection),
                    None,
                    with_copies,
                    after,
                    fold.held(),
                )?
            } else {
                self.compare_body(Address::shared(collection), None, false, None, fold.held())?
            };
            let answer: CompareAnswer = match reply(self.ask(&request, None).await?, false)? {
                Reply::Data(data) => read(data, "what a comparison answered")?,
                Reply::Absent => return Ok(None),
                Reply::Retired(_) => return Err(retired_where_no_write_was()),
            };
            one_history(&mut history, answer.recovery_id.0)?;
            let listed = answer
                .revisions
                .iter()
                .map(|position| (position.object_id, position.revision))
                .collect();
            let page = comparison(answer)?;
            let brought = fold.absorb(&page, listed)?;
            let (head, stored) = (page.head, page.stored);
            let first = first.get_or_insert(page);
            if !fold.missing() {
                let (objects, removed) = fold.answer()?;
                return Ok(Some(SyncComparison {
                    objects,
                    removed,
                    copies: std::mem::take(&mut first.copies),
                    more_copies: first.more_copies,
                    next_copies_after: first.next_copies_after,
                    head,
                    recovery: first.recovery,
                    stored,
                }));
            }
            if !brought {
                return Err(contrary(
                    "a comparison that names an object the reader lacks and carries none",
                ));
            }
        }
        Err(contrary(
            "a collection that kept changing while it was read",
        ))
    }

    /// Writes one object into a shared collection, sealed under `epoch`.
    ///
    /// `object` is the per-object name this crate gives the object's kind and identity, which
    /// names it inside the collection. `epoch` is part of what the request asks, so a retry names
    /// the epoch the first attempt named: the service answers it from its receipt, whatever the
    /// collection's epoch has become since.
    ///
    /// # Errors
    ///
    /// As [`SyncBackupService::compare_exchange`]. A write under a retired epoch is
    /// [`Keyed::Retired`] and a collection that does not list this installation [`Keyed::Absent`],
    /// both answers rather than errors.
    #[expect(
        clippy::too_many_arguments,
        reason = "each is a separate fact the request states: where, what, under which key, as which request, when, and against which revision"
    )]
    pub async fn exchange_shared(
        &self,
        collection: &CollectionRef,
        object: &str,
        epoch: u64,
        request_id: Uuid,
        signed_at_ms: u64,
        expected: Option<SyncPosition>,
        ciphertext: &[u8],
    ) -> Result<Keyed<SyncExchanged>> {
        let named = Collection::named(object)?;
        a_counter("a key epoch", epoch)?;
        let sealed = sealed_object(ciphertext)?;
        let request = exchange_body(
            Address::shared(collection),
            named,
            Some(epoch),
            request_id,
            expected,
            &sealed,
        );
        let answer = self.ask(&request, Some(signed_at_ms)).await?;
        if signed_before_cutoff(&answer) {
            // It left no receipt, and so names no key records either.
            return Ok(Keyed::Answered {
                answer: SyncExchanged::SignedBeforeCutoff,
                head: None,
            });
        }
        match reply(answer, true)? {
            Reply::Data(data) => {
                let answer: ExchangeAnswer = read(data, "what an exchange answered")?;
                let head = head_of(answer.key_epoch, answer.key_revision, answer.recovery_id.0)?;
                Ok(Keyed::Answered {
                    answer: exchanged(answer, named.object_id)?,
                    head,
                })
            }
            Reply::Retired(head) => Ok(Keyed::Retired { head }),
            Reply::Absent => Ok(Keyed::Absent),
        }
    }

    /// Asks what a shared collection recorded about one write's request identity.
    ///
    /// A member removed after it sent the write is still answered, from the receipt.
    ///
    /// # Errors
    ///
    /// As [`SyncBackupService::request_status`]. A write refused for a retired epoch is
    /// [`Keyed::Retired`], and an installation no record of the collection has listed
    /// [`Keyed::Absent`].
    pub async fn status_shared(
        &self,
        collection: &CollectionRef,
        request_id: Uuid,
    ) -> Result<Keyed<SyncRequestStatus>> {
        let request = SyncRequest::Status(StatusBody {
            collection_id: collection.collection_id,
            home: Some(collection.home),
            request_id,
        });
        match reply(self.ask(&request, None).await?, false)? {
            Reply::Data(data) => {
                let answer = status_answer(data, request_id, "what a status query answered")?;
                let recovery = answer.recovery_id.0;
                let (outcome, head) = write_outcome(&answer)?;
                Ok(match outcome {
                    WriteOutcome::Applied(position) => Keyed::Answered {
                        answer: SyncRequestStatus::Applied { position },
                        head,
                    },
                    WriteOutcome::Refused(retained) => Keyed::Answered {
                        answer: SyncRequestStatus::Refused { retained, recovery },
                        head,
                    },
                    WriteOutcome::Fenced { never_ran } => Keyed::Answered {
                        answer: SyncRequestStatus::Fenced {
                            never_ran,
                            recovery,
                        },
                        head,
                    },
                    WriteOutcome::Unknown => Keyed::Answered {
                        answer: SyncRequestStatus::Unknown { recovery },
                        head,
                    },
                    WriteOutcome::Retired(head) => Keyed::Retired { head },
                })
            }
            Reply::Absent => Ok(Keyed::Absent),
            Reply::Retired(_) => Err(retired_where_no_write_was()),
        }
    }

    /// Ends one write's request identity in a shared collection, naming the earliest and latest
    /// instant an attempt under it was signed at, and says what became of it.
    ///
    /// # Errors
    ///
    /// As [`SyncBackupService::fence_request`]. A write refused for a retired epoch is
    /// [`Keyed::Retired`], and an installation no record of the collection has listed
    /// [`Keyed::Absent`].
    pub async fn fence_shared(
        &self,
        collection: &CollectionRef,
        request_id: Uuid,
        first_signed_at_ms: u64,
        last_signed_at_ms: u64,
    ) -> Result<Keyed<SyncRequestFence>> {
        let request = fence_body(
            Address::shared(collection),
            request_id,
            first_signed_at_ms,
            last_signed_at_ms,
        )?;
        match reply(self.ask(&request, None).await?, false)? {
            Reply::Data(data) => {
                let answer = status_answer(data, request_id, "what a fence answered")?;
                let recovery = answer.recovery_id.0;
                let (outcome, head) = write_outcome(&answer)?;
                Ok(match outcome {
                    WriteOutcome::Applied(position) => Keyed::Answered {
                        answer: SyncRequestFence::Applied { position },
                        head,
                    },
                    WriteOutcome::Refused(retained) => Keyed::Answered {
                        answer: SyncRequestFence::Refused { retained, recovery },
                        head,
                    },
                    WriteOutcome::Fenced { never_ran } => Keyed::Answered {
                        answer: SyncRequestFence::Fenced {
                            never_ran,
                            recovery,
                        },
                        head,
                    },
                    WriteOutcome::Unknown => return Err(fence_answered_unknown()),
                    WriteOutcome::Retired(head) => Keyed::Retired { head },
                })
            }
            Reply::Absent => Ok(Keyed::Absent),
            Reply::Retired(_) => Err(retired_where_no_write_was()),
        }
    }

    /// Drops the copy a shared collection kept of one refused write, because the person has
    /// chosen.
    ///
    /// # Errors
    ///
    /// As [`SyncBackupService::resolve`]. A collection that does not list this installation is
    /// `None`.
    pub async fn resolve_shared(
        &self,
        collection: &CollectionRef,
        retained: SyncConflictId,
    ) -> Result<Option<bool>> {
        let request = resolve_body(Address::shared(collection), retained);
        match reply(self.ask(&request, None).await?, false)? {
            Reply::Data(data) => Ok(Some(dropped(data)?)),
            Reply::Absent => Ok(None),
            Reply::Retired(_) => Err(retired_where_no_write_was()),
        }
    }

    /// Reads everything a shared collection holds, each with the epoch it is sealed under, page by
    /// page, for at most `pages` pages.
    ///
    /// A collection keeps its copies of refused writes until a person chooses about them, so how
    /// many there are has no bound this client can state, and every page carries each copy's
    /// content. So a read stops at the budget the caller gives it and says where it stopped:
    /// [`Inventory::resume_after`] is the cursor the next call continues from, given the inventory
    /// this one returned as `resume`, and a read that reached the end names none. Every page after
    /// the first names the objects already read, so their content is not sent again. A cursor that
    /// does not move on is an answer this client does not follow.
    ///
    /// # Errors
    ///
    /// As [`Self::compare_shared`]. A collection that does not list this installation is `None`.
    pub async fn inventory(
        &self,
        collection: &CollectionRef,
        resume: Option<Inventory>,
        pages: NonZeroUsize,
    ) -> Result<Option<Inventory>> {
        // The history the pages already read were in, which every page read from here is held to.
        let mut history = resume.as_ref().map(|inventory| inventory.recovery);
        let (mut inventory, mut after) = match resume {
            // A read that already reached the end has nothing to continue.
            Some(inventory) if inventory.is_complete() => return Ok(Some(inventory)),
            Some(inventory) => {
                let after = inventory.resume_after;
                (inventory, after)
            }
            None => (Inventory::default(), None),
        };
        for _ in 0..pages.get() {
            let known = inventory
                .objects
                .iter()
                .filter_map(|object| {
                    object.position.revision.0.map(|revision| KnownRevision {
                        object_id: object.object_id,
                        revision,
                    })
                })
                .collect();
            let request =
                self.compare_body(Address::shared(collection), None, true, after, known)?;
            let answer: CompareAnswer = match reply(self.ask(&request, None).await?, false)? {
                Reply::Data(data) => read(data, "what a comparison answered")?,
                Reply::Absent => return Ok(None),
                Reply::Retired(_) => return Err(retired_where_no_write_was()),
            };
            let recovery = answer.recovery_id.0;
            one_history(&mut history, recovery)?;
            let head = head_of(answer.key_epoch, answer.key_revision, recovery)?;
            inventory.recovery = recovery;
            inventory.objects = answer
                .revisions
                .iter()
                .map(|position| {
                    Ok(InventoryObject {
                        object_id: position.object_id,
                        position: SyncPosition::at(
                            position.write_sequence.get(),
                            position.revision,
                            recovery,
                        ),
                        epoch: epoch_in(head, position.key_epoch)?,
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            inventory.head = head;
            for copy in &answer.conflicts {
                let behind = after.is_some_and(|cursor| copy.sequence.get() <= cursor)
                    || inventory
                        .copies
                        .last()
                        .is_some_and(|last| copy.sequence.get() <= last.sequence);
                if behind {
                    return Err(contrary("a page of copies that does not follow the cursor"));
                }
                inventory.copies.push(InventoryCopy {
                    sequence: copy.sequence.get(),
                    conflict_id: copy.conflict_id,
                    object_id: copy.object_id,
                    kind: copy.kind,
                    epoch: epoch_in(head, copy.key_epoch)?,
                });
            }
            let next = answer.next_conflicts_after_sequence.get();
            if !answer.more_conflicts {
                inventory.resume_after = None;
                return Ok(Some(inventory));
            }
            if answer.conflicts.is_empty() || after.is_some_and(|cursor| next <= cursor) {
                return Err(contrary(
                    "more copies behind a cursor that does not move on",
                ));
            }
            after = Some(next);
        }
        // The budget is spent before the end: the next call continues from here.
        inventory.resume_after = after;
        Ok(Some(inventory))
    }

    /// Lists the shared collections whose newest key record names this installation, page by page
    /// to the end.
    ///
    /// The listing is the service's index, which each collection brings up to date after it keeps
    /// a record: it can be behind, it admits nobody, and a device reads the records themselves
    /// before it trusts one.
    ///
    /// # Errors
    ///
    /// Returns an error when the service refuses the listing, when a cursor does not move on, and
    /// when more than [`MAX_MEMBERSHIPS_READ`] collections come back.
    pub async fn memberships(&self) -> Result<Vec<MembershipListing>> {
        let mut listed: Vec<MembershipListing> = Vec::new();
        let mut after: Option<String> = None;
        loop {
            let request = SyncRequest::Memberships(MembershipsBody {
                after: after.clone(),
            });
            let answer: MembershipsAnswer = read(
                self.ask(&request, None).await?.data()?,
                "what a membership listing answered",
            )?;
            for entry in &answer.memberships {
                a_counter("a key record revision", entry.key_revision.get())?;
                a_counter("a key epoch", entry.key_epoch.get())?;
                listed.push(MembershipListing {
                    collection: CollectionRef {
                        home: entry.home,
                        collection_id: entry.collection_id,
                    },
                    head: KeyHead {
                        epoch: entry.key_epoch.get(),
                        revision: entry.key_revision.get(),
                        recovery: entry.recovery_id.0,
                    },
                });
            }
            if listed.len() > MAX_MEMBERSHIPS_READ {
                return Err(contrary("more shared collections than one listing follows"));
            }
            if !answer.more {
                return Ok(listed);
            }
            let next = answer.next_after.0.ok_or_else(|| {
                contrary("more shared collections with no cursor to continue from")
            })?;
            if answer.memberships.is_empty()
                || after
                    .as_deref()
                    .is_some_and(|cursor| next.as_str() <= cursor)
            {
                return Err(contrary(
                    "more shared collections behind a cursor that does not move on",
                ));
            }
            after = Some(next);
        }
    }

    /* ---------------------------------------------------------------------- */
    /* One call                                                                */
    /* ---------------------------------------------------------------------- */

    /// Sends one request, signed at the instant the caller states or now, and returns what was
    /// answered, a refusal included.
    async fn ask(&self, request: &SyncRequest<'_>, signed_at_ms: Option<u64>) -> Result<Answer> {
        match signed_at_ms {
            Some(signed_at_ms) => {
                self.call
                    .answer_at(
                        SYNC_EXCHANGE_PATH,
                        Method::SyncCompareExchange,
                        request,
                        MAX_SYNC_REQUEST_BYTES,
                        signed_at_ms,
                    )
                    .await
            }
            None => {
                self.call
                    .answer(
                        SYNC_EXCHANGE_PATH,
                        Method::SyncCompareExchange,
                        request,
                        MAX_SYNC_REQUEST_BYTES,
                    )
                    .await
            }
        }
    }

    /// The request one comparison makes.
    #[expect(
        clippy::unused_self,
        reason = "a method so each request is built beside the calls that send it"
    )]
    fn compare_body(
        &self,
        address: Address,
        kind: Option<SyncObjectKind>,
        with_copies: bool,
        after: Option<u64>,
        known: Vec<KnownRevision>,
    ) -> Result<SyncRequest<'static>> {
        if let Some(cursor) = after {
            a_counter("a cursor", cursor)?;
        }
        Ok(SyncRequest::Compare(CompareBody {
            collection_id: address.collection_id,
            home: address.home,
            kind,
            known,
            with_conflicts: with_copies,
            conflicts_after_sequence: after.map(U64::new),
        }))
    }

    /* ---------------------------------------------------------------------- */
    /* A collection only its home writes                                       */
    /* ---------------------------------------------------------------------- */

    /// One exchange: the write, under the identity and the instant the caller states.
    async fn exchange(
        &self,
        collection: &str,
        request_id: Uuid,
        signed_at_ms: u64,
        expected: Option<SyncPosition>,
        ciphertext: &[u8],
    ) -> Result<SyncExchanged> {
        let named = Collection::named(collection)?;
        let object = sealed_object(ciphertext)?;
        let request = exchange_body(
            Address::own(named),
            named,
            None,
            request_id,
            expected,
            &object,
        );
        let answer = self.ask(&request, Some(signed_at_ms)).await?;
        if signed_before_cutoff(&answer) {
            return Ok(SyncExchanged::SignedBeforeCutoff);
        }
        exchanged(
            read(answer.data()?, "what an exchange answered")?,
            named.object_id,
        )
    }

    /// One status query: what the service recorded about one request identity.
    async fn status(&self, collection: &str, request_id: Uuid) -> Result<SyncRequestStatus> {
        let named = Collection::named(collection)?;
        let request = SyncRequest::Status(StatusBody {
            collection_id: named.id,
            home: None,
            request_id,
        });
        let data = self.ask(&request, None).await?.data()?;
        let answer = status_answer(data, request_id, "what a status query answered")?;
        let recovery = answer.recovery_id.0;
        Ok(match answer.state {
            StatusState::Applied => SyncRequestStatus::Applied {
                position: recorded_position(&answer)?,
            },
            StatusState::Refused => SyncRequestStatus::Refused {
                retained: answer.conflict_id.0,
                recovery,
            },
            StatusState::Fenced => SyncRequestStatus::Fenced {
                never_ran: answer.never_ran,
                recovery,
            },
            StatusState::Unknown => SyncRequestStatus::Unknown { recovery },
            // A write that named no epoch cannot have named a retired one.
            StatusState::Retired => return Err(retired_where_no_epoch_was()),
        })
    }

    /// One fence: ends the request identity, naming the earliest and latest instant an attempt
    /// under it was signed at.
    async fn fence(
        &self,
        collection: &str,
        request_id: Uuid,
        first_signed_at_ms: u64,
        last_signed_at_ms: u64,
    ) -> Result<SyncRequestFence> {
        let named = Collection::named(collection)?;
        let request = fence_body(
            Address::own(named),
            request_id,
            first_signed_at_ms,
            last_signed_at_ms,
        )?;
        let data = self.ask(&request, None).await?.data()?;
        let answer = status_answer(data, request_id, "what a fence answered")?;
        let recovery = answer.recovery_id.0;
        Ok(match answer.state {
            StatusState::Applied => SyncRequestFence::Applied {
                position: recorded_position(&answer)?,
            },
            StatusState::Refused => SyncRequestFence::Refused {
                retained: answer.conflict_id.0,
                recovery,
            },
            StatusState::Fenced => SyncRequestFence::Fenced {
                never_ran: answer.never_ran,
                recovery,
            },
            // A fence either finds an outcome or makes one, so the service never answers one with
            // "unknown". Inventing an answer for it here would be this client deciding whether a
            // request ended, which is the one thing a fence exists to have the service decide.
            StatusState::Unknown => return Err(fence_answered_unknown()),
            StatusState::Retired => return Err(retired_where_no_epoch_was()),
        })
    }

    /// One resolution: drops the copy one refusal kept.
    async fn drop_copy(&self, collection: &str, retained: SyncConflictId) -> Result<bool> {
        let named = Collection::named(collection)?;
        let request = resolve_body(Address::own(named), retained);
        dropped(self.ask(&request, None).await?.data()?)
    }

    /// One fetch: the object a collection holds and where it stands, or the history of a collection
    /// that holds none.
    async fn held(&self, collection: &str) -> Result<SyncFetched> {
        let named = Collection::named(collection)?;
        // A read for one kind, which is the whole of what section 20 lets the service know about
        // an object it cannot read.
        let request = self.compare_body(
            Address::own(named),
            Some(named.kind),
            false,
            None,
            Vec::new(),
        )?;
        let data = self.ask(&request, None).await?.data()?;
        let comparison = comparison(read(data, "what a comparison answered")?)?;
        let recovery = comparison.recovery;
        let Some(held) = comparison
            .objects
            .into_iter()
            .find(|held| held.object_id == named.object_id)
        else {
            // The comparison names its history even when it names no place, and an empty
            // collection is an answer about that history.
            return Ok(SyncFetched::Absent { recovery });
        };
        if held.kind != named.kind {
            return Err(contrary("a read for one kind with an object of another"));
        }
        Ok(SyncFetched::Held {
            position: held.position,
            ciphertext: held.ciphertext,
        })
    }

    /* ---------------------------------------------------------------------- */
    /* Key records                                                             */
    /* ---------------------------------------------------------------------- */

    /// One page of key records after a revision, or nothing when the collection does not list this
    /// installation.
    async fn keys_page(
        &self,
        collection: &CollectionRef,
        after: u64,
    ) -> Result<Option<KeysAnswer>> {
        a_counter("a key record revision", after)?;
        let request = SyncRequest::Keys(KeysBody {
            collection_id: collection.collection_id,
            home: Some(collection.home),
            after_revision: U64::new(after),
        });
        match reply(self.ask(&request, None).await?, false)? {
            Reply::Data(data) => Ok(Some(read(data, "what a read of key records answered")?)),
            Reply::Absent => Ok(None),
            Reply::Retired(_) => Err(retired_where_no_write_was()),
        }
    }

    /// Every key record after a revision, page by page to the newest.
    ///
    /// The records are passed on as the service answered them: whether they form a chain from the
    /// revision asked about is for the reader to establish, because a chain it cannot follow is an
    /// answer it acts on. Only the paging is held here, so a read ends: it follows a page only
    /// while the page moves the cursor on, and it stops at [`MAX_KEY_RECORDS_READ`] records.
    async fn read_records_after(
        &self,
        collection: &CollectionRef,
        after: u64,
    ) -> Result<KeyRecords> {
        let mut records: Vec<CollectionKeyRecord> = Vec::new();
        let mut cursor = after;
        // The history the first page was read in, which every later page is held to: a chain read
        // across a restore would join records of two histories.
        let mut history: Option<Option<SyncRecoveryId>> = None;
        loop {
            let Some(page) = self.keys_page(collection, cursor).await? else {
                return Ok(KeyRecords::Absent);
            };
            let recovery = page.recovery_id.0;
            one_history(&mut history, recovery)?;
            let last = page
                .records
                .last()
                .map(|record| record.payload.revision.get());
            records.extend(page.records);
            if records.len() > MAX_KEY_RECORDS_READ {
                return Err(contrary("more key records than one read follows"));
            }
            match last {
                Some(last) if page.more && last > cursor => cursor = last,
                // The newest was reached, or a page that does not move the cursor on: what was
                // answered is handed over, and the reader decides what it follows.
                _ => return Ok(KeyRecords::Records { records, recovery }),
            }
        }
    }

    /// The key record at one revision.
    async fn read_record_at(&self, collection: &CollectionRef, revision: u64) -> Result<RecordAt> {
        let after = revision
            .checked_sub(1)
            .ok_or_else(|| malformed("key record revisions count from one"))?;
        Ok(match self.keys_page(collection, after).await? {
            None => RecordAt::Absent,
            Some(page) => {
                let recovery = page.recovery_id.0;
                page.records
                    .into_iter()
                    .next()
                    .map_or(RecordAt::Missing { recovery }, |record| RecordAt::Record {
                        record,
                        recovery,
                    })
            }
        })
    }

    /// Offers the record that follows the collection's newest, under a request identity.
    async fn offer(
        &self,
        collection: &CollectionRef,
        request_id: Uuid,
        signed_at_ms: u64,
        record: &CollectionKeyRecord,
    ) -> Result<RekeyAnswer> {
        // The service admits a record only for the collection and the home the request names, only
        // one whose structure holds, and only counters it compares exactly; one it would refuse for
        // any of those never leaves this device.
        if record.payload.collection_id != collection.collection_id
            || record.payload.home != collection.home
        {
            return Err(malformed(
                "a key record is offered to the collection and home it names",
            ));
        }
        record.check_structure().map_err(|rule| {
            malformed(format!(
                "that key record is not one a service admits: {rule}"
            ))
        })?;
        a_counter("a key record revision", record.payload.revision.get())?;
        a_counter("a key epoch", record.payload.key_epoch.get())?;
        let request = SyncRequest::Rekey(RekeyBody {
            request_id,
            collection_id: collection.collection_id,
            home: Some(collection.home),
            record,
        });
        let answer: RekeyResult = read(
            self.ask(&request, Some(signed_at_ms)).await?.data()?,
            "what the offer of a key record answered",
        )?;
        let revision = answer.key_revision.get();
        let recovery = answer.recovery_id.0;
        Ok(match answer.state {
            RekeyState::Applied if revision == record.payload.revision.get() => {
                RekeyAnswer::Applied { revision, recovery }
            }
            RekeyState::Applied => {
                return Err(contrary(
                    "an applied key record at another revision than its own",
                ));
            }
            RekeyState::Refused => RekeyAnswer::Refused { revision, recovery },
        })
    }

    /// What the service recorded about one offer of a key record.
    async fn offer_status(
        &self,
        collection: &CollectionRef,
        request_id: Uuid,
    ) -> Result<RekeyStatus> {
        let request = SyncRequest::Status(StatusBody {
            collection_id: collection.collection_id,
            home: Some(collection.home),
            request_id,
        });
        let data = self.ask(&request, None).await?.data()?;
        let answer = status_answer(data, request_id, "what a status query answered")?;
        let recovery = answer.recovery_id.0;
        Ok(match offer_outcome(&answer)? {
            OfferOutcome::Unknown => RekeyStatus::Unknown { recovery },
            OfferOutcome::Applied(revision) => RekeyStatus::Applied { revision, recovery },
            OfferOutcome::Refused(revision) => RekeyStatus::Refused { revision, recovery },
            OfferOutcome::Fenced { never_ran } => RekeyStatus::Fenced {
                never_ran,
                recovery,
            },
        })
    }

    /// Ends one offer of a key record and says what became of it.
    async fn offer_fence(
        &self,
        collection: &CollectionRef,
        request_id: Uuid,
        first_signed_at_ms: u64,
        last_signed_at_ms: u64,
    ) -> Result<RekeyFence> {
        let request = fence_body(
            Address::shared(collection),
            request_id,
            first_signed_at_ms,
            last_signed_at_ms,
        )?;
        let data = self.ask(&request, None).await?.data()?;
        let answer = status_answer(data, request_id, "what a fence answered")?;
        let recovery = answer.recovery_id.0;
        Ok(match offer_outcome(&answer)? {
            OfferOutcome::Unknown => return Err(fence_answered_unknown()),
            OfferOutcome::Applied(revision) => RekeyFence::Applied { revision, recovery },
            OfferOutcome::Refused(revision) => RekeyFence::Refused { revision, recovery },
            OfferOutcome::Fenced { never_ran } => RekeyFence::Fenced {
                never_ran,
                recovery,
            },
        })
    }
}

impl SyncBackupService for ManagedSyncService {
    fn compare_exchange<'a>(
        &'a self,
        collection: &'a str,
        request_id: Uuid,
        signed_at_ms: u64,
        expected: Option<SyncPosition>,
        ciphertext: &'a [u8],
    ) -> ServiceFuture<'a, SyncExchanged> {
        Box::pin(self.exchange(collection, request_id, signed_at_ms, expected, ciphertext))
    }

    fn request_status<'a>(
        &'a self,
        collection: &'a str,
        request_id: Uuid,
    ) -> ServiceFuture<'a, SyncRequestStatus> {
        Box::pin(self.status(collection, request_id))
    }

    fn fence_request<'a>(
        &'a self,
        collection: &'a str,
        request_id: Uuid,
        first_signed_at_ms: u64,
        last_signed_at_ms: u64,
    ) -> ServiceFuture<'a, SyncRequestFence> {
        Box::pin(self.fence(
            collection,
            request_id,
            first_signed_at_ms,
            last_signed_at_ms,
        ))
    }

    fn fetch<'a>(&'a self, collection: &'a str) -> ServiceFuture<'a, SyncFetched> {
        Box::pin(self.held(collection))
    }

    fn resolve<'a>(
        &'a self,
        collection: &'a str,
        retained: SyncConflictId,
    ) -> ServiceFuture<'a, bool> {
        Box::pin(self.drop_copy(collection, retained))
    }
}

impl KeyRecordService for ManagedSyncService {
    fn records_after<'a>(
        &'a self,
        collection: &'a CollectionRef,
        after: u64,
    ) -> ServiceFuture<'a, KeyRecords> {
        Box::pin(self.read_records_after(collection, after))
    }

    fn record_at<'a>(
        &'a self,
        collection: &'a CollectionRef,
        revision: u64,
    ) -> ServiceFuture<'a, RecordAt> {
        Box::pin(self.read_record_at(collection, revision))
    }

    fn rekey<'a>(
        &'a self,
        collection: &'a CollectionRef,
        request_id: Uuid,
        signed_at_ms: u64,
        record: &'a CollectionKeyRecord,
    ) -> ServiceFuture<'a, RekeyAnswer> {
        Box::pin(self.offer(collection, request_id, signed_at_ms, record))
    }

    fn rekey_status<'a>(
        &'a self,
        collection: &'a CollectionRef,
        request_id: Uuid,
    ) -> ServiceFuture<'a, RekeyStatus> {
        Box::pin(self.offer_status(collection, request_id))
    }

    fn rekey_fence<'a>(
        &'a self,
        collection: &'a CollectionRef,
        request_id: Uuid,
        first_signed_at_ms: u64,
        last_signed_at_ms: u64,
    ) -> ServiceFuture<'a, RekeyFence> {
        Box::pin(self.offer_fence(
            collection,
            request_id,
            first_signed_at_ms,
            last_signed_at_ms,
        ))
    }
}

/* -------------------------------------------------------------------------- */
/* Requests                                                                    */
/* -------------------------------------------------------------------------- */

/// The request one exchange makes.
fn exchange_body<'a>(
    address: Address,
    named: Collection,
    key_epoch: Option<u64>,
    request_id: Uuid,
    expected: Option<SyncPosition>,
    object: &'a SealedSyncObject,
) -> SyncRequest<'a> {
    SyncRequest::Exchange(ExchangeBody {
        request_id,
        collection_id: address.collection_id,
        home: address.home,
        key_epoch: key_epoch.map(U64::new),
        kind: named.kind,
        object_id: named.object_id,
        // The comparison is about identity, so it names the revision and only the revision. No
        // position and a removal's position both name no object; the place in the order beside a
        // revision is this client's to compare answers by, and it never travels.
        expected_revision: expected.and_then(|position| position.revision.0),
        object,
    })
}

/// The request one fence makes, with its instants held to the rules the service reads them by.
fn fence_body(
    address: Address,
    request_id: Uuid,
    first_signed_at_ms: u64,
    last_signed_at_ms: u64,
) -> Result<SyncRequest<'static>> {
    a_counter("the earliest signing time", first_signed_at_ms)?;
    a_counter("the latest signing time", last_signed_at_ms)?;
    if first_signed_at_ms > last_signed_at_ms {
        return Err(malformed(
            "a fence names the earliest signing time no later than the latest",
        ));
    }
    Ok(SyncRequest::Fence(FenceBody {
        collection_id: address.collection_id,
        home: address.home,
        request_id,
        first_signed_at_ms: U64::new(first_signed_at_ms),
        last_signed_at_ms: U64::new(last_signed_at_ms),
    }))
}

/// The request one resolution makes.
fn resolve_body(address: Address, retained: SyncConflictId) -> SyncRequest<'static> {
    SyncRequest::Resolve(ResolveBody {
        collection_id: address.collection_id,
        home: address.home,
        conflict_ids: vec![retained],
    })
}

/* -------------------------------------------------------------------------- */
/* Answers                                                                     */
/* -------------------------------------------------------------------------- */

/// Reads the answer to a request about a shared collection, taking its two answering refusals as
/// answers.
///
/// `KEY_EPOCH_RETIRED` is an answer only to a write, so `write` says whether one was sent; any
/// other refusal is the error the service named.
fn reply(answer: Answer, write: bool) -> Result<Reply<serde_json::Value>> {
    match answer {
        Answer::Data(data) => Ok(Reply::Data(data)),
        Answer::Refused(refusal) => match refusal.code() {
            "COLLECTION_ABSENT" => Ok(Reply::Absent),
            "KEY_EPOCH_RETIRED" if write => Ok(Reply::Retired(retired_head(&refusal)?)),
            "KEY_EPOCH_RETIRED" => Err(retired_where_no_write_was()),
            _ => Err(refusal.into_error()),
        },
    }
}

/// Whether an answer to a write is the refusal of an attempt signed before the collection's
/// cutoff, which is an answer about that attempt rather than an error.
fn signed_before_cutoff(answer: &Answer) -> bool {
    matches!(answer, Answer::Refused(refusal) if refusal.code() == "SIGNED_BEFORE_CUTOFF")
}

/// The collection's epoch and revision a retired refusal names, both of which it must name, once.
fn retired_head(refusal: &Refusal) -> Result<KeyHead> {
    #[derive(Deserialize)]
    struct Named {
        key_epoch: U64,
        key_revision: U64,
        recovery_id: Nullable<SyncRecoveryId>,
    }
    let named: Named = refusal.members("what a retired epoch named")?;
    Ok(KeyHead {
        epoch: named.key_epoch.get(),
        revision: named.key_revision.get(),
        recovery: named.recovery_id.0,
    })
}

/// Reads one answer as the shape the contract gives it.
fn read<T: for<'de> Deserialize<'de>>(data: serde_json::Value, what: &str) -> Result<T> {
    serde_json::from_value(data).map_err(|error| unreadable_answer(what, &error))
}

/// What one exchange did, as the service stated it.
fn exchanged(answer: ExchangeAnswer, object_id: SyncObjectId) -> Result<SyncExchanged> {
    let recovery = answer.recovery_id;
    Ok(match answer.state {
        // Where the service put the write, as it stated it. A removal's place, and a place of
        // nought, come back as the service said them rather than as something a caller would
        // rather read: a caller that publishes writes declines both, and that is its decision.
        ExchangeState::Written | ExchangeState::Removed => SyncExchanged::Applied {
            position: SyncPosition {
                write_sequence: answer.current_write_sequence.get(),
                revision: answer.current_revision,
                recovery,
            },
        },
        ExchangeState::Conflict => SyncExchanged::Refused {
            retained: match answer.conflict.0 {
                // A copy is of the refused write, so it is of this object. One naming another is a
                // copy a resolution of this object must never be pointed at.
                Some(copy) if copy.object_id != object_id => {
                    return Err(contrary("a refusal whose copy is of another object"));
                }
                Some(copy) => Some(copy.conflict_id),
                None => None,
            },
            // Where the object stood: the write that won, a removal's place with no revision, or
            // nought for an object the collection had never held, which is no place at all.
            current: match (
                answer.current_revision.0,
                answer.current_write_sequence.get(),
            ) {
                (Some(revision), write_sequence) => {
                    Some(SyncPosition::at(write_sequence, revision, recovery.0))
                }
                (None, 0) => None,
                (None, write_sequence) => {
                    Some(SyncPosition::removed_at(write_sequence, recovery.0))
                }
            },
            recovery: recovery.0,
        },
    })
}

/// What one resolution did: dropped the one copy it named, or found it already gone.
fn dropped(data: serde_json::Value) -> Result<bool> {
    let answer: ResolveAnswer = read(data, "what a resolution answered")?;
    // One copy was named, so one was dropped or none was: a copy nobody holds any more is already
    // resolved, which the service answers as nought rather than as a refusal.
    match answer.resolved.get() {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(contrary(
            "a resolution of one copy that dropped more than one",
        )),
    }
}

/// What one comparison found, as the service stated it.
fn comparison(answer: CompareAnswer) -> Result<SyncComparison> {
    let recovery = answer.recovery_id.0;
    let head = head_of(answer.key_epoch, answer.key_revision, recovery)?;
    let objects = answer
        .changed
        .into_iter()
        .map(|held| {
            Ok(SyncHeldObject {
                object_id: held.object_id,
                kind: held.kind,
                position: SyncPosition::at(held.write_sequence.get(), held.revision, recovery),
                epoch: epoch_in(head, held.key_epoch)?,
                ciphertext: encoded(&held.object)?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let removed = answer
        .removed
        .iter()
        .map(|removed| SyncRemoved {
            object_id: removed.object_id,
            // A removal takes a place in the object's order; nought is an object never held.
            position: (removed.write_sequence.get() != 0)
                .then(|| SyncPosition::removed_at(removed.write_sequence.get(), recovery)),
        })
        .collect();
    let copies = answer
        .conflicts
        .into_iter()
        .map(|copy| {
            Ok(SyncHeldCopy {
                sequence: copy.sequence.get(),
                conflict_id: copy.conflict_id,
                object_id: copy.object_id,
                kind: copy.kind,
                expected_revision: copy.expected_revision,
                current: copy_position(
                    &copy.current_revision,
                    copy.current_write_sequence,
                    recovery,
                )?,
                epoch: epoch_in(head, copy.key_epoch)?,
                ciphertext: encoded(&copy.object)?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(SyncComparison {
        objects,
        removed,
        copies,
        more_copies: answer.more_conflicts,
        next_copies_after: answer.next_conflicts_after_sequence.get(),
        head,
        recovery,
        stored: answer.stored,
    })
}

/// Where the collection's key records stood, as an answer named it: both the epoch and the
/// revision, or neither.
fn head_of(
    key_epoch: Option<U64>,
    key_revision: Option<U64>,
    recovery: Option<SyncRecoveryId>,
) -> Result<Option<KeyHead>> {
    match (key_epoch, key_revision) {
        (Some(epoch), Some(revision)) => Ok(Some(KeyHead {
            epoch: epoch.get(),
            revision: revision.get(),
            recovery,
        })),
        (None, None) => Ok(None),
        _ => Err(contrary(
            "a key epoch without its record revision, or the other way round",
        )),
    }
}

/// The epoch one object or copy is sealed under, which is named exactly when the collection has a
/// key record, and never above the collection's own.
fn epoch_in(head: Option<KeyHead>, epoch: Option<U64>) -> Result<Option<u64>> {
    match (head, epoch) {
        (Some(head), Some(epoch)) if epoch.get() <= head.epoch => Ok(Some(epoch.get())),
        (Some(_), Some(_)) => Err(contrary(
            "an object sealed under an epoch after the collection's",
        )),
        (None, None) => Ok(None),
        (Some(_), None) => Err(contrary(
            "an object with no epoch in a collection that has one",
        )),
        (None, Some(_)) => Err(contrary(
            "an object with an epoch in a collection that has none",
        )),
    }
}

/// What a status query or a fence found about a write's identity in a shared collection.
enum WriteOutcome {
    /// Applied, leaving the object at this position.
    Applied(SyncPosition),
    /// Refused, with the copy the service kept when it kept one.
    Refused(Option<SyncConflictId>),
    /// Fenced before it ran.
    Fenced {
        /// Whether the service also established that it never ran.
        never_ran: bool,
    },
    /// No receipt is held for it.
    Unknown,
    /// Refused for naming a retired epoch; the receipt names the collection's head.
    Retired(KeyHead),
}

/// Reads what a status query or a fence answered about a write's identity, with the head its
/// receipt named.
///
/// In a shared collection one identity is one name whichever member used it and whatever it
/// carried, so the outcome is read beside the state and must be one the state is answered as. A
/// write's identity answers only a write's outcomes: one that names the offer of a key record is
/// an answer about another request.
fn write_outcome(answer: &StatusAnswer) -> Result<(WriteOutcome, Option<KeyHead>)> {
    let head = head_of(answer.key_epoch, answer.key_revision, answer.recovery_id.0)?;
    let outcome = match consistent_outcome(answer)? {
        None => WriteOutcome::Unknown,
        Some(ReceiptOutcome::Written | ReceiptOutcome::Removed) => {
            WriteOutcome::Applied(recorded_position(answer)?)
        }
        Some(ReceiptOutcome::Conflict) => WriteOutcome::Refused(answer.conflict_id.0),
        Some(ReceiptOutcome::Fenced) => WriteOutcome::Fenced {
            never_ran: answer.never_ran,
        },
        Some(ReceiptOutcome::Retired) => WriteOutcome::Retired(head.ok_or_else(|| {
            contrary("a retired write whose receipt names no epoch and revision")
        })?),
        Some(ReceiptOutcome::Rekeyed | ReceiptOutcome::RekeyRefused) => {
            return Err(contrary(
                "an answer about the offer of a key record for a write's identity",
            ));
        }
    };
    Ok((outcome, head))
}

/// What a status query or a fence found about the identity of a key record offer.
enum OfferOutcome {
    /// Applied: the record is the collection's at this revision.
    Applied(u64),
    /// Refused; the collection held this revision.
    Refused(u64),
    /// Fenced before it ran.
    Fenced {
        /// Whether the service also established that it never ran.
        never_ran: bool,
    },
    /// No receipt is held for it.
    Unknown,
}

/// Reads what a status query or a fence answered about the identity of a key record offer.
///
/// An offer's identity answers only an offer's outcomes and a fence: one that names a write's is
/// an answer about another request.
fn offer_outcome(answer: &StatusAnswer) -> Result<OfferOutcome> {
    let revision = || {
        answer
            .key_revision
            .map(U64::get)
            .ok_or_else(|| contrary("an answer about a key record offer that names no revision"))
    };
    Ok(match consistent_outcome(answer)? {
        None => OfferOutcome::Unknown,
        Some(ReceiptOutcome::Rekeyed) => OfferOutcome::Applied(revision()?),
        Some(ReceiptOutcome::RekeyRefused) => OfferOutcome::Refused(revision()?),
        Some(ReceiptOutcome::Fenced) => OfferOutcome::Fenced {
            never_ran: answer.never_ran,
        },
        Some(
            ReceiptOutcome::Written
            | ReceiptOutcome::Removed
            | ReceiptOutcome::Conflict
            | ReceiptOutcome::Retired,
        ) => {
            return Err(contrary(
                "an answer about a write for the identity of a key record offer",
            ));
        }
    })
}

/// The receipt's outcome, which must be the one the state it is answered as comes from.
fn consistent_outcome(answer: &StatusAnswer) -> Result<Option<ReceiptOutcome>> {
    match (answer.outcome.0, answer.state) {
        (None, StatusState::Unknown) => Ok(None),
        (Some(outcome), state) if outcome.state() == state => Ok(Some(outcome)),
        _ => Err(contrary(
            "a request's state that is not the one its recorded outcome is answered as",
        )),
    }
}

/// Reads the bytes a caller asked to publish as the sealed object they are, and holds that object
/// to every rule the service checks without a key.
///
/// Refused here rather than sent, so a caller is told which rule the object broke and nothing
/// leaves the device. The bytes are decoded, never re-sealed: what travels is the object the
/// caller's sealer made, field for field.
fn sealed_object(ciphertext: &[u8]) -> Result<SealedSyncObject> {
    let object: SealedSyncObject =
        kr_cbor::from_canonical_slice(ciphertext, &kr_cbor::Limits::DEFAULT)
            .map_err(|_| malformed("what was handed over to publish is not a sealed object"))?;
    // The rule broken, which names a bucket and a length and nothing that was sealed.
    object.check_structure().map_err(|rule| {
        malformed(format!(
            "that sealed object is not one a service admits: {rule}"
        ))
    })?;
    Ok(object)
}

/// The encoding a sealer opens, of one sealed object a comparison answered with.
///
/// The failure names nothing of the object, which is sealed content.
fn encoded(object: &SealedSyncObject) -> Result<Vec<u8>> {
    kr_cbor::to_canonical_vec(object)
        .map_err(|_| contrary("a sealed object this client cannot encode as one"))
}

/// Where the object stood when a copy was kept, as the service wrote it down.
///
/// The service writes a place in the order beside a revision, and empty text where the object held
/// no revision: a removal's place, or nought for an object the collection had never held, which is
/// no position at all.
fn copy_position(
    current_revision: &str,
    write_sequence: U64,
    recovery: Option<SyncRecoveryId>,
) -> Result<Option<SyncPosition>> {
    let write_sequence = write_sequence.get();
    if current_revision.is_empty() {
        return Ok(
            (write_sequence != 0).then(|| SyncPosition::removed_at(write_sequence, recovery))
        );
    }
    let revision = current_revision
        .parse::<Uuid>()
        .map_err(|_| contrary("a copy whose object stood at a revision that is not one"))?;
    Ok(Some(SyncPosition::at(
        write_sequence,
        SyncRevision::new(revision),
        recovery,
    )))
}

/// Reads what a status query or a fence answered, and holds it to the identity asked about.
fn status_answer(data: serde_json::Value, request_id: Uuid, what: &str) -> Result<StatusAnswer> {
    let answer: StatusAnswer = read(data, what)?;
    if answer.request_id != request_id {
        return Err(contrary("an answer about another request identity"));
    }
    Ok(answer)
}

/// The position a receipt recorded for an applied write, as the service stated it.
fn recorded_position(answer: &StatusAnswer) -> Result<SyncPosition> {
    let write_sequence = answer
        .current_write_sequence
        .as_ref()
        .ok_or_else(|| contrary("an applied request with no place in the order"))?;
    Ok(SyncPosition {
        write_sequence: write_sequence.get(),
        revision: answer.current_revision,
        recovery: answer.recovery_id,
    })
}

/// Holds every page of one read to the history the first page was read in.
///
/// Places in a collection's order compare only under one recovery, so a read that met a restore
/// between two pages would fold places from two histories into one answer. Such a read is declined
/// as an answer this client does not follow, and asking again reads one history whole.
fn one_history(
    history: &mut Option<Option<SyncRecoveryId>>,
    page: Option<SyncRecoveryId>,
) -> Result<()> {
    match history {
        None => {
            *history = Some(page);
            Ok(())
        }
        Some(first) if *first == page => Ok(()),
        Some(_) => Err(contrary(
            "pages of one read from two histories of the collection",
        )),
    }
}

/// Refuses a counter the service could not compare exactly, before anything is sent.
fn a_counter(what: &str, value: u64) -> Result<()> {
    if value > MAX_SYNC_COUNTER {
        return Err(malformed(format!(
            "{what} is at most {MAX_SYNC_COUNTER} and this one is {value}"
        )));
    }
    Ok(())
}

/// A fence either finds an outcome or makes one, so it is never answered `unknown`.
fn fence_answered_unknown() -> ClientError {
    contrary("a fence with \"unknown\", which a fence never answers")
}

/// A retired epoch is an answer only to a write that named one.
fn retired_where_no_write_was() -> ClientError {
    contrary("a retired epoch to a request that wrote nothing")
}

/// A write to a collection only its home writes names no epoch, so none of it can be retired.
fn retired_where_no_epoch_was() -> ClientError {
    contrary("a retired epoch about a write that named none")
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
mod tests;
