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
//! # One route, five members
//!
//! `sync.compare_exchange` is one signed method at one path, and a request asks for exactly one of
//! five things: an exchange, a comparison, a resolution, the status of a request identity, or a
//! fence of one. Each is signed under the same credential.
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
//! A collection belongs to the installation whose key signs for it, because the service derives it
//! from that key. Two installations therefore never reach one collection, whatever they name.
//!
//! # What it keeps
//!
//! Nothing. Every ordering fact is the service's: the position an exchange answers, what a receipt
//! recorded, whether a fenced request ever ran. This passes each of them through as the service
//! stated it, and an answer that does not state one is an error rather than a guess. A write is
//! signed at the instant its caller recorded, never at a reading taken here, and a request's bytes
//! are a function of what the caller passed and nothing else, so the same attempt made twice is the
//! same document twice: the service answers a retry from its receipt only when nothing its digest
//! covers has changed.
//!
//! # What an answer may carry
//!
//! Every member of an answer this client reads is required, and read as the type the contract
//! gives it: an answer missing one is an error rather than a default. A member it does not read is
//! let through. The service and this client are deployed on their own schedules, so the service can
//! add a member before this client knows of it, and refusing a whole answer over that would leave
//! a write the service had applied unsettled until this client caught up. A sealed object is the
//! exception and stays a closed schema, because what is stored has to be exactly what was sealed.
//!
//! # What is never rendered
//!
//! An exchange carries a sealed object and a comparison answers with them. Under this module's
//! rule the types that hold one write their own [`std::fmt::Debug`]: what the object is, its
//! declared size and where it stands, and nothing sealed.

use std::fmt;
use std::sync::Arc;

use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::ids::{DraftId, SyncCollectionId, SyncConflictId, SyncObjectId};
use kr_protocol::method::Method;
use kr_protocol::scalars::{Nullable, U64, Uuid};
use kr_protocol::service::GatewayOrigin;
use kr_protocol::sync::{SealedSyncObject, SyncObjectKind};
use serde::{Deserialize, Serialize};

use super::relay::{ServiceHttp, ServiceSigner};
use super::signed::{SignedService, malformed, unreadable_answer};
use super::{
    ServiceFuture, SyncBackupService, SyncExchanged, SyncPosition, SyncRequestFence,
    SyncRequestStatus, SyncRevision,
};
use crate::error::{ClientError, Result};

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
        let identity: Uuid = identity.parse().map_err(|_| refused())?;
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
}

/// Write one object, if the service still holds the revision the writer expects.
#[derive(Serialize)]
struct ExchangeBody<'a> {
    request_id: Uuid,
    collection_id: SyncCollectionId,
    kind: SyncObjectKind,
    object_id: SyncObjectId,
    /// The revision this write replaces, or null when it names no object.
    ///
    /// Present and null rather than absent, which is the shape the service's contract declares.
    expected_revision: Option<SyncRevision>,
    object: &'a SealedSyncObject,
}

impl fmt::Debug for ExchangeBody<'_> {
    /// What the object is, how large it declares itself and whether the write names a revision.
    /// Never the ciphertext or the nonce.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExchangeBody")
            .field("kind", &self.kind)
            .field("size_bucket_bytes", &self.object.size_bucket_bytes)
            .field("expects_an_object", &self.expected_revision.is_some())
            .finish_non_exhaustive()
    }
}

/// Read what the collection holds, and its copies when they are asked for.
#[derive(Debug, Serialize)]
struct CompareBody {
    collection_id: SyncCollectionId,
    #[serde(skip_serializing_if = "Option::is_none")]
    kind: Option<SyncObjectKind>,
    with_conflicts: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    conflicts_after_sequence: Option<U64>,
}

/// Drop copies the person has chosen about.
#[derive(Debug, Serialize)]
struct ResolveBody {
    collection_id: SyncCollectionId,
    conflict_ids: Vec<SyncConflictId>,
}

/// Ask what the service recorded about one request identity.
#[derive(Debug, Serialize)]
struct StatusBody {
    collection_id: SyncCollectionId,
    request_id: Uuid,
}

/// End one request identity, naming the instants its attempts were signed at.
#[derive(Debug, Serialize)]
struct FenceBody {
    collection_id: SyncCollectionId,
    request_id: Uuid,
    first_signed_at_ms: U64,
    last_signed_at_ms: U64,
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
    Unknown,
}

/// What a receipt recorded.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ReceiptOutcome {
    Written,
    Removed,
    Conflict,
    Fenced,
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
    #[expect(dead_code, reason = "held to its schema and never read")]
    outcome: Nullable<ReceiptOutcome>,
    #[expect(dead_code, reason = "held to its schema and never read")]
    record: Nullable<ObjectSummary>,
    current_revision: Nullable<SyncRevision>,
    current_write_sequence: Nullable<U64>,
    conflict_id: Nullable<SyncConflictId>,
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
    object: SealedSyncObject,
    #[expect(dead_code, reason = "held to its schema and never read")]
    updated_at: String,
}

/// One object a reader named that the collection no longer holds.
#[derive(Deserialize)]
#[expect(dead_code, reason = "held to its schema and never read")]
struct RemovedObject {
    object_id: SyncObjectId,
    write_sequence: U64,
}

/// Where one object stands.
#[derive(Deserialize)]
#[expect(dead_code, reason = "held to its schema and never read")]
struct ObjectPosition {
    object_id: SyncObjectId,
    revision: SyncRevision,
    write_sequence: U64,
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
    object: SealedSyncObject,
    #[expect(dead_code, reason = "held to its schema and never read")]
    recorded_at: String,
}

/// What `sync.compare_exchange` answers for a comparison.
#[derive(Deserialize)]
struct CompareAnswer {
    changed: Vec<ObjectRecord>,
    #[expect(dead_code, reason = "held to its schema and never read")]
    removed: Vec<RemovedObject>,
    #[expect(dead_code, reason = "held to its schema and never read")]
    revisions: Vec<ObjectPosition>,
    conflicts: Vec<ConflictRecord>,
    next_conflicts_after_sequence: U64,
    more_conflicts: bool,
    stored: SyncUsage,
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
    /// The sealed object, in canonical KR-CBOR-1, which is what a sealer opens.
    pub ciphertext: Vec<u8>,
}

impl fmt::Debug for SyncHeldObject {
    /// What the object is and where it stands. Never the sealed object.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SyncHeldObject")
            .field("object_id", &self.object_id)
            .field("kind", &self.kind)
            .field("position", &self.position)
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
    /// The refused write's sealed object, in canonical KR-CBOR-1, which is what a sealer opens.
    pub ciphertext: Vec<u8>,
}

impl fmt::Debug for SyncHeldCopy {
    /// Which copy it is, what it is about and where the object stood. Never the sealed object.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SyncHeldCopy")
            .field("sequence", &self.sequence)
            .field("conflict_id", &self.conflict_id)
            .field("object_id", &self.object_id)
            .field("kind", &self.kind)
            .field("current", &self.current)
            .finish_non_exhaustive()
    }
}

/// What one comparison found in a collection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyncComparison {
    /// The objects the collection holds.
    pub objects: Vec<SyncHeldObject>,
    /// The copies waiting for a choice, when they were asked for, in the order they were kept.
    pub copies: Vec<SyncHeldCopy>,
    /// Whether more copies were waiting than this page carried.
    pub more_copies: bool,
    /// The cursor to read the next page of copies from.
    pub next_copies_after: u64,
    /// How the collection stands.
    pub stored: SyncUsage,
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
    /// every collection a request reaches from the key that signed it.
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
        self.comparison(named, None, with_copies, after).await
    }

    /// One comparison of one collection.
    async fn comparison(
        &self,
        collection: Collection,
        kind: Option<SyncObjectKind>,
        with_copies: bool,
        after: Option<u64>,
    ) -> Result<SyncComparison> {
        if let Some(cursor) = after {
            a_counter("a cursor", cursor)?;
        }
        let data = self
            .call
            .call(
                SYNC_EXCHANGE_PATH,
                Method::SyncCompareExchange,
                &SyncRequest::Compare(CompareBody {
                    collection_id: collection.id,
                    kind,
                    with_conflicts: with_copies,
                    conflicts_after_sequence: after.map(U64::new),
                }),
                MAX_SYNC_REQUEST_BYTES,
            )
            .await?;
        let answer: CompareAnswer = serde_json::from_value(data)
            .map_err(|error| unreadable_answer("what a comparison answered", &error))?;

        let objects = answer
            .changed
            .into_iter()
            .map(|held| {
                Ok(SyncHeldObject {
                    object_id: held.object_id,
                    kind: held.kind,
                    position: SyncPosition::at(held.write_sequence.get(), held.revision),
                    ciphertext: encoded(&held.object)?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
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
                    current: copy_position(&copy.current_revision, copy.current_write_sequence)?,
                    ciphertext: encoded(&copy.object)?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(SyncComparison {
            objects,
            copies,
            more_copies: answer.more_conflicts,
            next_copies_after: answer.next_conflicts_after_sequence.get(),
            stored: answer.stored,
        })
    }

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
        let data = self
            .call
            .call_at(
                SYNC_EXCHANGE_PATH,
                Method::SyncCompareExchange,
                &SyncRequest::Exchange(ExchangeBody {
                    request_id,
                    collection_id: named.id,
                    kind: named.kind,
                    object_id: named.object_id,
                    // The comparison is about identity, so it names the revision and only the
                    // revision. No position and a removal's position both name no object; the
                    // place in the order beside a revision is this client's to compare answers by,
                    // and it never travels.
                    expected_revision: expected.and_then(|position| position.revision.0),
                    object: &object,
                }),
                MAX_SYNC_REQUEST_BYTES,
                signed_at_ms,
            )
            .await?;
        let answer: ExchangeAnswer = serde_json::from_value(data)
            .map_err(|error| unreadable_answer("what an exchange answered", &error))?;

        Ok(match answer.state {
            // Where the service put the write, as it stated it. A removal's place, and a place of
            // nought, come back as the service said them rather than as something a caller would
            // rather read: a caller that publishes writes declines both, and that is its decision.
            ExchangeState::Written | ExchangeState::Removed => SyncExchanged::Applied {
                position: SyncPosition {
                    write_sequence: answer.current_write_sequence.get(),
                    revision: answer.current_revision,
                },
            },
            ExchangeState::Conflict => SyncExchanged::Refused {
                retained: match answer.conflict.0 {
                    // A copy is of the refused write, so it is of this object. One naming another
                    // is a copy a resolution of this object must never be pointed at.
                    Some(copy) if copy.object_id != named.object_id => {
                        return Err(contrary("a refusal whose copy is of another object"));
                    }
                    Some(copy) => Some(copy.conflict_id),
                    None => None,
                },
            },
        })
    }

    /// One status query: what the service recorded about one request identity.
    async fn status(&self, collection: &str, request_id: Uuid) -> Result<SyncRequestStatus> {
        let named = Collection::named(collection)?;
        let data = self
            .call
            .call(
                SYNC_EXCHANGE_PATH,
                Method::SyncCompareExchange,
                &SyncRequest::Status(StatusBody {
                    collection_id: named.id,
                    request_id,
                }),
                MAX_SYNC_REQUEST_BYTES,
            )
            .await?;
        let answer = status_answer(data, request_id, "what a status query answered")?;
        Ok(match answer.state {
            StatusState::Applied => SyncRequestStatus::Applied {
                position: recorded_position(&answer)?,
            },
            StatusState::Refused => SyncRequestStatus::Refused {
                retained: answer.conflict_id.0,
            },
            StatusState::Fenced => SyncRequestStatus::Fenced {
                never_ran: answer.never_ran,
            },
            StatusState::Unknown => SyncRequestStatus::Unknown,
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
        a_counter("the earliest signing time", first_signed_at_ms)?;
        a_counter("the latest signing time", last_signed_at_ms)?;
        if first_signed_at_ms > last_signed_at_ms {
            return Err(malformed(
                "a fence names the earliest signing time no later than the latest",
            ));
        }
        let data = self
            .call
            .call(
                SYNC_EXCHANGE_PATH,
                Method::SyncCompareExchange,
                &SyncRequest::Fence(FenceBody {
                    collection_id: named.id,
                    request_id,
                    first_signed_at_ms: U64::new(first_signed_at_ms),
                    last_signed_at_ms: U64::new(last_signed_at_ms),
                }),
                MAX_SYNC_REQUEST_BYTES,
            )
            .await?;
        let answer = status_answer(data, request_id, "what a fence answered")?;
        Ok(match answer.state {
            StatusState::Applied => SyncRequestFence::Applied {
                position: recorded_position(&answer)?,
            },
            StatusState::Refused => SyncRequestFence::Refused {
                retained: answer.conflict_id.0,
            },
            StatusState::Fenced => SyncRequestFence::Fenced {
                never_ran: answer.never_ran,
            },
            // A fence either finds an outcome or makes one, so the service never answers one with
            // "unknown". Inventing an answer for it here would be this client deciding whether a
            // request ended, which is the one thing a fence exists to have the service decide.
            StatusState::Unknown => {
                return Err(contrary(
                    "a fence with \"unknown\", which a fence never answers",
                ));
            }
        })
    }

    /// One resolution: drops the copy one refusal kept.
    async fn drop_copy(&self, collection: &str, retained: SyncConflictId) -> Result<bool> {
        let named = Collection::named(collection)?;
        let data = self
            .call
            .call(
                SYNC_EXCHANGE_PATH,
                Method::SyncCompareExchange,
                &SyncRequest::Resolve(ResolveBody {
                    collection_id: named.id,
                    conflict_ids: vec![retained],
                }),
                MAX_SYNC_REQUEST_BYTES,
            )
            .await?;
        let answer: ResolveAnswer = serde_json::from_value(data)
            .map_err(|error| unreadable_answer("what a resolution answered", &error))?;
        // One copy was named, so one was dropped or none was: a copy nobody holds any more is
        // already resolved, which the service answers as nought rather than as a refusal.
        match answer.resolved.get() {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(contrary(
                "a resolution of one copy that dropped more than one",
            )),
        }
    }

    /// One fetch: the object a collection holds, and where it stands.
    async fn held(&self, collection: &str) -> Result<(SyncPosition, Vec<u8>)> {
        let named = Collection::named(collection)?;
        // A read for one kind, which is the whole of what section 20 lets the service know about
        // an object it cannot read.
        let comparison = self
            .comparison(named, Some(named.kind), false, None)
            .await?;
        let held = comparison
            .objects
            .into_iter()
            .find(|held| held.object_id == named.object_id)
            .ok_or_else(|| {
                ClientError::Host(ProtocolError::new(
                    ErrorCode::UnknownSession,
                    format!(
                        "the service holds no {} object in that collection",
                        named.kind
                    ),
                ))
            })?;
        if held.kind != named.kind {
            return Err(contrary("a read for one kind with an object of another"));
        }
        Ok((held.position, held.ciphertext))
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

    fn fetch<'a>(&'a self, collection: &'a str) -> ServiceFuture<'a, (SyncPosition, Vec<u8>)> {
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
fn copy_position(current_revision: &str, write_sequence: U64) -> Result<Option<SyncPosition>> {
    let write_sequence = write_sequence.get();
    if current_revision.is_empty() {
        return Ok((write_sequence != 0).then(|| SyncPosition::removed_at(write_sequence)));
    }
    let revision: Uuid = current_revision
        .parse()
        .map_err(|_| contrary("a copy whose object stood at a revision that is not one"))?;
    Ok(Some(SyncPosition::at(
        write_sequence,
        SyncRevision::new(revision),
    )))
}

/// Reads what a status query or a fence answered, and holds it to the identity asked about.
fn status_answer(data: serde_json::Value, request_id: Uuid, what: &str) -> Result<StatusAnswer> {
    let answer: StatusAnswer =
        serde_json::from_value(data).map_err(|error| unreadable_answer(what, &error))?;
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
    })
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
