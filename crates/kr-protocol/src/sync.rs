//! Encrypted settings, drafts and client positions, exchanged by compare and swap (section 20).
//!
//! A person's devices hold the same settings, the same unsent drafts and the same idea of where
//! they were. Keeping those in step needs somewhere to put them that is not one of the devices,
//! and section 20 says what that somewhere may know: the object is encrypted before it is stored,
//! it is written by compare and swap against a per-object revision, and a write that loses the
//! comparison is kept as a conflict copy for the person to choose from rather than resolved by
//! whichever clock was further ahead.
//!
//! # What a service may hold
//!
//! The kinds are closed. [`SyncObjectKind`] is settings, drafts and a client's own position, and
//! nothing else: section 20 gives host grants and revocation state one host authority, so they are
//! not synchronised objects and restoring a synchronised object can never reach them. A draft is a
//! draft: it is never an execution request, and nothing about this contract submits one.
//!
//! # Why a revision is not a counter
//!
//! [`crate::ids::SyncRevisionId`] is a fresh 128-bit value for every accepted write. A counter
//! would repeat: an object removed and written again would pass through revisions it has already
//! had, and a device holding an old revision of the earlier object would win a comparison it
//! should lose. A fresh value makes a revision name one write of one object and nothing else.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::ids::{SyncCollectionId, SyncConflictId, SyncObjectId, SyncRevisionId};
use crate::mailbox::{SEAL_OVERHEAD_BYTES, granularity_for_bucket};
use crate::scalars::{Bytes, Nonce192, Nullable, TimestampMs, U64};

/// What a synchronised object is.
///
/// The set is closed, and what it leaves out is as load bearing as what it holds. Host grants and
/// revocation state have one host authority (section 20), so there is no kind for them and a
/// restore of synchronised settings cannot overwrite them.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum SyncObjectKind {
    /// Application settings and preferences.
    Settings,
    /// An unsent draft prompt or answer.
    ///
    /// A draft is synchronised as a draft. Host reconnection does not submit it, and nothing in
    /// this contract turns one into an execution request.
    Draft,
    /// A client's own selection and position: which session it was looking at and where.
    ClientSelection,
}

impl SyncObjectKind {
    /// Every kind, in declaration order.
    pub const ALL: [Self; 3] = [Self::Settings, Self::Draft, Self::ClientSelection];

    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Settings => "settings",
            Self::Draft => "draft",
            Self::ClientSelection => "client_selection",
        }
    }
}

impl core::fmt::Display for SyncObjectKind {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The most plaintext one synchronised object may carry before padding, in bytes.
pub const MAX_SYNC_OBJECT_PLAINTEXT_BYTES: u64 = 64 * 1024;

/// The most objects one collection may hold.
pub const MAX_SYNC_OBJECTS_PER_COLLECTION: u64 = 256;

/// The most conflict copies one object retains.
///
/// A copy is kept so a person can choose; keeping an unbounded number of them would make a device
/// that never resolves them a way to spend somebody's allowance. The oldest is dropped first, and
/// the newest rejection is always the one that is kept.
pub const MAX_SYNC_CONFLICT_COPIES: u64 = 8;

/// One encrypted synchronised object as it is stored.
///
/// The service holds the nonce and the ciphertext and the declared bucket. It holds no plaintext
/// field of any kind: what an object is about is inside the encryption, and the kind beside it is
/// what the service needs to answer a read for that kind.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SealedSyncObject {
    /// The fresh 24-byte nonce, from libsodium's random generator.
    pub nonce: Nonce192,
    /// The declared size bucket, in bytes: the length of the padded plaintext that was encrypted.
    ///
    /// The buckets are section 20's, the same ones a mailbox item declares, so one padding rule
    /// covers both and a service checks a length it can compute.
    pub size_bucket_bytes: U64,
    /// The sealed object.
    pub ciphertext: Bytes,
}

/// Why a sealed synchronised object is not one this contract admits.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SyncObjectError {
    /// The declared bucket is not a length section 20's padding rules produce.
    #[error("the declared size bucket of {bucket} bytes is not one the padding rules produce")]
    UndeclaredBucket {
        /// The bucket the object declared.
        bucket: u64,
    },
    /// The ciphertext is not the declared bucket plus the seal's own overhead.
    #[error("the ciphertext is {len} bytes; a bucket of {bucket} bytes seals to {expected}")]
    CiphertextLength {
        /// The ciphertext length that arrived.
        len: u64,
        /// The declared bucket.
        bucket: u64,
        /// The length the declared bucket seals to.
        expected: u64,
    },
    /// The object is larger than one synchronised object may be.
    #[error(
        "a synchronised object holds at most {limit} bytes of plaintext; this one declares {bucket}"
    )]
    TooLarge {
        /// The bucket the object declared.
        bucket: u64,
        /// The limit.
        limit: u64,
    },
}

impl SealedSyncObject {
    /// The bytes this object occupies: the ciphertext, the nonce and the record around them.
    #[must_use]
    pub fn stored_bytes(&self) -> u64 {
        (self.ciphertext.as_slice().len() as u64)
            .saturating_add(Nonce192::LEN as u64)
            .saturating_add(SYNC_RECORD_BYTES)
    }

    /// Checks everything about this object that needs no key.
    ///
    /// # Errors
    ///
    /// Returns the first rule the object breaks.
    pub fn check_structure(&self) -> Result<(), SyncObjectError> {
        let bucket = self.size_bucket_bytes.get();
        if granularity_for_bucket(bucket).is_none() {
            return Err(SyncObjectError::UndeclaredBucket { bucket });
        }
        // The bucket is the padded plaintext, so the limit is checked against it rather than
        // against the plaintext the service never sees.
        if bucket > MAX_SYNC_OBJECT_PLAINTEXT_BYTES {
            return Err(SyncObjectError::TooLarge {
                bucket,
                limit: MAX_SYNC_OBJECT_PLAINTEXT_BYTES,
            });
        }
        let expected = bucket.saturating_add(SEAL_OVERHEAD_BYTES);
        let len = self.ciphertext.as_slice().len() as u64;
        if len != expected {
            return Err(SyncObjectError::CiphertextLength {
                len,
                bucket,
                expected,
            });
        }
        Ok(())
    }
}

/// What one object's record and its bookkeeping cost, in bytes.
///
/// A fixed allowance, for the reason [`crate::mailbox::ROUTING_RECORD_BYTES`] is one: the record is
/// a closed schema of identifiers and a timestamp, and a figure that varied with the storage would
/// make one device's allowance depend on how the service happens to hold it.
pub const SYNC_RECORD_BYTES: u64 = 256;

/// One synchronised object as the service holds it now.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SyncObjectRecord {
    /// The collection it belongs to.
    pub collection_id: SyncCollectionId,
    /// What kind of object it is.
    pub kind: SyncObjectKind,
    /// The object.
    pub object_id: SyncObjectId,
    /// The revision this content was accepted as.
    pub revision: SyncRevisionId,
    /// The sealed object.
    pub object: SealedSyncObject,
    /// When the service accepted it, in UTC milliseconds.
    pub updated_at_ms: TimestampMs,
}

/// A write that lost its comparison, kept for the person to choose from.
///
/// Section 20 keeps conflicting copies for user selection instead of silently choosing by
/// wall-clock time, so the rejected content is retained exactly as it arrived and the revision it
/// expected is retained beside it. Nothing here says which copy is right: the person does.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SyncConflictCopy {
    /// The copy.
    pub conflict_id: SyncConflictId,
    /// The object the rejected write was about.
    pub object_id: SyncObjectId,
    /// What kind of object it is.
    pub kind: SyncObjectKind,
    /// The revision the writer expected to replace, or null when it expected the object not to
    /// exist.
    pub expected_revision: Nullable<SyncRevisionId>,
    /// The revision the object actually held when the write was refused.
    pub current_revision: SyncRevisionId,
    /// The rejected content, unchanged.
    pub object: SealedSyncObject,
    /// When the service refused the write, in UTC milliseconds.
    pub recorded_at_ms: TimestampMs,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mailbox::{KIB, mailbox_size_bucket};

    fn sealed(bucket: u64, ciphertext_len: u64) -> SealedSyncObject {
        SealedSyncObject {
            nonce: Nonce192::from_bytes([5; 24]),
            size_bucket_bytes: U64::new(bucket),
            ciphertext: Bytes::new(vec![0xcd; ciphertext_len as usize]),
        }
    }

    #[test]
    fn the_kinds_are_settings_drafts_and_a_client_position() {
        // The closed set is the whole of what may be synchronised. Host grants and revocation state
        // have one host authority, so no kind names them and no restore can reach them.
        assert_eq!(
            SyncObjectKind::ALL.map(SyncObjectKind::as_str),
            ["settings", "draft", "client_selection"]
        );
    }

    #[test]
    fn an_object_is_admitted_when_its_shape_is_the_one_the_rules_produce() {
        let bucket = mailbox_size_bucket(1_000);
        assert_eq!(
            sealed(bucket, bucket + SEAL_OVERHEAD_BYTES).check_structure(),
            Ok(())
        );
    }

    #[test]
    fn a_bucket_no_padding_rule_produces_is_refused() {
        assert_eq!(
            sealed(18 * KIB, 18 * KIB + SEAL_OVERHEAD_BYTES).check_structure(),
            Err(SyncObjectError::UndeclaredBucket { bucket: 18 * KIB })
        );
    }

    #[test]
    fn an_object_larger_than_the_limit_is_refused_before_its_length_is_read() {
        let bucket = mailbox_size_bucket(MAX_SYNC_OBJECT_PLAINTEXT_BYTES + 1);
        assert!(bucket > MAX_SYNC_OBJECT_PLAINTEXT_BYTES);
        assert_eq!(
            sealed(bucket, 0).check_structure(),
            Err(SyncObjectError::TooLarge {
                bucket,
                limit: MAX_SYNC_OBJECT_PLAINTEXT_BYTES,
            })
        );
    }

    #[test]
    fn a_ciphertext_that_is_not_its_bucket_sealed_is_refused() {
        let bucket = mailbox_size_bucket(10);
        assert_eq!(
            sealed(bucket, bucket).check_structure(),
            Err(SyncObjectError::CiphertextLength {
                len: bucket,
                bucket,
                expected: bucket + SEAL_OVERHEAD_BYTES,
            })
        );
    }

    #[test]
    fn stored_bytes_measure_the_ciphertext_the_nonce_and_the_record() {
        let bucket = mailbox_size_bucket(10);
        let object = sealed(bucket, bucket + SEAL_OVERHEAD_BYTES);
        assert_eq!(
            object.stored_bytes(),
            bucket + SEAL_OVERHEAD_BYTES + Nonce192::LEN as u64 + SYNC_RECORD_BYTES
        );
    }
}
