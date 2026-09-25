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
//! The kinds are closed. [`SyncObjectKind`] is settings, drafts, a client's own position and the
//! recovery bundle, and nothing else: section 20 gives host grants and revocation state one host
//! authority, so they are not synchronised objects and restoring a synchronised object can never
//! reach them. A draft is a draft: it is never an execution request, and nothing about this
//! contract submits one.
//!
//! The recovery bundle is the owner's key material: the collection locators, the trusted writers'
//! public keys and the verified generation checkpoints a restore reads, encrypted as one
//! `secretstream` object under a key the recovery seed derives for the origin and locator it is
//! kept at. It grants nothing and names no host authority. It is kept at the stable locator the
//! recovery kit prints, by the same compare and swap as every other kind, so it travels as a
//! [`SealedRecoveryBundle`] with a bound of its own rather than as a [`SealedSyncObject`].
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
    /// The owner's recovery bundle, at the stable locator the recovery kit prints.
    ///
    /// Key material a restore authenticates with the kit and reads, never authority: it grants
    /// nothing, and a restore that reads it recreates no host control.
    RecoveryBundle,
}

impl SyncObjectKind {
    /// Every kind, in declaration order.
    pub const ALL: [Self; 4] = [
        Self::Settings,
        Self::Draft,
        Self::ClientSelection,
        Self::RecoveryBundle,
    ];

    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Settings => "settings",
            Self::Draft => "draft",
            Self::ClientSelection => "client_selection",
            Self::RecoveryBundle => "recovery_bundle",
        }
    }

    /// Returns true for a kind stored as a [`SealedSyncObject`], and false for the recovery
    /// bundle, which is stored as a [`SealedRecoveryBundle`].
    #[must_use]
    pub const fn holds_a_sealed_object(self) -> bool {
        !matches!(self, Self::RecoveryBundle)
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

/// The fewest bytes a sealed recovery bundle can be: a `secretstream` header of 24 bytes and one
/// final record carrying no message, which is its 17-byte tag and nothing else.
pub const MIN_SEALED_RECOVERY_BUNDLE_BYTES: u64 = 24 + 17;

/// The most bytes a sealed recovery bundle may be.
///
/// A bundle holds locators, public keys and checkpoints, a hundred or so bytes each, so this is
/// room for about a thousand of them. It travels base64url-encoded inside one settings-sync
/// request, as 174,763 bytes, well inside the 256 KiB a request may be, so the bundle needs no
/// path of its own.
pub const MAX_SEALED_RECOVERY_BUNDLE_BYTES: u64 = 128 * 1024;

/// The owner's recovery bundle as a service stores it: one `secretstream` object.
///
/// The stream carries its own header, so there is no nonce beside it, and no declared bucket: section
/// 20 lets a service see an object's size. The service holds the bytes and nothing it could open:
/// the key is derived from the recovery seed and the origin and locator the bundle is kept at.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SealedRecoveryBundle {
    /// The sealed bundle.
    pub ciphertext: Bytes,
}

/// Why a sealed recovery bundle is not one this contract admits.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RecoveryBundleError {
    /// Shorter than any stream a bundle is sealed as.
    #[error("a sealed recovery bundle is at least {min} bytes; this one is {len}")]
    TooShort {
        /// The length that arrived.
        len: u64,
        /// The fewest bytes a sealed bundle can be.
        min: u64,
    },
    /// Larger than a sealed bundle may be.
    #[error("a sealed recovery bundle is at most {limit} bytes; this one is {len}")]
    TooLarge {
        /// The length that arrived.
        len: u64,
        /// The limit.
        limit: u64,
    },
}

impl SealedRecoveryBundle {
    /// The bytes this bundle occupies: the ciphertext and the record around it.
    #[must_use]
    pub fn stored_bytes(&self) -> u64 {
        (self.ciphertext.as_slice().len() as u64).saturating_add(SYNC_RECORD_BYTES)
    }

    /// Checks everything about this bundle that needs no key: its length, and nothing else.
    ///
    /// The stream's tags are checked only where it is opened. A service holds no key, so it
    /// cannot tell a bundle from other bytes of the same length, and a device that opens one
    /// authenticates every record, the final one included.
    ///
    /// # Errors
    ///
    /// Returns the rule the bundle breaks.
    pub fn check_structure(&self) -> Result<(), RecoveryBundleError> {
        let len = self.ciphertext.as_slice().len() as u64;
        if len < MIN_SEALED_RECOVERY_BUNDLE_BYTES {
            return Err(RecoveryBundleError::TooShort {
                len,
                min: MIN_SEALED_RECOVERY_BUNDLE_BYTES,
            });
        }
        if len > MAX_SEALED_RECOVERY_BUNDLE_BYTES {
            return Err(RecoveryBundleError::TooLarge {
                len,
                limit: MAX_SEALED_RECOVERY_BUNDLE_BYTES,
            });
        }
        Ok(())
    }
}

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
    fn the_kinds_are_settings_drafts_a_client_position_and_the_recovery_bundle() {
        // The closed set is the whole of what may be synchronised. Host grants and revocation state
        // have one host authority, so no kind names them and no restore can reach them. The
        // recovery bundle is key material a restore reads, and grants nothing.
        assert_eq!(
            SyncObjectKind::ALL.map(SyncObjectKind::as_str),
            ["settings", "draft", "client_selection", "recovery_bundle"]
        );
        assert_eq!(
            SyncObjectKind::ALL.map(SyncObjectKind::holds_a_sealed_object),
            [true, true, true, false]
        );
    }

    fn bundle(len: u64) -> SealedRecoveryBundle {
        SealedRecoveryBundle {
            ciphertext: Bytes::new(vec![0xcd; usize::try_from(len).expect("a length")]),
        }
    }

    #[test]
    fn a_recovery_bundle_is_admitted_from_an_empty_stream_to_its_bound() {
        for len in [
            MIN_SEALED_RECOVERY_BUNDLE_BYTES,
            4_096,
            MAX_SEALED_RECOVERY_BUNDLE_BYTES,
        ] {
            assert_eq!(bundle(len).check_structure(), Ok(()), "{len}");
        }
        assert_eq!(
            bundle(MIN_SEALED_RECOVERY_BUNDLE_BYTES - 1).check_structure(),
            Err(RecoveryBundleError::TooShort {
                len: MIN_SEALED_RECOVERY_BUNDLE_BYTES - 1,
                min: MIN_SEALED_RECOVERY_BUNDLE_BYTES,
            })
        );
        assert_eq!(
            bundle(MAX_SEALED_RECOVERY_BUNDLE_BYTES + 1).check_structure(),
            Err(RecoveryBundleError::TooLarge {
                len: MAX_SEALED_RECOVERY_BUNDLE_BYTES + 1,
                limit: MAX_SEALED_RECOVERY_BUNDLE_BYTES,
            })
        );
    }

    #[test]
    fn a_recovery_bundle_is_its_stream_and_nothing_beside_it() {
        // The stream carries its own header, so there is no nonce and no bucket beside it, and a
        // member nobody agreed on is refused rather than stored.
        let object = bundle(64);
        let value = serde_json::to_value(&object).expect("a bundle");
        assert_eq!(
            value
                .as_object()
                .expect("an object")
                .keys()
                .collect::<Vec<_>>(),
            ["ciphertext"]
        );
        let mut extra = value;
        extra["nonce"] = serde_json::json!("AAAA");
        assert!(serde_json::from_value::<SealedRecoveryBundle>(extra).is_err());
        assert_eq!(
            object.stored_bytes(),
            64 + SYNC_RECORD_BYTES,
            "the ciphertext and the record"
        );
    }

    #[test]
    fn the_smallest_bundle_is_a_stream_header_and_one_final_record() {
        // A `secretstream` object is a 24-byte header and records of at least their 17-byte tag, so
        // the empty stream is 41 bytes, and every bundle a device seals is at least that.
        assert_eq!(MIN_SEALED_RECOVERY_BUNDLE_BYTES, 24 + 17);
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
