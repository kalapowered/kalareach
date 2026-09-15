//! Backup archives, key wraps, manifests and recovery material: the stored formats of section 20.
//!
//! Every backup object is encrypted under its own random 256-bit key with
//! `crypto_secretstream_xchacha20poly1305`, and that key is wrapped separately for each authorised
//! recipient with `crypto_box_easy`. A signed manifest lists the objects; the manifest itself is
//! encrypted as a separate object, so only an opaque archive identifier and encrypted-object
//! references stay outside it.
//!
//! This module holds the shapes and their limits. `kr-crypto` performs the encryption, the
//! wrapping and the signing.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::ids::{ArchiveId, BackupGeneration, BackupObjectId, DeviceId};
use crate::scalars::{
    AuthorisationKey, Bytes, CanonicalSet, Digest256, KeyId, Nonce192, Signature64, TimestampMs,
    U64,
};

/// The size of one `secretstream` record, in bytes.
pub const SECRETSTREAM_RECORD_LEN: usize = 1024 * 1024;

/// The maximum size of a public archive descriptor, in bytes.
pub const MAX_ARCHIVE_DESCRIPTOR_LEN: usize = 64 * 1024;

/// The maximum number of recipients an archive descriptor names by default.
pub const MAX_ARCHIVE_RECIPIENTS: usize = 128;

/// The `crypto_kdf` context the recovery seed derives under.
pub const RECOVERY_KDF_CONTEXT: &str = "KRRECOV1";

/// The `crypto_kdf` subkey identifier of the recovery-bundle encryption key.
pub const RECOVERY_BUNDLE_SUBKEY_ID: u64 = 1;

/// The `crypto_kdf` subkey identifier of the recovery recipient's `crypto_box` seed.
pub const RECOVERY_RECIPIENT_SUBKEY_ID: u64 = 2;

/// The domain an archive manifest signature covers.
pub const MANIFEST_DOMAIN: &str = "kr-archive-manifest/1";

/// The domain a recovery bundle signature covers.
pub const RECOVERY_BUNDLE_DOMAIN: &str = "kr-recovery-bundle/1";

/// The key-wrap format this build writes and reads.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub enum KeyWrapFormat {
    /// Version 1.
    #[serde(rename = "kr-keywrap/1")]
    V1,
}

/// What a wrapped key opens.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum KeyWrapPurpose {
    /// The key of the encrypted manifest object.
    ManifestKey,
    /// The key of one member object.
    ObjectKey,
    /// The key of an encrypted recovery bundle.
    RecoveryBundleKey,
}

/// The fields a key wrap authenticates, apart from the key itself.
///
/// The wrap is valid only for this object and this recipient: a receiver that reuses a wrap on a
/// different object or under a different archive fails authentication rather than decrypting the
/// wrong thing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct KeyWrapContext {
    /// The wrap format.
    pub format: KeyWrapFormat,
    /// What the wrapped key opens.
    pub purpose: KeyWrapPurpose,
    /// The archive.
    pub archive_id: ArchiveId,
    /// The backup generation.
    pub backup_generation: BackupGeneration,
    /// The object the key belongs to.
    pub object_id: BackupObjectId,
    /// The SHA-256 of the encrypted object.
    pub encrypted_object_hash: Digest256,
    /// The sender's stored-envelope key.
    pub sender_key_id: KeyId,
    /// The recipient's stored-envelope key.
    pub recipient_key_id: KeyId,
}

/// One wrapped object key.
///
/// Every wrap uses a fresh random 24-byte nonce. Reusing stored ciphertext when an upload resumes
/// never reuses a nonce for a new wrap.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SealedKeyWrap {
    /// The fields the wrap authenticates.
    pub context: KeyWrapContext,
    /// The fresh 24-byte nonce.
    pub nonce: Nonce192,
    /// The `crypto_box_easy` output over the canonical wrap plaintext.
    pub ciphertext: Bytes,
}

/// A reference to one encrypted object.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EncryptedObjectRef {
    /// The object identity.
    pub object_id: BackupObjectId,
    /// The SHA-256 of the encrypted object, including its `secretstream` header.
    pub encrypted_object_hash: Digest256,
    /// The stored size of the encrypted object, in bytes.
    pub encrypted_len: U64,
}

/// One member of a manifest.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ManifestObject {
    /// The encrypted object this entry describes.
    pub object: EncryptedObjectRef,
    /// The member's filename. Filenames live inside the encrypted manifest, never outside it.
    pub filename: String,
}

/// The manifest of one archive generation.
///
/// It is encrypted as a separate object before upload. Its signature is verified against a trusted
/// writer key from the recovery bundle, never against a key an untrusted archive descriptor
/// supplied.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ArchiveManifest {
    /// The manifest schema version.
    pub schema_version: U64,
    /// The archive.
    pub archive_id: ArchiveId,
    /// The device that owns the archive.
    pub owner_device_id: DeviceId,
    /// The generation this manifest describes.
    pub backup_generation: BackupGeneration,
    /// The member objects, in the order the producer wrote them.
    pub objects: Vec<ManifestObject>,
    /// When the producer wrote it, in UTC milliseconds.
    pub created_at_ms: TimestampMs,
}

/// A manifest and the backup writer's signature over it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SignedArchiveManifest {
    /// The manifest.
    pub manifest: ArchiveManifest,
    /// The writer's signing key.
    pub writer_key_id: KeyId,
    /// The Ed25519 signature over `CBOR(["kr-archive-manifest/1", manifest])`.
    pub signature: Signature64,
}

/// The public descriptor of one archive.
///
/// Everything outside it is opaque: the archive identity and encrypted-object references. The
/// descriptor is validated before any object is allocated or written, so an invalid one costs
/// nothing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ArchiveDescriptor {
    /// The descriptor version.
    pub version: U64,
    /// The archive.
    pub archive_id: ArchiveId,
    /// The generation this descriptor points at.
    pub backup_generation: BackupGeneration,
    /// The encrypted manifest object.
    pub encrypted_manifest: EncryptedObjectRef,
    /// The manifest key, wrapped once per authorised recipient.
    pub manifest_key_wraps: Vec<SealedKeyWrap>,
}

/// Why an archive descriptor was rejected.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DescriptorError {
    /// The descriptor was larger than the limit.
    #[error("the archive descriptor is {len} bytes, over the {limit}-byte limit")]
    TooLarge {
        /// The descriptor size.
        len: usize,
        /// The limit.
        limit: usize,
    },
    /// The descriptor named more recipients than the limit.
    #[error("the archive descriptor names {count} recipients, over the {limit}-recipient limit")]
    TooManyRecipients {
        /// The number of recipients.
        count: usize,
        /// The limit.
        limit: usize,
    },
    /// A wrap named an object other than the encrypted manifest.
    #[error("a manifest key wrap names object {named}, not the encrypted manifest")]
    WrapObjectMismatch {
        /// The object the wrap named.
        named: BackupObjectId,
    },
    /// A wrap named a hash other than the encrypted manifest's.
    #[error("a manifest key wrap names a different encrypted-manifest hash")]
    WrapHashMismatch,
    /// A wrap declared a purpose other than the manifest key.
    #[error("a manifest key wrap declares purpose {purpose:?}, not the manifest key")]
    WrapPurposeMismatch {
        /// The purpose the wrap declared.
        purpose: KeyWrapPurpose,
    },
    /// Two wraps named the same recipient.
    #[error("two manifest key wraps name the same recipient")]
    DuplicateRecipient,
}

impl ArchiveDescriptor {
    /// Validates the descriptor before any object is allocated or written.
    ///
    /// `encoded_len` is the size of the descriptor as it arrived, which is the quantity section 20
    /// bounds.
    ///
    /// # Errors
    ///
    /// Returns the first rule the descriptor breaks.
    pub fn validate(&self, encoded_len: usize) -> Result<(), DescriptorError> {
        if encoded_len > MAX_ARCHIVE_DESCRIPTOR_LEN {
            return Err(DescriptorError::TooLarge {
                len: encoded_len,
                limit: MAX_ARCHIVE_DESCRIPTOR_LEN,
            });
        }
        if self.manifest_key_wraps.len() > MAX_ARCHIVE_RECIPIENTS {
            return Err(DescriptorError::TooManyRecipients {
                count: self.manifest_key_wraps.len(),
                limit: MAX_ARCHIVE_RECIPIENTS,
            });
        }
        let mut recipients = Vec::with_capacity(self.manifest_key_wraps.len());
        for wrap in &self.manifest_key_wraps {
            if wrap.context.purpose != KeyWrapPurpose::ManifestKey {
                return Err(DescriptorError::WrapPurposeMismatch {
                    purpose: wrap.context.purpose,
                });
            }
            if wrap.context.object_id != self.encrypted_manifest.object_id {
                return Err(DescriptorError::WrapObjectMismatch {
                    named: wrap.context.object_id,
                });
            }
            if wrap.context.encrypted_object_hash != self.encrypted_manifest.encrypted_object_hash {
                return Err(DescriptorError::WrapHashMismatch);
            }
            if recipients.contains(&wrap.context.recipient_key_id) {
                return Err(DescriptorError::DuplicateRecipient);
            }
            recipients.push(wrap.context.recipient_key_id);
        }
        Ok(())
    }
}

/// A backup writer a restore is allowed to trust.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TrustedWriter {
    /// The writer's signing key identifier.
    pub writer_key_id: KeyId,
    /// The writer's Ed25519 signing public key.
    pub signing_key: AuthorisationKey,
    /// When the owner enrolled it, in UTC milliseconds.
    pub enrolled_at_ms: TimestampMs,
}

/// One collection a recovery bundle can find.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CollectionLocator {
    /// The service origin the collection lives at.
    pub service_origin: String,
    /// The stable opaque locator of the collection.
    pub locator: String,
    /// The archive the locator points at.
    pub archive_id: ArchiveId,
}

/// The latest generation an owner has verified for one archive.
///
/// A fresh client needs this to detect a service replaying an older valid backup. A recovery-only
/// restore still shows its checkpoint and cannot prove that no newer archive exists.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ArchiveCheckpoint {
    /// The archive.
    pub archive_id: ArchiveId,
    /// The latest generation the owner verified.
    pub backup_generation: BackupGeneration,
    /// The hash of that generation's encrypted manifest.
    pub encrypted_manifest_hash: Digest256,
    /// When the owner verified it, in UTC milliseconds.
    pub verified_at_ms: TimestampMs,
}

/// The versioned recovery bundle an owner keeps at a stable locator.
///
/// Enabling a new backup writer or rotating its signing key commits an updated bundle before that
/// writer is declared recovery-enabled.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RecoveryBundle {
    /// The bundle schema version.
    pub schema_version: U64,
    /// Where the owner's collections live.
    pub collections: Vec<CollectionLocator>,
    /// The writers a restore may trust.
    pub trusted_writers: CanonicalSet<TrustedWriter>,
    /// The latest generation the owner verified for each archive.
    pub checkpoints: CanonicalSet<ArchiveCheckpoint>,
    /// The bundle revision, advanced on every compare-and-swap write.
    pub revision: U64,
    /// When the owner wrote it, in UTC milliseconds.
    pub written_at_ms: TimestampMs,
}

/// The printable and QR recovery kit.
///
/// A seed with no way to find the encrypted bundle is not a complete kit, so the kit names the
/// configured service origins and the stable bundle locator alongside the seed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RecoveryKit {
    /// The kit format and cryptographic profile version.
    pub profile_version: U64,
    /// The 256-bit recovery seed.
    pub seed: Bytes,
    /// The seed checksum, so a mistyped kit fails before it is used.
    pub seed_checksum: Bytes,
    /// Each configured service origin.
    pub service_origins: Vec<String>,
    /// The stable opaque locator of the recovery bundle.
    pub bundle_locator: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scalars::Uuid;

    fn object_ref(seed: u8) -> EncryptedObjectRef {
        EncryptedObjectRef {
            object_id: BackupObjectId::new(Uuid::from_bytes([seed; 16])),
            encrypted_object_hash: Digest256::from_bytes([seed; 32]),
            encrypted_len: U64::new(4096),
        }
    }

    fn wrap(object: &EncryptedObjectRef, recipient: u8) -> SealedKeyWrap {
        SealedKeyWrap {
            context: KeyWrapContext {
                format: KeyWrapFormat::V1,
                purpose: KeyWrapPurpose::ManifestKey,
                archive_id: ArchiveId::new(Uuid::from_bytes([9; 16])),
                backup_generation: BackupGeneration::new(3),
                object_id: object.object_id,
                encrypted_object_hash: object.encrypted_object_hash,
                sender_key_id: KeyId::from_bytes([1; 32]),
                recipient_key_id: KeyId::from_bytes([recipient; 32]),
            },
            nonce: Nonce192::from_bytes([recipient; 24]),
            ciphertext: Bytes::new(vec![0; 48]),
        }
    }

    fn descriptor(wraps: Vec<SealedKeyWrap>) -> ArchiveDescriptor {
        ArchiveDescriptor {
            version: U64::new(1),
            archive_id: ArchiveId::new(Uuid::from_bytes([9; 16])),
            backup_generation: BackupGeneration::new(3),
            encrypted_manifest: object_ref(7),
            manifest_key_wraps: wraps,
        }
    }

    #[test]
    fn a_valid_descriptor_passes() {
        let manifest = object_ref(7);
        let descriptor = descriptor(vec![wrap(&manifest, 1), wrap(&manifest, 2)]);
        assert!(descriptor.validate(1024).is_ok());
    }

    #[test]
    fn an_oversized_descriptor_fails_before_allocation() {
        let manifest = object_ref(7);
        let descriptor = descriptor(vec![wrap(&manifest, 1)]);
        assert!(matches!(
            descriptor.validate(MAX_ARCHIVE_DESCRIPTOR_LEN + 1),
            Err(DescriptorError::TooLarge { .. })
        ));
    }

    #[test]
    fn a_descriptor_over_the_recipient_limit_fails() {
        let manifest = object_ref(7);
        let wraps = (0..=MAX_ARCHIVE_RECIPIENTS)
            .map(|index| {
                wrap(
                    &manifest,
                    u8::try_from(index % 251).expect("a byte-sized recipient seed"),
                )
            })
            .collect();
        assert!(matches!(
            descriptor(wraps).validate(1024),
            Err(DescriptorError::TooManyRecipients { .. })
        ));
    }

    #[test]
    fn a_wrap_bound_to_another_object_is_rejected() {
        let other = object_ref(8);
        let descriptor = descriptor(vec![wrap(&other, 1)]);
        assert!(matches!(
            descriptor.validate(1024),
            Err(DescriptorError::WrapObjectMismatch { .. })
        ));
    }

    #[test]
    fn a_repeated_recipient_is_rejected() {
        let manifest = object_ref(7);
        let descriptor = descriptor(vec![wrap(&manifest, 1), wrap(&manifest, 1)]);
        assert!(matches!(
            descriptor.validate(1024),
            Err(DescriptorError::DuplicateRecipient)
        ));
    }
}
