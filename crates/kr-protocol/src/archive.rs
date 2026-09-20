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

use kr_cbor::{CanonicalValue, CborError};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::ids::{ArchiveId, BackupGeneration, BackupObjectId, BackupWriterRevision, DeviceId};
use crate::scalars::{
    AuthorisationKey, Bytes, CanonicalSet, Digest256, KeyId, Nonce192, SecretBytes32, Signature64,
    TimestampMs, U64,
};

/// The size of one `secretstream` record, in bytes.
pub const SECRETSTREAM_RECORD_LEN: usize = 1024 * 1024;

/// The maximum size of a public archive descriptor, in bytes.
pub const MAX_ARCHIVE_DESCRIPTOR_LEN: usize = 64 * 1024;

/// The maximum number of recipients an archive descriptor names by default.
pub const MAX_ARCHIVE_RECIPIENTS: usize = 128;

/// The recovery kit profile version this build writes and reads.
pub const RECOVERY_KIT_PROFILE_VERSION: u64 = 1;

/// The `crypto_kdf` context the recovery seed derives under.
pub const RECOVERY_KDF_CONTEXT: &str = "KRRECOV1";

/// The `crypto_kdf` subkey identifier of the recovery-bundle encryption key.
pub const RECOVERY_BUNDLE_SUBKEY_ID: u64 = 1;

/// The `crypto_kdf` subkey identifier of the recovery recipient's `crypto_box` seed.
pub const RECOVERY_RECIPIENT_SUBKEY_ID: u64 = 2;

/// The domain an archive manifest signature covers.
pub const MANIFEST_DOMAIN: &str = "kr-archive-manifest/1";

/// The domain the recovery bundle's object key is derived under.
pub const RECOVERY_BUNDLE_DOMAIN: &str = "kr-recovery-bundle/1";

/// Where a recovery bundle is retrieved from.
///
/// The bundle's encryption key is derived from the recovery seed *and* this context, so a service
/// that serves a bundle from another origin or another locator serves one that does not
/// authenticate. Origin or locator substitution fails authentication rather than causing trust in
/// archive-supplied writer keys.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RecoveryContext {
    /// The configured service origin the bundle is retrieved from.
    pub service_origin: String,
    /// The stable opaque locator of the bundle.
    pub bundle_locator: String,
}

impl RecoveryContext {
    /// Builds the canonical bytes the bundle key is bound to.
    ///
    /// # Errors
    ///
    /// Returns a CBOR error when the context is outside KR-CBOR-1.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, CborError> {
        Ok(kr_cbor::encode(&kr_cbor::signing_value(
            RECOVERY_BUNDLE_DOMAIN,
            vec![
                CanonicalValue::text(self.service_origin.as_str()),
                CanonicalValue::text(self.bundle_locator.as_str()),
            ],
        )))
    }
}

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

/// Builds the authenticated plaintext of one key wrap: `CBOR([context, object_key])`.
///
/// The context carries the format, the purpose, the archive, the generation, the object, the
/// encrypted-object hash and both key identifiers, so a wrap opened against a different object,
/// generation or recipient fails to authenticate rather than yielding the wrong key.
///
/// The returned buffer holds the object key in the clear. Its caller seals it and then zeroises
/// it; nothing else may hold on to it.
///
/// # Errors
///
/// Returns a CBOR error when the context is outside KR-CBOR-1.
pub fn key_wrap_plaintext(
    context: &KeyWrapContext,
    object_key: &[u8; OBJECT_KEY_LEN],
) -> Result<Vec<u8>, CborError> {
    let mut plaintext = key_wrap_prefix(context)?;
    plaintext.extend_from_slice(object_key.as_slice());
    Ok(plaintext)
}

/// Bytes in an object key.
pub const OBJECT_KEY_LEN: usize = 32;

/// Builds everything in a key wrap plaintext up to, but not including, the key itself.
///
/// The encoding is assembled by hand rather than through a value tree: a tree would hold a second
/// copy of the object key that no caller can reach and therefore cannot zeroise. The bytes are
/// `0x82` (a two-element array), the canonical context, then `0x58 0x20` (a 32-byte string head).
/// `key_wrap_prefix_is_the_canonical_encoding` checks that against the value-tree encoder.
///
/// An opener rebuilds this prefix from the context it expects and compares it with the opened
/// plaintext, which is both the shape check and the context check.
///
/// # Errors
///
/// Returns a CBOR error when the context is outside KR-CBOR-1.
pub fn key_wrap_prefix(context: &KeyWrapContext) -> Result<Vec<u8>, CborError> {
    let encoded_context = kr_cbor::to_canonical_vec(context)?;
    let mut prefix = Vec::with_capacity(encoded_context.len() + 4 + OBJECT_KEY_LEN);
    prefix.push(0x82);
    prefix.extend_from_slice(&encoded_context);
    prefix.push(0x58);
    prefix.push(0x20);
    Ok(prefix)
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

/// What the encrypted manifest object carries: the signed manifest and every member key wrap.
///
/// Section 20 keeps object identifiers, filenames and encrypted-object hashes inside the encrypted
/// manifest, and a member key wrap names all three. So the member wraps travel here rather than in
/// the public descriptor, which carries only the opaque archive identifier, the encrypted-manifest
/// reference and the manifest-key wraps.
///
/// One manifest object serves every recipient. Each wrap is addressed to one of them and opens for
/// that one alone, exactly as the descriptor's manifest-key wraps do.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ManifestPayload {
    /// The signed manifest.
    pub manifest: SignedArchiveManifest,
    /// Each member object's key, wrapped once per authorised recipient.
    pub member_key_wraps: Vec<SealedKeyWrap>,
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

/// The archive descriptor version this build writes and reads.
pub const ARCHIVE_DESCRIPTOR_VERSION: u64 = 1;

/// Why an archive descriptor was rejected.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DescriptorError {
    /// The descriptor declared a version this build does not read.
    #[error("the archive descriptor declares version {version}; this build reads version 1")]
    UnsupportedVersion {
        /// The version the descriptor declared.
        version: u64,
    },
    /// A wrap named a different archive or generation from the descriptor.
    #[error("a manifest key wrap names another archive or backup generation")]
    WrapArchiveMismatch,
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
    /// The recovery kit does not name the service origin a restore is trying.
    #[error("the recovery kit does not name that service origin")]
    UnknownServiceOrigin,
    /// The publication names a writer the collection's owner has not enrolled.
    #[error("that writer is not the one this collection's owner enrolled")]
    WriterNotEnrolled,
    /// The bytes were not a canonical descriptor.
    #[error("the archive descriptor is not canonical KR-CBOR-1: {0}")]
    Encoding(#[from] CborError),
}

impl ArchiveDescriptor {
    /// Reads a descriptor from canonical bytes, bounding it before it is decoded.
    ///
    /// This is the entry point a restore uses. Section 20 requires an invalid descriptor to fail
    /// before object allocation or filesystem writes, and a descriptor that arrives over the
    /// network is bounded before it is parsed, not after.
    ///
    /// # Errors
    ///
    /// Returns [`DescriptorError::TooLarge`] before decoding, [`DescriptorError::Encoding`] when
    /// the bytes are not a canonical descriptor, and then whatever [`Self::validate`] returns.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, DescriptorError> {
        if bytes.len() > MAX_ARCHIVE_DESCRIPTOR_LEN {
            return Err(DescriptorError::TooLarge {
                len: bytes.len(),
                limit: MAX_ARCHIVE_DESCRIPTOR_LEN,
            });
        }
        let descriptor: Self = kr_cbor::from_canonical_slice(bytes, &kr_cbor::Limits::DEFAULT)?;
        descriptor.validate(bytes.len())?;
        Ok(descriptor)
    }

    /// Validates the descriptor before any object is allocated or written.
    ///
    /// `encoded_len` is the size of the descriptor as it arrived, which is the quantity section 20
    /// bounds.
    ///
    /// # Errors
    ///
    /// Returns the first rule the descriptor breaks.
    pub fn validate(&self, encoded_len: usize) -> Result<(), DescriptorError> {
        // The byte limit is checked first, so an oversized descriptor costs nothing beyond the
        // bytes that were already received.
        if encoded_len > MAX_ARCHIVE_DESCRIPTOR_LEN {
            return Err(DescriptorError::TooLarge {
                len: encoded_len,
                limit: MAX_ARCHIVE_DESCRIPTOR_LEN,
            });
        }
        if self.version.get() != ARCHIVE_DESCRIPTOR_VERSION {
            return Err(DescriptorError::UnsupportedVersion {
                version: self.version.get(),
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
            if wrap.context.archive_id != self.archive_id
                || wrap.context.backup_generation != self.backup_generation
            {
                return Err(DescriptorError::WrapArchiveMismatch);
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

/// The domain one collection's writer enrolment covers.
pub const BACKUP_WRITER_DOMAIN: &str = "kr-backup-writer/1";

/// The domain one published generation covers.
pub const BACKUP_PUBLICATION_DOMAIN: &str = "kr-backup-publication/1";

/// Which writer may publish generations of one collection, as its owner states it.
///
/// A managed service cannot read a manifest, so it cannot tell a genuine generation from one
/// somebody else uploaded. What it can do is refuse a publication that is not signed by the writer
/// the collection's owner enrolled, and that is what this record establishes: the owner's
/// authorisation key signs the writer's signing key into the collection.
///
/// The revision is what makes a replacement deliberate. A service that has accepted revision three
/// refuses revision two, so a captured earlier enrolment cannot restore a writer whose key the
/// owner has since retired.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BackupWriterRecordPayload {
    /// The archive whose generations this writer may publish.
    pub archive_id: ArchiveId,
    /// The writer the owner enrols.
    pub writer: TrustedWriter,
    /// The revision of this collection's enrolment. Only the owner advances it.
    pub writer_revision: BackupWriterRevision,
    /// The owner's authorisation key identifier.
    pub owner_key_id: KeyId,
    /// When the owner signed it, in UTC milliseconds.
    pub enrolled_at_ms: TimestampMs,
}

impl BackupWriterRecordPayload {
    /// Builds the canonical bytes an enrolment signature covers.
    ///
    /// # Errors
    ///
    /// Returns a CBOR error when the payload cannot be represented in KR-CBOR-1.
    pub fn signing_input(&self) -> Result<Vec<u8>, CborError> {
        Ok(kr_cbor::encode(&kr_cbor::signing_value(
            BACKUP_WRITER_DOMAIN,
            vec![kr_cbor::to_canonical_value(self)?],
        )))
    }
}

/// One collection's writer enrolment, signed by the collection owner's authorisation key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BackupWriterRecord {
    /// What the owner states.
    pub payload: BackupWriterRecordPayload,
    /// The owner's signature over [`BackupWriterRecordPayload::signing_input`].
    pub signature: Signature64,
}

/// One generation of one archive, as its writer publishes it.
///
/// The descriptor is the public half of an archive: the opaque archive identifier, the encrypted
/// manifest's reference and hash, and the manifest key wrapped once per authorised recipient. The
/// writer signs it so that a device fetching it verifies the writer's own statement rather than the
/// service's word about what was published.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BackupGenerationPublicationPayload {
    /// The public descriptor of this generation.
    pub descriptor: ArchiveDescriptor,
    /// The writer's signing key identifier.
    pub writer_key_id: KeyId,
    /// When the writer published it, in UTC milliseconds.
    pub published_at_ms: TimestampMs,
}

impl BackupGenerationPublicationPayload {
    /// Builds the canonical bytes a publication signature covers.
    ///
    /// # Errors
    ///
    /// Returns a CBOR error when the payload cannot be represented in KR-CBOR-1.
    pub fn signing_input(&self) -> Result<Vec<u8>, CborError> {
        Ok(kr_cbor::encode(&kr_cbor::signing_value(
            BACKUP_PUBLICATION_DOMAIN,
            vec![kr_cbor::to_canonical_value(self)?],
        )))
    }
}

/// One published generation and the writer's signature over it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BackupGenerationPublication {
    /// What the writer published.
    pub payload: BackupGenerationPublicationPayload,
    /// The writer's signature over [`BackupGenerationPublicationPayload::signing_input`].
    pub signature: Signature64,
}

impl BackupGenerationPublication {
    /// Validates the publication before anything is stored for it.
    ///
    /// `descriptor_len` is the size of the descriptor as it arrived, which is the quantity section
    /// 20 bounds. The descriptor's own rules are checked first, because an invalid descriptor must
    /// fail before allocation, and then the two facts that tie the publication to it: the writer
    /// the payload names is the writer the signature will be checked against, and the archive the
    /// descriptor names is the archive the enrolment covers.
    ///
    /// # Errors
    ///
    /// Returns the first rule the publication breaks.
    pub fn check_structure(
        &self,
        descriptor_len: usize,
        enrolled: &BackupWriterRecordPayload,
    ) -> Result<(), DescriptorError> {
        self.payload.descriptor.validate(descriptor_len)?;
        if self.payload.writer_key_id != enrolled.writer.writer_key_id {
            return Err(DescriptorError::WriterNotEnrolled);
        }
        if self.payload.descriptor.archive_id != enrolled.archive_id {
            return Err(DescriptorError::WrapArchiveMismatch);
        }
        Ok(())
    }

    /// The generation this publication is of.
    #[must_use]
    pub const fn backup_generation(&self) -> BackupGeneration {
        self.payload.descriptor.backup_generation
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

impl RecoveryKit {
    /// Returns the retrieval context of the bundle this kit points at.
    ///
    /// A kit names every configured service origin; `service_origin` selects the one being tried,
    /// and a restore tries each in turn. Substituting an origin changes the derived key, so the
    /// wrong one fails authentication.
    ///
    /// # Errors
    ///
    /// Returns an error when the kit does not name `service_origin`.
    pub fn context(&self, service_origin: &str) -> Result<RecoveryContext, DescriptorError> {
        if !self
            .service_origins
            .iter()
            .any(|origin| origin == service_origin)
        {
            return Err(DescriptorError::UnknownServiceOrigin);
        }
        Ok(RecoveryContext {
            service_origin: service_origin.to_owned(),
            bundle_locator: self.bundle_locator.clone(),
        })
    }
}

/// The printable and QR recovery kit.
///
/// A seed with no way to find the encrypted bundle is not a complete kit, so the kit names the
/// configured service origins and the stable bundle locator alongside the seed.
///
/// `Debug` is derived, and the seed redacts itself, so a kit can be logged without publishing the
/// owner's recovery authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RecoveryKit {
    /// The kit format and cryptographic profile version.
    pub profile_version: U64,
    /// The 256-bit recovery seed. It zeroises when the kit is dropped and never appears in debug
    /// output: it is the whole of the owner's recovery authority.
    pub seed: SecretBytes32,
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

    fn enrolment(writer_key: u8, revision: u64) -> BackupWriterRecordPayload {
        BackupWriterRecordPayload {
            archive_id: ArchiveId::new(Uuid::from_bytes([9; 16])),
            writer: TrustedWriter {
                writer_key_id: KeyId::from_bytes([writer_key; 32]),
                signing_key: AuthorisationKey::from_bytes([writer_key; 32]),
                enrolled_at_ms: TimestampMs::new(1_000),
            },
            writer_revision: BackupWriterRevision::new(revision),
            owner_key_id: KeyId::from_bytes([0x0e; 32]),
            enrolled_at_ms: TimestampMs::new(1_000),
        }
    }

    fn publication(writer_key: u8) -> BackupGenerationPublication {
        let manifest = object_ref(7);
        BackupGenerationPublication {
            payload: BackupGenerationPublicationPayload {
                descriptor: descriptor(vec![wrap(&manifest, 1)]),
                writer_key_id: KeyId::from_bytes([writer_key; 32]),
                published_at_ms: TimestampMs::new(2_000),
            },
            signature: Signature64::from_bytes([0x5e; 64]),
        }
    }

    #[test]
    fn a_publication_is_admitted_for_the_writer_the_owner_enrolled() {
        let enrolled = enrolment(0x77, 1);
        let published = publication(0x77);
        assert_eq!(published.check_structure(1024, &enrolled), Ok(()));
        assert_eq!(published.backup_generation(), BackupGeneration::new(3));
    }

    #[test]
    fn a_publication_by_another_writer_is_refused() {
        let enrolled = enrolment(0x77, 1);
        assert_eq!(
            publication(0x78).check_structure(1024, &enrolled),
            Err(DescriptorError::WriterNotEnrolled)
        );
    }

    #[test]
    fn a_publication_for_another_archive_is_refused() {
        let mut enrolled = enrolment(0x77, 1);
        enrolled.archive_id = ArchiveId::new(Uuid::from_bytes([0x0a; 16]));
        assert_eq!(
            publication(0x77).check_structure(1024, &enrolled),
            Err(DescriptorError::WrapArchiveMismatch)
        );
    }

    #[test]
    fn a_publication_whose_descriptor_is_over_the_limit_is_refused_first() {
        let enrolled = enrolment(0x77, 1);
        assert!(matches!(
            publication(0x77).check_structure(MAX_ARCHIVE_DESCRIPTOR_LEN + 1, &enrolled),
            Err(DescriptorError::TooLarge { .. })
        ));
    }

    #[test]
    fn the_two_backup_domains_cover_different_bytes() {
        let enrolled = enrolment(0x77, 1);
        let published = publication(0x77);
        let writer_bytes = enrolled.signing_input().expect("an enrolment input");
        let publication_bytes = published
            .payload
            .signing_input()
            .expect("a publication input");
        assert_ne!(writer_bytes, publication_bytes);
        assert!(
            writer_bytes
                .windows(BACKUP_WRITER_DOMAIN.len())
                .any(|window| window == BACKUP_WRITER_DOMAIN.as_bytes())
        );
        assert!(
            publication_bytes
                .windows(BACKUP_PUBLICATION_DOMAIN.len())
                .any(|window| window == BACKUP_PUBLICATION_DOMAIN.as_bytes())
        );
    }

    #[test]
    fn an_enrolment_of_a_later_revision_covers_different_bytes() {
        assert_ne!(
            enrolment(0x77, 1).signing_input().expect("an input"),
            enrolment(0x77, 2).signing_input().expect("an input")
        );
    }

    #[test]
    fn the_key_wrap_prefix_is_the_canonical_encoding() {
        let manifest = object_ref(7);
        let wrap = wrap(&manifest, 1);
        let key = [0xabu8; OBJECT_KEY_LEN];
        let assembled = key_wrap_plaintext(&wrap.context, &key).expect("a plaintext");
        let through_the_tree = kr_cbor::encode(&CanonicalValue::Array(vec![
            kr_cbor::to_canonical_value(&wrap.context).expect("a context"),
            CanonicalValue::bytes(key.as_slice()),
        ]));
        assert_eq!(assembled, through_the_tree);
        assert_eq!(
            key_wrap_prefix(&wrap.context).expect("a prefix").len() + OBJECT_KEY_LEN,
            assembled.len()
        );
    }

    #[test]
    fn a_descriptor_of_another_version_is_rejected() {
        let manifest = object_ref(7);
        let mut descriptor = descriptor(vec![wrap(&manifest, 1)]);
        descriptor.version = U64::new(2);
        assert!(matches!(
            descriptor.validate(1024),
            Err(DescriptorError::UnsupportedVersion { version: 2 })
        ));
    }

    #[test]
    fn a_wrap_from_another_generation_is_rejected() {
        let manifest = object_ref(7);
        let mut moved = wrap(&manifest, 1);
        moved.context.backup_generation = BackupGeneration::new(4);
        assert!(matches!(
            descriptor(vec![moved]).validate(1024),
            Err(DescriptorError::WrapArchiveMismatch)
        ));
    }

    #[test]
    fn a_kit_only_yields_a_context_for_an_origin_it_names() {
        let kit = RecoveryKit {
            profile_version: U64::new(1),
            seed: SecretBytes32::from_bytes([1; 32]),
            seed_checksum: Bytes::new(vec![2; 4]),
            service_origins: vec!["https://reach.kala.to".to_owned()],
            bundle_locator: "opaque-locator".to_owned(),
        };
        let context = kit.context("https://reach.kala.to").expect("a context");
        assert_eq!(context.bundle_locator, "opaque-locator");
        assert!(matches!(
            kit.context("https://elsewhere.example"),
            Err(DescriptorError::UnknownServiceOrigin)
        ));
        // A different origin changes the bytes the bundle key is bound to.
        let other = RecoveryContext {
            service_origin: "https://elsewhere.example".to_owned(),
            bundle_locator: context.bundle_locator.clone(),
        };
        assert_ne!(
            context.to_canonical_bytes().expect("bytes"),
            other.to_canonical_bytes().expect("bytes")
        );
    }

    #[test]
    fn an_oversized_descriptor_fails_before_it_is_decoded() {
        let oversized = vec![0u8; MAX_ARCHIVE_DESCRIPTOR_LEN + 1];
        assert!(matches!(
            ArchiveDescriptor::from_canonical_bytes(&oversized),
            Err(DescriptorError::TooLarge { .. })
        ));
    }

    #[test]
    fn a_descriptor_round_trips_through_its_bounded_entry_point() {
        let manifest = object_ref(7);
        let descriptor = descriptor(vec![wrap(&manifest, 1)]);
        let bytes = kr_cbor::to_canonical_vec(&descriptor).expect("canonical bytes");
        assert_eq!(
            ArchiveDescriptor::from_canonical_bytes(&bytes).expect("a descriptor"),
            descriptor
        );
    }

    #[test]
    fn a_recovery_kit_redacts_its_seed() {
        let kit = RecoveryKit {
            profile_version: U64::new(RECOVERY_KIT_PROFILE_VERSION),
            seed: SecretBytes32::from_bytes([7; 32]),
            seed_checksum: Bytes::new(vec![1; 4]),
            service_origins: vec!["https://reach.kala.to".to_owned()],
            bundle_locator: "opaque-locator".to_owned(),
        };
        let rendered = format!("{kit:?}");
        assert!(rendered.contains("SecretBytes32(redacted)"));
        assert!(!rendered.contains(&crate::scalars::to_base64url(&[7u8; 32])));
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
