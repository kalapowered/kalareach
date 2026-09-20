//! Staging, resuming and sealing one backup generation.

use kr_protocol::archive::{
    ArchiveDescriptor, ArchiveManifest, EncryptedObjectRef, MAX_ARCHIVE_DESCRIPTOR_LEN,
    MAX_ARCHIVE_RECIPIENTS, ManifestObject, ManifestPayload, SealedKeyWrap, SignedArchiveManifest,
};
use kr_protocol::ids::{ArchiveId, BackupGeneration, BackupObjectId, DeviceId};
use kr_protocol::scalars::{Digest256, TimestampMs, U64};

use crate::archive;
use crate::backup::recipients::ArchiveRecipients;
use crate::backup::{MANIFEST_SCHEMA_VERSION, manifest_context, member_context};
use crate::error::{CryptoError, Result};
use crate::keys::{AuthorisationKeyPair, StoredEnvelopeKeyPair};
use crate::secret::SymmetricKey;
use crate::sodium;

/// The version of the public archive descriptor this producer writes.
const DESCRIPTOR_VERSION: u64 = kr_protocol::archive::ARCHIVE_DESCRIPTOR_VERSION;

/// The most recipients whose manifest-key wraps fit one descriptor, in this encoding.
///
/// Section 20 gives a descriptor two defaults, 64 KiB and 128 recipients, and the first applicable
/// one binds. A manifest-key wrap is 648 bytes here, because [`SealedKeyWrap`] carries its whole
/// authenticated context beside the box: the format, the purpose, the archive, the generation, the
/// object, the encrypted-object hash and both key identifiers. A hundred of them and the
/// descriptor's own fields come to 64 902 bytes; a hundred and one come to 65 646, which is over
/// the byte limit. So the byte limit binds first, and this is where.
///
/// `a_descriptor_refuses_the_recipient_that_takes_it_over_the_byte_limit` pins both numbers, so a
/// change to the encoding that moves them is a change a test reports rather than one that quietly
/// shrinks how many devices an archive serves.
pub const RECIPIENTS_WITHIN_DESCRIPTOR_LIMIT: usize = 100;

/// One member object, as the producer is handed it.
#[derive(Clone, Copy, Debug)]
pub struct ObjectSource<'a> {
    /// The object's identity inside the archive.
    pub object_id: BackupObjectId,
    /// The name the manifest records. Filenames live inside the encrypted manifest.
    pub filename: &'a str,
    /// The bytes to encrypt.
    pub plaintext: &'a [u8],
}

/// One encrypted object, the key that opens it and what it was made from.
///
/// The key and the source digest are encryption state. Section 20 keeps both out of service
/// storage: a producer uploads [`Self::bytes`] and publishes [`Self::reference`], and everything
/// else here stays on the device that made it.
#[derive(Debug)]
pub struct StagedObject {
    /// The reference the manifest and every wrap name.
    pub reference: EncryptedObjectRef,
    /// The name the manifest records.
    pub filename: String,
    /// The ciphertext, `secretstream` header included, ending in the final authenticated record.
    pub bytes: Vec<u8>,
    /// The object key, held until the generation is sealed and wrapped for every recipient.
    pub key: SymmetricKey,
    /// The SHA-256 of the plaintext this ciphertext was made from.
    ///
    /// It is how a resumed upload tells an unchanged source from a changed one, and it never
    /// leaves the device: a service that held it would hold a fingerprint of the plaintext.
    pub source_digest: Digest256,
}

impl StagedObject {
    /// Returns true when `plaintext` is the content this ciphertext was made from.
    #[must_use]
    pub fn matches_source(&self, plaintext: &[u8]) -> bool {
        sodium::constant_time_eq(
            &kr_cbor::sha256(plaintext),
            self.source_digest.as_bytes().as_slice(),
        )
    }
}

/// Encrypts one member object under a fresh random key.
///
/// # Errors
///
/// Returns an error when libsodium is unavailable or reports a failure.
pub fn stage_object(source: &ObjectSource<'_>) -> Result<StagedObject> {
    let object = archive::encrypt_object(source.object_id, source.plaintext)?;
    Ok(StagedObject {
        reference: object.reference,
        filename: source.filename.to_owned(),
        bytes: object.bytes,
        key: object.key,
        source_digest: Digest256::from_bytes(kr_cbor::sha256(source.plaintext)),
    })
}

/// What resuming an upload did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResumeDecision {
    /// The source is what it was, so the ciphertext already created is uploaded again from where
    /// it stopped. No byte is re-encrypted and no key changes.
    ReusedCiphertext,
    /// The source changed, so encryption restarted under a new random key.
    ///
    /// Continuing the old ciphertext would have produced an object whose records came from two
    /// different sources under one key, which is not a backup of either of them.
    ReencryptedUnderNewKey,
}

/// A resumed object and what resuming it did.
#[derive(Debug)]
pub struct ResumedObject {
    /// The object to upload.
    pub staged: StagedObject,
    /// Whether the ciphertext was reused or made again.
    pub decision: ResumeDecision,
}

/// Resumes one object's upload.
///
/// `previous` is what this device staged before the upload stopped. When the source is unchanged
/// the same ciphertext is returned, so the upload continues from the byte it reached rather than
/// starting again. When it changed, encryption restarts under a new key.
///
/// Resuming never reuses a nonce for a new wrap: a wrap is sealed by
/// [`crate::archive::wrap_object_key`], which draws a fresh nonce for every call, and sealing a
/// generation is a new call whether or not its ciphertext is new.
///
/// # Errors
///
/// Returns an error when libsodium is unavailable or reports a failure.
pub fn resume_object(previous: StagedObject, source: &ObjectSource<'_>) -> Result<ResumedObject> {
    if previous.reference.object_id == source.object_id && previous.matches_source(source.plaintext)
    {
        return Ok(ResumedObject {
            staged: previous,
            decision: ResumeDecision::ReusedCiphertext,
        });
    }
    Ok(ResumedObject {
        staged: stage_object(source)?,
        decision: ResumeDecision::ReencryptedUnderNewKey,
    })
}

/// What one generation is sealed against.
#[derive(Clone, Copy, Debug)]
pub struct ArchivePlan {
    /// The archive.
    pub archive_id: ArchiveId,
    /// The generation being written.
    pub backup_generation: BackupGeneration,
    /// The device that owns the archive.
    pub owner_device_id: DeviceId,
    /// The identity of the encrypted manifest object itself.
    pub manifest_object_id: BackupObjectId,
    /// When the producer wrote it, in UTC milliseconds.
    pub created_at_ms: TimestampMs,
}

/// One sealed generation, ready to upload.
#[derive(Debug)]
pub struct SealedArchive {
    /// The public descriptor. Everything else about the archive is inside the encrypted manifest.
    pub descriptor: ArchiveDescriptor,
    /// The descriptor's canonical bytes, as they were bounded and validated.
    pub descriptor_bytes: Vec<u8>,
    /// The encrypted manifest object.
    pub encrypted_manifest: Vec<u8>,
    /// The signed manifest, for a producer that records what it published.
    ///
    /// It is the same value the encrypted manifest carries. It is returned in the clear because
    /// the device that wrote it already holds the plaintext; nothing here uploads it.
    pub signed_manifest: SignedArchiveManifest,
}

/// Seals one generation: signs the manifest, wraps every key, and builds the public descriptor.
///
/// The order is section 20's. Every member key is wrapped for every recipient first, because those
/// wraps are part of the manifest object's plaintext; the manifest object is then encrypted under
/// its own random key; and that key is wrapped once per recipient into the descriptor. A recipient
/// therefore reaches a member object only through a manifest it has decrypted and verified.
///
/// # Errors
///
/// Returns [`CryptoError::TooLarge`] when the recipient set or the encoded descriptor is over
/// section 20's limits, [`CryptoError::BindingMismatch`] when there is no recipient to wrap for,
/// an encoding error when a value is outside KR-CBOR-1, and a library error when libsodium fails.
pub fn seal_archive(
    writer: &AuthorisationKeyPair,
    sender: &StoredEnvelopeKeyPair,
    recipients: &ArchiveRecipients,
    plan: &ArchivePlan,
    objects: &[StagedObject],
) -> Result<SealedArchive> {
    // The recipient bound is checked before any wrap is sealed, so an oversized set costs one
    // comparison rather than a few hundred box operations.
    if recipients.len() > MAX_ARCHIVE_RECIPIENTS {
        return Err(CryptoError::TooLarge {
            what: "the recipients of an archive",
            limit: MAX_ARCHIVE_RECIPIENTS,
            actual: recipients.len(),
        });
    }
    if recipients.is_empty() {
        return Err(CryptoError::BindingMismatch {
            what: "an archive with no authorised recipient, which nothing could open",
        });
    }

    let manifest = ArchiveManifest {
        schema_version: U64::new(MANIFEST_SCHEMA_VERSION),
        archive_id: plan.archive_id,
        owner_device_id: plan.owner_device_id,
        backup_generation: plan.backup_generation,
        objects: objects
            .iter()
            .map(|staged| ManifestObject {
                object: staged.reference.clone(),
                filename: staged.filename.clone(),
            })
            .collect(),
        created_at_ms: plan.created_at_ms,
    };
    let signed_manifest = archive::sign_manifest(writer, manifest)?;

    let sender_key_id = sender.key_id();
    let mut member_key_wraps: Vec<SealedKeyWrap> =
        Vec::with_capacity(objects.len().saturating_mul(recipients.len()));
    for staged in objects {
        for recipient in recipients.iter() {
            let context = member_context(
                plan.archive_id,
                plan.backup_generation,
                &staged.reference,
                sender_key_id,
                crate::backup::recipient_key_id(recipient),
            );
            member_key_wraps.push(archive::wrap_object_key(
                sender,
                recipient,
                context,
                &staged.key,
            )?);
        }
    }

    let payload = ManifestPayload {
        manifest: signed_manifest.clone(),
        member_key_wraps,
    };
    let mut payload_bytes = kr_cbor::to_canonical_vec(&payload)?;
    let manifest_object = archive::encrypt_object(plan.manifest_object_id, &payload_bytes);
    // The plaintext carried every member wrap and the manifest; it is cleared whether or not the
    // encryption succeeded.
    sodium::memzero(&mut payload_bytes);
    let manifest_object = manifest_object?;

    let mut manifest_key_wraps = Vec::with_capacity(recipients.len());
    for recipient in recipients.iter() {
        let context = manifest_context(
            plan.archive_id,
            plan.backup_generation,
            &manifest_object.reference,
            sender_key_id,
            crate::backup::recipient_key_id(recipient),
        );
        manifest_key_wraps.push(archive::wrap_object_key(
            sender,
            recipient,
            context,
            &manifest_object.key,
        )?);
    }

    let descriptor = ArchiveDescriptor {
        version: U64::new(DESCRIPTOR_VERSION),
        archive_id: plan.archive_id,
        backup_generation: plan.backup_generation,
        encrypted_manifest: manifest_object.reference,
        manifest_key_wraps,
    };
    let descriptor_bytes = kr_cbor::to_canonical_vec(&descriptor)?;
    // Section 20 gives a descriptor two default limits, and the first applicable one binds. This
    // is the size limit; the recipient limit was applied before any wrap was sealed.
    if descriptor_bytes.len() > MAX_ARCHIVE_DESCRIPTOR_LEN {
        return Err(CryptoError::TooLarge {
            what: "the archive descriptor this producer built",
            limit: MAX_ARCHIVE_DESCRIPTOR_LEN,
            actual: descriptor_bytes.len(),
        });
    }
    // The producer holds itself to every rule a restore enforces, so an archive this build writes
    // is one this build can read.
    descriptor
        .validate(descriptor_bytes.len())
        .map_err(|_| CryptoError::BindingMismatch {
            what: "an archive descriptor this producer built and would itself refuse",
        })?;

    Ok(SealedArchive {
        descriptor,
        descriptor_bytes,
        encrypted_manifest: manifest_object.bytes,
        signed_manifest,
    })
}
