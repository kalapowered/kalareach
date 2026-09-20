//! Staging, resuming and sealing one backup generation.

use kr_protocol::archive::{
    ARCHIVE_MANIFEST_SCHEMA_VERSION, ArchiveDescriptor, ArchiveManifest, EncryptedObjectRef,
    MANIFEST_PAYLOAD_LIMITS, MAX_ARCHIVE_DESCRIPTOR_LEN, MAX_ARCHIVE_RECIPIENTS,
    MAX_MANIFEST_KEY_WRAPS, MAX_MANIFEST_OBJECTS, MAX_MANIFEST_PAYLOAD_LEN, ManifestObject,
    ManifestPayload, SealedKeyWrap, SignedArchiveManifest,
};
use kr_protocol::ids::{ArchiveId, BackupGeneration, BackupObjectId, DeviceId};
use kr_protocol::scalars::{Digest256, TimestampMs, U64};

use crate::archive;
use crate::backup::recipients::{ArchiveRecipients, KeyRotation};
use crate::backup::{manifest_context, member_context};
use crate::error::{CryptoError, Result};
use crate::keys::{AuthorisationKeyPair, StoredEnvelopeKeyPair};
use crate::secret::SymmetricKey;
use crate::sodium;

/// The version of the public archive descriptor this producer writes.
const DESCRIPTOR_VERSION: u64 = kr_protocol::archive::ARCHIVE_DESCRIPTOR_VERSION;

/// About how many recipients' manifest-key wraps fit one descriptor.
///
/// Section 20 gives a descriptor two defaults, 64 KiB and 128 recipients, and the first applicable
/// one binds. In this encoding that is the byte limit, at roughly a hundred recipients rather than
/// at a hundred and twenty-eight, because [`SealedKeyWrap`] carries its whole authenticated
/// context beside the box: the format, the purpose, the archive, the generation, the object, the
/// encrypted-object hash and both key identifiers, which is 648 bytes at a small generation
/// number.
///
/// **It is a figure, not a guarantee.** A wrap grows with the integer width of the backup
/// generation, so an archive at generation 65 536 fits fewer recipients than one at generation 3.
/// [`seal_archive`] enforces the *encoded size*, which is the quantity section 20 bounds, and
/// refuses whatever does not fit; this constant is what a caller sizing a recipient set should
/// expect, and `a_descriptor_refuses_the_recipient_that_takes_it_over_the_byte_limit` and
/// `a_larger_generation_number_fits_fewer_recipients` are what keep it honest.
pub const RECIPIENTS_WITHIN_DESCRIPTOR_LIMIT: usize = 100;

/// One member object, as the producer is handed it.
///
/// `Debug` names the object and its filename and says how many bytes there are. It does not print
/// the plaintext: a derived one would put a session's content into any log that formatted it.
#[derive(Clone, Copy)]
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
///
/// **Its fields are private, and that is the rotation rule.** The only ways to obtain one are
/// [`stage_object`] and [`resume_object`], which set the rotation from the argument they were
/// given and re-encrypt when it has moved. A caller that could write the rotation could relabel
/// ciphertext a revocation invalidated and seal it into the next generation, which is the one
/// thing rotating a mutable shared collection's keys exists to prevent.
///
/// `Debug` is written rather than derived for the same reason the fields are private: the key
/// redacts itself, but the source digest is a fingerprint of the plaintext and a derived `Debug`
/// would print it.
pub struct StagedObject {
    reference: EncryptedObjectRef,
    filename: String,
    bytes: Vec<u8>,
    key: SymmetricKey,
    source_digest: Digest256,
    rotation: KeyRotation,
}

impl std::fmt::Debug for ObjectSource<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ObjectSource")
            .field("object_id", &self.object_id)
            .field("filename", &self.filename)
            .field("plaintext_len", &self.plaintext.len())
            .finish()
    }
}

impl std::fmt::Debug for StagedObject {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StagedObject")
            .field("reference", &self.reference)
            .field("filename", &self.filename)
            .field("encrypted_len", &self.bytes.len())
            .field("key", &self.key)
            .field("source_digest", &"Digest256(redacted)")
            .field("rotation", &self.rotation)
            .finish()
    }
}

impl StagedObject {
    /// Returns the reference the manifest and every wrap name.
    #[must_use]
    pub const fn reference(&self) -> &EncryptedObjectRef {
        &self.reference
    }

    /// Returns the object's identity.
    #[must_use]
    pub const fn object_id(&self) -> BackupObjectId {
        self.reference.object_id
    }

    /// Returns the name the manifest records.
    #[must_use]
    pub fn filename(&self) -> &str {
        &self.filename
    }

    /// Returns the ciphertext to upload: the `secretstream` header and every record, ending in the
    /// final authenticated one.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the key rotation this ciphertext was made under.
    #[must_use]
    pub const fn rotation(&self) -> KeyRotation {
        self.rotation
    }

    /// Returns true when this object is under the same key as `other`.
    ///
    /// It answers the question a caller actually has - did staging this again produce a new key? -
    /// without the key leaving this type. A rotation or a changed source is supposed to produce a
    /// different one, and this is how that is established.
    #[must_use]
    pub fn shares_key_with(&self, other: &Self) -> bool {
        self.key.constant_time_eq(&other.key)
    }

    /// Returns true when `plaintext` is the content this ciphertext was made from.
    #[must_use]
    pub fn matches_source(&self, plaintext: &[u8]) -> bool {
        sodium::constant_time_eq(
            &kr_cbor::sha256(plaintext),
            self.source_digest.as_bytes().as_slice(),
        )
    }
}

/// Encrypts one member object under a fresh random key, for one key rotation.
///
/// `rotation` is the recipient set's, from [`ArchiveRecipients::rotation`]. It travels with the
/// ciphertext so that sealing can refuse an object staged before a revocation rotated the keys.
///
/// # Errors
///
/// Returns an error when libsodium is unavailable or reports a failure.
pub fn stage_object(source: &ObjectSource<'_>, rotation: KeyRotation) -> Result<StagedObject> {
    let object = archive::encrypt_object(source.object_id, source.plaintext)?;
    Ok(StagedObject {
        reference: object.reference,
        filename: source.filename.to_owned(),
        bytes: object.bytes,
        key: object.key,
        source_digest: Digest256::from_bytes(kr_cbor::sha256(source.plaintext)),
        rotation,
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
    /// The keys rotated, so encryption restarted under a new random key.
    ///
    /// The staged ciphertext is under a key a removed recipient holds a wrap for. Reusing it would
    /// mean that a device removed from a mutable shared collection went on reading what the others
    /// wrote after it left.
    ReencryptedAfterRotation,
    /// The source is what it was, and only its filename changed.
    ///
    /// The ciphertext and the key are kept; the manifest records the name the source has now.
    ReusedCiphertextRenamed,
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
pub fn resume_object(
    mut previous: StagedObject,
    source: &ObjectSource<'_>,
    rotation: KeyRotation,
) -> Result<ResumedObject> {
    if previous.reference.object_id == source.object_id && previous.matches_source(source.plaintext)
    {
        if previous.rotation != rotation {
            // The keys rotated under it. Its ciphertext is under a key a removed recipient holds a
            // wrap for, so it is made again rather than continued.
            return Ok(ResumedObject {
                staged: stage_object(source, rotation)?,
                decision: ResumeDecision::ReencryptedAfterRotation,
            });
        }
        let renamed = previous.filename != source.filename;
        if renamed {
            // The bytes did not change and the name did. The manifest records what the source is
            // called now; re-encrypting it would be work that changed nothing.
            source.filename.clone_into(&mut previous.filename);
        }
        return Ok(ResumedObject {
            staged: previous,
            decision: if renamed {
                ResumeDecision::ReusedCiphertextRenamed
            } else {
                ResumeDecision::ReusedCiphertext
            },
        });
    }
    Ok(ResumedObject {
        staged: stage_object(source, rotation)?,
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
    if objects.len() > MAX_MANIFEST_OBJECTS {
        return Err(CryptoError::TooLarge {
            what: "the member objects of one archive generation",
            limit: MAX_MANIFEST_OBJECTS,
            actual: objects.len(),
        });
    }
    let wraps = objects.len().saturating_mul(recipients.len());
    if wraps > MAX_MANIFEST_KEY_WRAPS {
        return Err(CryptoError::TooLarge {
            what: "the member key wraps of one archive generation, which is objects times \
                   recipients",
            limit: MAX_MANIFEST_KEY_WRAPS,
            actual: wraps,
        });
    }
    // Two objects under one identity would produce a manifest that names one of them twice, which
    // the restore refuses. A producer that wrote it would have written an archive nothing opens,
    // so it is refused here instead.
    let mut seen: Vec<BackupObjectId> = Vec::with_capacity(objects.len());
    for staged in objects {
        if staged.rotation != recipients.rotation() {
            return Err(CryptoError::BindingMismatch {
                what: "an object staged before this collection's keys were rotated, which a \
                       removed recipient still holds a wrap for",
            });
        }
        if seen.contains(&staged.reference.object_id) {
            return Err(CryptoError::BindingMismatch {
                what: "two member objects under one object identifier",
            });
        }
        seen.push(staged.reference.object_id);
    }

    let manifest = ArchiveManifest {
        schema_version: U64::new(ARCHIVE_MANIFEST_SCHEMA_VERSION),
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
    // Encoded under the same bounds the restore decodes with. A producer that wrote under looser
    // ones would write an archive nothing could open, which is the one failure a backup must not
    // have: it looks like a complete backup until the day somebody needs it.
    let mut payload_bytes = kr_cbor::to_canonical_vec_within(&payload, &MANIFEST_PAYLOAD_LIMITS)?;
    if payload_bytes.len() > MAX_MANIFEST_PAYLOAD_LEN {
        sodium::memzero(&mut payload_bytes);
        return Err(CryptoError::TooLarge {
            what: "the manifest payload of one archive generation",
            limit: MAX_MANIFEST_PAYLOAD_LEN,
            actual: payload_bytes.len(),
        });
    }
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
