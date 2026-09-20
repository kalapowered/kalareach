//! Opening one sealed generation again.
//!
//! The order here is a rule rather than a convenience. The descriptor is bounded and validated
//! before anything is allocated; the manifest is decrypted and its signature verified against the
//! owner's trusted writers; and only then can a member object be restored, through a wrap bound to
//! the object identifier and encrypted hash the *manifest* named.

use kr_protocol::archive::{
    ARCHIVE_MANIFEST_SCHEMA_VERSION, ArchiveCheckpoint, ArchiveDescriptor, MANIFEST_PAYLOAD_LIMITS,
    ManifestObject, ManifestPayload, SealedKeyWrap, SignedArchiveManifest, TrustedWriter,
};
use kr_protocol::ids::{ArchiveId, BackupObjectId};
use kr_protocol::scalars::{KeyId, StoredEnvelopeKey};

use crate::archive;
use crate::backup::generations::{CheckpointSource, RestoreGeneration};
use crate::backup::{manifest_context, member_context};
use crate::error::{CryptoError, Result};
use crate::kdf::RecoveryRecipient;
use crate::keys::StoredEnvelopeKeyPair;
use crate::secret::{SecretVec, SymmetricKey};

/// Which key opens an archive's wraps.
///
/// A device restores with its own stored-envelope key. A restore that has only the recovery kit
/// uses the recipient the seed derives, which is why every recovery-enabled archive wraps its
/// manifest key for that recipient as well.
#[derive(Debug)]
pub enum ArchiveReader<'a> {
    /// A paired device's stored-envelope key.
    Device(&'a StoredEnvelopeKeyPair),
    /// The recipient derived from the owner's recovery seed.
    Recovery(&'a RecoveryRecipient),
}

impl ArchiveReader<'_> {
    /// Returns the key identifier the wraps addressed to this reader carry.
    #[must_use]
    pub fn key_id(&self) -> KeyId {
        match self {
            Self::Device(keys) => keys.key_id(),
            Self::Recovery(recovery) => crate::backup::recipient_key_id(recovery.public()),
        }
    }

    fn unwrap(
        &self,
        sender: &StoredEnvelopeKey,
        wrap: &SealedKeyWrap,
        expected: &kr_protocol::archive::KeyWrapContext,
    ) -> Result<SymmetricKey> {
        match self {
            Self::Device(keys) => archive::unwrap_object_key(keys, sender, wrap, expected),
            Self::Recovery(recovery) => {
                archive::unwrap_object_key_with_recovery(recovery, sender, wrap, expected)
            }
        }
    }
}

/// What a restore expects the archive it is opening to be.
///
/// Both halves are what section 20 ¶7 asks for. The archive identity is the collection the caller
/// means to restore, so a descriptor for another one is a substitution rather than a different
/// backup. The checkpoint is the latest generation the owner verified, which is what catches a
/// service replaying an older archive whose signature is perfectly genuine.
///
/// A restore that has no checkpoint says so by leaving it `None`, which is the recovery-only case:
/// it goes ahead, and [`RestoreGeneration::proves_no_newer_archive`] stays false either way.
#[derive(Clone, Copy, Debug)]
pub struct ArchiveExpectation<'a> {
    /// The archive the caller means to restore.
    pub archive_id: ArchiveId,
    /// The latest generation the owner verified, and where that came from.
    pub checkpoint: Option<(CheckpointSource, &'a ArchiveCheckpoint)>,
}

/// Reads a descriptor, so a caller can show what it is about to restore before it restores it.
///
/// It is the same decode and the same validation [`open_archive`] performs, exposed on its own: a
/// caller that wants to display [`RestoreGeneration::describe`] needs the descriptor first.
/// Reading one grants nothing - opening the archive enforces the same rules again - so a caller
/// that skips the display still cannot restore a replayed generation.
///
/// # Errors
///
/// Returns [`CryptoError::BindingMismatch`] when the bytes are not a descriptor this build reads.
pub fn read_descriptor(descriptor_bytes: &[u8]) -> Result<ArchiveDescriptor> {
    ArchiveDescriptor::from_canonical_bytes(descriptor_bytes).map_err(|_| {
        CryptoError::BindingMismatch {
            what: "an archive descriptor this build will not read",
        }
    })
}

/// One archive whose manifest has been decrypted and verified.
///
/// Holding one is the evidence that the verification happened: there is no way to build it without
/// a descriptor that validated, an archive identity the caller expected, a generation the owner's
/// checkpoint admits, a manifest that decrypted, and a signature that verified against a writer
/// the caller supplied. [`Self::restore_object`] is therefore reachable only after all five.
#[derive(Debug)]
pub struct OpenArchive {
    descriptor: ArchiveDescriptor,
    manifest: SignedArchiveManifest,
    member_key_wraps: Vec<SealedKeyWrap>,
    reader_key_id: KeyId,
    generation: RestoreGeneration,
}

/// One restored member object.
#[derive(Debug)]
pub struct RestoredObject {
    /// The object's identity.
    pub object_id: BackupObjectId,
    /// The filename the manifest recorded.
    pub filename: String,
    /// The plaintext, which zeroises when it is dropped.
    pub plaintext: SecretVec,
}

impl OpenArchive {
    /// Returns the public descriptor this archive was opened from.
    #[must_use]
    pub const fn descriptor(&self) -> &ArchiveDescriptor {
        &self.descriptor
    }

    /// Returns the verified manifest.
    #[must_use]
    pub const fn manifest(&self) -> &SignedArchiveManifest {
        &self.manifest
    }

    /// Returns where this generation stands against the checkpoint, which a restore displays.
    #[must_use]
    pub const fn generation(&self) -> RestoreGeneration {
        self.generation
    }

    /// Returns the member objects, in the order the producer wrote them.
    #[must_use]
    pub fn objects(&self) -> &[ManifestObject] {
        &self.manifest.manifest.objects
    }

    /// Restores one member object from its stored ciphertext.
    ///
    /// The expected wrap context is built from the *manifest's* entry, so a wrap moved to another
    /// object, another generation or another recipient fails to authenticate rather than yielding
    /// a key. The ciphertext is then checked against the manifest's hash and length before it is
    /// decrypted, and its final authenticated record is required.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::BindingMismatch`] when the manifest does not name the object or no
    /// wrap addresses this reader, [`CryptoError::HashMismatch`] when the stored bytes are not the
    /// ones the manifest named, [`CryptoError::MissingFinalRecord`] when the upload was cut short,
    /// and [`CryptoError::Authentication`] when a record fails.
    pub fn restore_object(
        &self,
        reader: &ArchiveReader<'_>,
        sender: &StoredEnvelopeKey,
        object_id: BackupObjectId,
        bytes: &[u8],
    ) -> Result<RestoredObject> {
        let entry = self
            .objects()
            .iter()
            .find(|entry| entry.object.object_id == object_id)
            .ok_or(CryptoError::BindingMismatch {
                what: "an object the verified manifest does not name",
            })?;
        let expected = member_context(
            self.manifest.manifest.archive_id,
            self.manifest.manifest.backup_generation,
            &entry.object,
            crate::backup::recipient_key_id(sender),
            self.reader_key_id,
        );
        let wrap = self
            .member_key_wraps
            .iter()
            .find(|wrap| {
                wrap.context.object_id == object_id
                    && wrap.context.recipient_key_id == self.reader_key_id
            })
            .ok_or(CryptoError::BindingMismatch {
                what: "a member key wrap addressed to this recipient",
            })?;
        let key = reader.unwrap(sender, wrap, &expected)?;
        let plaintext = archive::decrypt_object(&key, &entry.object, bytes)?;
        Ok(RestoredObject {
            object_id,
            filename: entry.filename.clone(),
            plaintext,
        })
    }
}

/// Opens one archive: validates the descriptor, decrypts the manifest and verifies its signature.
///
/// `descriptor_bytes` are the bytes as they arrived. They are bounded before they are decoded, so
/// an invalid descriptor fails before an object is allocated or a byte is written anywhere.
///
/// `trusted_writers` come from the owner's recovery bundle. Nothing here reads a signing key out
/// of the archive, so a descriptor cannot introduce a writer.
///
/// # Errors
///
/// Returns [`CryptoError::BindingMismatch`] for an invalid descriptor, a manifest that does not
/// match the descriptor, a missing wrap or an untrusted writer, [`CryptoError::HashMismatch`] when
/// the stored manifest object is not the one the descriptor named, and
/// [`CryptoError::Authentication`] when the manifest object or the signature fails.
pub fn open_archive(
    reader: &ArchiveReader<'_>,
    sender: &StoredEnvelopeKey,
    trusted_writers: &[TrustedWriter],
    expectation: &ArchiveExpectation<'_>,
    descriptor_bytes: &[u8],
    encrypted_manifest: &[u8],
) -> Result<OpenArchive> {
    // Nothing is allocated for the archive before this returns: the bytes are bounded, decoded and
    // validated first, which is what section 20 means by an invalid descriptor failing before
    // object allocation or a filesystem write.
    let descriptor = read_descriptor(descriptor_bytes)?;

    // The collection the caller meant. A valid archive of another collection, signed by a writer
    // this owner trusts and addressed to this reader, is a substitution; without this it would
    // open.
    if descriptor.archive_id != expectation.archive_id {
        return Err(CryptoError::BindingMismatch {
            what: "an archive descriptor for another collection than the one being restored",
        });
    }
    // And the generation, against the checkpoint the owner verified. Refusing here rather than
    // leaving it to the caller is what makes the checkpoint a protection instead of a report: a
    // caller that never asked still cannot restore a replayed generation.
    let generation = RestoreGeneration::against(&descriptor, expectation.checkpoint);
    if !generation.is_admissible() {
        return Err(CryptoError::BindingMismatch {
            what: "an archive generation the owner's verified checkpoint refuses",
        });
    }

    let reader_key_id = reader.key_id();
    let wrap = archive::manifest_wrap_for(&descriptor, &reader_key_id).ok_or(
        CryptoError::BindingMismatch {
            what: "a manifest key wrap addressed to this recipient",
        },
    )?;
    let expected = manifest_context(
        descriptor.archive_id,
        descriptor.backup_generation,
        &descriptor.encrypted_manifest,
        crate::backup::recipient_key_id(sender),
        reader_key_id,
    );
    let manifest_key = reader.unwrap(sender, wrap, &expected)?;
    let plaintext = archive::decrypt_object(
        &manifest_key,
        &descriptor.encrypted_manifest,
        encrypted_manifest,
    )?;
    // The same bounds the producer encoded under, so an archive this build wrote is one it reads.
    let payload: ManifestPayload =
        kr_cbor::from_canonical_slice(plaintext.expose(), &MANIFEST_PAYLOAD_LIMITS)?;

    // The signature is verified before anything else is read out of the manifest, and before any
    // member object is restored.
    archive::verify_manifest(trusted_writers, &payload.manifest)?;

    // A verified manifest that describes another archive or another generation is a mismatch, and
    // section 20 stops a restore on one rather than restoring whichever half the caller trusted.
    if payload.manifest.manifest.archive_id != descriptor.archive_id
        || payload.manifest.manifest.backup_generation != descriptor.backup_generation
    {
        return Err(CryptoError::BindingMismatch {
            what: "a manifest that names another archive or backup generation",
        });
    }
    // The signature authenticates the schema version; it does not establish that this build knows
    // what that version means. A manifest a trusted writer signed under a later schema is refused
    // rather than read under this one's rules.
    if payload.manifest.manifest.schema_version.get() != ARCHIVE_MANIFEST_SCHEMA_VERSION {
        return Err(CryptoError::BindingMismatch {
            what: "a manifest schema version this build does not read",
        });
    }
    let mut seen: Vec<BackupObjectId> = Vec::with_capacity(payload.manifest.manifest.objects.len());
    for entry in &payload.manifest.manifest.objects {
        if seen.contains(&entry.object.object_id) {
            return Err(CryptoError::BindingMismatch {
                what: "a manifest that names one object twice",
            });
        }
        seen.push(entry.object.object_id);
    }

    Ok(OpenArchive {
        descriptor,
        manifest: payload.manifest,
        member_key_wraps: payload.member_key_wraps,
        reader_key_id,
        generation,
    })
}
