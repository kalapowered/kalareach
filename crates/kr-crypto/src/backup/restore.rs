//! Opening one sealed generation again.
//!
//! The order here is a rule rather than a convenience. The descriptor is bounded and validated
//! before anything is allocated; the manifest is decrypted and its signature verified against the
//! owner's trusted writers; and only then can a member object be restored, through a wrap bound to
//! the object identifier and encrypted hash the *manifest* named.

use kr_protocol::archive::{
    ArchiveDescriptor, ManifestObject, ManifestPayload, SealedKeyWrap, SignedArchiveManifest,
    TrustedWriter,
};
use kr_protocol::ids::BackupObjectId;
use kr_protocol::scalars::{KeyId, StoredEnvelopeKey};

use crate::archive;
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

/// One archive whose manifest has been decrypted and verified.
///
/// Holding one is the evidence that the verification happened: there is no way to build it without
/// a descriptor that validated, a manifest that decrypted, and a signature that verified against a
/// writer the caller supplied. [`Self::restore_object`] is therefore reachable only after all
/// three.
#[derive(Debug)]
pub struct OpenArchive {
    descriptor: ArchiveDescriptor,
    manifest: SignedArchiveManifest,
    member_key_wraps: Vec<SealedKeyWrap>,
    reader_key_id: KeyId,
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
    descriptor_bytes: &[u8],
    encrypted_manifest: &[u8],
) -> Result<OpenArchive> {
    // Nothing is allocated for the archive before this returns: the bytes are bounded, decoded and
    // validated first, which is what section 20 means by an invalid descriptor failing before
    // object allocation or a filesystem write.
    let descriptor = ArchiveDescriptor::from_canonical_bytes(descriptor_bytes).map_err(|_| {
        CryptoError::BindingMismatch {
            what: "an archive descriptor this build will not read",
        }
    })?;

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
    let payload: ManifestPayload =
        kr_cbor::from_canonical_slice(plaintext.expose(), &kr_cbor::Limits::DEFAULT)?;

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
    })
}
