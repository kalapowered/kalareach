//! Backup objects, key wraps, signed manifests and recovery material.
//!
//! One random 256-bit key per object, `secretstream` in 1 MiB records with the final record
//! required, and one `crypto_box_easy` wrap per authorised recipient. A signed manifest names the
//! objects and their encrypted hashes; the manifest is itself an encrypted object, so only an
//! opaque archive identifier and encrypted-object references stay outside it.
//!
//! # What a restore trusts
//!
//! A manifest signature is verified against a writer key from the owner's recovery bundle. A key
//! that an archive descriptor supplied is never trusted: [`verify_manifest`] takes the trusted
//! writers as an argument and has no way to read one out of the archive.

use kr_protocol::archive::{
    ArchiveDescriptor, ArchiveManifest, EncryptedObjectRef, KeyWrapContext, MANIFEST_DOMAIN,
    OBJECT_KEY_LEN, RecoveryBundle, SealedKeyWrap, SignedArchiveManifest, TrustedWriter,
    key_wrap_plaintext, key_wrap_prefix,
};
use kr_protocol::ids::BackupObjectId;
use kr_protocol::scalars::{Bytes, Digest256, KeyId, U64};

use crate::error::{CryptoError, Result};
use crate::kdf::RecoveryRecipient;
use crate::keys::{AuthorisationKeyPair, StoredEnvelopeKeyPair};
use crate::sealed;
use crate::secret::{Secret, SecretVec, SymmetricKey};
use crate::sign;
use crate::sodium;
use crate::stream;

/// One encrypted backup object and the key that opens it.
///
/// The key is kept only until it has been wrapped for every recipient. Plaintext object keys and
/// encryption state never enter service storage.
#[derive(Debug)]
pub struct EncryptedObject {
    /// The reference a manifest and a key wrap name.
    pub reference: EncryptedObjectRef,
    /// The ciphertext, header included.
    pub bytes: Vec<u8>,
    /// The object key.
    pub key: SymmetricKey,
}

/// Encrypts one backup object under a fresh random key.
///
/// # Errors
///
/// Returns an error when libsodium is unavailable or reports a failure.
pub fn encrypt_object(object_id: BackupObjectId, plaintext: &[u8]) -> Result<EncryptedObject> {
    let key = SymmetricKey::random()?;
    let bytes = stream::encrypt_object(&key, plaintext)?;
    Ok(EncryptedObject {
        reference: EncryptedObjectRef {
            object_id,
            encrypted_object_hash: Digest256::from_bytes(kr_cbor::sha256(&bytes)),
            encrypted_len: U64::new(bytes.len() as u64),
        },
        bytes,
        key,
    })
}

/// Decrypts one backup object after checking it against the reference that names it.
///
/// # Errors
///
/// Returns [`CryptoError::HashMismatch`] when the stored bytes are not the ones the manifest
/// named, and an authentication error when a record or the final record fails.
pub fn decrypt_object(
    key: &SymmetricKey,
    reference: &EncryptedObjectRef,
    bytes: &[u8],
) -> Result<SecretVec> {
    if bytes.len() as u64 != reference.encrypted_len.get() {
        return Err(CryptoError::HashMismatch {
            what: "the stored length of an encrypted object",
        });
    }
    let hash = kr_cbor::sha256(bytes);
    if !sodium::constant_time_eq(&hash, reference.encrypted_object_hash.as_bytes()) {
        return Err(CryptoError::HashMismatch {
            what: "an encrypted object",
        });
    }
    stream::decrypt_object(key, bytes)
}

/// Wraps one object key for one recipient.
///
/// The context binds the wrap to one object, one generation and one recipient. The nonce is fresh
/// for every wrap, so reusing stored ciphertext when an upload resumes never reuses a nonce.
///
/// # Errors
///
/// Returns [`CryptoError::BindingMismatch`] when the context does not name the two keys actually
/// used, and a library error when libsodium fails.
pub fn wrap_object_key(
    sender: &StoredEnvelopeKeyPair,
    recipient: &kr_protocol::scalars::StoredEnvelopeKey,
    context: KeyWrapContext,
    object_key: &SymmetricKey,
) -> Result<SealedKeyWrap> {
    if context.sender_key_id != sender.key_id() {
        return Err(CryptoError::BindingMismatch {
            what: "the sender key identifier in a key wrap",
        });
    }
    if context.recipient_key_id
        != crate::keys::key_id(
            kr_protocol::pairing::KeyPurpose::StoredEnvelope,
            recipient.as_bytes(),
        )
    {
        return Err(CryptoError::BindingMismatch {
            what: "the recipient key identifier in a key wrap",
        });
    }
    let mut plaintext = key_wrap_plaintext(&context, object_key.expose())?;
    let sealed_result = sealed::seal_stored_envelope(sender, recipient, &plaintext);
    sodium::memzero(&mut plaintext);
    let (nonce, ciphertext) = sealed_result?;
    Ok(SealedKeyWrap {
        context,
        nonce,
        ciphertext: Bytes::new(ciphertext),
    })
}

/// Opens one key wrap, checking it against the context the caller expects.
///
/// The expected context comes from the manifest or the descriptor the caller is restoring, so a
/// wrap moved to another object or another generation fails before its key is used.
///
/// # Errors
///
/// Returns [`CryptoError::BindingMismatch`] when the wrap's context is not the expected one, and
/// an authentication error when the wrap does not open.
pub fn unwrap_object_key(
    recipient: &StoredEnvelopeKeyPair,
    sender: &kr_protocol::scalars::StoredEnvelopeKey,
    wrap: &SealedKeyWrap,
    expected: &KeyWrapContext,
) -> Result<SymmetricKey> {
    check_wrap_parties(expected, sender, &recipient.key_id())?;
    let opened =
        sealed::open_stored_envelope(recipient, sender, &wrap.nonce, wrap.ciphertext.as_slice())?;
    read_wrapped_key(&opened, &wrap.context, expected)
}

/// Opens one key wrap with the recovery recipient derived from the owner's seed.
///
/// A restore that has only the recovery kit uses this: every recovery-enabled archive wraps its
/// manifest key for the recipient the seed derives, so a future archive stays readable without
/// copying a device private key.
///
/// # Errors
///
/// Returns [`CryptoError::BindingMismatch`] when the wrap's context is not the expected one or
/// does not name the two keys used, and an authentication error when the wrap does not open.
pub fn unwrap_object_key_with_recovery(
    recovery: &RecoveryRecipient,
    sender: &kr_protocol::scalars::StoredEnvelopeKey,
    wrap: &SealedKeyWrap,
    expected: &KeyWrapContext,
) -> Result<SymmetricKey> {
    let recipient_key_id = crate::keys::key_id(
        kr_protocol::pairing::KeyPurpose::StoredEnvelope,
        recovery.public().as_bytes(),
    );
    check_wrap_parties(expected, sender, &recipient_key_id)?;
    let opened = SecretVec::new(sodium::box_open_easy(
        wrap.ciphertext.as_slice(),
        wrap.nonce.as_bytes(),
        sender.as_bytes(),
        recovery.secret().expose(),
    )?);
    read_wrapped_key(&opened, &wrap.context, expected)
}

/// Checks that the expected context names the two keys the caller is actually using.
///
/// `crypto_box` derives one shared secret from either direction, so a wrap sealed from A to B also
/// opens from B to A. Without this check a recipient could open a wrap addressed to the sender and
/// accept it as its own.
fn check_wrap_parties(
    expected: &KeyWrapContext,
    sender: &kr_protocol::scalars::StoredEnvelopeKey,
    recipient_key_id: &KeyId,
) -> Result<()> {
    if &expected.recipient_key_id != recipient_key_id {
        return Err(CryptoError::BindingMismatch {
            what: "the recipient of a key wrap, which is not the key opening it",
        });
    }
    let sender_key_id = crate::keys::key_id(
        kr_protocol::pairing::KeyPurpose::StoredEnvelope,
        sender.as_bytes(),
    );
    if expected.sender_key_id != sender_key_id {
        return Err(CryptoError::BindingMismatch {
            what: "the sender of a key wrap, which is not the key it is opened against",
        });
    }
    Ok(())
}

/// Reads the object key out of an opened wrap.
///
/// The plaintext is `CBOR([context, key])`. Rather than decoding it, which would put the key in a
/// value tree no caller can zeroise, the expected prefix is rebuilt and compared: a wrap whose
/// authenticated context is not the expected one fails here, and the key is the remaining 32 bytes.
fn read_wrapped_key(
    opened: &SecretVec,
    declared: &KeyWrapContext,
    expected: &KeyWrapContext,
) -> Result<SymmetricKey> {
    if declared != expected {
        return Err(CryptoError::BindingMismatch {
            what: "the context of a key wrap",
        });
    }
    let prefix = key_wrap_prefix(expected)?;
    let bytes = opened.expose();
    if bytes.len() != prefix.len() + OBJECT_KEY_LEN {
        return Err(CryptoError::BindingMismatch {
            what: "the length of a key wrap plaintext",
        });
    }
    if !sodium::constant_time_eq(&bytes[..prefix.len()], &prefix) {
        return Err(CryptoError::BindingMismatch {
            what: "the context inside a key wrap",
        });
    }
    Secret::from_slice("a wrapped object key", &bytes[prefix.len()..])
}

/// Signs a manifest with a backup writer's authorisation key.
///
/// # Errors
///
/// Returns an encoding error when the manifest is outside KR-CBOR-1, and a library error when
/// libsodium fails.
pub fn sign_manifest(
    writer: &AuthorisationKeyPair,
    manifest: ArchiveManifest,
) -> Result<SignedArchiveManifest> {
    let signature = sign::sign_object(writer, MANIFEST_DOMAIN, &manifest)?;
    Ok(SignedArchiveManifest {
        manifest,
        writer_key_id: writer.key_id(),
        signature,
    })
}

/// Verifies a manifest against the owner's trusted writers.
///
/// # Errors
///
/// Returns [`CryptoError::BindingMismatch`] when the named writer is not trusted, and
/// [`CryptoError::Authentication`] when the signature does not verify.
pub fn verify_manifest(
    trusted_writers: &[TrustedWriter],
    signed: &SignedArchiveManifest,
) -> Result<()> {
    let writer = trusted_writers
        .iter()
        .find(|writer| writer.writer_key_id == signed.writer_key_id)
        .ok_or(CryptoError::BindingMismatch {
            what: "the backup writer of a manifest, which is not in the recovery bundle",
        })?;
    verify_writer_key(writer)?;
    sign::verify_object(
        &writer.signing_key,
        MANIFEST_DOMAIN,
        &signed.manifest,
        &signed.signature,
    )
}

/// Checks that a trusted writer's identifier is the identifier of its own signing key.
fn verify_writer_key(writer: &TrustedWriter) -> Result<()> {
    let expected = crate::keys::key_id(
        kr_protocol::pairing::KeyPurpose::Authorisation,
        writer.signing_key.as_bytes(),
    );
    if writer.writer_key_id != expected {
        return Err(CryptoError::BindingMismatch {
            what: "a trusted writer's key identifier",
        });
    }
    Ok(())
}

/// Returns the manifest-key wrap addressed to `recipient`, if the descriptor carries one.
#[must_use]
pub fn manifest_wrap_for<'a>(
    descriptor: &'a ArchiveDescriptor,
    recipient: &KeyId,
) -> Option<&'a SealedKeyWrap> {
    descriptor
        .manifest_key_wraps
        .iter()
        .find(|wrap| &wrap.context.recipient_key_id == recipient)
}

/// Encrypts a recovery bundle under the key the seed derives for one retrieval context.
///
/// The `secretstream` object authenticates the bundle, and its key is bound to the origin and
/// locator it is stored at, so nothing else has to sign it. A restore that has only the kit can
/// therefore authenticate the bundle; requiring a separate owner signing key would ask the kit for
/// something it does not carry.
///
/// # Errors
///
/// Returns an encoding error when the bundle is outside KR-CBOR-1, and a library error when
/// libsodium fails.
pub fn encrypt_recovery_bundle(key: &SymmetricKey, bundle: &RecoveryBundle) -> Result<Vec<u8>> {
    let mut encoded = kr_cbor::to_canonical_vec(bundle)?;
    let object = stream::encrypt_object(key, &encoded);
    sodium::memzero(&mut encoded);
    object
}

/// Decrypts a recovery bundle.
///
/// The key comes from [`crate::kdf::RecoverySeed::bundle_key_for`], which mixes the seed with the
/// origin and locator being read. Origin or locator substitution therefore fails authentication
/// here rather than causing trust in archive-supplied writer keys.
///
/// # Errors
///
/// Returns an authentication error when the object does not open, and an encoding error when the
/// plaintext is not a valid bundle.
pub fn decrypt_recovery_bundle(key: &SymmetricKey, object: &[u8]) -> Result<RecoveryBundle> {
    let plaintext = stream::decrypt_object(key, object)?;
    Ok(kr_cbor::from_canonical_slice(
        plaintext.expose(),
        &kr_cbor::Limits::DEFAULT,
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_protocol::archive::{
        ArchiveCheckpoint, KeyWrapFormat, KeyWrapPurpose, MAX_ARCHIVE_RECIPIENTS, ManifestObject,
    };
    use kr_protocol::ids::{ArchiveId, BackupGeneration, DeviceId};
    use kr_protocol::pairing::KeyPurpose;
    use kr_protocol::scalars::{CanonicalSet, TimestampMs, Uuid};

    fn archive_id() -> ArchiveId {
        ArchiveId::new(Uuid::from_bytes([1; 16]))
    }

    fn object_id() -> BackupObjectId {
        BackupObjectId::new(Uuid::from_bytes([2; 16]))
    }

    fn context(
        sender: &StoredEnvelopeKeyPair,
        recipient: &StoredEnvelopeKeyPair,
        reference: &EncryptedObjectRef,
    ) -> KeyWrapContext {
        KeyWrapContext {
            format: KeyWrapFormat::V1,
            purpose: KeyWrapPurpose::ObjectKey,
            archive_id: archive_id(),
            backup_generation: BackupGeneration::new(7),
            object_id: reference.object_id,
            encrypted_object_hash: reference.encrypted_object_hash,
            sender_key_id: sender.key_id(),
            recipient_key_id: recipient.key_id(),
        }
    }

    #[test]
    fn an_object_is_encrypted_under_its_own_key_and_restored_through_its_wrap() {
        let sender = StoredEnvelopeKeyPair::generate().expect("a keypair");
        let recipient = StoredEnvelopeKeyPair::generate().expect("a keypair");
        let object = encrypt_object(object_id(), b"the backup body").expect("an object");
        let context = context(&sender, &recipient, &object.reference);
        let wrap = wrap_object_key(&sender, recipient.public(), context.clone(), &object.key)
            .expect("a wrap");

        let key = unwrap_object_key(&recipient, sender.public(), &wrap, &context).expect("the key");
        let restored = decrypt_object(&key, &object.reference, &object.bytes).expect("the body");
        assert_eq!(restored.expose(), b"the backup body");
    }

    #[test]
    fn two_objects_get_two_keys() {
        let first = encrypt_object(object_id(), b"body").expect("an object");
        let second = encrypt_object(object_id(), b"body").expect("an object");
        assert!(!first.key.constant_time_eq(&second.key));
        assert_ne!(first.bytes, second.bytes);
    }

    #[test]
    fn a_wrap_moved_to_another_object_is_rejected() {
        let sender = StoredEnvelopeKeyPair::generate().expect("a keypair");
        let recipient = StoredEnvelopeKeyPair::generate().expect("a keypair");
        let object = encrypt_object(object_id(), b"body").expect("an object");
        let context = context(&sender, &recipient, &object.reference);
        let wrap = wrap_object_key(&sender, recipient.public(), context.clone(), &object.key)
            .expect("a wrap");

        let mut moved = context;
        moved.object_id = BackupObjectId::new(Uuid::from_bytes([9; 16]));
        assert!(matches!(
            unwrap_object_key(&recipient, sender.public(), &wrap, &moved),
            Err(CryptoError::BindingMismatch { .. })
        ));
    }

    #[test]
    fn a_wrap_whose_outer_context_was_rewritten_is_rejected() {
        let sender = StoredEnvelopeKeyPair::generate().expect("a keypair");
        let recipient = StoredEnvelopeKeyPair::generate().expect("a keypair");
        let object = encrypt_object(object_id(), b"body").expect("an object");
        let context = context(&sender, &recipient, &object.reference);
        let mut wrap = wrap_object_key(&sender, recipient.public(), context.clone(), &object.key)
            .expect("a wrap");
        wrap.context.backup_generation = BackupGeneration::new(8);
        let mut expected = context;
        expected.backup_generation = BackupGeneration::new(8);
        // The outer context now matches what the caller expects, but the box authenticates the
        // original context, so the open fails.
        assert!(unwrap_object_key(&recipient, sender.public(), &wrap, &expected).is_err());
    }

    #[test]
    fn a_tampered_object_fails_its_hash_before_it_is_decrypted() {
        let object = encrypt_object(object_id(), b"body").expect("an object");
        let mut bytes = object.bytes.clone();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        assert!(matches!(
            decrypt_object(&object.key, &object.reference, &bytes),
            Err(CryptoError::HashMismatch { .. })
        ));
    }

    fn manifest(reference: EncryptedObjectRef) -> ArchiveManifest {
        ArchiveManifest {
            schema_version: U64::new(1),
            archive_id: archive_id(),
            owner_device_id: DeviceId::new(Uuid::from_bytes([3; 16])),
            backup_generation: BackupGeneration::new(7),
            objects: vec![ManifestObject {
                object: reference,
                filename: "session-history.cbor".to_owned(),
            }],
            created_at_ms: TimestampMs::new(1_700_000_000_000),
        }
    }

    fn trusted(writer: &AuthorisationKeyPair) -> TrustedWriter {
        TrustedWriter {
            writer_key_id: writer.key_id(),
            signing_key: *writer.public(),
            enrolled_at_ms: TimestampMs::new(1),
        }
    }

    #[test]
    fn a_manifest_verifies_against_a_trusted_writer_only() {
        let writer = AuthorisationKeyPair::generate().expect("a keypair");
        let impostor = AuthorisationKeyPair::generate().expect("a keypair");
        let object = encrypt_object(object_id(), b"body").expect("an object");
        let signed = sign_manifest(&writer, manifest(object.reference)).expect("a signed manifest");

        assert!(verify_manifest(&[trusted(&writer)], &signed).is_ok());
        assert!(matches!(
            verify_manifest(&[trusted(&impostor)], &signed),
            Err(CryptoError::BindingMismatch { .. })
        ));
    }

    #[test]
    fn a_writer_key_supplied_by_the_archive_is_never_trusted() {
        // A descriptor cannot introduce a writer: verification takes the trusted set as an
        // argument, and a writer whose identifier does not match its own key is rejected even if
        // it reaches the trusted list.
        let writer = AuthorisationKeyPair::generate().expect("a keypair");
        let impostor = AuthorisationKeyPair::generate().expect("a keypair");
        let object = encrypt_object(object_id(), b"body").expect("an object");
        let signed = sign_manifest(&writer, manifest(object.reference)).expect("a signed manifest");
        let forged = TrustedWriter {
            writer_key_id: writer.key_id(),
            signing_key: *impostor.public(),
            enrolled_at_ms: TimestampMs::new(1),
        };
        assert!(matches!(
            verify_manifest(&[forged], &signed),
            Err(CryptoError::BindingMismatch {
                what: "a trusted writer's key identifier"
            })
        ));
    }

    #[test]
    fn a_recovery_bundle_round_trips_under_the_seed_derived_key() {
        let owner = AuthorisationKeyPair::generate().expect("a keypair");
        let seed = crate::kdf::RecoverySeed::generate().expect("a seed");
        let context = kr_protocol::archive::RecoveryContext {
            service_origin: "https://reach.kala.to".to_owned(),
            bundle_locator: "opaque-locator".to_owned(),
        };
        let key = seed.bundle_key_for(&context).expect("a bundle key");
        let bundle = RecoveryBundle {
            schema_version: U64::new(1),
            collections: Vec::new(),
            trusted_writers: [trusted(&owner)].into_iter().collect(),
            checkpoints: [ArchiveCheckpoint {
                archive_id: archive_id(),
                backup_generation: BackupGeneration::new(7),
                encrypted_manifest_hash: Digest256::from_bytes([4; 32]),
                verified_at_ms: TimestampMs::new(2),
            }]
            .into_iter()
            .collect::<CanonicalSet<_>>(),
            revision: U64::new(3),
            written_at_ms: TimestampMs::new(2),
        };
        let object = encrypt_recovery_bundle(&key, &bundle).expect("an encrypted bundle");
        assert_eq!(
            decrypt_recovery_bundle(&key, &object).expect("the bundle"),
            bundle
        );

        // The same seed and the same ciphertext, retrieved from another origin or under another
        // locator, does not authenticate.
        for substituted in [
            kr_protocol::archive::RecoveryContext {
                service_origin: "https://elsewhere.example".to_owned(),
                ..context.clone()
            },
            kr_protocol::archive::RecoveryContext {
                bundle_locator: "another-locator".to_owned(),
                ..context.clone()
            },
        ] {
            let wrong = seed.bundle_key_for(&substituted).expect("a bundle key");
            assert!(decrypt_recovery_bundle(&wrong, &object).is_err());
        }
    }

    #[test]
    fn a_descriptor_finds_the_wrap_for_one_recipient() {
        let sender = StoredEnvelopeKeyPair::generate().expect("a keypair");
        let recipient = StoredEnvelopeKeyPair::generate().expect("a keypair");
        let other = StoredEnvelopeKeyPair::generate().expect("a keypair");
        let object = encrypt_object(object_id(), b"manifest").expect("an object");
        let mut context = context(&sender, &recipient, &object.reference);
        context.purpose = KeyWrapPurpose::ManifestKey;
        let wrap =
            wrap_object_key(&sender, recipient.public(), context, &object.key).expect("a wrap");
        let descriptor = ArchiveDescriptor {
            version: U64::new(1),
            archive_id: archive_id(),
            backup_generation: BackupGeneration::new(7),
            encrypted_manifest: object.reference.clone(),
            manifest_key_wraps: vec![wrap],
        };
        assert!(descriptor.validate(2048).is_ok());
        assert!(manifest_wrap_for(&descriptor, &recipient.key_id()).is_some());
        assert!(manifest_wrap_for(&descriptor, &other.key_id()).is_none());
        assert!(descriptor.manifest_key_wraps.len() <= MAX_ARCHIVE_RECIPIENTS);
    }

    #[test]
    fn the_recovery_recipient_can_open_a_manifest_wrap() {
        let sender = StoredEnvelopeKeyPair::generate().expect("a keypair");
        let seed = crate::kdf::RecoverySeed::generate().expect("a seed");
        let recovery = seed.recipient().expect("a recipient");
        let object = encrypt_object(object_id(), b"manifest").expect("an object");
        let mut context = context(&sender, &sender, &object.reference);
        context.purpose = KeyWrapPurpose::ManifestKey;
        context.recipient_key_id =
            crate::keys::key_id(KeyPurpose::StoredEnvelope, recovery.public().as_bytes());
        let wrap = wrap_object_key(&sender, recovery.public(), context.clone(), &object.key)
            .expect("a wrap");

        // The recovery recipient opens the wrap with the key the seed derives, so a future archive
        // stays recoverable without copying a device private key.
        let other = StoredEnvelopeKeyPair::generate().expect("a keypair");
        assert!(
            unwrap_object_key(&other, sender.public(), &wrap, &context).is_err(),
            "another device cannot open it"
        );

        let key = unwrap_object_key_with_recovery(&recovery, sender.public(), &wrap, &context)
            .expect("the recovery recipient opens it");
        assert!(key.constant_time_eq(&object.key));
    }
}
