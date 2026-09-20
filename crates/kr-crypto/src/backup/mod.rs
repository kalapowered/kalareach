//! The backup producer: staging objects, sealing a generation, and opening one again.
//!
//! [`crate::archive`] holds the primitives: encrypt one object, wrap one key, sign one manifest,
//! verify one manifest. This module is the layer that puts them in the order section 20 fixes, so
//! a producer does not have to remember it:
//!
//! 1. **Stage each object.** One random 256-bit key per object, `secretstream` in 1 MiB records
//!    with the final authenticated record required. [`stage_object`].
//! 2. **Resume by reusing ciphertext.** An upload that stopped part way is continued with the
//!    bytes already created, and encryption restarts under a *new* key when the source changed.
//!    [`resume_object`].
//! 3. **Seal the generation.** The manifest is signed, every member key is wrapped once per
//!    recipient, the signed manifest and those wraps become the plaintext of one more encrypted
//!    object, and the manifest key is wrapped once per recipient into the public descriptor.
//!    [`seal_archive`].
//! 4. **Open it again.** The descriptor is validated before anything is allocated, the manifest is
//!    decrypted and its signature verified against the owner's trusted writers, and only then is a
//!    member object restored. [`open_archive`].
//!
//! # What stays on the device
//!
//! A [`StagedObject`] holds its object key and the digest of the plaintext it was made from. Both
//! are encryption state, and section 20 keeps plaintext object keys and encryption state out of
//! service storage: a producer uploads [`StagedObject::bytes`] and nothing else from this type.
//!
//! # What is outside the encrypted manifest
//!
//! The opaque archive identifier and the encrypted-object references, and that is all. Filenames,
//! object identifiers and the member key wraps are inside it, because a member wrap names the
//! object identifier and the encrypted hash it is bound to.
//!
//! # Two limits, and which one binds
//!
//! Section 20 gives the public descriptor two defaults: 64 KiB and 128 recipients. The first
//! applicable one binds, and in this encoding that is the byte limit, at about
//! [`RECIPIENTS_WITHIN_DESCRIPTOR_LIMIT`] recipients rather than at 128, because a sealed key wrap
//! carries its whole authenticated context beside the box. The exact figure moves with the
//! generation's integer width, so [`seal_archive`] enforces the encoded size rather than a count
//! and names the limit it hit.
//!
//! # What a backup carries
//!
//! [`may_back_up`] and [`may_restore`] are the whole of it. They are here rather than in each
//! caller so a device and a host cannot answer the same question differently.
//!
//! # What a restore trusts
//!
//! The owner's recovery bundle, through the trusted writers passed to [`open_archive`]. An archive
//! cannot introduce a writer: nothing here reads a signing key out of a descriptor or a manifest.

mod generations;
mod material;
mod produce;
mod recipients;
mod restore;

use kr_protocol::archive::{
    EncryptedObjectRef, KeyWrapContext, KeyWrapFormat, KeyWrapPurpose, MANIFEST_DOMAIN,
};
use kr_protocol::ids::{ArchiveId, BackupGeneration};
use kr_protocol::scalars::KeyId;

pub use crate::backup::generations::{CheckpointSource, GenerationStanding, RestoreGeneration};
pub use crate::backup::material::{
    Admission, Material, RestoreAdmissions, RestoreLimits, admit_for_restore, may_back_up,
    may_restore,
};
pub use crate::backup::produce::{
    ArchivePlan, ObjectSource, RECIPIENTS_WITHIN_DESCRIPTOR_LIMIT, ResumeDecision, ResumedObject,
    SealedArchive, StagedObject, resume_object, seal_archive, stage_object,
};
pub use crate::backup::recipients::{
    ArchiveRecipients, CollectionKind, KeyRotation, RetainedObjectKeys, Revocation,
    still_readable_after_revocation,
};
pub use crate::backup::restore::{
    ArchiveExpectation, ArchiveReader, OpenArchive, RestoredObject, open_archive, read_descriptor,
};

/// The domain a manifest signature covers, re-exported so a producer names one constant.
pub const ARCHIVE_MANIFEST_DOMAIN: &str = MANIFEST_DOMAIN;

/// Builds the wrap context of one member object key.
///
/// The producer and the restore both build it here, so the context a wrap is sealed under and the
/// context it is checked against cannot drift apart. Every field section 20 lists is in it: the
/// format, the purpose, the archive, the generation, the object, the encrypted-object hash and
/// both key identifiers.
fn member_context(
    archive_id: ArchiveId,
    backup_generation: BackupGeneration,
    object: &EncryptedObjectRef,
    sender_key_id: KeyId,
    recipient_key_id: KeyId,
) -> KeyWrapContext {
    KeyWrapContext {
        format: KeyWrapFormat::V1,
        purpose: KeyWrapPurpose::ObjectKey,
        archive_id,
        backup_generation,
        object_id: object.object_id,
        encrypted_object_hash: object.encrypted_object_hash,
        sender_key_id,
        recipient_key_id,
    }
}

/// Builds the wrap context of the manifest key.
fn manifest_context(
    archive_id: ArchiveId,
    backup_generation: BackupGeneration,
    manifest: &EncryptedObjectRef,
    sender_key_id: KeyId,
    recipient_key_id: KeyId,
) -> KeyWrapContext {
    KeyWrapContext {
        format: KeyWrapFormat::V1,
        purpose: KeyWrapPurpose::ManifestKey,
        archive_id,
        backup_generation,
        object_id: manifest.object_id,
        encrypted_object_hash: manifest.encrypted_object_hash,
        sender_key_id,
        recipient_key_id,
    }
}

/// Returns the stored-envelope key identifier of one public key.
///
/// The purpose is inside the identifier, so the same 32 bytes declared under another purpose
/// produce another identifier and a wrap addressed to one cannot be opened as the other.
#[must_use]
pub fn recipient_key_id(key: &kr_protocol::scalars::StoredEnvelopeKey) -> KeyId {
    crate::keys::key_id(
        kr_protocol::pairing::KeyPurpose::StoredEnvelope,
        key.as_bytes(),
    )
}
