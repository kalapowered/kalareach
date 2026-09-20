//! The backup producer: objects, wraps, the signed manifest, the descriptor, resume and restore.
//!
//! Section 20 ¶3 to ¶7 and ¶9, from the producer's side. The service half of these rules lives in
//! the storage service; everything here is what a device does before it uploads a byte and after
//! it fetches one back.

use kr_crypto::CryptoError;
use kr_crypto::archive::{self, EncryptedObject};
use kr_crypto::backup::{
    ArchiveExpectation, ArchivePlan, ArchiveReader, ArchiveRecipients, CheckpointSource,
    CollectionKind, GenerationStanding, KeyRotation, ObjectSource,
    RECIPIENTS_WITHIN_DESCRIPTOR_LIMIT, RestoreGeneration, ResumeDecision, RetainedObjectKeys,
    SealedArchive, StagedObject, open_archive, recipient_key_id, resume_object, seal_archive,
    stage_object, still_readable_after_revocation,
};
use kr_crypto::kdf::RecoverySeed;
use kr_crypto::keys::{AuthorisationKeyPair, StoredEnvelopeKeyPair};
use kr_protocol::archive::{
    ArchiveCheckpoint, KeyWrapPurpose, MAX_ARCHIVE_DESCRIPTOR_LEN, MAX_ARCHIVE_RECIPIENTS,
    ManifestPayload, TrustedWriter,
};
use kr_protocol::ids::{ArchiveId, BackupGeneration, BackupObjectId, DeviceId};
use kr_protocol::scalars::{Digest256, StoredEnvelopeKey, TimestampMs, U64, Uuid};

const RECORD_LEN: usize = kr_protocol::archive::SECRETSTREAM_RECORD_LEN;

fn archive_id() -> ArchiveId {
    ArchiveId::new(Uuid::from_bytes([0x11; 16]))
}

fn object_id(seed: u8) -> BackupObjectId {
    BackupObjectId::new(Uuid::from_bytes([seed; 16]))
}

fn owner() -> DeviceId {
    DeviceId::new(Uuid::from_bytes([0x33; 16]))
}

fn plan(generation: u64) -> ArchivePlan {
    ArchivePlan {
        archive_id: archive_id(),
        backup_generation: BackupGeneration::new(generation),
        owner_device_id: owner(),
        manifest_object_id: object_id(0xf0),
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

/// One producer and one device that restores from it.
struct Parties {
    writer: AuthorisationKeyPair,
    sender: StoredEnvelopeKeyPair,
    device: StoredEnvelopeKeyPair,
}

impl Parties {
    fn generate() -> Self {
        Self {
            writer: AuthorisationKeyPair::generate().expect("a writer key"),
            sender: StoredEnvelopeKeyPair::generate().expect("a producer key"),
            device: StoredEnvelopeKeyPair::generate().expect("a device key"),
        }
    }

    fn recipients(&self) -> ArchiveRecipients {
        let mut recipients = ArchiveRecipients::new(CollectionKind::Owned);
        assert!(recipients.add(*self.device.public()));
        recipients
    }

    fn sender_key(&self) -> StoredEnvelopeKey {
        *self.sender.public()
    }
}

fn stage(seed: u8, filename: &str, plaintext: &[u8]) -> StagedObject {
    stage_at(seed, filename, plaintext, KeyRotation::INITIAL)
}

fn stage_at(seed: u8, filename: &str, plaintext: &[u8], rotation: KeyRotation) -> StagedObject {
    stage_object(
        &ObjectSource {
            object_id: object_id(seed),
            filename,
            plaintext,
        },
        rotation,
    )
    .expect("a staged object")
}

/// What a restore expects when it is restoring the collection these tests write.
fn expecting() -> ArchiveExpectation<'static> {
    ArchiveExpectation {
        archive_id: archive_id(),
        checkpoint: None,
    }
}

fn seal(parties: &Parties, generation: u64, objects: &[StagedObject]) -> SealedArchive {
    seal_archive(
        &parties.writer,
        &parties.sender,
        &parties.recipients(),
        &plan(generation),
        objects,
    )
    .expect("a sealed archive")
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-20.06: per-object random key, secretstream in 1 MiB records, the final record required,
// per-recipient wraps.
// ---------------------------------------------------------------------------------------------

#[test]
fn every_object_is_encrypted_under_its_own_random_key() {
    let first = stage(1, "a.cbor", b"the same body");
    let second = stage(2, "b.cbor", b"the same body");
    assert!(
        !first.shares_key_with(&second),
        "two objects never share a key"
    );
    assert_ne!(
        first.bytes(),
        second.bytes(),
        "identical plaintext under two keys is two ciphertexts"
    );
}

#[test]
fn an_object_is_written_in_one_mebibyte_records_and_needs_its_final_record() {
    // Two full records and a remainder, so the framing rule is exercised rather than assumed.
    let plaintext: Vec<u8> = (0..(2 * RECORD_LEN + 7))
        .map(|index| u8::try_from(index % 251).expect("a byte"))
        .collect();
    let staged = stage(3, "large.cbor", &plaintext);
    let records = plaintext.len().div_ceil(RECORD_LEN);
    assert_eq!(records, 3, "two full records and a remainder");
    assert_eq!(
        staged.bytes().len(),
        kr_crypto::stream::HEADER_LEN
            + plaintext.len()
            + records * kr_crypto::stream::RECORD_OVERHEAD,
        "the object is a header and three records, each with its own tag"
    );

    let parties = Parties::generate();
    let sealed = seal(&parties, 1, std::slice::from_ref(&staged));
    let reader = ArchiveReader::Device(&parties.device);
    let opened = open_archive(
        &reader,
        &parties.sender_key(),
        &[trusted(&parties.writer)],
        &expecting(),
        &sealed.descriptor_bytes,
        &sealed.encrypted_manifest,
    )
    .expect("the archive opens");

    let restored = opened
        .restore_object(
            &reader,
            &parties.sender_key(),
            staged.object_id(),
            staged.bytes(),
        )
        .expect("the object restores");
    assert_eq!(restored.plaintext.expose(), plaintext.as_slice());

    // A length that is not the manifest's fails first, before the object is decrypted at all.
    let truncated = &staged.bytes()[..staged.bytes().len() - 64];
    assert!(
        matches!(
            opened.restore_object(
                &reader,
                &parties.sender_key(),
                staged.object_id(),
                truncated,
            ),
            Err(CryptoError::HashMismatch { .. })
        ),
        "a stored object of another length is refused before it is decrypted"
    );

    // And the final-record rule itself. `decrypt_object` is what a restore calls once it has the
    // key and the manifest's reference, so it is driven here with bytes whose hash and length are
    // its reference's: every check before the framing rule passes, and the missing final record is
    // the only thing left to refuse it.
    let object = archive::encrypt_object(object_id(4), &plaintext).expect("an object");
    let one_record = kr_crypto::stream::HEADER_LEN
        + kr_crypto::stream::RECORD_LEN
        + kr_crypto::stream::RECORD_OVERHEAD;
    let cut_short = &object.bytes[..one_record];
    let reference = kr_protocol::archive::EncryptedObjectRef {
        object_id: object_id(4),
        encrypted_object_hash: Digest256::from_bytes(kr_cbor::sha256(cut_short)),
        encrypted_len: U64::new(cut_short.len() as u64),
    };
    assert!(
        matches!(
            archive::decrypt_object(&object.key, &reference, cut_short),
            Err(CryptoError::MissingFinalRecord)
        ),
        "an upload cut short is not a shorter valid object"
    );
}

#[test]
fn every_recipient_gets_its_own_wrap_of_every_key() {
    let parties = Parties::generate();
    let second_device = StoredEnvelopeKeyPair::generate().expect("a device key");
    let seed = RecoverySeed::generate().expect("a seed");
    let recovery = seed.recipient().expect("a recovery recipient");

    let mut recipients = ArchiveRecipients::new(CollectionKind::Owned);
    assert!(recipients.add(*parties.device.public()));
    assert!(recipients.add(*second_device.public()));
    assert!(recipients.add_recovery(&recovery));
    assert!(!recipients.add(*parties.device.public()), "no duplicates");
    assert_eq!(recipients.len(), 3);

    let objects = [stage(1, "a.cbor", b"one"), stage(2, "b.cbor", b"two")];
    let sealed = seal_archive(
        &parties.writer,
        &parties.sender,
        &recipients,
        &plan(4),
        &objects,
    )
    .expect("a sealed archive");

    assert_eq!(
        sealed.descriptor.manifest_key_wraps.len(),
        3,
        "the manifest key is wrapped once per recipient"
    );
    for wrap in &sealed.descriptor.manifest_key_wraps {
        assert_eq!(wrap.context.purpose, KeyWrapPurpose::ManifestKey);
    }

    // Every one of the three opens the archive, including the recovery recipient a producer only
    // holds the public key of.
    for reader in [
        ArchiveReader::Device(&parties.device),
        ArchiveReader::Device(&second_device),
        ArchiveReader::Recovery(&recovery),
    ] {
        let opened = open_archive(
            &reader,
            &parties.sender_key(),
            &[trusted(&parties.writer)],
            &expecting(),
            &sealed.descriptor_bytes,
            &sealed.encrypted_manifest,
        )
        .expect("the archive opens for this recipient");
        for staged in &objects {
            let restored = opened
                .restore_object(
                    &reader,
                    &parties.sender_key(),
                    staged.object_id(),
                    staged.bytes(),
                )
                .expect("a member object restores");
            assert_eq!(restored.filename, staged.filename());
        }
    }

    // A device that is not a recipient has no wrap to open.
    let stranger = StoredEnvelopeKeyPair::generate().expect("a device key");
    assert!(
        open_archive(
            &ArchiveReader::Device(&stranger),
            &parties.sender_key(),
            &[trusted(&parties.writer)],
            &expecting(),
            &sealed.descriptor_bytes,
            &sealed.encrypted_manifest
        )
        .is_err(),
        "a device with no wrap cannot open the archive"
    );
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-20.08: a fresh nonce per wrap, bound to the object and the recipient.
// ---------------------------------------------------------------------------------------------

#[test]
fn every_wrap_carries_a_fresh_nonce_and_the_whole_declared_context() {
    let parties = Parties::generate();
    let objects = [stage(1, "a.cbor", b"one"), stage(2, "b.cbor", b"two")];
    let sealed = seal(&parties, 9, &objects);

    let payload = manifest_payload(&parties, &sealed);
    let mut nonces: Vec<[u8; 24]> = Vec::new();
    for wrap in sealed
        .descriptor
        .manifest_key_wraps
        .iter()
        .chain(payload.member_key_wraps.iter())
    {
        nonces.push(*wrap.nonce.as_bytes());
        assert_eq!(wrap.context.archive_id, archive_id());
        assert_eq!(wrap.context.backup_generation, BackupGeneration::new(9));
        assert_eq!(wrap.context.sender_key_id, parties.sender.key_id());
        assert_eq!(wrap.context.recipient_key_id, parties.device.key_id());
    }
    let before = nonces.len();
    nonces.sort_unstable();
    nonces.dedup();
    assert_eq!(nonces.len(), before, "no nonce is used twice");

    // Every member wrap names the object it belongs to and that object's encrypted hash.
    for wrap in &payload.member_key_wraps {
        let named = objects
            .iter()
            .find(|staged| staged.object_id() == wrap.context.object_id)
            .expect("a wrap names a member object");
        assert_eq!(wrap.context.purpose, KeyWrapPurpose::ObjectKey);
        assert_eq!(
            wrap.context.encrypted_object_hash,
            named.reference().encrypted_object_hash
        );
    }
}

#[test]
fn a_wrap_is_valid_only_for_its_own_object_and_recipient() {
    let parties = Parties::generate();
    let second_device = StoredEnvelopeKeyPair::generate().expect("a device key");
    let mut recipients = ArchiveRecipients::new(CollectionKind::Owned);
    assert!(recipients.add(*parties.device.public()));
    assert!(recipients.add(*second_device.public()));
    let objects = [stage(1, "a.cbor", b"one"), stage(2, "b.cbor", b"two")];
    let sealed = seal_archive(
        &parties.writer,
        &parties.sender,
        &recipients,
        &plan(1),
        &objects,
    )
    .expect("a sealed archive");
    let mut payload = manifest_payload_with(&parties.device, &parties, &sealed);

    // Move the first device's wrap of object one onto object two. Its authenticated context still
    // names object one, so the open fails rather than yielding the wrong key.
    let (first_object, second_object) = (&objects[0], &objects[1]);
    let moved = payload
        .member_key_wraps
        .iter()
        .find(|wrap| {
            wrap.context.object_id == first_object.object_id()
                && wrap.context.recipient_key_id == parties.device.key_id()
        })
        .expect("a wrap")
        .clone();
    for wrap in &mut payload.member_key_wraps {
        if wrap.context.object_id == second_object.object_id()
            && wrap.context.recipient_key_id == parties.device.key_id()
        {
            *wrap = moved.clone();
            wrap.context.object_id = second_object.object_id();
            wrap.context.encrypted_object_hash = second_object.reference().encrypted_object_hash;
        }
    }
    let (descriptor_bytes, encrypted_manifest) = reseal_manifest(
        &parties,
        &[&parties.device, &second_device],
        &sealed,
        &payload,
    );
    let reader = ArchiveReader::Device(&parties.device);
    let opened = open_archive(
        &reader,
        &parties.sender_key(),
        &[trusted(&parties.writer)],
        &expecting(),
        &descriptor_bytes,
        &encrypted_manifest,
    )
    .expect("the manifest still verifies");
    assert!(
        opened
            .restore_object(
                &reader,
                &parties.sender_key(),
                second_object.object_id(),
                second_object.bytes(),
            )
            .is_err(),
        "a wrap moved to another object does not open"
    );

    // And a wrap moved to another recipient. The second device's wrap of object one is
    // re-addressed to the first device; its authenticated context still names the second, so the
    // first cannot open it.
    let mut payload = manifest_payload_with(&parties.device, &parties, &sealed);
    let theirs = payload
        .member_key_wraps
        .iter()
        .find(|wrap| {
            wrap.context.object_id == first_object.object_id()
                && wrap.context.recipient_key_id == second_device.key_id()
        })
        .expect("a wrap")
        .clone();
    for wrap in &mut payload.member_key_wraps {
        if wrap.context.object_id == first_object.object_id()
            && wrap.context.recipient_key_id == parties.device.key_id()
        {
            *wrap = theirs.clone();
            wrap.context.recipient_key_id = parties.device.key_id();
        }
    }
    let (descriptor_bytes, encrypted_manifest) = reseal_manifest(
        &parties,
        &[&parties.device, &second_device],
        &sealed,
        &payload,
    );
    let opened = open_archive(
        &reader,
        &parties.sender_key(),
        &[trusted(&parties.writer)],
        &expecting(),
        &descriptor_bytes,
        &encrypted_manifest,
    )
    .expect("the manifest still verifies");
    assert!(
        opened
            .restore_object(
                &reader,
                &parties.sender_key(),
                first_object.object_id(),
                first_object.bytes(),
            )
            .is_err(),
        "a wrap addressed to another recipient does not open for this one"
    );
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-20.07: the manifest is signed, encrypted as its own object, and a mismatch stops restore.
// ---------------------------------------------------------------------------------------------

#[test]
fn only_the_archive_identifier_and_object_references_are_outside_the_encrypted_manifest() {
    let parties = Parties::generate();
    let objects = [stage(1, "session-history.cbor", b"the body")];
    let sealed = seal(&parties, 2, &objects);

    // The filename is inside the encrypted manifest and nowhere else.
    assert!(
        !contains(&sealed.descriptor_bytes, b"session-history.cbor"),
        "a filename is never outside the encrypted manifest"
    );
    assert!(
        !contains(&sealed.encrypted_manifest, b"session-history.cbor"),
        "the manifest object is ciphertext"
    );

    // Exhaustively: the descriptor's own members are the five section 20 lists and no others, so a
    // field added to it later has to be considered rather than slipping out in the clear.
    let decoded = kr_cbor::decode(&sealed.descriptor_bytes, &kr_cbor::Limits::DEFAULT)
        .expect("a canonical descriptor");
    let map = decoded.as_map().expect("a descriptor is a map");
    let mut members: Vec<&str> = map.entries().iter().map(|(key, _)| key.as_str()).collect();
    members.sort_unstable();
    assert_eq!(
        members,
        vec![
            "archive_id",
            "backup_generation",
            "encrypted_manifest",
            "manifest_key_wraps",
            "version",
        ]
    );

    // What the descriptor does carry: the version, the archive, the generation, the encrypted
    // manifest's reference and the manifest key wraps.
    assert_eq!(sealed.descriptor.version, U64::new(1));
    assert_eq!(sealed.descriptor.archive_id, archive_id());
    assert_eq!(
        sealed.descriptor.encrypted_manifest.encrypted_len.get(),
        sealed.encrypted_manifest.len() as u64
    );

    let payload = manifest_payload(&parties, &sealed);
    let manifest = &payload.manifest.manifest;
    assert_eq!(manifest.schema_version, U64::new(1));
    assert_eq!(manifest.owner_device_id, owner());
    assert_eq!(manifest.backup_generation, BackupGeneration::new(2));
    assert_eq!(manifest.objects[0].filename, "session-history.cbor");
    assert_eq!(
        manifest.objects[0].object.encrypted_object_hash,
        objects[0].reference().encrypted_object_hash
    );
}

#[test]
fn a_manifest_signed_by_an_untrusted_writer_stops_the_restore() {
    let parties = Parties::generate();
    let impostor = AuthorisationKeyPair::generate().expect("a writer key");
    let objects = [stage(1, "a.cbor", b"one")];
    let sealed = seal(&parties, 1, &objects);

    assert!(
        open_archive(
            &ArchiveReader::Device(&parties.device),
            &parties.sender_key(),
            &[trusted(&impostor)],
            &expecting(),
            &sealed.descriptor_bytes,
            &sealed.encrypted_manifest
        )
        .is_err(),
        "a writer the bundle does not name is not trusted"
    );
    assert!(
        open_archive(
            &ArchiveReader::Device(&parties.device),
            &parties.sender_key(),
            &[],
            &expecting(),
            &sealed.descriptor_bytes,
            &sealed.encrypted_manifest
        )
        .is_err(),
        "an empty trusted set trusts nothing"
    );
}

#[test]
fn a_manifest_that_names_another_archive_stops_the_restore() {
    let parties = Parties::generate();
    let objects = [stage(1, "a.cbor", b"one")];
    let sealed = seal(&parties, 1, &objects);
    let mut payload = manifest_payload(&parties, &sealed);

    // The writer re-signs a manifest for a different archive, so the signature is genuine and only
    // the binding to the descriptor is wrong.
    payload.manifest.manifest.archive_id = ArchiveId::new(Uuid::from_bytes([0x99; 16]));
    payload.manifest = archive::sign_manifest(&parties.writer, payload.manifest.manifest.clone())
        .expect("a signed manifest");
    let (descriptor_bytes, encrypted_manifest) =
        reseal_manifest(&parties, &[&parties.device], &sealed, &payload);

    assert!(
        open_archive(
            &ArchiveReader::Device(&parties.device),
            &parties.sender_key(),
            &[trusted(&parties.writer)],
            &expecting(),
            &descriptor_bytes,
            &encrypted_manifest
        )
        .is_err(),
        "a verified manifest for another archive is a mismatch"
    );
}

#[test]
fn a_tampered_object_fails_against_the_hash_the_manifest_named() {
    let parties = Parties::generate();
    let objects = [stage(1, "a.cbor", b"the body")];
    let sealed = seal(&parties, 1, &objects);
    let reader = ArchiveReader::Device(&parties.device);
    let opened = open_archive(
        &reader,
        &parties.sender_key(),
        &[trusted(&parties.writer)],
        &expecting(),
        &sealed.descriptor_bytes,
        &sealed.encrypted_manifest,
    )
    .expect("the archive opens");

    let mut bytes = objects[0].bytes().to_vec();
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    assert!(
        matches!(
            opened.restore_object(
                &reader,
                &parties.sender_key(),
                objects[0].object_id(),
                &bytes,
            ),
            Err(CryptoError::HashMismatch { .. })
        ),
        "a changed byte fails on the manifest's hash, before the object is decrypted"
    );
}

#[test]
fn a_tampered_manifest_object_stops_the_restore_before_any_member_is_reached() {
    let parties = Parties::generate();
    let objects = [stage(1, "a.cbor", b"one")];
    let sealed = seal(&parties, 1, &objects);
    let mut manifest = sealed.encrypted_manifest.clone();
    let last = manifest.len() - 1;
    manifest[last] ^= 0x01;
    assert!(
        open_archive(
            &ArchiveReader::Device(&parties.device),
            &parties.sender_key(),
            &[trusted(&parties.writer)],
            &expecting(),
            &sealed.descriptor_bytes,
            &manifest
        )
        .is_err(),
        "the manifest is verified before any member object is restored"
    );
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-20.09: the descriptor's limits, and an invalid one failing before allocation.
// ---------------------------------------------------------------------------------------------

#[test]
fn a_descriptor_refuses_the_recipient_that_takes_it_over_the_byte_limit() {
    // Section 20 gives the descriptor two defaults and the first applicable one binds. A sealed
    // wrap carries its whole authenticated context beside the box, so the 64 KiB limit is reached
    // at a hundred recipients rather than at a hundred and twenty-eight. Both figures are pinned
    // here, because a change to the encoding that moves them changes how many devices one archive
    // can serve.
    let parties = Parties::generate();
    let mut recipients = ArchiveRecipients::new(CollectionKind::Owned);
    let mut devices = Vec::new();
    for _ in 0..RECIPIENTS_WITHIN_DESCRIPTOR_LIMIT {
        let device = StoredEnvelopeKeyPair::generate().expect("a device key");
        assert!(recipients.add(*device.public()));
        devices.push(device);
    }
    let objects = [stage(1, "a.cbor", b"one")];
    let sealed = seal_archive(
        &parties.writer,
        &parties.sender,
        &recipients,
        &plan(1),
        &objects,
    )
    .expect("a sealed archive at the byte bound");
    assert!(
        sealed.descriptor_bytes.len() <= MAX_ARCHIVE_DESCRIPTOR_LEN,
        "{} bytes is inside the 64 KiB limit",
        sealed.descriptor_bytes.len()
    );
    const { assert!(RECIPIENTS_WITHIN_DESCRIPTOR_LIMIT < MAX_ARCHIVE_RECIPIENTS) };

    // The hundred and first is refused on the byte limit, before it is published.
    let extra = StoredEnvelopeKeyPair::generate().expect("a device key");
    assert!(recipients.add(*extra.public()));
    let refusal = seal_archive(
        &parties.writer,
        &parties.sender,
        &recipients,
        &plan(1),
        &objects,
    )
    .expect_err("one recipient past the byte limit");
    assert!(
        refusal.to_string().contains("65536-byte limit"),
        "the refusal names the limit it hit: {refusal}"
    );

    // And the recipient limit still binds on its own, before any wrap is sealed.
    while recipients.len() <= MAX_ARCHIVE_RECIPIENTS {
        let device = StoredEnvelopeKeyPair::generate().expect("a device key");
        assert!(recipients.add(*device.public()));
    }
    let refusal = seal_archive(
        &parties.writer,
        &parties.sender,
        &recipients,
        &plan(1),
        &objects,
    )
    .expect_err("more than a hundred and twenty-eight recipients");
    assert!(
        refusal.to_string().contains("128-byte limit"),
        "the recipient limit is the one reported: {refusal}"
    );
}

#[test]
fn a_larger_generation_number_fits_fewer_recipients() {
    // The recipient figure is a figure and not a guarantee: a wrap grows with the generation's
    // integer width. What is enforced is the encoded size, so the same recipient set that fits at
    // a small generation can be refused at a large one, and the refusal names the byte limit.
    let parties = Parties::generate();
    let mut recipients = ArchiveRecipients::new(CollectionKind::Owned);
    let mut devices = Vec::new();
    for _ in 0..RECIPIENTS_WITHIN_DESCRIPTOR_LIMIT {
        let device = StoredEnvelopeKeyPair::generate().expect("a device key");
        assert!(recipients.add(*device.public()));
        devices.push(device);
    }
    let objects = [stage(1, "a.cbor", b"one")];
    let small = seal_archive(
        &parties.writer,
        &parties.sender,
        &recipients,
        &plan(3),
        &objects,
    )
    .expect("a sealed archive at a small generation");

    let mut large = plan(3);
    large.backup_generation = BackupGeneration::new(u64::from(u32::MAX) + 1);
    let refusal = seal_archive(
        &parties.writer,
        &parties.sender,
        &recipients,
        &large,
        &objects,
    )
    .expect_err("the same recipients at a generation whose number is wider");
    assert!(
        refusal.to_string().contains("65536-byte limit"),
        "the byte limit is what binds: {refusal}"
    );
    assert!(small.descriptor_bytes.len() <= MAX_ARCHIVE_DESCRIPTOR_LEN);
}

#[test]
fn a_generation_of_many_objects_and_many_recipients_seals_and_opens() {
    // The producer encodes the manifest payload under the bounds the restore decodes with. A
    // producer with looser bounds would write archives nothing could open, which is the one
    // failure a backup must not have: it looks complete until somebody needs it.
    let parties = Parties::generate();
    let mut recipients = ArchiveRecipients::new(CollectionKind::Owned);
    assert!(recipients.add(*parties.device.public()));
    let mut devices = Vec::new();
    for _ in 0..39 {
        let device = StoredEnvelopeKeyPair::generate().expect("a device key");
        assert!(recipients.add(*device.public()));
        devices.push(device);
    }
    let objects: Vec<StagedObject> = (0u8..120)
        .map(|seed| stage(seed, "member.cbor", b"a member object"))
        .collect();
    // Four thousand eight hundred member wraps, which is past every default bound this would have
    // been decoded under before: the 1 MiB message, the 4 096-member collection and the 65 536
    // items.
    assert_eq!(objects.len() * recipients.len(), 4_800);

    let sealed = seal_archive(
        &parties.writer,
        &parties.sender,
        &recipients,
        &plan(1),
        &objects,
    )
    .expect("a sealed archive");
    let reader = ArchiveReader::Device(&parties.device);
    let opened = open_archive(
        &reader,
        &parties.sender_key(),
        &[trusted(&parties.writer)],
        &expecting(),
        &sealed.descriptor_bytes,
        &sealed.encrypted_manifest,
    )
    .expect("what this producer wrote is what this build reads");
    assert_eq!(opened.objects().len(), objects.len());
    let restored = opened
        .restore_object(
            &reader,
            &parties.sender_key(),
            objects[77].object_id(),
            objects[77].bytes(),
        )
        .expect("a member object restores");
    assert_eq!(restored.plaintext.expose(), b"a member object");
}

#[test]
fn two_member_objects_under_one_identifier_are_refused_before_the_manifest_is_signed() {
    let parties = Parties::generate();
    let duplicated = [
        stage(1, "a.cbor", b"one"),
        stage(1, "b.cbor", b"the same identifier"),
    ];
    let refusal = seal_archive(
        &parties.writer,
        &parties.sender,
        &parties.recipients(),
        &plan(1),
        &duplicated,
    )
    .expect_err("two objects under one identifier");
    assert!(
        refusal.to_string().contains("one object identifier"),
        "{refusal}"
    );
}

#[test]
fn a_manifest_under_a_schema_this_build_does_not_read_stops_the_restore() {
    // The signature authenticates the schema version; it does not establish that this build knows
    // what that version means. The writer here is genuinely trusted and genuinely signed it.
    let parties = Parties::generate();
    let objects = [stage(1, "a.cbor", b"one")];
    let sealed = seal(&parties, 1, &objects);
    let mut payload = manifest_payload(&parties, &sealed);
    payload.manifest.manifest.schema_version = U64::new(2);
    payload.manifest = archive::sign_manifest(&parties.writer, payload.manifest.manifest.clone())
        .expect("a signed manifest");
    let (descriptor_bytes, encrypted_manifest) =
        reseal_manifest(&parties, &[&parties.device], &sealed, &payload);
    assert!(
        open_archive(
            &ArchiveReader::Device(&parties.device),
            &parties.sender_key(),
            &[trusted(&parties.writer)],
            &expecting(),
            &descriptor_bytes,
            &encrypted_manifest,
        )
        .is_err(),
        "a later manifest schema is refused rather than read under this one's rules"
    );
}

#[test]
fn a_staged_object_never_prints_its_plaintext_or_its_fingerprint() {
    let plaintext = b"what the session actually said";
    let source = ObjectSource {
        object_id: object_id(1),
        filename: "a.cbor",
        plaintext,
    };
    let rendered = format!("{source:?}");
    assert!(!rendered.contains("session actually said"));
    assert!(rendered.contains("plaintext_len"));

    let staged = stage_object(&source, KeyRotation::INITIAL).expect("a staged object");
    let rendered = format!("{staged:?}");
    assert!(!rendered.contains("session actually said"));
    assert!(
        rendered.contains("Digest256(redacted)"),
        "the source digest is a fingerprint of the plaintext: {rendered}"
    );
    let digest = kr_protocol::scalars::to_base64url(&kr_cbor::sha256(plaintext));
    assert!(!rendered.contains(&digest));
}

#[test]
fn an_archive_with_no_recipient_is_refused() {
    let parties = Parties::generate();
    let empty = ArchiveRecipients::new(CollectionKind::Owned);
    assert!(
        seal_archive(
            &parties.writer,
            &parties.sender,
            &empty,
            &plan(1),
            &[stage(1, "a.cbor", b"one")],
        )
        .is_err(),
        "an archive nothing could open is not written"
    );
}

#[test]
fn an_invalid_descriptor_fails_before_any_object_is_opened() {
    let parties = Parties::generate();
    let objects = [stage(1, "a.cbor", b"one")];
    let sealed = seal(&parties, 1, &objects);

    // Over the byte limit, before it is even decoded.
    let oversized = vec![0u8; MAX_ARCHIVE_DESCRIPTOR_LEN + 1];
    assert!(
        open_archive(
            &ArchiveReader::Device(&parties.device),
            &parties.sender_key(),
            &[trusted(&parties.writer)],
            &expecting(),
            &oversized,
            &sealed.encrypted_manifest
        )
        .is_err()
    );

    // A version this build does not read.
    let mut descriptor = sealed.descriptor.clone();
    descriptor.version = U64::new(2);
    let bytes = kr_cbor::to_canonical_vec(&descriptor).expect("canonical bytes");
    assert!(
        open_archive(
            &ArchiveReader::Device(&parties.device),
            &parties.sender_key(),
            &[trusted(&parties.writer)],
            &expecting(),
            &bytes,
            &sealed.encrypted_manifest
        )
        .is_err()
    );

    // A manifest wrap moved onto another object.
    let mut descriptor = sealed.descriptor.clone();
    descriptor.manifest_key_wraps[0].context.object_id = object_id(0xee);
    let bytes = kr_cbor::to_canonical_vec(&descriptor).expect("canonical bytes");
    assert!(
        open_archive(
            &ArchiveReader::Device(&parties.device),
            &parties.sender_key(),
            &[trusted(&parties.writer)],
            &expecting(),
            &bytes,
            &sealed.encrypted_manifest
        )
        .is_err()
    );
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-20.07: resume reuses ciphertext, and a changed source restarts under a new key.
// ---------------------------------------------------------------------------------------------

#[test]
fn an_interrupted_upload_resumes_on_the_ciphertext_it_already_made() {
    let staged = stage(1, "a.cbor", b"the body");
    let before = staged.bytes().to_vec();
    let reference = staged.reference().clone();

    let resumed = resume_object(
        staged,
        &ObjectSource {
            object_id: object_id(1),
            filename: "a.cbor",
            plaintext: b"the body",
        },
        KeyRotation::INITIAL,
    )
    .expect("a resumed object");
    assert_eq!(resumed.decision, ResumeDecision::ReusedCiphertext);
    assert_eq!(
        resumed.staged.bytes(),
        before,
        "not one byte is re-encrypted"
    );
    assert_eq!(resumed.staged.reference(), &reference);

    // A source that was only renamed keeps its ciphertext and records the name it has now, so the
    // next manifest does not carry a filename the source no longer has.
    let renamed = resume_object(
        resumed.staged,
        &ObjectSource {
            object_id: object_id(1),
            filename: "renamed.cbor",
            plaintext: b"the body",
        },
        KeyRotation::INITIAL,
    )
    .expect("a resumed object");
    assert_eq!(renamed.decision, ResumeDecision::ReusedCiphertextRenamed);
    assert_eq!(
        renamed.staged.bytes(),
        before,
        "still not one byte re-encrypted"
    );
    assert_eq!(renamed.staged.filename(), "renamed.cbor");
}

#[test]
fn a_source_that_changed_restarts_encryption_under_a_new_key() {
    let staged = stage(1, "a.cbor", b"the body");
    let before = staged.bytes().to_vec();
    let kept = stage(1, "a.cbor", b"the body");

    let resumed = resume_object(
        staged,
        &ObjectSource {
            object_id: object_id(1),
            filename: "a.cbor",
            plaintext: b"a different body",
        },
        KeyRotation::INITIAL,
    )
    .expect("a resumed object");
    assert_eq!(resumed.decision, ResumeDecision::ReencryptedUnderNewKey);
    assert_ne!(resumed.staged.bytes(), before);
    assert!(
        !resumed.staged.shares_key_with(&kept),
        "a changed source never continues under the old key"
    );
}

#[test]
fn resuming_never_reuses_a_wrap_nonce() {
    let parties = Parties::generate();
    let staged = stage(1, "a.cbor", b"the body");
    let first = seal(&parties, 1, std::slice::from_ref(&staged));

    // The upload stopped after the objects were made; the producer resumes on the same ciphertext
    // and seals the generation again.
    let resumed = resume_object(
        staged,
        &ObjectSource {
            object_id: object_id(1),
            filename: "a.cbor",
            plaintext: b"the body",
        },
        KeyRotation::INITIAL,
    )
    .expect("a resumed object");
    assert_eq!(resumed.decision, ResumeDecision::ReusedCiphertext);
    let second = seal(&parties, 1, std::slice::from_ref(&resumed.staged));

    let mut nonces: Vec<[u8; 24]> = Vec::new();
    for sealed in [&first, &second] {
        let payload = manifest_payload(&parties, sealed);
        for wrap in sealed
            .descriptor
            .manifest_key_wraps
            .iter()
            .chain(payload.member_key_wraps.iter())
        {
            nonces.push(*wrap.nonce.as_bytes());
        }
    }
    let before = nonces.len();
    nonces.sort_unstable();
    nonces.dedup();
    assert_eq!(
        nonces.len(),
        before,
        "reused ciphertext still gets fresh wrap nonces"
    );
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-20.11: revocation, rotation, retained keys and the absence of a retroactive claim.
// ---------------------------------------------------------------------------------------------

#[test]
fn revoking_a_recipient_removes_it_from_every_future_wrap() {
    let parties = Parties::generate();
    let leaving = StoredEnvelopeKeyPair::generate().expect("a device key");
    let mut recipients = ArchiveRecipients::new(CollectionKind::Owned);
    assert!(recipients.add(*parties.device.public()));
    assert!(recipients.add(*leaving.public()));

    let objects = [stage(1, "a.cbor", b"one")];
    let before = seal_archive(
        &parties.writer,
        &parties.sender,
        &recipients,
        &plan(1),
        &objects,
    )
    .expect("a sealed archive");
    assert!(
        open_archive(
            &ArchiveReader::Device(&leaving),
            &parties.sender_key(),
            &[trusted(&parties.writer)],
            &expecting(),
            &before.descriptor_bytes,
            &before.encrypted_manifest
        )
        .is_ok(),
        "before the revocation it is a recipient"
    );

    let revocation = recipients
        .revoke(&leaving.key_id())
        .expect("the set named it");
    assert_eq!(revocation.removed, leaving.key_id());
    assert!(!recipients.contains(&leaving.key_id()));
    assert!(recipients.contains(&parties.device.key_id()));

    let after = seal_archive(
        &parties.writer,
        &parties.sender,
        &recipients,
        &plan(2),
        &objects,
    )
    .expect("a sealed archive");
    assert!(
        open_archive(
            &ArchiveReader::Device(&leaving),
            &parties.sender_key(),
            &[trusted(&parties.writer)],
            &expecting(),
            &after.descriptor_bytes,
            &after.encrypted_manifest,
        )
        .is_err(),
        "after the revocation there is no wrap for it"
    );

    // Not only the manifest key: the member wraps inside the new manifest name the one recipient
    // that is left, and none of them is addressed to the device that went.
    let payload = manifest_payload(&parties, &after);
    assert!(!payload.member_key_wraps.is_empty());
    for wrap in &payload.member_key_wraps {
        assert_ne!(wrap.context.recipient_key_id, leaving.key_id());
        assert_eq!(wrap.context.recipient_key_id, parties.device.key_id());
    }

    // And what it already had, it keeps. Revocation is prospective: the earlier generation it
    // holds a wrap for still opens and still restores.
    let opened = open_archive(
        &ArchiveReader::Device(&leaving),
        &parties.sender_key(),
        &[trusted(&parties.writer)],
        &expecting(),
        &before.descriptor_bytes,
        &before.encrypted_manifest,
    )
    .expect("the generation it already held");
    let restored = opened
        .restore_object(
            &ArchiveReader::Device(&leaving),
            &parties.sender_key(),
            objects[0].object_id(),
            objects[0].bytes(),
        )
        .expect("a removed device reads what it already had");
    assert_eq!(restored.plaintext.expose(), b"one");

    // Revoking something that is not in the set changes nothing.
    assert!(recipients.revoke(&leaving.key_id()).is_none());
}

#[test]
fn a_mutable_shared_collection_rotates_its_keys_and_an_owned_one_does_not() {
    let parties = Parties::generate();
    let leaving = StoredEnvelopeKeyPair::generate().expect("a device key");

    let mut shared = ArchiveRecipients::new(CollectionKind::MutableShared);
    assert!(shared.add(*parties.device.public()));
    assert!(shared.add(*leaving.public()));
    let before = shared.rotation();
    let staged = stage_at(1, "a.cbor", b"shared content", before);
    // The same object staged again at the same rotation, kept so the key after the rotation can be
    // compared with a key from before it without either leaving its own type.
    let twin = stage_at(1, "a.cbor", b"shared content", before);

    let rotated = shared.revoke(&leaving.key_id()).expect("a revocation");
    assert!(rotated.rotates_object_keys);
    assert!(
        !rotated.may_reuse_staged_ciphertext(),
        "staged ciphertext is discarded when the keys rotate"
    );
    assert_ne!(shared.rotation(), before, "the rotation advanced");

    // The rule is enforced, not reported: the ciphertext staged before the revocation cannot be
    // sealed into the next generation, whatever a caller does with the answer above.
    let refusal = seal_archive(
        &parties.writer,
        &parties.sender,
        &shared,
        &plan(2),
        std::slice::from_ref(&staged),
    )
    .expect_err("ciphertext from before the rotation");
    assert!(refusal.to_string().contains("rotated"), "{refusal}");

    // Resuming it makes it again, under a key the removed device holds no wrap for.
    let resumed = resume_object(
        staged,
        &ObjectSource {
            object_id: object_id(1),
            filename: "a.cbor",
            plaintext: b"shared content",
        },
        shared.rotation(),
    )
    .expect("a resumed object");
    assert_eq!(resumed.decision, ResumeDecision::ReencryptedAfterRotation);
    assert!(
        !resumed.staged.shares_key_with(&twin),
        "the object is under a new key"
    );
    assert!(
        seal_archive(
            &parties.writer,
            &parties.sender,
            &shared,
            &plan(2),
            std::slice::from_ref(&resumed.staged),
        )
        .is_ok(),
        "the re-staged object seals"
    );

    // An owned collection does not rotate, so its staged bytes still seal.
    let mut owned = ArchiveRecipients::new(CollectionKind::Owned);
    assert!(owned.add(*parties.device.public()));
    assert!(owned.add(*leaving.public()));
    let staged = stage_at(1, "a.cbor", b"my content", owned.rotation());
    let plain = owned.revoke(&leaving.key_id()).expect("a revocation");
    assert!(!plain.rotates_object_keys);
    assert!(plain.may_reuse_staged_ciphertext());
    assert!(
        seal_archive(
            &parties.writer,
            &parties.sender,
            &owned,
            &plan(2),
            std::slice::from_ref(&staged),
        )
        .is_ok(),
        "nothing it contains changed, so its ciphertext still seals"
    );

    for revocation in [rotated, plain] {
        assert!(
            !revocation.claims_retroactive_secrecy(),
            "no revocation claims retroactive secrecy"
        );
        let sentence = revocation.describe();
        assert!(
            sentence.contains("stay readable to it"),
            "the sentence says what the removed device keeps: {sentence}"
        );
    }
}

#[test]
fn a_removed_device_keeps_every_generation_it_already_held() {
    let published = [
        BackupGeneration::new(1),
        BackupGeneration::new(2),
        BackupGeneration::new(3),
        BackupGeneration::new(4),
    ];
    let readable = still_readable_after_revocation(&published, BackupGeneration::new(3));
    assert_eq!(
        readable,
        vec![BackupGeneration::new(1), BackupGeneration::new(2)],
        "revocation is prospective: everything before it stays readable"
    );
    assert!(
        still_readable_after_revocation(&published, BackupGeneration::new(1)).is_empty(),
        "a device removed before the first generation holds nothing"
    );
}

#[test]
fn old_object_keys_are_kept_only_while_their_backup_is_retained() {
    let mut retained = RetainedObjectKeys::new();
    assert!(retained.is_empty());
    for generation in 1u64..=3 {
        for object in 0u8..2 {
            retained.keep(
                BackupGeneration::new(generation),
                object_id(object),
                kr_crypto::secret::SymmetricKey::random().expect("a key"),
            );
        }
    }
    assert_eq!(retained.len(), 6);
    assert!(
        retained
            .key(BackupGeneration::new(2), object_id(1))
            .is_some()
    );

    // The host stops retaining generation one's backup, so its keys go with it.
    assert_eq!(retained.forget(BackupGeneration::new(1)), 2);
    assert!(
        retained
            .key(BackupGeneration::new(1), object_id(0))
            .is_none()
    );

    // And the policy in one call: only what is still retained is kept.
    assert_eq!(retained.retain_only(&[BackupGeneration::new(3)]), 2);
    assert_eq!(
        retained.generations(),
        vec![BackupGeneration::new(3)],
        "nothing is kept for a backup this host no longer retains"
    );
    assert_eq!(retained.retain_only(&[]), 2);
    assert!(retained.is_empty());
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-20.12 (producer half): the trusted latest-generation checkpoint.
// ---------------------------------------------------------------------------------------------

fn checkpoint(generation: u64, hash: Digest256) -> ArchiveCheckpoint {
    ArchiveCheckpoint {
        archive_id: archive_id(),
        backup_generation: BackupGeneration::new(generation),
        encrypted_manifest_hash: hash,
        verified_at_ms: TimestampMs::new(5),
    }
}

#[test]
fn a_checkpoint_from_a_paired_device_catches_a_replayed_older_archive() {
    let parties = Parties::generate();
    let objects = [stage(1, "a.cbor", b"one")];
    let old = seal(&parties, 3, &objects);
    let new = seal(&parties, 7, &objects);

    let verified = checkpoint(7, new.descriptor.encrypted_manifest.encrypted_object_hash);
    let replayed = RestoreGeneration::against(
        &old.descriptor,
        Some((CheckpointSource::Pairing, &verified)),
    );
    assert!(matches!(
        replayed.standing,
        GenerationStanding::Replayed { .. }
    ));
    assert!(!replayed.is_admissible());
    assert!(replayed.describe().contains("generation 3"));

    // And the restore itself refuses it, whatever the caller did with the report. Everything else
    // about the older archive is genuine: the writer is trusted, the wrap is this reader's and the
    // manifest verifies.
    let against = ArchiveExpectation {
        archive_id: archive_id(),
        checkpoint: Some((CheckpointSource::Pairing, &verified)),
    };
    assert!(
        open_archive(
            &ArchiveReader::Device(&parties.device),
            &parties.sender_key(),
            &[trusted(&parties.writer)],
            &against,
            &old.descriptor_bytes,
            &old.encrypted_manifest,
        )
        .is_err(),
        "a replayed older archive is refused by the restore, not only reported"
    );

    let current = RestoreGeneration::against(
        &new.descriptor,
        Some((CheckpointSource::Pairing, &verified)),
    );
    assert!(matches!(
        current.standing,
        GenerationStanding::AtCheckpoint { .. }
    ));
    assert!(current.is_admissible());
    let opened = open_archive(
        &ArchiveReader::Device(&parties.device),
        &parties.sender_key(),
        &[trusted(&parties.writer)],
        &against,
        &new.descriptor_bytes,
        &new.encrypted_manifest,
    )
    .expect("the generation the owner verified opens");
    assert!(matches!(
        opened.generation().standing,
        GenerationStanding::AtCheckpoint { .. }
    ));
}

#[test]
fn an_archive_of_another_collection_is_not_the_backup_that_was_asked_for() {
    let parties = Parties::generate();
    let objects = [stage(1, "a.cbor", b"one")];
    let sealed = seal(&parties, 1, &objects);

    // Everything about it is genuine: a trusted writer, this reader's wrap, a manifest that
    // verifies. It is simply not the collection being restored.
    let elsewhere = ArchiveExpectation {
        archive_id: ArchiveId::new(Uuid::from_bytes([0x99; 16])),
        checkpoint: None,
    };
    assert!(
        open_archive(
            &ArchiveReader::Device(&parties.device),
            &parties.sender_key(),
            &[trusted(&parties.writer)],
            &elsewhere,
            &sealed.descriptor_bytes,
            &sealed.encrypted_manifest,
        )
        .is_err(),
        "a descriptor for another collection is a substitution"
    );

    // And a checkpoint for another archive is a mismatch rather than an absence: a caller that
    // supplied one had an expectation, and this is not what it asked for.
    let other = ArchiveCheckpoint {
        archive_id: ArchiveId::new(Uuid::from_bytes([0x77; 16])),
        ..checkpoint(1, Digest256::from_bytes([0xcd; 32]))
    };
    let standing = RestoreGeneration::against(
        &sealed.descriptor,
        Some((CheckpointSource::Pairing, &other)),
    );
    assert!(matches!(
        standing.standing,
        GenerationStanding::OtherArchive { .. }
    ));
    assert!(!standing.is_admissible());
    assert!(
        open_archive(
            &ArchiveReader::Device(&parties.device),
            &parties.sender_key(),
            &[trusted(&parties.writer)],
            &ArchiveExpectation {
                archive_id: archive_id(),
                checkpoint: Some((CheckpointSource::Pairing, &other)),
            },
            &sealed.descriptor_bytes,
            &sealed.encrypted_manifest,
        )
        .is_err()
    );
}

#[test]
fn an_archive_claiming_the_checkpoints_generation_with_another_manifest_is_refused() {
    let parties = Parties::generate();
    let first = seal(&parties, 5, &[stage(1, "a.cbor", b"one")]);
    let second = seal(&parties, 5, &[stage(1, "a.cbor", b"something else")]);
    let verified = checkpoint(5, first.descriptor.encrypted_manifest.encrypted_object_hash);

    let substituted = RestoreGeneration::against(
        &second.descriptor,
        Some((CheckpointSource::Pairing, &verified)),
    );
    assert!(matches!(
        substituted.standing,
        GenerationStanding::Substituted { .. }
    ));
    assert!(!substituted.is_admissible());
    assert!(
        open_archive(
            &ArchiveReader::Device(&parties.device),
            &parties.sender_key(),
            &[trusted(&parties.writer)],
            &ArchiveExpectation {
                archive_id: archive_id(),
                checkpoint: Some((CheckpointSource::Pairing, &verified)),
            },
            &second.descriptor_bytes,
            &second.encrypted_manifest,
        )
        .is_err(),
        "an archive claiming the checkpoint's generation with another manifest is refused"
    );
}

#[test]
fn a_recovery_only_restore_states_its_generation_and_claims_nothing_more() {
    let parties = Parties::generate();
    let seed = RecoverySeed::generate().expect("a seed");
    let recovery = seed.recipient().expect("a recovery recipient");
    let mut recipients = ArchiveRecipients::new(CollectionKind::Owned);
    assert!(recipients.add_recovery(&recovery));
    let staged = stage(1, "a.cbor", b"one");
    let sealed = seal_archive(
        &parties.writer,
        &parties.sender,
        &recipients,
        &plan(11),
        std::slice::from_ref(&staged),
    )
    .expect("a sealed archive");

    // A device that holds only the recovery recipient restores the archive and is told which
    // generation it got.
    let reader = ArchiveReader::Recovery(&recovery);
    let bundle_checkpoint = checkpoint(9, Digest256::from_bytes([0xab; 32]));
    let opened = open_archive(
        &reader,
        &parties.sender_key(),
        &[trusted(&parties.writer)],
        &ArchiveExpectation {
            archive_id: archive_id(),
            checkpoint: Some((CheckpointSource::RecoveryBundle, &bundle_checkpoint)),
        },
        &sealed.descriptor_bytes,
        &sealed.encrypted_manifest,
    )
    .expect("the recovery recipient opens it");
    let restored = opened
        .restore_object(
            &reader,
            &parties.sender_key(),
            staged.object_id(),
            staged.bytes(),
        )
        .expect("the member object restores");
    assert_eq!(restored.plaintext.expose(), b"one");
    let shown = opened.generation();
    assert!(shown.describe().contains("generation 11"));
    assert!(!shown.proves_no_newer_archive());

    // With the bundle's checkpoint: it is newer than what was verified, which is what an owner who
    // kept backing up looks like.
    let verified = checkpoint(9, Digest256::from_bytes([0xab; 32]));
    let ahead = RestoreGeneration::against(
        &sealed.descriptor,
        Some((CheckpointSource::RecoveryBundle, &verified)),
    );
    assert!(matches!(ahead.standing, GenerationStanding::Ahead { .. }));
    assert!(ahead.is_admissible());
    assert!(ahead.checkpoint_available());
    assert!(!ahead.proves_no_newer_archive());
    let sentence = ahead.describe();
    assert!(sentence.contains("generation 11"));
    assert!(sentence.contains("the recovery bundle"));
    assert!(sentence.contains("holding a newer backup back"));

    // With no checkpoint at all, the generation is still displayed.
    let bare = RestoreGeneration::against(&sealed.descriptor, None);
    assert!(matches!(bare.standing, GenerationStanding::NoCheckpoint));
    assert!(bare.is_admissible());
    assert!(!bare.checkpoint_available());
    assert!(bare.describe().contains("generation 11"));
}

// ---------------------------------------------------------------------------------------------
// Helpers that open a sealed archive's manifest, so a test can inspect or rewrite it.
// ---------------------------------------------------------------------------------------------

fn manifest_payload(parties: &Parties, sealed: &SealedArchive) -> ManifestPayload {
    manifest_payload_with(&parties.device, parties, sealed)
}

fn manifest_payload_with(
    device: &StoredEnvelopeKeyPair,
    parties: &Parties,
    sealed: &SealedArchive,
) -> ManifestPayload {
    let key = manifest_key(device, parties, sealed);
    let plaintext = archive::decrypt_object(
        &key,
        &sealed.descriptor.encrypted_manifest,
        &sealed.encrypted_manifest,
    )
    .expect("the manifest object opens");
    kr_cbor::from_canonical_slice(plaintext.expose(), &kr_cbor::Limits::DEFAULT)
        .expect("a manifest payload")
}

fn manifest_key(
    device: &StoredEnvelopeKeyPair,
    parties: &Parties,
    sealed: &SealedArchive,
) -> kr_crypto::secret::SymmetricKey {
    let wrap = archive::manifest_wrap_for(&sealed.descriptor, &device.key_id())
        .expect("a wrap for this device");
    archive::unwrap_object_key(device, &parties.sender_key(), wrap, &wrap.context.clone())
        .expect("the manifest key")
}

/// Re-encrypts a rewritten manifest payload and rebuilds the descriptor around it.
///
/// A test that changes what the manifest says has to produce an archive a producer could have
/// produced, otherwise it proves only that random bytes fail.
fn reseal_manifest(
    parties: &Parties,
    recipients: &[&StoredEnvelopeKeyPair],
    sealed: &SealedArchive,
    payload: &ManifestPayload,
) -> (Vec<u8>, Vec<u8>) {
    let bytes = kr_cbor::to_canonical_vec(payload).expect("canonical bytes");
    let object: EncryptedObject =
        archive::encrypt_object(sealed.descriptor.encrypted_manifest.object_id, &bytes)
            .expect("an encrypted manifest");
    let mut descriptor = sealed.descriptor.clone();
    descriptor.encrypted_manifest = object.reference.clone();
    descriptor.manifest_key_wraps = sealed
        .descriptor
        .manifest_key_wraps
        .iter()
        .map(|wrap| {
            let mut context = wrap.context.clone();
            context.encrypted_object_hash = object.reference.encrypted_object_hash;
            let recipient = recipients
                .iter()
                .find(|keys| keys.key_id() == context.recipient_key_id)
                .expect("the test named every recipient of the descriptor");
            archive::wrap_object_key(&parties.sender, recipient.public(), context, &object.key)
                .expect("a wrap")
        })
        .collect();
    let descriptor_bytes = kr_cbor::to_canonical_vec(&descriptor).expect("canonical bytes");
    (descriptor_bytes, object.bytes)
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

#[test]
fn the_recipient_key_identifier_is_purpose_separated() {
    let device = StoredEnvelopeKeyPair::generate().expect("a device key");
    assert_eq!(recipient_key_id(device.public()), device.key_id());

    // The purpose is inside the identifier, so the same 32 bytes declared under another purpose
    // produce another identifier and a wrap addressed to one is not addressed to the other.
    let bytes = device.public().as_bytes();
    assert_ne!(
        kr_crypto::keys::key_id(kr_protocol::pairing::KeyPurpose::StoredEnvelope, bytes),
        kr_crypto::keys::key_id(kr_protocol::pairing::KeyPurpose::Authorisation, bytes)
    );
}
