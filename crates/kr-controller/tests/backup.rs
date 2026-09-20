//! The environment's backup service: its store, its reconciliation, its restore checks and its
//! privacy hook.
//!
//! Section 24's ownership row for backup generations, and section 24's privacy paragraphs. Rule 12
//! applies to every path here: `backup.sqlite` and every staged byte live under the platform
//! temporary directory, which is on the internal disk, and nothing in this file launches a process.

use kr_controller::backup::store::{GenerationState, ObjectState, Step};
use kr_controller::backup::{BackupService, RestoreRequest, SUBSYSTEM_NAME};
use kr_crypto::backup::{
    ArchivePlan, ArchiveRecipients, CheckpointSource, CollectionKind, Material, ObjectSource,
    SealedArchive, StagedObject, seal_archive, stage_object,
};
use kr_crypto::keys::{AuthorisationKeyPair, StoredEnvelopeKeyPair};
use kr_protocol::archive::{
    ArchiveCheckpoint, BackupGenerationPublication, BackupGenerationPublicationPayload,
    BackupWriterRecord, BackupWriterRecordPayload, TrustedWriter,
};
use kr_protocol::ids::{
    ArchiveId, BackupGeneration, BackupObjectId, BackupWriterRevision, DeviceId,
};
use kr_protocol::scalars::{Digest256, TimestampMs, Uuid};
use kr_worker::privacy::{PrivacyGeneration, PrivacyMode, PrivacySubsystem};

fn archive_id() -> ArchiveId {
    ArchiveId::new(Uuid::from_bytes([0x11; 16]))
}

fn owner_device() -> DeviceId {
    DeviceId::new(Uuid::from_bytes([0x33; 16]))
}

fn object_id(seed: u8) -> BackupObjectId {
    BackupObjectId::new(Uuid::from_bytes([seed; 16]))
}

/// A service whose store and staging directory live on the internal disk and go with the test.
struct Environment {
    service: BackupService,
    _root: tempfile::TempDir,
}

impl Environment {
    fn open() -> Self {
        let root = tempfile::tempdir().expect("a disposable directory on the internal disk");
        let service = BackupService::in_memory(&root.path().join("backup"))
            .expect("a backup service with its own staging directory");
        Self {
            service,
            _root: root,
        }
    }

    fn service(&self) -> &BackupService {
        &self.service
    }
}

/// One writer, one producer key and one recipient.
struct Producer {
    writer: AuthorisationKeyPair,
    owner: AuthorisationKeyPair,
    sender: StoredEnvelopeKeyPair,
    device: StoredEnvelopeKeyPair,
}

impl Producer {
    fn generate() -> Self {
        Self {
            writer: AuthorisationKeyPair::generate().expect("a writer key"),
            owner: AuthorisationKeyPair::generate().expect("an owner key"),
            sender: StoredEnvelopeKeyPair::generate().expect("a producer key"),
            device: StoredEnvelopeKeyPair::generate().expect("a device key"),
        }
    }

    fn seal(&self, generation: u64, objects: &[StagedObject]) -> SealedArchive {
        let mut recipients = ArchiveRecipients::new(CollectionKind::Owned);
        assert!(recipients.add(*self.device.public()));
        seal_archive(
            &self.writer,
            &self.sender,
            &recipients,
            &ArchivePlan {
                archive_id: archive_id(),
                backup_generation: BackupGeneration::new(generation),
                owner_device_id: owner_device(),
                manifest_object_id: object_id(0xf0),
                created_at_ms: TimestampMs::new(1_700_000_000_000),
            },
            objects,
        )
        .expect("a sealed archive")
    }

    fn enrolment(&self, revision: u64) -> BackupWriterRecord {
        let payload = BackupWriterRecordPayload {
            archive_id: archive_id(),
            writer: TrustedWriter {
                writer_key_id: self.writer.key_id(),
                signing_key: *self.writer.public(),
                enrolled_at_ms: TimestampMs::new(1_000),
            },
            writer_revision: BackupWriterRevision::new(revision),
            owner_key_id: self.owner.key_id(),
            enrolled_at_ms: TimestampMs::new(1_000),
        };
        let transcript = kr_crypto::sign::SigningTranscript::from_canonical_bytes(
            kr_protocol::archive::BACKUP_WRITER_DOMAIN,
            payload.signing_input().expect("an enrolment input"),
        )
        .expect("a transcript");
        let signature = kr_crypto::sign::sign(&self.owner, &transcript).expect("a signature");
        BackupWriterRecord { payload, signature }
    }

    fn publish(&self, sealed: &SealedArchive) -> BackupGenerationPublication {
        let payload = BackupGenerationPublicationPayload {
            descriptor: sealed.descriptor.clone(),
            writer_key_id: self.writer.key_id(),
            published_at_ms: TimestampMs::new(2_000),
        };
        let transcript = kr_crypto::sign::SigningTranscript::from_canonical_bytes(
            kr_protocol::archive::BACKUP_PUBLICATION_DOMAIN,
            payload.signing_input().expect("a publication input"),
        )
        .expect("a transcript");
        let signature = kr_crypto::sign::sign(&self.writer, &transcript).expect("a signature");
        BackupGenerationPublication { payload, signature }
    }
}

fn stage(seed: u8, filename: &str, plaintext: &[u8]) -> StagedObject {
    stage_object(&ObjectSource {
        object_id: object_id(seed),
        filename,
        plaintext,
    })
    .expect("a staged object")
}

// ---------------------------------------------------------------------------------------------
// The store: one transaction per state transition.
// ---------------------------------------------------------------------------------------------

#[test]
fn admitting_a_generation_writes_its_objects_and_its_outbox_entry_with_it() {
    let environment = Environment::open();
    let producer = Producer::generate();
    let objects = [stage(1, "a.cbor", b"one"), stage(2, "b.cbor", b"two")];
    let sealed = producer.seal(1, &objects);

    let admitted = environment
        .service()
        .admit(
            &sealed,
            &objects,
            producer.writer.key_id(),
            PrivacyGeneration::new(3),
            TimestampMs::new(5_000),
        )
        .expect("the generation is admitted");
    assert_eq!(admitted.archive_id, archive_id());
    assert_eq!(
        admitted.staged_objects, 3,
        "two members and the encrypted manifest"
    );
    assert!(admitted.staged_bytes > 0);

    let record = environment
        .service()
        .generation(archive_id(), BackupGeneration::new(1))
        .expect("a read")
        .expect("the generation");
    assert_eq!(record.state, GenerationState::Staging);
    assert_eq!(record.writer_key_id, producer.writer.key_id());
    assert_eq!(record.privacy_generation, 3);
    assert_eq!(
        record.descriptor.as_deref(),
        Some(sealed.descriptor_bytes.as_slice())
    );

    let rows = environment
        .service()
        .objects(archive_id(), BackupGeneration::new(1))
        .expect("a read");
    assert_eq!(rows.len(), 3);
    for row in &rows {
        assert_eq!(row.state, ObjectState::Staged);
        assert_eq!(row.uploaded_bytes, 0);
        assert!(
            row.staged_path.exists(),
            "the ciphertext is on this host at {}",
            row.staged_path.display()
        );
        let bytes = std::fs::read(&row.staged_path).expect("the staged ciphertext");
        assert_eq!(bytes.len() as u64, row.encrypted_len);
    }

    let outbox = environment.service().outbox().expect("a read");
    assert_eq!(outbox.len(), 1, "one entry, admitted with the generation");
    assert_eq!(outbox[0].step, Step::Upload);
    assert!(!outbox[0].dispatched);
    assert_eq!(outbox[0].privacy_generation, 3);
    assert_eq!(outbox[0].sequence, admitted.sequence);
}

#[test]
fn the_publish_step_is_enqueued_with_the_last_object_that_finished_uploading() {
    let environment = Environment::open();
    let producer = Producer::generate();
    let objects = [stage(1, "a.cbor", b"one"), stage(2, "b.cbor", b"two")];
    let sealed = producer.seal(1, &objects);
    environment
        .service()
        .admit(
            &sealed,
            &objects,
            producer.writer.key_id(),
            PrivacyGeneration::new(0),
            TimestampMs::new(5_000),
        )
        .expect("the generation is admitted");

    let rows = environment
        .service()
        .objects(archive_id(), BackupGeneration::new(1))
        .expect("a read");
    for (index, row) in rows.iter().enumerate() {
        let complete = environment
            .service()
            .note_object_uploaded(
                archive_id(),
                BackupGeneration::new(1),
                row.object_id,
                TimestampMs::new(6_000),
            )
            .expect("the object is recorded");
        assert_eq!(
            complete,
            index + 1 == rows.len(),
            "only the last object completes the generation"
        );
    }

    let outbox = environment.service().outbox().expect("a read");
    assert_eq!(outbox.len(), 2);
    assert_eq!(outbox[1].step, Step::Publish);
    let record = environment
        .service()
        .generation(archive_id(), BackupGeneration::new(1))
        .expect("a read")
        .expect("the generation");
    assert_eq!(record.state, GenerationState::Uploading);
}

// ---------------------------------------------------------------------------------------------
// Startup reconciliation.
// ---------------------------------------------------------------------------------------------

#[test]
fn reconciliation_resumes_what_is_authorised_and_cancels_what_is_not() {
    let environment = Environment::open();
    let producer = Producer::generate();
    let retired = AuthorisationKeyPair::generate().expect("a writer key");
    environment
        .service()
        .enrol_writer(producer.writer.key_id(), archive_id(), TimestampMs::new(1))
        .expect("the writer is enrolled");
    environment
        .service()
        .enrol_writer(retired.key_id(), archive_id(), TimestampMs::new(1))
        .expect("the second writer is enrolled");

    let objects = [stage(1, "a.cbor", b"one")];
    let first = producer.seal(1, &objects);
    let second = producer.seal(2, &objects);
    for (sealed, writer) in [
        (&first, producer.writer.key_id()),
        (&second, retired.key_id()),
    ] {
        environment
            .service()
            .admit(
                sealed,
                &objects,
                writer,
                PrivacyGeneration::new(0),
                TimestampMs::new(5_000),
            )
            .expect("the generation is admitted");
    }

    // The owner retires the second writer, and the daemon restarts.
    environment
        .service()
        .retire_writer(retired.key_id(), TimestampMs::new(6_000))
        .expect("the writer is retired");
    let outcome = environment
        .service()
        .reconcile(TimestampMs::new(7_000))
        .expect("reconciliation");

    assert_eq!(
        outcome.resumed,
        vec![(archive_id(), BackupGeneration::new(1))]
    );
    assert_eq!(
        outcome.no_longer_authorised,
        vec![(archive_id(), BackupGeneration::new(2))]
    );
    assert!(outcome.outcome_unknown.is_empty());

    let cancelled = environment
        .service()
        .generation(archive_id(), BackupGeneration::new(2))
        .expect("a read")
        .expect("the generation");
    assert_eq!(cancelled.state, GenerationState::Cancelled);
    assert!(
        cancelled
            .detail
            .as_deref()
            .expect("a reason")
            .contains("no longer holds an enrolment")
    );
    assert!(
        environment
            .service()
            .outbox()
            .expect("a read")
            .iter()
            .all(|entry| entry.backup_generation == BackupGeneration::new(1)),
        "a cancelled generation leaves nothing in the outbox"
    );
}

#[test]
fn a_publication_that_left_this_host_and_was_never_answered_is_recorded_as_unknown() {
    let environment = Environment::open();
    let producer = Producer::generate();
    environment
        .service()
        .enrol_writer(producer.writer.key_id(), archive_id(), TimestampMs::new(1))
        .expect("the writer is enrolled");
    let objects = [stage(1, "a.cbor", b"one")];
    let sealed = producer.seal(1, &objects);
    environment
        .service()
        .admit(
            &sealed,
            &objects,
            producer.writer.key_id(),
            PrivacyGeneration::new(0),
            TimestampMs::new(5_000),
        )
        .expect("the generation is admitted");

    // Every object arrives, the publish step is enqueued and dispatched, and then this host stops.
    for row in environment
        .service()
        .objects(archive_id(), BackupGeneration::new(1))
        .expect("a read")
    {
        environment
            .service()
            .note_object_uploaded(
                archive_id(),
                BackupGeneration::new(1),
                row.object_id,
                TimestampMs::new(6_000),
            )
            .expect("the object is recorded");
    }
    let publish = environment
        .service()
        .outbox()
        .expect("a read")
        .into_iter()
        .find(|entry| entry.step == Step::Publish)
        .expect("a publish entry");
    environment
        .service()
        .note_dispatched(publish.sequence)
        .expect("the entry is dispatched");

    let outcome = environment
        .service()
        .reconcile(TimestampMs::new(7_000))
        .expect("reconciliation");
    assert_eq!(
        outcome.outcome_unknown,
        vec![(archive_id(), BackupGeneration::new(1))]
    );
    assert!(outcome.resumed.is_empty());
    let record = environment
        .service()
        .generation(archive_id(), BackupGeneration::new(1))
        .expect("a read")
        .expect("the generation");
    assert_eq!(record.state, GenerationState::Unknown);
    assert!(
        record
            .detail
            .as_deref()
            .expect("a reason")
            .contains("not something this host can say")
    );
}

#[test]
fn a_dispatched_upload_goes_back_in_hand_rather_than_becoming_unknown() {
    let environment = Environment::open();
    let producer = Producer::generate();
    environment
        .service()
        .enrol_writer(producer.writer.key_id(), archive_id(), TimestampMs::new(1))
        .expect("the writer is enrolled");
    let objects = [stage(1, "a.cbor", b"one")];
    let sealed = producer.seal(1, &objects);
    let admitted = environment
        .service()
        .admit(
            &sealed,
            &objects,
            producer.writer.key_id(),
            PrivacyGeneration::new(0),
            TimestampMs::new(5_000),
        )
        .expect("the generation is admitted");
    environment
        .service()
        .note_dispatched(admitted.sequence)
        .expect("the upload is dispatched");

    // The same object under the same identity and hash is the same object, so sending it again is
    // not a second publication.
    let outcome = environment
        .service()
        .reconcile(TimestampMs::new(7_000))
        .expect("reconciliation");
    assert_eq!(
        outcome.resumed,
        vec![(archive_id(), BackupGeneration::new(1))]
    );
    assert!(outcome.outcome_unknown.is_empty());
    let outbox = environment.service().outbox().expect("a read");
    assert_eq!(outbox.len(), 1);
    assert!(!outbox[0].dispatched, "it is back in hand");
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-24.16: generation and writer authority verified, and a restore that returns data only.
// ---------------------------------------------------------------------------------------------

#[test]
fn a_restore_verifies_the_owners_enrolment_the_writers_signature_and_the_generation() {
    let producer = Producer::generate();
    let objects = [stage(1, "a.cbor", b"one")];
    let sealed = producer.seal(4, &objects);
    let publication = producer.publish(&sealed);
    let enrolment = producer.enrolment(1);
    let checkpoint = ArchiveCheckpoint {
        archive_id: archive_id(),
        backup_generation: BackupGeneration::new(4),
        encrypted_manifest_hash: sealed.descriptor.encrypted_manifest.encrypted_object_hash,
        verified_at_ms: TimestampMs::new(3_000),
    };

    let verified = RestoreRequest {
        publication: &publication,
        descriptor_len: sealed.descriptor_bytes.len(),
        enrolment: &enrolment,
        owner_key: producer.owner.public(),
        writer_key: producer.writer.public(),
        checkpoint: Some((CheckpointSource::Pairing, &checkpoint)),
    }
    .verify()
    .expect("the restore is admitted");
    assert_eq!(verified.archive_id, archive_id());
    assert_eq!(verified.writer_key_id, producer.writer.key_id());
    assert_eq!(verified.writer_revision, 1);
    assert!(verified.generation.describe().contains("generation 4"));
    assert!(!verified.generation.proves_no_newer_archive());
}

#[test]
fn a_restore_is_refused_when_any_of_the_three_checks_does_not_hold() {
    let producer = Producer::generate();
    let impostor = Producer::generate();
    let objects = [stage(1, "a.cbor", b"one")];
    let sealed = producer.seal(4, &objects);
    let publication = producer.publish(&sealed);
    let enrolment = producer.enrolment(1);

    // An enrolment signed by somebody who is not the collection's owner.
    assert!(
        RestoreRequest {
            publication: &publication,
            descriptor_len: sealed.descriptor_bytes.len(),
            enrolment: &enrolment,
            owner_key: impostor.owner.public(),
            writer_key: producer.writer.public(),
            checkpoint: None,
        }
        .verify()
        .is_err(),
        "the enrolment is verified against the owner's own key"
    );

    // A writer key that is not the one the owner enrolled.
    assert!(
        RestoreRequest {
            publication: &publication,
            descriptor_len: sealed.descriptor_bytes.len(),
            enrolment: &enrolment,
            owner_key: producer.owner.public(),
            writer_key: impostor.writer.public(),
            checkpoint: None,
        }
        .verify()
        .is_err(),
        "a writer the bundle supplied is checked against the owner's enrolment"
    );

    // A publication whose signature is another writer's.
    let forged = BackupGenerationPublication {
        payload: publication.payload.clone(),
        signature: impostor.publish(&sealed).signature,
    };
    assert!(
        RestoreRequest {
            publication: &forged,
            descriptor_len: sealed.descriptor_bytes.len(),
            enrolment: &enrolment,
            owner_key: producer.owner.public(),
            writer_key: producer.writer.public(),
            checkpoint: None,
        }
        .verify()
        .is_err(),
        "the publication's own signature is verified under the enrolled writer"
    );

    // A generation the checkpoint says is older than what the owner verified.
    let checkpoint = ArchiveCheckpoint {
        archive_id: archive_id(),
        backup_generation: BackupGeneration::new(9),
        encrypted_manifest_hash: Digest256::from_bytes([0xab; 32]),
        verified_at_ms: TimestampMs::new(3_000),
    };
    let refusal = RestoreRequest {
        publication: &publication,
        descriptor_len: sealed.descriptor_bytes.len(),
        enrolment: &enrolment,
        owner_key: producer.owner.public(),
        writer_key: producer.writer.public(),
        checkpoint: Some((CheckpointSource::Pairing, &checkpoint)),
    }
    .verify()
    .expect_err("a replayed older archive");
    assert!(refusal.to_string().contains("generation 4"));

    // A descriptor over section 20's byte limit fails before anything else.
    assert!(
        RestoreRequest {
            publication: &publication,
            descriptor_len: kr_protocol::archive::MAX_ARCHIVE_DESCRIPTOR_LEN + 1,
            enrolment: &enrolment,
            owner_key: producer.owner.public(),
            writer_key: producer.writer.public(),
            checkpoint: None,
        }
        .verify()
        .is_err()
    );
}

#[test]
fn a_restore_returns_data_and_never_a_reusable_host_control_key() {
    let admitted = RestoreRequest::admit(&[
        Material::SessionData,
        Material::DeviceConfiguration,
        Material::BackupGenerationCheckpoint,
        Material::EndpointPrivateKey,
        Material::ControlSigningPrivateKey,
        Material::NotificationPreviewPrivateKey,
        Material::RecoverySeed,
        Material::Grant { revoked: true },
        Material::HostGrantAuthority,
    ]);
    assert_eq!(admitted.restored.len(), 3);
    for refused in [
        Material::EndpointPrivateKey,
        Material::ControlSigningPrivateKey,
        Material::NotificationPreviewPrivateKey,
        Material::RecoverySeed,
        Material::Grant { revoked: true },
        Material::HostGrantAuthority,
    ] {
        assert!(admitted.refused_kind(refused), "{refused:?} is refused");
    }
    assert!(admitted.limits.requires_fresh_owner_authorised_pairing());
    assert!(!admitted.limits.creates_remote_control_authority());
}

// ---------------------------------------------------------------------------------------------
// The privacy hook, under T-040's generation contract.
// ---------------------------------------------------------------------------------------------

#[test]
fn privacy_mode_fences_cancels_and_removes_what_this_host_still_holds() {
    let mut environment = Environment::open();
    let producer = Producer::generate();
    environment
        .service()
        .enrol_writer(producer.writer.key_id(), archive_id(), TimestampMs::new(1))
        .expect("the writer is enrolled");

    // One generation is staged and undispatched; a second has already been published.
    let objects = [stage(1, "a.cbor", b"one")];
    let staged = producer.seal(1, &objects);
    environment
        .service()
        .admit(
            &staged,
            &objects,
            producer.writer.key_id(),
            PrivacyGeneration::new(0),
            TimestampMs::new(5_000),
        )
        .expect("the generation is admitted");
    let published = producer.seal(2, &objects);
    environment
        .service()
        .admit(
            &published,
            &objects,
            producer.writer.key_id(),
            PrivacyGeneration::new(0),
            TimestampMs::new(5_100),
        )
        .expect("the generation is admitted");
    let mode = PrivacyMode::new();
    environment
        .service()
        .note_published(
            archive_id(),
            BackupGeneration::new(2),
            PrivacyGeneration::INITIAL,
            &mode,
            TimestampMs::new(5_200),
        )
        .expect("the second generation is published");

    let mut mode = PrivacyMode::new();
    let generation = mode.open_generation(TimestampMs::new(6_000));
    let staged_paths: Vec<std::path::PathBuf> = environment
        .service()
        .objects(archive_id(), BackupGeneration::new(1))
        .expect("a read")
        .into_iter()
        .map(|row| row.staged_path)
        .collect();

    let enabling = {
        let mut subsystems: Vec<&mut dyn PrivacySubsystem> = vec![&mut environment.service];
        mode.apply(&mut subsystems, TimestampMs::new(6_000))
    };
    assert_eq!(enabling.generation, generation);

    let (name, fenced) = enabling.fenced[0];
    assert_eq!(name, SUBSYSTEM_NAME);
    assert_eq!(fenced.queues, 1);
    assert_eq!(
        fenced.items, 1,
        "one undispatched entry was holding content"
    );

    let (_, cancelled) = enabling.cancelled[0];
    assert_eq!(cancelled.undispatched, 1);
    assert_eq!(cancelled.in_flight, 0);

    let (_, removed) = enabling.removed[0];
    assert!(removed.bytes > 0, "staged ciphertext left this host");
    assert!(removed.records > 0);
    for path in &staged_paths {
        assert!(
            !path.exists(),
            "the staged ciphertext at {} is gone",
            path.display()
        );
    }

    // The unpublished generation is forgotten; the published one is kept as a retained artifact.
    assert!(
        environment
            .service()
            .generation(archive_id(), BackupGeneration::new(1))
            .expect("a read")
            .is_none()
    );
    let kept = environment
        .service()
        .generation(archive_id(), BackupGeneration::new(2))
        .expect("a read")
        .expect("the published generation is kept");
    assert_eq!(kept.state, GenerationState::Published);
    for row in environment
        .service()
        .objects(archive_id(), BackupGeneration::new(2))
        .expect("a read")
    {
        assert_eq!(row.state, ObjectState::Removed);
        assert!(!row.staged_path.exists());
    }

    // What had already left is shown rather than erased, with a deletion of its own.
    assert_eq!(enabling.exported.len(), 1);
    let exported = &enabling.exported[0];
    assert_eq!(exported.kind, "backup archive");
    assert!(exported.reference.contains("generation 2"));
    assert!(
        exported.deletable,
        "this host holds a reference it can ask the removal through"
    );
    assert!(
        !exported.reference.contains('/'),
        "the reference is an archive, never a path: {}",
        exported.reference
    );

    // What is kept is named rather than quietly retained.
    assert_eq!(enabling.kept.len(), 2);
    for kept in &enabling.kept {
        assert!(!kept.what.is_empty());
        assert!(!kept.why.is_empty());
    }

    // Nothing is outstanding, and nothing failed, so cleanup is complete.
    assert!(environment.service().faults().is_empty());
    let subsystems: Vec<&dyn PrivacySubsystem> = vec![&environment.service];
    assert!(PrivacyMode::reconcile(&subsystems).is_complete());
}

#[test]
fn dispatched_backup_work_keeps_reconciliation_open_until_it_is_settled() {
    let mut environment = Environment::open();
    let producer = Producer::generate();
    environment
        .service()
        .enrol_writer(producer.writer.key_id(), archive_id(), TimestampMs::new(1))
        .expect("the writer is enrolled");
    let objects = [stage(1, "a.cbor", b"one")];
    let sealed = producer.seal(1, &objects);
    let admitted = environment
        .service()
        .admit(
            &sealed,
            &objects,
            producer.writer.key_id(),
            PrivacyGeneration::new(0),
            TimestampMs::new(5_000),
        )
        .expect("the generation is admitted");
    environment
        .service()
        .note_dispatched(admitted.sequence)
        .expect("the upload is in flight");

    let mut mode = PrivacyMode::new();
    mode.open_generation(TimestampMs::new(6_000));
    let enabling = {
        let mut subsystems: Vec<&mut dyn PrivacySubsystem> = vec![&mut environment.service];
        mode.apply(&mut subsystems, TimestampMs::new(6_000))
    };
    let (_, cancelled) = enabling.cancelled[0];
    assert_eq!(cancelled.undispatched, 0);
    assert_eq!(cancelled.in_flight, 1, "it had already left this host");
    assert_eq!(enabling.in_flight(), 1);

    {
        let subsystems: Vec<&dyn PrivacySubsystem> = vec![&environment.service];
        assert!(
            !PrivacyMode::reconcile(&subsystems).is_complete(),
            "cleanup is not complete while a backup is still in flight"
        );
    }

    // The upload is followed to its end and the generation is settled, and only then is cleanup
    // complete.
    environment
        .service()
        .note_outcome_unknown(
            archive_id(),
            BackupGeneration::new(1),
            "the upload was in flight when privacy mode was enabled",
            TimestampMs::new(7_000),
        )
        .expect("the outcome is recorded");
    let subsystems: Vec<&dyn PrivacySubsystem> = vec![&environment.service];
    assert!(PrivacyMode::reconcile(&subsystems).is_complete());
}

#[test]
fn a_result_produced_under_an_earlier_generation_is_not_published() {
    let environment = Environment::open();
    let producer = Producer::generate();
    let objects = [stage(1, "a.cbor", b"one")];
    let sealed = producer.seal(1, &objects);
    environment
        .service()
        .admit(
            &sealed,
            &objects,
            producer.writer.key_id(),
            PrivacyGeneration::INITIAL,
            TimestampMs::new(5_000),
        )
        .expect("the generation is admitted");

    let mut mode = PrivacyMode::new();
    let now = mode.open_generation(TimestampMs::new(6_000));

    // The answer to work admitted before privacy mode was enabled comes back afterwards.
    let refusal = environment
        .service()
        .note_published(
            archive_id(),
            BackupGeneration::new(1),
            PrivacyGeneration::INITIAL,
            &mode,
            TimestampMs::new(7_000),
        )
        .expect_err("a late old-generation result");
    assert!(refusal.to_string().contains("privacy generation 0"));
    let record = environment
        .service()
        .generation(archive_id(), BackupGeneration::new(1))
        .expect("a read")
        .expect("the generation");
    assert_ne!(
        record.state,
        GenerationState::Published,
        "the refused result changed nothing"
    );

    // A result produced under the generation in force is published.
    environment
        .service()
        .note_published(
            archive_id(),
            BackupGeneration::new(1),
            now,
            &mode,
            TimestampMs::new(7_000),
        )
        .expect("a result from the generation in force");
    let record = environment
        .service()
        .generation(archive_id(), BackupGeneration::new(1))
        .expect("a read")
        .expect("the generation");
    assert_eq!(record.state, GenerationState::Published);
}

#[test]
fn a_fence_is_recorded_durably_and_a_restart_comes_back_fenced() {
    let root = tempfile::tempdir().expect("a disposable directory on the internal disk");
    let state = root.path().join("state");
    std::fs::create_dir_all(&state).expect("the state directory");
    {
        let mut service = BackupService::open(&state).expect("a backup service");
        assert_eq!(service.fenced_at().expect("a read"), None);
        let fenced = service.fence(PrivacyGeneration::new(4));
        assert_eq!(fenced.queues, 1);
        assert!(service.faults().is_empty());
        assert_eq!(service.fenced_at().expect("a read"), Some(4));
    }
    // A host that held the fence in memory would come back and dispatch what it had just stopped.
    let reopened = BackupService::open(&state).expect("the service opens again");
    assert_eq!(reopened.fenced_at().expect("a read"), Some(4));
}
