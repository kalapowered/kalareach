//! The environment's backup service: its store, its reconciliation, its restore checks and its
//! privacy hook.
//!
//! Section 24's ownership row for backup generations, and section 24's privacy paragraphs. Rule 12
//! applies to every path here: `backup.sqlite` and every staged byte live under the platform
//! temporary directory, which is on the internal disk, and nothing in this file launches a process.

use kr_controller::backup::store::{
    AttemptOutcome, AttemptStatus, BackupStore, FenceRelease, LocalState, ObligationKind,
    Production, Publication, Remote, SCHEMA_VERSION, Step, UploadRecord,
};
use kr_controller::backup::{BackupService, RestoreRequest, SUBSYSTEM_NAME};
use kr_controller::error::ControllerError;
use kr_crypto::backup::{
    ArchivePlan, ArchiveRecipients, CheckpointSource, CollectionKind, GenerationExpectation,
    KeyRotation, Material, ObjectSource, SealedArchive, StagedObject, seal_archive, stage_object,
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

/// Who these tests hand a dispatch attempt to. A real one names the transport that carries it.
const EXECUTOR: &str = "the test transport";

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
        Self::started(service, root)
    }

    /// One whose store is a file, so a test can read and write the same database beside it.
    fn at(state: &std::path::Path) -> Self {
        Self::started(
            BackupService::open(state).expect("a backup service on the internal disk"),
            tempfile::tempdir().expect("a disposable directory on the internal disk"),
        )
    }

    /// A service opens unready, so a started one has reconciled, exactly as a daemon does.
    fn started(service: BackupService, root: tempfile::TempDir) -> Self {
        service
            .reconcile(TimestampMs::new(4_000))
            .expect("startup reconciliation");
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
    stage_object(
        &ObjectSource {
            object_id: object_id(seed),
            filename,
            plaintext,
        },
        KeyRotation::INITIAL,
    )
    .expect("a staged object")
}

/// Acknowledges every object of one generation, as the upload attempt that carried them.
fn acknowledge_every_object(
    service: &BackupService,
    upload: u64,
    backup_generation: BackupGeneration,
    now_ms: TimestampMs,
) {
    for row in service
        .objects(archive_id(), backup_generation)
        .expect("a read")
    {
        service
            .note_object_uploaded(
                upload,
                archive_id(),
                backup_generation,
                row.object_id,
                now_ms,
            )
            .expect("the object is acknowledged");
    }
}

/// Carries one admitted generation as far as a publication attempt this host has dispatched.
///
/// Every object arrives, the executor holding the upload says that transfer finished, and the
/// descriptor the completion enqueues leaves too. Returns the publication attempt's sequence,
/// which is what an answer about it has to name.
fn dispatch_publication(
    service: &BackupService,
    upload: u64,
    backup_generation: BackupGeneration,
    now_ms: TimestampMs,
) -> u64 {
    acknowledge_every_object(service, upload, backup_generation, now_ms);
    service
        .note_attempt_accepted(upload, now_ms)
        .expect("the executor reports its upload finished");
    let publication = service
        .outbox()
        .expect("a read")
        .into_iter()
        .find(|attempt| {
            attempt.step == Step::Publish && attempt.backup_generation == backup_generation
        })
        .expect("a publication attempt");
    service
        .note_dispatched(publication.sequence, EXECUTOR, now_ms)
        .expect("the publication is in flight");
    publication.sequence
}

// ---------------------------------------------------------------------------------------------
// The store: one transaction per state transition.
// ---------------------------------------------------------------------------------------------

#[test]
fn admitting_a_generation_writes_its_objects_and_its_outbox_entry_with_it() {
    let environment = Environment::open();
    let producer = Producer::generate();
    environment
        .service()
        .enrol_writer(producer.writer.key_id(), archive_id(), TimestampMs::new(1))
        .expect("the writer is enrolled");
    let objects = [stage(1, "a.cbor", b"one"), stage(2, "b.cbor", b"two")];
    let sealed = producer.seal(1, &objects);

    let admitted = environment
        .service()
        .admit(
            &sealed,
            &objects,
            producer.writer.key_id(),
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
    assert_eq!(record.production, Production::Producing);
    assert_eq!(record.remote, Remote::Nothing);
    assert_eq!(record.writer_key_id, producer.writer.key_id());
    // The store's own durable generation, stamped inside the transaction that wrote the row. The
    // caller supplies none, so there is nothing for a stale one to be read from.
    let current = environment
        .service()
        .privacy_status()
        .expect("a read")
        .current_generation;
    assert_eq!(record.privacy_generation, current);
    assert_eq!(admitted.privacy_generation, current);
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
        assert_eq!(row.local_state, LocalState::Present);
        assert_eq!(row.acknowledged_bytes, 0);
        assert!(!row.is_acknowledged());
        assert!(
            row.staged_path.exists(),
            "the ciphertext is on this host at {}",
            row.staged_path.display()
        );
        let bytes = std::fs::read(&row.staged_path).expect("the staged ciphertext");
        assert_eq!(bytes.len() as u64, row.encrypted_len);
    }

    let outbox = environment.service().outbox().expect("a read");
    assert_eq!(outbox.len(), 1, "one attempt, admitted with the generation");
    assert_eq!(outbox[0].step, Step::Upload);
    assert_eq!(outbox[0].status, AttemptStatus::Queued);
    assert_eq!(outbox[0].outcome, None);
    assert_eq!(outbox[0].executor, None);
    assert_eq!(outbox[0].privacy_generation, current);
    assert_eq!(outbox[0].sequence, admitted.sequence);
}

#[test]
fn the_publish_step_is_enqueued_with_the_last_object_that_finished_uploading() {
    let environment = Environment::open();
    let producer = Producer::generate();
    environment
        .service()
        .enrol_writer(producer.writer.key_id(), archive_id(), TimestampMs::new(1))
        .expect("the writer is enrolled");
    let objects = [stage(1, "a.cbor", b"one"), stage(2, "b.cbor", b"two")];
    let sealed = producer.seal(1, &objects);
    let admitted = environment
        .service()
        .admit(
            &sealed,
            &objects,
            producer.writer.key_id(),
            TimestampMs::new(5_000),
        )
        .expect("the generation is admitted");
    environment
        .service()
        .note_dispatched(admitted.sequence, EXECUTOR, TimestampMs::new(5_500))
        .expect("the upload is in flight");

    let rows = environment
        .service()
        .objects(archive_id(), BackupGeneration::new(1))
        .expect("a read");
    for (index, row) in rows.iter().enumerate() {
        let complete = environment
            .service()
            .note_object_uploaded(
                admitted.sequence,
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

    // The object that completed the generation enqueues the publish step in the same transaction.
    // It ends no attempt: the upload keeps its place, because one object arriving is not the end
    // of a transfer and the objects say nothing about whether that executor is still sending.
    let outbox = environment.service().outbox().expect("a read");
    assert_eq!(outbox.len(), 2);
    assert!(
        outbox
            .iter()
            .any(|attempt| attempt.step == Step::Upload
                && attempt.status == AttemptStatus::Dispatched),
        "the upload attempt is still owed an answer"
    );
    assert!(
        outbox
            .iter()
            .any(|attempt| attempt.step == Step::Publish
                && attempt.status == AttemptStatus::Queued),
        "the publish step is enqueued"
    );

    // And a repeated acknowledgement of an object that had already arrived does not enqueue a
    // second publication.
    let first = rows[0].object_id;
    environment
        .service()
        .note_object_uploaded(
            admitted.sequence,
            archive_id(),
            BackupGeneration::new(1),
            first,
            TimestampMs::new(6_500),
        )
        .expect("a repeated acknowledgement");
    let outbox = environment.service().outbox().expect("a read");
    assert_eq!(outbox.len(), 2, "one publication, however often it is told");

    // The executor that held the upload says its transfer finished. That, and nothing else, ends
    // it; nothing can resume an upload that has finished.
    environment
        .service()
        .note_attempt_accepted(admitted.sequence, TimestampMs::new(6_600))
        .expect("the executor reports its upload finished");
    let outbox = environment.service().outbox().expect("a read");
    assert_eq!(outbox.len(), 1);
    assert_eq!(outbox[0].step, Step::Publish);
    let record = environment
        .service()
        .generation(archive_id(), BackupGeneration::new(1))
        .expect("a read")
        .expect("the generation");
    assert_eq!(record.production, Production::Producing);
    assert_eq!(
        record.remote,
        Remote::Objects,
        "the service holds its ciphertext, and no descriptor of it yet"
    );
}

// ---------------------------------------------------------------------------------------------
// Startup reconciliation.
// ---------------------------------------------------------------------------------------------

#[test]
fn reconciliation_resumes_what_is_authorised_and_cancels_what_is_not() {
    let environment = Environment::open();
    let producer = Producer::generate();
    // A second producer of the same collection, with its own signing key. The writer a generation
    // is admitted under has to be the writer that signed it, so the second generation is sealed by
    // the writer it is admitted under.
    let leaving = Producer::generate();
    for writer in [producer.writer.key_id(), leaving.writer.key_id()] {
        environment
            .service()
            .enrol_writer(writer, archive_id(), TimestampMs::new(1))
            .expect("the writer is enrolled");
    }

    let objects = [stage(1, "a.cbor", b"one")];
    let first = producer.seal(1, &objects);
    let second = leaving.seal(2, &objects);
    for (sealed, writer) in [
        (&first, producer.writer.key_id()),
        (&second, leaving.writer.key_id()),
    ] {
        environment
            .service()
            .admit(sealed, &objects, writer, TimestampMs::new(5_000))
            .expect("the generation is admitted");
    }

    // The owner retires the second writer, and the daemon restarts.
    environment
        .service()
        .retire_writer(
            archive_id(),
            leaving.writer.key_id(),
            TimestampMs::new(6_000),
        )
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
    assert_eq!(cancelled.production, Production::Cancelled);
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
    let admitted = environment
        .service()
        .admit(
            &sealed,
            &objects,
            producer.writer.key_id(),
            TimestampMs::new(5_000),
        )
        .expect("the generation is admitted");
    environment
        .service()
        .note_dispatched(admitted.sequence, EXECUTOR, TimestampMs::new(5_500))
        .expect("the upload is in flight");

    // Every object arrives, the publish step is enqueued and dispatched, and then this host stops.
    for row in environment
        .service()
        .objects(archive_id(), BackupGeneration::new(1))
        .expect("a read")
    {
        environment
            .service()
            .note_object_uploaded(
                admitted.sequence,
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
        .note_dispatched(publish.sequence, EXECUTOR, TimestampMs::new(6_500))
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
    assert_eq!(record.remote, Remote::Unknown);
    assert_eq!(record.production, Production::Cancelled);
    assert!(
        record
            .detail
            .as_deref()
            .expect("a reason")
            .contains("not something this host can say")
    );
}

#[test]
fn a_resumed_upload_is_a_new_attempt_and_the_one_that_left_stays_unanswered() {
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
            TimestampMs::new(5_000),
        )
        .expect("the generation is admitted");
    environment
        .service()
        .note_dispatched(admitted.sequence, EXECUTOR, TimestampMs::new(6_500))
        .expect("the upload is dispatched");

    // The same object under the same identity and hash is the same object, so sending it again is
    // not a second publication. It is, however, a second *attempt*: the one that left this host
    // keeps its identity and its unanswered status, because a restart establishes nothing about
    // what became of it.
    let outcome = environment
        .service()
        .reconcile(TimestampMs::new(7_000))
        .expect("reconciliation");
    assert_eq!(
        outcome.resumed,
        vec![(archive_id(), BackupGeneration::new(1))]
    );
    assert_eq!(
        outcome.unanswered,
        vec![(archive_id(), BackupGeneration::new(1))]
    );
    assert!(outcome.outcome_unknown.is_empty());
    let outbox = environment.service().outbox().expect("a read");
    assert_eq!(outbox.len(), 2, "the attempt that left, and a fresh one");
    assert_eq!(outbox[0].sequence, admitted.sequence);
    assert_eq!(
        outbox[0].status,
        AttemptStatus::Dispatched,
        "nothing here establishes how the attempt that left ended"
    );
    assert_eq!(outbox[0].executor.as_deref(), Some(EXECUTOR));
    assert_eq!(outbox[1].status, AttemptStatus::Queued);
    assert_eq!(outbox[1].step, Step::Upload);
    assert_ne!(outbox[1].sequence, admitted.sequence);

    // A fence arriving now therefore writes down what each one really is: the attempt that left is
    // followed, and only the fresh one is cancelled. A cancellation of the first would have ended
    // the only record that anything of this generation had gone anywhere.
    environment
        .service()
        .raise_fence(PrivacyGeneration::new(1), TimestampMs::new(8_000))
        .expect("the fence is raised");
    let owed = environment.service().obligations().expect("a read");
    let resolve: Vec<u64> = owed
        .iter()
        .filter(|obligation| obligation.kind == ObligationKind::ResolveUpload)
        .filter_map(|obligation| obligation.entry_sequence)
        .collect();
    let cancel: Vec<u64> = owed
        .iter()
        .filter(|obligation| obligation.kind == ObligationKind::CancelEntry)
        .filter_map(|obligation| obligation.entry_sequence)
        .collect();
    assert_eq!(resolve, vec![admitted.sequence]);
    assert_eq!(cancel, vec![outbox[1].sequence]);
}

#[test]
fn a_fence_stops_admission_and_dispatch_and_survives_a_restart() {
    let root = tempfile::tempdir().expect("a disposable directory on the internal disk");
    let state = root.path().join("state");
    std::fs::create_dir_all(&state).expect("the state directory");
    let producer = Producer::generate();
    let objects = [stage(1, "a.cbor", b"one")];
    let sealed = producer.seal(1, &objects);
    let second = producer.seal(2, &objects);
    let admitted;
    {
        let mut service = BackupService::open(&state).expect("a backup service");
        service
            .reconcile(TimestampMs::new(4_000))
            .expect("the startup reconciliation a service opens unready without");
        service
            .enrol_writer(producer.writer.key_id(), archive_id(), TimestampMs::new(1))
            .expect("the writer is enrolled");
        admitted = service
            .admit(
                &sealed,
                &objects,
                producer.writer.key_id(),
                TimestampMs::new(5_000),
            )
            .expect("the generation is admitted");

        service.fence(PrivacyGeneration::new(4));
        assert_eq!(service.fenced_at().expect("a read"), Some(4));

        // A fence that recorded a number and let the queue go would be a fence in name only.
        assert!(
            service
                .note_dispatched(admitted.sequence, EXECUTOR, TimestampMs::new(6_500))
                .is_err(),
            "the entry the fence stopped does not leave this host"
        );
        assert!(
            service
                .admit(
                    &second,
                    &objects,
                    producer.writer.key_id(),
                    TimestampMs::new(6_000),
                )
                .is_err(),
            "no more content-bearing backup work is admitted while the fence holds"
        );
    }

    // A restart comes back fenced, and its reconciliation puts nothing back in hand. The fence
    // prohibited production for that generation when it went up, and a restart does not undo it.
    let service = BackupService::open(&state).expect("the service opens again");
    assert_eq!(service.fenced_at().expect("a read"), Some(4));
    assert!(
        service
            .note_dispatched(admitted.sequence, EXECUTOR, TimestampMs::new(6_500))
            .is_err()
    );
    let outcome = service
        .reconcile(TimestampMs::new(7_000))
        .expect("reconciliation");
    assert!(outcome.resumed.is_empty());
    assert!(outcome.unanswered.is_empty(), "nothing had left this host");
    let record = service
        .generation(archive_id(), BackupGeneration::new(1))
        .expect("a read")
        .expect("the record");
    assert_eq!(record.production, Production::Cancelled);
    assert!(
        record
            .detail
            .as_deref()
            .is_some_and(|detail| detail.contains("privacy generation 4")),
        "the record says which fence stopped it: {:?}",
        record.detail
    );
}

#[test]
fn a_writer_enrolled_for_one_archive_does_not_authorise_another() {
    let environment = Environment::open();
    let producer = Producer::generate();
    let elsewhere = ArchiveId::new(Uuid::from_bytes([0x99; 16]));
    environment
        .service()
        .enrol_writer(producer.writer.key_id(), elsewhere, TimestampMs::new(1))
        .expect("the writer is enrolled for another archive");

    let objects = [stage(1, "a.cbor", b"one")];
    let sealed = producer.seal(1, &objects);
    assert!(
        environment
            .service()
            .admit(
                &sealed,
                &objects,
                producer.writer.key_id(),
                TimestampMs::new(5_000),
            )
            .is_err(),
        "an enrolment for one collection does not authorise work for another"
    );
}

#[test]
fn a_generation_already_admitted_is_not_admitted_again() {
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
            TimestampMs::new(5_000),
        )
        .expect("the generation is admitted");
    let staged: Vec<std::path::PathBuf> = environment
        .service()
        .objects(archive_id(), BackupGeneration::new(1))
        .expect("a read")
        .into_iter()
        .map(|row| row.staged_path)
        .collect();
    let before: Vec<Vec<u8>> = staged
        .iter()
        .map(|path| std::fs::read(path).expect("the staged ciphertext"))
        .collect();

    // Sealing the same generation again produces different ciphertext under different keys. If it
    // were staged over the top of the first, the rows this host has committed would name bytes
    // that no longer open.
    let again = producer.seal(1, &objects);
    assert!(
        environment
            .service()
            .admit(
                &again,
                &objects,
                producer.writer.key_id(),
                TimestampMs::new(6_000),
            )
            .is_err(),
        "a generation this host already accounts for is not admitted again"
    );
    for (path, bytes) in staged.iter().zip(before) {
        assert_eq!(
            std::fs::read(path).expect("the staged ciphertext"),
            bytes,
            "nothing wrote over the ciphertext this host is accounting for"
        );
    }
}

#[test]
fn releasing_the_fence_admits_backup_production_again_under_the_new_generation() {
    let environment = Environment::open();
    let producer = Producer::generate();
    environment
        .service()
        .enrol_writer(producer.writer.key_id(), archive_id(), TimestampMs::new(1))
        .expect("the writer is enrolled");
    let objects = [stage(1, "a.cbor", b"one")];

    let mut environment = environment;
    let mut mode = PrivacyMode::new();
    mode.open_generation(TimestampMs::new(6_000));
    {
        let mut subsystems: Vec<&mut dyn PrivacySubsystem> = vec![&mut environment.service];
        mode.apply(&mut subsystems, TimestampMs::new(6_000));
    }
    assert!(
        environment
            .service()
            .admit(
                &producer.seal(1, &objects),
                &objects,
                producer.writer.key_id(),
                TimestampMs::new(6_500),
            )
            .is_err(),
        "nothing is admitted while the fence holds"
    );

    // Turning privacy mode off releases the fence, under a generation of its own. Nothing the
    // fence cancelled comes back.
    let fenced_at = mode.generation();
    let resumed = mode.disable(TimestampMs::new(7_000));
    assert_eq!(
        environment
            .service()
            .release_fence(fenced_at, resumed.generation, TimestampMs::new(7_000))
            .expect("the release is attempted"),
        FenceRelease::Released,
        "nothing was left staged, so the fence has nothing outstanding under it"
    );
    assert_eq!(environment.service().fenced_at().expect("a read"), None);
    environment
        .service()
        .admit(
            &producer.seal(2, &objects),
            &objects,
            producer.writer.key_id(),
            TimestampMs::new(8_000),
        )
        .expect("backup production is admitted again");
    let record = environment
        .service()
        .generation(archive_id(), BackupGeneration::new(2))
        .expect("a read")
        .expect("the generation");
    assert_eq!(record.privacy_generation, resumed.generation.get());
    assert!(
        environment
            .service()
            .generation(archive_id(), BackupGeneration::new(1))
            .expect("a read")
            .is_none(),
        "what the fence stopped is not reconstructed"
    );
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
        archive_id: archive_id(),
        publication: &publication,
        descriptor_len: sealed.descriptor_bytes.len(),
        enrolment: &enrolment,
        owner_key: producer.owner.public(),
        writer_key: producer.writer.public(),
        generation: GenerationExpectation::Checkpoint(CheckpointSource::Pairing, &checkpoint),
    }
    .verify()
    .expect("the restore is admitted");
    assert_eq!(verified.archive_id(), archive_id());
    assert_eq!(verified.writer_key_id(), producer.writer.key_id());
    assert_eq!(verified.writer_revision(), 1);
    assert!(verified.generation().describe().contains("generation 4"));
    assert!(!verified.generation().proves_no_newer_archive());

    // What it hands the archive layer is built from what was verified and takes no argument, so a
    // second genuine generation of the same collection cannot be substituted for it.
    let expectation = verified.expectation();
    assert_eq!(expectation.archive_id, archive_id());
    let GenerationExpectation::Exactly(pinned) = expectation.generation else {
        panic!("a verified restore pins the generation it established");
    };
    assert_eq!(pinned.backup_generation, BackupGeneration::new(4));
    assert_eq!(
        pinned.encrypted_manifest_hash,
        sealed.descriptor.encrypted_manifest.encrypted_object_hash
    );

    // And the archive layer refuses another generation against it.
    let other = producer.seal(6, &objects);
    assert!(
        kr_crypto::backup::open_archive(
            &kr_crypto::backup::ArchiveReader::Device(&producer.device),
            producer.sender.public(),
            &[TrustedWriter {
                writer_key_id: producer.writer.key_id(),
                signing_key: *producer.writer.public(),
                enrolled_at_ms: TimestampMs::new(1_000),
            }],
            &expectation,
            &other.descriptor_bytes,
            &other.encrypted_manifest,
        )
        .is_err(),
        "the archive opened is the archive whose authority was established"
    );
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
        matches!(
            RestoreRequest {
                archive_id: archive_id(),
                publication: &publication,
                descriptor_len: sealed.descriptor_bytes.len(),
                enrolment: &enrolment,
                owner_key: impostor.owner.public(),
                writer_key: producer.writer.public(),
                generation: GenerationExpectation::Unverified,
            }
            .verify(),
            Err(kr_controller::error::ControllerError::PermissionDenied { .. })
        ),
        "the enrolment is verified against the owner's own key"
    );

    // A writer key that is not the one the owner enrolled.
    assert!(
        matches!(
            RestoreRequest {
                archive_id: archive_id(),
                publication: &publication,
                descriptor_len: sealed.descriptor_bytes.len(),
                enrolment: &enrolment,
                owner_key: producer.owner.public(),
                writer_key: impostor.writer.public(),
                generation: GenerationExpectation::Unverified,
            }
            .verify(),
            Err(kr_controller::error::ControllerError::PermissionDenied { .. })
        ),
        "a writer the bundle supplied is checked against the owner's enrolment"
    );

    // A publication whose signature is another writer's.
    let forged = BackupGenerationPublication {
        payload: publication.payload.clone(),
        signature: impostor.publish(&sealed).signature,
    };
    assert!(
        matches!(
            RestoreRequest {
                archive_id: archive_id(),
                publication: &forged,
                descriptor_len: sealed.descriptor_bytes.len(),
                enrolment: &enrolment,
                owner_key: producer.owner.public(),
                writer_key: producer.writer.public(),
                generation: GenerationExpectation::Unverified,
            }
            .verify(),
            Err(kr_controller::error::ControllerError::PermissionDenied { .. })
        ),
        "the publication's own signature is verified under the enrolled writer"
    );

    // A publication for another archive than the one being restored.
    assert!(
        matches!(
            RestoreRequest {
                archive_id: ArchiveId::new(Uuid::from_bytes([0x99; 16])),
                publication: &publication,
                descriptor_len: sealed.descriptor_bytes.len(),
                enrolment: &enrolment,
                owner_key: producer.owner.public(),
                writer_key: producer.writer.public(),
                generation: GenerationExpectation::Unverified,
            }
            .verify(),
            Err(kr_controller::error::ControllerError::PermissionDenied { .. })
        ),
        "the caller's own expectation is checked before any signature"
    );

    // A generation the checkpoint says is older than what the owner verified.
    let checkpoint = ArchiveCheckpoint {
        archive_id: archive_id(),
        backup_generation: BackupGeneration::new(9),
        encrypted_manifest_hash: Digest256::from_bytes([0xab; 32]),
        verified_at_ms: TimestampMs::new(3_000),
    };
    let refusal = RestoreRequest {
        archive_id: archive_id(),
        publication: &publication,
        descriptor_len: sealed.descriptor_bytes.len(),
        enrolment: &enrolment,
        owner_key: producer.owner.public(),
        writer_key: producer.writer.public(),
        generation: GenerationExpectation::Checkpoint(CheckpointSource::Pairing, &checkpoint),
    }
    .verify()
    .expect_err("a replayed older archive");
    assert!(refusal.to_string().contains("generation 4"));

    // A descriptor over section 20's byte limit fails before anything else.
    assert!(matches!(
        RestoreRequest {
            archive_id: archive_id(),
            publication: &publication,
            descriptor_len: kr_protocol::archive::MAX_ARCHIVE_DESCRIPTOR_LEN + 1,
            enrolment: &enrolment,
            owner_key: producer.owner.public(),
            writer_key: producer.writer.public(),
            generation: GenerationExpectation::Unverified,
        }
        .verify(),
        Err(kr_controller::error::ControllerError::PermissionDenied { .. })
    ));
}

/// The table's answers, which are the decision a restore acts on rather than a gate over bytes.
///
/// `RestoreRequest::admit` classifies kinds a caller names. The archive layer below it carries
/// opaque objects, so what closes section 20 ¶11 is each import path asking for every kind it
/// carries; this establishes the answer it gets.
#[test]
fn a_restore_classifies_a_reusable_host_control_key_as_material_it_refuses() {
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
// The privacy hook, under the privacy generation contract.
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
            TimestampMs::new(5_000),
        )
        .expect("the generation is admitted");
    let published = producer.seal(2, &objects);
    let second = environment
        .service()
        .admit(
            &published,
            &objects,
            producer.writer.key_id(),
            TimestampMs::new(5_100),
        )
        .expect("the generation is admitted");
    // The second generation goes the whole way: its upload leaves, every object arrives, its
    // executor reports the transfer finished, and the descriptor it enqueues leaves and is
    // accepted.
    environment
        .service()
        .note_dispatched(second.sequence, EXECUTOR, TimestampMs::new(5_110))
        .expect("its upload is in flight");
    let publication = dispatch_publication(
        environment.service(),
        second.sequence,
        BackupGeneration::new(2),
        TimestampMs::new(5_180),
    );
    assert_eq!(
        environment
            .service()
            .note_published(
                publication,
                PrivacyGeneration::INITIAL,
                TimestampMs::new(5_200)
            )
            .expect("the second generation is published"),
        Publication::Recorded
    );

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
    assert_eq!(kept.remote, Remote::Published);
    for row in environment
        .service()
        .objects(archive_id(), BackupGeneration::new(2))
        .expect("a read")
    {
        assert_eq!(row.local_state, LocalState::Absent);
        assert!(!row.staged_path.exists());
    }

    // What had already left is shown rather than erased, with a deletion of its own.
    assert_eq!(enabling.exported.len(), 1);
    let exported = &enabling.exported[0];
    assert_eq!(exported.kind, "backup archive");
    assert!(exported.reference.contains("generation 2"));
    assert!(
        !exported.deletable,
        "this host holds no route to ask for the removal, and does not claim one"
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
    assert!(
        environment
            .service()
            .obligations()
            .expect("a read")
            .is_empty()
    );
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
            TimestampMs::new(5_000),
        )
        .expect("the generation is admitted");
    environment
        .service()
        .note_dispatched(admitted.sequence, EXECUTOR, TimestampMs::new(6_500))
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
        .note_attempt_stopped(admitted.sequence, TimestampMs::new(7_000))
        .expect("the outcome is recorded");
    let subsystems: Vec<&dyn PrivacySubsystem> = vec![&environment.service];
    assert!(PrivacyMode::reconcile(&subsystems).is_complete());
}

#[test]
fn a_result_is_published_only_under_the_generation_this_host_admitted_the_work_under() {
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
            TimestampMs::new(5_000),
        )
        .expect("the generation is admitted");
    environment
        .service()
        .note_dispatched(admitted.sequence, EXECUTOR, TimestampMs::new(5_100))
        .expect("the upload is in flight");
    let publication = dispatch_publication(
        environment.service(),
        admitted.sequence,
        BackupGeneration::new(1),
        TimestampMs::new(5_200),
    );

    // Privacy mode is enabled. The boundary is the store's own: raising the fence is what moves
    // the generation in force, so nothing a caller says can put the line somewhere else.
    environment.service.fence(PrivacyGeneration::new(1));

    // The answer to work admitted before privacy mode was enabled comes back afterwards. It is an
    // answer, so it is recorded as one: the service holds that archive. It is not a publication of
    // this host's, because this host was stopped before it could make one.
    assert_eq!(
        environment
            .service()
            .note_published(
                publication,
                PrivacyGeneration::INITIAL,
                TimestampMs::new(7_000),
            )
            .expect("a late old-generation answer is recorded"),
        Publication::RetainedArtifact {
            privacy_generation: 0
        }
    );

    // And relabelling it does not help: the generation the work was admitted under is the store's,
    // not the caller's, so a caller that could name it could not name its way past the boundary.
    let relabelled = environment
        .service()
        .note_published(
            publication,
            PrivacyGeneration::new(1),
            TimestampMs::new(7_000),
        )
        .expect_err("a result relabelled with the generation in force");
    assert!(
        relabelled
            .to_string()
            .contains("this host admitted the work under 0")
    );
    let record = environment
        .service()
        .generation(archive_id(), BackupGeneration::new(1))
        .expect("a read")
        .expect("the generation");
    assert_eq!(
        record.remote,
        Remote::Published,
        "the service holds it, and that is written down"
    );
    assert_ne!(
        record.production,
        Production::Complete,
        "no production of this host's completed after privacy mode stopped it"
    );

    // Work admitted under the generation in force publishes. Privacy mode is off again here,
    // because a host in privacy mode admits no content-bearing backup work at all, and the fence
    // comes down only once the cleanup it wrote down is finished.
    environment
        .service
        .cancel_undispatched(PrivacyGeneration::new(1));
    environment
        .service
        .remove_retained(PrivacyGeneration::new(1));
    assert_eq!(
        environment
            .service()
            .release_fence(
                PrivacyGeneration::new(1),
                PrivacyGeneration::new(2),
                TimestampMs::new(8_000),
            )
            .expect("a release"),
        FenceRelease::Released
    );
    // With the fence down, the work it cancelled still cannot publish. Its ciphertext went, its
    // production is over for good, and what the service holds of it stays a retained artifact
    // however often the answer is repeated.
    assert_eq!(
        environment
            .service()
            .note_published(
                publication,
                PrivacyGeneration::INITIAL,
                TimestampMs::new(8_500),
            )
            .expect("a repeated answer about the old archive"),
        Publication::RetainedArtifact {
            privacy_generation: 0
        }
    );
    let old = environment
        .service()
        .generation(archive_id(), BackupGeneration::new(1))
        .expect("a read")
        .expect("the record a service's copy is accounted for by");
    assert_eq!(old.production, Production::Cancelled);
    assert_eq!(old.remote, Remote::Published);

    let second = producer.seal(2, &objects);
    let resumed = environment
        .service()
        .admit(
            &second,
            &objects,
            producer.writer.key_id(),
            TimestampMs::new(9_000),
        )
        .expect("the generation is admitted");
    environment
        .service()
        .note_dispatched(resumed.sequence, EXECUTOR, TimestampMs::new(9_100))
        .expect("the upload is in flight");
    let second_publication = dispatch_publication(
        environment.service(),
        resumed.sequence,
        BackupGeneration::new(2),
        TimestampMs::new(9_500),
    );
    environment
        .service()
        .note_published(
            second_publication,
            PrivacyGeneration::new(2),
            TimestampMs::new(10_000),
        )
        .expect("a result from the generation in force");
    let record = environment
        .service()
        .generation(archive_id(), BackupGeneration::new(2))
        .expect("a read")
        .expect("the generation");
    assert_eq!(record.production, Production::Complete);
    assert_eq!(record.remote, Remote::Published);
}

#[test]
fn a_publication_answered_after_the_line_is_an_artifact_and_never_a_new_one() {
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
            TimestampMs::new(5_000),
        )
        .expect("the generation is admitted");
    // The upload leaves, every object arrives, the executor says that transfer finished, and the
    // descriptor it enqueues leaves too.
    environment
        .service()
        .note_dispatched(admitted.sequence, EXECUTOR, TimestampMs::new(5_100))
        .expect("the upload is in flight");
    let publication = dispatch_publication(
        environment.service(),
        admitted.sequence,
        BackupGeneration::new(1),
        TimestampMs::new(5_300),
    );

    // The request is accepted and the fence does not go up. The host is stopped all the same, so
    // an answer arriving now is an artifact this host accounts for rather than a publication it
    // made.
    environment
        .service()
        .accept_privacy_request(PrivacyGeneration::new(1), TimestampMs::new(6_000))
        .expect("the request is accepted");
    assert_eq!(
        environment
            .service()
            .note_published(
                publication,
                PrivacyGeneration::INITIAL,
                TimestampMs::new(7_000)
            )
            .expect("an answer while this host is stopped"),
        Publication::RetainedArtifact {
            privacy_generation: 0
        }
    );
    let record = environment
        .service()
        .generation(archive_id(), BackupGeneration::new(1))
        .expect("a read")
        .expect("the generation");
    assert_ne!(record.production, Production::Complete);
    assert_eq!(record.remote, Remote::Published);

    // And the publication attempt that carried it is over, so nothing is left waiting for an
    // answer it has already had.
    assert!(
        environment.service().outbox().expect("a read").is_empty(),
        "the answer ended the attempt that carried it"
    );
    let attempts = environment.service().attempts().expect("a read");
    assert_eq!(attempts.len(), 2, "the upload and the publication");
    for attempt in &attempts {
        assert_eq!(attempt.status, AttemptStatus::Terminal);
        assert_eq!(attempt.outcome, Some(AttemptOutcome::Accepted));
    }
}

#[test]
fn a_fence_is_recorded_durably_and_a_restart_comes_back_fenced() {
    let root = tempfile::tempdir().expect("a disposable directory on the internal disk");
    let state = root.path().join("state");
    std::fs::create_dir_all(&state).expect("the state directory");
    {
        let mut service = BackupService::open(&state).expect("a backup service");
        service
            .reconcile(TimestampMs::new(4_000))
            .expect("the startup reconciliation a service opens unready without");
        assert_eq!(service.fenced_at().expect("a read"), None);
        let fenced = service.fence(PrivacyGeneration::new(4));
        assert_eq!(fenced.queues, 1);
        // The fence writes its own scope down. There is nothing staged here, so the only thing it
        // owes is the walk of the staging directory, which is how ciphertext no row names is found.
        let owed = service.obligations().expect("a read");
        assert_eq!(owed.len(), 1);
        assert_eq!(owed[0].kind, ObligationKind::ScanStaging);
        assert_eq!(service.fenced_at().expect("a read"), Some(4));
    }
    // A host that held the fence in memory would come back and dispatch what it had just stopped.
    let reopened = BackupService::open(&state).expect("the service opens again");
    reopened
        .reconcile(TimestampMs::new(4_000))
        .expect("the startup reconciliation a service opens unready without");
    assert_eq!(reopened.fenced_at().expect("a read"), Some(4));
    assert_eq!(reopened.obligations().expect("a read").len(), 1);
}

#[test]
fn a_store_that_will_not_take_the_request_reports_work_outstanding_rather_than_completion() {
    let root = tempfile::tempdir().expect("a disposable directory on the internal disk");
    let state = root.path().join("state");
    std::fs::create_dir_all(&state).expect("the state directory");
    let mut service = BackupService::open(&state).expect("a backup service");
    service
        .reconcile(TimestampMs::new(4_000))
        .expect("the startup reconciliation a service opens unready without");

    // Put SQLite into query-only mode so writes fail while reads still work.
    service.set_query_only(true).expect("query_only pragma");

    // The request cannot be accepted, so there is no request and no obligation: no design can
    // persist a request in the database that would not take it.
    let error = service
        .raise_fence(PrivacyGeneration::new(1), TimestampMs::new(6_000))
        .expect_err("a store that will not write says so");
    assert!(
        matches!(
            error,
            kr_controller::error::ControllerError::RegistryUnavailable { .. }
        ),
        "the reason is the answer: {error}"
    );
    let fenced = service.fence(PrivacyGeneration::new(1));
    assert_eq!(fenced.queues, 0);
    assert!(service.privacy_request(1).expect("a read").is_none());
    assert!(service.obligations().expect("a read").is_empty());

    // And the subsystem still reports work outstanding. A host that cannot say what it owes does
    // not owe nothing, and privacy mode must never read the first as the second.
    assert!(service.outstanding() > 0);
    let work = service.outstanding_work().expect("reads still work");
    assert!(!work.is_complete());
    assert_eq!(
        work.failed_steps,
        vec!["raise the backup privacy fence for privacy generation 1"]
    );

    // Production is stopped by that guard, and the gates are where it is enforced. The store holds
    // no row for this: the request it would not take left nothing behind.
    service.set_query_only(false).expect("query_only pragma");
    assert!(service.privacy_request(1).expect("a read").is_none());
    assert!(service.fenced_at().expect("a read").is_none());
    let producer = Producer::generate();
    service
        .enrol_writer(producer.writer.key_id(), archive_id(), TimestampMs::new(1))
        .expect("the writer is enrolled");
    let objects = [stage(1, "a.cbor", b"one")];
    let refusal = service
        .admit(
            &producer.seal(1, &objects),
            &objects,
            producer.writer.key_id(),
            TimestampMs::new(6_500),
        )
        .expect_err("nothing is admitted by a host that failed to stop");
    assert!(
        refusal
            .to_string()
            .contains("could not raise the backup privacy fence for privacy generation 1"),
        "{refusal}"
    );
    assert!(
        service
            .note_dispatched(1, EXECUTOR, TimestampMs::new(6_500))
            .is_err(),
        "and nothing is dispatched either"
    );

    // That step, for its own request, is what ends it.
    let fenced = service.fence(PrivacyGeneration::new(1));
    assert_eq!(fenced.queues, 1, "the backup outbox is fenced");
    assert_eq!(fenced.items, 0, "nothing was admitted to cancel");
    assert!(
        service
            .outstanding_work()
            .expect("a read")
            .failed_steps
            .is_empty()
    );
    assert!(service.unready().is_none());
    assert_eq!(service.fenced_at().expect("a read"), Some(1));

    // A newer request now fails to be accepted, and this host is stopped again.
    service.set_query_only(true).expect("query_only pragma");
    service
        .raise_fence(PrivacyGeneration::new(3), TimestampMs::new(7_000))
        .expect_err("a store that will not write says so");
    service.set_query_only(false).expect("query_only pragma");
    assert_eq!(
        service.outstanding_work().expect("a read").failed_steps,
        vec!["raise the backup privacy fence for privacy generation 3"]
    );

    // Repeating the older request, which this host already applied, succeeds and establishes
    // nothing whatever about the newer one that failed. The guard holds, and so does the gate.
    service
        .raise_fence(PrivacyGeneration::new(1), TimestampMs::new(7_500))
        .expect("a repeat of an applied request reads its record back");
    assert_eq!(
        service.outstanding_work().expect("a read").failed_steps,
        vec!["raise the backup privacy fence for privacy generation 3"],
        "an older success does not establish that the newer failure recovered"
    );
    assert!(service.unready().is_some());

    // Its own retry does.
    service
        .raise_fence(PrivacyGeneration::new(3), TimestampMs::new(8_000))
        .expect("the request that failed is accepted at last");
    assert!(
        service
            .outstanding_work()
            .expect("a read")
            .failed_steps
            .is_empty()
    );
    assert!(service.unready().is_none());
}

#[test]
fn a_service_admits_and_dispatches_nothing_until_it_has_reconciled() {
    let root = tempfile::tempdir().expect("a disposable directory on the internal disk");
    let state = root.path().join("state");
    std::fs::create_dir_all(&state).expect("the state directory");
    let producer = Producer::generate();
    let objects = [stage(1, "a.cbor", b"one")];
    let service = BackupService::open(&state).expect("a backup service");
    service
        .enrol_writer(producer.writer.key_id(), archive_id(), TimestampMs::new(1))
        .expect("the writer is enrolled");

    // What an earlier process left unfinished is not established until reconciliation has read it
    // back, so nothing is admitted into a store nothing has read.
    let refusal = service
        .admit(
            &producer.seal(1, &objects),
            &objects,
            producer.writer.key_id(),
            TimestampMs::new(5_000),
        )
        .expect_err("a store nothing has reconciled admits nothing");
    assert!(
        refusal.to_string().contains("has not reconciled"),
        "{refusal}"
    );
    assert!(service.unready().is_some());

    service
        .reconcile(TimestampMs::new(4_000))
        .expect("startup reconciliation");
    assert!(service.unready().is_none());
    let admitted = service
        .admit(
            &producer.seal(1, &objects),
            &objects,
            producer.writer.key_id(),
            TimestampMs::new(5_000),
        )
        .expect("production is admitted once the store has been read back");
    service
        .note_dispatched(admitted.sequence, EXECUTOR, TimestampMs::new(6_500))
        .expect("and dispatched");
}

#[test]
fn an_activation_that_fails_leaves_the_request_and_its_obligation_behind() {
    let root = tempfile::tempdir().expect("a disposable directory on the internal disk");
    let state = root.path().join("state");
    std::fs::create_dir_all(&state).expect("the state directory");
    {
        let mut service = BackupService::open(&state).expect("a backup service");
        service
            .reconcile(TimestampMs::new(4_000))
            .expect("the startup reconciliation a service opens unready without");
        service
            .accept_privacy_request(PrivacyGeneration::new(4), TimestampMs::new(6_000))
            .expect("the request is accepted");
        // Everything after the request fails. The request stands, because it was committed on its
        // own before anything was attempted over it.
        service.set_query_only(true).expect("query_only pragma");
        let fenced = service.fence(PrivacyGeneration::new(4));
        assert_eq!(fenced.queues, 0, "no fence is reported that did not go up");
        assert!(service.outstanding() > 0);
    }

    // A restart reads the request and its obligation back. Neither an empty list nor another
    // step's success can stand in for the activation this host never performed.
    let reopened = BackupService::open(&state).expect("the service opens again");
    reopened
        .reconcile(TimestampMs::new(4_000))
        .expect("the startup reconciliation a service opens unready without");
    let request = reopened
        .privacy_request(4)
        .expect("a read")
        .expect("the accepted request");
    assert!(!request.is_applied());
    let owed = reopened.obligations().expect("a read");
    assert_eq!(owed.len(), 1);
    assert_eq!(owed[0].kind, ObligationKind::ActivateFence);
    assert_eq!(owed[0].target_key, "request:4");
    assert!(reopened.outstanding() > 0);
    assert_eq!(
        reopened.fenced_at().expect("a read"),
        Some(4),
        "a request whose fence never went up still stops production"
    );

    // Its own retry is what ends it.
    let mut reopened = reopened;
    let fenced = reopened.fence(PrivacyGeneration::new(4));
    assert_eq!(fenced.queues, 1);
    let owed = reopened.obligations().expect("a read");
    assert!(
        owed.iter()
            .all(|obligation| obligation.kind != ObligationKind::ActivateFence),
        "the activation is done, and what is left is the scope it wrote: {owed:?}"
    );
    assert!(
        reopened
            .privacy_request(4)
            .expect("a read")
            .expect("the request")
            .is_applied()
    );
}

#[test]
fn a_fence_is_released_only_when_nothing_is_owed_under_it_and_never_by_hand() {
    let root = tempfile::tempdir().expect("a disposable directory on the internal disk");
    let state = root.path().join("state");
    std::fs::create_dir_all(&state).expect("the state directory");
    let mut service = BackupService::open(&state).expect("a backup service");
    service
        .reconcile(TimestampMs::new(4_000))
        .expect("the startup reconciliation a service opens unready without");
    service
        .accept_privacy_request(PrivacyGeneration::new(2), TimestampMs::new(6_000))
        .expect("the request is accepted");

    // The activation obligation is outstanding, so the fence stands.
    assert_eq!(
        service
            .release_fence(
                PrivacyGeneration::new(2),
                PrivacyGeneration::new(3),
                TimestampMs::new(7_000),
            )
            .expect("the release is attempted"),
        FenceRelease::NotHeld,
        "there is no raised fence yet, only the obligation to raise one"
    );
    let fenced = service.fence(PrivacyGeneration::new(2));
    assert_eq!(fenced.queues, 1);

    // A release under a generation that is not newer is refused outright.
    assert!(
        service
            .release_fence(
                PrivacyGeneration::new(2),
                PrivacyGeneration::new(2),
                TimestampMs::new(7_000),
            )
            .is_err(),
        "production never resumes under the generation the fence stopped it at"
    );

    // The fence wrote down a walk of the staging directory, and that is outstanding, so the fence
    // stands. Backup production does not resume into a scope this host has not finished clearing.
    assert_eq!(
        service
            .release_fence(
                PrivacyGeneration::new(2),
                PrivacyGeneration::new(3),
                TimestampMs::new(7_000),
            )
            .expect("the release is attempted"),
        FenceRelease::Pending { obligations: 1 }
    );
    assert_eq!(service.fenced_at().expect("a read"), Some(2));

    // Direct SQL cannot get round it either: the trigger refuses the release and the deletion.
    service
        .run_cleanup(PrivacyGeneration::new(1), TimestampMs::new(7_000))
        .expect("cleanup");

    // With nothing outstanding the release goes through, once.
    assert_eq!(
        service
            .release_fence(
                PrivacyGeneration::new(2),
                PrivacyGeneration::new(3),
                TimestampMs::new(7_000),
            )
            .expect("a release"),
        FenceRelease::Released
    );
    assert_eq!(
        service
            .release_fence(
                PrivacyGeneration::new(2),
                PrivacyGeneration::new(4),
                TimestampMs::new(7_500),
            )
            .expect("a second release"),
        FenceRelease::NotHeld,
        "a released fence is not released again"
    );
    let status = service.privacy_status().expect("a read");
    assert_eq!(status.current_generation, 3);
    assert!(!status.enabled);
    assert_eq!(service.fenced_at().expect("a read"), None);
}

#[test]
fn a_late_upload_acknowledgement_while_fenced_does_not_enqueue_publication() {
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
            TimestampMs::new(5_000),
        )
        .expect("the generation is admitted");

    // The upload outbox entry is dispatched to the service.
    environment
        .service()
        .note_dispatched(admitted.sequence, EXECUTOR, TimestampMs::new(6_500))
        .expect("dispatched");

    // Privacy mode is enabled: fence is recorded.
    let fenced = environment.service.fence(PrivacyGeneration::new(1));
    assert_eq!(fenced.queues, 1);
    let cancelled = environment
        .service
        .cancel_undispatched(PrivacyGeneration::new(1));
    assert_eq!(cancelled.in_flight, 1);

    // Now the in-flight uploads complete while fenced.
    let manifest_id = sealed.descriptor.encrypted_manifest.object_id;
    environment
        .service()
        .note_object_uploaded(
            admitted.sequence,
            archive_id(),
            BackupGeneration::new(1),
            objects[0].object_id(),
            TimestampMs::new(6_000),
        )
        .expect("upload noted");
    let complete = environment
        .service()
        .note_object_uploaded(
            admitted.sequence,
            archive_id(),
            BackupGeneration::new(1),
            manifest_id,
            TimestampMs::new(6_001),
        )
        .expect("manifest upload noted");
    assert!(complete);

    // It was the last object, but because the host was fenced, NO publish entry was enqueued into
    // outbox! The upload attempt that had already left keeps its place: acknowledgements say a
    // service holds the ciphertext and say nothing about whether that transfer ended.
    let outbox = environment.service().outbox().expect("outbox");
    assert!(
        outbox.iter().all(|attempt| attempt.step == Step::Upload),
        "no publish step may be enqueued while fenced: {outbox:?}"
    );
    assert_eq!(outbox.len(), 1);
    assert_eq!(outbox[0].status, AttemptStatus::Dispatched);

    // The generation was settled as Cancelled rather than Uploading/Published.
    let record = environment
        .service()
        .generation(archive_id(), BackupGeneration::new(1))
        .expect("read")
        .expect("record");
    assert_eq!(record.production, Production::Cancelled);

    // When the fence is released later, nothing becomes dispatchable.
    environment
        .service()
        .release_fence(
            PrivacyGeneration::new(1),
            PrivacyGeneration::new(2),
            TimestampMs::new(7_000),
        )
        .expect("a release");
    let outbox_after = environment
        .service()
        .outbox()
        .expect("outbox after release");
    assert!(
        outbox_after
            .iter()
            .all(|attempt| attempt.status == AttemptStatus::Dispatched),
        "nothing the fence stopped becomes dispatchable again: {outbox_after:?}"
    );
}

#[test]
fn an_upload_finishing_after_privacy_mode_stops_does_not_enqueue_publication_and_completes_reconciliation()
 {
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
            TimestampMs::new(5_000),
        )
        .expect("the generation is admitted");

    // The upload outbox entry is dispatched to the service.
    environment
        .service()
        .note_dispatched(admitted.sequence, EXECUTOR, TimestampMs::new(6_500))
        .expect("dispatched");

    // Privacy mode is enabled: fence is recorded and undispatched work cancelled.
    let _fenced = environment.service.fence(PrivacyGeneration::new(1));
    let cancelled = environment
        .service
        .cancel_undispatched(PrivacyGeneration::new(1));
    assert_eq!(cancelled.in_flight, 1);

    // Privacy mode is reconciling because work is in flight.
    {
        let subsystems: Vec<&dyn PrivacySubsystem> = vec![&environment.service];
        assert!(!PrivacyMode::reconcile(&subsystems).is_complete());
    }

    // Privacy mode is turned off before the in-flight upload completes, and the fence does not
    // come down: backup production does not resume into a scope this host has not finished
    // clearing, and the upload that left is still unanswered.
    environment
        .service
        .remove_retained(PrivacyGeneration::new(1));
    assert!(matches!(
        environment
            .service()
            .release_fence(
                PrivacyGeneration::new(1),
                PrivacyGeneration::new(2),
                TimestampMs::new(7_000),
            )
            .expect("the release is attempted"),
        FenceRelease::Pending { .. }
    ));
    assert_eq!(environment.service().fenced_at().expect("read"), Some(1));

    // The in-flight upload completes now, after privacy mode has stopped.
    let manifest_id = sealed.descriptor.encrypted_manifest.object_id;
    environment
        .service()
        .note_object_uploaded(
            admitted.sequence,
            archive_id(),
            BackupGeneration::new(1),
            objects[0].object_id(),
            TimestampMs::new(6_000),
        )
        .expect("upload noted");
    let complete = environment
        .service()
        .note_object_uploaded(
            admitted.sequence,
            archive_id(),
            BackupGeneration::new(1),
            manifest_id,
            TimestampMs::new(6_001),
        )
        .expect("manifest upload noted");
    assert!(complete);

    // No publish step is enqueued: the generation was cancelled when privacy mode was enabled.
    let outbox = environment.service().outbox().expect("outbox");
    assert!(
        outbox.iter().all(|attempt| attempt.step == Step::Upload),
        "no publish step may be enqueued for a generation cancelled by privacy mode: {outbox:?}"
    );

    // Every object of the generation is at a service, and that is *not* the end of the transfer
    // that carried them. The attempt keeps its place and its obligation, so cleanup is not
    // complete and the fence stays up.
    assert!(
        environment
            .service()
            .obligations()
            .expect("a read")
            .iter()
            .any(|obligation| obligation.kind == ObligationKind::ResolveUpload),
        "the attempt that left is still owed an answer"
    );
    {
        let subsystems: Vec<&dyn PrivacySubsystem> = vec![&environment.service];
        assert!(!PrivacyMode::reconcile(&subsystems).is_complete());
    }

    // The executor holding it says the transfer finished. That is evidence about that exact
    // attempt, so it ends with the obligation that named it. The staged ciphertext went before,
    // and nothing else is owed, so cleanup is complete and the fence can come down.
    environment
        .service()
        .note_attempt_accepted(admitted.sequence, TimestampMs::new(6_002))
        .expect("the executor reports its upload finished");
    assert!(
        environment
            .service()
            .obligations()
            .expect("a read")
            .is_empty()
    );
    {
        let subsystems: Vec<&dyn PrivacySubsystem> = vec![&environment.service];
        assert!(PrivacyMode::reconcile(&subsystems).is_complete());
    }
    assert_eq!(
        environment
            .service()
            .release_fence(
                PrivacyGeneration::new(1),
                PrivacyGeneration::new(2),
                TimestampMs::new(8_000),
            )
            .expect("a release"),
        FenceRelease::Released
    );

    // No ciphertext of it is left on this host. Its record is, and has to be: the service
    // acknowledged every object before the fence came down, so those bytes are somewhere else.
    // Deleting the record with the production it belonged to would leave this host unable to say
    // that anything of this generation had ever been uploaded.
    let record = environment
        .service()
        .generation(archive_id(), BackupGeneration::new(1))
        .expect("read")
        .expect("the record that accounts for the copy the service holds");
    assert_eq!(record.production, Production::Cancelled);
    assert_eq!(record.remote, Remote::Objects);
    for row in environment
        .service()
        .objects(archive_id(), BackupGeneration::new(1))
        .expect("a read")
    {
        assert_eq!(row.local_state, LocalState::Absent);
        assert!(
            row.is_acknowledged(),
            "the acknowledgement survives the cleanup that removed the file"
        );
        assert!(!row.staged_path.exists());
    }
    assert!(
        environment
            .service()
            .exported()
            .iter()
            .any(|artifact| artifact.kind == "backup object ciphertext"),
        "privacy mode shows what the service holds rather than deleting the evidence of it"
    );
}

#[test]
fn a_publication_that_left_before_the_cancellation_survives_a_repeated_upload_acknowledgement() {
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
            TimestampMs::new(5_000),
        )
        .expect("the generation is admitted");
    environment
        .service()
        .note_dispatched(admitted.sequence, EXECUTOR, TimestampMs::new(6_500))
        .expect("the upload is in flight");

    // Both objects arrive, so the publication is enqueued, and it leaves this host.
    let manifest_id = sealed.descriptor.encrypted_manifest.object_id;
    environment
        .service()
        .note_object_uploaded(
            admitted.sequence,
            archive_id(),
            BackupGeneration::new(1),
            objects[0].object_id(),
            TimestampMs::new(6_000),
        )
        .expect("the member is acknowledged");
    assert!(
        environment
            .service()
            .note_object_uploaded(
                admitted.sequence,
                archive_id(),
                BackupGeneration::new(1),
                manifest_id,
                TimestampMs::new(6_001),
            )
            .expect("the manifest is acknowledged")
    );
    environment
        .service()
        .note_attempt_accepted(admitted.sequence, TimestampMs::new(6_002))
        .expect("the executor reports its upload finished");
    let publication = environment.service().outbox().expect("a read");
    assert_eq!(publication.len(), 1);
    assert_eq!(publication[0].step, Step::Publish);
    environment
        .service()
        .note_dispatched(publication[0].sequence, EXECUTOR, TimestampMs::new(6_500))
        .expect("the publication is in flight");

    // Privacy mode draws its line while the publication is out there.
    let _fenced = environment.service.fence(PrivacyGeneration::new(1));
    let cancelled = environment
        .service
        .cancel_undispatched(PrivacyGeneration::new(1));
    assert_eq!(cancelled.in_flight, 1, "the publication had already left");

    // The service acknowledges an object a second time. That says nothing about the publication,
    // and the entry this host is still owed an answer for stays where it is.
    assert!(
        environment
            .service()
            .note_object_uploaded(
                admitted.sequence,
                archive_id(),
                BackupGeneration::new(1),
                objects[0].object_id(),
                TimestampMs::new(7_000),
            )
            .expect("the repeated acknowledgement is recorded")
    );
    let outbox = environment.service().outbox().expect("a read");
    assert_eq!(
        outbox.len(),
        1,
        "the dispatched publication is not deleted by an upload acknowledgement: {outbox:?}"
    );
    assert_eq!(outbox[0].step, Step::Publish);
    assert_eq!(outbox[0].status, AttemptStatus::Dispatched);

    // And cleanup is not reported complete over it.
    let subsystems: Vec<&dyn PrivacySubsystem> = vec![&environment.service];
    assert!(
        !PrivacyMode::reconcile(&subsystems).is_complete(),
        "a publication whose answer is still owed keeps cleanup open"
    );
}

#[test]
fn a_restart_does_not_end_the_wait_over_an_upload_that_left_this_host() {
    let root = tempfile::tempdir().expect("a disposable directory on the internal disk");
    let state = root.path().join("state");
    std::fs::create_dir_all(&state).expect("the state directory");
    let producer = Producer::generate();
    let objects = [stage(1, "a.cbor", b"one")];
    let sealed = producer.seal(1, &objects);
    {
        let mut service = BackupService::open(&state).expect("a backup service");
        service
            .reconcile(TimestampMs::new(4_000))
            .expect("the startup reconciliation a service opens unready without");
        service
            .enrol_writer(producer.writer.key_id(), archive_id(), TimestampMs::new(1))
            .expect("the writer is enrolled");
        let admitted = service
            .admit(
                &sealed,
                &objects,
                producer.writer.key_id(),
                TimestampMs::new(5_000),
            )
            .expect("the generation is admitted");
        service
            .note_dispatched(admitted.sequence, EXECUTOR, TimestampMs::new(6_500))
            .expect("the upload is in flight");
        let _fenced = service.fence(PrivacyGeneration::new(1));
        service.cancel_undispatched(PrivacyGeneration::new(1));
        service.remove_retained(PrivacyGeneration::new(1));

        // The fence cannot be released while the attempt that left this host is unanswered: the
        // obligation that names it is still there, and the guarded statement finds it.
        assert_eq!(
            service
                .release_fence(
                    PrivacyGeneration::new(1),
                    PrivacyGeneration::new(2),
                    TimestampMs::new(7_000),
                )
                .expect("the release is attempted"),
            FenceRelease::Pending { obligations: 2 },
            "the unanswered attempt, and the bookkeeping that waits on it"
        );
    }

    // A restart is not evidence about what the service did. The attempt stays, its obligation
    // stays, and cleanup is not complete. Only an answer, or the caller establishing that the
    // transfer stopped, ends it.
    let service = BackupService::open(&state).expect("the service opens again");
    let outcome = service
        .reconcile(TimestampMs::new(7_000))
        .expect("reconciliation");
    assert_eq!(
        outcome.unanswered,
        vec![(archive_id(), BackupGeneration::new(1))]
    );
    assert!(outcome.outcome_unknown.is_empty());
    assert!(outcome.resumed.is_empty());
    assert_eq!(service.outbox().expect("a read").len(), 1);
    let owed = service.obligations().expect("a read");
    assert_eq!(owed.len(), 2, "the unanswered attempt and its bookkeeping");
    assert!(
        owed.iter()
            .any(|obligation| obligation.kind == ObligationKind::ResolveUpload)
    );
    let record = service
        .generation(archive_id(), BackupGeneration::new(1))
        .expect("a read")
        .expect("the record");
    assert_eq!(record.production, Production::Cancelled);
    {
        let subsystems: Vec<&dyn PrivacySubsystem> = vec![&service];
        assert!(!PrivacyMode::reconcile(&subsystems).is_complete());
    }

    // The caller establishes that the transfer stopped without an answer. That is evidence about
    // this attempt, so the attempt and its obligation end together, and cleanup is complete.
    let unanswered = service.outbox().expect("a read");
    assert_eq!(unanswered.len(), 1);
    service
        .note_attempt_stopped(unanswered[0].sequence, TimestampMs::new(8_000))
        .expect("the outcome is recorded");
    assert!(service.outbox().expect("a read").is_empty());
    assert!(service.obligations().expect("a read").is_empty());
    let subsystems: Vec<&dyn PrivacySubsystem> = vec![&service];
    assert!(PrivacyMode::reconcile(&subsystems).is_complete());
}

#[test]
fn a_cancelled_generation_whose_publication_left_keeps_its_unanswered_attempt() {
    let root = tempfile::tempdir().expect("a disposable directory on the internal disk");
    let state = root.path().join("state");
    std::fs::create_dir_all(&state).expect("the state directory");
    let producer = Producer::generate();
    let objects = [stage(1, "a.cbor", b"one")];
    let sealed = producer.seal(1, &objects);
    {
        let mut service = BackupService::open(&state).expect("a backup service");
        service
            .reconcile(TimestampMs::new(4_000))
            .expect("the startup reconciliation a service opens unready without");
        service
            .enrol_writer(producer.writer.key_id(), archive_id(), TimestampMs::new(1))
            .expect("the writer is enrolled");
        let admitted = service
            .admit(
                &sealed,
                &objects,
                producer.writer.key_id(),
                TimestampMs::new(5_000),
            )
            .expect("the generation is admitted");
        service
            .note_dispatched(admitted.sequence, EXECUTOR, TimestampMs::new(6_500))
            .expect("the upload is in flight");
        dispatch_publication(
            &service,
            admitted.sequence,
            BackupGeneration::new(1),
            TimestampMs::new(6_500),
        );
        let _fenced = service.fence(PrivacyGeneration::new(1));
        service.cancel_undispatched(PrivacyGeneration::new(1));
    }

    // A publication left this host and was never answered. Whether the service holds it is not
    // something this host can say, and neither a cancellation nor a restart makes it say
    // otherwise.
    let service = BackupService::open(&state).expect("the service opens again");
    let outcome = service
        .reconcile(TimestampMs::new(7_000))
        .expect("reconciliation");
    assert!(outcome.outcome_unknown.is_empty());
    assert_eq!(
        outcome.unanswered,
        vec![(archive_id(), BackupGeneration::new(1))]
    );
    // The outcome is recorded as unknown and the attempt is still there. The two say different
    // things: what the service did is unknown, and this host has not established that the attempt
    // ended. A restart may say the first and never the second.
    assert_eq!(service.outbox().expect("a read").len(), 1);
    let owed = service.obligations().expect("a read");
    assert!(
        owed.iter()
            .any(|obligation| obligation.kind == ObligationKind::ResolvePublication),
        "the publication attempt keeps its own obligation: {owed:?}"
    );
    let record = service
        .generation(archive_id(), BackupGeneration::new(1))
        .expect("a read")
        .expect("the record");
    // Both facts, side by side: production is stopped, and the service acknowledged this
    // generation's ciphertext. Neither one is written over the other.
    assert_eq!(record.production, Production::Cancelled);
    assert_eq!(record.remote, Remote::Objects);
    assert!(
        service
            .exported()
            .iter()
            .any(|artifact| artifact.kind == "backup archive, outcome unknown"),
        "a copy this host cannot account for is shown rather than pretended away"
    );
}

#[test]
fn an_object_acknowledged_after_its_staged_copy_went_arrives_without_ending_its_transfer() {
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
            TimestampMs::new(5_000),
        )
        .expect("the generation is admitted");
    environment
        .service()
        .note_dispatched(admitted.sequence, EXECUTOR, TimestampMs::new(6_500))
        .expect("the upload is in flight");
    environment
        .service()
        .note_object_uploaded(
            admitted.sequence,
            archive_id(),
            BackupGeneration::new(1),
            objects[0].object_id(),
            TimestampMs::new(6_000),
        )
        .expect("the member arrives before privacy mode is enabled");

    // The whole privacy sequence, staged ciphertext and all.
    let mut mode = PrivacyMode::new();
    mode.open_generation(TimestampMs::new(6_500));
    let enabling = {
        let mut subsystems: Vec<&mut dyn PrivacySubsystem> = vec![&mut environment.service];
        mode.apply(&mut subsystems, TimestampMs::new(6_500))
    };
    assert_eq!(enabling.in_flight(), 1);
    for row in environment
        .service()
        .objects(archive_id(), BackupGeneration::new(1))
        .expect("a read")
    {
        assert!(!row.staged_path.exists(), "the ciphertext left this host");
    }

    // The last object of the transfer that was already out there reaches the service. Every object
    // has now arrived, and nothing is published in its place - but the transfer that carried them
    // has not been reported over, so cleanup is not complete either.
    let manifest_id = sealed.descriptor.encrypted_manifest.object_id;
    assert!(
        environment
            .service()
            .note_object_uploaded(
                admitted.sequence,
                archive_id(),
                BackupGeneration::new(1),
                manifest_id,
                TimestampMs::new(7_000),
            )
            .expect("the manifest is acknowledged")
    );
    let outbox = environment.service().outbox().expect("a read");
    assert!(
        outbox.iter().all(|attempt| attempt.step == Step::Upload),
        "nothing is published in place of a cancelled generation's upload: {outbox:?}"
    );
    {
        let subsystems: Vec<&dyn PrivacySubsystem> = vec![&environment.service];
        assert!(
            !PrivacyMode::reconcile(&subsystems).is_complete(),
            "a complete set of objects is not evidence that the transfer ended"
        );
    }

    // The executor says that transfer finished, and only then is every transfer over and the
    // cleanup with it.
    environment
        .service()
        .note_attempt_accepted(admitted.sequence, TimestampMs::new(7_100))
        .expect("the executor reports its upload finished");
    assert!(environment.service().outbox().expect("a read").is_empty());
    let subsystems: Vec<&dyn PrivacySubsystem> = vec![&environment.service];
    assert!(
        PrivacyMode::reconcile(&subsystems).is_complete(),
        "every transfer has ended, so the cleanup has too"
    );
}

#[test]
fn a_restart_over_an_unanswered_attempt_still_owes_the_ciphertext_this_host_holds() {
    let root = tempfile::tempdir().expect("a disposable directory on the internal disk");
    let state = root.path().join("state");
    std::fs::create_dir_all(&state).expect("the state directory");
    let producer = Producer::generate();
    let objects = [stage(1, "a.cbor", b"one")];
    let sealed = producer.seal(1, &objects);
    let staged_paths: Vec<std::path::PathBuf>;
    {
        let mut service = BackupService::open(&state).expect("a backup service");
        service
            .reconcile(TimestampMs::new(4_000))
            .expect("the startup reconciliation a service opens unready without");
        service
            .enrol_writer(producer.writer.key_id(), archive_id(), TimestampMs::new(1))
            .expect("the writer is enrolled");
        let admitted = service
            .admit(
                &sealed,
                &objects,
                producer.writer.key_id(),
                TimestampMs::new(5_000),
            )
            .expect("the generation is admitted");
        service
            .note_dispatched(admitted.sequence, EXECUTOR, TimestampMs::new(6_500))
            .expect("the upload is in flight");
        staged_paths = service
            .objects(archive_id(), BackupGeneration::new(1))
            .expect("a read")
            .into_iter()
            .map(|row| row.staged_path)
            .collect();

        // Privacy mode fences and cancels, and this host stops before it removes anything.
        let _fenced = service.fence(PrivacyGeneration::new(1));
        service.cancel_undispatched(PrivacyGeneration::new(1));
    }

    // The restart reads back what the fence wrote down: the staged ciphertext is still here, and
    // the removal obligations say so. The attempt that left this host is still unanswered too.
    let mut service = BackupService::open(&state).expect("the service opens again");
    let outcome = service
        .reconcile(TimestampMs::new(7_000))
        .expect("reconciliation");
    assert_eq!(
        outcome.unanswered,
        vec![(archive_id(), BackupGeneration::new(1))]
    );
    assert_eq!(service.outbox().expect("a read").len(), 1);
    for path in &staged_paths {
        assert!(path.exists(), "the ciphertext is still on this host");
    }
    assert!(!service.obligations().expect("a read").is_empty());
    {
        let subsystems: Vec<&dyn PrivacySubsystem> = vec![&service];
        assert!(
            !PrivacyMode::reconcile(&subsystems).is_complete(),
            "cleanup is not complete while this host still holds the ciphertext"
        );
    }

    // The removal it owed clears those obligations, and the attempt that left this host keeps its
    // own: removing the local copy says nothing about what the service did with the bytes.
    let removed = service.remove_retained(PrivacyGeneration::new(1));
    assert!(removed.bytes > 0);
    for path in &staged_paths {
        assert!(!path.exists(), "the ciphertext left this host");
    }
    {
        let owed = service.obligations().expect("a read");
        assert!(
            owed.iter()
                .any(|obligation| obligation.kind == ObligationKind::ResolveUpload),
            "removing the local copy is not evidence about the transfer: {owed:?}"
        );
        let subsystems: Vec<&dyn PrivacySubsystem> = vec![&service];
        assert!(!PrivacyMode::reconcile(&subsystems).is_complete());
    }

    // Evidence about that attempt is what ends it, and only then is the cleanup complete.
    let unanswered = service.outbox().expect("a read");
    assert_eq!(unanswered.len(), 1);
    service
        .note_attempt_stopped(unanswered[0].sequence, TimestampMs::new(8_000))
        .expect("the outcome is recorded");
    assert!(service.obligations().expect("a read").is_empty());
    let subsystems: Vec<&dyn PrivacySubsystem> = vec![&service];
    assert!(PrivacyMode::reconcile(&subsystems).is_complete());
}

#[test]
fn an_acknowledgement_repeated_after_publication_still_says_the_upload_had_finished() {
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
            TimestampMs::new(5_000),
        )
        .expect("the generation is admitted");
    environment
        .service()
        .note_dispatched(admitted.sequence, EXECUTOR, TimestampMs::new(6_500))
        .expect("the upload is in flight");
    let manifest_id = sealed.descriptor.encrypted_manifest.object_id;
    environment
        .service()
        .note_object_uploaded(
            admitted.sequence,
            archive_id(),
            BackupGeneration::new(1),
            objects[0].object_id(),
            TimestampMs::new(6_000),
        )
        .expect("the member is acknowledged");
    assert!(
        environment
            .service()
            .note_object_uploaded(
                admitted.sequence,
                archive_id(),
                BackupGeneration::new(1),
                manifest_id,
                TimestampMs::new(6_001),
            )
            .expect("the manifest is acknowledged")
    );

    environment
        .service()
        .note_attempt_accepted(admitted.sequence, TimestampMs::new(6_002))
        .expect("the executor reports its upload finished");
    let publication = environment
        .service()
        .outbox()
        .expect("a read")
        .into_iter()
        .find(|attempt| attempt.step == Step::Publish)
        .expect("a publication attempt");
    environment
        .service()
        .note_dispatched(publication.sequence, EXECUTOR, TimestampMs::new(6_500))
        .expect("the publication is in flight");
    environment
        .service()
        .note_published(
            publication.sequence,
            PrivacyGeneration::INITIAL,
            TimestampMs::new(6_500),
        )
        .expect("the service accepted it");

    // What the answer says is what the objects say, and every object had arrived. A settled
    // generation takes no more transitions, and nothing is enqueued in its place.
    assert!(
        environment
            .service()
            .note_object_uploaded(
                admitted.sequence,
                archive_id(),
                BackupGeneration::new(1),
                objects[0].object_id(),
                TimestampMs::new(7_000),
            )
            .expect("the repeated acknowledgement is recorded")
    );
    assert!(environment.service().outbox().expect("a read").is_empty());
    let record = environment
        .service()
        .generation(archive_id(), BackupGeneration::new(1))
        .expect("a read")
        .expect("the record");
    assert_eq!(record.remote, Remote::Published);
}

#[test]
fn a_restart_owes_the_ciphertext_of_cancelled_work_that_never_left_this_host() {
    let root = tempfile::tempdir().expect("a disposable directory on the internal disk");
    let state = root.path().join("state");
    std::fs::create_dir_all(&state).expect("the state directory");
    let producer = Producer::generate();
    let objects = [stage(1, "a.cbor", b"one")];
    let sealed = producer.seal(1, &objects);
    let staged_paths: Vec<std::path::PathBuf>;
    {
        let mut service = BackupService::open(&state).expect("a backup service");
        service
            .reconcile(TimestampMs::new(4_000))
            .expect("the startup reconciliation a service opens unready without");
        service
            .enrol_writer(producer.writer.key_id(), archive_id(), TimestampMs::new(1))
            .expect("the writer is enrolled");
        service
            .admit(
                &sealed,
                &objects,
                producer.writer.key_id(),
                TimestampMs::new(5_000),
            )
            .expect("the generation is admitted");
        staged_paths = service
            .objects(archive_id(), BackupGeneration::new(1))
            .expect("a read")
            .into_iter()
            .map(|row| row.staged_path)
            .collect();

        // Nothing was dispatched, so the cancellation empties the outbox outright. This host then
        // stops before it removes anything.
        let _fenced = service.fence(PrivacyGeneration::new(1));
        let cancelled = service.cancel_undispatched(PrivacyGeneration::new(1));
        assert_eq!(cancelled.in_flight, 0);
        assert!(service.outbox().expect("a read").is_empty());
    }

    // There is no outbox entry left to say the cleanup is unfinished, and the ciphertext is still
    // here. The restart says so itself rather than reporting a cleanup that did not happen.
    let service = BackupService::open(&state).expect("the service opens again");
    service
        .reconcile(TimestampMs::new(7_000))
        .expect("reconciliation");
    for path in &staged_paths {
        assert!(path.exists(), "the ciphertext is still on this host");
    }
    assert!(!service.obligations().expect("a read").is_empty());
    {
        let subsystems: Vec<&dyn PrivacySubsystem> = vec![&service];
        assert!(!PrivacyMode::reconcile(&subsystems).is_complete());
    }

    // A second restart before the removal still owes it: the obligation is durable, not something
    // the first reconciliation spent.
    drop(service);
    let mut service = BackupService::open(&state).expect("the service opens a third time");
    service
        .reconcile(TimestampMs::new(8_000))
        .expect("reconciliation");
    assert!(!service.obligations().expect("a read").is_empty());
    let removed = service.remove_retained(PrivacyGeneration::new(1));
    assert!(removed.bytes > 0);
    let subsystems: Vec<&dyn PrivacySubsystem> = vec![&service];
    assert!(PrivacyMode::reconcile(&subsystems).is_complete());
}

#[test]
fn a_late_acknowledgement_does_not_bring_back_a_cleanup_that_is_finished() {
    let root = tempfile::tempdir().expect("a disposable directory on the internal disk");
    let state = root.path().join("state");
    std::fs::create_dir_all(&state).expect("the state directory");
    let producer = Producer::generate();
    let objects = [stage(1, "a.cbor", b"one")];
    let sealed = producer.seal(1, &objects);
    {
        let mut service = BackupService::open(&state).expect("a backup service");
        service
            .reconcile(TimestampMs::new(4_000))
            .expect("the startup reconciliation a service opens unready without");
        service
            .enrol_writer(producer.writer.key_id(), archive_id(), TimestampMs::new(1))
            .expect("the writer is enrolled");
        let admitted = service
            .admit(
                &sealed,
                &objects,
                producer.writer.key_id(),
                TimestampMs::new(5_000),
            )
            .expect("the generation is admitted");
        service
            .note_dispatched(admitted.sequence, EXECUTOR, TimestampMs::new(6_500))
            .expect("the upload is in flight");
        service
            .note_object_uploaded(
                admitted.sequence,
                archive_id(),
                BackupGeneration::new(1),
                objects[0].object_id(),
                TimestampMs::new(6_000),
            )
            .expect("the member arrives first");

        // The whole privacy sequence, staged ciphertext and all.
        let mut mode = PrivacyMode::new();
        mode.open_generation(TimestampMs::new(6_500));
        {
            let mut subsystems: Vec<&mut dyn PrivacySubsystem> = vec![&mut service];
            mode.apply(&mut subsystems, TimestampMs::new(6_500));
        }

        // The transfer that had already left finishes afterwards. What the service has is written
        // down; where the ciphertext is does not change, because it is nowhere here.
        let manifest_id = sealed.descriptor.encrypted_manifest.object_id;
        assert!(
            service
                .note_object_uploaded(
                    admitted.sequence,
                    archive_id(),
                    BackupGeneration::new(1),
                    manifest_id,
                    TimestampMs::new(7_000),
                )
                .expect("the manifest is acknowledged")
        );
        for row in service
            .objects(archive_id(), BackupGeneration::new(1))
            .expect("a read")
        {
            assert_eq!(row.local_state, LocalState::Absent);
            assert!(!row.staged_path.exists());
        }
        // The executor that held it says the transfer ended, which is what finishes the cleanup
        // that named it.
        service
            .note_attempt_accepted(admitted.sequence, TimestampMs::new(7_100))
            .expect("the executor reports its upload finished");
        let subsystems: Vec<&dyn PrivacySubsystem> = vec![&service];
        assert!(PrivacyMode::reconcile(&subsystems).is_complete());
    }

    // A restart does not raise a removal this host has already done.
    let service = BackupService::open(&state).expect("the service opens again");
    service
        .reconcile(TimestampMs::new(8_000))
        .expect("reconciliation");
    assert!(
        service.obligations().expect("a read").is_empty(),
        "the cleanup is finished and stays finished"
    );
    let subsystems: Vec<&dyn PrivacySubsystem> = vec![&service];
    assert!(PrivacyMode::reconcile(&subsystems).is_complete());
}

#[test]
fn a_restart_owes_the_ciphertext_of_a_published_archive_the_fence_had_not_reached() {
    let root = tempfile::tempdir().expect("a disposable directory on the internal disk");
    let state = root.path().join("state");
    std::fs::create_dir_all(&state).expect("the state directory");
    let producer = Producer::generate();
    let objects = [stage(1, "a.cbor", b"one")];
    let sealed = producer.seal(1, &objects);
    let staged_paths: Vec<std::path::PathBuf>;
    {
        let mut service = BackupService::open(&state).expect("a backup service");
        service
            .reconcile(TimestampMs::new(4_000))
            .expect("the startup reconciliation a service opens unready without");
        service
            .enrol_writer(producer.writer.key_id(), archive_id(), TimestampMs::new(1))
            .expect("the writer is enrolled");
        let admitted = service
            .admit(
                &sealed,
                &objects,
                producer.writer.key_id(),
                TimestampMs::new(5_000),
            )
            .expect("the generation is admitted");
        service
            .note_dispatched(admitted.sequence, EXECUTOR, TimestampMs::new(6_500))
            .expect("the upload is in flight");
        let publication = dispatch_publication(
            &service,
            admitted.sequence,
            BackupGeneration::new(1),
            TimestampMs::new(6_000),
        );
        service
            .note_published(
                publication,
                PrivacyGeneration::INITIAL,
                TimestampMs::new(6_500),
            )
            .expect("the service accepted it");
        staged_paths = service
            .objects(archive_id(), BackupGeneration::new(1))
            .expect("a read")
            .into_iter()
            .map(|row| row.staged_path)
            .collect();

        // Privacy mode fences and cancels, and this host stops before it removes anything. The
        // published generation has nothing left in its outbox, so nothing there says its staged
        // copies are still here.
        let _fenced = service.fence(PrivacyGeneration::new(1));
        service.cancel_undispatched(PrivacyGeneration::new(1));
    }

    // While the fence is recorded, every staged copy is a removal privacy mode asked for. A
    // published archive's ciphertext is as much on this host as a cancelled one's.
    let mut service = BackupService::open(&state).expect("the service opens again");
    service
        .reconcile(TimestampMs::new(7_000))
        .expect("reconciliation");
    for path in &staged_paths {
        assert!(path.exists(), "the ciphertext is still on this host");
    }
    assert!(!service.obligations().expect("a read").is_empty());
    {
        let subsystems: Vec<&dyn PrivacySubsystem> = vec![&service];
        assert!(!PrivacyMode::reconcile(&subsystems).is_complete());
    }

    let removed = service.remove_retained(PrivacyGeneration::new(1));
    assert!(removed.bytes > 0);
    assert_eq!(
        removed.records, 0,
        "a published archive keeps its record as a retained artifact, so no row was removed"
    );
    for path in &staged_paths {
        assert!(!path.exists(), "the ciphertext left this host");
    }
    {
        let subsystems: Vec<&dyn PrivacySubsystem> = vec![&service];
        assert!(PrivacyMode::reconcile(&subsystems).is_complete());
    }

    // A second pass has nothing to remove and says so, and the record of what left this host stays.
    let again = service.remove_retained(PrivacyGeneration::new(1));
    assert_eq!(again.bytes, 0);
    assert_eq!(again.records, 0);
    let kept = service
        .generation(archive_id(), BackupGeneration::new(1))
        .expect("a read")
        .expect("a published archive is shown rather than pretended away");
    assert_eq!(kept.remote, Remote::Published);
}

// ---------------------------------------------------------------------------------------------
// Durable cleanup obligations: what a fence writes down, and what ends one.
// ---------------------------------------------------------------------------------------------

#[test]
fn a_fence_writes_down_every_target_it_implies_and_a_repeat_adds_nothing() {
    let mut environment = Environment::open();
    let producer = Producer::generate();
    environment
        .service()
        .enrol_writer(producer.writer.key_id(), archive_id(), TimestampMs::new(1))
        .expect("the writer is enrolled");
    let objects = [stage(1, "a.cbor", b"one"), stage(2, "b.cbor", b"two")];
    let sealed = producer.seal(1, &objects);
    environment
        .service()
        .admit(
            &sealed,
            &objects,
            producer.writer.key_id(),
            TimestampMs::new(5_000),
        )
        .expect("the generation is admitted");

    let fenced = environment.service.fence(PrivacyGeneration::new(1));
    assert_eq!(fenced.queues, 1);
    let owed = environment.service().obligations().expect("a read");
    // Three staged copies, one queued entry, one generation's bookkeeping, one staging walk.
    assert_eq!(
        owed.iter()
            .filter(|obligation| obligation.kind == ObligationKind::UnlinkObject)
            .count(),
        3
    );
    assert_eq!(
        owed.iter()
            .filter(|obligation| obligation.kind == ObligationKind::CancelEntry)
            .count(),
        1
    );
    assert_eq!(
        owed.iter()
            .filter(|obligation| obligation.kind == ObligationKind::FinishGeneration)
            .count(),
        1
    );
    assert_eq!(
        owed.iter()
            .filter(|obligation| obligation.kind == ObligationKind::ScanStaging)
            .count(),
        1
    );
    assert!(
        owed.iter()
            .all(|obligation| obligation.privacy_generation == 1)
    );

    // Every obligation names its own target, and each staged copy carries the path to remove.
    for obligation in owed
        .iter()
        .filter(|obligation| obligation.kind == ObligationKind::UnlinkObject)
    {
        assert!(obligation.staged_path.is_some());
        assert!(obligation.object_id.is_some());
        assert_eq!(obligation.archive_id, Some(archive_id()));
    }

    // Asking for the same generation again reads the request back. It does not write a second
    // scope, and it does not recreate cleanup that has already been done.
    let again = environment.service.fence(PrivacyGeneration::new(1));
    assert_eq!(again.queues, 1);
    assert_eq!(environment.service().obligations().expect("a read"), owed);
}

#[test]
fn a_repeated_request_after_cleanup_finished_does_not_recreate_it() {
    let mut environment = Environment::open();
    let producer = Producer::generate();
    environment
        .service()
        .enrol_writer(producer.writer.key_id(), archive_id(), TimestampMs::new(1))
        .expect("the writer is enrolled");
    let objects = [stage(1, "a.cbor", b"one")];
    environment
        .service()
        .admit(
            &producer.seal(1, &objects),
            &objects,
            producer.writer.key_id(),
            TimestampMs::new(5_000),
        )
        .expect("the generation is admitted");

    let mut mode = PrivacyMode::new();
    mode.open_generation(TimestampMs::new(6_000));
    {
        let mut subsystems: Vec<&mut dyn PrivacySubsystem> = vec![&mut environment.service];
        mode.apply(&mut subsystems, TimestampMs::new(6_000));
    }
    assert!(
        environment
            .service()
            .obligations()
            .expect("a read")
            .is_empty()
    );

    // The same request arriving again finds its record applied. Recreating the scope would put
    // back removals whose targets are already gone, which no retry could ever discharge.
    let repeated = environment.service.fence(mode.generation());
    assert_eq!(repeated.queues, 1);
    assert!(
        environment
            .service()
            .obligations()
            .expect("a read")
            .is_empty()
    );
}

#[cfg(unix)]
#[test]
fn a_staged_copy_this_host_cannot_remove_keeps_its_own_obligation_until_it_can() {
    let root = tempfile::tempdir().expect("a disposable directory on the internal disk");
    let state = root.path().join("state");
    std::fs::create_dir_all(&state).expect("the state directory");
    let producer = Producer::generate();
    let objects = [stage(1, "a.cbor", b"one")];
    let mut service = BackupService::open(&state).expect("a backup service");
    service
        .reconcile(TimestampMs::new(4_000))
        .expect("the startup reconciliation a service opens unready without");
    service
        .enrol_writer(producer.writer.key_id(), archive_id(), TimestampMs::new(1))
        .expect("the writer is enrolled");
    service
        .admit(
            &producer.seal(1, &objects),
            &objects,
            producer.writer.key_id(),
            TimestampMs::new(5_000),
        )
        .expect("the generation is admitted");
    let staged: Vec<std::path::PathBuf> = service
        .objects(archive_id(), BackupGeneration::new(1))
        .expect("a read")
        .into_iter()
        .map(|row| row.staged_path)
        .collect();
    service.fence(PrivacyGeneration::new(1));
    service.cancel_undispatched(PrivacyGeneration::new(1));

    // The directory that holds the ciphertext is made unwritable, so every unlink fails.
    let directory = staged[0]
        .parent()
        .expect("a staging directory")
        .to_path_buf();
    set_directory_writable(&directory, false);
    let removed = service.remove_retained(PrivacyGeneration::new(1));
    assert_eq!(removed.bytes, 0);
    let owed = service.obligations().expect("a read");
    let failed: Vec<&_> = owed
        .iter()
        .filter(|obligation| obligation.kind == ObligationKind::UnlinkObject)
        .collect();
    assert_eq!(failed.len(), staged.len());
    for obligation in &failed {
        assert!(obligation.attempt_count >= 1);
        assert!(
            obligation.last_error.is_some(),
            "the reason is recorded beside the obligation, never instead of it"
        );
    }
    assert!(!PrivacyMode::reconcile(&[&service as &dyn PrivacySubsystem]).is_complete());
    assert_eq!(
        service
            .release_fence(
                PrivacyGeneration::new(1),
                PrivacyGeneration::new(2),
                TimestampMs::new(7_000),
            )
            .expect("the release is attempted"),
        FenceRelease::Pending {
            obligations: owed.len() as u64
        }
    );

    // A second attempt while the fault holds finds the same targets, not new ones.
    service.remove_retained(PrivacyGeneration::new(1));
    let again = service.obligations().expect("a read");
    assert_eq!(again.len(), owed.len());
    for obligation in &failed {
        assert!(
            again
                .iter()
                .any(|later| later.id == obligation.id
                    && later.attempt_count > obligation.attempt_count),
            "the same row, tried again"
        );
    }

    // A restart does not recreate them either: the rows are the account, not the process.
    drop(service);
    let mut service = BackupService::open(&state).expect("the service opens again");
    service
        .reconcile(TimestampMs::new(4_000))
        .expect("the startup reconciliation a service opens unready without");
    assert_eq!(service.obligations().expect("a read").len(), again.len());

    // Access comes back, and their own success is what ends them.
    set_directory_writable(&directory, true);
    let removed = service.remove_retained(PrivacyGeneration::new(1));
    assert!(removed.bytes > 0);
    for path in &staged {
        assert!(!path.exists());
    }
    assert!(service.obligations().expect("a read").is_empty());
    assert!(PrivacyMode::reconcile(&[&service as &dyn PrivacySubsystem]).is_complete());
    assert_eq!(
        service
            .release_fence(
                PrivacyGeneration::new(1),
                PrivacyGeneration::new(2),
                TimestampMs::new(8_000),
            )
            .expect("a release"),
        FenceRelease::Released
    );
}

#[cfg(unix)]
#[test]
fn a_store_that_stops_accepting_writes_mid_cleanup_keeps_the_obligation_for_the_file_that_went() {
    let root = tempfile::tempdir().expect("a disposable directory on the internal disk");
    let state = root.path().join("state");
    std::fs::create_dir_all(&state).expect("the state directory");
    let producer = Producer::generate();
    let objects = [stage(1, "a.cbor", b"one")];
    let mut service = BackupService::open(&state).expect("a backup service");
    service
        .reconcile(TimestampMs::new(4_000))
        .expect("the startup reconciliation a service opens unready without");
    service
        .enrol_writer(producer.writer.key_id(), archive_id(), TimestampMs::new(1))
        .expect("the writer is enrolled");
    service
        .admit(
            &producer.seal(1, &objects),
            &objects,
            producer.writer.key_id(),
            TimestampMs::new(5_000),
        )
        .expect("the generation is admitted");
    let staged: Vec<std::path::PathBuf> = service
        .objects(archive_id(), BackupGeneration::new(1))
        .expect("a read")
        .into_iter()
        .map(|row| row.staged_path)
        .collect();
    service.fence(PrivacyGeneration::new(1));
    service.cancel_undispatched(PrivacyGeneration::new(1));

    // The first pass gets past the staging walk and fails at the removals, so what is left owed
    // is a removal rather than the walk in front of it.
    let directory = staged[0]
        .parent()
        .expect("a staging directory")
        .to_path_buf();
    set_directory_writable(&directory, false);
    service.remove_retained(PrivacyGeneration::new(1));
    set_directory_writable(&directory, true);
    let owed = service.obligations().expect("a read");
    assert!(
        owed.iter()
            .all(|obligation| obligation.kind != ObligationKind::ScanStaging),
        "the walk is done: {owed:?}"
    );
    assert!(
        owed.iter()
            .any(|obligation| obligation.kind == ObligationKind::UnlinkObject)
    );

    // The removal now happens and the store will not take the discharge. The effect is on the
    // disk; the record of it is not, and the obligation is what survives that gap.
    for path in &staged {
        std::fs::remove_file(path).expect("the file goes before the store is asked");
    }
    service.set_query_only(true).expect("query_only pragma");
    let removed = service.remove_retained(PrivacyGeneration::new(1));
    assert_eq!(removed.records, 0);
    let owed = service.obligations().expect("a read");
    assert!(
        owed.iter()
            .any(|obligation| obligation.kind == ObligationKind::UnlinkObject),
        "the removal is still owed although the file has gone: {owed:?}"
    );
    assert!(!PrivacyMode::reconcile(&[&service as &dyn PrivacySubsystem]).is_complete());

    // With write access back, a file that is already gone is exactly what the retry expects.
    service.set_query_only(false).expect("query_only pragma");
    service.remove_retained(PrivacyGeneration::new(1));
    for path in &staged {
        assert!(!path.exists());
    }
    assert!(service.obligations().expect("a read").is_empty());
    assert!(PrivacyMode::reconcile(&[&service as &dyn PrivacySubsystem]).is_complete());
}

/// Section 24: a staged copy's removal is reported only once the directory that named it is
/// flushed. On Windows that flush opens the directory through a handle that may add to it, so while
/// a handle that shares no writing holds the directory, the names go and their flush is refused:
/// every removal stays owed, with its reason beside it, until an attempt whose flush succeeds.
#[cfg(windows)]
#[test]
fn a_removal_whose_directory_cannot_be_flushed_keeps_its_obligation_until_it_can() {
    let root = tempfile::tempdir().expect("a disposable directory on the internal disk");
    let state = root.path().join("state");
    std::fs::create_dir_all(&state).expect("the state directory");
    let producer = Producer::generate();
    let objects = [stage(1, "a.cbor", b"one")];
    let mut service = BackupService::open(&state).expect("a backup service");
    service
        .reconcile(TimestampMs::new(4_000))
        .expect("the startup reconciliation a service opens unready without");
    service
        .enrol_writer(producer.writer.key_id(), archive_id(), TimestampMs::new(1))
        .expect("the writer is enrolled");
    service
        .admit(
            &producer.seal(1, &objects),
            &objects,
            producer.writer.key_id(),
            TimestampMs::new(5_000),
        )
        .expect("the generation is admitted, its staged names flushed");
    let staged: Vec<std::path::PathBuf> = service
        .objects(archive_id(), BackupGeneration::new(1))
        .expect("a read")
        .into_iter()
        .map(|row| row.staged_path)
        .collect();
    service.fence(PrivacyGeneration::new(1));
    service.cancel_undispatched(PrivacyGeneration::new(1));

    let directory = staged[0]
        .parent()
        .expect("a staging directory")
        .to_path_buf();
    let held = hold_without_shared_writing(&directory);
    let removed = service.remove_retained(PrivacyGeneration::new(1));
    assert_eq!(
        removed.bytes, 0,
        "no removal is reported while its flush is refused"
    );
    for path in &staged {
        assert!(
            !path.exists(),
            "the name went; its flush is what was refused"
        );
    }
    let owed = service.obligations().expect("a read");
    let failed: Vec<&_> = owed
        .iter()
        .filter(|obligation| obligation.kind == ObligationKind::UnlinkObject)
        .collect();
    assert_eq!(failed.len(), staged.len(), "{owed:?}");
    for obligation in &failed {
        assert!(obligation.attempt_count >= 1);
        assert!(
            obligation.last_error.is_some(),
            "the reason is recorded beside the obligation, never instead of it"
        );
    }
    assert!(!PrivacyMode::reconcile(&[&service as &dyn PrivacySubsystem]).is_complete());

    // With the directory free again, a name that is already gone is what the retry expects, and
    // the flush it makes is what ends each obligation.
    drop(held);
    service.remove_retained(PrivacyGeneration::new(1));
    assert!(service.obligations().expect("a read").is_empty());
    assert!(PrivacyMode::reconcile(&[&service as &dyn PrivacySubsystem]).is_complete());
}

/// Section 24: staged ciphertext is flushed into its directory, and each directory up to the
/// staging root into the one above it, before any row names it. On Windows each flush opens its
/// directory through a handle that may add to it, the generation's own for a file's name and the
/// staging root for a directory's, so while either is held by a handle that shares no writing the
/// admission is refused and no row names what was written. The ciphertext left behind is what a
/// crash between the file and the row leaves, which the staging walk exists to remove.
#[cfg(windows)]
#[test]
fn a_staged_write_whose_directory_cannot_be_flushed_is_not_admitted() {
    let environment = Environment::open();
    let service = environment.service();
    let producer = Producer::generate();
    service
        .enrol_writer(producer.writer.key_id(), archive_id(), TimestampMs::new(1))
        .expect("the writer is enrolled");
    let objects = [stage(1, "a.cbor", b"one")];
    let staging = service.staging_root();
    // Generation 1's objects are staged in a directory named after the archive and the generation,
    // made here so that a handle can hold it before the admission writes into it.
    let own = staging.join(format!("{}-1", archive_id()));
    std::fs::create_dir_all(&own).expect("the generation's staging directory");

    for (generation, held) in [(1, own.as_path()), (2, staging.as_path())] {
        let holding = hold_without_shared_writing(held);
        let refused = service.admit(
            &producer.seal(generation, &objects),
            &objects,
            producer.writer.key_id(),
            TimestampMs::new(5_000),
        );
        drop(holding);
        assert!(
            refused.is_err(),
            "generation {generation} is admitted while {} cannot be flushed",
            held.display()
        );
        assert!(
            service
                .objects(archive_id(), BackupGeneration::new(generation))
                .expect("a read")
                .is_empty(),
            "no row names what generation {generation} wrote"
        );
    }

    let admitted = service
        .admit(
            &producer.seal(3, &objects),
            &objects,
            producer.writer.key_id(),
            TimestampMs::new(6_000),
        )
        .expect("with nothing holding its directories, a generation is admitted");
    assert_eq!(
        admitted.staged_objects, 2,
        "one member and the encrypted manifest"
    );
}

#[test]
fn ciphertext_no_row_names_keeps_cleanup_pending_until_the_walk_finds_and_removes_it() {
    let environment = Environment::open();
    let mut environment = environment;
    let stray = environment
        .service()
        .staging_root()
        .join("11111111-1")
        .join("orphan.krb");
    std::fs::create_dir_all(stray.parent().expect("a directory")).expect("the directory");
    std::fs::write(&stray, b"ciphertext a stop left behind").expect("the stray file");

    environment.service.fence(PrivacyGeneration::new(1));
    // Nothing is registered, so nothing but the walk is owed until the walk has run.
    let owed = environment.service().obligations().expect("a read");
    assert_eq!(owed.len(), 1);
    assert_eq!(owed[0].kind, ObligationKind::ScanStaging);

    environment
        .service()
        .run_cleanup(PrivacyGeneration::new(1), TimestampMs::new(6_000))
        .expect("the walk runs");
    assert!(!stray.exists(), "the file the walk found is gone");
    assert!(
        environment
            .service()
            .obligations()
            .expect("a read")
            .is_empty()
    );
    assert!(PrivacyMode::reconcile(&[&environment.service as &dyn PrivacySubsystem]).is_complete());
}

#[test]
fn a_late_acknowledgement_ends_only_its_own_attempt_and_puts_no_file_back() {
    let mut environment = Environment::open();
    let producer = Producer::generate();
    environment
        .service()
        .enrol_writer(producer.writer.key_id(), archive_id(), TimestampMs::new(1))
        .expect("the writer is enrolled");
    let objects = [stage(1, "a.cbor", b"one"), stage(2, "b.cbor", b"two")];
    let sealed = producer.seal(1, &objects);
    let admitted = environment
        .service()
        .admit(
            &sealed,
            &objects,
            producer.writer.key_id(),
            TimestampMs::new(5_000),
        )
        .expect("the generation is admitted");
    environment
        .service()
        .note_dispatched(admitted.sequence, EXECUTOR, TimestampMs::new(6_500))
        .expect("the upload is in flight");
    // One member is acknowledged before the fence goes up.
    environment
        .service()
        .note_object_uploaded(
            admitted.sequence,
            archive_id(),
            BackupGeneration::new(1),
            objects[0].object_id(),
            TimestampMs::new(5_500),
        )
        .expect("the member is acknowledged");

    environment.service.fence(PrivacyGeneration::new(1));
    environment
        .service
        .cancel_undispatched(PrivacyGeneration::new(1));
    let removed = environment
        .service
        .remove_retained(PrivacyGeneration::new(1));
    assert!(removed.bytes > 0);
    for row in environment
        .service()
        .objects(archive_id(), BackupGeneration::new(1))
        .expect("a read")
    {
        assert_eq!(row.local_state, LocalState::Absent);
    }

    // The rest of the upload arrives afterwards. No publication is enqueued, and no object is
    // described as staged here again; the attempt stays where it is until its own executor
    // reports it, which is what ends it and the cleanup that names it.
    acknowledge_every_object(
        environment.service(),
        admitted.sequence,
        BackupGeneration::new(1),
        TimestampMs::new(6_000),
    );
    assert!(
        environment
            .service()
            .outbox()
            .expect("a read")
            .iter()
            .all(|attempt| attempt.step == Step::Upload
                && attempt.status == AttemptStatus::Dispatched)
    );
    assert!(
        !PrivacyMode::reconcile(&[&environment.service as &dyn PrivacySubsystem]).is_complete()
    );
    environment
        .service()
        .note_attempt_accepted(admitted.sequence, TimestampMs::new(6_100))
        .expect("the executor reports its upload finished");
    assert!(environment.service().outbox().expect("a read").is_empty());
    for row in environment
        .service()
        .objects(archive_id(), BackupGeneration::new(1))
        .expect("a read")
    {
        assert_eq!(
            row.local_state,
            LocalState::Absent,
            "an acknowledgement does not put a file back"
        );
    }
    assert!(
        environment
            .service()
            .obligations()
            .expect("a read")
            .is_empty()
    );
    assert!(PrivacyMode::reconcile(&[&environment.service as &dyn PrivacySubsystem]).is_complete());
}

#[cfg(unix)]
#[test]
fn a_second_fence_is_not_released_by_the_first_ones_cleanup() {
    let root = tempfile::tempdir().expect("a disposable directory on the internal disk");
    let state = root.path().join("state");
    std::fs::create_dir_all(&state).expect("the state directory");
    let producer = Producer::generate();
    let objects = [stage(1, "a.cbor", b"one")];
    let mut service = BackupService::open(&state).expect("a backup service");
    service
        .reconcile(TimestampMs::new(4_000))
        .expect("the startup reconciliation a service opens unready without");
    service
        .enrol_writer(producer.writer.key_id(), archive_id(), TimestampMs::new(1))
        .expect("the writer is enrolled");
    service
        .admit(
            &producer.seal(1, &objects),
            &objects,
            producer.writer.key_id(),
            TimestampMs::new(5_000),
        )
        .expect("the generation is admitted");
    let staged: Vec<std::path::PathBuf> = service
        .objects(archive_id(), BackupGeneration::new(1))
        .expect("a read")
        .into_iter()
        .map(|row| row.staged_path)
        .collect();
    let directory = staged[0]
        .parent()
        .expect("a staging directory")
        .to_path_buf();

    // The first fence leaves work behind, because nothing can be removed.
    service.fence(PrivacyGeneration::new(1));
    service.cancel_undispatched(PrivacyGeneration::new(1));
    set_directory_writable(&directory, false);
    service.remove_retained(PrivacyGeneration::new(1));
    assert!(!service.obligations().expect("a read").is_empty());

    // A second request arrives over the top of it.
    service.fence(PrivacyGeneration::new(5));
    let status = service.privacy_status().expect("a read");
    assert_eq!(status.current_generation, 5);
    assert_eq!(status.unreleased_fence, Some(1), "the older fence stands");

    // Cleanup of the older fence cannot release the newer one, and a release aimed at the older
    // one does not move the generation in force backwards.
    set_directory_writable(&directory, true);
    service.remove_retained(PrivacyGeneration::new(5));
    assert_eq!(
        service
            .release_fence(
                PrivacyGeneration::new(1),
                PrivacyGeneration::new(6),
                TimestampMs::new(8_000),
            )
            .expect("a release"),
        FenceRelease::Released
    );
    assert_eq!(
        service.fenced_at().expect("a read"),
        Some(5),
        "the newer fence is untouched by the older one's release"
    );
    let status = service.privacy_status().expect("a read");
    assert!(status.enabled);
    assert_eq!(status.current_generation, 6);
    assert!(
        service
            .release_fence(
                PrivacyGeneration::new(5),
                PrivacyGeneration::new(4),
                TimestampMs::new(8_500),
            )
            .is_err(),
        "the generation in force never moves backwards"
    );
}

#[test]
fn direct_sql_cannot_release_a_fence_that_still_has_cleanup_outstanding() {
    let root = tempfile::tempdir().expect("a disposable directory on the internal disk");
    let state = root.path().join("state");
    std::fs::create_dir_all(&state).expect("the state directory");
    {
        let mut service = BackupService::open(&state).expect("a backup service");
        service
            .reconcile(TimestampMs::new(4_000))
            .expect("the startup reconciliation a service opens unready without");
        service.fence(PrivacyGeneration::new(1));
        assert!(!service.obligations().expect("a read").is_empty());
    }

    // The rule lives in the database, not in the calling code. A writer that went round the store
    // still cannot say a fence with cleanup outstanding is released, or delete it instead.
    let connection =
        rusqlite::Connection::open(state.join("backup.sqlite")).expect("the backup store");
    let released = connection.execute(
        "UPDATE privacy_fences SET released_at_ms = 1 WHERE privacy_generation = 1",
        [],
    );
    assert!(released.is_err(), "{released:?}");
    let deleted = connection.execute(
        "DELETE FROM privacy_fences WHERE privacy_generation = 1",
        [],
    );
    assert!(deleted.is_err(), "{deleted:?}");

    // Nor by replacing the row, which is a delete and an insert wearing one statement.
    let replaced = connection.execute(
        "INSERT OR REPLACE INTO privacy_fences (privacy_generation, raised_at_ms, released_at_ms)
         VALUES (1, 1, 2)",
        [],
    );
    assert!(replaced.is_err(), "{replaced:?}");

    // Nor by moving the fence away from what it owes, or the cleanup away from its fence.
    let moved = connection.execute(
        "UPDATE privacy_fences SET privacy_generation = 7 WHERE privacy_generation = 1",
        [],
    );
    assert!(moved.is_err(), "{moved:?}");
    let reassigned = connection.execute(
        "UPDATE privacy_obligations SET privacy_generation = 7 WHERE privacy_generation = 1",
        [],
    );
    assert!(reassigned.is_err(), "{reassigned:?}");

    // And a released fence takes no new cleanup: an obligation written against one would be work
    // nothing would ever look at again.
    connection
        .execute("DELETE FROM privacy_obligations", [])
        .expect("the obligations are cleared for this check");
    connection
        .execute(
            "UPDATE privacy_fences SET released_at_ms = 1 WHERE privacy_generation = 1",
            [],
        )
        .expect("the fence releases once nothing is owed");
    let late = connection.execute(
        "INSERT INTO privacy_obligations
             (privacy_generation, kind, target_key, recorded_at_ms, attempt_count)
         VALUES (1, 'scan_staging', 'staging', 1, 0)",
        [],
    );
    assert!(late.is_err(), "{late:?}");

    // An obligation against a generation this host never accepted a request for is refused too.
    let rootless = connection.execute(
        "INSERT INTO privacy_obligations
             (privacy_generation, kind, target_key, recorded_at_ms, attempt_count)
         VALUES (99, 'scan_staging', 'staging', 1, 0)",
        [],
    );
    assert!(rootless.is_err(), "{rootless:?}");
}

#[test]
fn a_discharge_reads_the_kind_of_the_row_it_ends_rather_than_the_caller_s_copy() {
    let root = tempfile::tempdir().expect("a disposable directory on the internal disk");
    let state = root.path().join("state");
    std::fs::create_dir_all(&state).expect("the state directory");
    let mut store = BackupStore::open(&state).expect("a backup store");
    store
        .accept_privacy_request(1, TimestampMs::new(6_000))
        .expect("the request is accepted");
    let owed = store.obligations().expect("a read");
    assert_eq!(owed.len(), 1);
    assert_eq!(owed[0].kind, ObligationKind::ActivateFence);

    // The caller holds a copy of the row and may change it. Relabelling that copy and handing it
    // to a discharge handler must not end the row it names: the database is the authority, and an
    // activation this host never performed is not a removal it did.
    let mut forged = owed[0].clone();
    forged.kind = ObligationKind::UnlinkObject;
    forged.staged_path = Some(state.join("backup").join("nothing.krb"));
    let refused = store.note_object_unlinked(&forged);
    assert!(refused.is_err(), "{refused:?}");

    forged.kind = ObligationKind::ScanStaging;
    let refused = store.record_staging_scan(&forged, &[], TimestampMs::new(6_500));
    assert!(refused.is_err(), "{refused:?}");

    forged.kind = ObligationKind::FinishGeneration;
    forged.archive_id = Some(archive_id());
    forged.backup_generation = Some(BackupGeneration::new(1));
    let refused = store.finish_generation(&forged);
    assert!(refused.is_err(), "{refused:?}");

    let still_owed = store.obligations().expect("a read");
    assert_eq!(
        still_owed, owed,
        "the activation this host never performed is still owed, unchanged"
    );
}

#[test]
fn direct_sql_cannot_put_an_attempt_back_in_hand_or_unsay_what_a_service_holds() {
    let root = tempfile::tempdir().expect("a disposable directory on the internal disk");
    let state = root.path().join("state");
    std::fs::create_dir_all(&state).expect("the state directory");
    let producer = Producer::generate();
    let objects = [stage(1, "a.cbor", b"one")];
    let sealed = producer.seal(1, &objects);
    let admitted = {
        let service = BackupService::open(&state).expect("a backup service");
        service
            .reconcile(TimestampMs::new(4_000))
            .expect("the startup reconciliation a service opens unready without");
        service
            .enrol_writer(producer.writer.key_id(), archive_id(), TimestampMs::new(1))
            .expect("the writer is enrolled");
        let admitted = service
            .admit(
                &sealed,
                &objects,
                producer.writer.key_id(),
                TimestampMs::new(5_000),
            )
            .expect("the generation is admitted");
        service
            .note_dispatched(admitted.sequence, EXECUTOR, TimestampMs::new(6_500))
            .expect("the upload is in flight");
        service
            .note_object_uploaded(
                admitted.sequence,
                archive_id(),
                BackupGeneration::new(1),
                objects[0].object_id(),
                TimestampMs::new(6_000),
            )
            .expect("the member is acknowledged");
        admitted
    };

    // These rules live in the database, not in the calling code. An attempt that left this host
    // cannot be relabelled as one that never went, nor moved onto other work, nor given a
    // different executor after the fact.
    let connection =
        rusqlite::Connection::open(state.join("backup.sqlite")).expect("the backup store");
    for statement in [
        "UPDATE outbox SET status = 'queued' WHERE sequence = ?1",
        "UPDATE outbox SET step = 'publish' WHERE sequence = ?1",
        "UPDATE outbox SET backup_generation = 9 WHERE sequence = ?1",
        "UPDATE outbox SET privacy_generation = 9 WHERE sequence = ?1",
        "UPDATE outbox SET executor = 'somebody else' WHERE sequence = ?1",
        "UPDATE outbox SET sequence = 99 WHERE sequence = ?1",
        "UPDATE outbox SET status = 'terminal', outcome = 'cancelled', settled_at_ms = 1
          WHERE sequence = ?1",
    ] {
        let refused = connection.execute(statement, rusqlite::params![admitted.sequence as i64]);
        assert!(refused.is_err(), "{statement} was permitted: {refused:?}");
    }

    // Nor can an attempt be answered on evidence that is not about it: an upload does not end as
    // accepted while an object of its generation has still to arrive, and a publication does not
    // before this host has written down that a service holds the archive. That holds for a row
    // written from nothing as much as for one already there.
    let unarrived = connection.execute(
        "UPDATE outbox SET status = 'terminal', outcome = 'accepted', settled_at_ms = 1
          WHERE sequence = ?1",
        rusqlite::params![admitted.sequence as i64],
    );
    assert!(unarrived.is_err(), "{unarrived:?}");
    for step in ["upload", "publish"] {
        let written = connection.execute(
            "INSERT OR REPLACE INTO outbox
                 (archive_id, backup_generation, step, privacy_generation, status, outcome,
                  executor, enqueued_at_ms, dispatched_at_ms, settled_at_ms)
             SELECT archive_id, backup_generation, ?1, privacy_generation, 'terminal', 'accepted',
                    'a transport', 1, 1, 1
               FROM outbox WHERE sequence = ?2",
            rusqlite::params![step, admitted.sequence as i64],
        );
        assert!(
            written.is_err(),
            "a {step} was written accepted: {written:?}"
        );
    }

    // Nor by replacing the row, which is a delete and an insert wearing one statement.
    let replaced = connection.execute(
        "INSERT OR REPLACE INTO outbox
             (sequence, archive_id, backup_generation, step, privacy_generation, status, outcome,
              executor, enqueued_at_ms)
         SELECT sequence, archive_id, backup_generation, step, privacy_generation, 'queued', NULL,
                NULL, enqueued_at_ms
           FROM outbox WHERE sequence = ?1",
        rusqlite::params![admitted.sequence as i64],
    );
    assert!(replaced.is_err(), "{replaced:?}");

    // Nor by leaving the identity out and colliding through the index that admits one publication
    // per generation, which is the other unique key a replacement can delete a row through.
    connection
        .execute(
            "INSERT INTO outbox
                 (archive_id, backup_generation, step, privacy_generation, status, outcome,
                  executor, enqueued_at_ms, dispatched_at_ms)
             SELECT archive_id, backup_generation, 'publish', privacy_generation, 'dispatched',
                    NULL, 'a transport', 1, 1
               FROM outbox WHERE sequence = ?1",
            rusqlite::params![admitted.sequence as i64],
        )
        .expect("a publication attempt is recorded");
    // Nor does a publication end as accepted before this host has written down that a service
    // holds the archive, so an answer cannot be recorded without the artifact it is evidence of.
    let unheld = connection.execute(
        "UPDATE outbox SET status = 'terminal', outcome = 'accepted', settled_at_ms = 1
          WHERE step = 'publish'",
        [],
    );
    assert!(unheld.is_err(), "{unheld:?}");
    let through_index = connection.execute(
        "INSERT OR REPLACE INTO outbox
             (archive_id, backup_generation, step, privacy_generation, status, outcome, executor,
              enqueued_at_ms)
         SELECT archive_id, backup_generation, 'publish', privacy_generation, 'queued', NULL, NULL,
                enqueued_at_ms
           FROM outbox WHERE step = 'publish'",
        [],
    );
    assert!(through_index.is_err(), "{through_index:?}");
    let publications: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM outbox WHERE step = 'publish' AND status = 'dispatched'",
            [],
            |row| row.get(0),
        )
        .expect("a read");
    assert_eq!(publications, 1, "the publication that left is still there");

    // An attempt this host is still owed an answer for is not deleted, nor is the cleanup that
    // names it discharged: either would leave a fence able to report a cleanup finished over a
    // transfer nobody had followed.
    let deleted = connection.execute(
        "DELETE FROM outbox WHERE sequence = ?1",
        rusqlite::params![admitted.sequence as i64],
    );
    assert!(deleted.is_err(), "{deleted:?}");

    // Nor can an acknowledgement be withdrawn, nor a removed staged copy be recorded as present
    // again: both are facts this host has already acted on.
    let withdrawn = connection.execute("UPDATE objects SET acknowledged_bytes = 0", []);
    assert!(withdrawn.is_err(), "{withdrawn:?}");
    connection
        .execute("UPDATE objects SET local_state = 'absent'", [])
        .expect("a removal is recorded");
    let returned = connection.execute("UPDATE objects SET local_state = 'present'", []);
    assert!(returned.is_err(), "{returned:?}");

    // Nor by replacing an object row or a generation row, which resets every one of those facts
    // at once.
    let object_replaced = connection.execute(
        "INSERT OR REPLACE INTO objects
             (archive_id, backup_generation, object_id, encrypted_hash, encrypted_len, staged_path,
              local_state, acknowledged_bytes)
         SELECT archive_id, backup_generation, object_id, encrypted_hash, encrypted_len,
                staged_path, 'present', 0
           FROM objects",
        [],
    );
    assert!(object_replaced.is_err(), "{object_replaced:?}");
    connection
        .execute(
            "UPDATE generations SET production = 'cancelled', settled_at_ms = 1, detail = 'x'",
            [],
        )
        .expect("production ends");
    let generation_replaced = connection.execute(
        "INSERT OR REPLACE INTO generations
             (archive_id, backup_generation, production, remote, writer_key_id, privacy_generation,
              descriptor, created_at_ms, settled_at_ms, detail)
         SELECT archive_id, backup_generation, 'producing', 'none', writer_key_id,
                privacy_generation, descriptor, created_at_ms, NULL, NULL
           FROM generations",
        [],
    );
    assert!(generation_replaced.is_err(), "{generation_replaced:?}");

    // And the privacy generation in force never moves backwards.
    let backwards = connection.execute(
        "UPDATE privacy_state SET current_generation = current_generation - 1 WHERE id = 0",
        [],
    );
    assert!(backwards.is_err(), "{backwards:?}");
}

#[test]
fn direct_sql_cannot_end_a_transfer_by_stopping_forgetting_or_discharging_it() {
    let root = tempfile::tempdir().expect("a disposable directory on the internal disk");
    let state = root.path().join("state");
    std::fs::create_dir_all(&state).expect("the state directory");
    let producer = Producer::generate();
    let objects = [stage(1, "a.cbor", b"one")];
    let admitted = {
        let mut service = BackupService::open(&state).expect("a backup service");
        service
            .reconcile(TimestampMs::new(4_000))
            .expect("the startup reconciliation a service opens unready without");
        service
            .enrol_writer(producer.writer.key_id(), archive_id(), TimestampMs::new(1))
            .expect("the writer is enrolled");
        let admitted = service
            .admit(
                &producer.seal(1, &objects),
                &objects,
                producer.writer.key_id(),
                TimestampMs::new(5_000),
            )
            .expect("the generation is admitted");
        service
            .note_dispatched(admitted.sequence, EXECUTOR, TimestampMs::new(5_100))
            .expect("the upload is in flight");
        // The fence writes down one resolution for that exact attempt, which is what a cleanup
        // has to discharge before it can report itself finished.
        service.fence(PrivacyGeneration::new(1));
        service.cancel_undispatched(PrivacyGeneration::new(1));
        service.remove_retained(PrivacyGeneration::new(1));
        assert!(
            service
                .obligations()
                .expect("a read")
                .iter()
                .any(|obligation| obligation.entry_sequence == Some(admitted.sequence)),
            "the attempt that left has its own resolution"
        );
        admitted
    };
    let connection =
        rusqlite::Connection::open(state.join("backup.sqlite")).expect("the backup store");

    // Nothing of this generation has been acknowledged, so what a service may hold of it is still
    // nothing. An attempt cannot end as stopped from there: the call that ends one that way writes
    // the uncertainty down in the same transaction, and a writer going round the store that did
    // not would leave a generation whose copies nobody accounts for.
    let unwritten = connection.execute(
        "UPDATE outbox SET status = 'terminal', outcome = 'stopped', settled_at_ms = 1
          WHERE archive_id = ?1 AND backup_generation = 1",
        rusqlite::params![archive_id().get().as_bytes().as_slice()],
    );
    assert!(unwritten.is_err(), "{unwritten:?}");

    // Nor from nothing. A stopped attempt written straight into the outbox says the same thing
    // about the same generation, and it is refused on the same evidence.
    let from_nothing = connection.execute(
        "INSERT INTO outbox
             (archive_id, backup_generation, step, privacy_generation, status, outcome, executor,
              enqueued_at_ms, dispatched_at_ms, settled_at_ms)
         SELECT archive_id, backup_generation, 'upload', privacy_generation, 'terminal', 'stopped',
                'a transport', 1, 1, 1
           FROM generations
          WHERE archive_id = ?1 AND backup_generation = 1 AND remote = 'none'",
        rusqlite::params![archive_id().get().as_bytes().as_slice()],
    );
    assert!(from_nothing.is_err(), "{from_nothing:?}");

    // Nor is the attempt forgotten, nor the cleanup that names it discharged. Either would let a
    // fence report a cleanup finished over a transfer nobody had followed.
    let deleted = connection.execute(
        "DELETE FROM outbox WHERE sequence = ?1",
        rusqlite::params![admitted.sequence as i64],
    );
    assert!(deleted.is_err(), "{deleted:?}");
    let discharged = connection.execute(
        "DELETE FROM privacy_obligations WHERE entry_sequence = ?1",
        rusqlite::params![admitted.sequence as i64],
    );
    assert!(discharged.is_err(), "{discharged:?}");

    // Nor is it rewritten into cleanup for something else, which is the same discharge wearing an
    // update, nor written over by an insert carrying its identity.
    let rewritten = connection.execute(
        "UPDATE privacy_obligations SET kind = 'finish_generation', entry_sequence = NULL
          WHERE entry_sequence = ?1",
        rusqlite::params![admitted.sequence as i64],
    );
    assert!(rewritten.is_err(), "{rewritten:?}");
    // Nor is the moment it was written down moved, which is the same row wearing a later date.
    let redated = connection.execute(
        "UPDATE privacy_obligations SET recorded_at_ms = recorded_at_ms + 1
          WHERE entry_sequence = ?1",
        rusqlite::params![admitted.sequence as i64],
    );
    assert!(redated.is_err(), "{redated:?}");

    // Nor is it written over by an insert carrying its identity. The target below is one nothing
    // owes, so its own identity is the only thing this statement collides on.
    let written_over = connection.execute(
        "INSERT OR REPLACE INTO privacy_obligations
             (id, privacy_generation, kind, target_key, archive_id, backup_generation,
              recorded_at_ms, attempt_count)
         SELECT id, privacy_generation, 'finish_generation',
                'generation:' || hex(archive_id) || ':' || (backup_generation + 1),
                archive_id, backup_generation + 1, recorded_at_ms, attempt_count
           FROM privacy_obligations WHERE entry_sequence = ?1",
        rusqlite::params![admitted.sequence as i64],
    );
    assert!(written_over.is_err(), "{written_over:?}");

    // Nor by leaving the identity out and colliding through the key that admits one obligation per
    // target, which is the other unique key a replacement can delete a row through. The delete
    // inside such a statement is the one refused above, wearing an insert: it takes the resolution
    // this host owes for an attempt still in flight, and it does it without ever running a delete
    // the rules can see.
    let through_the_target = connection.execute(
        "INSERT OR REPLACE INTO privacy_obligations
             (privacy_generation, kind, target_key, archive_id, backup_generation, object_id,
              staged_path, entry_sequence, recorded_at_ms, attempt_count)
         SELECT privacy_generation, kind, target_key, archive_id, backup_generation, object_id,
                staged_path, entry_sequence, recorded_at_ms, 0
           FROM privacy_obligations WHERE entry_sequence = ?1",
        rusqlite::params![admitted.sequence as i64],
    );
    assert!(through_the_target.is_err(), "{through_the_target:?}");
    let still_owed: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM privacy_obligations WHERE entry_sequence = ?1",
            rusqlite::params![admitted.sequence as i64],
            |row| row.get(0),
        )
        .expect("a read");
    assert_eq!(
        still_owed, 1,
        "the resolution for that attempt is still owed"
    );
    drop(connection);

    // The call that ends it writes both facts, so it is not refused, and the cleanup it named goes
    // with it.
    let service = BackupService::open(&state).expect("the service opens again");
    service
        .reconcile(TimestampMs::new(6_000))
        .expect("reconciliation");
    service
        .note_attempt_stopped(admitted.sequence, TimestampMs::new(6_500))
        .expect("the transport stopped");
    let record = service
        .generation(archive_id(), BackupGeneration::new(1))
        .expect("a read")
        .expect("the generation");
    assert_eq!(record.remote, Remote::Unknown);
    assert!(
        service
            .obligations()
            .expect("a read")
            .iter()
            .all(|obligation| obligation.entry_sequence != Some(admitted.sequence))
    );
}

/// Every statement the backup store can execute goes through the one check that refuses a
/// replacement, and this is what keeps that true.
///
/// Two tables have a unique key besides their primary key: the index that admits one live
/// publication per generation, and the key that admits one cleanup obligation per target. A
/// replacement deletes a row through either without the statement ever naming a delete, so the
/// class is closed once rather than one table at a time.
///
/// The check itself is `Statement::checked`, which `sql!` calls in a constant, so a statement that
/// held a `REPLACE` conflict clause would fail the build, and one made anywhere else is refused
/// the same way. An escape, a join of two halves or a comment between the words changes the
/// spelling and not the statement; a statement built while the program runs is not a constant and
/// cannot be made into one at all.
///
/// Reaching the database needs a handle to it, and one file holds every handle the module has:
/// the connection and the transaction are private to it, and what it hands out takes a checked
/// statement and nothing else. That is what this reads. Every other file of the module is searched
/// for a database handle by name, and one found there fails this test whatever it is used for. The
/// directory is walked rather than listed, so a file added to the module is read the day it
/// arrives.
#[test]
fn nothing_but_the_boundary_of_the_backup_store_holds_a_handle_to_the_database() {
    let module = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/backup");
    let boundary = module.join("statements.rs");
    let sources = rust_sources(&module);
    assert!(
        sources.iter().any(|(path, _)| path == &boundary),
        "the boundary is where this expects it: {}",
        boundary.display()
    );
    assert!(
        sources.len() >= 3,
        "the backup module's own source is there to be read: {}",
        module.display()
    );
    for (path, source) in sources {
        if path == boundary {
            continue;
        }
        // The handles a statement can be given to, and the calls that would give it one. The
        // handles are what this rests on: the names below are a second net, not the whole list of
        // ways a call could be spelled.
        for named in [
            "Connection",
            "Transaction",
            "Savepoint",
            "Batch",
            "execute(",
            "execute_batch(",
            "query_row(",
            "query_one(",
            "query_and_then(",
            "query_row_and_then(",
            "prepare(",
            "prepare_cached(",
            "prepare_with_flags(",
            "pragma_query(",
            "pragma_update(",
        ] {
            assert!(
                !source.contains(named),
                "{} reaches the database itself, round the boundary that reads a statement \
                 first: {named}",
                path.display()
            );
        }
    }
}

/// Every Rust source in one directory and the directories under it, read whole.
fn rust_sources(directory: &std::path::Path) -> Vec<(std::path::PathBuf, String)> {
    let mut sources = Vec::new();
    let mut pending = vec![directory.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in std::fs::read_dir(&directory).expect("a directory of the module") {
            let path = entry.expect("an entry of the module").path();
            if path.is_dir() {
                pending.push(path);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                let source = std::fs::read_to_string(&path).expect("a source of the module");
                sources.push((path, source));
            }
        }
    }
    sources
}

/// A store whose schema is not the one this build writes is refused, whatever its version says.
///
/// The rules a store enforces are part of its schema. A database written when one of them was
/// weaker cannot be vouched for, so opening it is refused rather than held to the weaker rule, and
/// nothing about that depends on somebody having moved the version number when the rule changed.
#[test]
fn a_store_whose_rules_are_not_this_builds_rules_is_refused() {
    let root = tempfile::tempdir().expect("a disposable directory on the internal disk");
    let state = root.path().join("state");
    std::fs::create_dir_all(&state).expect("the state directory");
    drop(BackupStore::open(&state).expect("a backup store"));
    BackupStore::open(&state).expect("the same store opens again");

    // The rule that refuses an insert carrying an obligation's target is weakened to the one that
    // refuses only its identity, which is what an older build of this store enforced.
    let connection =
        rusqlite::Connection::open(state.join("backup.sqlite")).expect("the backup store");
    connection
        .execute_batch(
            "DROP TRIGGER an_obligation_is_never_replaced;
             CREATE TRIGGER an_obligation_is_never_replaced
             BEFORE INSERT ON privacy_obligations
             WHEN EXISTS (SELECT 1 FROM privacy_obligations WHERE id = NEW.id)
             BEGIN
                 SELECT RAISE(ABORT, 'cleanup this host already owes is never written over');
             END;",
        )
        .expect("the weaker rule is written");
    drop(connection);

    let message = match BackupStore::open(&state) {
        Ok(_) => panic!("a store holding the weaker rule was opened"),
        Err(refusal) => refusal.to_string(),
    };
    assert!(
        message.contains("an_obligation_is_never_replaced"),
        "the refusal says which rule is not this build's: {message}"
    );
}

/// A rule added to a store is not this build's rule either, even under a name that looks internal.
///
/// SQLite keeps its own objects under names that begin `sqlite_`, and a store is compared without
/// them. `sqlite_` is a name and not a pattern: a trigger called `sqliteXdelete` is an ordinary
/// trigger that SQLite will run, and one that deletes rows behind an insert is exactly what this
/// store is built to refuse.
#[test]
fn a_rule_this_build_never_wrote_is_refused_whatever_it_is_called() {
    let root = tempfile::tempdir().expect("a disposable directory on the internal disk");
    let state = root.path().join("state");
    std::fs::create_dir_all(&state).expect("the state directory");
    drop(BackupStore::open(&state).expect("a backup store"));

    let connection =
        rusqlite::Connection::open(state.join("backup.sqlite")).expect("the backup store");
    connection
        .execute_batch(
            "CREATE TRIGGER sqliteXdelete AFTER INSERT ON writers
             BEGIN
                 DELETE FROM writers WHERE rowid <> NEW.rowid;
             END;",
        )
        .expect("the added rule is written");
    drop(connection);

    let message = match BackupStore::open(&state) {
        Ok(_) => panic!("a store holding a rule this build never wrote was opened"),
        Err(refusal) => refusal.to_string(),
    };
    assert!(
        message.contains("sqliteXdelete"),
        "the refusal says what this build does not define: {message}"
    );
}

/// A store whose creation stopped half way is refused rather than finished over.
///
/// The version is the last thing written, so a database that holds objects and records no version
/// is one whose creation did not finish, or one another build left behind. Writing this build's
/// schema over it would leave whatever it already holds in place and claim this build's rules for
/// it.
#[test]
fn a_store_whose_creation_did_not_finish_is_refused() {
    let root = tempfile::tempdir().expect("a disposable directory on the internal disk");
    let state = root.path().join("state");
    std::fs::create_dir_all(&state).expect("the state directory");
    let connection =
        rusqlite::Connection::open(state.join("backup.sqlite")).expect("a database to open");
    connection
        .execute_batch(
            "CREATE TABLE privacy_obligations (
                 id                 INTEGER PRIMARY KEY AUTOINCREMENT,
                 privacy_generation INTEGER NOT NULL,
                 kind               TEXT NOT NULL,
                 target_key         TEXT NOT NULL,
                 recorded_at_ms     INTEGER NOT NULL
             );",
        )
        .expect("the half-written store");
    drop(connection);

    let message = match BackupStore::open(&state) {
        Ok(_) => panic!("a store whose creation did not finish was opened"),
        Err(refusal) => refusal.to_string(),
    };
    assert!(
        message.contains("no schema version"),
        "the refusal says what it found: {message}"
    );
}

#[test]
fn a_generation_that_moved_stops_the_publication_and_the_dispatch_of_older_work() {
    let root = tempfile::tempdir().expect("a disposable directory on the internal disk");
    let state = root.path().join("state");
    std::fs::create_dir_all(&state).expect("the state directory");
    let environment = Environment::at(&state);
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
            TimestampMs::new(5_000),
        )
        .expect("the generation is admitted");
    assert_eq!(admitted.privacy_generation, 0);
    environment
        .service()
        .note_dispatched(admitted.sequence, EXECUTOR, TimestampMs::new(5_100))
        .expect("its upload leaves while the generation still holds");
    // A second generation, still queued, so there is a claim left to make afterwards.
    let queued = environment
        .service()
        .admit(
            &producer.seal(7, &objects),
            &objects,
            producer.writer.key_id(),
            TimestampMs::new(5_200),
        )
        .expect("a second generation is admitted");

    // The privacy generation in force moves on while this work is under way, as it does when a
    // fence goes up and comes down again. Everything below reads that durable value inside the
    // transaction it is about to change state in, so none of it can act on the 0 it read earlier.
    rusqlite::Connection::open(state.join("backup.sqlite"))
        .expect("the backup store")
        .execute(
            "UPDATE privacy_state SET current_generation = 4 WHERE id = 0",
            [],
        )
        .expect("the generation in force moves on");

    // The dispatch claim. It is refused, so that work never leaves this host at all.
    let refusal = environment
        .service()
        .note_dispatched(queued.sequence, EXECUTOR, TimestampMs::new(6_500))
        .expect_err("a claim on work admitted under a generation this host has moved past");
    assert!(
        refusal
            .to_string()
            .contains("admitted under privacy generation 0, and this host is at 4"),
        "{refusal}"
    );

    // The publication enqueue. Every object is acknowledged, which would ordinarily enqueue the
    // descriptor; here it enqueues nothing and production is prohibited with the reason.
    let manifest_id = sealed.descriptor.encrypted_manifest.object_id;
    for object_id in [objects[0].object_id(), manifest_id] {
        environment
            .service()
            .note_object_uploaded(
                admitted.sequence,
                archive_id(),
                BackupGeneration::new(1),
                object_id,
                TimestampMs::new(7_000),
            )
            .expect("the object is acknowledged");
    }
    assert!(
        environment
            .service()
            .attempts()
            .expect("a read")
            .iter()
            .all(|attempt| attempt.step != Step::Publish),
        "no publication for work the generation in force has moved past"
    );
    let record = environment
        .service()
        .generation(archive_id(), BackupGeneration::new(1))
        .expect("a read")
        .expect("the generation");
    assert_eq!(record.production, Production::Cancelled);
    assert!(
        record
            .detail
            .as_deref()
            .expect("a reason")
            .contains("this host is at 4")
    );
    assert_eq!(
        record.remote,
        Remote::Objects,
        "what the service holds is recorded whatever production may do"
    );

    // Admission. A caller has no generation to offer, so the only one that can be stamped is the
    // one the store is at.
    let second = environment
        .service()
        .admit(
            &producer.seal(2, &objects),
            &objects,
            producer.writer.key_id(),
            TimestampMs::new(8_000),
        )
        .expect("fresh work is admitted");
    assert_eq!(second.privacy_generation, 4);
    let fresh = environment
        .service()
        .outbox()
        .expect("a read")
        .into_iter()
        .find(|attempt| attempt.sequence == second.sequence)
        .expect("the fresh attempt");
    assert_eq!(fresh.privacy_generation, 4);
    assert_eq!(fresh.backup_generation, BackupGeneration::new(2));
}

#[test]
fn an_acknowledgement_ends_no_transfer_and_a_finished_one_ends_only_itself() {
    let environment = Environment::open();
    let producer = Producer::generate();
    environment
        .service()
        .enrol_writer(producer.writer.key_id(), archive_id(), TimestampMs::new(1))
        .expect("the writer is enrolled");
    let objects = [stage(1, "a.cbor", b"one")];
    let sealed = producer.seal(1, &objects);
    let first = environment
        .service()
        .admit(
            &sealed,
            &objects,
            producer.writer.key_id(),
            TimestampMs::new(5_000),
        )
        .expect("the generation is admitted");
    environment
        .service()
        .note_dispatched(
            first.sequence,
            "the first transport",
            TimestampMs::new(5_100),
        )
        .expect("the first upload is in flight");

    // A restart resumes it as a second attempt, and that one goes out too. Two executors are now
    // sending the same objects, and neither one's end is established.
    environment
        .service()
        .reconcile(TimestampMs::new(5_200))
        .expect("reconciliation");
    let second = environment
        .service()
        .outbox()
        .expect("a read")
        .into_iter()
        .find(|attempt| attempt.status == AttemptStatus::Queued)
        .expect("the resumed attempt");
    environment
        .service()
        .note_dispatched(
            second.sequence,
            "the second transport",
            TimestampMs::new(5_300),
        )
        .expect("the second upload is in flight");

    environment
        .service()
        .raise_fence(PrivacyGeneration::new(1), TimestampMs::new(6_000))
        .expect("the fence is raised");
    environment
        .service()
        .run_cleanup(PrivacyGeneration::new(1), TimestampMs::new(6_100))
        .expect("the staged ciphertext goes");

    // The first transport delivers every acknowledgement. Every object of the generation is now at
    // the service, and that ends nothing at all: both transfers are still out there.
    let manifest_id = sealed.descriptor.encrypted_manifest.object_id;
    for object_id in [objects[0].object_id(), manifest_id] {
        environment
            .service()
            .note_object_uploaded(
                first.sequence,
                archive_id(),
                BackupGeneration::new(1),
                object_id,
                TimestampMs::new(7_000),
            )
            .expect("the object is acknowledged");
    }
    assert_eq!(
        environment.service().outbox().expect("a read").len(),
        2,
        "a complete set of objects is not the end of any transfer"
    );

    // The first transport says *its* transfer finished. That is evidence about that one attempt
    // and about no other: the second transport may still be pushing bytes, and a cleanup reported
    // complete over it would be a claim this host cannot make.
    environment
        .service()
        .note_attempt_accepted(first.sequence, TimestampMs::new(7_100))
        .expect("the first transport reports it finished");
    let open = environment.service().outbox().expect("a read");
    assert_eq!(open.len(), 1, "the second transfer is still out there");
    assert_eq!(open[0].sequence, second.sequence);
    assert_eq!(open[0].executor.as_deref(), Some("the second transport"));

    // And the second transport now acknowledges one object of its own while the rest of its
    // transfer runs. The generation has nothing outstanding, which says nothing about this
    // executor: its attempt keeps its place and its obligation.
    environment
        .service()
        .note_object_uploaded(
            second.sequence,
            archive_id(),
            BackupGeneration::new(1),
            objects[0].object_id(),
            TimestampMs::new(7_200),
        )
        .expect("the object is acknowledged");
    let open = environment.service().outbox().expect("a read");
    assert_eq!(open.len(), 1);
    assert_eq!(open[0].sequence, second.sequence);
    assert_eq!(open[0].status, AttemptStatus::Dispatched);
    let owed = environment.service().obligations().expect("a read");
    assert!(
        owed.iter().any(|obligation| {
            obligation.kind == ObligationKind::ResolveUpload
                && obligation.entry_sequence == Some(second.sequence)
        }),
        "the second attempt keeps its own obligation: {owed:?}"
    );
    {
        let subsystems: Vec<&dyn PrivacySubsystem> = vec![&environment.service];
        assert!(!PrivacyMode::reconcile(&subsystems).is_complete());
    }
    assert!(matches!(
        environment
            .service()
            .release_fence(
                PrivacyGeneration::new(1),
                PrivacyGeneration::new(2),
                TimestampMs::new(7_500),
            )
            .expect("the release is attempted"),
        FenceRelease::Pending { .. }
    ));

    // Only that exact transfer's own end settles it.
    environment
        .service()
        .note_attempt_stopped(second.sequence, TimestampMs::new(8_000))
        .expect("the second transport stopped");
    assert!(environment.service().outbox().expect("a read").is_empty());
    assert!(
        environment
            .service()
            .obligations()
            .expect("a read")
            .is_empty()
    );
}

#[test]
fn a_generation_whose_last_attempt_stopped_is_given_another_one() {
    let environment = Environment::open();
    let producer = Producer::generate();
    environment
        .service()
        .enrol_writer(producer.writer.key_id(), archive_id(), TimestampMs::new(1))
        .expect("the writer is enrolled");
    let objects = [stage(1, "a.cbor", b"one")];
    let admitted = environment
        .service()
        .admit(
            &producer.seal(1, &objects),
            &objects,
            producer.writer.key_id(),
            TimestampMs::new(5_000),
        )
        .expect("the generation is admitted");
    environment
        .service()
        .note_dispatched(admitted.sequence, EXECUTOR, TimestampMs::new(5_100))
        .expect("the upload is in flight");

    // The transport stops and no answer arrives. That ends the attempt and nothing else: what a
    // service may hold is written down, and production of the generation is not over.
    environment
        .service()
        .note_attempt_stopped(admitted.sequence, TimestampMs::new(6_000))
        .expect("the transport stopped");
    assert!(environment.service().outbox().expect("a read").is_empty());
    let record = environment
        .service()
        .generation(archive_id(), BackupGeneration::new(1))
        .expect("a read")
        .expect("the generation");
    assert_eq!(record.production, Production::Producing);
    assert_eq!(record.remote, Remote::Unknown);

    // Nothing is carrying it now, so reconciliation gives it something that will. Work this host
    // took on does not sit there waiting for a privacy fence to clear it away.
    let outcome = environment
        .service()
        .reconcile(TimestampMs::new(7_000))
        .expect("reconciliation");
    assert_eq!(
        outcome.resumed,
        vec![(archive_id(), BackupGeneration::new(1))]
    );
    assert!(outcome.unanswered.is_empty(), "nothing is still out there");
    let open = environment.service().outbox().expect("a read");
    assert_eq!(open.len(), 1);
    assert_eq!(open[0].status, AttemptStatus::Queued);
    assert_eq!(open[0].step, Step::Upload, "its objects have not arrived");
    assert_ne!(open[0].sequence, admitted.sequence);

    // And a second reconciliation adds nothing, because this host already holds one.
    environment
        .service()
        .reconcile(TimestampMs::new(7_500))
        .expect("reconciliation");
    assert_eq!(environment.service().outbox().expect("a read").len(), 1);
}

#[test]
fn a_publication_this_host_cannot_account_for_ends_production_rather_than_being_retried() {
    let environment = Environment::open();
    let producer = Producer::generate();
    environment
        .service()
        .enrol_writer(producer.writer.key_id(), archive_id(), TimestampMs::new(1))
        .expect("the writer is enrolled");
    let objects = [stage(1, "a.cbor", b"one")];
    let admitted = environment
        .service()
        .admit(
            &producer.seal(1, &objects),
            &objects,
            producer.writer.key_id(),
            TimestampMs::new(5_000),
        )
        .expect("the generation is admitted");
    environment
        .service()
        .note_dispatched(admitted.sequence, EXECUTOR, TimestampMs::new(5_100))
        .expect("the upload is in flight");
    let first = dispatch_publication(
        environment.service(),
        admitted.sequence,
        BackupGeneration::new(1),
        TimestampMs::new(5_200),
    );

    // The publication stops with no answer. Whether a service holds that descriptor is not
    // something this host can establish, so production of the generation is over: nothing sends a
    // second descriptor on the strength of not knowing.
    environment
        .service()
        .note_attempt_stopped(first, TimestampMs::new(6_000))
        .expect("the transport stopped");
    let record = environment
        .service()
        .generation(archive_id(), BackupGeneration::new(1))
        .expect("a read")
        .expect("the generation");
    assert_eq!(record.production, Production::Cancelled);
    assert_eq!(record.remote, Remote::Unknown);
    let outcome = environment
        .service()
        .reconcile(TimestampMs::new(6_100))
        .expect("reconciliation");
    assert!(
        outcome.resumed.is_empty(),
        "an unknown publication outcome is not retried: {outcome:?}"
    );
    assert!(
        environment.service().outbox().expect("a read").is_empty(),
        "no replacement descriptor is enqueued"
    );
    assert!(
        environment
            .service()
            .exported()
            .iter()
            .any(|artifact| artifact.kind == "backup archive, outcome unknown"),
        "a copy this host cannot account for is shown rather than pretended away"
    );

    // The answer to that attempt arrives afterwards. It is about that one attempt: what a service
    // holds is written down, the attempt keeps the outcome it was given, and no descriptor of this
    // host's becomes current.
    assert_eq!(
        environment
            .service()
            .note_published(first, PrivacyGeneration::INITIAL, TimestampMs::new(7_000))
            .expect("a late answer about the attempt that stopped"),
        Publication::RetainedArtifact {
            privacy_generation: 0
        }
    );
    let stopped = environment
        .service()
        .attempts()
        .expect("a read")
        .into_iter()
        .find(|attempt| attempt.sequence == first)
        .expect("the attempt that stopped");
    assert_eq!(
        stopped.outcome,
        Some(AttemptOutcome::Stopped),
        "an attempt that ended keeps how it ended"
    );
    let record = environment
        .service()
        .generation(archive_id(), BackupGeneration::new(1))
        .expect("a read")
        .expect("the generation");
    assert_eq!(record.remote, Remote::Published);
    assert_eq!(record.production, Production::Cancelled);
    assert!(environment.service().outbox().expect("a read").is_empty());
}

#[test]
fn a_finished_publication_takes_back_the_work_this_host_had_not_yet_sent() {
    let environment = Environment::open();
    let producer = Producer::generate();
    environment
        .service()
        .enrol_writer(producer.writer.key_id(), archive_id(), TimestampMs::new(1))
        .expect("the writer is enrolled");
    let objects = [stage(1, "a.cbor", b"one")];
    let admitted = environment
        .service()
        .admit(
            &producer.seal(1, &objects),
            &objects,
            producer.writer.key_id(),
            TimestampMs::new(5_000),
        )
        .expect("the generation is admitted");
    environment
        .service()
        .note_dispatched(admitted.sequence, EXECUTOR, TimestampMs::new(5_100))
        .expect("the upload is in flight");

    // A restart puts a second upload attempt in this host's hands while the first is still out
    // there, and the first one then delivers everything and finishes.
    environment
        .service()
        .reconcile(TimestampMs::new(5_200))
        .expect("reconciliation");
    let queued = environment
        .service()
        .outbox()
        .expect("a read")
        .into_iter()
        .find(|attempt| attempt.status == AttemptStatus::Queued)
        .expect("the resumed upload");
    let publication = dispatch_publication(
        environment.service(),
        admitted.sequence,
        BackupGeneration::new(1),
        TimestampMs::new(5_300),
    );

    // The descriptor is accepted, so production is over. The upload this host never handed over is
    // work it will never do: it is taken back rather than left queued behind a gate that refuses
    // it from here on.
    assert_eq!(
        environment
            .service()
            .note_published(
                publication,
                PrivacyGeneration::INITIAL,
                TimestampMs::new(7_000)
            )
            .expect("the service accepted it"),
        Publication::Recorded
    );
    assert!(environment.service().outbox().expect("a read").is_empty());
    let taken_back = environment
        .service()
        .attempts()
        .expect("a read")
        .into_iter()
        .find(|attempt| attempt.sequence == queued.sequence)
        .expect("the resumed upload");
    assert_eq!(taken_back.status, AttemptStatus::Terminal);
    assert_eq!(taken_back.outcome, Some(AttemptOutcome::Cancelled));
    let record = environment
        .service()
        .generation(archive_id(), BackupGeneration::new(1))
        .expect("a read")
        .expect("the generation");
    assert_eq!(record.production, Production::Complete);
    assert_eq!(record.remote, Remote::Published);
}

#[test]
fn an_answer_that_arrives_while_this_host_is_stopped_is_finished_at_the_next_reconciliation() {
    let root = tempfile::tempdir().expect("a disposable directory on the internal disk");
    let state = root.path().join("state");
    std::fs::create_dir_all(&state).expect("the state directory");
    let producer = Producer::generate();
    let objects = [stage(1, "a.cbor", b"one")];
    let sealed = producer.seal(1, &objects);
    let publication;
    {
        let service = BackupService::open(&state).expect("a backup service");
        service
            .reconcile(TimestampMs::new(4_000))
            .expect("the startup reconciliation a service opens unready without");
        service
            .enrol_writer(producer.writer.key_id(), archive_id(), TimestampMs::new(1))
            .expect("the writer is enrolled");
        let admitted = service
            .admit(
                &sealed,
                &objects,
                producer.writer.key_id(),
                TimestampMs::new(5_000),
            )
            .expect("the generation is admitted");
        service
            .note_dispatched(admitted.sequence, EXECUTOR, TimestampMs::new(5_100))
            .expect("the upload is in flight");
        publication = dispatch_publication(
            &service,
            admitted.sequence,
            BackupGeneration::new(1),
            TimestampMs::new(5_200),
        );
    }

    // The answer arrives before this process has read back what the last one left, so the service
    // is unready and withholds completion. The artifact is recorded all the same.
    let service = BackupService::open(&state).expect("the service opens again");
    assert_eq!(
        service
            .note_published(
                publication,
                PrivacyGeneration::INITIAL,
                TimestampMs::new(6_000)
            )
            .expect("an answer while this host is stopped"),
        Publication::RetainedArtifact {
            privacy_generation: 0
        }
    );
    let record = service
        .generation(archive_id(), BackupGeneration::new(1))
        .expect("a read")
        .expect("the generation");
    assert_eq!(record.remote, Remote::Published);
    assert_ne!(record.production, Production::Complete);

    // Nothing delivers that answer again, so reconciliation finishes the production it belongs to
    // rather than leaving a generation producing with nothing to carry it.
    let outcome = service
        .reconcile(TimestampMs::new(6_500))
        .expect("reconciliation");
    assert_eq!(
        outcome.completed,
        vec![(archive_id(), BackupGeneration::new(1))]
    );
    assert!(outcome.resumed.is_empty());
    assert!(service.outbox().expect("a read").is_empty());
    let record = service
        .generation(archive_id(), BackupGeneration::new(1))
        .expect("a read")
        .expect("the generation");
    assert_eq!(record.production, Production::Complete);

    // And a second reconciliation changes nothing.
    let outcome = service
        .reconcile(TimestampMs::new(7_000))
        .expect("reconciliation");
    assert!(outcome.is_empty(), "{outcome:?}");
}

#[test]
fn a_host_that_could_not_stop_finishes_no_production_at_reconciliation_either() {
    let root = tempfile::tempdir().expect("a disposable directory on the internal disk");
    let state = root.path().join("state");
    std::fs::create_dir_all(&state).expect("the state directory");
    let service = BackupService::open(&state).expect("a backup service");
    service
        .reconcile(TimestampMs::new(4_000))
        .expect("the startup reconciliation a service opens unready without");
    let producer = Producer::generate();
    service
        .enrol_writer(producer.writer.key_id(), archive_id(), TimestampMs::new(1))
        .expect("the writer is enrolled");
    let objects = [stage(1, "a.cbor", b"one")];
    let admitted = service
        .admit(
            &producer.seal(1, &objects),
            &objects,
            producer.writer.key_id(),
            TimestampMs::new(5_000),
        )
        .expect("the generation is admitted");
    service
        .note_dispatched(admitted.sequence, EXECUTOR, TimestampMs::new(5_100))
        .expect("the upload is in flight");
    let publication = dispatch_publication(
        &service,
        admitted.sequence,
        BackupGeneration::new(1),
        TimestampMs::new(5_200),
    );

    // Privacy mode asks this host to stop and the store will not take the request, so the step is
    // owed and production is withheld from here on.
    service.set_query_only(true).expect("query_only pragma");
    service
        .raise_fence(PrivacyGeneration::new(1), TimestampMs::new(6_000))
        .expect_err("a store that will not write says so");
    service.set_query_only(false).expect("query_only pragma");
    assert!(service.unready().is_some());

    // The answer arrives. It is recorded as a retained artifact, and this host completes no
    // production of its own while it is still withholding.
    assert_eq!(
        service
            .note_published(
                publication,
                PrivacyGeneration::INITIAL,
                TimestampMs::new(6_500)
            )
            .expect("an answer while this host is stopped"),
        Publication::RetainedArtifact {
            privacy_generation: 0
        }
    );

    // Reconciliation is no exception. It reads the store back and still finishes nothing, because
    // the step this host could not take is still owed.
    let outcome = service
        .reconcile(TimestampMs::new(7_000))
        .expect("reconciliation");
    assert!(
        outcome.completed.is_empty(),
        "a host that could not stop finishes nothing: {outcome:?}"
    );
    let record = service
        .generation(archive_id(), BackupGeneration::new(1))
        .expect("a read")
        .expect("the generation");
    assert_ne!(record.production, Production::Complete);
    assert_eq!(record.remote, Remote::Published);
    assert!(service.unready().is_some());

    // The step succeeds at the next attempt. The fence is what it was asked for, so production of
    // that generation is over for good rather than completed, and what a service holds of it stays
    // written down as the retained artifact it is.
    service
        .raise_fence(PrivacyGeneration::new(1), TimestampMs::new(7_500))
        .expect("the fence goes up");
    assert!(service.unready().is_none(), "the step it owed is taken");
    let outcome = service
        .reconcile(TimestampMs::new(8_000))
        .expect("reconciliation");
    assert!(outcome.completed.is_empty());
    let record = service
        .generation(archive_id(), BackupGeneration::new(1))
        .expect("a read")
        .expect("the generation");
    assert_eq!(record.production, Production::Cancelled);
    assert_eq!(record.remote, Remote::Published);
}

#[test]
fn an_answer_is_refused_for_work_of_a_kind_or_a_state_it_cannot_be_about() {
    let environment = Environment::open();
    let producer = Producer::generate();
    environment
        .service()
        .enrol_writer(producer.writer.key_id(), archive_id(), TimestampMs::new(1))
        .expect("the writer is enrolled");
    let objects = [stage(1, "a.cbor", b"one")];
    let admitted = environment
        .service()
        .admit(
            &producer.seal(1, &objects),
            &objects,
            producer.writer.key_id(),
            TimestampMs::new(5_000),
        )
        .expect("the generation is admitted");

    // Nothing has left this host yet, so no service can be answering for any of it.
    let never_sent = environment
        .service()
        .note_published(
            admitted.sequence,
            PrivacyGeneration::INITIAL,
            TimestampMs::new(5_100),
        )
        .expect_err("a queued attempt has no answer");
    assert!(never_sent.to_string().contains("objects and not its"));
    let not_out = environment
        .service()
        .note_attempt_accepted(admitted.sequence, TimestampMs::new(5_100))
        .expect_err("a queued attempt has no answer");
    assert!(not_out.to_string().contains("left this host"));

    environment
        .service()
        .note_dispatched(admitted.sequence, EXECUTOR, TimestampMs::new(5_200))
        .expect("the upload is in flight");
    let publication = dispatch_publication(
        environment.service(),
        admitted.sequence,
        BackupGeneration::new(1),
        TimestampMs::new(5_300),
    );

    // A publication is answered through the call that records what a service holds, and never
    // through the one that only ends an upload: an acceptance recorded without the artifact would
    // end the attempt and leave nothing saying the archive is at a service.
    let wrong_call = environment
        .service()
        .note_attempt_accepted(publication, TimestampMs::new(5_400))
        .expect_err("a publication is not accepted here");
    assert!(wrong_call.to_string().contains("what a service holds"));
    let record = environment
        .service()
        .generation(archive_id(), BackupGeneration::new(1))
        .expect("a read")
        .expect("the generation");
    assert_eq!(
        record.remote,
        Remote::Objects,
        "nothing was recorded by the refused call"
    );
    assert_eq!(
        environment
            .service()
            .attempts()
            .expect("a read")
            .into_iter()
            .find(|attempt| attempt.sequence == publication)
            .expect("the publication")
            .status,
        AttemptStatus::Dispatched
    );

    // And an upload is not answered through the publication call either.
    let wrong_step = environment
        .service()
        .note_published(
            admitted.sequence,
            PrivacyGeneration::INITIAL,
            TimestampMs::new(5_500),
        )
        .expect_err("an upload attempt carries no descriptor");
    assert!(wrong_step.to_string().contains("objects and not its"));

    // A repeated acceptance of the same upload is the same answer again, and changes nothing.
    environment
        .service()
        .note_attempt_accepted(admitted.sequence, TimestampMs::new(5_600))
        .expect("the same answer again");
    let attempts = environment.service().attempts().expect("a read");
    let upload = attempts
        .iter()
        .find(|attempt| attempt.sequence == admitted.sequence)
        .expect("the upload");
    assert_eq!(upload.outcome, Some(AttemptOutcome::Accepted));
    assert_eq!(upload.status, AttemptStatus::Terminal);
}

#[test]
fn one_cancellation_answers_every_fence_that_wrote_it_down() {
    let environment = Environment::open();
    let producer = Producer::generate();
    environment
        .service()
        .enrol_writer(producer.writer.key_id(), archive_id(), TimestampMs::new(1))
        .expect("the writer is enrolled");
    let objects = [stage(1, "a.cbor", b"one")];
    environment
        .service()
        .admit(
            &producer.seal(1, &objects),
            &objects,
            producer.writer.key_id(),
            TimestampMs::new(5_000),
        )
        .expect("the generation is admitted");

    // Two fences over the same queued attempt, before either cancellation runs. Each writes its
    // own cancellation down, because each is owed one.
    for generation in [1, 3] {
        environment
            .service()
            .raise_fence(PrivacyGeneration::new(generation), TimestampMs::new(6_000))
            .expect("the fence is raised");
    }
    let cancellations = environment
        .service()
        .obligations()
        .expect("a read")
        .into_iter()
        .filter(|obligation| obligation.kind == ObligationKind::CancelEntry)
        .count();
    assert_eq!(cancellations, 2, "one per fence");

    // The attempt is taken back once, and that one cancellation is the answer to both. A handler
    // that ended only the row it was looking at would leave the other owed for ever, and the
    // bookkeeping of every generation would wait on it.
    environment
        .service()
        .cancel_undispatched_work(PrivacyGeneration::new(3), TimestampMs::new(6_500))
        .expect("the cancellation runs");
    environment
        .service()
        .run_cleanup(PrivacyGeneration::new(3), TimestampMs::new(6_600))
        .expect("the cleanup runs");
    assert!(
        environment
            .service()
            .obligations()
            .expect("a read")
            .is_empty(),
        "nothing is owed under either fence"
    );
    for (fence, resumed) in [(1, 2), (3, 4)] {
        assert_eq!(
            environment
                .service()
                .release_fence(
                    PrivacyGeneration::new(fence),
                    PrivacyGeneration::new(resumed),
                    TimestampMs::new(7_000),
                )
                .expect("a release"),
            FenceRelease::Released
        );
    }
}

/// Makes a staging directory refuse or allow the removal of what is in it.
///
/// Unix only, and so are the two checks that need it: there is no portable way to deny a directory
/// write, so they are compiled out where there is none rather than failing there.
#[cfg(unix)]
fn set_directory_writable(directory: &std::path::Path, writable: bool) {
    use std::os::unix::fs::PermissionsExt as _;

    let mode = if writable { 0o700 } else { 0o500 };
    std::fs::set_permissions(directory, std::fs::Permissions::from_mode(mode))
        .expect("the staging directory's permissions");
}

/// Holds a directory open through a handle that shares no writing with any other.
///
/// Windows only. A name can still be created or removed in the directory while it is held, since
/// that opens the name rather than the directory, but nothing can open the directory itself with a
/// right to add to it, which is what a flush of it has to do there.
#[cfg(windows)]
fn hold_without_shared_writing(directory: &std::path::Path) -> std::fs::File {
    use std::os::windows::fs::OpenOptionsExt as _;

    /// The right to list a directory, which is all the handle holds.
    const FILE_LIST_DIRECTORY: u32 = 0x0001;
    /// Reading is shared with other handles.
    const FILE_SHARE_READ: u32 = 0x0001;
    /// Deleting is shared; writing is not.
    const FILE_SHARE_DELETE: u32 = 0x0004;
    /// What lets a program open a directory at all.
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;

    std::fs::OpenOptions::new()
        .access_mode(FILE_LIST_DIRECTORY)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(directory)
        .expect("the directory is held")
}

// ---------------------------------------------------------------------------------------------
// Uploads in progress: what lets an upload go on at its next part after a restart.
// ---------------------------------------------------------------------------------------------

/// A state directory on the internal disk, which goes with the test.
fn state_directory() -> (tempfile::TempDir, std::path::PathBuf) {
    let root = tempfile::tempdir().expect("a disposable directory on the internal disk");
    let state = root.path().join("state");
    std::fs::create_dir_all(&state).expect("the state directory");
    (root, state)
}

/// A store on the internal disk holding one generation whose upload attempt has left this host.
///
/// Returns the member that is uploading and that attempt's sequence. The service that wrote it is
/// gone, so a test reads and writes the store itself.
fn a_store_with_an_upload_in_flight(state: &std::path::Path) -> (BackupObjectId, u64) {
    let producer = Producer::generate();
    let objects = [stage(1, "a.cbor", b"one")];
    let sealed = producer.seal(1, &objects);
    let service = BackupService::open(state).expect("a backup service");
    service
        .reconcile(TimestampMs::new(4_000))
        .expect("the startup reconciliation a service opens unready without");
    service
        .enrol_writer(producer.writer.key_id(), archive_id(), TimestampMs::new(1))
        .expect("the writer is enrolled");
    let admitted = service
        .admit(
            &sealed,
            &objects,
            producer.writer.key_id(),
            TimestampMs::new(5_000),
        )
        .expect("the generation is admitted");
    service
        .note_dispatched(admitted.sequence, EXECUTOR, TimestampMs::new(5_100))
        .expect("the upload is in flight");
    (objects[0].object_id(), admitted.sequence)
}

#[test]
fn an_upload_in_progress_is_kept_across_a_restart_until_its_object_is_held() {
    let (_root, state) = state_directory();
    let (member, upload) = a_store_with_an_upload_in_flight(&state);
    let first = BackupGeneration::new(1);
    {
        let mut store = BackupStore::open(&state).expect("the backup store");
        store
            .record_upload(upload, archive_id(), first, member, "upload-one")
            .expect("the upload the service created is recorded");
        store
            .note_parts_acknowledged(archive_id(), first, member, "upload-one", 2)
            .expect("two parts are acknowledged");
        // A late answer names fewer parts than are already written down, and changes nothing.
        store
            .note_parts_acknowledged(archive_id(), first, member, "upload-one", 1)
            .expect("a late answer is taken and changes nothing");
        // An answer about an upload this host did not record is not about this one.
        let other = store.note_parts_acknowledged(archive_id(), first, member, "upload-two", 3);
        assert!(
            matches!(other, Err(ControllerError::InvalidArgument(_))),
            "{other:?}"
        );
        // One upload of an object at a time.
        let second = store.record_upload(upload, archive_id(), first, member, "upload-two");
        assert!(second.is_err(), "{second:?}");
        // And only an upload attempt of that generation that left this host records one.
        let elsewhere = store.record_upload(
            upload,
            archive_id(),
            BackupGeneration::new(2),
            member,
            "upload-three",
        );
        assert!(
            matches!(elsewhere, Err(ControllerError::InvalidArgument(_))),
            "{elsewhere:?}"
        );
    }

    // A restart finds it where it was.
    let mut store = BackupStore::open(&state).expect("the store opens again");
    let kept = UploadRecord {
        archive_id: archive_id(),
        backup_generation: first,
        object_id: member,
        upload_id: "upload-one".to_owned(),
        parts_acknowledged: 2,
    };
    assert_eq!(
        store.upload(archive_id(), first, member).expect("a read"),
        Some(kept.clone())
    );
    assert_eq!(store.uploads().expect("a read"), vec![kept]);

    // Forgetting names the upload: another identity forgets nothing.
    assert!(
        !store
            .forget_upload(archive_id(), first, member, "upload-two")
            .expect("a write")
    );
    assert!(
        store
            .upload(archive_id(), first, member)
            .expect("a read")
            .is_some()
    );

    // The object arriving ends its upload in the same write, and an object a service holds takes
    // no upload again.
    store
        .note_object_uploaded(upload, archive_id(), first, member, TimestampMs::new(6_000))
        .expect("the member is acknowledged");
    assert_eq!(
        store.upload(archive_id(), first, member).expect("a read"),
        None
    );
    let again = store.record_upload(upload, archive_id(), first, member, "upload-four");
    assert!(again.is_err(), "{again:?}");
}

#[test]
fn direct_sql_cannot_replace_an_upload_or_unsay_what_the_service_acknowledged() {
    let (_root, state) = state_directory();
    let (member, upload) = a_store_with_an_upload_in_flight(&state);
    {
        let mut store = BackupStore::open(&state).expect("the backup store");
        store
            .record_upload(
                upload,
                archive_id(),
                BackupGeneration::new(1),
                member,
                "upload-one",
            )
            .expect("the upload is recorded");
        store
            .note_parts_acknowledged(
                archive_id(),
                BackupGeneration::new(1),
                member,
                "upload-one",
                2,
            )
            .expect("two parts are acknowledged");
    }

    // These rules live in the database. An upload keeps its object and the identity the service
    // gave it, what the service acknowledged of it is never unsaid, a second upload of the same
    // object is written neither beside it nor over it, and an upload is of an object this host
    // staged.
    let connection =
        rusqlite::Connection::open(state.join("backup.sqlite")).expect("the backup store");
    connection
        .pragma_update(None, "foreign_keys", "ON")
        .expect("foreign keys, as the store opens its own connection");
    for statement in [
        "UPDATE uploads SET parts_acknowledged = 1",
        "UPDATE uploads SET upload_id = 'upload-two'",
        "UPDATE uploads SET backup_generation = 2",
        "UPDATE uploads SET object_id = X'000102030405060708090a0b0c0d0e0f'",
        "INSERT INTO uploads
             (archive_id, backup_generation, object_id, upload_id, parts_acknowledged)
         SELECT archive_id, backup_generation, object_id, 'upload-two', 0 FROM uploads",
        "INSERT OR REPLACE INTO uploads
             (archive_id, backup_generation, object_id, upload_id, parts_acknowledged)
         SELECT archive_id, backup_generation, object_id, 'upload-two', 0 FROM uploads",
        "INSERT INTO uploads
             (archive_id, backup_generation, object_id, upload_id, parts_acknowledged)
         SELECT archive_id, backup_generation, X'000102030405060708090a0b0c0d0e0f',
                'upload-three', 0
           FROM uploads",
    ] {
        let refused = connection.execute(statement, []);
        assert!(refused.is_err(), "{statement} was permitted: {refused:?}");
    }
    let member_bytes = member.get().as_bytes().to_vec();
    // An identity is text the service gave, never an empty one.
    let blank = connection.execute(
        "INSERT INTO uploads
             (archive_id, backup_generation, object_id, upload_id, parts_acknowledged)
         SELECT archive_id, backup_generation, object_id, '', 0 FROM objects
          WHERE object_id <> ?1",
        rusqlite::params![member_bytes],
    );
    assert!(blank.is_err(), "an upload without an identity: {blank:?}");

    // An object a service holds takes no upload.
    connection
        .execute("DELETE FROM uploads", [])
        .expect("forgetting an upload is how one ends");
    connection
        .execute(
            "UPDATE objects SET acknowledged_bytes = encrypted_len WHERE object_id = ?1",
            rusqlite::params![member_bytes],
        )
        .expect("the member is held");
    let held = connection.execute(
        "INSERT INTO uploads
             (archive_id, backup_generation, object_id, upload_id, parts_acknowledged)
         SELECT archive_id, backup_generation, object_id, 'upload-five', 0 FROM objects
          WHERE object_id = ?1",
        rusqlite::params![member_bytes],
    );
    assert!(
        held.is_err(),
        "an upload of an object a service holds: {held:?}"
    );
}

/// How many objects of the upload table a database holds: the table and its rules.
fn upload_objects(connection: &rusqlite::Connection) -> i64 {
    connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master
              WHERE tbl_name = 'uploads' AND name NOT GLOB 'sqlite_*'",
            [],
            |row| row.get(0),
        )
        .expect("the schema")
}

fn schema_version(connection: &rusqlite::Connection) -> i64 {
    connection
        .query_row("SELECT version FROM schema_version", [], |row| row.get(0))
        .expect("the version")
}

/// Writes a store back to the schema the previous build wrote: this build's schema without the
/// upload table and its rules, at version 6.
fn as_version_6(state: &std::path::Path) {
    let connection =
        rusqlite::Connection::open(state.join("backup.sqlite")).expect("the backup store");
    connection
        .execute_batch(
            "DROP TRIGGER an_upload_is_never_replaced;
             DROP TRIGGER an_object_a_service_holds_takes_no_upload;
             DROP TRIGGER an_upload_keeps_what_it_is;
             DROP TRIGGER an_acknowledged_part_is_never_withdrawn;
             DROP TABLE uploads;
             UPDATE schema_version SET version = 6;",
        )
        .expect("the store is written back to version 6");
    assert_eq!(upload_objects(&connection), 0);
    assert_eq!(schema_version(&connection), 6);
}

/// A store the previous build wrote is brought to this build's schema once, by the step that adds
/// the upload table, and keeps everything it had recorded.
#[test]
fn a_version_6_store_is_brought_to_this_builds_schema_once_and_keeps_what_it_recorded() {
    let (_root, state) = state_directory();
    let (member, upload) = a_store_with_an_upload_in_flight(&state);
    let first = BackupGeneration::new(1);
    let (generations, attempts, objects) = {
        let store = BackupStore::open(&state).expect("the backup store");
        (
            store.generations().expect("a read"),
            store.attempts().expect("a read"),
            store.objects(archive_id(), first).expect("a read"),
        )
    };
    as_version_6(&state);

    let mut store = BackupStore::open(&state).expect("a version-6 store opens, brought forward");
    assert_eq!(store.generations().expect("a read"), generations);
    assert_eq!(store.attempts().expect("a read"), attempts);
    assert_eq!(store.objects(archive_id(), first).expect("a read"), objects);
    assert!(store.uploads().expect("a read").is_empty());
    store
        .record_upload(upload, archive_id(), first, member, "upload-one")
        .expect("the upload table takes an upload");
    drop(store);

    let connection =
        rusqlite::Connection::open(state.join("backup.sqlite")).expect("the backup store");
    assert_eq!(schema_version(&connection), SCHEMA_VERSION);
    assert_eq!(
        upload_objects(&connection),
        5,
        "the table and its four rules"
    );
    drop(connection);

    // Once: the next open finds this build's store and takes it as it is.
    let store = BackupStore::open(&state).expect("the store opens again");
    assert_eq!(store.uploads().expect("a read").len(), 1);
}

/// A store at version 6 that holds something this build does not define is refused as any other
/// store is, and the step that would have brought it forward leaves it exactly as it was.
#[test]
fn a_version_6_store_holding_a_rule_this_build_never_wrote_is_refused_and_left_at_version_6() {
    let (_root, state) = state_directory();
    a_store_with_an_upload_in_flight(&state);
    as_version_6(&state);
    let connection =
        rusqlite::Connection::open(state.join("backup.sqlite")).expect("the backup store");
    connection
        .execute_batch(
            "CREATE TRIGGER sqliteXforget AFTER INSERT ON writers
             BEGIN
                 DELETE FROM outbox WHERE status = 'terminal';
             END;",
        )
        .expect("the added rule is written");
    drop(connection);

    let message = match BackupStore::open(&state) {
        Ok(_) => panic!("a version-6 store holding a rule this build never wrote was opened"),
        Err(refusal) => refusal.to_string(),
    };
    assert!(
        message.contains("sqliteXforget"),
        "the refusal says what this build does not define: {message}"
    );
    let connection =
        rusqlite::Connection::open(state.join("backup.sqlite")).expect("the backup store");
    assert_eq!(schema_version(&connection), 6);
    assert_eq!(upload_objects(&connection), 0);
}
