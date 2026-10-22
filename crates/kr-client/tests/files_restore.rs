//! A restore to files, held to hostile data at its own interface.
//!
//! The service and the honest clients refuse a replayed or substituted generation themselves, so a
//! test through them would pass with the restore's own check removed. These tests serve what a
//! hostile service could: a source that answers with whatever the test scripts, signed by writers
//! the owner trusts wherever the claim is about something other than the signature.
//!
//! The kit, the bundle and the archive are sealed here with the production primitives, and the
//! restore is the one `kr backup restore` calls.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use kr_client::ClientError;
use kr_client::recovery::{
    BundleWrite, BundleWriter, BundleWritten, CandidateState, CheckpointRecorded, ExportSource,
    FilesRestore, MemberRefusal, MemberRole, MemberVerdict, OfflineExport, PublicationRefusal,
    RecoveryError, RestoreError, RestoreSource, SignInCause, SourceService, SourceSignIn,
    fresh_locator,
};
use kr_client::services::{ServiceFuture, SyncFetched, SyncPosition};
use kr_crypto::backup::{
    ArchivePlan, ArchiveRecipients, CollectionKind, Material, ObjectSource, seal_archive,
    stage_object,
};
use kr_crypto::kdf::RecoverySeed;
use kr_crypto::keys::{AuthorisationKeyPair, StoredEnvelopeKeyPair};
use kr_crypto::sign::{SigningTranscript, sign};
use kr_protocol::archive::{
    ARCHIVE_DESCRIPTOR_VERSION, ARCHIVE_MANIFEST_SCHEMA_VERSION, ArchiveCheckpoint,
    ArchiveDescriptor, ArchiveManifest, BACKUP_PUBLICATION_DOMAIN, BackupGenerationPublication,
    BackupGenerationPublicationPayload, CollectionLocator, DescriptorError, EncryptedObjectRef,
    KeyWrapContext, KeyWrapFormat, KeyWrapPurpose, MANIFEST_PAYLOAD_LIMITS, ManifestObject,
    ManifestPayload, RECOVERY_BUNDLE_SCHEMA_VERSION, RecoveryBundle, RecoveryKit, TrustedProducer,
    TrustedWriter,
};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::ids::{ArchiveId, BackupGeneration, BackupObjectId, DeviceId};
use kr_protocol::scalars::{Digest256, TimestampMs, U64, Uuid};

const ORIGIN: &str = "https://reach.kala.to";
const OTHER_ORIGIN: &str = "https://elsewhere.example";

fn id(byte: u8) -> Uuid {
    Uuid::from_bytes([byte; 16])
}

fn archive() -> ArchiveId {
    ArchiveId::new(id(0x11))
}

/* -------------------------------------------------------------------------- */
/* What the test seals                                                         */
/* -------------------------------------------------------------------------- */

/// The owner's side: a seed, the keys of the writer and the producer, and the collection.
struct World {
    seed: RecoverySeed,
    locator: String,
    writer: AuthorisationKeyPair,
    producer: StoredEnvelopeKeyPair,
}

/// One sealed generation: its signed publication and the objects it names.
struct Sealed {
    publication: BackupGenerationPublication,
    objects: BTreeMap<BackupObjectId, Vec<u8>>,
    manifest_object: BackupObjectId,
}

impl World {
    fn new() -> Self {
        Self {
            seed: RecoverySeed::generate().expect("a seed"),
            locator: fresh_locator().expect("a locator"),
            writer: AuthorisationKeyPair::generate().expect("a writer key"),
            producer: StoredEnvelopeKeyPair::generate().expect("a producer key"),
        }
    }

    fn kit(&self) -> RecoveryKit {
        self.seed
            .to_kit(vec![ORIGIN.to_owned()], self.locator.clone())
    }

    fn trusted(key: &AuthorisationKeyPair) -> TrustedWriter {
        TrustedWriter {
            writer_key_id: key.key_id(),
            signing_key: *key.public(),
            enrolled_at_ms: TimestampMs::new(1_000),
        }
    }

    fn trusted_producer(&self) -> TrustedProducer {
        TrustedProducer {
            sender_key_id: self.producer.key_id(),
            stored_envelope_key: *self.producer.public(),
            enrolled_at_ms: TimestampMs::new(1_000),
        }
    }

    /// The recipients of an archive that the owner can recover: the recovery recipient.
    fn recipients(&self) -> ArchiveRecipients {
        let mut recipients = ArchiveRecipients::new(CollectionKind::Owned);
        assert!(recipients.add_recovery(&self.seed.recipient().expect("a recipient")));
        recipients
    }

    /// An archive of the members `(name, plaintext)`, sealed as the production primitives seal one.
    fn seal(&self, generation: u64, members: &[(&str, Vec<u8>)]) -> Sealed {
        self.seal_with(
            generation,
            members,
            &self.writer,
            &self.writer,
            &self.recipients(),
        )
    }

    /// As [`Self::seal`], with the key that signs the manifest, the key that signs the publication
    /// and the recipients named.
    fn seal_with(
        &self,
        generation: u64,
        members: &[(&str, Vec<u8>)],
        manifest_writer: &AuthorisationKeyPair,
        publication_writer: &AuthorisationKeyPair,
        recipients: &ArchiveRecipients,
    ) -> Sealed {
        let staged: Vec<_> = members
            .iter()
            .enumerate()
            .map(|(at, (name, plaintext))| {
                stage_object(
                    &ObjectSource {
                        object_id: BackupObjectId::new(id(0x20 + u8::try_from(at).expect("few"))),
                        filename: name,
                        plaintext,
                    },
                    recipients.rotation(),
                )
                .expect("a staged object")
            })
            .collect();
        let manifest_object = BackupObjectId::new(id(0xf0));
        let sealed = seal_archive(
            manifest_writer,
            &self.producer,
            recipients,
            &ArchivePlan {
                archive_id: archive(),
                backup_generation: BackupGeneration::new(generation),
                owner_device_id: DeviceId::new(id(0x33)),
                manifest_object_id: manifest_object,
                created_at_ms: TimestampMs::new(1_700_000_000_000),
            },
            &staged,
        )
        .expect("a sealed archive");
        let mut objects: BTreeMap<_, _> = staged
            .iter()
            .map(|staged| (staged.object_id(), staged.bytes().to_vec()))
            .collect();
        objects.insert(manifest_object, sealed.encrypted_manifest.clone());
        Sealed {
            publication: publish(&sealed.descriptor, publication_writer),
            objects,
            manifest_object,
        }
    }

    /// An archive whose members are only declared: a manifest naming them with the stored lengths
    /// given, and no bytes behind them. A restore plans from the manifest and reads nothing else.
    fn seal_declared(&self, generation: u64, members: &[(&str, u64)]) -> Sealed {
        let recipient = self.seed.recipient().expect("a recipient");
        let recipient_key_id = kr_crypto::backup::recipient_key_id(recipient.public());
        let objects: Vec<ManifestObject> = members
            .iter()
            .enumerate()
            .map(|(at, (name, stored))| ManifestObject {
                object: EncryptedObjectRef {
                    object_id: BackupObjectId::new(Uuid::from_bytes({
                        let mut bytes = [0x40; 16];
                        bytes[14] = u8::try_from(at >> 8).expect("a byte");
                        bytes[15] = u8::try_from(at & 0xff).expect("a byte");
                        bytes
                    })),
                    encrypted_object_hash: Digest256::from_bytes([0x44; 32]),
                    encrypted_len: U64::new(*stored),
                },
                filename: (*name).to_owned(),
            })
            .collect();
        let manifest = kr_crypto::archive::sign_manifest(
            &self.writer,
            ArchiveManifest {
                schema_version: U64::new(ARCHIVE_MANIFEST_SCHEMA_VERSION),
                archive_id: archive(),
                owner_device_id: DeviceId::new(id(0x33)),
                backup_generation: BackupGeneration::new(generation),
                objects,
                created_at_ms: TimestampMs::new(1_700_000_000_000),
            },
        )
        .expect("a signed manifest");
        let payload = ManifestPayload {
            manifest,
            member_key_wraps: Vec::new(),
        };
        let bytes =
            kr_cbor::to_canonical_vec_within(&payload, &MANIFEST_PAYLOAD_LIMITS).expect("encoded");
        let manifest_object = BackupObjectId::new(id(0xf1));
        let encrypted = kr_crypto::archive::encrypt_object(manifest_object, &bytes)
            .expect("an encrypted manifest");
        let wrap = kr_crypto::archive::wrap_object_key(
            &self.producer,
            recipient.public(),
            KeyWrapContext {
                format: KeyWrapFormat::V1,
                purpose: KeyWrapPurpose::ManifestKey,
                archive_id: archive(),
                backup_generation: BackupGeneration::new(generation),
                object_id: manifest_object,
                encrypted_object_hash: encrypted.reference.encrypted_object_hash,
                sender_key_id: self.producer.key_id(),
                recipient_key_id,
            },
            &encrypted.key,
        )
        .expect("a wrap");
        let descriptor = ArchiveDescriptor {
            version: U64::new(ARCHIVE_DESCRIPTOR_VERSION),
            archive_id: archive(),
            backup_generation: BackupGeneration::new(generation),
            encrypted_manifest: encrypted.reference.clone(),
            manifest_key_wraps: vec![wrap],
        };
        Sealed {
            publication: publish(&descriptor, &self.writer),
            objects: BTreeMap::from([(manifest_object, encrypted.bytes)]),
            manifest_object,
        }
    }

    /// The sealed bundle the owner keeps at the locator, for the origin the kit names.
    fn bundle(&self, shape: &Shape) -> Vec<u8> {
        let mut writers = vec![Self::trusted(&self.writer)];
        writers.extend(shape.more_writers.iter().cloned());
        if let Some(only) = &shape.only_writers {
            writers.clone_from(only);
        }
        let producers = if shape.no_producer {
            Vec::new()
        } else {
            vec![self.trusted_producer()]
        };
        let bundle = RecoveryBundle {
            schema_version: U64::new(RECOVERY_BUNDLE_SCHEMA_VERSION),
            collections: shape
                .collections
                .clone()
                .unwrap_or_else(|| vec![collection(ORIGIN, "collection-1", archive())]),
            trusted_writers: writers.into_iter().collect(),
            trusted_producers: producers.into_iter().collect(),
            checkpoints: shape
                .checkpoint
                .iter()
                .chain(shape.more_checkpoints.iter())
                .cloned()
                .collect(),
            revision: U64::new(shape.revision.unwrap_or(3)),
            written_at_ms: TimestampMs::new(2_000),
        };
        let key = self
            .seed
            .bundle_key_for(&kr_protocol::archive::RecoveryContext {
                service_origin: shape.sealed_for_origin.unwrap_or(ORIGIN).to_owned(),
                bundle_locator: shape
                    .sealed_at_locator
                    .clone()
                    .unwrap_or_else(|| self.locator.clone()),
            })
            .expect("a bundle key");
        kr_crypto::archive::encrypt_recovery_bundle(&key, &bundle).expect("a sealed bundle")
    }
}

/// How a test bends the bundle.
#[derive(Default)]
struct Shape {
    more_writers: Vec<TrustedWriter>,
    only_writers: Option<Vec<TrustedWriter>>,
    no_producer: bool,
    collections: Option<Vec<CollectionLocator>>,
    checkpoint: Option<ArchiveCheckpoint>,
    /// The checkpoints of other archives the bundle records.
    more_checkpoints: Vec<ArchiveCheckpoint>,
    /// The bundle's revision, when it is not the usual one.
    revision: Option<u64>,
    sealed_for_origin: Option<&'static str>,
    sealed_at_locator: Option<String>,
}

fn collection(origin: &str, locator: &str, archive_id: ArchiveId) -> CollectionLocator {
    CollectionLocator {
        service_origin: origin.to_owned(),
        locator: locator.to_owned(),
        archive_id,
    }
}

fn publish(
    descriptor: &ArchiveDescriptor,
    writer: &AuthorisationKeyPair,
) -> BackupGenerationPublication {
    let payload = BackupGenerationPublicationPayload {
        descriptor: descriptor.clone(),
        writer_key_id: writer.key_id(),
        published_at_ms: TimestampMs::new(5_000),
    };
    resign(payload, writer)
}

fn resign(
    payload: BackupGenerationPublicationPayload,
    writer: &AuthorisationKeyPair,
) -> BackupGenerationPublication {
    let signature = sign(
        writer,
        &SigningTranscript::from_canonical_bytes(
            BACKUP_PUBLICATION_DOMAIN,
            payload.signing_input().expect("a publication input"),
        )
        .expect("a transcript"),
    )
    .expect("a signature");
    BackupGenerationPublication { payload, signature }
}

fn checkpoint_of(sealed: &Sealed) -> ArchiveCheckpoint {
    let descriptor = &sealed.publication.payload.descriptor;
    ArchiveCheckpoint {
        archive_id: archive(),
        backup_generation: descriptor.backup_generation,
        encrypted_manifest_hash: descriptor.encrypted_manifest.encrypted_object_hash,
        verified_at_ms: TimestampMs::new(4_000),
    }
}

/* -------------------------------------------------------------------------- */
/* What the service serves                                                     */
/* -------------------------------------------------------------------------- */

/// What one script serves, and what it was asked.
#[derive(Debug)]
struct Scripted {
    service: SourceService,
    /// The sealed bundle, served for the locator it is at, or for any locator when `anywhere`.
    bundle: Mutex<Option<(String, Vec<u8>)>>,
    anywhere: bool,
    generations: Mutex<BTreeMap<ArchiveId, BackupGenerationPublication>>,
    objects: Mutex<BTreeMap<(ArchiveId, BackupObjectId), Vec<u8>>>,
    asked: Mutex<Vec<String>>,
    /// Where the bundle is in the collection's order: a write takes the next place.
    place: Mutex<u64>,
    /// Answer a request held to a checkpoint with nothing when the generation held is older, as the
    /// real service does; a hostile one serves what it holds whatever it was asked.
    honours_the_hold: bool,
    /// Answer every object read with no bytes, as a service that has lost the object might.
    serves_empty_ranges: bool,
    /// How many empty answers have been given, so a restore that keeps asking fails here.
    empty_answers: std::sync::atomic::AtomicUsize,
}

impl Scripted {
    fn serving(world: &World, bundle: Vec<u8>) -> Self {
        Self {
            service: SourceService {
                origin: ORIGIN.to_owned(),
                sign_in: SourceSignIn::Usable,
            },
            bundle: Mutex::new(Some((world.locator.clone(), bundle))),
            anywhere: false,
            generations: Mutex::default(),
            objects: Mutex::default(),
            asked: Mutex::default(),
            place: Mutex::new(1),
            honours_the_hold: false,
            serves_empty_ranges: false,
            empty_answers: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    fn honouring_the_hold(mut self) -> Self {
        self.honours_the_hold = true;
        self
    }

    fn publishing(self, sealed: &Sealed) -> Self {
        self.generations
            .lock()
            .expect("generations")
            .insert(archive(), sealed.publication.clone());
        let mut objects = self.objects.lock().expect("objects");
        for (object, bytes) in &sealed.objects {
            objects.insert((archive(), *object), bytes.clone());
        }
        drop(objects);
        self
    }

    fn asked(&self) -> Vec<String> {
        self.asked.lock().expect("asked").clone()
    }

    /// Where the bundle is now.
    fn position(&self) -> SyncPosition {
        let place = *self.place.lock().expect("place");
        SyncPosition::at(
            place,
            kr_client::services::SyncRevision::new(id(u8::try_from(0x70 + place).expect("few"))),
            None,
        )
    }

    /// Replaces the bundle at the next place, as a write from another device would.
    fn replace_bundle(&self, sealed: Vec<u8>) -> SyncPosition {
        *self.place.lock().expect("place") += 1;
        let mut held = self.bundle.lock().expect("bundle");
        let at = held.as_ref().map(|(at, _)| at.clone()).expect("a bundle");
        *held = Some((at, sealed));
        drop(held);
        self.position()
    }

    /// The sealed bundle the service holds.
    fn sealed_bundle(&self) -> Vec<u8> {
        self.bundle
            .lock()
            .expect("bundle")
            .as_ref()
            .map(|(_, sealed)| sealed.clone())
            .expect("a bundle")
    }

    fn object_reads(&self) -> usize {
        self.asked()
            .iter()
            .filter(|call| call.starts_with("object"))
            .count()
    }

    fn corrupt(&self, object: BackupObjectId) {
        let mut objects = self.objects.lock().expect("objects");
        let bytes = objects
            .get_mut(&(archive(), object))
            .expect("an object to corrupt");
        let middle = bytes.len() / 2;
        bytes[middle] ^= 0x01;
    }
}

impl RestoreSource for Scripted {
    fn service(&self) -> ServiceFuture<'_, SourceService> {
        Box::pin(async { Ok(self.service.clone()) })
    }

    fn bundle<'a>(&'a self, locator: &'a str) -> ServiceFuture<'a, SyncFetched> {
        self.asked.lock().expect("asked").push("bundle".to_owned());
        Box::pin(async move {
            let held = self.bundle.lock().expect("bundle").clone();
            Ok(match held {
                Some((at, ciphertext)) if self.anywhere || at == locator => SyncFetched::Held {
                    position: self.position(),
                    ciphertext,
                },
                _ => SyncFetched::Absent { recovery: None },
            })
        })
    }

    fn generation<'a>(
        &'a self,
        archive_id: ArchiveId,
        checkpoint: Option<&'a ArchiveCheckpoint>,
    ) -> ServiceFuture<'a, Option<kr_protocol::archive::BackupGenerationPublication>> {
        self.asked.lock().expect("asked").push(format!(
            "generation {} {}",
            archive_id,
            if checkpoint.is_some() {
                "held to a checkpoint"
            } else {
                "unheld"
            }
        ));
        Box::pin(async move {
            let held = self
                .generations
                .lock()
                .expect("generations")
                .get(&archive_id)
                .cloned();
            Ok(held.filter(|held| {
                !(self.honours_the_hold
                    && checkpoint.is_some_and(|checkpoint| {
                        held.payload.descriptor.backup_generation < checkpoint.backup_generation
                    }))
            }))
        })
    }

    fn object(
        &self,
        archive_id: ArchiveId,
        object: BackupObjectId,
        offset: u64,
        length: u64,
    ) -> ServiceFuture<'_, Vec<u8>> {
        self.asked
            .lock()
            .expect("asked")
            .push(format!("object {object:?} at {offset}"));
        Box::pin(async move {
            if self.serves_empty_ranges {
                let given = self
                    .empty_answers
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                assert!(
                    given < 5,
                    "the restore keeps asking a service that answers nothing"
                );
                return Ok(Vec::new());
            }
            let objects = self.objects.lock().expect("objects");
            let bytes = objects
                .get(&(archive_id, object))
                .expect("a read of an object the script holds");
            let start = usize::try_from(offset).expect("an offset");
            let end = usize::try_from(offset + length)
                .expect("an end")
                .min(bytes.len());
            Ok(bytes[start..end].to_vec())
        })
    }
}

async fn restore(
    world: &World,
    source: &Arc<Scripted>,
    chosen: Option<ArchiveId>,
) -> Result<kr_client::recovery::PreparedRestore, RestoreError> {
    FilesRestore::prepare(
        world.kit(),
        Arc::clone(source) as Arc<dyn RestoreSource>,
        chosen,
        None,
    )
    .await
}

fn honest_members() -> Vec<(&'static str, Vec<u8>)> {
    let session = format!("sessions/{}.json", "0a1b2c3d-0000-4000-8000-000000000001");
    vec![
        (
            Box::leak(session.into_boxed_str()) as &str,
            b"what the session did".to_vec(),
        ),
        ("host/configuration.json", b"{\"storage\":{}}".to_vec()),
    ]
}

/// The honest case, which every refusal below is a variation of.
#[tokio::test]
async fn an_archive_the_bundle_vouches_for_restores_its_session_and_configuration() {
    let world = World::new();
    let sealed = world.seal(4, &honest_members());
    let source =
        Arc::new(Scripted::serving(&world, world.bundle(&Shape::default())).publishing(&sealed));
    let prepared = restore(&world, &source, None).await.expect("a restore");
    let plan = prepared.plan();
    assert_eq!(plan.generation.get(), 4);
    assert_eq!(plan.members.len(), 2);
    let files: Vec<_> = plan
        .restored()
        .map(|(_, file, role)| (file.to_owned(), role))
        .collect();
    assert_eq!(
        files,
        vec![
            ("session-0001.json".to_owned(), MemberRole::Session),
            ("configuration.json".to_owned(), MemberRole::Configuration),
        ],
        "files are named from the role and a number, never from the archive's names"
    );
    assert!(plan.refused().next().is_none());
    // Nothing but the manifest object was read to make the plan.
    assert_eq!(source.object_reads(), 1);
    let first = prepared
        .member(plan.members[0].object_id)
        .await
        .expect("a member");
    assert_eq!(first.expose(), b"what the session did");
    let second = prepared
        .member(plan.members[1].object_id)
        .await
        .expect("a member");
    assert_eq!(second.expose(), b"{\"storage\":{}}");
}

/// A plan's digest is what a person confirms, so it changes with anything the person is
/// confirming.
#[tokio::test]
async fn the_digest_a_person_confirms_changes_with_the_destination_the_environment_and_the_archive()
{
    let world = World::new();
    let first = world.seal(4, &honest_members());
    let newer = world.seal(5, &honest_members());
    async fn digest(
        world: &World,
        sealed: &Sealed,
        environment: &str,
        destination: &[u8],
    ) -> String {
        let source =
            Arc::new(Scripted::serving(world, world.bundle(&Shape::default())).publishing(sealed));
        let prepared = restore(world, &source, None).await.expect("a restore");
        prepared
            .plan()
            .digest(environment, destination, "")
            .expect("a digest")
    }
    let base = digest(&world, &first, "env-1", b"/restore/a").await;
    assert_eq!(
        base,
        digest(&world, &first, "env-1", b"/restore/a").await,
        "it is stable"
    );
    assert_ne!(base, digest(&world, &first, "env-1", b"/restore/b").await);
    assert_ne!(base, digest(&world, &first, "env-2", b"/restore/a").await);
    assert_ne!(base, digest(&world, &newer, "env-1", b"/restore/a").await);
    // The same archive, signed again at another time, is another plan: the plan shows the time.
    let signed_again = {
        let mut payload = first.publication.payload.clone();
        payload.published_at_ms = TimestampMs::new(6_000);
        Sealed {
            publication: resign(payload, &world.writer),
            objects: first.objects.clone(),
            manifest_object: first.manifest_object,
        }
    };
    assert_ne!(
        base,
        digest(&world, &signed_again, "env-1", b"/restore/a").await
    );
    // Two folders whose names differ only in bytes that are not text are two destinations.
    assert_ne!(
        digest(&world, &first, "env-1", b"/restore/\xff").await,
        digest(&world, &first, "env-1", b"/restore/\xfe").await
    );
    // The same generation with other content has another manifest and the same names and sizes:
    // only the manifest's hash tells the two plans apart.
    let other_content = world.seal(
        4,
        &honest_members()
            .into_iter()
            .map(|(name, mut bytes)| {
                bytes[0] ^= 1;
                (name, bytes)
            })
            .collect::<Vec<_>>(),
    );
    assert_ne!(
        base,
        digest(&world, &other_content, "env-1", b"/restore/a").await,
        "a plan with another manifest is another plan"
    );
}

/// KR-REQ-24.16: writer authority is verified. Every claim about who may vouch for an archive, each
/// with a signature a trusted writer made wherever the claim is not about the signature itself.
#[tokio::test]
async fn a_restore_trusts_the_writers_and_the_generation_the_authenticated_bundle_names() {
    let world = World::new();
    let members = honest_members();

    // The control: the same archive, vouched for, restores.
    let honest = world.seal(4, &members);
    let source =
        Arc::new(Scripted::serving(&world, world.bundle(&Shape::default())).publishing(&honest));
    assert!(restore(&world, &source, None).await.is_ok());

    // A writer the bundle does not name signed the publication (validly, with its own key).
    let impostor = AuthorisationKeyPair::generate().expect("a key");
    let by_impostor = world.seal_with(4, &members, &impostor, &impostor, &world.recipients());
    let source = Arc::new(
        Scripted::serving(&world, world.bundle(&Shape::default())).publishing(&by_impostor),
    );
    assert!(matches!(
        restore(&world, &source, None).await.expect_err("refused"),
        RestoreError::Publication(PublicationRefusal::WriterNotInBundle)
    ));
    assert_eq!(source.object_reads(), 0, "refused before an object is read");

    // A genuine publication of another collection of the same writer.
    let other = {
        let mut sealed = world.seal(4, &members);
        let mut payload = sealed.publication.payload.clone();
        payload.descriptor.archive_id = ArchiveId::new(id(0x12));
        for wrap in &mut payload.descriptor.manifest_key_wraps {
            wrap.context.archive_id = ArchiveId::new(id(0x12));
        }
        sealed.publication = resign(payload, &world.writer);
        sealed
    };
    let source =
        Arc::new(Scripted::serving(&world, world.bundle(&Shape::default())).publishing(&other));
    assert!(matches!(
        restore(&world, &source, None).await.expect_err("refused"),
        RestoreError::Publication(PublicationRefusal::OtherArchive)
    ));
    assert_eq!(source.object_reads(), 0);

    // A publication whose signature fails.
    let mut forged = world.seal(4, &members);
    let mut payload = forged.publication.payload.clone();
    payload.published_at_ms = TimestampMs::new(9_999);
    forged.publication = BackupGenerationPublication {
        payload,
        signature: forged.publication.signature,
    };
    let source =
        Arc::new(Scripted::serving(&world, world.bundle(&Shape::default())).publishing(&forged));
    assert!(matches!(
        restore(&world, &source, None).await.expect_err("refused"),
        RestoreError::Publication(PublicationRefusal::BadSignature)
    ));

    // A writer whose identifier in the bundle is not the identifier of the key it carries.
    let confused = {
        let mut claimed = World::trusted(&world.writer);
        claimed.signing_key = *impostor.public();
        claimed
    };
    // The publication names the writer's identifier and is signed by the key the bundle carries
    // under it, so only the identifier check can refuse it.
    let mut confusing = world.seal(4, &members);
    confusing.publication = resign(confusing.publication.payload.clone(), &impostor);
    let source = Arc::new(
        Scripted::serving(
            &world,
            world.bundle(&Shape {
                only_writers: Some(vec![confused]),
                ..Shape::default()
            }),
        )
        .publishing(&confusing),
    );
    assert!(matches!(
        restore(&world, &source, None).await.expect_err("refused"),
        RestoreError::Publication(PublicationRefusal::WriterKeyMismatch)
    ));
    assert_eq!(source.object_reads(), 0);

    // A descriptor over the byte limit, validly signed by the trusted writer, is refused before an
    // object is read: the restore measures the descriptor it was handed.
    let mut oversize = world.seal(4, &members);
    let mut payload = oversize.publication.payload.clone();
    let wrap = payload.descriptor.manifest_key_wraps[0].clone();
    payload.descriptor.manifest_key_wraps = vec![wrap; 400];
    oversize.publication = resign(payload, &world.writer);
    let source =
        Arc::new(Scripted::serving(&world, world.bundle(&Shape::default())).publishing(&oversize));
    assert!(matches!(
        restore(&world, &source, None).await.expect_err("refused"),
        RestoreError::Publication(PublicationRefusal::Structure(
            DescriptorError::TooLarge { .. }
        ))
    ));
    assert_eq!(source.object_reads(), 0);

    // A descriptor the protocol refuses, validly signed by the trusted writer, is refused before
    // an object is read.
    let mut invalid = world.seal(4, &members);
    let mut payload = invalid.publication.payload.clone();
    payload.descriptor.version = U64::new(2);
    invalid.publication = resign(payload, &world.writer);
    let source =
        Arc::new(Scripted::serving(&world, world.bundle(&Shape::default())).publishing(&invalid));
    assert!(matches!(
        restore(&world, &source, None).await.expect_err("refused"),
        RestoreError::Publication(PublicationRefusal::Structure(_))
    ));
    assert_eq!(source.object_reads(), 0);

    // The publication's writer is not the manifest's: both are trusted, each signed its own.
    let second = AuthorisationKeyPair::generate().expect("a key");
    let split = world.seal_with(4, &members, &second, &world.writer, &world.recipients());
    let source = Arc::new(
        Scripted::serving(
            &world,
            world.bundle(&Shape {
                more_writers: vec![World::trusted(&second)],
                ..Shape::default()
            }),
        )
        .publishing(&split),
    );
    assert!(matches!(
        restore(&world, &source, None).await.expect_err("refused"),
        RestoreError::ManifestWriter
    ));

    // A producer the bundle does not hold.
    let source = Arc::new(
        Scripted::serving(
            &world,
            world.bundle(&Shape {
                no_producer: true,
                ..Shape::default()
            }),
        )
        .publishing(&honest),
    );
    assert!(matches!(
        restore(&world, &source, None).await.expect_err("refused"),
        RestoreError::NoProducer
    ));
    assert_eq!(source.object_reads(), 0);

    // A manifest key wrapped for another recipient only.
    let mut elsewhere = ArchiveRecipients::new(CollectionKind::Owned);
    assert!(elsewhere.add(*StoredEnvelopeKeyPair::generate().expect("a key").public()));
    let for_another = world.seal_with(4, &members, &world.writer, &world.writer, &elsewhere);
    let source = Arc::new(
        Scripted::serving(&world, world.bundle(&Shape::default())).publishing(&for_another),
    );
    assert!(matches!(
        restore(&world, &source, None).await.expect_err("refused"),
        RestoreError::NoWrap
    ));
    assert_eq!(source.object_reads(), 0);
}

/// KR-REQ-24.16: the generation is verified. The checkpoint is what catches a genuine archive from
/// the wrong time.
#[tokio::test]
async fn a_generation_the_checkpoint_refuses_is_refused_before_the_manifest_is_read() {
    let world = World::new();
    let members = honest_members();
    let current = world.seal(5, &members);
    let checkpoint = checkpoint_of(&current);
    let shape = || Shape {
        checkpoint: Some(checkpoint.clone()),
        ..Shape::default()
    };

    // The control: the checkpoint's own generation restores, and the standing says so.
    let source = Arc::new(Scripted::serving(&world, world.bundle(&shape())).publishing(&current));
    let prepared = restore(&world, &source, None).await.expect("a restore");
    assert!(prepared.plan().standing.checkpoint_available());
    assert!(
        source
            .asked()
            .iter()
            .any(|call| call.contains("held to a checkpoint"))
    );

    // A word that names an older generation does not cover the checkpoint's own: the service holds
    // generation 5, which needs none, and it is not restored under a word the person gave for
    // another.
    let named = FilesRestore::prepare(
        world.kit(),
        Arc::clone(&source) as Arc<dyn RestoreSource>,
        None,
        Some(BackupGeneration::new(3)),
    )
    .await
    .expect_err("the named generation is not what is held");
    assert!(matches!(
        named,
        RestoreError::NamedGenerationNotHeld { named: 3, held: 5 }
    ));

    // An older generation than the checkpoint, genuinely signed.
    let older = world.seal(3, &members);
    let source = Arc::new(Scripted::serving(&world, world.bundle(&shape())).publishing(&older));
    let replay = restore(&world, &source, None).await.expect_err("refused");
    assert!(matches!(
        replay,
        RestoreError::Publication(PublicationRefusal::Generation(..))
    ));
    // The person is told the two generations: the one offered and the one the checkpoint holds.
    let told = replay.to_string();
    assert!(
        told.contains("generation 3") && told.contains("generation 5"),
        "{told}"
    );
    assert!(
        !told.contains("Restoring"),
        "a generation that is refused is not introduced as being restored: {told}"
    );
    assert_eq!(source.object_reads(), 0, "a replay costs no download");

    // The checkpoint's generation with a second genuine manifest.
    let second = world.seal(5, &[("host/configuration.json", b"{}".to_vec())]);
    let source = Arc::new(Scripted::serving(&world, world.bundle(&shape())).publishing(&second));
    assert!(matches!(
        restore(&world, &source, None).await.expect_err("refused"),
        RestoreError::Publication(PublicationRefusal::Generation(..))
    ));
    assert_eq!(source.object_reads(), 0);

    // The honest service holds nothing at all: asked held to the checkpoint and then without it,
    // it answers nothing both times, and the restore stops, having read no object.
    let source = Arc::new(Scripted::serving(&world, world.bundle(&shape())));
    assert!(matches!(
        restore(&world, &source, None).await.expect_err("stopped"),
        RestoreError::NothingAsNewAsTheCheckpoint { checkpoint: 5 }
    ));
    assert_eq!(source.object_reads(), 0);

    // The honest service holds only an older generation: held to the checkpoint it answers
    // nothing, and the restore asks once more, without it, to say what the service does hold. That
    // is verified before it is named, and no object is read.
    let source = Arc::new(
        Scripted::serving(&world, world.bundle(&shape()))
            .publishing(&older)
            .honouring_the_hold(),
    );
    assert!(matches!(
        restore(&world, &source, None).await.expect_err("refused"),
        RestoreError::OlderThanTheCheckpoint {
            checkpoint: 5,
            held: 3
        }
    ));
    assert_eq!(source.object_reads(), 0);
    // Naming that generation restores it, and the standing says it was named.
    let prepared = FilesRestore::prepare(
        world.kit(),
        Arc::clone(&source) as Arc<dyn RestoreSource>,
        None,
        Some(BackupGeneration::new(3)),
    )
    .await
    .expect("the named generation restores");
    assert_eq!(prepared.plan().generation.get(), 3);
    // A generation the service does not hold is not accepted, and the refusal says what it holds.
    assert!(matches!(
        FilesRestore::prepare(
            world.kit(),
            Arc::clone(&source) as Arc<dyn RestoreSource>,
            None,
            Some(BackupGeneration::new(4)),
        )
        .await
        .expect_err("refused"),
        RestoreError::OlderThanTheCheckpoint {
            checkpoint: 5,
            held: 3
        }
    ));
    // With no checkpoint there is nothing to accept an older generation past.
    let source = Arc::new(
        Scripted::serving(&world, world.bundle(&Shape::default()))
            .publishing(&older)
            .honouring_the_hold(),
    );
    assert!(matches!(
        FilesRestore::prepare(
            world.kit(),
            Arc::clone(&source) as Arc<dyn RestoreSource>,
            None,
            Some(BackupGeneration::new(3)),
        )
        .await
        .expect_err("refused"),
        RestoreError::NoCheckpointToAcceptPast
    ));

    // With no checkpoint at all, an archive the service holds restores, and says nothing is
    // proven; and one it does not hold is a different stop.
    let source =
        Arc::new(Scripted::serving(&world, world.bundle(&Shape::default())).publishing(&current));
    let prepared = restore(&world, &source, None).await.expect("a restore");
    assert!(!prepared.plan().standing.checkpoint_available());
    assert!(!prepared.plan().standing.proves_no_newer_archive());
    let source = Arc::new(Scripted::serving(&world, world.bundle(&Shape::default())));
    assert!(matches!(
        restore(&world, &source, None).await.expect_err("stopped"),
        RestoreError::NoGeneration
    ));
}

/// A service that takes writes of the bundle by compare-and-swap, the way the real one does, with
/// one thing a test can script: a write that lands from somewhere else just before the restore's
/// own, or an answer to the restore's own that never arrives.
#[derive(Debug)]
struct Bundle {
    source: Arc<Scripted>,
    /// The sealed bundle another device writes just before the next write meets the service.
    meanwhile: Mutex<Option<Vec<u8>>>,
    /// Whether the next write that applies is answered at all.
    loses_the_answer: Mutex<bool>,
    /// How many writes met the service.
    writes: Mutex<usize>,
}

impl Bundle {
    fn over(source: &Arc<Scripted>) -> Self {
        Self {
            source: Arc::clone(source),
            meanwhile: Mutex::new(None),
            loses_the_answer: Mutex::new(false),
            writes: Mutex::new(0),
        }
    }
}

impl BundleWriter for Bundle {
    fn write<'a>(&'a self, write: BundleWrite<'a>) -> ServiceFuture<'a, BundleWritten> {
        Box::pin(async move {
            *self.writes.lock().expect("writes") += 1;
            if let Some(other) = self.meanwhile.lock().expect("meanwhile").take() {
                self.source.replace_bundle(other);
            }
            if write.expected != self.source.position() {
                return Ok(BundleWritten::Conflict);
            }
            let placed = self.source.replace_bundle(write.sealed.to_vec());
            if std::mem::take(&mut *self.loses_the_answer.lock().expect("loses")) {
                return Err(ClientError::Host(ProtocolError::new(
                    ErrorCode::OutcomeUnknown,
                    "the answer did not arrive".to_owned(),
                )));
            }
            Ok(BundleWritten::Written(placed))
        })
    }
}

/// The bundle the service holds, opened under the world's seed.
fn bundle_held(world: &World, source: &Scripted) -> RecoveryBundle {
    let key = world
        .seed
        .bundle_key_for(&kr_protocol::archive::RecoveryContext {
            service_origin: ORIGIN.to_owned(),
            bundle_locator: world.locator.clone(),
        })
        .expect("a bundle key");
    kr_crypto::archive::decrypt_recovery_bundle(&key, &source.sealed_bundle())
        .expect("the bundle opens")
}

/// KR-REQ-24.16, 20.12: the checkpoint a restore records is written on what the bundle holds when
/// the write is made, so a writer that another device added between the restore's read and its
/// write is still in the bundle afterwards, and a write whose answer never came is neither done
/// twice nor taken for undone.
#[tokio::test]
async fn recording_the_checkpoint_keeps_what_another_device_wrote_to_the_bundle_meanwhile() {
    let world = World::new();
    let sealed = world.seal(4, &honest_members());
    let source =
        Arc::new(Scripted::serving(&world, world.bundle(&Shape::default())).publishing(&sealed));
    let prepared = restore(&world, &source, None).await.expect("a restore");
    let before = bundle_held(&world, &source);
    assert!(before.checkpoints.is_empty());

    // Another device enrols a writer after the restore read the bundle.
    let added = TrustedWriter {
        writer_key_id: AuthorisationKeyPair::generate().expect("a key").key_id(),
        signing_key: *AuthorisationKeyPair::generate().expect("a key").public(),
        enrolled_at_ms: TimestampMs::new(1_500),
    };
    let other = world.bundle(&Shape {
        more_writers: vec![added.clone()],
        ..Shape::default()
    });
    let bundle = Bundle::over(&source);
    *bundle.meanwhile.lock().expect("meanwhile") = Some(other);
    let recorded = prepared
        .record_checkpoint(&bundle, TimestampMs::new(9_000))
        .await
        .expect("recorded");
    assert!(matches!(recorded, CheckpointRecorded::Written { .. }));
    assert_eq!(
        *bundle.writes.lock().expect("writes"),
        2,
        "a conflict, then the write"
    );

    let after = bundle_held(&world, &source);
    assert!(
        after.trusted_writers.contains(&added),
        "the writer another device added is still trusted"
    );
    assert_eq!(after.trusted_producers, before.trusted_producers);
    assert_eq!(after.collections, before.collections);
    assert_eq!(
        after.checkpoints.iter().cloned().collect::<Vec<_>>(),
        [ArchiveCheckpoint {
            verified_at_ms: TimestampMs::new(9_000),
            ..checkpoint_of(&sealed)
        }]
    );
    assert_eq!(after.revision.get(), before.revision.get() + 1);

    // A write that landed and was not answered: the next read finds the checkpoint recorded, and
    // nothing is written a second time.
    let source =
        Arc::new(Scripted::serving(&world, world.bundle(&Shape::default())).publishing(&sealed));
    let prepared = restore(&world, &source, None).await.expect("a restore");
    let bundle = Bundle::over(&source);
    *bundle.loses_the_answer.lock().expect("loses") = true;
    let recorded = prepared
        .record_checkpoint(&bundle, TimestampMs::new(9_000))
        .await
        .expect("settled by reading");
    assert!(matches!(recorded, CheckpointRecorded::AlreadyThere));
    assert_eq!(*bundle.writes.lock().expect("writes"), 1);
    assert_eq!(bundle_held(&world, &source).checkpoints.len(), 1);
}

/// KR-REQ-24.16: a checkpoint is never lowered and never recorded over another manifest of the
/// same generation. A restore that another restore overtakes finds the bundle already past it.
#[tokio::test]
async fn a_checkpoint_is_not_lowered_and_not_recorded_over_another_manifest_of_its_generation() {
    let world = World::new();
    let members = honest_members();
    let sealed = world.seal(4, &members);
    let source =
        Arc::new(Scripted::serving(&world, world.bundle(&Shape::default())).publishing(&sealed));
    let prepared = restore(&world, &source, None).await.expect("a restore");

    // Another restore recorded a newer generation of the archive after this one read the bundle.
    let newer = world.seal(6, &members);
    let bundle = Bundle::over(&source);
    *bundle.meanwhile.lock().expect("meanwhile") = Some(world.bundle(&Shape {
        checkpoint: Some(checkpoint_of(&newer)),
        ..Shape::default()
    }));
    // The bundle is changed once the restore has read it, so that the restore's write is the first
    // thing to meet the newer bundle; it reads again and finds nothing to record.
    let recorded = prepared
        .record_checkpoint(&bundle, TimestampMs::new(9_000))
        .await
        .expect("nothing to record");
    assert!(matches!(recorded, CheckpointRecorded::AlreadyThere));
    let held = bundle_held(&world, &source);
    assert_eq!(
        held.checkpoints.iter().cloned().collect::<Vec<_>>(),
        [checkpoint_of(&newer)],
        "the higher checkpoint stays"
    );

    // The bundle this restore read records generation 6, and it restores generation 4 on the
    // person's word. A later read that finds an older authentic bundle, one that records none, is
    // not written on, because the write would put the checkpoint at 4 where this restore saw 6.
    // The service replaces the bundle after the restore read it.
    let known = world.seal(6, &members);
    let source = Arc::new(
        Scripted::serving(
            &world,
            world.bundle(&Shape {
                checkpoint: Some(checkpoint_of(&known)),
                ..Shape::default()
            }),
        )
        .publishing(&sealed)
        .honouring_the_hold(),
    );
    let prepared = FilesRestore::prepare(
        world.kit(),
        Arc::clone(&source) as Arc<dyn RestoreSource>,
        None,
        Some(BackupGeneration::new(4)),
    )
    .await
    .expect("the named generation restores");
    let bundle = Bundle::over(&source);
    source.replace_bundle(world.bundle(&Shape::default()));
    let refused = prepared
        .record_checkpoint(&bundle, TimestampMs::new(9_000))
        .await
        .expect_err("the bundle went back");
    assert_eq!(*bundle.writes.lock().expect("writes"), 0);
    assert!(matches!(
        refused,
        RestoreError::Recovery(ref cause)
            if matches!(**cause, RecoveryError::CheckpointWentBack { known: 6 })
    ));
    assert!(
        bundle_held(&world, &source).checkpoints.is_empty(),
        "nothing was written over the bundle the service now holds"
    );

    // The bundle also records another archive, at generation 9, and this restore of the first at
    // generation 8 reads it. A later read that finds an older authentic bundle in which that other
    // archive stands at 5 is not written on either: the write would lower a checkpoint of an
    // archive the restore was not about.
    let other = another_archive_at(9);
    let lower = another_archive_at(5);
    let current = world.seal(8, &members);
    let source = Arc::new(
        Scripted::serving(
            &world,
            world.bundle(&Shape {
                checkpoint: Some(checkpoint_of(&sealed)),
                more_checkpoints: vec![other.clone()],
                ..Shape::default()
            }),
        )
        .publishing(&current),
    );
    let prepared = restore(&world, &source, None).await.expect("a restore");
    let bundle = Bundle::over(&source);
    source.replace_bundle(world.bundle(&Shape {
        checkpoint: Some(checkpoint_of(&sealed)),
        more_checkpoints: vec![lower],
        ..Shape::default()
    }));
    let refused = prepared
        .record_checkpoint(&bundle, TimestampMs::new(9_000))
        .await
        .expect_err("another archive's checkpoint went back");
    assert!(matches!(
        refused,
        RestoreError::Recovery(ref cause)
            if matches!(**cause, RecoveryError::CheckpointWentBack { known: 9 })
    ));
    assert_eq!(*bundle.writes.lock().expect("writes"), 0);

    // A bundle of an older revision than the one the restore read is not written on, whatever it
    // records.
    let source =
        Arc::new(Scripted::serving(&world, world.bundle(&Shape::default())).publishing(&sealed));
    let prepared = restore(&world, &source, None).await.expect("a restore");
    let bundle = Bundle::over(&source);
    source.replace_bundle(world.bundle(&Shape {
        revision: Some(2),
        ..Shape::default()
    }));
    let refused = prepared
        .record_checkpoint(&bundle, TimestampMs::new(9_000))
        .await
        .expect_err("an older revision");
    assert!(matches!(
        refused,
        RestoreError::Recovery(ref cause)
            if matches!(**cause, RecoveryError::BundleWentBackToAnOlderRevision { newest: 3 })
    ));
    assert_eq!(*bundle.writes.lock().expect("writes"), 0);

    // Another restore recorded this very generation with another encrypted manifest.
    let source =
        Arc::new(Scripted::serving(&world, world.bundle(&Shape::default())).publishing(&sealed));
    let prepared = restore(&world, &source, None).await.expect("a restore");
    let second = world.seal(4, &[("host/configuration.json", b"{}".to_vec())]);
    let bundle = Bundle::over(&source);
    *bundle.meanwhile.lock().expect("meanwhile") = Some(world.bundle(&Shape {
        checkpoint: Some(checkpoint_of(&second)),
        ..Shape::default()
    }));
    let refused = prepared
        .record_checkpoint(&bundle, TimestampMs::new(9_000))
        .await
        .expect_err("a disagreement");
    assert!(matches!(
        refused,
        RestoreError::Recovery(ref cause)
            if matches!(**cause, RecoveryError::CheckpointDisagrees { generation: 4 })
    ));
    assert_eq!(
        bundle_held(&world, &source)
            .checkpoints
            .iter()
            .cloned()
            .collect::<Vec<_>>(),
        [checkpoint_of(&second)],
        "the bundle is left as the other restore wrote it"
    );
}

/// The checkpoint of an archive the restore is not about, at the generation given.
fn another_archive_at(generation: u64) -> ArchiveCheckpoint {
    ArchiveCheckpoint {
        archive_id: ArchiveId::new(id(0x42)),
        backup_generation: BackupGeneration::new(generation),
        encrypted_manifest_hash: Digest256::from_bytes(
            [u8::try_from(generation).expect("few"); 32],
        ),
        verified_at_ms: TimestampMs::new(4_000),
    }
}

/// A restore that read revision 5 of the bundle, which records the checkpoints `read_first`, after
/// which another device wrote revision 6, which records `then`. It returns the restore, the
/// service, the bytes of revision 5 as the service first served them, and a writer whose first
/// write meets whatever the test puts in `meanwhile`.
async fn a_restore_that_revision_6_overtook(
    world: &World,
    read_first: &[ArchiveCheckpoint],
    then: &[ArchiveCheckpoint],
) -> (
    kr_client::recovery::PreparedRestore,
    Arc<Scripted>,
    Vec<u8>,
    Bundle,
) {
    let sealed = world.seal(4, &honest_members());
    let first = world.bundle(&Shape {
        revision: Some(5),
        more_checkpoints: read_first.to_vec(),
        ..Shape::default()
    });
    let source = Arc::new(Scripted::serving(world, first).publishing(&sealed));
    let prepared = restore(world, &source, None).await.expect("a restore");
    let revision_5 = source.sealed_bundle();
    source.replace_bundle(world.bundle(&Shape {
        revision: Some(6),
        more_checkpoints: then.to_vec(),
        ..Shape::default()
    }));
    let writer = Bundle::over(&source);
    (prepared, source, revision_5, writer)
}

/// KR-REQ-24.16: what any read of the bundle showed holds every read after it. A write that meets
/// a conflict reads again, and a service that answers with revision 5 again, at a later place,
/// after an attempt read revision 6, is not written on: the write would put back the older bundle
/// and drop what revision 6 held.
#[tokio::test]
async fn a_retry_does_not_write_on_a_bundle_older_than_one_an_attempt_read() {
    let world = World::new();
    let (prepared, source, revision_5, writer) = a_restore_that_revision_6_overtook(
        &world,
        &[another_archive_at(5)],
        &[another_archive_at(9)],
    )
    .await;
    *writer.meanwhile.lock().expect("meanwhile") = Some(revision_5.clone());
    let refused = prepared
        .record_checkpoint(&writer, TimestampMs::new(9_000))
        .await
        .expect_err("revision 5 is older than the revision 6 an attempt read");
    assert!(matches!(
        refused,
        RestoreError::Recovery(ref cause)
            if matches!(**cause, RecoveryError::BundleWentBackToAnOlderRevision { newest: 6 })
    ));
    assert_eq!(
        *writer.writes.lock().expect("writes"),
        1,
        "only the write that conflicted met the service"
    );
    assert_eq!(
        source.sealed_bundle(),
        revision_5,
        "nothing was written over what the service holds"
    );
}

/// KR-REQ-24.16: a checkpoint an attempt read is held on its own, whatever the revision: a retry
/// that finds a newer revision than any attempt read, with another archive's checkpoint lower than
/// one an attempt read, is not written on either.
#[tokio::test]
async fn a_retry_does_not_seal_a_checkpoint_below_one_an_attempt_read() {
    let world = World::new();
    let (prepared, source, _, writer) = a_restore_that_revision_6_overtook(
        &world,
        &[another_archive_at(5)],
        &[another_archive_at(9)],
    )
    .await;
    let revision_7 = world.bundle(&Shape {
        revision: Some(7),
        more_checkpoints: vec![another_archive_at(5)],
        ..Shape::default()
    });
    *writer.meanwhile.lock().expect("meanwhile") = Some(revision_7.clone());
    let refused = prepared
        .record_checkpoint(&writer, TimestampMs::new(9_000))
        .await
        .expect_err("the other archive's checkpoint went back");
    assert!(matches!(
        refused,
        RestoreError::Recovery(ref cause)
            if matches!(**cause, RecoveryError::CheckpointWentBack { known: 9 })
    ));
    assert_eq!(
        *writer.writes.lock().expect("writes"),
        1,
        "only the write that conflicted met the service"
    );
    assert_eq!(
        source.sealed_bundle(),
        revision_7,
        "nothing was written over what the service holds"
    );
}

/// KR-REQ-24.16: the manifest a checkpoint was read with at a generation is not replaced by
/// another when a later read records two manifests for that generation. The retry that finds one
/// of the two only is not written on, whichever of them it is.
#[tokio::test]
async fn a_retry_does_not_take_another_manifest_for_a_generation_an_attempt_read() {
    let world = World::new();
    let first = ArchiveCheckpoint {
        encrypted_manifest_hash: Digest256::from_bytes([6; 32]),
        ..another_archive_at(5)
    };
    let (prepared, source, _, writer) = a_restore_that_revision_6_overtook(
        &world,
        std::slice::from_ref(&first),
        &[another_archive_at(5), first.clone()],
    )
    .await;
    let revision_7 = world.bundle(&Shape {
        revision: Some(7),
        more_checkpoints: vec![another_archive_at(5)],
        ..Shape::default()
    });
    *writer.meanwhile.lock().expect("meanwhile") = Some(revision_7.clone());
    let refused = prepared
        .record_checkpoint(&writer, TimestampMs::new(9_000))
        .await
        .expect_err("another manifest for generation 5");
    assert!(matches!(
        refused,
        RestoreError::Recovery(ref cause)
            if matches!(**cause, RecoveryError::CheckpointDisagrees { generation: 5 })
    ));
    assert_eq!(
        *writer.writes.lock().expect("writes"),
        1,
        "only the write that conflicted met the service"
    );
    assert_eq!(
        source.sealed_bundle(),
        revision_7,
        "nothing was written over what the service holds"
    );
}

/// An export read back as a source, in bytes, as a file would hold it.
fn reread(export: &OfflineExport) -> Arc<ExportSource> {
    let bytes = export.to_canonical_bytes().expect("canonical bytes");
    Arc::new(ExportSource::new(
        OfflineExport::from_canonical_slice(&bytes).expect("the export reads back"),
    ))
}

/// KR-REQ-20.18: an archive exports as one file of ciphertext, and a host that holds nothing but the
/// kit and that file restores the same members as one that asks the service. The file holds no
/// member name or content in the clear, and everything about it is checked on the way back: the
/// kit's checksum, the bundle under the kit's key, the publication's signature and the manifest.
#[tokio::test]
async fn an_archive_exports_as_one_file_that_restores_with_only_the_kit() {
    let world = World::new();
    let members = honest_members();
    let sealed = world.seal(4, &members);
    let source =
        Arc::new(Scripted::serving(&world, world.bundle(&Shape::default())).publishing(&sealed));
    let prepared = restore(&world, &source, None).await.expect("a restore");
    let export = prepared.export().await.expect("an export");
    let bytes = export.to_canonical_bytes().expect("canonical bytes");
    for clear in [
        b"what the session did".as_slice(),
        b"host/configuration.json",
        b"sessions/",
    ] {
        assert!(
            !bytes.windows(clear.len()).any(|window| window == clear),
            "an offline export carries no member name or content in the clear"
        );
    }

    // The file is the whole source: with no service in reach, the kit restores the same members.
    let file = reread(&export);
    let from_file = FilesRestore::prepare(world.kit(), Arc::clone(&file) as _, None, None)
        .await
        .expect("a restore from the file");
    assert_eq!(from_file.plan().generation.get(), 4);
    assert_eq!(
        from_file.plan().members.len(),
        prepared.plan().members.len()
    );
    for planned in &prepared.plan().members {
        let asked = prepared.member(planned.object_id).await.expect("a member");
        let held = from_file.member(planned.object_id).await.expect("a member");
        assert_eq!(held.expose(), asked.expose());
    }
    assert!(!from_file.plan().standing.checkpoint_available());
}

/// KR-REQ-20.18: a file that is not what its reader trusts is refused by name, and restores
/// nothing: another format, a bundle sealed for another kit, an archive the bundle does not name, an
/// object whose bytes were changed, and an archive too large to be one file.
#[tokio::test]
async fn an_export_that_is_not_what_it_claims_is_refused_by_name() {
    let world = World::new();
    let sealed = world.seal(4, &honest_members());
    let source =
        Arc::new(Scripted::serving(&world, world.bundle(&Shape::default())).publishing(&sealed));
    let export = restore(&world, &source, None)
        .await
        .expect("a restore")
        .export()
        .await
        .expect("an export");

    // Another format.
    let mut other = export.clone();
    other.format = "kalareach-offline-export/2".to_owned();
    let bytes = other.to_canonical_bytes().expect("canonical bytes");
    assert!(matches!(
        OfflineExport::from_canonical_slice(&bytes),
        Err(RecoveryError::UnsupportedExport)
    ));
    // Not an export at all.
    assert!(OfflineExport::from_canonical_slice(b"not an export").is_err());

    // A bundle sealed for another kit does not authenticate under this one.
    let stranger = World::new();
    let refused = FilesRestore::prepare(stranger.kit(), reread(&export) as _, None, None)
        .await
        .expect_err("another kit");
    assert!(matches!(
        refused,
        RestoreError::Recovery(ref cause) if matches!(**cause, RecoveryError::BundleNotAuthentic)
    ));

    // An archive the bundle does not name.
    let unlisted = ArchiveId::new(id(0x99));
    assert!(matches!(
        FilesRestore::prepare(world.kit(), reread(&export) as _, Some(unlisted), None)
            .await
            .expect_err("not listed"),
        RestoreError::ArchiveNotListed
    ));

    // An object whose bytes were changed in the file is not a file.
    let mut changed = export.clone();
    let archive = changed.archive.0.as_mut().expect("an archive");
    let first = &mut archive.objects[0];
    let mut bytes = first.bytes.as_slice().to_vec();
    let middle = bytes.len() / 2;
    bytes[middle] ^= 0x01;
    first.bytes = kr_protocol::scalars::Bytes::new(bytes);
    let object = first.object_id;
    let prepared = FilesRestore::prepare(world.kit(), reread(&changed) as _, None, None)
        .await
        .expect("the plan reads the manifest, which is whole");
    assert!(matches!(
        prepared.member(object).await,
        Err(RestoreError::Member(_))
    ));

    // An object the service serves other than the signed manifest names is not copied into a file.
    let source =
        Arc::new(Scripted::serving(&world, world.bundle(&Shape::default())).publishing(&sealed));
    let prepared = restore(&world, &source, None).await.expect("a plan");
    source.corrupt(prepared.plan().members[0].object_id);
    assert!(matches!(
        prepared.export().await,
        Err(RestoreError::Member(_))
    ));

    // An archive too large to be one file is said so, and nothing is read.
    let large = world.seal_declared(
        4,
        &[(
            "sessions/0a1b2c3d-0000-4000-8000-000000000001.json",
            300 << 20,
        )],
    );
    let source =
        Arc::new(Scripted::serving(&world, world.bundle(&Shape::default())).publishing(&large));
    let prepared = restore(&world, &source, None).await.expect("a plan");
    assert!(matches!(
        prepared.export().await,
        Err(RestoreError::TooLargeToExport { .. })
    ));
    assert_eq!(source.object_reads(), 1, "only the manifest was read");
}

/// KR-REQ-20.18: the bundle alone exports too, after it has authenticated under the kit; a restore
/// from it has no archive to open and says so, and the archives it names are listed with the newest
/// generation of each.
#[tokio::test]
async fn the_bundle_exports_alone_and_the_archives_it_names_are_listed() {
    let world = World::new();
    let sealed = world.seal(4, &honest_members());
    let source =
        Arc::new(Scripted::serving(&world, world.bundle(&Shape::default())).publishing(&sealed));

    let listed = FilesRestore::archives(world.kit(), Arc::clone(&source) as _)
        .await
        .expect("the archives");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].archive_id, archive());
    assert!(matches!(
        &listed[0].newest,
        CandidateState::Newest(newest) if newest.generation.get() == 4
    ));

    let export = FilesRestore::export_bundle(world.kit(), Arc::clone(&source) as _)
        .await
        .expect("the bundle exports");
    assert!(export.archive.0.is_none());
    assert!(matches!(
        FilesRestore::prepare(world.kit(), reread(&export) as _, None, None)
            .await
            .expect_err("no archive in the file"),
        RestoreError::NoGeneration
    ));
    // Not a kit this bundle opens for: the export is refused at the bundle.
    assert!(
        FilesRestore::export_bundle(World::new().kit(), source as _)
            .await
            .is_err()
    );
}

/// KR-REQ-24.16: the archive that is opened is the one whose publication was verified. Another
/// genuine generation of the same collection, served under the manifest object the verified
/// publication names, is not it.
#[tokio::test]
async fn a_second_genuine_manifest_served_for_the_verified_publication_does_not_open() {
    let world = World::new();
    let members = honest_members();
    let verified = world.seal(4, &members);
    let later = world.seal(6, &members);
    let swapped = Sealed {
        publication: verified.publication.clone(),
        objects: later.objects.clone(),
        manifest_object: verified.manifest_object,
    };
    let source =
        Arc::new(Scripted::serving(&world, world.bundle(&Shape::default())).publishing(&swapped));
    assert!(matches!(
        restore(&world, &source, None).await.expect_err("refused"),
        RestoreError::Archive(_)
    ));
    assert_eq!(source.object_reads(), 1, "only the manifest was read");
}

/// A publication that declares a manifest longer than any manifest is, is refused before a byte is
/// read.
#[tokio::test]
async fn a_manifest_longer_than_any_manifest_is_refused_before_it_is_read() {
    let world = World::new();
    let mut sealed = world.seal(4, &honest_members());
    let mut payload = sealed.publication.payload.clone();
    payload.descriptor.encrypted_manifest.encrypted_len = U64::new(1 << 40);
    for wrap in &mut payload.descriptor.manifest_key_wraps {
        wrap.context.encrypted_object_hash =
            payload.descriptor.encrypted_manifest.encrypted_object_hash;
    }
    sealed.publication = resign(payload, &world.writer);
    let source =
        Arc::new(Scripted::serving(&world, world.bundle(&Shape::default())).publishing(&sealed));
    assert!(matches!(
        restore(&world, &source, None).await.expect_err("refused"),
        RestoreError::ManifestTooLarge { .. }
    ));
    assert_eq!(source.object_reads(), 0);
}

/// Who the kit, the origin and the locator say a bundle belongs to.
#[tokio::test]
async fn a_bundle_served_for_another_kit_locator_or_origin_does_not_open() {
    let world = World::new();
    let sealed = world.seal(4, &honest_members());
    let serve = |bundle: Vec<u8>, anywhere: bool| {
        let mut source = Scripted::serving(&world, bundle).publishing(&sealed);
        source.anywhere = anywhere;
        Arc::new(source)
    };

    // A kit of another seed meets the owner's bundle.
    let other = World {
        seed: RecoverySeed::generate().expect("a seed"),
        locator: world.locator.clone(),
        writer: AuthorisationKeyPair::generate().expect("a key"),
        producer: StoredEnvelopeKeyPair::generate().expect("a key"),
    };
    let source = serve(world.bundle(&Shape::default()), false);
    let refused = FilesRestore::prepare(other.kit(), Arc::clone(&source) as _, None, None)
        .await
        .expect_err("refused");
    assert!(matches!(
        refused,
        RestoreError::Recovery(ref inner) if matches!(**inner, kr_client::recovery::RecoveryError::BundleNotAuthentic)
    ));

    // A bundle sealed for another locator, served at the kit's.
    let source = serve(
        world.bundle(&Shape {
            sealed_at_locator: Some(fresh_locator().expect("a locator")),
            ..Shape::default()
        }),
        false,
    );
    assert!(matches!(
        restore(&world, &source, None).await.expect_err("refused"),
        RestoreError::Recovery(ref inner) if matches!(**inner, kr_client::recovery::RecoveryError::BundleNotAuthentic)
    ));

    // A bundle sealed for another origin, served as this one's.
    let source = serve(
        world.bundle(&Shape {
            sealed_for_origin: Some(OTHER_ORIGIN),
            ..Shape::default()
        }),
        false,
    );
    assert!(matches!(
        restore(&world, &source, None).await.expect_err("refused"),
        RestoreError::Recovery(ref inner) if matches!(**inner, kr_client::recovery::RecoveryError::BundleNotAuthentic)
    ));

    // A bundle at no locator the kit names is an absent bundle, kept apart from a bad one.
    let mut source = Scripted::serving(&world, world.bundle(&Shape::default()));
    source.bundle = Mutex::new(Some((fresh_locator().expect("a locator"), Vec::new())));
    assert!(matches!(
        restore(&world, &Arc::new(source), None)
            .await
            .expect_err("absent"),
        RestoreError::BundleAbsent
    ));
}

/// The kit has to name the service this host is configured for, and a mistyped kit stops first.
#[tokio::test]
async fn a_kit_that_names_no_service_this_host_reaches_is_refused_by_name() {
    let world = World::new();
    let sealed = world.seal(4, &honest_members());
    let source =
        Arc::new(Scripted::serving(&world, world.bundle(&Shape::default())).publishing(&sealed));
    let self_hosted = world
        .seed
        .to_kit(vec![OTHER_ORIGIN.to_owned()], world.locator.clone());
    let refused = FilesRestore::prepare(self_hosted, Arc::clone(&source) as _, None, None)
        .await
        .expect_err("refused");
    assert!(matches!(refused, RestoreError::OriginNotConfigured));
    assert!(
        !source.asked().iter().any(|call| call == "bundle"),
        "no locator left this process"
    );

    // A spelling of the configured origin other than the canonical one is another service's name:
    // the bundle key is derived from the kit's text byte for byte.
    let respelled = world.seed.to_kit(
        vec!["https://Reach.Kala.To".to_owned()],
        world.locator.clone(),
    );
    let refused = FilesRestore::prepare(respelled, Arc::clone(&source) as _, None, None)
        .await
        .expect_err("refused");
    assert!(matches!(refused, RestoreError::OriginNotConfigured));

    // A locator that is not an identifier in its canonical spelling is wrong before it is sent.
    let mut odd = world.kit();
    odd.bundle_locator = "not/an-identifier".to_owned();
    let source =
        Arc::new(Scripted::serving(&world, world.bundle(&Shape::default())).publishing(&sealed));
    let refused = FilesRestore::prepare(odd, Arc::clone(&source) as _, None, None)
        .await
        .expect_err("refused");
    assert!(matches!(
        refused,
        RestoreError::Recovery(ref inner) if matches!(**inner, kr_client::recovery::RecoveryError::MalformedKit { .. })
    ));
    assert!(!source.asked().iter().any(|call| call == "bundle"));

    // A mistyped kit stops before the service is asked anything.
    let mut mistyped = world.kit();
    mistyped.seed_checksum = kr_protocol::scalars::Bytes::new(vec![0; 4]);
    let source =
        Arc::new(Scripted::serving(&world, world.bundle(&Shape::default())).publishing(&sealed));
    let refused = FilesRestore::prepare(mistyped, Arc::clone(&source) as _, None, None)
        .await
        .expect_err("refused");
    assert!(matches!(
        refused,
        RestoreError::Recovery(ref inner) if matches!(**inner, kr_client::recovery::RecoveryError::MistypedKit)
    ));
    assert!(source.asked().is_empty());

    // A host with no usable sign-in is told so, and nothing is sent.
    let mut signed_out = Scripted::serving(&world, world.bundle(&Shape::default()));
    signed_out.service.sign_in = SourceSignIn::Unusable(SignInCause::SignedOut);
    let signed_out = Arc::new(signed_out);
    assert!(matches!(
        restore(&world, &signed_out, None)
            .await
            .expect_err("refused"),
        RestoreError::NotSignedIn { .. }
    ));
    assert!(signed_out.asked().is_empty());
}

/// An explicit archive has to be one the bundle lists at the configured origin, and without one the
/// restore will not guess among several.
#[tokio::test]
async fn the_archive_is_one_the_authenticated_bundle_lists_at_the_configured_service() {
    let world = World::new();
    let sealed = world.seal(4, &honest_members());
    let elsewhere = ArchiveId::new(id(0x12));
    let two = vec![
        collection(ORIGIN, "collection-1", archive()),
        collection(OTHER_ORIGIN, "collection-2", elsewhere),
    ];
    let shape = || Shape {
        collections: Some(two.clone()),
        ..Shape::default()
    };

    // The archive the bundle lists under another origin is refused before any generation request.
    let source = Arc::new(Scripted::serving(&world, world.bundle(&shape())).publishing(&sealed));
    assert!(matches!(
        restore(&world, &source, Some(elsewhere))
            .await
            .expect_err("refused"),
        RestoreError::ArchiveNotListed
    ));
    assert!(
        !source
            .asked()
            .iter()
            .any(|call| call.starts_with("generation")),
        "no generation was asked for"
    );
    // The one it lists at the configured origin is the default, and may be named.
    assert!(restore(&world, &source, None).await.is_ok());
    assert!(restore(&world, &source, Some(archive())).await.is_ok());

    // An archive the bundle does not list at all.
    assert!(matches!(
        restore(&world, &source, Some(ArchiveId::new(id(0x13))))
            .await
            .expect_err("refused"),
        RestoreError::ArchiveNotListed
    ));

    // Nothing listed here.
    let source = Arc::new(Scripted::serving(
        &world,
        world.bundle(&Shape {
            collections: Some(vec![collection(OTHER_ORIGIN, "collection-2", elsewhere)]),
            ..Shape::default()
        }),
    ));
    assert!(matches!(
        restore(&world, &source, None).await.expect_err("refused"),
        RestoreError::NoArchive
    ));

    // Several at the configured origin: the restore lists each with its newest generation, its
    // signed time and its writer, and picks none.
    let second = ArchiveId::new(id(0x14));
    let source = Arc::new(
        Scripted::serving(
            &world,
            world.bundle(&Shape {
                collections: Some(vec![
                    collection(ORIGIN, "collection-1", archive()),
                    collection(ORIGIN, "collection-3", second),
                ]),
                ..Shape::default()
            }),
        )
        .publishing(&sealed),
    );
    let candidates_of = |error: RestoreError| match error {
        RestoreError::SeveralArchives { count, candidates } => {
            assert_eq!(count, 2);
            candidates
        }
        other => panic!("several archives are listed, not chosen: {other:?}"),
    };
    let candidates = candidates_of(restore(&world, &source, None).await.expect_err("refused"));
    let held = candidates
        .iter()
        .find(|candidate| candidate.archive_id == archive())
        .expect("the first archive");
    let CandidateState::Newest(newest) = &held.newest else {
        panic!("the first archive has a generation");
    };
    assert_eq!(newest.generation.get(), 4);
    assert_eq!(newest.published_at_ms.get(), 5_000);
    assert_eq!(newest.writer, world.writer.key_id());
    let none = candidates
        .iter()
        .find(|candidate| candidate.archive_id == second)
        .expect("the second archive");
    assert!(
        matches!(none.newest, CandidateState::Nothing),
        "the service holds nothing of it"
    );

    // A candidate whose publication a restore would refuse is shown as refused, apart from one the
    // service holds nothing of.
    let impostor = AuthorisationKeyPair::generate().expect("a key");
    let forged = world.seal_with(
        4,
        &honest_members(),
        &impostor,
        &impostor,
        &world.recipients(),
    );
    source
        .generations
        .lock()
        .expect("generations")
        .insert(second, forged.publication.clone());
    let candidates = candidates_of(restore(&world, &source, None).await.expect_err("refused"));
    let other = candidates
        .iter()
        .find(|candidate| candidate.archive_id == second)
        .expect("the second archive");
    assert!(matches!(other.newest, CandidateState::Refused(_)));
}

/// KR-REQ-24.16 and 20.17: a restore returns data only. What a member is called decides what a
/// restore does with it, and nothing it is not told about is written.
#[tokio::test]
async fn members_a_restore_never_puts_back_and_names_it_does_not_know_are_refused() {
    let world = World::new();
    let session = "sessions/0a1b2c3d-0000-4000-8000-000000000001.json";
    let stored = kr_crypto::stream::encrypted_len(100) as u64;
    let sealed = world.seal_declared(
        4,
        &[
            (session, stored),
            ("keys/endpoint/device-1", stored),
            ("keys/control/host", stored),
            ("keys/notification-preview/device-1", stored),
            ("keys/collection/settings", stored),
            ("authority/grants", stored),
            ("recovery/seed", stored),
            ("grants/revoked/g-1", stored),
            ("notes/readme.txt", stored),
            ("sessions/../../etc/passwd", stored),
            ("host/configuration.json", stored),
            ("host/configuration.json", stored),
        ],
    );
    let source =
        Arc::new(Scripted::serving(&world, world.bundle(&Shape::default())).publishing(&sealed));
    let prepared = restore(&world, &source, None).await.expect("a plan");
    let plan = prepared.plan();
    let verdicts: Vec<_> = plan
        .members
        .iter()
        .map(|member| member.verdict.clone())
        .collect();

    assert!(matches!(
        &verdicts[0],
        MemberVerdict::Restore {
            role: MemberRole::Session,
            ..
        }
    ));
    let kinds: Vec<Material> = verdicts[1..8]
        .iter()
        .map(|verdict| match verdict {
            MemberVerdict::Refused(MemberRefusal::Kind { material, .. }) => *material,
            other => panic!("a kind the table refuses was {other:?}"),
        })
        .collect();
    assert_eq!(
        kinds,
        vec![
            Material::EndpointPrivateKey,
            Material::ControlSigningPrivateKey,
            Material::NotificationPreviewPrivateKey,
            Material::SyncCollectionKey,
            Material::HostGrantAuthority,
            Material::RecoverySeed,
            Material::Grant { revoked: true },
        ]
    );
    // A name the convention does not know, and a traversal, are refused as unknown.
    assert!(matches!(
        verdicts[8],
        MemberVerdict::Refused(MemberRefusal::UnknownKind)
    ));
    assert!(matches!(
        verdicts[9],
        MemberVerdict::Refused(MemberRefusal::UnknownKind)
    ));
    // Two members with one name are both refused.
    assert!(matches!(
        verdicts[10],
        MemberVerdict::Refused(MemberRefusal::Duplicate)
    ));
    assert!(matches!(
        verdicts[11],
        MemberVerdict::Refused(MemberRefusal::Duplicate)
    ));
    assert_eq!(plan.restored().count(), 1, "only the session is written");
    // No name the archive supplied reaches a file name.
    for (_, file, _) in plan.restored() {
        assert!(!file.contains('/') && !file.contains(".."), "{file}");
    }
}

/// A member, the members together and the number of members have a bound, and a member over its
/// bound is listed with the number that broke it and is not read.
#[tokio::test]
async fn members_over_their_bounds_are_refused_in_the_plan_and_never_read() {
    let world = World::new();
    let stored = |plaintext: u64| {
        let blocks = plaintext.div_ceil(1 << 20).max(1);
        24 + plaintext + blocks * 17
    };
    let cap = kr_crypto::backup::MAX_SESSION_MEMBER_BYTES;
    let name = |n: u32| format!("sessions/0a1b2c3d-0000-4000-8000-{n:012}.json");

    // At the cap restores; one byte over does not.
    let names: Vec<String> = (1..=8).map(name).collect();
    let sealed = world.seal_declared(
        4,
        &[
            (names[0].as_str(), stored(cap)),
            (names[1].as_str(), stored(cap + 1)),
            ("host/configuration.json", stored(1 << 20)),
        ],
    );
    let source =
        Arc::new(Scripted::serving(&world, world.bundle(&Shape::default())).publishing(&sealed));
    let prepared = restore(&world, &source, None).await.expect("a plan");
    let plan = prepared.plan();
    assert!(matches!(
        plan.members[0].verdict,
        MemberVerdict::Restore { .. }
    ));
    assert!(matches!(
        plan.members[1].verdict,
        MemberVerdict::Refused(MemberRefusal::OverMemberCap { size, cap: c }) if size == cap + 1 && c == cap
    ));
    assert!(matches!(
        plan.members[2].verdict,
        MemberVerdict::Restore { .. }
    ));
    assert_eq!(
        source.object_reads(),
        1,
        "only the manifest was read for the plan"
    );

    // A configuration over its own bound.
    let sealed = world.seal_declared(4, &[("host/configuration.json", stored((1 << 20) + 1))]);
    let source =
        Arc::new(Scripted::serving(&world, world.bundle(&Shape::default())).publishing(&sealed));
    let prepared = restore(&world, &source, None).await.expect("a plan");
    assert!(matches!(
        prepared.plan().members[0].verdict,
        MemberVerdict::Refused(MemberRefusal::OverMemberCap { .. })
    ));

    // The total: members are admitted in manifest order until the next would pass it, and that
    // member and every later one are listed as refused.
    let total = kr_crypto::backup::MAX_RESTORED_BYTES;
    let each = cap;
    let fitting = usize::try_from(total / each).expect("a count");
    let many: Vec<String> = (1..=u32::try_from(fitting + 2).expect("a count"))
        .map(name)
        .collect();
    let members: Vec<(&str, u64)> = many
        .iter()
        .map(|name| (name.as_str(), stored(each)))
        .collect();
    let sealed = world.seal_declared(4, &members);
    let source =
        Arc::new(Scripted::serving(&world, world.bundle(&Shape::default())).publishing(&sealed));
    let prepared = restore(&world, &source, None).await.expect("a plan");
    let plan = prepared.plan();
    assert_eq!(plan.restored().count(), fitting);
    assert!(plan.restored_bytes() <= total);
    assert!(plan.members[fitting..].iter().all(|member| matches!(
        member.verdict,
        MemberVerdict::Refused(MemberRefusal::OverTotal { .. })
    )));

    // A stored length no object has.
    let sealed = world.seal_declared(4, &[("host/configuration.json", 30)]);
    let source =
        Arc::new(Scripted::serving(&world, world.bundle(&Shape::default())).publishing(&sealed));
    let prepared = restore(&world, &source, None).await.expect("a plan");
    assert!(matches!(
        prepared.plan().members[0].verdict,
        MemberVerdict::Refused(MemberRefusal::BadStoredLength)
    ));

    // More members than an archive has: the whole archive is refused.
    let flood: Vec<String> = (1..=4097_u32).map(name).collect();
    let members: Vec<(&str, u64)> = flood
        .iter()
        .map(|name| (name.as_str(), stored(10)))
        .collect();
    let sealed = world.seal_declared(4, &members);
    let source =
        Arc::new(Scripted::serving(&world, world.bundle(&Shape::default())).publishing(&sealed));
    assert!(matches!(
        restore(&world, &source, None).await.expect_err("refused"),
        RestoreError::TooManyMembers {
            count: 4097,
            limit: 4096
        }
    ));
}

/// A corrupted object is an error, never a shorter file.
#[tokio::test]
async fn a_corrupted_manifest_or_member_is_an_error_and_not_a_file() {
    let world = World::new();
    let sealed = world.seal(4, &honest_members());

    let source =
        Arc::new(Scripted::serving(&world, world.bundle(&Shape::default())).publishing(&sealed));
    source.corrupt(sealed.manifest_object);
    assert!(matches!(
        restore(&world, &source, None).await.expect_err("refused"),
        RestoreError::Archive(_)
    ));

    let source =
        Arc::new(Scripted::serving(&world, world.bundle(&Shape::default())).publishing(&sealed));
    let prepared = restore(&world, &source, None).await.expect("a plan");
    let member = prepared.plan().members[0].object_id;
    source.corrupt(member);
    assert!(matches!(
        prepared.member(member).await,
        Err(RestoreError::Member(_))
    ));
    // The other member is untouched.
    assert!(
        prepared
            .member(prepared.plan().members[1].object_id)
            .await
            .is_ok()
    );
}

/// The record a restore leaves holds the plan and the refusals and none of the kit.
#[tokio::test]
async fn the_record_says_what_was_written_and_what_was_refused_and_holds_nothing_of_the_kit() {
    let world = World::new();
    let stored = kr_crypto::stream::encrypted_len(100) as u64;
    let sealed = world.seal_declared(
        4,
        &[
            ("sessions/0a1b2c3d-0000-4000-8000-000000000001.json", stored),
            ("keys/control/host", stored),
        ],
    );
    let source =
        Arc::new(Scripted::serving(&world, world.bundle(&Shape::default())).publishing(&sealed));
    let prepared = restore(&world, &source, None).await.expect("a plan");
    let plan = prepared.plan();
    let digest = plan.digest("env-1", b"/restore/a", "").expect("a digest");
    let written = vec![plan.members[0].object_id];
    let record = plan.record(&digest, &written, false).to_string();
    assert!(record.contains("kalareach-restore/1"));
    assert!(record.contains(&digest));
    assert!(record.contains("material_never_restored"));
    assert!(record.contains("session-0001.json"));
    let kit = world.kit();
    let seed_text = serde_json::to_string(&kit.seed).expect("the seed as the kit writes it");
    for secret in [world.locator.as_str(), seed_text.trim_matches('"')] {
        assert!(!record.contains(secret), "the record holds a kit value");
    }
    assert!(!format!("{prepared:?}").contains(&world.locator));
    // The kit and the context that reaches the bundle render without the locator, the seed or its
    // checksum, so a log line that carries one carries none of them.
    let context = kr_protocol::archive::RecoveryContext {
        service_origin: ORIGIN.to_owned(),
        bundle_locator: world.locator.clone(),
    };
    for shown in [format!("{kit:?}"), format!("{context:?}")] {
        assert!(!shown.contains(&world.locator), "{shown}");
        assert!(!shown.contains("checksum"), "{shown}");
    }
}

/// What a restore writes is a prefix of what fits: once one member would pass the total, it and
/// every member after it are refused, small ones included.
#[tokio::test]
async fn once_a_member_would_pass_the_total_every_later_member_is_refused() {
    let world = World::new();
    let stored = |plaintext: u64| 24 + plaintext + plaintext.div_ceil(1 << 20).max(1) * 17;
    let session = |n: u32| format!("sessions/0a1b2c3d-0000-4000-8000-{n:012}.json");
    let big = 190_u64 << 20;
    let names: Vec<String> = (1..=9).map(session).collect();
    let mut members: Vec<(&str, u64)> = names
        .iter()
        .map(|name| (name.as_str(), stored(big)))
        .collect();
    // 8 x 190 MiB is 1,520 MiB, so the ninth session passes the 1,536 MiB total and the
    // configuration after it, which alone would fit, is refused with it.
    members.push(("host/configuration.json", stored(1 << 20)));
    let sealed = world.seal_declared(4, &members);
    let source =
        Arc::new(Scripted::serving(&world, world.bundle(&Shape::default())).publishing(&sealed));
    let prepared = restore(&world, &source, None).await.expect("a plan");
    let plan = prepared.plan();
    assert_eq!(plan.restored().count(), 8);
    assert!(matches!(
        plan.members[8].verdict,
        MemberVerdict::Refused(MemberRefusal::OverTotal { .. })
    ));
    assert!(matches!(
        plan.members[9].verdict,
        MemberVerdict::Refused(MemberRefusal::OverTotal { .. })
    ));
}

/// A member is asked for by the plan's own entry: a refused one, or an object the manifest never
/// named, is not read.
#[tokio::test]
async fn only_a_member_the_plan_writes_can_be_read() {
    let world = World::new();
    let stored = kr_crypto::stream::encrypted_len(100) as u64;
    let sealed = world.seal_declared(
        4,
        &[
            ("sessions/0a1b2c3d-0000-4000-8000-000000000001.json", stored),
            ("keys/control/host", stored),
        ],
    );
    let source =
        Arc::new(Scripted::serving(&world, world.bundle(&Shape::default())).publishing(&sealed));
    let prepared = restore(&world, &source, None).await.expect("a plan");
    let reads = source.object_reads();
    for object in [
        prepared.plan().members[1].object_id,
        BackupObjectId::new(id(0x99)),
    ] {
        assert!(matches!(
            prepared.member(object).await,
            Err(RestoreError::NotInPlan)
        ));
    }
    assert_eq!(source.object_reads(), reads, "nothing was read for either");
}

/// A service that answers a read with no bytes cannot hold a restore in a loop.
#[tokio::test]
async fn a_service_that_answers_a_read_with_nothing_stops_the_restore() {
    let world = World::new();
    let sealed = world.seal(4, &honest_members());
    let mut source = Scripted::serving(&world, world.bundle(&Shape::default())).publishing(&sealed);
    source.serves_empty_ranges = true;
    // The script fails the test when the restore asks more than a few times, so a restore that
    // never gave up fails here and does not hang.
    let stopped = restore(&world, &Arc::new(source), None).await;
    assert!(matches!(stopped.expect_err("stopped"), RestoreError::Range));
}
