//! The retention rules of managed backup storage, against the web service itself.
//!
//! Section 20: cloud history backup is off until it is enabled; when enabled, thirty daily
//! snapshots are kept; a deleted object is a tombstone for seven days and its ciphertext is then
//! deleted; the service reports storage and deletion status; the provider's own recovery window is
//! published at thirty days. The web service's suites show each rule inside its own runtime. These
//! legs show them through the client every other managed call uses, on a local deployment, so the
//! chain length the host keeps and the chain length the service keeps are held to each other.
//!
//! A tombstone's window is seven days and a local deployment cannot be made to wait that long. The
//! web repository's local restore driver moves the window instead: `age` moves every tombstone in
//! the deployment's storage index back by a number of days, and `sweep` runs the pass that removes
//! the ciphertext of tombstones that are due. `scripts/e2e-backup.sh` runs them between the three
//! phases, each phase a test of its own that reads what the one before it left in the run
//! directory.
//!
//! 1. A device turns backup storage on, backs thirty-one generations up through the real storage
//!    and manifest services, and deletes the objects of the generation the thirty-first pushed out
//!    of the chain.
//! 2. After a sweep inside the window: nothing was removed, and the status still reports the
//!    tombstones and the bytes they hold.
//! 3. After the window was aged away and swept: the tombstones are gone and their bytes are no
//!    longer reported; the readable generations are as they were; the removed ciphertext cannot be
//!    read.
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-REQ-20.22 | the three phases together: `thirty_daily_snapshots_are_kept_and_a_deleted_generation_is_a_tombstone`, `a_sweep_inside_the_window_removes_nothing`, `after_the_window_the_sweep_removes_the_tombstone_and_its_charge_ends` |
//!
//! Not shown here: deleting a whole collection from the account console. That route takes a browser
//! session and a fresh sign-in, which the driver's account does not hold; the web service's console
//! suite shows it inside its own runtime (every object of the collection a tombstone for seven days,
//! the collection closed to new uploads and publications, its generations' descriptors kept).
//!
//! What a deployed run adds is the real clock for the seven days and the provider's own thirty,
//! which no client can observe; it is not run (it would need a production token and would spend a
//! production account's storage for a week).
//!
//! # What they leave
//!
//! Nothing outside the run directory and the local deployment's persistence, which the script
//! removes with it.

use std::sync::Arc;

use kr_backup_integration::{DeviceSigner, RunDirectory, TOKENS_VARIABLE, account_tokens, skipped};
use kr_client::recovery::{
    ArchiveServices, BundleStore, SETTINGS_FILENAME, SettingsArchive, SettingsCollection,
};
use kr_client::services::account::{AccountTokenSource, BACKUP_WRITE_SCOPE};
use kr_client::services::backup::ManagedBackupManifestService;
use kr_client::services::relay::ServiceSigner;
use kr_client::services::storage::{ManagedStorageService, StorageStatus};
use kr_client::services::sync::ManagedSyncService;
use kr_client::services::{
    BackupManifestService, BackupState, RetentionChange, StorageService, SyncBackupService,
};
use kr_client::sync::{SettingValue, SyncBody, SyncObject, SyncSettings, SyncStore};
use kr_crypto::backup::{ArchiveExpectation, ArchiveReader, GenerationExpectation, open_archive};
use kr_crypto::kdf::RecoverySeed;
use kr_crypto::keys::StoredEnvelopeKeyPair;
use kr_protocol::archive::{RecoveryContext, TrustedWriter};
use kr_protocol::ids::{
    ArchiveId, BackupGeneration, BackupObjectId, BackupWriterRevision, DeviceId, SyncObjectId,
};
use kr_protocol::scalars::{TimestampMs, Uuid};
use kr_sync_integration::{Deployment, fresh_uuid, now_ms, proved};

/// The variable naming the directory the legs keep what they hand each other in.
const RUN_VARIABLE: &str = "KR_BACKUP_RUN_DIR";

/// The file the first phase hands the others: the archive and the objects it deleted.
const PLAN: &str = "retention.json";

/// How many generations the service keeps, and so how many the host may.
const KEPT: u64 = 30;

/// A day in milliseconds.
const DAY_MS: u64 = 24 * 60 * 60 * 1000;

fn now() -> TimestampMs {
    TimestampMs::new(now_ms())
}

/// What the service wrote for an instant, as milliseconds since the epoch.
///
/// The service writes `YYYY-MM-DDTHH:MM:SS.mmmZ`. The date is counted from the civil calendar
/// (days from 1970-01-01), so no clock library is needed for one comparison.
fn epoch_ms(text: &str) -> u64 {
    let number = |range: std::ops::Range<usize>| -> i64 {
        text.get(range)
            .and_then(|digits| digits.parse().ok())
            .unwrap_or_else(|| panic!("an instant the service wrote: {text}"))
    };
    let (year, month, day) = (number(0..4), number(5..7), number(8..10));
    let (hour, minute, second, milli) = (
        number(11..13),
        number(14..16),
        number(17..19),
        number(20..23),
    );
    let shifted = if month <= 2 { year - 1 } else { year };
    let era = shifted.div_euclid(400);
    let year_of_era = shifted - era * 400;
    let month_index = (month + 9) % 12;
    let day_of_year = (153 * month_index + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146_097 + day_of_era - 719_468;
    let seconds = days * 86_400 + hour * 3_600 + minute * 60 + second;
    u64::try_from(seconds * 1_000 + milli).expect("an instant after the epoch")
}

/// The services one device speaks to, signing with its own key and presenting the account's
/// `backup.write` token.
struct Services {
    signer: Arc<DeviceSigner>,
    tokens: Arc<dyn AccountTokenSource>,
    deployment: Deployment,
}

impl Services {
    fn new(
        run: &RunDirectory,
        deployment: &Deployment,
        tokens: Arc<dyn AccountTokenSource>,
    ) -> Self {
        Self {
            signer: Arc::new(DeviceSigner::new(run.device_keys())),
            tokens,
            deployment: deployment.clone(),
        }
    }

    fn signer(&self) -> Arc<dyn ServiceSigner> {
        Arc::clone(&self.signer) as Arc<dyn ServiceSigner>
    }

    fn storage(&self) -> ManagedStorageService {
        ManagedStorageService::new(
            self.deployment.origin().clone(),
            self.deployment.transport(),
            self.signer(),
        )
        .presenting(Arc::clone(&self.tokens))
    }

    fn manifest(&self) -> ManagedBackupManifestService {
        ManagedBackupManifestService::new(
            self.deployment.origin().clone(),
            self.deployment.transport(),
            self.signer(),
        )
        .presenting(Arc::clone(&self.tokens))
    }

    fn bundles(&self) -> Arc<dyn SyncBackupService> {
        Arc::new(
            ManagedSyncService::new(
                self.deployment.origin().clone(),
                self.deployment.transport(),
                self.signer(),
            )
            .presenting(Arc::clone(&self.tokens), BACKUP_WRITE_SCOPE),
        )
    }

    fn archive_services(&self) -> ArchiveServices {
        ArchiveServices {
            origin: self.deployment.origin().clone(),
            http: self.deployment.transport(),
            signer: self.signer(),
            tokens: Arc::clone(&self.tokens),
        }
    }
}

/// What the status read says, with the figures every phase holds it to.
async fn status(services: &Services) -> StorageStatus {
    services.storage().status().await.expect("a status read")
}

/// The phases' common start: the deployment, the account's tokens and the run directory, or nothing
/// when the run named none of them.
fn start() -> Option<(Deployment, Arc<dyn AccountTokenSource>, RunDirectory)> {
    let deployment = Deployment::from_environment()?;
    let Some(tokens) = account_tokens(deployment.origin().as_str()) else {
        skipped(TOKENS_VARIABLE);
        return None;
    };
    let Some(run) = RunDirectory::from_variable(RUN_VARIABLE) else {
        skipped(RUN_VARIABLE);
        return None;
    };
    Some((deployment, tokens.write, run))
}

/// Phase 1: backup storage off, then on at thirty snapshots; thirty-one generations through the
/// real services keep thirty; the objects of the generation pushed out are deleted and are
/// tombstones for seven days that are still charged.
#[tokio::test]
async fn thirty_daily_snapshots_are_kept_and_a_deleted_generation_is_a_tombstone() {
    let Some((deployment, tokens, run)) = start() else {
        return;
    };
    assert!(
        !run.path(PLAN).exists(),
        "this run directory already holds a retention leg; each run starts from an empty one"
    );
    let services = Services::new(&run, &deployment, tokens);

    // Off until it is asked for, with the retention the service publishes.
    let before = status(&services).await;
    assert_eq!(
        before.backup,
        BackupState::Off,
        "backup is off until it is turned on"
    );
    assert_eq!(
        (
            before.retention.daily_snapshots,
            before.retention.tombstone_days,
            before.retention.provider_recovery_days
        ),
        (30, 7, 30),
        "thirty daily snapshots, seven days of tombstone, a provider bound of thirty days"
    );
    let turned_on = services
        .storage()
        .set_retention(&RetentionChange {
            backup: BackupState::On,
            daily_snapshots: Some(30),
            expected_revision: before.retention_revision,
        })
        .await
        .expect("the change is answered");
    match turned_on {
        kr_client::services::storage::RetentionAnswer::Done(set) => {
            assert!(set.changed);
            assert_eq!(set.backup, BackupState::On);
            assert_eq!(set.retention.daily_snapshots, 30);
        }
        other => panic!("the change was made against the revision it read: {other:?}"),
    }

    // The device: a recovery seed, a writer that is also the owner, a producer, one settings
    // object, and the bundle first.
    let disk = tempfile::tempdir().expect("a directory on the internal disk");
    let seed = RecoverySeed::generate().expect("a seed");
    let producer = StoredEnvelopeKeyPair::generate().expect("a producer key");
    let keys = run.device_keys();
    let archive_id = ArchiveId::new(fresh_uuid());
    let locator = kr_client::recovery::fresh_locator().expect("a locator");
    let origin = deployment.origin().as_str().to_owned();
    let records = disk.path().join("records");
    std::fs::create_dir_all(&records).expect("a directory");
    let bundle_dir = disk.path().join("bundle");
    std::fs::create_dir_all(&bundle_dir).expect("a directory");
    let mut bundles = BundleStore::open(
        services.bundles(),
        RecoveryContext {
            service_origin: origin.clone(),
            bundle_locator: locator,
        },
        &bundle_dir,
    )
    .expect("the bundle store");
    let mut bundle = BundleStore::empty(now());
    let recovery = seed.recipient().expect("the recovery recipient");
    let archive = SettingsArchive::enable(
        SettingsCollection {
            archive_id,
            service_origin: origin,
            owner_device_id: DeviceId::new(fresh_uuid()),
            writer: keys.authorisation.clone(),
            writer_revision: BackupWriterRevision::new(1),
            producer: producer.clone(),
            recovery: *recovery.public(),
            records,
        },
        &mut bundles,
        &seed,
        &mut bundle,
        &keys.authorisation,
        &services.manifest(),
        now(),
    )
    .await
    .expect("the bundle landed and the writer is enrolled");

    let store = SyncStore::open(disk.path().join("sync")).expect("a sync store");
    let object_id = SyncObjectId::new(fresh_uuid());
    store
        .put_object(&SyncObject {
            object_id,
            revision: kr_client::sync::fresh_revision().expect("a revision"),
            device_id: DeviceId::new(fresh_uuid()),
            updated_at_ms: now(),
            body: SyncBody::Settings(SyncSettings {
                values: [("theme".to_owned(), SettingValue::Text("dusk".to_owned()))]
                    .into_iter()
                    .collect(),
                pinned_labels: std::collections::BTreeSet::new(),
            }),
            went_over: Vec::new(),
        })
        .expect("the settings");

    // Thirty-one generations. The first is opened as it lands, for the identity of its objects;
    // the thirty-first is the one that pushes it out of the chain.
    let archive_services = services.archive_services();
    let mut first_objects: Vec<BackupObjectId> = Vec::new();
    for generation in 1..=KEPT + 1 {
        let backed_up = archive
            .back_up(
                &store,
                object_id,
                BackupGeneration::new(generation),
                &archive_services,
                now(),
            )
            .await
            .unwrap_or_else(|error| panic!("generation {generation} was backed up: {error}"));
        let published = backed_up.published;
        assert!(!published.duplicate);
        assert_eq!(published.collection.checkpoint_generation, generation);
        assert_eq!(
            published.collection.generations.len() as u64,
            generation.min(KEPT),
            "the chain holds {} descriptors after generation {generation}",
            generation.min(KEPT)
        );
        if generation <= KEPT {
            assert!(
                published.dropped.is_empty(),
                "nothing is dropped at {generation}"
            );
        } else {
            assert_eq!(
                published.dropped,
                [1],
                "the thirty-first publication drops the first"
            );
        }
        if generation == 1 {
            first_objects = objects_of(&services, archive_id, 1, &seed, &producer, &keys).await;
        }
    }

    // The chain, as a fetch reads it: thirty generations, the newest first, and the first gone.
    let held = services
        .manifest()
        .fetch(archive_id, None, None)
        .await
        .expect("a fetch")
        .expect("the newest generation");
    assert_eq!(held.collection.checkpoint_generation, KEPT + 1);
    assert_eq!(held.collection.generations.len() as u64, KEPT);
    assert_eq!(held.collection.generations.first(), Some(&(KEPT + 1)));
    assert_eq!(held.collection.generations.last(), Some(&2));
    assert!(
        services
            .manifest()
            .fetch(archive_id, Some(BackupGeneration::new(1)), None)
            .await
            .expect("a fetch")
            .is_none(),
        "the service holds nothing as old as generation 1"
    );

    // The objects of the pushed-out generation are deleted: each is a tombstone at once, charged
    // for seven days.
    let stored_before = status(&services).await;
    assert_eq!(stored_before.tombstoned.objects, 0);
    let mut retained = 0;
    let mut first_purge: Option<String> = None;
    for object in &first_objects {
        let deleted = services
            .storage()
            .delete_object(archive_id, *object)
            .await
            .expect("the object is deleted");
        assert!(!deleted.already, "this deletion made the tombstone");
        assert_eq!(
            epoch_ms(&deleted.purge_after) - epoch_ms(&deleted.deleted_at),
            7 * DAY_MS,
            "the ciphertext goes seven days after the deletion"
        );
        assert!(
            deleted.retained_bytes > 0,
            "the deleted bytes are still charged"
        );
        assert_eq!(deleted.retention.tombstone_days, 7);
        retained += deleted.retained_bytes;
        first_purge.get_or_insert(deleted.purge_after);
        let again = services
            .storage()
            .delete_object(archive_id, *object)
            .await
            .expect("the same deletion is answered again");
        assert!(again.already, "a second deletion finds the tombstone");
    }
    let after = status(&services).await;
    assert_eq!(after.tombstoned.objects, first_objects.len() as u64);
    assert_eq!(
        after.tombstoned.bytes, retained,
        "deleted bytes stay charged"
    );
    assert_eq!(
        after.next_purge, first_purge,
        "the status says when the first is removed"
    );
    assert_eq!(
        after.stored.objects,
        stored_before.stored.objects - first_objects.len() as u64,
        "a tombstone is not readable"
    );
    let unreadable = services
        .storage()
        .read_object(archive_id, first_objects[0], 0, 1)
        .await;
    assert!(unreadable.is_err(), "a deleted object is not readable");

    run.write(
        PLAN,
        &serde_json::json!({
            "archive_id": archive_id.to_string(),
            "objects": first_objects.iter().map(|object| object.to_string()).collect::<Vec<_>>(),
            "tombstoned_objects": after.tombstoned.objects,
            "tombstoned_bytes": after.tombstoned.bytes,
            "stored_objects": after.stored.objects,
            "stored_bytes": after.stored.bytes,
            "next_purge": after.next_purge,
        }),
    );
}

/// The objects one generation of the settings archive holds: its member and its encrypted manifest.
async fn objects_of(
    services: &Services,
    archive_id: ArchiveId,
    generation: u64,
    seed: &RecoverySeed,
    producer: &StoredEnvelopeKeyPair,
    keys: &kr_crypto::keys::DeviceKeys,
) -> Vec<BackupObjectId> {
    let found = services
        .manifest()
        .fetch(archive_id, Some(BackupGeneration::new(generation)), None)
        .await
        .expect("a fetch")
        .expect("the generation is held");
    let descriptor_bytes =
        kr_cbor::to_canonical_vec(&found.publication.payload.descriptor).expect("a descriptor");
    let descriptor = kr_crypto::backup::read_descriptor(&descriptor_bytes).expect("a descriptor");
    let manifest = &descriptor.encrypted_manifest;
    let reach = services.storage();
    let encrypted_manifest = StorageService::read_object(
        &reach,
        archive_id,
        manifest.object_id,
        0,
        manifest.encrypted_len.get(),
    )
    .await
    .expect("the manifest reads")
    .bytes;
    let recovery = seed.recipient().expect("the recovery recipient");
    let writers = vec![TrustedWriter {
        writer_key_id: keys.authorisation.key_id(),
        signing_key: *keys.authorisation.public(),
        enrolled_at_ms: TimestampMs::new(0),
    }];
    let reader = ArchiveReader::Recovery(&recovery);
    let opened = open_archive(
        &reader,
        producer.public(),
        &writers,
        &ArchiveExpectation {
            archive_id,
            generation: GenerationExpectation::Unverified,
        },
        &descriptor_bytes,
        &encrypted_manifest,
    )
    .expect("the archive opens");
    let mut objects: Vec<BackupObjectId> = opened
        .objects()
        .iter()
        .map(|member| {
            assert_eq!(member.filename, SETTINGS_FILENAME);
            member.object.object_id
        })
        .collect();
    objects.push(manifest.object_id);
    objects
}

/// Phase 2: a sweep while the window is open removes nothing, and the status still reports the
/// tombstones and the bytes they hold.
#[tokio::test]
async fn a_sweep_inside_the_window_removes_nothing() {
    let Some((deployment, tokens, run)) = start() else {
        return;
    };
    let plan = run.read(PLAN);
    let services = Services::new(&run, &deployment, tokens);
    let now = status(&services).await;
    assert_eq!(
        now.tombstoned.objects,
        plan["tombstoned_objects"].as_u64().expect("a count"),
        "the sweep left the tombstones where they were"
    );
    assert_eq!(
        now.tombstoned.bytes,
        plan["tombstoned_bytes"].as_u64().expect("a figure")
    );
    assert_eq!(
        now.stored.objects,
        plan["stored_objects"].as_u64().expect("a count")
    );
    assert_eq!(
        now.next_purge.as_deref(),
        plan["next_purge"].as_str(),
        "the window has not moved"
    );
    let object = plan["objects"][0]
        .as_str()
        .and_then(|text| text.parse::<Uuid>().ok())
        .map(BackupObjectId::new)
        .expect("an object");
    let archive_id = plan["archive_id"]
        .as_str()
        .and_then(|text| text.parse::<Uuid>().ok())
        .map(ArchiveId::new)
        .expect("an archive");
    // Still a tombstone: deleting it again finds the one that is there.
    let again = services
        .storage()
        .delete_object(archive_id, object)
        .await
        .expect("answered");
    assert!(again.already);
}

/// Phase 3: after the window was aged away and the sweep ran, the tombstones are gone, their bytes
/// are no longer reported, the readable objects are as they were, and the removed ciphertext is not
/// there to read.
#[tokio::test]
async fn after_the_window_the_sweep_removes_the_tombstone_and_its_charge_ends() {
    let Some((deployment, tokens, run)) = start() else {
        return;
    };
    let plan = run.read(PLAN);
    let services = Services::new(&run, &deployment, tokens);
    let now = status(&services).await;
    assert_eq!(
        (now.tombstoned.objects, now.tombstoned.bytes),
        (0, 0),
        "the removed ciphertext is no longer charged"
    );
    assert_eq!(now.next_purge, None, "nothing is waiting to be removed");
    assert_eq!(
        (now.stored.objects, now.stored.bytes),
        (
            plan["stored_objects"].as_u64().expect("a count"),
            plan["stored_bytes"].as_u64().expect("a figure")
        ),
        "the readable objects were not touched by the sweep"
    );
    let archive_id = plan["archive_id"]
        .as_str()
        .and_then(|text| text.parse::<Uuid>().ok())
        .map(ArchiveId::new)
        .expect("an archive");
    let object = plan["objects"][0]
        .as_str()
        .and_then(|text| text.parse::<Uuid>().ok())
        .map(BackupObjectId::new)
        .expect("an object");
    assert!(
        services
            .storage()
            .read_object(archive_id, object, 0, 1)
            .await
            .is_err(),
        "the removed ciphertext cannot be read"
    );
    let chain = services
        .manifest()
        .fetch(archive_id, None, None)
        .await
        .expect("a fetch")
        .expect("the newest generation");
    assert_eq!(
        chain.collection.generations.len() as u64,
        KEPT,
        "the chain still holds its thirty"
    );
    proved(
        "retention",
        &deployment,
        "backup storage was off until asked for; thirty-one generations kept thirty; the deleted generation's objects were tombstones charged for seven days, unchanged by a sweep inside the window, and removed and no longer charged by the sweep after it; the published provider bound is thirty days",
    );
}
