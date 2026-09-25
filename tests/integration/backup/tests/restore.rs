//! A device's settings-sync stores meeting a deployment restored from an export.
//!
//! A deployment put back from an export gives every collection it holds, and every one created in
//! it afterwards, a recovery identity of its own, and names it beside every place it answers with.
//! A device that made its stores before the export meets a collection put back rather than one that
//! went backwards or forked. Every other suite holds `kr-client` to a service that pretends to be
//! put back. This leg holds it to two local deployments of the web service: a source, whose export
//! is loaded into a target prepared for it on the target's restore-test schedule.
//!
//! # Three phases
//!
//! The deployments are exported, stopped, prepared and restored between the phases, by
//! `scripts/e2e-backup.sh` through the web repository's local restore driver. The device's keys and
//! stores live in [`RUN_VARIABLE`]'s directory between them, as they would on a device that
//! restarts, and each phase reads what the one before it wrote there.
//!
//! 1. Before the export, on the source: a settings object written twice, a shared collection
//!    started and installed, one draft published and another only created. The phase writes the
//!    names of the objects the export has to carry.
//! 2. After the export, on the source: the settings object written a third time, the published
//!    draft edited and published again, and the other draft published with its answer lost, into a
//!    collection the export does not hold. Then a copy of every store meets the source as the
//!    control: nothing there was put back, and nothing moves as though it had been.
//! 3. The stores meet the target: every answer names the target's recovery, the settings write the
//!    restore lost comes back beside the device's own object, the membership follows its own head
//!    into the new history, the published draft's restored revision comes down beside the edited
//!    one, and the draft whose answer was lost is ended at once without ever being sent again.
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-REQ-20.13, KR-REQ-24.28, KR-REQ-18.05 and KR-REQ-24.13, client side across a restore | the three phases together, against a restored local deployment |
//!
//! # What it leaves
//!
//! Nothing outside the run directory and the two deployments' persistence, which the script
//! removes with them.

use std::path::Path;
use std::sync::Arc;

use kr_backup_integration::{DeviceSigner, RunDirectory, Watched, copy_tree, skipped, variable};
use kr_client::drafts::{
    DraftSealer, DraftStore, DraftSync, DraftTarget, Published as DraftPublished,
};
use kr_client::services::relay::{ServiceHttp, ServiceSigner};
use kr_client::services::sync::ManagedSyncService;
use kr_client::services::{ServiceFuture, SyncBackupService, SyncPosition, SyncRecoveryId};
use kr_client::sync::membership::{
    DeviceDirectory, HostAnswers, HostDevice, HostReport, KeyRecordService, Refreshed, Step,
    SyncMembership,
};
use kr_client::sync::{
    CollectionSealer, MemoryCollectionKeys, Published, RequestState, Restored, SettingValue,
    StoredCollectionKeys, SyncBody, SyncClient, SyncObject, SyncSettings, SyncStore,
    fresh_object_id, fresh_revision,
};
use kr_crypto::store::StoreSelection;
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::{DeviceId, DraftId, SessionId, SyncCollectionId, SyncObjectId};
use kr_protocol::scalars::{TimestampMs, Uuid};
use kr_protocol::service::GatewayOrigin;
use kr_protocol::sync::SyncObjectKind;
use kr_sync_integration::{Deployment, fresh_uuid, now_ms};

/// The variable naming the directory the device keeps its keys and stores in between phases.
const RUN_VARIABLE: &str = "KR_BACKUP_RUN_DIR";
/// The variable naming the source deployment's loopback origin.
const SOURCE_VARIABLE: &str = "KR_BACKUP_SOURCE_ORIGIN";
/// The variable naming the restored deployment's loopback origin.
const TARGET_VARIABLE: &str = "KR_BACKUP_TARGET_ORIGIN";
/// The variable naming the recovery the restored deployment recorded.
const RECOVERY_VARIABLE: &str = "KR_BACKUP_RECOVERY_ID";

/// The file each phase hands the next: what the device made and where each write landed.
const PLAN: &str = "plan.json";
/// The file naming, one `<kind>=<name>` a line, the objects the export has to carry.
const EXPECTED: &str = "expected-objects.txt";

/// The name the settings and drafts are sealed under, and the scopes the run's keys are kept in.
const SEALING: &str = "settings-and-drafts";
const SEALING_SCOPE: &str = "kalareach-backup-sealing";
const MEMBERSHIP_SCOPE: &str = "kalareach-backup-membership";

fn now() -> TimestampMs {
    TimestampMs::new(now_ms())
}

/* -------------------------------------------------------------------------- */
/* One device, as it stands in a run directory                                */
/* -------------------------------------------------------------------------- */

/// The one host this device is paired with, answering that the device is paired and manages it.
#[derive(Debug)]
struct Hosts {
    device: HostDevice,
}

impl DeviceDirectory for Hosts {
    fn answers(&self) -> ServiceFuture<'_, Option<HostAnswers>> {
        let answers = HostAnswers {
            reports: vec![HostReport {
                devices: vec![self.device],
            }],
        };
        Box::pin(std::future::ready(Ok(Some(answers))))
    }
}

/// A device's stores over one service, as a device opens them when it starts.
struct Device {
    transport: Arc<Watched>,
    settings: SyncClient,
    drafts: DraftStore,
    draft_sync: DraftSync,
    membership: SyncMembership,
}

/// Opens the device whose stores are under `stores`, speaking to `origin` and holding every answer
/// to naming `expected`.
fn open_device(
    run: &RunDirectory,
    stores: &Path,
    origin: &str,
    expected: Option<SyncRecoveryId>,
    device_id: DeviceId,
) -> Device {
    let keys = run.device_keys();
    let host_device = HostDevice {
        authorisation: *keys.authorisation.public(),
        stored_envelope: *keys.stored_envelope.public(),
        manages_host: true,
        revoked: false,
    };
    let signer = Arc::new(DeviceSigner::new(run.device_keys()));
    let origin = GatewayOrigin::new(origin).expect("a loopback origin");
    let transport = Watched::new(Deployment::at(origin.clone()).transport(), expected);
    let service = Arc::new(ManagedSyncService::new(
        origin,
        Arc::clone(&transport) as Arc<dyn ServiceHttp>,
        Arc::clone(&signer) as Arc<dyn ServiceSigner>,
    ));
    let sealing = StoredCollectionKeys::open(
        StoreSelection::File,
        SEALING_SCOPE,
        &run.path("sealing-keys"),
        SEALING_SCOPE,
    )
    .expect("the run's sealing keys");
    let sealer: Arc<dyn DraftSealer> =
        Arc::new(CollectionSealer::new(Arc::new(sealing), SEALING, 1));
    let membership_keys = StoredCollectionKeys::open(
        StoreSelection::File,
        MEMBERSHIP_SCOPE,
        &stores.join("membership-keys"),
        MEMBERSHIP_SCOPE,
    )
    .expect("the membership's key store");
    Device {
        settings: SyncClient::new(
            Arc::clone(&service) as Arc<dyn SyncBackupService>,
            Arc::clone(&sealer),
            SyncStore::open(stores.join("settings")).expect("the settings store"),
        ),
        drafts: DraftStore::open(stores.join("drafts"), device_id).expect("the draft store"),
        draft_sync: DraftSync::new(
            Arc::clone(&service) as Arc<dyn SyncBackupService>,
            sealer,
            SyncStore::open(stores.join("drafts-sync")).expect("the drafts' sync store"),
        ),
        membership: SyncMembership::open(
            stores.join("membership"),
            &keys,
            membership_keys,
            Arc::clone(&service) as Arc<dyn KeyRecordService>,
            Arc::new(Hosts {
                device: host_device,
            }),
        )
        .expect("the membership store"),
        transport,
    }
}

/// Draws the key the run's settings and drafts are sealed under, once.
fn draw_sealing_key(run: &RunDirectory) {
    let key = MemoryCollectionKeys::new()
        .draw(SEALING, 1)
        .expect("a sealing key");
    StoredCollectionKeys::open(
        StoreSelection::File,
        SEALING_SCOPE,
        &run.path("sealing-keys"),
        SEALING_SCOPE,
    )
    .expect("the run's sealing keys")
    .put(SEALING, 1, &key)
    .expect("stored");
}

fn settings_object(object_id: SyncObjectId, device_id: DeviceId, theme: &str) -> SyncObject {
    SyncObject {
        object_id,
        revision: fresh_revision().expect("a revision"),
        device_id,
        updated_at_ms: now(),
        body: SyncBody::Settings(SyncSettings {
            values: [("theme".to_owned(), SettingValue::Text(theme.to_owned()))]
                .into_iter()
                .collect(),
            pinned_labels: std::collections::BTreeSet::new(),
        }),
    }
}

/// Stores a new revision of the settings object and publishes it.
async fn publish_settings(
    device: &Device,
    object_id: SyncObjectId,
    device_id: DeviceId,
    theme: &str,
) -> (SyncObject, Published) {
    let object = settings_object(object_id, device_id, theme);
    device.settings.store().put_object(&object).expect("stored");
    let published = device
        .settings
        .publish(object_id, now())
        .await
        .expect("an answer");
    (object, published)
}

fn accepted_at(published: &Published) -> SyncPosition {
    match published {
        Published::Accepted { position } => *position,
        other => panic!("the service accepted the write: {other:?}"),
    }
}

fn draft_accepted_at(published: &DraftPublished) -> SyncPosition {
    match published {
        DraftPublished::Accepted { position } => *position,
        other => panic!("the service accepted the draft: {other:?}"),
    }
}

fn position_json(position: SyncPosition) -> serde_json::Value {
    serde_json::to_value(position).expect("a position")
}

fn position_from(value: &serde_json::Value) -> SyncPosition {
    serde_json::from_value(value.clone()).expect("a position")
}

fn uuid_from(value: &serde_json::Value) -> Uuid {
    value
        .as_str()
        .and_then(|text| text.parse().ok())
        .expect("an identifier")
}

fn in_history(position: SyncPosition, recovery: Option<SyncRecoveryId>) -> SyncPosition {
    SyncPosition {
        recovery: kr_protocol::scalars::Nullable::from(recovery),
        ..position
    }
}

/* -------------------------------------------------------------------------- */
/* Phase 1: before the export                                                  */
/* -------------------------------------------------------------------------- */

/// Phase 1, on the source before its export: a settings object written twice, a shared collection
/// started and installed, one draft published and another only created.
#[tokio::test]
async fn a_device_makes_its_settings_drafts_and_membership_before_the_export() {
    let Some(run) = RunDirectory::from_variable(RUN_VARIABLE) else {
        return skipped(RUN_VARIABLE);
    };
    let Some(source) = variable(SOURCE_VARIABLE) else {
        return skipped(SOURCE_VARIABLE);
    };
    assert!(
        !run.path(PLAN).exists(),
        "this run directory already holds a device; each run starts from an empty one"
    );
    draw_sealing_key(&run);
    let device_id = DeviceId::new(fresh_uuid());
    let mut device = open_device(&run, &run.path("device"), &source, None, device_id);

    // A settings object, written twice.
    let object_id = fresh_object_id().expect("an identity");
    let (_, first) = publish_settings(&device, object_id, device_id, "dark").await;
    let first = accepted_at(&first);
    assert_eq!(
        (first.write_sequence, first.recovery()),
        (1, None),
        "the first write, in a history never put back"
    );
    let (second_object, second) = publish_settings(&device, object_id, device_id, "light").await;
    let second = accepted_at(&second);
    assert_eq!((second.write_sequence, second.recovery()), (2, None));

    // A shared collection, started here and installed: its first key record lists this device.
    let collection = device
        .membership
        .start(SyncCollectionId::new(fresh_uuid()), now())
        .await
        .expect("started");
    let steps = device
        .membership
        .reconcile(now())
        .await
        .expect("reconciled");
    let status = device
        .membership
        .members()
        .expect("a readable membership")
        .expect("a membership");
    assert_eq!(
        (status.installed, status.head, status.recovery, status.out),
        (Some((0, 1)), 1, None, false),
        "the first record is installed in a history never put back: {steps:?}"
    );
    assert!(
        device
            .membership
            .publishes()
            .expect("a readable membership")
    );

    // One draft published, and one only created.
    let target = DraftTarget::session(SessionId::new(fresh_uuid()));
    let published = device
        .drafts
        .create(
            target.clone(),
            "a draft published before the export".to_owned(),
            now(),
        )
        .expect("a draft");
    let published_at = draft_accepted_at(
        &device
            .draft_sync
            .publish(
                &device.drafts,
                published.draft_id,
                published.revision,
                now(),
            )
            .await
            .expect("an answer"),
    );
    assert_eq!(
        (published_at.write_sequence, published_at.recovery()),
        (1, None)
    );
    let lost = device
        .drafts
        .create(
            target,
            "a draft whose publication's answer is lost".to_owned(),
            now(),
        )
        .expect("a draft");

    device.transport.assert_every_answer_named_its_history();

    // The objects the export has to carry, by the names the service gives them: a collection
    // lives in its home installation's namespace, and the ledger and the index of the shared
    // collections that list the installation are the installation's own.
    let installation = DeviceSigner::new(run.device_keys()).installation();
    let principal = format!("installation:{installation}");
    let expected = [
        format!("sync-collection={principal}/{object_id}"),
        format!("sync-collection={principal}/{}", published.draft_id),
        format!("sync-collection={principal}/{}", collection.collection_id),
        format!("sync-memberships={principal}"),
        format!("account-ledger={principal}"),
    ];
    std::fs::write(run.path(EXPECTED), format!("{}\n", expected.join("\n")))
        .expect("the expected objects");
    run.write(
        PLAN,
        &serde_json::json!({
            "device_id": device_id.get().to_string(),
            "settings": {
                "object_id": object_id.to_string(),
                "second_revision": second_object.revision.to_string(),
                "second_position": position_json(second),
            },
            "membership": { "collection_id": collection.collection_id.to_string() },
            "published_draft": {
                "draft_id": published.draft_id.to_string(),
                "text": published.text,
                "position": position_json(published_at),
            },
            "lost_draft": { "draft_id": lost.draft_id.to_string() },
        }),
    );
    println!(
        "restore phase 1: settings at write 2, a shared collection installed, a draft published and another made, every answer naming no history ({source})"
    );
}

/* -------------------------------------------------------------------------- */
/* Phase 2: after the export                                                   */
/* -------------------------------------------------------------------------- */

/// Phase 2, on the source after its export: a third settings write, the published draft edited and
/// published again, and the other draft published with its answer lost. Then a copy of the stores
/// meets the source as the control, and nothing moves as though anything had been put back.
#[tokio::test]
async fn after_the_export_the_device_writes_on_and_a_copy_meets_the_source_unchanged() {
    let Some(run) = RunDirectory::from_variable(RUN_VARIABLE) else {
        return skipped(RUN_VARIABLE);
    };
    let Some(source) = variable(SOURCE_VARIABLE) else {
        return skipped(SOURCE_VARIABLE);
    };
    let mut plan = run.read(PLAN);
    let device_id = DeviceId::new(uuid_from(&plan["device_id"]));
    let object_id = SyncObjectId::new(uuid_from(&plan["settings"]["object_id"]));
    let published_id = DraftId::new(uuid_from(&plan["published_draft"]["draft_id"]));
    let lost_id = DraftId::new(uuid_from(&plan["lost_draft"]["draft_id"]));

    let lost_request = {
        let device = open_device(&run, &run.path("device"), &source, None, device_id);

        // The settings object, a third time: the export does not hold this write.
        let (third_object, third) =
            publish_settings(&device, object_id, device_id, "solarised").await;
        let third = accepted_at(&third);
        assert_eq!((third.write_sequence, third.recovery()), (3, None));
        plan["settings"]["third_revision"] = third_object.revision.to_string().into();
        plan["settings"]["third_position"] = position_json(third);

        // The published draft, edited and published again.
        let held = device
            .drafts
            .load(published_id)
            .expect("the published draft");
        let edited = device
            .drafts
            .update(
                &kr_client::drafts::Draft {
                    text: format!("{}, edited after the export", held.text),
                    ..held
                },
                now(),
            )
            .expect("an edit");
        let edited_at = draft_accepted_at(
            &device
                .draft_sync
                .publish(&device.drafts, edited.draft_id, edited.revision, now())
                .await
                .expect("an answer"),
        );
        assert_eq!((edited_at.write_sequence, edited_at.recovery()), (2, None));
        plan["published_draft"]["edited_text"] = edited.text.clone().into();

        // The other draft, published for the first time, and its answer lost on the way back. The
        // service applied it: the answer this leg keeps says so.
        let lost = device.drafts.load(lost_id).expect("the lost draft");
        device.transport.lose_the_next_answer();
        device
            .draft_sync
            .publish(&device.drafts, lost.draft_id, lost.revision, now())
            .await
            .expect_err("the answer never came back");
        let answer = device.transport.take_lost().expect("the service answered");
        let answer: serde_json::Value =
            serde_json::from_slice(&answer.body).expect("the service's envelope");
        assert_eq!(
            answer["data"]["state"], "written",
            "the service applied the draft"
        );
        let record = device
            .draft_sync
            .store()
            .requests()
            .expect("the requests")
            .items
            .into_iter()
            .find(|record| record.dispatched())
            .expect("the publication is outstanding");
        assert_eq!(record.object_id, SyncObjectId::new(lost_id.get()));
        device.transport.assert_every_answer_named_its_history();
        record.work_id
    };
    plan["lost_draft"]["request_id"] = lost_request.to_string().into();
    run.write(PLAN, &plan);

    // The control: a copy of every store, as it stands now, meets the source. Nothing was put back
    // there, so every answer names no history and nothing moves as though anything had been.
    copy_tree(&run.path("device"), &run.path("control")).expect("a copy of the stores");
    let mut control = open_device(&run, &run.path("control"), &source, None, device_id);
    let third = position_from(&plan["settings"]["third_position"]);

    let fetched = control
        .settings
        .fetch(SyncObjectKind::Settings, object_id, now())
        .await
        .expect("fetched");
    let Restored::Settings { object, copy } = fetched else {
        panic!("a settings object came down: {fetched:?}");
    };
    assert_eq!(
        object.revision.to_string(),
        plan["settings"]["third_revision"]
            .as_str()
            .expect("a revision"),
        "the source holds this device's own third write"
    );
    assert_eq!(
        copy, None,
        "the device already holds that revision, so nothing is kept beside it"
    );
    assert_eq!(
        control
            .settings
            .store()
            .checkpoint(object_id)
            .expect("a note")
            .expect("one stands")
            .position,
        third,
        "the note stays where the third write left it"
    );

    assert_eq!(
        control.membership.refresh().await.expect("refreshed"),
        Refreshed::Recorded
    );
    let status = control
        .membership
        .members()
        .expect("a readable membership")
        .expect("a membership");
    assert_eq!((status.head, status.recovery, status.out), (1, None, false));
    assert_eq!(
        control.membership.step(now()).await.expect("a step"),
        Step::Nothing
    );

    let reconciled = control
        .draft_sync
        .reconcile_unsettled(&control.drafts, now())
        .await
        .expect("reconciled");
    assert_eq!(
        (reconciled.settled, reconciled.fenced, reconciled.unsettled),
        (1, 0, 0),
        "the lost answer settles from the source's receipt, in the history it was made in"
    );
    let fetched = control
        .draft_sync
        .fetch_beside(&control.drafts, published_id, now())
        .await
        .expect("fetched");
    assert_eq!(fetched.position.recovery(), None);
    assert_eq!(fetched.position.write_sequence, 2);
    assert_eq!(
        fetched.remote.text,
        plan["published_draft"]["edited_text"]
            .as_str()
            .expect("a text"),
        "the source holds the edited draft"
    );
    assert!(control.transport.fences().is_empty(), "nothing was fenced");
    control.transport.assert_every_answer_named_its_history();
    println!(
        "restore phase 2: a write, an edit and a lost answer after the export; a copy of the stores met the source and nothing moved ({source})"
    );
}

/* -------------------------------------------------------------------------- */
/* Phase 3: the restored deployment                                            */
/* -------------------------------------------------------------------------- */

/// Phase 3: the stores made before the export meet the deployment restored from it.
#[tokio::test]
async fn the_device_meets_the_deployment_restored_from_the_export() {
    let Some(run) = RunDirectory::from_variable(RUN_VARIABLE) else {
        return skipped(RUN_VARIABLE);
    };
    let Some(target) = variable(TARGET_VARIABLE) else {
        return skipped(TARGET_VARIABLE);
    };
    let Some(recovery) = variable(RECOVERY_VARIABLE) else {
        return skipped(RECOVERY_VARIABLE);
    };
    let recovery = SyncRecoveryId::new(recovery.parse().expect("a recovery identity"));
    let plan = run.read(PLAN);
    let device_id = DeviceId::new(uuid_from(&plan["device_id"]));
    let object_id = SyncObjectId::new(uuid_from(&plan["settings"]["object_id"]));
    let published_id = DraftId::new(uuid_from(&plan["published_draft"]["draft_id"]));
    let lost_id = DraftId::new(uuid_from(&plan["lost_draft"]["draft_id"]));
    let lost_request = plan["lost_draft"]["request_id"]
        .as_str()
        .expect("the lost request's identity")
        .to_owned();
    let second = position_from(&plan["settings"]["second_position"]);
    let third = position_from(&plan["settings"]["third_position"]);

    let mut device = open_device(
        &run,
        &run.path("device"),
        &target,
        Some(recovery),
        device_id,
    );

    // Settings. The collection holds the second write, put back under the recovery, and this
    // device's note names the third, in the history the restore replaced. The two places do not
    // compare, so a publication brings the restored content down beside the device's object and
    // the note follows the collection as it now stands.
    let (mine, published) = publish_settings(&device, object_id, device_id, "high contrast").await;
    let Published::Conflicted {
        copy,
        other_revision,
        position,
    } = published
    else {
        panic!("a collection put back brings its content down beside this device's: {published:?}");
    };
    assert_eq!(
        position,
        in_history(second, Some(recovery)),
        "the second write, put back"
    );
    assert_eq!(
        other_revision.to_string(),
        plan["settings"]["second_revision"]
            .as_str()
            .expect("a revision"),
        "what came down is the second write"
    );
    assert_eq!(
        device.settings.store().object(object_id).expect("read"),
        Some(mine),
        "the device's own object is untouched"
    );
    let copies = device
        .settings
        .store()
        .conflicts(object_id)
        .expect("copies")
        .items;
    assert!(
        copies.iter().any(|kept| kept.conflict_id == copy),
        "the restored content is kept beside the device's own"
    );
    assert_eq!(
        device
            .settings
            .store()
            .checkpoint(object_id)
            .expect("a note")
            .expect("one stands")
            .position,
        in_history(second, Some(recovery)),
        "the note follows the collection put back"
    );
    assert!(
        device
            .settings
            .store()
            .publications()
            .expect("the publications")
            .items
            .iter()
            .any(|publication| publication.position == third),
        "the account of the third write, which the restore lost, is kept"
    );

    // Membership. The restored collection holds this device's own head, the same record at the
    // same revision, so the device follows it into the new history and stays a member.
    assert_eq!(
        device.membership.refresh().await.expect("refreshed"),
        Refreshed::Recorded
    );
    let status = device
        .membership
        .members()
        .expect("a readable membership")
        .expect("a membership");
    assert_eq!(
        (status.installed, status.head, status.recovery, status.out),
        (Some((0, 1)), 1, Some(recovery), false),
        "the device follows its own head into the restored history"
    );
    assert!(
        device
            .membership
            .publishes()
            .expect("a readable membership")
    );
    assert_eq!(
        device.membership.step(now()).await.expect("a step"),
        Step::Nothing
    );

    // The published draft. The restored collection holds its first publication; the edited draft
    // is the person's own and stays, and the restored revision comes down beside it.
    let fetched = device
        .draft_sync
        .fetch_beside(&device.drafts, published_id, now())
        .await
        .expect("the collection put back is followed");
    assert_eq!(
        fetched.position,
        in_history(
            position_from(&plan["published_draft"]["position"]),
            Some(recovery)
        )
    );
    assert_eq!(
        fetched.remote.text,
        plan["published_draft"]["text"].as_str().expect("a text")
    );
    assert_eq!(
        fetched.copy.conflict_of.as_ref().copied(),
        Some(published_id)
    );
    assert_eq!(
        device.drafts.load(published_id).expect("the draft").text,
        plan["published_draft"]["edited_text"]
            .as_str()
            .expect("a text"),
        "the person's draft is untouched"
    );

    // The draft whose answer was lost. Its collection was made after the export, so the restored
    // deployment holds none, and the fetch says so under the recovery: the store reads the
    // collection in the restored history from that answer alone.
    let lost_object = SyncObjectId::new(lost_id.get());
    let absent = device
        .draft_sync
        .fetch_beside(&device.drafts, lost_id, now())
        .await
        .expect_err("the restored deployment holds no such draft");
    assert_eq!(absent.code(), ErrorCode::UnknownSession);
    assert_eq!(
        device
            .draft_sync
            .store()
            .basis(lost_object)
            .expect("a basis")
            .recovery(),
        Some(recovery),
        "the empty fetch moved the collection into the restored history"
    );
    // The publication was attempted in the history the restore replaced, so it is ended at once:
    // a collection created after the recovery cannot say it never ran, and the account stays.
    let reconciled = device
        .draft_sync
        .reconcile_unsettled(&device.drafts, now())
        .await
        .expect("reconciled");
    assert_eq!(
        (
            reconciled.fenced,
            reconciled.accounts_kept,
            reconciled.unsettled
        ),
        (1, 1, 0),
        "ended at once, with its account kept: {reconciled:?}"
    );
    let fences: Vec<_> = device
        .transport
        .fences()
        .into_iter()
        .filter(|fence| fence.request_id == lost_request)
        .collect();
    assert_eq!(fences.len(), 1, "one fence ended it");
    assert!(
        !fences[0].never_ran,
        "a request signed before the recovery may have run"
    );
    let record = device
        .draft_sync
        .store()
        .requests()
        .expect("the requests")
        .items
        .into_iter()
        .find(|record| record.work_id.to_string() == lost_request)
        .expect("the account of the publication");
    assert_eq!(record.state, RequestState::Unaccounted);
    assert!(
        device.drafts.load(lost_id).is_ok(),
        "the draft itself is still the person's"
    );
    device.transport.assert_every_answer_named_its_history();
    let first_pass = device.transport.sent();
    drop(device);

    // Opened again and reconciled again: nothing is outstanding, so nothing at all is sent, under
    // the ended identity or any other.
    let device = open_device(
        &run,
        &run.path("device"),
        &target,
        Some(recovery),
        device_id,
    );
    let again = device
        .draft_sync
        .reconcile_unsettled(&device.drafts, now())
        .await
        .expect("reconciled");
    assert_eq!((again.settled, again.fenced, again.unsettled), (0, 0, 0));
    assert_eq!(
        device.transport.sent(),
        Vec::new(),
        "a reconciliation with nothing outstanding asks the service nothing"
    );
    // Before the reopening the ended identity went out once more after the restore, as the fence
    // that ended it, and never as an attempt.
    let after_the_restore: Vec<_> = first_pass
        .iter()
        .filter(|sent| sent.request_id.as_deref() == Some(&lost_request))
        .map(|sent| sent.member.as_str())
        .collect();
    assert!(
        !after_the_restore.contains(&"exchange"),
        "the lost publication is never attempted again: {after_the_restore:?}"
    );
    assert_eq!(
        after_the_restore
            .iter()
            .filter(|member| **member == "fence")
            .count(),
        1,
        "one fence ended it: {after_the_restore:?}"
    );
    println!(
        "restore phase 3: every answer named recovery {recovery}; the lost settings write came back beside the device's object, the membership followed its own head, the restored draft came down beside the edited one, and the lost publication was ended at once and never sent again ({target})"
    );
}
