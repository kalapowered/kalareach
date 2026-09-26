//! What is already at the services when the client enables privacy mode, against a local
//! deployment.
//!
//! Section 24: already uploaded archives and notifications are not retroactively erased. They are
//! shown, and offered for deletion through an explicit, separately authorised action, and no
//! unrelated backup collection is deleted silently. This leg holds the web service to its half of
//! that: two backup collections and a notification the push gateway still holds are in place when
//! the client enables privacy mode; the services still list all three afterwards; each goes only
//! through its own action, the account console's deletion with the account's session and the
//! gateway's forget with the credential the installation issued; each of those refuses a request
//! without that authorisation; and the other collection is untouched throughout.
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-REQ-24.29, service side | `kr_req_24_29_what_is_at_the_services_stays_until_its_own_authorised_action_removes_it` |
//! | KR-REQ-24.28, a notification in flight at the gateway | the same leg: the gateway is still retrying it when privacy mode is enabled |
//!
//! # Local only
//!
//! The leg signs accounts in through the deployment's mail sink and answers the gateway's challenge
//! from the installation's own object, both read beside the running deployment. A deployment over
//! HTTPS offers neither, so the leg runs against a local deployment only.

use std::sync::Arc;
use std::time::{Duration, Instant};

use kr_client::drafts::DraftSealer;
use kr_client::services::StorageService as _;
use kr_client::services::SyncBackupService;
use kr_client::services::relay::{ServiceHttp, ServiceSigner};
use kr_client::services::storage::{
    BackupState, ManagedStorageService, NewUpload, RetentionChange, upload_parts,
};
use kr_client::services::sync::ManagedSyncService;
use kr_client::sync::{
    CollectionSealer, MemoryCollectionKeys, Published, SettingValue, SyncBody, SyncClient,
    SyncObject, SyncSettings, SyncStore, fresh_object_id, fresh_revision,
};
use kr_delivery::push::{SendOutcome, StatusAnswer};
use kr_privacy_integration::giveback::give_back;
use kr_privacy_integration::held::Held;
use kr_privacy_integration::local::{Account, LocalStack, Site};
use kr_privacy_integration::push::{Gateway, notification};
use kr_privacy_integration::{RunKey, fresh_uuid, not_given_back, now_ms, proved};
use kr_protocol::ids::{ArchiveId, BackupGeneration, BackupObjectId, DeviceId};
use kr_protocol::push::PushDeliveryState;
use kr_protocol::scalars::{Digest256, TimestampMs, Uuid};

/// How long the notification lives: long enough that the gateway is still retrying it for the whole
/// leg, whatever its waits between attempts come to.
const NOTIFICATION_LIFETIME_MS: u64 = 60 * 60 * 1000;

/// How long the leg may take from the delivery to its last question about the notification. Well
/// inside what keeps the gateway retrying: twelve attempts take at least three quarters of an hour.
const NOTIFICATION_STEPS: Duration = Duration::from_secs(60);

fn now() -> TimestampMs {
    TimestampMs::new(now_ms())
}

/// One collection as the account console lists it, or nothing when it is not listed.
async fn listed(
    stack: &LocalStack,
    account: &Account,
    archive: ArchiveId,
) -> Option<serde_json::Value> {
    let answer = stack.collections(Some(account)).await;
    assert_eq!(
        answer.status, 200,
        "the console lists the account's collections: {answer:?}"
    );
    answer.body["data"]["collections"]
        .as_array()
        .expect("a list")
        .iter()
        .find(|entry| entry["archiveId"] == archive.to_string())
        .cloned()
}

/// Asserts the console lists `archive` as kept, holding the one object stored in it.
async fn kept(stack: &LocalStack, account: &Account, archive: ArchiveId) {
    let entry = listed(stack, account, archive)
        .await
        .expect("the collection is listed");
    assert_eq!(entry["state"], "kept", "{entry}");
    assert_eq!(entry["stored"]["objects"], 1, "{entry}");
}

/// Stores one object in a new backup collection, as a device backing up does.
async fn one_collection(storage: &ManagedStorageService) -> ArchiveId {
    let archive_id = ArchiveId::new(fresh_uuid());
    let ciphertext = vec![0x5a_u8; 1024];
    let created = storage
        .create_upload(&NewUpload {
            archive_id,
            object_id: BackupObjectId::new(fresh_uuid()),
            backup_generation: BackupGeneration::new(1),
            declared_max_bytes: 1024,
            total_bytes: 1024,
            encrypted_object_hash: Digest256::from_bytes(kr_cbor::sha256(&ciphertext)),
        })
        .await
        .expect("an upload")
        .done()
        .expect("created");
    let mut progress = created.progress();
    upload_parts(storage, &mut progress, &ciphertext, &mut |_| Ok(()))
        .await
        .expect("the part")
        .done()
        .expect("sent");
    storage
        .complete_upload(&progress.upload_id, &progress.table)
        .await
        .expect("completed")
        .done()
        .expect("stored");
    archive_id
}

/// The one outcome a forget reports for `notification`.
fn forgot(answer: &kr_privacy_integration::local::Answer, notification: &str) -> (String, bool) {
    let removed = answer.body["data"]["removed"]
        .as_array()
        .expect("an outcome per identifier");
    let outcome = removed
        .iter()
        .find(|entry| entry["notification_id"] == notification)
        .expect("the notification's outcome");
    (
        outcome["held"].as_str().expect("what was held").to_owned(),
        outcome["dispatched"].as_bool().expect("whether it left"),
    )
}

/// KR-REQ-24.29: two backup collections and a notification the gateway holds are at the services
/// when the client enables privacy mode, and each goes only through its own authorised action.
#[tokio::test(flavor = "multi_thread")]
async fn kr_req_24_29_what_is_at_the_services_stays_until_its_own_authorised_action_removes_it() {
    let Some(stack) = LocalStack::from_environment() else {
        return;
    };
    let deployment = stack.deployment();

    // 1. Two accounts, each signed in within the leg.
    let owner = stack.sign_in().await;
    let stranger = stack.sign_in().await;

    // 2. Two backup collections, stored under the owner's account by installation K.
    let k = RunKey::installation();
    let storage = ManagedStorageService::new(
        stack.origin().clone(),
        deployment.transport(),
        Arc::clone(&k) as Arc<dyn ServiceSigner>,
    )
    .presenting(owner.tokens());
    let status = storage.status().await.expect("the storage status");
    storage
        .set_retention(&RetentionChange {
            backup: BackupState::On,
            daily_snapshots: None,
            expected_revision: status.retention_revision,
        })
        .await
        .expect("backup storage on");
    let a = one_collection(&storage).await;
    let b = one_collection(&storage).await;
    kept(&stack, &owner, a).await;
    kept(&stack, &owner, b).await;

    // 3. A notification the gateway holds: K registers a push token and authorises two hosts, and
    // host H delivers through its own gateway client. No provider answers, so the gateway retries.
    let gateway = Gateway::of(deployment);
    gateway.register(&k, &stack).await;
    let h = RunKey::host();
    let h2 = RunKey::host();
    let credential = gateway.authorise(&k, &h).await;
    let another = gateway.authorise(&k, &h2).await;
    let n = notification(
        credential.sender_record_id,
        now_ms() + NOTIFICATION_LIFETIME_MS,
    );
    let delivered = Instant::now();
    let SendOutcome::Decided(ack) = gateway.deliver(&credential, &n).await else {
        panic!("the gateway decided about the delivery");
    };
    assert_eq!(
        ack.state,
        PushDeliveryState::Retrying,
        "the gateway holds it and keeps trying"
    );

    // 4. K's own client enables privacy mode, with a write of its own published and one in flight.
    let held = Held::over(deployment.transport());
    let service = Arc::new(ManagedSyncService::new(
        stack.origin().clone(),
        Arc::clone(&held) as Arc<dyn ServiceHttp>,
        Arc::clone(&k) as Arc<dyn ServiceSigner>,
    ));
    let keys = Arc::new(MemoryCollectionKeys::new());
    let key_name = fresh_uuid().to_string();
    keys.draw(&key_name, 1).expect("a collection key");
    let directory = tempfile::tempdir().expect("a directory for the device's store");
    let client = Arc::new(SyncClient::new(
        Arc::clone(&service) as Arc<dyn SyncBackupService>,
        Arc::new(CollectionSealer::new(keys, &key_name, 1)) as Arc<dyn DraftSealer>,
        SyncStore::open(directory.path().join("device")).expect("a store"),
    ));
    let settings = |value: &str| SyncObject {
        object_id: fresh_object_id().expect("an identity"),
        revision: fresh_revision().expect("a revision"),
        device_id: DeviceId::new(Uuid::from_bytes([1; 16])),
        updated_at_ms: now(),
        body: SyncBody::Settings(SyncSettings {
            values: [("theme".to_owned(), SettingValue::Text(value.to_owned()))]
                .into_iter()
                .collect(),
            pinned_labels: std::collections::BTreeSet::new(),
        }),
    };
    let published = settings("dark");
    client.store().put_object(&published).expect("stored");
    assert!(matches!(
        client
            .publish(published.object_id, now())
            .await
            .expect("published"),
        Published::Accepted { .. }
    ));
    let in_flight = settings("light");
    client.store().put_object(&in_flight).expect("stored");
    let mut holding = held.hold_the_next_exchange(in_flight.object_id.get());
    let publishing = tokio::spawn({
        let client = Arc::clone(&client);
        let object_id = in_flight.object_id;
        async move { client.publish(object_id, now()).await }
    });
    holding.answered().await;
    client.fence(1).expect("fenced");
    client
        .cancel_undispatched(1, now())
        .await
        .expect("cancelled");
    client.remove_retained(1, now()).await.expect("removed");
    holding.release();
    assert!(matches!(
        publishing.await.expect("the task").expect("answered"),
        Published::Discarded { .. }
    ));
    assert_eq!(
        client.outstanding().expect("a count"),
        0,
        "privacy mode is complete"
    );

    // 5. Nothing at the services went.
    kept(&stack, &owner, a).await;
    kept(&stack, &owner, b).await;
    let StatusAnswer::Recorded(ack) = gateway.status(&credential, n.notification_id).await else {
        panic!("the gateway still has the notification");
    };
    assert_eq!(ack.state, PushDeliveryState::Retrying);

    // 6. The console's deletion of A, refused without its authorisation.
    let refused = stack.delete_collection(None, Site::This, a).await;
    assert_eq!(
        (refused.status, refused.code()),
        (401, Some("UNAUTHENTICATED")),
        "{refused:?}"
    );
    kept(&stack, &owner, a).await;
    let refused = stack
        .delete_collection(Some(&owner), Site::Another, a)
        .await;
    assert_eq!(
        (refused.status, refused.code()),
        (403, Some("FORBIDDEN")),
        "{refused:?}"
    );
    kept(&stack, &owner, a).await;
    let refused = stack
        .delete_collection(Some(&stranger), Site::This, a)
        .await;
    assert_eq!(refused.code(), Some("NOT_FOUND"), "{refused:?}");
    kept(&stack, &owner, a).await;
    // And with it.
    let deleted = stack.delete_collection(Some(&owner), Site::This, a).await;
    assert_eq!(deleted.status, 200, "{deleted:?}");
    let entry = &deleted.body["data"];
    assert_eq!(entry["state"], "deleted", "{entry}");
    assert_eq!(entry["awaitingRemoval"]["objects"], 1, "{entry}");
    let (deleted_at, due) = (
        entry["deletedAt"].as_str().expect("when it was deleted"),
        entry["removalDueAt"].as_str().expect("when its objects go"),
    );
    assert!(
        due > deleted_at,
        "its objects are removed later, not now: {entry}"
    );
    let listing = stack.collections(Some(&owner)).await;
    assert_eq!(listing.body["data"]["tombstoneDays"], 7);
    assert_eq!(
        listed(&stack, &owner, a).await.expect("still listed")["state"],
        "deleted"
    );
    kept(&stack, &owner, b).await;

    // 7. The gateway's forget of N, refused without its authorisation.
    let refused = gateway.forget(None, &[n.notification_id]).await;
    assert_eq!(
        (refused.status, refused.code()),
        (401, Some("UNAUTHENTICATED")),
        "{refused:?}"
    );
    let reached = gateway.forget(Some(&another), &[n.notification_id]).await;
    assert_eq!(reached.status, 200, "{reached:?}");
    assert_eq!(
        forgot(&reached, &n.notification_id.to_string()),
        ("none".to_owned(), false),
        "another authorisation reaches nothing"
    );
    let StatusAnswer::Recorded(ack) = gateway.status(&credential, n.notification_id).await else {
        panic!("the gateway still has the notification");
    };
    assert_eq!(ack.state, PushDeliveryState::Retrying);
    // And with it.
    let removed = gateway
        .forget(Some(&credential), &[n.notification_id])
        .await;
    assert_eq!(removed.status, 200, "{removed:?}");
    assert_eq!(
        forgot(&removed, &n.notification_id.to_string()),
        ("queued".to_owned(), true)
    );
    let note = removed.body["data"]["note"]
        .as_str()
        .expect("the service's note");
    assert!(note.contains("recalls nothing"), "{note}");
    assert!(matches!(
        gateway.status(&credential, n.notification_id).await,
        StatusAnswer::NoRecord { .. }
    ));
    assert!(
        delivered.elapsed() < NOTIFICATION_STEPS,
        "the notification's steps took {:?}, longer than the gateway is certain to keep retrying",
        delivered.elapsed()
    );

    let left = give_back(deployment, &k, &held.reached()).await;
    for what in &left {
        println!("{}", not_given_back(what));
    }
    assert!(
        left.is_empty(),
        "this leg did not give back what it took: {left:?}"
    );
    proved(
        "retained",
        deployment,
        "two backup collections and a notification the gateway was retrying were still listed \
         after the client enabled privacy mode; the console's deletion was refused without a \
         session, from another site and for another account, and deleted the collection with \
         the owner's session, its objects due for removal later and the other collection kept; \
         the gateway's forget was refused without a credential, reached nothing with another \
         host's, and removed the queued notification with its own, saying it recalls nothing a \
         provider accepted",
    );
}
