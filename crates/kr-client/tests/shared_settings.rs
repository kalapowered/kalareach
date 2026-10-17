//! Settings in a collection a key record has claimed, written through the clients that write a
//! device's own settings, against the stand-in `settings_answers.rs` holds to a recording.
//!
//! A claimed collection takes no write that does not name the epoch it is sealed under, so the
//! settings client reaches it through [`SharedCollectionService`], built with the sealer for the
//! same epoch. Everything the settings client does is the one it does for a collection nobody
//! claimed; what these cases show is that it still does it, with a real sealer and a real
//! service, and what the adapter says of the two answers the single-object interface has no word
//! for.
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-REQ-20.13, compare and swap in a shared collection, the other device's content kept beside this device's own | `a_refused_write_in_a_claimed_collection_keeps_the_other_devices_settings_for_the_person` |
//! | KR-REQ-20.13, a write is sealed and the service holds no plaintext | `settings_written_into_a_claimed_collection_are_read_back_sealed_under_its_key` |
//! | KR-REQ-20.11, sync-collection half, a write under a retired epoch is not stored | `a_write_under_a_retired_epoch_stores_nothing_and_the_work_is_settled_as_never_run` |

use std::collections::BTreeMap;
use std::sync::Arc;

use kr_client::services::{ManagedSyncService, ServiceHttp, SyncBackupService, SyncFetched};
use kr_client::sync::membership::{CollectionRef, KeyRecordService, RekeyAnswer};
use kr_client::sync::{
    CollectionKeys, CollectionSealer, MemoryCollectionKeys, Published, Restored, SettingValue,
    SharedCollectionService, SyncBody, SyncClient, SyncObject, SyncSettings, SyncStore,
    fresh_object_id, fresh_revision, sync_collection,
};
use kr_crypto::envelope::{
    CollectionRecipient, CollectionRecordDraft, issue_collection_key_record,
};
use kr_crypto::keys::DeviceKeys;
use kr_crypto::secret::SymmetricKey;
use kr_protocol::collection_keys::CollectionKeyRecord;
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::{
    DeviceId, SyncCollectionId, SyncKeyEpoch, SyncKeyRecordRevision, SyncObjectId,
};
use kr_protocol::scalars::{TimestampMs, Uuid};
use kr_protocol::service::{GatewayOrigin, ServiceRequestSigner, installation_id};
use kr_protocol::sync::SyncObjectKind;
use kr_service_stand_in::ServiceWeb;

mod recording;

fn now() -> TimestampMs {
    TimestampMs::new(
        u64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("a clock after 1970")
                .as_millis(),
        )
        .expect("a time in range"),
    )
}

fn identity() -> Uuid {
    kr_transport::random::fresh_uuid_v4().expect("an identity")
}

/// One installation, a collection it claimed, and the keys of the epochs it has issued.
struct Home {
    keys: DeviceKeys,
    service: Arc<ManagedSyncService>,
    collection: CollectionRef,
    secrets: Arc<MemoryCollectionKeys>,
    /// The records the collection holds, oldest first.
    records: Vec<CollectionKeyRecord>,
}

impl Home {
    /// An installation with a collection of its own, claimed at the first epoch by its first
    /// record.
    async fn claim(web: &Arc<ServiceWeb>) -> Self {
        let keys = DeviceKeys::generate().expect("a device's keys");
        let signer = Arc::new(recording::Keyed {
            key: keys.authorisation.clone(),
            signer: ServiceRequestSigner::Installation,
        });
        let service = Arc::new(ManagedSyncService::new(
            GatewayOrigin::new(web.origin()).expect("an origin"),
            Arc::clone(web) as Arc<dyn ServiceHttp>,
            signer as _,
        ));
        let collection = CollectionRef {
            home: installation_id(keys.authorisation.public()),
            collection_id: SyncCollectionId::new(identity()),
        };
        let mut home = Self {
            keys,
            service,
            collection,
            secrets: Arc::new(MemoryCollectionKeys::new()),
            records: Vec::new(),
        };
        home.issue().await;
        home
    }

    /// Issues the record that follows the newest (the first, when there is none) with a fresh key
    /// for its epoch, and has the service keep it.
    async fn issue(&mut self) {
        let previous = self.records.last();
        let epoch = previous.map_or(0, |record| record.payload.key_epoch.get() + 1);
        let key = SymmetricKey::from_bytes([u8::try_from(epoch + 1).expect("a small epoch"); 32]);
        let draft = CollectionRecordDraft {
            collection_id: self.collection.collection_id,
            home: self.collection.home,
            key_epoch: SyncKeyEpoch::new(epoch),
            revision: SyncKeyRecordRevision::new(
                previous.map_or(1, |record| record.payload.revision.get() + 1),
            ),
            previous: previous.map(|record| record.digest().expect("a digest")),
            issued_at_ms: now(),
            members: vec![CollectionRecipient {
                authorisation: *self.keys.authorisation.public(),
                stored_envelope: *self.keys.stored_envelope.public(),
            }],
        };
        let record = issue_collection_key_record(
            &self.keys.authorisation,
            &self.keys.stored_envelope,
            &draft,
            &key,
        )
        .expect("a record");
        let answer = self
            .service
            .rekey(&self.collection, identity(), now().get(), &record)
            .await
            .expect("the record is offered");
        assert!(
            matches!(answer, RekeyAnswer::Applied { .. }),
            "the service kept the record: {answer:?}"
        );
        self.secrets
            .put(&self.collection.collection_id.to_string(), epoch, key)
            .expect("the key is held");
        self.records.push(record);
    }

    fn epoch(&self) -> u64 {
        self.records
            .last()
            .map_or(0, |record| record.payload.key_epoch.get())
    }

    /// A settings client for one device's store, writing under the epoch the newest record has.
    fn client(&self, store: &std::path::Path) -> SyncClient {
        let epoch = self.epoch();
        SyncClient::new(
            Arc::new(SharedCollectionService::new(
                Arc::clone(&self.service),
                self.collection,
                epoch,
            )),
            Arc::new(CollectionSealer::new(
                Arc::clone(&self.secrets) as Arc<dyn CollectionKeys>,
                &self.collection.collection_id.to_string(),
                epoch,
            )),
            SyncStore::open(store).expect("a store"),
        )
    }
}

/// The settings object a device holds, with one value.
fn settings(object_id: SyncObjectId, colour: &str) -> SyncObject {
    SyncObject {
        object_id,
        revision: fresh_revision().expect("a revision"),
        device_id: DeviceId::new(identity()),
        updated_at_ms: now(),
        body: SyncBody::Settings(SyncSettings {
            values: BTreeMap::from([(
                "colour_mode".to_owned(),
                SettingValue::Text(colour.to_owned()),
            )]),
            pinned_labels: std::collections::BTreeSet::new(),
        }),
    }
}

/// What the colour mode of a settings object is.
fn colour(object: &SyncObject) -> String {
    match &object.body {
        SyncBody::Settings(settings) => match settings.values.get("colour_mode") {
            Some(SettingValue::Text(text)) => text.clone(),
            other => panic!("no colour mode: {other:?}"),
        },
        other => panic!("not settings: {other:?}"),
    }
}

/// A device that writes a setting is read by a second store of the same collection, and what the
/// service holds is the sealed object and nothing a reader without the key could use.
#[tokio::test]
async fn settings_written_into_a_claimed_collection_are_read_back_sealed_under_its_key() {
    let web = Arc::new(ServiceWeb::new());
    let home = Home::claim(&web).await;
    let (first, second) = (
        tempfile::tempdir().expect("a directory"),
        tempfile::tempdir().expect("a directory"),
    );
    let object_id = fresh_object_id().expect("an object");
    let one = home.client(first.path());
    let two = home.client(second.path());

    one.store()
        .put_object(&settings(object_id, "dark"))
        .expect("the object is kept");
    let published = one.publish(object_id, now()).await.expect("a publication");
    assert!(matches!(published, Published::Accepted { .. }));

    // The service holds a sealed object: a reader without the key meets ciphertext.
    let service =
        SharedCollectionService::new(Arc::clone(&home.service), home.collection, home.epoch());
    let SyncFetched::Held { ciphertext, .. } = service
        .fetch(&sync_collection(SyncObjectKind::Settings, object_id))
        .await
        .expect("a read")
    else {
        panic!("the collection holds the object");
    };
    assert!(
        !ciphertext.windows(4).any(|window| window == b"dark"),
        "what the service holds does not contain the setting"
    );

    // A second store of the same collection opens it with the collection's key.
    let Restored::Settings { object, copy } = two
        .fetch(SyncObjectKind::Settings, object_id, now())
        .await
        .expect("a fetch")
    else {
        panic!("settings");
    };
    assert_eq!(colour(&object), "dark");
    assert!(
        copy.is_none(),
        "a store that held nothing has nothing to choose between"
    );
}

/// Two stores edit from the same base; the second to publish is refused, and what the first wrote
/// comes down beside its own for the person to choose, as it does in a collection nobody claimed.
/// The service keeps the refused write too, until the choice drops it.
#[tokio::test]
async fn a_refused_write_in_a_claimed_collection_keeps_the_other_devices_settings_for_the_person() {
    let web = Arc::new(ServiceWeb::new());
    let home = Home::claim(&web).await;
    let (first, second) = (
        tempfile::tempdir().expect("a directory"),
        tempfile::tempdir().expect("a directory"),
    );
    let object_id = fresh_object_id().expect("an object");
    let one = home.client(first.path());
    let two = home.client(second.path());

    // The second store has nothing to compare against, so its first write is a write against
    // absence, and it is the first to arrive.
    two.store()
        .put_object(&settings(object_id, "light"))
        .expect("the object is kept");
    assert!(matches!(
        two.publish(object_id, now()).await.expect("a publication"),
        Published::Accepted { .. }
    ));

    // The first store never saw it: its own write against absence is refused.
    one.store()
        .put_object(&settings(object_id, "dark"))
        .expect("the object is kept");
    let Published::Conflicted { copy, .. } =
        one.publish(object_id, now()).await.expect("a publication")
    else {
        panic!("the comparison was lost");
    };
    let kept = one.store().conflicts(object_id).expect("the copies").items;
    assert_eq!(kept.len(), 1);
    assert_eq!(
        colour(&kept[0].other),
        "light",
        "the other device's content is kept"
    );
    assert_eq!(
        colour(
            &one.store()
                .object(object_id)
                .expect("a read")
                .expect("held")
        ),
        "dark",
        "this device's own settings are as they were"
    );

    // The service holds this device's refused write as a copy too, until the choice drops it.
    let waiting = home
        .service
        .compare_shared(&home.collection, &[], true, None)
        .await
        .expect("a comparison")
        .expect("a member");
    assert_eq!(waiting.copies.len(), 1);
    let resolved = one
        .resolve(copy)
        .await
        .expect("a choice")
        .expect("a copy this device held");
    assert_eq!(resolved.service.dropped, 1);
    let waiting = home
        .service
        .compare_shared(&home.collection, &[], true, None)
        .await
        .expect("a comparison")
        .expect("a member");
    assert!(waiting.copies.is_empty());
}

/// The collection moves to a newer epoch while a device still writes under the older one. The
/// service stores nothing and keeps the refusal as the request's receipt; the client leaves the
/// work outstanding, asks about it, and is told it never ran, which ends it with nothing kept.
#[tokio::test]
async fn a_write_under_a_retired_epoch_stores_nothing_and_the_work_is_settled_as_never_run() {
    let web = Arc::new(ServiceWeb::new());
    let mut home = Home::claim(&web).await;
    let store = tempfile::tempdir().expect("a directory");
    let object_id = fresh_object_id().expect("an object");
    let old = home.client(store.path());

    old.store()
        .put_object(&settings(object_id, "dark"))
        .expect("the object is kept");
    home.issue().await;

    let error = old
        .publish(object_id, now())
        .await
        .expect_err("the epoch the client writes under is retired");
    assert_eq!(error.code(), ErrorCode::ResyncRequired);
    assert_eq!(old.outstanding().expect("a count"), 1);

    // Nothing was stored.
    let service =
        SharedCollectionService::new(Arc::clone(&home.service), home.collection, home.epoch());
    assert!(matches!(
        service
            .fetch(&sync_collection(SyncObjectKind::Settings, object_id))
            .await
            .expect("a read"),
        SyncFetched::Absent { .. }
    ));

    // The work is asked about, and the answer ends it.
    let reconciled = old
        .reconcile_unsettled(now())
        .await
        .expect("a reconciliation");
    assert_eq!(old.outstanding().expect("a count"), 0, "{reconciled:?}");

    // A client built for the epoch the collection is at writes the same setting.
    let current = home.client(store.path());
    assert!(matches!(
        current
            .publish(object_id, now())
            .await
            .expect("a publication"),
        Published::Accepted { .. }
    ));
}
