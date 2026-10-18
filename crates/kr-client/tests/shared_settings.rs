//! Settings and drafts in a collection a key record has claimed, written through the clients that
//! write a device's own settings and drafts, against the stand-in `settings_answers.rs` holds to a
//! recording.
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
//! | KR-REQ-20.11, sync-collection half, a member reads what an earlier epoch's key sealed down to its floor, an object from before the floor is not believed until a member seals it again, a device that never held that key is told so, and an epoch the client was not built for is refused by name | `an_object_sealed_under_an_earlier_epoch_is_read_with_that_epochs_key_after_a_rekey`, `an_object_sealed_before_the_floor_is_refused_by_name_until_a_member_seals_it_again`, `a_device_given_only_the_newer_key_is_told_by_name_that_it_cannot_open_an_older_object`, `an_object_sealed_under_a_later_epoch_is_refused_by_name_and_not_as_tampering` |
//! | KR-REQ-20.13, a draft removed on a device leaves the service no content, and its place is free | `a_removed_draft_leaves_nothing_to_read_and_a_second_removal_finds_it_gone` |
//! | KR-REQ-20.13, a collection that holds as many drafts as it may takes another once one is removed | `a_full_collection_takes_another_draft_once_one_is_removed` |
//! | KR-REQ-20.13, a removal never replaces what another device wrote, and keeps nothing | `a_removal_after_another_device_wrote_removes_nothing_and_keeps_no_copy` |
//! | KR-REQ-24.28, no removal leaves while privacy mode is on | `no_removal_is_sent_while_privacy_mode_is_on` |

use std::collections::BTreeMap;
use std::sync::Arc;

use kr_client::drafts::{
    DraftRemoval, DraftSealer, DraftStore, DraftSync, DraftTarget, Published as DraftPublished,
    draft_collection,
};
use kr_client::services::{
    ManagedSyncService, ServiceHttp, SyncBackupService, SyncExchanged, SyncFetched,
};
use kr_client::sync::membership::{CollectionRef, KeyRecordService, RekeyAnswer};
use kr_client::sync::{
    CollectionKeys, MemoryCollectionKeys, Published, Restored, SettingValue,
    SharedCollectionService, SyncBody, SyncClient, SyncError, SyncObject, SyncSettings, SyncStore,
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
    DeviceId, DraftId, SessionId, SyncCollectionId, SyncKeyEpoch, SyncKeyRecordRevision,
    SyncObjectId,
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

    /// A settings client for one device's store, writing under the epoch the newest record has and
    /// believing only what that epoch sealed.
    fn client(&self, store: &std::path::Path) -> SyncClient {
        self.client_believing_from(store, self.epoch())
    }

    /// As [`Self::client`], believing what the epochs from `floor` on sealed as well.
    fn client_believing_from(&self, store: &std::path::Path, floor: u64) -> SyncClient {
        let epoch = self.epoch();
        let shared =
            SharedCollectionService::new(Arc::clone(&self.service), self.collection, epoch)
                .believing_from(floor);
        let sealer = shared.sealer(Arc::clone(&self.secrets) as Arc<dyn CollectionKeys>);
        SyncClient::new(
            Arc::new(shared),
            Arc::new(sealer),
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

/// A collection that has been rekeyed still holds what it held, sealed under the keys it was sealed
/// with. A member that was given those keys reads it, so a device with nothing of its own to
/// publish does not fail every step after a rekey, and what it writes next is sealed under the
/// newer epoch.
#[tokio::test]
async fn an_object_sealed_under_an_earlier_epoch_is_read_with_that_epochs_key_after_a_rekey() {
    let web = Arc::new(ServiceWeb::new());
    let mut home = Home::claim(&web).await;
    let (written, read) = (
        tempfile::tempdir().expect("a directory"),
        tempfile::tempdir().expect("a directory"),
    );
    let object_id = fresh_object_id().expect("an object");
    let old = home.client(written.path());
    old.store()
        .put_object(&settings(object_id, "dark"))
        .expect("the object is kept");
    assert!(matches!(
        old.publish(object_id, now()).await.expect("a publication"),
        Published::Accepted { .. }
    ));
    home.issue().await;
    assert_eq!(home.epoch(), 1);

    // A client built for the newer epoch reads the object the earlier epoch's key sealed, when its
    // floor reaches back to that epoch.
    let newer = home.client_believing_from(read.path(), 0);
    let Restored::Settings { object, .. } = newer
        .fetch(SyncObjectKind::Settings, object_id, now())
        .await
        .expect("an object of an earlier epoch is read with that epoch's key")
    else {
        panic!("settings");
    };
    assert_eq!(colour(&object), "dark");

    // What it writes next is sealed under the newer epoch, and is read by it too.
    newer
        .store()
        .put_object(&settings(object_id, "light"))
        .expect("the object is kept");
    assert!(matches!(
        newer
            .publish(object_id, now())
            .await
            .expect("a publication"),
        Published::Accepted { .. }
    ));
    let Restored::Settings { object, .. } = newer
        .fetch(SyncObjectKind::Settings, object_id, now())
        .await
        .expect("a fetch")
    else {
        panic!("settings");
    };
    assert_eq!(colour(&object), "light");
}

/// A device that was not a member when an object was sealed holds no key for that epoch. It is told
/// so by name, and not with the answer a ciphertext that fails to authenticate gets, which reads as
/// tampering.
#[tokio::test]
async fn a_device_given_only_the_newer_key_is_told_by_name_that_it_cannot_open_an_older_object() {
    let web = Arc::new(ServiceWeb::new());
    let mut home = Home::claim(&web).await;
    let (written, read) = (
        tempfile::tempdir().expect("a directory"),
        tempfile::tempdir().expect("a directory"),
    );
    let object_id = fresh_object_id().expect("an object");
    let old = home.client(written.path());
    old.store()
        .put_object(&settings(object_id, "dark"))
        .expect("the object is kept");
    assert!(matches!(
        old.publish(object_id, now()).await.expect("a publication"),
        Published::Accepted { .. }
    ));
    home.issue().await;

    // A member of the newer epoch only: it holds the newer key and none before it.
    let late = Arc::new(MemoryCollectionKeys::new());
    late.put(
        &home.collection.collection_id.to_string(),
        1,
        SymmetricKey::from_bytes([2; 32]),
    )
    .expect("the key is held");
    let shared =
        SharedCollectionService::new(Arc::clone(&home.service), home.collection, home.epoch())
            .believing_from(0);
    let sealer = shared.sealer(late as Arc<dyn CollectionKeys>);
    let client = SyncClient::new(
        Arc::new(shared),
        Arc::new(sealer),
        SyncStore::open(read.path()).expect("a store"),
    );

    let error = client
        .fetch(SyncObjectKind::Settings, object_id, now())
        .await
        .expect_err("no key this device holds opens an object of the epoch before");
    let SyncError::Client(error) = error else {
        panic!("a refusal that names what is missing, not a failure to open: {error:?}");
    };
    assert_eq!(error.code(), ErrorCode::HostNotConfigured);
    assert!(
        error.to_string().contains("holds no key for"),
        "the refusal says which key is missing: {error}"
    );
}

/// A device that was taken out holds every key it held, and what it could seal is not believed
/// once the collection has moved on: the object is refused by name before any key is tried, however
/// many keys the reader holds. A member that holds the plaintext seals it again under the newer
/// epoch, and that is read.
#[tokio::test]
async fn an_object_sealed_before_the_floor_is_refused_by_name_until_a_member_seals_it_again() {
    let web = Arc::new(ServiceWeb::new());
    let mut home = Home::claim(&web).await;
    let (written, read) = (
        tempfile::tempdir().expect("a directory"),
        tempfile::tempdir().expect("a directory"),
    );
    let object_id = fresh_object_id().expect("an object");
    let old = home.client(written.path());
    old.store()
        .put_object(&settings(object_id, "dark"))
        .expect("the object is kept");
    assert!(matches!(
        old.publish(object_id, now()).await.expect("a publication"),
        Published::Accepted { .. }
    ));
    home.issue().await;

    // The reader holds the keys of both epochs and believes from the newer one.
    let reader = home.client_believing_from(read.path(), 1);
    let error = reader
        .fetch(SyncObjectKind::Settings, object_id, now())
        .await
        .expect_err("sealed before the floor");
    let SyncError::Client(error) = error else {
        panic!("a refusal that names the epochs, not a failure to open: {error:?}");
    };
    assert_eq!(error.code(), ErrorCode::HostNotConfigured);
    let said = error.to_string();
    assert!(
        said.contains("epoch 0") && said.contains("epoch 1"),
        "the refusal names the two epochs: {said}"
    );

    // A member that holds the settings seals them again under the newer epoch, against what it
    // last agreed with, and the reader believes that.
    let member = home.client_believing_from(written.path(), 0);
    let Restored::Settings { object, .. } = member
        .fetch(SyncObjectKind::Settings, object_id, now())
        .await
        .expect("a member that believes from the first epoch reads it")
    else {
        panic!("settings");
    };
    member
        .store()
        .put_object(&SyncObject {
            revision: fresh_revision().expect("a revision"),
            ..object
        })
        .expect("the object is sealed again");
    assert!(matches!(
        member
            .publish(object_id, now())
            .await
            .expect("a publication"),
        Published::Accepted { .. }
    ));
    let Restored::Settings { object, .. } = reader
        .fetch(SyncObjectKind::Settings, object_id, now())
        .await
        .expect("sealed under the floor's epoch, it is believed")
    else {
        panic!("settings");
    };
    assert_eq!(colour(&object), "dark");
}

/// An object sealed under a newer epoch than the one a client was built for is not opened with an
/// older key: the client is told which epochs are in play, by name, and the answer is not the one a
/// ciphertext that fails to authenticate gets, which reads as tampering.
#[tokio::test]
async fn an_object_sealed_under_a_later_epoch_is_refused_by_name_and_not_as_tampering() {
    let web = Arc::new(ServiceWeb::new());
    let mut home = Home::claim(&web).await;
    let (written, read) = (
        tempfile::tempdir().expect("a directory"),
        tempfile::tempdir().expect("a directory"),
    );
    let object_id = fresh_object_id().expect("an object");
    home.issue().await;
    let newer = home.client(written.path());
    newer
        .store()
        .put_object(&settings(object_id, "dark"))
        .expect("the object is kept");
    assert!(matches!(
        newer
            .publish(object_id, now())
            .await
            .expect("a publication"),
        Published::Accepted { .. }
    ));

    // A client built for the epoch before holds both keys and is still not to read what the later
    // epoch sealed: it has not seen the key record that opens that epoch.
    let shared = SharedCollectionService::new(Arc::clone(&home.service), home.collection, 0);
    let sealer = shared.sealer(Arc::clone(&home.secrets) as Arc<dyn CollectionKeys>);
    let older = SyncClient::new(
        Arc::new(shared),
        Arc::new(sealer),
        SyncStore::open(read.path()).expect("a store"),
    );
    let error = older
        .fetch(SyncObjectKind::Settings, object_id, now())
        .await
        .expect_err("the object is sealed under the epoch after");
    let SyncError::Client(error) = error else {
        panic!("the service's own refusal, not a failure to open: {error:?}");
    };
    assert_eq!(error.code(), ErrorCode::ResyncRequired);
    let said = error.to_string();
    assert!(
        said.contains("epoch 1") && said.contains("epoch 0"),
        "the refusal names the two epochs: {said}"
    );
    // The epoch it was sealed under reads it.
    assert!(matches!(
        newer
            .fetch(SyncObjectKind::Settings, object_id, now())
            .await
            .expect("a fetch"),
        Restored::Settings { .. }
    ));
}

/* -------------------------------------------------------------------------- */
/* Drafts                                                                      */
/* -------------------------------------------------------------------------- */

/// One device's drafts in the shared collection: its draft store, its draft half over a store of
/// its own, and the settings client over that same store, which is the client privacy mode drives.
struct DraftDevice {
    drafts: DraftStore,
    sync: DraftSync,
    client: SyncClient,
    _directory: tempfile::TempDir,
}

impl Home {
    fn draft_device(&self) -> DraftDevice {
        let directory = tempfile::tempdir().expect("a directory");
        let epoch = self.epoch();
        let shared =
            SharedCollectionService::new(Arc::clone(&self.service), self.collection, epoch);
        let sealer: Arc<dyn DraftSealer> =
            Arc::new(shared.sealer(Arc::clone(&self.secrets) as Arc<dyn CollectionKeys>));
        let shared = Arc::new(shared);
        let store = || SyncStore::open(directory.path().join("sync")).expect("the sync store");
        DraftDevice {
            drafts: DraftStore::open(
                directory.path().join("drafts"),
                DeviceId::new(installation_id(self.keys.authorisation.public()).get()),
            )
            .expect("a draft store"),
            sync: DraftSync::new(
                Arc::clone(&shared) as Arc<dyn SyncBackupService>,
                Arc::clone(&sealer),
                store(),
            ),
            client: SyncClient::new(shared, sealer, store()),
            _directory: directory,
        }
    }
}

impl DraftDevice {
    /// A draft for a session, written and published, and where the service holds it.
    async fn published(&self, text: &str) -> (DraftId, kr_client::services::SyncPosition) {
        let draft = self
            .drafts
            .create(
                DraftTarget::session(SessionId::new(identity())),
                text.to_owned(),
                now(),
            )
            .expect("a draft");
        self.sync
            .publish(&self.drafts, draft.draft_id, draft.revision, now())
            .await
            .expect("a publication");
        let note = self
            .drafts
            .checkpoint(draft.draft_id)
            .expect("the note is readable")
            .expect("the publication left a note");
        (draft.draft_id, note.position)
    }
}

/// What a shared collection holds, as the service counts it.
async fn held_objects(home: &Home) -> u64 {
    home.service
        .compare_shared(&home.collection, &[], false, None)
        .await
        .expect("a comparison")
        .expect("a member")
        .stored
        .objects
        .get()
}

/// A draft thrown away on a device is removed at the service: what it held is gone for a reader, and
/// asking again after an answer was lost finds it gone and says so.
#[tokio::test]
async fn a_removed_draft_leaves_nothing_to_read_and_a_second_removal_finds_it_gone() {
    let web = Arc::new(ServiceWeb::new());
    let home = Home::claim(&web).await;
    let device = home.draft_device();
    let (draft, position) = device.published("a prompt to send later").await;
    assert_eq!(held_objects(&home).await, 1);

    let removed = device
        .sync
        .remove(draft, position, now())
        .await
        .expect("a removal");
    let DraftRemoval::Removed { position: gone } = removed else {
        panic!("the service removed it: {removed:?}");
    };
    assert!(gone.is_removal(), "a removal has no revision: {gone:?}");
    assert_eq!(held_objects(&home).await, 0, "its place is free");

    // A reader finds nothing to open, where it found a sealed draft before.
    let shared =
        SharedCollectionService::new(Arc::clone(&home.service), home.collection, home.epoch());
    assert!(matches!(
        shared
            .fetch(&draft_collection(draft))
            .await
            .expect("a read"),
        SyncFetched::Absent { .. }
    ));

    // The answer to the first removal may never have come back: asking again is a new request
    // against the same position, and the object is already gone.
    assert_eq!(
        device
            .sync
            .remove(draft, position, now())
            .await
            .expect("a second removal"),
        DraftRemoval::AlreadyGone
    );
}

/// A collection holds a fixed number of objects. Drafts that are sent and thrown away would fill it
/// for good if their sealed copies stayed, and every later draft would be refused.
#[tokio::test]
async fn a_full_collection_takes_another_draft_once_one_is_removed() {
    let web = Arc::new(ServiceWeb::new());
    let home = Home::claim(&web).await;
    let device = home.draft_device();
    let mut first = None;
    for number in 0..kr_protocol::sync::MAX_SYNC_OBJECTS_PER_COLLECTION {
        let published = device.published(&format!("draft {number}")).await;
        first.get_or_insert(published);
    }
    assert_eq!(
        held_objects(&home).await,
        kr_protocol::sync::MAX_SYNC_OBJECTS_PER_COLLECTION
    );

    // One more is refused: there is no place for it.
    let extra = device
        .drafts
        .create(
            DraftTarget::session(SessionId::new(identity())),
            "one too many".to_owned(),
            now(),
        )
        .expect("a draft");
    let refused = device
        .sync
        .publish(&device.drafts, extra.draft_id, extra.revision, now())
        .await
        .expect_err("a full collection takes no new object");
    assert_eq!(refused.code(), ErrorCode::QuotaExceeded);

    // A draft that was sent is removed, and the one that was refused now has a place.
    let (sent, position) = first.expect("a first draft");
    assert!(matches!(
        device.sync.remove(sent, position, now()).await,
        Ok(DraftRemoval::Removed { .. })
    ));
    let accepted = device
        .sync
        .publish(&device.drafts, extra.draft_id, extra.revision, now())
        .await
        .expect("the freed place takes it");
    assert!(matches!(accepted, DraftPublished::Accepted { .. }));
}

/// Another device wrote the draft after this device last saw it, so a removal compared against the
/// position this device holds is refused. It removes nothing and keeps nothing: a removal carries no
/// content, and what the other device wrote stays where it is.
#[tokio::test]
async fn a_removal_after_another_device_wrote_removes_nothing_and_keeps_no_copy() {
    let web = Arc::new(ServiceWeb::new());
    let home = Home::claim(&web).await;
    let device = home.draft_device();
    let (draft, position) = device.published("what this device wrote").await;

    // The other device's write of the same draft, against the revision this device published.
    let theirs = device
        .drafts
        .load(draft)
        .expect("the draft")
        .text
        .replace("this", "that");
    let mut their_draft = device.drafts.load(draft).expect("the draft");
    their_draft.text = theirs;
    let sealed =
        SharedCollectionService::new(Arc::clone(&home.service), home.collection, home.epoch())
            .sealer(Arc::clone(&home.secrets) as Arc<dyn CollectionKeys>);
    let ciphertext = sealed
        .seal(&DraftStore::encode_payload(&their_draft).expect("canonical bytes"))
        .expect("sealed");
    let wrote = home
        .service
        .exchange_shared(
            &home.collection,
            &draft_collection(draft),
            home.epoch(),
            identity(),
            now().get(),
            Some(position),
            &ciphertext,
        )
        .await
        .expect("the other device's write");
    assert!(matches!(
        wrote,
        kr_client::services::Keyed::Answered {
            answer: SyncExchanged::Applied { .. },
            ..
        }
    ));
    let copies_before = home
        .service
        .compare_shared(&home.collection, &[], true, None)
        .await
        .expect("a comparison")
        .expect("a member")
        .copies
        .len();

    let removed = device
        .sync
        .remove(draft, position, now())
        .await
        .expect("a removal");
    assert!(
        matches!(removed, DraftRemoval::Moved { current } if !current.is_removal()),
        "the draft moved on: {removed:?}"
    );
    assert_eq!(
        held_objects(&home).await,
        1,
        "what the other device wrote stays"
    );
    let copies_after = home
        .service
        .compare_shared(&home.collection, &[], true, None)
        .await
        .expect("a comparison")
        .expect("a member")
        .copies
        .len();
    assert_eq!(
        copies_after, copies_before,
        "a refused removal keeps nothing"
    );
}

/// Privacy mode stops what leaves a device, and a removal is a request that leaves it: none is sent
/// while the device's store is fenced, and the object stays where it is.
#[tokio::test]
async fn no_removal_is_sent_while_privacy_mode_is_on() {
    let web = Arc::new(ServiceWeb::new());
    let home = Home::claim(&web).await;
    let device = home.draft_device();
    let (draft, position) = device.published("kept while private").await;
    let before = web.requests_to("/api/sync/exchange");

    device.client.fence(7).expect("the fence is recorded");
    let refused = device
        .sync
        .remove(draft, position, now())
        .await
        .expect_err("a fenced device removes nothing");
    assert!(matches!(refused, SyncError::Fenced { generation: 7 }));
    assert_eq!(
        web.requests_to("/api/sync/exchange"),
        before,
        "nothing was sent"
    );
    assert_eq!(held_objects(&home).await, 1);

    // The fence lifts, and the removal goes.
    device.client.resume(8).expect("production resumes");
    assert!(matches!(
        device.sync.remove(draft, position, now()).await,
        Ok(DraftRemoval::Removed { .. })
    ));
}
