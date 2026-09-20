//! Encrypted settings sync: the compare-and-swap client, its conflicts and its privacy hook.
//!
//! The service in this suite is a real compare-and-exchange store over opaque bytes, and the
//! sealing is real: the objects it holds are sealed with `kr-crypto` under a key it never sees, so
//! what the tests read out of it is what a service would hold.

use std::collections::BTreeMap;
use std::sync::Arc;

use kr_client::ClientError;
use kr_client::drafts::{
    Draft, DraftSealer, DraftStore, DraftSync, DraftTarget, NotSubmittable,
    Published as DraftPublished,
};
use kr_client::services::{ServiceFuture, SyncBackupService};
use kr_client::sync::{
    ClientSelection, ConflictCopy, Published, Restored, SettingValue, StorageFeature, SyncBody,
    SyncClient, SyncError, SyncObject, SyncSettings, SyncStore, fresh_object_id, fresh_revision,
    sync_collection,
};
use kr_crypto::envelope::{open_sync_object, seal_sync_object};
use kr_crypto::secret::{Secret, SymmetricKey};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::ids::{
    AgentBindingRevision, ApplicationInstanceId, DeviceId, SessionId, SyncConflictId, SyncObjectId,
};
use kr_protocol::scalars::{Nullable, TimestampMs, U64, Uuid};
use kr_protocol::sync::{MAX_SYNC_CONFLICT_COPIES, SyncObjectKind};
use tokio::sync::Mutex;

const NOW: u64 = 1_764_000_000_000;

/// A compare-and-exchange store over opaque bytes, which is all a service is.
#[derive(Debug, Default)]
struct Service {
    objects: Mutex<BTreeMap<String, (u64, Vec<u8>)>>,
}

impl Service {
    /// Forgets everything, which is what a reset or a replaced service looks like to a device.
    async fn reset(&self) {
        self.objects.lock().await.clear();
    }

    async fn stored(&self, collection: &str) -> Option<(u64, Vec<u8>)> {
        self.objects.lock().await.get(collection).cloned()
    }

    async fn collections(&self) -> Vec<String> {
        self.objects.lock().await.keys().cloned().collect()
    }
}

impl SyncBackupService for Service {
    fn compare_exchange<'a>(
        &'a self,
        collection: &'a str,
        expected_generation: u64,
        ciphertext: &'a [u8],
    ) -> ServiceFuture<'a, u64> {
        Box::pin(async move {
            let mut objects = self.objects.lock().await;
            let current = objects
                .get(collection)
                .map_or(0, |(generation, _)| *generation);
            if current != expected_generation {
                return Err(ClientError::Host(ProtocolError::new(
                    ErrorCode::DraftConflict,
                    "another writer got there first",
                )));
            }
            let next = current + 1;
            objects.insert(collection.to_owned(), (next, ciphertext.to_vec()));
            Ok(next)
        })
    }

    fn fetch<'a>(&'a self, collection: &'a str) -> ServiceFuture<'a, (u64, Vec<u8>)> {
        Box::pin(async move {
            self.objects
                .lock()
                .await
                .get(collection)
                .cloned()
                .ok_or_else(|| {
                    ClientError::Host(ProtocolError::new(
                        ErrorCode::UnknownSession,
                        "no such object",
                    ))
                })
        })
    }
}

/// A service that holds a publication at the wire until a test lets it go.
///
/// Section 24 asks for privacy mode to be enabled while upload work is in flight. Without somewhere
/// to hold the call, a test could only enable it before or after, which is the case that needs no
/// rule.
#[derive(Debug)]
struct GatedService {
    inner: Service,
    entered: tokio::sync::Semaphore,
    release: tokio::sync::Semaphore,
}

impl GatedService {
    fn new() -> Self {
        Self {
            inner: Service::default(),
            entered: tokio::sync::Semaphore::new(0),
            release: tokio::sync::Semaphore::new(0),
        }
    }

    /// Waits until a publication has reached the service and is waiting there.
    async fn wait_for_a_publication(&self) {
        self.entered
            .acquire()
            .await
            .expect("the gate is open")
            .forget();
    }

    /// Lets the waiting publication finish.
    fn let_it_go(&self) {
        self.release.add_permits(1);
    }
}

impl SyncBackupService for GatedService {
    fn compare_exchange<'a>(
        &'a self,
        collection: &'a str,
        expected_generation: u64,
        ciphertext: &'a [u8],
    ) -> ServiceFuture<'a, u64> {
        Box::pin(async move {
            self.entered.add_permits(1);
            self.release
                .acquire()
                .await
                .expect("the gate is open")
                .forget();
            self.inner
                .compare_exchange(collection, expected_generation, ciphertext)
                .await
        })
    }

    fn fetch<'a>(&'a self, collection: &'a str) -> ServiceFuture<'a, (u64, Vec<u8>)> {
        self.inner.fetch(collection)
    }
}

/// This device's sealing: a real synchronised object under a key the service never sees.
#[derive(Debug)]
struct DeviceSealer {
    key: SymmetricKey,
}

impl DeviceSealer {
    fn new(byte: u8) -> Self {
        Self {
            key: Secret::from_bytes([byte; 32]),
        }
    }
}

impl DraftSealer for DeviceSealer {
    fn seal(&self, plaintext: &[u8]) -> kr_client::Result<Vec<u8>> {
        let object = seal_sync_object(&self.key, plaintext).map_err(refused)?;
        Ok(kr_cbor::to_canonical_vec(&object)?)
    }

    fn open(&self, ciphertext: &[u8]) -> kr_client::Result<Vec<u8>> {
        let object: kr_protocol::sync::SealedSyncObject =
            kr_cbor::from_canonical_slice(ciphertext, &kr_cbor::Limits::DEFAULT)?;
        let opened = open_sync_object(&self.key, &object).map_err(refused)?;
        Ok(opened.expose().to_vec())
    }
}

/// Reports a sealing failure the way a client reports one it cannot classify further.
fn refused(error: kr_crypto::CryptoError) -> ClientError {
    ClientError::Host(ProtocolError::new(
        ErrorCode::InvalidArgument,
        error.to_string(),
    ))
}

fn device(byte: u8) -> DeviceId {
    DeviceId::new(Uuid::from_bytes([byte; 16]))
}

fn settings(pairs: &[(&str, &str)], pinned: &[&str]) -> SyncSettings {
    SyncSettings {
        values: pairs
            .iter()
            .map(|(name, value)| ((*name).to_owned(), SettingValue::Text((*value).to_owned())))
            .collect(),
        pinned_labels: pinned.iter().map(|label| (*label).to_owned()).collect(),
    }
}

fn object(object_id: SyncObjectId, device_byte: u8, body: SyncBody, at_ms: u64) -> SyncObject {
    SyncObject {
        object_id,
        revision: fresh_revision().expect("a revision"),
        device_id: device(device_byte),
        updated_at_ms: TimestampMs::new(at_ms),
        body,
    }
}

/// One conflict copy of `other`, recorded at `at_ms`.
fn conflict(object_id: SyncObjectId, other: &SyncObject, at_ms: u64) -> ConflictCopy {
    ConflictCopy {
        conflict_id: SyncConflictId::new(
            kr_transport::random::fresh_uuid_v4().expect("an identity"),
        ),
        object_id,
        offered_revision: fresh_revision().expect("a revision"),
        expected_generation: Nullable::null(),
        current_generation: U64::new(1),
        other: other.clone(),
        recorded_at_ms: TimestampMs::new(at_ms),
    }
}

/// One device: its own store and its own client over the shared service.
fn device_client(
    directory: &std::path::Path,
    name: &str,
    service: &Arc<Service>,
) -> (SyncClient, SyncObjectId) {
    let store = SyncStore::open(directory.join(name)).expect("a store");
    let client = SyncClient::new(
        Arc::clone(service) as Arc<dyn SyncBackupService>,
        Arc::new(DeviceSealer::new(0x5a)) as Arc<dyn DraftSealer>,
        store,
    );
    (client, fresh_object_id().expect("an identity"))
}

// ---------------------------------------------------------------------------
// KR-REQ-20.13: per-object revisions and compare-and-swap writes
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_settings_object_is_published_under_compare_and_swap_against_the_generation_it_last_saw()
{
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(Service::default());
    let (client, object_id) = device_client(directory.path(), "one", &service);

    let first = object(
        object_id,
        1,
        SyncBody::Settings(settings(&[("theme", "dark")], &[])),
        NOW,
    );
    client.store().put_object(&first).expect("stored");

    // Nothing is there yet, so the first comparison is against generation nought.
    assert_eq!(
        client
            .publish(object_id, TimestampMs::new(NOW))
            .await
            .expect("published"),
        Published::Accepted { generation: 1 }
    );
    let note = client
        .store()
        .checkpoint(object_id)
        .expect("a note")
        .expect("one was written");
    assert_eq!(note.generation.get(), 1);
    assert_eq!(note.published_revision, Nullable::some(first.revision));

    // A second write compares against what the note now says, and the revision is a fresh value
    // rather than the next number: an object removed and written again never repeats one.
    let mut second = first.clone();
    second.revision = fresh_revision().expect("a revision");
    second.body = SyncBody::Settings(settings(&[("theme", "light")], &[]));
    client.store().put_object(&second).expect("stored");
    assert_ne!(second.revision, first.revision);
    assert_eq!(
        client
            .publish(object_id, TimestampMs::new(NOW + 1))
            .await
            .expect("published"),
        Published::Accepted { generation: 2 }
    );
    assert_eq!(
        service
            .collections()
            .await
            .first()
            .expect("one collection")
            .as_str(),
        sync_collection(SyncObjectKind::Settings, object_id)
    );
}

#[tokio::test]
async fn a_write_that_loses_the_comparison_keeps_the_other_copy_beside_it_rather_than_a_clock() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(Service::default());
    let (one, object_id) = device_client(directory.path(), "one", &service);
    let two = SyncClient::new(
        Arc::clone(&service) as Arc<dyn SyncBackupService>,
        Arc::new(DeviceSealer::new(0x5a)) as Arc<dyn DraftSealer>,
        SyncStore::open(directory.path().join("two")).expect("a store"),
    );

    // The first device publishes. The second holds its own edit and has never seen the object, so
    // it compares against nothing and loses.
    let theirs = object(
        object_id,
        1,
        SyncBody::Settings(settings(&[("theme", "dark")], &[])),
        NOW + 5_000,
    );
    one.store().put_object(&theirs).expect("stored");
    one.publish(object_id, TimestampMs::new(NOW))
        .await
        .expect("published");

    // Deliberately the *later* clock, so a wall-clock rule would take this one.
    let mine = object(
        object_id,
        2,
        SyncBody::Settings(settings(&[("theme", "light")], &[])),
        NOW + 10_000,
    );
    two.store().put_object(&mine).expect("stored");
    let outcome = two
        .publish(object_id, TimestampMs::new(NOW + 1))
        .await
        .expect("answered");
    let Published::Conflicted {
        copy,
        other_revision,
        generation,
    } = outcome
    else {
        panic!("the second device lost the comparison: {outcome:?}")
    };
    assert_eq!(other_revision, theirs.revision);
    assert_eq!(generation, 1);

    // This device's own content is exactly as it was, and the other device's is beside it.
    let held = two
        .store()
        .object(object_id)
        .expect("an object")
        .expect("one is held");
    assert_eq!(held, mine, "a lost comparison never replaces local content");
    let copies = two.store().conflicts(object_id).expect("the copies").items;
    assert_eq!(copies.len(), 1);
    assert_eq!(copies[0].conflict_id, copy);
    assert_eq!(copies[0].other, theirs);
    assert_eq!(copies[0].offered_revision, mine.revision);

    // Nothing was chosen. The person chooses, and this is what that looks like: take the copy out
    // and publish what was chosen against the generation that won.
    let copies = two.store().conflicts(object_id).expect("the copies").items;
    let chosen = copies.first().expect("the copy is there").clone();
    let mut merged = mine.clone();
    merged.revision = fresh_revision().expect("a revision");
    merged.body = chosen.other.body.clone();
    // The choice is stored before its copy is taken away, so a stop between the two leaves the
    // person with a copy rather than with neither.
    two.store().put_object(&merged).expect("stored");
    assert_eq!(
        two.store()
            .resolve_conflict(copy)
            .expect("resolved")
            .expect("the copy was still there")
            .conflict_id,
        copy
    );
    assert_eq!(
        two.publish(object_id, TimestampMs::new(NOW + 2))
            .await
            .expect("published"),
        Published::Accepted { generation: 2 }
    );
    assert!(two.store().conflicts(object_id).expect("none").is_empty());
}

#[tokio::test]
async fn copies_are_bounded_and_the_newest_refusal_is_the_one_that_is_kept() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(Service::default());
    let (one, object_id) = device_client(directory.path(), "one", &service);
    let two = SyncClient::new(
        Arc::clone(&service) as Arc<dyn SyncBackupService>,
        Arc::new(DeviceSealer::new(0x5a)) as Arc<dyn DraftSealer>,
        SyncStore::open(directory.path().join("two")).expect("a store"),
    );

    let mut theirs = object(
        object_id,
        1,
        SyncBody::Settings(settings(&[("theme", "dark")], &[])),
        NOW,
    );
    let mine = object(
        object_id,
        2,
        SyncBody::Settings(settings(&[("theme", "light")], &[])),
        NOW,
    );
    two.store().put_object(&mine).expect("stored");

    let mut newest = theirs.revision;
    for round in 0..(MAX_SYNC_CONFLICT_COPIES + 3) {
        theirs.revision = fresh_revision().expect("a revision");
        newest = theirs.revision;
        one.store().put_object(&theirs).expect("stored");
        one.publish(object_id, TimestampMs::new(NOW + round))
            .await
            .expect("published");
        // The second device's note is now behind again, so its next write loses again.
        two.store().forget_checkpoint(object_id).expect("forgotten");
        let outcome = two
            .publish(object_id, TimestampMs::new(NOW + round))
            .await
            .expect("answered");
        assert!(matches!(outcome, Published::Conflicted { .. }));
    }

    let copies = two.store().conflicts(object_id).expect("the copies").items;
    assert_eq!(copies.len() as u64, MAX_SYNC_CONFLICT_COPIES);
    assert_eq!(
        copies.last().expect("the newest").other.revision,
        newest,
        "the newest refusal is always the one that is kept"
    );
}

#[tokio::test]
async fn a_fetch_keeps_what_the_service_holds_beside_this_devices_own_content() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(Service::default());
    let (one, object_id) = device_client(directory.path(), "one", &service);
    let two = SyncClient::new(
        Arc::clone(&service) as Arc<dyn SyncBackupService>,
        Arc::new(DeviceSealer::new(0x5a)) as Arc<dyn DraftSealer>,
        SyncStore::open(directory.path().join("two")).expect("a store"),
    );

    let theirs = object(
        object_id,
        1,
        SyncBody::Settings(settings(&[("theme", "dark")], &[])),
        NOW,
    );
    one.store().put_object(&theirs).expect("stored");
    one.publish(object_id, TimestampMs::new(NOW))
        .await
        .expect("published");

    // A device with nothing of its own is seeing the object for the first time: there is nothing
    // to conflict with, and nothing is applied either.
    let restored = two
        .fetch(SyncObjectKind::Settings, object_id, TimestampMs::new(NOW))
        .await
        .expect("fetched");
    assert!(matches!(restored, Restored::Settings { .. }));
    assert_eq!(restored.copy(), None);
    assert_eq!(restored.object(), &theirs);
    assert!(
        two.store().object(object_id).expect("read").is_none(),
        "a fetch applies nothing"
    );

    // Once it holds a revision of its own, the same fetch keeps the other content beside it.
    let mine = object(
        object_id,
        2,
        SyncBody::Settings(settings(&[("theme", "light")], &[])),
        NOW,
    );
    two.store().put_object(&mine).expect("stored");
    let restored = two
        .fetch(SyncObjectKind::Settings, object_id, TimestampMs::new(NOW))
        .await
        .expect("fetched");
    assert!(restored.copy().is_some());
    assert_eq!(
        two.store().object(object_id).expect("read").expect("held"),
        mine
    );
}

#[tokio::test]
async fn an_object_that_is_not_the_one_the_collection_was_asked_for_is_refused() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(Service::default());
    let (one, object_id) = device_client(directory.path(), "one", &service);
    let elsewhere = fresh_object_id().expect("an identity");

    let theirs = object(
        object_id,
        1,
        SyncBody::Settings(settings(&[("theme", "dark")], &[])),
        NOW,
    );
    one.store().put_object(&theirs).expect("stored");
    one.publish(object_id, TimestampMs::new(NOW))
        .await
        .expect("published");

    // The service serves this object under another object's collection. Sealing says the bytes came
    // from a device holding the key; it says nothing about where they belong.
    let (generation, ciphertext) = service
        .stored(&sync_collection(SyncObjectKind::Settings, object_id))
        .await
        .expect("it is stored");
    service
        .compare_exchange(
            &sync_collection(SyncObjectKind::Settings, elsewhere),
            0,
            &ciphertext,
        )
        .await
        .expect("stored elsewhere");
    assert_eq!(generation, 1);

    assert!(matches!(
        one.fetch(SyncObjectKind::Settings, elsewhere, TimestampMs::new(NOW))
            .await,
        Err(SyncError::NotThatObject { .. })
    ));
}

#[tokio::test]
async fn a_copy_that_arrives_out_of_order_is_kept_rather_than_pruning_itself() {
    let directory = tempfile::tempdir().expect("a directory");
    let store = SyncStore::open(directory.path().join("one")).expect("a store");
    let object_id = fresh_object_id().expect("an identity");
    let other = object(
        object_id,
        1,
        SyncBody::Settings(settings(&[("theme", "dark")], &[])),
        NOW,
    );

    // Eight copies, all at one instant, which is what two answers finishing out of order or a
    // clock that stepped back produce.
    let mut kept = Vec::new();
    for _ in 0..MAX_SYNC_CONFLICT_COPIES {
        let copy = conflict(object_id, &other, NOW);
        kept.push(copy.conflict_id);
        store.keep_conflict(&copy).expect("kept");
    }
    assert_eq!(
        store.conflicts(object_id).expect("copies").len() as u64,
        MAX_SYNC_CONFLICT_COPIES
    );

    // A ninth at an *earlier* instant. It is the one just admitted, so it is never the one pruned:
    // a caller holding its identity must find it stored.
    let newest = conflict(object_id, &other, NOW - 1);
    store.keep_conflict(&newest).expect("kept");
    let copies = store.conflicts(object_id).expect("copies");
    assert_eq!(copies.len() as u64, MAX_SYNC_CONFLICT_COPIES);
    assert!(
        copies
            .items
            .iter()
            .any(|copy| copy.conflict_id == newest.conflict_id),
        "the copy just admitted is never the one pruned"
    );
    assert!(
        store
            .resolve_conflict(newest.conflict_id)
            .expect("resolved")
            .is_some()
    );
}

// ---------------------------------------------------------------------------
// KR-REQ-20.13: one host authority, and drafts that stay drafts
// ---------------------------------------------------------------------------

#[test]
fn host_grants_and_revocation_state_are_not_things_a_restore_can_reach() {
    // Section 20 gives host grants and revocation state one host authority, and the closed kind set
    // is how it says so: there is no kind for them, so a synchronised object cannot be one.
    assert_eq!(
        SyncObjectKind::ALL.map(SyncObjectKind::as_str),
        ["settings", "draft", "client_selection"]
    );

    // A settings value is text, a number or a switch. Nothing in that shape carries a key, a
    // signature or a grant, so there is no settings object that could smuggle authority in.
    let with_authority = serde_json::json!({
        "collection_id": Uuid::from_bytes([1; 16]).to_string(),
        "object_id": Uuid::from_bytes([2; 16]).to_string(),
        "revision": Uuid::from_bytes([3; 16]).to_string(),
        "device_id": Uuid::from_bytes([4; 16]).to_string(),
        "updated_at_ms": NOW,
        "body": {
            "settings": {
                "values": { "theme": { "grant": { "grant_id": Uuid::from_bytes([5; 16]).to_string() } } },
                "pinned_labels": [],
            }
        }
    });
    assert!(
        serde_json::from_value::<SyncObject>(with_authority).is_err(),
        "a grant is not a setting this build reads"
    );

    // A whole extra field is refused too, so a newer writer cannot add one and have an older
    // reader accept it as settings.
    let with_extra = serde_json::json!({
        "collection_id": Uuid::from_bytes([1; 16]).to_string(),
        "object_id": Uuid::from_bytes([2; 16]).to_string(),
        "revision": Uuid::from_bytes([3; 16]).to_string(),
        "device_id": Uuid::from_bytes([4; 16]).to_string(),
        "updated_at_ms": NOW,
        "authority_revision": 4,
        "body": { "settings": { "values": {}, "pinned_labels": [] } }
    });
    assert!(serde_json::from_value::<SyncObject>(with_extra).is_err());
}

#[tokio::test]
async fn a_draft_is_synchronised_as_a_draft_and_never_as_an_execution_request() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(Service::default());
    let sealer: Arc<dyn DraftSealer> = Arc::new(DeviceSealer::new(0x5a));

    // The draft store publishes its own records through its own synchronised half, which is the one
    // way a draft reaches a service.
    let theirs = DraftStore::open(directory.path().join("theirs"), device(1)).expect("a store");
    let target = DraftTarget::session(SessionId::new(Uuid::from_bytes([3; 16]))).in_application(
        ApplicationInstanceId::new(Uuid::from_bytes([4; 16])),
        AgentBindingRevision::new(1),
    );
    let draft = theirs
        .create(
            target,
            "a prompt nobody asked to run".to_owned(),
            TimestampMs::new(NOW),
        )
        .expect("a draft");
    let drafts = DraftSync::new(
        Arc::clone(&service) as Arc<dyn SyncBackupService>,
        Arc::clone(&sealer),
    );
    assert!(matches!(
        drafts
            .publish(
                &theirs,
                draft.draft_id,
                draft.revision,
                TimestampMs::new(NOW)
            )
            .await
            .expect("published"),
        DraftPublished::Accepted { .. }
    ));

    // On the other device it arrives as a draft, beside whatever that device holds, and the only
    // path towards a submission answers a question and performs nothing.
    let mine = DraftStore::open(directory.path().join("mine"), device(2)).expect("a store");
    let fetched = drafts
        .fetch_beside(&mine, draft.draft_id, TimestampMs::new(NOW + 1))
        .await
        .expect("fetched");
    assert_eq!(fetched.remote.text, draft.text);
    // What arrived is a draft on this device, under its own identity, saying which draft it sits
    // beside. Nothing submitted it, and the one path towards a submission is a question rather than
    // an action: it answers with the target a caller *would* send against, and sending is that
    // caller's own separate step.
    let copy: Draft = fetched.copy;
    assert_eq!(copy.conflict_of, Nullable::some(draft.draft_id));
    assert_eq!(copy.device_id, device(2));
    assert_eq!(copy.submission().expect("it answers"), &copy.target);

    // A copy whose application or binding has moved on is not submittable at all until a person
    // retargets it, which is the same rule reaching the same answer.
    let mut moved = copy.clone();
    moved.rebind(Some(&DraftTarget::session(SessionId::new(
        Uuid::from_bytes([3; 16]),
    ))));
    assert_eq!(
        moved.submission().expect_err("it is conflicted"),
        NotSubmittable::Conflicted
    );

    // The settings client refuses a draft before it asks the service, rather than growing a second
    // way to apply one.
    let object_id = SyncObjectId::new(draft.draft_id.get());
    let store = SyncStore::open(directory.path().join("settings")).expect("a store");
    let client = SyncClient::new(
        Arc::clone(&service) as Arc<dyn SyncBackupService>,
        sealer,
        store,
    );
    assert!(matches!(
        client
            .fetch(SyncObjectKind::Draft, object_id, TimestampMs::new(NOW))
            .await,
        Err(SyncError::DraftElsewhere { .. })
    ));

    // And a settings collection that happens to hold a draft's bytes decodes as nothing this
    // module reads, so the refusal does not depend on the collection being honestly named.
    let (_, draft_bytes) = service
        .stored(&kr_client::drafts::draft_collection(draft.draft_id))
        .await
        .expect("the draft is stored");
    service
        .compare_exchange(
            &sync_collection(SyncObjectKind::Settings, object_id),
            0,
            &draft_bytes,
        )
        .await
        .expect("stored under a settings name");
    assert!(matches!(
        client
            .fetch(SyncObjectKind::Settings, object_id, TimestampMs::new(NOW))
            .await,
        Err(SyncError::Encoding(_))
    ));
}

// ---------------------------------------------------------------------------
// KR-REQ-20.13: a checkpoint the service no longer holds
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_service_that_was_reset_leaves_a_checkpoint_only_an_explicit_step_clears() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(Service::default());
    let (client, object_id) = device_client(directory.path(), "one", &service);

    let mine = object(
        object_id,
        1,
        SyncBody::Settings(settings(&[("theme", "dark")], &[])),
        NOW,
    );
    client.store().put_object(&mine).expect("stored");
    client
        .publish(object_id, TimestampMs::new(NOW))
        .await
        .expect("published");

    // The service is reset or replaced. The note names a generation nothing holds, the comparison
    // is refused, and the fetch that would have brought the other content down finds nothing. This
    // device cannot tell an absent object from a service it could not reach, so the refusal is the
    // service's own rather than a diagnosis it has not earned.
    service.reset().await;
    let refused = client
        .publish(object_id, TimestampMs::new(NOW + 1))
        .await
        .expect_err("the comparison is lost and the fetch finds nothing");
    assert!(
        matches!(refused, SyncError::Client(_)),
        "an unreachable object is reported as it came: {refused}"
    );
    assert!(
        client
            .store()
            .checkpoint(object_id)
            .expect("a note")
            .is_some(),
        "nothing clears the note automatically"
    );

    // Forgetting it is the explicit recovery, and it costs a comparison rather than a setting.
    client
        .store()
        .forget_checkpoint(object_id)
        .expect("forgotten");
    assert_eq!(
        client
            .publish(object_id, TimestampMs::new(NOW + 2))
            .await
            .expect("published"),
        Published::Accepted { generation: 1 }
    );
}

#[tokio::test]
async fn a_service_that_has_gone_back_behind_the_note_says_so() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(Service::default());
    let (client, object_id) = device_client(directory.path(), "one", &service);
    let mut mine = object(
        object_id,
        1,
        SyncBody::Settings(settings(&[("theme", "dark")], &[])),
        NOW,
    );
    client.store().put_object(&mine).expect("stored");
    client
        .publish(object_id, TimestampMs::new(NOW))
        .await
        .expect("published");
    mine.revision = fresh_revision().expect("a revision");
    client.store().put_object(&mine).expect("stored");
    client
        .publish(object_id, TimestampMs::new(NOW + 1))
        .await
        .expect("published");

    // The service is replaced and another device writes once, so it answers at a generation below
    // the one this device's note names. That is provable rather than guessed, and it is the case
    // the explicit recovery exists for.
    service.reset().await;
    let elsewhere = SyncClient::new(
        Arc::clone(&service) as Arc<dyn SyncBackupService>,
        Arc::new(DeviceSealer::new(0x5a)) as Arc<dyn DraftSealer>,
        SyncStore::open(directory.path().join("two")).expect("a store"),
    );
    let theirs = object(
        object_id,
        2,
        SyncBody::Settings(settings(&[("theme", "light")], &[])),
        NOW,
    );
    elsewhere.store().put_object(&theirs).expect("stored");
    elsewhere
        .publish(object_id, TimestampMs::new(NOW))
        .await
        .expect("published");

    mine.revision = fresh_revision().expect("a revision");
    client.store().put_object(&mine).expect("stored");
    let refused = client
        .publish(object_id, TimestampMs::new(NOW + 2))
        .await
        .expect_err("the note names a generation the service is behind");
    assert!(
        matches!(refused, SyncError::StaleCheckpoint { expected: 2, .. }),
        "the refusal names what is wrong and what to do: {refused}"
    );

    client
        .store()
        .forget_checkpoint(object_id)
        .expect("forgotten");
    assert!(matches!(
        client
            .publish(object_id, TimestampMs::new(NOW + 3))
            .await
            .expect("answered"),
        Published::Conflicted { .. }
    ));
}

// ---------------------------------------------------------------------------
// KR-REQ-18.05: encrypted settings sync, named beside the rest of the feature
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_service_holds_ciphertext_in_a_declared_bucket_and_never_a_setting() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(Service::default());
    let (client, object_id) = device_client(directory.path(), "one", &service);

    let mine = object(
        object_id,
        1,
        SyncBody::Settings(settings(
            &[("theme", "a-distinctive-setting-value")],
            &["a pinned label"],
        )),
        NOW,
    );
    client.store().put_object(&mine).expect("stored");
    client
        .publish(object_id, TimestampMs::new(NOW))
        .await
        .expect("published");

    let (_, stored) = service
        .stored(&sync_collection(SyncObjectKind::Settings, object_id))
        .await
        .expect("it is stored");
    let haystack = String::from_utf8_lossy(&stored);
    assert!(!haystack.contains("a-distinctive-setting-value"));
    assert!(!haystack.contains("a pinned label"));
    assert!(!haystack.contains("theme"));

    // What it holds is a sealed object with a declared bucket, which is the one length rule a
    // service can check without a key.
    let object: kr_protocol::sync::SealedSyncObject =
        kr_cbor::from_canonical_slice(&stored, &kr_cbor::Limits::DEFAULT).expect("a sealed object");
    assert_eq!(object.check_structure(), Ok(()));
    assert_eq!(object.size_bucket_bytes.get(), 1024);

    // A device holding another key does not read it, which is the whole of what "encrypted" buys
    // against a service that stores the bytes.
    assert!(DeviceSealer::new(0x5b).open(&stored).is_err());
    assert_eq!(
        DeviceSealer::new(0x5a)
            .open(&stored)
            .expect("the device's own key reads it"),
        kr_cbor::to_canonical_vec(&mine).expect("canonical bytes")
    );
}

#[test]
fn the_feature_names_its_three_parts_and_which_of_them_is_optional() {
    assert_eq!(
        StorageFeature::ALL.map(StorageFeature::as_str),
        [
            "encrypted settings sync",
            "history backups",
            "recovery material"
        ]
    );
    assert!(!StorageFeature::SettingsSync.is_optional());
    assert!(StorageFeature::HistoryBackups.is_optional());
    assert!(StorageFeature::RecoveryMaterial.is_optional());
    for part in StorageFeature::ALL {
        assert!(!part.alternative().is_empty());
    }
}

// ---------------------------------------------------------------------------
// Section 24: the privacy hook
// ---------------------------------------------------------------------------

#[tokio::test]
async fn enabling_privacy_fences_production_and_removes_what_it_says_it_removed() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(Service::default());
    let (one, object_id) = device_client(directory.path(), "one", &service);
    let two = SyncClient::new(
        Arc::clone(&service) as Arc<dyn SyncBackupService>,
        Arc::new(DeviceSealer::new(0x5a)) as Arc<dyn DraftSealer>,
        SyncStore::open(directory.path().join("two")).expect("a store"),
    );

    // Give the second device something of each kind to clean up: a checkpoint, a conflict copy and
    // a publication record.
    let theirs = object(
        object_id,
        1,
        SyncBody::Settings(settings(&[("theme", "dark")], &[])),
        NOW,
    );
    one.store().put_object(&theirs).expect("stored");
    one.publish(object_id, TimestampMs::new(NOW))
        .await
        .expect("published");
    let mine = object(
        object_id,
        2,
        SyncBody::Settings(settings(&[("theme", "light")], &[])),
        NOW,
    );
    two.store().put_object(&mine).expect("stored");
    two.publish(object_id, TimestampMs::new(NOW))
        .await
        .expect("answered");
    two.store()
        .pin_label("a label", TimestampMs::new(NOW))
        .expect("pinned");
    assert_eq!(two.store().conflicts(object_id).expect("copies").len(), 1);

    let fenced = two.fence(7).expect("fenced");
    assert_eq!(fenced.queues, 1);
    assert!(two.is_fenced().expect("a record"));
    assert_eq!(two.generation().expect("a record"), 7);
    assert!(matches!(
        two.publish(object_id, TimestampMs::new(NOW + 1)).await,
        Err(SyncError::Fenced { generation: 7 })
    ));

    let cancelled = two.cancel_undispatched(7).expect("cancelled");
    assert_eq!(cancelled.in_flight, 0);
    assert!(two.store().staged().expect("staged").is_empty());

    let removed = two.remove_retained(7).expect("removed");
    assert!(removed.records > 0);
    assert!(removed.bytes > 0);
    // What it reported removed is gone, which is what makes the figures worth reading.
    assert!(two.store().conflicts(object_id).expect("copies").is_empty());
    assert!(two.store().checkpoint(object_id).expect("a note").is_none());
    assert!(two.store().staged().expect("staged").is_empty());

    // What stays is named rather than left out.
    let kept = two.kept().expect("kept");
    assert!(kept.iter().any(|item| item.what.contains("pinned")));
    assert!(kept.iter().any(|item| item.what.contains("settings")));
    assert_eq!(two.store().pinned_labels().expect("labels").len(), 1);
    assert!(two.store().object(object_id).expect("held").is_some());
}

#[tokio::test]
async fn pinned_labels_stay_on_the_device_and_are_left_out_of_what_is_published_while_private() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(Service::default());
    let (client, _) = device_client(directory.path(), "one", &service);
    let mine = settings(&[("theme", "dark")], &["one", "two"]);

    // Not private: the labels travel with the settings.
    let publishable = client.settings_to_publish(&mine).expect("a filter");
    assert_eq!(publishable.pinned_labels.len(), 2);

    // Private: they are left out of what is published, and the device still holds them.
    client.fence(3).expect("fenced");
    let publishable = client.settings_to_publish(&mine).expect("a filter");
    assert!(publishable.pinned_labels.is_empty());
    assert_eq!(publishable.values, mine.values);
    assert_eq!(mine.pinned_labels.len(), 2);

    client
        .store()
        .pin_label("one", TimestampMs::new(NOW))
        .expect("pinned");
    client.remove_retained(3).expect("removed");
    assert_eq!(
        client.store().pinned_labels().expect("labels").len(),
        1,
        "privacy mode does not clear a pinned label"
    );

    // Clearing one is explicit, and it is the only thing that removes one.
    assert!(client.store().clear_pinned_label("one").expect("cleared"));
    assert!(!client.store().clear_pinned_label("one").expect("again"));
    assert!(client.store().pinned_labels().expect("labels").is_empty());

    // Turning privacy mode off starts a generation of its own and reconstructs nothing.
    let resumed = client.resume(4).expect("resumed");
    assert_eq!(resumed.generation, 4);
    assert!(!client.is_fenced().expect("a record"));
    assert!(!client.accepts_result(3).expect("a record"));
    assert!(client.accepts_result(4).expect("a record"));
}

#[tokio::test]
async fn a_result_produced_under_an_earlier_generation_is_not_published() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(GatedService::new());
    let store = SyncStore::open(directory.path().join("one")).expect("a store");
    let client = Arc::new(SyncClient::new(
        Arc::clone(&service) as Arc<dyn SyncBackupService>,
        Arc::new(DeviceSealer::new(0x5a)) as Arc<dyn DraftSealer>,
        store,
    ));
    let object_id = fresh_object_id().expect("an identity");
    let mine = object(
        object_id,
        1,
        SyncBody::Settings(settings(&[("theme", "dark")], &[])),
        NOW,
    );
    client.store().put_object(&mine).expect("stored");

    // The publication leaves and waits at the service.
    let publishing = tokio::spawn({
        let client = Arc::clone(&client);
        async move { client.publish(object_id, TimestampMs::new(NOW)).await }
    });
    service.wait_for_a_publication().await;
    assert_eq!(
        client.outstanding().expect("a count"),
        1,
        "it is dispatched and unsettled"
    );

    // Privacy mode is enabled while it is in flight, which is the case section 24 names.
    client.fence(5).expect("fenced");
    let cancelled = client.cancel_undispatched(5).expect("cancelled");
    assert_eq!(
        cancelled.undispatched, 0,
        "work that has left cannot be taken back"
    );
    assert_eq!(cancelled.in_flight, 1, "it is counted rather than hidden");

    // The answer comes back for work admitted under the generation before this one. It is not
    // published, and nothing about where the object stands moves.
    service.let_it_go();
    let outcome = publishing
        .await
        .expect("the task finished")
        .expect("answered");
    assert_eq!(
        outcome,
        Published::Discarded {
            produced_under: 0,
            current: 5
        }
    );
    assert!(
        client
            .store()
            .checkpoint(object_id)
            .expect("a note")
            .is_none(),
        "no checkpoint moves for a result privacy mode refused"
    );

    // The upload itself happened, and this device says so. Suppressing the result does not undo
    // what left, and section 24 shows what left rather than pretending it did not.
    let exported = client.exported().expect("exported");
    assert_eq!(exported.len(), 1);
    assert!(exported[0].reference.contains("generation 1"));
    assert!(!exported[0].deletable);
    assert_eq!(
        client.outstanding().expect("a count"),
        0,
        "it has now been reconciled"
    );
}

#[tokio::test]
async fn a_publication_whose_caller_walked_away_stays_work_this_device_cannot_account_for() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(GatedService::new());
    let store = SyncStore::open(directory.path().join("one")).expect("a store");
    let client = Arc::new(SyncClient::new(
        Arc::clone(&service) as Arc<dyn SyncBackupService>,
        Arc::new(DeviceSealer::new(0x5a)) as Arc<dyn DraftSealer>,
        store,
    ));
    let object_id = fresh_object_id().expect("an identity");
    let mine = object(
        object_id,
        1,
        SyncBody::Settings(settings(&[("theme", "dark")], &[])),
        NOW,
    );
    client.store().put_object(&mine).expect("stored");

    let publishing = tokio::spawn({
        let client = Arc::clone(&client);
        async move { client.publish(object_id, TimestampMs::new(NOW)).await }
    });
    service.wait_for_a_publication().await;
    assert_eq!(client.outstanding().expect("a count"), 1);

    // The caller abandons the call at the await. Nothing about that establishes that the write did
    // not land, so the work stays outstanding: a count that followed the future rather than the
    // work would report a cleanup complete while the object may have been on its way.
    publishing.abort();
    let _ = publishing.await;
    assert_eq!(
        client.outstanding().expect("a count"),
        1,
        "an abandoned call settles nothing"
    );
    let staged = client.store().staged().expect("staged");
    assert_eq!(staged.len(), 1);
    assert!(staged.items[0].dispatched);
    assert_eq!(
        client
            .cancel_undispatched(0)
            .expect("cancelled")
            .undispatched,
        0,
        "work that has left cannot be taken back"
    );

    // A client built over the same store counts it too, because a restart does not make an
    // uncertain outcome certain.
    let reopened = SyncClient::new(
        Arc::clone(&service) as Arc<dyn SyncBackupService>,
        Arc::new(DeviceSealer::new(0x5a)) as Arc<dyn DraftSealer>,
        SyncStore::open(directory.path().join("one")).expect("a store"),
    );
    assert_eq!(reopened.outstanding().expect("a count"), 1);

    // Nothing settles it, and this client does not pretend otherwise. A later answer about the
    // object says what the service holds; it does not say what became of this request, and one
    // whose answer was lost can still be accepted afterwards. This contract offers no way to ask:
    // a service takes a comparison and answers with a generation, and there is nothing to ask it
    // about one write of an object.
    service.let_it_go();
    reopened.store().put_object(&mine).expect("stored");
    assert!(matches!(
        reopened
            .publish(object_id, TimestampMs::new(NOW + 2))
            .await
            .expect("answered"),
        Published::Accepted { .. } | Published::Conflicted { .. }
    ));
    assert_eq!(
        reopened.outstanding().expect("a count"),
        1,
        "an answer about the object settles that request and not another one"
    );

    // What it may have sent is named, because it left this device and nothing here can say whether
    // the service stored it.
    let exported = reopened.exported().expect("exported");
    assert!(
        exported
            .iter()
            .any(|entry| entry.kind.contains("sent without an answer")),
        "what may have left is named rather than dropped: {exported:?}"
    );
    assert!(exported.iter().all(|entry| !entry.deletable));
}

#[tokio::test]
async fn a_cleanup_keeps_the_record_of_work_that_had_already_left() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(GatedService::new());
    let store = SyncStore::open(directory.path().join("one")).expect("a store");
    let client = Arc::new(SyncClient::new(
        Arc::clone(&service) as Arc<dyn SyncBackupService>,
        Arc::new(DeviceSealer::new(0x5a)) as Arc<dyn DraftSealer>,
        store,
    ));
    let object_id = fresh_object_id().expect("an identity");
    let mine = object(
        object_id,
        1,
        SyncBody::Settings(settings(&[("theme", "dark")], &[])),
        NOW,
    );
    client.store().put_object(&mine).expect("stored");

    let publishing = tokio::spawn({
        let client = Arc::clone(&client);
        async move { client.publish(object_id, TimestampMs::new(NOW)).await }
    });
    service.wait_for_a_publication().await;
    assert_eq!(client.outstanding().expect("a count"), 1);

    // The whole cleanup, in the order section 24 states it. It must not make this device say
    // nothing is outstanding while a write it sent has no answer.
    client.fence(4).expect("fenced");
    assert_eq!(
        client.cancel_undispatched(4).expect("cancelled").in_flight,
        1
    );
    client.remove_retained(4).expect("removed");
    assert_eq!(
        client.outstanding().expect("a count"),
        1,
        "a cleanup does not settle a write that has left"
    );
    let staged = client.store().staged().expect("staged");
    assert_eq!(staged.len(), 1);
    assert!(staged.items[0].dispatched);

    service.let_it_go();
    let _ = publishing.await.expect("the task finished");
}

#[tokio::test]
async fn a_fence_between_admission_and_dispatch_takes_the_work_back() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(Service::default());
    let (client, object_id) = device_client(directory.path(), "one", &service);
    let mine = object(
        object_id,
        1,
        SyncBody::Settings(settings(&[("theme", "dark")], &[])),
        NOW,
    );
    client.store().put_object(&mine).expect("stored");

    // Admitted under generation nought, and a fence lands before it is sent. The record is taken
    // back rather than dispatched, which is what the cancellation would have done to it.
    let staged = client
        .store()
        .admit(object_id, |object| {
            Ok(kr_cbor::to_canonical_vec(object).expect("canonical bytes"))
        })
        .expect("admitted");
    client.fence(9).expect("fenced");
    assert!(matches!(
        client.store().mark_dispatched(staged.work_id, object_id),
        Err(SyncError::Fenced { generation: 9 })
    ));
    assert!(client.store().staged().expect("staged").is_empty());
    assert_eq!(client.outstanding().expect("a count"), 0);

    // And a publication started after the fence never reaches the service at all.
    assert!(matches!(
        client.publish(object_id, TimestampMs::new(NOW)).await,
        Err(SyncError::Fenced { generation: 9 })
    ));
    assert!(service.collections().await.is_empty());
}

#[tokio::test]
async fn outstanding_reaches_nought_only_once_a_dispatched_publication_has_settled() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(Service::default());
    let (client, object_id) = device_client(directory.path(), "one", &service);
    let mine = object(
        object_id,
        1,
        SyncBody::Settings(settings(&[("theme", "dark")], &[])),
        NOW,
    );
    client.store().put_object(&mine).expect("stored");

    assert_eq!(client.outstanding().expect("a count"), 0);
    client
        .publish(object_id, TimestampMs::new(NOW))
        .await
        .expect("published");
    assert_eq!(
        client.outstanding().expect("a count"),
        0,
        "a settled publication is no longer in flight"
    );
    // A cancellation reports what is still out, which is nothing once it has settled.
    assert_eq!(
        client.cancel_undispatched(1).expect("cancelled").in_flight,
        0
    );
}

#[tokio::test]
async fn what_has_already_left_is_shown_rather_than_claimed_to_be_erased() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(Service::default());
    let (client, object_id) = device_client(directory.path(), "one", &service);
    let mine = object(
        object_id,
        1,
        SyncBody::Settings(settings(&[("theme", "dark")], &[])),
        NOW,
    );
    client.store().put_object(&mine).expect("stored");
    client
        .publish(object_id, TimestampMs::new(NOW))
        .await
        .expect("published");

    client.fence(2).expect("fenced");
    client.remove_retained(2).expect("removed");

    let exported = client.exported().expect("exported");
    assert_eq!(exported.len(), 1);
    assert_eq!(exported[0].left_at_ms, TimestampMs::new(NOW));
    assert!(exported[0].reference.contains("generation 1"));
    assert!(
        !exported[0].deletable,
        "this client has no way to ask a compare-and-exchange store to delete an object"
    );
    // The record survives the cleanup, because it is the only account of what left.
    assert_eq!(client.store().publications().expect("records").len(), 1);
}

#[tokio::test]
async fn a_client_selection_is_a_position_rather_than_a_row() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(Service::default());
    let (client, object_id) = device_client(directory.path(), "one", &service);

    let mut selection = ClientSelection::nothing_selected();
    selection.session_id = Nullable::some(SessionId::new(Uuid::from_bytes([3; 16])));
    selection.rows_from_newest = U64::new(12);
    let mine = object(
        object_id,
        1,
        SyncBody::ClientSelection(selection.clone()),
        NOW,
    );
    client.store().put_object(&mine).expect("stored");
    client
        .publish(object_id, TimestampMs::new(NOW))
        .await
        .expect("published");

    assert!(
        service
            .collections()
            .await
            .iter()
            .any(|name| name.starts_with("client_selection/"))
    );
    let restored = client
        .fetch(
            SyncObjectKind::ClientSelection,
            object_id,
            TimestampMs::new(NOW),
        )
        .await
        .expect("fetched");
    assert_eq!(restored.object().body, SyncBody::ClientSelection(selection));
}

#[tokio::test]
async fn a_cleanup_that_a_later_generation_overtook_is_refused() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(Service::default());
    let (client, object_id) = device_client(directory.path(), "one", &service);
    let mine = object(
        object_id,
        1,
        SyncBody::Settings(settings(&[("theme", "dark")], &[])),
        NOW,
    );
    client.store().put_object(&mine).expect("stored");

    // Privacy mode is enabled and then turned off again. A cleanup step of the older generation
    // arriving now is refused rather than carried out: the generation in force has already decided
    // what is retained, and the older step would delete what it admitted.
    client.fence(5).expect("fenced");
    client.resume(6).expect("resumed");
    client
        .publish(object_id, TimestampMs::new(NOW))
        .await
        .expect("published");

    assert!(matches!(
        client.cancel_undispatched(5),
        Err(SyncError::LateResult {
            produced_under: 5,
            current: 6
        })
    ));
    assert!(matches!(
        client.remove_retained(5),
        Err(SyncError::LateResult {
            produced_under: 5,
            current: 6
        })
    ));
    assert!(
        client
            .store()
            .checkpoint(object_id)
            .expect("a note")
            .is_some(),
        "an overtaken cleanup reaches nothing the generation in force admitted"
    );
    assert_eq!(client.generation().expect("a record"), 6);
}
