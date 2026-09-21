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
use kr_client::services::{
    SYNC_RECEIPT_RETENTION_MS, SYNC_RECEIPT_SWEEP_MARGIN_MS, ServiceFuture, SyncBackupService,
    SyncExchanged, SyncPosition, SyncRequestFence, SyncRequestStatus, SyncRevision,
    fence_proves_it_never_ran,
};
use kr_client::sync::{
    Claimed, ClientSelection, ConflictCopy, Dispatch, Outcome, PrivacyRecord, Publication,
    Published, Reconciled, RequestRecord, RequestState, Restored, SettingValue, Settlement,
    StorageFeature, SyncBody, SyncCheckpoint, SyncClient, SyncError, SyncObject, SyncSettings,
    SyncStore, fresh_object_id, fresh_revision, sync_collection,
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

/// The position a service reports for the nth write of a collection.
///
/// The deployed service names each write with an opaque identifier of its own; this suite derives
/// one from the write sequence so a test can say where it expects a write to land. Only writes of
/// one collection are ever compared, which is what makes deriving it safe here.
fn at(write_sequence: u64) -> SyncPosition {
    SyncPosition {
        write_sequence,
        revision: SyncRevision::new(Uuid::from_bytes([write_sequence as u8; 16])),
    }
}

/// What one request was answered with, kept under the identity that request presented.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Recorded {
    /// The write was applied, leaving the object at this position.
    Applied(SyncPosition),
    /// The comparison was refused, and the service kept the rejected write as this copy of its own.
    Refused(SyncConflictId),
    /// The request was fenced before anything ran under it, so nothing ever will.
    Fenced,
}

/// The receipt one request left behind.
#[derive(Clone, Debug)]
struct Receipt {
    /// The request this receipt answered, as the wire carried it: the revision the comparison
    /// named and the bytes. The deployed service records a digest of those fields, and its order is
    /// not one of them. A fence receipt answers no request, so it has nothing to hold: there is no
    /// payload for a request that never ran.
    request: Option<(Option<SyncRevision>, Vec<u8>)>,
    /// The reply that was given.
    recorded: Recorded,
}

impl Receipt {
    const fn recorded(&self) -> &Recorded {
        &self.recorded
    }
}

/// One exchange as this device sent it.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Exchange {
    collection: String,
    request_id: Uuid,
    expected: Option<SyncPosition>,
    ciphertext: Vec<u8>,
}

/// What becomes of the next exchange, so a test can lose an answer the way a network does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Interruption {
    /// The service applies the request and the answer never reaches the device.
    AfterTheWrite,
    /// The request never reaches the service, so no receipt is ever written for it.
    BeforeItArrives,
    /// The identity the request presents already answered a different request.
    ///
    /// The receipt under it accounts for that other request, and the object is left alone: what
    /// section 9 refuses is the second request wearing the first one's name.
    IdentityTaken,
}

/// A compare-and-exchange store over opaque bytes, and the request receipts beside it.
///
/// It is the service's half of section 20's compare and swap and of section 9's receipt: it holds
/// one position and one object per collection, records the reply it gave each request identity,
/// replays that reply for an exact retry, refuses a reused identity carrying different content,
/// and answers about an identity it has no receipt for by saying it holds none.
#[derive(Debug, Default)]
struct Service {
    objects: Mutex<BTreeMap<String, (SyncPosition, Vec<u8>)>>,
    receipts: Mutex<BTreeMap<(String, Uuid), Receipt>>,
    sent: Mutex<Vec<Exchange>>,
    asked: Mutex<Vec<(String, Uuid)>>,
    fences: Mutex<Vec<(String, Uuid)>>,
    fence_unreachable: Mutex<bool>,
    /// Whether the next status query answers before the request it asks about has committed.
    status_misses_the_receipt: Mutex<bool>,
    interruption: Mutex<Option<Interruption>>,
    status_unreachable: Mutex<bool>,
    /// The collection each request was sent to, so a forgotten receipt can be found again.
    receipt_of: Mutex<BTreeMap<Uuid, String>>,
}

impl Service {
    /// Forgets everything, which is what a reset or a replaced service looks like to a device.
    async fn reset(&self) {
        self.objects.lock().await.clear();
        self.receipts.lock().await.clear();
    }

    /// Puts one object in a collection at a position of the caller's choosing.
    ///
    /// What a service restored from somewhere else looks like: the order is continued from a
    /// history this device never saw.
    async fn hold(&self, collection: &str, position: SyncPosition, ciphertext: Vec<u8>) {
        self.objects
            .lock()
            .await
            .insert(collection.to_owned(), (position, ciphertext));
    }

    async fn stored(&self, collection: &str) -> Option<(SyncPosition, Vec<u8>)> {
        self.objects.lock().await.get(collection).cloned()
    }

    async fn collections(&self) -> Vec<String> {
        self.objects.lock().await.keys().cloned().collect()
    }

    /// Applies the next exchange and loses its answer on the way back.
    async fn lose_the_next_answer(&self) {
        *self.interruption.lock().await = Some(Interruption::AfterTheWrite);
    }

    /// Stops the next exchange before the service sees it, so it leaves no receipt.
    async fn drop_the_next_request(&self) {
        *self.interruption.lock().await = Some(Interruption::BeforeItArrives);
    }

    /// Answers the next exchange as an identity a different request already wore.
    async fn give_the_next_identity_to_another_request(&self) {
        *self.interruption.lock().await = Some(Interruption::IdentityTaken);
    }

    /// Makes every status query fail, which is a service this device cannot ask.
    async fn stop_answering_about_requests(&self) {
        *self.status_unreachable.lock().await = true;
    }

    /// Forgets one receipt, which is section 9's thirty-day retention passing.
    ///
    /// The receipt is gone, not hidden: an exchange under that identity would be executed again,
    /// a status query holds nothing to answer from, and a fence records the fence over nothing.
    /// That is what makes the window matter, because afterwards the service cannot tell a request
    /// it ran from one it never saw.
    async fn forget_the_receipt(&self, request_id: Uuid) {
        let collection = self.receipt_of.lock().await.remove(&request_id);
        if let Some(collection) = collection {
            self.receipts.lock().await.remove(&(collection, request_id));
        }
    }

    /// Every exchange this device sent, whether or not the service acted on it.
    async fn exchanges(&self) -> Vec<Exchange> {
        self.sent.lock().await.clone()
    }

    /// Every request identity this device asked the status of.
    async fn status_queries(&self) -> Vec<(String, Uuid)> {
        self.asked.lock().await.clone()
    }

    /// Every request identity this device asked the service to fence.
    async fn fence_requests(&self) -> Vec<(String, Uuid)> {
        self.fences.lock().await.clone()
    }

    /// Makes every fence fail, which is a service this device cannot ask to end a request.
    async fn stop_fencing_requests(&self) {
        *self.fence_unreachable.lock().await = true;
    }

    /// Lets the service answer fences again.
    async fn answer_fences_again(&self) {
        *self.fence_unreachable.lock().await = false;
    }

    /// Answers the next status query before the request it asks about has committed.
    ///
    /// The request is on its way and the service has written no receipt for it yet, which is the
    /// case a status query cannot tell from one that never arrived.
    async fn let_the_next_status_miss_the_receipt(&self) {
        *self.status_misses_the_receipt.lock().await = true;
    }

    /// Answers one exchange, from the receipt when this identity has one.
    async fn exchange(
        &self,
        collection: &str,
        request_id: Uuid,
        expected: Option<SyncPosition>,
        ciphertext: &[u8],
    ) -> kr_client::Result<SyncExchanged> {
        let key = (collection.to_owned(), request_id);
        let request = (
            expected.map(|position| position.revision),
            ciphertext.to_vec(),
        );
        let mut receipts = self.receipts.lock().await;
        if let Some(receipt) = receipts.get(&key) {
            // An identity that was fenced runs nothing afterwards, whatever it carries.
            if receipt.recorded == Recorded::Fenced {
                return Err(ClientError::Host(ProtocolError::new(
                    ErrorCode::PermissionDenied,
                    "that request was fenced",
                )));
            }
            // An exact retry is answered from the receipt and applied no second time. The same
            // identity carrying different content is a second request wearing the first one's
            // name, which section 9 refuses rather than answers.
            if receipt.request != Some(request) {
                return Err(ClientError::Host(ProtocolError::new(
                    ErrorCode::IdConflict,
                    "that identity already answered a different request",
                )));
            }
            return Ok(answer(receipt.recorded));
        }
        let mut objects = self.objects.lock().await;
        let current = objects.get(collection).map(|(position, _)| *position);
        // The comparison is against the revision the caller named, which is the only part of a
        // position the exchange carries. The order beside it is the service's own answer.
        let recorded = if current.map(|position| position.revision)
            == expected.map(|position| position.revision)
        {
            // The service's own order: the next write of this object takes the next place in it,
            // and the first write of all takes place one.
            let next = at(current.map_or(1, |position| position.write_sequence + 1));
            objects.insert(collection.to_owned(), (next, ciphertext.to_vec()));
            Recorded::Applied(next)
        } else {
            // The service keeps the rejected write as a copy of its own, and the receipt names it.
            // A refusal is therefore an answer about the comparison and never a claim that the
            // service stored nothing.
            Recorded::Refused(SyncConflictId::new(fresh_request_id()))
        };
        receipts.insert(
            key.clone(),
            Receipt {
                request: Some(request),
                recorded,
            },
        );
        self.receipt_of.lock().await.insert(request_id, key.0);
        Ok(answer(recorded))
    }
}

/// The reply a receipt records, as the exchange itself would have answered.
fn answer(recorded: Recorded) -> SyncExchanged {
    match recorded {
        Recorded::Applied(position) => SyncExchanged::Applied { position },
        Recorded::Refused(conflict_id) => SyncExchanged::Refused {
            retained: Some(conflict_id),
        },
        Recorded::Fenced => unreachable!("a fenced identity never answers an exchange"),
    }
}

/// An answer that never came back, which is the one refusal that establishes nothing.
fn lost(what: &'static str) -> ClientError {
    ClientError::Host(ProtocolError::new(ErrorCode::UpstreamUnavailable, what))
}

impl SyncBackupService for Service {
    fn compare_exchange<'a>(
        &'a self,
        collection: &'a str,
        request_id: Uuid,
        expected: Option<SyncPosition>,
        ciphertext: &'a [u8],
    ) -> ServiceFuture<'a, SyncExchanged> {
        Box::pin(async move {
            self.sent.lock().await.push(Exchange {
                collection: collection.to_owned(),
                request_id,
                expected,
                ciphertext: ciphertext.to_vec(),
            });
            let interruption = self.interruption.lock().await.take();
            if interruption == Some(Interruption::BeforeItArrives) {
                return Err(lost("the request never reached the service"));
            }
            if interruption == Some(Interruption::IdentityTaken) {
                // The receipt under this identity answers a request that carried other content,
                // and it says that request was applied. The object is untouched.
                let current = self
                    .objects
                    .lock()
                    .await
                    .get(collection)
                    .map_or(0, |(position, _)| position.write_sequence);
                self.receipts.lock().await.insert(
                    (collection.to_owned(), request_id),
                    Receipt {
                        request: Some((
                            expected.map(|position| position.revision),
                            b"a different payload".to_vec(),
                        )),
                        recorded: Recorded::Applied(at(current + 1)),
                    },
                );
                return Err(ClientError::Host(ProtocolError::new(
                    ErrorCode::IdConflict,
                    "that identity already answered a different request",
                )));
            }
            let answered = self
                .exchange(collection, request_id, expected, ciphertext)
                .await;
            if interruption == Some(Interruption::AfterTheWrite) {
                return Err(lost("the answer never came back"));
            }
            answered
        })
    }

    fn request_status<'a>(
        &'a self,
        collection: &'a str,
        request_id: Uuid,
    ) -> ServiceFuture<'a, SyncRequestStatus> {
        Box::pin(async move {
            self.asked
                .lock()
                .await
                .push((collection.to_owned(), request_id));
            if *self.status_unreachable.lock().await {
                return Err(lost("the service could not be asked"));
            }
            if std::mem::take(&mut *self.status_misses_the_receipt.lock().await) {
                return Ok(SyncRequestStatus::Unknown);
            }
            Ok(
                match self
                    .receipts
                    .lock()
                    .await
                    .get(&(collection.to_owned(), request_id))
                    .map(|receipt| receipt.recorded)
                {
                    Some(Recorded::Applied(position)) => SyncRequestStatus::Applied { position },
                    Some(Recorded::Refused(conflict_id)) => SyncRequestStatus::Refused {
                        retained: Some(conflict_id),
                    },
                    Some(Recorded::Fenced) => SyncRequestStatus::Fenced,
                    None => SyncRequestStatus::Unknown,
                },
            )
        })
    }

    fn fence_request<'a>(
        &'a self,
        collection: &'a str,
        request_id: Uuid,
    ) -> ServiceFuture<'a, SyncRequestFence> {
        Box::pin(async move {
            self.fences
                .lock()
                .await
                .push((collection.to_owned(), request_id));
            if *self.fence_unreachable.lock().await {
                return Err(lost("the service could not be asked to fence"));
            }
            let key = (collection.to_owned(), request_id);
            let mut receipts = self.receipts.lock().await;
            // A request the service has already decided keeps its outcome; one it has not is
            // fenced, and the receipt that records the fence is what refuses an exchange
            // afterwards. A fence never answers that it does not know.
            let recorded = *receipts
                .entry(key)
                .or_insert(Receipt {
                    request: None,
                    recorded: Recorded::Fenced,
                })
                .recorded();
            Ok(match recorded {
                Recorded::Applied(position) => SyncRequestFence::Applied { position },
                Recorded::Refused(conflict_id) => SyncRequestFence::Refused {
                    retained: Some(conflict_id),
                },
                Recorded::Fenced => SyncRequestFence::Fenced,
            })
        })
    }

    fn fetch<'a>(&'a self, collection: &'a str) -> ServiceFuture<'a, (SyncPosition, Vec<u8>)> {
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
    /// Whether the reply is held rather than the request.
    afterwards: Mutex<bool>,
}

impl GatedService {
    fn new() -> Self {
        Self {
            inner: Service::default(),
            entered: tokio::sync::Semaphore::new(0),
            release: tokio::sync::Semaphore::new(0),
            afterwards: Mutex::new(false),
        }
    }

    /// Holds the reply instead of the request, so the write is committed and its receipt written
    /// before the device making the call learns anything.
    async fn hold_the_answer_instead(&self) {
        *self.afterwards.lock().await = true;
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

    /// Announces that a publication has reached the gate, and waits there.
    async fn wait_at_the_gate(&self) {
        self.entered.add_permits(1);
        self.release
            .acquire()
            .await
            .expect("the gate is open")
            .forget();
    }
}

impl SyncBackupService for GatedService {
    fn compare_exchange<'a>(
        &'a self,
        collection: &'a str,
        request_id: Uuid,
        expected: Option<SyncPosition>,
        ciphertext: &'a [u8],
    ) -> ServiceFuture<'a, SyncExchanged> {
        Box::pin(async move {
            let afterwards = *self.afterwards.lock().await;
            if !afterwards {
                self.wait_at_the_gate().await;
            }
            let answered = self
                .inner
                .compare_exchange(collection, request_id, expected, ciphertext)
                .await;
            if afterwards {
                self.wait_at_the_gate().await;
            }
            answered
        })
    }

    fn request_status<'a>(
        &'a self,
        collection: &'a str,
        request_id: Uuid,
    ) -> ServiceFuture<'a, SyncRequestStatus> {
        self.inner.request_status(collection, request_id)
    }

    fn fence_request<'a>(
        &'a self,
        collection: &'a str,
        request_id: Uuid,
    ) -> ServiceFuture<'a, SyncRequestFence> {
        self.inner.fence_request(collection, request_id)
    }

    fn fetch<'a>(&'a self, collection: &'a str) -> ServiceFuture<'a, (SyncPosition, Vec<u8>)> {
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

/// One identity for a request a test sends itself, rather than through a client.
fn fresh_request_id() -> Uuid {
    kr_transport::random::fresh_uuid_v4().expect("an identity")
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
        expected: Nullable::null(),
        current: at(1),
        other: other.clone(),
        recorded_at_ms: TimestampMs::new(at_ms),
    }
}

/// Claims one request's dispatch, which is what a settlement is decided under.
fn claim(store: &SyncStore, work_id: Uuid) -> Dispatch {
    match store.claim_dispatched(work_id).expect("a claim") {
        Claimed::Taken(dispatch, _) => dispatch,
        other => panic!("that request is not claimable: {other:?}"),
    }
}

/// Claims one request whose staged record has already gone, for a late answer about it.
fn claim_after_discard(store: &SyncStore, work_id: Uuid) -> Dispatch {
    store
        .claim_request(work_id)
        .expect("a claim")
        .expect("nobody is waiting on it")
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
        Published::Accepted { position: at(1) }
    );
    let note = client
        .store()
        .checkpoint(object_id)
        .expect("a note")
        .expect("one was written");
    assert_eq!(note.position, at(1));
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
        Published::Accepted { position: at(2) }
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
        position,
    } = outcome
    else {
        panic!("the second device lost the comparison: {outcome:?}")
    };
    assert_eq!(other_revision, theirs.revision);
    assert_eq!(position, at(1));

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
        Published::Accepted { position: at(2) }
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
    let (position, ciphertext) = service
        .stored(&sync_collection(SyncObjectKind::Settings, object_id))
        .await
        .expect("it is stored");
    service
        .compare_exchange(
            &sync_collection(SyncObjectKind::Settings, elsewhere),
            fresh_request_id(),
            None,
            &ciphertext,
        )
        .await
        .expect("stored elsewhere");
    assert_eq!(position, at(1));

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
            fresh_request_id(),
            None,
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

    // The service is reset or replaced. The note names a write nothing holds, the comparison
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
        Published::Accepted { position: at(1) }
    );
}

#[test]
fn a_note_is_never_replaced_by_an_answer_that_does_not_follow_it() {
    let directory = tempfile::tempdir().expect("a directory");
    let store = SyncStore::open(directory.path().join("one")).expect("a store");
    let object_id = fresh_object_id().expect("an identity");
    let forked = SyncPosition {
        write_sequence: 5,
        revision: SyncRevision::new(Uuid::from_bytes([0xf0; 16])),
    };

    let note = |position| SyncCheckpoint {
        position,
        published_revision: Nullable::null(),
    };
    assert!(
        store
            .record_checkpoint(object_id, note(at(5)))
            .expect("a note")
    );

    // One write sequence names one write for the life of a collection, so an answer naming the
    // same place under another name comes from a second history rather than from a later write.
    // The note this device established stands, and so does the account of what it published.
    assert!(
        !store
            .record_checkpoint(object_id, note(forked))
            .expect("a note")
    );
    assert!(
        !store
            .record_checkpoint(object_id, note(at(4)))
            .expect("a note")
    );
    assert_eq!(
        store
            .checkpoint(object_id)
            .expect("a note")
            .expect("one stands")
            .position,
        at(5)
    );

    let published = |position| Publication {
        object_id,
        kind: SyncObjectKind::Settings,
        position,
        published_at_ms: TimestampMs::new(NOW),
    };
    assert!(
        store
            .record_publication(&published(at(5)))
            .expect("a record")
    );
    assert!(
        !store
            .record_publication(&published(forked))
            .expect("a record")
    );
    assert_eq!(
        store.publications().expect("records").items[0].position,
        at(5)
    );

    // A later write still lands, on both.
    assert!(
        store
            .record_checkpoint(object_id, note(at(6)))
            .expect("a note")
    );
    assert!(
        store
            .record_publication(&published(at(6)))
            .expect("a record")
    );
}

#[tokio::test]
async fn a_service_holding_another_write_in_the_same_place_says_the_history_forked() {
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
    let collection = sync_collection(SyncObjectKind::Settings, object_id);

    // The collection is rebuilt somewhere else and reaches the same place in the order under
    // another name. One write sequence names one write for the life of a collection, so this is
    // two histories rather than one, and the note beside this object belongs to the other.
    let (position, ciphertext) = service.stored(&collection).await.expect("it is stored");
    service
        .hold(
            &collection,
            SyncPosition {
                write_sequence: position.write_sequence,
                revision: SyncRevision::new(Uuid::from_bytes([0xf0; 16])),
            },
            ciphertext,
        )
        .await;

    let refused = client
        .fetch(
            SyncObjectKind::Settings,
            object_id,
            TimestampMs::new(NOW + 1),
        )
        .await
        .expect_err("the service holds another write in the same place");
    assert!(
        matches!(
            refused,
            SyncError::ForkedHistory {
                write_sequence: 1,
                ..
            }
        ),
        "the refusal says which of the two things went wrong: {refused}"
    );
    assert_eq!(
        client
            .store()
            .checkpoint(object_id)
            .expect("a note")
            .expect("the write left one")
            .position,
        at(1),
        "nothing writes a note from a history this device cannot follow"
    );

    // Forgetting the note is the explicit recovery here as well, and the fetch then succeeds.
    client
        .store()
        .forget_checkpoint(object_id)
        .expect("forgotten");
    client
        .fetch(
            SyncObjectKind::Settings,
            object_id,
            TimestampMs::new(NOW + 2),
        )
        .await
        .expect("fetched");
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

    // The service is replaced and another device writes once, so it answers with a write sequence
    // below the one this device's note names. A write sequence only goes forward, so that is
    // provable rather than guessed, and it is the case the explicit recovery exists for.
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
        .expect_err("the note names a write the service is behind");
    assert!(
        matches!(
            refused,
            SyncError::StaleCheckpoint {
                expected: 2,
                found: 1,
                ..
            }
        ),
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

    let cancelled = two
        .cancel_undispatched(7, TimestampMs::new(NOW + 2))
        .await
        .expect("cancelled");
    assert_eq!(cancelled.in_flight, 0);
    // Nothing is waiting for an answer. What stays is the account of the write the service refused
    // and kept a copy of, which is a record of what left rather than work still to do.
    let waiting = |client: &SyncClient| {
        client
            .store()
            .requests()
            .expect("requests")
            .items
            .iter()
            .filter(|record| !record.ended())
            .count()
    };
    assert_eq!(waiting(&two), 0);

    let removed = two
        .remove_retained(7, TimestampMs::new(NOW + 2))
        .await
        .expect("removed");
    assert!(removed.records > 0);
    assert!(removed.bytes > 0);
    // What it reported removed is gone, which is what makes the figures worth reading.
    assert!(two.store().conflicts(object_id).expect("copies").is_empty());
    assert!(two.store().checkpoint(object_id).expect("a note").is_none());
    assert_eq!(waiting(&two), 0);

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
    client
        .remove_retained(3, TimestampMs::new(NOW))
        .await
        .expect("removed");
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
    let cancelled = client
        .cancel_undispatched(5, TimestampMs::new(NOW + 1))
        .await
        .expect("cancelled");
    assert_eq!(
        cancelled.undispatched, 0,
        "work that has left cannot be taken back"
    );
    // The cleanup reconciles first, and the service holds no receipt for a request it has not
    // committed yet. This device is the only thing that can tell that from a request that never
    // arrived, because the call is its own, so the work is counted rather than discarded.
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
    assert!(exported[0].reference.contains("write 1"));
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
    let staged = client.store().requests().expect("requests");
    assert_eq!(staged.len(), 1);
    assert!(staged.items[0].dispatched());
    assert_eq!(
        client
            .cancel_undispatched(0, TimestampMs::new(NOW + 1))
            .await
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

    // Nothing here settles it, and this client does not pretend otherwise. A later answer about
    // the object says what the service holds; it does not say what became of this request, and one
    // whose answer was lost can still be accepted afterwards. What settles it is the request's own
    // identity, which is a separate question put to the service and never an inference from what
    // the object holds now.
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
        client
            .cancel_undispatched(4, TimestampMs::new(NOW + 1))
            .await
            .expect("cancelled")
            .in_flight,
        1
    );
    client
        .remove_retained(4, TimestampMs::new(NOW + 1))
        .await
        .expect("removed");
    assert_eq!(
        client.outstanding().expect("a count"),
        1,
        "a cleanup does not settle a write that has left"
    );
    let staged = client.store().requests().expect("requests");
    assert_eq!(staged.len(), 1);
    assert!(staged.items[0].dispatched());

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
        client
            .store()
            .begin_dispatch(staged.work_id, object_id, TimestampMs::new(NOW)),
        Err(SyncError::Fenced { generation: 9 })
    ));
    assert!(client.store().requests().expect("requests").is_empty());
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
        client
            .cancel_undispatched(1, TimestampMs::new(NOW))
            .await
            .expect("cancelled")
            .in_flight,
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
    client
        .remove_retained(2, TimestampMs::new(NOW))
        .await
        .expect("removed");

    let exported = client.exported().expect("exported");
    assert_eq!(exported.len(), 1);
    assert_eq!(exported[0].left_at_ms, TimestampMs::new(NOW));
    assert!(exported[0].reference.contains("write 1"));
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
        client.cancel_undispatched(5, TimestampMs::new(NOW)).await,
        Err(SyncError::LateResult {
            produced_under: 5,
            current: 6
        })
    ));
    assert!(matches!(
        client.remove_retained(5, TimestampMs::new(NOW)).await,
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

// ---------------------------------------------------------------------------
// KR-REQ-20.13 and section 24: settling a dispatch whose answer was lost
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_lost_answer_to_a_write_the_service_applied_is_settled_by_asking_about_the_request() {
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

    // The service applies the write and the answer never comes back.
    service.lose_the_next_answer().await;
    let error = client
        .publish(object_id, TimestampMs::new(NOW))
        .await
        .expect_err("the answer never came back");
    assert_eq!(error.code(), ErrorCode::UpstreamUnavailable);
    assert_eq!(
        client.outstanding().expect("a count"),
        1,
        "nothing about a lost answer establishes that the write did not land"
    );
    assert!(
        client
            .store()
            .checkpoint(object_id)
            .expect("a note")
            .is_none(),
        "no checkpoint moves on an answer this device never received"
    );

    // The receipt the service kept under the identity the request carried is what settles it.
    let reconciled = client
        .reconcile_unsettled(TimestampMs::new(NOW + 1))
        .await
        .expect("reconciled");
    assert_eq!(
        reconciled,
        Reconciled {
            settled: 1,
            fenced: 0,
            accounts_kept: 0,
            unresolved: 0,
            copies_not_taken: 0,
            unsettled: 0,
        }
    );
    assert_eq!(client.outstanding().expect("a count"), 0);
    assert_eq!(
        client
            .store()
            .checkpoint(object_id)
            .expect("a note")
            .expect("the write left one")
            .position,
        at(1)
    );
    let exported = client.exported().expect("exported");
    assert_eq!(exported.len(), 1);
    assert!(exported[0].reference.contains("write 1"));

    // It asked about the request it had sent, under that request's own identity.
    let sent = service.exchanges().await;
    assert_eq!(sent.len(), 1);
    assert_eq!(
        service.status_queries().await,
        vec![(sent[0].collection.clone(), sent[0].request_id)]
    );

    // And the next publication compares against the generation the settlement recorded, so a
    // device that lost an answer is not left publishing against a comparison it must lose.
    let next = object(
        object_id,
        1,
        SyncBody::Settings(settings(&[("theme", "light")], &[])),
        NOW + 2,
    );
    client.store().put_object(&next).expect("stored");
    assert_eq!(
        client
            .publish(object_id, TimestampMs::new(NOW + 2))
            .await
            .expect("published"),
        Published::Accepted { position: at(2) }
    );
}

#[tokio::test]
async fn a_lost_answer_to_a_write_the_service_refused_is_settled_as_a_copy_beside_this_device() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(Service::default());
    let (one, object_id) = device_client(directory.path(), "one", &service);
    let (two, _) = device_client(directory.path(), "two", &service);

    // The other device writes first, so this device's comparison is the one that loses.
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
    service.lose_the_next_answer().await;
    two.publish(object_id, TimestampMs::new(NOW))
        .await
        .expect_err("the refusal never came back");
    assert_eq!(two.outstanding().expect("a count"), 1);
    assert!(two.store().conflicts(object_id).expect("copies").is_empty());

    let reconciled = two
        .reconcile_unsettled(TimestampMs::new(NOW + 1))
        .await
        .expect("reconciled");
    assert_eq!(reconciled.settled, 1);
    assert_eq!(reconciled.copies_not_taken, 0);
    assert_eq!(reconciled.unsettled, 0);
    assert_eq!(two.outstanding().expect("a count"), 0);

    // Section 20 keeps what the service held, beside this device's own content, which is where it
    // was. A refusal settled late is still a refusal that nothing of this device's replaced.
    let copies = two.store().conflicts(object_id).expect("copies");
    assert_eq!(copies.len(), 1);
    assert_eq!(copies.items[0].other.revision, theirs.revision);
    assert_eq!(copies.items[0].expected, Nullable::null());
    assert_eq!(
        two.store()
            .object(object_id)
            .expect("held")
            .expect("this device's own")
            .revision,
        mine.revision
    );
    // A refusal establishes that the comparison did not replace the object, and nothing more. The
    // service kept the rejected write as a copy of its own, so the account of what left names it.
    let exported = two.exported().expect("exported");
    assert_eq!(exported.len(), 1);
    assert!(
        exported
            .iter()
            .all(|entry| !entry.kind.contains("sent without an answer")),
        "the service accounted for this request, so nothing is left unanswered"
    );
    assert!(exported[0].kind.contains("kept as a copy by the service"));
    assert_eq!(exported[0].left_at_ms, TimestampMs::new(NOW));
}

#[tokio::test]
async fn a_request_the_service_has_no_receipt_for_is_fenced_once_privacy_mode_has_moved_past_it() {
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

    // The request never reaches the service, so no receipt is ever written for it.
    service.drop_the_next_request().await;
    client
        .publish(object_id, TimestampMs::new(NOW))
        .await
        .expect_err("it never arrived");
    assert_eq!(client.outstanding().expect("a count"), 1);
    assert!(service.collections().await.is_empty());

    // The whole cleanup, in the order section 24 states it. Each step reconciles, so the count it
    // reports is what the service could not account for rather than every answer that went astray.
    client.fence(3).expect("fenced");
    let cancelled = client
        .cancel_undispatched(3, TimestampMs::new(NOW + 1))
        .await
        .expect("cancelled");
    assert_eq!(cancelled.undispatched, 0);
    assert_eq!(
        cancelled.reconciled.fenced, 1,
        "the service is asked to end the request, and answers that it never ran it"
    );
    assert_eq!(
        cancelled.in_flight, 0,
        "a request the service will never execute is not one the barrier waits for"
    );
    assert_eq!(
        service.fence_requests().await.len(),
        1,
        "the fence names the identity this device sent"
    );
    client
        .remove_retained(3, TimestampMs::new(NOW + 1))
        .await
        .expect("removed");
    assert_eq!(client.outstanding().expect("a count"), 0);
    assert!(client.store().requests().expect("requests").is_empty());

    // Nothing resurfaces: no checkpoint, no copy, and the object this device holds is its own.
    assert!(
        client
            .store()
            .checkpoint(object_id)
            .expect("a note")
            .is_none()
    );
    assert!(
        client
            .store()
            .conflicts(object_id)
            .expect("copies")
            .is_empty()
    );
    assert_eq!(
        client
            .store()
            .object(object_id)
            .expect("held")
            .expect("this device's own")
            .revision,
        mine.revision
    );

    // Nothing is shown as having left, because nothing of it is anywhere: the service answered
    // that it executed nothing under that identity and will refuse anything that arrives under it.
    assert_eq!(client.exported().expect("exported"), Vec::new());

    // A second pass finds nothing left to do, and nothing is asked again about work that is gone.
    let again = client
        .reconcile_unsettled(TimestampMs::new(NOW + 2))
        .await
        .expect("reconciled");
    assert_eq!(again, Reconciled::default());
    assert_eq!(
        service.status_queries().await.len(),
        1,
        "the request was asked about once, and nothing asks again about work that is gone"
    );
}

#[tokio::test]
async fn a_request_the_service_has_no_receipt_for_stays_counted_while_its_generation_is_in_force() {
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

    service.drop_the_next_request().await;
    client
        .publish(object_id, TimestampMs::new(NOW))
        .await
        .expect_err("it never arrived");

    // No fence has been recorded, so an answer to this work could still be published and the work
    // stays where it is: a receipt may yet be found, and section 23 makes an unknown outcome one
    // nothing retries by itself.
    let reconciled = client
        .reconcile_unsettled(TimestampMs::new(NOW + 1))
        .await
        .expect("reconciled");
    assert_eq!(
        reconciled,
        Reconciled {
            settled: 0,
            fenced: 0,
            accounts_kept: 0,
            unresolved: 1,
            copies_not_taken: 0,
            unsettled: 1,
        }
    );
    assert_eq!(client.outstanding().expect("a count"), 1);
    assert_eq!(service.exchanges().await.len(), 1, "nothing was sent again");
    assert!(
        client
            .exported()
            .expect("exported")
            .iter()
            .any(|entry| entry.kind.contains("sent without an answer"))
    );

    // A service this device cannot ask at all leaves it counted too, rather than failing the pass:
    // a cleanup that could not report what is outstanding would be worse than one that reports it.
    service.stop_answering_about_requests().await;
    let unreachable = client
        .reconcile_unsettled(TimestampMs::new(NOW + 2))
        .await
        .expect("reconciled");
    assert_eq!(unreachable.unresolved, 1);
    assert_eq!(unreachable.unsettled, 1);
    assert_eq!(client.outstanding().expect("a count"), 1);
}

#[tokio::test]
async fn a_retry_presents_the_identity_the_first_attempt_did_and_is_answered_from_the_receipt() {
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

    service.lose_the_next_answer().await;
    client
        .publish(object_id, TimestampMs::new(NOW))
        .await
        .expect_err("the answer never came back");

    // What one exchange carries: the collection, the request's own identity, the comparison and
    // the sealed object. The identity is the staged work's, so the record on disk holds it and a
    // restart presents the same one.
    let sent = service.exchanges().await;
    assert_eq!(sent.len(), 1);
    let first = sent[0].clone();
    assert_eq!(
        first.collection,
        sync_collection(SyncObjectKind::Settings, object_id)
    );
    assert_eq!(first.expected, None);
    let staged = client.store().requests().expect("requests");
    assert_eq!(staged.items[0].work_id, first.request_id);
    assert_eq!(
        staged.items[0]
            .ciphertext()
            .expect("it is still to be answered"),
        first.ciphertext
    );
    assert_ne!(
        first.request_id,
        object_id.get(),
        "a request is not the object it is about"
    );

    // Presenting it again, byte for byte, is answered from the receipt: nothing is applied a
    // second time and the object stays where the first attempt left it.
    assert_eq!(
        service
            .compare_exchange(
                &first.collection,
                first.request_id,
                first.expected.as_ref().copied(),
                &first.ciphertext,
            )
            .await
            .expect("answered from the receipt"),
        SyncExchanged::Applied { position: at(1) }
    );
    assert_eq!(
        service
            .stored(&first.collection)
            .await
            .expect("it is stored")
            .0,
        at(1)
    );

    // The same identity carrying different content is a second request wearing the first one's
    // name, which is refused rather than answered.
    assert_eq!(
        service
            .compare_exchange(
                &first.collection,
                first.request_id,
                first.expected.as_ref().copied(),
                b"content the first attempt never carried",
            )
            .await
            .expect_err("one identity, two requests")
            .code(),
        ErrorCode::IdConflict
    );

    // And the settlement asks about that identity rather than about the object.
    client
        .reconcile_unsettled(TimestampMs::new(NOW + 1))
        .await
        .expect("reconciled");
    assert_eq!(
        service.status_queries().await,
        vec![(first.collection, first.request_id)]
    );
}

#[tokio::test]
async fn a_request_the_service_will_never_run_leaves_the_store_with_nothing_to_account_for() {
    let directory = tempfile::tempdir().expect("a directory");
    let store = SyncStore::open(directory.path().join("one")).expect("a store");
    let object_id = fresh_object_id().expect("an identity");
    let mine = object(
        object_id,
        1,
        SyncBody::Settings(settings(&[("theme", "dark")], &[])),
        NOW,
    );
    store.put_object(&mine).expect("stored");
    let staged = store
        .admit(object_id, |object| {
            Ok(kr_cbor::to_canonical_vec(object).expect("canonical bytes"))
        })
        .expect("admitted");
    drop(
        store
            .begin_dispatch(staged.work_id, object_id, TimestampMs::new(NOW))
            .expect("dispatched"),
    );

    // Under the generation that admitted it, the work is still wanted, so nothing fences it: the
    // store says so, and a reconciliation reads that before it asks the service to end anything.
    assert!(
        !store
            .beyond_its_generation(&staged)
            .expect("the generation in force")
    );
    assert_eq!(store.unsettled().expect("a count"), 1);

    // Work that was never sent is never one of these: nothing left the device under it, so there
    // is no departure to account for and no dispatch of it to decide anything under.
    let never_sent = store
        .admit(object_id, |object| {
            Ok(kr_cbor::to_canonical_vec(object).expect("canonical bytes"))
        })
        .expect("admitted");
    assert!(matches!(
        store.claim_dispatched(never_sent.work_id).expect("a claim"),
        Claimed::Gone
    ));

    // Once privacy mode has moved past that generation, the request can be ended at the service,
    // and a request the service executed nothing under leaves nothing behind: no ciphertext, and
    // no account, because there is nothing of it anywhere to account for.
    store
        .record_privacy(PrivacyRecord {
            generation: U64::new(4),
            fenced: true,
        })
        .expect("fenced");
    assert!(
        store
            .beyond_its_generation(&staged)
            .expect("the generation in force")
    );
    assert!(
        store
            .close_unexecuted(&claim(&store, staged.work_id), staged.work_id)
            .expect("closed")
    );
    assert_eq!(store.unsettled().expect("a count"), 0);
    let left = store.what_left().expect("what left");
    assert!(left.publications.is_empty());
    assert_eq!(left.requests.len(), 1, "only the work that never went");
    assert!(left.requests.items[0].admitted());

    // Closing it twice is closing nothing, whoever asks.
    assert!(
        !store
            .close_unexecuted(&claim_after_discard(&store, staged.work_id), staged.work_id)
            .expect("nothing to close")
    );

    // An answer that arrives afterwards changes nothing and publishes nothing. It is refused by
    // the generation rule rather than reported as settled, so a caller cannot report a late
    // old-generation result as an accepted publication.
    assert_eq!(
        store
            .settle(
                &claim_after_discard(&store, staged.work_id),
                &staged,
                Outcome::Accepted { position: at(7) },
            )
            .expect("settled"),
        Settlement::Discarded {
            produced_under: 0,
            current: 4
        }
    );
    assert!(
        store.checkpoint(object_id).expect("a note").is_none(),
        "no checkpoint moves for a result privacy mode refused"
    );
    assert!(store.publications().expect("records").is_empty());
}

/// One device over a gated service, so a test can hold a publication at the wire.
fn gated_client(
    directory: &std::path::Path,
    name: &str,
    service: &Arc<GatedService>,
) -> Arc<SyncClient> {
    Arc::new(SyncClient::new(
        Arc::clone(service) as Arc<dyn SyncBackupService>,
        Arc::new(DeviceSealer::new(0x5a)) as Arc<dyn DraftSealer>,
        SyncStore::open(directory.join(name)).expect("a store"),
    ))
}

#[tokio::test]
async fn one_window_never_decides_what_became_of_another_windows_live_dispatch() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(GatedService::new());
    // Two clients over one store, which is two windows of the same application.
    let one = gated_client(directory.path(), "shared", &service);
    let two = gated_client(directory.path(), "shared", &service);
    let object_id = fresh_object_id().expect("an identity");
    let mine = object(
        object_id,
        1,
        SyncBody::Settings(settings(&[("theme", "dark")], &[])),
        NOW,
    );
    one.store().put_object(&mine).expect("stored");

    let publishing = tokio::spawn({
        let one = Arc::clone(&one);
        async move { one.publish(object_id, TimestampMs::new(NOW)).await }
    });
    service.wait_for_a_publication().await;

    // The other window cannot claim the request, because the first window has a call out for it.
    // A service writes its receipt when it commits the write, so asking about a request still on
    // the wire would be answered "no receipt" exactly as a request that never arrived is.
    let work_id = two.store().requests().expect("requests").items[0].work_id;
    assert!(matches!(
        two.store().claim_dispatched(work_id).expect("a claim"),
        Claimed::InHand
    ));

    // So a whole privacy cleanup driven from the other window leaves it outstanding rather than
    // discarding live work and reporting complete.
    two.fence(5).expect("fenced");
    let cancelled = two
        .cancel_undispatched(5, TimestampMs::new(NOW + 1))
        .await
        .expect("cancelled");
    assert_eq!(cancelled.in_flight, 1, "it is counted rather than hidden");
    assert_eq!(
        cancelled.reconciled.unresolved, 1,
        "the cleanup reports what its reconciliation could establish, not only a total"
    );
    let reconciled = two
        .reconcile_unsettled(TimestampMs::new(NOW + 1))
        .await
        .expect("reconciled");
    assert_eq!(
        reconciled,
        Reconciled {
            settled: 0,
            fenced: 0,
            accounts_kept: 0,
            unresolved: 1,
            copies_not_taken: 0,
            unsettled: 1,
        }
    );
    assert_eq!(two.outstanding().expect("a count"), 1);
    assert!(
        service.inner.status_queries().await.is_empty(),
        "nothing is asked about a request somebody is still waiting on"
    );

    // The first window's answer comes back. It is refused by the generation rule, the upload is
    // recorded as what left, and the request is no longer outstanding in either window.
    service.let_it_go();
    assert_eq!(
        publishing
            .await
            .expect("the task finished")
            .expect("answered"),
        Published::Discarded {
            produced_under: 0,
            current: 5
        }
    );
    assert_eq!(two.outstanding().expect("a count"), 0);
    assert_eq!(one.outstanding().expect("a count"), 0);
    assert!(
        two.store().checkpoint(object_id).expect("a note").is_none(),
        "no checkpoint moves for a result privacy mode refused"
    );
    let exported = two.exported().expect("exported");
    assert_eq!(exported.len(), 1);
    assert!(exported[0].reference.contains("write 1"));
}

#[tokio::test]
async fn an_answer_to_a_request_something_else_settled_is_still_checked_against_the_generation() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(GatedService::new());
    let one = gated_client(directory.path(), "shared", &service);
    let two = gated_client(directory.path(), "shared", &service);
    let object_id = fresh_object_id().expect("an identity");
    let mine = object(
        object_id,
        1,
        SyncBody::Settings(settings(&[("theme", "dark")], &[])),
        NOW,
    );
    one.store().put_object(&mine).expect("stored");

    // The service commits the write, its reply is held on the way back, and the window that sent
    // it stops waiting. The request is claimable again, and the write happened all the same.
    service.hold_the_answer_instead().await;
    let publishing = tokio::spawn({
        let one = Arc::clone(&one);
        async move { one.publish(object_id, TimestampMs::new(NOW)).await }
    });
    service.wait_for_a_publication().await;
    let staged = two.store().requests().expect("requests").items[0].clone();
    publishing.abort();
    assert!(publishing.await.expect_err("abandoned").is_cancelled());

    // The other window claims what nobody is holding and settles it from the receipt.
    let reconciled = two
        .reconcile_unsettled(TimestampMs::new(NOW + 1))
        .await
        .expect("reconciled");
    assert_eq!(reconciled.settled, 1);
    assert_eq!(two.outstanding().expect("a count"), 0);

    // Privacy mode then moves past the generation that admitted the work, and the answer to that
    // request arrives late, to a store holding no record of it at all. It is refused by the
    // generation rule: saying "already settled" here would report a publication under a generation
    // privacy mode had closed.
    two.fence(3).expect("fenced");
    assert_eq!(
        two.store()
            .settle(
                &claim_after_discard(two.store(), staged.work_id),
                &staged,
                Outcome::Accepted { position: at(1) },
            )
            .expect("settled"),
        Settlement::Discarded {
            produced_under: 0,
            current: 3
        }
    );
    assert_eq!(
        two.store().publications().expect("records").len(),
        1,
        "the settlement recorded the upload once"
    );
}

#[tokio::test]
async fn a_request_the_service_ran_after_the_caller_walked_away_is_settled_from_its_receipt() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(GatedService::new());
    let client = gated_client(directory.path(), "one", &service);
    let object_id = fresh_object_id().expect("an identity");
    let mine = object(
        object_id,
        1,
        SyncBody::Settings(settings(&[("theme", "dark")], &[])),
        NOW,
    );
    client.store().put_object(&mine).expect("stored");

    // The service commits the write; the caller abandons the call before the reply reaches it.
    // Dropping a future proves that this device stopped waiting, never that the request stopped.
    service.hold_the_answer_instead().await;
    let publishing = tokio::spawn({
        let client = Arc::clone(&client);
        async move { client.publish(object_id, TimestampMs::new(NOW)).await }
    });
    service.wait_for_a_publication().await;
    publishing.abort();
    assert!(publishing.await.expect_err("abandoned").is_cancelled());

    assert_eq!(
        client.outstanding().expect("a count"),
        1,
        "the record says the content left, and nothing has established what became of it"
    );
    assert!(
        client
            .store()
            .checkpoint(object_id)
            .expect("a note")
            .is_none()
    );
    // The call is over, so the request is claimable again: a released dispatch is a request this
    // device may ask about, which is exactly what it does next.
    let work_id = client.store().requests().expect("requests").items[0].work_id;
    assert!(matches!(
        client.store().claim_dispatched(work_id).expect("a claim"),
        Claimed::Taken(_, _)
    ));

    let reconciled = client
        .reconcile_unsettled(TimestampMs::new(NOW + 1))
        .await
        .expect("reconciled");
    assert_eq!(reconciled.settled, 1);
    assert_eq!(reconciled.unsettled, 0);
    assert_eq!(client.outstanding().expect("a count"), 0);
    assert_eq!(
        client
            .store()
            .checkpoint(object_id)
            .expect("a note")
            .expect("the write left one")
            .position,
        at(1),
        "the write the service ran is what the note now names"
    );
}

#[tokio::test]
async fn a_device_that_stopped_part_way_through_a_transition_counts_the_request_once() {
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

    // Stopped after the staged record and before the dispatch: nothing left, so a cleanup takes it
    // back and nothing is counted.
    let never_sent = client
        .store()
        .admit(object_id, |object| {
            Ok(kr_cbor::to_canonical_vec(object).expect("canonical bytes"))
        })
        .expect("admitted");
    assert_eq!(client.outstanding().expect("a count"), 0);
    assert_eq!(client.store().take_back_undispatched(0).expect("taken"), 1);
    assert!(client.store().requests().expect("requests").is_empty());
    assert!(
        matches!(
            client
                .store()
                .claim_dispatched(never_sent.work_id)
                .expect("a claim"),
            Claimed::Gone
        ),
        "work that never left has no dispatch to decide anything under"
    );

    // Stopped after the dispatch record and before the call: the content may have left, so it is
    // counted, and the next reconciliation asks about it.
    let staged = client
        .store()
        .admit(object_id, |object| {
            Ok(kr_cbor::to_canonical_vec(object).expect("canonical bytes"))
        })
        .expect("admitted");
    drop(
        client
            .store()
            .begin_dispatch(staged.work_id, object_id, TimestampMs::new(NOW))
            .expect("dispatched"),
    );
    assert_eq!(client.outstanding().expect("a count"), 1);

    // A dispatch names one request in one store. Another store's claim on the same identity
    // decides nothing here, and work that has left does not leave a second time under one account.
    let elsewhere = SyncStore::open(directory.path().join("two")).expect("a store");
    assert_eq!(
        client
            .store()
            .close_unexecuted(
                &elsewhere
                    .claim_request(staged.work_id)
                    .expect("a claim")
                    .expect("nobody is waiting on it"),
                staged.work_id,
            )
            .expect_err("that claim is another store's")
            .code(),
        ErrorCode::InvalidArgument
    );
    assert!(
        client
            .store()
            .begin_dispatch(staged.work_id, object_id, TimestampMs::new(NOW + 1))
            .is_err(),
        "one piece of work leaves this device once"
    );

    // Stopped after the request was ended at the service and before the record went. The record
    // is what counts, so the work is outstanding again and the next pass asks about it.
    let request_path = directory
        .path()
        .join("one")
        .join(format!("{}.request", staged.work_id));
    let dispatched = std::fs::read(&request_path).expect("the request's record");
    client.fence(1).expect("fenced");
    client.store().advance_privacy(1).expect("moved on");
    assert!(
        client
            .store()
            .close_unexecuted(&claim(client.store(), staged.work_id), staged.work_id)
            .expect("closed")
    );
    std::fs::write(&request_path, &dispatched)
        .expect("a device that stopped between the two writes");

    // One request is one entry, in the count and in the account of what left.
    assert_eq!(client.outstanding().expect("a count"), 1);
    let left = client.store().what_left().expect("what left");
    assert_eq!(left.requests.len(), 1);
    assert_eq!(client.exported().expect("exported").len(), 1);

    // And the first settlement of that request leaves one account of it and no second.
    assert_eq!(
        client
            .store()
            .settle(
                &claim(client.store(), staged.work_id),
                &staged,
                Outcome::Accepted { position: at(4) },
            )
            .expect("settled"),
        Settlement::Discarded {
            produced_under: 0,
            current: 1
        }
    );
    assert_eq!(client.outstanding().expect("a count"), 0);
    let left = client.store().what_left().expect("what left");
    assert!(left.requests.is_empty());
    assert_eq!(left.publications.len(), 1);
    // The account says when the content left this device, not when something got round to asking.
    assert_eq!(
        left.publications.items[0].published_at_ms,
        TimestampMs::new(NOW),
    );
}

/// Puts one request's record on disk exactly as a device that stopped part way would have left it.
///
/// Every write the store makes is a whole file renamed into place, so what a stop leaves behind is
/// one of these and never half of one.
fn leave_record_as_it_was(path: &std::path::Path, record: &RequestRecord) {
    std::fs::write(
        path,
        kr_cbor::to_canonical_vec(record).expect("canonical bytes"),
    )
    .expect("a record");
}

#[tokio::test]
async fn a_stop_anywhere_in_a_settlement_leaves_one_account_of_the_request() {
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

    // A write the service applied, whose answer was lost, and the record exactly as the store
    // wrote it before the call left.
    service.lose_the_next_answer().await;
    client
        .publish(object_id, TimestampMs::new(NOW))
        .await
        .expect_err("the answer never came back");
    let dispatched = client.store().requests().expect("requests").items[0].clone();
    let path = directory
        .path()
        .join("one")
        .join(format!("{}.request", dispatched.work_id));

    // Stopped after the note the answer moved and before the answer reached the record. The record
    // is what counts, so the request is still waiting: one entry, and the next pass asks again.
    client
        .store()
        .record_checkpoint(
            object_id,
            SyncCheckpoint {
                position: at(1),
                published_revision: Nullable::some(mine.revision),
            },
        )
        .expect("a note");
    assert_eq!(client.outstanding().expect("a count"), 1);
    let exported = client.exported().expect("exported");
    assert_eq!(exported.len(), 1);
    assert!(exported[0].kind.contains("sent without an answer"));

    // Stopped after the answer reached the record and before the account it owes was written. The
    // request is over, so nothing counts it, and the next read writes the account: one entry.
    leave_record_as_it_was(
        &path,
        &RequestRecord {
            state: RequestState::Applied { position: at(1) },
            ..dispatched.clone()
        },
    );
    assert_eq!(client.outstanding().expect("a count"), 0);
    let exported = client.exported().expect("exported");
    assert_eq!(exported.len(), 1, "one request is one entry: {exported:?}");
    assert!(exported[0].reference.contains("write 1"));
    assert_eq!(
        exported[0].left_at_ms,
        TimestampMs::new(NOW),
        "the account says when the content left, not when something finished the step"
    );
    assert_eq!(client.store().publications().expect("records").len(), 1);

    // Stopped after the account was written and before the record went. This is the arrangement
    // that used to be two accounts of one request, and it is one.
    leave_record_as_it_was(
        &path,
        &RequestRecord {
            state: RequestState::Applied { position: at(1) },
            ..dispatched.clone()
        },
    );
    let exported = client.exported().expect("exported");
    assert_eq!(
        exported.len(),
        1,
        "one request is one entry, whatever the stop interrupted: {exported:?}"
    );
    assert!(
        !path.exists(),
        "and the record goes once its account stands"
    );

    // A refusal the service kept nothing of ends the request and owes no account, so the next read
    // removes the record and names nothing of it.
    leave_record_as_it_was(
        &path,
        &RequestRecord {
            state: RequestState::Refused {
                retained: Nullable::null(),
            },
            ..dispatched.clone()
        },
    );
    assert_eq!(client.outstanding().expect("a count"), 0);
    assert_eq!(
        client.exported().expect("exported").len(),
        1,
        "the publication, and nothing of a refusal the service kept nothing of"
    );
    assert!(!path.exists());

    // A refusal the service kept a copy of **is** its own account, so its record stays and names
    // the copy the service holds.
    let conflict_id = SyncConflictId::new(fresh_request_id());
    leave_record_as_it_was(
        &path,
        &RequestRecord {
            state: RequestState::Refused {
                retained: Nullable::some(conflict_id),
            },
            ..dispatched
        },
    );
    assert_eq!(client.outstanding().expect("a count"), 0);
    let exported = client.exported().expect("exported");
    assert_eq!(exported.len(), 2);
    assert!(
        exported
            .iter()
            .any(|entry| entry.reference.contains(&conflict_id.to_string()))
    );
    assert!(path.exists(), "the account of what left is not swept away");
}

#[tokio::test]
async fn a_service_that_cannot_end_a_request_leaves_the_barrier_where_it_was() {
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

    service.drop_the_next_request().await;
    client
        .publish(object_id, TimestampMs::new(NOW))
        .await
        .expect_err("it never arrived");
    assert_eq!(client.outstanding().expect("a count"), 1);

    // Privacy mode moves past the generation that admitted the work, so the request should be
    // ended at the service. The service cannot be asked, and a request nothing has established an
    // end for stays counted: a cleanup reports what is outstanding rather than assuming.
    client.fence(3).expect("fenced");
    service.stop_fencing_requests().await;
    let cancelled = client
        .cancel_undispatched(3, TimestampMs::new(NOW + 1))
        .await
        .expect("cancelled");
    assert_eq!(cancelled.reconciled.fenced, 0);
    assert_eq!(cancelled.reconciled.unresolved, 1);
    assert_eq!(cancelled.in_flight, 1);
    assert_eq!(client.outstanding().expect("a count"), 1);
    let removed = client
        .remove_retained(3, TimestampMs::new(NOW + 1))
        .await
        .expect("removed");
    assert_eq!(
        removed.records, 0,
        "a dispatched record is not local content a cleanup may remove"
    );
    assert_eq!(
        client.outstanding().expect("a count"),
        1,
        "nothing reaches nought while a request has no end"
    );

    // When the service can be asked again, the same identity is what it is asked about, and the
    // barrier lifts.
    service.answer_fences_again().await;
    let reconciled = client
        .reconcile_unsettled(TimestampMs::new(NOW + 2))
        .await
        .expect("reconciled");
    assert_eq!(reconciled.fenced, 1);
    assert_eq!(reconciled.unsettled, 0);
    assert_eq!(client.outstanding().expect("a count"), 0);
    let sent = service.exchanges().await;
    let asked = service.fence_requests().await;
    assert!(
        asked
            .iter()
            .all(|(collection, request_id)| *collection == sent[0].collection
                && *request_id == sent[0].request_id),
        "every attempt asks about the identity this device sent: {asked:?}"
    );
}

#[tokio::test]
async fn a_request_that_lands_between_the_two_calls_is_settled_by_the_fence() {
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

    // The write is applied and the answer is lost on the way back.
    service.lose_the_next_answer().await;
    client
        .publish(object_id, TimestampMs::new(NOW))
        .await
        .expect_err("the answer never came back");

    // The status query answers before the receipt is there, which is what a request still on its
    // way looks like. The fence that follows finds the receipt, so the request is settled by what
    // the service recorded rather than ended as one that never ran.
    client.fence(2).expect("fenced");
    client.store().advance_privacy(2).expect("moved on");
    service.let_the_next_status_miss_the_receipt().await;
    let reconciled = client
        .reconcile_unsettled(TimestampMs::new(NOW + 1))
        .await
        .expect("reconciled");
    assert_eq!(reconciled.settled, 1);
    assert_eq!(reconciled.fenced, 0);
    assert_eq!(client.outstanding().expect("a count"), 0);

    // The content left and the service holds it, so the account of what left says so, and no note
    // moves, because the generation that admitted the work has been fenced.
    let published = client.store().publications().expect("records");
    assert_eq!(published.len(), 1);
    assert_eq!(published.items[0].position, at(1));
    assert!(
        client
            .store()
            .checkpoint(object_id)
            .expect("a note")
            .is_none()
    );
    let exported = client.exported().expect("exported");
    assert_eq!(exported.len(), 1);
    assert!(exported[0].reference.contains("write 1"));
    assert_eq!(exported[0].left_at_ms, TimestampMs::new(NOW));
}

/// A device whose write was applied, whose answer was lost, and whose receipt the service no
/// longer keeps.
///
/// From here that is exactly what a request which never arrived looks like, which is the whole
/// difficulty: neither says the write did not land.
async fn a_write_whose_receipt_is_gone(
    directory: &std::path::Path,
    service: &Arc<Service>,
) -> (SyncClient, SyncObjectId) {
    let (client, object_id) = device_client(directory, "one", service);
    let mine = object(
        object_id,
        1,
        SyncBody::Settings(settings(&[("theme", "dark")], &[])),
        NOW,
    );
    client.store().put_object(&mine).expect("stored");
    service.lose_the_next_answer().await;
    client
        .publish(object_id, TimestampMs::new(NOW))
        .await
        .expect_err("the answer never came back");
    let request_id = service.exchanges().await[0].request_id;
    assert!(
        service
            .stored(&sync_collection(SyncObjectKind::Settings, object_id))
            .await
            .is_some(),
        "the write landed, whatever this device can establish about it"
    );
    service.forget_the_receipt(request_id).await;
    (client, object_id)
}

#[test]
fn what_a_fence_proves_about_the_past_ends_with_the_receipt_retention() {
    // Inside the retention, less the margin the service's sweep needs, a fence that found no
    // receipt found one that would still have been there to find.
    assert!(fence_proves_it_never_ran(NOW, NOW));
    assert!(fence_proves_it_never_ran(
        NOW,
        NOW + SYNC_RECEIPT_RETENTION_MS - SYNC_RECEIPT_SWEEP_MARGIN_MS - 1
    ));

    // At that boundary and past it, a receipt that was swept and a request that never arrived
    // answer the same way, so the fence says nothing about the past.
    assert!(!fence_proves_it_never_ran(
        NOW,
        NOW + SYNC_RECEIPT_RETENTION_MS - SYNC_RECEIPT_SWEEP_MARGIN_MS
    ));
    assert!(!fence_proves_it_never_ran(
        NOW,
        NOW + SYNC_RECEIPT_RETENTION_MS
    ));

    // A clock that reads earlier than the dispatch has measured nothing at all.
    assert!(!fence_proves_it_never_ran(NOW, NOW - 1));

    // The retention this client measures against is the service contract's own.
    assert_eq!(SYNC_RECEIPT_RETENTION_MS, 30 * 24 * 60 * 60 * 1_000);
    assert_eq!(SYNC_RECEIPT_SWEEP_MARGIN_MS, 24 * 60 * 60 * 1_000);
}

#[tokio::test]
async fn a_fence_inside_the_receipt_retention_says_the_request_never_ran() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(Service::default());
    let (client, _) = a_write_whose_receipt_is_gone(directory.path(), &service).await;

    // A day inside the boundary. A receipt of a run would still have been there, and the fence
    // found none, so this request never ran and nothing of it is anywhere.
    let inside = NOW + SYNC_RECEIPT_RETENTION_MS - SYNC_RECEIPT_SWEEP_MARGIN_MS - 1;
    client.fence(2).expect("fenced");
    let cancelled = client
        .cancel_undispatched(2, TimestampMs::new(inside))
        .await
        .expect("cancelled");
    assert_eq!(cancelled.reconciled.fenced, 1);
    assert_eq!(cancelled.reconciled.accounts_kept, 0);
    assert_eq!(client.outstanding().expect("a count"), 0);
    assert!(client.store().requests().expect("requests").is_empty());
    assert_eq!(
        client.exported().expect("exported"),
        Vec::new(),
        "a request that provably never ran leaves nothing of itself anywhere"
    );
}

#[tokio::test]
async fn a_fence_after_the_receipt_retention_keeps_the_account_of_what_left() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(Service::default());
    let (client, object_id) = a_write_whose_receipt_is_gone(directory.path(), &service).await;

    // While the generation that admitted it is in force, nothing ends it: the work stays counted
    // and the next pass asks again.
    let reconciled = client
        .reconcile_unsettled(TimestampMs::new(NOW + 1))
        .await
        .expect("reconciled");
    assert_eq!(reconciled.unresolved, 1);
    assert_eq!(reconciled.fenced, 0);
    assert_eq!(client.outstanding().expect("a count"), 1);

    // Privacy mode moves past that generation, and the cleanup runs after the receipt retention.
    // The fence still ends the request, because nothing executes under a fenced identity, so the
    // barrier releases. What it cannot establish is whether the write had already run.
    let after = NOW + SYNC_RECEIPT_RETENTION_MS;
    client.fence(2).expect("fenced");
    let cancelled = client
        .cancel_undispatched(2, TimestampMs::new(after))
        .await
        .expect("cancelled");
    assert_eq!(cancelled.reconciled.fenced, 1);
    assert_eq!(
        cancelled.reconciled.accounts_kept, 1,
        "the fence ended it, and this device cannot say it never ran"
    );
    assert_eq!(
        client.outstanding().expect("a count"),
        0,
        "nothing more can happen to it, so the barrier is not waiting for it"
    );

    // The ciphertext left this device and the service may be holding it, so the account says so.
    let exported = client.exported().expect("exported");
    assert_eq!(exported.len(), 1);
    assert!(exported[0].kind.contains("never accounted for"));
    assert!(
        exported[0]
            .reference
            .contains(&sync_collection(SyncObjectKind::Settings, object_id))
    );
    assert_eq!(
        exported[0].left_at_ms,
        TimestampMs::new(NOW),
        "when the content left, not when something got round to ending the request"
    );
    assert!(!exported[0].deletable);
    assert!(
        client
            .kept()
            .expect("kept")
            .iter()
            .any(|entry| entry.what.contains("too late to say whether it ran"))
    );

    // It is an account and not content: a cleanup removes what this device holds and leaves it,
    // and the record carries no ciphertext to remove.
    let removed = client
        .remove_retained(2, TimestampMs::new(after))
        .await
        .expect("removed");
    assert_eq!(
        removed.records, 0,
        "the request was ended at the service, not removed as local content"
    );
    assert_eq!(client.exported().expect("exported").len(), 1);
    let held = client.store().requests().expect("requests");
    assert_eq!(held.len(), 1);
    assert!(held.items[0].ended());
    assert_eq!(
        held.items[0].ciphertext(),
        None,
        "an account carries no content"
    );
}

#[tokio::test]
async fn a_clock_that_reads_earlier_than_the_dispatch_concludes_nothing_about_the_past() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(Service::default());
    let (client, _) = a_write_whose_receipt_is_gone(directory.path(), &service).await;

    // The device's clock has gone back, so the interval since the dispatch is not one it measured.
    // The barrier still releases, and the account stays, which is the safe direction of the two.
    client.fence(2).expect("fenced");
    let cancelled = client
        .cancel_undispatched(2, TimestampMs::new(NOW - 1))
        .await
        .expect("cancelled");
    assert_eq!(cancelled.reconciled.fenced, 1);
    assert_eq!(cancelled.reconciled.accounts_kept, 1);
    assert_eq!(client.outstanding().expect("a count"), 0);
    assert_eq!(client.exported().expect("exported").len(), 1);
}

#[tokio::test]
async fn an_answer_naming_an_earlier_generation_never_moves_the_note_backwards() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(Service::default());
    let (one, object_id) = device_client(directory.path(), "one", &service);
    let (two, _) = device_client(directory.path(), "two", &service);
    let mine = object(
        object_id,
        1,
        SyncBody::Settings(settings(&[("theme", "dark")], &[])),
        NOW,
    );
    one.store().put_object(&mine).expect("stored");

    // This device's write is applied at generation 1 and its answer is lost.
    service.lose_the_next_answer().await;
    one.publish(object_id, TimestampMs::new(NOW))
        .await
        .expect_err("the answer never came back");

    // Another device writes over it, and this device fetches what is there now.
    let theirs = object(
        object_id,
        2,
        SyncBody::Settings(settings(&[("theme", "light")], &[])),
        NOW + 1,
    );
    two.store().put_object(&theirs).expect("stored");
    two.store()
        .record_checkpoint(
            object_id,
            SyncCheckpoint {
                position: at(1),
                published_revision: Nullable::null(),
            },
        )
        .expect("a note");
    assert_eq!(
        two.publish(object_id, TimestampMs::new(NOW + 1))
            .await
            .expect("published"),
        Published::Accepted { position: at(2) }
    );
    one.fetch(
        SyncObjectKind::Settings,
        object_id,
        TimestampMs::new(NOW + 2),
    )
    .await
    .expect("fetched");
    assert_eq!(
        one.store()
            .checkpoint(object_id)
            .expect("a note")
            .expect("the fetch left one")
            .position,
        at(2)
    );

    // The older receipt is settled last. It names write 1, which is where that write left the
    // object, and the note stays where the later answer put it.
    let reconciled = one
        .reconcile_unsettled(TimestampMs::new(NOW + 3))
        .await
        .expect("reconciled");
    assert_eq!(reconciled.settled, 1);
    assert_eq!(one.outstanding().expect("a count"), 0);
    assert_eq!(
        one.store()
            .checkpoint(object_id)
            .expect("a note")
            .expect("a note")
            .position,
        at(2),
        "an answer about an older state does not make it the current one"
    );
}

#[tokio::test]
async fn a_staged_payload_past_the_readers_collection_bound_is_read_back() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(Service::default());
    let (client, object_id) = device_client(directory.path(), "one", &service);
    // Well past the four thousand members a collection may hold, which is what a sealed object
    // written as a list of numbers would have been bounded by.
    let long = "s".repeat(8 * 1024);
    let mine = object(
        object_id,
        1,
        SyncBody::Settings(settings(&[("theme", long.as_str())], &[])),
        NOW,
    );
    client.store().put_object(&mine).expect("stored");

    service.lose_the_next_answer().await;
    client
        .publish(object_id, TimestampMs::new(NOW))
        .await
        .expect_err("the answer never came back");

    // The record is readable, which is what makes the work settleable at all.
    let staged = client.store().requests().expect("requests");
    assert!(
        staged.unreadable.is_empty(),
        "a staged record this device cannot open is work it can never settle"
    );
    assert_eq!(staged.len(), 1);
    assert!(
        staged.items[0]
            .ciphertext()
            .expect("it is still to be answered")
            .len()
            > 4_096
    );
    assert_eq!(client.outstanding().expect("a count"), 1);

    let reconciled = client
        .reconcile_unsettled(TimestampMs::new(NOW + 1))
        .await
        .expect("reconciled");
    assert_eq!(reconciled.settled, 1);
    assert_eq!(client.outstanding().expect("a count"), 0);
    assert_eq!(
        service
            .stored(&sync_collection(SyncObjectKind::Settings, object_id))
            .await
            .expect("it is stored")
            .1,
        service.exchanges().await[0].ciphertext,
        "what the service holds is the sealed object this device staged"
    );
}

#[tokio::test]
async fn a_refused_write_the_service_kept_a_copy_of_is_named_among_what_left() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(Service::default());
    let (one, object_id) = device_client(directory.path(), "one", &service);
    let (two, _) = device_client(directory.path(), "two", &service);

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

    // This device's comparison is the one that loses. The service keeps the rejected write as a
    // copy of its own, so the ciphertext is on the service whatever the comparison decided.
    let mine = object(
        object_id,
        2,
        SyncBody::Settings(settings(&[("theme", "light")], &[])),
        NOW + 1,
    );
    two.store().put_object(&mine).expect("stored");
    assert!(matches!(
        two.publish(object_id, TimestampMs::new(NOW + 1))
            .await
            .expect("answered"),
        Published::Conflicted { .. }
    ));

    let exported = two.exported().expect("exported");
    assert_eq!(exported.len(), 1);
    assert!(exported[0].kind.contains("kept as a copy by the service"));
    assert!(exported[0].reference.contains("holds as copy"));
    assert_eq!(exported[0].left_at_ms, TimestampMs::new(NOW + 1));
    assert!(!exported[0].deletable);
    assert!(
        two.kept()
            .expect("kept")
            .iter()
            .any(|entry| entry.what.contains("kept a copy of"))
    );

    // It is an account and not content: a cleanup removes what this device holds and leaves it.
    two.fence(1).expect("fenced");
    two.remove_retained(1, TimestampMs::new(NOW + 2))
        .await
        .expect("removed");
    assert_eq!(two.exported().expect("exported").len(), 1);
}

#[tokio::test]
async fn an_identity_another_request_has_worn_never_settles_this_payload() {
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

    // The service says the identity this request presented already answered a different one.
    service.give_the_next_identity_to_another_request().await;
    let error = client
        .publish(object_id, TimestampMs::new(NOW))
        .await
        .expect_err("that identity is taken");
    assert_eq!(error.code(), ErrorCode::IdConflict);

    // The service compared this content against the receipt it holds and declined to run it, so
    // this payload did not execute and never will under that identity. That ends the request: the
    // work goes, and nothing of it is on the service to account for.
    assert_eq!(client.outstanding().expect("a count"), 0);
    assert!(client.store().requests().expect("requests").is_empty());
    assert_eq!(client.exported().expect("exported"), Vec::new());

    // The receipt under that identity says applied. It is never asked for, because it accounts for
    // the other request: settling this payload from it would put the note at a revision this
    // content never produced.
    let reconciled = client
        .reconcile_unsettled(TimestampMs::new(NOW + 1))
        .await
        .expect("reconciled");
    assert_eq!(reconciled, Reconciled::default());
    assert!(
        service.status_queries().await.is_empty(),
        "an identity another request wore is not one to ask about"
    );
    assert!(
        service.fence_requests().await.is_empty(),
        "nor one to ask the service to end, because it is already over"
    );
    assert!(
        client
            .store()
            .checkpoint(object_id)
            .expect("a note")
            .is_none()
    );
}

#[tokio::test]
async fn a_late_refusal_names_the_copy_the_service_kept_and_when_the_content_left() {
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

    // The copy the caller holds is the one admission returned, which names no departure: the
    // instant is written when the work is dispatched, and the store is what remembers it.
    let staged = client
        .store()
        .admit(object_id, |object| {
            Ok(kr_cbor::to_canonical_vec(object).expect("canonical bytes"))
        })
        .expect("admitted");
    assert_eq!(staged.dispatched_at_ms, Nullable::null());
    drop(
        client
            .store()
            .begin_dispatch(staged.work_id, object_id, TimestampMs::new(NOW))
            .expect("dispatched"),
    );

    // Privacy mode moves past the generation that admitted the work, and the refusal arrives
    // afterwards: nothing may be published from it, and what it says about content that left is
    // recorded all the same.
    client.fence(2).expect("fenced");
    client.store().advance_privacy(2).expect("moved on");
    let conflict_id = SyncConflictId::new(fresh_request_id());
    assert_eq!(
        client
            .store()
            .settle(
                &claim(client.store(), staged.work_id),
                &staged,
                Outcome::Refused {
                    retained: Some(conflict_id)
                },
            )
            .expect("settled"),
        Settlement::Discarded {
            produced_under: 0,
            current: 2
        }
    );

    // What left is named once, with the instant the content left rather than the instant something
    // got round to asking about it.
    let exported = client.exported().expect("exported");
    assert_eq!(exported.len(), 1);
    assert!(exported[0].reference.contains(&conflict_id.to_string()));
    assert_eq!(exported[0].left_at_ms, TimestampMs::new(NOW));
}
