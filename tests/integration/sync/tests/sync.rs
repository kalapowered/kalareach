//! Settings sync, against a deployment.
//!
//! Section 20 says how a person's settings travel between their devices: sealed before they are
//! stored, written by compare and swap against a per-object revision, and a write that loses the
//! comparison kept for the person to choose from rather than decided by whichever clock was
//! further ahead. Every other suite holds `kr-client`'s sync client to a service this repository
//! wrote. These legs hold it to the deployed one: the client, its store and its sealing are the
//! product's own, and only the collection key is made for the run.
//!
//! # Two devices, one installation
//!
//! The service derives every collection a request reaches from the installation key that signed
//! it, so two installations never share one. What a leg calls two devices is therefore two client
//! stores under one run key: two records of what left, two notes, two sets of copies, and one
//! collection on the service. That proves the conflict and resolution rules, and it says nothing
//! about two installations sharing a collection.
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-REQ-20.13 | `kr_req_20_13_a_lost_comparison_keeps_both_copies_until_the_person_chooses`, `kr_req_20_13_a_stale_expected_revision_is_refused_and_kept_as_a_copy`, `kr_req_20_13_a_draft_is_published_as_a_draft_and_never_as_an_execution_request`, `kr_req_20_13_a_sealed_object_the_service_refuses_is_refused_here_first`, `kr_req_20_13_an_answer_lost_in_flight_is_settled_from_the_receipt_and_applied_once`, `kr_req_20_13_a_fenced_identity_never_ran_and_nothing_runs_under_it_afterwards`, `kr_req_20_13_a_fetch_of_an_object_never_published_answers_its_absence_under_no_history` |
//! | KR-REQ-20.13, KR-REQ-24.28 and KR-REQ-18.05, client side across a restore | The same legs read the recovery identity on every answer they take, an exchange, a refusal, a comparison, a status query with and without a receipt, a fence and a fetch that finds nothing, and hold a deployment that has never been put back to naming none |
//! | KR-REQ-18.05 | `kr_req_18_05_a_setting_is_stored_sealed_in_a_declared_bucket` |
//! | KR-REQ-24.28 | `kr_req_24_28_a_client_fenced_by_privacy_mode_publishes_nothing_and_keeps_its_pinned_labels` |
//!
//! # What the lost-answer leg takes as proof
//!
//! Only a write the service accepted whose answer was lost on the way back. A `503` with
//! `SERVICE_UNAVAILABLE` is the service declining to decide, which proves nothing, so the leg sends
//! that request again under the same identity with the same bytes, a bounded number of times, and
//! fails when no send is accepted. Two checks hold that step to this against a stand-in, with no
//! deployment: `the_lost_answer_leg_takes_no_503_for_an_accepted_write` and
//! `the_lost_answer_leg_sends_a_declined_write_again_until_it_is_accepted`.
//!
//! # What a leg leaves
//!
//! Each leg gives back what the service lets it give back, whether it passed or failed. Every
//! request identity it presented is fenced first, so a write whose answer the leg never saw either
//! has already run, and is removed below, or never will. Then every copy the service kept is
//! resolved and every object is removed under comparison, until a comparison finds the collection
//! empty. What stays is what the service keeps by its own rules and no client may remove: the
//! receipt of each identity for thirty days, a content-free record of each removed object's place
//! in the order, spent nonces, and the ledger's record of the installation the run key made.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::future::Future;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use kr_client::ClientError;
use kr_client::drafts::{
    DraftSealer, DraftStore, DraftSync, DraftTarget, Published as DraftPublished,
};
use kr_client::services::relay::{ServiceHttp, ServiceHttpAnswer, ServiceSigner};
use kr_client::services::signed::SignedService;
use kr_client::services::sync::{MAX_SYNC_REQUEST_BYTES, ManagedSyncService, SYNC_EXCHANGE_PATH};
use kr_client::services::{
    ServiceFuture, SyncBackupService, SyncExchanged, SyncFetched, SyncPosition, SyncRequestFence,
    SyncRequestStatus, SyncRevision,
};
use kr_client::sync::{
    CollectionSealer, MemoryCollectionKeys, Published, Resolutions, SettingValue, SyncBody,
    SyncClient, SyncError, SyncObject, SyncSettings, SyncStore, fresh_object_id, fresh_revision,
    sync_collection,
};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::ids::{DeviceId, SessionId, SyncObjectId};
use kr_protocol::mailbox::mailbox_size_bucket;
use kr_protocol::method::Method;
use kr_protocol::scalars::{TimestampMs, Uuid};
use kr_protocol::service::GatewayOrigin;
use kr_protocol::sync::{SealedSyncObject, SyncObjectKind};
use kr_sync_integration::{Deployment, RunKey, fresh_uuid, now_ms, proved};

/* -------------------------------------------------------------------------- */
/* Where each request goes                                                     */
/* -------------------------------------------------------------------------- */

/// Every collection and request identity a leg's requests reached.
///
/// Written by the transport, from the request itself, before the request leaves. A leg cannot
/// forget to say where it went, because it never says: whatever carries a request writes it down.
#[derive(Default)]
struct Reached {
    /// Every collection a request named.
    collections: Mutex<BTreeSet<String>>,
    /// Every identity an exchange presented, with the collection and the earliest and latest
    /// instant it was signed at.
    identities: Mutex<BTreeMap<String, (String, u64, u64)>>,
}

impl Reached {
    /// Writes down where one signed request is going.
    fn note(&self, request: &[u8]) {
        let Ok(request) = serde_json::from_slice::<serde_json::Value>(request) else {
            return;
        };
        let Some((member, asked)) = request["body"]
            .as_object()
            .and_then(|body| body.iter().next())
        else {
            return;
        };
        let Some(collection) = asked["collection_id"].as_str() else {
            return;
        };
        self.collections
            .lock()
            .expect("the collections")
            .insert(collection.to_owned());
        let signed_at = request["signature"]["payload"]["signed_at_ms"]
            .as_str()
            .and_then(|instant| instant.parse::<u64>().ok());
        if let (true, Some(identity), Some(signed_at)) = (
            member == "exchange",
            asked["request_id"].as_str(),
            signed_at,
        ) {
            self.identities
                .lock()
                .expect("the identities")
                .entry(identity.to_owned())
                .and_modify(|(_, first, last)| {
                    *first = (*first).min(signed_at);
                    *last = (*last).max(signed_at);
                })
                .or_insert((collection.to_owned(), signed_at, signed_at));
        }
    }
}

/// The deployment's transport, with a note of where each request goes and a way to lose an
/// answer.
struct Recording {
    inner: Arc<dyn ServiceHttp>,
    reached: Arc<Reached>,
    /// How many requests have left through it.
    sent: AtomicUsize,
    /// Whether the next answer is to be lost on its way back.
    lose_the_next_answer: AtomicBool,
    /// The answer that was lost, as the service gave it, so a leg can see what the service did with
    /// the request before it goes on.
    lost: Mutex<Option<ServiceHttpAnswer>>,
}

impl fmt::Debug for Recording {
    /// How many requests have left. Never one of them.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Recording")
            .field("sent", &self.sent.load(Ordering::SeqCst))
            .finish_non_exhaustive()
    }
}

impl ServiceHttp for Recording {
    fn post_json<'a>(
        &'a self,
        url: &'a str,
        body: &'a [u8],
        headers: &'a [(&'a str, &'a str)],
    ) -> ServiceFuture<'a, ServiceHttpAnswer> {
        Box::pin(async move {
            // Before the request leaves, so a request whose answer never arrives is written down
            // all the same.
            self.reached.note(body);
            self.sent.fetch_add(1, Ordering::SeqCst);
            let answer = self.inner.post_json(url, body, headers).await;
            if self.lose_the_next_answer.swap(false, Ordering::SeqCst) {
                // The service has answered, and the answer goes no further than here: what a
                // connection that dropped on the way back looks like to the device that sent it.
                // It is kept for the leg, which holds it to being the answer it means to lose: an
                // exchange that failed before it arrived would look the same to the device.
                *self.lost.lock().expect("the lost answer") = answer.ok();
                return Err(ClientError::Host(ProtocolError::new(
                    ErrorCode::OutcomeUnknown,
                    "the answer never came back",
                )));
            }
            answer
        })
    }
}

/* -------------------------------------------------------------------------- */
/* One leg's devices                                                           */
/* -------------------------------------------------------------------------- */

/// One run's installation, the service client it signs through, and the devices that use it.
struct Run {
    deployment: Deployment,
    /// The installation every device of the leg signs as.
    key: Arc<RunKey>,
    transport: Arc<Recording>,
    reached: Arc<Reached>,
    /// The service client every device of the leg shares, over the recording transport.
    service: Arc<ManagedSyncService>,
    /// The collection key the leg's objects are sealed under: drawn for the run, held in memory.
    sealer: Arc<CollectionSealer>,
    /// Where the leg's devices keep their stores, on this machine's own disk.
    directory: tempfile::TempDir,
}

impl Run {
    /// The run's installation, or nothing when this run was given no deployment.
    fn open() -> Option<Self> {
        let deployment = Deployment::from_environment()?;
        let inner = deployment.transport();
        Some(Self::over(deployment, inner))
    }

    /// A run whose requests leave through `inner`, which for every leg is the deployment's own
    /// transport and for a check of a leg's rules is a stand-in that answers in its place.
    fn over(deployment: Deployment, inner: Arc<dyn ServiceHttp>) -> Self {
        let key = RunKey::installation();
        let reached = Arc::new(Reached::default());
        let transport = Arc::new(Recording {
            inner,
            reached: Arc::clone(&reached),
            sent: AtomicUsize::new(0),
            lose_the_next_answer: AtomicBool::new(false),
            lost: Mutex::new(None),
        });
        let service = Arc::new(ManagedSyncService::new(
            deployment.origin().clone(),
            Arc::clone(&transport) as Arc<dyn ServiceHttp>,
            Arc::clone(&key) as Arc<dyn ServiceSigner>,
        ));
        let keys = Arc::new(MemoryCollectionKeys::new());
        let key_name = fresh_uuid().to_string();
        keys.draw(&key_name, 1)
            .expect("a collection key for the run");
        Self {
            sealer: Arc::new(CollectionSealer::new(keys, &key_name, 1)),
            deployment,
            key,
            transport,
            reached,
            service,
            directory: tempfile::tempdir().expect("a directory for the devices' stores"),
        }
    }

    /// One device: a store of its own and the shared service client.
    fn device(&self, name: &str) -> SyncClient {
        SyncClient::new(
            Arc::clone(&self.service) as Arc<dyn SyncBackupService>,
            Arc::clone(&self.sealer) as Arc<dyn DraftSealer>,
            SyncStore::open(self.directory.path().join(name)).expect("a device's store"),
        )
    }

    /// How many requests have left this run so far.
    fn sent(&self) -> usize {
        self.transport.sent.load(Ordering::SeqCst)
    }

    /// Opens a sealed object the service holds and reads the synchronised object inside it.
    fn opened(&self, ciphertext: &[u8]) -> SyncObject {
        let plaintext = self
            .sealer
            .open(ciphertext)
            .expect("sealed under the run's key");
        kr_cbor::from_canonical_slice(&plaintext, &kr_cbor::Limits::DEFAULT)
            .expect("a synchronised object")
    }

    /// Gives back what the leg took, and says what the service would not take back.
    ///
    /// Every identity first, then every collection, and each attempted whatever happened to the
    /// one before it: a failure with one must not be why another keeps its content.
    async fn clear(&self) -> Vec<String> {
        let signed = SignedService::new(
            self.deployment.origin().clone(),
            self.deployment.transport(),
            Arc::clone(&self.key) as Arc<dyn ServiceSigner>,
        );
        let mut left = Vec::new();
        let identities = self
            .reached
            .identities
            .lock()
            .expect("the identities")
            .clone();
        for (identity, (collection, first, last)) in identities {
            // A fence answers a request that has run with its receipt and changes nothing, and it
            // ends one that has not, so after this no write of the leg's can still arrive.
            let fence = serde_json::json!({
                "fence": {
                    "collection_id": collection,
                    "request_id": identity,
                    "first_signed_at_ms": first.to_string(),
                    "last_signed_at_ms": last.to_string(),
                },
            });
            match sync_call(&signed, &fence).await {
                Ok(answer) => {
                    if let Err(what) = ended(&answer, &identity) {
                        left.push(what);
                    }
                }
                Err(error) => left.push(format!("a request identity could not be ended: {error}")),
            }
        }
        let collections = self
            .reached
            .collections
            .lock()
            .expect("the collections")
            .clone();
        for collection in collections {
            if let Err(what) = empty(&signed, &collection).await {
                left.push(what);
            }
        }
        left
    }
}

/// Holds a fence's answer to having ended the identity it named.
///
/// Only three answers end a request: the receipt of one that ran, applied or refused, and the fence
/// itself. Anything else, including an answer about another identity or one that does not say
/// whether the request ran, leaves an upload that may still arrive, so a leg that took it for an end
/// could report a collection empty just before a delayed write filled it again.
fn ended(answer: &serde_json::Value, identity: &str) -> Result<(), String> {
    if answer["request_id"] != identity {
        return Err("a fence was answered about another request identity".to_owned());
    }
    if !answer["never_ran"].is_boolean() {
        return Err("a fence answer did not say whether the request ran".to_owned());
    }
    match answer["state"].as_str() {
        Some("applied" | "refused" | "fenced") => Ok(()),
        _ => Err("a fence answer did not end the request it named".to_owned()),
    }
}

/// Sends one settings-sync request as it is written.
async fn sync_call(
    signed: &SignedService,
    body: &serde_json::Value,
) -> kr_client::Result<serde_json::Value> {
    signed
        .call(
            SYNC_EXCHANGE_PATH,
            Method::SyncCompareExchange,
            body,
            MAX_SYNC_REQUEST_BYTES,
        )
        .await
}

/// Empties one collection, or says why it is not empty.
///
/// A bounded number of passes rather than a loop: a collection that always had more ends the leg
/// rather than holding it, and running out is a failure, because the collection still holds
/// something. A removal compares like any other write, so one that meets a write it did not expect
/// loses and the next pass reads the collection again.
async fn empty(signed: &SignedService, collection: &str) -> Result<(), String> {
    for _ in 0..4u32 {
        let held = sync_call(
            signed,
            &serde_json::json!({ "compare": { "collection_id": collection, "with_conflicts": true } }),
        )
        .await
        .map_err(|error| format!("a collection could not be read: {error}"))?;
        let copies: Vec<serde_json::Value> = held["conflicts"]
            .as_array()
            .map(|copies| {
                copies
                    .iter()
                    .map(|copy| copy["conflict_id"].clone())
                    .collect()
            })
            .unwrap_or_default();
        let objects = held["changed"].as_array().cloned().unwrap_or_default();
        if copies.is_empty() && objects.is_empty() {
            let stored = &held["stored"];
            if stored["objects"] == "0" && stored["conflicts"] == "0" && stored["bytes"] == "0" {
                return Ok(());
            }
            return Err(format!(
                "a collection with nothing left to remove still counts {stored}"
            ));
        }
        if !copies.is_empty() {
            sync_call(
                signed,
                &serde_json::json!({
                    "resolve": { "collection_id": collection, "conflict_ids": copies },
                }),
            )
            .await
            .map_err(|error| format!("a collection's copies could not be dropped: {error}"))?;
        }
        for object in objects {
            // No request identity: a removal made to give back what a leg took leaves no receipt
            // of its own behind.
            sync_call(
                signed,
                &serde_json::json!({
                    "exchange": {
                        "collection_id": collection,
                        "kind": object["kind"],
                        "object_id": object["object_id"],
                        "expected_revision": object["revision"],
                        "object": null,
                    },
                }),
            )
            .await
            .map_err(|error| format!("an object could not be removed: {error}"))?;
        }
    }
    Err("a collection still held something after every pass this leg is allowed".to_owned())
}

/// Runs one leg and gives back what it took, whether the leg passed or failed.
///
/// The leg's work runs as a task of its own, so a failed assertion ends that task rather than this
/// one: what the leg published is removed either way and the failure is raised again afterwards.
async fn leg<Body, Work>(body: Body)
where
    Body: FnOnce(Arc<Run>) -> Work + Send + 'static,
    Work: Future<Output = String> + Send + 'static,
{
    let Some(run) = Run::open() else {
        return;
    };
    let run = Arc::new(run);

    let outcome = tokio::spawn(body(Arc::clone(&run))).await;
    let left = run.clear().await;

    match outcome {
        Ok(what) => {
            assert!(
                left.is_empty(),
                "this leg did not give back what it took: {left:?}"
            );
            proved("sync", &run.deployment, &what);
        }
        Err(failed) => {
            for what in left {
                eprintln!("this leg could not give back what it took: {what}");
            }
            std::panic::resume_unwind(failed.into_panic());
        }
    }
}

/* -------------------------------------------------------------------------- */
/* What the lost-answer leg takes as proof                                     */
/* -------------------------------------------------------------------------- */

/// How many times the lost-answer leg sends its first write: once, and twice more when the service
/// declines to decide it.
const FIRST_WRITE_SENDS: usize = 3;

/// The longest the leg waits before it sends the first write again, whatever the service asked.
const LONGEST_WAIT_TO_SEND_AGAIN: Duration = Duration::from_secs(5);

/// Publishes one object with its answer lost on the way back, and returns that answer once it is
/// the answer to a write the service accepted.
///
/// The lost-answer leg needs a write the service applied whose answer never reached the device. A
/// `503` with `SERVICE_UNAVAILABLE` is the service saying it has decided nothing it can report: it
/// names no position and proves nothing. So that answer is lost as well, and after the wait it asks
/// for, the same request is sent again as a device that lost an answer sends it: the identity, the
/// bytes and the expected position the device recorded before its first send. The service runs the
/// request once or answers it from its receipt, and the leg holds what comes back here to being an
/// accepted write, exactly as it would have held the first answer.
///
/// # Errors
///
/// Returns why there is no accepted write: no answer at all, an answer that is neither an accepted
/// write nor a `503 SERVICE_UNAVAILABLE`, or [`FIRST_WRITE_SENDS`] of those `503`s. None of them is
/// the answer the leg means.
async fn drop_an_accepted_write(
    run: &Run,
    client: &SyncClient,
    object_id: SyncObjectId,
) -> Result<ServiceHttpAnswer, String> {
    run.transport
        .lose_the_next_answer
        .store(true, Ordering::SeqCst);
    if client.publish(object_id, now()).await.is_ok() {
        return Err("a write whose answer was lost was reported as answered".to_owned());
    }
    let mut sent = 1;
    loop {
        let answer = run
            .transport
            .lost
            .lock()
            .expect("the lost answer")
            .take()
            .ok_or_else(|| "the service did not answer the write".to_owned())?;
        if answer.status == 200 {
            return Ok(answer);
        }
        let envelope: serde_json::Value = serde_json::from_slice(&answer.body).unwrap_or_default();
        if answer.status != 503 || envelope["error"]["code"] != "SERVICE_UNAVAILABLE" {
            return Err(format!(
                "the service answered the write {} {}, which is not a write it accepted",
                answer.status, envelope["error"]["code"]
            ));
        }
        if sent == FIRST_WRITE_SENDS {
            return Err(format!(
                "the service answered the write 503 SERVICE_UNAVAILABLE {sent} times, and a write it declined to decide proves nothing"
            ));
        }
        let asked = envelope["error"]["retryAfterSeconds"]
            .as_u64()
            .map_or(Duration::from_secs(1), Duration::from_secs);
        tokio::time::sleep(asked.min(LONGEST_WAIT_TO_SEND_AGAIN)).await;

        // The record the device wrote before its first send is the request: sent again from it,
        // the service is asked the same thing under the same identity.
        let staged = client
            .store()
            .requests()
            .map_err(|error| format!("the device's requests could not be read: {error}"))?
            .items
            .into_iter()
            .find(|record| record.dispatched())
            .ok_or_else(|| "the device holds no record of the write it sent".to_owned())?;
        let collection = staged.collection();
        let ciphertext = staged
            .ciphertext()
            .ok_or_else(|| "a sent record carries its bytes".to_owned())?;
        run.transport
            .lose_the_next_answer
            .store(true, Ordering::SeqCst);
        let again = run
            .service
            .compare_exchange(
                &collection,
                staged.work_id,
                now_ms(),
                staged.expected.as_ref().copied(),
                ciphertext,
            )
            .await;
        if again.is_ok() {
            return Err("a write whose answer was lost was reported as answered".to_owned());
        }
        sent += 1;
    }
}

/* -------------------------------------------------------------------------- */
/* What the legs publish                                                       */
/* -------------------------------------------------------------------------- */

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

/// One settings object written by one device at one instant.
fn settings_object(object_id: SyncObjectId, by: u8, body: SyncSettings, at_ms: u64) -> SyncObject {
    SyncObject {
        object_id,
        revision: fresh_revision().expect("a revision"),
        device_id: device(by),
        updated_at_ms: TimestampMs::new(at_ms),
        body: SyncBody::Settings(body),
    }
}

fn now() -> TimestampMs {
    TimestampMs::new(now_ms())
}

/* -------------------------------------------------------------------------- */
/* The legs                                                                    */
/* -------------------------------------------------------------------------- */

/// KR-REQ-20.13: a write that loses the comparison is kept for the person to choose from, both
/// versions are readable on the service, and the person's choice leaves no copy on either side.
#[tokio::test]
async fn kr_req_20_13_a_lost_comparison_keeps_both_copies_until_the_person_chooses() {
    leg(|run| async move {
        let one = run.device("one");
        let two = run.device("two");
        let object_id = fresh_object_id().expect("an identity");
        let collection = sync_collection(SyncObjectKind::Settings, object_id);

        // Two devices hold the same object. The second wrote its version later by its own clock,
        // which is exactly what a rule that took the later clock would pick.
        let written = now_ms();
        let theirs = settings_object(object_id, 1, settings(&[("theme", "dark")], &[]), written - 60_000);
        let mine = settings_object(object_id, 2, settings(&[("theme", "light")], &[]), written);
        one.store().put_object(&theirs).expect("stored");
        two.store().put_object(&mine).expect("stored");

        let Published::Accepted { position: first } =
            one.publish(object_id, now()).await.expect("published")
        else {
            panic!("the first write of an object the service has never held is accepted")
        };
        assert_eq!(first.write_sequence, 1, "the service's order starts at one");
        assert_eq!(
            first.recovery(),
            None,
            "a deployment never put back names no history"
        );

        // The second loses the comparison: it expected nothing and the object is there. It is told
        // where the object stands and keeps the other device's content beside its own.
        let Published::Conflicted {
            copy,
            other_revision,
            position,
        } = two.publish(object_id, now()).await.expect("answered")
        else {
            panic!("the second write compared against nothing and something was there")
        };
        assert_eq!(other_revision, theirs.revision);
        assert_eq!(position, first, "it is told the position that beat it");
        assert_eq!(position.recovery(), None, "a refusal names no history either");
        assert_eq!(
            two.store().object(object_id).expect("read").expect("held"),
            mine,
            "a lost comparison never replaces this device's own content"
        );

        // Both versions are on the service and both are readable: the object is the first
        // device's, and the copy the service kept is the second device's refused write. Neither
        // was chosen by the later clock.
        let compared = run
            .service
            .compare(&collection, true, None)
            .await
            .expect("compared");
        assert_eq!(compared.objects.len(), 1);
        assert_eq!(compared.objects[0].position, first);
        assert_eq!(compared.recovery, None, "nor does a comparison");
        assert_eq!(run.opened(&compared.objects[0].ciphertext), theirs);
        assert_eq!(compared.copies.len(), 1);
        assert_eq!(compared.copies[0].current, Some(first));
        assert_eq!(run.opened(&compared.copies[0].ciphertext), mine);
        assert_eq!(compared.stored.conflicts.get(), 1);
        let kept = two
            .store()
            .conflicts(object_id)
            .expect("copies")
            .items;
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].conflict_id, copy);
        assert_eq!(kept[0].retained.as_ref().copied(), Some(compared.copies[0].conflict_id));

        // The person on the second device chooses the first device's settings. The choice is put
        // in place, the copy leaves this device and the copy the service kept leaves the service.
        let mut chosen = mine.clone();
        chosen.revision = fresh_revision().expect("a revision");
        chosen.body = theirs.body.clone();
        two.store().put_object(&chosen).expect("stored");
        let resolved = two
            .resolve(copy)
            .await
            .expect("the choice is recorded")
            .expect("the copy was there");
        assert_eq!(
            resolved.service,
            Resolutions {
                dropped: 1,
                pending: 0
            }
        );
        assert!(two.store().conflicts(object_id).expect("copies").is_empty());
        let compared = run
            .service
            .compare(&collection, true, None)
            .await
            .expect("compared");
        assert!(compared.copies.is_empty(), "no copy stays on the service");
        assert_eq!(compared.stored.conflicts.get(), 0);

        // What was chosen is published against where the object stands, and it is what the service
        // now holds.
        let Published::Accepted { position: second } =
            two.publish(object_id, now()).await.expect("published")
        else {
            panic!("the choice is published against the position the refusal named")
        };
        assert_eq!(second.write_sequence, 2);
        let compared = run
            .service
            .compare(&collection, false, None)
            .await
            .expect("compared");
        assert_eq!(run.opened(&compared.objects[0].ciphertext), chosen);

        "two devices holding one object: the second loses the comparison and keeps the first's content beside its own, both versions are readable through a comparison with its copies, and the person's choice leaves no copy on either side, with no clock deciding anything".to_owned()
    })
    .await;
}

/// KR-REQ-20.13: a write naming a revision the object has moved past is refused, and the service
/// keeps what it carried.
#[tokio::test]
async fn kr_req_20_13_a_stale_expected_revision_is_refused_and_kept_as_a_copy() {
    leg(|run| async move {
        let one = run.device("one");
        let two = run.device("two");
        let object_id = fresh_object_id().expect("an identity");
        let collection = sync_collection(SyncObjectKind::Settings, object_id);

        let mut theirs = settings_object(object_id, 1, settings(&[("theme", "dark")], &[]), now_ms());
        one.store().put_object(&theirs).expect("stored");
        one.publish(object_id, now()).await.expect("published");

        // The second device brings the object down and takes it as its own, so its note names the
        // first write.
        let restored = two
            .fetch(SyncObjectKind::Settings, object_id, now())
            .await
            .expect("fetched");
        let mut mine = restored.object().clone();
        two.store().put_object(&mine).expect("stored");
        let note = two
            .store()
            .checkpoint(object_id)
            .expect("a note")
            .expect("one was written");

        // The first device writes again, so the revision the second device's note names is stale.
        theirs.revision = fresh_revision().expect("a revision");
        theirs.body = SyncBody::Settings(settings(&[("theme", "solarised")], &[]));
        one.store().put_object(&theirs).expect("stored");
        let Published::Accepted { position: latest } =
            one.publish(object_id, now()).await.expect("published")
        else {
            panic!("the first device's note is current")
        };

        // The second device edits and writes against its stale note. The comparison is refused and
        // the object is where the first device left it.
        mine.revision = fresh_revision().expect("a revision");
        mine.device_id = device(2);
        mine.body = SyncBody::Settings(settings(&[("theme", "light")], &[]));
        two.store().put_object(&mine).expect("stored");
        let Published::Conflicted { position, .. } =
            two.publish(object_id, now()).await.expect("answered")
        else {
            panic!("a write against a stale revision is refused")
        };
        assert_eq!(position, latest);

        // The service kept the refused write, and its copy records the stale revision it expected
        // and where the object stood.
        let compared = run
            .service
            .compare(&collection, true, None)
            .await
            .expect("compared");
        assert_eq!(compared.objects[0].position, latest);
        assert_eq!(run.opened(&compared.objects[0].ciphertext), theirs);
        assert_eq!(compared.copies.len(), 1);
        assert_eq!(
            compared.copies[0].expected_revision.as_ref().copied(),
            note.position.revision.as_ref().copied()
        );
        assert_eq!(compared.copies[0].current, Some(latest));
        assert_eq!(run.opened(&compared.copies[0].ciphertext), mine);

        "a write naming a revision the object has moved past is refused, the object stays where the later write left it, and the service keeps the refused write as a copy naming the stale revision".to_owned()
    })
    .await;
}

/// KR-REQ-20.13: a draft is synchronised as a draft, and nothing on the way submits it.
#[tokio::test]
async fn kr_req_20_13_a_draft_is_published_as_a_draft_and_never_as_an_execution_request() {
    leg(|run| async move {
        let drafts = DraftSync::new(
            Arc::clone(&run.service) as Arc<dyn SyncBackupService>,
            Arc::clone(&run.sealer) as Arc<dyn DraftSealer>,
            SyncStore::open(run.directory.path().join("drafts-sync")).expect("a device's store"),
        );
        let here = DraftStore::open(run.directory.path().join("drafts-one"), device(1))
            .expect("a draft store");
        let there = DraftStore::open(run.directory.path().join("drafts-two"), device(2))
            .expect("another device's draft store");
        let draft = here
            .create(
                DraftTarget::session(SessionId::new(fresh_uuid())),
                "a prompt the person has not sent".to_owned(),
                now(),
            )
            .expect("a draft");

        assert!(matches!(
            drafts
                .publish(&here, draft.draft_id, draft.revision, now())
                .await
                .expect("published"),
            DraftPublished::Accepted { .. }
        ));

        // The service holds it as a draft, and as nothing else.
        let collection = kr_client::drafts::draft_collection(draft.draft_id);
        let compared = run
            .service
            .compare(&collection, false, None)
            .await
            .expect("compared");
        assert_eq!(compared.objects.len(), 1);
        assert_eq!(compared.objects[0].kind, SyncObjectKind::Draft);

        // The settings client does not read drafts: it refuses one before anything is sent.
        let settings = run.device("settings");
        let before = run.sent();
        assert!(matches!(
            settings
                .fetch(
                    SyncObjectKind::Draft,
                    SyncObjectId::new(draft.draft_id.get()),
                    now(),
                )
                .await,
            Err(SyncError::DraftElsewhere { .. })
        ));
        assert_eq!(run.sent(), before, "nothing was sent for it");

        // Another device brings it down beside its own drafts, as a draft. What it holds answers a
        // question about where a submission would go and performs nothing: submitting is a call
        // to a host, which nothing on this path makes.
        let fetched = drafts
            .fetch_beside(&there, draft.draft_id, now())
            .await
            .expect("fetched");
        assert_eq!(fetched.remote.text, draft.text);
        assert_eq!(fetched.copy.conflict_of.as_ref().copied(), Some(draft.draft_id));
        assert_eq!(fetched.copy.submission(), Ok(&draft.target));

        "a draft is published under the draft kind, a settings client refuses it without asking the service, and another device brings it down beside its own as a draft that nothing submits".to_owned()
    })
    .await;
}

/// KR-REQ-24.28: a client fenced by privacy mode publishes nothing, and its pinned labels are left
/// out of what it would publish while the device keeps them.
#[tokio::test]
async fn kr_req_24_28_a_client_fenced_by_privacy_mode_publishes_nothing_and_keeps_its_pinned_labels()
 {
    leg(|run| async move {
        let client = run.device("one");
        let object_id = fresh_object_id().expect("an identity");
        let collection = sync_collection(SyncObjectKind::Settings, object_id);
        let held = settings(&[("theme", "dark")], &["deploys", "reviews"]);
        client
            .store()
            .put_object(&settings_object(object_id, 1, held.clone(), now_ms()))
            .expect("stored");
        client.store().pin_label("deploys", now()).expect("pinned");

        client.fence(1).expect("privacy mode is on");
        let before = run.sent();
        assert!(matches!(
            client.publish(object_id, now()).await,
            Err(SyncError::Fenced { generation: 1 })
        ));
        assert_eq!(run.sent(), before, "nothing left this device");

        // The labels are left out of what would be published and stay on the device.
        let published = client.settings_to_publish(&held).expect("filtered");
        assert!(published.pinned_labels.is_empty());
        assert_eq!(published.values, held.values);
        let SyncBody::Settings(kept) = client
            .store()
            .object(object_id)
            .expect("read")
            .expect("held")
            .body
        else {
            panic!("a settings object")
        };
        assert_eq!(kept.pinned_labels, held.pinned_labels);
        assert_eq!(
            client.store().pinned_labels().expect("labels").len(),
            1,
            "a pinned label stays until the person clears it"
        );

        // And the deployment holds nothing for the object.
        let compared = run
            .service
            .compare(&collection, true, None)
            .await
            .expect("compared");
        assert!(compared.objects.is_empty() && compared.copies.is_empty());
        assert_eq!(compared.stored.objects.get(), 0);

        "a client fenced by privacy mode refuses to publish before anything is sent, the deployment holds nothing for the object, and its pinned labels are left out of what it would publish while the device keeps them".to_owned()
    })
    .await;
}

/// KR-REQ-20.13: a sealed object the service would refuse for its structure never leaves this
/// device, and the service does refuse it.
#[tokio::test]
async fn kr_req_20_13_a_sealed_object_the_service_refuses_is_refused_here_first() {
    leg(|run| async move {
        let object_id = fresh_object_id().expect("an identity");
        let collection = sync_collection(SyncObjectKind::Settings, object_id);
        let object = settings_object(object_id, 1, settings(&[("theme", "dark")], &[]), now_ms());
        let sealed = run
            .sealer
            .seal(&kr_cbor::to_canonical_vec(&object).expect("canonical bytes"))
            .expect("sealed");
        let mut broken: SealedSyncObject =
            kr_cbor::from_canonical_slice(&sealed, &kr_cbor::Limits::DEFAULT).expect("an object");
        // A ciphertext that is not the declared bucket sealed: something no sealer makes, and
        // something the service checks without a key.
        let mut ciphertext = broken.ciphertext.as_slice().to_vec();
        ciphertext.truncate(ciphertext.len() - 1);
        broken.ciphertext = kr_protocol::scalars::Bytes::new(ciphertext);
        assert!(broken.check_structure().is_err());

        let before = run.sent();
        let refused = run
            .service
            .compare_exchange(
                &collection,
                fresh_uuid(),
                now_ms(),
                None,
                &kr_cbor::to_canonical_vec(&broken).expect("canonical bytes"),
            )
            .await
            .expect_err("a sealed object the service would refuse");
        assert_eq!(refused.code(), ErrorCode::InvalidArgument);
        assert_eq!(run.sent(), before, "nothing left this device");

        // The same object, sent as it is, is refused by the service for the same rule.
        let signed = SignedService::new(
            run.deployment.origin().clone(),
            Arc::clone(&run.transport) as Arc<dyn ServiceHttp>,
            Arc::clone(&run.key) as Arc<dyn ServiceSigner>,
        );
        let refused = sync_call(
            &signed,
            &serde_json::json!({
                "exchange": {
                    "collection_id": object_id.get().to_string(),
                    "kind": "settings",
                    "object_id": object_id.get().to_string(),
                    "expected_revision": null,
                    "object": broken,
                },
            }),
        )
        .await
        .expect_err("the service refuses it");
        assert_eq!(refused.code(), ErrorCode::InvalidArgument);
        assert!(
            refused.to_string().contains("declared bucket"),
            "the service names the rule: {refused}"
        );
        let compared = run
            .service
            .compare(&collection, false, None)
            .await
            .expect("compared");
        assert!(compared.objects.is_empty(), "nothing was stored");

        "a sealed object whose ciphertext is not its declared bucket sealed is refused by this client with nothing sent, and the deployment refuses the same object for the same rule".to_owned()
    })
    .await;
}

/// KR-REQ-20.13: an answer lost on its way back settles from the receipt, the same identity
/// presented again is answered with what was recorded, and the write is applied once.
#[tokio::test]
async fn kr_req_20_13_an_answer_lost_in_flight_is_settled_from_the_receipt_and_applied_once() {
    leg(|run| async move {
        let client = run.device("one");
        let object_id = fresh_object_id().expect("an identity");
        let collection = sync_collection(SyncObjectKind::Settings, object_id);
        client
            .store()
            .put_object(&settings_object(
                object_id,
                1,
                settings(&[("theme", "dark")], &[]),
                now_ms(),
            ))
            .expect("stored");

        // The service applies the write and the answer is lost on its way back.
        //
        // What was lost is the answer this leg means: the service applied the write, at a place
        // the leg reads from that answer. An exchange that failed before it arrived, one the
        // service refused and one it declined to decide would look the same to the device and
        // prove nothing below.
        let lost = drop_an_accepted_write(&run, &client, object_id)
            .await
            .unwrap_or_else(|why| panic!("{why}"));
        assert_eq!(client.outstanding().expect("a count"), 1);
        assert_eq!(lost.status, 200);
        let lost: serde_json::Value =
            serde_json::from_slice(&lost.body).expect("the service's envelope");
        assert_eq!(lost["ok"], true, "the service admitted the write");
        assert_eq!(lost["data"]["state"], "written", "the service applied it");
        // The answer names its history, as a member present and null for a deployment never put
        // back, which is what the positions below are read in.
        assert_eq!(
            lost["data"].get("recovery_id"),
            Some(&serde_json::Value::Null),
            "the history is named, and it is none"
        );
        let applied_at = SyncPosition::at(
            lost["data"]["current_write_sequence"]
                .as_str()
                .and_then(|sequence| sequence.parse().ok())
                .expect("the place it was applied at"),
            SyncRevision::new(
                lost["data"]["current_revision"]
                    .as_str()
                    .and_then(|revision| revision.parse().ok())
                    .expect("the name it was given"),
            ),
            None,
        );
        let staged = client
            .store()
            .requests()
            .expect("requests")
            .items
            .into_iter()
            .find(|record| record.dispatched())
            .expect("the record says it was sent");

        // The same request, under the same identity and with the same bytes, is answered from the
        // receipt: the position the write was recorded at, and no second write.
        let again = run
            .service
            .compare_exchange(
                &collection,
                staged.work_id,
                now_ms(),
                staged.expected.as_ref().copied(),
                staged.ciphertext().expect("a dispatched record carries its bytes"),
            )
            .await
            .expect("answered from the receipt");
        let SyncExchanged::Applied { position } = again else {
            panic!("the write was applied")
        };
        // The very position the lost answer named. Had the service run the write again, a write
        // that expected no object would have been refused, because the first one is there now: an
        // applied answer at the same place is the receipt speaking.
        assert_eq!(position, applied_at, "answered from the receipt");
        assert_eq!(position.write_sequence, 1);

        // The client settles it by asking about the request.
        let reconciled = client
            .reconcile_unsettled(now())
            .await
            .expect("reconciled");
        assert_eq!(reconciled.settled, 1);
        assert_eq!(reconciled.unsettled, 0);
        assert_eq!(
            client
                .store()
                .checkpoint(object_id)
                .expect("a note")
                .expect("one was written")
                .position,
            position
        );
        assert_eq!(
            run.service
                .request_status(&collection, staged.work_id)
                .await
                .expect("asked"),
            SyncRequestStatus::Applied { position }
        );

        // Applied once: the object is at the first place in its order.
        let compared = run
            .service
            .compare(&collection, false, None)
            .await
            .expect("compared");
        assert_eq!(compared.objects.len(), 1);
        assert_eq!(compared.objects[0].position, position);
        assert_eq!(compared.objects[0].position.write_sequence, 1);

        "an answer lost on its way back leaves the request outstanding, the same identity presented again is answered from the receipt, the client settles it by asking about the request, and the write is applied once".to_owned()
    })
    .await;
}

/// KR-REQ-20.13: a fence of an identity that never arrived says so, and nothing runs under it
/// afterwards.
#[tokio::test]
async fn kr_req_20_13_a_fenced_identity_never_ran_and_nothing_runs_under_it_afterwards() {
    leg(|run| async move {
        let object_id = fresh_object_id().expect("an identity");
        let collection = sync_collection(SyncObjectKind::Settings, object_id);
        let identity = fresh_uuid();
        let signed_at = now_ms();

        // Asked about first, an identity nothing was ever sent under has no receipt, in no history.
        assert_eq!(
            run.service
                .request_status(&collection, identity)
                .await
                .expect("asked"),
            SyncRequestStatus::Unknown { recovery: None }
        );

        // An identity nothing was ever sent under, fenced naming the instant an attempt would have
        // been signed at. The collection is the run's own and has swept nothing, so the service
        // can say from its own records that nothing ran.
        assert_eq!(
            run.service
                .fence_request(&collection, identity, signed_at, signed_at)
                .await
                .expect("fenced"),
            SyncRequestFence::Fenced {
                never_ran: true,
                recovery: None,
            }
        );

        // An exchange that arrives under it afterwards runs nothing.
        let object = settings_object(object_id, 1, settings(&[("theme", "dark")], &[]), now_ms());
        let sealed = run
            .sealer
            .seal(&kr_cbor::to_canonical_vec(&object).expect("canonical bytes"))
            .expect("sealed");
        let refused = run
            .service
            .compare_exchange(&collection, identity, now_ms(), None, &sealed)
            .await
            .expect_err("a fenced identity runs nothing");
        assert_eq!(refused.code(), ErrorCode::PermissionDenied);
        assert_eq!(
            refused.user_action(),
            kr_client::retry::UserAction::Nothing,
            "there is nothing for a person to do about it: {refused}"
        );

        // Asking about the identity repeats what the fence established.
        assert_eq!(
            run.service
                .request_status(&collection, identity)
                .await
                .expect("asked"),
            SyncRequestStatus::Fenced {
                never_ran: true,
                recovery: None,
            }
        );
        let compared = run
            .service
            .compare(&collection, false, None)
            .await
            .expect("compared");
        assert!(compared.objects.is_empty(), "the exchange stored nothing");

        "a fence of an identity that never arrived answers that nothing ran, an exchange under it afterwards is refused as fenced and stores nothing, and a status query repeats what the fence established".to_owned()
    })
    .await;
}

/// KR-REQ-20.13: a fetch of an object never published finds its collection holding none, and the
/// answer names the history that holds none: no history, on a deployment never put back.
#[tokio::test]
async fn kr_req_20_13_a_fetch_of_an_object_never_published_answers_its_absence_under_no_history() {
    leg(|run| async move {
        let object_id = fresh_object_id().expect("an identity");
        let collection = sync_collection(SyncObjectKind::Settings, object_id);

        assert_eq!(
            run.service.fetch(&collection).await.expect("answered"),
            SyncFetched::Absent { recovery: None },
            "an empty collection is an answer, in the history the deployment names"
        );

        // A device told so keeps nothing: no note, no copy, and the collection is read in no
        // history, as it was before it asked.
        let client = run.device("one");
        let before = run.sent();
        let absent = client
            .fetch(SyncObjectKind::Settings, object_id, now())
            .await
            .expect_err("nothing is held");
        assert_eq!(absent.code(), ErrorCode::UnknownSession, "{absent}");
        assert_eq!(run.sent(), before + 1, "one read and nothing written");
        assert_eq!(client.store().checkpoint(object_id).expect("a note"), None);
        assert!(client.store().conflicts(object_id).expect("copies").is_empty());
        assert_eq!(
            client.store().basis(object_id).expect("a history").recovery(),
            None
        );

        "a fetch of an object never published is answered as a collection holding none, naming no history on a deployment never put back, and a device told so writes nothing and keeps no note".to_owned()
    })
    .await;
}

/// KR-REQ-18.05: a setting travels sealed, and the service counts a declared bucket rather than
/// anything about the setting.
#[tokio::test]
async fn kr_req_18_05_a_setting_is_stored_sealed_in_a_declared_bucket() {
    leg(|run| async move {
        let client = run.device("one");
        let object_id = fresh_object_id().expect("an identity");
        let collection = sync_collection(SyncObjectKind::Settings, object_id);
        let marker = "a-setting-value-nobody-should-see";
        let object = settings_object(object_id, 1, settings(&[("editor", marker)], &[]), now_ms());
        client.store().put_object(&object).expect("stored");
        client.publish(object_id, now()).await.expect("published");

        let compared = run
            .service
            .compare(&collection, false, None)
            .await
            .expect("compared");
        let held: SealedSyncObject = kr_cbor::from_canonical_slice(
            &compared.objects[0].ciphertext,
            &kr_cbor::Limits::DEFAULT,
        )
        .expect("a sealed object");
        let plaintext = kr_cbor::to_canonical_vec(&object).expect("canonical bytes");
        assert_eq!(
            held.size_bucket_bytes.get(),
            mailbox_size_bucket(plaintext.len() as u64),
            "the declared bucket is the padding rule's, not the setting's length"
        );
        assert!(
            !held
                .ciphertext
                .as_slice()
                .windows(marker.len())
                .any(|window| window == marker.as_bytes()),
            "the service holds no setting in the clear"
        );
        assert_eq!(compared.stored.bytes.get(), held.stored_bytes());
        assert_eq!(run.opened(&compared.objects[0].ciphertext), object);

        "a setting is stored as a sealed object in the bucket the padding rule declares, the service counts that bucket and never holds the setting in the clear, and it opens again under the collection key".to_owned()
    })
    .await;
}

/* -------------------------------------------------------------------------- */
/* The lost-answer leg's proof, against a stand-in                             */
/* -------------------------------------------------------------------------- */

/// A settings-sync service that declines every exchange it is sent with `503 SERVICE_UNAVAILABLE`,
/// until the one it is told to accept, and keeps what each exchange asked for.
///
/// It stands where the deployment stands for the lost-answer leg's first write, so the rule that
/// step keeps is checked on every run of this suite, deployment or none: nothing leaves this
/// machine.
#[derive(Debug)]
struct Declining {
    /// Which exchange, counted from one, it answers as an accepted write; none, if it never does.
    accepts: Option<usize>,
    /// What each exchange it was sent asked for, in the order they came.
    exchanges: Mutex<Vec<serde_json::Value>>,
}

impl Declining {
    fn new(accepts: Option<usize>) -> Arc<Self> {
        Arc::new(Self {
            accepts,
            exchanges: Mutex::new(Vec::new()),
        })
    }

    /// What each exchange it was sent asked for.
    fn exchanges(&self) -> Vec<serde_json::Value> {
        self.exchanges.lock().expect("the exchanges").clone()
    }
}

impl ServiceHttp for Declining {
    fn post_json<'a>(
        &'a self,
        _url: &'a str,
        body: &'a [u8],
        _headers: &'a [(&'a str, &'a str)],
    ) -> ServiceFuture<'a, ServiceHttpAnswer> {
        Box::pin(async move {
            let request: serde_json::Value = serde_json::from_slice(body).unwrap_or_default();
            let sent = {
                let mut exchanges = self.exchanges.lock().expect("the exchanges");
                exchanges.push(request["body"]["exchange"].clone());
                exchanges.len()
            };
            let (status, answer) = if self.accepts == Some(sent) {
                (
                    200,
                    serde_json::json!({
                        "ok": true,
                        "data": {
                            "state": "written",
                            "current_revision": fresh_uuid().to_string(),
                            "current_write_sequence": "1",
                            "recovery_id": null,
                        },
                    }),
                )
            } else {
                (
                    503,
                    serde_json::json!({
                        "ok": false,
                        "error": {
                            "code": "SERVICE_UNAVAILABLE",
                            "message": "The collection could not finish that request. Send it again shortly.",
                            "retryAfterSeconds": 0,
                        },
                    }),
                )
            };
            Ok(ServiceHttpAnswer {
                status,
                body: serde_json::to_vec(&answer).expect("an answer"),
            })
        })
    }
}

/// A run whose every request goes to `service` and nowhere else.
fn run_against(service: &Arc<Declining>) -> Run {
    let origin = GatewayOrigin::new("https://stand-in.example").expect("an origin");
    Run::over(
        Deployment::at(origin),
        Arc::clone(service) as Arc<dyn ServiceHttp>,
    )
}

/// One device holding one settings object to publish, as the lost-answer leg's device does.
fn one_object(run: &Run) -> (SyncClient, SyncObjectId) {
    let client = run.device("one");
    let object_id = fresh_object_id().expect("an identity");
    client
        .store()
        .put_object(&settings_object(
            object_id,
            1,
            settings(&[("theme", "dark")], &[]),
            now_ms(),
        ))
        .expect("stored");
    (client, object_id)
}

/// Holds every exchange a stand-in was sent to being one request: one identity, one set of bytes and
/// one comparison.
fn one_request(exchanges: &[serde_json::Value]) {
    let first = &exchanges[0];
    assert!(
        first["request_id"].is_string(),
        "the write names its request"
    );
    for exchange in exchanges {
        assert_eq!(
            exchange["request_id"], first["request_id"],
            "the same identity"
        );
        assert_eq!(exchange["object"], first["object"], "the same bytes");
        assert_eq!(
            exchange["expected_revision"], first["expected_revision"],
            "the same comparison"
        );
    }
}

/// KR-REQ-20.13: the lost-answer leg's first write, against a service that declines it every
/// time. It is sent the bounded number of times, as one request, and no accepted write comes of
/// it, so the leg does not pass.
#[tokio::test]
async fn the_lost_answer_leg_takes_no_503_for_an_accepted_write() {
    let service = Declining::new(None);
    let run = run_against(&service);
    let (client, object_id) = one_object(&run);

    let why = drop_an_accepted_write(&run, &client, object_id)
        .await
        .expect_err("a 503 is not an accepted write");
    assert!(why.contains("503 SERVICE_UNAVAILABLE"), "{why}");
    let exchanges = service.exchanges();
    assert_eq!(exchanges.len(), FIRST_WRITE_SENDS);
    one_request(&exchanges);
    assert_eq!(
        client.outstanding().expect("a count"),
        1,
        "the request stays outstanding"
    );
}

/// KR-REQ-20.13: the same first write, against a service that declines the first send and accepts
/// the next. The accepted write is what comes back, from the second send of the same request.
#[tokio::test]
async fn the_lost_answer_leg_sends_a_declined_write_again_until_it_is_accepted() {
    let service = Declining::new(Some(2));
    let run = run_against(&service);
    let (client, object_id) = one_object(&run);

    let accepted = drop_an_accepted_write(&run, &client, object_id)
        .await
        .expect("the second send was accepted");
    assert_eq!(accepted.status, 200);
    let envelope: serde_json::Value =
        serde_json::from_slice(&accepted.body).expect("the service's envelope");
    assert_eq!(envelope["ok"], true);
    assert_eq!(envelope["data"]["state"], "written");
    let exchanges = service.exchanges();
    assert_eq!(exchanges.len(), 2);
    one_request(&exchanges);
    assert_eq!(client.outstanding().expect("a count"), 1);
}
