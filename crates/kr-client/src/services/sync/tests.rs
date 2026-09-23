//! What the settings-sync client sends, and what it makes of every answer the service can give.
//!
//! The service here is scripted: it records each request whole and answers what a test told it to.
//! That is enough to hold every mapping to the contract, because the client keeps nothing between
//! calls, and the deployed legs under `tests/integration/sync` hold the same client to the service
//! itself.

use super::*;
use crate::retry::{Step, UserAction};
use crate::services::ServiceHttpAnswer;
use crate::services::rendering::{NEVER_RENDERED, renders_only};
use kr_crypto::secret::Secret;
use kr_protocol::mailbox::{SEAL_OVERHEAD_BYTES, mailbox_size_bucket};
use kr_protocol::scalars::{AuthorisationKey, Bytes, Nonce192, Signature64, TimestampMs};
use kr_protocol::service::{SERVICE_REQUEST_FRESHNESS_MS, ServiceRequestSigner};
use kr_protocol::sync::MAX_SYNC_OBJECT_PLAINTEXT_BYTES;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// A service that records what it was sent and answers with what it was told to.
///
/// It holds whole signed requests, so it writes its own [`fmt::Debug`] like everything else in
/// this module: a derived one would print those bytes as decimals.
struct Recorder {
    sent: Mutex<Vec<(String, Vec<u8>)>>,
    answers: Mutex<Vec<ServiceHttpAnswer>>,
}

impl fmt::Debug for Recorder {
    /// How many requests it has taken. Never one of them.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Recorder")
            .field("requests", &self.requests())
            .finish_non_exhaustive()
    }
}

impl Recorder {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            sent: Mutex::new(Vec::new()),
            answers: Mutex::new(Vec::new()),
        })
    }

    /// The answers this service gives, in order, each as the data of a successful envelope. The
    /// last one is repeated once they run out.
    fn answering(&self, data: Vec<serde_json::Value>) {
        self.answering_with(
            data.into_iter()
                .map(|data| ServiceHttpAnswer {
                    status: 200,
                    body: serde_json::to_vec(&serde_json::json!({ "ok": true, "data": data }))
                        .expect("an answer"),
                })
                .collect(),
        );
    }

    /// The answers this service gives, exactly as they arrive.
    fn answering_with(&self, answers: Vec<ServiceHttpAnswer>) {
        *self.answers.lock().expect("the answers") = answers;
    }

    /// The body of the last request, without its credential.
    fn last_body(&self) -> serde_json::Value {
        self.last()["body"].clone()
    }

    /// The last request, as the service would read it.
    fn last(&self) -> serde_json::Value {
        let sent = self.sent.lock().expect("what was sent");
        let (_, body) = sent.last().expect("one request");
        serde_json::from_slice(body).expect("a request this client wrote")
    }

    fn last_url(&self) -> String {
        let sent = self.sent.lock().expect("what was sent");
        sent.last().expect("one request").0.clone()
    }

    fn requests(&self) -> usize {
        self.sent.lock().expect("what was sent").len()
    }
}

impl ServiceHttp for Recorder {
    fn post_json<'a>(
        &'a self,
        url: &'a str,
        body: &'a [u8],
        headers: &'a [(&'a str, &'a str)],
    ) -> ServiceFuture<'a, ServiceHttpAnswer> {
        assert!(
            headers.is_empty(),
            "a signed request sends no extra headers"
        );
        self.sent
            .lock()
            .expect("what was sent")
            .push((url.to_owned(), body.to_vec()));
        let mut answers = self.answers.lock().expect("the answers");
        let answer = if answers.len() > 1 {
            answers.remove(0)
        } else {
            answers.first().expect("an answer").clone()
        };
        Box::pin(async move { Ok(answer) })
    }
}

/// One installation's authorisation key, held the way a client holds one.
#[derive(Debug)]
struct Device {
    pair: kr_crypto::keys::AuthorisationKeyPair,
}

impl ServiceSigner for Device {
    fn signer(&self) -> ServiceRequestSigner {
        ServiceRequestSigner::Installation
    }

    fn public_key(&self) -> AuthorisationKey {
        *self.pair.public()
    }

    fn sign(&self, message: &[u8]) -> Result<Signature64> {
        let transcript = kr_crypto::sign::SigningTranscript::from_canonical_bytes(
            ServiceRequestSigner::Installation.domain(),
            message.to_vec(),
        )
        .expect("a domain-tagged transcript");
        Ok(kr_crypto::sign::sign(&self.pair, &transcript).expect("a signature"))
    }
}

fn sync_client() -> (ManagedSyncService, Arc<Recorder>) {
    let recorder = Recorder::new();
    let client = ManagedSyncService::new(
        GatewayOrigin::new("https://reach.kala.to").expect("an origin"),
        Arc::clone(&recorder) as Arc<_>,
        Arc::new(Device {
            pair: kr_crypto::keys::AuthorisationKeyPair::generate().expect("a key pair"),
        }) as Arc<_>,
    );
    (client, recorder)
}

/// This machine's clock, which is what a caller signing an attempt now reads.
fn now_ms() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("a clock after the epoch")
            .as_millis(),
    )
    .expect("a clock this century")
}

fn identity(byte: u8) -> Uuid {
    Uuid::from_bytes([byte; 16])
}

fn revision(byte: u8) -> SyncRevision {
    SyncRevision::new(identity(byte))
}

/// A real sealed object, under a key the service never sees.
fn sealed(plaintext: &[u8]) -> SealedSyncObject {
    kr_crypto::envelope::seal_sync_object(&Secret::from_bytes([0x5a; 32]), plaintext)
        .expect("a sealed object")
}

/// The bytes a sealer hands a caller to publish.
fn published(object: &SealedSyncObject) -> Vec<u8> {
    kr_cbor::to_canonical_vec(object).expect("canonical bytes")
}

fn settings_of(object: Uuid) -> String {
    crate::sync::sync_collection(SyncObjectKind::Settings, SyncObjectId::new(object))
}

/// What a collection reports about itself, which no assertion here is about.
fn usage() -> serde_json::Value {
    serde_json::json!({
        "objects": "1",
        "conflicts": "0",
        "bytes": "1320",
        "object_limit": "256",
        "allowance_bytes": null,
    })
}

fn summary(object: Uuid, revision: SyncRevision, write_sequence: &str) -> serde_json::Value {
    serde_json::json!({
        "kind": "settings",
        "object_id": object.to_string(),
        "revision": revision.to_string(),
        "write_sequence": write_sequence,
        "updated_at": "2026-09-23T10:00:00.000Z",
        "bytes": "1320",
    })
}

fn copy_summary(object: Uuid, conflict: Uuid, current: SyncRevision) -> serde_json::Value {
    serde_json::json!({
        "sequence": "1",
        "conflict_id": conflict.to_string(),
        "object_id": object.to_string(),
        "expected_revision": null,
        "current_revision": current.to_string(),
        "current_write_sequence": "4",
        "recorded_at": "2026-09-23T10:00:00.000Z",
    })
}

/// What an exchange is answered with.
fn exchanged(
    state: &str,
    record: serde_json::Value,
    current_revision: Option<SyncRevision>,
    current_write_sequence: &str,
    conflict: serde_json::Value,
) -> serde_json::Value {
    serde_json::json!({
        "state": state,
        "record": record,
        "current_revision": current_revision.map(|revision| revision.to_string()),
        "current_write_sequence": current_write_sequence,
        "conflict": conflict,
        "stored": usage(),
    })
}

/// What a status query or a fence is answered with, `never_ran` included.
fn status(request: Uuid, state: &str, never_ran: bool) -> serde_json::Value {
    serde_json::json!({
        "request_id": request.to_string(),
        "state": state,
        "never_ran": never_ran,
        "outcome": null,
        "record": null,
        "current_revision": null,
        "current_write_sequence": null,
        "conflict_id": null,
        "recorded_at": null,
    })
}

/// A refusal the service named, with the status it serves that code with.
fn refusal(status: u16, code: &str, message: &str) -> ServiceHttpAnswer {
    ServiceHttpAnswer {
        status,
        body: serde_json::to_vec(&serde_json::json!({
            "ok": false,
            "error": { "code": code, "message": message },
        }))
        .expect("a refusal"),
    }
}

#[test]
fn the_bound_an_answer_is_read_under_covers_the_largest_comparison() {
    // A comparison answers a page of objects and a page of copies. Each carries one sealed object,
    // the largest a synchronised object may be, as base64 at four bytes for three, and eight
    // kibibytes of record around it. A bound under this would make a collection this client cannot
    // read at the size the service lets it grow to.
    let per_entry = (MAX_SYNC_OBJECT_PLAINTEXT_BYTES + SEAL_OVERHEAD_BYTES) * 4 / 3 + 8 * 1024;
    let comparison = 2 * SYNC_ANSWER_PAGE * per_entry;
    assert!(
        SYNC_ANSWER_LIMIT_BYTES >= comparison,
        "a comparison needs {comparison} bytes and the bound is {SYNC_ANSWER_LIMIT_BYTES}"
    );
    const {
        assert!(SYNC_ANSWER_LIMIT_BYTES > super::super::http::DEFAULT_RESPONSE_LIMIT_BYTES);
    }
}

#[test]
fn the_largest_exchange_fits_the_request_the_service_admits() {
    // The largest object a caller can hand over, sealed, as the request that would carry it.
    let largest = sealed(&vec![
        0x61;
        usize::try_from(MAX_SYNC_OBJECT_PLAINTEXT_BYTES - 16)
            .expect("a length")
    ]);
    assert_eq!(
        largest.size_bucket_bytes.get(),
        MAX_SYNC_OBJECT_PLAINTEXT_BYTES
    );
    let body = serde_json::to_vec(&SyncRequest::Exchange(ExchangeBody {
        request_id: identity(1),
        collection_id: SyncCollectionId::new(identity(2)),
        kind: SyncObjectKind::Settings,
        object_id: SyncObjectId::new(identity(2)),
        expected_revision: Some(revision(3)),
        object: &largest,
    }))
    .expect("a request");
    // A credential is a few hundred bytes. What matters is that the room left for it is ample.
    assert!(
        body.len() + 4 * 1024 < MAX_SYNC_REQUEST_BYTES,
        "the largest exchange is {} bytes",
        body.len()
    );
}

#[tokio::test]
async fn a_collection_this_crate_did_not_name_never_leaves_this_device() {
    let (client, recorder) = sync_client();
    // Letters as well as digits, so the upper-case spelling below differs from the canonical one.
    let object = identity(0xab);
    let bytes = published(&sealed(b"a setting"));

    for named in [
        // The spelling the synchronised half would give a draft, which it never asks for: drafts
        // are named by the draft store.
        format!("draft/{object}"),
        format!("backups/{object}"),
        format!("settings/{}", object.to_string().to_uppercase()),
        "settings/not-an-identity".to_owned(),
        "settings".to_owned(),
        String::new(),
    ] {
        let refused = client
            .compare_exchange(&named, identity(1), now_ms(), None, &bytes)
            .await
            .expect_err("that is not a collection settings sync names");
        assert_eq!(refused.code(), ErrorCode::InvalidArgument, "{named}");
        assert!(
            client.request_status(&named, identity(1)).await.is_err(),
            "{named}"
        );
        assert!(client.fetch(&named).await.is_err(), "{named}");
    }
    assert_eq!(recorder.requests(), 0, "nothing left this device");

    // The three names this crate does give a collection are the three it reads.
    for (named, kind) in [
        (settings_of(object), "settings"),
        (
            crate::sync::sync_collection(
                SyncObjectKind::ClientSelection,
                SyncObjectId::new(object),
            ),
            "client_selection",
        ),
        (
            crate::drafts::draft_collection(DraftId::new(object)),
            "draft",
        ),
    ] {
        recorder.answering(vec![exchanged(
            "written",
            summary(object, revision(9), "1"),
            Some(revision(9)),
            "1",
            serde_json::Value::Null,
        )]);
        client
            .compare_exchange(&named, identity(1), now_ms(), None, &bytes)
            .await
            .expect("a collection this crate names");
        let body = recorder.last_body();
        assert_eq!(body["exchange"]["kind"], kind);
        assert_eq!(body["exchange"]["object_id"], object.to_string());
        assert_eq!(
            body["exchange"]["collection_id"],
            object.to_string(),
            "one object, one collection: the collection is named by the object it holds"
        );
    }
}

#[tokio::test]
async fn an_exchange_carries_the_callers_identity_instant_and_object() {
    let (client, recorder) = sync_client();
    let object = identity(7);
    let request = identity(8);
    let signed_at = now_ms() - 1_000;
    let sealed_object = sealed(b"theme=dark");
    recorder.answering(vec![exchanged(
        "written",
        summary(object, revision(9), "4"),
        Some(revision(9)),
        "4",
        serde_json::Value::Null,
    )]);

    client
        .compare_exchange(
            &settings_of(object),
            request,
            signed_at,
            Some(SyncPosition::at(3, revision(3))),
            &published(&sealed_object),
        )
        .await
        .expect("applied");

    assert_eq!(
        recorder.last_url(),
        "https://reach.kala.to/api/sync/exchange"
    );
    let sent = recorder.last();
    assert_eq!(
        sent["signature"]["payload"]["method"],
        "sync.compare_exchange"
    );
    // The instant the caller recorded, and not a reading of this client's own clock.
    assert_eq!(
        sent["signature"]["payload"]["signed_at_ms"],
        serde_json::to_value(TimestampMs::new(signed_at)).expect("an instant")
    );
    let exchange = &sent["body"]["exchange"];
    assert_eq!(exchange["request_id"], request.to_string());
    // The revision, and only the revision: the place in the order beside it never travels.
    assert_eq!(exchange["expected_revision"], revision(3).to_string());
    assert_eq!(
        exchange["object"],
        serde_json::to_value(&sealed_object).expect("the object"),
        "the object the caller's sealer made, field for field"
    );
    assert_eq!(
        exchange.as_object().expect("members").len(),
        6,
        "an exchange carries its six members and nothing else"
    );

    // No position and a removal's position both name no object, and the comparison says so with
    // a revision that is present and null.
    for expected in [None, Some(SyncPosition::removed_at(5))] {
        client
            .compare_exchange(
                &settings_of(object),
                request,
                signed_at,
                expected,
                &published(&sealed_object),
            )
            .await
            .expect("applied");
        let body = recorder.last_body();
        assert!(
            body["exchange"]
                .as_object()
                .expect("members")
                .contains_key("expected_revision")
        );
        assert_eq!(
            body["exchange"]["expected_revision"],
            serde_json::Value::Null
        );
    }
}

#[tokio::test]
async fn the_same_attempt_made_twice_is_the_same_document_twice() {
    // The service answers a retry from its receipt when everything its digest covers is unchanged:
    // the collection, the kind, the object, the revision it expects and the sealed object. So the
    // body is a function of what the caller handed over and nothing else, and only the credential,
    // with its fresh nonce, differs between two attempts.
    let (client, recorder) = sync_client();
    let object = identity(7);
    let bytes = published(&sealed(b"theme=dark"));
    recorder.answering(vec![exchanged(
        "written",
        summary(object, revision(9), "1"),
        Some(revision(9)),
        "1",
        serde_json::Value::Null,
    )]);
    let signed_at = now_ms();

    let mut sent = Vec::new();
    for _ in 0..2 {
        client
            .compare_exchange(&settings_of(object), identity(8), signed_at, None, &bytes)
            .await
            .expect("answered");
        sent.push(recorder.last());
    }
    assert_eq!(sent[0]["body"], sent[1]["body"]);
    assert_ne!(
        sent[0]["signature"]["payload"]["nonce"], sent[1]["signature"]["payload"]["nonce"],
        "each attempt is its own signature"
    );
}

#[tokio::test]
async fn an_exchange_answer_is_passed_through_as_the_service_stated_it() {
    let (client, recorder) = sync_client();
    let object = identity(7);
    let bytes = published(&sealed(b"theme=dark"));
    let conflict = identity(0x44);

    let cases = [
        (
            exchanged(
                "written",
                summary(object, revision(9), "4"),
                Some(revision(9)),
                "4",
                serde_json::Value::Null,
            ),
            SyncExchanged::Applied {
                position: SyncPosition::at(4, revision(9)),
            },
        ),
        // A removal's place, and a place of nought, are passed through as they were stated. The
        // caller publishes writes and declines both; declining is its decision and not this one's.
        (
            exchanged(
                "removed",
                serde_json::Value::Null,
                None,
                "5",
                serde_json::Value::Null,
            ),
            SyncExchanged::Applied {
                position: SyncPosition::removed_at(5),
            },
        ),
        (
            exchanged(
                "written",
                summary(object, revision(9), "0"),
                Some(revision(9)),
                "0",
                serde_json::Value::Null,
            ),
            SyncExchanged::Applied {
                position: SyncPosition::at(0, revision(9)),
            },
        ),
        // A refusal is an answer, and it names the copy the service kept of the refused write.
        (
            exchanged(
                "conflict",
                summary(object, revision(4), "4"),
                Some(revision(4)),
                "4",
                copy_summary(object, conflict, revision(4)),
            ),
            SyncExchanged::Refused {
                retained: Some(SyncConflictId::new(conflict)),
            },
        ),
        (
            exchanged(
                "conflict",
                summary(object, revision(4), "4"),
                Some(revision(4)),
                "4",
                serde_json::Value::Null,
            ),
            SyncExchanged::Refused { retained: None },
        ),
    ];
    for (answer, expected) in cases {
        recorder.answering(vec![answer]);
        assert_eq!(
            client
                .compare_exchange(&settings_of(object), identity(8), now_ms(), None, &bytes)
                .await
                .expect("answered"),
            expected
        );
    }

    // A copy is of the refused write, so of this object. One of another object is a copy nothing
    // resolving this object may be pointed at, and the answer is not one this client reads.
    recorder.answering(vec![exchanged(
        "conflict",
        summary(object, revision(4), "4"),
        Some(revision(4)),
        "4",
        copy_summary(identity(0x55), conflict, revision(4)),
    )]);
    let unreadable = client
        .compare_exchange(&settings_of(object), identity(8), now_ms(), None, &bytes)
        .await
        .expect_err("a copy of another object");
    assert_eq!(unreadable.code(), ErrorCode::OutcomeUnknown);
}

#[tokio::test]
async fn a_status_answer_is_what_the_receipt_recorded() {
    let (client, recorder) = sync_client();
    let object = identity(7);
    let request = identity(8);
    let conflict = identity(0x44);

    let mut applied = status(request, "applied", false);
    applied["outcome"] = "written".into();
    applied["record"] = summary(object, revision(9), "4");
    applied["current_revision"] = revision(9).to_string().into();
    applied["current_write_sequence"] = "4".into();
    applied["recorded_at"] = "2026-09-23T10:00:00.000Z".into();

    let mut removed = status(request, "applied", false);
    removed["outcome"] = "removed".into();
    removed["current_write_sequence"] = "5".into();
    removed["recorded_at"] = "2026-09-23T10:00:00.000Z".into();

    let mut refused = status(request, "refused", false);
    refused["outcome"] = "conflict".into();
    refused["current_revision"] = revision(4).to_string().into();
    refused["current_write_sequence"] = "4".into();
    refused["conflict_id"] = conflict.to_string().into();
    refused["recorded_at"] = "2026-09-23T10:00:00.000Z".into();

    let mut fenced = status(request, "fenced", true);
    fenced["outcome"] = "fenced".into();
    fenced["recorded_at"] = "2026-09-23T10:00:00.000Z".into();
    let mut fenced_unvouched = fenced.clone();
    fenced_unvouched["never_ran"] = false.into();

    for (answer, expected) in [
        (
            applied,
            SyncRequestStatus::Applied {
                position: SyncPosition::at(4, revision(9)),
            },
        ),
        (
            removed,
            SyncRequestStatus::Applied {
                position: SyncPosition::removed_at(5),
            },
        ),
        (
            refused,
            SyncRequestStatus::Refused {
                retained: Some(SyncConflictId::new(conflict)),
            },
        ),
        (fenced, SyncRequestStatus::Fenced { never_ran: true }),
        (
            fenced_unvouched,
            SyncRequestStatus::Fenced { never_ran: false },
        ),
        (
            status(request, "unknown", false),
            SyncRequestStatus::Unknown,
        ),
    ] {
        recorder.answering(vec![answer]);
        assert_eq!(
            client
                .request_status(&settings_of(object), request)
                .await
                .expect("answered"),
            expected
        );
        assert_eq!(
            recorder.last_body(),
            serde_json::json!({
                "status": {
                    "collection_id": object.to_string(),
                    "request_id": request.to_string(),
                },
            })
        );
    }

    // A receipt of an applied write that names no place in the order is not one this client can
    // settle a request from.
    let mut placeless = status(request, "applied", false);
    placeless["outcome"] = "written".into();
    recorder.answering(vec![placeless]);
    assert_eq!(
        client
            .request_status(&settings_of(object), request)
            .await
            .expect_err("an applied write with no place")
            .code(),
        ErrorCode::OutcomeUnknown
    );
}

#[tokio::test]
async fn an_answer_that_does_not_say_whether_the_request_ran_is_an_error() {
    // Whether anything ran is the service's statement, and a missing one is not "no": the caller
    // would delete the account of an upload on the strength of a default this client made up.
    let (client, recorder) = sync_client();
    let object = identity(7);
    let request = identity(8);
    let mut silent = status(request, "fenced", true);
    silent.as_object_mut().expect("members").remove("never_ran");
    recorder.answering(vec![silent]);

    assert_eq!(
        client
            .request_status(&settings_of(object), request)
            .await
            .expect_err("a status answer that does not say")
            .code(),
        ErrorCode::OutcomeUnknown
    );
    let now = now_ms();
    assert_eq!(
        client
            .fence_request(&settings_of(object), request, now, now)
            .await
            .expect_err("a fence answer that does not say")
            .code(),
        ErrorCode::OutcomeUnknown
    );
}

#[tokio::test]
async fn a_fence_answered_unknown_is_an_error_rather_than_an_answer_invented_here() {
    // A fence finds an outcome or makes one, so "unknown" is never its answer, and the client has
    // no answer of its own to put in the place of one.
    let (client, recorder) = sync_client();
    let object = identity(7);
    let request = identity(8);
    recorder.answering(vec![status(request, "unknown", false)]);
    let now = now_ms();
    assert_eq!(
        client
            .fence_request(&settings_of(object), request, now, now)
            .await
            .expect_err("a fence never answers that")
            .code(),
        ErrorCode::OutcomeUnknown
    );
}

#[tokio::test]
async fn a_fence_names_both_signing_times_and_is_answered_as_the_service_states() {
    let (client, recorder) = sync_client();
    let object = identity(7);
    let request = identity(8);
    let (first, last) = (1_764_000_000_000, 1_764_000_090_000);

    let mut fenced = status(request, "fenced", true);
    fenced["outcome"] = "fenced".into();
    fenced["recorded_at"] = "2026-09-23T10:00:00.000Z".into();
    recorder.answering(vec![fenced]);
    assert_eq!(
        client
            .fence_request(&settings_of(object), request, first, last)
            .await
            .expect("fenced"),
        SyncRequestFence::Fenced { never_ran: true }
    );
    assert_eq!(
        recorder.last_body(),
        serde_json::json!({
            "fence": {
                "collection_id": object.to_string(),
                "request_id": request.to_string(),
                "first_signed_at_ms": first.to_string(),
                "last_signed_at_ms": last.to_string(),
            },
        })
    );

    // A request the service had already decided keeps its outcome, and the fence repeats it.
    let mut applied = status(request, "applied", false);
    applied["outcome"] = "written".into();
    applied["record"] = summary(object, revision(9), "4");
    applied["current_revision"] = revision(9).to_string().into();
    applied["current_write_sequence"] = "4".into();
    applied["recorded_at"] = "2026-09-23T10:00:00.000Z".into();
    recorder.answering(vec![applied]);
    assert_eq!(
        client
            .fence_request(&settings_of(object), request, first, last)
            .await
            .expect("answered"),
        SyncRequestFence::Applied {
            position: SyncPosition::at(4, revision(9)),
        }
    );
}

#[tokio::test]
async fn a_fence_whose_instants_the_service_would_refuse_never_leaves_this_device() {
    let (client, recorder) = sync_client();
    let object = identity(7);
    for (first, last) in [
        (2, 1),
        (1, MAX_SYNC_COUNTER + 1),
        (MAX_SYNC_COUNTER + 1, MAX_SYNC_COUNTER + 1),
    ] {
        assert_eq!(
            client
                .fence_request(&settings_of(object), identity(8), first, last)
                .await
                .expect_err("instants the service would refuse")
                .code(),
            ErrorCode::InvalidArgument
        );
    }
    assert_eq!(recorder.requests(), 0, "nothing left this device");
}

#[tokio::test]
async fn an_answer_about_another_request_identity_is_an_error() {
    let (client, recorder) = sync_client();
    let object = identity(7);
    recorder.answering(vec![status(identity(9), "unknown", false)]);
    assert_eq!(
        client
            .request_status(&settings_of(object), identity(8))
            .await
            .expect_err("an answer about another request")
            .code(),
        ErrorCode::OutcomeUnknown
    );
}

#[tokio::test]
async fn the_services_own_refusals_are_errors_that_say_what_they_are() {
    let (client, recorder) = sync_client();
    let object = identity(7);
    let bytes = published(&sealed(b"theme=dark"));

    // A fenced identity. Nothing ran under this attempt and nothing will, so it is never a
    // refusal of the comparison and never a conflict for a person to resolve: the device that
    // fenced the request settles it from the fence's own answer.
    recorder.answering_with(vec![refusal(
        409,
        "REQUEST_FENCED",
        "That settings-sync request identity has been fenced and will not be run.",
    )]);
    let fenced = client
        .compare_exchange(&settings_of(object), identity(8), now_ms(), None, &bytes)
        .await
        .expect_err("a fenced identity runs nothing");
    assert_eq!(fenced.code(), ErrorCode::PermissionDenied);
    assert_ne!(fenced.code(), ErrorCode::DraftConflict);
    assert_eq!(fenced.user_action(), UserAction::Nothing);
    assert_eq!(crate::retry::entry(fenced.code()).step, Step::Stop);
    assert!(fenced.to_string().contains("has been fenced"), "{fenced}");

    // Another request already wore the identity.
    recorder.answering_with(vec![refusal(
        409,
        "ID_CONFLICT",
        "That request identity was used for a different settings-sync exchange request.",
    )]);
    let taken = client
        .compare_exchange(&settings_of(object), identity(8), now_ms(), None, &bytes)
        .await
        .expect_err("the identity is another request's");
    assert_eq!(taken.code(), ErrorCode::IdConflict);
    assert_eq!(crate::retry::entry(taken.code()).step, Step::Stop);

    // A fence naming instants past what the service keeps a refusal for.
    recorder.answering_with(vec![refusal(
        400,
        "INVALID_ARGUMENT",
        "A fence names when it signed within the time this service keeps a refusal for.",
    )]);
    let now = now_ms();
    let out_of_reach = client
        .fence_request(&settings_of(object), identity(8), now, now)
        .await
        .expect_err("instants out of the service's reach");
    assert_eq!(out_of_reach.code(), ErrorCode::InvalidArgument);
    assert!(
        out_of_reach.to_string().contains("keeps a refusal for"),
        "the service's own message is what a person is shown: {out_of_reach}"
    );
}

#[tokio::test]
async fn a_sealed_object_the_service_would_refuse_never_leaves_this_device() {
    let (client, recorder) = sync_client();
    let object = identity(7);
    let well_formed = sealed(b"theme=dark");

    let mut undeclared = well_formed.clone();
    undeclared.size_bucket_bytes = U64::new(18 * 1024);
    let mut mislength = well_formed.clone();
    mislength.ciphertext = Bytes::new(vec![0; 10]);
    let mut too_large = well_formed.clone();
    too_large.size_bucket_bytes =
        U64::new(mailbox_size_bucket(MAX_SYNC_OBJECT_PLAINTEXT_BYTES + 1));

    for bytes in [
        published(&undeclared),
        published(&mislength),
        published(&too_large),
        b"not a sealed object".to_vec(),
    ] {
        assert_eq!(
            client
                .compare_exchange(&settings_of(object), identity(8), now_ms(), None, &bytes)
                .await
                .expect_err("a sealed object the service would refuse")
                .code(),
            ErrorCode::InvalidArgument
        );
    }
    assert_eq!(recorder.requests(), 0, "nothing left this device");
}

#[tokio::test]
async fn an_attempt_signed_outside_the_window_never_leaves_this_device() {
    let (client, recorder) = sync_client();
    let object = identity(7);
    let bytes = published(&sealed(b"theme=dark"));
    let now = now_ms();

    // The service admits a signature within its window of its own clock either side, so an attempt
    // this device signed well before or well after its own clock reads now is refused here: it
    // would be refused there, and nothing re-dates an attempt.
    for signed_at in [
        now - 2 * SERVICE_REQUEST_FRESHNESS_MS,
        now + 2 * SERVICE_REQUEST_FRESHNESS_MS,
    ] {
        assert_eq!(
            client
                .compare_exchange(&settings_of(object), identity(8), signed_at, None, &bytes)
                .await
                .expect_err("an attempt outside the window")
                .code(),
            ErrorCode::ClockUntrusted
        );
    }
    assert_eq!(recorder.requests(), 0, "nothing left this device");
}

/// What a comparison is answered with: the objects and copies given.
fn compared(
    changed: Vec<serde_json::Value>,
    conflicts: Vec<serde_json::Value>,
) -> serde_json::Value {
    serde_json::json!({
        "changed": changed,
        "removed": [],
        "revisions": [],
        "conflicts": conflicts,
        "next_conflicts_after_sequence": "0",
        "more_conflicts": false,
        "stored": usage(),
    })
}

fn held(
    object: Uuid,
    revision: SyncRevision,
    write_sequence: &str,
    sealed: &SealedSyncObject,
) -> serde_json::Value {
    serde_json::json!({
        "kind": "settings",
        "object_id": object.to_string(),
        "revision": revision.to_string(),
        "write_sequence": write_sequence,
        "object": sealed,
        "updated_at": "2026-09-23T10:00:00.000Z",
    })
}

#[tokio::test]
async fn a_fetch_is_the_object_and_the_place_the_service_states() {
    let (client, recorder) = sync_client();
    let object = identity(7);
    let theirs = sealed(b"theme=light");
    recorder.answering(vec![compared(
        vec![held(object, revision(9), "4", &theirs)],
        Vec::new(),
    )]);

    let (position, ciphertext) = client.fetch(&settings_of(object)).await.expect("fetched");
    assert_eq!(position, SyncPosition::at(4, revision(9)));
    assert_eq!(
        ciphertext,
        published(&theirs),
        "the bytes a sealer opens, encoded as a sealer encodes them"
    );
    assert_eq!(
        recorder.last_body(),
        serde_json::json!({
            "compare": {
                "collection_id": object.to_string(),
                "kind": "settings",
                "with_conflicts": false,
            },
        }),
        "a read for the one kind the name says"
    );

    // A collection holding nothing of that kind has nothing to fetch.
    recorder.answering(vec![compared(Vec::new(), Vec::new())]);
    assert_eq!(
        client
            .fetch(&settings_of(object))
            .await
            .expect_err("nothing is held")
            .code(),
        ErrorCode::UnknownSession
    );
}

#[tokio::test]
async fn a_comparison_reads_every_copy_with_where_the_object_stood() {
    let (client, recorder) = sync_client();
    let object = identity(7);
    let mine = sealed(b"theme=dark");
    let theirs = sealed(b"theme=light");
    let copy = |conflict: u8, current_revision: &str, current_write_sequence: &str| {
        serde_json::json!({
            "sequence": conflict.to_string(),
            "conflict_id": identity(conflict).to_string(),
            "kind": "settings",
            "object_id": object.to_string(),
            "expected_revision": null,
            "current_revision": current_revision,
            "current_write_sequence": current_write_sequence,
            "object": mine,
            "recorded_at": "2026-09-23T10:00:00.000Z",
        })
    };
    recorder.answering(vec![compared(
        vec![held(object, revision(9), "4", &theirs)],
        vec![
            copy(1, &revision(9).to_string(), "4"),
            copy(2, "", "6"),
            copy(3, "", "0"),
        ],
    )]);

    let comparison = client
        .compare(&settings_of(object), true, Some(0))
        .await
        .expect("compared");
    assert_eq!(comparison.objects.len(), 1);
    assert_eq!(
        comparison.objects[0].position,
        SyncPosition::at(4, revision(9))
    );
    assert_eq!(
        comparison
            .copies
            .iter()
            .map(|copy| (copy.conflict_id, copy.current))
            .collect::<Vec<_>>(),
        vec![
            (
                SyncConflictId::new(identity(1)),
                Some(SyncPosition::at(4, revision(9)))
            ),
            // Refused while the object was removed: the removal's place, with no revision.
            (
                SyncConflictId::new(identity(2)),
                Some(SyncPosition::removed_at(6))
            ),
            // Refused while the collection had never held the object: no position at all.
            (SyncConflictId::new(identity(3)), None),
        ]
    );
    assert_eq!(comparison.copies[0].ciphertext, published(&mine));
    assert_eq!(
        recorder.last_body(),
        serde_json::json!({
            "compare": {
                "collection_id": object.to_string(),
                "with_conflicts": true,
                "conflicts_after_sequence": "0",
            },
        })
    );
}

#[tokio::test]
async fn a_rendering_of_the_service_these_tests_send_to_carries_none_of_what_it_was_sent() {
    let (client, recorder) = sync_client();
    let object = identity(7);
    recorder.answering(vec![exchanged(
        "written",
        summary(object, revision(9), "1"),
        Some(revision(9)),
        "1",
        serde_json::Value::Null,
    )]);
    client
        .compare_exchange(
            &settings_of(object),
            identity(8),
            now_ms(),
            None,
            &published(&sealed(NEVER_RENDERED.as_bytes())),
        )
        .await
        .expect("one request to render");
    renders_only(recorder.as_ref(), "Recorder{requests:1,..}");
}

#[test]
fn a_rendering_of_a_request_an_object_or_a_copy_carries_nothing_sealed() {
    let mut object = sealed(NEVER_RENDERED.as_bytes());
    object.nonce = Nonce192::from_bytes([0x7e; 24]);

    renders_only(
        &ExchangeBody {
            request_id: identity(1),
            collection_id: SyncCollectionId::new(identity(2)),
            kind: SyncObjectKind::Settings,
            object_id: SyncObjectId::new(identity(2)),
            expected_revision: Some(revision(3)),
            object: &object,
        },
        "ExchangeBody{kind:Settings,size_bucket_bytes:U64(1024),expects_an_object:true,..}",
    );

    let ciphertext = published(&object);
    let held = SyncHeldObject {
        object_id: SyncObjectId::new(identity(2)),
        kind: SyncObjectKind::Settings,
        position: SyncPosition::at(4, revision(9)),
        ciphertext: ciphertext.clone(),
    };
    renders_only(
        &held,
        &format!(
            "SyncHeldObject{{object_id:{:?},kind:Settings,position:{:?},..}}",
            held.object_id, held.position
        )
        .replace(' ', ""),
    );

    let copy = SyncHeldCopy {
        sequence: 3,
        conflict_id: SyncConflictId::new(identity(4)),
        object_id: SyncObjectId::new(identity(2)),
        kind: SyncObjectKind::Settings,
        expected_revision: Nullable::null(),
        current: Some(SyncPosition::at(4, revision(9))),
        ciphertext,
    };
    renders_only(
        &copy,
        &format!(
            "SyncHeldCopy{{sequence:3,conflict_id:{:?},object_id:{:?},kind:Settings,current:{:?},..}}",
            copy.conflict_id, copy.object_id, copy.current
        )
        .replace(' ', ""),
    );

    // The nonce travels beside the ciphertext and is part of what is sealed. The renderings above
    // are held to exact fields, and this is the marker check that goes with them.
    for rendering in [format!("{held:?}"), format!("{copy:#?}")] {
        assert!(!rendering.contains("126"), "{rendering}");
        assert!(!rendering.contains("7e"), "{rendering}");
    }
}
