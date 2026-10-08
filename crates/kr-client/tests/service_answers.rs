//! What the managed storage service and the backup manifest answer, and what the stand-in the
//! daemon's tests talk to answers, held to one recording.
//!
//! The Worker in the web repository is what answers in production. A stand-in written in this
//! repository answers as the contract is read here, and a test that runs against it proves nothing
//! about the Worker where the two differ. So one script of requests, made by this crate's own
//! clients, was run against a Worker on this machine, and what it answered is recorded in
//! `fixtures/service/storage-answers.json`: for each request, the HTTP status, and the answer's
//! shape, which is its members and their types, with the words that decide what a caller does
//! (the error code, the state, whether backup is on) kept as they were. [`the_stand_in_answers_as_
//! the_worker_did`] runs the same script against the stand-in and holds each answer to its record.
//!
//! The recording is made again when the service's contract changes, by running
//! [`record_a_local_workers_answers`] against a local deployment:
//!
//! ```text
//! node infra/scripts/testing/local-restore.mjs start   --state <dir> --name first --port <port>
//! node infra/scripts/testing/local-restore.mjs sign-in --state <dir> --name first --tokens <file>
//! KR_DEPLOYED_ORIGIN=http://127.0.0.1:<port> KR_BACKUP_TOKENS=<file> \
//!   KR_RECORD_SERVICE_ANSWERS=fixtures/service/storage-answers.json \
//!   KR_WEB_COMMIT=<the web commit> cargo test -p kr-client --test service_answers record
//! ```

use std::sync::{Arc, Mutex};

use kr_client::error::ClientError;
use kr_client::services::account::{AccountToken, AccountTokenSource};
use kr_client::services::{
    BackupManifestService, BackupState, HttpDeadlines, HttpService, ManagedBackupManifestService,
    ManagedStorageService, NewUpload, PartTable, RetentionChange, ServiceFuture, ServiceHttp,
    ServiceHttpAnswer, ServiceSigner, StorageService, UploadProgress, managed_response_limits,
    upload_parts,
};
use kr_crypto::backup::{
    ArchivePlan, ArchiveRecipients, CollectionKind, KeyRotation, ObjectSource, seal_archive,
    stage_object,
};
use kr_crypto::keys::{AuthorisationKeyPair, StoredEnvelopeKeyPair};
use kr_crypto::sign::{SigningTranscript, sign};
use kr_protocol::archive::{
    BACKUP_PUBLICATION_DOMAIN, BACKUP_WRITER_DOMAIN, BackupGenerationPublication,
    BackupGenerationPublicationPayload, BackupWriterRecord, BackupWriterRecordPayload,
    TrustedWriter,
};
use kr_protocol::ids::{
    ArchiveId, BackupGeneration, BackupObjectId, BackupWriterRevision, DeviceId,
};
use kr_protocol::scalars::{AuthorisationKey, Digest256, Signature64, TimestampMs, Uuid};
use kr_protocol::service::{GatewayOrigin, ServiceRequestSigner};
use kr_service_stand_in::{StorageWeb, TOKEN};

const FIXTURE: &str = include_str!("../../../fixtures/service/storage-answers.json");

/// The words of an answer that decide what a caller does with it, which a shape keeps verbatim.
const DECISIVE: [&str; 5] = ["code", "state", "backup", "reason", "ok"];

/* -------------------------------------------------------------------------- */
/* The transport that records                                                  */
/* -------------------------------------------------------------------------- */

/// One answer, as it came back.
#[derive(Clone, Debug)]
struct Exchange {
    step: String,
    path: String,
    status: u16,
    body: Vec<u8>,
}

/// A transport that passes every request on and keeps every answer.
#[derive(Debug)]
struct Recording {
    inner: Arc<dyn ServiceHttp>,
    origin: String,
    step: Mutex<String>,
    log: Mutex<Vec<Exchange>>,
}

impl Recording {
    fn new(inner: Arc<dyn ServiceHttp>, origin: &str) -> Arc<Self> {
        Arc::new(Self {
            inner,
            origin: origin.to_owned(),
            step: Mutex::default(),
            log: Mutex::default(),
        })
    }

    /// Names what the requests that follow are for.
    fn step(&self, name: &str) {
        *self.step.lock().expect("the step") = name.to_owned();
    }

    fn keep(&self, url: &str, answer: &ServiceHttpAnswer) {
        self.log.lock().expect("the log").push(Exchange {
            step: self.step.lock().expect("the step").clone(),
            path: url.strip_prefix(&self.origin).unwrap_or(url).to_owned(),
            status: answer.status,
            body: answer.body.clone(),
        });
    }

    fn exchanges(&self) -> Vec<Exchange> {
        self.log.lock().expect("the log").clone()
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
            let answer = self.inner.post_json(url, body, headers).await?;
            self.keep(url, &answer);
            Ok(answer)
        })
    }

    fn post_bytes<'a>(
        &'a self,
        url: &'a str,
        body: &'a [u8],
        headers: &'a [(&'a str, &'a str)],
    ) -> ServiceFuture<'a, ServiceHttpAnswer> {
        Box::pin(async move {
            let answer = self.inner.post_bytes(url, body, headers).await?;
            self.keep(url, &answer);
            Ok(answer)
        })
    }
}

/* -------------------------------------------------------------------------- */
/* The keys, and the account                                                   */
/* -------------------------------------------------------------------------- */

/// An installation's key, or a host's, signing as it is.
#[derive(Debug)]
struct Keyed {
    key: AuthorisationKeyPair,
    signer: ServiceRequestSigner,
}

impl ServiceSigner for Keyed {
    fn signer(&self) -> ServiceRequestSigner {
        self.signer
    }

    fn public_key(&self) -> AuthorisationKey {
        *self.key.public()
    }

    fn sign(&self, message: &[u8]) -> kr_client::Result<Signature64> {
        let transcript =
            SigningTranscript::from_canonical_bytes(self.signer.domain(), message.to_vec())
                .expect("a transcript");
        Ok(sign(&self.key, &transcript).expect("a signature"))
    }
}

/// An account token, as a source hands it over.
#[derive(Debug)]
struct Bearer(String);

impl AccountTokenSource for Bearer {
    fn token<'a>(&'a self, _scope: &'a str) -> ServiceFuture<'a, AccountToken> {
        let token = AccountToken::new(self.0.clone());
        Box::pin(async move { token })
    }
}

fn keyed(signer: ServiceRequestSigner) -> Arc<Keyed> {
    Arc::new(Keyed {
        key: AuthorisationKeyPair::generate().expect("a key"),
        signer,
    })
}

/* -------------------------------------------------------------------------- */
/* The script                                                                  */
/* -------------------------------------------------------------------------- */

/// A lower-case hyphenated identifier of a fresh random object.
fn fresh_uuid() -> Uuid {
    kr_transport::random::fresh_uuid_v4().expect("a fresh identifier")
}

/// Runs the script against one service.
///
/// Every request is made by this crate's own clients, as a host and an owner make them, and every
/// answer is kept by `http`. Whatever a step expects it does not assert: what each answer was is
/// the record's to say, and the stand-in is held to it afterwards.
async fn run_the_script(http: &Arc<Recording>, origin: &GatewayOrigin, account_token: &str) {
    let owner = keyed(ServiceRequestSigner::Installation);
    let writer = keyed(ServiceRequestSigner::Host);
    let service: Arc<dyn ServiceHttp> = Arc::clone(http) as _;
    let storage = |signer: &Arc<Keyed>, token: &str| {
        ManagedStorageService::new(
            origin.clone(),
            Arc::clone(&service),
            Arc::clone(signer) as _,
        )
        .presenting(Arc::new(Bearer(token.to_owned())))
    };
    let manifest = |signer: &Arc<Keyed>, token: &str| {
        ManagedBackupManifestService::new(
            origin.clone(),
            Arc::clone(&service),
            Arc::clone(signer) as _,
        )
        .presenting(Arc::new(Bearer(token.to_owned())))
    };

    let archive = ArchiveId::new(fresh_uuid());
    let object = BackupObjectId::new(fresh_uuid());

    // The account.
    http.step("status of a token the service did not issue");
    let _ = storage(&writer, "not-a-token-this-service-issued")
        .status()
        .await;
    http.step("status with the account");
    let status = storage(&writer, account_token)
        .status()
        .await
        .expect("a status");
    http.step("turn backup storage on");
    let _ = storage(&writer, account_token)
        .set_retention(&RetentionChange {
            backup: BackupState::On,
            daily_snapshots: None,
            expected_revision: status.retention_revision,
        })
        .await;
    http.step("turn backup storage on against a revision it has left");
    let _ = storage(&writer, account_token)
        .set_retention(&RetentionChange {
            backup: BackupState::On,
            daily_snapshots: Some(7),
            expected_revision: status.retention_revision,
        })
        .await;
    http.step("status after the change");
    let _ = storage(&writer, account_token).status().await;

    // One object, in one part.
    let ciphertext: Vec<u8> = (0..1000_u32)
        .map(|at| u8::try_from(at % 251).expect("a byte"))
        .collect();
    let upload = NewUpload {
        archive_id: archive,
        object_id: object,
        backup_generation: BackupGeneration::new(1),
        declared_max_bytes: ciphertext.len() as u64,
        total_bytes: ciphertext.len() as u64,
        encrypted_object_hash: Digest256::from_bytes(kr_cbor::sha256(&ciphertext)),
    };
    let host = storage(&writer, account_token);
    http.step("create an upload");
    let created = host.create_upload(&upload).await;
    http.step("create it again while it is open");
    let _ = host.create_upload(&upload).await;
    if let Ok(kr_client::services::ArchiveAnswer::Done(created)) = created {
        let mut progress: UploadProgress = created.progress();
        http.step("send a part");
        let _ = upload_parts(&host, &mut progress, &ciphertext, &mut |_| Ok(())).await;
        http.step("send it again");
        progress.parts_acknowledged = 0;
        let _ = upload_parts(&host, &mut progress, &ciphertext, &mut |_| Ok(())).await;
        http.step("complete the upload");
        let table = PartTable::for_total(ciphertext.len() as u64).expect("a part table");
        let _ = host.complete_upload(&progress.upload_id, &table).await;
        http.step("complete it again");
        let _ = host.complete_upload(&progress.upload_id, &table).await;
    }
    http.step("read the object");
    let _ = host.read_object(archive, object, 0, 100).await;
    http.step("read past its end");
    let _ = host.read_object(archive, object, 5_000, 100).await;

    // The manifest.
    let device = StoredEnvelopeKeyPair::generate().expect("a device key");
    let sender = StoredEnvelopeKeyPair::generate().expect("a producer key");
    let staged = stage_object(
        &ObjectSource {
            object_id: object,
            filename: "notes.txt",
            plaintext: b"the notes",
        },
        KeyRotation::INITIAL,
    )
    .expect("a staged object");
    let mut recipients = ArchiveRecipients::new(CollectionKind::Owned);
    assert!(recipients.add(*device.public()));
    let sealed = seal_archive(
        &writer.key,
        &sender,
        &recipients,
        &ArchivePlan {
            archive_id: archive,
            backup_generation: BackupGeneration::new(1),
            owner_device_id: DeviceId::new(Uuid::from_bytes([0x33; 16])),
            manifest_object_id: BackupObjectId::new(fresh_uuid()),
            created_at_ms: TimestampMs::new(1_700_000_000_000),
        },
        &[staged],
    )
    .expect("a sealed archive");
    let payload = BackupGenerationPublicationPayload {
        descriptor: sealed.descriptor.clone(),
        writer_key_id: writer.key.key_id(),
        published_at_ms: TimestampMs::new(2_000),
    };
    let publication = BackupGenerationPublication {
        signature: sign(
            &writer.key,
            &SigningTranscript::from_canonical_bytes(
                BACKUP_PUBLICATION_DOMAIN,
                payload.signing_input().expect("a publication input"),
            )
            .expect("a transcript"),
        )
        .expect("a signature"),
        payload,
    };
    let enrolment = |revision: u64| {
        let payload = BackupWriterRecordPayload {
            archive_id: archive,
            writer: TrustedWriter {
                writer_key_id: writer.key.key_id(),
                signing_key: *writer.key.public(),
                enrolled_at_ms: TimestampMs::new(1_000),
            },
            writer_revision: BackupWriterRevision::new(revision),
            owner_key_id: owner.key.key_id(),
            enrolled_at_ms: TimestampMs::new(1_000),
        };
        let signature = sign(
            &owner.key,
            &SigningTranscript::from_canonical_bytes(
                BACKUP_WRITER_DOMAIN,
                payload.signing_input().expect("an enrolment input"),
            )
            .expect("a transcript"),
        )
        .expect("a signature");
        BackupWriterRecord { payload, signature }
    };
    http.step("publish before any writer is enrolled");
    let _ = manifest(&writer, account_token).publish(&publication).await;
    http.step("enrol the writer");
    let _ = manifest(&owner, account_token).enrol(&enrolment(1)).await;
    http.step("enrol the same writer again");
    let _ = manifest(&owner, account_token).enrol(&enrolment(1)).await;
    http.step("publish a generation");
    let _ = manifest(&writer, account_token).publish(&publication).await;
    http.step("publish it again");
    let _ = manifest(&writer, account_token).publish(&publication).await;
    http.step("publish a generation with no account");
    let _ = manifest(&writer, "not-a-token-this-service-issued")
        .publish(&publication)
        .await;
    http.step("fetch the newest generation");
    let _ = manifest(&writer, account_token)
        .fetch(archive, None, None)
        .await;
    http.step("fetch a generation that is not held");
    let _ = manifest(&writer, account_token)
        .fetch(archive, Some(BackupGeneration::new(9)), None)
        .await;
    http.step("fetch an archive that is not held");
    let _ = manifest(&writer, account_token)
        .fetch(ArchiveId::new(fresh_uuid()), None, None)
        .await;

    // Deleting the object.
    http.step("delete the object");
    let _ = host.delete_object(archive, object).await;
    http.step("delete it again");
    let _ = host.delete_object(archive, object).await;
    http.step("delete an object that is not held");
    let _ = host
        .delete_object(archive, BackupObjectId::new(fresh_uuid()))
        .await;
}

/* -------------------------------------------------------------------------- */
/* Shapes                                                                      */
/* -------------------------------------------------------------------------- */

/// The shape of one JSON value: members and types, with the decisive words kept.
fn shape(key: &str, value: &serde_json::Value) -> serde_json::Value {
    use serde_json::Value;
    match value {
        Value::Object(members) => Value::Object(
            members
                .iter()
                .map(|(name, member)| (name.clone(), shape(name, member)))
                .collect(),
        ),
        Value::Array(items) => serde_json::json!({
            "array": items.first().map_or(Value::Null, |first| shape(key, first)),
        }),
        Value::String(text) if DECISIVE.contains(&key) => Value::String(text.clone()),
        Value::Bool(flag) if DECISIVE.contains(&key) => Value::Bool(*flag),
        Value::String(_) => Value::String("string".to_owned()),
        Value::Number(_) => Value::String("number".to_owned()),
        Value::Bool(_) => Value::String("boolean".to_owned()),
        Value::Null => Value::String("null".to_owned()),
    }
}

/// An answer's shape, or the word for an answer that is content and not a document.
fn shape_of(exchange: &Exchange) -> serde_json::Value {
    serde_json::from_slice::<serde_json::Value>(&exchange.body).map_or_else(
        |_| serde_json::json!("content"),
        |document| shape("", &document),
    )
}

fn recorded(exchanges: &[Exchange], web_commit: &str) -> serde_json::Value {
    serde_json::json!({
        "recorded_from": "a Worker on this machine, started by infra/scripts/testing/local-restore.mjs",
        "web_commit": web_commit,
        "exchanges": exchanges.iter().map(|exchange| serde_json::json!({
            "step": exchange.step,
            "path": exchange.path,
            "status": exchange.status,
            "shape": shape_of(exchange),
        })).collect::<Vec<_>>(),
    })
}

/* -------------------------------------------------------------------------- */
/* The two runs                                                                */
/* -------------------------------------------------------------------------- */

/// The stand-in answers the script as the Worker did.
#[tokio::test]
async fn the_stand_in_answers_as_the_worker_did() {
    let held: serde_json::Value = serde_json::from_str(FIXTURE).expect("the recording");
    let web = Arc::new(StorageWeb::new());
    let origin = GatewayOrigin::new(web.origin()).expect("an origin");
    let http = Recording::new(Arc::clone(&web) as _, web.origin());
    run_the_script(&http, &origin, TOKEN).await;
    let ran = recorded(&http.exchanges(), "");

    let held = held["exchanges"].as_array().expect("recorded exchanges");
    let ran = ran["exchanges"].as_array().expect("exchanges");
    let mut differences = Vec::new();
    for (index, held) in held.iter().enumerate() {
        match ran.get(index) {
            Some(ran) if ran["step"] == held["step"] && ran["path"] == held["path"] => {
                for member in ["status", "shape"] {
                    if ran[member] != held[member] {
                        differences.push(format!(
                            "{}: {member} was {} and the Worker's was {}",
                            held["step"], ran[member], held[member]
                        ));
                    }
                }
            }
            other => differences.push(format!(
                "{}: the stand-in made {other:?} where the Worker was asked {}",
                held["step"], held["path"]
            )),
        }
    }
    if ran.len() > held.len() {
        differences.push(format!(
            "the stand-in answered {} requests and the recording holds {}",
            ran.len(),
            held.len()
        ));
    }
    assert!(
        differences.is_empty(),
        "the stand-in differs from the recording:\n{}",
        differences.join("\n")
    );
}

/// Runs the script against a local Worker and writes what it answered.
///
/// It runs only when it is told where to write and which Worker to ask, so an ordinary run of this
/// workspace asks nothing of any service.
#[tokio::test]
async fn record_a_local_workers_answers() {
    let (Some(path), Some(origin), Some(tokens)) = (
        std::env::var_os("KR_RECORD_SERVICE_ANSWERS"),
        std::env::var("KR_DEPLOYED_ORIGIN").ok(),
        std::env::var_os("KR_BACKUP_TOKENS"),
    ) else {
        eprintln!("skipping: nothing names a Worker to record, so nothing was sent anywhere");
        return;
    };
    let tokens: serde_json::Value =
        serde_json::from_slice(&std::fs::read(tokens).expect("the tokens file")).expect("tokens");
    let token = tokens[&origin]["write"]
        .as_str()
        .expect("a backup.write token for this origin")
        .to_owned();
    let gateway = GatewayOrigin::new(origin.clone()).expect("an origin");
    let transport: Arc<dyn ServiceHttp> = Arc::new(
        HttpService::with(
            gateway.clone(),
            HttpDeadlines::default(),
            managed_response_limits(),
        )
        .expect("a transport"),
    );
    let http = Recording::new(transport, &origin);
    run_the_script(&http, &gateway, &token).await;
    let commit = std::env::var("KR_WEB_COMMIT").unwrap_or_else(|_| "not stated".to_owned());
    let mut text =
        serde_json::to_string_pretty(&recorded(&http.exchanges(), &commit)).expect("a recording");
    text.push('\n');
    std::fs::write(path, text).expect("the recording is written");
}

#[allow(
    dead_code,
    reason = "named so a refusal from the transport reads as one"
)]
fn refused(_: &ClientError) {}
