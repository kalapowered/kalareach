//! What the managed storage service and the backup manifest answer, what this crate's clients
//! make of it, and what the stand-in the daemon's tests talk to answers, held to one recording.
//!
//! The Worker in the web repository is what answers in production. A stand-in written in this
//! repository answers as the contract is read here, and a test that runs against it proves nothing
//! about the Worker where the two differ. So one script of requests, made by this crate's own
//! clients, was run against a Worker on this machine, and `fixtures/service/storage-answers.json`
//! keeps, for each request, the status and the body the Worker answered (a body that is content and
//! not a document is kept as its bytes), and for each step what the client decoded it to.
//!
//! Two tests hold the recording to the code that reads it and to the stand-in:
//!
//! * [`the_clients_decode_what_the_worker_answered`] replays the recorded bodies through the
//!   clients and asserts what they decode to. A change to a reader that no longer reads what the
//!   Worker says fails there, with no stand-in between.
//! * [`the_stand_in_answers_as_the_worker_did`] runs the same script against the stand-in and holds
//!   each answer's status, its shape (members and types) and what the client decoded it to against
//!   the record, so every value that decides what a caller does is held: the error code, the delay
//!   a refusal names, the state a write reports, the checkpoint, the generations held, and what
//!   an object's usage is.
//!
//! The recording is made again when the service's contract changes, by running
//! [`record_a_local_workers_answers`] against a local deployment:
//!
//! ```text
//! node infra/scripts/testing/local-restore.mjs start   --state <dir> --name first --port <port>
//! node infra/scripts/testing/local-restore.mjs sign-in --state <dir> --name first --tokens <file>
//! KR_DEPLOYED_ORIGIN=http://127.0.0.1:<port> KR_BACKUP_TOKENS=<file> \
//!   KR_RECORD_SERVICE_ANSWERS=fixtures/service/storage-answers.json \
//!   KR_WEB_COMMIT=<the web commit> cargo test -p kr-client --test service_answers record -- --ignored
//! ```
//!
//! What a local Worker cannot be made to do is not in the script: a refusal that names a delay
//! (`RATE_LIMITED`, `SERVICE_UNAVAILABLE`), a part whose write storage does not confirm, a
//! collection deleted from the account console, and a new generation published with no account's
//! proof, which a deployment answers `QUOTA_EXHAUSTED` unless its free tier includes backup
//! storage, as a local deployment's does. The stand-in's answers for those are read from the
//! contract and the Worker's source, and the table in the stand-in crate's documentation names the
//! line of each.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use base64::Engine as _;
use kr_client::error::ClientError;
use kr_client::services::account::{AccountToken, AccountTokenSource};
use kr_client::services::{
    BackupManifestService, BackupState, HttpDeadlines, HttpService, ManagedBackupManifestService,
    ManagedStorageService, NewUpload, PartTable, RetentionChange, ServiceFuture, ServiceHttp,
    ServiceHttpAnswer, ServiceSigner, StorageService, UploadId, UploadProgress,
    managed_response_limits, upload_parts,
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
use kr_protocol::pairing::GenerationCheckpoint;
use kr_protocol::scalars::{AuthorisationKey, Digest256, Signature64, TimestampMs, Uuid};
use kr_protocol::service::{GatewayOrigin, ServiceRequestSigner};
use kr_service_stand_in::{StorageWeb, TOKEN};

const FIXTURE: &str = include_str!("../../../fixtures/service/storage-answers.json");

/// The words of an answer that decide what a caller does with it, which a shape keeps verbatim.
const DECISIVE: [&str; 5] = ["code", "state", "backup", "reason", "ok"];

/* -------------------------------------------------------------------------- */
/* What a run keeps                                                            */
/* -------------------------------------------------------------------------- */

/// One answer, as it came back.
#[derive(Clone, Debug)]
struct Exchange {
    step: String,
    path: String,
    status: u16,
    body: Vec<u8>,
}

/// What the script did, step by step.
#[derive(Debug, Default)]
struct Journal {
    step: Mutex<String>,
    exchanges: Mutex<Vec<Exchange>>,
    outcomes: Mutex<Vec<(String, String)>>,
    /// What this run made afresh that an answer repeats, in the order it was made: the identifiers
    /// of the keys it signed with, and the hash of each manifest it sealed, as an answer writes
    /// them.
    names: Mutex<Vec<String>>,
}

impl Journal {
    /// Keeps something this run made afresh that an answer may repeat.
    fn name(&self, text: String) {
        self.names.lock().expect("the names").push(text);
    }

    /// Names what the requests that follow are for.
    fn step(&self, name: &str) {
        *self.step.lock().expect("the step") = name.to_owned();
    }

    /// Keeps what the client made of the answers to the step in hand.
    fn decoded(&self, outcome: String) {
        let step = self.step.lock().expect("the step").clone();
        self.outcomes
            .lock()
            .expect("the outcomes")
            .push((step, outcome));
    }

    fn exchanges(&self) -> Vec<Exchange> {
        self.exchanges.lock().expect("the exchanges").clone()
    }

    fn outcomes(&self) -> Vec<(String, String)> {
        self.outcomes.lock().expect("the outcomes").clone()
    }
}

/// A transport that passes every request on and keeps every answer.
#[derive(Debug)]
struct Recording {
    inner: Arc<dyn ServiceHttp>,
    origin: String,
    journal: Arc<Journal>,
}

impl Recording {
    fn keep(&self, url: &str, answer: &ServiceHttpAnswer) {
        self.journal
            .exchanges
            .lock()
            .expect("the exchanges")
            .push(Exchange {
                step: self.journal.step.lock().expect("the step").clone(),
                path: url.strip_prefix(&self.origin).unwrap_or(url).to_owned(),
                status: answer.status,
                body: answer.body.clone(),
            });
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

/// A transport that answers each request with the next answer the recording holds, whatever the
/// request said, once it has checked that the request is to the path the recording expects.
///
/// A key and an encrypted manifest are made afresh for each run, so an answer that names what the
/// recording made is given back naming what this run made in its place, and nothing else of it is
/// changed.
#[derive(Debug)]
struct Replaying {
    answers: Mutex<VecDeque<Exchange>>,
    recorded_names: Vec<String>,
    journal: Arc<Journal>,
}

impl Replaying {
    fn answer(&self, url: &str) -> ServiceHttpAnswer {
        let next = self
            .answers
            .lock()
            .expect("the answers")
            .pop_front()
            .unwrap_or_else(|| panic!("the client made a request to {url} the recording lacks"));
        assert!(
            url.ends_with(&next.path),
            "the client asked {url} where the recording expects {} for {}",
            next.path,
            next.step
        );
        let mut body = String::from_utf8_lossy(&next.body).into_owned();
        for (recorded, now) in self
            .recorded_names
            .iter()
            .zip(self.journal.names.lock().expect("the names").iter())
        {
            body = body.replace(recorded, now);
        }
        ServiceHttpAnswer {
            status: next.status,
            body: if next.body.is_ascii() {
                body.into_bytes()
            } else {
                next.body
            },
        }
    }
}

impl ServiceHttp for Replaying {
    fn post_json<'a>(
        &'a self,
        url: &'a str,
        _body: &'a [u8],
        _headers: &'a [(&'a str, &'a str)],
    ) -> ServiceFuture<'a, ServiceHttpAnswer> {
        Box::pin(async move { Ok(self.answer(url)) })
    }

    fn post_bytes<'a>(
        &'a self,
        url: &'a str,
        _body: &'a [u8],
        _headers: &'a [(&'a str, &'a str)],
    ) -> ServiceFuture<'a, ServiceHttpAnswer> {
        Box::pin(async move { Ok(self.answer(url)) })
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

/// How a key identifier is written in an answer.
fn written(key: &Keyed) -> String {
    serde_json::to_value(key.key.key_id())
        .expect("a key identifier")
        .as_str()
        .expect("text")
        .to_owned()
}

/* -------------------------------------------------------------------------- */
/* What the client made of an answer                                           */
/* -------------------------------------------------------------------------- */

/// What a refusal or a failure is to a caller: the code, what a person does, and the delay named.
fn refused(error: &ClientError) -> String {
    let delay = match error {
        ClientError::Refused {
            retry_after_seconds,
            ..
        } => *retry_after_seconds,
        _ => None,
    };
    format!(
        "refused {:?}, {:?}, after {delay:?}",
        error.code(),
        error.user_action()
    )
}

/// What a decoded answer is, in the words of the values the caller acts on.
fn decoded<T>(answer: &Result<T, ClientError>, show: impl FnOnce(&T) -> String) -> String {
    match answer {
        Ok(answer) => show(answer),
        Err(error) => refused(error),
    }
}

fn debug<T: std::fmt::Debug>(value: &T) -> String {
    format!("{value:?}")
}

/* -------------------------------------------------------------------------- */
/* The script                                                                  */
/* -------------------------------------------------------------------------- */

/// A fixed identifier, so a recording and a replay of it name the same archive and objects.
fn fixed(byte: u8) -> Uuid {
    Uuid::from_bytes([byte; 16])
}

/// One sealed generation: its publication, signed by the writer, and the manifest hash a
/// checkpoint names.
fn publication(
    writer: &Keyed,
    sender: &StoredEnvelopeKeyPair,
    device: &StoredEnvelopeKeyPair,
    archive: ArchiveId,
    generation: u64,
    plaintext: &[u8],
) -> (BackupGenerationPublication, Digest256) {
    let staged = stage_object(
        &ObjectSource {
            object_id: BackupObjectId::new(fixed(0x72)),
            filename: "notes.txt",
            plaintext,
        },
        KeyRotation::INITIAL,
    )
    .expect("a staged object");
    let mut recipients = ArchiveRecipients::new(CollectionKind::Owned);
    assert!(recipients.add(*device.public()));
    let sealed = seal_archive(
        &writer.key,
        sender,
        &recipients,
        &ArchivePlan {
            archive_id: archive,
            backup_generation: BackupGeneration::new(generation),
            owner_device_id: DeviceId::new(fixed(0x33)),
            manifest_object_id: BackupObjectId::new(fixed(
                0xa0 + u8::try_from(generation).expect("a small generation"),
            )),
            created_at_ms: TimestampMs::new(1_700_000_000_000),
        },
        &[staged],
    )
    .expect("a sealed archive");
    let hash = sealed.descriptor.encrypted_manifest.encrypted_object_hash;
    let payload = BackupGenerationPublicationPayload {
        descriptor: sealed.descriptor.clone(),
        writer_key_id: writer.key.key_id(),
        published_at_ms: TimestampMs::new(2_000),
    };
    let signature = sign(
        &writer.key,
        &SigningTranscript::from_canonical_bytes(
            BACKUP_PUBLICATION_DOMAIN,
            payload.signing_input().expect("a publication input"),
        )
        .expect("a transcript"),
    )
    .expect("a signature");
    (BackupGenerationPublication { payload, signature }, hash)
}

/// Runs the script against one service through `service`.
///
/// Every request is made by this crate's own clients, as a host and an owner make them, and what
/// each client decoded is kept in `journal`. Whatever a step expects it does not assert: what each
/// answer was is the record's to say, and the stand-in is held to it afterwards.
async fn run_the_script(
    service: &Arc<dyn ServiceHttp>,
    origin: &GatewayOrigin,
    account_token: &str,
    journal: &Journal,
) {
    let owner = keyed(ServiceRequestSigner::Installation);
    let writer = keyed(ServiceRequestSigner::Host);
    journal.name(written(&owner));
    journal.name(written(&writer));
    let storage = |signer: &Arc<Keyed>, token: &str| {
        ManagedStorageService::new(origin.clone(), Arc::clone(service), Arc::clone(signer) as _)
            .presenting(Arc::new(Bearer(token.to_owned())))
    };
    let manifest = |signer: &Arc<Keyed>, token: &str| {
        ManagedBackupManifestService::new(
            origin.clone(),
            Arc::clone(service),
            Arc::clone(signer) as _,
        )
        .presenting(Arc::new(Bearer(token.to_owned())))
    };
    let unknown = "not-a-token-this-service-issued";

    let archive = ArchiveId::new(fixed(0x71));
    let object = BackupObjectId::new(fixed(0x72));
    let second = BackupObjectId::new(fixed(0x73));

    // The account.
    journal.step("status of a token the service did not issue");
    let answer = storage(&writer, unknown).status().await;
    journal.decoded(decoded(&answer, debug));
    journal.step("status with the account");
    let answer = storage(&writer, account_token).status().await;
    let revision = answer.as_ref().expect("a status").retention_revision;
    let showing = |status: &kr_client::services::StorageStatus| {
        format!(
            "backup {:?}, revision {}, retention {:?}, stored {:?}, tombstoned {:?}, uploading \
             {:?}, reserved {}, allowance {:?}, limits {:?}",
            status.backup,
            status.retention_revision,
            status.retention,
            status.stored,
            status.tombstoned,
            status.uploading,
            status.reserved_bytes,
            status.allowance_bytes,
            status.limits
        )
    };
    journal.decoded(decoded(&answer, showing));
    journal.step("turn backup storage on");
    let answer = storage(&writer, account_token)
        .set_retention(&RetentionChange {
            backup: BackupState::On,
            daily_snapshots: None,
            expected_revision: revision,
        })
        .await;
    journal.decoded(decoded(&answer, debug));
    journal.step("turn backup storage on against a revision it has left");
    let answer = storage(&writer, account_token)
        .set_retention(&RetentionChange {
            backup: BackupState::On,
            daily_snapshots: Some(7),
            expected_revision: revision,
        })
        .await;
    journal.decoded(decoded(&answer, debug));
    journal.step("status after the change");
    let answer = storage(&writer, account_token).status().await;
    journal.decoded(decoded(&answer, showing));

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
    let created_showing = |created: &kr_client::services::ArchiveAnswer<
        kr_client::services::UploadCreated,
    >| match created {
        kr_client::services::ArchiveAnswer::Done(created) => format!(
            "created, parts {:?}, reserved {}, principal {:?}",
            created.table, created.reserved_bytes, created.principal
        ),
        other => format!("{other:?}"),
    };
    journal.step("create an upload");
    let created = host.create_upload(&upload).await;
    journal.decoded(decoded(&created, created_showing));
    journal.step("create it again while it is open");
    let again = host.create_upload(&upload).await;
    journal.decoded(decoded(&again, created_showing));
    let mut progress: Option<UploadProgress> = None;
    if let Ok(kr_client::services::ArchiveAnswer::Done(created)) = created {
        let mut held = created.progress();
        journal.step("send a part");
        let sent = upload_parts(&host, &mut held, &ciphertext, &mut |_| Ok(())).await;
        journal.decoded(decoded(&sent, debug));
        journal.step("send it again");
        held.parts_acknowledged = 0;
        let sent = upload_parts(&host, &mut held, &ciphertext, &mut |_| Ok(())).await;
        journal.decoded(decoded(&sent, debug));
        journal.step("complete the upload");
        let table = PartTable::for_total(ciphertext.len() as u64).expect("a part table");
        let done = host.complete_upload(&held.upload_id, &table).await;
        journal.decoded(decoded(&done, debug));
        journal.step("complete it again");
        let done = host.complete_upload(&held.upload_id, &table).await;
        journal.decoded(decoded(&done, debug));
        progress = Some(held);
    }
    journal.step("complete an upload nobody created");
    if let Some(held) = &progress {
        let none = UploadId::new("upload-nobody-created").expect("an identity");
        let done = host.complete_upload(&none, &held.table).await;
        journal.decoded(decoded(&done, debug));
    }
    journal.step("read the object");
    let read = host.read_object(archive, object, 0, 100).await;
    journal.decoded(decoded(&read, debug));
    journal.step("read past its end");
    let read = host.read_object(archive, object, 5_000, 100).await;
    journal.decoded(decoded(&read, debug));

    // An upload begun and given up.
    let given_up = NewUpload {
        object_id: second,
        ..upload
    };
    journal.step("create an upload to give up");
    let created = host.create_upload(&given_up).await;
    journal.decoded(decoded(&created, created_showing));
    if let Ok(kr_client::services::ArchiveAnswer::Done(created)) = created {
        journal.step("abandon it");
        let aborted = host.abort_upload(&created.upload_id).await;
        journal.decoded(decoded(&aborted, debug));
        journal.step("abandon it again");
        let aborted = host.abort_upload(&created.upload_id).await;
        journal.decoded(decoded(&aborted, debug));
        journal.step("send a part to the abandoned upload");
        let mut held = created.progress();
        let sent = upload_parts(&host, &mut held, &ciphertext, &mut |_| Ok(())).await;
        journal.decoded(decoded(&sent, debug));
    }

    // The manifest.
    let device = StoredEnvelopeKeyPair::generate().expect("a device key");
    let sender = StoredEnvelopeKeyPair::generate().expect("a producer key");
    let sealed = |generation: u64, plaintext: &[u8]| {
        let sealed = publication(&writer, &sender, &device, archive, generation, plaintext);
        journal.name(
            serde_json::to_value(sealed.1)
                .expect("a hash")
                .as_str()
                .expect("text")
                .to_owned(),
        );
        sealed
    };
    let (first, first_hash) = sealed(1, b"the notes");
    let (other_first, _) = sealed(1, b"other notes");
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
    let published_showing = |published: &kr_client::services::ArchiveAnswer<
        kr_client::services::Published,
    >| match published {
        kr_client::services::ArchiveAnswer::Done(published) => format!("{published:?}"),
        other => format!("{other:?}"),
    };
    journal.step("publish before any writer is enrolled");
    let answer = manifest(&writer, account_token).publish(&first).await;
    journal.decoded(decoded(&answer, published_showing));
    journal.step("enrol the writer");
    let answer = manifest(&owner, account_token).enrol(&enrolment(1)).await;
    journal.decoded(decoded(&answer, debug));
    journal.step("enrol the same writer again");
    let answer = manifest(&owner, account_token).enrol(&enrolment(1)).await;
    journal.decoded(decoded(&answer, debug));
    journal.step("publish a generation");
    let answer = manifest(&writer, account_token).publish(&first).await;
    journal.decoded(decoded(&answer, published_showing));
    journal.step("publish it again");
    let answer = manifest(&writer, account_token).publish(&first).await;
    journal.decoded(decoded(&answer, published_showing));
    journal.step("publish it again with no account");
    let answer = manifest(&writer, unknown).publish(&first).await;
    journal.decoded(decoded(&answer, published_showing));
    journal.step("publish other content under a generation it holds");
    let answer = manifest(&writer, account_token).publish(&other_first).await;
    journal.decoded(decoded(&answer, published_showing));
    let mut newest = first_hash;
    for generation in [2, 4] {
        let (next, hash) = sealed(generation, b"the notes");
        journal.step(&format!("publish generation {generation}"));
        let answer = manifest(&writer, account_token).publish(&next).await;
        journal.decoded(decoded(&answer, published_showing));
        newest = hash;
    }
    let (below, _) = sealed(3, b"the notes");
    journal.step("publish a generation below one the collection has published");
    let answer = manifest(&writer, account_token).publish(&below).await;
    journal.decoded(decoded(&answer, published_showing));

    let fetched_showing = |fetched: &Option<kr_client::services::FetchedGeneration>| match fetched {
        Some(fetched) => format!(
            "held generation {}, {:?}, writer {:?}",
            fetched
                .publication
                .payload
                .descriptor
                .backup_generation
                .get(),
            fetched.collection,
            fetched.current_writer
        ),
        None => "holds nothing to answer with".to_owned(),
    };
    let checkpoint = |generation: u64, hash: Digest256, of: ArchiveId| GenerationCheckpoint {
        archive_id: of,
        backup_generation: BackupGeneration::new(generation),
        encrypted_manifest_hash: hash,
        observed_at_ms: TimestampMs::new(3_000),
    };
    let reader = manifest(&writer, account_token);
    journal.step("fetch the newest generation");
    let answer = reader.fetch(archive, None, None).await;
    journal.decoded(decoded(&answer, fetched_showing));
    journal.step("fetch a generation that is held");
    let answer = reader
        .fetch(archive, Some(BackupGeneration::new(1)), None)
        .await;
    journal.decoded(decoded(&answer, fetched_showing));
    journal.step("fetch a generation that is not held");
    let answer = reader
        .fetch(archive, Some(BackupGeneration::new(9)), None)
        .await;
    journal.decoded(decoded(&answer, fetched_showing));
    journal.step("fetch an archive that is not held");
    let answer = reader.fetch(ArchiveId::new(fixed(0x74)), None, None).await;
    journal.decoded(decoded(&answer, fetched_showing));
    journal.step("fetch with the checkpoint the collection holds");
    let answer = reader
        .fetch(archive, None, Some(&checkpoint(4, newest, archive)))
        .await;
    journal.decoded(decoded(&answer, fetched_showing));
    journal.step("fetch with a checkpoint newer than the collection");
    let answer = reader
        .fetch(archive, None, Some(&checkpoint(9, newest, archive)))
        .await;
    journal.decoded(decoded(&answer, fetched_showing));
    journal.step("fetch with a checkpoint whose manifest differs");
    let answer = reader
        .fetch(archive, None, Some(&checkpoint(4, first_hash, archive)))
        .await;
    journal.decoded(decoded(&answer, fetched_showing));
    journal.step("fetch a generation older than the checkpoint");
    let answer = reader
        .fetch(
            archive,
            Some(BackupGeneration::new(1)),
            Some(&checkpoint(2, newest, archive)),
        )
        .await;
    journal.decoded(decoded(&answer, fetched_showing));
    journal.step("fetch with a checkpoint about another archive");
    let answer = reader
        .fetch(
            archive,
            None,
            Some(&checkpoint(4, newest, ArchiveId::new(fixed(0x74)))),
        )
        .await;
    journal.decoded(decoded(&answer, fetched_showing));

    // The history is bounded.
    for generation in 5..=18 {
        let (next, _) = sealed(generation, b"the notes");
        journal.step(&format!("publish generation {generation}"));
        let answer = manifest(&writer, account_token).publish(&next).await;
        journal.decoded(decoded(&answer, published_showing));
    }
    journal.step("fetch a generation the history has dropped");
    let answer = reader
        .fetch(archive, Some(BackupGeneration::new(1)), None)
        .await;
    journal.decoded(decoded(&answer, fetched_showing));

    // Deleting the object.
    journal.step("delete the object");
    let answer = host.delete_object(archive, object).await;
    journal.decoded(decoded(&answer, debug));
    journal.step("delete it again");
    let answer = host.delete_object(archive, object).await;
    journal.decoded(decoded(&answer, debug));
    journal.step("delete an object that is not held");
    let answer = host
        .delete_object(archive, BackupObjectId::new(fixed(0x75)))
        .await;
    journal.decoded(decoded(&answer, debug));
}

/* -------------------------------------------------------------------------- */
/* Shapes, and the record                                                      */
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

/// An answer's body for the record: the document, or the content's bytes in base64.
fn body_of(exchange: &Exchange) -> serde_json::Value {
    serde_json::from_slice::<serde_json::Value>(&exchange.body).unwrap_or_else(|_| {
        serde_json::json!({
            "content_base64": base64::engine::general_purpose::STANDARD.encode(&exchange.body),
        })
    })
}

fn recorded(journal: &Journal, web_commit: &str) -> serde_json::Value {
    serde_json::json!({
        "recorded_from": "a Worker on this machine, started by infra/scripts/testing/local-restore.mjs",
        "web_commit": web_commit,
        "names": journal.names.lock().expect("the names").clone(),
        "exchanges": journal.exchanges().iter().map(|exchange| serde_json::json!({
            "step": exchange.step,
            "path": exchange.path,
            "status": exchange.status,
            "shape": shape_of(exchange),
            "body": body_of(exchange),
        })).collect::<Vec<_>>(),
        "decoded": journal.outcomes().iter().map(|(step, outcome)| serde_json::json!({
            "step": step,
            "outcome": outcome,
        })).collect::<Vec<_>>(),
    })
}

/// The recorded answers as exchanges a transport can give back.
fn held_exchanges(held: &serde_json::Value) -> Vec<Exchange> {
    held["exchanges"]
        .as_array()
        .expect("recorded exchanges")
        .iter()
        .map(|exchange| Exchange {
            step: exchange["step"].as_str().expect("a step").to_owned(),
            path: exchange["path"].as_str().expect("a path").to_owned(),
            status: u16::try_from(exchange["status"].as_u64().expect("a status"))
                .expect("a status"),
            body: match exchange["body"]["content_base64"].as_str() {
                Some(content) => base64::engine::general_purpose::STANDARD
                    .decode(content)
                    .expect("content"),
                None => serde_json::to_vec(&exchange["body"]).expect("a body"),
            },
        })
        .collect()
}

/// What the recording says each step decoded to.
fn held_outcomes(held: &serde_json::Value) -> Vec<(String, String)> {
    held["decoded"]
        .as_array()
        .expect("recorded outcomes")
        .iter()
        .map(|outcome| {
            (
                outcome["step"].as_str().expect("a step").to_owned(),
                outcome["outcome"].as_str().expect("an outcome").to_owned(),
            )
        })
        .collect()
}

/// The steps at which `ran` differs from `held`, in words.
fn differences(held: &[(String, String)], ran: &[(String, String)]) -> Vec<String> {
    let mut differing = Vec::new();
    for (index, (step, outcome)) in held.iter().enumerate() {
        match ran.get(index) {
            Some((ran_step, ran_outcome)) if ran_step == step && ran_outcome == outcome => {}
            Some((ran_step, ran_outcome)) => differing.push(format!(
                "{step}: the client decoded\n    {ran_outcome}\n  at {ran_step}, and the recording \
                 holds\n    {outcome}"
            )),
            None => differing.push(format!("{step}: this run made no such step")),
        }
    }
    if ran.len() > held.len() {
        differing.push(format!(
            "this run made {} steps and the recording holds {}",
            ran.len(),
            held.len()
        ));
    }
    differing
}

/* -------------------------------------------------------------------------- */
/* The runs                                                                    */
/* -------------------------------------------------------------------------- */

/// What the clients decode from the answers a Worker gave is what they decoded when it gave them.
///
/// The bodies are the Worker's own, with no stand-in between, so a reader that stops reading what
/// the Worker says fails here.
#[tokio::test]
async fn the_clients_decode_what_the_worker_answered() {
    let held: serde_json::Value = serde_json::from_str(FIXTURE).expect("the recording");
    let journal = Arc::new(Journal::default());
    let replay: Arc<dyn ServiceHttp> = Arc::new(Replaying {
        answers: Mutex::new(held_exchanges(&held).into()),
        recorded_names: held["names"]
            .as_array()
            .expect("the recorded names")
            .iter()
            .map(|name| name.as_str().expect("a name").to_owned())
            .collect(),
        journal: Arc::clone(&journal),
    });
    let origin = GatewayOrigin::new("http://127.0.0.1:8787").expect("an origin");
    run_the_script(&replay, &origin, TOKEN, &journal).await;
    let differing = differences(&held_outcomes(&held), &journal.outcomes());
    assert!(
        differing.is_empty(),
        "the clients no longer read the Worker's answers as they did:\n{}",
        differing.join("\n")
    );
}

/// The stand-in answers the script as the Worker did.
#[tokio::test]
async fn the_stand_in_answers_as_the_worker_did() {
    let held: serde_json::Value = serde_json::from_str(FIXTURE).expect("the recording");
    let web = Arc::new(StorageWeb::new());
    let origin = GatewayOrigin::new(web.origin()).expect("an origin");
    let journal = Arc::new(Journal::default());
    let http: Arc<dyn ServiceHttp> = Arc::new(Recording {
        inner: Arc::clone(&web) as _,
        origin: web.origin().to_owned(),
        journal: Arc::clone(&journal),
    });
    run_the_script(&http, &origin, TOKEN, &journal).await;
    let ran = recorded(&journal, "");

    let held_exchanges = held["exchanges"].as_array().expect("recorded exchanges");
    let ran_exchanges = ran["exchanges"].as_array().expect("exchanges");
    let mut differing = Vec::new();
    for (index, held) in held_exchanges.iter().enumerate() {
        match ran_exchanges.get(index) {
            Some(ran) if ran["step"] == held["step"] && ran["path"] == held["path"] => {
                for member in ["status", "shape"] {
                    if ran[member] != held[member] {
                        differing.push(format!(
                            "{}: {member} was {} and the Worker's was {}",
                            held["step"], ran[member], held[member]
                        ));
                    }
                }
            }
            other => differing.push(format!(
                "{}: the stand-in made {other:?} where the Worker was asked {}",
                held["step"], held["path"]
            )),
        }
    }
    if ran_exchanges.len() > held_exchanges.len() {
        differing.push(format!(
            "the stand-in answered {} requests and the recording holds {}",
            ran_exchanges.len(),
            held_exchanges.len()
        ));
    }
    differing.extend(differences(&held_outcomes(&held), &journal.outcomes()));
    assert!(
        differing.is_empty(),
        "the stand-in differs from the recording:\n{}",
        differing.join("\n")
    );
}

/// Runs the script against a local Worker and writes what it answered.
///
/// It is ignored unless it is asked for, and then it needs the Worker to ask and the account
/// tokens that Worker's development sign-in wrote, so an ordinary run of this workspace asks
/// nothing of any service.
#[tokio::test]
#[ignore = "runs only against a Worker on this machine named by KR_DEPLOYED_ORIGIN, KR_BACKUP_TOKENS and KR_RECORD_SERVICE_ANSWERS"]
async fn record_a_local_workers_answers() {
    let (Some(path), Some(origin), Some(tokens)) = (
        std::env::var_os("KR_RECORD_SERVICE_ANSWERS"),
        std::env::var("KR_DEPLOYED_ORIGIN").ok(),
        std::env::var_os("KR_BACKUP_TOKENS"),
    ) else {
        panic!(
            "KR_RECORD_SERVICE_ANSWERS, KR_DEPLOYED_ORIGIN and KR_BACKUP_TOKENS name what to record"
        );
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
    let journal = Arc::new(Journal::default());
    let http: Arc<dyn ServiceHttp> = Arc::new(Recording {
        inner: transport,
        origin,
        journal: Arc::clone(&journal),
    });
    run_the_script(&http, &gateway, &token, &journal).await;
    let commit = std::env::var("KR_WEB_COMMIT").unwrap_or_else(|_| "not stated".to_owned());
    let mut text = serde_json::to_string_pretty(&recorded(&journal, &commit)).expect("a recording");
    text.push('\n');
    std::fs::write(path, text).expect("the recording is written");
}
