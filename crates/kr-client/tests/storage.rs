//! Managed storage's client and the backup manifest's client, against a service that answers as the
//! managed service does.
//!
//! Nothing here talks to a real service. `support/storage_web.rs` checks every request the way the
//! service checks it, the signature, the method, the installation and the account token, and keeps
//! what the service keeps, so each answer here is one the service can give.

#[path = "support/storage_web.rs"]
mod storage_web;

use std::sync::{Arc, Mutex};

use kr_client::error::ClientError;
use kr_client::retry::UserAction;
use kr_client::services::account::{AccountToken, AccountTokenSource};
use kr_client::services::backup::ManagedBackupManifestService;
use kr_client::services::storage::{
    ArchiveAnswer, BackupState, ManagedStorageService, NewUpload, PartTable, RetentionChange,
    STORAGE_PART_SIZE_BYTES, StoragePrincipal, UploadPart, UploadProgress, upload_parts,
};
use kr_client::services::{
    BackupManifestService, Dispatched, NullService, ServiceFuture, ServiceSigner, StorageService,
};
use kr_crypto::backup::{
    ArchivePlan, ArchiveRecipients, CollectionKind, KeyRotation, ObjectSource, SealedArchive,
    seal_archive, stage_object,
};
use kr_crypto::keys::{AuthorisationKeyPair, StoredEnvelopeKeyPair};
use kr_protocol::archive::{
    BackupGenerationPublication, BackupGenerationPublicationPayload, BackupWriterRecord,
    BackupWriterRecordPayload, TrustedWriter,
};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::ids::{
    ArchiveId, BackupGeneration, BackupObjectId, BackupWriterRevision, DeviceId,
};
use kr_protocol::scalars::{AuthorisationKey, Digest256, Signature64, TimestampMs, Uuid};
use kr_protocol::service::{GatewayOrigin, ServiceRequestSigner};
use storage_web::{ACCOUNT, Moment, StorageWeb, TOKEN};

/* -------------------------------------------------------------------------- */
/* A device, its account, and its two clients                                  */
/* -------------------------------------------------------------------------- */

/// One installation's authorisation key, signing as a device signs.
#[derive(Debug)]
struct Device(AuthorisationKeyPair);

impl Device {
    fn generate() -> Arc<Self> {
        Arc::new(Self(AuthorisationKeyPair::generate().expect("a key pair")))
    }
}

impl ServiceSigner for Device {
    fn signer(&self) -> ServiceRequestSigner {
        ServiceRequestSigner::Installation
    }

    fn public_key(&self) -> AuthorisationKey {
        *self.0.public()
    }

    fn sign(&self, message: &[u8]) -> kr_client::Result<Signature64> {
        let transcript = kr_crypto::sign::SigningTranscript::from_canonical_bytes(
            ServiceRequestSigner::Installation.domain(),
            message.to_vec(),
        )
        .expect("a domain-tagged transcript");
        Ok(kr_crypto::sign::sign(&self.0, &transcript).expect("a signature"))
    }
}

/// Where account tokens come from: the account's token for `backup.write`, or none, and a record of
/// every scope it was asked for.
#[derive(Debug)]
struct Tokens {
    grants_backup_write: bool,
    asked: Mutex<Vec<String>>,
}

impl Tokens {
    fn signed_in() -> Arc<Self> {
        Arc::new(Self {
            grants_backup_write: true,
            asked: Mutex::new(Vec::new()),
        })
    }

    /// A sign-in that was not granted `backup.write`, which is what an application's own sign-in
    /// holds until the person turns recovery-enabled backup on.
    fn without_backup_write() -> Arc<Self> {
        Arc::new(Self {
            grants_backup_write: false,
            asked: Mutex::new(Vec::new()),
        })
    }

    fn asked(&self) -> Vec<String> {
        self.asked.lock().expect("the scopes").clone()
    }
}

impl AccountTokenSource for Tokens {
    fn token<'a>(&'a self, scope: &'a str) -> ServiceFuture<'a, AccountToken> {
        self.asked
            .lock()
            .expect("the scopes")
            .push(scope.to_owned());
        let token = if self.grants_backup_write && scope == "backup.write" {
            AccountToken::new(TOKEN)
        } else {
            Err(ClientError::Host(ProtocolError::new(
                ErrorCode::PermissionDenied,
                format!("this sign-in was not granted the {scope} scope"),
            )))
        };
        Box::pin(async move { token })
    }
}

fn origin() -> GatewayOrigin {
    GatewayOrigin::new("https://reach.kala.to").expect("an origin")
}

/// A storage client for `device`, presenting `tokens` when given.
fn storage(
    web: &Arc<StorageWeb>,
    device: &Arc<Device>,
    tokens: Option<&Arc<Tokens>>,
) -> ManagedStorageService {
    let client = ManagedStorageService::new(
        origin(),
        Arc::clone(web) as Arc<_>,
        Arc::clone(device) as Arc<dyn ServiceSigner>,
    );
    match tokens {
        Some(tokens) => client.presenting(Arc::clone(tokens) as Arc<dyn AccountTokenSource>),
        None => client,
    }
}

/// A manifest client for `device`, presenting `tokens` when given.
fn manifest(
    web: &Arc<StorageWeb>,
    device: &Arc<Device>,
    tokens: Option<&Arc<Tokens>>,
) -> ManagedBackupManifestService {
    let client = ManagedBackupManifestService::new(
        origin(),
        Arc::clone(web) as Arc<_>,
        Arc::clone(device) as Arc<dyn ServiceSigner>,
    );
    match tokens {
        Some(tokens) => client.presenting(Arc::clone(tokens) as Arc<dyn AccountTokenSource>),
        None => client,
    }
}

fn archive_id() -> ArchiveId {
    ArchiveId::new(Uuid::from_bytes([0x11; 16]))
}

fn object_id(seed: u8) -> BackupObjectId {
    BackupObjectId::new(Uuid::from_bytes([seed; 16]))
}

/// `length` bytes that differ from part to part, so a part sent in the wrong place would not hash
/// to what it declared.
fn ciphertext(length: u64) -> Vec<u8> {
    (0..length)
        .map(|at| u8::try_from((at * 7 + at / 8_388_608) % 251).expect("a byte"))
        .collect()
}

/// The upload of `bytes` as `object`.
fn new_upload(object: u8, bytes: &[u8]) -> NewUpload {
    NewUpload {
        archive_id: archive_id(),
        object_id: object_id(object),
        backup_generation: BackupGeneration::new(1),
        declared_max_bytes: bytes.len() as u64,
        total_bytes: bytes.len() as u64,
        encrypted_object_hash: Digest256::from_bytes(kr_cbor::sha256(bytes)),
    }
}

/// Turns backup storage on for the account, from wherever it is.
async fn backup_on(client: &ManagedStorageService) {
    let status = client.status().await.expect("a status");
    client
        .set_retention(&RetentionChange {
            backup: BackupState::On,
            daily_snapshots: None,
            expected_revision: status.retention_revision,
        })
        .await
        .expect("backup storage turned on");
}

/// Creates the upload of `bytes` as `object`, which the service answers with a new upload.
async fn created(client: &ManagedStorageService, object: u8, bytes: &[u8]) -> UploadProgress {
    match client
        .create_upload(&new_upload(object, bytes))
        .await
        .expect("an answer")
    {
        ArchiveAnswer::Done(created) => created.progress(),
        other => panic!("an upload: {other:?}"),
    }
}

/// Keeps nothing of what an upload acknowledged.
fn forget(_: &UploadProgress) -> kr_client::Result<()> {
    Ok(())
}

/// Asserts a refusal the service named, and what a person does about it.
fn refused(error: &ClientError, code: ErrorCode, action: UserAction) {
    assert_eq!(error.code(), code, "{error}");
    assert_eq!(error.user_action(), action, "{error}");
}

/* -------------------------------------------------------------------------- */
/* Each method once                                                            */
/* -------------------------------------------------------------------------- */

/// KR-REQ-20.22: every storage method, once, answered as the service answers it: backup storage is
/// off until it is turned on, an upload is created with its part table, its parts are stored, it is
/// completed into the object, the object reads back and is deleted into a tombstone, and an upload
/// abandoned is cleaned up. Every request carries the account token and names the installation the
/// signing key derives.
#[tokio::test]
async fn each_storage_method_is_answered_as_the_service_answers_it() {
    let web = Arc::new(StorageWeb::new());
    let device = Device::generate();
    let tokens = Tokens::signed_in();
    let client = storage(&web, &device, Some(&tokens));

    let status = client.status().await.expect("a status");
    assert_eq!(
        status.principal,
        StoragePrincipal::Account(ACCOUNT.to_owned())
    );
    assert_eq!(status.backup, BackupState::Off, "off until it is turned on");
    assert_eq!(status.retention.daily_snapshots, 30);
    assert_eq!(status.retention.tombstone_days, 7);
    assert_eq!(status.limits.part_size_bytes, STORAGE_PART_SIZE_BYTES);

    let set = client
        .set_retention(&RetentionChange {
            backup: BackupState::On,
            daily_snapshots: Some(14),
            expected_revision: status.retention_revision,
        })
        .await
        .expect("a change");
    assert!(set.changed);
    assert_eq!(set.backup, BackupState::On);
    assert_eq!(set.retention.daily_snapshots, 14);
    assert_eq!(set.revision, status.retention_revision + 1);

    let bytes = ciphertext(STORAGE_PART_SIZE_BYTES + 5);
    let upload = new_upload(1, &bytes);
    let ArchiveAnswer::Done(created) = client.create_upload(&upload).await.expect("an answer")
    else {
        panic!("an upload");
    };
    assert_eq!(
        created.table,
        PartTable::for_total(bytes.len() as u64).expect("a table")
    );
    assert_eq!(created.table.part_count(), 2);
    assert_eq!(created.reserved_bytes, bytes.len() as u64);
    assert_eq!(
        created.principal,
        StoragePrincipal::Account(ACCOUNT.to_owned())
    );

    let mut progress = created.progress();
    let mut kept = Vec::new();
    let finished = upload_parts(&client, &mut progress, &bytes, &mut |progress| {
        kept.push(progress.parts_acknowledged);
        Ok(())
    })
    .await
    .expect("the parts");
    assert_eq!(finished, ArchiveAnswer::Done(()));
    assert_eq!(
        kept,
        [1, 2],
        "each acknowledgement is told before the next part"
    );
    assert_eq!(web.parts_sent(), [1, 2]);

    let ArchiveAnswer::Done(completed) = client
        .complete_upload(&progress.upload_id, &progress.table)
        .await
        .expect("an answer")
    else {
        panic!("a completion");
    };
    assert!(!completed.duplicate);
    assert_eq!(completed.archive_id, archive_id());
    assert_eq!(completed.backup_generation, BackupGeneration::new(1));
    assert_eq!(completed.object.object_id, object_id(1));
    assert_eq!(
        completed.object.encrypted_object_hash,
        upload.encrypted_object_hash
    );
    assert_eq!(completed.object.encrypted_len, bytes.len() as u64);
    assert_eq!(completed.committed_bytes, bytes.len() as u64);

    // Read back in two ranges, the second one short at the end of the object.
    let mut read = Vec::new();
    let mut offset = 0;
    while offset < bytes.len() as u64 {
        let range = client
            .read_object(archive_id(), object_id(1), offset, STORAGE_PART_SIZE_BYTES)
            .await
            .expect("a range");
        assert_eq!(range.offset, offset);
        offset += range.bytes.len() as u64;
        read.extend(range.bytes);
    }
    assert_eq!(read, bytes, "the ciphertext it stored, byte for byte");

    let deleted = client
        .delete_object(archive_id(), object_id(1))
        .await
        .expect("a deletion");
    assert!(!deleted.already);
    assert_eq!(deleted.retained_bytes, bytes.len() as u64);
    assert_eq!(deleted.retention.tombstone_days, 7);
    assert!(
        client
            .delete_object(archive_id(), object_id(1))
            .await
            .expect("a deletion asked again")
            .already
    );

    let abandoned = created_and_abandoned(&client).await;
    assert!(abandoned.cleaned);

    // Every request carried the account's token for backup.write and named this installation.
    let installation = kr_protocol::service::installation_id(&device.public_key()).to_string();
    for arrived in web.arrived() {
        assert_eq!(arrived.token.as_deref(), Some(TOKEN), "{}", arrived.path);
        assert_eq!(
            arrived.body["installation_id"].as_str(),
            Some(installation.as_str()),
            "{}",
            arrived.path
        );
    }
    assert!(tokens.asked().iter().all(|scope| scope == "backup.write"));
}

/// Creates one upload of one byte and abandons it.
async fn created_and_abandoned(
    client: &ManagedStorageService,
) -> kr_client::services::UploadAborted {
    let progress = created(client, 9, &[0x2a]).await;
    match client
        .abort_upload(&progress.upload_id)
        .await
        .expect("an answer")
    {
        ArchiveAnswer::Done(aborted) => aborted,
        other => panic!("an abandonment: {other:?}"),
    }
}

/// A part's signed request travels in its header and names the upload, the part, its length and
/// the hash of what it carries; the body is the ciphertext and nothing else.
#[tokio::test]
async fn a_part_travels_as_its_ciphertext_beside_its_signed_request() {
    let web = Arc::new(StorageWeb::new());
    let device = Device::generate();
    let client = storage(&web, &device, Some(&Tokens::signed_in()));
    backup_on(&client).await;
    let bytes = ciphertext(300);
    let progress = created(&client, 1, &bytes).await;

    let answer = client
        .upload_part(
            &progress.upload_id,
            UploadPart {
                number: 1,
                bytes: &bytes,
            },
        )
        .await
        .expect("an answer");
    let ArchiveAnswer::Done(stored) = answer else {
        panic!("a part: {answer:?}");
    };
    assert!(!stored.duplicate);
    assert_eq!(stored.parts_stored, 1);
    assert_eq!(stored.bytes_stored, 300);

    let part = web
        .arrived()
        .into_iter()
        .find(|arrived| arrived.path == "/api/storage/upload/part")
        .expect("the part");
    assert_eq!(part.content.as_deref(), Some(bytes.as_slice()));
    assert_eq!(part.body["upload_id"], progress.upload_id.as_str());
    assert_eq!(part.body["part_number"], 1);
    assert_eq!(part.body["length_bytes"], "300");
    assert_eq!(
        part.body["sha256"],
        serde_json::to_value(Digest256::from_bytes(kr_cbor::sha256(&bytes))).expect("a hash")
    );
    assert_eq!(
        part.body.as_object().expect("members").len(),
        5,
        "the installation, the upload, the number, the length and the hash, and nothing else"
    );
}

/* -------------------------------------------------------------------------- */
/* One refusal a method                                                        */
/* -------------------------------------------------------------------------- */

/// KR-REQ-20.22: one refusal each method meets, as the service sends it, with what a person does
/// about it. An upload into storage that is off is the permission the person turns on; a stale
/// retention change is the service's generic refusal, which says to read the revision again; a part
/// and a completion of an upload that expired are the service's own `FORBIDDEN`, which also answers
/// other things, so the upload keeps its identity and its abandonment is what ends it; the
/// abandonment of an upload the service never made is an upload it holds none of; a completion whose
/// parts do not add up is the service's `INVALID_REQUEST`; a service with no room for a part is
/// capacity to wait for; a read and a deletion of nothing stored are an object the service holds
/// none of.
#[tokio::test]
async fn each_storage_method_meets_a_refusal_the_service_sends() {
    let web = Arc::new(StorageWeb::new());
    let device = Device::generate();
    let client = storage(&web, &device, Some(&Tokens::signed_in()));
    let bytes = ciphertext(64);

    let off = client
        .create_upload(&new_upload(1, &bytes))
        .await
        .expect_err("backup storage is off");
    refused(
        &off,
        ErrorCode::PermissionDenied,
        UserAction::FixConfiguration,
    );
    assert!(off.to_string().contains("Turn it on"), "{off}");

    let stale = client
        .set_retention(&RetentionChange {
            backup: BackupState::On,
            daily_snapshots: None,
            expected_revision: 7,
        })
        .await
        .expect_err("a revision the record has left");
    refused(&stale, ErrorCode::InvalidArgument, UserAction::Update);

    backup_on(&client).await;
    let progress = created(&client, 1, &bytes).await;
    web.expire_uploads();
    let expired = client
        .upload_part(
            &progress.upload_id,
            UploadPart {
                number: 1,
                bytes: &bytes,
            },
        )
        .await
        .expect_err("an expired upload");
    refused(
        &expired,
        ErrorCode::PermissionDenied,
        UserAction::FixConfiguration,
    );
    let expired = client
        .complete_upload(&progress.upload_id, &progress.table)
        .await
        .expect_err("an expired upload");
    refused(
        &expired,
        ErrorCode::PermissionDenied,
        UserAction::FixConfiguration,
    );
    // Its abandonment is the explicit state: the service confirms the upload is over.
    let ArchiveAnswer::Done(abandoned) = client
        .abort_upload(&progress.upload_id)
        .await
        .expect("an answer")
    else {
        panic!("an abandonment");
    };
    assert!(abandoned.cleaned);
    assert_eq!(
        client
            .abort_upload(&kr_client::services::UploadId::new("no-such-upload").expect("an id"))
            .await
            .expect("an answer"),
        ArchiveAnswer::UploadGone,
        "an upload the service never made"
    );

    // A completion whose parts do not add up.
    let two_parts = ciphertext(STORAGE_PART_SIZE_BYTES + 1);
    let mut halfway = created(&client, 2, &two_parts).await;
    halfway.table = PartTable::for_total(STORAGE_PART_SIZE_BYTES).expect("a table");
    upload_parts(
        &client,
        &mut halfway,
        &two_parts[..usize::try_from(STORAGE_PART_SIZE_BYTES).expect("a length")],
        &mut forget,
    )
    .await
    .expect("the first part");
    let whole = PartTable::for_total(two_parts.len() as u64).expect("a table");
    let short = client
        .complete_upload(&halfway.upload_id, &whole)
        .await
        .expect_err("a part is missing");
    refused(&short, ErrorCode::InvalidArgument, UserAction::Update);

    let absent = client
        .read_object(archive_id(), object_id(0x44), 0, 16)
        .await
        .expect_err("nothing stored");
    refused(&absent, ErrorCode::UnknownSession, UserAction::Nothing);
    let absent = client
        .delete_object(archive_id(), object_id(0x44))
        .await
        .expect_err("nothing stored");
    refused(&absent, ErrorCode::UnknownSession, UserAction::Nothing);

    // Backpressure before the part's body is read: capacity, with the delay the service named.
    let web = Arc::new(BusyWeb);
    let busy = ManagedStorageService::new(origin(), Arc::clone(&web) as Arc<_>, device)
        .presenting(Tokens::signed_in() as Arc<dyn AccountTokenSource>);
    let waited = busy
        .upload_part(
            &kr_client::services::UploadId::new("an-upload").expect("an id"),
            UploadPart {
                number: 1,
                bytes: &bytes,
            },
        )
        .await
        .expect_err("no room");
    refused(&waited, ErrorCode::ServiceCapacity, UserAction::Wait);
    let ClientError::Refused {
        retry_after_seconds,
        ..
    } = waited
    else {
        panic!("a refusal the service named: {waited:?}");
    };
    assert_eq!(retry_after_seconds, Some(2));
    let status = busy.status().await.expect_err("not configured");
    refused(
        &status,
        ErrorCode::HostNotConfigured,
        UserAction::FixConfiguration,
    );
}

/// A service with no room for a part, and no storage configured for anything else.
#[derive(Debug, Default)]
struct BusyWeb;

impl kr_client::services::ServiceHttp for BusyWeb {
    fn post_json<'a>(
        &'a self,
        _url: &'a str,
        _body: &'a [u8],
        _headers: &'a [(&'a str, &'a str)],
    ) -> ServiceFuture<'a, kr_client::services::ServiceHttpAnswer> {
        Box::pin(async {
            Ok(storage_web::refusal(
                501,
                "NOT_CONFIGURED",
                "Managed storage is not configured in this deployment.",
            ))
        })
    }

    fn post_bytes<'a>(
        &'a self,
        _url: &'a str,
        _body: &'a [u8],
        _headers: &'a [(&'a str, &'a str)],
    ) -> ServiceFuture<'a, kr_client::services::ServiceHttpAnswer> {
        Box::pin(async {
            Ok(kr_client::services::ServiceHttpAnswer {
                status: 503,
                body: serde_json::to_vec(&serde_json::json!({
                    "ok": false,
                    "error": {
                        "code": "SERVICE_UNAVAILABLE",
                        "message": "This service has no room for that part at the moment. Send it again shortly.",
                        "retryAfterSeconds": 2,
                    },
                }))
                .expect("a refusal"),
            })
        })
    }
}

/* -------------------------------------------------------------------------- */
/* A resumed upload and a repeated completion                                  */
/* -------------------------------------------------------------------------- */

/// An upload interrupted after its second part goes on at the third, and sends neither of the
/// first two again: the progress its caller kept names the upload, its part table and the parts
/// the service acknowledged.
#[tokio::test]
async fn an_upload_interrupted_after_its_second_part_goes_on_without_sending_that_part_again() {
    let web = Arc::new(StorageWeb::new());
    let device = Device::generate();
    let client = storage(&web, &device, Some(&Tokens::signed_in()));
    backup_on(&client).await;
    let bytes = ciphertext(2 * STORAGE_PART_SIZE_BYTES + 3);
    let progress = created(&client, 1, &bytes).await;
    assert_eq!(progress.table.part_count(), 3);

    // The third part's request never reaches the service.
    web.fail("/api/storage/upload/part", 3, Moment::Before);
    let mut kept = progress.clone();
    let interrupted = upload_parts(&client, &mut kept, &bytes, &mut |_| Ok(()))
        .await
        .expect_err("the connection dropped");
    assert_eq!(interrupted.code(), ErrorCode::UpstreamUnavailable);
    assert_eq!(kept.parts_acknowledged, 2, "two parts acknowledged");

    // What the caller kept is all a resume needs, whatever else it has lost.
    let mut resumed = UploadProgress {
        upload_id: kept.upload_id.clone(),
        table: kept.table,
        parts_acknowledged: kept.parts_acknowledged,
    };
    assert_eq!(
        upload_parts(&client, &mut resumed, &bytes, &mut forget)
            .await
            .expect("the rest"),
        ArchiveAnswer::Done(())
    );
    assert_eq!(
        web.parts_sent(),
        [1, 2, 3, 3],
        "the third part once in vain and once through; the second part once"
    );
    let ArchiveAnswer::Done(completed) = client
        .complete_upload(&resumed.upload_id, &resumed.table)
        .await
        .expect("an answer")
    else {
        panic!("a completion");
    };
    assert_eq!(completed.object.encrypted_len, bytes.len() as u64);
    assert_eq!(
        web.stored(&archive_id().to_string(), &object_id(1).to_string()),
        Some(bytes),
        "the object, whole and in order"
    );
}

/// A part the service refused because it could not bind the account's proof this once is an error,
/// not the end of the upload: the upload keeps its identity and takes the same part under the next
/// request, whose proof binds.
#[tokio::test]
async fn an_upload_whose_proof_the_service_could_not_bind_once_goes_on_under_the_next() {
    let web = Arc::new(StorageWeb::new());
    let device = Device::generate();
    let client = storage(&web, &device, Some(&Tokens::signed_in()));
    backup_on(&client).await;
    let bytes = ciphertext(STORAGE_PART_SIZE_BYTES + 9);
    let mut progress = created(&client, 1, &bytes).await;

    web.fail("/api/storage/upload/part", 2, Moment::ProofUnread);
    let unbound = upload_parts(&client, &mut progress, &bytes, &mut forget)
        .await
        .expect_err("the second part's proof did not bind");
    refused(
        &unbound,
        ErrorCode::PermissionDenied,
        UserAction::FixConfiguration,
    );
    assert_eq!(progress.parts_acknowledged, 1);

    assert_eq!(
        upload_parts(&client, &mut progress, &bytes, &mut forget)
            .await
            .expect("the rest"),
        ArchiveAnswer::Done(())
    );
    let ArchiveAnswer::Done(completed) = client
        .complete_upload(&progress.upload_id, &progress.table)
        .await
        .expect("an answer")
    else {
        panic!("a completion");
    };
    assert_eq!(completed.object.encrypted_len, bytes.len() as u64);
    assert_eq!(web.parts_sent(), [1, 2, 2]);
    assert_eq!(
        web.stored(&archive_id().to_string(), &object_id(1).to_string()),
        Some(bytes)
    );
}

/// A part whose body arrived cut short is refused as not the length it declared, and the upload
/// takes it again whole: the refusal is an error about that body and not the end of the upload.
#[tokio::test]
async fn a_part_cut_short_on_its_way_is_refused_and_taken_again_whole() {
    let web = Arc::new(StorageWeb::new());
    let device = Device::generate();
    let client = storage(&web, &device, Some(&Tokens::signed_in()));
    backup_on(&client).await;
    let bytes = ciphertext(4_096);
    let mut progress = created(&client, 1, &bytes).await;

    web.fail("/api/storage/upload/part", 1, Moment::BodyCut);
    let cut = upload_parts(&client, &mut progress, &bytes, &mut forget)
        .await
        .expect_err("the body was cut short");
    refused(&cut, ErrorCode::InvalidArgument, UserAction::Update);
    assert_eq!(progress.parts_acknowledged, 0);

    upload_parts(&client, &mut progress, &bytes, &mut forget)
        .await
        .expect("the part, whole");
    let ArchiveAnswer::Done(completed) = client
        .complete_upload(&progress.upload_id, &progress.table)
        .await
        .expect("an answer")
    else {
        panic!("a completion");
    };
    assert!(!completed.duplicate);
    assert_eq!(
        web.stored(&archive_id().to_string(), &object_id(1).to_string()),
        Some(bytes)
    );
}

/// A part whose answer was lost is sent again and answered as the part it is, and a caller that
/// could not keep an acknowledgement stops before the next part leaves.
#[tokio::test]
async fn a_part_sent_again_is_answered_as_the_part_it_is_and_an_unkept_acknowledgement_stops_the_upload()
 {
    let web = Arc::new(StorageWeb::new());
    let device = Device::generate();
    let client = storage(&web, &device, Some(&Tokens::signed_in()));
    backup_on(&client).await;
    let bytes = ciphertext(2 * STORAGE_PART_SIZE_BYTES + 1);
    let mut progress = created(&client, 1, &bytes).await;

    web.fail("/api/storage/upload/part", 1, Moment::After);
    upload_parts(&client, &mut progress, &bytes, &mut forget)
        .await
        .expect_err("the answer was lost");
    assert_eq!(progress.parts_acknowledged, 0);
    let answer = client
        .upload_part(
            &progress.upload_id,
            UploadPart {
                number: 1,
                bytes: &bytes[..usize::try_from(STORAGE_PART_SIZE_BYTES).expect("a length")],
            },
        )
        .await
        .expect("an answer");
    let ArchiveAnswer::Done(again) = answer else {
        panic!("the part: {answer:?}");
    };
    assert!(again.duplicate, "stored once, answered as the part it is");
    assert_eq!(again.parts_stored, 1);

    progress.parts_acknowledged = 1;
    let unkept = upload_parts(&client, &mut progress, &bytes, &mut |_| {
        Err(ClientError::Host(ProtocolError::new(
            ErrorCode::StorageUnavailable,
            "the store is full".to_owned(),
        )))
    })
    .await
    .expect_err("not kept");
    assert_eq!(unkept.code(), ErrorCode::StorageUnavailable);
    assert_eq!(
        web.parts_sent(),
        [1, 1, 2],
        "nothing after the part it could not keep"
    );
}

/// A completion asked for again is answered with the result it already gave, whether its first
/// answer arrived or was lost, and the service stores the object once.
#[tokio::test]
async fn a_completion_asked_for_again_is_answered_with_the_result_it_already_gave() {
    let web = Arc::new(StorageWeb::new());
    let device = Device::generate();
    let client = storage(&web, &device, Some(&Tokens::signed_in()));
    backup_on(&client).await;
    let bytes = ciphertext(1_000);
    let mut progress = created(&client, 1, &bytes).await;
    upload_parts(&client, &mut progress, &bytes, &mut forget)
        .await
        .expect("the part");

    web.fail("/api/storage/upload/complete", 1, Moment::After);
    client
        .complete_upload(&progress.upload_id, &progress.table)
        .await
        .expect_err("the answer was lost");
    let ArchiveAnswer::Done(first) = client
        .complete_upload(&progress.upload_id, &progress.table)
        .await
        .expect("an answer")
    else {
        panic!("a completion");
    };
    let ArchiveAnswer::Done(second) = client
        .complete_upload(&progress.upload_id, &progress.table)
        .await
        .expect("an answer")
    else {
        panic!("a completion");
    };
    assert!(first.duplicate && second.duplicate, "both after the first");
    assert_eq!(first, second, "the result it already gave");
    assert_eq!(first.object.encrypted_len, 1_000);
    assert_eq!(web.stored_objects(), 1, "stored once");
}

/* -------------------------------------------------------------------------- */
/* A collection deleted from the account console                               */
/* -------------------------------------------------------------------------- */

/// A collection deleted from the account console is an answer of its own to an upload's creation,
/// to its completion and to a publication: it takes nothing more, and what a person is told is that
/// it was deleted and that backing up again means enrolling a new collection, never an update.
#[tokio::test]
async fn a_deleted_collection_is_an_answer_of_its_own_to_an_upload_and_a_publication() {
    let web = Arc::new(StorageWeb::new());
    let device = Device::generate();
    let tokens = Tokens::signed_in();
    let client = storage(&web, &device, Some(&tokens));
    let publisher = manifest(&web, &device, Some(&tokens));
    backup_on(&client).await;
    let archive = Archive::sealed(&device, 1);
    publisher
        .enrol(&archive.enrolment(1))
        .await
        .expect("the writer is enrolled");
    let bytes = ciphertext(64);
    let mut progress = created(&client, 1, &bytes).await;
    upload_parts(&client, &mut progress, &bytes, &mut forget)
        .await
        .expect("the part");

    web.delete_collection(&archive_id().to_string());
    let completion = client
        .complete_upload(&progress.upload_id, &progress.table)
        .await
        .expect("an answer");
    assert_eq!(completion, ArchiveAnswer::CollectionDeleted);
    assert_eq!(
        client
            .create_upload(&new_upload(2, &bytes))
            .await
            .expect("an answer"),
        ArchiveAnswer::CollectionDeleted
    );
    assert_eq!(
        publisher
            .publish(&archive.publication())
            .await
            .expect("an answer"),
        ArchiveAnswer::CollectionDeleted
    );

    // The error a caller that cannot act on it reports says what happened and what to do.
    let said = completion.done().expect_err("deleted");
    refused(
        &said,
        ErrorCode::PermissionDenied,
        UserAction::FixConfiguration,
    );
    assert!(said.to_string().contains("was deleted"), "{said}");
    assert!(
        said.to_string().contains("enrol a new collection"),
        "{said}"
    );
    assert_ne!(said.user_action(), UserAction::Update);
}

/* -------------------------------------------------------------------------- */
/* The backup manifest                                                         */
/* -------------------------------------------------------------------------- */

/// One sealed generation of one archive, whose writer and owner are one device's key.
struct Archive {
    sealed: SealedArchive,
    device: Arc<Device>,
}

impl Archive {
    /// Generation `generation`, sealed and signed by `device`'s key, for one recipient.
    fn sealed(device: &Arc<Device>, generation: u64) -> Self {
        Self::sealed_for(device, generation, 1).expect("a sealed archive")
    }

    /// Generation `generation`, sealed and signed by `device`'s key, for `readers` recipients, or
    /// none when that many take the descriptor past its bound.
    fn sealed_for(device: &Arc<Device>, generation: u64, readers: usize) -> Option<Self> {
        let writer = &device.0;
        let sender = StoredEnvelopeKeyPair::generate().expect("a producer key");
        let mut recipients = ArchiveRecipients::new(CollectionKind::Owned);
        for _ in 0..readers {
            let reader = StoredEnvelopeKeyPair::generate().expect("a recipient key");
            assert!(recipients.add(*reader.public()));
        }
        let objects = [stage_object(
            &ObjectSource {
                object_id: object_id(1),
                filename: "device-configuration/settings.cbor",
                plaintext: b"theme=dark",
            },
            KeyRotation::INITIAL,
        )
        .expect("a staged object")];
        let sealed = seal_archive(
            writer,
            &sender,
            &recipients,
            &ArchivePlan {
                archive_id: archive_id(),
                backup_generation: BackupGeneration::new(generation),
                owner_device_id: DeviceId::new(Uuid::from_bytes([0x33; 16])),
                manifest_object_id: object_id(0xf0),
                created_at_ms: TimestampMs::new(1_700_000_000_000),
            },
            &objects,
        )
        .ok()?;
        Some(Self {
            sealed,
            device: Arc::clone(device),
        })
    }

    /// The archive whose descriptor is as large as a producer seals one: as many recipients as fit
    /// under the descriptor's bound.
    fn largest(device: &Arc<Device>) -> Self {
        let (mut fits, mut past) = (1, kr_protocol::archive::MAX_ARCHIVE_RECIPIENTS + 1);
        while past - fits > 1 {
            let middle = usize::midpoint(fits, past);
            if Self::sealed_for(device, 1, middle).is_some() {
                fits = middle;
            } else {
                past = middle;
            }
        }
        Self::sealed_for(device, 1, fits).expect("the largest archive that fits")
    }

    /// The key that writes and owns the archive.
    fn writer(&self) -> &AuthorisationKeyPair {
        &self.device.0
    }

    /// The owner's enrolment of the writer, at `revision`.
    fn enrolment(&self, revision: u64) -> BackupWriterRecord {
        let payload = BackupWriterRecordPayload {
            archive_id: archive_id(),
            writer: TrustedWriter {
                writer_key_id: self.writer().key_id(),
                signing_key: *self.writer().public(),
                enrolled_at_ms: TimestampMs::new(1_000),
            },
            writer_revision: BackupWriterRevision::new(revision),
            owner_key_id: self.writer().key_id(),
            enrolled_at_ms: TimestampMs::new(1_000),
        };
        let transcript = kr_crypto::sign::SigningTranscript::from_canonical_bytes(
            kr_protocol::archive::BACKUP_WRITER_DOMAIN,
            payload.signing_input().expect("an enrolment input"),
        )
        .expect("a transcript");
        BackupWriterRecord {
            signature: kr_crypto::sign::sign(self.writer(), &transcript).expect("a signature"),
            payload,
        }
    }

    /// The writer's publication of this generation, published at `2_000` milliseconds.
    fn publication(&self) -> BackupGenerationPublication {
        self.publication_at(2_000)
    }

    fn publication_at(&self, published_at_ms: u64) -> BackupGenerationPublication {
        let payload = BackupGenerationPublicationPayload {
            descriptor: self.sealed.descriptor.clone(),
            writer_key_id: self.writer().key_id(),
            published_at_ms: TimestampMs::new(published_at_ms),
        };
        let transcript = kr_crypto::sign::SigningTranscript::from_canonical_bytes(
            kr_protocol::archive::BACKUP_PUBLICATION_DOMAIN,
            payload.signing_input().expect("a publication input"),
        )
        .expect("a transcript");
        BackupGenerationPublication {
            signature: kr_crypto::sign::sign(self.writer(), &transcript).expect("a signature"),
            payload,
        }
    }
}

/// KR-REQ-20.12: the writer is enrolled, a generation is published under its signature with the
/// account's token beside it, and a fetch answers with the publication exactly as it was
/// published; an enrolment and a fetch carry no token.
#[tokio::test]
async fn the_backup_manifest_enrols_publishes_and_fetches_as_the_service_answers() {
    let web = Arc::new(StorageWeb::new());
    let device = Device::generate();
    let tokens = Tokens::signed_in();
    let publisher = manifest(&web, &device, Some(&tokens));
    let archive = Archive::sealed(&device, 1);

    let enrolled = publisher
        .enrol(&archive.enrolment(1))
        .await
        .expect("an enrolment");
    assert!(enrolled.changed);
    assert_eq!(enrolled.writer.writer_key_id, archive.writer().key_id());
    assert_eq!(enrolled.writer.writer_revision, 1);
    assert_eq!(enrolled.collection.archive_id, archive_id());
    assert!(
        !publisher
            .enrol(&archive.enrolment(1))
            .await
            .expect("the same enrolment")
            .changed
    );

    assert_eq!(
        publisher
            .fetch(archive_id(), None, None)
            .await
            .expect("an answer"),
        None,
        "nothing published yet"
    );
    let publication = archive.publication();
    let ArchiveAnswer::Done(published) = publisher.publish(&publication).await.expect("an answer")
    else {
        panic!("a publication");
    };
    assert!(!published.duplicate);
    assert_eq!(
        published.generation.backup_generation,
        BackupGeneration::new(1)
    );
    assert_eq!(
        published.generation.encrypted_manifest_hash,
        archive
            .sealed
            .descriptor
            .encrypted_manifest
            .encrypted_object_hash
    );
    assert_eq!(published.collection.checkpoint_generation, 1);

    let fetched = publisher
        .fetch(archive_id(), Some(BackupGeneration::new(1)), None)
        .await
        .expect("an answer")
        .expect("the generation");
    assert_eq!(
        fetched.publication, publication,
        "exactly as it was published"
    );
    assert_eq!(
        fetched.current_writer.writer_key_id,
        archive.writer().key_id()
    );
    assert_eq!(
        publisher
            .fetch(archive_id(), Some(BackupGeneration::new(2)), None)
            .await
            .expect("an answer"),
        None,
        "a generation the service does not hold"
    );

    let carried: Vec<(Option<String>, bool)> = web
        .arrived()
        .iter()
        .map(|arrived| (arrived.token.clone(), arrived.body.get("publish").is_some()))
        .collect();
    for (token, publishes) in carried {
        assert_eq!(
            token.is_some(),
            publishes,
            "a token beside a publication and beside nothing else"
        );
    }
}

/// A publication sent again is answered as a duplicate and stores nothing twice; different content
/// for a generation already published, and an enrolment by another owner, are refused.
#[tokio::test]
async fn a_publication_sent_again_is_a_duplicate_and_other_content_for_it_is_refused() {
    let web = Arc::new(StorageWeb::new());
    let device = Device::generate();
    let publisher = manifest(&web, &device, Some(&Tokens::signed_in()));
    let archive = Archive::sealed(&device, 1);
    publisher
        .enrol(&archive.enrolment(1))
        .await
        .expect("an enrolment");
    let publication = archive.publication();
    publisher.publish(&publication).await.expect("published");

    web.fail("/api/backup/manifest", 1, Moment::After);
    publisher
        .publish(&publication)
        .await
        .expect_err("the answer was lost");
    let ArchiveAnswer::Done(again) = publisher.publish(&publication).await.expect("an answer")
    else {
        panic!("a publication");
    };
    assert!(again.duplicate);
    assert_eq!(web.generations(&archive_id().to_string()), [1]);

    let other = publisher
        .publish(&archive.publication_at(3_000))
        .await
        .expect_err("other content for a generation already published");
    refused(
        &other,
        ErrorCode::PermissionDenied,
        UserAction::FixConfiguration,
    );
    assert!(other.to_string().contains("different content"), "{other}");

    let stranger = Device::generate();
    let taken = manifest(&web, &stranger, None)
        .enrol(&Archive::sealed(&stranger, 1).enrolment(2))
        .await
        .expect_err("another owner's collection");
    refused(
        &taken,
        ErrorCode::PermissionDenied,
        UserAction::FixConfiguration,
    );
}

/* -------------------------------------------------------------------------- */
/* Controls                                                                    */
/* -------------------------------------------------------------------------- */

/// The control: without the account's proof for `backup.write` nothing is sent where the service
/// asks for it. A client given no account sends no storage request and no publication, and a
/// sign-in that was not granted `backup.write` has its source refuse the token, so nothing leaves
/// either. An enrolment and a fetch, which spend nothing, still go.
#[tokio::test]
async fn nothing_is_sent_without_the_accounts_proof_where_the_service_asks_for_it() {
    let web = Arc::new(StorageWeb::new());
    let device = Device::generate();
    let archive = Archive::sealed(&device, 1);
    let bytes = ciphertext(64);
    let upload_id = kr_client::services::UploadId::new("an-upload").expect("an id");
    let table = PartTable::for_total(64).expect("a table");

    for (what, tokens) in [
        ("no account", None),
        ("no backup.write", Some(Tokens::without_backup_write())),
    ] {
        let client = storage(&web, &device, tokens.as_ref());
        let refusals = [
            client.status().await.map(|_| ()),
            client
                .set_retention(&RetentionChange {
                    backup: BackupState::On,
                    daily_snapshots: None,
                    expected_revision: 0,
                })
                .await
                .map(|_| ()),
            client
                .create_upload(&new_upload(1, &bytes))
                .await
                .map(|_| ()),
            client
                .upload_part(
                    &upload_id,
                    UploadPart {
                        number: 1,
                        bytes: &bytes,
                    },
                )
                .await
                .map(|_| ()),
            client.complete_upload(&upload_id, &table).await.map(|_| ()),
            client.abort_upload(&upload_id).await.map(|_| ()),
            client
                .read_object(archive_id(), object_id(1), 0, 16)
                .await
                .map(|_| ()),
            client
                .delete_object(archive_id(), object_id(1))
                .await
                .map(|_| ()),
            manifest(&web, &device, tokens.as_ref())
                .publish(&archive.publication())
                .await
                .map(|_| ()),
        ];
        for refusal in refusals {
            let error = refusal.expect_err(what);
            assert!(
                matches!(
                    error.code(),
                    ErrorCode::HostNotConfigured | ErrorCode::PermissionDenied
                ),
                "{what}: {error}"
            );
        }
        assert!(web.arrived().is_empty(), "{what}: nothing was sent");
    }

    let publisher = manifest(&web, &device, None);
    publisher
        .enrol(&archive.enrolment(1))
        .await
        .expect("an enrolment spends nothing");
    publisher
        .fetch(archive_id(), None, None)
        .await
        .expect("a fetch spends nothing");
    assert!(web.arrived().iter().all(|arrived| arrived.token.is_none()));
}

/// The control: a client with no managed storage or manifest configured answers every call as the
/// null service does, which is that no sync and backup service is configured.
#[tokio::test]
async fn a_client_with_no_storage_service_answers_as_the_null_service_does() {
    let storage: Arc<dyn StorageService> = Arc::new(NullService);
    let manifest: Arc<dyn BackupManifestService> = Arc::new(NullService);
    let bytes = ciphertext(8);
    let upload_id = kr_client::services::UploadId::new("an-upload").expect("an id");
    let table = PartTable::for_total(8).expect("a table");
    let archive = Archive::sealed(&Device::generate(), 1);
    let answers = [
        storage.status().await.map(|_| ()),
        storage
            .set_retention(&RetentionChange {
                backup: BackupState::On,
                daily_snapshots: None,
                expected_revision: 0,
            })
            .await
            .map(|_| ()),
        storage
            .create_upload(&new_upload(1, &bytes))
            .await
            .map(|_| ()),
        storage
            .upload_part(
                &upload_id,
                UploadPart {
                    number: 1,
                    bytes: &bytes,
                },
            )
            .await
            .map(|_| ()),
        storage
            .complete_upload(&upload_id, &table)
            .await
            .map(|_| ()),
        storage.abort_upload(&upload_id).await.map(|_| ()),
        storage
            .read_object(archive_id(), object_id(1), 0, 8)
            .await
            .map(|_| ()),
        storage
            .delete_object(archive_id(), object_id(1))
            .await
            .map(|_| ()),
        manifest.enrol(&archive.enrolment(1)).await.map(|_| ()),
        manifest.publish(&archive.publication()).await.map(|_| ()),
        manifest.fetch(archive_id(), None, None).await.map(|_| ()),
    ];
    for answer in answers {
        let error = answer.expect_err("nothing is configured");
        assert_eq!(error.code(), ErrorCode::HostNotConfigured);
        assert!(error.to_string().contains("sync and backup"), "{error}");
    }
    let dispatched = manifest
        .publish_dispatched(&archive.publication())
        .await
        .expect("an answer about the request");
    let Dispatched::NotSent(error) = dispatched else {
        panic!("nothing is configured, so nothing was sent: {dispatched:?}");
    };
    assert_eq!(error.code(), ErrorCode::HostNotConfigured);
}

/// A publisher learns whether a publication that went unanswered left this device: one refused
/// here, for want of an account, cannot have landed; one the transport was given may have, and is an
/// error; one the service answered is its answer.
#[tokio::test]
async fn a_publication_says_whether_it_left_this_device() {
    let web = Arc::new(StorageWeb::new());
    let device = Device::generate();
    let archive = Archive::sealed(&device, 1);
    manifest(&web, &device, None)
        .enrol(&archive.enrolment(1))
        .await
        .expect("an enrolment");

    let dispatched = manifest(&web, &device, None)
        .publish_dispatched(&archive.publication())
        .await
        .expect("an answer about the request");
    assert!(
        matches!(dispatched, Dispatched::NotSent(_)),
        "{dispatched:?}"
    );
    assert!(web.generations(&archive_id().to_string()).is_empty());

    let publisher = manifest(&web, &device, Some(&Tokens::signed_in()));
    web.fail("/api/backup/manifest", 1, Moment::After);
    publisher
        .publish_dispatched(&archive.publication())
        .await
        .expect_err("it may have landed");
    let again = publisher
        .publish_dispatched(&archive.publication())
        .await
        .expect("an answer");
    let Dispatched::Answered(ArchiveAnswer::Done(published)) = again else {
        panic!("answered: {again:?}");
    };
    assert!(published.duplicate, "it had landed");
}

/* -------------------------------------------------------------------------- */
/* Through the transport                                                       */
/* -------------------------------------------------------------------------- */

/// Serves every request on `listener` with `answer`, as a plain HTTP service on loopback would.
async fn serve(listener: tokio::net::TcpListener, answer: Vec<u8>) {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    while let Ok((mut socket, _)) = listener.accept().await {
        let answer = answer.clone();
        tokio::spawn(async move {
            // The request's head, and its body as long as the head says it is.
            let mut request = Vec::new();
            let mut buffer = [0_u8; 16 * 1024];
            loop {
                let Ok(read) = socket.read(&mut buffer).await else {
                    return;
                };
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..read]);
                let Some(end) = request.windows(4).position(|window| window == b"\r\n\r\n") else {
                    continue;
                };
                let head = String::from_utf8_lossy(&request[..end]).to_ascii_lowercase();
                let length = head
                    .lines()
                    .find_map(|line| line.strip_prefix("content-length:"))
                    .and_then(|value| value.trim().parse::<usize>().ok())
                    .unwrap_or(0);
                if request.len() >= end + 4 + length {
                    break;
                }
            }
            let head = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                answer.len()
            );
            let _ = socket.write_all(head.as_bytes()).await;
            let _ = socket.write_all(&answer).await;
            let _ = socket.shutdown().await;
        });
    }
}

/// A fetch of the largest descriptor a producer seals answers with more than the transport reads of
/// an ordinary answer, and the manifest's own bound reads it whole, through the transport a
/// composition root builds. The control: the same answer under the ordinary bound is refused as
/// too large.
#[tokio::test]
async fn a_fetch_of_the_largest_descriptor_is_read_under_the_manifests_own_bound() {
    use kr_client::services::backup::BACKUP_ANSWER_LIMIT_BYTES;
    use kr_client::services::http::DEFAULT_RESPONSE_LIMIT_BYTES;
    use kr_client::services::{
        HttpDeadlines, HttpService, ResponseLimits, managed_response_limits,
    };

    let device = Device::generate();
    let archive = Archive::largest(&device);
    let publication = archive.publication();
    let generations: Vec<String> = (1..=16)
        .rev()
        .map(|generation: u64| generation.to_string())
        .collect();
    let writer = serde_json::json!({
        "writer_key_id": archive.writer().key_id(),
        "writer_revision": "1",
        "enrolled_at": "2026-09-25T16:00:00.000Z",
    });
    let answer = serde_json::to_vec(&serde_json::json!({
        "ok": true,
        "data": {
            "publication": publication,
            "published_at": "2026-09-25T17:00:00.000Z",
            "collection": {
                "archive_id": archive_id(),
                "checkpoint_generation": "16",
                "generations": generations,
                "bytes": "1048576",
                "allowance_bytes": "10737418240",
            },
            "current_writer": writer,
        },
    }))
    .expect("an answer");
    assert!(
        answer.len() as u64 > DEFAULT_RESPONSE_LIMIT_BYTES,
        "the largest fetch is {} bytes, past the ordinary bound",
        answer.len()
    );
    assert!(
        answer.len() as u64 <= BACKUP_ANSWER_LIMIT_BYTES,
        "the largest fetch is {} bytes, within the manifest's own bound",
        answer.len()
    );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a loopback listener");
    let origin = GatewayOrigin::new(format!(
        "http://127.0.0.1:{}",
        listener.local_addr().expect("an address").port()
    ))
    .expect("a loopback origin");
    let server = tokio::spawn(serve(listener, answer));

    let fetch = |limits: ResponseLimits| {
        let origin = origin.clone();
        let device = Arc::clone(&device);
        async move {
            let http = HttpService::with(origin.clone(), HttpDeadlines::default(), limits)
                .expect("a transport");
            ManagedBackupManifestService::new(
                origin,
                Arc::new(http) as Arc<_>,
                device as Arc<dyn ServiceSigner>,
            )
            .fetch(archive_id(), Some(BackupGeneration::new(1)), None)
            .await
        }
    };

    let fetched = fetch(managed_response_limits())
        .await
        .expect("an answer")
        .expect("the generation");
    assert_eq!(fetched.publication, publication, "read whole");
    let refused = fetch(ResponseLimits::default())
        .await
        .expect_err("too large for the ordinary bound");
    assert!(refused.to_string().contains("bytes"), "{refused}");
    server.abort();
}
