//! Managed storage and the backup manifest, answering as the managed service answers them.
//!
//! It checks what the service checks before it acts: the signature over the digest of the
//! canonical body, the method the credential names, the installation the body names against the key
//! that signed, and the account token beside the request. It keeps what the service keeps: whether
//! backup storage is on and at which revision, who owns each archive, each upload's part table and
//! parts, each stored object, and each collection's writer, checkpoint and publications. Its
//! refusals are the service's codes, at the service's statuses, for the service's reasons.
//!
//! A test can also make the transport fail, before the service sees a request or after it acted
//! on one, which is how an interrupted transfer and a lost answer are made.

#![allow(
    dead_code,
    reason = "each suite that includes this uses the part it needs"
)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

use base64::Engine as _;
use kr_client::error::ClientError;
use kr_client::services::{ServiceFuture, ServiceHttp, ServiceHttpAnswer};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::service::{ServiceRequestSignature, canonical_body_digest, installation_id};

/// The one account this web knows, and the token that proves it.
pub const ACCOUNT: &str = "account-one";

/// The token that proves [`ACCOUNT`].
pub const TOKEN: &str = "the-account-token";

/// The part size, which is the protocol's.
pub const PART: u64 = 8 * 1024 * 1024;

/// Where a fault meets a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Moment {
    /// The transport fails before the service sees the request.
    Before,
    /// The service acts on the request and its answer is lost.
    After,
}

/// One fault a test arranged: the `nth` request to `path` from now on, counting from one, fails.
#[derive(Clone, Copy, Debug)]
struct Fault {
    path: &'static str,
    nth: u32,
    moment: Moment,
}

/// One request as the transport was given it.
#[derive(Clone, Debug)]
pub struct Arrived {
    /// Where it was addressed, without the origin.
    pub path: String,
    /// The signed document's body.
    pub body: serde_json::Value,
    /// The account token beside it, if one was.
    pub token: Option<String>,
    /// The content beside it, for a part.
    pub content: Option<Vec<u8>>,
    /// Whether the service saw it.
    pub reached: bool,
}

/// One upload, as the service's upload object keeps it.
#[derive(Clone, Debug)]
struct Upload {
    archive: String,
    object: String,
    generation: u64,
    total: u64,
    declared: u64,
    hash: String,
    installation: String,
    account: Option<String>,
    /// Each part's declared length and hash, and its bytes.
    parts: BTreeMap<u64, (u64, String, Vec<u8>)>,
    state: UploadState,
}

/// Where one upload has got to.
#[derive(Clone, Debug, PartialEq, Eq)]
enum UploadState {
    Open,
    Expired,
    Completed(serde_json::Value),
    Cleaned,
}

/// One stored object.
#[derive(Clone, Debug)]
enum Object {
    Uploading,
    Stored { bytes: Vec<u8>, principal: String },
    Tombstoned { principal: String, bytes: u64 },
}

/// One manifest collection.
#[derive(Clone, Debug)]
struct Collection {
    owner_key: String,
    writer_key_id: String,
    writer_revision: u64,
    writer_digest: String,
    checkpoint: u64,
    generations: BTreeMap<u64, (String, serde_json::Value)>,
}

/// Everything the service keeps.
#[derive(Debug, Default)]
struct State {
    backup_on: bool,
    revision: u64,
    daily_snapshots: u32,
    archives: BTreeMap<String, String>,
    deleted: BTreeSet<String>,
    objects: BTreeMap<(String, String), Object>,
    uploads: BTreeMap<String, Upload>,
    next_upload: u32,
    collections: BTreeMap<String, Collection>,
    nonces: BTreeSet<String>,
}

/// Managed storage and the backup manifest.
#[derive(Debug, Default)]
pub struct StorageWeb {
    state: Mutex<State>,
    arrived: Mutex<Vec<Arrived>>,
    faults: Mutex<Vec<Fault>>,
}

impl StorageWeb {
    /// A service holding nothing, with backup storage off.
    #[must_use]
    pub fn new() -> Self {
        let web = Self::default();
        web.state.lock().expect("the state").daily_snapshots = 30;
        web
    }

    /// The `nth` request to `path` from now on fails at `moment`.
    pub fn fail(&self, path: &'static str, nth: u32, moment: Moment) {
        self.faults
            .lock()
            .expect("the faults")
            .push(Fault { path, nth, moment });
    }

    /// Every request the transport was given, in order.
    #[must_use]
    pub fn arrived(&self) -> Vec<Arrived> {
        self.arrived.lock().expect("what arrived").clone()
    }

    /// How many requests went to `path`, reaching the service or not.
    #[must_use]
    pub fn requests_to(&self, path: &str) -> usize {
        self.arrived()
            .iter()
            .filter(|arrived| arrived.path == path)
            .count()
    }

    /// The part numbers sent, in order, each time one was sent.
    #[must_use]
    pub fn parts_sent(&self) -> Vec<u64> {
        self.arrived()
            .iter()
            .filter(|arrived| arrived.path == "/api/storage/upload/part")
            .map(|arrived| arrived.body["part_number"].as_u64().expect("a part number"))
            .collect()
    }

    /// The bytes stored under one object, if the service stores it.
    #[must_use]
    pub fn stored(&self, archive: &str, object: &str) -> Option<Vec<u8>> {
        match self
            .state
            .lock()
            .expect("the state")
            .objects
            .get(&(archive.to_owned(), object.to_owned()))
        {
            Some(Object::Stored { bytes, .. }) => Some(bytes.clone()),
            _ => None,
        }
    }

    /// How many objects the service stores, tombstones aside.
    #[must_use]
    pub fn stored_objects(&self) -> usize {
        self.state
            .lock()
            .expect("the state")
            .objects
            .values()
            .filter(|object| matches!(object, Object::Stored { .. }))
            .count()
    }

    /// The generations one collection holds.
    #[must_use]
    pub fn generations(&self, archive: &str) -> Vec<u64> {
        self.state
            .lock()
            .expect("the state")
            .collections
            .get(archive)
            .map(|collection| collection.generations.keys().copied().collect())
            .unwrap_or_default()
    }

    /// The owner deletes one archive's collection from the account console.
    pub fn delete_collection(&self, archive: &str) {
        self.state
            .lock()
            .expect("the state")
            .deleted
            .insert(archive.to_owned());
    }

    /// Every open upload passes its lifetime.
    pub fn expire_uploads(&self) {
        for upload in self.state.lock().expect("the state").uploads.values_mut() {
            if upload.state == UploadState::Open {
                upload.state = UploadState::Expired;
            }
        }
    }

    /// Backup storage is turned on or off by some other client.
    pub fn set_backup(&self, on: bool) {
        let mut state = self.state.lock().expect("the state");
        state.backup_on = on;
        state.revision += 1;
    }

    /// Answers one request as the service does, or fails as a test arranged.
    fn take(
        &self,
        url: &str,
        document: Option<serde_json::Value>,
        headers: &[(&str, &str)],
        content: Option<&[u8]>,
    ) -> kr_client::Result<ServiceHttpAnswer> {
        let path = url
            .strip_prefix("https://reach.kala.to")
            .expect("the gateway this suite addresses")
            .to_owned();
        let token = headers
            .iter()
            .find(|(name, _)| *name == "authorization")
            .map(|(_, value)| {
                value
                    .strip_prefix("Bearer ")
                    .expect("a bearer token")
                    .to_owned()
            });
        let document = match document {
            Some(document) => document,
            None => {
                let carried = headers
                    .iter()
                    .find(|(name, _)| *name == "kr-service-request")
                    .expect("a part carries its signed request in a header")
                    .1;
                let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(carried)
                    .expect("unpadded base64url");
                serde_json::from_slice(&bytes).expect("a signed request")
            }
        };
        let moment = {
            let mut faults = self.faults.lock().expect("the faults");
            let mut met = None;
            for fault in faults.iter_mut().filter(|fault| path == fault.path) {
                fault.nth -= 1;
                if fault.nth == 0 {
                    met = Some(fault.moment);
                }
            }
            faults.retain(|fault| fault.nth > 0);
            met
        };
        let reached = moment != Some(Moment::Before);
        self.arrived.lock().expect("what arrived").push(Arrived {
            path: path.clone(),
            body: document["body"].clone(),
            token: token.clone(),
            content: content.map(<[u8]>::to_vec),
            reached,
        });
        let lost = || {
            Err(ClientError::Host(ProtocolError::new(
                ErrorCode::UpstreamUnavailable,
                "the connection dropped".to_owned(),
            )))
        };
        if !reached {
            return lost();
        }
        let answer = self.answer(&path, &document, token.as_deref(), content);
        if moment == Some(Moment::After) {
            return lost();
        }
        Ok(answer)
    }

    /// What the service answers one request that reached it.
    fn answer(
        &self,
        path: &str,
        document: &serde_json::Value,
        token: Option<&str>,
        content: Option<&[u8]>,
    ) -> ServiceHttpAnswer {
        let method = match path {
            "/api/storage/status" => "storage.status",
            "/api/storage/retention" => "storage.retention.set",
            "/api/storage/upload/create" => "storage.upload.create",
            "/api/storage/upload/part" => "storage.upload.part",
            "/api/storage/upload/complete" => "storage.upload.complete",
            "/api/storage/upload/abort" => "storage.upload.abort",
            "/api/storage/object/read" => "storage.object.read",
            "/api/storage/object/delete" => "storage.object.delete",
            "/api/backup/manifest" => "backup.manifest",
            other => panic!("no route at {other}"),
        };
        let signature: ServiceRequestSignature =
            serde_json::from_value(document["signature"].clone()).expect("a credential");
        let body = &document["body"];
        let digest = canonical_body_digest(body).expect("a canonical body");
        if signature.payload.body_digest != digest
            || signature.payload.method.as_str() != method
            || !verifies(&signature)
        {
            return refusal(
                401,
                "UNAUTHENTICATED",
                "That request was not signed as it says.",
            );
        }
        let nonce = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(signature.payload.nonce.as_bytes());
        let mut state = self.state.lock().expect("the state");
        if !state.nonces.insert(nonce) {
            return refusal(
                401,
                "UNAUTHENTICATED",
                "That request has already been made.",
            );
        }
        let caller = installation_id(&signature.public_key).to_string();
        if method == "backup.manifest" {
            return manifest(&mut state, &signature, body, token);
        }
        if body["installation_id"].as_str() != Some(caller.as_str()) {
            return refusal(
                403,
                "FORBIDDEN",
                "That request names an installation other than the one whose key carried it.",
            );
        }
        // The account half is proved only by the token this web issued for its one account.
        let account = token.filter(|token| *token == TOKEN).map(|_| ACCOUNT);
        let principal = account.map_or_else(
            || format!("installation:{caller}"),
            |account| format!("account:{account}"),
        );
        match method {
            "storage.status" => status(&state, &principal, account.is_some()),
            "storage.retention.set" => retention(&mut state, body, account.is_some()),
            "storage.upload.create" => create(&mut state, body, &caller, account, &principal),
            "storage.upload.part" => part(&mut state, body, &caller, account, content),
            "storage.upload.complete" => complete(&mut state, body, &caller, account),
            "storage.upload.abort" => abort(&mut state, body, &caller, account),
            "storage.object.read" => read(&state, body, &principal),
            _ => delete(&mut state, body, &principal),
        }
    }
}

impl ServiceHttp for StorageWeb {
    fn post_json<'a>(
        &'a self,
        url: &'a str,
        body: &'a [u8],
        headers: &'a [(&'a str, &'a str)],
    ) -> ServiceFuture<'a, ServiceHttpAnswer> {
        let document = serde_json::from_slice(body).expect("a signed request");
        let answer = self.take(url, Some(document), headers, None);
        Box::pin(async move { answer })
    }

    fn post_bytes<'a>(
        &'a self,
        url: &'a str,
        body: &'a [u8],
        headers: &'a [(&'a str, &'a str)],
    ) -> ServiceFuture<'a, ServiceHttpAnswer> {
        let answer = self.take(url, None, headers, Some(body));
        Box::pin(async move { answer })
    }
}

/// Whether the credential verifies under the key it names, in its signer's domain.
fn verifies(signature: &ServiceRequestSignature) -> bool {
    let Ok(input) = signature.signing_input() else {
        return false;
    };
    let Ok(transcript) =
        kr_crypto::sign::SigningTranscript::from_canonical_bytes(signature.signer.domain(), input)
    else {
        return false;
    };
    kr_crypto::sign::verify(&signature.public_key, &transcript, &signature.signature).is_ok()
}

/// A success, in the service's envelope.
fn answered(data: serde_json::Value) -> ServiceHttpAnswer {
    ServiceHttpAnswer {
        status: 200,
        body: serde_json::to_vec(&serde_json::json!({ "ok": true, "data": data }))
            .expect("an answer"),
    }
}

/// A refusal, in the service's envelope.
pub fn refusal(status: u16, code: &str, message: &str) -> ServiceHttpAnswer {
    ServiceHttpAnswer {
        status,
        body: serde_json::to_vec(&serde_json::json!({
            "ok": false,
            "error": { "code": code, "message": message },
        }))
        .expect("a refusal"),
    }
}

/// The retention the service publishes.
fn retention_policy(daily_snapshots: u32) -> serde_json::Value {
    serde_json::json!({
        "daily_snapshots": daily_snapshots,
        "tombstone_days": 7,
        "provider_recovery_days": 30,
    })
}

/// The figures the deployment pins.
fn limits() -> serde_json::Value {
    serde_json::json!({
        "part_size_bytes": PART.to_string(),
        "max_object_bytes": (1024 * 1024 * 1024_u64).to_string(),
        "max_parts": 128,
        "max_read_bytes": PART.to_string(),
        "upload_lifetime_seconds": 3600,
        "outstanding_uploads": 2,
    })
}

/// A decimal counter the body names, as the service reads one.
fn counter(value: &serde_json::Value) -> Option<u64> {
    let text = value.as_str()?;
    if text.is_empty() || text.len() > 16 || (text.len() > 1 && text.starts_with('0')) {
        return None;
    }
    text.parse().ok()
}

/// A lower-case hyphenated identifier the body names, as the service reads one.
fn identifier(value: &serde_json::Value) -> Option<String> {
    let text = value.as_str()?;
    let shaped = text.len() == 36
        && text.char_indices().all(|(at, character)| match at {
            8 | 13 | 18 | 23 => character == '-',
            _ => character.is_ascii_digit() || ('a'..='f').contains(&character),
        });
    shaped.then(|| text.to_owned())
}

fn status(state: &State, principal: &str, funded: bool) -> ServiceHttpAnswer {
    let on = funded && state.backup_on;
    let owned = |wanted: &str| {
        state
            .objects
            .values()
            .filter(|object| match object {
                Object::Stored {
                    principal: owner, ..
                } => wanted == "stored" && owner == principal,
                Object::Tombstoned {
                    principal: owner, ..
                } => wanted == "tombstoned" && owner == principal,
                Object::Uploading => false,
            })
            .count()
    };
    answered(serde_json::json!({
        "principal": principal,
        "backup": if on { "on" } else { "off" },
        "retention_revision": if funded { state.revision } else { 0 }.to_string(),
        "retention": retention_policy(state.daily_snapshots),
        "stored": { "objects": owned("stored"), "bytes": "0" },
        "tombstoned": { "objects": owned("tombstoned"), "bytes": "0", "next_purge": null },
        "uploading": { "objects": 0, "bytes": "0", "reserved_bytes": "0" },
        "allowance_bytes": if funded { serde_json::json!("10737418240") } else { serde_json::Value::Null },
        "limits": limits(),
    }))
}

fn retention(state: &mut State, body: &serde_json::Value, funded: bool) -> ServiceHttpAnswer {
    let asked = match body["backup"].as_str() {
        Some("on") => true,
        Some("off") => false,
        _ => {
            return refusal(
                400,
                "INVALID_REQUEST",
                "A retention change turns backup on or off.",
            );
        }
    };
    let snapshots = match &body["daily_snapshots"] {
        serde_json::Value::Null => None,
        declared => match declared.as_u64() {
            Some(snapshots @ 1..=30) => Some(u32::try_from(snapshots).expect("a count")),
            _ => {
                return refusal(
                    400,
                    "INVALID_REQUEST",
                    "Snapshots kept is between one and 30.",
                );
            }
        },
    };
    let Some(expected) = counter(&body["expected_revision"]) else {
        return refusal(
            400,
            "INVALID_REQUEST",
            "A retention change names the revision it was decided against.",
        );
    };
    if asked && !funded {
        return refusal(
            402,
            "QUOTA_EXHAUSTED",
            "This installation has no backup storage. Sign this host in to an account whose plan includes backup storage, and try again.",
        );
    }
    if expected != state.revision {
        return refusal(
            400,
            "INVALID_REQUEST",
            "That change was decided against another revision. Read it again and decide against that.",
        );
    }
    let changed =
        asked != state.backup_on || snapshots.is_some_and(|kept| kept != state.daily_snapshots);
    if changed {
        state.backup_on = asked;
        state.daily_snapshots = snapshots.unwrap_or(state.daily_snapshots);
        state.revision += 1;
    }
    answered(serde_json::json!({
        "state": if changed { "set" } else { "unchanged" },
        "backup": if state.backup_on { "on" } else { "off" },
        "retention": retention_policy(state.daily_snapshots),
        "revision": state.revision,
    }))
}

fn create(
    state: &mut State,
    body: &serde_json::Value,
    caller: &str,
    account: Option<&str>,
    principal: &str,
) -> ServiceHttpAnswer {
    let (Some(archive), Some(object)) = (
        identifier(&body["archive_id"]),
        identifier(&body["object_id"]),
    ) else {
        return refusal(
            400,
            "INVALID_REQUEST",
            "An upload names the archive and the object it is for.",
        );
    };
    let generation = counter(&body["backup_generation"]).filter(|generation| *generation > 0);
    let declared = counter(&body["declared_max_bytes"]);
    let total = counter(&body["total_bytes"]);
    let hash = body["encrypted_object_hash"].as_str().map(str::to_owned);
    let (Some(generation), Some(declared), Some(total), Some(hash)) =
        (generation, declared, total, hash)
    else {
        return refusal(
            400,
            "INVALID_REQUEST",
            "That upload is not declared as the service reads one.",
        );
    };
    if total == 0 || total > declared || declared > 1024 * 1024 * 1024 {
        return refusal(
            400,
            "INVALID_REQUEST",
            "An object is between one byte and the maximum the upload declares.",
        );
    }
    if account.is_none() {
        return refusal(
            402,
            "QUOTA_EXHAUSTED",
            "This installation has no backup storage. Sign this host in to an account whose plan includes backup storage, and try again.",
        );
    }
    if !state.backup_on {
        return refusal(
            403,
            "FORBIDDEN",
            "Managed backup storage is off for this account. Turn it on with storage.retention.set, then upload.",
        );
    }
    if state
        .archives
        .get(&archive)
        .is_some_and(|owner| owner != principal)
    {
        return refusal(403, "FORBIDDEN", "That archive belongs to another account.");
    }
    if state.deleted.contains(&archive) {
        return refusal(
            410,
            "COLLECTION_DELETED",
            "That backup collection was deleted from the account console. Enrol a new collection to back up again.",
        );
    }
    let key = (archive.clone(), object.clone());
    let live = state.objects.get(&key).is_some_and(|held| match held {
        Object::Uploading => state.uploads.values().any(|upload| {
            upload.archive == archive
                && upload.object == object
                && upload.state == UploadState::Open
        }),
        Object::Stored { .. } => true,
        Object::Tombstoned { .. } => false,
    });
    if live {
        return refusal(
            403,
            "FORBIDDEN",
            "That object of that archive is already being uploaded or already stored. Continue that upload, or delete the object first.",
        );
    }
    state.archives.insert(archive.clone(), principal.to_owned());
    state.objects.insert(key, Object::Uploading);
    state.next_upload += 1;
    let upload_id = format!("upload-{:04}-{}", state.next_upload, &object[..8]);
    let parts = total.div_ceil(PART);
    state.uploads.insert(
        upload_id.clone(),
        Upload {
            archive,
            object,
            generation,
            total,
            declared,
            hash,
            installation: caller.to_owned(),
            account: account.map(str::to_owned),
            parts: BTreeMap::new(),
            state: UploadState::Open,
        },
    );
    answered(serde_json::json!({
        "state": "created",
        "layout": {
            "total_bytes": total.to_string(),
            "part_size_bytes": PART.to_string(),
            "part_count": parts,
            "final_part_bytes": (total - (parts - 1) * PART).to_string(),
        },
        "upload_id": upload_id,
        "principal": principal,
        "reserved_bytes": declared.to_string(),
        "expires_at": "2026-09-25T18:00:00.000Z",
        "limits": limits(),
    }))
}

/// The upload a request names, when this caller may reach it.
fn reach<'a>(
    state: &'a mut State,
    body: &serde_json::Value,
    caller: &str,
    account: Option<&str>,
) -> Result<(&'a mut Upload, String), ServiceHttpAnswer> {
    let upload_id = body["upload_id"].as_str().unwrap_or_default().to_owned();
    let Some(upload) = state.uploads.get_mut(&upload_id) else {
        return Err(refusal(404, "NOT_FOUND", "No such upload."));
    };
    if upload.installation != caller {
        return Err(refusal(
            403,
            "FORBIDDEN",
            "That upload belongs to another installation.",
        ));
    }
    if upload.account.as_deref() != account {
        return Err(refusal(
            403,
            "FORBIDDEN",
            "That upload is funded by another account.",
        ));
    }
    Ok((upload, upload_id))
}

fn part(
    state: &mut State,
    body: &serde_json::Value,
    caller: &str,
    account: Option<&str>,
    content: Option<&[u8]>,
) -> ServiceHttpAnswer {
    let content = content.expect("a part's content");
    let (upload, _) = match reach(state, body, caller, account) {
        Ok(reached) => reached,
        Err(refused) => return refused,
    };
    match &upload.state {
        UploadState::Open => {}
        UploadState::Expired => {
            return refusal(
                403,
                "FORBIDDEN",
                "This upload has expired, so it accepts no part.",
            );
        }
        UploadState::Completed(_) => {
            return refusal(403, "FORBIDDEN", "This upload is already stored.");
        }
        UploadState::Cleaned => return refusal(403, "FORBIDDEN", "This upload is closed."),
    }
    let (Some(number), Some(length), Some(sha)) = (
        body["part_number"].as_u64(),
        counter(&body["length_bytes"]),
        body["sha256"].as_str(),
    ) else {
        return refusal(
            400,
            "INVALID_REQUEST",
            "A part names its upload, its number, its length and its hash.",
        );
    };
    let parts = upload.total.div_ceil(PART);
    if number == 0 || number > parts {
        return refusal(
            400,
            "INVALID_REQUEST",
            "That part is not one this upload has.",
        );
    }
    let expected = if number < parts {
        PART
    } else {
        upload.total - (parts - 1) * PART
    };
    if length != expected {
        return refusal(
            400,
            "INVALID_REQUEST",
            "That part is not the length the part table gives it.",
        );
    }
    if let Some((held_length, held_sha, _)) = upload.parts.get(&number) {
        if *held_length != length || held_sha != sha {
            return refusal(
                403,
                "FORBIDDEN",
                "That part number was declared with a different length or hash.",
            );
        }
        return answered(part_answer(upload, number, length, "duplicate"));
    }
    let measured =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(kr_cbor::sha256(content));
    if content.len() as u64 != length {
        return refusal(
            400,
            "INVALID_REQUEST",
            "That part is not the length it declared.",
        );
    }
    if measured != sha {
        return refusal(
            400,
            "INVALID_REQUEST",
            "That part does not hash to the digest it declared.",
        );
    }
    upload
        .parts
        .insert(number, (length, sha.to_owned(), content.to_vec()));
    answered(part_answer(upload, number, length, "stored"))
}

fn part_answer(upload: &Upload, number: u64, length: u64, state: &str) -> serde_json::Value {
    serde_json::json!({
        "state": state,
        "part_number": number,
        "length_bytes": length.to_string(),
        "parts_stored": upload.parts.len(),
        "bytes_stored": upload.parts.values().map(|(length, _, _)| *length).sum::<u64>().to_string(),
    })
}

fn complete(
    state: &mut State,
    body: &serde_json::Value,
    caller: &str,
    account: Option<&str>,
) -> ServiceHttpAnswer {
    let deleted = state.deleted.clone();
    let (upload, _) = match reach(state, body, caller, account) {
        Ok(reached) => reached,
        Err(refused) => return refused,
    };
    if deleted.contains(&upload.archive) {
        return refusal(
            410,
            "COLLECTION_DELETED",
            "That backup collection was deleted from the account console. Enrol a new collection to back up again.",
        );
    }
    match &upload.state {
        UploadState::Completed(answer) => {
            let mut repeated = answer.clone();
            repeated["state"] = serde_json::json!("duplicate");
            return answered(repeated);
        }
        UploadState::Open => {}
        UploadState::Expired => return refusal(403, "FORBIDDEN", "This upload has expired."),
        UploadState::Cleaned => return refusal(403, "FORBIDDEN", "This upload is closed."),
    }
    let parts = upload.total.div_ceil(PART);
    if counter(&body["total_bytes"]) != Some(upload.total)
        || body["part_count"].as_u64() != Some(parts)
    {
        return refusal(
            400,
            "INVALID_REQUEST",
            "That is not the total and part count this upload was created with.",
        );
    }
    if u64::try_from(upload.parts.len()).expect("a count") != parts {
        return refusal(
            400,
            "INVALID_REQUEST",
            "This upload does not hold every part that total needs.",
        );
    }
    let bytes: Vec<u8> = upload
        .parts
        .values()
        .flat_map(|(_, _, bytes)| bytes.iter().copied())
        .collect();
    let answer = serde_json::json!({
        "state": "stored",
        "archive_id": upload.archive,
        "backup_generation": upload.generation.to_string(),
        "object": {
            "object_id": upload.object,
            "encrypted_object_hash": upload.hash,
            "encrypted_len": upload.total.to_string(),
        },
        "size_bucket_bytes": upload.total.next_power_of_two().to_string(),
        "stored_at": "2026-09-25T17:00:00.000Z",
        "committed_bytes": upload.total.to_string(),
        "principal": format!("account:{ACCOUNT}"),
    });
    upload.state = UploadState::Completed(answer.clone());
    let key = (upload.archive.clone(), upload.object.clone());
    state.objects.insert(
        key,
        Object::Stored {
            bytes,
            principal: format!("account:{ACCOUNT}"),
        },
    );
    answered(answer)
}

fn abort(
    state: &mut State,
    body: &serde_json::Value,
    caller: &str,
    account: Option<&str>,
) -> ServiceHttpAnswer {
    let (upload, _) = match reach(state, body, caller, account) {
        Ok(reached) => reached,
        Err(refused) => return refused,
    };
    if matches!(upload.state, UploadState::Completed(_)) {
        return refusal(
            403,
            "FORBIDDEN",
            "That upload is stored. Delete the object instead.",
        );
    }
    upload.state = UploadState::Cleaned;
    let key = (upload.archive.clone(), upload.object.clone());
    state.objects.remove(&key);
    answered(serde_json::json!({ "state": "cleaned", "released_bytes": "0" }))
}

fn read(state: &State, body: &serde_json::Value, principal: &str) -> ServiceHttpAnswer {
    let (Some(archive), Some(object)) = (
        identifier(&body["archive_id"]),
        identifier(&body["object_id"]),
    ) else {
        return refusal(
            400,
            "INVALID_REQUEST",
            "A read names the archive and the object.",
        );
    };
    let (Some(offset), Some(length)) = (counter(&body["offset"]), counter(&body["length"])) else {
        return refusal(
            400,
            "INVALID_REQUEST",
            "A read states its offset and its length.",
        );
    };
    if length == 0 || length > PART {
        return refusal(
            400,
            "INVALID_REQUEST",
            "A read asks for between one byte and the most a read may.",
        );
    }
    let Some(Object::Stored {
        bytes,
        principal: owner,
    }) = state.objects.get(&(archive, object))
    else {
        return refusal(404, "NOT_FOUND", "No such stored object.");
    };
    if owner != principal {
        return refusal(404, "NOT_FOUND", "No such stored object.");
    }
    let stored = bytes.len() as u64;
    if offset >= stored {
        return refusal(
            400,
            "INVALID_REQUEST",
            "That offset is past the end of the object.",
        );
    }
    let end = usize::try_from(offset + length.min(stored - offset)).expect("an end");
    ServiceHttpAnswer {
        status: 200,
        body: bytes[usize::try_from(offset).expect("an offset")..end].to_vec(),
    }
}

fn delete(state: &mut State, body: &serde_json::Value, principal: &str) -> ServiceHttpAnswer {
    let (Some(archive), Some(object)) = (
        identifier(&body["archive_id"]),
        identifier(&body["object_id"]),
    ) else {
        return refusal(
            400,
            "INVALID_REQUEST",
            "A deletion names the archive and the object.",
        );
    };
    let key = (archive, object);
    let answer = |state: &str, bytes: u64| {
        answered(serde_json::json!({
            "state": state,
            "deleted_at": "2026-09-25T17:00:00.000Z",
            "purge_after": "2026-10-02T17:00:00.000Z",
            "retained_bytes": bytes.to_string(),
            "retention": retention_policy(30),
        }))
    };
    match state.objects.get(&key).cloned() {
        Some(Object::Stored {
            bytes,
            principal: owner,
        }) if owner == principal => {
            let length = bytes.len() as u64;
            state.objects.insert(
                key,
                Object::Tombstoned {
                    principal: owner,
                    bytes: length,
                },
            );
            answer("tombstoned", length)
        }
        Some(Object::Tombstoned {
            principal: owner,
            bytes,
        }) if owner == principal => answer("already_tombstoned", bytes),
        _ => refusal(404, "NOT_FOUND", "No such stored object."),
    }
}

/// The identifier of an authorisation key, as the service derives it.
fn key_id_of(key: &kr_protocol::scalars::AuthorisationKey) -> String {
    let id = kr_crypto::keys::key_id(
        kr_protocol::pairing::KeyPurpose::Authorisation,
        key.as_bytes(),
    );
    serde_json::to_value(id)
        .expect("a key identifier")
        .as_str()
        .expect("text")
        .to_owned()
}

/// The digest the collection remembers one record by.
fn digest_of(record: &serde_json::Value) -> String {
    let digest = canonical_body_digest(record).expect("a canonical record");
    serde_json::to_value(digest)
        .expect("a digest")
        .as_str()
        .expect("text")
        .to_owned()
}

fn manifest(
    state: &mut State,
    signature: &ServiceRequestSignature,
    body: &serde_json::Value,
    token: Option<&str>,
) -> ServiceHttpAnswer {
    let carried = key_id_of(&signature.public_key);
    let members = body.as_object().expect("a request");
    if members.len() != 1 {
        return refusal(
            400,
            "INVALID_REQUEST",
            "A backup request enrols a writer, publishes a generation or fetches one.",
        );
    }
    if let Some(asked) = members.get("enrol") {
        let record = &asked["record"];
        let Ok(parsed) =
            serde_json::from_value::<kr_protocol::archive::BackupWriterRecord>(record.clone())
        else {
            return refusal(
                400,
                "INVALID_REQUEST",
                "An enrolment carries the owner's signed writer record.",
            );
        };
        if key_id_of_record(&parsed.payload.owner_key_id) != carried {
            return refusal(
                403,
                "FORBIDDEN",
                "That record names a key other than the one that carried the request.",
            );
        }
        let archive = parsed.payload.archive_id.to_string();
        let digest = digest_of(record);
        let writer = key_id_of_record(&parsed.payload.writer.writer_key_id);
        let revision = parsed.payload.writer_revision.get();
        let changed = match state.collections.get_mut(&archive) {
            None => {
                state.collections.insert(
                    archive.clone(),
                    Collection {
                        owner_key: carried,
                        writer_key_id: writer,
                        writer_revision: revision,
                        writer_digest: digest,
                        checkpoint: 0,
                        generations: BTreeMap::new(),
                    },
                );
                true
            }
            Some(collection) if collection.owner_key != carried => {
                return refusal(
                    403,
                    "FORBIDDEN",
                    "This collection belongs to another owner key.",
                );
            }
            Some(collection) if collection.writer_digest == digest => false,
            Some(collection) if revision <= collection.writer_revision => {
                return refusal(
                    403,
                    "FORBIDDEN",
                    "That writer revision is not above the one this collection holds.",
                );
            }
            Some(collection) => {
                collection.writer_key_id = writer;
                collection.writer_revision = revision;
                collection.writer_digest = digest;
                true
            }
        };
        let collection = &state.collections[&archive];
        return answered(serde_json::json!({
            "state": if changed { "enrolled" } else { "unchanged" },
            "writer": writer_summary(collection),
            "collection": collection_summary(&archive, collection),
        }));
    }
    if let Some(asked) = members.get("publish") {
        let publication = &asked["publication"];
        let Ok(parsed) = serde_json::from_value::<kr_protocol::archive::BackupGenerationPublication>(
            publication.clone(),
        ) else {
            return refusal(
                400,
                "INVALID_REQUEST",
                "A publication carries the writer's signed generation publication.",
            );
        };
        if key_id_of_record(&parsed.payload.writer_key_id) != carried {
            return refusal(
                403,
                "FORBIDDEN",
                "That record names a key other than the one that carried the request.",
            );
        }
        let archive = parsed.payload.descriptor.archive_id.to_string();
        if state.deleted.contains(&archive) {
            return refusal(
                410,
                "COLLECTION_DELETED",
                "This backup collection was deleted from the account console. Enrol a new collection to back up again.",
            );
        }
        let Some(collection) = state.collections.get_mut(&archive) else {
            return refusal(403, "FORBIDDEN", "This collection has no enrolled writer.");
        };
        if collection.writer_key_id != carried {
            return refusal(
                403,
                "FORBIDDEN",
                "That writer is not the one this collection enrolled.",
            );
        }
        let generation = parsed.payload.descriptor.backup_generation.get();
        let digest = digest_of(publication);
        let duplicate = match collection.generations.get(&generation) {
            Some((held, _)) if *held == digest => true,
            Some(_) => {
                return refusal(
                    403,
                    "FORBIDDEN",
                    "That generation has already been published with different content.",
                );
            }
            None if generation <= collection.checkpoint => {
                return refusal(
                    403,
                    "FORBIDDEN",
                    "This collection has published that generation or a later one.",
                );
            }
            None => false,
        };
        // Only a publication about to be stored reaches the ledger, which is where an account's
        // proof is needed: a duplicate holds nothing.
        if !duplicate && token != Some(TOKEN) {
            return refusal(
                402,
                "QUOTA_EXHAUSTED",
                "This installation has no backup storage. Sign this host in to an account whose plan includes backup storage, and try again.",
            );
        }
        if !duplicate {
            collection
                .generations
                .insert(generation, (digest, publication.clone()));
            collection.checkpoint = generation;
        }
        let hash = serde_json::to_value(
            parsed
                .payload
                .descriptor
                .encrypted_manifest
                .encrypted_object_hash,
        )
        .expect("a hash");
        let collection = &state.collections[&archive];
        return answered(serde_json::json!({
            "state": if duplicate { "duplicate" } else { "published" },
            "generation": {
                "backup_generation": generation.to_string(),
                "encrypted_manifest_hash": hash,
                "descriptor_bytes": "512",
                "recipients": parsed.payload.descriptor.manifest_key_wraps.len(),
                "published_at": "2026-09-25T17:00:00.000Z",
            },
            "collection": collection_summary(&archive, collection),
            "dropped": [],
        }));
    }
    let asked = &members["fetch"];
    let Some(archive) = identifier(&asked["archive_id"]) else {
        return refusal(400, "INVALID_REQUEST", "A fetch names the archive.");
    };
    let Some(collection) = state.collections.get(&archive) else {
        return refusal(404, "NOT_FOUND", "No such collection.");
    };
    let wanted = match &asked["backup_generation"] {
        serde_json::Value::Null => collection.generations.keys().next_back().copied(),
        named => counter(named),
    };
    let Some((generation, (_, publication))) =
        wanted.and_then(|wanted| collection.generations.get_key_value(&wanted))
    else {
        return refusal(404, "NOT_FOUND", "No such generation.");
    };
    let _ = generation;
    answered(serde_json::json!({
        "publication": publication,
        "published_at": "2026-09-25T17:00:00.000Z",
        "collection": collection_summary(&archive, collection),
        "current_writer": writer_summary(collection),
    }))
}

/// A key identifier a record names, in the spelling the service compares.
fn key_id_of_record(key_id: &kr_protocol::scalars::KeyId) -> String {
    serde_json::to_value(key_id)
        .expect("a key identifier")
        .as_str()
        .expect("text")
        .to_owned()
}

fn writer_summary(collection: &Collection) -> serde_json::Value {
    serde_json::json!({
        "writer_key_id": collection.writer_key_id,
        "writer_revision": collection.writer_revision.to_string(),
        "enrolled_at": "2026-09-25T16:00:00.000Z",
    })
}

fn collection_summary(archive: &str, collection: &Collection) -> serde_json::Value {
    serde_json::json!({
        "archive_id": archive,
        "checkpoint_generation": collection.checkpoint.to_string(),
        "generations": collection
            .generations
            .keys()
            .rev()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        "bytes": "512",
        "allowance_bytes": null,
    })
}
