//! A phone sends files to a paired host: from the command to the handle, across a connection that
//! ends, and across a restart of the application.
//!
//! The host is kr-controller's in-process daemon. The phone is this crate's backend on the mock
//! runtime, paired with the host, and a call below is made the way the page makes it, through the
//! invoke path, except where a case drives the desk that owns the uploads with a content of its own.

#![cfg(unix)]

#[path = "../../../../crates/kr-controller/tests/net_support/mod.rs"]
mod net_support;
mod support;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use companion_tauri::open_transfers::{Desk, Keeping, Paired, Request, kept_in, testing};
use kr_client::uploads::{Content, Held};
use kr_protocol::limits::UPLOAD_CHUNK_LEN;
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{Nullable, TimestampMs, Uuid};
use net_support::proposal;
use net_support::worker::Adopted;
use serde_json::{Value, json};
use support::{Companion, LinkControl, Phone, WATCHDOG, pair_under, unpaired_phone_controlled};
use tauri::Manager as _;

fn pairing() -> kr_protocol::pairing::ProposedGrant {
    let mut grant = proposal(&[
        ActionRight::SessionView,
        ActionRight::FilesUpload,
        ActionRight::AgentPrompt,
    ]);
    grant.history.lower_bound_ms = Nullable::some(TimestampMs::new(0));
    grant
}

/// A phone paired with the host, in contact with it, whose dials `control` can hold.
async fn phone_for(adopted: &Adopted) -> (Phone, Arc<LinkControl>) {
    let control = LinkControl::new();
    let phone = unpaired_phone_controlled(&adopted.host, &control);
    pair_under(&phone, &adopted.host, &adopted.owner, pairing()).await;
    tokio::time::timeout(WATCHDOG, async {
        loop {
            let state = phone
                .companion
                .call("connection_state", json!({}))
                .expect("the connection's state");
            if state["connected"] == true {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the connection comes up");
    (phone, control)
}

fn paired_of(companion: &Companion) -> Paired {
    let (device_id, environment_id, session) = companion
        .app
        .state::<companion_tauri::AppState>()
        .paired_snapshot()
        .expect("a paired host");
    Paired {
        device_id,
        environment_id,
        session,
    }
}

fn folder(phone: &Phone) -> PathBuf {
    kept_in(phone.data.path())
}

fn copies_in(folder: &Path) -> usize {
    std::fs::read_dir(folder)
        .map(|listing| {
            listing
                .flatten()
                .filter(|item| item.path().extension().is_some_and(|ext| ext == "bytes"))
                .count()
        })
        .unwrap_or(0)
}

fn entries_in(folder: &Path) -> usize {
    std::fs::read_dir(folder)
        .map(|listing| {
            listing
                .flatten()
                .filter(|item| item.path().extension().is_some_and(|ext| ext == "upload"))
                .count()
        })
        .unwrap_or(0)
}

fn pattern(extra: usize) -> Vec<u8> {
    (0..2 * UPLOAD_CHUNK_LEN + extra)
        .map(|index| u8::try_from(index % 251).unwrap_or(0))
        .collect()
}

fn request(adopted: &Adopted, bytes: &[u8], content: Arc<dyn Content>, key: Uuid) -> Request {
    Request {
        key,
        target: net_support::on_the_host(&adopted.host),
        session_id: None,
        content,
        name: "kept.bin".to_owned(),
        media_type: "application/octet-stream".to_owned(),
        keeping: Keeping::Copy(bytes.to_vec()),
    }
}

/// What the page reads of the open uploads, or the refusal while the phone is not connected.
fn try_open(companion: &Companion) -> Result<Vec<Value>, Value> {
    companion
        .call("uploads_open", json!({}))
        .map(|listed| listed.as_array().expect("a list").clone())
}

/// What the page reads of the open uploads.
fn open(companion: &Companion) -> Vec<Value> {
    try_open(companion).expect("the open uploads are read")
}

async fn open_where(companion: &Companion, wanted: impl Fn(&[Value]) -> bool) -> Vec<Value> {
    tokio::time::timeout(WATCHDOG, async {
        loop {
            if let Ok(now) = try_open(companion)
                && wanted(&now)
            {
                return now;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the open uploads reach the state the case waits for")
}

/// What an upload's content waits for before it gives any chunk after the first.
#[derive(Debug, Default)]
struct ChunkGate {
    reached: std::sync::atomic::AtomicBool,
    released: std::sync::Mutex<bool>,
    letting_go: std::sync::Condvar,
}

impl ChunkGate {
    fn release(&self) {
        *self
            .released
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = true;
        self.letting_go.notify_all();
    }

    async fn reached(&self) {
        tokio::time::timeout(WATCHDOG, async {
            while !self.reached.load(std::sync::atomic::Ordering::Acquire) {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("the upload reaches its second chunk");
    }
}

/// Lets the content go when the case ends, so that a case that fails first leaves no thread waiting.
struct Releasing(Arc<ChunkGate>);

impl Drop for Releasing {
    fn drop(&mut self) {
        self.0.release();
    }
}

/// Content that reads like [`Held`] and holds at the second chunk.
#[derive(Debug)]
struct HeldAtTheSecondChunk {
    held: Held,
    gate: Arc<ChunkGate>,
}

impl Content for HeldAtTheSecondChunk {
    fn byte_len(&self) -> u64 {
        self.held.byte_len()
    }

    fn digest(&self) -> kr_protocol::scalars::Digest256 {
        self.held.digest()
    }

    fn read_at(&self, offset: u64, len: u64) -> kr_client::Result<Vec<u8>> {
        if offset > 0 {
            self.gate
                .reached
                .store(true, std::sync::atomic::Ordering::Release);
            let released = self
                .gate
                .released
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let (_released, wait) = self
                .gate
                .letting_go
                .wait_timeout_while(released, WATCHDOG, |released| !*released)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            assert!(!wait.timed_out(), "the case never let the content go");
        }
        self.held.read_at(offset, len)
    }
}

fn gated(bytes: &[u8]) -> (Arc<dyn Content>, Arc<ChunkGate>, Releasing) {
    let gate = Arc::new(ChunkGate::default());
    let content: Arc<dyn Content> = Arc::new(HeldAtTheSecondChunk {
        held: Held::new(bytes.to_vec()),
        gate: Arc::clone(&gate),
    });
    let releasing = Releasing(Arc::clone(&gate));
    (content, gate, releasing)
}

/// KR-REQ-13.12: a file the page hands over as bytes, over one chunk, reaches a handle on a paired
/// host, and the copy kept for a restart is gone when the upload is published.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_13_12_a_handed_file_over_one_chunk_reaches_a_handle_on_a_paired_host() {
    let adopted = Adopted::start(1).await;
    let (phone, _control) = phone_for(&adopted).await;
    let companion = &phone.companion;
    let bytes = pattern(1_000);
    let key = kr_ipc::new_uuid().to_string();

    let handle = companion
        .call_bytes(
            "attachment_upload_bytes",
            bytes.clone(),
            &[("kr-file-name", "three.bin"), ("kr-transfer-key", &key)],
        )
        .expect("the file reaches a handle");
    assert_eq!(handle["byte_len"], bytes.len().to_string(), "{handle}");

    let listed = open(companion);
    assert_eq!(listed.len(), 1, "{listed:?}");
    assert_eq!(listed[0]["state"], "published", "{listed:?}");
    assert_eq!(listed[0]["key"], key);
    assert_eq!(listed[0]["handle"], handle);
    assert_eq!(
        copies_in(&folder(&phone)),
        0,
        "the copy ends with the upload"
    );
    adopted.stop().await;
}

/// KR-REQ-13.12: a file dropped on the window goes the same way, from its path.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_13_12_a_dropped_file_reaches_a_handle_on_a_paired_host() {
    let adopted = Adopted::start(1).await;
    let (phone, _control) = phone_for(&adopted).await;
    let companion = &phone.companion;
    let bytes = pattern(77);
    let directory = tempfile::tempdir().expect("a directory");
    let path = directory.path().join("dropped.bin");
    std::fs::write(&path, &bytes).expect("the file");
    companion
        .app
        .state::<companion_tauri::AppState>()
        .dropped([path.clone()]);

    let handle = companion
        .call(
            "attachment_upload",
            json!({ "subject": {}, "path": path.to_str(), "sessionId": null }),
        )
        .expect("the dropped file reaches a handle");
    assert_eq!(handle["byte_len"], bytes.len().to_string(), "{handle}");
    assert_eq!(open(companion)[0]["state"], "published");
    adopted.stop().await;
}

/// KR-REQ-13.12: a third open upload is refused in words before a reservation is asked for, and the
/// two that are open finish.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_13_12_a_third_open_upload_is_refused_in_words() {
    let adopted = Adopted::start(1).await;
    let (phone, _control) = phone_for(&adopted).await;
    let companion = &phone.companion;
    let desk = companion
        .app
        .state::<companion_tauri::AppState>()
        .transfers();
    let bytes = pattern(5);
    let (first, first_gate, _release_first) = gated(&bytes);
    let (second, second_gate, _release_second) = gated(&bytes);
    let sending: Vec<_> = [first, second]
        .into_iter()
        .map(|content| {
            let desk = Arc::clone(&desk);
            let sent = request(&adopted, &bytes, content, kr_ipc::new_uuid());
            let paired = paired_of(companion);
            tokio::spawn(async move { desk.send(paired, sent).await })
        })
        .collect();
    first_gate.reached().await;
    second_gate.reached().await;

    let refused = companion
        .call_bytes("attachment_upload_bytes", bytes.clone(), &[])
        .expect_err("a third is refused");
    assert_eq!(
        refused["message"],
        companion_tauri::open_transfers::TOO_MANY_OPEN,
        "{refused}"
    );
    assert_eq!(open(companion).len(), 2, "the refusal reserved nothing");

    first_gate.release();
    second_gate.release();
    for upload in sending {
        upload
            .await
            .expect("the task ran")
            .expect("the upload is published");
    }
    adopted.stop().await;
}

/// KR-REQ-13.12: a cancel is read against the host first and shows the released bytes from the
/// host's answer; the waiting call is told it was cancelled, and the entry and its copy go.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_13_12_a_cancel_shows_the_released_bytes_from_the_answer() {
    let adopted = Adopted::start(1).await;
    let (phone, _control) = phone_for(&adopted).await;
    let companion = &phone.companion;
    let desk = companion
        .app
        .state::<companion_tauri::AppState>()
        .transfers();
    let bytes = pattern(5);
    let (content, gate, _release) = gated(&bytes);
    let key = kr_ipc::new_uuid();
    let sending = {
        let sent = request(&adopted, &bytes, content, key);
        let paired = paired_of(companion);
        tokio::spawn(async move { desk.send(paired, sent).await })
    };
    gate.reached().await;
    gate.release();

    let answer = companion
        .call("upload_cancel", json!({ "transferKey": key.to_string() }))
        .expect("the cancel is answered");
    assert_eq!(answer["state"], "cancelled", "{answer}");
    assert_eq!(
        answer["releasedByteLen"],
        bytes.len().to_string(),
        "the bytes are the host's answer: {answer}"
    );
    let told = sending.await.expect("the task ran").expect_err("cancelled");
    assert_eq!(told.message, companion_tauri::open_transfers::CANCELLED);
    assert!(open(companion).is_empty());
    assert_eq!(copies_in(&folder(&phone)), 0);
    assert_eq!(entries_in(&folder(&phone)), 0);
    adopted.stop().await;
}

/// KR-REQ-13.12: the open view names the session an upload is for, so that a restart can show a
/// kept upload on its own session's composer, and says so with no session for one that has none.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_13_12_the_open_view_names_the_session_the_file_is_for() {
    let adopted = Adopted::start(1).await;
    let (phone, _control) = phone_for(&adopted).await;
    let companion = &phone.companion;
    let session = adopted.workers[0].session_id;
    let desk = companion
        .app
        .state::<companion_tauri::AppState>()
        .transfers();
    let bytes = pattern(5);
    let (content, gate, _release) = gated(&bytes);
    let key = kr_ipc::new_uuid();
    let sent = Request {
        session_id: Some(session),
        target: net_support::on_the_session(&adopted.host, session),
        ..request(&adopted, &bytes, content, key)
    };
    let paired = paired_of(companion);
    let sending = tokio::spawn(async move { desk.send(paired, sent).await });
    gate.reached().await;

    let listed = open(companion);
    assert_eq!(listed.len(), 1, "{listed:?}");
    assert_eq!(listed[0]["key"], key.to_string());
    assert_eq!(
        listed[0]["sessionId"],
        session.to_string(),
        "the view names the session: {}",
        listed[0]
    );
    gate.release();
    let _ = companion.call("upload_cancel", json!({ "transferKey": key.to_string() }));
    let _ = sending.await;
    adopted.stop().await;
}

/// KR-REQ-13.12: a connection that ends pauses the upload, and the next one resumes it under the
/// same transfer with the content the process holds: the call that began it gets the handle.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_13_12_a_reconnect_resumes_the_upload_the_connection_interrupted() {
    let adopted = Adopted::start(1).await;
    let (phone, _control) = phone_for(&adopted).await;
    let companion = &phone.companion;
    let desk = companion
        .app
        .state::<companion_tauri::AppState>()
        .transfers();
    let bytes = pattern(5);
    let (content, gate, _release) = gated(&bytes);
    let paired = paired_of(companion);
    let session = Arc::clone(&paired.session);
    let sending = {
        let sent = request(&adopted, &bytes, content, kr_ipc::new_uuid());
        tokio::spawn(async move { desk.send(paired, sent).await })
    };
    gate.reached().await;
    session.transport().close();
    gate.release();

    let handle = tokio::time::timeout(WATCHDOG, sending)
        .await
        .expect("the upload ends after the reconnect")
        .expect("the task ran")
        .expect("the resumed upload is published");
    assert_eq!(handle.byte_len.get(), bytes.len() as u64);
    adopted.stop().await;
}

/// An upload that a first process began and left, with the connection ended before it finished: its
/// entry and its copy are in the folder, and a second process, the phone's own desk, reads them.
async fn left_by_a_first_process(
    adopted: &Adopted,
    phone: &Phone,
    control: &LinkControl,
    bytes: &[u8],
    keeping: Keeping,
    before_the_host_is_reached: impl FnOnce(),
) -> Uuid {
    let companion = &phone.companion;
    let first = Arc::new(Desk::default());
    first.keep_at(folder(phone));
    let (content, gate, release) = gated(bytes);
    let key = kr_ipc::new_uuid();
    let mut sent = request(adopted, bytes, content, key);
    sent.keeping = keeping;
    let paired = paired_of(companion);
    let session = Arc::clone(&paired.session);
    // The task is the first process: nothing ever resumes it, and it ends with the case.
    let first_process = tokio::spawn(async move { first.send(paired, sent).await });
    gate.reached().await;
    control.hold();
    session.transport().close();
    gate.release();
    drop(release);
    before_the_host_is_reached();
    control.stop_holding();
    control.release_all();
    assert!(
        !first_process.is_finished(),
        "the first process is not told an outcome"
    );
    first_process.abort();
    key
}

/// KR-REQ-13.12: after a restart an upload the host still receives, whose content is kept, resumes
/// with the rest and ends published, and the copy is gone.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_13_12_a_restart_resumes_an_upload_whose_content_is_kept() {
    let adopted = Adopted::start(1).await;
    let (phone, control) = phone_for(&adopted).await;
    let bytes = pattern(5);
    let key = left_by_a_first_process(
        &adopted,
        &phone,
        &control,
        &bytes,
        Keeping::Copy(bytes.clone()),
        || {
            assert_eq!(
                copies_in(&folder(&phone)),
                1,
                "the copy is kept while the upload is open"
            );
        },
    )
    .await;

    let listed = open_where(&phone.companion, |now| {
        now.iter().any(|view| view["state"] == "published")
    })
    .await;
    assert_eq!(listed[0]["key"], key.to_string());
    assert_eq!(listed[0]["handle"]["byte_len"], bytes.len().to_string());
    assert_eq!(copies_in(&folder(&phone)), 0);
    adopted.stop().await;
}

/// KR-REQ-13.12: an entry whose copy is gone says it cannot resume and offers a cancel, which reads
/// the host first and releases the reservation from the host's answer; the entry goes.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_13_12_a_restart_says_that_an_upload_with_no_content_cannot_resume() {
    let adopted = Adopted::start(1).await;
    let (phone, control) = phone_for(&adopted).await;
    let bytes = pattern(5);
    let key = left_by_a_first_process(
        &adopted,
        &phone,
        &control,
        &bytes,
        Keeping::Copy(bytes.clone()),
        || {
            let copy = folder(&phone).join(format!("{}.bytes", {
                let mut name = String::new();
                for item in std::fs::read_dir(folder(&phone))
                    .expect("the folder")
                    .flatten()
                {
                    if item.path().extension().is_some_and(|ext| ext == "bytes") {
                        name = item
                            .path()
                            .file_stem()
                            .expect("a stem")
                            .to_string_lossy()
                            .into_owned();
                    }
                }
                name
            }));
            std::fs::remove_file(&copy).expect("the copy goes");
        },
    )
    .await;

    let listed = open_where(&phone.companion, |now| {
        now.iter().any(|view| view["state"] == "cannotResume")
    })
    .await;
    assert_eq!(
        listed[0]["said"],
        companion_tauri::open_transfers::CANNOT_RESUME
    );
    let answer = phone
        .companion
        .call("upload_cancel", json!({ "transferKey": key.to_string() }))
        .expect("the cancel is offered and answered");
    assert_eq!(answer["state"], "cancelled", "{answer}");
    assert_eq!(answer["releasedByteLen"], bytes.len().to_string());
    assert!(open(&phone.companion).is_empty());
    adopted.stop().await;
}

/// KR-REQ-13.12: a file kept by its path whose content changed is not sent on: the digest is checked
/// before the first resumed chunk.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_13_12_a_restart_does_not_send_a_file_whose_digest_changed() {
    let adopted = Adopted::start(1).await;
    let (phone, control) = phone_for(&adopted).await;
    let bytes = pattern(5);
    let directory = tempfile::tempdir().expect("a directory");
    let path = directory.path().join("kept.bin");
    std::fs::write(&path, &bytes).expect("the file");
    let _key = left_by_a_first_process(
        &adopted,
        &phone,
        &control,
        &bytes,
        Keeping::Path(path.clone()),
        || {
            let mut changed = bytes.clone();
            changed[3] ^= 0xff;
            std::fs::write(&path, changed).expect("the file changes");
        },
    )
    .await;

    let listed = open_where(&phone.companion, |now| {
        now.iter().any(|view| view["state"] == "cannotResume")
    })
    .await;
    assert_eq!(
        listed[0]["said"],
        companion_tauri::open_transfers::CANNOT_RESUME
    );
    adopted.stop().await;
}

/// The entry of an upload the host published whose finish answer never came, kept with the transfer
/// identifier and no handle.
async fn published_with_a_lost_answer(adopted: &Adopted, phone: &Phone) -> (Uuid, Vec<u8>) {
    use kr_client::chunks::ChunkRoute;
    use kr_client::uploads::{self, Progress, Subject, Upload};

    let paired = paired_of(&phone.companion);
    let bytes = pattern(9);
    let route = ChunkRoute::network(&paired.session, adopted.host.environment_id)
        .await
        .expect("a route");
    let mut upload = Upload::new(
        Subject {
            environment_id: adopted.host.environment_id,
            session_id: None,
            device_id: None,
            declared_media_type: "application/octet-stream".to_owned(),
            original_file_name: "kept.bin".to_owned(),
        },
        Box::new(Held::new(bytes.clone())),
    );
    let (progress, _watching) = tokio::sync::watch::channel(Progress::default());
    uploads::send(
        &paired.session,
        &route,
        &net_support::on_the_host(&adopted.host),
        &mut upload,
        kr_protocol::scalars::DurationMs::new(60_000),
        &progress,
        &kr_client::uploads::NoJournal,
    )
    .await
    .expect("published");
    let key = kr_ipc::new_uuid();
    testing::keep(
        &folder(phone),
        key,
        paired.environment_id,
        paired.device_id,
        net_support::on_the_host(&adopted.host),
        upload.transfer_id().copied(),
        testing::Got::Finishing,
        bytes.len() as u64,
        Held::new(bytes.clone()).digest(),
        testing::Where::Copy,
    );
    (key, bytes)
}

/// KR-REQ-13.12: a finish whose answer was lost leaves the handle: the restart reads the host first
/// and keeps the published handle, and a cancel of it reads the host first and cancels nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_13_12_a_restart_keeps_the_handle_of_a_published_upload_and_never_cancels_it() {
    let adopted = Adopted::start(1).await;
    let (phone, _control) = phone_for(&adopted).await;
    let (key, bytes) = published_with_a_lost_answer(&adopted, &phone).await;
    let desk = phone
        .companion
        .app
        .state::<companion_tauri::AppState>()
        .transfers();
    desk.restart(paired_of(&phone.companion)).await;

    let listed = open(&phone.companion);
    assert_eq!(listed.len(), 1, "{listed:?}");
    assert_eq!(listed[0]["state"], "published", "{listed:?}");
    assert_eq!(listed[0]["handle"]["byte_len"], bytes.len().to_string());

    let answer = phone
        .companion
        .call("upload_cancel", json!({ "transferKey": key.to_string() }))
        .expect("the cancel is answered");
    assert_eq!(answer["state"], "published", "{answer}");
    assert!(answer["releasedByteLen"].is_null(), "{answer}");
    assert_eq!(
        open(&phone.companion)[0]["state"],
        "published",
        "the entry stands"
    );
    adopted.stop().await;
}

/// KR-REQ-13.12: a reservation whose answer never came cannot be found again: the entry says so and
/// a cancel forgets it without a call to the host.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_13_12_a_reservation_whose_answer_never_came_is_said_to_be_unrecoverable() {
    let adopted = Adopted::start(1).await;
    let (phone, _control) = phone_for(&adopted).await;
    let paired = paired_of(&phone.companion);
    let key = kr_ipc::new_uuid();
    testing::keep(
        &folder(&phone),
        key,
        paired.environment_id,
        paired.device_id,
        net_support::on_the_host(&adopted.host),
        None,
        testing::Got::Beginning,
        10,
        Held::new(vec![0; 10]).digest(),
        testing::Where::Copy,
    );
    let listed = open(&phone.companion);
    assert_eq!(listed[0]["state"], "unrecoverable", "{listed:?}");
    assert_eq!(
        listed[0]["said"],
        companion_tauri::open_transfers::UNRECOVERABLE
    );
    let answer = phone
        .companion
        .call("upload_cancel", json!({ "transferKey": key.to_string() }))
        .expect("the cancel is answered");
    assert_eq!(answer["state"], "forgotten", "{answer}");
    assert!(open(&phone.companion).is_empty());
    adopted.stop().await;
}

/// KR-REQ-13.12: an entry the host does not know is dropped with its copy.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_13_12_a_restart_drops_an_entry_the_host_does_not_know_and_its_copy() {
    let adopted = Adopted::start(1).await;
    let (phone, _control) = phone_for(&adopted).await;
    let paired = paired_of(&phone.companion);
    let key = kr_ipc::new_uuid();
    let bytes = vec![1_u8; 32];
    testing::keep(
        &folder(&phone),
        key,
        paired.environment_id,
        paired.device_id,
        net_support::on_the_host(&adopted.host),
        Some(kr_protocol::ids::TransferId::new(kr_ipc::new_uuid())),
        testing::Got::Begun,
        32,
        Held::new(bytes.clone()).digest(),
        testing::Where::Copy,
    );
    testing::keep_copy(&folder(&phone), key, &bytes);
    let desk = phone
        .companion
        .app
        .state::<companion_tauri::AppState>()
        .transfers();
    desk.restart(paired).await;
    assert!(open(&phone.companion).is_empty());
    assert_eq!(copies_in(&folder(&phone)), 0);
    assert_eq!(entries_in(&folder(&phone)), 0);
    adopted.stop().await;
}

// ---- the draft a device keeps on a paired host -------------------------------------------------

/// The page's subject for a session.
fn on_session(session: kr_protocol::ids::SessionId) -> Value {
    json!({ "sessionId": session.to_string(), "sessionEpoch": "1" })
}

fn contribution() -> Value {
    serde_json::to_value(kr_protocol::transfer::AttachmentContribution {
        operation_id: "attach".to_owned(),
        accepted_media_types: vec!["application/octet-stream".to_owned()],
        max_byte_len: kr_protocol::scalars::U64::new(1 << 20),
        max_count: kr_protocol::scalars::U64::new(4),
        insertion_method: kr_protocol::transfer::InsertionMethod::ManualTerminalWorkflow,
        external_destination: Nullable::null(),
        model_media_capability: false,
    })
    .expect("encodes")
}

/// Sends a small file as the page does and answers its handle.
fn handed(companion: &Companion) -> Value {
    companion
        .call_bytes(
            "attachment_upload_bytes",
            vec![7_u8; 64],
            &[("kr-file-name", "note.bin")],
        )
        .expect("the file reaches a handle")
}

/// Binds the published `handle` to the draft kept for `session`, as the page does.
fn bind(
    companion: &Companion,
    session: kr_protocol::ids::SessionId,
    handle: &Value,
) -> Result<Value, Value> {
    companion.call(
        "draft_add_attachment",
        json!({
            "subject": on_session(session),
            "params": {
                "session_id": session.to_string(),
                "text": "see the file",
                "transfer_id": handle["transfer_id"],
                "contribution": contribution(),
            },
        }),
    )
}

fn kept(companion: &Companion, session: kr_protocol::ids::SessionId) -> Value {
    let answer = companion
        .call(
            "draft_create",
            json!({
                "subject": on_session(session),
                "params": {
                    "environment_id": paired_of(companion).environment_id.to_string(),
                    "device_id": null,
                    "session_id": session.to_string(),
                    "application_instance_id": null,
                    "text": "",
                },
            }),
        )
        .expect("the kept draft is read");
    answer["value"].clone()
}

/// KR-REQ-23.41: a device makes its draft at the first bind and never before, one for each session,
/// and a later bind and a new window use it again.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_23_41_the_draft_is_made_at_the_first_bind_and_used_again() {
    let adopted = Adopted::start(1).await;
    let (phone, _control) = phone_for(&adopted).await;
    let companion = &phone.companion;
    let session = adopted.workers[0].session_id;

    assert_eq!(
        kept(companion, session)["made"],
        false,
        "no draft before a bind"
    );
    let first = bind(companion, session, &handed(companion)).expect("the first bind");
    let made = &first["value"];
    assert_eq!(made["revision"], "2", "{first}");
    let again = bind(companion, session, &handed(companion)).expect("the second bind");
    assert_eq!(
        again["value"]["draftId"], made["draftId"],
        "the draft is used again"
    );
    assert_eq!(again["value"]["revision"], "3");

    // A new window reads the same draft, with the files this device bound.
    let reread = kept(companion, session);
    assert_eq!(reread["made"], true);
    assert_eq!(reread["draftId"], made["draftId"]);
    assert_eq!(
        reread["attachments"].as_array().map(Vec::len),
        Some(2),
        "{reread}"
    );
    assert!(open(companion).is_empty(), "a bound upload's entry ends");
    adopted.stop().await;
}

/// The message the host's refusal of a draft update carries.
fn said(error: &kr_client::ClientError) -> String {
    match error {
        kr_client::ClientError::Host(refused) => refused.message.clone(),
        kr_client::ClientError::Refused { error, .. } => error.message.clone(),
        other => panic!("not a refusal of the host: {other}"),
    }
}

/// KR-REQ-23.41: the reader takes the revision from the host's own words, which a golden file
/// records from the real exchange of a stale `draft.update`, and gives nothing for words that do not
/// carry it.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_23_41_the_reader_takes_the_revision_from_the_real_conflict_message() {
    use kr_protocol::ids::DraftRevision;
    use kr_protocol::method::Method;
    use kr_protocol::transfer::{
        DraftCreateParams, DraftCreateResult, DraftUpdateParams, DraftUpdateResult,
    };

    let adopted = Adopted::start(1).await;
    let (phone, _control) = phone_for(&adopted).await;
    let paired = paired_of(&phone.companion);
    let session_id = adopted.workers[0].session_id;
    let target = net_support::on_the_session(&adopted.host, session_id);
    let created: DraftCreateResult = paired
        .session
        .mutate(
            Method::DraftCreate,
            target.clone(),
            None,
            &json!({}),
            &DraftCreateParams {
                environment_id: adopted.host.environment_id,
                device_id: Nullable::null(),
                session_id: Nullable::some(session_id),
                application_instance_id: Nullable::null(),
                text: "first".to_owned(),
            },
            kr_protocol::scalars::DurationMs::new(60_000),
        )
        .await
        .expect("the draft is made")
        .to_typed()
        .expect("a result");
    let update = |expected: u64| DraftUpdateParams {
        draft_id: created.draft.draft_id,
        expected_revision: DraftRevision::new(expected),
        text: "later".to_owned(),
    };
    let _: DraftUpdateResult = paired
        .session
        .mutate(
            Method::DraftUpdate,
            target.clone(),
            None,
            &json!({}),
            &update(1),
            kr_protocol::scalars::DurationMs::new(60_000),
        )
        .await
        .expect("the update at the current revision is served")
        .to_typed()
        .expect("a result");
    let stale = paired
        .session
        .mutate(
            Method::DraftUpdate,
            target,
            None,
            &json!({}),
            &update(1),
            kr_protocol::scalars::DurationMs::new(60_000),
        )
        .await
        .expect_err("the revision moved");
    let message = said(&stale);
    assert_eq!(
        message,
        include_str!("fixtures/draft-conflict-message.txt").trim_end(),
        "the host's words are the recorded ones: record them again if the host changed them"
    );
    let read = companion_tauri::paired_drafts::revision_in;
    assert_eq!(read(&message), Some(DraftRevision::new(2)));
    // The sentence the host gives a bind, recorded from the exchange of the stale-revision case.
    assert_eq!(
        read("this draft is at revision 3 and the binding expects 2"),
        Some(DraftRevision::new(3))
    );
    assert_eq!(read("this draft moved on"), None);
    assert_eq!(
        read("this draft is at revision x and the update expects 1"),
        None
    );
    assert_eq!(read("this draft is at revision 2"), None);
    adopted.stop().await;
}

/// KR-REQ-23.41: a bind at a revision the draft has moved past takes the revision from the host's
/// words and goes on: the draft is not ended and no second one is made.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_23_41_a_stale_revision_is_taken_from_the_message_and_the_bind_goes_on() {
    use kr_protocol::ids::{DraftId, DraftRevision};
    use kr_protocol::method::Method;
    use kr_protocol::transfer::{DraftUpdateParams, DraftUpdateResult};

    let adopted = Adopted::start(1).await;
    let (phone, _control) = phone_for(&adopted).await;
    let companion = &phone.companion;
    let session = adopted.workers[0].session_id;
    let first = bind(companion, session, &handed(companion)).expect("the first bind");
    let draft_id: DraftId = first["value"]["draftId"]
        .as_str()
        .expect("a draft")
        .parse()
        .expect("an identifier");
    // Another writer moves the draft on, from 2 to 3.
    let paired = paired_of(companion);
    let _: DraftUpdateResult = paired
        .session
        .mutate(
            Method::DraftUpdate,
            net_support::on_the_session(&adopted.host, session),
            None,
            &json!({}),
            &DraftUpdateParams {
                draft_id,
                expected_revision: DraftRevision::new(2),
                text: "moved".to_owned(),
            },
            kr_protocol::scalars::DurationMs::new(60_000),
        )
        .await
        .expect("the draft moves")
        .to_typed()
        .expect("a result");

    let next = bind(companion, session, &handed(companion)).expect("the bind goes on");
    assert_eq!(
        next["value"]["draftId"], first["value"]["draftId"],
        "{next}"
    );
    assert_eq!(next["value"]["revision"], "4", "{next}");
    assert_eq!(kept(companion, session)["revision"], "4");
    adopted.stop().await;
}

/// A `draft.create` whose answer was lost is not made again: the host's record of the
/// action answers it, and the draft it made is the one that is kept.
#[ignore = "waiting for a ruling: the host answers only an exact repeat of the first request, and the receipt read of a host-level action is refused; see the hand-over"]
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_lost_create_is_answered_by_the_hosts_record_and_not_made_again() {
    use kr_protocol::ids::ActionId;
    use kr_protocol::method::Method;
    use kr_protocol::transfer::{DraftCreateParams, DraftCreateResult};

    let adopted = Adopted::start(1).await;
    let (phone, _control) = phone_for(&adopted).await;
    let companion = &phone.companion;
    let session = adopted.workers[0].session_id;
    let paired = paired_of(companion);
    let action = ActionId::new(kr_ipc::new_uuid());
    let composed = paired
        .session
        .compose(
            Method::DraftCreate,
            action,
            net_support::on_the_session(&adopted.host, session),
            None,
            &json!({}),
            &DraftCreateParams {
                environment_id: adopted.host.environment_id,
                device_id: Nullable::null(),
                session_id: Nullable::some(session),
                application_instance_id: Nullable::null(),
                text: "made before the answer was lost".to_owned(),
            },
            kr_protocol::scalars::DurationMs::new(60_000),
        )
        .await
        .expect("composed");
    let made: DraftCreateResult = paired
        .session
        .send(&composed)
        .await
        .expect("the host made the draft")
        .to_typed()
        .expect("a result");
    // The process that sent it never saw the answer: it kept the action, and no draft.
    companion
        .app
        .state::<companion_tauri::AppState>()
        .paired_drafts()
        .keep_for_test(&paired, session, None, None, Some(action));

    let bound = bind(companion, session, &handed(companion)).expect("the bind goes on");
    assert_eq!(
        bound["value"]["draftId"],
        made.draft.draft_id.to_string(),
        "the draft the host made is the one kept: {bound}"
    );
    adopted.stop().await;
}

/// KR-REQ-23.41: the composer that drops its files ends the draft with `draft.discard`: the entry
/// goes, and the next bind makes a new draft.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_23_41_a_draft_the_composer_drops_is_ended_on_the_host() {
    let adopted = Adopted::start(1).await;
    let (phone, _control) = phone_for(&adopted).await;
    let companion = &phone.companion;
    let session = adopted.workers[0].session_id;
    let first = bind(companion, session, &handed(companion)).expect("the first bind");

    companion
        .call(
            "draft_end",
            json!({ "subject": on_session(session), "sessionId": session.to_string() }),
        )
        .expect("the draft is ended");
    assert_eq!(kept(companion, session)["made"], false);
    let next = bind(companion, session, &handed(companion)).expect("a new draft is made");
    assert_ne!(
        next["value"]["draftId"], first["value"]["draftId"],
        "{next}"
    );
    adopted.stop().await;
}

/// KR-REQ-23.41: at each start the drafts whose session the host no longer lists are ended, and a
/// draft the host has already ended is harmless to end again.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_23_41_a_start_ends_the_drafts_of_sessions_the_host_no_longer_lists() {
    use kr_protocol::ids::{DraftId, DraftRevision, SessionId};

    let adopted = Adopted::start(1).await;
    let (phone, _control) = phone_for(&adopted).await;
    let companion = &phone.companion;
    let paired = paired_of(companion);
    let gone = SessionId::new(kr_ipc::new_uuid());
    let drafts = companion
        .app
        .state::<companion_tauri::AppState>()
        .paired_drafts();
    drafts.keep_for_test(
        &paired,
        gone,
        Some(DraftId::new(kr_ipc::new_uuid())),
        Some(DraftRevision::new(1)),
        None,
    );
    assert_eq!(kept(companion, gone)["made"], true);
    drafts.sweep_after_reach(paired).await;
    assert_eq!(kept(companion, gone)["made"], false);
    adopted.stop().await;
}

/// Sets the text of the draft kept for `session`, as the page does before it sends the prompt that
/// names the draft.
fn set_text(
    companion: &Companion,
    session: kr_protocol::ids::SessionId,
    text: &str,
) -> Result<Value, Value> {
    companion.call(
        "draft_set_text",
        json!({
            "subject": on_session(session),
            "sessionId": session.to_string(),
            "text": text,
        }),
    )
}

/// KR-REQ-23.41: the text the person typed reaches the draft the files are bound to, at the
/// revision this device keeps, and each answer moves the kept revision on.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_23_41_the_text_reaches_the_draft_at_the_kept_revision() {
    let adopted = Adopted::start(1).await;
    let (phone, _control) = phone_for(&adopted).await;
    let companion = &phone.companion;
    let session = adopted.workers[0].session_id;
    let first = bind(companion, session, &handed(companion)).expect("the first bind");
    assert_eq!(first["value"]["revision"], "2", "{first}");

    let one = set_text(companion, session, "first words").expect("the text is set");
    assert_eq!(one["text"], "first words", "the host holds it: {one}");
    assert_eq!(one["revision"], "3", "{one}");
    assert_eq!(one["draftId"], first["value"]["draftId"], "{one}");
    let two = set_text(companion, session, "other words").expect("the text is set again");
    assert_eq!(two["text"], "other words", "{two}");
    assert_eq!(two["revision"], "4", "{two}");
    assert_eq!(kept(companion, session)["revision"], "4");
    adopted.stop().await;
}

/// KR-REQ-23.41: a text update at a stale revision takes the revision from the host's words and
/// goes on once, and the draft is neither ended nor made again.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_23_41_a_stale_revision_of_a_text_update_is_taken_from_the_message() {
    use kr_protocol::ids::{DraftId, DraftRevision};
    use kr_protocol::method::Method;
    use kr_protocol::transfer::{DraftUpdateParams, DraftUpdateResult};

    let adopted = Adopted::start(1).await;
    let (phone, _control) = phone_for(&adopted).await;
    let companion = &phone.companion;
    let session = adopted.workers[0].session_id;
    let first = bind(companion, session, &handed(companion)).expect("the first bind");
    let draft_id: DraftId = first["value"]["draftId"]
        .as_str()
        .expect("a draft")
        .parse()
        .expect("an identifier");
    let paired = paired_of(companion);
    let _: DraftUpdateResult = paired
        .session
        .mutate(
            Method::DraftUpdate,
            net_support::on_the_session(&adopted.host, session),
            None,
            &json!({}),
            &DraftUpdateParams {
                draft_id,
                expected_revision: DraftRevision::new(2),
                text: "moved".to_owned(),
            },
            kr_protocol::scalars::DurationMs::new(60_000),
        )
        .await
        .expect("the draft moves")
        .to_typed()
        .expect("a result");

    let set = set_text(companion, session, "mine").expect("the update goes on");
    assert_eq!(set["draftId"], first["value"]["draftId"], "{set}");
    assert_eq!(set["revision"], "4", "{set}");
    assert_eq!(set["text"], "mine", "{set}");
    assert_eq!(kept(companion, session)["revision"], "4");
    adopted.stop().await;
}

/// KR-REQ-23.41: a text for a session this device keeps no draft for is refused in words, and
/// makes no draft.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_23_41_a_text_with_no_kept_draft_is_refused_in_words() {
    let adopted = Adopted::start(1).await;
    let (phone, _control) = phone_for(&adopted).await;
    let companion = &phone.companion;
    let session = adopted.workers[0].session_id;

    let refused = set_text(companion, session, "words").expect_err("there is no draft to set");
    assert_eq!(
        refused["message"],
        companion_tauri::paired_drafts::NO_DRAFT,
        "{refused}"
    );
    assert_eq!(kept(companion, session)["made"], false);
    adopted.stop().await;
}
