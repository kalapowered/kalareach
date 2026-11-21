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

fn pairing_with(rights: &[ActionRight]) -> kr_protocol::pairing::ProposedGrant {
    let mut grant = proposal(rights);
    grant.history.lower_bound_ms = Nullable::some(TimestampMs::new(0));
    grant
}

fn pairing() -> kr_protocol::pairing::ProposedGrant {
    pairing_with(&[
        ActionRight::SessionView,
        ActionRight::FilesUpload,
        ActionRight::AgentPrompt,
    ])
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
        account: None,
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
        let (desk, paired) = (Arc::clone(&desk), paired_of(companion));
        tokio::spawn(async move { desk.send(paired, sent).await })
    };
    gate.reached().await;

    // The cancel stops the sender first: the content is let go only once the cancel is under way, so
    // that the upload cannot publish before it.
    let cancelling = {
        let (desk, paired) = (Arc::clone(&desk), paired_of(companion));
        tokio::spawn(async move { desk.cancel(paired, key).await })
    };
    tokio::time::sleep(Duration::from_millis(500)).await;
    gate.release();
    let answer = cancelling
        .await
        .expect("the cancel ran")
        .expect("the cancel is answered");
    assert_eq!(answer.state, "cancelled", "{answer:?}");
    assert_eq!(
        answer.released_byte_len,
        Some(bytes.len().to_string()),
        "the bytes are the host's answer: {answer:?}"
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
        None,
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
        None,
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
        None,
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
        &net_support::on_the_host(&adopted.host),
        Some(DraftId::new(kr_ipc::new_uuid())),
        Some(DraftRevision::new(1)),
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

// ---- the fix round: what a read of the first build found ------------------------------------------

/// Waits for the phone to be connected.
async fn connected(companion: &Companion) {
    tokio::time::timeout(WATCHDOG, async {
        loop {
            if companion
                .call("connection_state", json!({}))
                .is_ok_and(|state| state["connected"] == true)
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the connection comes up");
}

/// The host on a connection other than `old`, once the phone has made one.
async fn on_another_connection(companion: &Companion, old: &Arc<kr_client::Session>) -> Paired {
    tokio::time::timeout(WATCHDOG, async {
        loop {
            if let Ok((device_id, environment_id, session)) = companion
                .app
                .state::<companion_tauri::AppState>()
                .paired_snapshot()
                && !Arc::ptr_eq(&session, old)
            {
                return Paired {
                    device_id,
                    environment_id,
                    account: None,
                    session,
                };
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the phone makes a new connection")
}

fn desk_of(companion: &Companion) -> Arc<Desk> {
    companion
        .app
        .state::<companion_tauri::AppState>()
        .transfers()
}

/// KR-REQ-13.12: a key an open upload holds is refused in words, and the first upload goes on.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_13_12_a_transfer_key_in_use_is_refused_and_the_first_upload_is_undisturbed() {
    let adopted = Adopted::start(1).await;
    let (phone, _control) = phone_for(&adopted).await;
    let companion = &phone.companion;
    let desk = desk_of(companion);
    let bytes = pattern(5);
    let (content, gate, _release) = gated(&bytes);
    let key = kr_ipc::new_uuid();
    let first = {
        let sent = request(&adopted, &bytes, content, key);
        let (desk, paired) = (Arc::clone(&desk), paired_of(companion));
        tokio::spawn(async move { desk.send(paired, sent).await })
    };
    gate.reached().await;

    let refused = desk
        .send(
            paired_of(companion),
            request(&adopted, &bytes, Arc::new(Held::new(bytes.clone())), key),
        )
        .await
        .expect_err("the key is in use");
    assert_eq!(refused.message, companion_tauri::open_transfers::KEY_IN_USE);
    assert_eq!(open(companion).len(), 1);
    assert_eq!(copies_in(&folder(&phone)), 1);

    gate.release();
    first
        .await
        .expect("the task ran")
        .expect("the first upload is published");
    adopted.stop().await;
}

/// KR-REQ-13.12: three sends at once admit two: the count and the key are taken before any send.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_13_12_three_sends_at_once_admit_two() {
    let adopted = Adopted::start(1).await;
    let (phone, _control) = phone_for(&adopted).await;
    let companion = &phone.companion;
    let desk = desk_of(companion);
    let bytes = pattern(5);
    let held: Vec<_> = (0..3).map(|_| gated(&bytes)).collect();
    let sending: Vec<_> = held
        .iter()
        .map(|(content, _, _)| {
            let sent = request(&adopted, &bytes, Arc::clone(content), kr_ipc::new_uuid());
            let (desk, paired) = (Arc::clone(&desk), paired_of(companion));
            tokio::spawn(async move { desk.send(paired, sent).await })
        })
        .collect();
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(
        sending.iter().filter(|task| task.is_finished()).count(),
        1,
        "one send is refused at once"
    );
    assert_eq!(open(companion).len(), 2, "two are open");
    for (_, gate, _) in &held {
        gate.release();
    }
    let mut refused = 0;
    for task in sending {
        match task.await.expect("the task ran") {
            Ok(_) => {}
            Err(error) => {
                assert_eq!(
                    error.message,
                    companion_tauri::open_transfers::TOO_MANY_OPEN
                );
                refused += 1;
            }
        }
    }
    assert_eq!(refused, 1);
    adopted.stop().await;
}

/// KR-REQ-13.12: a cancel the host cannot be asked for leaves nothing stuck: it is finished when the
/// host is reached again, the upload is never sent on, and the waiting call is told it was cancelled.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_13_12_a_cancel_the_host_cannot_be_asked_is_finished_when_it_is_reached() {
    let adopted = Adopted::start(1).await;
    let (phone, control) = phone_for(&adopted).await;
    let companion = &phone.companion;
    let desk = desk_of(companion);
    let bytes = pattern(5);
    let (content, gate, _release) = gated(&bytes);
    let key = kr_ipc::new_uuid();
    let paired = paired_of(companion);
    let session = Arc::clone(&paired.session);
    let sending = {
        let sent = request(&adopted, &bytes, content, key);
        let (desk, paired) = (Arc::clone(&desk), paired.clone());
        tokio::spawn(async move { desk.send(paired, sent).await })
    };
    gate.reached().await;
    control.hold();
    session.transport().close();
    let cancelling = {
        let desk = Arc::clone(&desk);
        tokio::spawn(async move { desk.cancel(paired, key).await })
    };
    tokio::time::sleep(Duration::from_millis(300)).await;
    gate.release();
    cancelling
        .await
        .expect("the task ran")
        .expect_err("the host cannot be asked");

    control.stop_holding();
    control.release_all();
    let told = tokio::time::timeout(WATCHDOG, sending)
        .await
        .expect("the upload is ended once the host is reached")
        .expect("the task ran")
        .expect_err("cancelled");
    assert_eq!(told.message, companion_tauri::open_transfers::CANCELLED);
    open_where(companion, <[Value]>::is_empty).await;
    assert_eq!(entries_in(&folder(&phone)), 0);
    assert_eq!(copies_in(&folder(&phone)), 0);
    adopted.stop().await;
}

/// KR-REQ-13.12: a file read from where it is, and changed while the upload was paused, is not sent
/// on: the entry says it cannot resume.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_13_12_a_dropped_file_changed_during_a_pause_is_not_sent_on() {
    let adopted = Adopted::start(1).await;
    let (phone, control) = phone_for(&adopted).await;
    let companion = &phone.companion;
    let desk = desk_of(companion);
    let bytes = pattern(5);
    let directory = tempfile::tempdir().expect("a directory");
    let path = directory.path().join("dropped.bin");
    std::fs::write(&path, &bytes).expect("the file");
    let (content, gate, _release) = gated(&bytes);
    let paired = paired_of(companion);
    let session = Arc::clone(&paired.session);
    let sending = {
        let mut sent = request(&adopted, &bytes, content, kr_ipc::new_uuid());
        sent.keeping = Keeping::Path(path.clone());
        tokio::spawn(async move { desk.send(paired, sent).await })
    };
    gate.reached().await;
    control.hold();
    session.transport().close();
    let changed: Vec<u8> = bytes.iter().map(|byte| byte.wrapping_add(1)).collect();
    std::fs::write(&path, &changed).expect("the file changes");
    gate.release();
    control.stop_holding();
    control.release_all();

    let told = tokio::time::timeout(WATCHDOG, sending)
        .await
        .expect("the upload ends")
        .expect("the task ran")
        .expect_err("a changed file is not sent on");
    assert_eq!(told.message, companion_tauri::open_transfers::CANNOT_RESUME);
    let listed = open_where(companion, |now| {
        now.iter().any(|view| view["state"] == "cannotResume")
    })
    .await;
    assert_eq!(
        listed[0]["said"],
        companion_tauri::open_transfers::CANNOT_RESUME
    );
    adopted.stop().await;
}

/// KR-REQ-13.12: an entry of another version is left alone with its copy, and its key is not given
/// to a new upload.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_13_12_an_entry_of_another_version_is_left_with_its_copy() {
    let adopted = Adopted::start(1).await;
    let (phone, _control) = phone_for(&adopted).await;
    let key = kr_ipc::new_uuid();
    let root = folder(&phone);
    std::fs::create_dir_all(&root).expect("the folder");
    let entry = root.join(format!("{key}.upload"));
    let copy = root.join(format!("{key}.bytes"));
    std::fs::write(&entry, br#"{"version":2,"kept":"by a later release"}"#).expect("the entry");
    std::fs::write(&copy, b"the person's file").expect("the copy");

    let desk = desk_of(&phone.companion);
    desk.restart(paired_of(&phone.companion)).await;
    assert_eq!(
        std::fs::read(&entry).expect("the entry stands"),
        br#"{"version":2,"kept":"by a later release"}"#
    );
    assert_eq!(
        std::fs::read(&copy).expect("the copy stands"),
        b"the person's file"
    );

    let bytes = pattern(5);
    let refused = desk
        .send(
            paired_of(&phone.companion),
            request(&adopted, &bytes, Arc::new(Held::new(bytes.clone())), key),
        )
        .await
        .expect_err("the key is held by the later entry");
    assert_eq!(refused.message, companion_tauri::open_transfers::KEY_IN_USE);
    assert_eq!(
        std::fs::read(&copy).expect("the copy stands"),
        b"the person's file"
    );
    adopted.stop().await;
}

/// KR-REQ-13.12: a copy ends with its entry: after a published upload, for an upload found
/// unrecoverable, for a copy a stopped process left half written, and for one no entry names.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_13_12_a_copy_that_no_upload_needs_is_removed_at_the_next_reach() {
    let adopted = Adopted::start(1).await;
    let (phone, _control) = phone_for(&adopted).await;
    let paired = paired_of(&phone.companion);
    let desk = desk_of(&phone.companion);
    let root = folder(&phone);

    // Published, and the copy outlived it (a stop between the two writes).
    let (published, bytes) = published_with_a_lost_answer(&adopted, &phone).await;
    desk.restart(paired.clone()).await;
    testing::keep_copy(&root, published, &bytes);
    assert_eq!(copies_in(&root), 1, "the stray copy is there");
    desk.restart(paired.clone()).await;
    assert_eq!(copies_in(&root), 0, "a published upload keeps no copy");

    // Found unrecoverable: it cannot resume, so its copy is of no use.
    let lost = kr_ipc::new_uuid();
    testing::keep(
        &root,
        lost,
        paired.environment_id,
        paired.device_id,
        None,
        net_support::on_the_host(&adopted.host),
        None,
        testing::Got::Beginning,
        10,
        Held::new(vec![0; 10]).digest(),
        testing::Where::Copy,
    );
    testing::keep_copy(&root, lost, &[0; 10]);
    // One a stopped process left half written, and one no entry names.
    let staged = root.join(format!("{}.bytes.staged-1-0", kr_ipc::new_uuid()));
    std::fs::write(&staged, b"half").expect("the staged file");
    testing::keep_copy(&root, kr_ipc::new_uuid(), b"no entry");
    desk.restart(paired).await;
    assert_eq!(copies_in(&root), 0, "no copy stands");
    assert!(!staged.exists(), "the half-written file is removed");
    assert_eq!(
        open(&phone.companion)
            .iter()
            .filter(|view| view["state"] == "unrecoverable")
            .count(),
        1,
        "the entry stays and says so"
    );
    adopted.stop().await;
}

/// KR-REQ-13.12: an entry of another principal on the host belongs to a sign-in that is not the one
/// in force: it is dropped with its copy, and so is its draft.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_13_12_an_entry_of_another_principal_is_dropped_with_its_copy_and_its_draft() {
    let adopted = Adopted::start(1).await;
    let (phone, _control) = phone_for(&adopted).await;
    let companion = &phone.companion;
    let paired = paired_of(companion);
    let other = Paired {
        device_id: kr_protocol::ids::DeviceId::new(kr_ipc::new_uuid()),
        ..paired.clone()
    };
    let key = kr_ipc::new_uuid();
    let bytes = vec![5_u8; 16];
    testing::keep(
        &folder(&phone),
        key,
        other.environment_id,
        other.device_id,
        None,
        net_support::on_the_host(&adopted.host),
        Some(kr_protocol::ids::TransferId::new(kr_ipc::new_uuid())),
        testing::Got::Begun,
        16,
        Held::new(bytes.clone()).digest(),
        testing::Where::Copy,
    );
    testing::keep_copy(&folder(&phone), key, &bytes);
    let session = adopted.workers[0].session_id;
    let drafts = companion
        .app
        .state::<companion_tauri::AppState>()
        .paired_drafts();
    drafts.keep_for_test(
        &other,
        session,
        &net_support::on_the_session(&adopted.host, session),
        Some(kr_protocol::ids::DraftId::new(kr_ipc::new_uuid())),
        Some(kr_protocol::ids::DraftRevision::new(1)),
    );
    let drafts_in = || {
        std::fs::read_dir(folder(&phone))
            .map(|listing| {
                listing
                    .flatten()
                    .filter(|item| item.path().extension().is_some_and(|ext| ext == "draft"))
                    .count()
            })
            .unwrap_or(0)
    };
    assert_eq!(drafts_in(), 1);

    desk_of(companion).restart(paired.clone()).await;
    drafts.sweep(paired, &[session]).await;
    assert_eq!(entries_in(&folder(&phone)), 0);
    assert_eq!(copies_in(&folder(&phone)), 0);
    assert_eq!(drafts_in(), 0);
    adopted.stop().await;
}

/// KR-REQ-13.12: forgetting a host ends what is sent to it and removes every entry, copy and draft
/// kept for the pairing.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_13_12_forgetting_a_host_removes_its_uploads_copies_and_drafts() {
    let adopted = Adopted::start(1).await;
    let (phone, _control) = phone_for(&adopted).await;
    let companion = &phone.companion;
    let session = adopted.workers[0].session_id;
    bind(companion, session, &handed(companion)).expect("a draft is kept");
    let bytes = pattern(5);
    let (content, gate, _release) = gated(&bytes);
    let desk = desk_of(companion);
    let sending = {
        let sent = request(&adopted, &bytes, content, kr_ipc::new_uuid());
        let paired = paired_of(companion);
        tokio::spawn(async move { desk.send(paired, sent).await })
    };
    gate.reached().await;
    let everything = || {
        std::fs::read_dir(folder(&phone))
            .map(|listing| listing.flatten().count())
            .unwrap_or(0)
    };
    assert!(everything() >= 3, "an entry, a copy and a draft are kept");

    let view = companion
        .call("pairing_view", json!({}))
        .expect("the pairing screen");
    let reference = view["hosts"][0]["reference"]
        .as_str()
        .expect("a reference to the host")
        .to_owned();
    let host = companion
        .device()
        .host_by_reference(&reference)
        .expect("the pairing is listed");
    companion_tauri::hosts::forget_host(companion.app.handle(), &host)
        .await
        .expect("the host is forgotten");
    gate.release();

    assert_eq!(everything(), 0, "nothing is kept for the forgotten host");
    let told = tokio::time::timeout(WATCHDOG, sending)
        .await
        .expect("the upload ends")
        .expect("the task ran")
        .expect_err("a forgotten host is not sent to");
    assert_eq!(told.message, companion_tauri::open_transfers::CANCELLED);
    adopted.stop().await;
}

/// The id of the one draft file the phone keeps, and the bytes in it.
fn draft_file(phone: &Phone) -> (PathBuf, Vec<u8>) {
    let path = std::fs::read_dir(folder(phone))
        .expect("the folder")
        .flatten()
        .map(|item| item.path())
        .find(|path| path.extension().is_some_and(|ext| ext == "draft"))
        .expect("a draft is kept");
    let bytes = std::fs::read(&path).expect("the draft");
    (path, bytes)
}

/// KR-REQ-23.41: a bind the host refuses for a reason other than a missing draft keeps the draft, and
/// the refusal is the host's own words, not the sentence for a draft that is gone.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_23_41_a_bind_refused_for_another_reason_than_gone_keeps_the_draft() {
    let adopted = Adopted::start(1).await;
    let (phone, _control) = phone_for(&adopted).await;
    let companion = &phone.companion;
    let session = adopted.workers[0].session_id;
    let mut last = Value::Null;
    for _ in 0..4 {
        last = bind(companion, session, &handed(companion)).expect("a bind within the count");
    }
    let refused = bind(companion, session, &handed(companion)).expect_err("a fifth is refused");
    assert_ne!(
        refused["message"],
        companion_tauri::paired_drafts::GONE,
        "the draft is not gone: {refused}"
    );
    let reread = kept(companion, session);
    assert_eq!(reread["made"], true, "the draft stands: {reread}");
    assert_eq!(reread["draftId"], last["value"]["draftId"]);
    assert_eq!(reread["attachments"].as_array().map(Vec::len), Some(4));
    adopted.stop().await;
}

/// KR-REQ-23.41: a bind whose request never left, because the connection had ended, keeps the draft
/// and the files already on it: the next bind uses the same draft.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_23_41_a_bind_that_never_left_keeps_the_draft_and_its_files() {
    let adopted = Adopted::start(1).await;
    let (phone, control) = phone_for(&adopted).await;
    let companion = &phone.companion;
    let session = adopted.workers[0].session_id;
    let first = bind(companion, session, &handed(companion)).expect("the first bind");
    let second = handed(companion);
    let old = paired_of(companion).session;
    control.hold();
    old.transport().close();
    bind(companion, session, &second).expect_err("the connection has ended");
    control.stop_holding();
    control.release_all();
    on_another_connection(companion, &old).await;
    connected(companion).await;

    let again = bind(companion, session, &second).expect("the bind goes on");
    assert_eq!(
        again["value"]["draftId"], first["value"]["draftId"],
        "the files stay on one draft: {again}"
    );
    assert_eq!(
        kept(companion, session)["attachments"]
            .as_array()
            .map(Vec::len),
        Some(2)
    );
    adopted.stop().await;
}

/// KR-REQ-23.41: a draft kept by a later release is never read or overwritten, and the bind says so.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_23_41_a_draft_of_a_later_version_is_not_overwritten() {
    let adopted = Adopted::start(1).await;
    let (phone, _control) = phone_for(&adopted).await;
    let companion = &phone.companion;
    let session = adopted.workers[0].session_id;
    bind(companion, session, &handed(companion)).expect("the first bind");
    let (path, bytes) = draft_file(&phone);
    let later =
        String::from_utf8(bytes)
            .expect("json")
            .replacen("\"version\":1", "\"version\":2", 1);
    std::fs::write(&path, &later).expect("a later release writes it");

    let refused = bind(companion, session, &handed(companion)).expect_err("the bind is refused");
    assert_eq!(
        refused["message"],
        companion_tauri::paired_drafts::NEWER_DRAFT
    );
    assert_eq!(std::fs::read_to_string(&path).expect("the draft"), later);
    adopted.stop().await;
}

/// KR-REQ-23.41: two binds at once make one draft and lose no attachment record.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_23_41_two_binds_at_once_make_one_draft_and_keep_both_files() {
    let adopted = Adopted::start(1).await;
    let (phone, _control) = phone_for(&adopted).await;
    let companion = &phone.companion;
    let session = adopted.workers[0].session_id;
    let (one, two) = (handed(companion), handed(companion));
    let drafts = companion
        .app
        .state::<companion_tauri::AppState>()
        .paired_drafts();
    let binding = |handle: &Value| {
        let bind = companion_tauri::paired_drafts::Bind {
            session_id: session,
            application_instance_id: None,
            text: "see the file".to_owned(),
            transfer_id: serde_json::from_value(handle["transfer_id"].clone()).expect("an id"),
            contribution: serde_json::from_value(contribution()).expect("a contribution"),
        };
        let (drafts, paired) = (Arc::clone(&drafts), paired_of(companion));
        let target = net_support::on_the_session(&adopted.host, session);
        tokio::spawn(async move { drafts.bind(paired, target, bind).await })
    };
    let (first, second) = (binding(&one), binding(&two));
    let first = first.await.expect("ran").expect("one bind");
    let second = second.await.expect("ran").expect("the other bind");
    assert_eq!(first.draft_id, second.draft_id);
    let reread = kept(companion, session);
    assert_eq!(
        reread["attachments"].as_array().map(Vec::len),
        Some(2),
        "{reread}"
    );
    adopted.stop().await;
}

/// KR-REQ-23.41: the start's sweep ends a draft that no listed session holds on the target the draft
/// was made on, so the host really holds no draft after it.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_23_41_the_sweep_ends_a_real_draft_on_its_own_target() {
    use kr_protocol::transfer::DraftDiscardParams;

    let adopted = Adopted::start(1).await;
    let (phone, _control) = phone_for(&adopted).await;
    let companion = &phone.companion;
    let session = adopted.workers[0].session_id;
    let first = bind(companion, session, &handed(companion)).expect("the first bind");
    let draft_id: kr_protocol::ids::DraftId =
        serde_json::from_value(first["value"]["draftId"].clone()).expect("a draft id");
    let paired = paired_of(companion);
    let drafts = companion
        .app
        .state::<companion_tauri::AppState>()
        .paired_drafts();

    drafts.sweep(paired.clone(), &[]).await;
    assert_eq!(kept(companion, session)["made"], false);
    let again = paired
        .session
        .mutate(
            kr_protocol::method::Method::DraftDiscard,
            net_support::on_the_session(&adopted.host, session),
            None,
            &json!({}),
            &DraftDiscardParams { draft_id },
            kr_protocol::scalars::DurationMs::new(60_000),
        )
        .await
        .expect_err("the host holds no such draft any more");
    assert!(said(&again).starts_with("no draft "), "{again}");
    adopted.stop().await;
}

/// KR-REQ-23.41: a `draft.create` whose answer was lost is sent again exactly, on a new connection,
/// and the host's record answers it: the draft the host made is the one kept, and none is made again.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_23_41_a_lost_create_is_answered_by_the_hosts_record_and_not_made_again() {
    use kr_protocol::ids::ActionId;
    use kr_protocol::method::Method;
    use kr_protocol::transfer::{DraftCreateParams, DraftCreateResult};

    let adopted = Adopted::start(1).await;
    let (phone, _control) = phone_for(&adopted).await;
    let companion = &phone.companion;
    let session = adopted.workers[0].session_id;
    let paired = paired_of(companion);
    let target = net_support::on_the_session(&adopted.host, session);
    let composed = paired
        .session
        .compose(
            Method::DraftCreate,
            ActionId::new(kr_ipc::new_uuid()),
            target.clone(),
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
    // The process that sent it never saw the answer: it kept the request, and no draft.
    let drafts = companion
        .app
        .state::<companion_tauri::AppState>()
        .paired_drafts();
    drafts.keep_create_for_test(&paired, session, &target, &composed);
    let old = Arc::clone(&paired.session);
    old.transport().close();
    on_another_connection(companion, &old).await;

    let bound = bind(companion, session, &handed(companion)).expect("the bind goes on");
    assert_eq!(
        bound["value"]["draftId"],
        made.draft.draft_id.to_string(),
        "the draft the host made is the one kept: {bound}"
    );
    adopted.stop().await;
}

/// KR-REQ-23.41: a `draft.create` the host never got is not made again at once, and does not block the
/// session's binds for good: the bind says the answer has not been received, and the entry is kept.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_23_41_a_create_not_known_to_have_failed_is_kept_and_said() {
    use kr_protocol::ids::ActionId;
    use kr_protocol::method::Method;
    use kr_protocol::transfer::DraftCreateParams;

    let adopted = Adopted::start(1).await;
    let (phone, _control) = phone_for(&adopted).await;
    let companion = &phone.companion;
    let session = adopted.workers[0].session_id;
    let paired = paired_of(companion);
    let target = net_support::on_the_session(&adopted.host, session);
    let composed = paired
        .session
        .compose(
            Method::DraftCreate,
            ActionId::new(kr_ipc::new_uuid()),
            target.clone(),
            None,
            &json!({}),
            &DraftCreateParams {
                environment_id: adopted.host.environment_id,
                device_id: Nullable::null(),
                session_id: Nullable::some(session),
                application_instance_id: Nullable::null(),
                text: String::new(),
            },
            kr_protocol::scalars::DurationMs::new(60_000),
        )
        .await
        .expect("composed");
    companion
        .app
        .state::<companion_tauri::AppState>()
        .paired_drafts()
        .keep_create_for_test(&paired, session, &target, &composed);
    let old = Arc::clone(&paired.session);
    old.transport().close();
    on_another_connection(companion, &old).await;

    let refused =
        bind(companion, session, &handed(companion)).expect_err("not known to have failed");
    assert_eq!(
        refused["message"],
        companion_tauri::paired_drafts::CREATE_PENDING,
        "{refused}"
    );
    assert_eq!(kept(companion, session)["made"], false);
    let (_, bytes) = draft_file(&phone);
    assert!(
        String::from_utf8_lossy(&bytes).contains("\"create\":{"),
        "the request stays kept"
    );
    adopted.stop().await;
}

/// KR-REQ-23.41: a `draft.discard` whose answer was lost is sent again exactly on a new connection and
/// answered from the host's record: the entry ends, and the next bind makes a new draft.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_23_41_a_lost_discard_is_answered_by_the_hosts_record() {
    use kr_protocol::ids::ActionId;
    use kr_protocol::method::Method;
    use kr_protocol::transfer::DraftDiscardParams;

    let adopted = Adopted::start(1).await;
    let (phone, _control) = phone_for(&adopted).await;
    let companion = &phone.companion;
    let session = adopted.workers[0].session_id;
    let first = bind(companion, session, &handed(companion)).expect("the first bind");
    let draft_id: kr_protocol::ids::DraftId =
        serde_json::from_value(first["value"]["draftId"].clone()).expect("a draft id");
    let revision: kr_protocol::ids::DraftRevision =
        serde_json::from_value(first["value"]["revision"].clone()).expect("a revision");
    let paired = paired_of(companion);
    let target = net_support::on_the_session(&adopted.host, session);
    let composed = paired
        .session
        .compose(
            Method::DraftDiscard,
            ActionId::new(kr_ipc::new_uuid()),
            target.clone(),
            None,
            &json!({}),
            &DraftDiscardParams { draft_id },
            kr_protocol::scalars::DurationMs::new(60_000),
        )
        .await
        .expect("composed");
    paired
        .session
        .send(&composed)
        .await
        .expect("the host ended the draft");
    companion
        .app
        .state::<companion_tauri::AppState>()
        .paired_drafts()
        .keep_discard_for_test(&paired, session, &target, draft_id, revision, &composed);
    let old = Arc::clone(&paired.session);
    old.transport().close();
    on_another_connection(companion, &old).await;

    companion
        .call(
            "draft_end",
            json!({ "subject": on_session(session), "sessionId": session.to_string() }),
        )
        .expect("the host's record ends it");
    assert_eq!(kept(companion, session)["made"], false);
    let next = bind(companion, session, &handed(companion)).expect("a new draft is made");
    assert_ne!(
        next["value"]["draftId"], first["value"]["draftId"],
        "{next}"
    );
    adopted.stop().await;
}

/// KR-REQ-23.41: a stop in the middle of a bind leaves no falsely known revision. The entry says the
/// revision is unknown while the call is out, so the next bind ends that draft and makes a new one,
/// and does not add to a draft at a revision the host may have moved past.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_23_41_a_stop_during_a_bind_leaves_no_falsely_known_revision() {
    use kr_protocol::method::Method;

    let adopted = Adopted::start(1).await;
    let (phone, control) = phone_for(&adopted).await;
    let companion = &phone.companion;
    let session = adopted.workers[0].session_id;
    let first = bind(companion, session, &handed(companion)).expect("the first bind");
    assert_eq!(
        kept(companion, session)["revision"],
        first["value"]["revision"],
        "the revision is known between binds"
    );
    let second = handed(companion);
    let drafts = companion
        .app
        .state::<companion_tauri::AppState>()
        .paired_drafts();
    let bind_of = companion_tauri::paired_drafts::Bind {
        session_id: session,
        application_instance_id: None,
        text: "see the file".to_owned(),
        transfer_id: serde_json::from_value(second["transfer_id"].clone()).expect("an id"),
        contribution: serde_json::from_value(contribution()).expect("a contribution"),
    };

    control.hold_next_request(Method::AgentDraftAddAttachment);
    let binding = {
        let (drafts, paired) = (Arc::clone(&drafts), paired_of(companion));
        let target = net_support::on_the_session(&adopted.host, session);
        tokio::spawn(async move { drafts.bind(paired, target, bind_of).await })
    };
    control.until_request_held().await;
    // The process stops here: the call is out and its answer is never read.
    binding.abort();
    assert!(binding.await.is_err(), "the bind was stopped");
    let (path, bytes) = draft_file(&phone);
    let entry: Value = serde_json::from_slice(&bytes).expect("the entry reads");
    assert_eq!(
        entry["draftId"], first["value"]["draftId"],
        "the draft is the one that was made: {entry}"
    );
    assert!(
        entry["revision"].is_null(),
        "the revision is not known while the call is out: {entry}"
    );
    let shown = kept(companion, session);
    assert_eq!(shown["made"], true, "{shown}");
    assert!(shown["revision"].is_null(), "{shown}");

    // The stopped process may or may not have moved the host's draft: the entry does not guess.
    control.release_request();
    let next = bind(companion, session, &second).expect("the next bind makes a new draft");
    assert_ne!(
        next["value"]["draftId"], first["value"]["draftId"],
        "a draft of an unknown revision is ended and not added to: {next}"
    );
    let reread = kept(companion, session);
    assert_eq!(
        reread["attachments"].as_array().map(Vec::len),
        Some(1),
        "{reread}"
    );
    assert!(path.exists(), "the new draft is kept");
    adopted.stop().await;
}

/// KR-REQ-23.41: the wait for a `draft.create` the host may never have got runs to its end. Inside
/// the window and its margin the bind says the answer has not been received and the request stays
/// kept; once they have passed the request is known not to have taken effect, it is dropped from the
/// entry, and the bind makes the draft.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_23_41_the_wait_for_a_lost_create_runs_out_and_the_draft_is_made_anew() {
    use kr_protocol::ids::ActionId;
    use kr_protocol::method::Method;
    use kr_protocol::transfer::DraftCreateParams;

    let adopted = Adopted::start(1).await;
    let (phone, _control) = phone_for(&adopted).await;
    let companion = &phone.companion;
    let session = adopted.workers[0].session_id;
    let paired = paired_of(companion);
    let target = net_support::on_the_session(&adopted.host, session);
    // The request was composed and kept, and the host never got it.
    let composed = paired
        .session
        .compose(
            Method::DraftCreate,
            ActionId::new(kr_ipc::new_uuid()),
            target.clone(),
            None,
            &json!({}),
            &DraftCreateParams {
                environment_id: adopted.host.environment_id,
                device_id: Nullable::null(),
                session_id: Nullable::some(session),
                application_instance_id: Nullable::null(),
                text: String::new(),
            },
            kr_protocol::scalars::DurationMs::new(60_000),
        )
        .await
        .expect("composed");
    let drafts = companion
        .app
        .state::<companion_tauri::AppState>()
        .paired_drafts();
    drafts.keep_create_for_test(&paired, session, &target, &composed);
    let old = Arc::clone(&paired.session);
    old.transport().close();
    on_another_connection(companion, &old).await;
    connected(companion).await;
    let window = Duration::from_millis(composed.window_valid_for_ms());

    // Inside the wait: the window and the margin of 30 seconds have not passed.
    drafts.armed_ago_for_test(composed.action_id(), window + Duration::from_secs(20));
    let refused = bind(companion, session, &handed(companion)).expect_err("inside the wait");
    assert_eq!(
        refused["message"],
        companion_tauri::paired_drafts::CREATE_PENDING,
        "{refused}"
    );
    let (_, kept_bytes) = draft_file(&phone);
    assert!(
        String::from_utf8_lossy(&kept_bytes).contains("\"create\":{"),
        "the request stays kept inside the wait"
    );

    // Past the wait: nothing was made, and the bind goes on to make the draft.
    drafts.armed_ago_for_test(composed.action_id(), window + Duration::from_secs(31));
    let made = bind(companion, session, &handed(companion)).expect("the wait ran out");
    assert!(made["value"]["draftId"].is_string(), "{made}");
    let shown = kept(companion, session);
    assert_eq!(shown["made"], true, "{shown}");
    assert_eq!(shown["draftId"], made["value"]["draftId"]);
    let (_, bytes) = draft_file(&phone);
    assert!(
        !String::from_utf8_lossy(&bytes).contains("\"create\":{"),
        "the settled request is not kept"
    );
    adopted.stop().await;
}

/// A prompt that names `draft_id`, for the agent `instance` of `session`, as the page sends it.
fn draft_prompt(
    session: kr_protocol::ids::SessionId,
    instance: kr_protocol::ids::ApplicationInstanceId,
    draft_id: kr_protocol::ids::DraftId,
) -> Value {
    serde_json::to_value(kr_protocol::agent::AgentPromptParams {
        target: kr_protocol::agent::AgentMutationTarget {
            subject: kr_worker::broker::subject(session, instance),
            binding_revision: kr_protocol::ids::AgentBindingRevision::new(1),
        },
        draft_id: Nullable::some(draft_id),
        text: Nullable::null(),
    })
    .expect("encodes")
}

fn made_draft(bound: &Value) -> kr_protocol::ids::DraftId {
    serde_json::from_value(bound["value"]["draftId"].clone()).expect("a draft id")
}

/// KR-REQ-23.41: a prompt that names the draft, sent to a live agent over the paired door, ends what
/// this device kept of the draft only when the host applied it and only for the draft the entry is
/// for. An outcome nobody can establish leaves the draft where it is.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_23_41_a_draft_prompt_to_a_live_agent_ends_the_kept_draft_only_when_applied_for_that_draft()
 {
    let adopted = Adopted::start(3).await;
    let (phone, _control) = phone_for(&adopted).await;
    let companion = &phone.companion;
    let held = Arc::new(net_support::worker::HeldUpstream::default());
    let taken = [
        Arc::new(net_support::worker::Upstream::default()),
        Arc::new(net_support::worker::Upstream::default()),
    ];
    let instances = [
        adopted.workers[0].register_agent_on(Arc::clone(&held) as _),
        adopted.workers[1].register_agent_on(Arc::clone(&taken[0]) as _),
        adopted.workers[2].register_agent_on(Arc::clone(&taken[1]) as _),
    ];
    let sessions = [
        adopted.workers[0].session_id,
        adopted.workers[1].session_id,
        adopted.workers[2].session_id,
    ];
    // The page opens each session's screen first, and sends the prompt under that opening.
    for session in sessions {
        companion
            .call(
                "session_open",
                json!({ "sessionId": session.to_string(), "grantId": null, "opening": "screen" }),
            )
            .expect("the session opens");
    }
    let prompt_for = |at: usize, draft_id| {
        companion.call(
            "agent_prompt_submit",
            json!({
                "params": draft_prompt(sessions[at], instances[at], draft_id),
                "opening": "screen",
            }),
        )
    };

    // An outcome nobody can establish: the agent has the prompt and nothing says it was applied.
    let unknown = made_draft(&bind(companion, sessions[0], &handed(companion)).expect("a bind"));
    let answer = prompt_for(0, unknown).expect("an outcome nobody can establish is an answer");
    assert!(answer["value"].is_null(), "{answer}");
    let stays = kept(companion, sessions[0]);
    assert_eq!(stays["made"], true, "the draft stays: {stays}");
    assert_eq!(stays["draftId"], unknown.to_string());

    // A prompt the host applied for the kept draft ends what is kept of it.
    let used = made_draft(&bind(companion, sessions[1], &handed(companion)).expect("a bind"));
    prompt_for(1, used).expect("the prompt is applied");
    assert_eq!(taken[0].prompts().len(), 1, "the agent has the prompt");
    assert_eq!(
        kept(companion, sessions[1])["made"],
        false,
        "the entry of a draft that was sent ends"
    );

    // A prompt for another draft than the one kept leaves the entry: the host applies it for the
    // draft it names, and the entry is for a later draft.
    let named = made_draft(&bind(companion, sessions[2], &handed(companion)).expect("a bind"));
    let later = kr_protocol::ids::DraftId::new(kr_ipc::new_uuid());
    companion
        .app
        .state::<companion_tauri::AppState>()
        .paired_drafts()
        .keep_for_test(
            &paired_of(companion),
            sessions[2],
            &net_support::on_the_session(&adopted.host, sessions[2]),
            Some(later),
            Some(kr_protocol::ids::DraftRevision::new(1)),
        );
    prompt_for(2, named).expect("the prompt is applied");
    assert_eq!(taken[1].prompts().len(), 1);
    let entry = kept(companion, sessions[2]);
    assert_eq!(entry["draftId"], later.to_string(), "{entry}");
    held.release();
    adopted.stop().await;
}

/// KR-REQ-13.12: a connection that comes up before the driver of an upload has failed on its own is
/// the one the upload goes on, at once. The host was reached while the upload still ran, so nothing
/// else would resume it when its connection's failure is told.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_13_12_a_reconnect_before_the_driver_fails_resumes_the_upload_on_the_new_connection()
{
    let adopted = Adopted::start(1).await;
    let (phone, _control) = phone_for(&adopted).await;
    let companion = &phone.companion;
    let desk = desk_of(companion);
    let bytes = pattern(5);
    let (content, gate, _release) = gated(&bytes);
    let paired = paired_of(companion);
    let old = Arc::clone(&paired.session);
    let sending = {
        let sent = request(&adopted, &bytes, content, kr_ipc::new_uuid());
        let desk = Arc::clone(&desk);
        tokio::spawn(async move { desk.send(paired, sent).await })
    };
    gate.reached().await;
    // The connection ends and the phone makes another while the content still holds the driver.
    old.transport().close();
    let newer = on_another_connection(companion, &old).await;
    tokio::time::timeout(WATCHDOG, async {
        while !desk.holds_newest_for_test(&newer) {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the desk is told the host was reached on the new connection");
    assert!(!sending.is_finished(), "the upload has not ended");

    // The driver fails only now, on the connection that has ended.
    gate.release();
    let handle = tokio::time::timeout(WATCHDOG, sending)
        .await
        .expect("the upload goes on at once on the new connection")
        .expect("the task ran")
        .expect("the upload is published");
    assert_eq!(handle.byte_len.get(), bytes.len() as u64);
    assert_eq!(
        copies_in(&folder(&phone)),
        0,
        "the copy ends with the upload"
    );
    adopted.stop().await;
}

/// How many draft creations and discards the client's book still holds as unresolved on `session`.
async fn draft_actions_in_the_book(session: &kr_client::Session) -> usize {
    use kr_protocol::method::Method;

    session
        .submitted_actions()
        .await
        .iter()
        .filter(|action| matches!(action.method, Method::DraftCreate | Method::DraftDiscard))
        .count()
}

/// KR-REQ-23.41: a draft creation or discard the host has answered leaves the client's book of
/// unresolved actions, whether it was answered at once or from the host's record after a lost answer.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_23_41_an_answered_draft_action_leaves_the_clients_book() {
    use kr_protocol::ids::ActionId;
    use kr_protocol::method::Method;
    use kr_protocol::transfer::{DraftCreateParams, DraftDiscardParams};

    let adopted = Adopted::start(1).await;
    let (phone, _control) = phone_for(&adopted).await;
    let companion = &phone.companion;
    let session = adopted.workers[0].session_id;
    let target = net_support::on_the_session(&adopted.host, session);
    let drafts = companion
        .app
        .state::<companion_tauri::AppState>()
        .paired_drafts();
    let end = || {
        companion
            .call(
                "draft_end",
                json!({ "subject": on_session(session), "sessionId": session.to_string() }),
            )
            .expect("the draft ends")
    };

    // A creation and a discard answered at once.
    bind(companion, session, &handed(companion)).expect("the draft is made");
    let connection = paired_of(companion).session;
    assert_eq!(draft_actions_in_the_book(&connection).await, 0, "creation");
    end();
    assert_eq!(draft_actions_in_the_book(&connection).await, 0, "discard");

    // A creation whose answer was lost, answered from the host's record on the next connection.
    let paired = paired_of(companion);
    let composed = paired
        .session
        .compose(
            Method::DraftCreate,
            ActionId::new(kr_ipc::new_uuid()),
            target.clone(),
            None,
            &json!({}),
            &DraftCreateParams {
                environment_id: adopted.host.environment_id,
                device_id: Nullable::null(),
                session_id: Nullable::some(session),
                application_instance_id: Nullable::null(),
                text: String::new(),
            },
            kr_protocol::scalars::DurationMs::new(60_000),
        )
        .await
        .expect("composed");
    paired
        .session
        .send(&composed)
        .await
        .expect("the host made the draft");
    drafts.keep_create_for_test(&paired, session, &target, &composed);
    let old = Arc::clone(&paired.session);
    old.transport().close();
    let next = on_another_connection(companion, &old).await;
    connected(companion).await;
    let made = bind(companion, session, &handed(companion)).expect("the host's record answers");
    assert_eq!(
        draft_actions_in_the_book(&next.session).await,
        0,
        "the repeated creation"
    );

    // A discard whose answer was lost, answered from the host's record on the next connection.
    let draft_id: kr_protocol::ids::DraftId =
        serde_json::from_value(made["value"]["draftId"].clone()).expect("a draft id");
    let revision: kr_protocol::ids::DraftRevision =
        serde_json::from_value(made["value"]["revision"].clone()).expect("a revision");
    let discard = next
        .session
        .compose(
            Method::DraftDiscard,
            ActionId::new(kr_ipc::new_uuid()),
            target.clone(),
            None,
            &json!({}),
            &DraftDiscardParams { draft_id },
            kr_protocol::scalars::DurationMs::new(60_000),
        )
        .await
        .expect("composed");
    next.session
        .send(&discard)
        .await
        .expect("the host ended the draft");
    drafts.keep_discard_for_test(&next, session, &target, draft_id, revision, &discard);
    let old = Arc::clone(&next.session);
    old.transport().close();
    let last = on_another_connection(companion, &old).await;
    connected(companion).await;
    end();
    assert_eq!(
        draft_actions_in_the_book(&last.session).await,
        0,
        "the repeated discard"
    );
    adopted.stop().await;
}

fn drafts_in(folder: &Path) -> usize {
    std::fs::read_dir(folder)
        .map(|listing| {
            listing
                .flatten()
                .filter(|item| item.path().extension().is_some_and(|ext| ext == "draft"))
                .count()
        })
        .unwrap_or(0)
}

/// KR-REQ-13.12, KR-REQ-23.41: an account replacement, end to end. When the host is reached as the
/// device is now, an upload still sent as the earlier principal is stopped with its copy, and an
/// entry, a copy and a draft that a process of the earlier principal left when it stopped before it
/// saw the change are dropped. Nothing of the earlier principal is resumed or read from the host.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_13_12_a_reach_as_another_principal_stops_what_it_sent_and_drops_what_it_left() {
    use kr_protocol::method::Method;

    let adopted = Adopted::start(1).await;
    let (phone, control) = phone_for(&adopted).await;
    let companion = &phone.companion;
    let desk = desk_of(companion);
    let paired = paired_of(companion);
    let session = adopted.workers[0].session_id;
    let earlier = Paired {
        device_id: kr_protocol::ids::DeviceId::new(kr_ipc::new_uuid()),
        ..paired.clone()
    };

    // An upload that is still sent as the earlier principal, held in its content.
    let bytes = pattern(5);
    let (content, gate, _release) = gated(&bytes);
    let running = {
        let sent = request(&adopted, &bytes, content, kr_ipc::new_uuid());
        let (desk, earlier) = (Arc::clone(&desk), earlier.clone());
        tokio::spawn(async move { desk.send(earlier, sent).await })
    };
    gate.reached().await;
    // What a process of the earlier principal left: an upload entry with its copy, and a draft.
    let left = vec![9_u8; 16];
    let key = kr_ipc::new_uuid();
    testing::keep(
        &folder(&phone),
        key,
        earlier.environment_id,
        earlier.device_id,
        None,
        net_support::on_the_host(&adopted.host),
        Some(kr_protocol::ids::TransferId::new(kr_ipc::new_uuid())),
        testing::Got::Begun,
        16,
        Held::new(left.clone()).digest(),
        testing::Where::Copy,
    );
    testing::keep_copy(&folder(&phone), key, &left);
    companion
        .app
        .state::<companion_tauri::AppState>()
        .paired_drafts()
        .keep_for_test(
            &earlier,
            session,
            &net_support::on_the_session(&adopted.host, session),
            Some(kr_protocol::ids::DraftId::new(kr_ipc::new_uuid())),
            Some(kr_protocol::ids::DraftRevision::new(1)),
        );
    assert_eq!(entries_in(&folder(&phone)), 2);
    assert_eq!(copies_in(&folder(&phone)), 2);
    assert_eq!(drafts_in(&folder(&phone)), 1);
    let status_reads = control.sent(Method::UploadStatus);

    // The host is reached again, as the device is now.
    let old = Arc::clone(&paired.session);
    old.transport().close();
    on_another_connection(companion, &old).await;
    connected(companion).await;

    let stopped = tokio::time::timeout(WATCHDOG, running)
        .await
        .expect("the upload of the earlier principal ends")
        .expect("the task ran")
        .expect_err("an upload of another principal is not sent on");
    assert_eq!(stopped.message, companion_tauri::open_transfers::CANCELLED);
    tokio::time::timeout(WATCHDOG, async {
        while entries_in(&folder(&phone)) + copies_in(&folder(&phone)) + drafts_in(&folder(&phone))
            > 0
        {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("every entry, copy and draft of the earlier principal is dropped");
    assert_eq!(
        control.sent(Method::UploadStatus),
        status_reads,
        "nothing of the earlier principal is read from the host or resumed"
    );
    gate.release();
    adopted.stop().await;
}

/// KR-REQ-13.12, KR-REQ-23.41: a new sign-in on the same pairing. A host that answers to an
/// organisation sees one principal whoever is signed in, so what is kept is told apart by the
/// account: the new account is shown nothing of the earlier one's and reads none of its draft, and
/// when the host is reached under the new account an upload still sent under the earlier one is
/// stopped with its copy, and an entry, a copy and a draft the earlier account left are dropped.
/// Nothing of the earlier account is read from the host or resumed.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_13_12_a_new_sign_in_on_the_same_pairing_drops_what_the_earlier_account_kept() {
    use kr_client::services::AccountMark;
    use kr_protocol::method::Method;

    let adopted = Adopted::start(1).await;
    let (phone, control) = phone_for(&adopted).await;
    let companion = &phone.companion;
    let desk = desk_of(companion);
    let paired = paired_of(companion);
    let session = adopted.workers[0].session_id;
    // The same device on the same host: only the sign-in differs.
    let earlier = Paired {
        account: Some(AccountMark::from_bytes([1; 32])),
        ..paired.clone()
    };
    let now = Paired {
        account: Some(AccountMark::from_bytes([2; 32])),
        ..paired.clone()
    };

    // An upload still sent under the earlier account, held in its content.
    let bytes = pattern(5);
    let (content, gate, _release) = gated(&bytes);
    let running = {
        let sent = request(&adopted, &bytes, content, kr_ipc::new_uuid());
        let (desk, earlier) = (Arc::clone(&desk), earlier.clone());
        tokio::spawn(async move { desk.send(earlier, sent).await })
    };
    gate.reached().await;
    // What a process under the earlier account left: an entry with its copy, and a draft.
    let left = vec![9_u8; 16];
    let key = kr_ipc::new_uuid();
    testing::keep(
        &folder(&phone),
        key,
        earlier.environment_id,
        earlier.device_id,
        earlier.account,
        net_support::on_the_host(&adopted.host),
        Some(kr_protocol::ids::TransferId::new(kr_ipc::new_uuid())),
        testing::Got::Begun,
        16,
        Held::new(left.clone()).digest(),
        testing::Where::Copy,
    );
    testing::keep_copy(&folder(&phone), key, &left);
    let drafts = companion
        .app
        .state::<companion_tauri::AppState>()
        .paired_drafts();
    drafts.keep_for_test(
        &earlier,
        session,
        &net_support::on_the_session(&adopted.host, session),
        Some(kr_protocol::ids::DraftId::new(kr_ipc::new_uuid())),
        Some(kr_protocol::ids::DraftRevision::new(1)),
    );
    assert_eq!(entries_in(&folder(&phone)), 2);
    assert_eq!(copies_in(&folder(&phone)), 2);
    assert_eq!(drafts_in(&folder(&phone)), 1);

    // Before the host is reached again the new account is shown none of it.
    assert!(
        desk.open(&now.who()).is_empty(),
        "the new sign-in is shown nothing of the earlier account's uploads"
    );
    assert!(
        !drafts.kept(&now, session).made,
        "the new sign-in does not read the earlier account's draft"
    );
    let status_reads = control.sent(Method::UploadStatus);

    // The host is reached under the new account.
    desk.host_reached(now.clone());
    drafts.sweep_after_reach(now.clone()).await;

    let stopped = tokio::time::timeout(WATCHDOG, running)
        .await
        .expect("the upload of the earlier account ends")
        .expect("the task ran")
        .expect_err("an upload of another account is not sent on");
    assert_eq!(stopped.message, companion_tauri::open_transfers::CANCELLED);
    tokio::time::timeout(WATCHDOG, async {
        while entries_in(&folder(&phone)) + copies_in(&folder(&phone)) + drafts_in(&folder(&phone))
            > 0
        {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("every entry, copy and draft of the earlier account is dropped");
    assert_eq!(
        control.sent(Method::UploadStatus),
        status_reads,
        "nothing of the earlier account is read from the host or resumed"
    );
    gate.release();
    adopted.stop().await;
}

/// KR-REQ-13.12: while the host is out of reach the application still answers what it holds: an
/// upload whose connection ended reads as paused, with no connection to ask on, and reads as sent
/// again once the host is reached.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_13_12_a_paused_upload_is_read_while_the_host_is_out_of_reach() {
    let adopted = Adopted::start(1).await;
    let (phone, control) = phone_for(&adopted).await;
    let companion = &phone.companion;
    let desk = desk_of(companion);
    let bytes = pattern(5);
    let (content, gate, _release) = gated(&bytes);
    let paired = paired_of(companion);
    let (who, session) = (paired.who(), Arc::clone(&paired.session));
    let sending = {
        let sent = request(&adopted, &bytes, content, kr_ipc::new_uuid());
        tokio::spawn(async move { desk.send(paired, sent).await })
    };
    gate.reached().await;
    // The host cannot be reached again while the dials are held.
    control.hold();
    session.transport().close();
    gate.release();
    tokio::time::timeout(WATCHDOG, async {
        while companion
            .call("connection_state", json!({}))
            .is_ok_and(|state| state["connected"] == true)
        {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the connection ends");
    // The desk says the upload is paused as soon as its sender sees the end.
    let desk = desk_of(companion);
    tokio::time::timeout(WATCHDOG, async {
        while !desk
            .open(&who)
            .iter()
            .any(|view| view.state == companion_tauri::open_transfers::OpenState::Paused)
        {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the upload is paused");

    let read = try_open(companion).expect("the application answers while the host is out of reach");
    assert_eq!(read.len(), 1);
    assert_eq!(read[0]["state"], "paused");

    control.stop_holding();
    control.release_all();
    tokio::time::timeout(WATCHDOG, sending)
        .await
        .expect("the upload resumes once the host is reached")
        .expect("the task ran")
        .expect("the upload is published");
    adopted.stop().await;
}

/// KR-REQ-13.12: a cancel that comes while the copy of the file is still being written finds no sender
/// to stop, and the upload does not start afterwards: nothing reaches the host, the copy is gone, and
/// the waiting call is told it was cancelled.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_13_12_a_cancel_while_the_copy_is_written_stops_the_upload_from_starting() {
    use kr_protocol::method::Method;

    let adopted = Adopted::start(1).await;
    let (phone, control) = phone_for(&adopted).await;
    let companion = &phone.companion;
    let desk = desk_of(companion);
    let gate = desk.hold_after_copy_for_test();
    let bytes = pattern(5);
    let key = kr_ipc::new_uuid();
    let sending = {
        let sent = request(&adopted, &bytes, Arc::new(Held::new(bytes.clone())), key);
        let (desk, paired) = (Arc::clone(&desk), paired_of(companion));
        tokio::spawn(async move { desk.send(paired, sent).await })
    };
    tokio::time::timeout(WATCHDOG, async {
        while copies_in(&folder(&phone)) == 0 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the copy is written");
    desk.cancel(paired_of(companion), key)
        .await
        .expect("the cancel is answered");
    gate.add_permits(1);

    let told = tokio::time::timeout(WATCHDOG, sending)
        .await
        .expect("the send ends")
        .expect("the task ran")
        .expect_err("a cancelled upload does not start");
    assert_eq!(told.message, companion_tauri::open_transfers::CANCELLED);
    assert_eq!(
        control.sent(Method::UploadBegin),
        0,
        "nothing reached the host"
    );
    assert_eq!(copies_in(&folder(&phone)), 0, "the copy is gone");
    assert_eq!(entries_in(&folder(&phone)), 0, "the entry is gone");
    // Nothing starts late either.
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(
        control.sent(Method::UploadBegin),
        0,
        "nothing reaches the host late"
    );
    assert_eq!(entries_in(&folder(&phone)), 0, "no entry is written late");
    adopted.stop().await;
}
