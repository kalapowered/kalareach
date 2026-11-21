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
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use companion_tauri::open_transfers::{Desk, Keeping, Paired, Request, Who, kept_in, testing};
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

/// How long a case waits for a connection that is being taken up again.
const CONNECTION_WAIT: Duration = Duration::from_secs(20);

/// The paired host of `companion`, as soon as its connection is held, and the words of the last
/// refusal when `wait` ends first. Each look that found no connection is counted in `missed`.
async fn paired_within(
    companion: &Companion,
    wait: Duration,
    missed: &AtomicUsize,
) -> Result<Paired, String> {
    let mut last = String::new();
    let found = tokio::time::timeout(wait, async {
        loop {
            match companion
                .app
                .state::<companion_tauri::AppState>()
                .paired_snapshot()
            {
                Ok(held) => return held,
                Err(error) => {
                    missed.fetch_add(1, Ordering::SeqCst);
                    last = error.message;
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
        }
    })
    .await;
    match found {
        Ok((device_id, environment_id, session)) => Ok(Paired {
            device_id,
            environment_id,
            account: None,
            session,
        }),
        Err(_) => Err(last),
    }
}

/// The paired host of `companion`. A connection that is being taken up again is waited for, so a
/// case does not fail for a moment in which none is held.
async fn paired_of(companion: &Companion) -> Paired {
    match paired_within(companion, CONNECTION_WAIT, &AtomicUsize::new(0)).await {
        Ok(paired) => paired,
        Err(last) => panic!("no held connection within 20 s: {last}"),
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
    let mut sending = Vec::new();
    for content in [first, second] {
        let desk = Arc::clone(&desk);
        let sent = request(&adopted, &bytes, content, kr_ipc::new_uuid());
        let paired = paired_of(companion).await;
        sending.push(tokio::spawn(async move { desk.send(paired, sent).await }));
    }
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
        let (desk, paired) = (Arc::clone(&desk), paired_of(companion).await);
        tokio::spawn(async move { desk.send(paired, sent).await })
    };
    gate.reached().await;

    // The cancel stops the sender first: the content is let go only once the cancel is under way, so
    // that the upload cannot publish before it.
    let cancelling = {
        let (desk, paired) = (Arc::clone(&desk), paired_of(companion).await);
        tokio::spawn(async move { desk.cancel(paired.who(), Some(paired), key).await })
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
    let paired = paired_of(companion).await;
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
    let paired = paired_of(companion).await;
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
    before_the_host_is_reached: impl FnOnce(Uuid),
) -> Uuid {
    let companion = &phone.companion;
    let first = Arc::new(Desk::default());
    first.keep_at(folder(phone));
    let (content, gate, release) = gated(bytes);
    let key = kr_ipc::new_uuid();
    let mut sent = request(adopted, bytes, content, key);
    sent.keeping = keeping;
    let paired = paired_of(companion).await;
    let session = Arc::clone(&paired.session);
    // The task is the first process: nothing ever resumes it, and it ends with the case.
    let first_process = tokio::spawn(async move { first.send(paired, sent).await });
    gate.reached().await;
    control.hold();
    session.transport().close();
    gate.release();
    drop(release);
    before_the_host_is_reached(key);
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
        |_| {
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
        |_| {
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
        |_| {
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

    let paired = paired_of(&phone.companion).await;
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
    desk.restart(paired_of(&phone.companion).await).await;

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
    let paired = paired_of(&phone.companion).await;
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
    let paired = paired_of(&phone.companion).await;
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

async fn kept(companion: &Companion, session: kr_protocol::ids::SessionId) -> Value {
    let answer = try_kept(companion, session)
        .await
        .expect("the kept draft is read");
    answer["value"].clone()
}

/// The page's read of the draft kept for the session, or the refusal it gets.
async fn try_kept(
    companion: &Companion,
    session: kr_protocol::ids::SessionId,
) -> Result<Value, Value> {
    companion.call(
        "draft_create",
        json!({
            "subject": on_session(session),
            "params": {
                "environment_id": paired_of(companion).await.environment_id.to_string(),
                "device_id": null,
                "session_id": session.to_string(),
                "application_instance_id": null,
                "text": "",
            },
        }),
    )
}

/// KR-REQ-23.41: a draft entry this device cannot read is a failed read the page receives, never no
/// draft: a draft that may exist is not made again over, and an entry that is not there is no draft.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_23_41_a_stored_draft_that_cannot_be_read_is_a_failed_read_and_an_absent_one_is_no_draft()
 {
    let adopted = Adopted::start(1).await;
    let (phone, _control) = phone_for(&adopted).await;
    let companion = &phone.companion;
    let drafts = companion
        .app
        .state::<companion_tauri::AppState>()
        .paired_drafts();
    let paired = paired_of(companion).await;
    let session = adopted.workers[0].session_id;

    let none = try_kept(companion, session).await;
    assert_eq!(
        none.as_ref()
            .ok()
            .map(|answer| answer["value"]["made"].clone()),
        Some(json!(false)),
        "an entry that is not there is no draft: {none:?}"
    );

    drafts.keep_for_test(
        &paired,
        session,
        &net_support::on_the_session(&adopted.host, session),
        Some(kr_protocol::ids::DraftId::new(kr_ipc::new_uuid())),
        Some(kr_protocol::ids::DraftRevision::new(1)),
    );
    let made = try_kept(companion, session).await;
    assert_eq!(
        made.as_ref()
            .ok()
            .map(|answer| answer["value"]["made"].clone()),
        Some(json!(true)),
        "the draft is read: {made:?}"
    );

    // The entry is damaged, as a write that was cut short leaves it.
    let entries: Vec<_> = std::fs::read_dir(folder(&phone))
        .expect("the folder")
        .flatten()
        .map(|item| item.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "draft"))
        .collect();
    assert_eq!(entries.len(), 1);
    std::fs::write(&entries[0], b"{ not a draft").expect("the entry is damaged");
    let failed = try_kept(companion, session).await;
    assert_eq!(
        failed
            .as_ref()
            .err()
            .map(|refusal| refusal["message"].clone()),
        Some(json!(companion_tauri::paired_drafts::NEWER_DRAFT)),
        "an entry that cannot be read is a failed read: {failed:?}"
    );
    assert!(
        drafts.kept(&paired, session).is_err(),
        "the same for the native read"
    );
    adopted.stop().await;
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
        kept(companion, session).await["made"],
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
    let reread = kept(companion, session).await;
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
    let paired = paired_of(&phone.companion).await;
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
    let paired = paired_of(companion).await;
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
    assert_eq!(kept(companion, session).await["revision"], "4");
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
    assert_eq!(kept(companion, session).await["made"], false);
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
    let paired = paired_of(companion).await;
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
    assert_eq!(kept(companion, gone).await["made"], true);
    drafts.sweep_after_reach(paired).await;
    assert_eq!(kept(companion, gone).await["made"], false);
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
    assert_eq!(kept(companion, session).await["revision"], "4");
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
    let paired = paired_of(companion).await;
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
    assert_eq!(kept(companion, session).await["revision"], "4");
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
    assert_eq!(kept(companion, session).await["made"], false);
    adopted.stop().await;
}

// ---- the fix round: what a read of the first build found ------------------------------------------

/// KR-REQ-13.12: the connection state the page reads says that a host this device is paired with
/// under a grant that answers to no organisation is not one that does, so the page leaves the
/// device's uploads and drafts alone when the account changes.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_13_12_a_connection_to_a_host_with_no_organisation_says_so_to_the_page() {
    let adopted = Adopted::start(1).await;
    let (phone, _control) = phone_for(&adopted).await;
    connected(&phone.companion).await;
    let state = phone
        .companion
        .call("connection_state", json!({}))
        .expect("the connection's state");
    assert_eq!(state["paired"], true, "{state}");
    assert_eq!(state["organisation"], false, "{state}");
    adopted.stop().await;
}

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
        let (desk, paired) = (Arc::clone(&desk), paired_of(companion).await);
        tokio::spawn(async move { desk.send(paired, sent).await })
    };
    gate.reached().await;

    let refused = desk
        .send(
            paired_of(companion).await,
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
    let mut sending = Vec::new();
    for (content, _, _) in &held {
        let sent = request(&adopted, &bytes, Arc::clone(content), kr_ipc::new_uuid());
        let (desk, paired) = (Arc::clone(&desk), paired_of(companion).await);
        sending.push(tokio::spawn(async move { desk.send(paired, sent).await }));
    }
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
    let paired = paired_of(companion).await;
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
        tokio::spawn(async move { desk.cancel(paired.who(), Some(paired), key).await })
    };
    tokio::time::sleep(Duration::from_millis(300)).await;
    gate.release();
    let answer = cancelling
        .await
        .expect("the task ran")
        .expect("the cancel is answered");
    assert_eq!(
        answer.state, "asked",
        "the host cannot be asked, so the cancel is kept"
    );

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
    let paired = paired_of(companion).await;
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
    desk.restart(paired_of(&phone.companion).await).await;
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
            paired_of(&phone.companion).await,
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
    let paired = paired_of(&phone.companion).await;
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
    let paired = paired_of(companion).await;
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
        let paired = paired_of(companion).await;
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
    // The removal waits for the sender it stopped; it is over before the folder is read.
    desk_of(companion).idle().await;

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
    let reread = kept(companion, session).await;
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
    let old = paired_of(companion).await.session;
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
        kept(companion, session).await["attachments"]
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
    let binding = |handle: &Value, paired: Paired| {
        let bind = companion_tauri::paired_drafts::Bind {
            session_id: session,
            application_instance_id: None,
            text: "see the file".to_owned(),
            transfer_id: serde_json::from_value(handle["transfer_id"].clone()).expect("an id"),
            contribution: serde_json::from_value(contribution()).expect("a contribution"),
        };
        let drafts = Arc::clone(&drafts);
        let target = net_support::on_the_session(&adopted.host, session);
        tokio::spawn(async move { drafts.bind(paired, target, bind).await })
    };
    let (first, second) = (
        binding(&one, paired_of(companion).await),
        binding(&two, paired_of(companion).await),
    );
    let first = first.await.expect("ran").expect("one bind");
    let second = second.await.expect("ran").expect("the other bind");
    assert_eq!(first.draft_id, second.draft_id);
    let reread = kept(companion, session).await;
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
    let paired = paired_of(companion).await;
    let drafts = companion
        .app
        .state::<companion_tauri::AppState>()
        .paired_drafts();

    drafts.sweep(paired.clone(), &[]).await;
    assert_eq!(kept(companion, session).await["made"], false);
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
    let paired = paired_of(companion).await;
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
    let paired = paired_of(companion).await;
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
    assert_eq!(kept(companion, session).await["made"], false);
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
    let paired = paired_of(companion).await;
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
    assert_eq!(kept(companion, session).await["made"], false);
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
        kept(companion, session).await["revision"],
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
        let (drafts, paired) = (Arc::clone(&drafts), paired_of(companion).await);
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
    let shown = kept(companion, session).await;
    assert_eq!(shown["made"], true, "{shown}");
    assert!(shown["revision"].is_null(), "{shown}");

    // The stopped process may or may not have moved the host's draft: the entry does not guess.
    control.release_request();
    let next = bind(companion, session, &second).expect("the next bind makes a new draft");
    assert_ne!(
        next["value"]["draftId"], first["value"]["draftId"],
        "a draft of an unknown revision is ended and not added to: {next}"
    );
    let reread = kept(companion, session).await;
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
    let paired = paired_of(companion).await;
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
    let shown = kept(companion, session).await;
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
    let stays = kept(companion, sessions[0]).await;
    assert_eq!(stays["made"], true, "the draft stays: {stays}");
    assert_eq!(stays["draftId"], unknown.to_string());

    // A prompt the host applied for the kept draft ends what is kept of it.
    let used = made_draft(&bind(companion, sessions[1], &handed(companion)).expect("a bind"));
    prompt_for(1, used).expect("the prompt is applied");
    assert_eq!(taken[0].prompts().len(), 1, "the agent has the prompt");
    assert_eq!(
        kept(companion, sessions[1]).await["made"],
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
            &paired_of(companion).await,
            sessions[2],
            &net_support::on_the_session(&adopted.host, sessions[2]),
            Some(later),
            Some(kr_protocol::ids::DraftRevision::new(1)),
        );
    prompt_for(2, named).expect("the prompt is applied");
    assert_eq!(taken[1].prompts().len(), 1);
    let entry = kept(companion, sessions[2]).await;
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
    let paired = paired_of(companion).await;
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
    let connection = paired_of(companion).await.session;
    assert_eq!(draft_actions_in_the_book(&connection).await, 0, "creation");
    end();
    assert_eq!(draft_actions_in_the_book(&connection).await, 0, "discard");

    // A creation whose answer was lost, answered from the host's record on the next connection.
    let paired = paired_of(companion).await;
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
    let paired = paired_of(companion).await;
    let session = adopted.workers[0].session_id;
    let earlier = Paired {
        device_id: kr_protocol::ids::DeviceId::new(kr_ipc::new_uuid()),
        ..paired.clone()
    };

    // An upload that is still sent as the earlier principal, held in its content. The stop of a
    // sender waits for the sender to end, and a read of the content cannot be interrupted, so the
    // content is let go once the desk has asked the sender to stop, and not before.
    let bytes = pattern(5);
    let (content, gate, _release) = gated(&bytes);
    let upload_key = kr_ipc::new_uuid();
    let stop_asked = testing::hold_at(upload_key, testing::Point::CancelWaiting);
    let running = {
        let sent = request(&adopted, &bytes, content, upload_key);
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
    until(
        "the desk asks the sender of the earlier principal to stop",
        || stop_asked.passed() >= 1,
    )
    .await;
    gate.release();

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
    adopted.stop().await;
}

/// What an account left on a paired host: a published upload, an entry of an upload the host never
/// answered, a draft, and an upload still held by the desk and paused. All of it is the account's.
struct Left {
    handle: kr_protocol::transfer::AttachmentHandle,
    sending:
        tokio::task::JoinHandle<companion_tauri::Result<kr_protocol::transfer::AttachmentHandle>>,
    live_key: Uuid,
    entry_key: Uuid,
    /// The connection that replaced the one the account's upload was sent on.
    newer: Paired,
}

/// Leaves the work of `earlier` on the host and then replaces the connection, so that an account that
/// signed in since finds it on a connection of its own.
async fn left_by(adopted: &Adopted, phone: &Phone, desk: &Arc<Desk>, earlier: &Paired) -> Left {
    let companion = &phone.companion;
    let session = adopted.workers[0].session_id;
    // A published upload whose entry is kept until it is bound.
    let published = pattern(3);
    let handle = desk
        .send(
            earlier.clone(),
            request(
                adopted,
                &published,
                Arc::new(Held::new(published.clone())),
                kr_ipc::new_uuid(),
            ),
        )
        .await
        .expect("the upload is published");
    // An entry for an upload the host never answered, with its copy.
    let left = vec![9_u8; 16];
    let entry_key = kr_ipc::new_uuid();
    testing::keep(
        &folder(phone),
        entry_key,
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
    testing::keep_copy(&folder(phone), entry_key, &left);
    // A draft.
    companion
        .app
        .state::<companion_tauri::AppState>()
        .paired_drafts()
        .keep_for_test(
            earlier,
            session,
            &net_support::on_the_session(&adopted.host, session),
            Some(kr_protocol::ids::DraftId::new(kr_ipc::new_uuid())),
            Some(kr_protocol::ids::DraftRevision::new(1)),
        );
    // An upload still sent when its connection ends and another comes up: it is paused, because the
    // connection that came up is not its account's.
    let bytes = pattern(5);
    let (content, gate, _release) = gated(&bytes);
    let live_key = kr_ipc::new_uuid();
    let sending = {
        let sent = request(adopted, &bytes, content, live_key);
        let (desk, earlier) = (Arc::clone(desk), earlier.clone());
        tokio::spawn(async move { desk.send(earlier, sent).await })
    };
    gate.reached().await;
    earlier.session.transport().close();
    let newer = on_another_connection(companion, &earlier.session).await;
    until("the desk is told of the new connection", || {
        desk.holds_newest_for_test(&newer)
    })
    .await;
    gate.release();
    until("the upload is paused", || {
        desk.open(&earlier.who())
            .iter()
            .any(|view| view.state == companion_tauri::open_transfers::OpenState::Paused)
    })
    .await;
    Left {
        handle,
        sending,
        live_key,
        entry_key,
        newer,
    }
}

/// KR-REQ-13.12, KR-REQ-23.41: what one account left on a paired host is neither shown to nor acted
/// on for another account. The host sees one principal whoever is signed in, so the application tells
/// the accounts apart, and every desk and drafts operation acts on the account of the connection it
/// is given: the other account's uploads, copies and drafts stay on disk, hidden, and no call is made
/// to the host for them.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_13_12_another_accounts_entries_are_neither_shown_nor_acted_on() {
    use kr_client::services::AccountMark;
    use kr_protocol::method::Method;

    let adopted = Adopted::start(1).await;
    let (phone, control) = phone_for(&adopted).await;
    let companion = &phone.companion;
    let desk = desk_of(companion);
    let paired = paired_of(companion).await;
    let session = adopted.workers[0].session_id;
    let earlier = Paired {
        account: Some(AccountMark::from_bytes([1; 32])),
        ..paired.clone()
    };
    let left = left_by(&adopted, &phone, &desk, &earlier).await;
    let now = Paired {
        account: Some(AccountMark::from_bytes([2; 32])),
        ..left.newer.clone()
    };
    let drafts = companion
        .app
        .state::<companion_tauri::AppState>()
        .paired_drafts();
    let held = |when: &str| {
        let (entries, copies, kept) = (
            entries_in(&folder(&phone)),
            copies_in(&folder(&phone)),
            drafts_in(&folder(&phone)),
        );
        assert_eq!(
            (entries, copies, kept),
            (3, 2, 1),
            "{when}: the published entry, the hidden entry and the paused upload's entry, their two copies and the draft are all kept"
        );
    };
    held("before");
    let reads = control.sent(Method::UploadStatus);
    let begins = control.sent(Method::UploadBegin);

    // Nothing of the earlier account is shown to the new one, nor to a sign-in with no account.
    assert!(desk.open(&now.who()).is_empty(), "no upload is shown");
    assert!(
        desk.open(&left.newer.who()).is_empty(),
        "an organisation host with no account signed in shows nothing"
    );
    assert!(
        !drafts.kept(&now, session).expect("the draft is read").made,
        "no draft is read"
    );
    // A cancel finds no upload and records no key, for a held upload and for a kept entry.
    for key in [left.live_key, left.entry_key] {
        let refused = desk
            .cancel(now.who(), Some(now.clone()), key)
            .await
            .expect_err("no upload of the new account has that key");
        assert_eq!(
            refused.message,
            companion_tauri::open_transfers::NO_OPEN_UPLOAD
        );
        assert!(!desk.is_cancelled(key), "the key is not recorded");
    }
    // The host is reached under the new account, and the entries are read again.
    desk.host_reached(now.clone());
    desk.idle().await;
    desk.restart(now.clone()).await;
    drafts.sweep_after_reach(now.clone()).await;
    // The upload's handle is bound to a draft by the new account: the earlier account's entry stays.
    desk.bound(&now.who(), left.handle.transfer_id).await;
    held("after");
    assert_eq!(
        control.sent(Method::UploadStatus),
        reads,
        "nothing of the earlier account is read from the host"
    );
    assert_eq!(control.sent(Method::UploadBegin), begins);
    assert!(
        !left.sending.is_finished(),
        "the paused upload was not ended"
    );
    assert!(
        drafts
            .kept(&earlier, session)
            .expect("the draft is read")
            .made,
        "the earlier account's draft is still its own"
    );
    adopted.stop().await;
}

/// KR-REQ-13.12, KR-REQ-23.41: an account that signs in again finds what it left: the upload that was
/// paused goes on and is published, and the draft is read again.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_13_12_an_account_sees_its_own_entries_and_drafts_again_when_it_signs_in_again() {
    use kr_client::services::AccountMark;

    let adopted = Adopted::start(1).await;
    let (phone, _control) = phone_for(&adopted).await;
    let companion = &phone.companion;
    let desk = desk_of(companion);
    let paired = paired_of(companion).await;
    let session = adopted.workers[0].session_id;
    let earlier = Paired {
        account: Some(AccountMark::from_bytes([1; 32])),
        ..paired.clone()
    };
    let left = left_by(&adopted, &phone, &desk, &earlier).await;
    let now = Paired {
        account: Some(AccountMark::from_bytes([2; 32])),
        ..left.newer.clone()
    };
    let drafts = companion
        .app
        .state::<companion_tauri::AppState>()
        .paired_drafts();
    // The other account reaches the host: nothing of the earlier account moves.
    desk.host_reached(now.clone());
    drafts.sweep_after_reach(now.clone()).await;
    desk.idle().await;
    assert!(!left.sending.is_finished());

    // The earlier account reaches the host again: its upload goes on and is published, and its
    // draft is read again.
    let again = Paired {
        account: earlier.account,
        ..left.newer.clone()
    };
    desk.host_reached(again.clone());
    let handle = tokio::time::timeout(WATCHDOG, left.sending)
        .await
        .expect("the upload goes on when its account reaches the host")
        .expect("the task ran")
        .expect("the upload is published");
    assert_eq!(handle.byte_len.get(), pattern(5).len() as u64);
    assert!(
        drafts
            .kept(&again, session)
            .expect("the draft is read")
            .made,
        "the draft is read again"
    );
    assert!(
        desk.open(&again.who())
            .iter()
            .any(|view| view.handle.is_some()),
        "the published upload is shown again"
    );
    adopted.stop().await;
}

/// KR-REQ-13.12: an upload whose connection ended while another account's connection came up goes on
/// for no connection but its own account's: the sender that sees the end settles as paused, and the
/// connection that came up first is not used for it.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_13_12_a_send_is_not_resumed_on_a_connection_of_another_account() {
    use kr_client::services::AccountMark;

    let adopted = Adopted::start(1).await;
    let (phone, control) = phone_for(&adopted).await;
    let companion = &phone.companion;
    let desk = desk_of(companion);
    let paired = paired_of(companion).await;
    let earlier = Paired {
        account: Some(AccountMark::from_bytes([1; 32])),
        ..paired.clone()
    };
    let bytes = pattern(5);
    let (content, gate, _release) = gated(&bytes);
    let sending = {
        let sent = request(&adopted, &bytes, content, kr_ipc::new_uuid());
        let (desk, earlier) = (Arc::clone(&desk), earlier.clone());
        tokio::spawn(async move { desk.send(earlier, sent).await })
    };
    gate.reached().await;
    // The connection ends, and the phone makes another that is not the account's, while the content
    // still holds the driver.
    earlier.session.transport().close();
    let newer = on_another_connection(companion, &earlier.session).await;
    until("the desk is told of the new connection", || {
        desk.holds_newest_for_test(&newer)
    })
    .await;
    let chunks = control.sent(kr_protocol::method::Method::UploadChunk);
    gate.release();
    until("the upload is paused", || {
        desk.open(&earlier.who())
            .iter()
            .any(|view| view.state == companion_tauri::open_transfers::OpenState::Paused)
    })
    .await;
    desk.idle().await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        !sending.is_finished(),
        "the upload was not sent on the other account's connection"
    );
    assert_eq!(
        control.sent(kr_protocol::method::Method::UploadChunk),
        chunks,
        "the host was sent no more of the upload"
    );

    // Its own account's connection takes it up.
    desk.host_reached(Paired {
        account: earlier.account,
        ..newer
    });
    tokio::time::timeout(WATCHDOG, sending)
        .await
        .expect("the upload goes on under its own account")
        .expect("the task ran")
        .expect("the upload is published");
    adopted.stop().await;
}

/// Two uploads of `earlier` hold the device's two places on the host and are paused, and the phone
/// has made a connection that is not theirs. Answers that connection.
async fn two_places_held_by(
    adopted: &Adopted,
    phone: &Phone,
    desk: &Arc<Desk>,
    earlier: &Paired,
) -> Paired {
    let bytes = pattern(5);
    let mut gates = Vec::new();
    for _ in 0..2 {
        let (content, gate, release) = gated(&bytes);
        let sent = request(adopted, &bytes, content, kr_ipc::new_uuid());
        let (desk, earlier) = (Arc::clone(desk), earlier.clone());
        tokio::spawn(async move { desk.send(earlier, sent).await });
        gates.push((gate, release));
    }
    for (gate, _) in &gates {
        gate.reached().await;
    }
    earlier.session.transport().close();
    let newer = on_another_connection(&phone.companion, &earlier.session).await;
    until("the desk is told of the new connection", || {
        desk.holds_newest_for_test(&newer)
    })
    .await;
    for (gate, _) in &gates {
        gate.release();
    }
    until("both uploads are paused", || {
        desk.open(&earlier.who())
            .iter()
            .filter(|view| view.state == companion_tauri::open_transfers::OpenState::Paused)
            .count()
            == 2
    })
    .await;
    newer
}

/// KR-REQ-13.12: the host counts a device's open transfers for every account of the device, so an
/// account cannot see or free the places another left. A begin the host refuses for that count frees
/// the other account's places, each read and cancelled once on the connection in force, and is tried
/// once more; two sends refused together free each place once and both go on.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_13_12_a_begin_refused_for_the_devices_count_frees_the_other_accounts_places_and_goes_on()
 {
    use kr_client::services::AccountMark;
    use kr_protocol::method::Method;

    for together in [false, true] {
        let adopted = Adopted::start(1).await;
        let (phone, control) = phone_for(&adopted).await;
        let desk = desk_of(&phone.companion);
        let paired = paired_of(&phone.companion).await;
        let earlier = Paired {
            account: Some(AccountMark::from_bytes([1; 32])),
            ..paired.clone()
        };
        let newer = two_places_held_by(&adopted, &phone, &desk, &earlier).await;
        let now = Paired {
            account: Some(AccountMark::from_bytes([2; 32])),
            ..newer
        };
        let (reads, cancels, begins) = (
            control.sent(Method::UploadStatus),
            control.sent(Method::UploadCancel),
            control.sent(Method::UploadBegin),
        );
        let bytes = pattern(3);
        let send = |desk: &Arc<Desk>| {
            let desk = Arc::clone(desk);
            let now = now.clone();
            let sent = request(
                &adopted,
                &bytes,
                Arc::new(Held::new(bytes.clone())),
                kr_ipc::new_uuid(),
            );
            async move { desk.send(now, sent).await }
        };
        let sent = if together {
            let (first, second) = tokio::join!(send(&desk), send(&desk));
            vec![first, second]
        } else {
            vec![send(&desk).await]
        };
        for outcome in sent {
            outcome.expect(
                "the begin is tried again once the places are freed, and the upload is published",
            );
        }
        assert_eq!(
            control.sent(Method::UploadCancel) - cancels,
            2,
            "each place is cancelled once ({together})"
        );
        assert_eq!(
            control.sent(Method::UploadStatus) - reads,
            2,
            "each is read before it is cancelled ({together})"
        );
        assert!(
            control.sent(Method::UploadBegin) - begins >= 2,
            "the begin was refused, then tried again ({together})"
        );
        assert!(
            desk.open(&earlier.who()).is_empty(),
            "the earlier account's uploads are gone ({together})"
        );
        assert_eq!(
            entries_in(&folder(&phone)),
            if together { 2 } else { 1 },
            "what is kept is the published uploads of the new account ({together})"
        );
        assert_eq!(copies_in(&folder(&phone)), 0);
        adopted.stop().await;
    }
}

/// The request that makes a draft on the host for `session`, composed and not sent.
async fn compose_create(
    adopted: &Adopted,
    paired: &Paired,
    session: kr_protocol::ids::SessionId,
    text: &str,
) -> kr_client::session::ComposedMutation {
    use kr_protocol::ids::ActionId;
    use kr_protocol::method::Method;
    use kr_protocol::transfer::DraftCreateParams;

    paired
        .session
        .compose(
            Method::DraftCreate,
            ActionId::new(kr_ipc::new_uuid()),
            net_support::on_the_session(&adopted.host, session),
            None,
            &json!({}),
            &DraftCreateParams {
                environment_id: adopted.host.environment_id,
                device_id: Nullable::null(),
                session_id: Nullable::some(session),
                application_instance_id: Nullable::null(),
                text: text.to_owned(),
            },
            kr_protocol::scalars::DurationMs::new(60_000),
        )
        .await
        .expect("composed")
}

/// A draft the host holds for this device, which no entry of this application names.
async fn host_draft(
    adopted: &Adopted,
    paired: &Paired,
    session: kr_protocol::ids::SessionId,
) -> kr_protocol::ids::DraftId {
    use kr_protocol::transfer::DraftCreateResult;

    let composed = compose_create(adopted, paired, session, "a draft the host holds").await;
    let made: DraftCreateResult = paired
        .session
        .send(&composed)
        .await
        .expect("the host made the draft")
        .to_typed()
        .expect("a result");
    made.draft.draft_id
}

/// KR-REQ-23.41: the host counts a device's open drafts for every account of the device. A creation
/// the host refuses for that count discards the other account's known drafts, each by its own
/// account's entry and in its own turn, and is tried once more; the new account's own entry is not
/// touched.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_23_41_a_draft_creation_refused_for_the_devices_count_discards_the_other_accounts_drafts_and_goes_on()
 {
    use kr_client::services::AccountMark;
    use kr_protocol::method::Method;

    let adopted = Adopted::start(3).await;
    let (phone, control) = phone_for(&adopted).await;
    let companion = &phone.companion;
    let desk = desk_of(companion);
    let drafts = companion
        .app
        .state::<companion_tauri::AppState>()
        .paired_drafts();
    let paired = paired_of(companion).await;
    let earlier = Paired {
        account: Some(AccountMark::from_bytes([1; 32])),
        ..paired.clone()
    };
    let now = Paired {
        account: Some(AccountMark::from_bytes([2; 32])),
        ..paired.clone()
    };
    let sessions: Vec<_> = adopted
        .workers
        .iter()
        .map(|worker| worker.session_id)
        .collect();
    // The earlier account keeps a draft for each session, and the device holds the host's whole bound
    // of 64 open drafts.
    for session in &sessions {
        let id = host_draft(&adopted, &paired, *session).await;
        drafts.keep_for_test(
            &earlier,
            *session,
            &net_support::on_the_session(&adopted.host, *session),
            Some(id),
            Some(kr_protocol::ids::DraftRevision::new(1)),
        );
    }
    for _ in sessions.len()..64 {
        host_draft(&adopted, &paired, sessions[0]).await;
    }
    // A file of the new account is published, and its bind asks the host for a draft.
    let bytes = vec![7_u8; 1000];
    let handle = desk
        .send(
            now.clone(),
            request(
                &adopted,
                &bytes,
                Arc::new(Held::new(bytes.clone())),
                kr_ipc::new_uuid(),
            ),
        )
        .await
        .expect("the upload is published");
    let creates = control.sent(Method::DraftCreate);
    let bind: companion_tauri::paired_drafts::Bind = serde_json::from_value(json!({
        "session_id": sessions[0].to_string(),
        "text": "see the file",
        "transfer_id": handle.transfer_id,
        "contribution": contribution(),
    }))
    .expect("a bind");
    drafts
        .bind(
            now.clone(),
            net_support::on_the_session(&adopted.host, sessions[0]),
            bind,
        )
        .await
        .expect("the creation is tried again once the places are freed, and the file is bound");
    assert_eq!(
        control.sent(Method::DraftCreate) - creates,
        2,
        "refused once, then tried again"
    );
    assert_eq!(
        control.sent(Method::DraftDiscard),
        3,
        "the earlier account's three drafts"
    );
    for session in &sessions {
        assert!(
            !drafts
                .kept(&earlier, *session)
                .expect("the draft is read")
                .made,
            "the earlier account's entry went with the host's answer"
        );
    }
    assert!(
        drafts
            .kept(&now, sessions[0])
            .expect("the draft is read")
            .made,
        "the new account's draft is its own"
    );
    assert_eq!(
        drafts_in(&folder(&phone)),
        1,
        "only the new account's entry is kept"
    );
    adopted.stop().await;
}

/// The earlier account keeps a known draft for each of `sessions`, and the device holds the host's
/// whole bound of 64 open drafts.
async fn fill_the_hosts_drafts(
    adopted: &Adopted,
    drafts: &companion_tauri::paired_drafts::Drafts,
    paired: &Paired,
    earlier: &Paired,
    sessions: &[kr_protocol::ids::SessionId],
) {
    for session in sessions {
        let id = host_draft(adopted, paired, *session).await;
        drafts.keep_for_test(
            earlier,
            *session,
            &net_support::on_the_session(&adopted.host, *session),
            Some(id),
            Some(kr_protocol::ids::DraftRevision::new(1)),
        );
    }
    for _ in sessions.len()..64 {
        host_draft(adopted, paired, sessions[0]).await;
    }
}

/// KR-REQ-23.41: the freeing of another account's drafts reads each entry again in its own turn. A
/// draft its account bound again since the entries were collected, whose creation has no answer yet,
/// is left, and so is one its account has ended; only the draft that is still there as it was
/// collected is discarded, and the creation that was refused is tried again with the place freed.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_23_41_a_draft_bound_again_after_the_cleanup_collected_it_is_left_alone() {
    use kr_client::services::AccountMark;
    use kr_protocol::method::Method;

    let adopted = Adopted::start(3).await;
    let (phone, control) = phone_for(&adopted).await;
    let companion = &phone.companion;
    let desk = desk_of(companion);
    let drafts = companion
        .app
        .state::<companion_tauri::AppState>()
        .paired_drafts();
    let paired = paired_of(companion).await;
    let earlier = Paired {
        account: Some(AccountMark::from_bytes([1; 32])),
        ..paired.clone()
    };
    let now = Paired {
        account: Some(AccountMark::from_bytes([2; 32])),
        ..paired.clone()
    };
    let sessions: Vec<_> = adopted
        .workers
        .iter()
        .map(|worker| worker.session_id)
        .collect();
    let target = |index: usize| net_support::on_the_session(&adopted.host, sessions[index]);
    fill_the_hosts_drafts(&adopted, &drafts, &paired, &earlier, &sessions).await;
    let bytes = vec![7_u8; 1000];
    let handle = desk
        .send(
            now.clone(),
            request(
                &adopted,
                &bytes,
                Arc::new(Held::new(bytes.clone())),
                kr_ipc::new_uuid(),
            ),
        )
        .await
        .expect("the upload is published");
    let creates = control.sent(Method::DraftCreate);
    let discards = control.sent(Method::DraftDiscard);
    let collected = drafts.hold_after_collecting_for_test();
    let binding = {
        let bind: companion_tauri::paired_drafts::Bind = serde_json::from_value(json!({
            "session_id": sessions[0].to_string(),
            "text": "see the file",
            "transfer_id": handle.transfer_id,
            "contribution": contribution(),
        }))
        .expect("a bind");
        let (drafts, now, target) = (Arc::clone(&drafts), now.clone(), target(0));
        tokio::spawn(async move { drafts.bind(now, target, bind).await })
    };
    until("the freeing has collected the entries", || {
        collected.passed() >= 1
    })
    .await;

    // Since then the earlier account bound its second session's draft again, and the creation has
    // no answer, and it ended its third session's draft.
    let composed = compose_create(&adopted, &earlier, sessions[1], "bound again").await;
    drafts.keep_create_for_test(&earlier, sessions[1], &target(1), &composed);
    drafts
        .end(earlier.clone(), target(2), sessions[2])
        .await
        .expect("the earlier account ends its draft");
    collected.release();
    let bound = binding.await.expect("the task ran");

    assert!(
        bound.is_ok(),
        "the creation is tried again with the place freed: {bound:?}"
    );
    assert_eq!(
        control.sent(Method::DraftCreate) - creates,
        2,
        "refused once, then tried again"
    );
    assert_eq!(
        control.sent(Method::DraftDiscard) - discards,
        2,
        "the earlier account's own end, and the one draft the freeing found as it was collected"
    );
    assert_eq!(
        drafts_in(&folder(&phone)),
        2,
        "the new account's entry and the earlier account's draft whose creation has no answer"
    );
    assert!(
        !drafts
            .kept(&earlier, sessions[0])
            .expect("the draft is read")
            .made,
        "the draft still there as it was collected is gone"
    );
    adopted.stop().await;
}

/// KR-REQ-23.41: a freeing that finds no draft left as it was collected frees no place, so the
/// creation that was refused is not tried again: the one draft the earlier account kept was bound
/// again meanwhile and its creation has no answer, and the host's refusal stands.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_23_41_a_cleanup_that_finds_no_draft_left_as_collected_frees_no_place_and_asks_no_more()
 {
    use kr_client::services::AccountMark;
    use kr_protocol::method::Method;

    let adopted = Adopted::start(1).await;
    let (phone, control) = phone_for(&adopted).await;
    let companion = &phone.companion;
    let desk = desk_of(companion);
    let drafts = companion
        .app
        .state::<companion_tauri::AppState>()
        .paired_drafts();
    let paired = paired_of(companion).await;
    let earlier = Paired {
        account: Some(AccountMark::from_bytes([1; 32])),
        ..paired.clone()
    };
    let now = Paired {
        account: Some(AccountMark::from_bytes([2; 32])),
        ..paired.clone()
    };
    let session = adopted.workers[0].session_id;
    let target = net_support::on_the_session(&adopted.host, session);
    fill_the_hosts_drafts(&adopted, &drafts, &paired, &earlier, &[session]).await;
    let bytes = vec![7_u8; 1000];
    let handle = desk
        .send(
            now.clone(),
            request(
                &adopted,
                &bytes,
                Arc::new(Held::new(bytes.clone())),
                kr_ipc::new_uuid(),
            ),
        )
        .await
        .expect("the upload is published");
    let creates = control.sent(Method::DraftCreate);
    let discards = control.sent(Method::DraftDiscard);
    let collected = drafts.hold_after_collecting_for_test();
    let binding = {
        let bind: companion_tauri::paired_drafts::Bind = serde_json::from_value(json!({
            "session_id": session.to_string(),
            "text": "see the file",
            "transfer_id": handle.transfer_id,
            "contribution": contribution(),
        }))
        .expect("a bind");
        let (drafts, now, target) = (Arc::clone(&drafts), now.clone(), target.clone());
        tokio::spawn(async move { drafts.bind(now, target, bind).await })
    };
    until("the freeing has collected the entry", || {
        collected.passed() >= 1
    })
    .await;
    let composed = compose_create(&adopted, &earlier, session, "bound again").await;
    drafts.keep_create_for_test(&earlier, session, &target, &composed);
    collected.release();
    let bound = binding.await.expect("the task ran");

    assert!(
        bound.is_err(),
        "the host's refusal stands, no place was freed: {bound:?}"
    );
    assert_eq!(
        control.sent(Method::DraftCreate) - creates,
        1,
        "the creation was asked for once"
    );
    assert_eq!(
        control.sent(Method::DraftDiscard) - discards,
        0,
        "nothing was discarded"
    );
    assert_eq!(
        drafts_in(&folder(&phone)),
        2,
        "the earlier account's draft whose creation has no answer is left, beside the new account's entry"
    );
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
    let paired = paired_of(companion).await;
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
    // One connection for the send and for the cancel: a second look at a connection that is being
    // taken up again is no part of what the case asks.
    let paired = paired_of(companion).await;
    let sending = {
        let sent = request(&adopted, &bytes, Arc::new(Held::new(bytes.clone())), key);
        let (desk, paired) = (Arc::clone(&desk), paired.clone());
        tokio::spawn(async move { desk.send(paired, sent).await })
    };
    tokio::time::timeout(WATCHDOG, async {
        while copies_in(&folder(&phone)) == 0 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the copy is written");
    desk.cancel(paired.who(), Some(paired), key)
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
    // Nothing starts late either: what the desk started for itself is over before the host and the
    // folder are read again.
    desk.idle().await;
    assert_eq!(
        control.sent(Method::UploadBegin),
        0,
        "nothing reaches the host late"
    );
    assert_eq!(copies_in(&folder(&phone)), 0, "no copy is written late");
    assert_eq!(entries_in(&folder(&phone)), 0, "no entry is written late");
    adopted.stop().await;
}

/// A connection that is being taken up again is waited for: the helper that names the paired host
/// finds none held while the dials are held, counts that look, and returns the new connection once
/// contact is back.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn paired_of_waits_for_a_connection_that_is_being_taken_up_again() {
    let adopted = Adopted::start(1).await;
    let (phone, control) = phone_for(&adopted).await;
    let companion = &phone.companion;
    let old = paired_of(companion).await.session;
    // The host cannot be reached again while the dials are held.
    control.hold();
    old.transport().close();
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

    let missed = AtomicUsize::new(0);
    // Contact returns only after the helper has looked once and found no connection.
    let returning = async {
        while missed.load(Ordering::SeqCst) == 0 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        control.stop_holding();
        control.release_all();
    };
    let (found, ()) = tokio::time::timeout(WATCHDOG, async {
        tokio::join!(
            paired_within(companion, CONNECTION_WAIT, &missed),
            returning
        )
    })
    .await
    .expect("the helper ends");
    let paired = found.expect("the helper waits for the connection that is taken up again");
    assert!(
        missed.load(Ordering::SeqCst) >= 1,
        "the helper looked while no connection was held"
    );
    assert!(
        !Arc::ptr_eq(&paired.session, &old),
        "the connection it returns is the new one"
    );
    adopted.stop().await;
}

/// The transfers the host holds open, as the requests this phone made say: reservations asked for,
/// less the ones cancelled or finished.
fn host_open(control: &LinkControl) -> usize {
    use kr_protocol::method::Method;

    control
        .sent(Method::UploadBegin)
        .saturating_sub(control.sent(Method::UploadCancel) + control.sent(Method::UploadFinish))
}

/// Waits, for at most the watchdog, until `done` holds.
async fn until(what: &str, mut done: impl FnMut() -> bool) {
    tokio::time::timeout(WATCHDOG, async {
        while !done() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{what}"));
}

/// KR-REQ-13.12: a cancel that comes before the key is registered, while the bytes still go to the
/// application, is recorded: the send that follows is refused, and nothing is copied or asked of the
/// host.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_13_12_a_cancel_before_the_key_is_registered_refuses_the_send_and_nothing_begins() {
    use kr_protocol::method::Method;

    let adopted = Adopted::start(1).await;
    let (phone, control) = phone_for(&adopted).await;
    let companion = &phone.companion;
    let desk = desk_of(companion);
    let gate = desk.hold_before_admission_for_test();
    let bytes = pattern(5);
    let key = kr_ipc::new_uuid();
    let paired = paired_of(companion).await;
    let sending = {
        let sent = request(&adopted, &bytes, Arc::new(Held::new(bytes.clone())), key);
        let (desk, paired) = (Arc::clone(&desk), paired.clone());
        tokio::spawn(async move { desk.send(paired, sent).await })
    };
    let answer = desk
        .cancel(paired.who(), Some(paired), key)
        .await
        .expect("a cancel of a key nothing holds is answered");
    assert_eq!(answer.state, "forgotten");
    gate.add_permits(1);

    let told = tokio::time::timeout(WATCHDOG, sending)
        .await
        .expect("the send ends")
        .expect("the task ran")
        .expect_err("a key the person cancelled is refused");
    assert_eq!(told.message, companion_tauri::open_transfers::CANCELLED);
    desk.idle().await;
    assert_eq!(control.sent(Method::UploadBegin), 0, "nothing was begun");
    assert_eq!(entries_in(&folder(&phone)), 0, "no entry");
    assert_eq!(copies_in(&folder(&phone)), 0, "no copy");
    adopted.stop().await;
}

/// KR-REQ-13.12: a cancel that comes while the sender is being started, inside the one section that
/// checks and starts it, waits for that section and then finds the sender: it stops the sender
/// before the sender asks the host for anything, so the host is never asked and holds nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_13_12_a_cancel_that_comes_while_the_sender_starts_leaves_the_host_holding_nothing()
{
    use kr_protocol::method::Method;
    use testing::Point;

    let adopted = Adopted::start(1).await;
    let (phone, control) = phone_for(&adopted).await;
    let companion = &phone.companion;
    let desk = desk_of(companion);
    let bytes = pattern(5);
    let (content, gate, _release) = gated(&bytes);
    let key = kr_ipc::new_uuid();
    let started = testing::hold_at(key, Point::Started);
    let first_line = testing::hold_at(key, Point::SenderStarting);
    let began = testing::hold_at(key, Point::CancelBegun);
    let waiting = testing::hold_at(key, Point::CancelWaiting);
    let paired = paired_of(companion).await;
    let sending = {
        let sent = request(&adopted, &bytes, content, key);
        let (desk, paired) = (Arc::clone(&desk), paired.clone());
        tokio::spawn(async move { desk.send(paired, sent).await })
    };
    // The send is inside the section that starts the sender, and the sender is at its first line.
    started.until_passed(1).await;
    first_line.until_passed(1).await;
    let cancelling = {
        let desk = Arc::clone(&desk);
        tokio::spawn(async move { desk.cancel(paired.who(), Some(paired), key).await })
    };
    began.until_passed(1).await;
    started.release();
    // The cancel finds the sender and waits for it, or, without the cure, is over already.
    until("the cancel waits for the sender or ends", || {
        waiting.passed() >= 1 || cancelling.is_finished()
    })
    .await;
    first_line.release();
    gate.release();
    let answer = cancelling
        .await
        .expect("the task ran")
        .expect("the cancel is answered");

    let told = tokio::time::timeout(WATCHDOG, sending)
        .await
        .expect("the send ends")
        .expect("the task ran")
        .expect_err("the upload the person cancelled ends cancelled");
    assert_eq!(told.message, companion_tauri::open_transfers::CANCELLED);
    desk.idle().await;
    // A sender that was not stopped goes on at once when released; give it the time it needs.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert!(
        !gate.reached.load(Ordering::Acquire),
        "the sender went on to read the file"
    );
    assert_eq!(
        control.sent(Method::UploadBegin),
        0,
        "the sender was stopped before it asked the host for anything"
    );
    assert_eq!(
        answer.state, "forgotten",
        "the host holds nothing to cancel"
    );
    assert_eq!(host_open(&control), 0, "the host holds nothing");
    assert_eq!(entries_in(&folder(&phone)), 0, "no entry");
    assert_eq!(copies_in(&folder(&phone)), 0, "no copy");
    adopted.stop().await;
}

/// KR-REQ-13.12: the sender's handle is stored in the section that starts it, so a cancel that waits
/// for that section finds the handle and waits for the sender.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_13_12_a_handle_is_stored_before_the_cancel_can_take_it() {
    use testing::Point;

    let adopted = Adopted::start(1).await;
    let (phone, _control) = phone_for(&adopted).await;
    let companion = &phone.companion;
    let desk = desk_of(companion);
    let bytes = pattern(5);
    let (content, gate, _release) = gated(&bytes);
    let key = kr_ipc::new_uuid();
    let started = testing::hold_at(key, Point::Started);
    let began = testing::hold_at(key, Point::CancelBegun);
    let waiting = testing::hold_at(key, Point::CancelWaiting);
    let paired = paired_of(companion).await;
    let sending = {
        let sent = request(&adopted, &bytes, content, key);
        let (desk, paired) = (Arc::clone(&desk), paired.clone());
        tokio::spawn(async move { desk.send(paired, sent).await })
    };
    started.until_passed(1).await;
    let cancelling = {
        let desk = Arc::clone(&desk);
        tokio::spawn(async move { desk.cancel(paired.who(), Some(paired), key).await })
    };
    began.until_passed(1).await;
    started.release();
    // The cancel took the handle of the sender that the section started, and waits for it.
    until("the cancel finds the sender or ends", || {
        waiting.passed() >= 1 || cancelling.is_finished()
    })
    .await;
    assert_eq!(
        waiting.passed(),
        1,
        "the cancel found the handle the section stored"
    );
    gate.release();
    cancelling
        .await
        .expect("the task ran")
        .expect("the cancel is answered");
    let _ = tokio::time::timeout(WATCHDOG, sending)
        .await
        .expect("the send ends");
    desk.idle().await;
    adopted.stop().await;
}

/// KR-REQ-13.12: cancels and sends that start together never leave work behind. A probe: the end
/// state of each round is read once both have ended and the desk's tasks are over.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_13_12_a_cancel_and_a_send_started_together_never_leave_work_behind() {
    let adopted = Adopted::start(1).await;
    let (phone, control) = phone_for(&adopted).await;
    let companion = &phone.companion;
    let desk = desk_of(companion);
    let bytes = pattern(5);
    let paired = paired_of(companion).await;
    let mut forgotten_cancels = 0;
    for round in 0..200_usize {
        let key = kr_ipc::new_uuid();
        let sending = {
            let sent = request(&adopted, &bytes, Arc::new(Held::new(bytes.clone())), key);
            let (desk, paired) = (Arc::clone(&desk), paired.clone());
            tokio::spawn(async move { desk.send(paired, sent).await })
        };
        for _ in 0..round % 7 {
            tokio::task::yield_now().await;
        }
        let answer = desk
            .cancel(paired.who(), Some(paired.clone()), key)
            .await
            .expect("the cancel is answered");
        let told = tokio::time::timeout(WATCHDOG, sending)
            .await
            .expect("the send ends")
            .expect("the task ran");
        desk.idle().await;
        let entry = folder(&phone).join(format!("{key}.upload"));
        let copy = folder(&phone).join(format!("{key}.bytes"));
        match told {
            Ok(_) => {
                assert_eq!(answer.state, "published", "round {round}");
                assert!(
                    !copy.exists(),
                    "round {round}: a published upload keeps no copy"
                );
                // Published entries end when bound; this probe leaves none behind.
                let _ = std::fs::remove_file(&entry);
            }
            Err(error) => {
                assert_eq!(
                    error.message,
                    companion_tauri::open_transfers::CANCELLED,
                    "round {round}"
                );
                assert!(!entry.exists(), "round {round}: no entry is left");
                assert!(!copy.exists(), "round {round}: no copy is left");
                if answer.state == "forgotten" {
                    forgotten_cancels += 1;
                }
            }
        }
    }
    // A cancel that came before the host's answer to the reservation names no transfer, and the host
    // may hold what it could not be told to cancel; every other cancelled round holds nothing.
    assert!(
        host_open(&control) <= forgotten_cancels,
        "the host holds {} open, {forgotten_cancels} cancels named no transfer",
        host_open(&control)
    );
    adopted.stop().await;
}

/// KR-REQ-13.12: a restart that is reading an entry's content when the person cancels it does not
/// start the upload: the cancel is finished against the host, and no sender is ever started.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_13_12_a_restart_does_not_start_an_upload_cancelled_while_its_content_is_read() {
    use kr_protocol::method::Method;
    use testing::Point;

    let adopted = Adopted::start(1).await;
    let (phone, control) = phone_for(&adopted).await;
    let companion = &phone.companion;
    let desk = desk_of(companion);
    let bytes = pattern(5);
    let reading = Arc::new(std::sync::Mutex::new(None));
    let started = Arc::new(std::sync::Mutex::new(None));
    let key = left_by_a_first_process(
        &adopted,
        &phone,
        &control,
        &bytes,
        Keeping::Copy(bytes.clone()),
        |key| {
            // The restart that the reach makes is held once it has read the content.
            *reading.lock().expect("the slot") = Some(testing::hold_at(key, Point::Reading));
            let counting = testing::hold_at(key, Point::Started);
            counting.release();
            *started.lock().expect("the slot") = Some(counting);
        },
    )
    .await;
    let reading = reading.lock().expect("the slot").clone().expect("armed");
    let started = started.lock().expect("the slot").clone().expect("armed");
    reading.until_passed(1).await;

    let cancelling = {
        let (desk, paired) = (Arc::clone(&desk), paired_of(companion).await);
        tokio::spawn(async move { desk.cancel(paired.who(), Some(paired), key).await })
    };
    until("the key is recorded as cancelled", || {
        desk.is_cancelled(key)
    })
    .await;
    reading.release();
    let answer = cancelling
        .await
        .expect("the task ran")
        .expect("the cancel is answered");
    assert_eq!(answer.state, "cancelled");
    desk.idle().await;
    assert_eq!(started.passed(), 0, "no sender was started for the key");
    assert_eq!(
        control.sent(Method::UploadCancel),
        1,
        "the host was asked once"
    );
    assert_eq!(host_open(&control), 0, "the host holds nothing");
    assert_eq!(entries_in(&folder(&phone)), 0, "no entry is rewritten");
    adopted.stop().await;
}

/// KR-REQ-13.12: a cancel waits for a sender that is inside a blocking write of its journal; the
/// sender's write is not the last, and the entry is gone when the cancel answers.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_13_12_a_cancel_waits_for_a_sender_that_is_inside_a_blocking_write() {
    use testing::{Point, Step};

    let adopted = Adopted::start(1).await;
    let (phone, control) = phone_for(&adopted).await;
    let companion = &phone.companion;
    let desk = desk_of(companion);
    let bytes = pattern(5);
    let key = kr_ipc::new_uuid();
    let writing = testing::hold_at(key, Point::Writing(Step::Begun));
    let waiting = testing::hold_at(key, Point::CancelWaiting);
    let paired = paired_of(companion).await;
    let sending = {
        let sent = request(&adopted, &bytes, Arc::new(Held::new(bytes.clone())), key);
        let (desk, paired) = (Arc::clone(&desk), paired.clone());
        tokio::spawn(async move { desk.send(paired, sent).await })
    };
    // The host gave its identifier, and the sender is inside the write that keeps it.
    writing.until_passed(1).await;
    let cancelling = {
        let desk = Arc::clone(&desk);
        tokio::spawn(async move { desk.cancel(paired.who(), Some(paired), key).await })
    };
    // The cancel is in its step 2, waiting for the sender; it is not ready while the sender is held.
    waiting.until_passed(1).await;
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(
            !cancelling.is_finished(),
            "the cancel answered while the sender was inside a write"
        );
    }
    writing.release();
    let answer = cancelling
        .await
        .expect("the task ran")
        .expect("the cancel is answered");
    assert_eq!(answer.state, "cancelled");
    let told = tokio::time::timeout(WATCHDOG, sending)
        .await
        .expect("the send ends")
        .expect("the task ran")
        .expect_err("cancelled");
    assert_eq!(told.message, companion_tauri::open_transfers::CANCELLED);
    desk.idle().await;
    assert_eq!(
        entries_in(&folder(&phone)),
        0,
        "the sender's write was not the last"
    );
    assert_eq!(host_open(&control), 0, "the host holds nothing");
    adopted.stop().await;
}

/// KR-REQ-13.12: two callers that start the same paused upload together, each from a list it read
/// while the upload was paused, start one sender.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_13_12_two_starts_of_one_upload_run_one_task() {
    use testing::Point;

    let adopted = Adopted::start(1).await;
    let (phone, control) = phone_for(&adopted).await;
    let companion = &phone.companion;
    let desk = desk_of(companion);
    let bytes = pattern(5);
    let (content, gate, _release) = gated(&bytes);
    let key = kr_ipc::new_uuid();
    // Every start of the upload is counted: the hold is let go at once.
    let started = testing::hold_at(key, Point::Started);
    started.release();
    let claiming = testing::hold_at(key, Point::Claiming);
    let first = paired_of(companion).await;
    let session = Arc::clone(&first.session);
    let who = first.who();
    let sending = {
        let sent = request(&adopted, &bytes, content, key);
        let desk = Arc::clone(&desk);
        tokio::spawn(async move { desk.send(first, sent).await })
    };
    gate.reached().await;
    control.hold();
    session.transport().close();
    gate.release();
    until("the upload is paused", || {
        desk.open(&who)
            .iter()
            .any(|view| view.state == companion_tauri::open_transfers::OpenState::Paused)
    })
    .await;
    // The connection comes back: the application's own reach claims the upload, and a second reach
    // from the same list does too. Both are held at the claim, and let go together.
    control.stop_holding();
    control.release_all();
    let again = on_another_connection(companion, &session).await;
    let second = {
        let desk = Arc::clone(&desk);
        tokio::task::spawn_blocking(move || desk.host_reached(again))
    };
    claiming.until_passed(2).await;
    claiming.release();
    second.await.expect("the second reach ran");
    let handle = tokio::time::timeout(WATCHDOG, sending)
        .await
        .expect("the upload ends")
        .expect("the task ran")
        .expect("the upload is published");
    assert_eq!(handle.byte_len.get(), bytes.len() as u64);
    desk.idle().await;
    assert_eq!(
        started.passed(),
        2,
        "the send started one sender and the two claims started one more"
    );
    adopted.stop().await;
}

/// KR-REQ-13.12: a second cancel waits for the first and finds the key gone: the host is asked once,
/// and no entry is written after the removal.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_13_12_a_second_cancel_waits_for_the_first_and_does_not_rewrite_the_entry() {
    use kr_protocol::method::Method;
    use testing::{Point, Step};

    let adopted = Adopted::start(1).await;
    let (phone, control) = phone_for(&adopted).await;
    let companion = &phone.companion;
    let desk = desk_of(companion);
    let bytes = pattern(5);
    let key = kr_ipc::new_uuid();
    let writing = testing::hold_at(key, Point::Writing(Step::Begun));
    let began = testing::hold_at(key, Point::CancelBegun);
    let waiting = testing::hold_at(key, Point::CancelWaiting);
    let paired = paired_of(companion).await;
    let sending = {
        let sent = request(&adopted, &bytes, Arc::new(Held::new(bytes.clone())), key);
        let (desk, paired) = (Arc::clone(&desk), paired.clone());
        tokio::spawn(async move { desk.send(paired, sent).await })
    };
    // The host gave its identifier, and the sender is inside the write that keeps it.
    writing.until_passed(1).await;
    let first = {
        let (desk, paired) = (Arc::clone(&desk), paired.clone());
        tokio::spawn(async move { desk.cancel(paired.who(), Some(paired), key).await })
    };
    waiting.until_passed(1).await;
    let second = {
        let desk = Arc::clone(&desk);
        tokio::spawn(async move { desk.cancel(paired.who(), Some(paired), key).await })
    };
    began.until_passed(2).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    writing.release();
    let first = first
        .await
        .expect("the task ran")
        .expect("the first cancel is answered");
    let second = second
        .await
        .expect("the task ran")
        .expect("the second cancel is answered");
    assert_eq!(first.state, "cancelled");
    assert_eq!(
        second.state, "forgotten",
        "the key was gone when its turn came"
    );
    let _ = tokio::time::timeout(WATCHDOG, sending)
        .await
        .expect("the send ends");
    desk.idle().await;
    assert_eq!(
        control.sent(Method::UploadCancel),
        1,
        "the host was asked once"
    );
    assert_eq!(entries_in(&folder(&phone)), 0, "no entry is rewritten");
    assert_eq!(copies_in(&folder(&phone)), 0, "no copy");
    adopted.stop().await;
}

/// KR-REQ-13.12: a reach that comes between the stop of a paused upload and the removal of its entry
/// starts no sender, and no entry is written after the removal.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_13_12_a_reach_between_a_stop_and_a_removal_starts_no_sender() {
    use testing::Point;

    let adopted = Adopted::start(1).await;
    let (phone, control) = phone_for(&adopted).await;
    let companion = &phone.companion;
    let desk = desk_of(companion);
    let bytes = pattern(5);
    let (content, gate, _release) = gated(&bytes);
    let key = kr_ipc::new_uuid();
    // Every start of the upload is counted: the hold is let go at once.
    let started = testing::hold_at(key, Point::Started);
    started.release();
    let stopped = testing::hold_at(key, Point::Stopped);
    let first = paired_of(companion).await;
    let (session, who, device_id) = (Arc::clone(&first.session), first.who(), first.device_id);
    let sending = {
        let sent = request(&adopted, &bytes, content, key);
        let desk = Arc::clone(&desk);
        tokio::spawn(async move { desk.send(first, sent).await })
    };
    gate.reached().await;
    control.hold();
    session.transport().close();
    gate.release();
    until("the upload is paused", || {
        desk.open(&who)
            .iter()
            .any(|view| view.state == companion_tauri::open_transfers::OpenState::Paused)
    })
    .await;

    // The host is forgotten: the upload is stopped, and its removal is held.
    desk.forgotten(device_id);
    stopped.until_passed(1).await;
    // The connection comes back and the host is reached, twice, before the removal.
    control.stop_holding();
    control.release_all();
    let again = on_another_connection(companion, &session).await;
    desk.host_reached(again);
    stopped.release();
    let told = tokio::time::timeout(WATCHDOG, sending)
        .await
        .expect("the send ends")
        .expect("the task ran")
        .expect_err("the upload of a forgotten host ends cancelled");
    assert_eq!(told.message, companion_tauri::open_transfers::CANCELLED);
    desk.idle().await;
    assert_eq!(started.passed(), 1, "no sender was started after the stop");
    assert_eq!(
        entries_in(&folder(&phone)),
        0,
        "no entry is written after the removal"
    );
    assert_eq!(copies_in(&folder(&phone)), 0, "no copy is left");
    adopted.stop().await;
}

/// Makes a folder unwritable for as long as it lives.
struct Unwritable(PathBuf);

impl Unwritable {
    fn new(folder: &Path) -> Self {
        use std::os::unix::fs::PermissionsExt as _;

        std::fs::set_permissions(folder, std::fs::Permissions::from_mode(0o555))
            .expect("the folder is read only");
        Self(folder.to_path_buf())
    }
}

impl Drop for Unwritable {
    fn drop(&mut self) {
        use std::os::unix::fs::PermissionsExt as _;

        let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o755));
    }
}

/// KR-REQ-13.12: a cancel pressed while the host is out of reach is kept, read as cancel asked, and
/// finished at the reach: the host is told once, no chunk or finish goes after it, and nothing is left.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_13_12_a_cancel_with_the_host_out_of_reach_is_kept_and_finished_at_the_reach() {
    use kr_protocol::method::Method;

    let adopted = Adopted::start(1).await;
    let (phone, control) = phone_for(&adopted).await;
    let companion = &phone.companion;
    let desk = desk_of(companion);
    let bytes = pattern(5);
    let (content, gate, _release) = gated(&bytes);
    let key = kr_ipc::new_uuid();
    let paired = paired_of(companion).await;
    let session = Arc::clone(&paired.session);
    let sending = {
        let sent = request(&adopted, &bytes, content, key);
        let desk = Arc::clone(&desk);
        tokio::spawn(async move { desk.send(paired, sent).await })
    };
    gate.reached().await;
    control.hold();
    session.transport().close();
    gate.release();
    until("the upload is paused", || {
        try_open(companion).is_ok_and(|views| views.iter().any(|view| view["state"] == "paused"))
    })
    .await;

    let answered = companion
        .call("upload_cancel", json!({ "transferKey": key.to_string() }))
        .expect("the cancel is answered with no connection");
    assert_eq!(answered["state"], "asked");
    let listed = open(companion);
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0]["state"], "cancelAsked");

    control.stop_holding();
    control.release_all();
    let told = tokio::time::timeout(WATCHDOG, sending)
        .await
        .expect("the send ends once the host is reached")
        .expect("the task ran")
        .expect_err("cancelled");
    assert_eq!(told.message, companion_tauri::open_transfers::CANCELLED);
    desk.idle().await;
    assert_eq!(
        control.sent(Method::UploadCancel),
        1,
        "the host is told once"
    );
    assert_eq!(
        control.sent(Method::UploadFinish),
        0,
        "nothing is finished after it"
    );
    assert_eq!(host_open(&control), 0, "the host holds nothing");
    assert_eq!(entries_in(&folder(&phone)), 0);
    assert_eq!(copies_in(&folder(&phone)), 0);
    adopted.stop().await;
}

/// KR-REQ-13.12: a reach that comes while a cancel waits for a sender that has not noticed its
/// connection end does not leave the cancel waiting for the next reach: the command looks for a
/// connection again and finishes the cancel.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_13_12_a_reach_during_a_cancel_finishes_it_at_once() {
    use kr_protocol::method::Method;
    use testing::{Point, Step};

    let adopted = Adopted::start(1).await;
    let (phone, control) = phone_for(&adopted).await;
    let companion = &phone.companion;
    let desk = desk_of(companion);
    let bytes = pattern(5);
    let key = kr_ipc::new_uuid();
    // The sender is held inside the write that keeps the host's identifier: it is still sending.
    let writing = testing::hold_at(key, Point::Writing(Step::Begun));
    let waiting = testing::hold_at(key, Point::CancelWaiting);
    let paired = paired_of(companion).await;
    let session = Arc::clone(&paired.session);
    let sending = {
        let sent = request(&adopted, &bytes, Arc::new(Held::new(bytes.clone())), key);
        let desk = Arc::clone(&desk);
        tokio::spawn(async move { desk.send(paired, sent).await })
    };
    writing.until_passed(1).await;
    control.hold();
    session.transport().close();
    until("the connection ends", || {
        companion
            .call("connection_state", json!({}))
            .is_ok_and(|state| state["connected"] != true)
    })
    .await;
    // Once the cancel waits for the sender, contact returns and the host is reached; only then is
    // the sender let go.
    let returning = {
        let (control, desk, app) = (
            Arc::clone(&control),
            Arc::clone(&desk),
            companion.app.handle().clone(),
        );
        let old = Arc::clone(&session);
        tokio::spawn(async move {
            waiting.until_passed(1).await;
            control.stop_holding();
            control.release_all();
            until("the desk is told the host was reached", || {
                app.state::<companion_tauri::AppState>()
                    .paired_snapshot()
                    .is_ok_and(|(device_id, environment_id, session)| {
                        !Arc::ptr_eq(&session, &old)
                            && desk.holds_newest_for_test(&Paired {
                                device_id,
                                environment_id,
                                account: None,
                                session,
                            })
                    })
            })
            .await;
            writing.release();
        })
    };
    // The command finds no connection the first time, and the second time finds the new one.
    let answered = companion
        .call("upload_cancel", json!({ "transferKey": key.to_string() }))
        .expect("the cancel is answered");
    returning.await.expect("the task ran");
    assert_eq!(
        answered["state"], "cancelled",
        "the second look finished it"
    );
    let told = tokio::time::timeout(WATCHDOG, sending)
        .await
        .expect("the send ends")
        .expect("the task ran")
        .expect_err("cancelled");
    assert_eq!(told.message, companion_tauri::open_transfers::CANCELLED);
    desk.idle().await;
    assert_eq!(
        control.sent(Method::UploadCancel),
        1,
        "the host is told once"
    );
    assert_eq!(host_open(&control), 0);
    assert_eq!(entries_in(&folder(&phone)), 0);
    adopted.stop().await;
}

/// An upload that a first process began and left paused, with its entry in the folder, and the dials
/// held so that no reach has happened yet.
async fn left_paused(
    adopted: &Adopted,
    phone: &Phone,
    control: &LinkControl,
    bytes: &[u8],
) -> (Uuid, Arc<Desk>, Who) {
    let companion = &phone.companion;
    let first = Arc::new(Desk::default());
    first.keep_at(folder(phone));
    let (content, gate, release) = gated(bytes);
    let key = kr_ipc::new_uuid();
    let sent = request(adopted, bytes, content, key);
    let paired = paired_of(companion).await;
    let (session, who) = (Arc::clone(&paired.session), paired.who());
    let first_process = {
        let first = Arc::clone(&first);
        tokio::spawn(async move { first.send(paired, sent).await })
    };
    gate.reached().await;
    control.hold();
    session.transport().close();
    gate.release();
    drop(release);
    until("the first process pauses the upload", || {
        first
            .open(&who)
            .iter()
            .any(|view| view.state == companion_tauri::open_transfers::OpenState::Paused)
    })
    .await;
    first_process.abort();
    (key, first, who)
}

/// KR-REQ-13.12: an unfinished cancel that an earlier process recorded is read as cancel asked by the
/// application that starts next, and its first reach tells the host and removes the entry.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_13_12_a_restart_finishes_an_asked_cancel_and_shows_it_as_asked() {
    use kr_protocol::method::Method;

    let adopted = Adopted::start(1).await;
    let (phone, control) = phone_for(&adopted).await;
    let companion = &phone.companion;
    let bytes = pattern(5);
    let (key, first, who) = left_paused(&adopted, &phone, &control, &bytes).await;
    let asked = first
        .cancel(who.clone(), None, key)
        .await
        .expect("the earlier process records the cancel");
    assert_eq!(asked.state, "asked");

    let desk = desk_of(companion);
    let read = desk.open(&who);
    assert_eq!(read.len(), 1);
    assert_eq!(
        read[0].state,
        companion_tauri::open_transfers::OpenState::CancelAsked
    );

    control.stop_holding();
    control.release_all();
    open_where(companion, <[Value]>::is_empty).await;
    desk.idle().await;
    assert_eq!(
        control.sent(Method::UploadCancel),
        1,
        "the host is told once"
    );
    assert_eq!(host_open(&control), 0);
    assert_eq!(entries_in(&folder(&phone)), 0);
    adopted.stop().await;
}

/// KR-REQ-13.12: a restored upload whose cancel could not be recorded is still read as cancelled, and
/// the next reach finishes the cancel and never resumes the upload.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_13_12_a_restored_upload_whose_cancel_record_failed_is_finished_at_the_reach() {
    use kr_protocol::method::Method;

    let adopted = Adopted::start(1).await;
    let (phone, control) = phone_for(&adopted).await;
    let companion = &phone.companion;
    let bytes = pattern(5);
    let (key, _first, who) = left_paused(&adopted, &phone, &control, &bytes).await;
    let desk = desk_of(companion);
    let answer = {
        let _unwritable = Unwritable::new(&folder(&phone));
        desk.cancel(who.clone(), None, key).await
    }
    .expect("the cancel is answered");
    assert_eq!(answer.state, "asked");
    assert!(answer.said.is_some(), "the failed record is said");
    let read = desk.open(&who);
    assert_eq!(
        read[0].state,
        companion_tauri::open_transfers::OpenState::CancelAsked,
        "read as cancelled, not as waiting"
    );

    control.stop_holding();
    control.release_all();
    open_where(companion, <[Value]>::is_empty).await;
    desk.idle().await;
    assert_eq!(
        control.sent(Method::UploadCancel),
        1,
        "the host is told once"
    );
    assert_eq!(host_open(&control), 0, "the upload is not resumed");
    assert_eq!(entries_in(&folder(&phone)), 0);
    adopted.stop().await;
}
