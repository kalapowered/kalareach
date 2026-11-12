//! A paired device's upload, driven by the client library against a real host.
//!
//! The device is a `Session` over an authorised connection, and the upload goes through
//! `ChunkRoute::network` and `uploads::send`: the client asks the host which streams it takes, reserves
//! the upload, sends every chunk on a data stream of its own, finishes it and reads that it is
//! published. The host is the daemon's own, so what the cases show is what a client sees of the
//! host's arms and not what a script says they do.

mod net_support;

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use kr_client::chunks::ChunkRoute;
use kr_client::session::{Session, Settled};
use kr_client::transport::{ControlTransport, Reach, StreamOpener, TransportFuture};
use kr_client::uploads::{self, Held, Progress, Stage, Subject, Upload};
use kr_controller::service::net::config::NetworkSettings;
use kr_controller::service::net::devices::DeviceRecord;
use kr_crypto::keys::DeviceKeys;
use kr_protocol::envelope::ControlFrame;
use kr_protocol::error::ProtocolError;
use kr_protocol::frame::StreamHeader;
use kr_protocol::hello::{ActionWindow, ReceiveLimits};
use kr_protocol::ids::{ActionId, ConnectionId, SessionId, TransferId};
use kr_protocol::limits::UPLOAD_CHUNK_LEN;
use kr_protocol::method::{Method, MethodName};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{Bytes, Digest256, DurationMs, Nullable, U64};
use kr_protocol::transfer::{
    ChunkDescriptor, ChunkLayout, UploadBeginParams, UploadBeginResult, UploadCancelParams,
    UploadCancelResult, UploadChunkParams, UploadFinishParams, UploadFinishResult, UploadState,
    UploadStatusParams, UploadStatusResult,
};
use kr_transport::deadlines::ManualDeadlines;
use kr_transport::streams::DataStream;
use net_support::worker::Adopted;
use net_support::{Device, Host, on_the_host, on_the_session};

/// What a case waits at most for the host: it ends a case that would hang and measures nothing.
const WAIT: Duration = Duration::from_secs(120);

const TTL: DurationMs = DurationMs::new(60_000);

async fn within<T>(future: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(WAIT, future)
        .await
        .expect("the call ended in time")
}

fn pattern(len: usize) -> Vec<u8> {
    (0..len)
        .map(|index| u8::try_from((index * 17 + 3) % 251).unwrap_or(0))
        .collect()
}

fn digest(bytes: &[u8]) -> Digest256 {
    Digest256::from_bytes(kr_cbor::sha256(bytes))
}

/// What the client is asked to upload: `bytes` under `name`, for the host or for one of its sessions.
fn plan(host: &Host, session_id: Option<SessionId>, name: &str, bytes: &[u8]) -> Upload {
    Upload::new(
        Subject {
            environment_id: host.environment_id,
            session_id,
            device_id: None,
            declared_media_type: "application/octet-stream".to_owned(),
            original_file_name: name.to_owned(),
        },
        Box::new(Held::new(bytes.to_vec())),
    )
}

/// A device paired under `rights`, and its record.
async fn paired(host: &Host, owner: &DeviceKeys, rights: &[ActionRight]) -> (Device, DeviceRecord) {
    let device = Device::create().await;
    let record = net_support::pair_with(host, &device, owner, net_support::proposal(rights)).await;
    (device, record)
}

/// A connection of the device's, as a session that counts the data streams it opens.
async fn counted_session(
    host: &Host,
    device: &Device,
    record: &DeviceRecord,
) -> (Session, Arc<AtomicU64>) {
    let (session, opened, _finished, _status_reads) = counting_session(host, device, record).await;
    (session, opened)
}

/// A connection of the device's, as a session that counts the data streams it opens, the
/// `upload.finish` mutations it sends and the `upload.status` reads it sends.
async fn counting_session(
    host: &Host,
    device: &Device,
    record: &DeviceRecord,
) -> (Session, Arc<AtomicU64>, Arc<AtomicU64>, StatusReads) {
    let opened = Arc::new(AtomicU64::new(0));
    let finished = Arc::new(AtomicU64::new(0));
    let status_reads = StatusReads::default();
    let transport = net_support::paired_dial(host, device, record).dial().await;
    let session = Session::start(Arc::new(Counted {
        inner: Arc::new(transport),
        opened: Arc::clone(&opened),
        finished: Arc::clone(&finished),
        status_reads: status_reads.clone(),
    }))
    .expect("a session");
    (session, opened, finished, status_reads)
}

/// Each `upload.status` read a session sent, as the number of finishes it had sent before it.
type StatusReads = Arc<std::sync::Mutex<Vec<u64>>>;

fn staged(host: &Host) -> u64 {
    host.controller()
        .transfer()
        .service()
        .staged_byte_len()
        .expect("the staged bytes")
}

async fn status_of(session: &Session, transfer_id: TransferId) -> UploadStatusResult {
    session
        .read(Method::UploadStatus, &UploadStatusParams { transfer_id })
        .await
        .expect("the host reads the upload's status")
}

/// A transport that counts the data streams opened through it, each once its header is written,
/// the `upload.finish` mutations sent through it, and each `upload.status` read with the number of
/// finishes sent before it.
#[derive(Debug)]
struct Counted {
    inner: Arc<dyn ControlTransport>,
    opened: Arc<AtomicU64>,
    finished: Arc<AtomicU64>,
    status_reads: StatusReads,
}

#[derive(Debug)]
struct CountingOpener {
    inner: Arc<dyn StreamOpener>,
    opened: Arc<AtomicU64>,
}

impl StreamOpener for CountingOpener {
    fn open(&self, header: StreamHeader) -> TransportFuture<'_, DataStream> {
        Box::pin(async move {
            let stream = self.inner.open(header).await?;
            self.opened.fetch_add(1, Ordering::AcqRel);
            Ok(stream)
        })
    }

    fn revoked(&self) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
        self.inner.revoked()
    }
}

impl ControlTransport for Counted {
    fn connection_id(&self) -> ConnectionId {
        self.inner.connection_id()
    }
    fn limits(&self) -> ReceiveLimits {
        self.inner.limits()
    }
    fn initial_action_window(&self) -> ActionWindow {
        self.inner.initial_action_window()
    }
    fn reach(&self) -> Option<Reach> {
        self.inner.reach()
    }
    fn ended_by_this_device(&self) -> Option<ProtocolError> {
        self.inner.ended_by_this_device()
    }
    fn send<'a>(&'a self, frame: &'a ControlFrame) -> TransportFuture<'a, ()> {
        match frame {
            ControlFrame::Mutation(mutation)
                if mutation.method == MethodName::from(Method::UploadFinish) =>
            {
                self.finished.fetch_add(1, Ordering::AcqRel);
            }
            ControlFrame::Request(request)
                if request.method == MethodName::from(Method::UploadStatus) =>
            {
                self.status_reads
                    .lock()
                    .expect("the status reads")
                    .push(self.finished.load(Ordering::Acquire));
            }
            _ => {}
        }
        self.inner.send(frame)
    }
    fn claim_receiver(&self) -> kr_client::Result<()> {
        self.inner.claim_receiver()
    }
    fn stream_opener(&self) -> Option<Arc<dyn StreamOpener>> {
        Some(Arc::new(CountingOpener {
            inner: self.inner.stream_opener()?,
            opened: Arc::clone(&self.opened),
        }))
    }
    fn recv(&self) -> TransportFuture<'_, Option<ControlFrame>> {
        self.inner.recv()
    }
    fn revoke_streams(&self) {
        self.inner.revoke_streams();
    }
    fn close(&self) {
        self.inner.close();
    }
}

/// KR-REQ-23.21 and KR-REQ-14.12: a paired device sends two full chunks and a short one through
/// `ChunkRoute::network`, finishes the upload and is told it is published. The chunks went on data
/// streams, because the host takes none on the control stream, and the bytes the host staged are the
/// file's.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_paired_device_sends_two_full_chunks_and_a_short_one_and_the_host_publishes_the_file() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let (device, record) = paired(&host, &owner, &[ActionRight::FilesUpload]).await;
    let (session, opened) = counted_session(&host, &device, &record).await;
    let route = ChunkRoute::network(&session, host.environment_id)
        .await
        .expect("the host takes an attachment stream from a device");
    let bytes = pattern(2 * UPLOAD_CHUNK_LEN + 5_000);
    let mut upload = plan(&host, None, "three.bin", &bytes);
    let (progress, watching) = tokio::sync::watch::channel(Progress::default());

    let handle = within(uploads::send(
        &session,
        &route,
        &on_the_host(&host),
        &mut upload,
        TTL,
        &progress,
    ))
    .await
    .expect("the upload is published");

    assert_eq!(handle.byte_len.get(), bytes.len() as u64);
    assert_eq!(handle.content_digest, digest(&bytes));
    let told = *watching.borrow();
    assert_eq!(told.stage, Stage::Published);
    assert_eq!((told.acknowledged_chunks, told.chunks), (3, 3));
    assert_eq!(
        opened.load(Ordering::Acquire),
        1,
        "one stream carried the transfer"
    );
    let transfer = *upload.transfer_id().expect("the plan holds the transfer");
    assert_eq!(
        status_of(&session, transfer).await.state,
        UploadState::Published
    );
    assert_eq!(
        staged(&host),
        bytes.len() as u64,
        "the host staged the file"
    );
    session.close();
    host.stop().await;
}

/// KR-REQ-23.21: a stream that ends after the first chunk is replaced by a new one for the same
/// transfer, which the host takes: two streams carry the upload, the host stages the file once and the
/// upload is published. Which chunks the new stream carries is the scripted host's case.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stream_that_ends_after_the_first_chunk_is_replaced_and_the_host_publishes_the_file() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let (device, record) = paired(&host, &owner, &[ActionRight::FilesUpload]).await;
    let (session, opened) = counted_session(&host, &device, &record).await;
    let route = ChunkRoute::network(&session, host.environment_id)
        .await
        .expect("the host takes an attachment stream from a device")
        .resetting_first_lane_after(1);
    let bytes = pattern(2 * UPLOAD_CHUNK_LEN + 5_000);
    let mut upload = plan(&host, None, "reset.bin", &bytes);
    let (progress, watching) = tokio::sync::watch::channel(Progress::default());

    let handle = within(uploads::send(
        &session,
        &route,
        &on_the_host(&host),
        &mut upload,
        TTL,
        &progress,
    ))
    .await
    .expect("the upload is published");

    assert_eq!(handle.content_digest, digest(&bytes));
    assert_eq!(watching.borrow().stage, Stage::Published);
    assert_eq!(
        opened.load(Ordering::Acquire),
        2,
        "the stream that ended and the one that replaced it"
    );
    assert_eq!(staged(&host), bytes.len() as u64);
    session.close();
    host.stop().await;
}

/// KR-REQ-14.12: a client that lost the answer to its last request, and so does not know the upload
/// is published, builds the plan again on a replacement connection. It reads the host's status, is
/// given the handle and opens no stream: nothing is sent twice.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_upload_resumed_on_a_replacement_connection_after_its_publication_sends_nothing() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let (device, record) = paired(&host, &owner, &[ActionRight::FilesUpload]).await;
    let bytes = pattern(UPLOAD_CHUNK_LEN + 100);

    let first = net_support::connect(&host, &device, &record).await;
    let first_route = ChunkRoute::network(&first, host.environment_id)
        .await
        .expect("the host takes an attachment stream from a device");
    let mut upload = plan(&host, None, "kept.bin", &bytes);
    let (progress, _) = tokio::sync::watch::channel(Progress::default());
    let published = within(uploads::send(
        &first,
        &first_route,
        &on_the_host(&host),
        &mut upload,
        TTL,
        &progress,
    ))
    .await
    .expect("the upload is published");
    let transfer = *upload.transfer_id().expect("the plan holds the transfer");
    first.close();

    let (second, opened) = counted_session(&host, &device, &record).await;
    let second_route = ChunkRoute::network(&second, host.environment_id)
        .await
        .expect("the host takes an attachment stream from a device");
    let mut again = Upload::resuming(
        Subject {
            environment_id: host.environment_id,
            session_id: None,
            device_id: None,
            declared_media_type: "application/octet-stream".to_owned(),
            original_file_name: "kept.bin".to_owned(),
        },
        Box::new(Held::new(bytes.clone())),
        transfer,
    );
    let (progress, watching) = tokio::sync::watch::channel(Progress::default());
    let handle = within(uploads::send(
        &second,
        &second_route,
        &on_the_host(&host),
        &mut again,
        TTL,
        &progress,
    ))
    .await
    .expect("the status says it is published");

    assert_eq!(handle, published);
    assert_eq!(watching.borrow().stage, Stage::Published);
    assert_eq!(opened.load(Ordering::Acquire), 0, "no stream was opened");
    assert_eq!(staged(&host), bytes.len() as u64, "one file");
    second.close();
    host.stop().await;
}

/// The one chunk of a file of at most one chunk, as the lane sends it.
fn only_chunk(transfer_id: TransferId, bytes: &[u8]) -> UploadChunkParams {
    let layout = ChunkLayout::for_length(bytes.len() as u64);
    assert_eq!(layout.chunk_count.get(), 1, "a file of one chunk");
    UploadChunkParams {
        transfer_id,
        chunk: ChunkDescriptor {
            index: U64::new(0),
            byte_len: U64::new(bytes.len() as u64),
            digest: digest(bytes),
        },
        bytes: Bytes::new(bytes.to_vec()),
    }
}

/// KR-REQ-14.12: a client that lost the answer to a finish or a cancel asks again with exactly the
/// request it composed, on a replacement connection, and is answered from the host's record: the same
/// result, and the host acted once. The control is the connection that composed the request, which
/// is refused the repeat before anything is asked.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_finish_and_a_cancel_asked_again_on_a_replacement_connection_are_answered_from_the_record()
 {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let (device, record) = paired(&host, &owner, &[ActionRight::FilesUpload]).await;
    let bytes = pattern(4096);
    let target = on_the_host(&host);

    let first = net_support::connect(&host, &device, &record).await;
    let route = ChunkRoute::network(&first, host.environment_id)
        .await
        .expect("the host takes an attachment stream from a device");
    let reserve = |name: &str| UploadBeginParams {
        environment_id: host.environment_id,
        session_id: Nullable::null(),
        device_id: Nullable::null(),
        declared_byte_len: U64::new(bytes.len() as u64),
        declared_digest: digest(&bytes),
        declared_media_type: "application/octet-stream".to_owned(),
        original_file_name: name.to_owned(),
    };
    let mut begun = Vec::new();
    for name in ["finished.bin", "cancelled.bin"] {
        let settled = first
            .mutate(
                Method::UploadBegin,
                target.clone(),
                None,
                &serde_json::json!({}),
                &reserve(name),
                TTL,
            )
            .await
            .expect("the host reserves the upload");
        let Settled::Result(value) = settled else {
            panic!("the reservation is answered with its result");
        };
        let result: UploadBeginResult = value.to_typed().expect("a reservation");
        begun.push(result.transfer_id);
    }
    let (finished, cancelled) = (begun[0], begun[1]);
    let mut lane = within(route.open(finished)).await.expect("a lane");
    within(lane.send_chunk(&target, &only_chunk(finished, &bytes), TTL))
        .await
        .expect("the chunk is staged");
    drop(lane);

    let finish = first
        .compose(
            Method::UploadFinish,
            ActionId::new(kr_ipc::new_uuid()),
            target.clone(),
            None,
            &serde_json::json!({}),
            &UploadFinishParams {
                transfer_id: finished,
                declared_byte_len: U64::new(bytes.len() as u64),
                declared_digest: digest(&bytes),
            },
            TTL,
        )
        .await
        .expect("the finish is composed");
    let cancel = first
        .compose(
            Method::UploadCancel,
            ActionId::new(kr_ipc::new_uuid()),
            target.clone(),
            None,
            &serde_json::json!({}),
            &UploadCancelParams {
                transfer_id: cancelled,
            },
            TTL,
        )
        .await
        .expect("the cancel is composed");
    let Settled::Result(finish_answer) = within(first.send(&finish))
        .await
        .expect("the host publishes the upload")
    else {
        panic!("the finish is answered with its result");
    };
    let Settled::Result(cancel_answer) = within(first.send(&cancel))
        .await
        .expect("the host cancels the upload")
    else {
        panic!("the cancel is answered with its result");
    };
    let published: UploadFinishResult = finish_answer.to_typed().expect("a finish result");
    let released: UploadCancelResult = cancel_answer.to_typed().expect("a cancel result");
    assert_eq!(released.state, UploadState::Cancelled);
    let charged = staged(&host);

    let refused = first
        .repeat(&finish)
        .await
        .expect_err("the connection that composed the request is not asked again");
    assert!(matches!(
        refused,
        kr_client::ClientError::Misdirected { repeating: true }
    ));

    let second = net_support::connect(&host, &device, &record).await;
    let Settled::Result(finish_again) = within(second.repeat(&finish))
        .await
        .expect("the host answers the finish from its record")
    else {
        panic!("the repeat is answered with the result");
    };
    let Settled::Result(cancel_again) = within(second.repeat(&cancel))
        .await
        .expect("the host answers the cancel from its record")
    else {
        panic!("the repeat is answered with the result");
    };
    assert_eq!(
        finish_again
            .to_typed::<UploadFinishResult>()
            .expect("a result"),
        published
    );
    assert_eq!(
        cancel_again
            .to_typed::<UploadCancelResult>()
            .expect("a result"),
        released
    );
    assert_eq!(staged(&host), charged, "the host acted once");
    assert_eq!(
        status_of(&second, finished).await.state,
        UploadState::Published
    );
    first.close();
    second.close();
    host.stop().await;
}

/// A device that may not view a session can reserve an upload bound to it and send its chunks, and the
/// host does not tell it what became of the finish: its answer is that the outcome is not known,
/// though the upload is published, so that the device is shown nothing of a session it may not view in
/// an answer it could keep. The client reads the status, which is shown, in the same call and returns
/// the handle: one finish is sent, and the send does not end with an error for a file that arrived.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_that_may_not_view_a_session_is_not_told_its_finish_and_reads_it_published_from_the_status()
 {
    let adopted = Adopted::start(1).await;
    let host = &adopted.host;
    let session_id = adopted.workers[0].session_id;
    let (device, record) = paired(host, &adopted.owner, &[ActionRight::FilesUpload]).await;
    let (session, _opened, finished, status_reads) = counting_session(host, &device, &record).await;
    let route = ChunkRoute::network(&session, host.environment_id)
        .await
        .expect("the host takes an attachment stream from a device");
    let bytes = pattern(96);
    let target = on_the_session(host, session_id);
    let mut upload = plan(host, Some(session_id), "scoped.bin", &bytes);
    let (progress, watching) = tokio::sync::watch::channel(Progress::default());

    let handle = within(uploads::send(
        &session,
        &route,
        &target,
        &mut upload,
        TTL,
        &progress,
    ))
    .await
    .expect("the status says the upload is published, and the send returns its handle");
    assert_eq!(
        Some(handle.transfer_id),
        upload.transfer_id().copied(),
        "the handle is the upload's"
    );
    assert_eq!(handle.content_digest, digest(&bytes));
    assert_eq!(watching.borrow().stage, Stage::Published);
    assert_eq!(
        finished.load(Ordering::Acquire),
        1,
        "the finish was sent once and not again"
    );
    assert_eq!(
        *status_reads.lock().expect("the status reads"),
        vec![1],
        "the status was read once, after the finish the host could not answer"
    );
    assert_eq!(staged(host), bytes.len() as u64, "one file");
    session.close();
    adopted.stop().await;
}

/// KR-REQ-14.12: a caller that gives up a send while a chunk is at the host releases the upload with
/// `uploads::cancel`, which names the transfer the plan holds. The host holds the first chunk after it
/// took its transfer's gate, so the exchange is under way when the send is dropped. The dropped lane
/// resets its stream: once the held chunk goes on, the host's task for the stream ends, no chunk is left
/// in the transfer service, and the host then cancels the upload and gives back the bytes it reserved.
/// The host's data-stream deadlines are the case's own and never fire, so the host's idle reset cannot
/// be what ends the stream: only the client's reset can, and a lane that left its stream open would
/// leave the host's task standing until the case's liveness wait fails it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_upload_the_caller_gives_up_is_cancelled_by_its_transfer_and_its_bytes_are_released() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start_with_settings(
        &owner,
        NetworkSettings {
            endpoint: net_support::loopback(),
            data_stream_deadlines: Some(ManualDeadlines::new()),
            ..NetworkSettings::default()
        },
    )
    .await;
    let (device, record) = paired(&host, &owner, &[ActionRight::FilesUpload]).await;
    let session = net_support::connect(&host, &device, &record).await;
    let route = ChunkRoute::network(&session, host.environment_id)
        .await
        .expect("the host takes an attachment stream from a device");
    let bytes = pattern(2 * UPLOAD_CHUNK_LEN + 5_000);
    let mut upload = plan(&host, None, "given-up.bin", &bytes);
    let (progress, _watching) = tokio::sync::watch::channel(Progress::default());
    let target = on_the_host(&host);
    let (held, release) = host.network().hold_chunks_after_the_gate();
    let mut ended = host.network().chunk_tasks_ended();
    {
        // The send is dropped while the host holds the first chunk: the chunk is written and its
        // answer is awaited, so the lane is part way through its call.
        let sending = uploads::send(&session, &route, &target, &mut upload, TTL, &progress);
        tokio::pin!(sending);
        tokio::select! {
            sent = &mut sending => panic!("the upload ended before it was given up: {sent:?}"),
            arrived = held => arrived.expect("the host holds the first chunk"),
        }
    }
    let transfer = *upload.transfer_id().expect("the plan holds the transfer");
    release.send(()).expect("the held chunk goes on");
    within(ended.wait_for(|ended| *ended >= 1))
        .await
        .expect("the host's task for the dropped lane's stream ends, and the count stays open");
    within(
        host.network()
            .until_no_chunk_is_in_the_service(record.device_id, transfer),
    )
    .await;

    let cancelled = within(uploads::cancel(&session, &target, transfer, TTL))
        .await
        .expect("the host cancels the upload");
    assert_eq!(cancelled.state, UploadState::Cancelled);
    assert_eq!(staged(&host), 0, "the bytes the upload held are given back");
    assert_eq!(
        status_of(&session, transfer).await.state,
        UploadState::Cancelled
    );
    session.close();
    host.stop().await;
}
