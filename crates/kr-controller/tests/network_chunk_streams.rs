//! A paired device's attachment-chunk stream over real paired connections.
//!
//! A device sends an upload's chunks on a data stream of its own, never on the control stream, and
//! asks the host which streams it takes before it begins an upload. The streams are real: a paired
//! device opens them on its authorised connection, and the host reads their headers, admits them
//! under the device's own principal and answers each chunk on the stream it came on.
//!
//! The uploads these cases send chunks to are begun in the transfer service under the device's own
//! principal, since a device's `upload.begin` is a method of its own and not what a stream is about.
//! Each upload is 96 bytes, one chunk, unless a case needs more.

mod net_support;

use std::task::Poll;
use std::time::Duration;

use kr_controller::service::net::config::NetworkSettings;
use kr_controller::service::net::devices::DeviceRecord;
use kr_controller::service::net::{DEVICE_LIVE_CONNECTIONS, DEVICE_SILENT_FOR};
use kr_crypto::keys::DeviceKeys;
use kr_protocol::envelope::{ControlFrame, Outcome, ParamsValue};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::frame::{StreamHeader, StreamKind, StreamResource};
use kr_protocol::ids::{ActionId, ActorId, EnvironmentId, RequestId, SessionId, TransferId};
use kr_protocol::method::Method;
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{Bytes, Digest256, Nullable, U64};
use kr_protocol::transfer::{
    ChunkDescriptor, TransferStreamsParams, TransferStreamsResult, UploadBeginParams,
    UploadCancelParams, UploadChunkParams, UploadStatusParams,
};
use kr_transport::deadlines::{DeadlineKind, ManualDeadlines};
use kr_transport::streams::DataStream;
use net_support::{Device, Host, Moved, RawDevice, an_open_session, on_the_host, on_the_session};

/// A method name the registry does not list, as an older host would meet a method it has not heard of.
const A_METHOD_THE_HOST_DOES_NOT_LIST: &str = "transfer.stream_kinds";

/// What a case waits at most for a frame, an answer or a reset. A host that does what the case
/// says answers at once: the bound only ends a case that would hang.
const WAIT: Duration = Duration::from_secs(60);

/// Parameters of a method that takes none.
#[derive(serde::Serialize)]
struct NoParams {}

/// The bytes of the one chunk an upload of these cases has.
const CHUNK: [u8; 96] = [7; 96];

/// A paired device, its record and its connection.
struct Paired {
    device: Device,
    record: DeviceRecord,
    raw: RawDevice,
}

impl Paired {
    /// The principal the host acts for this device under.
    fn actor(&self) -> ActorId {
        kr_transport::listener::device_principal(&self.record.device_id)
    }

    /// Connects the device again, as a device does that lost a connection. The host admits a burst
    /// of new connections across every peer and returns a place at a fixed rate, so a case that
    /// connects more than the burst in a moment is refused until a place is returned: it tries
    /// again until it is admitted.
    async fn again(&self, host: &Host) -> RawDevice {
        let deadline = tokio::time::Instant::now() + WAIT;
        loop {
            match RawDevice::admitted(host, &self.device, &self.record).await {
                Ok(raw) => {
                    raw.claim();
                    return raw;
                }
                Err(error) if tokio::time::Instant::now() >= deadline => {
                    panic!("the paired device connects: {error:?}");
                }
                Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
            }
        }
    }
}

async fn paired(host: &Host, owner: &DeviceKeys, rights: &[ActionRight]) -> Paired {
    let device = Device::create().await;
    let record = net_support::pair_with(host, &device, owner, net_support::proposal(rights)).await;
    let raw = RawDevice::connect(host, &device, &record).await;
    raw.claim();
    Paired {
        device,
        record,
        raw,
    }
}

/// An upload of `CHUNK`'s length begun for `actor`, bound to `session` or to the host.
fn begin(host: &Host, actor: &ActorId, session: Option<SessionId>) -> TransferId {
    begin_of(host, actor, session, CHUNK.len() as u64)
}

fn begin_of(host: &Host, actor: &ActorId, session: Option<SessionId>, length: u64) -> TransferId {
    host.controller()
        .transfer()
        .service()
        .upload_begin(
            actor,
            &UploadBeginParams {
                environment_id: host.environment_id,
                session_id: Nullable(session),
                device_id: Nullable::null(),
                declared_byte_len: U64::new(length),
                declared_digest: Digest256::from_bytes([0xd1; 32]),
                declared_media_type: "application/octet-stream".to_owned(),
                original_file_name: "notes.bin".to_owned(),
            },
            None,
            None,
        )
        .expect("the upload begins")
        .transfer_id
}

/// How many bytes of the upload are staged and verified.
fn received(host: &Host, actor: &ActorId, transfer: TransferId) -> u64 {
    host.controller()
        .transfer()
        .service()
        .upload_status(
            actor,
            &UploadStatusParams {
                transfer_id: transfer,
            },
        )
        .expect("the upload's status")
        .received_byte_len
        .get()
}

fn header_in(raw: &RawDevice, environment: EnvironmentId, transfer: TransferId) -> StreamHeader {
    StreamHeader {
        kind: StreamKind::AttachmentChunks,
        connection_id: raw.connection_id(),
        stream_id: Nullable::null(),
        resource: StreamResource {
            environment_id: environment,
            session_id: Nullable::null(),
            attachment_id: Nullable::null(),
            transfer_id: Nullable::some(transfer),
        },
    }
}

fn header(host: &Host, raw: &RawDevice, transfer: TransferId) -> StreamHeader {
    header_in(raw, host.environment_id, transfer)
}

/// The frame that sends `bytes` as chunk `index` of `transfer`, on the host's target.
fn chunk_frame(host: &Host, raw: &RawDevice, transfer: TransferId, bytes: &[u8]) -> ControlFrame {
    chunk_numbered(host, raw, transfer, 0, bytes)
}

fn chunk_numbered(
    host: &Host,
    raw: &RawDevice,
    transfer: TransferId,
    index: u64,
    bytes: &[u8],
) -> ControlFrame {
    raw.mutation_frame_for(
        Method::UploadChunk,
        ActionId::new(kr_ipc::new_uuid()),
        on_the_host(host),
        &UploadChunkParams {
            transfer_id: transfer,
            chunk: ChunkDescriptor {
                index: U64::new(index),
                byte_len: U64::new(bytes.len() as u64),
                digest: Digest256::from_bytes(kr_cbor::sha256(bytes)),
            },
            bytes: Bytes::new(bytes.to_vec()),
        },
    )
    .1
}

/// Reads the next frame the host sent on a stream: an answer, or why there is none.
async fn next(stream: &mut DataStream) -> std::result::Result<Option<ControlFrame>, String> {
    tokio::time::timeout(WAIT, stream.read_message::<ControlFrame>())
        .await
        .expect("the host answers or ends the stream in time")
        .map_err(|error| format!("{error:?}"))
}

/// Sends `frame` on `stream` and returns the host's answer to it.
async fn ask(
    stream: &mut DataStream,
    frame: &ControlFrame,
) -> std::result::Result<ParamsValue, ProtocolError> {
    stream
        .write_message(frame)
        .await
        .expect("the frame is written");
    match next(stream).await {
        Ok(Some(ControlFrame::Response(response))) => match response.outcome {
            Outcome::Ok(value) => Ok(value),
            Outcome::Error(error) => Err(error),
        },
        other => panic!("an answer was expected, and the stream said {other:?}"),
    }
}

/// Whether the host took the stream away: a reset, and not a clean end or an answer. What a reset
/// says is returned, so that the refusals of one case can be compared.
async fn reset(stream: &mut DataStream) -> String {
    match next(stream).await {
        Err(reset) => reset,
        other => panic!("the stream was to be reset, and it said {other:?}"),
    }
}

/// Waits for a blocking pause to say it has arrived, without holding a worker thread of the case.
async fn arrived(rx: std::sync::mpsc::Receiver<()>) {
    tokio::task::spawn_blocking(move || rx.recv_timeout(WAIT))
        .await
        .expect("the wait ends")
        .expect("the held call arrives");
}

/// Polls `future` once and returns what it said.
async fn poll_once<F: std::future::Future + Unpin>(future: &mut F) -> Poll<F::Output> {
    std::future::poll_fn(|context| Poll::Ready(std::pin::Pin::new(&mut *future).poll(context)))
        .await
}

/// Writes `frame` to a stream the future owns, and gives the stream back with the result, so that a
/// write that is pending holds the stream and the case can ask again.
async fn write_owned(
    mut stream: DataStream,
    frame: ControlFrame,
) -> (DataStream, kr_transport::Result<()>) {
    let written = stream.write_message(&frame).await;
    (stream, written)
}

/// KR-REQ-23.21: a paired device that holds no right at all is told which streams the host takes,
/// so that a device decides before it reserves anything whether its chunks have a stream to travel
/// on. The control is a method the host does not list: it is refused as a host older than the
/// method refuses it, `PERMISSION_DENIED` with the registry's own words, which is how a client
/// tells a host that cannot take the form from one that refused for another reason.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_with_no_rights_is_told_which_streams_the_host_takes() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let device = Device::create().await;
    let record = net_support::pair_with(&host, &device, &owner, net_support::proposal(&[])).await;
    let raw = RawDevice::connect(&host, &device, &record).await;
    raw.claim();

    let answered: TransferStreamsResult = raw
        .read(Method::TransferStreams, &TransferStreamsParams {})
        .await
        .expect("a device with no rights is told")
        .to_typed()
        .expect("a result of the declared shape");
    assert_eq!(
        answered.accepted_streams,
        vec![StreamKind::AttachmentChunks]
    );

    let unlisted = raw
        .read_named(A_METHOD_THE_HOST_DOES_NOT_LIST, &TransferStreamsParams {})
        .await
        .expect_err("a method the registry does not list");
    assert_eq!(unlisted.code, ErrorCode::PermissionDenied, "{unlisted:?}");
    assert_eq!(
        unlisted.message,
        kr_transport::actor::METHOD_NOT_AVAILABLE,
        "the registry's own words, which a client reads as a host that does not list the method"
    );
    raw.close();
    host.stop().await;
}

/// KR-REQ-23.21 and KR-REQ-23.41: a chunk sent on a stream the device opened for its own upload is
/// answered on that stream and staged. A header that names another device's upload, the owner's, one
/// that never existed, a cancelled one or another environment's, and a stream of a kind the host does
/// not take, is reset with nothing staged, and each upload is refused alike, so that a device learns
/// nothing of which identifiers exist.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_chunk_is_staged_from_the_devices_own_upload_and_every_other_header_is_reset() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let own = paired(&host, &owner, &[ActionRight::FilesUpload]).await;
    let other = paired(&host, &owner, &[ActionRight::FilesUpload]).await;
    let service = host.controller().transfer().service();

    let mine = begin(&host, &own.actor(), None);
    let theirs = begin(&host, &other.actor(), None);
    let owners_actor = ActorId::new("local:501").expect("the owner's principal");
    let owners = begin(&host, &owners_actor, None);
    let cancelled = begin(&host, &own.actor(), None);
    service
        .upload_cancel(
            &own.actor(),
            &UploadCancelParams {
                transfer_id: cancelled,
            },
            None,
        )
        .expect("the upload is cancelled");
    let unknown = TransferId::new(kr_ipc::new_uuid());

    // The control: the device's own upload.
    let mut stream = own.raw.open_stream(header(&host, &own.raw, mine)).await;
    ask(&mut stream, &chunk_frame(&host, &own.raw, mine, &CHUNK))
        .await
        .expect("a chunk of the device's own upload is served");
    assert_eq!(received(&host, &own.actor(), mine), 96);

    let mut refusals = Vec::new();
    for transfer in [theirs, owners, unknown, cancelled] {
        let mut stream = own.raw.open_stream(header(&host, &own.raw, transfer)).await;
        refusals.push(reset(&mut stream).await);
    }
    assert!(
        refusals.windows(2).all(|pair| pair[0] == pair[1]),
        "another device's upload, the owner's, an unknown one and a cancelled one are refused alike: {refusals:?}"
    );
    assert_eq!(received(&host, &other.actor(), theirs), 0);
    assert_eq!(received(&host, &owners_actor, owners), 0);

    // Another environment's upload, with nothing of the device's own staged.
    let fresh = begin(&host, &own.actor(), None);
    let mut stream = own
        .raw
        .open_stream(header_in(
            &own.raw,
            EnvironmentId::new(kr_ipc::new_uuid()),
            fresh,
        ))
        .await;
    reset(&mut stream).await;
    assert_eq!(received(&host, &own.actor(), fresh), 0);

    // A stream of a kind the host does not take.
    let mut terminal = header(&host, &own.raw, fresh);
    terminal.kind = StreamKind::TerminalOutput;
    terminal.resource.session_id = Nullable::some(SessionId::new(kr_ipc::new_uuid()));
    terminal.resource.attachment_id =
        Nullable::some(kr_protocol::ids::AttachmentId::new(kr_ipc::new_uuid()));
    let mut stream = own.raw.open_stream(terminal).await;
    reset(&mut stream).await;
    assert_eq!(received(&host, &own.actor(), fresh), 0);

    own.raw.close();
    other.raw.close();
    host.stop().await;
}

/// KR-REQ-23.21 and KR-REQ-23.41: a stream is held to the rights the door decides for a chunk of the
/// upload's session. A device that does not hold `files.upload` is reset at its header, and the
/// control, a device that does, is served for an upload bound to a session.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_header_for_an_upload_the_device_holds_no_right_to_send_is_reset() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let (session, _) = an_open_session(&host);
    let without = paired(&host, &owner, &[ActionRight::SessionView]).await;
    // `session.view` too: a chunk's answer is withheld as a copy from a device that may not read
    // the session's receipts, which the arm for the upload methods decides for each.
    let with = paired(
        &host,
        &owner,
        &[ActionRight::FilesUpload, ActionRight::SessionView],
    )
    .await;

    let refused = begin(&host, &without.actor(), Some(session));
    let mut stream = without
        .raw
        .open_stream(header(&host, &without.raw, refused))
        .await;
    reset(&mut stream).await;
    assert_eq!(received(&host, &without.actor(), refused), 0);

    let allowed = begin(&host, &with.actor(), Some(session));
    let mut stream = with
        .raw
        .open_stream(header(&host, &with.raw, allowed))
        .await;
    let frame = with.raw.mutation_frame_for(
        Method::UploadChunk,
        ActionId::new(kr_ipc::new_uuid()),
        on_the_session(&host, session),
        &UploadChunkParams {
            transfer_id: allowed,
            chunk: ChunkDescriptor {
                index: U64::new(0),
                byte_len: U64::new(96),
                digest: Digest256::from_bytes(kr_cbor::sha256(&CHUNK)),
            },
            bytes: Bytes::new(CHUNK.to_vec()),
        },
    );
    ask(&mut stream, &frame.1)
        .await
        .expect("a device that holds the right is served for the upload's session");
    assert_eq!(received(&host, &with.actor(), allowed), 96);

    without.raw.close();
    with.raw.close();
    host.stop().await;
}

/// KR-REQ-23.21: a newer stream for a transfer replaces the older, on one connection and across two:
/// the older is reset and the newer serves. An ordinary stream failure leaves the connection
/// standing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_newer_stream_for_a_transfer_replaces_the_older() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let device = paired(&host, &owner, &[ActionRight::FilesUpload]).await;
    let transfer = begin(&host, &device.actor(), None);

    let mut first = device
        .raw
        .open_stream(header(&host, &device.raw, transfer))
        .await;
    ask(
        &mut first,
        &chunk_frame(&host, &device.raw, transfer, &CHUNK),
    )
    .await
    .expect("the first stream serves");

    // On the same connection.
    let mut second = device
        .raw
        .open_stream(header(&host, &device.raw, transfer))
        .await;
    reset(&mut first).await;
    ask(
        &mut second,
        &chunk_frame(&host, &device.raw, transfer, &CHUNK),
    )
    .await
    .expect("the newer stream serves");

    // Across two connections.
    let again = device.again(&host).await;
    let mut third = again.open_stream(header(&host, &again, transfer)).await;
    reset(&mut second).await;
    ask(&mut third, &chunk_frame(&host, &again, transfer, &CHUNK))
        .await
        .expect("the stream on the replacement connection serves");

    // The failure of a stream is not the connection's.
    device
        .raw
        .read(Method::HostInfo, &NoParams {})
        .await
        .expect("the first connection stands");
    again.close();
    device.raw.close();
    host.stop().await;
}

/// Waits until `condition` holds, polling it: for the one thing a case has no signal for, that a
/// connection's guard has been dropped by the host.
async fn until(condition: impl Fn() -> bool) {
    tokio::time::timeout(WAIT, async {
        while !condition() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the condition came to hold");
}

/// Fires the admission deadline once a lookup is waiting on one, and waits for a lookup to have
/// given up because of it. A host that never starts a deadline or never lets one resolve fails the
/// case here instead of holding it.
async fn fire_admission(deadlines: &ManualDeadlines) {
    tokio::time::timeout(WAIT, deadlines.fire_when_armed(DeadlineKind::Admission))
        .await
        .expect("an admission deadline was fired and a lookup gave up on it");
}

/// Waits for `count` lookups to arrive at the hold, and gives the end back.
async fn lookups_arrived(
    arrivals: std::sync::mpsc::Receiver<()>,
    count: usize,
) -> std::sync::mpsc::Receiver<()> {
    tokio::task::spawn_blocking(move || {
        for _ in 0..count {
            arrivals
                .recv_timeout(WAIT)
                .expect("a lookup arrives at the hold");
        }
        arrivals
    })
    .await
    .expect("the wait ends")
}

/// The answer a chunk was given, read from a stream where the case did not ask in the same step.
async fn answered(stream: &mut DataStream) -> std::result::Result<ParamsValue, ProtocolError> {
    match next(stream).await {
        Ok(Some(ControlFrame::Response(response))) => match response.outcome {
            Outcome::Ok(value) => Ok(value),
            Outcome::Error(error) => Err(error),
        },
        other => panic!("an answer was expected, and the stream said {other:?}"),
    }
}

/// KR-REQ-23.21: the older stream's chunk, held inside the transfer service, leaves it before the
/// newer stream's first frame enters. The newer frame is held at the transfer's gate (the case waits
/// until it has reached it, and sees that it has not entered the service), the older is released and
/// refused at the service's own ask because its stream was replaced, and then the newer is served.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_older_streams_chunk_leaves_the_service_before_the_newer_streams_first_frame_enters_it()
{
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let device = paired(&host, &owner, &[ActionRight::FilesUpload]).await;
    let transfer = begin(&host, &device.actor(), None);
    let module = host.controller().transfer();

    let (held, release) = module.pause_after_the_outer_check();
    let mut older = device
        .raw
        .open_stream(header(&host, &device.raw, transfer))
        .await;
    older
        .write_message(&chunk_frame(&host, &device.raw, transfer, &CHUNK))
        .await
        .expect("the frame is written");
    arrived(held).await;

    let mut waits = host.network().chunk_gate_waits();
    let mut newer = device
        .raw
        .open_stream(header(&host, &device.raw, transfer))
        .await;
    newer
        .write_message(&chunk_frame(&host, &device.raw, transfer, &CHUNK))
        .await
        .expect("the frame is written");
    // The count is of frames that found the gate held: the newer waits behind the older's chunk.
    tokio::time::timeout(WAIT, waits.wait_for(|waits| *waits >= 1))
        .await
        .expect("the newer frame finds the gate held")
        .expect("the count stays open");
    let (entered, enter) = module.pause_after_the_outer_check();
    assert!(
        entered.try_recv().is_err(),
        "the newer frame does not enter the service while the older chunk is in it"
    );

    release.send(()).expect("the older chunk goes on");
    arrived(entered).await;
    enter.send(()).expect("the newer chunk goes on");
    answered(&mut newer)
        .await
        .expect("the newer stream's chunk is served");
    assert_eq!(received(&host, &device.actor(), transfer), 96);
    reset(&mut older).await;
    device.raw.close();
    host.stop().await;
}

/// KR-REQ-23.21: the abort path. The connection of the older stream is dropped while its chunk is
/// held inside the service: its task is aborted, and the transfer's gate is still held by the blocking
/// call that has the chunk, so the newer stream's first frame, on a replacement connection, waits for
/// that call and does not enter beside it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_chunk_in_the_service_keeps_the_gate_after_its_connection_is_dropped() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let device = paired(&host, &owner, &[ActionRight::FilesUpload]).await;
    let transfer = begin(&host, &device.actor(), None);
    let module = host.controller().transfer();

    let (held, release) = module.pause_after_the_outer_check();
    let mut older = device
        .raw
        .open_stream(header(&host, &device.raw, transfer))
        .await;
    older
        .write_message(&chunk_frame(&host, &device.raw, transfer, &CHUNK))
        .await
        .expect("the frame is written");
    arrived(held).await;
    device.raw.close();
    until(|| host.connections_of(&device.record) == 0).await;
    // The aborted task is gone before the newer frame asks for the gate, so a gate the task held
    // for its chunk would be free by then.
    let mut ended = host.network().chunk_tasks_ended();
    tokio::time::timeout(WAIT, ended.wait_for(|ended| *ended >= 1))
        .await
        .expect("the dropped connection's stream task ends")
        .expect("the count stays open");

    let again = device.again(&host).await;
    let mut waits = host.network().chunk_gate_waits();
    let mut newer = again.open_stream(header(&host, &again, transfer)).await;
    newer
        .write_message(&chunk_frame(&host, &again, transfer, &CHUNK))
        .await
        .expect("the frame is written");
    // The count is of frames that found the gate held: the newer waits behind the chunk that is
    // still in the service.
    tokio::time::timeout(WAIT, waits.wait_for(|waits| *waits >= 1))
        .await
        .expect("the newer frame finds the gate held by the dropped connection's chunk")
        .expect("the count stays open");
    let (entered, enter) = module.pause_after_the_outer_check();
    assert!(
        entered.try_recv().is_err(),
        "the newer frame does not enter the service while the dropped connection's chunk is in it"
    );
    release.send(()).expect("the held chunk goes on");
    arrived(entered).await;
    enter.send(()).expect("the newer chunk goes on");
    answered(&mut newer)
        .await
        .expect("the newer stream's chunk is served");
    assert_eq!(received(&host, &device.actor(), transfer), 96);
    again.close();
    host.stop().await;
}

/// KR-REQ-23.21: an older stream's task that read its frame before the replacement and takes the
/// gate after it ends with no call into the service. The case holds the older after the gate,
/// replaces its stream (the newer's first frame waiting at the gate says it has), and lets the older
/// go; the newer's own pass of the gate is held, so that nothing of the newer can be in the service
/// while the case reads that the older never reached the service's entry. The newer stream's chunk,
/// different bytes for the same position, is then the one that is staged, and the upload stands.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_older_task_that_takes_the_gate_after_its_stream_was_replaced_calls_nothing() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let device = paired(&host, &owner, &[ActionRight::FilesUpload]).await;
    let transfer = begin(&host, &device.actor(), None);

    let (at_the_gate, go) = host.network().hold_chunks_after_the_gate();
    let mut older = device
        .raw
        .open_stream(header(&host, &device.raw, transfer))
        .await;
    older
        .write_message(&chunk_frame(&host, &device.raw, transfer, &[1; 96]))
        .await
        .expect("the frame is written");
    tokio::time::timeout(WAIT, at_the_gate)
        .await
        .expect("the older frame reaches the gate")
        .expect("the hold is armed");

    let mut waits = host.network().chunk_gate_waits();
    let (newer_at_the_gate, newer_go) = host.network().hold_chunks_after_the_gate();
    let (entered, enter) = host.controller().transfer().pause_after_the_outer_check();
    let mut newer = device
        .raw
        .open_stream(header(&host, &device.raw, transfer))
        .await;
    newer
        .write_message(&chunk_frame(&host, &device.raw, transfer, &[2; 96]))
        .await
        .expect("the frame is written");
    // The newer's first frame found the gate held by the older, which its stream's replacement of
    // the older's precedes.
    tokio::time::timeout(WAIT, waits.wait_for(|waits| *waits >= 1))
        .await
        .expect("the newer frame finds the gate held")
        .expect("the count stays open");
    go.send(()).expect("the older task goes on");
    reset(&mut older).await;
    assert!(
        entered.try_recv().is_err(),
        "the older task made no call into the service"
    );
    tokio::time::timeout(WAIT, newer_at_the_gate)
        .await
        .expect("the newer frame takes the gate once the older has gone")
        .expect("the hold is armed");
    newer_go.send(()).expect("the newer frame goes on");
    arrived(entered).await;
    enter.send(()).expect("the newer chunk goes on");
    answered(&mut newer)
        .await
        .expect("the newer stream's chunk is served");
    let status = host
        .controller()
        .transfer()
        .service()
        .upload_status(
            &device.actor(),
            &UploadStatusParams {
                transfer_id: transfer,
            },
        )
        .expect("the upload's status");
    assert_eq!(
        status.state,
        kr_protocol::transfer::UploadState::Receiving,
        "the older chunk never entered the service, so nothing contradicts the newer's"
    );
    assert_eq!(status.received_byte_len.get(), 96);
    device.raw.close();
    host.stop().await;
}

/// KR-REQ-23.21 and KR-REQ-23.41: a chunk on the control stream is refused by name with nothing
/// staged. On a chunk stream, a read and a mutation that is not a chunk are refused and the stream
/// ends, and a chunk that names another upload of the same device than the header's is refused with
/// nothing staged in that other upload. The control is the right frame.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_chunk_stream_carries_the_chunks_of_its_own_transfer_and_nothing_else() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let device = paired(&host, &owner, &[ActionRight::FilesUpload]).await;
    let transfer = begin(&host, &device.actor(), None);
    let second = begin(&host, &device.actor(), None);

    let (_, on_the_control_stream) = device.raw.mutation_frame_for(
        Method::UploadChunk,
        ActionId::new(kr_ipc::new_uuid()),
        on_the_host(&host),
        &UploadChunkParams {
            transfer_id: transfer,
            chunk: ChunkDescriptor {
                index: U64::new(0),
                byte_len: U64::new(96),
                digest: Digest256::from_bytes(kr_cbor::sha256(&CHUNK)),
            },
            bytes: Bytes::new(CHUNK.to_vec()),
        },
    );
    let ControlFrame::Mutation(mutation) = on_the_control_stream else {
        panic!("a mutation");
    };
    let refused = device
        .raw
        .mutate(
            Method::UploadChunk,
            mutation.action_id,
            mutation.target.clone(),
            &mutation.params,
        )
        .await
        .expect_err("a chunk on the control stream");
    assert_eq!(
        refused.code,
        ErrorCode::UnsupportedCapability,
        "{refused:?}"
    );
    assert!(
        refused.message.starts_with("upload.chunk")
            && refused.message.contains("attachment-chunk stream"),
        "the refusal names the method and the stream it belongs on: {refused:?}"
    );
    assert_eq!(received(&host, &device.actor(), transfer), 0);

    // A read, and a mutation that is not a chunk, end the stream.
    let read = device.raw.read_frame_for(Method::HostInfo, &NoParams {}).1;
    let begin_frame = device
        .raw
        .mutation_frame_for(
            Method::UploadBegin,
            ActionId::new(kr_ipc::new_uuid()),
            on_the_host(&host),
            &NoParams {},
        )
        .1;
    for frame in [read, begin_frame] {
        let mut stream = device
            .raw
            .open_stream(header(&host, &device.raw, transfer))
            .await;
        let refusal = ask(&mut stream, &frame)
            .await
            .expect_err("a frame a chunk stream does not carry");
        assert_eq!(
            refusal.code,
            ErrorCode::UnsupportedCapability,
            "{refusal:?}"
        );
        assert!(
            !matches!(next(&mut stream).await, Ok(Some(_))),
            "the stream ends with the refusal"
        );
    }

    // A chunk of another upload of the same device.
    let mut stream = device
        .raw
        .open_stream(header(&host, &device.raw, transfer))
        .await;
    let refusal = ask(
        &mut stream,
        &chunk_frame(&host, &device.raw, second, &CHUNK),
    )
    .await
    .expect_err("a chunk naming another upload");
    assert_eq!(refusal.code, ErrorCode::InvalidArgument, "{refusal:?}");
    assert_eq!(received(&host, &device.actor(), second), 0);
    assert!(!matches!(next(&mut stream).await, Ok(Some(_))));

    // The control: the right frame on a stream of its own.
    let mut stream = device
        .raw
        .open_stream(header(&host, &device.raw, transfer))
        .await;
    ask(
        &mut stream,
        &chunk_frame(&host, &device.raw, transfer, &CHUNK),
    )
    .await
    .expect("the right frame is served");
    assert_eq!(received(&host, &device.actor(), transfer), 96);
    device.raw.close();
    host.stop().await;
}

/// KR-REQ-23.21: a device's lookups of its uploads are held to two places for its principal across
/// its connections. Three streams of one device ask at once: two lookups run and the third waits for
/// a place, and the admission deadline resets all three while the two lookups, which a deadline
/// cannot cancel, go on holding their places. A replacement connection's header then waits for a place
/// that is not free and is reset without a lookup, and once the held lookups end, its next stream is
/// served. Another device's lookups are not held by this device's places.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_devices_lookups_are_held_to_two_places_across_its_connections() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let deadlines = ManualDeadlines::new();
    let host = Host::start_with_settings(
        &owner,
        NetworkSettings {
            endpoint: net_support::loopback(),
            data_stream_deadlines: Some(deadlines.clone()),
            ..NetworkSettings::default()
        },
    )
    .await;
    let device = paired(&host, &owner, &[ActionRight::FilesUpload]).await;
    let neighbour = paired(&host, &owner, &[ActionRight::FilesUpload]).await;
    // A principal holds two open uploads, so the third stream names an upload that is not there:
    // its lookup waits for a place all the same.
    let uploads = [
        begin(&host, &device.actor(), None),
        begin(&host, &device.actor(), None),
        TransferId::new(kr_ipc::new_uuid()),
    ];
    let neighbours = begin(&host, &neighbour.actor(), None);

    let (arrivals, release) = host.controller().transfer().hold_the_stream_lookups();
    let mut streams = Vec::new();
    for transfer in &uploads[..2] {
        streams.push(
            device
                .raw
                .open_stream(header(&host, &device.raw, *transfer))
                .await,
        );
    }
    let arrivals = lookups_arrived(arrivals, 2).await;
    streams.push(
        device
            .raw
            .open_stream(header(&host, &device.raw, uploads[2]))
            .await,
    );
    // Another device's lookup is not held by this device's places: it arrives beside theirs.
    let mut other = neighbour
        .raw
        .open_stream(header(&host, &neighbour.raw, neighbours))
        .await;
    let arrivals = lookups_arrived(arrivals, 1).await;
    until(|| deadlines.armed(DeadlineKind::Admission) >= 4).await;
    fire_admission(&deadlines).await;
    for stream in &mut streams {
        reset(stream).await;
    }
    reset(&mut other).await;
    assert!(
        arrivals.try_recv().is_err(),
        "the third lookup of the device never ran: its streams' lookups were held to two places"
    );

    // A replacement connection draws on the same two places, which the held lookups still hold.
    device.raw.close();
    until(|| host.connections_of(&device.record) == 0).await;
    let again = device.again(&host).await;
    let mut waiting = again.open_stream(header(&host, &again, uploads[2])).await;
    until(|| deadlines.armed(DeadlineKind::Admission) >= 1).await;
    fire_admission(&deadlines).await;
    reset(&mut waiting).await;
    assert!(
        arrivals.try_recv().is_err(),
        "the replacement connection's header ran no lookup while the held lookups kept both places"
    );

    release.release();
    let mut stream = again.open_stream(header(&host, &again, uploads[0])).await;
    ask(&mut stream, &chunk_frame(&host, &again, uploads[0], &CHUNK))
        .await
        .expect("once the held lookups end, the device's stream is served");
    again.close();
    neighbour.raw.close();
    host.stop().await;
}

/// KR-REQ-23.21: a stream of a connection that was lost while its header's lookup ran is reset and
/// leaves the device's live stream on its new connection serving. That a revoked stream is never
/// registered, and so replaces nothing, is shown by the registry's own case.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_revoked_stream_does_not_replace_the_live_stream_of_its_transfer() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let device = paired(&host, &owner, &[ActionRight::FilesUpload]).await;
    let transfer = begin(&host, &device.actor(), None);

    let mut live = device
        .raw
        .open_stream(header(&host, &device.raw, transfer))
        .await;
    ask(
        &mut live,
        &chunk_frame(&host, &device.raw, transfer, &CHUNK),
    )
    .await
    .expect("the live stream serves");

    let (arrivals, release) = host.controller().transfer().hold_the_stream_lookups();
    let doomed = device.again(&host).await;
    let mut stream = doomed.open_stream(header(&host, &doomed, transfer)).await;
    let _arrivals = lookups_arrived(arrivals, 1).await;
    doomed.close();
    until(|| host.connections_of(&device.record) == 1).await;
    release.release();
    reset(&mut stream).await;
    ask(
        &mut live,
        &chunk_frame(&host, &device.raw, transfer, &CHUNK),
    )
    .await
    .expect("the live stream was not replaced by a stream that was already gone");
    device.raw.close();
    host.stop().await;
}

/// KR-REQ-23.21 and KR-REQ-23.41: the loss of the control stream, once declared, is a condition of a
/// chunk's admission. (a) A chunk held before the service's ask, with its connection's registration
/// held in place, is refused at the ask when the loss is declared and is not staged; the chunk sent
/// again on a new connection is staged. (b) A chunk the service has staged, whose answer waits to be
/// written when the loss is declared, is in the upload.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_loss_of_the_control_stream_ends_the_chunks_that_have_not_begun_their_effect() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let device = paired(&host, &owner, &[ActionRight::FilesUpload]).await;
    let transfer = begin(&host, &device.actor(), None);
    let module = host.controller().transfer();

    // (a) The declaration before the ask.
    let (held, release) = module.pause_after_the_outer_check();
    let (deregistering, deregister) = host.controller().pause_connection_deregistration();
    let mut stream = device
        .raw
        .open_stream(header(&host, &device.raw, transfer))
        .await;
    stream
        .write_message(&chunk_frame(&host, &device.raw, transfer, &CHUNK))
        .await
        .expect("the frame is written");
    arrived(held).await;
    device.raw.close();
    // The withdrawal of the control stream's connection announces itself once the loss is declared,
    // which is after the connection's streams are revoked; the connection's own end is held with it.
    tokio::time::timeout(WAIT, deregistering)
        .await
        .expect("the loss is declared")
        .expect("the hold is armed");
    release.send(()).expect("the chunk goes on to the ask");
    host.network()
        .until_no_chunk_is_in_the_service(device.record.device_id, transfer)
        .await;
    assert_eq!(
        received(&host, &device.actor(), transfer),
        0,
        "the chunk was refused at the ask, with its registration still in place"
    );
    deregister.send(true).expect("the withdrawals go on");
    let again = device.again(&host).await;
    let mut resent = again.open_stream(header(&host, &again, transfer)).await;
    ask(&mut resent, &chunk_frame(&host, &again, transfer, &CHUNK))
        .await
        .expect("the chunk sent again on a new connection is staged");
    assert_eq!(received(&host, &device.actor(), transfer), 96);

    // (b) The declaration after the commit.
    let second = begin(&host, &device.actor(), None);
    let (answering, go) = host.network().hold_chunks_after_they_are_answered();
    let mut stream = again.open_stream(header(&host, &again, second)).await;
    stream
        .write_message(&chunk_frame(&host, &again, second, &CHUNK))
        .await
        .expect("the frame is written");
    tokio::time::timeout(WAIT, answering)
        .await
        .expect("the answer waits to be written")
        .expect("the hold is armed");
    assert_eq!(received(&host, &device.actor(), second), 96);
    again.close();
    until(|| host.connections_of(&device.record) == 0).await;
    let _ = go.send(());
    drop(stream);
    host.stop().await;
}

/// KR-REQ-23.21 and KR-REQ-23.41: a revocation while a chunk is held keeps it from being staged and
/// ends the stream, and the next frame of the device is refused anywhere. The control is another
/// device, whose chunk is staged as usual.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_revocation_while_a_chunk_is_held_keeps_it_from_being_staged() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let device = paired(&host, &owner, &[ActionRight::FilesUpload]).await;
    let other = paired(&host, &owner, &[ActionRight::FilesUpload]).await;
    let transfer = begin(&host, &device.actor(), None);
    let module = host.controller().transfer();

    let (held, release) = module.pause_after_the_outer_check();
    let mut stream = device
        .raw
        .open_stream(header(&host, &device.raw, transfer))
        .await;
    stream
        .write_message(&chunk_frame(&host, &device.raw, transfer, &CHUNK))
        .await
        .expect("the frame is written");
    arrived(held).await;
    host.network()
        .revoke_device(device.record.device_id)
        .await
        .expect("the device is revoked");
    release.send(()).expect("the chunk goes on");
    host.network()
        .until_no_chunk_is_in_the_service(device.record.device_id, transfer)
        .await;
    assert_eq!(received(&host, &device.actor(), transfer), 0);
    assert!(!matches!(next(&mut stream).await, Ok(Some(_))));
    assert!(
        !matches!(
            device.raw.try_read(Method::HostInfo, &NoParams {}).await,
            Some(Ok(_))
        ),
        "a revoked device is served nothing, on any stream"
    );

    let theirs = begin(&host, &other.actor(), None);
    let mut stream = other
        .raw
        .open_stream(header(&host, &other.raw, theirs))
        .await;
    ask(&mut stream, &chunk_frame(&host, &other.raw, theirs, &CHUNK))
        .await
        .expect("another device's chunk is staged");
    assert_eq!(received(&host, &other.actor(), theirs), 96);
    other.raw.close();
    host.stop().await;
}

/// KR-REQ-23.21 and KR-REQ-14.12: a connection the authority feed refuses stays up, and its streams
/// are refused: the header's lookup asks what the door asks of a chunk, the feed's refusal included.
/// The control is the same device's stream before the refusal rose.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_connection_the_authority_feed_refuses_is_given_no_stream() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let device = paired(&host, &owner, &[ActionRight::FilesUpload]).await;
    let before = begin(&host, &device.actor(), None);
    let after = begin(&host, &device.actor(), None);

    let mut stream = device
        .raw
        .open_stream(header(&host, &device.raw, before))
        .await;
    ask(
        &mut stream,
        &chunk_frame(&host, &device.raw, before, &CHUNK),
    )
    .await
    .expect("before the refusal the device is served");

    host.controller()
        .raise_the_unverified_withdrawal_refusal()
        .await;
    let mut refused = device
        .raw
        .open_stream(header(&host, &device.raw, after))
        .await;
    reset(&mut refused).await;
    assert_eq!(received(&host, &device.actor(), after), 0);
    // The connection stands: a request on its control stream is answered, whatever the answer is.
    assert!(
        device
            .raw
            .try_read(Method::HostInfo, &NoParams {})
            .await
            .is_some(),
        "the host answers on the control stream of the connection it refused a stream on"
    );
    device.raw.close();
    host.stop().await;
}

/// KR-REQ-23.21 and KR-PERF-005: a data stream whose peer writes past the credit the host gave it
/// stalls on its own and holds nothing else. A raw stream is written until a write is pending, by the
/// sizes, with the first chunk held at the service's pause; then a read, a mutation with its receipt
/// and the status read are answered on the control stream while the write is still pending. The
/// control is the same calls with nothing held.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stalled_chunk_stream_holds_nothing_on_the_control_stream() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let device = paired(
        &host,
        &owner,
        &[ActionRight::FilesUpload, ActionRight::SessionView],
    )
    .await;
    let length = 4 * 1024 * 1024;
    let transfer = begin_of(&host, &device.actor(), None, length);
    let big = vec![5_u8; 1024 * 1024];
    let (session_id, _) = an_open_session(&host);
    let draft = |text: &str| kr_protocol::transfer::DraftCreateParams {
        environment_id: host.environment_id,
        device_id: Nullable::null(),
        session_id: Nullable::some(session_id),
        application_instance_id: Nullable::null(),
        text: text.to_owned(),
    };
    let control_calls = |text: &'static str| {
        let device = &device;
        let host = &host;
        let params = draft(text);
        async move {
            device
                .raw
                .read(Method::HostInfo, &NoParams {})
                .await
                .expect("host.info is answered");
            // The status read is answered, whatever it says: the control path is not held.
            let _ = device
                .raw
                .read(
                    Method::UploadStatus,
                    &UploadStatusParams {
                        transfer_id: transfer,
                    },
                )
                .await;
            device
                .raw
                .mutate(
                    Method::DraftCreate,
                    ActionId::new(kr_ipc::new_uuid()),
                    on_the_session(host, session_id),
                    &params,
                )
                .await
                .expect("a mutation is answered with its receipt");
        }
    };
    control_calls("nothing held").await;

    let (held, release) = host.controller().transfer().pause_after_the_outer_check();
    let mut stream = device
        .raw
        .open_stream(header(&host, &device.raw, transfer))
        .await;
    stream
        .write_message(&chunk_numbered(&host, &device.raw, transfer, 0, &big))
        .await
        .expect("the first chunk is written");
    arrived(held).await;

    // Further frames of the attachment bound until a write is pending, by the sizes.
    let mut idle = Some(stream);
    let mut stalled = None;
    for index in 1..4 {
        let frame = chunk_numbered(&host, &device.raw, transfer, index, &big);
        let mut write = Box::pin(write_owned(idle.take().expect("the stream"), frame));
        match poll_once(&mut write).await {
            Poll::Ready((stream, written)) => {
                written.expect("a frame that fits the credit is written");
                idle = Some(stream);
            }
            Poll::Pending => {
                stalled = Some(write);
                break;
            }
        }
    }
    let mut stalled = stalled.expect("a write is pending once the credit is spent");
    control_calls("held").await;
    // The write is polled again once the control calls were answered, and is still pending: the
    // calls neither waited behind it nor gave it the credit it waits for.
    assert!(
        matches!(poll_once(&mut stalled).await, Poll::Pending),
        "the stalled write is still pending after the control calls were answered"
    );
    drop(stalled);
    release.send(()).expect("the chunk goes on");
    host.stop().await;
}

/// Whether a control connection of a device is served: it answers a read.
async fn is_served(raw: &RawDevice) -> bool {
    matches!(
        raw.try_read(Method::HostInfo, &NoParams {}).await,
        Some(Ok(_))
    )
}

/// Opens the connections a bound allows for `device`, the one `paired` opened being the oldest, and
/// returns the others in the order they were opened. Each is served before the next is opened, so
/// that the host counts them in that order.
async fn up_to_the_bound(device: &Paired, host: &Host) -> Vec<RawDevice> {
    assert!(
        is_served(&device.raw).await,
        "the first connection is served"
    );
    let mut more = Vec::new();
    for _ in 1..DEVICE_LIVE_CONNECTIONS {
        let raw = device.again(host).await;
        assert!(
            is_served(&raw).await,
            "a connection within the bound is served"
        );
        more.push(raw);
    }
    more
}

/// Whether a connection of a device has ended at the device, with no answer to a request it never
/// made.
async fn has_ended(raw: &RawDevice) -> bool {
    raw.answered_before_closing(RequestId::new(u64::MAX), WAIT)
        .await
        == Some(false)
}

/// KR-REQ-23.21: a connection is dated by the frames the transport counts from its device, requests
/// or not. A device that has made a request on a connection has sent frames the host's transport
/// received, and the host dates the connection to the time it read them, which is later than the
/// time it counted it. A device that then sends nothing still sends the transport's keepalive, and
/// the acknowledgements of the host's own, which date it again: the acknowledgement of the host's
/// reply can date it once more, so the case waits for a change after that one. Each wait is for the
/// host's reading, which it makes a second after the packets arrive at the latest.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_connection_is_dated_by_the_packets_its_device_sends_on_it() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let device = paired(&host, &owner, &[ActionRight::SessionView]).await;
    until(|| host.heard_from_of(&device.record).len() == 1).await;
    let admitted = host.heard_from_of(&device.record)[0];
    assert!(is_served(&device.raw).await, "the connection is served");
    until(|| host.heard_from_of(&device.record)[0] > admitted).await;
    // No request follows. The device's acknowledgement of the host's reply can date the connection
    // once more, and nothing but a keepalive of the two ends can date it after that.
    let after_the_request = host.heard_from_of(&device.record)[0];
    until(|| host.heard_from_of(&device.record)[0] > after_the_request).await;
    let after_the_acknowledgement = host.heard_from_of(&device.record)[0];
    until(|| host.heard_from_of(&device.record)[0] > after_the_acknowledgement).await;
    host.stop().await;
}

/// What the host answered a connection it refused with: the error of the response with the request
/// identifier zero that a refusal at connection is, or nothing when the connection was served.
async fn refusal_of(raw: &RawDevice) -> Option<ProtocolError> {
    match raw.next_answer(WAIT).await {
        Some((id, Outcome::Error(error))) if id == RequestId::new(0) => Some(error),
        _ => None,
    }
}

/// How long a case moves the host's readings on to make a connection that went silent read as
/// silent for more than the time the host requires.
fn past_the_silence() -> Duration {
    DEVICE_SILENT_FOR + Duration::from_secs(1)
}

/// KR-REQ-23.21: a device holds at most `DEVICE_LIVE_CONNECTIONS` live connections, and a
/// connection the host heard from inside the time a live connection is heard from is never
/// withdrawn for a new one. With every connection of the device heard from, which is what a device
/// that has left links and waits for their replies holds, the connection above the bound is refused
/// for now with the code a device tries again after, and none of the others ends. When one of the
/// others has been silent for longer than that time, the next connection above the bound is served
/// and that one, and only that one, ends; and the connection that follows it is refused again, so a
/// device that connects again after a withdrawal starts no chain. Another device's connections are
/// untouched by either, and so is its count; and nothing of a refused connection is left behind
/// but the refusal.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn with_every_connection_in_use_the_first_above_the_bound_is_refused_and_withdraws_none() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let rights = [ActionRight::FilesUpload, ActionRight::SessionView];
    let device = paired(&host, &owner, &rights).await;
    let neighbour = paired(&host, &owner, &rights).await;
    let more = up_to_the_bound(&device, &host).await;
    // The neighbour holds two connections, well inside its own bound.
    let neighbours_second = neighbour.again(&host).await;
    assert!(is_served(&neighbour.raw).await && is_served(&neighbours_second).await);
    let bound = u32::try_from(DEVICE_LIVE_CONNECTIONS).expect("a small bound");
    assert_eq!(
        host.connections_of(&device.record),
        bound,
        "a bound's worth of connections withdraws nobody"
    );
    let admitted = host.controller().admitted_connections();
    let readings = host.readings_running();

    // Every connection answers, so every one was heard from just now, and the one above the bound
    // is refused.
    for raw in std::iter::once(&device.raw).chain(&more) {
        assert!(
            is_served(raw).await,
            "a connection within the bound is served"
        );
    }
    let refused = device.again(&host).await;
    let refusal = refusal_of(&refused).await.expect("the host says why");
    assert_eq!(refusal.code, ErrorCode::ResourceUnavailable);
    assert_eq!(refusal.retry, kr_protocol::error::RetryCategory::Transient);
    assert!(
        has_ended(&refused).await,
        "the host ends the connection it refused"
    );
    for raw in std::iter::once(&device.raw).chain(&more) {
        assert!(is_served(raw).await, "no connection in use was withdrawn");
    }
    assert_eq!(host.connections_of(&device.record), bound);
    until(|| host.controller().admitted_connections() == admitted).await;
    until(|| host.readings_running() == readings).await;
    assert_eq!(
        host.heard_from_of(&device.record).len(),
        DEVICE_LIVE_CONNECTIONS
    );

    // One connection goes silent and the host's time moves past the silence the host requires; the
    // others answer again, which is hearing from them.
    host.silence_connections_of(&device.record, 5..6);
    host.advance_the_readings(past_the_silence());
    for raw in std::iter::once(&device.raw)
        .chain(&more)
        .enumerate()
        .filter(|(place, _)| *place != 5)
        .map(|(_, raw)| raw)
    {
        assert!(
            is_served(raw).await,
            "a connection that answers is heard from"
        );
    }
    let above = device.again(&host).await;
    assert!(
        is_served(&above).await,
        "the connection above the bound is served"
    );
    until(|| host.connections_of(&device.record) == bound).await;
    let silent = more.get(4).expect("the sixth connection of the device");
    assert!(
        has_ended(silent).await,
        "the silent connection was withdrawn"
    );

    // The device that lost its connection connects again: every other connection was heard from
    // since, so it is refused, and nothing in use is withdrawn for it.
    let again = device.again(&host).await;
    assert_eq!(
        refusal_of(&again).await.map(|error| error.code),
        Some(ErrorCode::ResourceUnavailable),
        "a connection that connects again after a withdrawal is refused, not served at another's cost"
    );
    for raw in std::iter::once(&device.raw)
        .chain(
            more.iter()
                .enumerate()
                .filter(|(place, _)| *place != 4)
                .map(|(_, raw)| raw),
        )
        .chain([&above])
    {
        assert!(is_served(raw).await, "no connection in use was withdrawn");
    }

    assert!(is_served(&neighbour.raw).await && is_served(&neighbours_second).await);
    assert_eq!(host.connections_of(&neighbour.record), 2);
    host.stop().await;
}

/// KR-REQ-23.21: the connections whose packets no longer arrive, which are the copies a lossy path
/// leaves of the links it replaced, are withdrawn before a connection the device still sends on,
/// although that connection is the oldest. Every connection the device still uses sends a request
/// after the copies went quiet, and the host's periodic readings are held, so that only the reading
/// it makes when it chooses can date those packets: they count. One of the copies has a mutation
/// in flight, held before
/// the service's ask: it ends with no answer, and the same action sent on a new connection settles
/// and is made at most once, whether or not the held request committed before it was lost. The
/// copies go in the order they were opened, one for each connection above the bound; the device's
/// other connections stand, and so do another device's. When every connection was heard from at one
/// moment, the one counted first is the one that goes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_copies_a_device_left_are_withdrawn_before_the_oldest_connection_it_still_uses() {
    const COPIES: usize = 4;

    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let rights = [ActionRight::FilesUpload, ActionRight::SessionView];
    let device = paired(&host, &owner, &rights).await;
    let neighbour = paired(&host, &owner, &rights).await;
    let more = up_to_the_bound(&device, &host).await;
    let neighbours_second = neighbour.again(&host).await;
    let bound = u32::try_from(DEVICE_LIVE_CONNECTIONS).expect("a small bound");

    // The copies are the first of the others, so that each is younger than the oldest connection,
    // which is the one the device goes on using. Their packets no longer arrive. The periodic
    // readings are held, so that the reading made at the choice is what dates the requests below,
    // whatever time the case takes.
    host.hold_the_periodic_readings(true);
    host.silence_connections_of(&device.record, 1..COPIES + 1);
    host.advance_the_readings(past_the_silence());
    let action = ActionId::new(kr_ipc::new_uuid());
    let (session_id, _) = an_open_session(&host);
    let create = kr_protocol::transfer::DraftCreateParams {
        environment_id: host.environment_id,
        device_id: Nullable::null(),
        session_id: Nullable::some(session_id),
        application_instance_id: Nullable::null(),
        text: "made once".to_owned(),
    };
    let window = more[0].action_window_id();
    let (held, release) = host.controller().transfer().pause_after_the_outer_check();
    let request = more[0]
        .submit(
            Method::DraftCreate,
            action,
            on_the_session(&host, session_id),
            &create,
        )
        .await;
    arrived(held).await;

    // The device goes on using every connection but the copies, the oldest among them.
    for raw in std::iter::once(&device.raw).chain(&more[COPIES..]) {
        assert!(is_served(raw).await, "a connection in use answers");
    }

    // One connection above the bound for each copy: each is served and withdraws the oldest copy.
    let mut above = Vec::new();
    for _ in 0..COPIES {
        let raw = device.again(&host).await;
        assert!(
            is_served(&raw).await,
            "the connection above the bound is served"
        );
        above.push(raw);
        until(|| host.connections_of(&device.record) == bound).await;
    }
    assert_eq!(
        more[0].answered_before_closing(request, WAIT).await,
        Some(false),
        "the first copy ends with no answer to its held request"
    );
    for copy in &more[1..COPIES] {
        assert!(has_ended(copy).await, "each copy was withdrawn");
    }
    release.send(()).expect("the held request goes on");
    let repeated = above[0]
        .mutate_in(
            window,
            Method::DraftCreate,
            action,
            on_the_session(&host, session_id),
            &create,
        )
        .await;
    assert!(
        repeated.is_ok()
            || matches!(&repeated, Err(error) if error.code == ErrorCode::OutcomeUnknown),
        "the same action on a new connection settles: {repeated:?}"
    );
    let drafts = host
        .controller()
        .transfer()
        .service()
        .open_drafts(&device.actor())
        .expect("the drafts are counted");
    assert!(drafts <= 1, "the action made at most one draft: {drafts}");

    // The oldest connection and every other one stand, and so do the second device's.
    for raw in std::iter::once(&device.raw)
        .chain(&more[COPIES..])
        .chain(&above)
        .chain([&neighbour.raw, &neighbours_second])
    {
        assert!(
            is_served(raw).await,
            "no connection but the copies was withdrawn"
        );
    }
    assert_eq!(host.connections_of(&neighbour.record), 2);

    // Heard from on none of them since one moment, and that moment is further back than the time a
    // connection must be silent: of connections silent since the same moment the one counted later
    // goes, so the oldest connection, which is the one a device has had longest, is the last to
    // go, and a device whose connections are all silent still gets its new one.
    host.silence_connections_of(&device.record, 0..DEVICE_LIVE_CONNECTIONS);
    let stamps = host.heard_from_of(&device.record);
    assert_eq!(stamps.len(), DEVICE_LIVE_CONNECTIONS);
    assert!(
        stamps.iter().all(|stamp| *stamp == stamps[0]),
        "every connection was heard from at the same moment"
    );
    host.advance_the_readings(past_the_silence());
    let last = device.again(&host).await;
    assert!(
        is_served(&last).await,
        "the connection above the bound is served"
    );
    let newest = above.last().expect("the connections above the bound");
    assert!(
        has_ended(newest).await,
        "the connection counted last of those silent since one moment ends"
    );
    assert!(
        is_served(&device.raw).await,
        "the oldest connection stands: equal stamps do not fall to it"
    );
    for raw in more[COPIES..].iter().chain(&above[..COPIES - 1]) {
        assert!(is_served(raw).await, "no other connection was withdrawn");
    }
    host.stop().await;
}

/// KR-REQ-23.21: the main link of a device that sends nothing but keepalives is not withdrawn
/// because the device's other connections, replaced three times inside one keepalive interval with
/// their closes lost, are younger than its last keepalive. The device holds the main link, sixteen
/// links that it uses and copies of the sixteen links' three replacements, all copies silent since
/// after the main link was last heard from. The next replacement is refused: no connection has
/// been silent for longer than the time the host requires. Once that time has passed for the
/// copies, the main link has been heard from again and the links in use answer, and the next
/// connection is served at a copy's cost, the one counted last of them, and no other ends.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_idle_main_link_is_not_withdrawn_for_the_copies_that_followed_its_last_keepalive() {
    const IN_USE: usize = 16;
    const COPIES: usize = DEVICE_LIVE_CONNECTIONS - 1 - IN_USE;

    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let device = paired(&host, &owner, &[ActionRight::SessionView]).await;
    host.hold_the_periodic_readings(true);
    let more = up_to_the_bound(&device, &host).await;

    // The main link was last heard from first; the copies were heard from later and went quiet.
    host.silence_connections_of(&device.record, 0..1);
    host.advance_the_readings(Duration::from_secs(6));
    host.silence_connections_of(&device.record, 1..COPIES + 1);
    for raw in &more[COPIES..] {
        assert!(is_served(raw).await, "a link in use answers");
    }
    let refused = device.again(&host).await;
    assert_eq!(
        refusal_of(&refused).await.map(|error| error.code),
        Some(ErrorCode::ResourceUnavailable),
        "no connection was silent for long enough, so the replacement is refused"
    );
    assert!(
        is_served(&more[COPIES]).await && has_ended(&refused).await,
        "the connections in use stand and the refused one ends"
    );

    // Time passes, the main link sends a keepalive and the links in use answer.
    host.advance_the_readings(past_the_silence());
    host.hear_connections_of(&device.record, 0..1);
    assert!(is_served(&device.raw).await, "the main link is heard from");
    for raw in &more[COPIES..] {
        assert!(is_served(raw).await, "a link in use answers");
    }
    let next = device.again(&host).await;
    assert!(is_served(&next).await, "the next connection is served");
    assert!(
        has_ended(&more[COPIES - 1]).await,
        "the copy counted last was withdrawn"
    );
    assert!(is_served(&device.raw).await, "the main link stands");
    for raw in &more[COPIES..] {
        assert!(is_served(raw).await, "no link in use was withdrawn");
    }
    host.stop().await;
}

/// KR-REQ-23.21: a connection the host refuses costs the device none of its connections. The grant
/// of a device that holds a bound's worth has run out by the wall clock, which the connections it
/// holds were not admitted under, so the host refuses the connection above the bound after it
/// admitted it, and no connection of the device is withdrawn for it; nothing of the refused
/// connection stays in the host's table of admitted connections or in its readings.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_connection_the_host_refuses_above_the_bound_withdraws_none() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let (moved, clocks) = Moved::new();
    let host = Host::start_on_clocks(&owner, clocks).await;
    let device = paired(&host, &owner, &[ActionRight::SessionView]).await;
    let _more = up_to_the_bound(&device, &host).await;
    let bound = u32::try_from(DEVICE_LIVE_CONNECTIONS).expect("a small bound");
    let admitted = host.controller().admitted_connections();
    let readings = host.readings_running();
    moved.past_the_grant_by_utc();

    // The connection is made, and the host ends it once it has read the grant's deadline. A place
    // the admission bucket has not yet returned is tried for again.
    let deadline = tokio::time::Instant::now() + WAIT;
    let refused = loop {
        match RawDevice::admitted(&host, &device.device, &device.record).await {
            Ok(raw) => break raw,
            Err(error) => {
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "the host admits the connection: {error:?}"
                );
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    };
    assert!(
        refused
            .answered_before_closing(RequestId::new(0), WAIT)
            .await
            .is_some(),
        "the host ends a connection of a device whose grant has run out"
    );
    assert_eq!(
        device
            .raw
            .answered_before_closing(RequestId::new(u64::MAX), Duration::from_secs(2))
            .await,
        None,
        "the oldest connection was not withdrawn for a connection that was refused"
    );
    assert_eq!(host.connections_of(&device.record), bound);
    until(|| host.controller().admitted_connections() == admitted).await;
    until(|| host.readings_running() == readings).await;
    host.stop().await;
}

/// KR-REQ-23.21: a device that takes the handshake and then reads nothing leaves nothing of the
/// connection the host refuses once the host's time to tell it why has run out. The device lets the
/// host send fewer bytes on its stream than the refusal is long and reads none, so the host cannot
/// finish the write: it gives the write up, and the connection ends with no entry of it in the
/// host's table of admitted connections and no reading of its packets, and nothing of the device's
/// other connections was withdrawn for it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_that_reads_none_of_its_refusal_leaves_nothing_of_the_connection() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let device = paired(&host, &owner, &[ActionRight::SessionView]).await;
    let more = up_to_the_bound(&device, &host).await;
    let bound = u32::try_from(DEVICE_LIVE_CONNECTIONS).expect("a small bound");
    let admitted = host.controller().admitted_connections();
    let readings = host.readings_running();
    // Every connection answers, so the one above the bound is refused.
    for raw in std::iter::once(&device.raw).chain(&more) {
        assert!(
            is_served(raw).await,
            "a connection within the bound is served"
        );
    }

    let unread = net_support::dial_unread(&host, &device.device, &device.record, 32).await;
    until(|| unread.connection.close_reason().is_some()).await;
    until(|| host.controller().admitted_connections() == admitted).await;
    until(|| host.readings_running() == readings).await;
    assert_eq!(host.connections_of(&device.record), bound);
    for raw in std::iter::once(&device.raw).chain(&more) {
        assert!(is_served(raw).await, "no connection in use was withdrawn");
    }
    drop(unread);
    host.stop().await;
}

/// KR-REQ-23.21 and KR-REQ-19.08: a device that holds nine connections, as the companion does with
/// its main one and one for each of eight open sessions, is answered on every one of them after the
/// ninth is made: the bound is above what the device uses, so nothing it uses is withdrawn.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_holding_nine_connections_is_answered_on_every_one() {
    const HELD: u32 = 9;

    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let device = paired(
        &host,
        &owner,
        &[ActionRight::FilesUpload, ActionRight::SessionView],
    )
    .await;
    // The first connection is the one `paired` opened.
    let mut more = Vec::new();
    for _ in 1..HELD {
        more.push(device.again(&host).await);
    }
    for raw in std::iter::once(&device.raw).chain(&more) {
        assert!(
            is_served(raw).await,
            "every one of {HELD} connections is answered"
        );
    }
    assert_eq!(host.connections_of(&device.record), HELD);
    host.stop().await;
}
