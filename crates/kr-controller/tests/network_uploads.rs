//! A paired device's uploads over real paired connections.
//!
//! A device reserves an upload on its control stream, sends the chunks on an attachment-chunk stream
//! of its own, finishes it on the control stream and reads its state there. The host performs each
//! under the device's own principal.

mod net_support;

use std::time::Duration;

use kr_crypto::keys::DeviceKeys;
use kr_controller::service::net::devices::DeviceRecord;
use kr_protocol::envelope::{ControlFrame, MutationRequest, Outcome, ParamsValue};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::frame::{StreamHeader, StreamKind, StreamResource};
use kr_protocol::ids::{ActionId, ActorId, TransferId};
use kr_protocol::method::Method;
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{Bytes, Digest256, Nullable, U64};
use kr_protocol::transfer::{
    ChunkDescriptor, ChunkLayout, UploadBeginParams, UploadBeginResult, UploadCancelParams,
    UploadCancelResult, UploadChunkParams, UploadChunkResult, UploadFinishParams,
    UploadFinishResult, UploadState, UploadStatusParams, UploadStatusResult,
};
use kr_transport::streams::DataStream;
use net_support::{Device, Host, RawDevice, on_the_host};

/// What a case waits at most for a frame, an answer or a reset. A host that does what the case
/// says answers at once: the bound only ends a case that would hang.
const WAIT: Duration = Duration::from_secs(60);

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

    /// Connects the device again, as a device does that lost a connection.
    async fn again(&self, host: &Host) -> RawDevice {
        let raw = RawDevice::connect(host, &self.device, &self.record).await;
        raw.claim();
        raw
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

fn digest(bytes: &[u8]) -> Digest256 {
    Digest256::from_bytes(kr_cbor::sha256(bytes))
}

fn pattern(len: usize) -> Vec<u8> {
    (0..len)
        .map(|index| u8::try_from((index * 17 + 3) % 251).unwrap_or(0))
        .collect()
}

fn typed<T: kr_protocol::wire::WireMessage>(value: &ParamsValue) -> T {
    value.to_typed().expect("a result of the declared shape")
}

fn chunk_of(bytes: &[u8], index: u64) -> (ChunkDescriptor, Bytes) {
    let layout = ChunkLayout::for_length(bytes.len() as u64);
    let offset = layout.offset_of(index).expect("an index in the layout");
    let len = layout.length_of(index).expect("an index in the layout");
    let start = usize::try_from(offset).expect("an addressable offset");
    let end = start + usize::try_from(len).expect("an addressable length");
    let payload = &bytes[start..end];
    (
        ChunkDescriptor {
            index: U64::new(index),
            byte_len: U64::new(len),
            digest: digest(payload),
        },
        Bytes::new(payload.to_vec()),
    )
}

fn begin_params(host: &Host, bytes: &[u8], name: &str) -> UploadBeginParams {
    UploadBeginParams {
        environment_id: host.environment_id,
        session_id: Nullable::null(),
        device_id: Nullable::null(),
        declared_byte_len: U64::new(bytes.len() as u64),
        declared_digest: digest(bytes),
        declared_media_type: "application/octet-stream".to_owned(),
        original_file_name: name.to_owned(),
    }
}

/// Reserves an upload of `bytes` for the device on `raw`, through the host's door.
async fn begin_at_the_door(
    raw: &RawDevice,
    host: &Host,
    bytes: &[u8],
    name: &str,
) -> UploadBeginResult {
    typed(
        &raw.mutate(
            Method::UploadBegin,
            ActionId::new(kr_ipc::new_uuid()),
            on_the_host(host),
            &begin_params(host, bytes, name),
        )
        .await
        .expect("the host reserves the upload"),
    )
}

async fn status_of(raw: &RawDevice, transfer: TransferId) -> UploadStatusResult {
    typed(
        &raw.read(
            Method::UploadStatus,
            &UploadStatusParams {
                transfer_id: transfer,
            },
        )
        .await
        .expect("the host reads the upload's status"),
    )
}

async fn finish_at_the_door(
    raw: &RawDevice,
    host: &Host,
    transfer: TransferId,
    bytes: &[u8],
) -> UploadFinishResult {
    typed(
        &raw.mutate(
            Method::UploadFinish,
            ActionId::new(kr_ipc::new_uuid()),
            on_the_host(host),
            &UploadFinishParams {
                transfer_id: transfer,
                declared_byte_len: U64::new(bytes.len() as u64),
                declared_digest: digest(bytes),
            },
        )
        .await
        .expect("the host publishes the upload"),
    )
}

fn header(host: &Host, raw: &RawDevice, transfer: TransferId) -> StreamHeader {
    StreamHeader {
        kind: StreamKind::AttachmentChunks,
        connection_id: raw.connection_id(),
        stream_id: Nullable::null(),
        resource: StreamResource {
            environment_id: host.environment_id,
            session_id: Nullable::null(),
            attachment_id: Nullable::null(),
            transfer_id: Nullable::some(transfer),
        },
    }
}

/// The frame that sends chunk `index` of `bytes` as part of `transfer`, on the host's target.
fn chunk_frame(
    host: &Host,
    raw: &RawDevice,
    transfer: TransferId,
    bytes: &[u8],
    index: u64,
) -> ControlFrame {
    let (chunk, payload) = chunk_of(bytes, index);
    raw.mutation_frame_for(
        Method::UploadChunk,
        ActionId::new(kr_ipc::new_uuid()),
        on_the_host(host),
        &UploadChunkParams {
            transfer_id: transfer,
            chunk,
            bytes: payload,
        },
    )
    .1
}

/// Sends every chunk of `bytes` as part of `transfer`, on a stream the device opens for it.
async fn send_every_chunk(host: &Host, raw: &RawDevice, transfer: TransferId, bytes: &[u8]) {
    let mut stream = raw.open_stream(header(host, raw, transfer)).await;
    for index in 0..ChunkLayout::for_length(bytes.len() as u64).chunk_count.get() {
        ask(
            &mut stream,
            &chunk_frame(host, raw, transfer, bytes, index),
        )
        .await
        .expect("the chunk is staged");
    }
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
    match tokio::time::timeout(WAIT, stream.read_message::<ControlFrame>())
        .await
        .expect("the host answers or ends the stream in time")
    {
        Ok(Some(ControlFrame::Response(response))) => match response.outcome {
            Outcome::Ok(value) => Ok(value),
            Outcome::Error(error) => Err(error),
        },
        other => panic!("an answer was expected, and the stream said {other:?}"),
    }
}

/// KR-REQ-23.21 and KR-REQ-14.12: a paired device reserves an upload, sends two full chunks and a
/// short one on a data stream of its own, finishes it, and reads that it is published. The staged
/// bytes are the file's, and the handle carries the digest the file verified against. The control
/// is a file of no bytes, which needs no stream and is published at once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_uploads_a_file_in_three_chunks_on_a_data_stream_and_publishes_it() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let device = paired(&host, &owner, &[ActionRight::FilesUpload]).await;
    let bytes = pattern(2 * kr_protocol::limits::UPLOAD_CHUNK_LEN + 5_000);

    let begun = begin_at_the_door(&device.raw, &host, &bytes, "three.bin").await;
    assert_eq!(begun.layout.chunk_count.get(), 3);
    let transfer = begun.transfer_id;

    let mut stream = device
        .raw
        .open_stream(header(&host, &device.raw, transfer))
        .await;
    for index in 0..3 {
        let answered: UploadChunkResult = typed(
            &ask(
                &mut stream,
                &chunk_frame(&host, &device.raw, transfer, &bytes, index),
            )
            .await
            .expect("the chunk is staged"),
        );
        assert_eq!(answered.index.get(), index);
    }
    let receiving = status_of(&device.raw, transfer).await;
    assert_eq!(receiving.state, UploadState::Receiving);
    assert_eq!(receiving.received_byte_len.get(), bytes.len() as u64);

    let finished = finish_at_the_door(&device.raw, &host, transfer, &bytes).await;
    assert_eq!(finished.handle.content_digest, digest(&bytes));
    assert_eq!(finished.handle.byte_len.get(), bytes.len() as u64);
    let published = status_of(&device.raw, transfer).await;
    assert_eq!(published.state, UploadState::Published);
    assert_eq!(
        published.handle.0.as_ref().map(|handle| handle.transfer_id),
        Some(transfer),
        "the status carries the handle"
    );
    assert_eq!(
        host.controller()
            .transfer()
            .service()
            .staged_byte_len()
            .expect("the staged bytes"),
        bytes.len() as u64,
        "the staged bytes are the file's"
    );

    // The control: a file of no bytes needs no stream.
    let empty = begin_at_the_door(&device.raw, &host, &[], "empty.bin").await;
    assert_eq!(empty.layout.chunk_count.get(), 0);
    let finished = finish_at_the_door(&device.raw, &host, empty.transfer_id, &[]).await;
    assert_eq!(finished.handle.byte_len.get(), 0);
    assert_eq!(
        status_of(&device.raw, empty.transfer_id).await.state,
        UploadState::Published
    );
    device.raw.close();
    host.stop().await;
}

/// The mutation a device would send, composed on `raw` and not sent.
#[cfg(unix)]
fn composed<P: serde::Serialize>(
    raw: &RawDevice,
    host: &Host,
    method: Method,
    params: &P,
) -> MutationRequest {
    match raw
        .mutation_frame_for(
            method,
            ActionId::new(kr_ipc::new_uuid()),
            on_the_host(host),
            params,
        )
        .1
    {
        ControlFrame::Mutation(mutation) => *mutation,
        other => panic!("a mutation was expected: {other:?}"),
    }
}

/// The transfer journal, opened beside the host's own handle on it.
#[cfg(unix)]
fn journal(host: &Host) -> kr_transfer::Store {
    kr_transfer::Store::open(
        kr_transfer::StagingArea::store_path(host.controller().paths()),
        host.environment_id,
    )
    .expect("opens the transfer journal")
}

/// The claim `request` leaves when it is interrupted before it settles: its action, and no result.
#[cfg(unix)]
fn claim_of(
    request: &MutationRequest,
    actor: &ActorId,
    transfer: TransferId,
) -> kr_transfer::store::RetainedAction {
    kr_transfer::store::RetainedAction {
        payload_digest: kr_protocol::digest::mutation_digest(request, actor)
            .expect("digests the mutation"),
        actor_id: actor.clone(),
        action_id: request.action_id.get(),
        method: request.method.as_str().to_owned(),
        subject: Some(transfer),
        result: None,
        failure: None,
        recorded_at_ms: kr_protocol::scalars::TimestampMs::new(kr_ipc::now_ms().get()),
    }
}

/// Commits the claim a finish makes with its publication intent and nothing after it, as an
/// interrupted finish leaves it: the journal says the publication began, and no handle is recorded.
#[cfg(unix)]
fn leave_a_publication_unrecorded(
    host: &Host,
    transfer: TransferId,
    bytes: &[u8],
    name: &str,
    actor: &ActorId,
    finish: &MutationRequest,
) {
    use std::os::unix::fs::MetadataExt as _;

    let staged = host
        .controller()
        .transfer()
        .service()
        .staging()
        .incomplete()
        .display_path()
        .join(
            kr_transfer::StorageName::derive(transfer, name)
                .incomplete()
                .expect("the payload's staged name")
                .as_str(),
        );
    let metadata = std::fs::metadata(&staged).expect("the staged payload is there");
    let claim = claim_of(finish, actor, transfer);
    journal(host)
        .begin_publish(
            transfer,
            &kr_transfer::store::Publication {
                content_digest: digest(bytes),
                payload_identity: kr_transfer::ObjectIdentity {
                    device: metadata.dev(),
                    file_id: metadata.ino(),
                },
                preview: None,
                preview_unavailable: None,
            },
            claim.recorded_at_ms,
            Some(&claim),
        )
        .expect("records the publication and its claim");
}

/// Commits the claim a cancel makes with the close of its upload and nothing after it, as an
/// interrupted cancel leaves it: the upload is closed, its payload and its bytes are still there.
#[cfg(unix)]
fn leave_a_cancellation_unrecorded(
    host: &Host,
    transfer: TransferId,
    actor: &ActorId,
    cancel: &MutationRequest,
) {
    let claim = claim_of(cancel, actor, transfer);
    journal(host)
        .close_upload(
            transfer,
            UploadState::Cancelled,
            None,
            claim.recorded_at_ms,
            Some(&claim),
        )
        .expect("records the close and its claim");
}

/// KR-REQ-14.12: a device that lost the answer to `upload.finish` reads the upload's status and is
/// told it is published, with the handle and one file; the finish asked again, on a replacement
/// connection and under the window the first connection issued, is answered from its record. A
/// finish or a cancel that was interrupted between its two commits is settled by an exact repeat on
/// a replacement connection, whose window admits nothing. The control is a finish and a cancel the
/// host never admitted, which are refused for the window as a first admission is.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_lost_finish_answer_is_resolved_and_an_interrupted_finish_or_cancel_is_settled_on_a_replacement_connection()
 {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let device = paired(&host, &owner, &[ActionRight::FilesUpload]).await;
    let service = host.controller().transfer().service();
    let bytes = pattern(4096);
    let finish_of = |transfer_id| UploadFinishParams {
        transfer_id,
        declared_byte_len: U64::new(bytes.len() as u64),
        declared_digest: digest(&bytes),
    };

    // The answer to a finish is lost: the device asks for the upload's status, and for the finish
    // again, on a connection of its own that never issued the window the finish was sent under.
    let lost = begin_at_the_door(&device.raw, &host, &bytes, "lost.bin")
        .await
        .transfer_id;
    send_every_chunk(&host, &device.raw, lost, &bytes).await;
    let action = ActionId::new(kr_ipc::new_uuid());
    let window = device.raw.action_window_id();
    let finished: UploadFinishResult = typed(
        &device
            .raw
            .mutate(
                Method::UploadFinish,
                action,
                on_the_host(&host),
                &finish_of(lost),
            )
            .await
            .expect("the host publishes the upload"),
    );
    let again = device.again(&host).await;
    let status = status_of(&again, lost).await;
    assert_eq!(status.state, UploadState::Published);
    assert_eq!(status.handle.0.as_ref(), Some(&finished.handle));
    let repeated: UploadFinishResult = typed(
        &again
            .mutate_in(
                window,
                Method::UploadFinish,
                action,
                on_the_host(&host),
                &finish_of(lost),
            )
            .await
            .expect("the repeat is answered from the record"),
    );
    assert_eq!(repeated, finished);
    assert_eq!(
        service.staged_byte_len().expect("the staged bytes"),
        bytes.len() as u64,
        "one file"
    );

    // A finish whose publication began and was never recorded is settled by its exact repeat.
    let claimed = begin_at_the_door(&device.raw, &host, &bytes, "claimed.bin")
        .await
        .transfer_id;
    send_every_chunk(&host, &device.raw, claimed, &bytes).await;
    let finish = composed(
        &device.raw,
        &host,
        Method::UploadFinish,
        &finish_of(claimed),
    );
    leave_a_publication_unrecorded(&host, claimed, &bytes, "claimed.bin", &device.actor(), &finish);
    let settled: UploadFinishResult = typed(
        &again
            .mutate_in(
                finish.action_window_id.clone(),
                Method::UploadFinish,
                finish.action_id,
                on_the_host(&host),
                &finish_of(claimed),
            )
            .await
            .expect("the repeat settles the publication"),
    );
    assert_eq!(settled.handle.transfer_id, claimed);
    assert_eq!(settled.handle.content_digest, digest(&bytes));
    assert_eq!(status_of(&again, claimed).await.state, UploadState::Published);

    // The control: a finish this host never admitted gets no such allowance.
    let never = begin_at_the_door(&device.raw, &host, &bytes, "never.bin")
        .await
        .transfer_id;
    send_every_chunk(&host, &device.raw, never, &bytes).await;
    let unsent = composed(&device.raw, &host, Method::UploadFinish, &finish_of(never));
    let refusal = again
        .mutate_in(
            unsent.action_window_id.clone(),
            Method::UploadFinish,
            unsent.action_id,
            on_the_host(&host),
            &finish_of(never),
        )
        .await
        .expect_err("a finish this host never admitted");
    assert_eq!(refusal.code, ErrorCode::PermissionDenied, "{refusal:?}");
    assert_eq!(status_of(&again, never).await.state, UploadState::Receiving);

    // A cancel whose upload was closed and whose payload is still held is settled the same way,
    // and releases the bytes the upload reserved.
    let closed = begin_at_the_door(&device.raw, &host, &bytes, "closed.bin")
        .await
        .transfer_id;
    let cancel_params = UploadCancelParams {
        transfer_id: closed,
    };
    let cancel = composed(&device.raw, &host, Method::UploadCancel, &cancel_params);
    leave_a_cancellation_unrecorded(&host, closed, &device.actor(), &cancel);
    let charged = service.staged_byte_len().expect("the staged bytes");
    let released: UploadCancelResult = typed(
        &again
            .mutate_in(
                cancel.action_window_id.clone(),
                Method::UploadCancel,
                cancel.action_id,
                on_the_host(&host),
                &cancel_params,
            )
            .await
            .expect("the repeat settles the cancellation"),
    );
    assert_eq!(released.state, UploadState::Cancelled);
    assert_eq!(released.released_byte_len.get(), bytes.len() as u64);
    assert_eq!(
        service.staged_byte_len().expect("the staged bytes"),
        charged - bytes.len() as u64,
        "the cancelled upload's bytes are released"
    );

    let kept = begin_at_the_door(&device.raw, &host, &bytes, "kept.bin")
        .await
        .transfer_id;
    let kept_params = UploadCancelParams { transfer_id: kept };
    let unsent = composed(&device.raw, &host, Method::UploadCancel, &kept_params);
    let refusal = again
        .mutate_in(
            unsent.action_window_id.clone(),
            Method::UploadCancel,
            unsent.action_id,
            on_the_host(&host),
            &kept_params,
        )
        .await
        .expect_err("a cancel this host never admitted");
    assert_eq!(refusal.code, ErrorCode::PermissionDenied, "{refusal:?}");
    assert_eq!(status_of(&again, kept).await.state, UploadState::Receiving);
    again.close();
    device.raw.close();
    host.stop().await;
}
