//! A paired device's uploads over real paired connections.
//!
//! A device reserves an upload on its control stream, sends the chunks on an attachment-chunk stream
//! of its own, finishes it on the control stream and reads its state there. The host performs each
//! under the device's own principal.

mod net_support;

use std::time::Duration;

use kr_crypto::keys::DeviceKeys;
use kr_protocol::envelope::{ControlFrame, Outcome, ParamsValue};
use kr_protocol::error::ProtocolError;
use kr_protocol::frame::{StreamHeader, StreamKind, StreamResource};
use kr_protocol::ids::{ActionId, TransferId};
use kr_protocol::method::Method;
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{Bytes, Digest256, Nullable, U64};
use kr_protocol::transfer::{
    ChunkDescriptor, ChunkLayout, UploadBeginParams, UploadBeginResult, UploadChunkParams,
    UploadChunkResult, UploadFinishParams, UploadFinishResult, UploadState, UploadStatusParams,
    UploadStatusResult,
};
use kr_transport::streams::DataStream;
use net_support::{Device, Host, RawDevice, on_the_host};

/// What a case waits at most for a frame, an answer or a reset. A host that does what the case
/// says answers at once: the bound only ends a case that would hang.
const WAIT: Duration = Duration::from_secs(60);

/// A paired device, its record and its connection.
struct Paired {
    /// Held so that the device's endpoint stays up as long as its connection.
    _device: Device,
    raw: RawDevice,
}

async fn paired(host: &Host, owner: &DeviceKeys, rights: &[ActionRight]) -> Paired {
    let device = Device::create().await;
    let record = net_support::pair_with(host, &device, owner, net_support::proposal(rights)).await;
    let raw = RawDevice::connect(host, &device, &record).await;
    raw.claim();
    Paired {
        _device: device,
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
