//! A paired device's uploads over real paired connections.
//!
//! A device reserves an upload on its control stream, sends the chunks on an attachment-chunk stream
//! of its own, finishes it on the control stream and reads its state there. The host performs each
//! under the device's own principal.

mod net_support;

use std::task::Poll;
use std::time::Duration;

use kr_controller::service::net::devices::DeviceRecord;
use kr_crypto::keys::DeviceKeys;
use kr_protocol::envelope::{ActionTarget, ControlFrame, MutationRequest, Outcome, ParamsValue};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::frame::{StreamHeader, StreamKind, StreamResource};
use kr_protocol::ids::{ActionId, ActorId, SessionId, TransferId};
use kr_protocol::method::Method;
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{Bytes, Digest256, Nullable, U64};
use kr_protocol::session::SessionOpenParams;
use kr_protocol::transfer::{
    ChunkDescriptor, ChunkLayout, UploadBeginParams, UploadBeginResult, UploadCancelParams,
    UploadCancelResult, UploadChunkParams, UploadChunkResult, UploadFinishParams,
    UploadFinishResult, UploadState, UploadStatusParams, UploadStatusResult,
};
use kr_transfer::store::{Limits, UploadRow};
use kr_transport::streams::DataStream;
use net_support::worker::Adopted;
use net_support::{Device, Host, Moved, RawDevice, on_the_host, on_the_session};

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
    chunk_frame_on(raw, on_the_host(host), transfer, bytes, index)
}

/// The frame that sends chunk `index` of `bytes` as part of `transfer`, on `target`.
fn chunk_frame_on(
    raw: &RawDevice,
    target: ActionTarget,
    transfer: TransferId,
    bytes: &[u8],
    index: u64,
) -> ControlFrame {
    let (chunk, payload) = chunk_of(bytes, index);
    raw.mutation_frame_for(
        Method::UploadChunk,
        ActionId::new(kr_ipc::new_uuid()),
        target,
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
    for index in 0..ChunkLayout::for_length(bytes.len() as u64)
        .chunk_count
        .get()
    {
        ask(&mut stream, &chunk_frame(host, raw, transfer, bytes, index))
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
    leave_a_publication_unrecorded(
        &host,
        claimed,
        &bytes,
        "claimed.bin",
        &device.actor(),
        &finish,
    );
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
    assert_eq!(
        status_of(&again, claimed).await.state,
        UploadState::Published
    );

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

/// KR-REQ-23.21: a device that reserves an upload is shown the bytes its own principal has staged,
/// and a retained copy of the answer shows the same; the refusal for the environment's bytes names
/// the environment's limit and no other principal's total. The control is the person at this
/// machine, who is told what is staged.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_is_shown_its_own_bytes_and_a_quota_refusal_names_no_ones_total() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let device = paired(&host, &owner, &[ActionRight::FilesUpload]).await;
    let other = paired(&host, &owner, &[ActionRight::FilesUpload]).await;
    let service = host.controller().transfer().service();
    service
        .set_limits(Limits {
            max_staged_len: 10_000,
            ..Limits::default()
        })
        .expect("sets the limits");
    let the_owner = ActorId::new("local:501").expect("the owner's principal");
    service
        .upload_begin(
            &the_owner,
            &begin_params(&host, &[1; 2_345], "owners.bin"),
            None,
            None,
        )
        .expect("the owner stages 2,345 bytes");
    begin_at_the_door(&other.raw, &host, &[2; 3_000], "theirs.bin").await;

    let params = begin_params(&host, &[3; 1_000], "mine.bin");
    let action = ActionId::new(kr_ipc::new_uuid());
    let target = on_the_host(&host);
    let first: UploadBeginResult = typed(
        &device
            .raw
            .mutate(Method::UploadBegin, action, target.clone(), &params)
            .await
            .expect("the device begins"),
    );
    assert_eq!(first.staged_byte_len.get(), 1_000, "its own bytes");
    assert_eq!(first.staged_byte_limit.get(), 10_000);
    begin_at_the_door(&other.raw, &host, &[4; 100], "more.bin").await;
    let repeated: UploadBeginResult = typed(
        &device
            .raw
            .mutate(Method::UploadBegin, action, target, &params)
            .await
            .expect("the repeat is answered from the record"),
    );
    assert_eq!(repeated, first, "a retained copy shows the same");

    // 2,345 + 3,000 + 100 + 1,000 are staged: 6,445 bytes, of which the device holds 1,000.
    let refused: ProtocolError = device
        .raw
        .mutate(
            Method::UploadBegin,
            ActionId::new(kr_ipc::new_uuid()),
            on_the_host(&host),
            &begin_params(&host, &[5; 5_000], "big.bin"),
        )
        .await
        .expect_err("the environment has no room");
    assert_eq!(refused.code, ErrorCode::QuotaExceeded, "{refused:?}");
    assert!(refused.message.contains("10000"), "{refused:?}");
    for number in ["6445", "2345", "3000"] {
        assert!(
            !refused.message.contains(number),
            "the refusal names no one's total ({number}): {refused:?}"
        );
    }
    let told = service
        .upload_begin(
            &the_owner,
            &begin_params(&host, &[5; 5_000], "owners-big.bin"),
            None,
            None,
        )
        .expect_err("the owner is refused too")
        .to_string();
    assert!(told.contains("6445"), "the owner is told the total: {told}");
    device.raw.close();
    other.raw.close();
    host.stop().await;
}

/// One published upload of no bytes, recorded in the journal as a finished upload of `actor`'s.
fn a_published_upload(host: &Host, actor: &ActorId) -> UploadRow {
    let now = kr_protocol::scalars::TimestampMs::new(kr_ipc::now_ms().get());
    UploadRow {
        transfer_id: TransferId::new(kr_ipc::new_uuid()),
        environment_id: host.environment_id,
        session_id: None,
        device_id: None,
        actor_id: actor.clone(),
        declared_byte_len: 0,
        declared_digest: digest(&[]),
        declared_media_type: "application/octet-stream".to_owned(),
        original_file_name: "kept.bin".to_owned(),
        stored_name: "kept.bin".to_owned(),
        state: UploadState::Published,
        invalid_reason: None,
        reserved_byte_len: 0,
        content_digest: Some(digest(&[])),
        payload_identity: None,
        cleanup_pending: false,
        preview: None,
        preview_unavailable: None,
        created_at_ms: now,
        expires_at_ms: kr_protocol::scalars::TimestampMs::new(now.get() + 7 * 24 * 60 * 60 * 1000),
        published_at_ms: Some(now),
        submitted_at_ms: None,
    }
}

/// KR-REQ-23.21: a device keeps at most `DEVICE_STAGED_UPLOADS` uploads staged. The next reservation
/// is refused with the quota code, in words that name the bound and how a place is freed; a cancel
/// of an upload that is still receiving frees a place; another device is unaffected.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_keeps_at_most_the_bound_of_staged_uploads_and_a_cancel_frees_a_place() {
    let bound = kr_controller::transfer::DEVICE_STAGED_UPLOADS;
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let device = paired(&host, &owner, &[ActionRight::FilesUpload]).await;
    let other = paired(&host, &owner, &[ActionRight::FilesUpload]).await;
    {
        let mut journal = journal(&host);
        for _ in 1..bound {
            journal
                .insert_upload(&a_published_upload(&host, &device.actor()), None)
                .expect("records the upload");
        }
    }

    let last = begin_at_the_door(&device.raw, &host, &[1; 64], "last.bin").await;
    let refused: ProtocolError = device
        .raw
        .mutate(
            Method::UploadBegin,
            ActionId::new(kr_ipc::new_uuid()),
            on_the_host(&host),
            &begin_params(&host, &[2; 64], "over.bin"),
        )
        .await
        .expect_err("the device keeps as many uploads as it may");
    assert_eq!(refused.code, ErrorCode::QuotaExceeded, "{refused:?}");
    assert!(
        refused.message.contains(&format!("{bound} of the {bound}"))
            && refused
                .message
                .contains("cancel an upload that is still receiving"),
        "the refusal names the bound and how a place is freed: {refused:?}"
    );

    begin_at_the_door(&other.raw, &host, &[3; 64], "theirs.bin").await;
    let cancelled: UploadCancelResult = typed(
        &device
            .raw
            .mutate(
                Method::UploadCancel,
                ActionId::new(kr_ipc::new_uuid()),
                on_the_host(&host),
                &UploadCancelParams {
                    transfer_id: last.transfer_id,
                },
            )
            .await
            .expect("cancels the upload that is still receiving"),
    );
    assert_eq!(cancelled.state, UploadState::Cancelled);
    begin_at_the_door(&device.raw, &host, &[4; 64], "again.bin").await;
    device.raw.close();
    other.raw.close();
    host.stop().await;
}

/// Reads the next frame the host sent on a stream: an answer, or why there is none.
async fn next(stream: &mut DataStream) -> std::result::Result<Option<ControlFrame>, String> {
    tokio::time::timeout(WAIT, stream.read_message::<ControlFrame>())
        .await
        .expect("the host answers or ends the stream in time")
        .map_err(|error| format!("{error:?}"))
}

/// Whether the host took the stream away: a reset, and not a clean end or an answer.
async fn reset(stream: &mut DataStream) {
    match next(stream).await {
        Err(_) => {}
        other => panic!("the stream was to be reset, and it said {other:?}"),
    }
}

/// What the host did with a frame the case wrote: its answer, or `None` when it ended the stream
/// without one.
async fn answer_or_end(
    stream: &mut DataStream,
) -> Option<std::result::Result<ParamsValue, ProtocolError>> {
    match next(stream).await {
        Ok(Some(ControlFrame::Response(response))) => Some(match response.outcome {
            Outcome::Ok(value) => Ok(value),
            Outcome::Error(error) => Err(error),
        }),
        Ok(Some(other)) => panic!("an answer was expected, and the stream said {other:?}"),
        Ok(None) | Err(_) => None,
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

/// How many bytes of the upload are staged and verified, read from the service.
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

/// Opens the connection on `raw` for `session`, or for the host alone.
async fn open_for(raw: &RawDevice, session: Option<SessionId>) {
    raw.read(
        Method::SessionOpen,
        &SessionOpenParams {
            session_id: Nullable(session),
            grant_id: Nullable::null(),
        },
    )
    .await
    .expect("the connection is opened");
}

/// Reserves an upload of `bytes` bound to `session`, through the host's door.
async fn begin_in_session(
    raw: &RawDevice,
    host: &Host,
    session: SessionId,
    bytes: &[u8],
) -> TransferId {
    let mut params = begin_params(host, bytes, "scoped.bin");
    params.session_id = Nullable::some(session);
    typed::<UploadBeginResult>(
        &raw.mutate(
            Method::UploadBegin,
            ActionId::new(kr_ipc::new_uuid()),
            on_the_session(host, session),
            &params,
        )
        .await
        .expect("the host reserves the upload in the session"),
    )
    .transfer_id
}

/// KR-REQ-23.21 and KR-REQ-23.41: a stream is held to the session its connection was opened for. A
/// header for an upload bound to a session is reset on a connection opened for another session, with
/// nothing staged; the control is the connection opened for that session, whose chunk is staged. The
/// sessions are two the daemon serves through workers.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_header_for_a_session_the_connection_is_not_opened_for_is_reset() {
    let adopted = Adopted::start(2).await;
    let host = &adopted.host;
    let session = adopted.workers[0].session_id;
    let another = adopted.workers[1].session_id;
    let device = paired(
        host,
        &adopted.owner,
        &[ActionRight::FilesUpload, ActionRight::SessionView],
    )
    .await;
    let to_another = device.again(host).await;
    open_for(&device.raw, Some(session)).await;
    open_for(&to_another, Some(another)).await;

    let bytes = [9_u8; 96];
    let upload = begin_in_session(&device.raw, host, session, &bytes).await;
    let mut stream = to_another
        .open_stream(header(host, &to_another, upload))
        .await;
    reset(&mut stream).await;
    assert_eq!(received(host, &device.actor(), upload), 0);

    let mut stream = device
        .raw
        .open_stream(header(host, &device.raw, upload))
        .await;
    let frame = chunk_frame_on(
        &device.raw,
        on_the_session(host, session),
        upload,
        &bytes,
        0,
    );
    ask(&mut stream, &frame)
        .await
        .expect("the connection opened for the upload's session is served");
    assert_eq!(received(host, &device.actor(), upload), 96);
    device.raw.close();
    to_another.close();
    adopted.stop().await;
}

/// Begins an upload of `bytes` through the door, holds its one chunk at the transfer service's
/// first pause, runs `meanwhile`, releases the chunk, and says what the host did with it.
async fn hold_a_chunk_while(
    host: &Host,
    device: &Paired,
    bytes: &[u8],
    meanwhile: impl FnOnce(),
) -> (
    TransferId,
    Option<std::result::Result<ParamsValue, ProtocolError>>,
    DataStream,
) {
    let transfer = begin_at_the_door(&device.raw, host, bytes, "held.bin")
        .await
        .transfer_id;
    let (held, release) = host.controller().transfer().pause_after_the_outer_check();
    let mut stream = device
        .raw
        .open_stream(header(host, &device.raw, transfer))
        .await;
    stream
        .write_message(&chunk_frame(host, &device.raw, transfer, bytes, 0))
        .await
        .expect("the frame is written");
    arrived(held).await;
    meanwhile();
    release.send(()).expect("the chunk goes on");
    let answered = answer_or_end(&mut stream).await;
    host.network()
        .until_no_chunk_is_in_the_service(device.record.device_id, transfer)
        .await;
    (transfer, answered, stream)
}

/// KR-REQ-23.21 and KR-REQ-23.41: a device revoked while its header's lookup runs has the stream
/// reset, with nothing staged: the header is admitted against the registration as it stands when the
/// lookup ends. The control is the same hold, released with the device standing, whose chunk is staged.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_revoked_while_its_header_is_looked_up_has_the_stream_reset() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let device = paired(&host, &owner, &[ActionRight::FilesUpload]).await;
    let bytes = [8_u8; 96];
    let kept = begin_at_the_door(&device.raw, &host, &bytes, "kept.bin")
        .await
        .transfer_id;
    let lost = begin_at_the_door(&device.raw, &host, &bytes, "lost.bin")
        .await
        .transfer_id;

    let (arrivals, release) = host.controller().transfer().hold_the_stream_lookups();
    let mut stream = device
        .raw
        .open_stream(header(&host, &device.raw, kept))
        .await;
    arrived(arrivals).await;
    release.release();
    ask(
        &mut stream,
        &chunk_frame(&host, &device.raw, kept, &bytes, 0),
    )
    .await
    .expect("a header whose lookup ended with the device standing is served");
    assert_eq!(received(&host, &device.actor(), kept), 96);

    let (arrivals, release) = host.controller().transfer().hold_the_stream_lookups();
    let mut stream = device
        .raw
        .open_stream(header(&host, &device.raw, lost))
        .await;
    arrived(arrivals).await;
    host.network()
        .revoke_device(device.record.device_id)
        .await
        .expect("the device is revoked");
    release.release();
    assert!(
        !matches!(next(&mut stream).await, Ok(Some(_))),
        "the stream of a revoked device is taken away"
    );
    host.stop().await;
}

/// KR-REQ-23.21 and KR-REQ-23.41: a grant that runs out while a chunk is held between the door's
/// check and the service keeps the chunk from being staged. The control is the same hold with the
/// grant standing, whose chunk is staged.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_grant_that_ends_while_a_chunk_is_held_keeps_it_from_being_staged() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let (moved, clocks) = Moved::new();
    let host = Host::start_on_clocks(&owner, clocks).await;
    let device = paired(&host, &owner, &[ActionRight::FilesUpload]).await;
    let bytes = [3_u8; 96];

    let (kept, answered, _stream) = hold_a_chunk_while(&host, &device, &bytes, || {}).await;
    answered
        .expect("the host answers")
        .expect("a chunk held while the grant stands is staged");
    assert_eq!(received(&host, &device.actor(), kept), 96);

    let (lost, answered, _stream) =
        hold_a_chunk_while(&host, &device, &bytes, || moved.past_the_grant()).await;
    if let Some(answer) = answered {
        let refused = answer.expect_err("a chunk held while the grant ends is refused");
        assert_eq!(refused.code, ErrorCode::PermissionDenied, "{refused:?}");
    }
    assert_eq!(received(&host, &device.actor(), lost), 0);
    host.stop().await;
}

/// KR-REQ-23.21 and KR-REQ-23.41: a chunk whose action window runs out while it is held between the
/// door's check and the service is refused at the service for the deadline it was admitted under,
/// with the grant standing, and nothing is staged. The control is the same hold with the window
/// standing, whose chunk is staged.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_window_that_lapses_while_a_chunk_is_held_keeps_it_from_being_staged() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let (moved, clocks) = Moved::new();
    let host = Host::start_on_clocks(&owner, clocks).await;
    let device = paired(&host, &owner, &[ActionRight::FilesUpload]).await;
    let bytes = [3_u8; 96];

    let (kept, answered, _stream) = hold_a_chunk_while(&host, &device, &bytes, || {}).await;
    answered
        .expect("the host answers")
        .expect("a chunk held while its window stands is staged");
    assert_eq!(received(&host, &device.actor(), kept), 96);

    let (lost, answered, _stream) = hold_a_chunk_while(&host, &device, &bytes, || {
        moved.advance(Duration::from_secs(60 * 60));
    })
    .await;
    let refused = answered
        .expect("the device is told")
        .expect_err("a chunk held past its deadline is refused");
    assert_eq!(refused.code, ErrorCode::PermissionDenied, "{refused:?}");
    assert!(refused.message.contains("deadline"), "{refused:?}");
    assert_eq!(received(&host, &device.actor(), lost), 0);
    host.stop().await;
}

/// KR-REQ-23.21 and KR-REQ-23.41: a fence owed while a chunk is held between the door's check and
/// the service refuses the chunk and ends the stream, with nothing staged; once the debt is paid the
/// device's next stream is served. The control is the same hold with no debt.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_fence_owed_while_a_chunk_is_held_refuses_it_and_ends_the_stream() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let device = paired(&host, &owner, &[ActionRight::FilesUpload]).await;
    let bytes = [4_u8; 96];

    let (kept, answered, _stream) = hold_a_chunk_while(&host, &device, &bytes, || {}).await;
    answered
        .expect("the host answers")
        .expect("a chunk held with no fence owed is staged");
    assert_eq!(received(&host, &device.actor(), kept), 96);

    let controller = host.controller();
    let (owed, answered, mut stream) =
        hold_a_chunk_while(&host, &device, &bytes, || controller.hold_fence(true)).await;
    let refused = answered
        .expect("the device is told")
        .expect_err("a chunk held while a fence is owed is refused");
    assert_eq!(refused.code, ErrorCode::PermissionDenied, "{refused:?}");
    assert!(
        !matches!(next(&mut stream).await, Ok(Some(_))),
        "the stream ends after the refusal"
    );
    controller.hold_fence(false);
    assert_eq!(received(&host, &device.actor(), owed), 0);

    let mut again = device
        .raw
        .open_stream(header(&host, &device.raw, owed))
        .await;
    ask(
        &mut again,
        &chunk_frame(&host, &device.raw, owed, &bytes, 0),
    )
    .await
    .expect("once the debt is paid the device's next stream is served");
    assert_eq!(received(&host, &device.actor(), owed), 96);
    device.raw.close();
    host.stop().await;
}

/// KR-REQ-23.21: a chunk that the service refused at its ask because its stream was replaced left
/// nothing behind, so the exact repeat of it (same action, same window) on the replacing stream is a
/// first attempt: it is staged and answered as one. The upload's status shows both chunks.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_exact_repeat_of_a_chunk_refused_for_its_replaced_stream_is_staged() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let device = paired(&host, &owner, &[ActionRight::FilesUpload]).await;
    let bytes = pattern(kr_protocol::limits::UPLOAD_CHUNK_LEN + 100);
    let transfer = begin_at_the_door(&device.raw, &host, &bytes, "replaced.bin")
        .await
        .transfer_id;
    let first = chunk_frame(&host, &device.raw, transfer, &bytes, 0);
    let second = chunk_frame(&host, &device.raw, transfer, &bytes, 1);

    let (held, release) = host.controller().transfer().pause_after_the_outer_check();
    let mut older = device
        .raw
        .open_stream(header(&host, &device.raw, transfer))
        .await;
    older
        .write_message(&first)
        .await
        .expect("the first chunk is written");
    arrived(held).await;
    // The newer stream replaces the older, and its frame waits at the transfer's gate behind the
    // older's chunk, which is refused at the service's ask once it is released.
    let mut waits = host.network().chunk_gate_waits();
    let mut newer = device
        .raw
        .open_stream(header(&host, &device.raw, transfer))
        .await;
    newer
        .write_message(&second)
        .await
        .expect("the second chunk is written");
    tokio::time::timeout(WAIT, waits.wait_for(|waits| *waits >= 1))
        .await
        .expect("the newer frame finds the gate held")
        .expect("the count stays open");
    release.send(()).expect("the older chunk goes on");
    answer_or_end(&mut newer)
        .await
        .expect("the newer stream is answered")
        .expect("the newer stream's chunk is staged");
    assert_eq!(received(&host, &device.actor(), transfer), 100);

    ask(&mut newer, &first)
        .await
        .expect("the exact repeat is a first attempt: the refusal left nothing of it");
    let status = status_of(&device.raw, transfer).await;
    assert_eq!(
        status.received_byte_len.get(),
        kr_protocol::limits::UPLOAD_CHUNK_LEN as u64 + 100
    );
    drop(older);
    device.raw.close();
    host.stop().await;
}

/// KR-REQ-23.21: a chunk that the service refused at its ask because its connection was lost may or
/// may not have been carried out as far as the host can say, and a replacement connection is not
/// where it settles a chunk: the exact repeat there is told `OUTCOME_UNKNOWN`, and stages nothing. The
/// device reads the upload's status, which shows what is staged, and sends the chunk again as a new
/// action, which is staged.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_exact_repeat_of_a_chunk_refused_for_its_lost_connection_is_told_the_outcome_is_unknown()
{
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let device = paired(&host, &owner, &[ActionRight::FilesUpload]).await;
    let bytes = [6_u8; 96];
    let transfer = begin_at_the_door(&device.raw, &host, &bytes, "lost.bin")
        .await
        .transfer_id;
    let frame = chunk_frame(&host, &device.raw, transfer, &bytes, 0);

    let (held, release) = host.controller().transfer().pause_after_the_outer_check();
    let mut stream = device
        .raw
        .open_stream(header(&host, &device.raw, transfer))
        .await;
    stream
        .write_message(&frame)
        .await
        .expect("the chunk is written");
    arrived(held).await;
    let mut ended = host.network().chunk_tasks_ended();
    device.raw.close();
    tokio::time::timeout(WAIT, ended.wait_for(|ended| *ended >= 1))
        .await
        .expect("the lost connection's stream task ends")
        .expect("the count stays open");
    release.send(()).expect("the chunk goes on");
    host.network()
        .until_no_chunk_is_in_the_service(device.record.device_id, transfer)
        .await;
    assert_eq!(received(&host, &device.actor(), transfer), 0);

    let again = device.again(&host).await;
    let mut stream = again.open_stream(header(&host, &again, transfer)).await;
    let told = ask(&mut stream, &frame)
        .await
        .expect_err("the exact repeat on the replacement connection is not served");
    assert_eq!(told.code, ErrorCode::OutcomeUnknown, "{told:?}");
    assert_eq!(status_of(&again, transfer).await.received_byte_len.get(), 0);

    ask(
        &mut stream,
        &chunk_frame(&host, &again, transfer, &bytes, 0),
    )
    .await
    .expect("the chunk sent again as a new action is staged");
    assert_eq!(
        status_of(&again, transfer).await.received_byte_len.get(),
        96
    );
    again.close();
    host.stop().await;
}

/// KR-REQ-23.21: a stream whose peer writes past the credit stalls on its own, and the upload's
/// status is still read on the control stream, with the bitmap of what is staged: nothing, while the
/// first chunk is held; the held chunk once it is released. The control is the same read with nothing
/// held.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stalled_chunk_stream_leaves_the_upload_status_readable_with_its_bitmap() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let device = paired(&host, &owner, &[ActionRight::FilesUpload]).await;
    let whole = vec![5_u8; 4 * 1024 * 1024];
    let transfer = begin_at_the_door(&device.raw, &host, &whole, "big.bin")
        .await
        .transfer_id;
    let nothing_staged = |status: &UploadStatusResult| {
        status.state == UploadState::Receiving
            && status.received_byte_len.get() == 0
            && status
                .received_chunks
                .as_slice()
                .iter()
                .all(|byte| *byte == 0)
    };
    assert!(nothing_staged(&status_of(&device.raw, transfer).await));

    let (held, release) = host.controller().transfer().pause_after_the_outer_check();
    let mut stream = device
        .raw
        .open_stream(header(&host, &device.raw, transfer))
        .await;
    stream
        .write_message(&chunk_frame(&host, &device.raw, transfer, &whole, 0))
        .await
        .expect("the first chunk is written");
    arrived(held).await;

    // Further frames are written until a write is pending, by the sizes.
    let mut idle = Some(stream);
    let mut stalled = None;
    for index in 1..4 {
        let frame = chunk_frame(&host, &device.raw, transfer, &whole, index);
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
    let status = status_of(&device.raw, transfer).await;
    assert!(
        nothing_staged(&status),
        "the held chunk is not staged, and the bitmap says so: {status:?}"
    );
    assert!(
        matches!(poll_once(&mut stalled).await, Poll::Pending),
        "the stalled write is still pending after the status was read"
    );
    drop(stalled);
    release.send(()).expect("the chunk goes on");
    host.network()
        .until_no_chunk_is_in_the_service(device.record.device_id, transfer)
        .await;
    let status = status_of(&device.raw, transfer).await;
    assert!(
        status.received_byte_len.get() >= 1024 * 1024
            && status
                .received_chunks
                .as_slice()
                .iter()
                .any(|byte| *byte != 0),
        "the released chunk is staged, and the bitmap says so: {status:?}"
    );
    device.raw.close();
    host.stop().await;
}

/// KR-REQ-23.21 and KR-REQ-23.41: an upload that no session holds is read under the pairing grant,
/// and one that a draft for a session binds while the read is in flight is not shown under that
/// decision: the device is told the answer is not shown, reads again, and is decided over the
/// session the upload is bound to now. The control is the same read with nothing bound.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_upload_bound_to_a_session_while_its_status_is_read_is_not_shown() {
    let adopted = Adopted::start(1).await;
    let host = &adopted.host;
    let session = adopted.workers[0].session_id;
    let device = paired(
        host,
        &adopted.owner,
        &[ActionRight::FilesUpload, ActionRight::SessionView],
    )
    .await;
    let bytes = [2_u8; 96];
    let transfer = begin_at_the_door(&device.raw, host, &bytes, "bound.bin")
        .await
        .transfer_id;
    assert_eq!(
        status_of(&device.raw, transfer).await.state,
        UploadState::Receiving,
        "with nothing bound the status is answered under the pairing grant"
    );

    let (arrived, go) = host.pause_retained_lookup();
    let request = UploadStatusParams {
        transfer_id: transfer,
    };
    let reading = device.raw.read(Method::UploadStatus, &request);
    tokio::pin!(reading);
    tokio::select! {
        arrived = tokio::time::timeout(WAIT, arrived) => {
            arrived
                .expect("the read reaches its end check")
                .expect("the pause is armed");
        }
        early = &mut reading => panic!("the read was answered before its end check: {early:?}"),
    }
    let database = rusqlite::Connection::open(kr_transfer::StagingArea::store_path(
        host.controller().paths(),
    ))
    .expect("opens the transfer journal");
    let bound = database
        .execute(
            "UPDATE uploads SET session_id = ?2 WHERE transfer_id = ?1 AND session_id IS NULL",
            rusqlite::params![
                transfer.get().as_bytes().to_vec(),
                session.get().as_bytes().to_vec()
            ],
        )
        .expect("binds the upload to the session");
    assert_eq!(bound, 1, "the upload had no session");
    go.send(()).expect("the read goes on");
    let told = reading
        .await
        .expect_err("a status read under the decision for no session is not shown");
    assert_eq!(told.code, ErrorCode::OutcomeUnknown, "{told:?}");

    assert_eq!(
        status_of(&device.raw, transfer).await.state,
        UploadState::Receiving,
        "read again, it is decided over the session it is bound to now"
    );
    device.raw.close();
    adopted.stop().await;
}
