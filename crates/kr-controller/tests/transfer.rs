//! The transfer methods through the real control daemon, on both of its endpoints.
//!
//! Requirement rows closed here: KR-REQ-14.07 (the seven methods, dispatched through the daemon's
//! own admission path), KR-REQ-14.12 (a lost reply resolved from the retained record),
//! KR-REQ-23.41 (draft and media methods under the daemon's authority) and KR-REQ-24.09 (resumable
//! by identifier).
//!
//! These run the real endpoints, the real handshake, the real envelope checks and the real store.
//! A 1 MiB chunk does not fit a control frame, so the chunk traffic runs on the attachment-chunk
//! endpoint, which is the whole reason that endpoint exists.

use std::sync::Arc;

use kr_controller::service::{Controller, ControllerSetup};
use kr_controller::supervision::{LaunchOutcome, WorkerLaunch, WorkerSupervisor};
use kr_crypto::store::open_store;
use kr_ipc::client::LocalClient;
use kr_ipc::endpoint::Listener;
use kr_ipc::verify::{CONTROLLER_SECRET_SERVICE, ControllerIdentity};
use kr_protocol::envelope::{ActionTarget, ParamsValue};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::frame::StreamKind;
use kr_protocol::ids::{ActionId, BuildId, EnvironmentId, SessionEpoch, SessionId, TransferId};
use kr_protocol::limits::UPLOAD_CHUNK_LEN;
use kr_protocol::local::LocalClientKind;
use kr_protocol::method::Method;
use kr_protocol::scalars::{Bytes, Digest256, Nullable, U64};
use kr_protocol::transfer::{
    ChunkBitmap, ChunkDescriptor, ChunkLayout, DownloadBeginParams, DownloadBeginResult,
    DownloadSource, DraftCreateParams, DraftCreateResult, UploadBeginParams, UploadBeginResult,
    UploadFinishParams, UploadFinishResult, UploadState, UploadStatusParams, UploadStatusResult,
};
use kr_transfer::chunks::{ChunkChannel, chunk_endpoint};

/// A supervisor that starts nothing. These tests create no sessions.
#[derive(Debug)]
struct RefusingSupervisor;

impl WorkerSupervisor for RefusingSupervisor {
    fn start(&self, _launch: &WorkerLaunch) -> LaunchOutcome {
        LaunchOutcome::NotStarted {
            detail: "this test starts no workers".to_owned(),
        }
    }

    fn describe(&self) -> String {
        "a supervisor that starts nothing".to_owned()
    }
}

struct Host {
    _temp: kr_ipc::testing::TempHost,
    controller: Arc<Controller>,
    environment_id: EnvironmentId,
    endpoint: kr_ipc::paths::Endpoint,
    chunks: kr_ipc::paths::Endpoint,
}

fn build() -> BuildId {
    BuildId::new("kr-test/0").expect("a build identifier")
}

async fn host() -> Host {
    let temp = kr_ipc::testing::TempHost::create();
    let environment = temp.environment();
    let environment_id = temp.environment_id();
    let secrets = environment.secrets_dir();
    let controller = Controller::start(ControllerSetup {
        paths: environment.clone(),
        environment_id,
        identity: Box::new(move || {
            let store = open_store(CONTROLLER_SECRET_SERVICE, &secrets)
                .expect("a secret store for the test environment");
            Ok(
                ControllerIdentity::open(store.store.as_ref(), environment_id, false)
                    .expect("an identity"),
            )
        }),
        boot_identity: kr_ipc::identity::boot_identity().expect("a boot identity"),
        supervisor: Box::new(RefusingSupervisor),
        worker_program: std::path::PathBuf::from("/nonexistent/kr-worker"),
        build_id: build(),
        release: "0".to_owned(),
    })
    .await
    .expect("the daemon starts");
    let endpoint = environment.controller_endpoint().expect("an endpoint");
    let listener = Listener::bind(&endpoint).expect("binds the endpoint");
    tokio::spawn(Arc::clone(&controller).serve_clients(listener));
    let chunks = chunk_endpoint(&environment).expect("an addressable chunk endpoint");
    Host {
        _temp: temp,
        controller,
        environment_id,
        endpoint,
        chunks,
    }
}

async fn client(host: &Host) -> LocalClient {
    LocalClient::connect(&host.endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects to the control endpoint")
}

async fn channel(host: &Host) -> ChunkChannel {
    ChunkChannel::connect(&host.chunks, build())
        .await
        .expect("connects to the attachment-chunk endpoint")
}

fn digest(bytes: &[u8]) -> Digest256 {
    Digest256::from_bytes(kr_cbor::sha256(bytes))
}

fn pattern(len: usize) -> Vec<u8> {
    (0..len)
        .map(|index| u8::try_from((index * 17 + 3) % 251).unwrap_or(0))
        .collect()
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

fn typed<T: serde::de::DeserializeOwned + serde::Serialize>(value: &ParamsValue) -> T {
    value.to_typed().expect("a result of the declared shape")
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

/// KR-REQ-14.07: the seven transfer methods reach the service through the daemon's own admission
/// path, on the endpoint each one's frame size needs.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_upload_and_a_download_run_end_to_end_over_the_two_endpoints() {
    let host = host().await;
    let mut control = client(&host).await;
    let mut chunks = channel(&host).await;
    // One full chunk and a remainder: the first frame is the largest one the protocol allows.
    let bytes = pattern(UPLOAD_CHUNK_LEN + 4096);

    let begun: UploadBeginResult = typed(
        &control
            .mutate(
                Method::UploadBegin,
                ActionId::new(kr_ipc::new_uuid()),
                ActionTarget::environment(host.environment_id),
                &begin_params(&host, &bytes, "notes.bin"),
            )
            .await
            .expect("the call reaches the daemon")
            .expect("upload.begin succeeds"),
    );
    assert_eq!(begun.layout.chunk_count, U64::new(2));

    for index in 0..begun.layout.chunk_count.get() {
        let (chunk, payload) = chunk_of(&bytes, index);
        let accepted = chunks
            .send_chunk(
                &ActionTarget::environment(host.environment_id),
                begun.transfer_id,
                chunk,
                payload,
            )
            .await
            .expect("upload.chunk succeeds on the attachment endpoint");
        assert_eq!(accepted.index, U64::new(index));
        assert!(!accepted.duplicate);
    }

    let status: UploadStatusResult = typed(
        &control
            .request(
                Method::UploadStatus,
                &UploadStatusParams {
                    transfer_id: begun.transfer_id,
                },
            )
            .await
            .expect("the call reaches the daemon")
            .expect("upload.status succeeds"),
    );
    assert_eq!(status.state, UploadState::Receiving);
    let bitmap = ChunkBitmap::decode(&status.received_chunks, status.layout.chunk_count.get())
        .expect("a bitmap for this layout");
    assert!(bitmap.is_complete(), "every chunk arrived");

    let finished: UploadFinishResult = typed(
        &control
            .mutate(
                Method::UploadFinish,
                ActionId::new(kr_ipc::new_uuid()),
                ActionTarget::environment(host.environment_id),
                &UploadFinishParams {
                    transfer_id: begun.transfer_id,
                    declared_byte_len: U64::new(bytes.len() as u64),
                    declared_digest: digest(&bytes),
                },
            )
            .await
            .expect("the call reaches the daemon")
            .expect("upload.finish succeeds"),
    );
    assert!(!finished.already_published);
    assert_eq!(finished.handle.content_digest, digest(&bytes));
    assert_eq!(finished.handle.environment_id, host.environment_id);

    // The published attachment is an immutable source, and its chunks come back over the same
    // attachment endpoint.
    let download: DownloadBeginResult = typed(
        &control
            .request(
                Method::DownloadBegin,
                &DownloadBeginParams {
                    environment_id: host.environment_id,
                    resume_transfer_id: Nullable::null(),
                    source: Nullable::some(DownloadSource::Attachment {
                        transfer_id: finished.handle.transfer_id,
                    }),
                    device_id: Nullable::null(),
                },
            )
            .await
            .expect("the call reaches the daemon")
            .expect("download.begin succeeds"),
    );
    assert_eq!(download.byte_len, U64::new(bytes.len() as u64));
    assert_eq!(download.content_digest, digest(&bytes));
    let mut assembled = Vec::new();
    for index in 0..download.layout.chunk_count.get() {
        let chunk = chunks
            .read_chunk(download.transfer_id, index)
            .await
            .expect("download.chunk succeeds on the attachment endpoint");
        assert_eq!(chunk.chunk.digest, digest(chunk.bytes.as_slice()));
        assembled.extend_from_slice(chunk.bytes.as_slice());
    }
    assert_eq!(assembled, bytes, "the bytes came back exactly");
}

/// KR-REQ-14.12, KR-REQ-24.09: a lost reply to `upload.finish` is answered from the retained
/// record, under the same identifier, without publishing a second file.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_lost_reply_to_finish_is_answered_from_the_retained_record() {
    let host = host().await;
    let mut control = client(&host).await;
    let mut chunks = channel(&host).await;
    let bytes = pattern(4096);

    let begun: UploadBeginResult = typed(
        &control
            .mutate(
                Method::UploadBegin,
                ActionId::new(kr_ipc::new_uuid()),
                ActionTarget::environment(host.environment_id),
                &begin_params(&host, &bytes, "notes.bin"),
            )
            .await
            .expect("the call reaches the daemon")
            .expect("upload.begin succeeds"),
    );
    let (chunk, payload) = chunk_of(&bytes, 0);
    chunks
        .send_chunk(
            &ActionTarget::environment(host.environment_id),
            begun.transfer_id,
            chunk,
            payload,
        )
        .await
        .expect("upload.chunk succeeds");

    // The exact mutation is kept, so the repeat is the original payload and window rather than a
    // new action with the same identifier.
    let finish = control
        .compose(
            Method::UploadFinish,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(host.environment_id),
            &UploadFinishParams {
                transfer_id: begun.transfer_id,
                declared_byte_len: U64::new(bytes.len() as u64),
                declared_digest: digest(&bytes),
            },
        )
        .await
        .expect("composes the mutation");
    let first: UploadFinishResult = typed(
        &control
            .repeat(&finish)
            .await
            .expect("the call reaches the daemon")
            .expect("upload.finish succeeds"),
    );
    assert!(!first.already_published);

    // The reply is lost and the caller sends the same action again, on a new connection.
    drop(control);
    let mut resumed = client(&host).await;
    let again: UploadFinishResult = typed(
        &resumed
            .repeat(&finish)
            .await
            .expect("the call reaches the daemon")
            .expect("the repeat is answered"),
    );
    assert_eq!(
        again.handle.transfer_id, first.handle.transfer_id,
        "the same identifier, the same file"
    );
    assert_eq!(again.handle.content_digest, first.handle.content_digest);
    let status: UploadStatusResult = typed(
        &resumed
            .request(
                Method::UploadStatus,
                &UploadStatusParams {
                    transfer_id: begun.transfer_id,
                },
            )
            .await
            .expect("the call reaches the daemon")
            .expect("upload.status succeeds"),
    );
    assert_eq!(status.state, UploadState::Published);
    assert_eq!(
        status
            .handle
            .as_ref()
            .expect("a published handle")
            .transfer_id,
        first.handle.transfer_id
    );
}

/// KR-REQ-14.07: one action identifier used for two different payloads is a reused identifier,
/// not a retry.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_action_identifier_with_two_payloads_is_refused() {
    let host = host().await;
    let mut control = client(&host).await;
    let action_id = ActionId::new(kr_ipc::new_uuid());
    let first: UploadBeginResult = typed(
        &control
            .mutate(
                Method::UploadBegin,
                action_id,
                ActionTarget::environment(host.environment_id),
                &begin_params(&host, &pattern(64), "first.bin"),
            )
            .await
            .expect("the call reaches the daemon")
            .expect("upload.begin succeeds"),
    );
    let refusal = failure(
        control
            .mutate(
                Method::UploadBegin,
                action_id,
                ActionTarget::environment(host.environment_id),
                &begin_params(&host, &pattern(128), "second.bin"),
            )
            .await
            .expect("the call reaches the daemon"),
    );
    assert_eq!(refusal.code, ErrorCode::IdConflict);
    // The first reservation is untouched by the refusal.
    let status: UploadStatusResult = typed(
        &control
            .request(
                Method::UploadStatus,
                &UploadStatusParams {
                    transfer_id: first.transfer_id,
                },
            )
            .await
            .expect("the call reaches the daemon")
            .expect("upload.status succeeds"),
    );
    assert_eq!(status.state, UploadState::Receiving);
}

/// KR-REQ-14.07: a full chunk needs the attachment endpoint, because it does not fit a control
/// frame at all.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_full_chunk_does_not_fit_a_control_frame() {
    let host = host().await;
    let mut control = client(&host).await;
    let mut chunks = channel(&host).await;
    let bytes = pattern(UPLOAD_CHUNK_LEN);
    let begun: UploadBeginResult = typed(
        &control
            .mutate(
                Method::UploadBegin,
                ActionId::new(kr_ipc::new_uuid()),
                ActionTarget::environment(host.environment_id),
                &begin_params(&host, &bytes, "notes.bin"),
            )
            .await
            .expect("the call reaches the daemon")
            .expect("upload.begin succeeds"),
    );
    let (chunk, payload) = chunk_of(&bytes, 0);

    // The same mutation, framed for a control stream, is refused as too large before it is sent.
    let params = kr_protocol::transfer::UploadChunkParams {
        transfer_id: begun.transfer_id,
        chunk,
        bytes: payload.clone(),
    };
    let mutation = control
        .compose(
            Method::UploadChunk,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(host.environment_id),
            &params,
        )
        .await
        .expect("composes the mutation");
    let frame = kr_protocol::envelope::ControlFrame::Mutation(Box::new(mutation));
    assert!(
        kr_protocol::frame::FrameCodec::new(StreamKind::Control)
            .encode_message(&frame)
            .is_err(),
        "a full chunk cannot travel on a control stream"
    );
    kr_protocol::frame::FrameCodec::new(StreamKind::AttachmentChunks)
        .encode_message(&frame)
        .expect("it fits an attachment frame");

    // And on the endpoint framed for it, the host accepts it.
    let accepted = chunks
        .send_chunk(
            &ActionTarget::environment(host.environment_id),
            begun.transfer_id,
            params.chunk,
            payload,
        )
        .await
        .expect("upload.chunk succeeds on the attachment endpoint");
    assert_eq!(
        accepted.received_byte_len,
        U64::new(UPLOAD_CHUNK_LEN as u64)
    );
}

/// KR-REQ-14.07: a transfer refusal reaches the caller under the code the service decided.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_transfer_refusal_keeps_the_code_the_service_decided() {
    let host = host().await;
    let mut control = client(&host).await;
    let mut chunks = channel(&host).await;
    let bytes = pattern(4096);
    let begun: UploadBeginResult = typed(
        &control
            .mutate(
                Method::UploadBegin,
                ActionId::new(kr_ipc::new_uuid()),
                ActionTarget::environment(host.environment_id),
                &begin_params(&host, &bytes, "notes.bin"),
            )
            .await
            .expect("the call reaches the daemon")
            .expect("upload.begin succeeds"),
    );

    // A chunk whose bytes do not match its own digest is an integrity failure, not a bad argument.
    let (chunk, _) = chunk_of(&bytes, 0);
    let refusal = chunks
        .send_chunk(
            &ActionTarget::environment(host.environment_id),
            begun.transfer_id,
            chunk,
            Bytes::new(vec![0; bytes.len()]),
        )
        .await
        .expect_err("the host refuses the chunk");
    assert_eq!(refusal.code(), ErrorCode::AttachmentIntegrity);

    // A file above the environment's per-file limit is a quota failure.
    host.controller
        .transfer()
        .service()
        .set_limits(kr_transfer::Limits {
            max_file_len: 8,
            ..kr_transfer::Limits::default()
        })
        .expect("writes the limits");
    let over = failure(
        control
            .mutate(
                Method::UploadBegin,
                ActionId::new(kr_ipc::new_uuid()),
                ActionTarget::environment(host.environment_id),
                &begin_params(&host, &pattern(64), "big.bin"),
            )
            .await
            .expect("the call reaches the daemon"),
    );
    assert_eq!(over.code, ErrorCode::QuotaExceeded);

    // A transfer identifier that names nothing is an invalid argument, and never says whether
    // something with that identifier exists elsewhere.
    let unknown = failure(
        control
            .request(
                Method::UploadStatus,
                &UploadStatusParams {
                    transfer_id: TransferId::new(kr_ipc::new_uuid()),
                },
            )
            .await
            .expect("the call reaches the daemon"),
    );
    assert_eq!(unknown.code, ErrorCode::InvalidArgument);

    // A source that no snapshot exists for is refused rather than silently replaced.
    let gone = failure(
        control
            .request(
                Method::DownloadBegin,
                &DownloadBeginParams {
                    environment_id: host.environment_id,
                    resume_transfer_id: Nullable::some(TransferId::new(kr_ipc::new_uuid())),
                    source: Nullable::null(),
                    device_id: Nullable::null(),
                },
            )
            .await
            .expect("the call reaches the daemon"),
    );
    assert_eq!(gone.code, ErrorCode::InvalidArgument);
}

/// KR-REQ-14.01, KR-REQ-23.41: the envelope and the parameters have to name the same subject, and
/// the daemon refuses another environment before the service is reached.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_envelope_that_disagrees_with_its_parameters_is_refused() {
    let host = host().await;
    let mut control = client(&host).await;
    let bytes = pattern(64);

    // A target naming a session the parameters do not.
    let mismatch = failure(
        control
            .mutate(
                Method::UploadBegin,
                ActionId::new(kr_ipc::new_uuid()),
                ActionTarget {
                    environment_id: host.environment_id,
                    session_id: Nullable::some(SessionId::new(kr_ipc::new_uuid())),
                    session_epoch: Nullable::some(SessionEpoch::V1),
                    application_instance_id: Nullable::null(),
                    agent_binding_revision: Nullable::null(),
                },
                &begin_params(&host, &bytes, "notes.bin"),
            )
            .await
            .expect("the call reaches the daemon"),
    );
    assert_eq!(mismatch.code, ErrorCode::InvalidArgument);

    // A target naming another environment is refused by the daemon's own envelope check.
    let elsewhere = failure(
        control
            .mutate(
                Method::UploadBegin,
                ActionId::new(kr_ipc::new_uuid()),
                ActionTarget::environment(EnvironmentId::new(kr_ipc::new_uuid())),
                &begin_params(&host, &bytes, "notes.bin"),
            )
            .await
            .expect("the call reaches the daemon"),
    );
    assert_eq!(elsewhere.code, ErrorCode::InvalidArgument);
}

/// KR-REQ-23.41: a draft is created under the caller's own authority, at its own revision.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_draft_is_created_through_the_daemon_and_carries_its_revision() {
    let host = host().await;
    let mut control = client(&host).await;
    let created: DraftCreateResult = typed(
        &control
            .mutate(
                Method::DraftCreate,
                ActionId::new(kr_ipc::new_uuid()),
                ActionTarget::environment(host.environment_id),
                &DraftCreateParams {
                    environment_id: host.environment_id,
                    device_id: Nullable::null(),
                    session_id: Nullable::null(),
                    application_instance_id: Nullable::null(),
                    text: "have a look".to_owned(),
                },
            )
            .await
            .expect("the call reaches the daemon")
            .expect("draft.create succeeds"),
    );
    assert_eq!(created.draft.environment_id, host.environment_id);
    assert_eq!(created.draft.revision.get(), 1);
    assert!(created.draft.attachments.is_empty());

    // A submission is an agent mutation against the session's worker, not something this daemon
    // performs. It is refused here rather than served.
    let refusal = failure(
        control
            .mutate(
                Method::AgentPromptSubmit,
                ActionId::new(kr_ipc::new_uuid()),
                ActionTarget {
                    environment_id: host.environment_id,
                    session_id: Nullable::some(SessionId::new(kr_ipc::new_uuid())),
                    session_epoch: Nullable::some(SessionEpoch::V1),
                    application_instance_id: Nullable::null(),
                    agent_binding_revision: Nullable::null(),
                },
                &ParamsValue::empty(),
            )
            .await
            .expect("the call reaches the daemon"),
    );
    assert_eq!(refusal.code, ErrorCode::InvalidArgument);
}

/// KR-REQ-24.09: the daemon's own expiry sweep runs against the registry's view of its sessions.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_daemon_sweeps_under_its_registrys_view_of_its_sessions() {
    let host = host().await;
    let retention = host
        .controller
        .session_retention()
        .await
        .expect("reads the registry");
    assert!(
        retention.is_empty(),
        "this environment has created no sessions"
    );
    let sweep = host
        .controller
        .transfer()
        .sweep(&host.controller)
        .await
        .expect("the sweep runs");
    assert_eq!(sweep.expired_uploads, 0);
    assert_eq!(sweep.expired_attachments, 0);
    assert_eq!(sweep.expired_snapshots, 0);
}

fn failure(outcome: std::result::Result<ParamsValue, ProtocolError>) -> ProtocolError {
    match outcome {
        Ok(value) => panic!("expected a refusal, got {value:?}"),
        Err(error) => error,
    }
}
