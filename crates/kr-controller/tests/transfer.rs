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
use kr_crypto::store::{StoreSelection, open_store_in};
use kr_ipc::client::LocalClient;
use kr_ipc::endpoint::Listener;
use kr_ipc::verify::ControllerIdentity;
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
    temp: kr_ipc::testing::TempHost,
    controller: Arc<Controller>,
    environment_id: EnvironmentId,
    endpoint: kr_ipc::paths::Endpoint,
    chunks: kr_ipc::paths::Endpoint,
    clients: tokio::task::JoinHandle<kr_controller::error::Result<()>>,
    chunk_task: tokio::task::JoinHandle<()>,
}

impl Host {
    /// Ends this daemon the way its process ending would end it, and returns the environment.
    ///
    /// Both endpoints are released before this returns: the tasks that hold the listeners are
    /// stopped and awaited, so a replacement daemon binding the same addresses finds them free.
    async fn stop(self) -> kr_ipc::testing::TempHost {
        self.clients.abort();
        self.chunk_task.abort();
        let _ = self.clients.await;
        let _ = self.chunk_task.await;
        drop(self.controller);
        self.temp
    }
}

fn build() -> BuildId {
    BuildId::new("kr-test/0").expect("a build identifier")
}

async fn host() -> Host {
    host_on(kr_ipc::testing::TempHost::create()).await
}

/// How long a replacement daemon is given to take the environment over.
///
/// A daemon in this suite ends in the process that started it, and the environment's lock is
/// released when the last reference to the controller goes. Awaiting the two listener tasks does
/// not account for every reference: a connection task the daemon spawned of its own, or a sweep
/// still running, holds one too. So a replacement starting at once can find the environment held.
/// That is a liveness condition: what these tests assert is that the replacement takes the
/// environment over, not how soon the last reference goes.
const ENVIRONMENT_HANDOVER_DEADLINE: std::time::Duration = std::time::Duration::from_secs(120);

/// Starts a daemon on an environment that may already hold a transfer journal.
async fn host_on(temp: kr_ipc::testing::TempHost) -> Host {
    let environment = temp.environment();
    let environment_id = temp.environment_id();
    let controller = start_controller(&environment, environment_id).await;
    let endpoint = environment.controller_endpoint().expect("an endpoint");
    let listener = Listener::bind(&endpoint).expect("binds the endpoint");
    let clients = tokio::spawn(Arc::clone(&controller).serve_clients(listener));
    // The attachment-chunk endpoint belongs to whoever runs the daemon, exactly as the control
    // endpoint does, so these tests bind it and own the task that serves it.
    let chunk_listener = kr_controller::transfer::bind_chunk_endpoint(&environment)
        .expect("binds the attachment-chunk endpoint");
    let chunk_task = tokio::spawn(kr_controller::transfer::serve_chunks(
        Arc::downgrade(&controller),
        chunk_listener,
    ));
    let chunks = chunk_endpoint(&environment).expect("an addressable chunk endpoint");
    Host {
        temp,
        controller,
        environment_id,
        endpoint,
        chunks,
        clients,
        chunk_task,
    }
}

/// Starts the controller, waiting for a daemon this one replaces to let go of the environment.
///
/// Anything other than the environment still being held fails at once, with what it said and how
/// long the start had been going.
async fn start_controller(
    environment: &kr_ipc::paths::EnvironmentPaths,
    environment_id: EnvironmentId,
) -> Arc<Controller> {
    let started = std::time::Instant::now();
    loop {
        let secrets = environment.secrets_dir();
        let outcome = Controller::start(ControllerSetup {
            paths: environment.clone(),
            environment_id,
            identity: Box::new(move || {
                let store =
                    open_store_in(&secrets).expect("a secret store for the test environment");
                Ok(
                    ControllerIdentity::open(store.store.as_ref(), environment_id, false)
                        .expect("an identity"),
                )
            }),
            secret_store: StoreSelection::File,
            boot_identity: kr_ipc::identity::boot_identity().expect("a boot identity"),
            supervisor: Box::new(RefusingSupervisor),
            worker_program: std::path::PathBuf::from("/nonexistent/kr-worker"),
            build_id: build(),
            release: "0".to_owned(),
            shell_packages: None,
        })
        .await;
        match outcome {
            Ok(controller) => return controller,
            Err(kr_controller::error::ControllerError::AlreadyRunning { .. })
                if started.elapsed() < ENVIRONMENT_HANDOVER_DEADLINE => {}
            Err(error) => panic!(
                "the daemon did not start in {:.1?}: {error}",
                started.elapsed()
            ),
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
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
    let retention = {
        // Read the way the daemon reads it, on a blocking task: the registry's lock is a
        // task-aware one and its blocking form is only correct off the reactor.
        let controller = Arc::clone(&host.controller);
        tokio::task::spawn_blocking(move || controller.session_retention())
            .await
            .expect("the task ran")
            .expect("reads the registry")
    };
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

/// KR-REQ-23.41: the admission a transfer mutation runs under is checked again at dispatch, so an
/// action whose accepted deadline has passed writes nothing.
///
/// The deadline is the earliest of the window's expiry and the lifetime the caller asked for, so a
/// caller that asks for no lifetime at all is admitted by the envelope check and then refused by
/// the barrier in front of the write. That is the ordering under test: the envelope accepted it,
/// and the last check before the effect did not.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_action_whose_admitted_deadline_passed_is_refused_before_it_writes() {
    let host = host().await;
    let mut control = client(&host).await;
    let bytes = pattern(64);
    let mut mutation = control
        .compose(
            Method::UploadBegin,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(host.environment_id),
            &begin_params(&host, &bytes, "notes.bin"),
        )
        .await
        .expect("composes the mutation");
    mutation.requested_ttl_ms = kr_protocol::scalars::DurationMs::new(0);

    let refusal = failure(
        control
            .repeat(&mutation)
            .await
            .expect("the call reaches the daemon"),
    );

    assert_eq!(refusal.code, ErrorCode::PermissionDenied);
    assert!(
        refusal.message.contains("deadline"),
        "the refusal says what ran out: {}",
        refusal.message
    );
    // Nothing was reserved: the environment has no staged bytes at all.
    assert_eq!(
        host.controller
            .transfer()
            .service()
            .staged_byte_len()
            .expect("reads the staged total"),
        0
    );
}

/// KR-REQ-23.41: a mutation whose envelope names a different session from the transfer it acts on
/// is refused, whoever owns the transfer.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_mutation_that_names_another_session_than_its_transfer_is_refused() {
    let host = host().await;
    let mut control = client(&host).await;
    let mut chunks = channel(&host).await;
    let bytes = pattern(64);
    let session = SessionId::new(kr_ipc::new_uuid());
    let elsewhere = SessionId::new(kr_ipc::new_uuid());
    let target = ActionTarget {
        environment_id: host.environment_id,
        session_id: Nullable::some(session),
        session_epoch: Nullable::some(SessionEpoch::V1),
        application_instance_id: Nullable::null(),
        agent_binding_revision: Nullable::null(),
    };
    let mut params = begin_params(&host, &bytes, "notes.bin");
    params.session_id = Nullable::some(session);
    let begun: UploadBeginResult = typed(
        &control
            .mutate(
                Method::UploadBegin,
                ActionId::new(kr_ipc::new_uuid()),
                target.clone(),
                &params,
            )
            .await
            .expect("the call reaches the daemon")
            .expect("upload.begin succeeds"),
    );
    let (chunk, payload) = chunk_of(&bytes, 0);
    chunks
        .send_chunk(&target, begun.transfer_id, chunk, payload)
        .await
        .expect("the chunk is accepted under the session that owns the transfer");

    // The same transfer, named by a request whose envelope points at another session.
    let refusal = failure(
        control
            .mutate(
                Method::UploadFinish,
                ActionId::new(kr_ipc::new_uuid()),
                ActionTarget {
                    session_id: Nullable::some(elsewhere),
                    ..target.clone()
                },
                &UploadFinishParams {
                    transfer_id: begun.transfer_id,
                    declared_byte_len: U64::new(bytes.len() as u64),
                    declared_digest: digest(&bytes),
                },
            )
            .await
            .expect("the call reaches the daemon"),
    );
    assert_eq!(refusal.code, ErrorCode::InvalidArgument);
    assert!(
        refusal.message.contains("session"),
        "the refusal names the disagreement: {}",
        refusal.message
    );

    // A target that names no session at all is refused too: an object that belongs to a session is
    // acted on by a request that names that session, or the receipt names something the effect
    // never touched.
    let refusal = failure(
        control
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
            .expect("the call reaches the daemon"),
    );
    assert_eq!(refusal.code, ErrorCode::InvalidArgument);
    assert!(
        refusal.message.contains("session"),
        "the refusal says what the target left out: {}",
        refusal.message
    );

    // The transfer is untouched, and the same call under its own session publishes it.
    let finished: UploadFinishResult = typed(
        &control
            .mutate(
                Method::UploadFinish,
                ActionId::new(kr_ipc::new_uuid()),
                target,
                &UploadFinishParams {
                    transfer_id: begun.transfer_id,
                    declared_byte_len: U64::new(bytes.len() as u64),
                    declared_digest: digest(&bytes),
                },
            )
            .await
            .expect("the call reaches the daemon")
            .expect("upload.finish succeeds under the session that owns it"),
    );
    assert_eq!(finished.handle.content_digest, digest(&bytes));
    assert_eq!(finished.handle.session_id, Nullable::some(session));
}

/// KR-REQ-14.12, KR-REQ-24.09: a daemon that ends mid-upload leaves a transfer its replacement
/// resumes from the verified chunk bitmap, under the same identifier.
///
/// The daemon is ended the way its process ending would end it: both endpoints are released, the
/// controller is dropped with its journal connection, and a replacement opens the same environment
/// and binds the same addresses.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_restarted_daemon_resumes_an_upload_from_its_bitmap() {
    let first = host().await;
    // Two chunks, of which exactly one arrives before the daemon ends.
    let bytes = pattern(UPLOAD_CHUNK_LEN + 4096);
    let transfer_id: TransferId;
    let temp = {
        let mut control = client(&first).await;
        let mut chunks = channel(&first).await;
        let begun: UploadBeginResult = typed(
            &control
                .mutate(
                    Method::UploadBegin,
                    ActionId::new(kr_ipc::new_uuid()),
                    ActionTarget::environment(first.environment_id),
                    &begin_params(&first, &bytes, "notes.bin"),
                )
                .await
                .expect("the call reaches the daemon")
                .expect("upload.begin succeeds"),
        );
        transfer_id = begun.transfer_id;
        assert_eq!(begun.layout.chunk_count, U64::new(2));
        let (chunk, payload) = chunk_of(&bytes, 0);
        chunks
            .send_chunk(
                &ActionTarget::environment(first.environment_id),
                transfer_id,
                chunk,
                payload,
            )
            .await
            .expect("the first chunk is accepted");
        drop(control);
        drop(chunks);
        first.stop().await
    };

    let second = host_on(temp).await;
    let mut control = client(&second).await;
    let mut chunks = channel(&second).await;

    let status: UploadStatusResult = typed(
        &control
            .request(Method::UploadStatus, &UploadStatusParams { transfer_id })
            .await
            .expect("the call reaches the replacement daemon")
            .expect("upload.status succeeds"),
    );
    assert_eq!(status.state, UploadState::Receiving);
    let bitmap = ChunkBitmap::decode(&status.received_chunks, status.layout.chunk_count.get())
        .expect("a bitmap for this layout");
    assert_eq!(
        bitmap.missing(),
        vec![1],
        "the chunk that arrived is recorded and the other one is not"
    );

    for index in bitmap.missing() {
        let (chunk, payload) = chunk_of(&bytes, index);
        chunks
            .send_chunk(
                &ActionTarget::environment(second.environment_id),
                transfer_id,
                chunk,
                payload,
            )
            .await
            .expect("the remaining chunk is accepted by the replacement");
    }

    let finished: UploadFinishResult = typed(
        &control
            .mutate(
                Method::UploadFinish,
                ActionId::new(kr_ipc::new_uuid()),
                ActionTarget::environment(second.environment_id),
                &UploadFinishParams {
                    transfer_id,
                    declared_byte_len: U64::new(bytes.len() as u64),
                    declared_digest: digest(&bytes),
                },
            )
            .await
            .expect("the call reaches the replacement daemon")
            .expect("upload.finish succeeds"),
    );
    assert_eq!(finished.handle.transfer_id, transfer_id);
    assert_eq!(finished.handle.content_digest, digest(&bytes));
    assert_eq!(finished.handle.byte_len, U64::new(bytes.len() as u64));
}

/// KR-REQ-14.07: each endpoint carries the methods its frame bound is for, and nothing else.
///
/// The attachment endpoint exists because a 1 MiB chunk does not fit a control frame. Letting it
/// carry ordinary requests as well would make it a second admission with a larger bound, so the
/// two endpoints carry disjoint sets of methods and say so when a caller uses the wrong one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn each_endpoint_carries_only_the_methods_its_frame_bound_is_for() {
    let host = host().await;
    let mut control = client(&host).await;
    let bytes = pattern(64);
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

    // A chunk on the control endpoint is refused, small enough to fit the frame or not.
    let (chunk, payload) = chunk_of(&bytes, 0);
    let refusal = failure(
        control
            .mutate(
                Method::UploadChunk,
                ActionId::new(kr_ipc::new_uuid()),
                ActionTarget::environment(host.environment_id),
                &kr_protocol::transfer::UploadChunkParams {
                    transfer_id: begun.transfer_id,
                    chunk,
                    bytes: payload,
                },
            )
            .await
            .expect("the call reaches the daemon"),
    );
    assert_eq!(refusal.code, ErrorCode::PermissionDenied);
    assert!(
        refusal.message.contains("attachment-chunk endpoint"),
        "the refusal names the endpoint that carries it: {}",
        refusal.message
    );

    // And an ordinary request on the attachment endpoint is refused there.
    let mut wrong = LocalClient::connect(&host.chunks, LocalClientKind::Cli, build())
        .await
        .expect("connects to the attachment-chunk endpoint");
    let refusal = failure(
        wrong
            .request(
                Method::UploadStatus,
                &UploadStatusParams {
                    transfer_id: begun.transfer_id,
                },
            )
            .await
            .expect("the call reaches the daemon"),
    );
    assert_eq!(refusal.code, ErrorCode::PermissionDenied);
    assert!(refusal.message.contains("control endpoint"));

    // The upload itself is untouched by either refusal: no chunk arrived and it is still receiving.
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
    assert_eq!(bitmap.missing(), vec![0]);
}

/// KR-REQ-14.12, KR-REQ-24.09: a daemon killed outright mid-upload leaves a transfer its
/// replacement resumes from the verified chunk bitmap, with every byte counted exactly once.
///
/// This one runs the daemon as a real process and ends it with `SIGKILL`: no unwinding, no
/// destructors, no flush of anything the journal had not already committed. The binary is copied to
/// the internal disk and every directory it touches is there too, so nothing it opens is on the
/// removable volume this tree lives on.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_daemon_killed_mid_upload_is_replaced_and_the_upload_resumes() {
    let host = kr_ipc::testing::TempHost::create();
    let environment = host.environment();
    let environment_id = host.environment_id();
    let program = host.root().join("kr-controller");
    std::fs::copy(env!("CARGO_BIN_EXE_kr-controller"), &program).expect("copies the daemon");
    let endpoint = environment.controller_endpoint().expect("an endpoint");
    let chunk_address = chunk_endpoint(&environment).expect("an addressable chunk endpoint");
    let bytes = pattern(UPLOAD_CHUNK_LEN + 4096);
    let declared = bytes.len() as u64;

    // Both guards clean up on the way out, including the way out an assertion takes.
    let mut first = start_daemon(&program, &host);
    wait_for_daemon(&endpoint).await;
    let transfer_id: TransferId;
    {
        let mut control = LocalClient::connect(&endpoint, LocalClientKind::Cli, build())
            .await
            .expect("connects to the daemon this test started");
        let mut chunks = ChunkChannel::connect(&chunk_address, build())
            .await
            .expect("connects to its attachment endpoint");
        let begun: UploadBeginResult = typed(
            &control
                .mutate(
                    Method::UploadBegin,
                    ActionId::new(kr_ipc::new_uuid()),
                    ActionTarget::environment(environment_id),
                    &UploadBeginParams {
                        environment_id,
                        session_id: Nullable::null(),
                        device_id: Nullable::null(),
                        declared_byte_len: U64::new(declared),
                        declared_digest: digest(&bytes),
                        declared_media_type: "application/octet-stream".to_owned(),
                        original_file_name: "notes.bin".to_owned(),
                    },
                )
                .await
                .expect("the call reaches the daemon")
                .expect("upload.begin succeeds"),
        );
        transfer_id = begun.transfer_id;
        assert_eq!(begun.layout.chunk_count, U64::new(2));
        let (chunk, payload) = chunk_of(&bytes, 0);
        chunks
            .send_chunk(
                &ActionTarget::environment(environment_id),
                transfer_id,
                chunk,
                payload,
            )
            .await
            .expect("the first chunk is accepted");
    }

    // The daemon dies where it stands.
    first.stop();

    let mut second = start_daemon(&program, &host);
    wait_for_daemon(&endpoint).await;
    let mut control = LocalClient::connect(&endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects to the replacement");
    let mut chunks = ChunkChannel::connect(&chunk_address, build())
        .await
        .expect("connects to the replacement's attachment endpoint");

    let status: UploadStatusResult = typed(
        &control
            .request(Method::UploadStatus, &UploadStatusParams { transfer_id })
            .await
            .expect("the call reaches the replacement")
            .expect("upload.status succeeds"),
    );
    assert_eq!(status.state, UploadState::Receiving);
    assert_eq!(
        status.received_byte_len,
        U64::new(UPLOAD_CHUNK_LEN as u64),
        "the chunk that arrived is counted once, and the one that did not is not counted"
    );
    let bitmap = ChunkBitmap::decode(&status.received_chunks, status.layout.chunk_count.get())
        .expect("a bitmap for this layout");
    assert_eq!(bitmap.missing(), vec![1]);

    for index in bitmap.missing() {
        let (chunk, payload) = chunk_of(&bytes, index);
        let accepted = chunks
            .send_chunk(
                &ActionTarget::environment(environment_id),
                transfer_id,
                chunk,
                payload,
            )
            .await
            .expect("the remaining chunk is accepted");
        assert!(
            !accepted.duplicate,
            "the chunk that never arrived is not a duplicate"
        );
    }

    // Nothing serves an upload that is not published, however complete its chunks are.
    let refusal = failure(
        control
            .request(
                Method::DownloadBegin,
                &DownloadBeginParams {
                    environment_id,
                    resume_transfer_id: Nullable::null(),
                    source: Nullable::some(DownloadSource::Attachment { transfer_id }),
                    device_id: Nullable::null(),
                },
            )
            .await
            .expect("the call reaches the replacement"),
    );
    assert_eq!(
        refusal.code,
        ErrorCode::ResourceUnavailable,
        "an unpublished upload serves nothing: {}",
        refusal.message
    );

    let finished: UploadFinishResult = typed(
        &control
            .mutate(
                Method::UploadFinish,
                ActionId::new(kr_ipc::new_uuid()),
                ActionTarget::environment(environment_id),
                &UploadFinishParams {
                    transfer_id,
                    declared_byte_len: U64::new(declared),
                    declared_digest: digest(&bytes),
                },
            )
            .await
            .expect("the call reaches the replacement")
            .expect("upload.finish succeeds"),
    );
    assert!(!finished.already_published);
    assert_eq!(finished.handle.transfer_id, transfer_id);
    assert_eq!(finished.handle.content_digest, digest(&bytes));
    assert_eq!(finished.handle.byte_len, U64::new(declared));

    // Nothing was double-counted: a second reservation reports the environment's staged total, and
    // it is this attachment's bytes plus the new reservation, once each.
    let next: UploadBeginResult = typed(
        &control
            .mutate(
                Method::UploadBegin,
                ActionId::new(kr_ipc::new_uuid()),
                ActionTarget::environment(environment_id),
                &UploadBeginParams {
                    environment_id,
                    session_id: Nullable::null(),
                    device_id: Nullable::null(),
                    declared_byte_len: U64::new(1),
                    declared_digest: digest(&[0]),
                    declared_media_type: "application/octet-stream".to_owned(),
                    original_file_name: "one.bin".to_owned(),
                },
            )
            .await
            .expect("the call reaches the replacement")
            .expect("upload.begin succeeds"),
    );
    assert_eq!(next.staged_byte_len, U64::new(declared + 1));

    // And the published attachment serves exactly the bytes that were uploaded.
    let download: DownloadBeginResult = typed(
        &control
            .request(
                Method::DownloadBegin,
                &DownloadBeginParams {
                    environment_id,
                    resume_transfer_id: Nullable::null(),
                    source: Nullable::some(DownloadSource::Attachment {
                        transfer_id: finished.handle.transfer_id,
                    }),
                    device_id: Nullable::null(),
                },
            )
            .await
            .expect("the call reaches the replacement")
            .expect("download.begin succeeds"),
    );
    assert_eq!(download.byte_len, U64::new(declared));
    assert_eq!(download.content_digest, digest(&bytes));
    let mut served = Vec::new();
    for index in 0..download.layout.chunk_count.get() {
        let chunk = chunks
            .read_chunk(download.transfer_id, index)
            .await
            .expect("the replacement serves the attachment's chunks");
        assert_eq!(chunk.chunk.digest, digest(chunk.bytes.as_slice()));
        served.extend_from_slice(chunk.bytes.as_slice());
    }
    assert_eq!(
        served, bytes,
        "the bytes that come back are the bytes that went in, across the kill"
    );

    drop(control);
    drop(chunks);
    second.stop();
    keys_are_this_test_s(
        &environment,
        environment_id,
        &host.root().join("daemon.log"),
    );
}

/// A daemon this test started, ended when it goes out of scope however that happens.
#[cfg(unix)]
struct Daemon(Option<std::process::Child>);

#[cfg(unix)]
impl Daemon {
    /// Ends it now, without giving it a chance to tidy up.
    fn stop(&mut self) {
        let Some(mut child) = self.0.take() else {
            return;
        };
        if let Ok(pid) = i32::try_from(child.id())
            && let Some(pid) = rustix::process::Pid::from_raw(pid)
        {
            let _ = rustix::process::kill_process(pid, rustix::process::Signal::KILL);
        }
        let _ = child.wait();
    }
}

#[cfg(unix)]
impl Drop for Daemon {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Asserts the daemon kept its device keys where this test told it to.
///
/// A daemon started with `--secret-store file` writes them into this environment's own `secrets`
/// directory, which goes when the temporary host does. That is what keeps a test run out of the
/// person's own credential store, and this is the check that says it happened rather than the flag
/// on the command line saying it was asked for. The daemon's own log is checked too, because the
/// line it prints is what a run's evidence rests on when nobody is reading the directory.
#[cfg(unix)]
fn keys_are_this_test_s(
    environment: &kr_ipc::paths::EnvironmentPaths,
    environment_id: EnvironmentId,
    log: &std::path::Path,
) {
    let scope = environment_id.to_string();
    for purpose in kr_protocol::pairing::KeyPurpose::ALL {
        let name = kr_crypto::store::SecretName::device_key(&scope, purpose)
            .expect("a name this store takes");
        let path = name
            .as_str()
            .split('/')
            .fold(environment.secrets_dir(), |path, part| path.join(part));
        assert!(
            path.is_file(),
            "the daemon's {purpose:?} key is not at {}, so it went to a store this test does not own",
            path.display()
        );
    }
    // The daemon names the directory as it resolved it, which is not always how this test spells
    // it: a daemon given relative directories resolves them against the working directory the
    // kernel reports, and on macOS that has already followed the link at `/var`. So the two names
    // are compared as directories rather than as text.
    // The suffix is removed rather than split on, because a directory's own name may contain the
    // text the suffix starts with.
    let said = std::fs::read_to_string(log).unwrap_or_default();
    let named = said
        .lines()
        .find_map(|line| {
            line.strip_prefix("kr-controller: keys in the 0700 fallback directory at ")
        })
        .and_then(|rest| {
            rest.strip_suffix(" (protected only by OS account isolation and disk encryption)")
        })
        .unwrap_or_else(|| {
            panic!("the daemon's log does not say where its keys went; it says: {said}")
        });
    assert_eq!(
        std::fs::canonicalize(named).expect("the directory the daemon named"),
        std::fs::canonicalize(environment.secrets_dir()).expect("this test's secrets directory"),
        "the daemon named a directory other than this test's own"
    );
}

/// Starts the copied daemon on this test's own directories, with no worker program.
#[cfg(unix)]
fn start_daemon(program: &std::path::Path, host: &kr_ipc::testing::TempHost) -> Daemon {
    start_daemon_with(program, host, false)
}

/// Starts the copied daemon, naming its directories relatively when `relative` is set.
///
/// A daemon is ordinarily given absolute directories, and an installation that gives it relative
/// ones is giving them against the directory it is started in. Everything the daemon derives from
/// them travels: the endpoints it binds, the roots it hands a worker it starts, and the endpoint
/// identity a worker signs and this daemon later compares. All of that has to name the same
/// directories as the ones this test derives from its own absolute root.
#[cfg(unix)]
fn start_daemon_with(
    program: &std::path::Path,
    host: &kr_ipc::testing::TempHost,
    relative: bool,
) -> Daemon {
    let logs = host.root().join("daemon.log");
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&logs)
        .expect("opens the daemon's log");
    let (runtime_dir, state_dir) = if relative {
        (std::path::PathBuf::from("r"), std::path::PathBuf::from("s"))
    } else {
        (host.root().join("r"), host.root().join("s"))
    };
    let daemon = std::process::Command::new(program)
        .arg("--runtime-dir")
        .arg(runtime_dir)
        .arg("--state-dir")
        .arg(state_dir)
        // This test creates no sessions, and a worker that cannot be found is refused rather than
        // started.
        .arg("--worker")
        .arg(host.root().join("no-such-worker"))
        // Its device keys belong to this run: they go in this environment's own secrets directory
        // and leave with the temporary host, rather than into the person's credential store.
        .arg("--secret-store")
        .arg("file")
        // Never this test's own directory: the build tree can be on a removable volume, and a
        // process holding one open is a volume the person at the machine cannot eject.
        .current_dir(host.root())
        .stdin(std::process::Stdio::null())
        .stdout(log.try_clone().expect("duplicates the log"))
        .stderr(log)
        .spawn()
        .map(|child| Daemon(Some(child)))
        .expect("starts the daemon");
    runs_where_this_test_put_it(&daemon, host);
    daemon
}

/// Asserts that the daemon this test started runs where this test put it.
///
/// Read from the process table, because what is being checked is what the operating system
/// actually gave the process: a launch that quietly inherited a directory looks exactly like one
/// that was given the right one until the kernel is asked.
#[cfg(unix)]
fn runs_where_this_test_put_it(daemon: &Daemon, host: &kr_ipc::testing::TempHost) {
    let Some(child) = daemon.0.as_ref() else {
        return;
    };
    let expected = std::fs::canonicalize(host.root()).expect("this test's own directory exists");
    let workspace = workspace_root();
    assert!(
        !expected.starts_with(&workspace),
        "this test's directories are not inside the workspace: {}",
        expected.display()
    );
    let Some(actual) = working_directory_of(child.id()) else {
        eprintln!(
            "skipped: this platform does not report another process's working directory here"
        );
        return;
    };
    assert_eq!(
        std::fs::canonicalize(&actual).unwrap_or(actual),
        expected,
        "the daemon runs in the directory this test configured"
    );
}

/// Returns the working directory the operating system gave a running process.
#[cfg(unix)]
fn working_directory_of(pid: u32) -> Option<std::path::PathBuf> {
    #[cfg(target_os = "linux")]
    {
        Some(
            std::fs::read_link(format!("/proc/{pid}/cwd")).unwrap_or_else(|error| {
                panic!("the working directory of process {pid} could not be read: {error}")
            }),
        )
    }
    #[cfg(target_os = "macos")]
    {
        let output = std::process::Command::new("/usr/sbin/lsof")
            .args(["-a", "-d", "cwd", "-p", &pid.to_string(), "-Fn"])
            .output()
            .unwrap_or_else(|error| panic!("the process table could not be read: {error}"));
        Some(
            String::from_utf8_lossy(&output.stdout)
                .lines()
                .find_map(|line| line.strip_prefix('n').map(std::path::PathBuf::from))
                .unwrap_or_else(|| {
                    panic!("the process table named no working directory for process {pid}")
                }),
        )
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = pid;
        None
    }
}

/// Returns the workspace this test was built from.
#[cfg(unix)]
fn workspace_root() -> std::path::PathBuf {
    let mut root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    // `<workspace>/crates/<crate>`.
    root.pop();
    root.pop();
    std::fs::canonicalize(&root).unwrap_or(root)
}

/// How long a freshly started daemon is given to answer.
///
/// A daemon coming up opens its journals, reads its secrets and binds both of its endpoints, and on
/// a machine that is building something else at the same time that has taken over half a minute.
/// What the wait below asserts is that the daemon comes up at all, so its bound is generous: a run
/// that reaches it is saying the daemon never answered, not that the machine was busy.
#[cfg(unix)]
const DAEMON_START_DEADLINE: std::time::Duration = std::time::Duration::from_secs(120);

/// Waits for a daemon to answer on its control endpoint.
///
/// A liveness wait, not a measurement. The poll is fast so a daemon that is up is used at once, the
/// deadline is [`DAEMON_START_DEADLINE`], and the message says how long it actually waited.
#[cfg(unix)]
async fn wait_for_daemon(endpoint: &kr_ipc::paths::Endpoint) {
    let started = std::time::Instant::now();
    loop {
        let remaining = DAEMON_START_DEADLINE.saturating_sub(started.elapsed());
        assert!(
            !remaining.is_zero(),
            "the daemon did not answer on {} in {:.1?}",
            endpoint.as_text(),
            started.elapsed()
        );
        // Bounded by what is left of the deadline. The handshake has no timeout of its own, so a
        // daemon that binds its endpoint and then stops answering would hold this wait open for
        // ever rather than reaching the check above.
        if let Ok(Ok(_answered)) = tokio::time::timeout(
            remaining,
            LocalClient::connect(endpoint, LocalClientKind::Cli, build()),
        )
        .await
        {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}

/// A daemon given relative directories names the same places as one given absolute ones.
///
/// It is started in a directory of its own with `--runtime-dir r --state-dir s`. This test knows
/// only the absolute root, and derives the endpoint, the environment identity and the registry
/// from it. If the daemon resolved those names anywhere but where it was started, it would bind a
/// different socket and this test would never reach it.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_daemon_given_relative_directories_binds_the_endpoints_this_test_derives() {
    let host = kr_ipc::testing::TempHost::create();
    let environment = host.environment();
    let environment_id = host.environment_id();
    let program = host.root().join("kr-controller");
    std::fs::copy(env!("CARGO_BIN_EXE_kr-controller"), &program).expect("copies the daemon");
    let endpoint = environment.controller_endpoint().expect("an endpoint");

    let mut daemon = start_daemon_with(&program, &host, true);
    wait_for_daemon(&endpoint).await;
    let mut control = LocalClient::connect(&endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects to the daemon this test started");
    let info: kr_protocol::hostinfo::HostInfoResult = typed(
        &control
            .request(Method::HostInfo, &())
            .await
            .expect("the call reaches the daemon")
            .expect("host.info succeeds"),
    );
    assert_eq!(
        info.environment_id, environment_id,
        "the daemon opened this test's own environment"
    );
    // And the directories it reports are the absolute ones this test knows, not the two words it
    // was given. Compared as directories rather than as text: a temporary root reached through a
    // symbolic link is one directory under two names, and what is under test is which directory
    // the daemon resolved to.
    let environments: kr_protocol::hostinfo::EnvironmentListResult = typed(
        &control
            .request(Method::EnvironmentList, &())
            .await
            .expect("the call reaches the daemon")
            .expect("environment.list succeeds"),
    );
    let listed = environments
        .environments
        .first()
        .expect("the daemon lists the environment it owns");
    let same = |reported: &str, derived: &std::path::Path| {
        let reported = std::path::PathBuf::from(reported);
        assert!(reported.is_absolute(), "{} is absolute", reported.display());
        assert_eq!(
            std::fs::canonicalize(&reported).expect("the daemon's directory exists"),
            std::fs::canonicalize(derived).expect("this test's directory exists"),
            "{} and {} are one directory",
            reported.display(),
            derived.display()
        );
    };
    same(&listed.runtime_directory, environment.runtime_dir());
    same(&listed.state_directory, environment.state_dir());

    drop(control);
    daemon.stop();
    keys_are_this_test_s(
        &environment,
        environment_id,
        &host.root().join("daemon.log"),
    );
}
