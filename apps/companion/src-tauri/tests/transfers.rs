//! A dropped file sent to the host on this machine, through the companion's own upload.
//!
//! The daemon is kr-controller's in-process host with both of its local endpoints: the control
//! endpoint the companion's session speaks on, and the attachment-chunk endpoint a 1 MiB chunk
//! needs, because a full chunk does not fit a control frame. Its environment is a temporary tree
//! on the internal disk and its secret store is a file inside it, so nothing here reaches this
//! computer's keychain. It starts no worker: an upload that names no session is the daemon's own.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use kr_client::Session;
use kr_client::chunks::ChunkRoute;
use kr_client::ipc::IpcTransport;
use kr_controller::service::{Controller, ControllerSetup};
use kr_controller::supervision::{LaunchOutcome, WorkerLaunch, WorkerSupervisor};
use kr_crypto::store::{StoreSelection, open_store_in};
use kr_ipc::endpoint::{Connection, Listener};
use kr_ipc::paths::Endpoint;
use kr_ipc::testing::TempHost;
use kr_ipc::verify::ControllerIdentity;
use kr_protocol::envelope::{ActionTarget, ControlFrame};
use kr_protocol::frame::{FRAME_LENGTH_PREFIX_LEN, StreamKind};
use kr_protocol::ids::{EnvironmentId, SessionEpoch, SessionId, TransferId};
use kr_protocol::limits::UPLOAD_CHUNK_LEN;
use kr_protocol::method::Method;
use kr_protocol::scalars::{Digest256, Nullable};
use kr_protocol::transfer::{
    AgentDraftAddAttachmentParams, AgentDraftAddAttachmentResult, AttachmentContribution,
    AttachmentHandle, DownloadBeginParams, DownloadBeginResult, DownloadSource, DraftCreateParams,
    DraftCreateResult, InsertionMethod, UploadChunkParams, UploadState, UploadStatusParams,
    UploadStatusResult,
};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

/// A supervisor that starts nothing. These tests create no sessions.
#[derive(Debug)]
struct RefusingSupervisor;

impl WorkerSupervisor for RefusingSupervisor {
    fn start(&self, _launch: &WorkerLaunch) -> LaunchOutcome {
        LaunchOutcome::NotStarted {
            detail: "this test starts no workers".to_owned(),
        }
    }

    fn describe(&self) -> &'static str {
        "a supervisor that starts nothing"
    }
}

/// What a daemon of this suite is started with: an environment on the internal disk, its secrets in
/// a file inside it, and no worker.
fn setup(tree: &TempHost) -> ControllerSetup {
    let environment = tree.environment();
    let environment_id = tree.environment_id();
    let secrets = environment.secrets_dir();
    ControllerSetup {
        paths: environment,
        environment_id,
        identity: Box::new(move || {
            let store = open_store_in(&secrets).expect("a secret store for the test environment");
            Ok(
                ControllerIdentity::open(store.store.as_ref(), environment_id, false)
                    .expect("an identity"),
            )
        }),
        secret_store: StoreSelection::File,
        boot_identity: kr_ipc::identity::boot_identity().expect("a boot identity"),
        supervisor: Box::new(RefusingSupervisor),
        worker_program: PathBuf::from("/nonexistent/kr-worker"),
        build_id: companion_tauri::connection::build_id().expect("a build identity"),
        release: "0".to_owned(),
        shell_packages: None,
        terminal: Box::new(kr_controller::supervision::NoTerminal),
    }
}

/// The tasks that serve a daemon's two endpoints, ended with it.
struct Serving {
    clients: tokio::task::JoinHandle<kr_controller::error::Result<()>>,
    chunks: tokio::task::JoinHandle<()>,
}

impl Serving {
    /// Ends both tasks and waits until they have let go of their endpoints.
    async fn end(&mut self) {
        self.clients.abort();
        self.chunks.abort();
        let _ = (&mut self.clients).await;
        let _ = (&mut self.chunks).await;
    }
}

impl Drop for Serving {
    fn drop(&mut self) {
        self.clients.abort();
        self.chunks.abort();
    }
}

/// The daemon of one test, with the tasks that serve its two endpoints.
struct Daemon {
    tree: TempHost,
    /// Held so the daemon lives exactly as long as its test.
    controller: Arc<Controller>,
    serving: Serving,
    /// The tree whose address the chunk listener borrows when a relay stands at this
    /// environment's own, kept so its directory outlives the listener.
    _elsewhere: Option<TempHost>,
}

impl Daemon {
    /// Starts a daemon that serves both endpoints at the environment's own addresses.
    async fn start() -> Self {
        Self::start_on(TempHost::create()).await
    }

    /// Starts a daemon on an environment that may already hold a transfer journal.
    async fn start_on(tree: TempHost) -> Self {
        let chunk_listener = kr_controller::transfer::bind_chunk_endpoint(&tree.environment())
            .expect("binds the attachment-chunk endpoint");
        Self::serving(tree, chunk_listener, None).await
    }

    /// Ends this daemon the way its process ending would end it, and returns the environment.
    ///
    /// Both endpoints are released before this returns, so a daemon started on the same
    /// environment afterwards finds them free.
    async fn stop(self) -> TempHost {
        let Self {
            tree,
            controller,
            mut serving,
            ..
        } = self;
        serving.end().await;
        drop(controller);
        tree
    }

    /// Starts a daemon whose attachment-chunk listener is at an address nothing else uses, and
    /// returns that address, so a relay can stand at the environment's own.
    async fn start_elsewhere() -> (Self, Endpoint) {
        let tree = TempHost::create();
        let elsewhere = TempHost::create();
        // Another environment's control endpoint: an address on the internal disk that no daemon
        // in this test serves.
        let address = elsewhere
            .environment()
            .controller_endpoint()
            .expect("an addressable endpoint");
        let chunk_listener = Listener::bind(&address).expect("binds the relayed address");
        let daemon = Self::serving(tree, chunk_listener, Some(elsewhere)).await;
        (daemon, address)
    }

    async fn serving(
        tree: TempHost,
        chunk_listener: Listener,
        elsewhere: Option<TempHost>,
    ) -> Self {
        let environment = tree.environment();
        // Waits for a daemon this one replaces to let go of the environment.
        let controller = kr_controller::testing::taken_over(|| Controller::start(setup(&tree)))
            .await
            .expect("the daemon starts");
        let listener = Listener::bind(&environment.controller_endpoint().expect("an endpoint"))
            .expect("binds the control endpoint");
        let clients = tokio::spawn(Arc::clone(&controller).serve_clients(listener));
        let chunks = tokio::spawn(kr_controller::transfer::serve_chunks(
            Arc::downgrade(&controller),
            chunk_listener,
        ));
        Self {
            tree,
            controller,
            serving: Serving { clients, chunks },
            _elsewhere: elsewhere,
        }
    }

    fn environment_id(&self) -> EnvironmentId {
        self.tree.environment_id()
    }

    /// Connects a session the way the companion connects to its own host.
    async fn session(&self) -> Session {
        let endpoint = self
            .tree
            .environment()
            .controller_endpoint()
            .expect("an endpoint");
        let transport = IpcTransport::connect(
            &endpoint,
            companion_tauri::connection::build_id().expect("a build identity"),
        )
        .await
        .expect("connects to the control endpoint");
        Session::start(transport.shared()).expect("a session")
    }
}

/// Sends one file as the window's drop does, to the daemon's environment.
async fn upload(
    daemon: &Daemon,
    session: &Session,
    path: PathBuf,
) -> companion_tauri::Result<AttachmentHandle> {
    companion_tauri::transfers::upload_to(
        session,
        &daemon.tree.environment(),
        ActionTarget::environment(daemon.environment_id()),
        None,
        path,
    )
    .await
}

/// Reads an attachment back through a lane of its own, checking every chunk against the
/// descriptor the host gave and the whole file against its digest.
async fn read_back(daemon: &Daemon, session: &Session, handle: &AttachmentHandle) -> Vec<u8> {
    let download: DownloadBeginResult = session
        .read(
            Method::DownloadBegin,
            &DownloadBeginParams {
                environment_id: daemon.environment_id(),
                resume_transfer_id: Nullable::null(),
                source: Nullable::some(DownloadSource::Attachment {
                    transfer_id: handle.transfer_id,
                }),
                device_id: Nullable::null(),
            },
        )
        .await
        .expect("the host opens the attachment for reading");
    let route = ChunkRoute::local(
        &daemon.tree.environment(),
        companion_tauri::connection::build_id().expect("a build identity"),
    )
    .expect("an addressable route");
    let mut lane = route
        .open(download.transfer_id)
        .await
        .expect("a lane for the download");
    let mut whole = Vec::new();
    for chunk in &download.chunks {
        let bytes = lane
            .read_chunk(chunk)
            .await
            .expect("every chunk is the one described");
        whole.extend_from_slice(bytes.as_slice());
    }
    assert_eq!(whole.len() as u64, download.byte_len.get());
    assert_eq!(digest(&whole), download.content_digest);
    whole
}

/// Writes `len` bytes of a pattern no two neighbouring chunks share, and returns them.
fn dropped_file(directory: &Path, name: &str, len: usize) -> (PathBuf, Vec<u8>) {
    let bytes: Vec<u8> = (0..len)
        .map(|index| u8::try_from((index * 31 + index / UPLOAD_CHUNK_LEN) % 251).unwrap_or(0))
        .collect();
    let path = directory.join(name);
    std::fs::write(&path, &bytes).expect("the dropped file is written");
    (path, bytes)
}

fn digest(bytes: &[u8]) -> Digest256 {
    Digest256::from_bytes(kr_cbor::sha256(bytes))
}

/// Checks a handle against the bytes it names and against the host's own record of it.
async fn verified(session: &Session, handle: &AttachmentHandle, bytes: &[u8]) {
    assert_eq!(handle.byte_len.get(), bytes.len() as u64);
    assert_eq!(handle.content_digest, digest(bytes));
    let status: UploadStatusResult = session
        .read(
            Method::UploadStatus,
            &UploadStatusParams {
                transfer_id: handle.transfer_id,
            },
        )
        .await
        .expect("the host reports the upload");
    assert_eq!(status.state, UploadState::Published);
    assert_eq!(status.handle.0.as_ref(), Some(handle));
}

/// KR-REQ-12.31: a dropped file of several full chunks reaches a verified attachment handle.
///
/// A full chunk does not fit a control frame, so the chunks travel on the environment's
/// attachment-chunk endpoint while the reservation and the publication go on the session.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dropped_file_of_several_full_chunks_reaches_a_verified_handle() {
    let daemon = Daemon::start().await;
    let session = daemon.session().await;
    let directory = tempfile::tempdir().expect("a directory on the internal disk");
    // Four full chunks and a remainder.
    let (path, bytes) = dropped_file(directory.path(), "capture.bin", 4 * UPLOAD_CHUNK_LEN + 1000);

    let handle = upload(&daemon, &session, path)
        .await
        .expect("the upload reaches a handle");
    verified(&session, &handle, &bytes).await;
    assert_eq!(handle.original_file_name, "capture.bin");
    assert_eq!(handle.environment_id, daemon.environment_id());
    // And the bytes the host published are the file's, chunk by chunk and whole, read back over
    // the same kind of lane.
    assert_eq!(read_back(&daemon, &session, &handle).await, bytes);
}

/// KR-REQ-14.12: an upload whose chunk connection drops part way resumes from `upload.status`
/// under the same upload identifier, and sends only the chunks the host is missing.
///
/// A relay stands at the environment's attachment-chunk address. On the first connection it
/// withholds the host's answer to the second chunk and ends the connection, so the host holds
/// that chunk and the client never heard so. Only the host's status can tell the client not to
/// send it again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_upload_resumes_from_status_after_its_chunk_connection_drops() {
    let (daemon, address) = Daemon::start_elsewhere().await;
    let relay = Relay::start(&daemon, address, 2);
    let session = daemon.session().await;
    let directory = tempfile::tempdir().expect("a directory on the internal disk");
    let (path, bytes) = dropped_file(directory.path(), "capture.bin", 4 * UPLOAD_CHUNK_LEN + 1000);

    let handle = upload(&daemon, &session, path)
        .await
        .expect("the upload resumes and reaches a handle");
    verified(&session, &handle, &bytes).await;

    let legs = relay.legs();
    assert_eq!(
        legs.len(),
        2,
        "one connection dropped and one more carried the rest"
    );
    assert_eq!(
        legs[0].chunks,
        vec![0, 1],
        "the first connection carried two chunks before it dropped"
    );
    assert_eq!(
        legs[1].chunks,
        vec![2, 3, 4],
        "the second connection carried only what the host's status said was missing"
    );
    for leg in &legs {
        assert!(
            leg.transfers.iter().all(|seen| *seen == handle.transfer_id),
            "every chunk named the one upload identifier"
        );
    }
    assert!(
        legs[1].bytes < bytes.len(),
        "the resumed connection carried less than the whole file"
    );
}

/// The control: an empty file has no chunk, so nothing travels on the attachment-chunk endpoint,
/// and it reaches a handle as it always did.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_empty_file_reaches_a_handle_without_a_chunk() {
    let daemon = Daemon::start().await;
    let session = daemon.session().await;
    let directory = tempfile::tempdir().expect("a directory on the internal disk");
    let (path, bytes) = dropped_file(directory.path(), "empty.txt", 0);

    let handle = upload(&daemon, &session, path)
        .await
        .expect("an empty upload reaches a handle");
    verified(&session, &handle, &bytes).await;
}

/// The control for the chunk size: a file smaller than one chunk reaches a handle too.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_file_smaller_than_one_chunk_reaches_a_handle() {
    let daemon = Daemon::start().await;
    let session = daemon.session().await;
    let directory = tempfile::tempdir().expect("a directory on the internal disk");
    let (path, bytes) = dropped_file(directory.path(), "notes.txt", 4096);

    let handle = upload(&daemon, &session, path)
        .await
        .expect("a small upload reaches a handle");
    verified(&session, &handle, &bytes).await;
    assert_eq!(handle.declared_media_type, "text/plain");
}

/// KR-REQ-13.16, 13.17: a file the page hands over as bytes, pasted onto the window or picked on a
/// phone, goes through the same upload a dropped one does and reaches a verified handle, under the
/// last component of the name it came with and the media type that name declares.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_handed_file_goes_through_the_same_upload_as_a_dropped_one() {
    let daemon = Daemon::start().await;
    let session = daemon.session().await;
    let bytes: Vec<u8> = (0..(UPLOAD_CHUNK_LEN + 4096))
        .map(|index| u8::try_from(index % 253).unwrap_or(0))
        .collect();
    let file = companion_tauri::transfers::HandedFile::new(bytes.clone(), "Pictures/café.png")
        .expect("a handed file inside the bound");

    let handle = companion_tauri::transfers::upload_handed_to(
        &session,
        &daemon.tree.environment(),
        ActionTarget::environment(daemon.environment_id()),
        None,
        file,
    )
    .await
    .expect("the handed file reaches a handle");
    verified(&session, &handle, &bytes).await;
    assert_eq!(handle.original_file_name, "café.png");
    assert_eq!(handle.declared_media_type, "image/png");
    assert_eq!(read_back(&daemon, &session, &handle).await, bytes);
}

/// A target naming a session at its first epoch, as a page names one it read in a list.
fn target_of(daemon: &Daemon, session_id: SessionId) -> ActionTarget {
    ActionTarget {
        environment_id: daemon.environment_id(),
        session_id: Nullable::some(session_id),
        session_epoch: Nullable::some(SessionEpoch::V1),
        application_instance_id: Nullable::null(),
        agent_binding_revision: Nullable::null(),
    }
}

/// Asks the host for a draft for `session_id`, the way the page asks for the one a file is bound to.
async fn try_host_draft(
    daemon: &Daemon,
    session: &Session,
    session_id: SessionId,
) -> Result<kr_protocol::transfer::DraftRecord, kr_client::ClientError> {
    let created = session
        .mutate(
            Method::DraftCreate,
            target_of(daemon, session_id),
            None,
            &serde_json::json!({}),
            &DraftCreateParams {
                environment_id: daemon.environment_id(),
                device_id: Nullable::null(),
                session_id: Nullable::some(session_id),
                application_instance_id: Nullable::null(),
                text: String::new(),
            },
            kr_protocol::scalars::DurationMs::new(30_000),
        )
        .await?;
    let kr_client::Settled::Result(value) = created else {
        panic!("a draft is made with a result, not a receipt");
    };
    let made: DraftCreateResult = value.to_typed().expect("a draft the page can read");
    Ok(made.draft)
}

/// A host draft for `session_id`, which the host makes.
async fn host_draft(
    daemon: &Daemon,
    session: &Session,
    session_id: SessionId,
) -> kr_protocol::transfer::DraftRecord {
    try_host_draft(daemon, session, session_id)
        .await
        .expect("the host makes the draft")
}

/// Binds `handle` to `draft` as a manual terminal workflow, as the page does.
async fn bind_manually(
    daemon: &Daemon,
    session: &Session,
    session_id: SessionId,
    draft: &kr_protocol::transfer::DraftRecord,
    handle: &AttachmentHandle,
) -> Result<AgentDraftAddAttachmentResult, kr_client::ClientError> {
    let bound = session
        .mutate(
            Method::AgentDraftAddAttachment,
            target_of(daemon, session_id),
            None,
            &serde_json::json!({}),
            &AgentDraftAddAttachmentParams {
                draft_id: draft.draft_id,
                expected_revision: draft.revision,
                transfer_id: handle.transfer_id,
                contribution: AttachmentContribution {
                    operation_id: "attach".to_owned(),
                    accepted_media_types: vec![handle.declared_media_type.clone()],
                    max_byte_len: handle.byte_len,
                    max_count: kr_protocol::scalars::U64::new(64),
                    insertion_method: InsertionMethod::ManualTerminalWorkflow,
                    external_destination: Nullable::null(),
                    model_media_capability: false,
                },
            },
            kr_protocol::scalars::DurationMs::new(30_000),
        )
        .await?;
    let kr_client::Settled::Result(value) = bound else {
        panic!("a binding is answered with a result, not a receipt");
    };
    Ok(value.to_typed().expect("a binding the page can read"))
}

/// KR-REQ-13.14: a file sent for a session and bound to a host draft as a manual terminal workflow
/// comes back with the path the person is shown, and the file at that path is the file that was
/// sent, byte for byte, with an expiry still to come.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_bound_file_comes_back_with_the_path_it_can_be_read_at() {
    let daemon = Daemon::start().await;
    let session = daemon.session().await;
    let session_id = SessionId::new(kr_ipc::new_uuid());
    let directory = tempfile::tempdir().expect("a directory on the internal disk");
    let (path, bytes) = dropped_file(directory.path(), "capture.bin", 4096);
    let handle = companion_tauri::transfers::upload_to(
        &session,
        &daemon.tree.environment(),
        target_of(&daemon, session_id),
        Some(session_id),
        path,
    )
    .await
    .expect("the file reaches a handle");

    let draft = host_draft(&daemon, &session, session_id).await;
    let bound = bind_manually(&daemon, &session, session_id, &draft, &handle)
        .await
        .expect("the host binds the file");

    let grant = bound
        .attachment
        .read_grant
        .0
        .expect("the binding carries the grant the path is shown from");
    assert_eq!(
        grant.insertion_method,
        InsertionMethod::ManualTerminalWorkflow
    );
    assert!(grant.expires_at_ms.get() > kr_ipc::now_ms().get());
    assert_eq!(
        std::fs::read(&grant.host_path).expect("the file is at the path the person is shown"),
        bytes
    );
    assert_eq!(bound.draft.revision.get(), draft.revision.get() + 1);
}

/// KR-REQ-24.09: once the closure of a session is recorded and the host has started again, the
/// draft the window holds for the session's files has been moved on by the closure, so a binding at
/// the revision the window saw is refused as a conflict, and a draft made anew for the session is
/// refused as the session's closure; the window is given no path, and the file keeps the identity
/// it had: the host still reports it published, and the handle is the one the person holds.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_file_for_a_closed_session_is_refused_a_path_and_keeps_its_identity() {
    let first = Daemon::start().await;
    let session = first.session().await;
    let session_id = SessionId::new(kr_ipc::new_uuid());
    let directory = tempfile::tempdir().expect("a directory on the internal disk");
    let (path, bytes) = dropped_file(directory.path(), "capture.bin", 4096);
    let handle = companion_tauri::transfers::upload_to(
        &session,
        &first.tree.environment(),
        target_of(&first, session_id),
        Some(session_id),
        path,
    )
    .await
    .expect("the file reaches a handle");
    let draft = host_draft(&first, &session, session_id).await;
    drop(session);

    // The host ends with the session's closure recorded and not yet acted on.
    let environment_id = first.environment_id();
    let tree = first.stop().await;
    kr_controller::registry::Registry::open(tree.environment().registry_database(), environment_id)
        .expect("opens the host's registry")
        .record_closure(&kr_protocol::session::ClosureRecord {
            session_id,
            session_epoch: SessionEpoch::V1,
            reason: kr_protocol::session::ClosureReason::WorkerCrash,
            root_exit_code: Nullable::null(),
            root_signal: Nullable::null(),
            terminated: Vec::new(),
            surviving: Vec::new(),
            ownership_coverage: kr_protocol::session::OwnershipCoverage::Incomplete,
            durability: kr_protocol::session::Durability::Durable,
            closed_at_ms: kr_ipc::now_ms(),
        })
        .expect("records the closure");

    let second = Daemon::start_on(tree).await;
    let session = second.session().await;
    let stale = bind_manually(&second, &session, session_id, &draft, &handle)
        .await
        .expect_err("the closure moved the draft on, so the revision the window saw is stale");
    assert_eq!(
        stale.code(),
        kr_protocol::error::ErrorCode::DraftConflict,
        "{stale:?}"
    );
    let fresh = try_host_draft(&second, &session, session_id)
        .await
        .expect_err("a closed session is given no new draft, and so no path");
    assert_eq!(
        fresh.code(),
        kr_protocol::error::ErrorCode::SessionClosed,
        "the host refused it as the session's closure: {fresh:?}"
    );

    // The file is what it was: published, the same handle, the same bytes.
    verified(&session, &handle, &bytes).await;
    assert_eq!(read_back(&second, &session, &handle).await, bytes);
}

/// What one relayed connection carried from the client to the host.
#[derive(Clone, Debug, Default)]
struct Leg {
    /// Every byte relayed towards the host, length prefixes included.
    bytes: usize,
    /// The index of each chunk the connection carried whole, in order.
    chunks: Vec<u64>,
    /// The transfer each of those chunks named.
    transfers: Vec<TransferId>,
}

/// A relay at the environment's attachment-chunk address, in front of the daemon's own listener.
///
/// It relays whole frames and reads each one, so it can say what a connection carried. On the
/// first connection it withholds the host's `cut_after`th answer and ends both sides.
struct Relay {
    legs: Arc<Mutex<Vec<Leg>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Relay {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Relay {
    fn start(daemon: &Daemon, upstream: Endpoint, cut_after: usize) -> Self {
        let listener = kr_controller::transfer::bind_chunk_endpoint(&daemon.tree.environment())
            .expect("the relay binds the environment's attachment-chunk address");
        let legs = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&legs);
        let task = tokio::spawn(async move {
            let mut connections = 0_usize;
            loop {
                let Ok((client, _peer)) = listener.accept().await else {
                    return;
                };
                let Ok(host) = Connection::connect(&upstream).await else {
                    return;
                };
                let leg = {
                    let mut legs = recorded.lock().expect("the legs");
                    legs.push(Leg::default());
                    legs.len() - 1
                };
                let cut = (connections == 0).then_some(cut_after);
                connections += 1;
                tokio::spawn(relay_one(client, host, Arc::clone(&recorded), leg, cut));
            }
        });
        Self { legs, task }
    }

    fn legs(&self) -> Vec<Leg> {
        self.legs.lock().expect("the legs").clone()
    }
}

/// Relays one connection until either side ends it, or until the host's `cut`th answer, which is
/// withheld.
async fn relay_one(
    client: Connection,
    host: Connection,
    legs: Arc<Mutex<Vec<Leg>>>,
    leg: usize,
    cut: Option<usize>,
) {
    let (mut client_read, mut client_write) = tokio::io::split(client);
    let (mut host_read, mut host_write) = tokio::io::split(host);
    let towards_host = async {
        while let Some(frame) = read_frame(&mut client_read).await {
            if let Some(chunk) = chunk_of(&frame) {
                let mut legs = legs.lock().expect("the legs");
                legs[leg].chunks.push(chunk.chunk.index.get());
                legs[leg].transfers.push(chunk.transfer_id);
            }
            legs.lock().expect("the legs")[leg].bytes += frame.len();
            if host_write.write_all(&frame).await.is_err() {
                return;
            }
        }
    };
    let towards_client = async {
        let mut answers = 0_usize;
        while let Some(frame) = read_frame(&mut host_read).await {
            if matches!(decoded(&frame), Some(ControlFrame::Response(_))) {
                answers += 1;
                if Some(answers) == cut {
                    // Withheld, and the connection ends: the host has acted on the chunk and the
                    // client will never hear that it did.
                    return;
                }
            }
            if client_write.write_all(&frame).await.is_err() {
                return;
            }
        }
    };
    // Whichever direction ends first ends the connection: both halves of both sockets are dropped
    // when this returns.
    tokio::select! {
        () = towards_host => {}
        () = towards_client => {}
    }
}

/// Reads one whole frame, prefix included, or `None` when the stream ends.
async fn read_frame(reader: &mut (impl tokio::io::AsyncRead + Unpin)) -> Option<Vec<u8>> {
    let mut prefix = [0_u8; FRAME_LENGTH_PREFIX_LEN];
    reader.read_exact(&mut prefix).await.ok()?;
    let len = usize::try_from(u32::from_be_bytes(prefix)).ok()?;
    if len > StreamKind::AttachmentChunks.max_payload_len() {
        return None;
    }
    let mut frame = vec![0_u8; FRAME_LENGTH_PREFIX_LEN + len];
    frame[..FRAME_LENGTH_PREFIX_LEN].copy_from_slice(&prefix);
    reader
        .read_exact(&mut frame[FRAME_LENGTH_PREFIX_LEN..])
        .await
        .ok()?;
    Some(frame)
}

fn decoded(frame: &[u8]) -> Option<ControlFrame> {
    kr_protocol::wire::decode(
        &frame[FRAME_LENGTH_PREFIX_LEN..],
        &StreamKind::AttachmentChunks.cbor_limits(),
    )
    .ok()
}

/// The chunk a frame carries, when it carries one.
fn chunk_of(frame: &[u8]) -> Option<UploadChunkParams> {
    let Some(ControlFrame::Mutation(mutation)) = decoded(frame) else {
        return None;
    };
    if mutation.method.method() != Some(Method::UploadChunk) {
        return None;
    }
    mutation.params.to_typed().ok()
}
