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
use kr_protocol::ids::{EnvironmentId, TransferId};
use kr_protocol::limits::UPLOAD_CHUNK_LEN;
use kr_protocol::method::Method;
use kr_protocol::scalars::{Digest256, Nullable};
use kr_protocol::transfer::{
    AttachmentHandle, DownloadBeginParams, DownloadBeginResult, DownloadSource, UploadChunkParams,
    UploadState, UploadStatusParams, UploadStatusResult,
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

/// The daemon of one test, with the tasks that serve its two endpoints.
struct Daemon {
    tree: TempHost,
    /// Held so the daemon lives exactly as long as its test.
    _controller: Arc<Controller>,
    clients: tokio::task::JoinHandle<kr_controller::error::Result<()>>,
    chunks: tokio::task::JoinHandle<()>,
    /// The tree whose address the chunk listener borrows when a relay stands at this
    /// environment's own, kept so its directory outlives the listener.
    _elsewhere: Option<TempHost>,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        self.clients.abort();
        self.chunks.abort();
    }
}

impl Daemon {
    /// Starts a daemon that serves both endpoints at the environment's own addresses.
    async fn start() -> Self {
        let tree = TempHost::create();
        let chunk_listener = kr_controller::transfer::bind_chunk_endpoint(&tree.environment())
            .expect("binds the attachment-chunk endpoint");
        Self::serving(tree, chunk_listener, None).await
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
        let environment_id = tree.environment_id();
        let secrets = environment.secrets_dir();
        let controller = Controller::start(ControllerSetup {
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
            worker_program: PathBuf::from("/nonexistent/kr-worker"),
            build_id: companion_tauri::connection::build_id().expect("a build identity"),
            release: "0".to_owned(),
            shell_packages: None,
            terminal: Box::new(kr_controller::supervision::NoTerminal),
        })
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
            _controller: controller,
            clients,
            chunks,
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
