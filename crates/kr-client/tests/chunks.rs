//! The attachment-chunk lane and the upload driver, against a scripted host on this machine.
//!
//! The host answers the upload methods from a small table of its own on an environment's two local
//! endpoints: the control endpoint a session speaks on, and the attachment-chunk endpoint a lane
//! opens. A script says where it departs from an ordinary answer: a window it renews at once, a
//! connection it ends with a chunk stored and unanswered, a reservation it never answers, a chunk
//! it answers with bytes other than the ones described, an acknowledgement in another
//! environment's name. The daemon's own transfer service meets the same calls in the companion's
//! suite; these are the cases a real daemon does not produce on demand.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

use kr_client::Session;
use kr_client::chunks::ChunkRoute;
use kr_client::error::ClientError;
use kr_client::ipc::IpcTransport;
use kr_client::uploads::{self, Held, Subject, Upload};
use kr_ipc::endpoint::Listener;
use kr_ipc::framed::{FrameReader, FrameWriter, split};
use kr_ipc::peer::PeerIdentity;
use kr_ipc::testing::TempHost;
use kr_protocol::envelope::{
    ActionTarget, ControlEvent, ControlFrame, MutationRequest, Outcome, ParamsValue, Request,
    Response,
};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::frame::StreamKind;
use kr_protocol::hello::{ActionWindow, PROTOCOL_VERSION};
use kr_protocol::identity::{BootIdentity, BootIdentitySource};
use kr_protocol::ids::{
    ActionWindowId, ActorId, BootEpoch, BuildId, ConnectionId, EnvironmentId, RequestId, TransferId,
};
use kr_protocol::limits::UPLOAD_CHUNK_LEN;
use kr_protocol::local::{LocalHelloAck, LocalPeer, LocalRole};
use kr_protocol::method::Method;
use kr_protocol::receipt::{Receipt, ReceiptResponse, ReceiptState};
use kr_protocol::scalars::{
    Bytes, CanonicalSet, Digest256, DurationMs, Nullable, TimestampMs, U64, Uuid,
};
use kr_protocol::transfer::{
    AttachmentHandle, ChunkBitmap, ChunkDescriptor, ChunkLayout, DownloadChunkParams,
    DownloadChunkResult, UploadBeginParams, UploadBeginResult, UploadChunkParams,
    UploadChunkResult, UploadFinishParams, UploadFinishResult, UploadState, UploadStatusParams,
    UploadStatusResult,
};

/// The lifetime every call in these tests requests.
const TTL: DurationMs = DurationMs::new(60_000);

fn build() -> BuildId {
    BuildId::new("kr/0.1.0+test").expect("a build identity")
}

fn window(id: &str) -> ActionWindowId {
    ActionWindowId::new(id).expect("a window identifier")
}

fn digest(bytes: &[u8]) -> Digest256 {
    Digest256::from_bytes(kr_cbor::sha256(bytes))
}

fn pattern(len: usize) -> Vec<u8> {
    (0..len)
        .map(|index| u8::try_from((index * 7 + index / UPLOAD_CHUNK_LEN) % 251).unwrap_or(0))
        .collect()
}

/// Where the scripted host departs from an ordinary answer.
#[derive(Default)]
struct Script {
    /// A window the attachment-chunk endpoint issues as soon as it has acknowledged a hello.
    renewal: Option<ActionWindowId>,
    /// The environment the attachment-chunk endpoint names in its acknowledgement, when it names
    /// another than its own.
    chunk_environment: Option<EnvironmentId>,
    /// On the first chunk connection, how many chunks the host stores before it ends the
    /// connection with the last of them unanswered.
    drop_after_chunks: Option<usize>,
    /// How the control endpoint answers a reservation.
    reservation: Reply,
    /// Once the attachment-chunk endpoint has renewed the window, the first window has expired.
    expire_first_window: bool,
    /// How many keepalives the attachment-chunk endpoint sends before it renews the window.
    keepalives_before_renewal: usize,
    /// The control endpoint issues a window that admits nothing.
    no_control_window: bool,
    /// The attachment-chunk endpoint follows its acknowledgement with a frame a lane does not
    /// carry, and keeps the connection open.
    stray_frame: bool,
    /// The attachment-chunk endpoint ends the connection instead of acknowledging the hello.
    drop_hello: bool,
    /// What the host answers `download.chunk` with, by index: the descriptor and the bytes.
    download: BTreeMap<u64, (ChunkDescriptor, Vec<u8>)>,
}

/// What the host saw.
#[derive(Clone, Debug, Default)]
struct Seen {
    /// The window each chunk was sent under.
    windows: Vec<String>,
    /// The chunks each attachment-chunk connection carried, in order.
    legs: Vec<Vec<u64>>,
    reservations: usize,
    publications: usize,
    statuses: usize,
    /// How many renewals the attachment-chunk endpoint has written.
    renewals: usize,
}

/// How the scripted host answers a reservation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Reply {
    /// With the reservation.
    #[default]
    Answer,
    /// Not at all: the connection ends.
    Drop,
    /// With `OUTCOME_UNKNOWN`, as a host that could not learn what its own work did.
    Unknown,
    /// With a receipt in this state and no result.
    Receipt(ReceiptState),
    /// Not yet: the host keeps the reservation and the connection, and never answers.
    Hold,
    /// With a result that is not a reservation.
    Unreadable,
}

/// One upload the host holds.
struct Staged {
    params: UploadBeginParams,
    layout: ChunkLayout,
    chunks: BTreeMap<u64, Vec<u8>>,
    handle: Option<AttachmentHandle>,
}

struct Host {
    tree: TempHost,
    script: Script,
    seen: Mutex<Seen>,
    staged: Mutex<HashMap<TransferId, Staged>>,
    tasks: Mutex<Vec<tokio::task::JoinHandle<()>>>,
}

impl Drop for Host {
    fn drop(&mut self) {
        for task in self.tasks.lock().expect("the tasks").drain(..) {
            task.abort();
        }
    }
}

impl Host {
    fn start(script: Script) -> Arc<Self> {
        let tree = TempHost::create();
        let environment = tree.environment();
        let control = Listener::bind(&environment.controller_endpoint().expect("an address"))
            .expect("binds the control endpoint");
        let chunks = Listener::bind(&environment.attachment_chunk_endpoint().expect("an address"))
            .expect("binds the attachment-chunk endpoint");
        let host = Arc::new(Self {
            tree,
            script,
            seen: Mutex::new(Seen::default()),
            staged: Mutex::new(HashMap::new()),
            tasks: Mutex::new(Vec::new()),
        });
        let serving_control = tokio::spawn(serve(Arc::downgrade(&host), control, false));
        let serving_chunks = tokio::spawn(serve(Arc::downgrade(&host), chunks, true));
        host.tasks
            .lock()
            .expect("the tasks")
            .extend([serving_control, serving_chunks]);
        host
    }

    fn environment_id(&self) -> EnvironmentId {
        self.tree.environment_id()
    }

    fn seen(&self) -> Seen {
        self.seen.lock().expect("what the host saw").clone()
    }

    async fn session(&self) -> Session {
        let endpoint = self
            .tree
            .environment()
            .controller_endpoint()
            .expect("an address");
        let transport = IpcTransport::connect(&endpoint, build())
            .await
            .expect("connects to the control endpoint");
        Session::start(transport.shared()).expect("a session")
    }

    fn route(&self) -> ChunkRoute {
        ChunkRoute::local(&self.tree.environment(), build()).expect("an addressable route")
    }

    fn target(&self) -> ActionTarget {
        ActionTarget::environment(self.environment_id())
    }

    fn subject(&self) -> Subject {
        Subject {
            environment_id: self.environment_id(),
            session_id: None,
            device_id: None,
            declared_media_type: "application/octet-stream".to_owned(),
            original_file_name: "capture.bin".to_owned(),
        }
    }

    fn acknowledgement(
        &self,
        peer: &PeerIdentity,
        environment_id: EnvironmentId,
        window: ActionWindow,
    ) -> ControlFrame {
        let connection_id = ConnectionId::new(Uuid::from_bytes([42; 16]));
        ControlFrame::HelloAck(Box::new(LocalHelloAck {
            selected_version: PROTOCOL_VERSION,
            role: LocalRole::Controller,
            connection_id,
            environment_id,
            boot_identity: BootIdentity {
                source: BootIdentitySource::BootTime,
                value: Bytes::new(vec![1, 2, 3, 4]),
            },
            peer: LocalPeer {
                uid: U64::new(u64::from(peer.uid)),
                gid: U64::new(u64::from(peer.gid)),
                pid: Nullable::null(),
            },
            action_window: window,
            capabilities: CanonicalSet::new(),
            max_receive: kr_protocol::hello::ReceiveLimits::default(),
        }))
    }

    fn begin(&self, params: UploadBeginParams) -> Result<ParamsValue, ProtocolError> {
        if params.environment_id != self.environment_id() {
            return Err(ProtocolError::new(
                ErrorCode::EnvironmentUnavailable,
                "this host does not own that environment",
            ));
        }
        let transfer_id = TransferId::new(kr_ipc::new_uuid());
        let layout = ChunkLayout::for_length(params.declared_byte_len.get());
        let answer = UploadBeginResult {
            transfer_id,
            environment_id: self.environment_id(),
            layout,
            received_chunks: ChunkBitmap::empty(layout.chunk_count.get()).encode(),
            expires_at_ms: TimestampMs::new(1),
            staged_byte_len: U64::new(0),
            staged_byte_limit: U64::new(1 << 30),
        };
        self.staged.lock().expect("the table").insert(
            transfer_id,
            Staged {
                params,
                layout,
                chunks: BTreeMap::new(),
                handle: None,
            },
        );
        typed(&answer)
    }

    fn chunk(&self, params: UploadChunkParams) -> Result<ParamsValue, ProtocolError> {
        let mut staged = self.staged.lock().expect("the table");
        let upload = staged.get_mut(&params.transfer_id).ok_or_else(unknown)?;
        let index = params.chunk.index.get();
        let expected = upload.layout.length_of(index).ok_or_else(unknown)?;
        if params.chunk.byte_len.get() != expected
            || params.bytes.len() as u64 != expected
            || digest(params.bytes.as_slice()) != params.chunk.digest
        {
            return Err(ProtocolError::new(
                ErrorCode::AttachmentIntegrity,
                "the chunk does not verify",
            ));
        }
        upload.chunks.insert(index, params.bytes.into_vec());
        let answer = UploadChunkResult {
            transfer_id: params.transfer_id,
            index: params.chunk.index,
            duplicate: false,
            received_chunks: bitmap(upload).encode(),
            received_byte_len: U64::new(0),
        };
        typed(&answer)
    }

    fn status(&self, params: &UploadStatusParams) -> Result<ParamsValue, ProtocolError> {
        self.seen.lock().expect("what the host saw").statuses += 1;
        let staged = self.staged.lock().expect("the table");
        let upload = staged.get(&params.transfer_id).ok_or_else(unknown)?;
        let answer = UploadStatusResult {
            transfer_id: params.transfer_id,
            environment_id: self.environment_id(),
            state: if upload.handle.is_some() {
                UploadState::Published
            } else {
                UploadState::Receiving
            },
            layout: upload.layout,
            received_chunks: bitmap(upload).encode(),
            received_byte_len: U64::new(0),
            expires_at_ms: TimestampMs::new(1),
            handle: upload
                .handle
                .clone()
                .map_or(Nullable::null(), Nullable::some),
            invalid_reason: Nullable::null(),
        };
        typed(&answer)
    }

    fn finish(&self, params: &UploadFinishParams) -> Result<ParamsValue, ProtocolError> {
        self.seen.lock().expect("what the host saw").publications += 1;
        let mut staged = self.staged.lock().expect("the table");
        let upload = staged.get_mut(&params.transfer_id).ok_or_else(unknown)?;
        let whole: Vec<u8> = upload.chunks.values().flatten().copied().collect();
        if !bitmap(upload).is_complete()
            || whole.len() as u64 != params.declared_byte_len.get()
            || digest(&whole) != params.declared_digest
            || params.declared_digest != upload.params.declared_digest
        {
            return Err(ProtocolError::new(
                ErrorCode::AttachmentIntegrity,
                "the file does not verify",
            ));
        }
        let handle = AttachmentHandle {
            environment_id: self.environment_id(),
            transfer_id: params.transfer_id,
            session_id: upload.params.session_id,
            byte_len: params.declared_byte_len,
            content_digest: params.declared_digest,
            declared_media_type: upload.params.declared_media_type.clone(),
            original_file_name: upload.params.original_file_name.clone(),
            preview: Nullable::null(),
            presented_as_image: false,
            published_at_ms: TimestampMs::new(1),
            expires_at_ms: TimestampMs::new(2),
            submitted: false,
        };
        upload.handle = Some(handle.clone());
        typed(&UploadFinishResult {
            handle,
            already_published: false,
            preview_unavailable: Nullable::null(),
        })
    }

    fn download(&self, params: &DownloadChunkParams) -> Result<ParamsValue, ProtocolError> {
        let (chunk, bytes) = self
            .script
            .download
            .get(&params.index.get())
            .ok_or_else(unknown)?;
        typed(&DownloadChunkResult {
            transfer_id: params.transfer_id,
            chunk: *chunk,
            bytes: Bytes::new(bytes.clone()),
        })
    }
}

fn action_window(id: ActionWindowId) -> ActionWindow {
    ActionWindow {
        action_window_id: id,
        connection_id: ConnectionId::new(Uuid::from_bytes([42; 16])),
        boot_epoch: BootEpoch::new(1),
        issued_at_ms: TimestampMs::new(0),
        valid_for_ms: DurationMs::new(60_000),
    }
}

fn bitmap(upload: &Staged) -> ChunkBitmap {
    let mut bitmap = ChunkBitmap::empty(upload.layout.chunk_count.get());
    for index in upload.chunks.keys() {
        bitmap.insert(*index);
    }
    bitmap
}

fn unknown() -> ProtocolError {
    ProtocolError::new(ErrorCode::InvalidArgument, "no such transfer")
}

fn typed<T: serde::Serialize>(value: &T) -> Result<ParamsValue, ProtocolError> {
    ParamsValue::from_typed(value)
        .map_err(|error| ProtocolError::new(ErrorCode::InvalidArgument, error.to_string()))
}

fn answer(request_id: RequestId, outcome: Result<ParamsValue, ProtocolError>) -> ControlFrame {
    ControlFrame::Response(Response {
        request_id,
        outcome: match outcome {
            Ok(value) => Outcome::Ok(value),
            Err(error) => Outcome::Error(error),
        },
    })
}

fn parameters<T: kr_protocol::wire::WireMessage>(params: &ParamsValue) -> Result<T, ProtocolError> {
    params
        .to_typed()
        .map_err(|error| ProtocolError::new(ErrorCode::InvalidArgument, error.to_string()))
}

/// Serves one of the two endpoints until the host goes.
async fn serve(host: std::sync::Weak<Host>, listener: Listener, chunks: bool) {
    let mut connections = 0_usize;
    loop {
        let Ok((connection, peer)) = listener.accept().await else {
            return;
        };
        let Some(host) = host.upgrade() else {
            return;
        };
        let kind = if chunks {
            StreamKind::AttachmentChunks
        } else {
            StreamKind::Control
        };
        let (reader, writer) = split(connection, kind);
        let leg = if chunks {
            let mut seen = host.seen.lock().expect("what the host saw");
            seen.legs.push(Vec::new());
            Some(seen.legs.len() - 1)
        } else {
            None
        };
        let first = connections == 0;
        connections += 1;
        tokio::spawn(converse(host, reader, writer, peer, leg, first));
    }
}

/// Answers one connection until it ends, or until the script ends it.
async fn converse(
    host: Arc<Host>,
    mut reader: FrameReader,
    mut writer: FrameWriter,
    peer: PeerIdentity,
    leg: Option<usize>,
    first: bool,
) {
    let Ok(ControlFrame::Hello(_)) = reader.read_message::<ControlFrame>().await else {
        return;
    };
    if leg.is_some() && host.script.drop_hello {
        return;
    }
    let environment_id = match leg {
        Some(_) => host
            .script
            .chunk_environment
            .unwrap_or_else(|| host.environment_id()),
        None => host.environment_id(),
    };
    let issued = if leg.is_none() && host.script.no_control_window {
        ActionWindow {
            valid_for_ms: DurationMs::new(0),
            ..action_window(window("window-1"))
        }
    } else {
        action_window(window("window-1"))
    };
    if writer
        .write_message(&host.acknowledgement(&peer, environment_id, issued))
        .await
        .is_err()
    {
        return;
    }
    if leg.is_some() && host.script.stray_frame {
        let stray = host.acknowledgement(&peer, environment_id, action_window(window("window-9")));
        if writer.write_message(&stray).await.is_err() {
            return;
        }
    }
    let mut current = window("window-1");
    if let (Some(_), Some(renewal)) = (leg, host.script.renewal.clone()) {
        for _ in 0..host.script.keepalives_before_renewal {
            if writer
                .write_message(&ControlFrame::Event(ControlEvent::Keepalive))
                .await
                .is_err()
            {
                return;
            }
        }
        let renewed = ControlFrame::Event(ControlEvent::ActionWindowRenewed(action_window(
            renewal.clone(),
        )));
        if writer.write_message(&renewed).await.is_err() {
            return;
        }
        host.seen.lock().expect("what the host saw").renewals += 1;
        current = renewal;
    }
    let mut carried = 0_usize;
    loop {
        let Ok(frame) = reader.read_message::<ControlFrame>().await else {
            return;
        };
        let reply = match frame {
            ControlFrame::Mutation(mutation) => {
                let MutationRequest {
                    request_id,
                    method,
                    method_version,
                    action_id,
                    params,
                    action_window_id,
                    ..
                } = *mutation;
                match (method.method(), leg) {
                    (Some(Method::UploadChunk), Some(_))
                        if host.script.expire_first_window && action_window_id != current =>
                    {
                        answer(
                            request_id,
                            Err(ProtocolError::new(
                                ErrorCode::PermissionDenied,
                                "the action window has expired",
                            )),
                        )
                    }
                    (Some(Method::UploadChunk), Some(leg)) => {
                        let outcome = parameters::<UploadChunkParams>(&params).and_then(|chunk| {
                            let index = chunk.chunk.index.get();
                            let outcome = host.chunk(chunk);
                            let mut seen = host.seen.lock().expect("what the host saw");
                            seen.windows.push(action_window_id.to_string());
                            seen.legs[leg].push(index);
                            outcome
                        });
                        carried += 1;
                        if first && host.script.drop_after_chunks == Some(carried) {
                            // Stored, and never answered: the connection ends here.
                            return;
                        }
                        answer(request_id, outcome)
                    }
                    (Some(Method::UploadBegin), None) => {
                        host.seen.lock().expect("what the host saw").reservations += 1;
                        let reserved = parameters(&params).and_then(|p| host.begin(p));
                        match host.script.reservation {
                            Reply::Answer => answer(request_id, reserved),
                            Reply::Drop => return,
                            Reply::Unknown => answer(
                                request_id,
                                Err(ProtocolError::new(
                                    ErrorCode::OutcomeUnknown,
                                    "the host could not report what became of the reservation",
                                )),
                            ),
                            Reply::Receipt(state) => {
                                ControlFrame::Receipt(Box::new(ReceiptResponse {
                                    request_id,
                                    receipt: Receipt {
                                        action_id,
                                        actor_id: ActorId::new("local:501").expect("a principal"),
                                        method,
                                        method_version,
                                        revision: U64::new(1),
                                        state,
                                        reason: Nullable::null(),
                                        payload_digest: Digest256::from_bytes([0; 32]),
                                        accepted_deadline_ms: Nullable::null(),
                                        error: Nullable::null(),
                                        updated_at_ms: TimestampMs::new(0),
                                    },
                                }))
                            }
                            Reply::Hold => {
                                std::future::pending::<()>().await;
                                return;
                            }
                            Reply::Unreadable => answer(request_id, typed(&serde_json::json!({}))),
                        }
                    }
                    (Some(Method::UploadFinish), None) => answer(
                        request_id,
                        parameters::<UploadFinishParams>(&params).and_then(|p| host.finish(&p)),
                    ),
                    _ => answer(
                        request_id,
                        Err(ProtocolError::new(
                            ErrorCode::PermissionDenied,
                            "this endpoint does not carry that method",
                        )),
                    ),
                }
            }
            ControlFrame::Request(Request {
                request_id,
                method,
                params,
                ..
            }) => match (method.method(), leg) {
                (Some(Method::UploadStatus), None) => answer(
                    request_id,
                    parameters::<UploadStatusParams>(&params).and_then(|p| host.status(&p)),
                ),
                (Some(Method::DownloadChunk), Some(_)) => answer(
                    request_id,
                    parameters::<DownloadChunkParams>(&params).and_then(|p| host.download(&p)),
                ),
                _ => answer(
                    request_id,
                    Err(ProtocolError::new(
                        ErrorCode::PermissionDenied,
                        "this endpoint does not carry that method",
                    )),
                ),
            },
            _ => return,
        };
        if writer.write_message(&reply).await.is_err() {
            return;
        }
    }
}

/// Reserves one upload directly, for a test that drives a lane by hand.
async fn reserve(host: &Host, session: &Session, bytes: &[u8]) -> UploadBeginResult {
    let settled = session
        .mutate(
            Method::UploadBegin,
            host.target(),
            None,
            &serde_json::json!({}),
            &UploadBeginParams {
                environment_id: host.environment_id(),
                session_id: Nullable::null(),
                device_id: Nullable::null(),
                declared_byte_len: U64::new(bytes.len() as u64),
                declared_digest: digest(bytes),
                declared_media_type: "application/octet-stream".to_owned(),
                original_file_name: "capture.bin".to_owned(),
            },
            TTL,
        )
        .await
        .expect("the host reserves the upload");
    settled.to_typed().expect("a reservation")
}

fn chunk_of(transfer_id: TransferId, bytes: &[u8], index: u64) -> UploadChunkParams {
    let layout = ChunkLayout::for_length(bytes.len() as u64);
    let start = usize::try_from(layout.offset_of(index).expect("an index")).expect("an offset");
    let len = usize::try_from(layout.length_of(index).expect("an index")).expect("a length");
    let payload = &bytes[start..start + len];
    UploadChunkParams {
        transfer_id,
        chunk: ChunkDescriptor {
            index: U64::new(index),
            byte_len: U64::new(len as u64),
            digest: digest(payload),
        },
        bytes: Bytes::new(payload.to_vec()),
    }
}

/// KR-REQ-23.21: a full chunk travels on the attachment-chunk lane, which adopts the window the host
/// renews on it without being asked.
#[tokio::test]
async fn a_full_chunk_travels_on_the_lane_under_the_window_the_host_renewed() {
    let host = Host::start(Script {
        renewal: Some(window("window-2")),
        ..Script::default()
    });
    let session = host.session().await;
    let bytes = pattern(UPLOAD_CHUNK_LEN + 10);
    let mut plan = Upload::new(host.subject(), Box::new(Held::new(bytes.clone())));

    let handle = uploads::send(&session, &host.route(), &host.target(), &mut plan, TTL)
        .await
        .expect("the upload reaches a handle");
    assert_eq!(handle.content_digest, digest(&bytes));
    assert_eq!(handle.byte_len.get(), bytes.len() as u64);

    let seen = host.seen();
    assert_eq!(seen.legs, vec![vec![0, 1]], "one lane carried both chunks");
    // The first chunk went under whichever of the two windows the lane had read when it was built;
    // the renewal was read by the time the second one was, at the latest with the first answer.
    assert_eq!(seen.windows.len(), 2);
    assert!(["window-1", "window-2"].contains(&seen.windows[0].as_str()));
    assert_eq!(seen.windows[1], "window-2");
    assert_eq!(seen.reservations, 1);
    assert_eq!(seen.publications, 1);
}

/// A lane carries one transfer's chunks, and refuses another's before anything is sent.
#[tokio::test]
async fn a_lane_refuses_another_transfers_chunk_before_sending_it() {
    let host = Host::start(Script::default());
    let session = host.session().await;
    let bytes = pattern(4096);
    let reserved = reserve(&host, &session, &bytes).await;
    let mut lane = host
        .route()
        .open(reserved.transfer_id)
        .await
        .expect("a lane");
    assert_eq!(lane.transfer_id(), reserved.transfer_id);

    let other = TransferId::new(Uuid::from_bytes([9; 16]));
    let refused = lane
        .send_chunk(&host.target(), &chunk_of(other, &bytes, 0), TTL)
        .await
        .expect_err("another transfer's chunk is refused");
    assert_eq!(refused.code(), ErrorCode::InvalidArgument);
    assert_eq!(
        host.seen().legs,
        vec![Vec::<u64>::new()],
        "nothing reached the host"
    );

    // The lane is still whole, and carries its own transfer's chunk.
    let accepted = lane
        .send_chunk(
            &host.target(),
            &chunk_of(reserved.transfer_id, &bytes, 0),
            TTL,
        )
        .await
        .expect("the lane's own chunk is accepted");
    assert_eq!(accepted.index, U64::new(0));
}

/// KR-REQ-14.16: a downloaded chunk comes back only when it is exactly the chunk the download
/// described, bytes and all.
#[tokio::test]
async fn a_downloaded_chunk_that_is_not_the_one_described_is_refused() {
    let bytes = pattern(4096);
    let described = ChunkDescriptor {
        index: U64::new(0),
        byte_len: U64::new(4096),
        digest: digest(&bytes),
    };
    let mut tampered = bytes.clone();
    tampered[17] ^= 1;
    let other_descriptor = ChunkDescriptor {
        index: U64::new(1),
        byte_len: U64::new(4096),
        digest: digest(&tampered),
    };
    let host = Host::start(Script {
        download: BTreeMap::from([
            // Index 0: the right descriptor with bytes that do not match it.
            (0, (described, tampered.clone())),
            // Index 1: bytes that match the descriptor the host sent, which is not the one the
            // download described.
            (1, (other_descriptor, tampered)),
            // Index 2: exactly what was described.
            (
                2,
                (
                    ChunkDescriptor {
                        index: U64::new(2),
                        ..described
                    },
                    bytes.clone(),
                ),
            ),
        ]),
        ..Script::default()
    });
    let transfer_id = TransferId::new(Uuid::from_bytes([7; 16]));
    let mut lane = host.route().open(transfer_id).await.expect("a lane");

    let refused = lane
        .read_chunk(&described)
        .await
        .expect_err("bytes that do not match their descriptor are refused");
    assert_eq!(refused.code(), ErrorCode::AttachmentIntegrity);
    let refused = lane
        .read_chunk(&ChunkDescriptor {
            index: U64::new(1),
            ..described
        })
        .await
        .expect_err("a chunk other than the one described is refused");
    assert_eq!(refused.code(), ErrorCode::AttachmentIntegrity);
    let read = lane
        .read_chunk(&ChunkDescriptor {
            index: U64::new(2),
            ..described
        })
        .await
        .expect("the chunk described is read");
    assert_eq!(read.as_slice(), bytes.as_slice());
}

/// An attachment-chunk endpoint answered in another environment's name is not where this
/// environment's chunks go.
#[tokio::test]
async fn a_chunk_endpoint_answered_for_another_environment_is_refused() {
    let host = Host::start(Script {
        chunk_environment: Some(EnvironmentId::new(Uuid::from_bytes([8; 16]))),
        ..Script::default()
    });
    let refused = host
        .route()
        .open(TransferId::new(Uuid::from_bytes([7; 16])))
        .await
        .expect_err("the lane is refused");
    assert_eq!(refused.code(), ErrorCode::PermissionDenied);
}

/// A lane whose hello goes unanswered is a lost connection, as one lost later is.
#[tokio::test]
async fn a_hello_the_host_never_answers_is_a_lost_connection() {
    let host = Host::start(Script {
        drop_hello: true,
        ..Script::default()
    });
    let lost = host
        .route()
        .open(TransferId::new(Uuid::from_bytes([7; 16])))
        .await
        .expect_err("the lane is not opened");
    assert!(matches!(lost, ClientError::ConnectionEnded), "{lost}");
}

/// A lane whose connection ended says so, and sends nothing on it again.
#[tokio::test]
async fn a_lost_connection_ends_the_lane() {
    let host = Host::start(Script {
        drop_after_chunks: Some(1),
        ..Script::default()
    });
    let session = host.session().await;
    let bytes = pattern(UPLOAD_CHUNK_LEN + 10);
    let reserved = reserve(&host, &session, &bytes).await;
    let mut lane = host
        .route()
        .open(reserved.transfer_id)
        .await
        .expect("a lane");

    let lost = lane
        .send_chunk(
            &host.target(),
            &chunk_of(reserved.transfer_id, &bytes, 0),
            TTL,
        )
        .await
        .expect_err("the connection ended before the answer");
    assert!(matches!(lost, ClientError::ConnectionEnded), "{lost}");
    let again = lane
        .send_chunk(
            &host.target(),
            &chunk_of(reserved.transfer_id, &bytes, 1),
            TTL,
        )
        .await
        .expect_err("the lane has ended");
    assert!(matches!(again, ClientError::ConnectionEnded), "{again}");
    assert_eq!(
        host.seen().legs,
        vec![vec![0]],
        "the second chunk was never sent"
    );
}

/// KR-REQ-14.12: the driver resumes an upload whose lane dropped from the host's status, under the
/// same upload identifier, and sends only what the host is missing.
///
/// The host stores the second chunk and ends the connection without answering, so the client never
/// hears that chunk arrived; only the status tells it not to send it again.
#[tokio::test]
async fn the_driver_resumes_from_the_status_bitmap_after_its_lane_drops() {
    let host = Host::start(Script {
        drop_after_chunks: Some(2),
        ..Script::default()
    });
    let session = host.session().await;
    let bytes = pattern(3 * UPLOAD_CHUNK_LEN + 10);
    let mut plan = Upload::new(host.subject(), Box::new(Held::new(bytes.clone())));

    let handle = uploads::send(&session, &host.route(), &host.target(), &mut plan, TTL)
        .await
        .expect("the upload resumes and reaches a handle");
    assert_eq!(handle.content_digest, digest(&bytes));
    assert_eq!(Some(&handle.transfer_id), plan.transfer_id());

    let seen = host.seen();
    assert_eq!(seen.legs, vec![vec![0, 1], vec![2, 3]]);
    assert_eq!(seen.reservations, 1, "one upload identifier throughout");
    assert_eq!(seen.publications, 1);
    assert!(seen.statuses >= 1, "the driver asked the host what it held");
}

/// A plan that already holds a transfer starts from the host's status, so an upload the host has
/// published is not published again: the case of a publication whose reply was lost.
#[tokio::test]
async fn a_plan_that_holds_a_transfer_starts_from_status() {
    let host = Host::start(Script::default());
    let session = host.session().await;
    let bytes = pattern(UPLOAD_CHUNK_LEN + 10);
    let mut first = Upload::new(host.subject(), Box::new(Held::new(bytes.clone())));
    let published = uploads::send(&session, &host.route(), &host.target(), &mut first, TTL)
        .await
        .expect("the upload reaches a handle");

    let mut resumed = Upload::resuming(
        host.subject(),
        Box::new(Held::new(bytes)),
        published.transfer_id,
    );
    let handle = uploads::send(&session, &host.route(), &host.target(), &mut resumed, TTL)
        .await
        .expect("the resumed plan reaches the published handle");
    assert_eq!(handle, published);

    let seen = host.seen();
    assert_eq!(seen.publications, 1, "nothing was published twice");
    assert_eq!(seen.legs.len(), 1, "the resumed plan opened no lane");
}

/// A reservation whose reply was lost is never made again by the same plan.
#[tokio::test]
async fn an_uncertain_reservation_is_never_reserved_again() {
    let host = Host::start(Script {
        reservation: Reply::Drop,
        ..Script::default()
    });
    let session = host.session().await;
    let mut plan = Upload::new(host.subject(), Box::new(Held::new(pattern(4096))));

    let uncertain = uploads::send(&session, &host.route(), &host.target(), &mut plan, TTL)
        .await
        .expect_err("the reservation's reply was lost");
    let ClientError::SubmissionUncertain { action_id } = uncertain else {
        panic!("the reservation is uncertain, not {uncertain}");
    };
    let refused = plan.next().expect_err("the plan will not reserve again");
    assert_eq!(refused.code(), ErrorCode::OutcomeUnknown);
    assert!(refused.to_string().contains(&action_id.to_string()));

    let reconnected = host.session().await;
    let refused = uploads::send(&reconnected, &host.route(), &host.target(), &mut plan, TTL)
        .await
        .expect_err("a new session does not reserve again either");
    assert_eq!(refused.code(), ErrorCode::OutcomeUnknown);
    assert_eq!(host.seen().reservations, 1);
}

/// Asks for a reservation the host answers as `reply`, and checks that the plan will not ask for
/// another, on this session or a new one.
async fn never_reserved_twice(reply: Reply) -> ClientError {
    let host = Host::start(Script {
        reservation: reply,
        ..Script::default()
    });
    let session = host.session().await;
    let mut plan = Upload::new(host.subject(), Box::new(Held::new(pattern(4096))));

    let first = uploads::send(&session, &host.route(), &host.target(), &mut plan, TTL)
        .await
        .expect_err("the reservation has no definite answer");
    let refused = plan.next().expect_err("the plan will not reserve again");
    assert_eq!(refused.code(), ErrorCode::OutcomeUnknown);
    let refused = uploads::send(&session, &host.route(), &host.target(), &mut plan, TTL)
        .await
        .expect_err("the same session does not reserve again");
    assert_eq!(refused.code(), ErrorCode::OutcomeUnknown);
    let reconnected = host.session().await;
    let refused = uploads::send(&reconnected, &host.route(), &host.target(), &mut plan, TTL)
        .await
        .expect_err("a new session does not reserve again either");
    assert_eq!(refused.code(), ErrorCode::OutcomeUnknown);
    assert_eq!(host.seen().reservations, 1);
    first
}

/// A host that says it cannot report what became of a reservation has not said it made none.
#[tokio::test]
async fn a_reservation_the_host_could_not_report_is_never_reserved_again() {
    let first = never_reserved_twice(Reply::Unknown).await;
    assert_eq!(first.code(), ErrorCode::OutcomeUnknown);
}

/// A receipt without the reservation's result names the action, and nothing more.
#[tokio::test]
async fn a_reservation_settled_by_a_receipt_alone_is_never_reserved_again() {
    let first = never_reserved_twice(Reply::Receipt(ReceiptState::Accepted)).await;
    assert_eq!(first.code(), ErrorCode::OutcomeUnknown);
}

/// A receipt that says the reservation never took effect is as definite as a refusal, so the plan
/// may ask again.
#[tokio::test]
async fn a_reservation_whose_receipt_says_it_never_took_effect_may_be_asked_for_again() {
    for state in [ReceiptState::Refused, ReceiptState::Rejected] {
        let host = Host::start(Script {
            reservation: Reply::Receipt(state),
            ..Script::default()
        });
        let session = host.session().await;
        let mut plan = Upload::new(host.subject(), Box::new(Held::new(pattern(4096))));

        let refused = uploads::send(&session, &host.route(), &host.target(), &mut plan, TTL)
            .await
            .expect_err("the host's receipt refuses the reservation");
        assert_ne!(refused.code(), ErrorCode::OutcomeUnknown, "{state:?}");
        assert!(
            matches!(plan.next(), Ok(uploads::Step::Begin(_))),
            "{state:?}: the plan may ask again"
        );
        let _ = uploads::send(&session, &host.route(), &host.target(), &mut plan, TTL).await;
        assert_eq!(host.seen().reservations, 2, "{state:?}: it asked again");
    }
}

/// A caller that abandons the call after the host has taken the reservation leaves a plan that
/// knows a reservation may exist.
#[tokio::test]
async fn a_reservation_abandoned_in_flight_is_never_reserved_again() {
    let host = Host::start(Script {
        reservation: Reply::Hold,
        ..Script::default()
    });
    let session = host.session().await;
    let mut plan = Upload::new(host.subject(), Box::new(Held::new(pattern(4096))));

    let route = host.route();
    let target = host.target();
    {
        let first = uploads::send(&session, &route, &target, &mut plan, TTL);
        tokio::pin!(first);
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            tokio::select! {
                outcome = &mut first => panic!("the host never answers, and yet: {outcome:?}"),
                () = tokio::time::sleep(std::time::Duration::from_millis(10)) => {
                    if host.seen().reservations == 1 {
                        break;
                    }
                    assert!(tokio::time::Instant::now() < deadline, "the host saw no reservation");
                }
            }
        }
        // The call is abandoned here, with the host holding the reservation it never answered.
    }
    let refused = plan.next().expect_err("the plan will not reserve again");
    assert_eq!(refused.code(), ErrorCode::OutcomeUnknown);
    let refused = uploads::send(&session, &host.route(), &host.target(), &mut plan, TTL)
        .await
        .expect_err("the plan does not reserve again");
    assert_eq!(refused.code(), ErrorCode::OutcomeUnknown);
    assert_eq!(host.seen().reservations, 1);
}

/// A result that is not a reservation says nothing of whether one was made.
#[tokio::test]
async fn a_reservation_answered_with_an_unreadable_result_is_never_reserved_again() {
    never_reserved_twice(Reply::Unreadable).await;
}

/// A reservation that never left this client reserved nothing, so the plan may ask again.
#[tokio::test]
async fn a_reservation_that_never_left_the_client_may_be_asked_for_again() {
    let host = Host::start(Script {
        no_control_window: true,
        ..Script::default()
    });
    let session = host.session().await;
    let mut plan = Upload::new(host.subject(), Box::new(Held::new(pattern(4096))));

    let refused = uploads::send(&session, &host.route(), &host.target(), &mut plan, TTL)
        .await
        .expect_err("a session with no window sends no reservation");
    assert!(matches!(refused, ClientError::NoActionWindow), "{refused}");
    assert!(matches!(plan.next(), Ok(uploads::Step::Begin(_))));
    assert_eq!(host.seen().reservations, 0);
}

/// A refusal the host decided leaves nothing reserved, so the plan may ask again.
#[tokio::test]
async fn a_refused_reservation_may_be_asked_for_again() {
    let host = Host::start(Script::default());
    let session = host.session().await;
    let mut plan = Upload::new(
        Subject {
            // An environment the host does not own, which it refuses.
            environment_id: EnvironmentId::new(Uuid::from_bytes([8; 16])),
            ..host.subject()
        },
        Box::new(Held::new(pattern(4096))),
    );
    let refused = uploads::send(&session, &host.route(), &host.target(), &mut plan, TTL)
        .await
        .expect_err("the host refuses a reservation for another environment");
    assert_ne!(refused.code(), ErrorCode::OutcomeUnknown);
    assert!(matches!(plan.next(), Ok(uploads::Step::Begin(_))));
}

/// A lane that sat idle while its window expired sends its next chunk under the window the host
/// renewed meanwhile, not the one it opened with.
#[tokio::test]
async fn an_idle_lane_sends_under_the_window_the_host_renewed_while_it_waited() {
    let host = Host::start(Script {
        renewal: Some(window("window-2")),
        expire_first_window: true,
        ..Script::default()
    });
    let session = host.session().await;
    let bytes = pattern(4096);
    let reserved = reserve(&host, &session, &bytes).await;
    let mut lane = host
        .route()
        .open(reserved.transfer_id)
        .await
        .expect("a lane");
    // The lane waits, and the host renews its window and lets the first one expire meanwhile.
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
    while host.seen().renewals == 0 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the host never renewed"
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let accepted = lane
        .send_chunk(
            &host.target(),
            &chunk_of(reserved.transfer_id, &bytes, 0),
            TTL,
        )
        .await
        .expect("the chunk goes under the renewed window");
    assert_eq!(accepted.index, U64::new(0));
    assert_eq!(host.seen().windows, vec!["window-2"]);
}

/// A lane that sat idle under a backlog of keepalives still sends under the window the host
/// renewed after them: the lane keeps up with its connection while nothing is being sent.
#[tokio::test]
async fn a_lane_behind_a_backlog_of_keepalives_sends_under_the_window_renewed_after_them() {
    let host = Host::start(Script {
        renewal: Some(window("window-2")),
        expire_first_window: true,
        keepalives_before_renewal: 300,
        ..Script::default()
    });
    let session = host.session().await;
    let bytes = pattern(4096);
    let reserved = reserve(&host, &session, &bytes).await;
    let mut lane = host
        .route()
        .open(reserved.transfer_id)
        .await
        .expect("a lane");
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
    while host.seen().renewals == 0 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the host never renewed"
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    lane.send_chunk(
        &host.target(),
        &chunk_of(reserved.transfer_id, &bytes, 0),
        TTL,
    )
    .await
    .expect("the chunk goes under the renewed window");
    assert_eq!(host.seen().windows, vec!["window-2"]);
}

/// A lane whose reader stopped at a frame it cannot carry sends nothing more, even though the
/// connection is still open: the next call fails with what the reader said.
#[tokio::test]
async fn a_lane_whose_reader_stopped_sends_nothing_more() {
    let host = Host::start(Script {
        stray_frame: true,
        ..Script::default()
    });
    let session = host.session().await;
    let bytes = pattern(4096);
    let reserved = reserve(&host, &session, &bytes).await;
    let mut lane = host
        .route()
        .open(reserved.transfer_id)
        .await
        .expect("a lane");
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let refused = lane
        .send_chunk(
            &host.target(),
            &chunk_of(reserved.transfer_id, &bytes, 0),
            TTL,
        )
        .await
        .expect_err("the lane has stopped");
    assert_eq!(refused.code(), ErrorCode::InvalidArgument, "{refused}");
    let again = lane
        .send_chunk(
            &host.target(),
            &chunk_of(reserved.transfer_id, &bytes, 0),
            TTL,
        )
        .await
        .expect_err("the lane stays stopped");
    assert!(matches!(again, ClientError::ConnectionEnded), "{again}");
    // Time for a chunk that did go out to reach the host's record.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert_eq!(
        host.seen().legs,
        vec![Vec::<u64>::new()],
        "no chunk went out"
    );
}
