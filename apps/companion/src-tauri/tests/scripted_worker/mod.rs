//! A session worker the test scripts, reached the way a raw terminal view reaches a real one.
//!
//! The view reads a descriptor from the host's runtime directory, connects to the endpoint it names,
//! challenges the worker and only then attaches. This publishes a real descriptor in a disposable
//! host tree on the internal disk, listens on the endpoint it names, answers the opening exchange
//! and the challenge with a real per-session key, and then hands each connection to the test, which
//! reads the calls the view makes and answers them, and pushes the events a session would.
//!
//! Every frame is a real protocol value: the view under test decodes what a worker sends.

#![allow(dead_code, reason = "each suite uses the part of the script it needs")]

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use kr_ipc::endpoint::Listener;
use kr_ipc::framed::{FrameReader, FrameWriter, split};
use kr_ipc::paths::EnvironmentPaths;
use kr_ipc::testing::TempHost;
use kr_ipc::verify::WorkerIdentity;
use kr_protocol::attachment::{
    AttachMode, AttachmentSummary, GeometryState, SessionAttachParams, SessionAttachResult,
    TerminalPresentationMode,
};
use kr_protocol::envelope::{ControlFrame, Notification, Outcome, ParamsValue, Response};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::frame::StreamKind;
use kr_protocol::hello::{ActionWindow, PROTOCOL_VERSION, ReceiveLimits};
use kr_protocol::identity::WorkerProfile;
use kr_protocol::ids::{
    ActionWindowId, AttachmentId, BootEpoch, ConnectionId, EnvironmentId, EventSequence, EventType,
    GeometryEpoch, RequestId, SessionEpoch, SessionId, StreamId,
};
use kr_protocol::local::{LocalHelloAck, LocalPeer, LocalRole};
use kr_protocol::method::Method;
use kr_protocol::projection::{
    CellRendition, CellRun, CharsetState, KittyKeyboardState, MarginState, PaletteProvenance,
    PaletteState, ProjectedBuffer, ProjectedCursor, ProjectedKeyboard, ProjectedRow,
    ProjectedTitle, ProjectedViewport, ProjectionDelta, ProjectionReset, ProjectionResetReason,
    ProjectionRowPage, ProjectionSnapshot, Rgb,
};
use kr_protocol::recovery::EventsSubscribeResult;
use kr_protocol::scalars::{CanonicalSet, DurationMs, Nullable, TimestampMs, U64};
use kr_protocol::session::{Dimensions, DisplayNumber};
use kr_protocol::worker::WorkerDescriptor;

/// How long a script waits for the view before it calls the test a failure.
pub const WATCHDOG: Duration = Duration::from_secs(20);

/// The stream every notification of a worker's output is carried on.
pub const OUTPUT_STREAM: &str = "session.output";

/// How the scripted worker answers the view's challenge.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Challenge {
    /// With the key the descriptor names.
    Answered,
    /// With a key of another worker's, which the view must refuse.
    Forged,
}

/// The display number of the next worker this process starts, so two never share an endpoint.
static NEXT_DISPLAY: AtomicU64 = AtomicU64::new(1);

/// One scripted worker, the host tree it is published in and the connections views open to it.
pub struct ScriptedWorker {
    /// The host tree, when this worker was started in one of its own.
    host: Option<TempHost>,
    environment: EnvironmentPaths,
    environment_id: EnvironmentId,
    pub session_id: SessionId,
    pub descriptor: WorkerDescriptor,
    accepted: tokio::sync::mpsc::UnboundedReceiver<Link>,
    serving: tokio::task::JoinHandle<()>,
}

impl Drop for ScriptedWorker {
    fn drop(&mut self) {
        self.serving.abort();
    }
}

impl ScriptedWorker {
    /// A worker for one session, published in a fresh host tree, answering its challenge as told.
    pub fn start(challenge: Challenge) -> Self {
        let host = TempHost::create();
        let mut worker = Self::publish(host.environment(), host.environment_id(), challenge);
        worker.host = Some(host);
        worker
    }

    /// A second session's worker, published in the host tree `beside` is.
    pub fn start_beside(beside: &Self, challenge: Challenge) -> Self {
        Self::publish(beside.environment.clone(), beside.environment_id, challenge)
    }

    /// The host tree's environment, where the application reads descriptors.
    pub fn paths(&self) -> EnvironmentPaths {
        self.environment.clone()
    }

    fn publish(
        environment: EnvironmentPaths,
        environment_id: EnvironmentId,
        challenge: Challenge,
    ) -> Self {
        let session_id = SessionId::new(kr_ipc::new_uuid());
        let boot = kr_ipc::identity::boot_identity().expect("a boot identity");
        let process =
            kr_ipc::identity::current_process_start_identity().expect("a process identity");
        let identity = WorkerIdentity::generate(
            session_id,
            SessionEpoch::V1,
            boot.clone(),
            process.clone(),
            PROTOCOL_VERSION,
        )
        .expect("a session key");
        // Another key for the same session, which answers the challenge with a signature the
        // descriptor's key does not verify.
        let impostor = WorkerIdentity::generate(
            session_id,
            SessionEpoch::V1,
            boot.clone(),
            process.clone(),
            PROTOCOL_VERSION,
        )
        .expect("another session key");
        let display = DisplayNumber::new(NEXT_DISPLAY.fetch_add(1, Ordering::Relaxed));
        let endpoint = environment
            .worker_endpoint(display)
            .expect("an endpoint for the session");
        let listener = Listener::bind(&endpoint).expect("the worker listens");
        let descriptor = WorkerDescriptor {
            session_id,
            session_epoch: SessionEpoch::V1,
            environment_id,
            display_number: display,
            boot_identity: boot,
            process_start_identity: process,
            protocol_version: PROTOCOL_VERSION,
            endpoint: endpoint.as_text(),
            worker_public_key: *identity.public_key(),
            worker_profile: WorkerProfile::HeadlessUser,
            published_at_ms: TimestampMs::new(0),
        };
        kr_ipc::descriptor::publish(&environment, &descriptor)
            .expect("the descriptor is published");
        let (handing, accepted) = tokio::sync::mpsc::unbounded_channel();
        let endpoint_text = endpoint.as_text();
        let serving = tokio::spawn(async move {
            loop {
                let Ok((connection, peer)) = listener.accept().await else {
                    return;
                };
                let (mut reader, mut writer) = split(connection, StreamKind::Control);
                let Ok(ControlFrame::Hello(_)) = reader.read_message::<ControlFrame>().await else {
                    continue;
                };
                let connection_id = ConnectionId::new(kr_ipc::new_uuid());
                let acknowledgement = LocalHelloAck {
                    selected_version: PROTOCOL_VERSION,
                    role: LocalRole::Worker,
                    connection_id,
                    environment_id,
                    boot_identity: kr_ipc::identity::boot_identity().expect("a boot identity"),
                    peer: LocalPeer {
                        uid: U64::new(u64::from(peer.uid)),
                        gid: U64::new(u64::from(peer.gid)),
                        pid: Nullable::null(),
                    },
                    action_window: ActionWindow {
                        action_window_id: ActionWindowId::new("window-1")
                            .expect("a literal window identifier"),
                        connection_id,
                        boot_epoch: BootEpoch::new(1),
                        issued_at_ms: TimestampMs::new(0),
                        valid_for_ms: DurationMs::new(60_000),
                    },
                    capabilities: CanonicalSet::new(),
                    max_receive: ReceiveLimits::default(),
                };
                if writer
                    .write_message(&ControlFrame::HelloAck(Box::new(acknowledgement)))
                    .await
                    .is_err()
                {
                    continue;
                }
                let Ok(ControlFrame::VerifyChallenge(asked)) =
                    reader.read_message::<ControlFrame>().await
                else {
                    continue;
                };
                let signer = match challenge {
                    Challenge::Answered => &identity,
                    Challenge::Forged => &impostor,
                };
                let proof = signer
                    .answer(&asked, &endpoint_text)
                    .expect("the challenge is answered");
                if writer
                    .write_message(&ControlFrame::VerifyProof(proof))
                    .await
                    .is_err()
                {
                    continue;
                }
                let _ = handing.send(Link {
                    reader,
                    writer,
                    sequence: 0,
                    session_id,
                });
            }
        });
        Self {
            host: None,
            environment,
            environment_id,
            session_id,
            descriptor,
            accepted,
            serving,
        }
    }

    /// The next connection a view opened, once it has proved nothing and been answered.
    pub async fn link(&mut self) -> Link {
        tokio::time::timeout(WATCHDOG, self.accepted.recv())
            .await
            .expect("a view connected within the watchdog")
            .expect("the worker is still listening")
    }

    /// Whether a view has connected since the last one the test took.
    pub fn connected(&mut self) -> bool {
        !self.accepted.is_empty()
    }
}

/// One view's connection to the scripted worker.
pub struct Link {
    reader: FrameReader,
    writer: FrameWriter,
    /// The sequence of the next notification on the output stream.
    sequence: u64,
    session_id: SessionId,
}

/// One call a view made: a read or a mutation, with what it asked.
#[derive(Debug)]
pub struct Call {
    pub request_id: RequestId,
    pub method: String,
    pub params: ParamsValue,
}

impl Call {
    /// The call's parameters as `T`.
    pub fn params<T: kr_protocol::wire::WireMessage>(&self) -> T {
        self.params
            .to_typed()
            .unwrap_or_else(|error| panic!("{}'s parameters: {error:?}", self.method))
    }
}

impl Link {
    /// The next call the view makes.
    pub async fn call(&mut self) -> Call {
        let frame = tokio::time::timeout(WATCHDOG, self.reader.read_message::<ControlFrame>())
            .await
            .expect("the view called within the watchdog")
            .expect("the view's connection is open");
        match frame {
            ControlFrame::Request(request) => Call {
                request_id: request.request_id,
                method: request.method.to_string(),
                params: request.params,
            },
            ControlFrame::Mutation(mutation) => Call {
                request_id: mutation.request_id,
                method: mutation.method.to_string(),
                params: mutation.params,
            },
            other => panic!("the view sent {other:?} rather than a call"),
        }
    }

    /// The next call, which has to be `method`.
    pub async fn expect(&mut self, method: Method) -> Call {
        let call = self.call().await;
        assert_eq!(call.method, method.to_string(), "the view's next call");
        call
    }

    /// Whether the view sends nothing more within `quiet`.
    pub async fn quiet_for(&mut self, quiet: Duration) -> bool {
        tokio::time::timeout(quiet, self.reader.read_message::<ControlFrame>())
            .await
            .is_err()
    }

    /// Waits for the view to close its connection, reading anything it still sends.
    pub async fn closed(&mut self) -> Vec<Call> {
        let mut sent = Vec::new();
        let ended = tokio::time::timeout(WATCHDOG, async {
            loop {
                match self.reader.read_message::<ControlFrame>().await {
                    Ok(ControlFrame::Request(request)) => sent.push(Call {
                        request_id: request.request_id,
                        method: request.method.to_string(),
                        params: request.params,
                    }),
                    Ok(ControlFrame::Mutation(mutation)) => sent.push(Call {
                        request_id: mutation.request_id,
                        method: mutation.method.to_string(),
                        params: mutation.params,
                    }),
                    Ok(_) => {}
                    Err(_) => return,
                }
            }
        })
        .await;
        assert!(
            ended.is_ok(),
            "the view closed its connection within the watchdog"
        );
        sent
    }

    /// Answers `call` with `value`.
    pub async fn answer<T: serde::Serialize>(&mut self, call: &Call, value: &T) {
        let payload = ParamsValue::from_typed(value).expect("an answer the protocol encodes");
        self.writer
            .write_message(&ControlFrame::Response(Response {
                request_id: call.request_id,
                outcome: Outcome::Ok(payload),
            }))
            .await
            .expect("the answer is written");
    }

    /// Refuses `call` with `message`.
    pub async fn refuse(&mut self, call: &Call, message: &str) {
        self.writer
            .write_message(&ControlFrame::Response(Response {
                request_id: call.request_id,
                outcome: Outcome::Error(ProtocolError::new(ErrorCode::InvalidArgument, message)),
            }))
            .await
            .expect("the refusal is written");
    }

    /// Pushes one event on the output stream, at the stream's next sequence.
    pub async fn push<T: serde::Serialize>(&mut self, event_type: &str, payload: &T) {
        let payload = ParamsValue::from_typed(payload).expect("a payload the protocol encodes");
        self.push_raw(event_type, payload).await;
    }

    /// Pushes one event whose payload is whatever `payload` is, decodable or not.
    pub async fn push_raw(&mut self, event_type: &str, payload: ParamsValue) {
        let sequence = self.sequence;
        self.sequence += 1;
        self.writer
            .write_message(&ControlFrame::Notification(Notification {
                stream_id: StreamId::new(OUTPUT_STREAM).expect("a literal stream name"),
                sequence: EventSequence::new(sequence),
                event_type: EventType::new(event_type).expect("a literal event type"),
                payload,
            }))
            .await
            .expect("the event is written");
    }

    /// Starts the stream again, as a new subscription's delivery does: the next event is at 0.
    pub fn restart_stream(&mut self) {
        self.sequence = 0;
    }

    /// Answers the attach and the subscription the way a worker does, and returns the attachment.
    pub async fn attach(&mut self) -> (AttachmentId, SessionAttachParams) {
        let call = self.expect(Method::SessionAttach).await;
        let asked: SessionAttachParams = call.params();
        let attachment_id = AttachmentId::new(kr_ipc::new_uuid());
        let dimensions = asked
            .dimensions
            .0
            .expect("a terminal attachment names its size");
        self.answer(
            &call,
            &SessionAttachResult {
                attachment: summary(attachment_id, dimensions),
                geometry: GeometryState {
                    owner: Nullable::null(),
                    epoch: GeometryEpoch::new(1),
                    dimensions: Dimensions::new(80, 24),
                },
                output_cursor: U64::new(40),
            },
        )
        .await;
        let subscribe = self.expect(Method::EventsSubscribe).await;
        self.answer(&subscribe, &subscribed()).await;
        (attachment_id, asked)
    }
}

/// The summary a worker gives a view that declared no terminal profile.
pub fn summary(attachment_id: AttachmentId, dimensions: Dimensions) -> AttachmentSummary {
    let mut granted = CanonicalSet::new();
    granted.insert(kr_protocol::attachment::AttachmentCapability::ObserveTerminal);
    AttachmentSummary {
        attachment_id,
        ordinal: kr_protocol::ids::AttachmentOrdinal::new(2),
        mode: AttachMode::Terminal,
        claim_geometry: false,
        dimensions: Nullable::some(dimensions),
        presentation: Nullable::some(TerminalPresentationMode::Viewport),
        presentation_reason: Some(kr_protocol::attachment::PresentationReason::NoTerminalProfile),
        terminal_profile_id: Nullable::null(),
        granted,
        attached_at_ms: TimestampMs::new(1),
    }
}

/// A subscription's answer.
pub fn subscribed() -> EventsSubscribeResult {
    EventsSubscribeResult {
        stream_id: StreamId::new(OUTPUT_STREAM).expect("a literal stream name"),
        from_cursor: U64::new(40),
        oldest_retained_cursor: U64::new(0),
        gap: Nullable::null(),
        agent_resources: kr_protocol::projection::AgentResourceSnapshot {
            snapshot_id: U64::ZERO,
            stream_generation: U64::ZERO,
            cursor: U64::ZERO,
            resources: Vec::new(),
            continue_after: Nullable::null(),
        },
        agent_instances: kr_protocol::projection::AgentInstanceList {
            sequence: U64::ZERO,
            instances: Vec::new(),
        },
    }
}

/// One row of plain text.
pub fn row(id: u64, text: &str) -> ProjectedRow {
    ProjectedRow {
        row: U64::new(id),
        soft_wrapped: false,
        truncated: false,
        runs: if text.is_empty() {
            Vec::new()
        } else {
            vec![CellRun {
                column: U64::ZERO,
                cells: U64::new(u64::try_from(text.chars().count()).unwrap_or_default()),
                text: text.to_owned(),
                rendition: CellRendition::PLAIN,
                hyperlink: Nullable::null(),
            }]
        },
    }
}

/// The window a view of `columns` by `rows` is shown on a session of that size, on the live screen.
pub fn viewport(top_row: u64, columns: u64, rows: u64) -> ProjectedViewport {
    ProjectedViewport {
        top_row: U64::new(top_row),
        screen_top_row: U64::new(top_row),
        rows: U64::new(rows),
        left_column: U64::ZERO,
        columns: U64::new(columns),
    }
}

/// The palette a session with the dark preset has.
pub fn palette() -> PaletteState {
    let colour = |red, green, blue| Rgb { red, green, blue };
    PaletteState {
        source: PaletteProvenance::DarkPreset,
        foreground: colour(0xdc, 0xdc, 0xda),
        background: colour(0x07, 0x12, 0x17),
        cursor: colour(0xdc, 0xdc, 0xda),
        pointer_foreground: colour(0xdc, 0xdc, 0xda),
        pointer_background: colour(0x07, 0x12, 0x17),
        selection_background: colour(0x31, 0x5e, 0x4a),
        selection_foreground: colour(0xff, 0xff, 0xff),
        overrides: Vec::new(),
    }
}

/// A reset, at `generation`.
pub fn reset(generation: u64, cursor: u64, reason: ProjectionResetReason) -> ProjectionReset {
    ProjectionReset {
        projection_generation: U64::new(generation),
        cursor: U64::new(cursor),
        reason,
    }
}

/// A snapshot's header: a `columns` by `rows` session, the window at `top_row`.
pub fn snapshot(
    generation: u64,
    cursor: u64,
    columns: u64,
    rows: u64,
    top_row: u64,
) -> ProjectionSnapshot {
    ProjectionSnapshot {
        projection_generation: U64::new(generation),
        output_cursor: U64::new(cursor),
        active_buffer: ProjectedBuffer::Primary,
        dimensions: Dimensions::new(columns, rows),
        viewport: viewport(top_row, columns, rows),
        cursor: ProjectedCursor {
            column: U64::new(2),
            row: U64::ZERO,
            visible: true,
            style: U64::new(1),
            pending_wrap: false,
        },
        saved_cursors: Vec::new(),
        margins: MarginState {
            top: U64::ZERO,
            bottom: U64::new(rows.saturating_sub(1)),
            left: U64::ZERO,
            right: U64::new(columns.saturating_sub(1)),
        },
        rendition: CellRendition::PLAIN,
        tab_stops: Vec::new(),
        charsets: CharsetState {
            g0: "Ascii".to_owned(),
            g1: "Ascii".to_owned(),
            shift_out: false,
        },
        modes: Vec::new(),
        keypad_application: false,
        keyboard: ProjectedKeyboard {
            modify_other_keys: U64::ZERO,
            primary: KittyKeyboardState {
                flags: Nullable::null(),
                stack: Vec::new(),
            },
            alternate: KittyKeyboardState {
                flags: Nullable::null(),
                stack: Vec::new(),
            },
        },
        title: ProjectedTitle::default(),
        title_stack: Vec::new(),
        hyperlink: Nullable::null(),
        palette: palette(),
        oldest_retained_row: U64::ZERO,
        evicted: false,
        degraded: false,
    }
}

/// One page of a snapshot's rows.
pub fn page(
    generation: u64,
    cursor: u64,
    rows: Vec<ProjectedRow>,
    more: bool,
) -> ProjectionRowPage {
    ProjectionRowPage {
        projection_generation: U64::new(generation),
        output_cursor: U64::new(cursor),
        buffer: ProjectedBuffer::Primary,
        rows,
        oldest_retained_row: U64::ZERO,
        evicted: false,
        more,
    }
}

/// An update from `base` to `next` that rewrites `rows`, with the window at `top_row`.
pub fn delta(
    generation: u64,
    base: u64,
    next: u64,
    columns: u64,
    screen_rows: u64,
    top_row: u64,
    rows: Vec<ProjectedRow>,
) -> ProjectionDelta {
    ProjectionDelta {
        base_cursor: U64::new(base),
        next_cursor: U64::new(next),
        projection_generation: U64::new(generation),
        buffer: ProjectedBuffer::Primary,
        viewport: viewport(top_row, columns, screen_rows),
        rows,
        cursor: ProjectedCursor {
            column: U64::new(3),
            row: U64::ZERO,
            visible: true,
            style: U64::new(1),
            pending_wrap: false,
        },
        modes: Vec::new(),
        margins: Nullable::null(),
        rendition: Nullable::null(),
        tab_stops: Nullable::null(),
        charsets: Nullable::null(),
        hyperlinks: Vec::new(),
        hyperlink: Nullable::null(),
        title: Nullable::null(),
        title_stack: Nullable::null(),
        keyboard: Nullable::null(),
        palette: Nullable::null(),
        dimensions: Nullable::null(),
        saved_cursors: Nullable::null(),
        oldest_retained_row: U64::ZERO,
        evicted: false,
        degraded: false,
    }
}

/// A subscription's opening screen: its reset, its header and one page of `rows`.
pub async fn screen(link: &mut Link, generation: u64, cursor: u64, rows: Vec<ProjectedRow>) {
    let height = u64::try_from(rows.len()).unwrap_or(1);
    link.push(
        kr_protocol::projection::PROJECTION_RESET_EVENT,
        &reset(generation, cursor, ProjectionResetReason::Attached),
    )
    .await;
    link.push(
        kr_protocol::projection::PROJECTION_SNAPSHOT_EVENT,
        &snapshot(generation, cursor, 10, height, 0),
    )
    .await;
    link.push(
        kr_protocol::projection::PROJECTION_ROWS_EVENT,
        &page(generation, cursor, rows, false),
    )
    .await;
}
