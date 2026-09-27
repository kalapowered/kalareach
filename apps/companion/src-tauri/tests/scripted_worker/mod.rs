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
    /// Not at all before the view leaves: the worker holds each connection at its hello, before
    /// it acknowledges it, and reports when the view closes it there.
    HeldAtHello,
    /// Not before the view leaves: the worker acknowledges the hello, reads the challenge, holds
    /// the connection there without a proof, and reports when the view closes it.
    HeldAtProof,
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
    /// Connections the worker has begun to hold before the view could attach.
    holding: tokio::sync::mpsc::UnboundedReceiver<()>,
    /// Connections the view closed while the worker held them before the view could attach.
    abandoned: tokio::sync::mpsc::UnboundedReceiver<()>,
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
        let (leaving, abandoned) = tokio::sync::mpsc::unbounded_channel();
        let (held, holding) = tokio::sync::mpsc::unbounded_channel();
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
                if challenge == Challenge::HeldAtHello {
                    // Held until the view gives up: the next read ends when it closes.
                    let _ = held.send(());
                    let _ = reader.read_message::<ControlFrame>().await;
                    let _ = leaving.send(());
                    continue;
                }
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
                    build: None,
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
                    Challenge::HeldAtHello | Challenge::HeldAtProof => {
                        let _ = held.send(());
                        let _ = reader.read_message::<ControlFrame>().await;
                        let _ = leaving.send(());
                        continue;
                    }
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
            holding,
            abandoned,
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

    /// Waits until the worker holds a view's connection before its attach.
    pub async fn holding(&mut self) {
        tokio::time::timeout(WATCHDOG, self.holding.recv())
            .await
            .expect("a view connected within the watchdog")
            .expect("the worker is still listening");
    }

    /// Waits until a view closed a connection the worker was holding before its attach.
    pub async fn abandoned(&mut self) {
        tokio::time::timeout(WATCHDOG, self.abandoned.recv())
            .await
            .expect("the view closed the held connection within the watchdog")
            .expect("the worker is still listening");
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

/// How a call reached the worker: as a plain request, or as a mutation with an action identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CallKind {
    Request,
    Mutation,
}

/// One call a view made: a read or a mutation, with what it asked.
#[derive(Debug)]
pub struct Call {
    pub request_id: RequestId,
    pub method: String,
    pub params: ParamsValue,
    pub kind: CallKind,
    /// What a mutation's envelope says it acts on; a read carries none.
    pub target: Option<kr_protocol::envelope::ActionTarget>,
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
                kind: CallKind::Request,
                target: None,
            },
            ControlFrame::Mutation(mutation) => Call {
                request_id: mutation.request_id,
                method: mutation.method.to_string(),
                params: mutation.params,
                kind: CallKind::Mutation,
                target: Some(mutation.target),
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
                        kind: CallKind::Request,
                        target: None,
                    }),
                    Ok(ControlFrame::Mutation(mutation)) => sent.push(Call {
                        request_id: mutation.request_id,
                        method: mutation.method.to_string(),
                        params: mutation.params,
                        kind: CallKind::Mutation,
                        target: Some(mutation.target),
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
        self.refuse_with(call, ErrorCode::InvalidArgument, message)
            .await;
    }

    /// Refuses `call` with the host's `code` and `message`.
    pub async fn refuse_with(&mut self, call: &Call, code: ErrorCode, message: &str) {
        self.writer
            .write_message(&ControlFrame::Response(Response {
                request_id: call.request_id,
                outcome: Outcome::Error(ProtocolError::new(code, message)),
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
        assert!(
            asked.dimensions.0.is_some(),
            "a terminal attachment names its size"
        );
        self.answer(
            &call,
            &SessionAttachResult {
                attachment: summary(attachment_id, &asked),
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

/// The summary a worker gives the attachment `asked` for, as the local owner: granted what it
/// asked for, and shown a viewport, since this worker has qualified no terminal to take its stream.
pub fn summary(attachment_id: AttachmentId, asked: &SessionAttachParams) -> AttachmentSummary {
    AttachmentSummary {
        attachment_id,
        ordinal: kr_protocol::ids::AttachmentOrdinal::new(2),
        mode: AttachMode::Terminal,
        claim_geometry: false,
        dimensions: asked.dimensions,
        presentation: Nullable::some(TerminalPresentationMode::Viewport),
        presentation_reason: Some(if asked.terminal_profile_id.0.is_some() {
            kr_protocol::attachment::PresentationReason::UnqualifiedTerminalProfile
        } else {
            kr_protocol::attachment::PresentationReason::NoTerminalProfile
        }),
        terminal_profile_id: asked.terminal_profile_id.clone(),
        granted: asked.requested.clone(),
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

/// A reset, at `generation`, drawn for the view's window at `window_revision`: 0 until the window
/// first changes, and one more at each change the host makes to it.
pub fn reset(
    generation: u64,
    cursor: u64,
    reason: ProjectionResetReason,
    window_revision: u64,
) -> ProjectionReset {
    ProjectionReset {
        projection_generation: U64::new(generation),
        cursor: U64::new(cursor),
        reason,
        window_revision: U64::new(window_revision),
    }
}

/// A snapshot's header: a `columns` by `rows` session, the window at `top_row`, drawn for the
/// view's window at `window_revision`.
pub fn snapshot(
    generation: u64,
    cursor: u64,
    columns: u64,
    rows: u64,
    top_row: u64,
    window_revision: u64,
) -> ProjectionSnapshot {
    ProjectionSnapshot {
        projection_generation: U64::new(generation),
        output_cursor: U64::new(cursor),
        window_revision: U64::new(window_revision),
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

/// A subscription's opening screen, drawn for the view's window at `window_revision`: its reset,
/// its header and one page of `rows`.
pub async fn screen(
    link: &mut Link,
    generation: u64,
    cursor: u64,
    rows: Vec<ProjectedRow>,
    window_revision: u64,
) {
    let height = u64::try_from(rows.len()).unwrap_or(1);
    link.push(
        kr_protocol::projection::PROJECTION_RESET_EVENT,
        &reset(
            generation,
            cursor,
            ProjectionResetReason::Attached,
            window_revision,
        ),
    )
    .await;
    link.push(
        kr_protocol::projection::PROJECTION_SNAPSHOT_EVENT,
        &snapshot(generation, cursor, 10, height, 0, window_revision),
    )
    .await;
    link.push(
        kr_protocol::projection::PROJECTION_ROWS_EVENT,
        &page(generation, cursor, rows, false),
    )
    .await;
}

/// A screen of a session with the view's window placed on it: what the host installs for a window
/// a report moved, or one the session's own change put somewhere.
#[derive(Clone, Copy, Debug)]
pub struct Frame {
    /// The projection's generation and the output cursor it stands at.
    pub generation: u64,
    pub cursor: u64,
    /// The revision of the view's window this screen is drawn for.
    pub revision: u64,
    /// The session's size.
    pub columns: u64,
    pub rows: u64,
    /// The window's size.
    pub window_columns: u64,
    pub window_rows: u64,
    /// The row the window starts at.
    pub top_row: u64,
    /// The live screen's first row.
    pub live_top: u64,
    /// The first column the window shows.
    pub column: u64,
    /// The oldest row the session still keeps.
    pub oldest: u64,
    /// Which buffer is showing.
    pub buffer: ProjectedBuffer,
    /// How the program reports the mouse.
    pub mouse: Mouse,
    /// How the program reads keys.
    pub keys: Keys,
}

/// How a program reads keys, as a screen says: the keyboard negotiation of each buffer, and the
/// modes that change what a key or a paste sends.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Keys {
    /// The `modifyOtherKeys` level.
    pub modify_other_keys: u64,
    /// The primary buffer's Kitty flags, while the protocol is in use there.
    pub primary: Option<u64>,
    /// The alternate buffer's.
    pub alternate: Option<u64>,
    /// DEC mode 1, application cursor keys.
    pub cursor_keys: bool,
    /// DEC mode 2004, bracketed paste.
    pub bracketed_paste: bool,
}

impl Keys {
    /// A program that negotiated nothing.
    pub fn ordinary() -> Self {
        Self::default()
    }

    /// A program in the primary buffer that set the Kitty protocol's `flags`.
    pub fn kitty(flags: u64) -> Self {
        Self {
            primary: Some(flags),
            ..Self::default()
        }
    }

    /// A program that set `modifyOtherKeys` at `level`.
    pub fn modify_other_keys(level: u64) -> Self {
        Self {
            modify_other_keys: level,
            ..Self::default()
        }
    }

    /// The keyboard negotiation, as a header or an update carries it.
    pub fn keyboard(&self) -> ProjectedKeyboard {
        let state = |flags: Option<u64>| KittyKeyboardState {
            flags: Nullable(flags.map(U64::new)),
            stack: Vec::new(),
        };
        ProjectedKeyboard {
            modify_other_keys: U64::new(self.modify_other_keys),
            primary: state(self.primary),
            alternate: state(self.alternate),
        }
    }

    /// The modes that go with it, and the alternate buffer's three when `alternate` is showing.
    pub fn modes(&self, alternate: bool) -> Vec<kr_protocol::projection::ProjectedMode> {
        let dec = |mode: u64, enabled: bool| kr_protocol::projection::ProjectedMode {
            kind: kr_protocol::projection::ProjectedModeKind::Dec,
            mode: U64::new(mode),
            enabled,
        };
        vec![
            dec(1, self.cursor_keys),
            dec(47, alternate),
            dec(1047, alternate),
            dec(1049, alternate),
            dec(2004, self.bracketed_paste),
        ]
    }

    /// The encoding the host reads off the canonical grid from this, with the alternate buffer
    /// showing or not: the showing buffer's Kitty flags when any is set, else `modifyOtherKeys`,
    /// else the ordinary encoding.
    pub fn negotiated(&self, alternate: bool) -> Negotiated {
        match if alternate {
            self.alternate
        } else {
            self.primary
        } {
            Some(flags) if flags != 0 => Negotiated::Kitty(u8::try_from(flags).unwrap_or(u8::MAX)),
            _ if self.modify_other_keys > 0 => {
                Negotiated::ModifyOtherKeys(u8::try_from(self.modify_other_keys).unwrap_or(u8::MAX))
            }
            _ => Negotiated::Ordinary,
        }
    }
}

/// The encoding a program reads, as the host reads it off the canonical grid.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Negotiated {
    /// The ordinary encoding.
    #[default]
    Ordinary,
    /// `modifyOtherKeys` at a level.
    ModifyOtherKeys(u8),
    /// The Kitty protocol with a set of flags.
    Kitty(u8),
}

impl Negotiated {
    /// Whether a view can hold the keys under it: what the host's keyboard table gives the view's
    /// profile, `modifyOtherKeys` up to level 2 and the Kitty protocol's disambiguation and event
    /// types.
    pub fn supplied(self) -> bool {
        match self {
            Self::Ordinary => true,
            Self::ModifyOtherKeys(level) => level <= 2,
            Self::Kitty(flags) => flags & !0b0000_0011 == 0,
        }
    }

    /// The host's words for it.
    pub fn describe(self) -> String {
        match self {
            Self::Ordinary => "the ordinary terminal encoding".to_owned(),
            Self::ModifyOtherKeys(level) => format!("modifyOtherKeys level {level}"),
            Self::Kitty(flags) => format!("the Kitty keyboard protocol with flags {flags}"),
        }
    }
}

/// How a program reports the mouse, as the DEC modes it has set say.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mouse {
    /// It does not: none of 1000, 1002 and 1003 is set.
    Off,
    /// Presses and the wheel (1000) in the SGR encoding (1006).
    Sgr,
    /// Presses and the wheel (1000) in the original report.
    Original,
    /// Presses and the wheel (1000) in the UTF-8 encoding (1005), which no client here writes.
    Utf8,
}

/// The modes `mouse` sets and clears, as a header lists every tracked mode and an update lists
/// those that changed.
pub fn mouse_modes(mouse: Mouse) -> Vec<kr_protocol::projection::ProjectedMode> {
    let dec = |mode: u64, enabled: bool| kr_protocol::projection::ProjectedMode {
        kind: kr_protocol::projection::ProjectedModeKind::Dec,
        mode: U64::new(mode),
        enabled,
    };
    vec![
        dec(1000, mouse != Mouse::Off),
        dec(1002, false),
        dec(1003, false),
        dec(1005, mouse == Mouse::Utf8),
        dec(1006, mouse == Mouse::Sgr),
    ]
}

impl Frame {
    /// A window of `window` columns and rows on a session of `session`, at the live screen's first
    /// line and column, drawn for revision 0, with `history` rows kept above the live screen.
    pub fn live(session: (u64, u64), window: (u64, u64), history: u64) -> Self {
        Self {
            generation: 1,
            cursor: 40,
            revision: 0,
            columns: session.0,
            rows: session.1,
            window_columns: window.0.min(session.0),
            window_rows: window.1.min(session.1),
            top_row: history,
            live_top: history,
            column: 0,
            oldest: 0,
            buffer: ProjectedBuffer::Primary,
            mouse: Mouse::Off,
            keys: Keys::ordinary(),
        }
    }

    /// The same window, of a program that reads keys as `keys` says.
    pub fn keys(self, keys: Keys) -> Self {
        Self { keys, ..self }
    }

    /// The same window, of a program that reports the mouse as `mouse` says.
    pub fn reporting(self, mouse: Mouse) -> Self {
        Self { mouse, ..self }
    }

    /// The same session, the window at line `line` of the live screen and column `column`.
    pub fn at(self, line: u64, column: u64) -> Self {
        Self {
            top_row: self.live_top + line,
            column,
            ..self
        }
    }

    /// The same session, the window starting at history row `row` and column `column`.
    pub fn in_history(self, row: u64, column: u64) -> Self {
        Self {
            top_row: row,
            column,
            ..self
        }
    }

    /// The same window, drawn for `revision`.
    pub fn revision(self, revision: u64) -> Self {
        Self { revision, ..self }
    }

    /// The window as the header and an update carry it.
    pub fn viewport(&self) -> ProjectedViewport {
        ProjectedViewport {
            top_row: U64::new(self.top_row),
            screen_top_row: U64::new(self.live_top),
            rows: U64::new(self.window_rows),
            left_column: U64::new(self.column),
            columns: U64::new(self.window_columns),
        }
    }

    /// The window's rows, each the letters of the alphabet across the session's width and named by
    /// its own row, so what a view draws says which rows and columns its window holds.
    pub fn rows(&self) -> Vec<ProjectedRow> {
        (self.top_row..self.top_row + self.window_rows)
            .map(|id| {
                let text: String = (0..self.columns)
                    .map(|column| char::from(b'a' + u8::try_from(column % 26).unwrap_or(0)))
                    .collect();
                row(id, &text)
            })
            .collect()
    }
}

/// Pushes `frame` as a subscription or a reinstallation opens: its reset, its header and one page
/// of its window's rows.
pub async fn frame(link: &mut Link, frame: &Frame) {
    link.push(
        kr_protocol::projection::PROJECTION_RESET_EVENT,
        &reset(
            frame.generation,
            frame.cursor,
            ProjectionResetReason::Attached,
            frame.revision,
        ),
    )
    .await;
    let mut header = snapshot(
        frame.generation,
        frame.cursor,
        frame.columns,
        frame.rows,
        frame.top_row,
        frame.revision,
    );
    header.viewport = frame.viewport();
    header.active_buffer = frame.buffer;
    header.oldest_retained_row = U64::new(frame.oldest);
    header.modes = mouse_modes(frame.mouse);
    header
        .modes
        .extend(frame.keys.modes(frame.buffer == ProjectedBuffer::Alternate));
    header.keyboard = frame.keys.keyboard();
    link.push(kr_protocol::projection::PROJECTION_SNAPSHOT_EVENT, &header)
        .await;
    let mut rows = page(frame.generation, frame.cursor, frame.rows(), false);
    rows.buffer = frame.buffer;
    rows.oldest_retained_row = U64::new(frame.oldest);
    link.push(kr_protocol::projection::PROJECTION_ROWS_EVENT, &rows)
        .await;
}

/// An update from `base` to `next` that leaves `frame`'s window as it is and rewrites no row.
pub fn frame_delta(frame: &Frame, base: u64, next: u64) -> ProjectionDelta {
    let mut update = delta(
        frame.generation,
        base,
        next,
        1,
        1,
        frame.top_row,
        Vec::new(),
    );
    update.viewport = frame.viewport();
    update.buffer = frame.buffer;
    update.oldest_retained_row = U64::new(frame.oldest);
    update
}

/// An update from `base` to `next` that leaves `frame`'s window and rows as they are and changes how
/// the program reports the mouse to `mouse`.
pub fn mouse_delta(frame: &Frame, base: u64, next: u64, mouse: Mouse) -> ProjectionDelta {
    let mut update = frame_delta(frame, base, next);
    update.modes = mouse_modes(mouse);
    update
}

/// An update from `base` to `next` that leaves `frame`'s window and rows as they are and changes how
/// the program reads keys to `keys`.
pub fn keys_delta(frame: &Frame, base: u64, next: u64, keys: Keys) -> ProjectionDelta {
    let mut update = frame_delta(frame, base, next);
    update.modes = keys.modes(frame.buffer == ProjectedBuffer::Alternate);
    update.keyboard = Nullable::some(keys.keyboard());
    update
}

// ---- The input lease -------------------------------------------------------------------------

/// The session's input lease, kept the way the worker keeps it, answering a view's acquire, release
/// and write as the worker does: a takeover and a release each advance the epoch, a write is taken
/// only from the holder at the current epoch and only at the next number of its ordered stream, and
/// an acquire is refused while the program reads an encoding the view's profile is not given.
#[derive(Debug, Default)]
pub struct WorkerLease {
    pub epoch: u64,
    pub holder: Option<AttachmentId>,
    /// The next number the holder's ordered input stream has to write.
    pub next: u64,
    /// The encoding the program reads, as the host reads it.
    pub negotiated: Negotiated,
    /// Every batch the worker took, in order: its epoch, its number and its bytes.
    pub written: Vec<(u64, u64, Vec<u8>)>,
}

impl WorkerLease {
    /// A lease whose epoch has already moved `epoch` times.
    pub fn at(epoch: u64) -> Self {
        Self {
            epoch,
            ..Self::default()
        }
    }

    fn state(&self) -> kr_protocol::input::InputLeaseState {
        kr_protocol::input::InputLeaseState {
            epoch: kr_protocol::ids::InputLeaseEpoch::new(self.epoch),
            holder: Nullable(self.holder),
            connection_id: Nullable::null(),
            next_sequence: kr_protocol::ids::InputSequence::new(self.next),
        }
    }

    /// Answers `call`, an acquire, a release or a write, as the worker does.
    pub async fn answer(&mut self, link: &mut Link, call: &Call) {
        if call.method == Method::InputAcquire.to_string() {
            assert_eq!(call.kind, CallKind::Mutation, "an acquire is a mutation");
            let asked: kr_protocol::input::InputAcquireParams = call.params();
            if let Some(expected) = asked.expected_epoch.0
                && expected.get() != self.epoch
            {
                link.refuse_with(call, ErrorCode::LeaseLost, "the lease has moved on")
                    .await;
                return;
            }
            if !self.negotiated.supplied() {
                let refusal = format!(
                    "the application reads {}, and this attachment offers modifyOtherKeys up to \
                     level 2 and the Kitty keyboard protocol with flags 3",
                    self.negotiated.describe()
                );
                link.refuse_with(call, ErrorCode::InputIncompatible, &refusal)
                    .await;
                return;
            }
            self.epoch += 1;
            self.holder = Some(asked.attachment_id);
            self.next = 0;
            let answer = kr_protocol::input::InputAcquireResult {
                lease: self.state(),
                discarded_bytes: U64::ZERO,
                closed_open_paste: false,
            };
            link.answer(call, &answer).await;
        } else if call.method == Method::InputRelease.to_string() {
            assert_eq!(call.kind, CallKind::Mutation, "a release is a mutation");
            let asked: kr_protocol::input::InputReleaseParams = call.params();
            if self.holder != Some(asked.attachment_id) || asked.epoch.get() != self.epoch {
                link.refuse_with(
                    call,
                    ErrorCode::LeaseLost,
                    "this attachment does not hold it",
                )
                .await;
                return;
            }
            self.epoch += 1;
            self.holder = None;
            self.next = 0;
            let answer = kr_protocol::input::InputLeaseResult {
                lease: self.state(),
            };
            link.answer(call, &answer).await;
        } else if call.method == Method::InputWrite.to_string() {
            assert_eq!(
                call.kind,
                CallKind::Request,
                "input is a request, not a mutation"
            );
            let asked: kr_protocol::input::InputWriteParams = call.params();
            if self.holder != Some(asked.attachment_id) || asked.epoch.get() != self.epoch {
                link.refuse_with(call, ErrorCode::LeaseLost, "the lease has moved on")
                    .await;
                return;
            }
            if asked.sequence.get() != self.next {
                link.refuse(
                    call,
                    &format!(
                        "input sequence {} does not follow {}",
                        asked.sequence.get(),
                        self.next
                    ),
                )
                .await;
                return;
            }
            self.next += 1;
            let bytes = asked.bytes.as_slice().to_vec();
            let forwarded = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
            self.written.push((self.epoch, asked.sequence.get(), bytes));
            let answer = kr_protocol::input::InputWriteResult {
                sequence: asked.sequence,
                forwarded_bytes: U64::new(forwarded),
                held_prefix_bytes: U64::ZERO,
            };
            link.answer(call, &answer).await;
        } else {
            panic!("{} is not a call of the input lease", call.method);
        }
    }

    /// Refuses the write `call` with the host's `code`, as the worker does for a refusal it decides
    /// before the stream takes the write's number (`consumes` false) or after (`consumes` true).
    pub async fn refuse_write(
        &mut self,
        link: &mut Link,
        call: &Call,
        code: ErrorCode,
        message: &str,
        consumes: bool,
    ) {
        assert_eq!(call.method, Method::InputWrite.to_string());
        if consumes {
            self.next += 1;
        }
        link.refuse_with(call, code, message).await;
    }

    /// Another attachment takes the lease over, as a takeover does.
    pub fn taken_over(&mut self) {
        self.epoch += 1;
        self.holder = Some(AttachmentId::new(kr_ipc::new_uuid()));
        self.next = 0;
    }

    /// The program negotiates `negotiated`: a lease the view's profile cannot serve under it ends,
    /// as the host's re-evaluation ends it on the change.
    pub fn negotiate(&mut self, negotiated: Negotiated) {
        self.negotiated = negotiated;
        if !negotiated.supplied() && self.holder.take().is_some() {
            self.epoch += 1;
            self.next = 0;
        }
    }

    /// A detach, which releases a lease its attachment holds.
    pub fn detached(&mut self, attachment_id: AttachmentId) {
        if self.holder == Some(attachment_id) {
            self.epoch += 1;
            self.holder = None;
            self.next = 0;
        }
    }
}
