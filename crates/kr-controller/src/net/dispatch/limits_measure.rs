//! What the network door writes to a paired device, measured as the device receives it.
//!
//! Each case builds the widest instance of a frame the door can carry from the types' own bounds
//! and the worker's own builders, passes it through the rewrite the door applies to every frame
//! ([`frame_for_a_device`]) and records three figures for it, separately: the size of its payload,
//! the size of the complete frame a device receives, and what the worker's send queue charges for
//! it. A case prints one table; read it with `--nocapture`. The assertions hold a figure to the
//! bound the limits design states for it, and they do not look at a clock.
//!
//! The closure, the reduced record and the notification that replaces a frame are built here by
//! hand, because the constructors that will build them are not in the tree yet; the figures are the
//! design's allowances checked against the real encoding, and a constructor's own test holds them
//! once it exists.

use std::fmt::Write as _;
use std::hint::black_box;
use std::time::Instant;

use kr_cbor::{Limits, encoded_len, to_canonical_value, to_canonical_vec_within};
use kr_protocol::envelope::{ControlFrame, Notification, Outcome, ParamsValue, Response};
use kr_protocol::frame::FRAME_LENGTH_PREFIX_LEN;
use kr_protocol::ids::{
    ActorId, AgentBindingRevision, ApplicationInstanceId, AttachmentId, DiagnosticId,
    EventSequence, EventType, GatewayConnectionId, InputLeaseEpoch, LaunchProfileId,
    PendingResourceId, PluginId, RequestId, SessionEpoch, SessionId, SourceGeneration, StreamId,
    UpstreamMethod, UpstreamRequestId,
};
use kr_protocol::projection::{
    AGENT_INSTANCE_EVENT, AGENT_RESOURCE_EVENT, AgentInstanceEvent, AgentInstanceList,
    AgentInstanceSummary, AgentResourceCause, AgentResourceContentClass, AgentResourceEvent,
    AgentResourceSnapshot, PROJECTION_DELTA_EVENT, PROJECTION_RESET_EVENT, PROJECTION_ROWS_EVENT,
    PROJECTION_SNAPSHOT_EVENT, PaletteOverride, ProjectedBuffer, ProjectedHyperlink, ProjectedRow,
    ProjectionDelta, ProjectionEvent, ProjectionReset, ProjectionResetReason, ProjectionSnapshot,
    SavedTitleEntry,
};
use kr_protocol::recovery::{
    AgentInstancesResult, EventsSubscribeResult, HistoryGap, HistoryGapCause, OutputEvent,
    ResyncReason, ResyncRequired,
};
use kr_protocol::root::{EDITOR_BUSY_EVENT, EditorBusyEvent, EditorBusyReason, FenceState};
use kr_protocol::scalars::{Bytes, Nullable, TimestampMs, U64};
use kr_protocol::session::{
    ClosureReason, ClosureRecord, Dimensions, DisplayNumber, Durability, OwnershipCoverage,
    SESSION_CLOSED_EVENT, SessionCloseResult, SessionState, SessionSummary, ShellMode,
    SurvivingResource,
};
use kr_worker::output::{OutputDelivery, RESYNC_MARKER_BYTES};
use kr_worker::snapshot::{Outgoing, PAGE_BYTES, PAGE_ITEMS, install, wire};
use serde::Serialize;

use super::super::device_errors::{fits, frame_for_a_device};

/// The floor of the control frame the network door negotiates, in bytes, length prefix included.
const FLOOR: usize = 262_144;
/// The compiled control frame, length prefix included.
const COMPILED: usize = kr_protocol::limits::MAX_CONTROL_FRAME_LEN;
/// The least control frame the transport negotiates for any user of it.
const TRANSPORT_FLOOR: usize = 16_384;
/// The smallest send queue the design allows at the floor of the control frame.
const QUEUE_FLOOR: usize = 2_101_248;
/// What a closure may be charged: one compiled frame.
const CLOSURE_ROOM: usize = COMPILED;
/// What the design assumes the three small records cost together, with the factor of two.
const RESERVE_SMALL_BOUND: usize = 3_072;
/// What the design says a full page needs of the queue at the floor.
const USABLE_BOUND: usize = 1_049_600;
/// Where the design stops and asks: the margin above a page plus the assumed reserve.
const STOP_LINE: usize = 13_312;
/// What the design allows a record that replaces a frame, envelope included.
const REPLACEMENT_BOUND: usize = 3_072;
/// What the design allows the largest closure notification a device is shown.
const CLOSURE_FRAME_BOUND: usize = 199_680;
/// What the design allows the closure's lists as a device is shown them.
const CLOSURE_LISTS_BOUND: usize = 196_608;
/// The design's allowance for the closure's members outside its lists, `root_signal` at 1,024.
const CLOSURE_FIXED_BOUND: usize = 1_536;
/// The design's allowance for a notification's envelope.
const ENVELOPE_BOUND: usize = 1_024;
/// The longest a free text member of a closure is cut to.
const CLOSURE_TEXT_BYTES: usize = 1_024;
/// What the design allows the connection's refusal to an unpaired peer, as a frame.
const REFUSAL_BOUND: usize = 1_300;
/// What the design allows an agent instance event, whole.
const AGENT_INSTANCE_BOUND: usize = 2_048;
/// What the design's census estimated for an agent resource event, whole. The measurement is
/// larger, and the figures below are what it found.
const AGENT_RESOURCE_ESTIMATE: usize = 2_200;
/// The payload of the widest agent resource event the type allows.
const AGENT_RESOURCE_PAYLOAD: usize = 2_147;
/// The complete frame of the widest agent resource event the type allows.
const AGENT_RESOURCE_FRAME: usize = 2_247;
/// What the design derives for the longest causal root: 20 digits, a colon and the longest upstream
/// identifier.
const CAUSAL_ROOT_BOUND: usize = 1_559;
/// What the input stream's floor of 1,024 bytes leaves for a message, its length prefix out.
const INPUT_PAYLOAD_FLOOR: usize = 1_024 - FRAME_LENGTH_PREFIX_LEN;

/// What the worker's send queue charges for a closure notice today: nothing, by the `Closed` arm of
/// `OutputDelivery::len`. A notice is built only inside the worker's hub, so the figure is read from
/// that arm and not measured here; the design charges the notice's encoding to the reserve instead.
const CLOSED_NOTICE_CHARGE: usize = 0;

/// The size of `payload` as the codec encodes it, which is what a stream charges before its frame.
fn payload_len(payload: &impl Serialize) -> usize {
    encoded_len(&to_canonical_value(payload).expect("a payload the codec can represent"))
}

/// The size of `frame` as the control stream counts it, without the length prefix.
fn frame_len(frame: &ControlFrame) -> usize {
    encoded_len(&to_canonical_value(frame).expect("a frame the codec can represent"))
}

/// `frame` as a device is given it.
fn shown(frame: &ControlFrame) -> ControlFrame {
    frame_for_a_device(frame).into_owned()
}

/// A notification at the widest stream, sequence and event type the worker sends it under.
fn notice(event: &str, payload: &impl Serialize) -> ControlFrame {
    ControlFrame::Notification(Notification {
        stream_id: StreamId::new(kr_worker::service::OUTPUT_STREAM).expect("a stream"),
        sequence: EventSequence::new(u64::MAX),
        event_type: EventType::new(event).expect("an event type"),
        payload: ParamsValue::from_typed(payload).expect("encodes"),
    })
}

/// The answer to a request at the widest request identifier.
fn answer(payload: &impl Serialize) -> ControlFrame {
    ControlFrame::Response(Response {
        request_id: RequestId::new(u64::MAX),
        outcome: Outcome::Ok(ParamsValue::from_typed(payload).expect("encodes")),
    })
}

/// The candidate whose encoding is the longest.
fn widest<T: Serialize>(candidates: Vec<T>) -> T {
    candidates
        .into_iter()
        .max_by_key(payload_len)
        .expect("a candidate")
}

/// One line of a case's table: the three figures of a frame, and where it came from.
fn line(name: &str, payload: usize, frame: &ControlFrame, charge: Option<usize>) -> String {
    let complete = frame_len(frame);
    let charge = charge.map_or_else(|| "n/a".to_owned(), |charge| charge.to_string());
    format!(
        "MEASURE | {name} | payload {payload} | frame {complete} | frame with prefix {} | queue charge {charge}\n",
        complete + FRAME_LENGTH_PREFIX_LEN
    )
}

/// What one frame of the widest kind a worker sends is, with the queue charge the worker gives it.
struct Measured {
    /// The event type.
    name: &'static str,
    /// The notification as the worker builds it.
    frame: ControlFrame,
    /// The size of its payload.
    payload: usize,
    /// What the worker's send queue charges for it, where it charges anything.
    charge: Option<usize>,
}

impl Measured {
    fn new(
        name: &'static str,
        payload: &impl Serialize,
        charge: impl FnOnce(usize) -> Option<usize>,
    ) -> Self {
        let size = payload_len(payload);
        Self {
            name,
            frame: notice(name, payload),
            payload: size,
            charge: charge(size),
        }
    }
}

fn session_id() -> SessionId {
    SessionId::new(kr_ipc::new_uuid())
}

fn marker() -> ResyncRequired {
    ResyncRequired {
        reason: widest(vec![
            ResyncReason::SendQueueFull,
            ResyncReason::HistoryEvicted,
            ResyncReason::ProjectionReset,
            ResyncReason::AgentStreamGap,
        ]),
        cursor: U64::new(u64::MAX),
        oldest_retained_cursor: U64::new(u64::MAX),
    }
}

fn editor_busy() -> EditorBusyEvent {
    EditorBusyEvent {
        session_id: session_id(),
        attachment_id: AttachmentId::new(kr_ipc::new_uuid()),
        input_epoch: InputLeaseEpoch::new(u64::MAX),
        reason: widest(vec![
            EditorBusyReason::FenceExchangeTimedOut,
            EditorBusyReason::FenceRefused,
            EditorBusyReason::QueuesNotDrained,
            EditorBusyReason::LaunchReservationTimedOut,
        ]),
        released_input_bytes: U64::new(u64::MAX),
        state: widest(vec![
            FenceState::Outside,
            FenceState::Unfenced,
            FenceState::Fenced,
            FenceState::LaunchReserved,
            FenceState::Closing,
        ]),
    }
}

/// The detach notification with every member the type has set, `line_token` left null as the one
/// producer writes it.
fn detached() -> kr_protocol::attachment::SessionDetachParams {
    kr_protocol::attachment::SessionDetachParams {
        attachment_id: Nullable::some(AttachmentId::new(kr_ipc::new_uuid())),
        line_token: Nullable::null(),
        after_input: Some(kr_protocol::input::InputBarrier {
            attachment_id: AttachmentId::new(kr_ipc::new_uuid()),
            epoch: InputLeaseEpoch::new(u64::MAX),
            count: U64::new(u64::MAX),
            launch: Nullable::some(u32::MAX),
        }),
        fenced_report: true,
    }
}

/// The detach notification as the worker's one producer writes it: no token, no barrier, no report.
fn detached_as_produced() -> kr_protocol::attachment::SessionDetachParams {
    kr_protocol::attachment::SessionDetachParams {
        attachment_id: Nullable::some(AttachmentId::new(kr_ipc::new_uuid())),
        line_token: Nullable::null(),
        after_input: None,
        fenced_report: false,
    }
}

fn gap() -> HistoryGap {
    HistoryGap {
        from_cursor: U64::new(u64::MAX),
        to_cursor: U64::new(u64::MAX),
        cause: Some(widest(vec![
            HistoryGapCause::Retention,
            HistoryGapCause::HostCapacity,
            HistoryGapCause::SessionCapacity,
            HistoryGapCause::SpoolUnavailable,
            HistoryGapCause::ArchiveIncomplete,
        ])),
    }
}

fn reset() -> ProjectionReset {
    ProjectionReset {
        projection_generation: U64::new(u64::MAX),
        cursor: U64::new(u64::MAX),
        reason: ProjectionResetReason::longest(),
        window_revision: U64::new(u64::MAX),
    }
}

/// An agent instance with every member at its widest: both identifiers at their protocol bound,
/// and the refusal at the 512 bytes the worker cuts it to.
fn instance(refusal: usize) -> AgentInstanceSummary {
    AgentInstanceSummary {
        application_instance_id: ApplicationInstanceId::new(kr_ipc::new_uuid()),
        plugin_id: Nullable::some(PluginId::new("p".repeat(256)).expect("a plugin identifier")),
        profile_id: Nullable::some(
            LaunchProfileId::new("l".repeat(256)).expect("a launch profile identifier"),
        ),
        mode: widest(vec![
            kr_protocol::broker::IntegrationMode::NativeTerminal,
            kr_protocol::broker::IntegrationMode::Gateway,
            kr_protocol::broker::IntegrationMode::NativeBridge,
        ]),
        bypass: Nullable::some(widest(vec![
            kr_protocol::root::CommandBypassReason::NotIntegrated,
            kr_protocol::root::CommandBypassReason::Disabled,
            kr_protocol::root::CommandBypassReason::AbsolutePath,
            kr_protocol::root::CommandBypassReason::UnmanagedShell,
            kr_protocol::root::CommandBypassReason::NotInteractive,
            kr_protocol::root::CommandBypassReason::BackendUnavailable,
            kr_protocol::root::CommandBypassReason::SessionClosing,
            kr_protocol::root::CommandBypassReason::FlagsConflict,
        ])),
        started_at: TimestampMs::new(u64::MAX),
        ended_at: Nullable::some(TimestampMs::new(u64::MAX)),
        refusal: Nullable::some("r".repeat(refusal)),
    }
}

fn instance_event(refusal: usize) -> AgentInstanceEvent {
    AgentInstanceEvent {
        session_id: session_id(),
        sequence: U64::new(u64::MAX),
        instance: instance(refusal),
    }
}

/// The text of a request identifier at its widest: the connection counter in decimal, a colon and
/// the longest upstream identifier.
fn causal_root() -> String {
    kr_protocol::gateway::DownstreamRequestId::new(
        GatewayConnectionId::new(u64::MAX),
        widest_upstream_id(),
    )
    .to_string()
}

/// The longest upstream request identifier the type holds: its JSON form of a string value of 256
/// control characters, each at the six bytes of its escape, between two quotes.
fn widest_upstream_id() -> UpstreamRequestId {
    let id = UpstreamRequestId::new(format!(
        "\"{}\"",
        "\\u0000".repeat(kr_protocol::ids::MAX_OPAQUE_ID_LEN)
    ))
    .expect("the longest upstream identifier");
    assert_eq!(
        id.as_str().len(),
        kr_protocol::ids::MAX_UPSTREAM_REQUEST_ID_LEN,
        "the identifier is as long as the type allows"
    );
    id
}

fn resource_event() -> AgentResourceEvent {
    AgentResourceEvent {
        session_id: session_id(),
        application_instance_id: ApplicationInstanceId::new(kr_ipc::new_uuid()),
        resource_id: PendingResourceId::new(kr_ipc::new_uuid()),
        state: widest(vec![
            kr_protocol::gateway::PendingState::Pending,
            kr_protocol::gateway::PendingState::Claimed,
            kr_protocol::gateway::PendingState::Resolved,
            kr_protocol::gateway::PendingState::Cancelled,
            kr_protocol::gateway::PendingState::Expired,
            kr_protocol::gateway::PendingState::Uncertain,
        ]),
        content: widest(vec![
            AgentResourceContentClass::Metadata,
            AgentResourceContentClass::TerminalContent,
            AgentResourceContentClass::AuthoredContent,
            AgentResourceContentClass::ApplicationNotice,
            AgentResourceContentClass::Secret,
        ]),
        durability: Durability::Volatile,
        cause: widest(vec![
            AgentResourceCause::Recorded,
            AgentResourceCause::Interpreted,
            AgentResourceCause::RichClaim,
            AgentResourceCause::Dispatched,
            AgentResourceCause::RichAnswer,
            AgentResourceCause::NativeAnswer,
            AgentResourceCause::HostAnswer,
            AgentResourceCause::Upstream,
            AgentResourceCause::Reconciliation,
        ]),
        actor_id: Nullable::some(ActorId::new("a".repeat(256)).expect("an actor identifier")),
        causal_root: causal_root(),
        binding_revision: AgentBindingRevision::new(u64::MAX),
        stream_generation: U64::new(u64::MAX),
        sequence: U64::new(u64::MAX),
        event_id: kr_ipc::new_uuid(),
        parent_sequence: Nullable::some(U64::new(u64::MAX)),
    }
}

/// A pending resource with the upstream identifier and method at their longest.
fn pending_resource() -> kr_protocol::gateway::PendingResource {
    use kr_protocol::gateway::{
        DownstreamRequestId, NativeClassification, NativeMethodClass, PendingKind, PendingResource,
        PendingState,
    };
    PendingResource {
        resource_id: PendingResourceId::new(kr_ipc::new_uuid()),
        application_instance_id: ApplicationInstanceId::new(kr_ipc::new_uuid()),
        request: DownstreamRequestId::new(GatewayConnectionId::new(u64::MAX), widest_upstream_id()),
        kind: widest(vec![
            PendingKind::Approval,
            PendingKind::ReverseRpc,
            PendingKind::UpstreamAction,
        ]),
        method: UpstreamMethod::new("m".repeat(256)).expect("a method"),
        classification: NativeClassification {
            class: NativeMethodClass::CredentialOrConfiguration,
            declared: true,
        },
        source_generation: SourceGeneration::new(u64::MAX),
        state: PendingState::Uncertain,
        durability: Durability::Volatile,
        deadline_ms: Nullable::some(TimestampMs::new(u64::MAX)),
        recorded_at: TimestampMs::new(u64::MAX),
        interpretation_verified: true,
    }
}

/// A closure record with `survivors` entries whose detail is `detail`, a note of `note` bytes as
/// its last entry, and `root_signal` of `signal` bytes.
fn closure(survivors: usize, detail: &str, note: usize, signal: usize) -> ClosureRecord {
    let mut surviving: Vec<SurvivingResource> = (0..survivors)
        .map(|_| SurvivingResource {
            kind: "unestablished".to_owned(),
            detail: detail.to_owned(),
        })
        .collect();
    if note > 0 {
        surviving.push(SurvivingResource {
            kind: "not_listed".to_owned(),
            detail: "n".repeat(note),
        });
    }
    ClosureRecord {
        session_id: session_id(),
        session_epoch: SessionEpoch::V1,
        reason: ClosureReason::RootSignal,
        root_exit_code: Nullable::some(U64::new(u64::MAX)),
        root_signal: if signal == 0 {
            Nullable::null()
        } else {
            Nullable::some("s".repeat(signal))
        },
        terminated: Vec::new(),
        surviving,
        ownership_coverage: OwnershipCoverage::Incomplete,
        durability: Durability::Volatile,
        closed_at_ms: TimestampMs::new(u64::MAX),
    }
}

/// A session summary as a worker answers it, with the two paths at the 4,096 bytes of a path.
fn summary(closure: Option<ClosureRecord>) -> SessionSummary {
    SessionSummary {
        session_id: session_id(),
        session_epoch: SessionEpoch::V1,
        environment_id: kr_protocol::ids::EnvironmentId::new(kr_ipc::new_uuid()),
        display_number: DisplayNumber::new(u64::MAX),
        state: SessionState::Closed,
        shell_mode: ShellMode::NativeCompat,
        shell_path: "s".repeat(4_096),
        cwd: "c".repeat(4_096),
        worker_profile: kr_protocol::identity::WorkerProfile::HeadlessUser,
        desktop: kr_protocol::identity::DesktopBinding::none(),
        created_at_ms: TimestampMs::new(u64::MAX),
        dimensions: Dimensions::new(u64::MAX, u64::MAX),
        attachment_count: U64::new(u64::MAX),
        application_state: Nullable::null(),
        root_process: Nullable::null(),
        closure: Nullable::from(closure),
        environment_sources: None,
        root: None,
        application: None,
    }
}

/// The close answer a worker gives for a closed session: the record in `closure`, and the summary
/// beside it with its own copy of the record when `twice`.
fn close_answer(record: &ClosureRecord, twice: bool) -> ControlFrame {
    answer(&SessionCloseResult {
        session_id: session_id(),
        state: SessionState::Closed,
        durability: Durability::Volatile,
        closure: Nullable::some(record.clone()),
        session: Some(summary(twice.then(|| record.clone()))),
    })
}

/// A screen driven by `script`, installed the way a worker installs it for a projected client, at
/// `cols` by `rows` and in pages of the compiled bound.
fn installed(cols: u32, rows: u32, script: &[u8]) -> Vec<Outgoing> {
    use kr_term::budget::GridSize;
    use kr_term::engine::{Engine, EngineConfig};
    use kr_term::snapshot::Viewport;

    let mut engine = Engine::new(EngineConfig {
        size: GridSize { cols, rows },
        ..EngineConfig::DEFAULT
    })
    .expect("an engine");
    engine.feed(script, 0);
    let window = Viewport {
        top_row: 0,
        rows,
        left_col: 0,
        cols,
    };
    let (snapshot, _) = engine.snapshot(window, 0);
    install(
        &snapshot,
        window,
        0,
        ProjectionResetReason::Attached,
        u64::MAX,
        false,
        PAGE_BYTES,
        kr_worker::render::Scope::WholeScreen,
        &engine,
    )
    .expect("the screen installs")
    .events
}

/// The header an installation carries.
fn header_of(events: &[Outgoing]) -> ProjectionSnapshot {
    events
        .iter()
        .find_map(|outgoing| match &outgoing.event {
            ProjectionEvent::Snapshot(header) => Some(header.as_ref().clone()),
            _ => None,
        })
        .expect("an installation opens with a header")
}

/// What a script that fills every table a header carries asks of a screen: a title and a pushed
/// title at each depth, a colour for each palette index, a tab stop at each column and a link.
fn crowded_script(cols: u32) -> Vec<u8> {
    let mut script = String::new();
    for depth in 0..=kr_term::title::MAX_DEPTH {
        let title = format!(
            "{depth:04}{}",
            "t".repeat(kr_term::title::MAX_TITLE_BYTES - 4)
        );
        write!(script, "\x1b]0;{title}\x07\x1b[22;0t").expect("a string takes a write");
    }
    for index in 0..=255_u32 {
        write!(
            script,
            "\x1b]4;{index};rgb:{:02x}/{:02x}/{:02x}\x07",
            index,
            255 - index,
            index / 2
        )
        .expect("a string takes a write");
    }
    script.push_str("\x1b[3g");
    for column in 1..=cols {
        write!(script, "\x1b[{column}G\x1bH").expect("a string takes a write");
    }
    for mode in [
        1_u32, 6, 7, 9, 12, 25, 45, 47, 66, 69, 1000, 1002, 1003, 1004, 1005, 1006, 1015, 1047,
        1048, 1049, 2004, 2026,
    ] {
        write!(script, "\x1b[?{mode}h").expect("a string takes a write");
    }
    write!(script, "\x1b]8;;h://{}\x07", "u".repeat(2_000)).expect("a string takes a write");
    script.into_bytes()
}

/// A script that writes `cells` cells, each with every colour set so that it is a run of its own.
fn styled_cells(cells: u32) -> Vec<u8> {
    let mut script = String::new();
    for cell in 0..cells {
        write!(
            script,
            "\x1b[38;2;{};{};{};48;2;{};{};{};58;2;{};{};{};1;3;4mx",
            cell % 251,
            (cell / 3) % 251,
            (cell / 7) % 251,
            (cell + 1) % 251,
            (cell / 5) % 251,
            (cell / 11) % 251,
            (cell + 2) % 251,
            (cell / 13) % 251,
            (cell / 17) % 251,
        )
        .expect("a string takes a write");
    }
    script.into_bytes()
}

/// A script that fills `rows` rows with `cols` styled cells each, every cell a run of its own. The
/// engine holds at most 262,144 cells, so a screen cannot fill a page of the compiled bound with
/// text; a row of runs fills a page to its value limit instead, which is the widest page there is.
fn packed_script(cols: u32, rows: u32) -> Vec<u8> {
    let mut script = Vec::new();
    for row in 0..rows {
        if row > 0 {
            script.extend_from_slice(b"\r\n");
        }
        script.extend_from_slice(&styled_cells(cols));
    }
    script
}

/// What the worker's send queue charges for a projection event: the encoded size of the payload it
/// carries, as the worker measures it when it builds the event.
fn projection_charge(event: &ProjectionEvent) -> usize {
    let cost = match event {
        ProjectionEvent::Reset(reset) => wire::measure(reset),
        ProjectionEvent::Snapshot(header) => wire::measure(header),
        ProjectionEvent::Rows(page) => wire::measure(page),
        ProjectionEvent::Delta(delta) => wire::measure(delta),
    }
    .expect("the codec represents a projection payload");
    OutputDelivery::Projection {
        cursor: u64::MAX,
        event: Box::new(event.clone()),
        bytes: cost.bytes,
    }
    .len()
}

/// Every kind of notification a worker sends, at its widest, with what the worker's queue charges.
fn widest_events() -> Vec<Measured> {
    let events = installed(2_048, 24, &crowded_script(2_048));
    let header = header_of(&events);
    // The pages of a screen of three rows of styled cells, the widest of which is the widest page: a
    // row of runs reaches the limit of values on a page before the limit of bytes. The first page
    // of an installation is the buffer that is not showing, and it is empty.
    let packed = installed(2_048, 3, &packed_script(2_048, 3));
    let page = widest(
        packed
            .iter()
            .filter_map(|outgoing| match &outgoing.event {
                ProjectionEvent::Rows(page) => Some(page.clone()),
                _ => None,
            })
            .collect(),
    );
    let delta = ProjectionDelta {
        base_cursor: U64::new(u64::MAX),
        next_cursor: U64::new(u64::MAX),
        projection_generation: U64::new(u64::MAX),
        buffer: ProjectedBuffer::Primary,
        viewport: header.viewport,
        rows: page.rows.iter().take(4).cloned().collect(),
        cursor: header.cursor,
        modes: header.modes.clone(),
        margins: Nullable::some(header.margins),
        rendition: Nullable::some(header.rendition),
        tab_stops: Nullable::some(header.tab_stops.clone()),
        charsets: Nullable::some(header.charsets.clone()),
        hyperlinks: Vec::new(),
        hyperlink: Nullable::null(),
        title: Nullable::some(header.title.clone()),
        title_stack: Nullable::some(header.title_stack.clone()),
        keyboard: Nullable::some(header.keyboard.clone()),
        palette: Nullable::some(header.palette.clone()),
        dimensions: Nullable::some(header.dimensions),
        saved_cursors: Nullable::some(header.saved_cursors.clone()),
        oldest_retained_row: U64::new(u64::MAX),
        evicted: true,
        degraded: true,
    };
    let output = OutputEvent {
        cursor: U64::new(u64::MAX),
        bytes: Bytes::new(vec![0xa5; kr_worker::service::MAX_OUTPUT_EVENT_BYTES]),
    };
    // The worker's own charge for the events of an installation is the figure to hold the
    // measurement to: the same payload measured here must be what the worker recorded.
    for outgoing in events.iter().chain(&packed) {
        assert_eq!(
            projection_charge(&outgoing.event),
            outgoing.bytes,
            "the charge measured here is the worker's own for a {} event",
            outgoing.event.event_type()
        );
    }
    let agent_resource = resource_event();
    let agent_instance = instance_event(512);
    let resource_cost = wire::measure(&agent_resource)
        .expect("the codec represents an agent resource event")
        .bytes;
    let instance_cost = wire::measure(&agent_instance)
        .expect("the codec represents an agent instance event")
        .bytes;
    let busy = editor_busy();
    vec![
        Measured::new("session.output", &output, |_| {
            Some(output.bytes.as_slice().len())
        }),
        Measured::new("session.gap", &gap(), |_| None),
        Measured::new(PROJECTION_RESET_EVENT, &reset(), |_| {
            Some(projection_charge(&ProjectionEvent::Reset(reset())))
        }),
        Measured::new(PROJECTION_SNAPSHOT_EVENT, &header, |_| {
            Some(projection_charge(&ProjectionEvent::Snapshot(Box::new(
                header.clone(),
            ))))
        }),
        Measured::new(PROJECTION_ROWS_EVENT, &page, |_| {
            Some(projection_charge(&ProjectionEvent::Rows(page.clone())))
        }),
        Measured::new(PROJECTION_DELTA_EVENT, &delta, |_| {
            Some(projection_charge(&ProjectionEvent::Delta(Box::new(
                delta.clone(),
            ))))
        }),
        Measured::new(AGENT_RESOURCE_EVENT, &agent_resource, |_| {
            Some(
                OutputDelivery::AgentResource {
                    event: Box::new(agent_resource.clone()),
                    bytes: resource_cost,
                }
                .len(),
            )
        }),
        Measured::new(AGENT_INSTANCE_EVENT, &agent_instance, |_| {
            Some(
                OutputDelivery::AgentInstance {
                    event: Box::new(agent_instance.clone()),
                    bytes: instance_cost,
                }
                .len(),
            )
        }),
        Measured::new(EDITOR_BUSY_EVENT, &busy, |_| {
            Some(OutputDelivery::EditorBusy(Box::new(busy.clone())).len())
        }),
        Measured::new("session.resync", &marker(), |_| {
            Some(OutputDelivery::Resync(marker()).len())
        }),
        Measured::new("session.detached", &detached(), |_| {
            Some(OutputDelivery::Detached.len())
        }),
        Measured::new(
            SESSION_CLOSED_EVENT,
            &closure(1, "/", CLOSURE_TEXT_BYTES / 2, CLOSURE_TEXT_BYTES),
            |_| None,
        ),
    ]
}

/// A frame whose payload carries `members` members in one array.
fn members_frame(members: usize) -> ControlFrame {
    #[derive(Serialize)]
    struct Members {
        items: Vec<u64>,
    }
    answer(&Members {
        items: vec![1; members],
    })
}

/// An output notification whose frame is `target` bytes, as the encoder counts it.
fn output_frame_of(target: usize) -> ControlFrame {
    let frame = |bytes: usize| {
        notice(
            "session.output",
            &OutputEvent {
                cursor: U64::new(u64::MAX),
                bytes: Bytes::new(vec![0xa5; bytes]),
            },
        )
    };
    let mut bytes = target.saturating_sub(frame_len(&frame(0)));
    loop {
        let built = frame(bytes);
        let length = frame_len(&built);
        if length == target {
            return built;
        }
        assert!(
            length > target || target - length < 16,
            "the search for a frame of {target} bytes stays near it"
        );
        bytes = if length > target {
            bytes - (length - target)
        } else {
            bytes + (target - length)
        };
    }
}

/// `after` less `before`, signed, so that a frame the rewrite shortens shows as a negative growth.
fn signed_difference(after: usize, before: usize) -> i64 {
    i64::try_from(after).expect("a length fits") - i64::try_from(before).expect("a length fits")
}

/// The median of `runs` timings of `work`, in nanoseconds.
fn median_ns(runs: usize, mut work: impl FnMut()) -> u128 {
    let mut samples: Vec<u128> = (0..runs)
        .map(|_| {
            let start = Instant::now();
            work();
            start.elapsed().as_nanos()
        })
        .collect();
    samples.sort_unstable();
    samples[samples.len() / 2]
}

/// What the guard's extra test costs a device-bound frame, and that the guard and the transport's
/// writer count one unit.
///
/// The times are recorded and carry no assertion. The assertions hold what does not depend on a
/// clock: the guard's length is the writer's, the compiled-bound frame is what it says, and a frame
/// of 4,097 members passes today's check and fails the encoder's own.
#[test]
fn the_guards_extra_cost_is_recorded_and_its_unit_is_the_encoders() {
    let bound = COMPILED - FRAME_LENGTH_PREFIX_LEN;
    let limits = Limits::DEFAULT.with_max_message_len(bound);
    let widest_frame = output_frame_of(bound);
    let many = members_frame(4_096);
    let small = notice("session.resync", &marker());

    let build = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };
    let mut table = format!("MEASURE | the guard's cost | build {build}\n");
    for (name, frame) in [
        ("a frame of the compiled bound", &widest_frame),
        ("a frame of 4,096 members", &many),
        ("a small frame", &small),
    ] {
        let value = to_canonical_value(frame).expect("a frame converts");
        let guard_accepts = value.check_limits(&limits).is_ok() && encoded_len(&value) <= bound;
        let written = to_canonical_vec_within(frame, &limits).expect("the transport encodes it");
        assert!(guard_accepts, "{name}: the guard's test accepts it");
        assert_eq!(
            encoded_len(&value),
            written.len(),
            "{name}: the guard counts what the transport writes"
        );
        assert!(fits(frame, bound), "{name}: today's check accepts it");

        let runs = match written.len() {
            0..=10_000 => 20_001,
            10_001..=100_000 => 1_001,
            _ => 21,
        };
        let today = median_ns(runs, || {
            black_box(fits(black_box(frame), bound));
        });
        let guarded = median_ns(runs, || {
            let value = to_canonical_value(black_box(frame)).expect("converts");
            black_box(value.check_limits(&limits).is_ok() && encoded_len(&value) <= bound);
        });
        let check_alone = median_ns(runs, || {
            black_box(value.check_limits(black_box(&limits)).is_ok());
        });
        let transport = median_ns(runs, || {
            black_box(to_canonical_vec_within(black_box(frame), &limits)).ok();
        });
        writeln!(
            table,
            "MEASURE | {name} | frame {} | today's check {today} ns | guard's test {guarded} ns | check_limits alone {check_alone} ns | the transport's encode {transport} ns | runs {runs}",
            written.len()
        )
        .expect("a string takes a write");
    }
    println!("{table}");

    // The compiled-bound frame is the compiled bound, prefix excluded.
    assert_eq!(frame_len(&widest_frame), bound);
    // Four thousand and ninety-seven members: today's check passes it and the encoder refuses it.
    let over = members_frame(4_097);
    let over_value = to_canonical_value(&over).expect("converts");
    assert!(
        over_value.check_limits(&limits).is_err(),
        "the encoder's own check refuses 4,097 members"
    );
    assert!(
        to_canonical_vec_within(&over, &limits).is_err(),
        "the transport's writer refuses 4,097 members"
    );
    assert!(
        fits(&over, bound),
        "today's check passes the 4,097 members the writer refuses"
    );
}

/// What a device is shown of the frames a worker cuts to its bound, against what the worker built.
///
/// The relay adds no envelope; the door's rewrite is the only growth, so the figure is the
/// difference between the two encodings. The output notification's envelope is the difference
/// between its frame and its bytes, which a cut by the receiver's bound has to leave room for.
#[test]
fn a_cut_output_and_projection_frame_grows_by_nothing_when_a_device_is_shown_it() {
    let events = widest_events();
    let mut table = String::from("MEASURE | the relay's overhead\n");
    let mut overhead_max = i64::MIN;
    for name in [
        "session.output",
        PROJECTION_RESET_EVENT,
        PROJECTION_SNAPSHOT_EVENT,
        PROJECTION_ROWS_EVENT,
        PROJECTION_DELTA_EVENT,
    ] {
        let measured = events
            .iter()
            .find(|measured| measured.name == name)
            .expect("the kind is measured");
        let before = frame_len(&measured.frame);
        let after = frame_len(&shown(&measured.frame));
        let growth = signed_difference(after, before);
        overhead_max = overhead_max.max(growth);
        writeln!(
            table,
            "MEASURE | {name} | payload {} | frame before {before} | frame after {after} | growth {growth} | queue charge {}",
            measured.payload,
            measured
                .charge
                .map_or_else(|| "n/a".to_owned(), |charge| charge.to_string())
        )
        .expect("a string takes a write");
        assert_eq!(
            after, before,
            "{name}: the rewrite leaves the frame as it was"
        );
    }
    let output = events
        .iter()
        .find(|measured| measured.name == "session.output")
        .expect("output is measured");
    writeln!(
        table,
        "MEASURE | session.output envelope | bytes {} | frame {} | everything but the bytes {}",
        kr_worker::service::MAX_OUTPUT_EVENT_BYTES,
        frame_len(&output.frame),
        frame_len(&output.frame) - kr_worker::service::MAX_OUTPUT_EVENT_BYTES
    )
    .expect("a string takes a write");
    writeln!(table, "MEASURE | RELAY_OVERHEAD_MAX {overhead_max}").expect("a string takes a write");
    let page = events
        .iter()
        .find(|measured| measured.name == PROJECTION_ROWS_EVENT)
        .expect("a page is measured");
    let page_frame = frame_len(&shown(&page.frame));
    writeln!(
        table,
        "MEASURE | the widest page: payload {} | PAGE_BYTES {PAGE_BYTES} | frame {page_frame} | the compiled frame without its prefix {}",
        page.payload,
        COMPILED - FRAME_LENGTH_PREFIX_LEN
    )
    .expect("a string takes a write");
    println!("{table}");

    // A full page, the most the worker builds, is whole in the compiled frame once the notification
    // around it is added.
    assert!(
        page.payload <= PAGE_BYTES,
        "a page is at most {PAGE_BYTES} bytes of payload, found {}",
        page.payload
    );
    assert!(
        page_frame <= COMPILED - FRAME_LENGTH_PREFIX_LEN,
        "the widest page is whole in the compiled frame, found {page_frame}"
    );

    // The control: a closure that names the host in a survivor's detail is lengthened by the same
    // rewrite, so the zero above is the frames' own and not a measurement that cannot see growth.
    let named = notice(SESSION_CLOSED_EVENT, &closure(8, "/", 0, 0));
    assert!(
        frame_len(&shown(&named)) > frame_len(&named),
        "the rewrite lengthens a survivor that names the host"
    );
}

/// The three records the queue holds beside ordinary room, and the reserve they make.
///
/// The marker's charge is a constant and the other two are charged nothing today; the design
/// charges the reserve for all three. The case records the payload, the frame and the charge of
/// each, and holds the reserve both ways: by the payload's size, which is what a queue charges for
/// every other event, and by the complete frame.
#[test]
fn the_small_records_and_the_reserve_they_make() {
    let records = [
        Measured::new("session.resync", &marker(), |_| {
            Some(OutputDelivery::Resync(marker()).len())
        }),
        Measured::new(EDITOR_BUSY_EVENT, &editor_busy(), |_| {
            Some(OutputDelivery::EditorBusy(Box::new(editor_busy())).len())
        }),
        Measured::new("session.detached", &detached(), |_| {
            Some(OutputDelivery::Detached.len())
        }),
        Measured::new("session.gap", &gap(), |_| None),
        Measured::new(PROJECTION_RESET_EVENT, &reset(), |_| None),
    ];
    let mut table = String::from("MEASURE | the small records\n");
    for record in &records {
        let frame = frame_len(&shown(&record.frame));
        table.push_str(&line(
            record.name,
            record.payload,
            &shown(&record.frame),
            record.charge,
        ));
        assert!(
            frame < 512,
            "{}: the complete frame is under 512 bytes, found {frame}",
            record.name
        );
    }
    let produced = detached_as_produced();
    let produced_payload = payload_len(&produced);
    let produced_frame = frame_len(&shown(&notice("session.detached", &produced)));
    table.push_str(&line(
        "session.detached, as the worker's one producer writes it",
        produced_payload,
        &shown(&notice("session.detached", &produced)),
        Some(OutputDelivery::Detached.len()),
    ));
    let [marker_record, busy, detach, _, _] = &records;
    let marker_frame = frame_len(&shown(&marker_record.frame));
    let busy_frame = frame_len(&shown(&busy.frame));
    let detach_frame = frame_len(&shown(&detach.frame));
    // Two deliveries each hold one marker, one `EditorBusy` and one `Detached`.
    let reserve_of =
        |busy_size: usize, detach_size: usize| 2 * (RESYNC_MARKER_BYTES + busy_size + detach_size);
    let by_payload = reserve_of(busy.payload, detach.payload);
    let by_frame = reserve_of(busy_frame, detach_frame);
    let reserve_small = by_payload.max(by_frame);
    // The same reserve with the detach notification as the one producer writes it.
    let produced_reserve =
        reserve_of(busy.payload, produced_payload).max(reserve_of(busy_frame, produced_frame));
    let usable = QUEUE_FLOOR
        .checked_sub(CLOSURE_ROOM + reserve_small)
        .expect("the reserve is smaller than the queue the floor allows");
    let margin = signed_difference(usable, PAGE_BYTES);
    writeln!(
        table,
        "MEASURE | RESERVE_SMALL, detach with every member the type has: by payloads {by_payload} | by frames {by_frame} | taken {reserve_small} | against the allowance {RESERVE_SMALL_BOUND}: {} | against the trigger {STOP_LINE}: {}",
        signed_difference(reserve_small, RESERVE_SMALL_BOUND),
        signed_difference(reserve_small, STOP_LINE)
    )
    .expect("a string takes a write");
    writeln!(
        table,
        "MEASURE | RESERVE_SMALL, detach as the worker's one producer writes it: taken {produced_reserve} | against the allowance {RESERVE_SMALL_BOUND}: {} | against the trigger {STOP_LINE}: {}",
        signed_difference(produced_reserve, RESERVE_SMALL_BOUND),
        signed_difference(produced_reserve, STOP_LINE)
    )
    .expect("a string takes a write");
    writeln!(
        table,
        "MEASURE | usable at the floor {usable} | against {USABLE_BOUND}: {} | PAGE_BYTES {PAGE_BYTES} | margin above a page {margin}",
        signed_difference(usable, USABLE_BOUND)
    )
    .expect("a string takes a write");
    writeln!(
        table,
        "MEASURE | the marker: payload {} | frame {marker_frame} | charge {RESYNC_MARKER_BYTES}",
        marker_record.payload
    )
    .expect("a string takes a write");
    println!("{table}");

    // The constant says it is at least what any marker encodes to: its payload.
    assert!(
        marker_record.payload <= RESYNC_MARKER_BYTES,
        "a marker's payload is at most its charge of {RESYNC_MARKER_BYTES}, found {}",
        marker_record.payload
    );
    // The design's census says the marker is 96 bytes and whole; the complete frame is the figure a
    // device receives.
    assert!(
        marker_frame <= REPLACEMENT_BOUND,
        "a marker's complete frame fits the replacement bound, found {marker_frame}"
    );
    // The limits design's section on the queue's closed arithmetic keeps the closure's room at one
    // frame unless the three small records cost more than the trigger: the room the queue at the
    // floor leaves above a page once that frame is taken. A figure above the allowance of 3,072
    // and at or under the trigger is a finding the table reports, not a failure here.
    assert_eq!(
        QUEUE_FLOOR - CLOSURE_ROOM - PAGE_BYTES,
        STOP_LINE,
        "the trigger is what the queue at the floor leaves above a page after the closure's room"
    );
    assert!(
        reserve_small <= STOP_LINE,
        "the three small records cost at most the trigger of {STOP_LINE}, found {reserve_small}"
    );
}

/// The widest projection header and row, from a real screen driven to fill every table a header
/// carries, and from the header with each table stuffed to its bound.
#[test]
fn the_widest_projection_header_and_row() {
    let cols = 2_048;
    let events = installed(cols, 24, &crowded_script(cols));
    let driven = header_of(&events);
    let mut stuffed = driven.clone();
    stuffed.title_stack = (0..kr_term::title::MAX_DEPTH)
        .map(|depth| SavedTitleEntry {
            icon: Nullable::some(format!(
                "{depth:04}{}",
                "i".repeat(kr_term::title::MAX_TITLE_BYTES - 4)
            )),
            window: Nullable::some(format!(
                "{depth:04}{}",
                "w".repeat(kr_term::title::MAX_TITLE_BYTES - 4)
            )),
        })
        .collect();
    stuffed.tab_stops = (0..u64::from(cols)).map(U64::new).collect();
    stuffed.palette.overrides = (0..=255_u8)
        .map(|index| PaletteOverride {
            index,
            colour: stuffed.palette.foreground,
        })
        .collect();
    stuffed.hyperlink = Nullable::some(ProjectedHyperlink {
        uri: "u".repeat(2_048),
        params: String::new(),
    });
    let mut bare = stuffed.clone();
    bare.title_stack = Vec::new();
    bare.tab_stops = Vec::new();
    bare.palette.overrides = Vec::new();
    bare.hyperlink = Nullable::null();

    let mut table = String::from("MEASURE | the projection header\n");
    for (name, header) in [
        ("driven by a real screen", &driven),
        ("every table at its bound", &stuffed),
        ("modes, keys and framing alone", &bare),
    ] {
        let payload = payload_len(header);
        let frame = notice(PROJECTION_SNAPSHOT_EVENT, header);
        let charge = wire::measure(header)
            .expect("the codec represents a projection header")
            .bytes;
        table.push_str(&line(name, payload, &shown(&frame), Some(charge)));
    }
    writeln!(
        table,
        "MEASURE | the driven header holds {} title entries, {} tab stops, {} palette overrides, {} modes, {} saved cursors, a link {}",
        driven.title_stack.len(),
        driven.tab_stops.len(),
        driven.palette.overrides.len(),
        driven.modes.len(),
        driven.saved_cursors.len(),
        driven.hyperlink.0.is_some()
    )
    .expect("a string takes a write");

    let stuffed_frame = frame_len(&shown(&notice(PROJECTION_SNAPSHOT_EVENT, &stuffed)));
    writeln!(
        table,
        "MEASURE | the header with every table at its bound: frame {stuffed_frame} | against the floor {FLOOR}: {} | against the transport's floor {TRANSPORT_FLOOR}: {}",
        signed_difference(stuffed_frame + FRAME_LENGTH_PREFIX_LEN, FLOOR),
        signed_difference(stuffed_frame + FRAME_LENGTH_PREFIX_LEN, TRANSPORT_FLOOR)
    )
    .expect("a string takes a write");
    assert!(
        stuffed_frame + FRAME_LENGTH_PREFIX_LEN <= FLOOR,
        "the header with every table at its bound is whole at the floor of {FLOOR}, found {stuffed_frame}"
    );
    assert!(
        payload_len(&stuffed) >= payload_len(&driven),
        "the stuffed header is the wider one"
    );

    // The widest row: two thousand and forty-eight cells, each its own run.
    let styled = styled_cells;
    let plain_runs = |cells: u32| -> Vec<u8> {
        let mut script = String::new();
        for cell in 0..cells {
            script.push_str(if cell % 2 == 0 {
                "\x1b[1mx"
            } else {
                "\x1b[22mx"
            });
        }
        script.into_bytes()
    };
    let rows_of = |script: &[u8]| -> Vec<ProjectedRow> {
        installed(cols, 24, script)
            .into_iter()
            .filter_map(|outgoing| match outgoing.event {
                ProjectionEvent::Rows(page) => Some(page.rows),
                _ => None,
            })
            .flatten()
            .collect()
    };
    // The row with the most runs: the rows of an installation come in pages, the first of which is
    // the buffer that is not showing, so the first row is not the one the script wrote.
    let first_row = |script: &[u8]| {
        rows_of(script)
            .into_iter()
            .max_by_key(|row| row.runs.len())
            .expect("a row")
    };
    // The marginal cost of one run, from two rows that differ by a hundred runs and are both whole.
    let (few, many) = (first_row(&plain_runs(20)), first_row(&plain_runs(120)));
    let default_run_items = (wire::row_cost(&many).items - wire::row_cost(&few).items) / 100;
    let default_run_bytes = (wire::row_cost(&many).bytes - wire::row_cost(&few).bytes) / 100;
    let (few, many) = (first_row(&styled(20)), first_row(&styled(120)));
    let styled_run_items = (wire::row_cost(&many).items - wire::row_cost(&few).items) / 100;
    let styled_run_bytes = (wire::row_cost(&many).bytes - wire::row_cost(&few).bytes) / 100;
    let wide = first_row(&styled(cols));
    let plain_wide = first_row(b"xxxxxxxxxx");
    writeln!(
        table,
        "MEASURE | a run with default colours costs {default_run_items} values and {default_run_bytes} bytes; a run with every colour set costs {styled_run_items} values and {styled_run_bytes} bytes"
    )
    .expect("a string takes a write");
    writeln!(
        table,
        "MEASURE | a row of {cols} styled cells, whole: {} values, {} bytes; the worker's row: {} runs, truncated {}, {} values, {} bytes; PAGE_ITEMS {PAGE_ITEMS}, PAGE_BYTES {PAGE_BYTES}",
        usize::try_from(cols).expect("a column count") * styled_run_items,
        usize::try_from(cols).expect("a column count") * styled_run_bytes,
        wide.runs.len(),
        wide.truncated,
        wire::row_cost(&wide).items,
        wire::row_cost(&wide).bytes,
    )
    .expect("a string takes a write");
    println!("{table}");

    assert!(
        default_run_items >= 37,
        "a run with default colours costs at least 37 values, found {default_run_items}"
    );
    assert!(
        usize::try_from(cols).expect("a column count") * default_run_items > PAGE_ITEMS,
        "a row of {cols} styled cells is over the item limit of a page"
    );
    assert!(
        usize::try_from(cols).expect("a column count") * styled_run_bytes > FLOOR,
        "a row of {cols} cells with every colour set is over the floor in bytes"
    );
    assert!(
        wide.truncated && wire::row_cost(&wide).items <= PAGE_ITEMS,
        "the worker cuts and marks it, inside a page's item limit"
    );
    assert!(
        !plain_wide.truncated && plain_wide.runs.len() == 1,
        "a row of one run is delivered whole"
    );
}

/// The widest answer to an unpaired peer, the widest error answer, and the widest acknowledgement
/// of the input stream.
///
/// An acknowledgement is written to the input stream as a message of its own, not inside a control
/// frame, so its payload and its complete frame are one figure; the input stream's bound is
/// compared with it.
#[test]
fn the_widest_pairing_answer_and_the_widest_refusal() {
    use kr_protocol::pairing::DirectChallenge;
    use kr_protocol::preauth::{PairFinishResult, PairRedeemResult, PairStatusResult};
    use kr_protocol::scalars::Nonce256;

    let keys = kr_crypto::keys::DeviceKeys::generate().expect("keys");
    let public = keys.public_keys();
    let challenge = PairRedeemResult::Challenge(Box::new(DirectChallenge {
        invitation_id: kr_protocol::ids::InvitationId::new(kr_ipc::new_uuid()),
        host_nonce: Nonce256::from_bytes([0xff; 32]),
        host_keys: public,
        device_key_revision: kr_protocol::ids::DeviceKeyRevision::new(u64::MAX),
        endpoint_id: public.transport,
        expires_at_ms: TimestampMs::new(u64::MAX),
    }));
    let locked = PairRedeemResult::Locked {
        attempt_id: kr_protocol::ids::AttemptId::new(kr_ipc::new_uuid()),
        verification_value: "f".repeat(8),
    };
    let finished = PairFinishResult {
        attempt_id: kr_protocol::ids::AttemptId::new(kr_ipc::new_uuid()),
        verification_value: "f".repeat(8),
    };
    let status = PairStatusResult {
        status: kr_protocol::pairing::PairStatus::AwaitingApproval {
            attempt_id: kr_protocol::ids::AttemptId::new(kr_ipc::new_uuid()),
            verification_value: "f".repeat(8),
            expires_at_ms: TimestampMs::new(u64::MAX),
        },
        owner: Nullable::null(),
    };
    // The connection's refusal is the frame the door's own `refusal` makes of a controller error's
    // protocol error: a code and its text, with no diagnostic identifier and no fence flag. The
    // widest of it is the code whose encoding is longest, with the longest text an error carries.
    let widest_error = widest(
        kr_protocol::error::ErrorCode::ALL
            .iter()
            .map(|code| {
                kr_protocol::error::ProtocolError::new(
                    *code,
                    "m".repeat(kr_protocol::error::MAX_ERROR_MESSAGE_LEN),
                )
            })
            .collect(),
    );
    let refusal = super::super::refusal(&widest_error);
    // The widest an error is by its type, which no refusal of the door sets.
    let typed_error = {
        let mut error = widest_error
            .clone()
            .with_diagnostic_id(DiagnosticId::new("d".repeat(256)).expect("a diagnostic"));
        error.link_fenced = true;
        error
    };
    let typed_refusal = ControlFrame::Response(Response {
        request_id: RequestId::new(u64::MAX),
        outcome: Outcome::Error(typed_error.clone()),
    });

    let mut table = String::from("MEASURE | the pairing answers and the refusal\n");
    let mut widest_answer = 0;
    for (name, frame, payload) in [
        (
            "pair.redeem, a challenge",
            answer(&challenge),
            payload_len(&challenge),
        ),
        ("pair.redeem, locked", answer(&locked), payload_len(&locked)),
        ("pair.finish", answer(&finished), payload_len(&finished)),
        (
            "pair.status, awaiting approval",
            answer(&status),
            payload_len(&status),
        ),
    ] {
        widest_answer = widest_answer.max(frame_len(&frame));
        table.push_str(&line(name, payload, &frame, None));
    }
    let refusal_frame = frame_len(&refusal);
    table.push_str(&line(
        "the connection's refusal, as the door writes it",
        payload_len(&widest_error),
        &refusal,
        None,
    ));
    table.push_str(&line(
        "a refusal by its type, with a diagnostic identifier and the fence flag",
        payload_len(&typed_error),
        &typed_refusal,
        None,
    ));
    let epoch = InputLeaseEpoch::new(u64::MAX);
    let sequence = kr_protocol::ids::InputSequence::new(u64::MAX);
    let refused = kr_protocol::input::InputAck::Refused {
        epoch,
        sequence,
        accepted_through: Nullable::some(sequence),
        error: {
            let mut error = kr_protocol::error::ProtocolError::new(
                kr_protocol::error::ErrorCode::InvalidArgument,
                "m".repeat(kr_protocol::error::MAX_ERROR_MESSAGE_LEN),
            )
            .with_diagnostic_id(DiagnosticId::new("d".repeat(256)).expect("a diagnostic"));
            error.link_fenced = true;
            error
        },
    };
    let small = [
        kr_protocol::input::InputAck::Ready {
            window: kr_protocol::input::InputWindow {
                frames: u32::MAX,
                bytes: U64::new(u64::MAX),
            },
        },
        kr_protocol::input::InputAck::Accepted {
            epoch,
            through: sequence,
        },
        kr_protocol::input::InputAck::LaunchReserved { launch: u32::MAX },
        kr_protocol::input::InputAck::EpochEnded {
            epoch,
            fenced_bytes: U64::new(u64::MAX),
        },
    ];
    let refused_len = payload_len(&refused);
    let widest_small = small.iter().map(payload_len).max().expect("a variant");
    writeln!(
        table,
        "MEASURE | InputAck::Refused with a message of {} bytes | payload {refused_len} | frame {refused_len} | frame with prefix {} | queue charge n/a | the input stream's payload at its floor {INPUT_PAYLOAD_FLOOR}",
        kr_protocol::error::MAX_ERROR_MESSAGE_LEN,
        refused_len + FRAME_LENGTH_PREFIX_LEN
    )
    .expect("a string takes a write");
    writeln!(
        table,
        "MEASURE | the widest of the other four InputAck variants | payload {widest_small} | frame {widest_small}"
    )
    .expect("a string takes a write");
    println!("{table}");

    assert!(
        refused_len > INPUT_PAYLOAD_FLOOR,
        "a refusal with a message of 1,024 bytes does not encode within the input stream's floor of {INPUT_PAYLOAD_FLOOR}, found {refused_len}"
    );
    assert!(
        widest_small <= INPUT_PAYLOAD_FLOOR,
        "every other acknowledgement fits the input stream's floor of {INPUT_PAYLOAD_FLOOR}, found {widest_small}"
    );
    assert!(
        widest_answer < TRANSPORT_FLOOR,
        "the widest pairing answer is under the transport's floor of {TRANSPORT_FLOOR}, found {widest_answer}"
    );
    assert!(
        refusal_frame <= REFUSAL_BOUND,
        "the widest refusal is under {REFUSAL_BOUND} bytes, found {refusal_frame}"
    );
}

/// The two agent events at their widest.
#[test]
fn the_widest_agent_events() {
    let instance_widest = instance_event(512);
    let instance_sdk = {
        let mut event = instance_event(512);
        event.instance.plugin_id =
            Nullable::some(PluginId::new("p".repeat(129)).expect("a plugin identifier"));
        event
    };
    let resource = resource_event();
    let root = causal_root();
    let mut table = String::from("MEASURE | the agent events\n");
    for (name, event) in [
        (
            "agent instance, identifiers at the protocol bound",
            &instance_widest,
        ),
        (
            "agent instance, plugin identifier as the SDK builds it",
            &instance_sdk,
        ),
    ] {
        // The worker's charge for the event is the cost it measures when it builds it.
        let charge = OutputDelivery::AgentInstance {
            event: Box::new(event.clone()),
            bytes: wire::measure(event)
                .expect("the codec represents an agent instance event")
                .bytes,
        }
        .len();
        table.push_str(&line(
            name,
            payload_len(event),
            &shown(&notice(AGENT_INSTANCE_EVENT, event)),
            Some(charge),
        ));
    }
    let resource_frame = notice(AGENT_RESOURCE_EVENT, &resource);
    let resource_charge = OutputDelivery::AgentResource {
        event: Box::new(resource.clone()),
        bytes: wire::measure(&resource)
            .expect("the codec represents an agent resource event")
            .bytes,
    }
    .len();
    table.push_str(&line(
        "agent resource",
        payload_len(&resource),
        &shown(&resource_frame),
        Some(resource_charge),
    ));
    writeln!(table, "MEASURE | causal_root {} bytes", root.len()).expect("a string takes a write");
    writeln!(
        table,
        "MEASURE | agent resource, plan: under {AGENT_RESOURCE_ESTIMATE}; measured: payload {} | frame {}",
        payload_len(&resource),
        frame_len(&shown(&resource_frame))
    )
    .expect("a string takes a write");
    println!("{table}");

    let instance_frame = frame_len(&shown(&notice(AGENT_INSTANCE_EVENT, &instance_widest)));
    assert!(
        payload_len(&instance_widest) < AGENT_INSTANCE_BOUND
            && instance_frame < AGENT_INSTANCE_BOUND,
        "an agent instance event is under {AGENT_INSTANCE_BOUND} bytes, payload {} and frame {instance_frame}",
        payload_len(&instance_widest)
    );
    assert_eq!(
        root.len(),
        CAUSAL_ROOT_BOUND,
        "the widest causal root is {CAUSAL_ROOT_BOUND} bytes"
    );
    // The design's census estimated the event at under 2,200 bytes; the measurement corrects it. The
    // figures are pinned at the type's widest, and what the design rests on is that the frame is
    // whole at the floor.
    assert_eq!(
        payload_len(&resource),
        AGENT_RESOURCE_PAYLOAD,
        "the widest agent resource event is {AGENT_RESOURCE_PAYLOAD} bytes of payload"
    );
    assert_eq!(
        frame_len(&shown(&resource_frame)),
        AGENT_RESOURCE_FRAME,
        "the widest agent resource event is {AGENT_RESOURCE_FRAME} bytes as a complete frame"
    );
    assert!(
        frame_len(&shown(&resource_frame)) + FRAME_LENGTH_PREFIX_LEN <= FLOOR,
        "the widest agent resource event is whole at the floor of {FLOOR}"
    );
}

/// The widest close answer of a closed session, and the closure notice, as a device receives them.
///
/// The record is built at the design's budget for the closure's lists, with each survivor's detail
/// one byte that names the host, which the door lengthens. The worker builds the answer today with
/// the record twice; the design builds it once.
#[test]
fn the_widest_close_answer_of_a_closed_session() {
    // The size one survivor takes in the form a device is shown, from a record with and without it.
    let device_entry = {
        let with = frame_len(&shown(&notice(
            SESSION_CLOSED_EVENT,
            &closure(2, "/", 0, 0),
        )));
        let without = frame_len(&shown(&notice(
            SESSION_CLOSED_EVENT,
            &closure(1, "/", 0, 0),
        )));
        with - without
    };
    let survivors = CLOSURE_LISTS_BOUND / device_entry;
    let record = closure(survivors, "/", CLOSURE_TEXT_BYTES / 2, CLOSURE_TEXT_BYTES);
    let bare = closure(0, "/", 0, CLOSURE_TEXT_BYTES);
    let notification = notice(SESSION_CLOSED_EVENT, &record);
    let once = close_answer(&record, false);
    let twice = close_answer(&record, true);

    let lists =
        frame_len(&shown(&notification)) - frame_len(&shown(&notice(SESSION_CLOSED_EVENT, &bare)));
    let fixed = payload_len(&bare);
    let envelope = frame_len(&notice(SESSION_CLOSED_EVENT, &bare)) - fixed;
    let mut table = String::from("MEASURE | the closure and the close answer\n");
    table.push_str(&line(
        "session.closed, as the worker builds it",
        payload_len(&record),
        &notification,
        Some(CLOSED_NOTICE_CHARGE),
    ));
    table.push_str(&line(
        "session.closed, as a device is shown it",
        payload_len(&record),
        &shown(&notification),
        Some(CLOSED_NOTICE_CHARGE),
    ));
    table.push_str(&line(
        "session.close answer, the record once",
        payload_len(&record),
        &shown(&once),
        None,
    ));
    table.push_str(&line(
        "session.close answer, the record twice (as the worker builds it today)",
        payload_len(&record),
        &shown(&twice),
        None,
    ));
    writeln!(
        table,
        "MEASURE | {survivors} survivors of {device_entry} bytes each | lists as shown {lists} | members outside the lists with root_signal at {CLOSURE_TEXT_BYTES}: {fixed} | notification envelope {envelope}"
    )
    .expect("a string takes a write");
    println!("{table}");

    assert!(
        lists <= CLOSURE_LISTS_BOUND + CLOSURE_TEXT_BYTES / 2 + 512,
        "the lists as a device is shown them are within the budget and the entry, found {lists}"
    );
    assert!(
        fixed <= CLOSURE_FIXED_BOUND,
        "the closure's other members are within {CLOSURE_FIXED_BOUND} bytes, found {fixed}"
    );
    assert!(
        envelope <= ENVELOPE_BOUND,
        "the notification's envelope is within {ENVELOPE_BOUND} bytes, found {envelope}"
    );
    assert!(
        frame_len(&shown(&notification)) <= CLOSURE_FRAME_BOUND,
        "the largest closure notification is at most {CLOSURE_FRAME_BOUND} bytes, found {}",
        frame_len(&shown(&notification))
    );
    assert!(
        frame_len(&shown(&once)) < FLOOR - FRAME_LENGTH_PREFIX_LEN,
        "the close answer with the record once is whole at the floor, found {}",
        frame_len(&shown(&once))
    );
    assert!(
        frame_len(&shown(&twice)) > FLOOR - FRAME_LENGTH_PREFIX_LEN,
        "the close answer with the record twice is over the floor, found {}",
        frame_len(&shown(&twice))
    );
}

/// The marker and the reduced record, and the figures of what replaces a frame.
#[test]
fn the_marker_and_the_reduced_record() {
    let marker_frame = notice("session.resync", &marker());
    let entry_detail = CLOSURE_TEXT_BYTES / 2;
    let reduced = closure(0, "", entry_detail, CLOSURE_TEXT_BYTES);
    let reduced_frame = notice(SESSION_CLOSED_EVENT, &reduced);
    let long_signal = closure(0, "", entry_detail, 4 * CLOSURE_TEXT_BYTES);
    let mut table = String::from("MEASURE | the replacements\n");
    table.push_str(&line(
        "the marker",
        payload_len(&marker()),
        &shown(&marker_frame),
        Some(OutputDelivery::Resync(marker()).len()),
    ));
    table.push_str(&line(
        "the reduced record",
        payload_len(&reduced),
        &shown(&reduced_frame),
        Some(CLOSED_NOTICE_CHARGE),
    ));
    table.push_str(&line(
        "the reduced record with a root_signal of 4,096 bytes",
        payload_len(&long_signal),
        &shown(&notice(SESSION_CLOSED_EVENT, &long_signal)),
        Some(CLOSED_NOTICE_CHARGE),
    ));
    println!("{table}");

    assert!(
        frame_len(&shown(&marker_frame)) <= REPLACEMENT_BOUND,
        "the marker is within {REPLACEMENT_BOUND} bytes"
    );
    assert!(
        frame_len(&shown(&reduced_frame)) <= REPLACEMENT_BOUND,
        "the reduced record is within {REPLACEMENT_BOUND} bytes, found {}",
        frame_len(&shown(&reduced_frame))
    );
    assert!(
        frame_len(&shown(&reduced_frame)) <= TRANSPORT_FLOOR,
        "the reduced record fits the transport's floor"
    );
}

/// The subscribe and agent-instances answers as a device receives them, and where they stop fitting.
///
/// Nothing caps the live instances a session has. The case builds the answers with instances whose
/// refusal is at its cut, whose refusal is one byte that names the host, and whose refusal is
/// absent, and records how many fit at the floor.
#[test]
fn the_subscribe_and_agent_instances_answers_as_a_device_receives_them() {
    let bound = FLOOR - FRAME_LENGTH_PREFIX_LEN;
    let subscribe = |instances: Vec<AgentInstanceSummary>| {
        answer(&EventsSubscribeResult {
            stream_id: StreamId::new(kr_worker::service::OUTPUT_STREAM).expect("a stream"),
            from_cursor: U64::new(u64::MAX),
            oldest_retained_cursor: U64::new(u64::MAX),
            gap: Nullable::some(gap()),
            agent_resources: AgentResourceSnapshot {
                snapshot_id: U64::new(u64::MAX),
                stream_generation: U64::new(u64::MAX),
                cursor: U64::new(u64::MAX),
                resources: Vec::new(),
                continue_after: Nullable::some(PendingResourceId::new(kr_ipc::new_uuid())),
            },
            agent_instances: AgentInstanceList {
                sequence: U64::new(u64::MAX),
                instances,
            },
        })
    };
    let listing = |instances: Vec<AgentInstanceSummary>| {
        answer(&AgentInstancesResult {
            agent_resources: AgentResourceSnapshot {
                snapshot_id: U64::new(u64::MAX),
                stream_generation: U64::new(u64::MAX),
                cursor: U64::new(u64::MAX),
                resources: Vec::new(),
                continue_after: Nullable::some(PendingResourceId::new(kr_ipc::new_uuid())),
            },
            agent_instances: AgentInstanceList {
                sequence: U64::new(u64::MAX),
                instances,
            },
        })
    };
    let with_refusal = |text: Option<&str>| {
        let mut one = instance(0);
        one.refusal = text.map_or_else(Nullable::null, |text| Nullable::some(text.to_owned()));
        one
    };
    let mut table = String::from("MEASURE | the subscribe and agent.instances answers\n");
    let mut fitting = Vec::new();
    for (name, one) in [
        (
            "refusal at its cut of 512 bytes",
            with_refusal(Some(&"r".repeat(512))),
        ),
        (
            "refusal of one byte that names the host",
            with_refusal(Some("/")),
        ),
        ("no refusal", with_refusal(None)),
    ] {
        for (kind, build) in [
            (
                "subscribe",
                &subscribe as &dyn Fn(Vec<AgentInstanceSummary>) -> ControlFrame,
            ),
            ("agent.instances", &listing),
        ] {
            let sized = |count: usize| frame_len(&shown(&build(vec![one.clone(); count])));
            let (none, single) = (sized(0), sized(1));
            let per_instance = single - none;
            let fit = (bound - none) / per_instance;
            let at_64 = sized(64);
            writeln!(
                table,
                "MEASURE | {kind}, {name} | empty answer {none} | one instance adds {per_instance} | 64 instances {at_64} | fit at the floor {fit}"
            )
            .expect("a string takes a write");
            assert!(
                sized(fit) <= bound && sized(fit + 1) > bound,
                "{kind}, {name}: {fit} instances fit and one more does not"
            );
            fitting.push((kind, name, fit, at_64));
        }
    }
    let resource = pending_resource();
    let resource_payload = payload_len(&resource);
    writeln!(
        table,
        "MEASURE | one pending resource at its widest {resource_payload} bytes; the worker's own bound {}",
        kr_worker::recovery::MAX_RECOVERY_RESOURCE_BYTES
    )
    .expect("a string takes a write");
    println!("{table}");

    assert!(
        resource_payload <= kr_worker::recovery::MAX_RECOVERY_RESOURCE_BYTES,
        "a pending resource is within the worker's bound, found {resource_payload}"
    );
    assert!(
        fitting
            .iter()
            .all(|(_, _, fit, at_64)| *fit >= 64 && *at_64 <= bound),
        "64 instances fit at the floor for every refusal: {fitting:?}"
    );
}

/// The sources of the two free text members of a closure, and the smallest entries the design's
/// member cap depends on.
///
/// `TerminatedProcess.name` is written by three producers, each from a fixed sentence: the
/// worker's (`ownership.rs`) writes "the session's root shell" or nothing, and the daemon's
/// (`service/close.rs`) writes "the session's worker", "the session's root shell" or "a process
/// this session owned". `root_signal` is the platform's own text for the signal that ended the
/// root shell: the worker takes it from the pty crate's exit status, which takes it from the
/// platform's `strsignal` (or "Signal {n}" when the platform has none), so its type carries no
/// bound and the platform sets its length. The case records the fixed names at their longest and
/// the sizes of the smallest entries of each list.
#[test]
fn the_sources_of_root_signal_and_a_terminated_process_name() {
    use kr_protocol::identity::{ProcessStartIdentity, ProcessStartSource};
    use kr_protocol::session::TerminatedProcess;

    let names = [
        "the session's root shell",
        "the session's worker",
        "a process this session owned",
    ];
    let longest_name = names.iter().map(|name| name.len()).max().expect("a name");
    let ended = |name: Option<&str>| TerminatedProcess {
        identity: ProcessStartIdentity::new(1, ProcessStartSource::LinuxProcStat, 1),
        name: name.map_or_else(Nullable::null, |name| Nullable::some(name.to_owned())),
        forced: false,
    };
    let smallest_terminated = payload_len(&ended(None));
    let widest_terminated = payload_len(&TerminatedProcess {
        identity: ProcessStartIdentity::new(
            u64::MAX,
            ProcessStartSource::WindowsProcessCreationTime,
            u64::MAX,
        ),
        name: Nullable::some("n".repeat(longest_name)),
        forced: true,
    });
    // The smallest survivor as a device is shown it: a one-byte kind and a one-byte detail that
    // names the host, which the door writes as the kind and its fixed sentence.
    let smallest_surviving = {
        let one = |detail: &str| {
            let mut record = closure(1, detail, 0, 0);
            record.surviving[0].kind = "k".to_owned();
            record
        };
        let (with, without) = (
            frame_len(&shown(&notice(SESSION_CLOSED_EVENT, &one("/")))),
            frame_len(&shown(&notice(SESSION_CLOSED_EVENT, &closure(0, "", 0, 0)))),
        );
        with - without
    };
    let by_budget = CLOSURE_LISTS_BOUND / smallest_terminated.min(smallest_surviving);
    println!(
        "MEASURE | the sources of closure text | TerminatedProcess.name: three fixed producers, longest {longest_name} bytes | root_signal: the platform's text, no bound in its type | smallest terminated entry {smallest_terminated} bytes, widest {widest_terminated} | smallest surviving entry as shown {smallest_surviving} | entries the budget of {CLOSURE_LISTS_BOUND} holds at the smaller {by_budget} against the member cap of 4,096"
    );

    assert!(
        longest_name < CLOSURE_TEXT_BYTES,
        "the fixed names are far under the cut of {CLOSURE_TEXT_BYTES} bytes, found {longest_name}"
    );
    assert!(
        by_budget < 4_096,
        "the byte budget binds before the member cap of 4,096, found room for {by_budget}"
    );
    assert!(
        smallest_terminated >= 40 && smallest_surviving >= 60,
        "the smallest entries are about 61 and 77 bytes, found {smallest_terminated} and {smallest_surviving}"
    );
}
