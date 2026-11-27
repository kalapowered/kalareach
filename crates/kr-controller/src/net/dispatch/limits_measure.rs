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
//! hand, because the constructors that will build them are not in the tree yet; they are models of
//! what those constructors will make, and their figures are the design's allowances checked against
//! the real encoding, which a constructor's own test holds once it exists.
//!
//! Every input that a figure calls the widest is built from the limit of its type, by that limit's
//! constant where the code has one ([`LINK_BYTES`], `kr_term::title::MAX_TITLE_BYTES`,
//! `kr_term::title::MAX_DEPTH`, `kr_protocol::ids::MAX_OPAQUE_ID_LEN`, `MAX_UPSTREAM_REQUEST_ID_LEN`,
//! `kr_protocol::error::MAX_ERROR_MESSAGE_LEN`, `kr_worker::service::MAX_OUTPUT_EVENT_BYTES`, the
//! page's own [`PAGE_BYTES`] and [`PAGE_ITEMS`]), and each case says which.
//!
//! The projection frames are samples, not maxima. The page is one that reaches its byte bound, and
//! the delta is the largest update that a search over linked cells finds; neither is shown to be
//! the largest the engine can make (a combining mark after each cell's character adds bytes without
//! adding a cell, for one). The header with every table at its bound
//! is a hand-built upper bound that the engine cannot produce: its saved cursors, styles and
//! keyboard values are at the largest value of their wire types, where the engine keeps smaller
//! ones. It bounds the size of a header; it is not a state of the engine.
//!
//! Every frame a case prints, and every message of the input stream and bare answer before hello,
//! has passed the transport's own encoder at the compiled bound, with its collection, item, depth
//! and string limits and not only its length.

use std::fmt::Write as _;
use std::hint::black_box;
use std::time::Instant;

use kr_cbor::{CanonicalValue, Limits, encoded_len, to_canonical_value, to_canonical_vec_within};
use kr_protocol::envelope::{ControlFrame, Notification, Outcome, ParamsValue, Response};
use kr_protocol::frame::FRAME_LENGTH_PREFIX_LEN;
use kr_protocol::ids::{
    ActorId, AgentBindingRevision, ApplicationInstanceId, AttachmentId, ConnectionId, DiagnosticId,
    EventSequence, EventType, GatewayConnectionId, InputLeaseEpoch, LaunchProfileId,
    PendingResourceId, PluginId, RequestId, SessionEpoch, SessionId, SourceGeneration, StreamId,
    UpstreamMethod, UpstreamRequestId,
};
use kr_protocol::projection::{
    AGENT_INSTANCE_EVENT, AGENT_RESOURCE_EVENT, AgentInstanceEvent, AgentInstanceList,
    AgentInstanceSummary, AgentResourceCause, AgentResourceContentClass, AgentResourceEvent,
    AgentResourceSnapshot, KittyKeyboardState, PROJECTION_DELTA_EVENT, PROJECTION_RESET_EVENT,
    PROJECTION_ROWS_EVENT, PROJECTION_SNAPSHOT_EVENT, PaletteOverride, ProjectedBuffer,
    ProjectedHyperlink, ProjectedKeyboard, ProjectedRow, ProjectionEvent, ProjectionReset,
    ProjectionResetReason, ProjectionSnapshot, SavedCursorState, SavedTitleEntry,
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
use kr_worker::output::{OutputDelivery, OutputHub, Presentation, RESYNC_MARKER_BYTES};
use kr_worker::snapshot::{Outgoing, Owed, PAGE_BYTES, PAGE_ITEMS, advance, install, wire};
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
/// The payload of the widest agent resource event the type allows. An exact pin: when the event's
/// type changes and this moves, read the design's row for the event and the floor it is held
/// against, then change the figure and the row together.
const AGENT_RESOURCE_PAYLOAD: usize = 2_147;
/// The complete frame of the widest agent resource event the type allows. An exact pin, as above.
const AGENT_RESOURCE_FRAME: usize = 2_247;
/// The payload of the smallest pending resource the types allow: the shortest kind, class, state and
/// durability, one-byte identifiers and nothing optional. An exact pin: when a type gains a shorter
/// variant and this moves, the counts of the subscribe case move with it, so change both.
const SMALL_RESOURCE_PAYLOAD: usize = 270;
/// What the design derives for the longest causal root: 20 digits, a colon and the longest upstream
/// identifier. An exact pin: when the identifier's bound moves, change this with the design.
const CAUSAL_ROOT_BOUND: usize = 1_559;
/// What the input stream's floor of 1,024 bytes leaves for a message, its length prefix out.
const INPUT_PAYLOAD_FLOOR: usize = 1_024 - FRAME_LENGTH_PREFIX_LEN;

/// What the worker's send queue charges for a closure notice today: nothing, by the `Closed` arm of
/// `OutputDelivery::len`. The sources case compares it with the charge of a real closed delivery that
/// a hub makes; when that case fails, the arm has changed and the design's reserve must change with
/// it.
const CLOSED_NOTICE_CHARGE: usize = 0;
/// The bound of a hyperlink, its target and its parameters together, as the engine's own budget
/// holds it.
const LINK_BYTES: usize = kr_term::budget::BudgetLimits::DEFAULT.link_bytes;
/// The depth of one buffer's keyboard flag stack. The engine keeps it in a private constant
/// (`KITTY_STACK_DEPTH` of its modes module) and cuts a longer stack to it.
const KEYBOARD_STACK_DEPTH: usize = 16;
/// The length of a path in a session summary, which no limit in the code holds: the figure is an
/// assumption, not a bound (a Windows path can be about 32,767 UTF-16 units).
const PATH_ASSUMED: usize = 4_096;

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
///
/// A candidate list is the type's own list of its variants (`ALL`) where the type has one. For
/// `ResyncReason`, `EditorBusyReason`, `HistoryGapCause`, `AgentResourceContentClass`,
/// `AgentResourceCause`, `CommandBypassReason` and `ClosureReason` the type has none, so those lists
/// are written by hand and a variant added later is not seen here.
fn widest<T: Serialize>(candidates: Vec<T>) -> T {
    candidates
        .into_iter()
        .max_by_key(payload_len)
        .expect("a candidate")
}

/// The candidate whose encoding is the shortest; the lists are the types' own where they have one.
fn narrowest<T: Serialize>(candidates: Vec<T>) -> T {
    candidates
        .into_iter()
        .min_by_key(payload_len)
        .expect("a candidate")
}

/// The limits the transport's encoder holds a frame to at the compiled bound: the message length and
/// the collection, item, depth and string limits.
fn encoder_limits() -> Limits {
    Limits::DEFAULT.with_max_message_len(COMPILED - FRAME_LENGTH_PREFIX_LEN)
}

/// Whether the transport's encoder writes `message`, a frame or a message of a stream of its own,
/// at the compiled bound.
fn encoder_accepts(message: &(impl Serialize + ?Sized)) -> bool {
    to_canonical_vec_within(message, &encoder_limits()).is_ok()
}

/// The size of the payload `frame` carries as the codec encodes it: a notification's payload, a
/// result, or an error.
fn payload_of(frame: &ControlFrame) -> usize {
    match frame {
        ControlFrame::Notification(notification) => encoded_len(notification.payload.as_value()),
        ControlFrame::Response(Response {
            outcome: Outcome::Ok(result),
            ..
        }) => encoded_len(result.as_value()),
        ControlFrame::Response(Response {
            outcome: Outcome::Error(error),
            ..
        }) => payload_len(error),
        _ => panic!("a case prints only notifications and responses"),
    }
}

/// One line of a case's table: the three figures of a frame, and where it came from. The payload is
/// the payload of the very frame printed, and the frame must pass the transport's encoder.
fn line(name: &str, frame: &ControlFrame, charge: Option<usize>) -> String {
    assert!(
        encoder_accepts(frame),
        "{name}: the transport's encoder refuses this frame at the compiled bound"
    );
    let payload = payload_of(frame);
    let complete = frame_len(frame);
    let charge = charge.map_or_else(|| "n/a".to_owned(), |charge| charge.to_string());
    format!(
        "MEASURE | {name} | payload {payload} | frame {complete} | frame with prefix {} | queue charge {charge}\n",
        complete + FRAME_LENGTH_PREFIX_LEN
    )
}

/// What one frame of a kind a worker sends is, with the queue charge the worker gives it.
struct Measured {
    /// The event type.
    name: &'static str,
    /// The notification as the worker builds it.
    frame: ControlFrame,
    /// The size of its payload.
    payload: usize,
    /// What the worker's send queue charges for it, where it charges anything.
    charge: Option<usize>,
    /// How many values its payload counts against the codec's item limit.
    items: usize,
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
            items: wire::measure(payload).map_or(0, |cost| cost.items),
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
        state: widest(FenceState::ALL.to_vec()),
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
    instance_with(Some("r".repeat(refusal)))
}

/// A live instance, one the session still holds: it has not ended, because the list of live
/// instances leaves an ended one out.
fn live_instance(refusal: Option<String>) -> AgentInstanceSummary {
    let mut one = instance_with(refusal);
    one.ended_at = Nullable::null();
    one
}

/// The refusal of an agent instance, as the door shows it in the announcement that carries `text`.
fn shown_refusal(text: &str) -> String {
    let ControlFrame::Notification(notification) = shown(&notice(
        AGENT_INSTANCE_EVENT,
        &instance_event_of(instance_with(Some(text.to_owned()))),
    )) else {
        unreachable!("a notice is a notification");
    };
    let CanonicalValue::Map(event) = notification.payload.as_value() else {
        panic!("an agent instance event is a map");
    };
    let Some(CanonicalValue::Map(instance)) = event.get("instance") else {
        panic!("the event holds its instance");
    };
    instance
        .get("refusal")
        .and_then(CanonicalValue::as_text)
        .expect("the instance holds its refusal as text")
        .to_owned()
}

/// The refusal text, of the 512 bytes the worker cuts it to, that the door shows longest, which is
/// the longest an error's message may be.
///
/// The door replaces each quotation in backticks that holds white space by the nine bytes of `a
/// command`, with no space inserted beside it (the reading that inserts one only decides whether a
/// name can be kept), and it holds a text to [`kr_protocol::error::MAX_ERROR_MESSAGE_LEN`]: a longer
/// one is replaced by a fixed sentence. A quotation of one space is three bytes and gains six, so
/// 512 bytes of them end at 1,022 bytes (85 of them) or over the limit (86); the 512 bytes reach
/// exactly 1,024 only with one quotation of a different width, and a quotation of five spaces gains
/// two. The search takes a count of one-space quotations, then one quotation of each width, then
/// plain text, and the door's own rewrite picks the longest.
fn longest_refusal_shown() -> String {
    const CUT: usize = 512;
    let mut best = "r".repeat(CUT);
    let mut best_len = shown_refusal(&best).len();
    for width in 0..=8 {
        let other = if width == 0 {
            String::new()
        } else {
            format!("`{}`", " ".repeat(width))
        };
        for count in 0..=(CUT - other.len()) / 3 {
            let text = format!(
                "{}{other}{}",
                "` `".repeat(count),
                "r".repeat(CUT - count * 3 - other.len())
            );
            let len = shown_refusal(&text).len();
            if len > best_len {
                best = text;
                best_len = len;
            }
        }
    }
    best
}

fn instance_with(refusal: Option<String>) -> AgentInstanceSummary {
    AgentInstanceSummary {
        application_instance_id: ApplicationInstanceId::new(kr_ipc::new_uuid()),
        plugin_id: Nullable::some(PluginId::new("p".repeat(256)).expect("a plugin identifier")),
        profile_id: Nullable::some(
            LaunchProfileId::new("l".repeat(256)).expect("a launch profile identifier"),
        ),
        mode: widest(kr_protocol::broker::IntegrationMode::ALL.to_vec()),
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
        refusal: refusal.map_or_else(Nullable::null, Nullable::some),
    }
}

fn instance_event(refusal: usize) -> AgentInstanceEvent {
    instance_event_of(instance(refusal))
}

fn instance_event_of(instance: AgentInstanceSummary) -> AgentInstanceEvent {
    AgentInstanceEvent {
        session_id: session_id(),
        sequence: U64::new(u64::MAX),
        instance,
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
        state: widest(kr_protocol::gateway::PendingState::ALL.to_vec()),
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
        kind: widest(PendingKind::ALL.to_vec()),
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
        // The type has no list of its variants, so a variant added later is not seen here.
        reason: [
            ClosureReason::CloseRequested,
            ClosureReason::RootExit,
            ClosureReason::RootSignal,
            ClosureReason::RootLaunchFailed,
            ClosureReason::WorkerCrash,
            ClosureReason::DesktopLost,
            ClosureReason::HostShutdown,
        ]
        .into_iter()
        .max_by_key(|reason| reason.as_str().len())
        .expect("a reason"),
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

/// A session summary as a worker answers it, with the two paths at [`PATH_ASSUMED`], a length no
/// limit in the code holds.
fn summary(closure: Option<ClosureRecord>) -> SessionSummary {
    SessionSummary {
        session_id: session_id(),
        session_epoch: SessionEpoch::V1,
        environment_id: kr_protocol::ids::EnvironmentId::new(kr_ipc::new_uuid()),
        display_number: DisplayNumber::new(u64::MAX),
        state: SessionState::Closed,
        shell_mode: ShellMode::NativeCompat,
        shell_path: "s".repeat(PATH_ASSUMED),
        cwd: "c".repeat(PATH_ASSUMED),
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
/// `cols` by `rows` and in pages of the compiled bound, with the send queue at the floor.
fn installed(cols: u32, rows: u32, script: &[u8]) -> Vec<Outgoing> {
    installed_within(cols, rows, script, QUEUE_FLOOR)
}

/// The same, held to `budget`: the send queue the subscriber has, as the worker passes it (`limit_of`
/// of the attachment). A queue that is small against the screen cuts the installation before the
/// page's own bound ends a page: the first page of the three rows of linked cells is 721,334 bytes
/// at the floor and 1,037,370 with room to spare.
fn installed_within(cols: u32, rows: u32, script: &[u8], budget: usize) -> Vec<Outgoing> {
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
        budget,
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
/// title at each depth, a colour for each palette index, a tab stop at each column and a link. With
/// `switching` the script also sets the three modes that switch to the alternate screen, which reset
/// the projection.
fn crowded_script(cols: u32, switching: bool) -> Vec<u8> {
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
        if !switching && matches!(mode, 47 | 1047 | 1049) {
            continue;
        }
        write!(script, "\x1b[?{mode}h").expect("a string takes a write");
    }
    script.push_str("\x1b[38;2;1;2;3;48;2;4;5;6;58;2;7;8;9;1;3;4m");
    write!(
        script,
        "\x1b]8;;h://{}\x07",
        "u".repeat(LINK_BYTES - 1 - "h://".len())
    )
    .expect("a string takes a write");
    script.into_bytes()
}

/// One cell with every colour set, so that it is a run of its own.
fn styled_cell(cell: u32) -> String {
    format!(
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
}

/// A script that writes `cells` cells, each with every colour set so that it is a run of its own.
fn styled_cells(cells: u32) -> Vec<u8> {
    (0..cells).map(styled_cell).collect::<String>().into_bytes()
}

/// The target of one of two hyperlinks, each the largest the engine admits: it holds the parameters, a
/// semicolon and the target to [`LINK_BYTES`] together, and these links have no parameters, so the
/// target is one byte short of it.
fn link_target(which: u32) -> String {
    let mut target = String::from("h://");
    target.push(if which.is_multiple_of(2) { 'a' } else { 'b' });
    target.push_str(&"u".repeat(LINK_BYTES - 1 - target.len()));
    target
}

/// A script that writes `cells` styled cells, each under the largest hyperlink the engine admits. The
/// link alternates from one cell to the next, so every cell is a run of its own, and a run carries
/// its own copy of its link.
fn linked_cells(cells: u32) -> Vec<u8> {
    let targets = [link_target(0), link_target(1)];
    (0..cells)
        .map(|cell| {
            format!(
                "\x1b]8;;{}\x07{}",
                targets[usize::from(cell % 2 == 1)],
                styled_cell(cell)
            )
        })
        .collect::<String>()
        .into_bytes()
}

/// A script that fills `rows` rows with `cols` linked cells each, every cell a run of its own. The
/// engine holds at most 262,144 cells, so a screen cannot fill a page with text; a row of runs that
/// each carry a link of the largest size fills a page to its byte bound instead.
fn packed_script(cols: u32, rows: u32) -> Vec<u8> {
    let mut script = Vec::new();
    for row in 0..rows {
        if row > 0 {
            script.extend_from_slice(b"\r\n");
        }
        script.extend_from_slice(&linked_cells(cols));
    }
    script
}

/// A delta the worker's own builder makes: the engine's delta of a screen that changed
/// every table a header carries and `cells` linked cells since a snapshot, passed through `advance`.
/// `None` when the change is too large for one update and the builder asks for a snapshot instead.
fn product_delta(cells: u32) -> Option<Outgoing> {
    use kr_term::budget::GridSize;
    use kr_term::engine::{Engine, EngineConfig};
    use kr_term::snapshot::{ActiveBuffer, Viewport};

    let cols = 2_048;
    let mut engine = Engine::new(EngineConfig {
        size: GridSize { cols, rows: 24 },
        ..EngineConfig::DEFAULT
    })
    .expect("an engine");
    let window = Viewport {
        top_row: 0,
        rows: 24,
        left_col: 0,
        cols,
    };
    let (base, _) = engine.snapshot(window, 0);
    // The changes without the three modes that switch screens: a switch resets the projection, drops
    // every base, and a client is then sent a snapshot and not a delta.
    engine.feed(&crowded_script(cols, false), 0);
    engine.feed(&linked_cells(cells), 0);
    let delta = engine
        .delta(base.output_cursor, base.projection_generation)
        .expect("the base is inside the window");
    match advance(
        &delta,
        ActiveBuffer::Primary,
        window,
        window.top_row,
        0,
        true,
        true,
        kr_worker::render::Scope::WholeScreen,
        Some(window),
    )
    .expect("an answer")
    {
        Owed::Update(update) => update
            .events
            .into_iter()
            .find(|outgoing| matches!(outgoing.event, ProjectionEvent::Delta(_))),
        _ => None,
    }
}

/// A large delta the builder sends as an update: the most linked cells a change can carry before the
/// builder asks for a snapshot. The cost of the message grows with the cells and stops at the row's
/// cut, so the search takes the largest count that is still an update. It is a sample and not the
/// largest delta: it stays under the page's byte bound, and a search over the cells alone does not
/// try other ways to add bytes to it.
fn delta_sample() -> Outgoing {
    let (mut low, mut high) = (1_u32, 2_048_u32);
    let mut widest = product_delta(low).expect("a delta of one cell and the tables is an update");
    while low < high {
        let middle = low + (high - low).div_ceil(2);
        if let Some(outgoing) = product_delta(middle) {
            widest = outgoing;
            low = middle;
        } else {
            high = middle - 1;
        }
    }
    widest
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

/// Every kind of notification a worker sends, with what the worker's queue charges. The kinds that
/// carry no projection are at the bounds of their types; the projection kinds (the header, the page
/// and the delta) are samples from a driven engine.
fn measured_events() -> Vec<Measured> {
    let events = installed(2_048, 24, &crowded_script(2_048, true));
    let header = header_of(&events);
    // The pages of a screen of three rows of linked cells, of which the sample is the largest: a run
    // carries its own copy of its link, so a page of runs that each hold a link of the largest size
    // reaches the byte bound of a page before the limit of its values. The first page of an
    // installation is the buffer that is not showing, and it is empty.
    let packed = installed_within(2_048, 3, &packed_script(2_048, 3), 4 * PAGE_BYTES);
    let page = widest(
        packed
            .iter()
            .filter_map(|outgoing| match &outgoing.event {
                ProjectionEvent::Rows(page) => Some(page.clone()),
                _ => None,
            })
            .collect(),
    );
    // The delta is one the worker's own builder makes, not one built by hand: a delta that carries
    // more than a page of values is a snapshot's work and is never sent.
    let delta_outgoing = delta_sample();
    let ProjectionEvent::Delta(delta) = &delta_outgoing.event else {
        unreachable!("the builder's update carries a delta");
    };
    let delta = delta.as_ref().clone();
    let output = OutputEvent {
        cursor: U64::new(u64::MAX),
        bytes: Bytes::new(vec![0xa5; kr_worker::service::MAX_OUTPUT_EVENT_BYTES]),
    };
    // The worker's own charge for the events of an installation is the figure to hold the
    // measurement to: the same payload measured here must be what the worker recorded.
    for outgoing in events
        .iter()
        .chain(&packed)
        .chain(std::iter::once(&delta_outgoing))
    {
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

/// That the guard and the transport's writer count one unit, and what the guard accepts.
///
/// The guard is the encoder's own test of a frame: its length and its collection, item, depth and
/// string limits. The assertions hold what does not depend on a clock: the guard's length is the
/// writer's, the compiled-bound frame is what it says, and a frame of 4,097 members passes today's
/// check and fails the encoder's own. What the test costs is the ignored case below.
#[test]
fn the_guards_unit_is_the_encoders() {
    let bound = COMPILED - FRAME_LENGTH_PREFIX_LEN;
    let limits = Limits::DEFAULT.with_max_message_len(bound);
    let widest_frame = output_frame_of(bound);
    let many = members_frame(4_096);
    let small = notice("session.resync", &marker());

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
    }

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
    // This holds today's fault: the check the door makes of a rewritten frame passes the 4,097
    // members that the writer refuses. The change that adds the encoder's own test to that check
    // turns this assertion red, and replaces it with one that the check refuses them.
    assert!(
        fits(&over, bound),
        "today's check passes the 4,097 members the writer refuses"
    );
}

/// What the guard's extra test costs a device-bound frame, by a clock. It asserts nothing, so it is
/// not part of an ordinary run: run it by name in a release build, with `--ignored --nocapture`.
///
/// Today's check runs only on a frame the door's rewrite changed; for an unchanged frame the door
/// makes no check at all, so the whole of the guard's test is new cost there. The line of each frame
/// gives the guard's test whole, the encoder's limit test alone, the transport's own encode of the
/// frame, and the first as a share of the last.
#[test]
#[ignore = "a timing run: run it by name in a release build with --ignored --nocapture"]
fn the_guards_cost_is_recorded() {
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
        let written = to_canonical_vec_within(frame, &limits).expect("the transport encodes it");

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
            "MEASURE | {name} | frame {} | today's check, on a frame the door changed {today} ns | guard's test whole, all new cost on an unchanged frame {guarded} ns | check_limits alone {check_alone} ns | the transport's encode {transport} ns | the guard is {}% of the encode | runs {runs}",
            written.len(),
            guarded * 100 / transport.max(1)
        )
        .expect("a string takes a write");
    }
    println!("{table}");
}

/// What a device is shown of the frames a worker cuts to its bound, against what the worker built.
///
/// The relay adds no envelope; the door's rewrite is the only growth, so the figure is the
/// difference between the two encodings. The output notification's envelope is the difference
/// between its frame and its bytes, which a cut by the receiver's bound has to leave room for.
#[test]
fn a_cut_output_and_projection_frame_grows_by_nothing_when_a_device_is_shown_it() {
    let events = measured_events();
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
        assert!(
            encoder_accepts(&shown(&measured.frame)),
            "{name}: the transport's encoder accepts the frame at the compiled bound"
        );
        writeln!(
            table,
            "MEASURE | {name} | payload {} | frame before {before} | frame after {after} | growth {growth} | queue charge {}",
            payload_of(&shown(&measured.frame)),
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
    let page_items = page.items;
    writeln!(
        table,
        "MEASURE | a page sample at the byte bound: payload {} | values {page_items} of PAGE_ITEMS {PAGE_ITEMS} | PAGE_BYTES {PAGE_BYTES} | frame {page_frame} | the compiled frame without its prefix {}",
        page.payload,
        COMPILED - FRAME_LENGTH_PREFIX_LEN
    )
    .expect("a string takes a write");
    println!("{table}");

    // A full page, the most the worker builds, is whole in the compiled frame once the notification
    // around it is added. A run carries its own copy of its link, so a page of runs that each hold a
    // link of the largest size is cut by the page's byte bound within a few runs of it.
    assert!(
        page.payload <= PAGE_BYTES,
        "a page is at most {PAGE_BYTES} bytes of payload, found {}",
        page.payload
    );
    assert!(
        page.payload + 4 * LINK_BYTES > PAGE_BYTES,
        "a page of linked runs reaches the page's byte bound, found {} of {PAGE_BYTES}",
        page.payload
    );
    assert!(
        page_frame <= COMPILED - FRAME_LENGTH_PREFIX_LEN,
        "a page sample at the byte bound is whole in the compiled frame, found {page_frame}"
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
        table.push_str(&line(record.name, &shown(&record.frame), record.charge));
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
    // The same reserve with every record at its complete frame and none at a charge. The marker's
    // queue charge is a constant that is not its frame, so the design's formula above mixes units.
    let frames_only = 2 * (marker_frame + busy_frame + detach_frame);
    let usable = QUEUE_FLOOR
        .checked_sub(CLOSURE_ROOM + reserve_small)
        .expect("the reserve is smaller than the queue the floor allows");
    let margin = signed_difference(usable, PAGE_BYTES);
    writeln!(
        table,
        "MEASURE | RESERVE_SMALL, detach with every member the type has: by payloads {by_payload} | by frames with the marker at its charge of {RESYNC_MARKER_BYTES} {by_frame} | by complete frames only {frames_only} | taken {reserve_small} | against the allowance {RESERVE_SMALL_BOUND}: {} | against the trigger {STOP_LINE}: {}",
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
    assert!(
        frames_only <= STOP_LINE,
        "the three small records, each at its complete frame, cost at most the trigger of {STOP_LINE}, found {frames_only}"
    );
}

/// The projection header and row sizes: the header of a real screen driven to fill every table a
/// header carries, and a hand-built upper bound with each table stuffed to its bound.
///
/// The stuffed header is a hand-built upper bound that the engine cannot produce: its saved
/// cursors, its styles and its keyboard values are at `u64::MAX` where the engine keeps smaller
/// ones. It is built from the limits of the engine's tables: ten title pairs of
/// `kr_term::title::MAX_TITLE_BYTES` and `MAX_DEPTH`, a tab stop in each of 2,048 columns, a
/// palette override for each of 256 indices, three hyperlinks of the largest size the engine admits,
/// [`LINK_BYTES`] less the semicolon that parts its parameters from its target (the open link and
/// the link of each buffer's saved cursor), a saved cursor for each buffer, and a flag stack of
/// [`KEYBOARD_STACK_DEPTH`] for each buffer's keyboard.
#[test]
fn the_projection_header_and_row_sizes() {
    let cols = 2_048;
    let events = installed(cols, 24, &crowded_script(cols, true));
    let driven = header_of(&events);
    let link = ProjectedHyperlink {
        uri: "u".repeat(LINK_BYTES - 1),
        params: String::new(),
    };
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
    stuffed.hyperlink = Nullable::some(link.clone());
    let saved = |buffer: ProjectedBuffer| SavedCursorState {
        buffer,
        column: U64::new(u64::MAX),
        row: U64::new(u64::MAX),
        pending_wrap: true,
        rendition: stuffed.rendition,
        charsets: stuffed.charsets.clone(),
        origin_mode: true,
        style: U64::new(u64::MAX),
        hyperlink: Nullable::some(link.clone()),
    };
    stuffed.saved_cursors = vec![
        saved(ProjectedBuffer::Primary),
        saved(ProjectedBuffer::Alternate),
    ];
    let flags = KittyKeyboardState {
        flags: Nullable::some(U64::new(u64::MAX)),
        stack: vec![U64::new(u64::MAX); KEYBOARD_STACK_DEPTH],
    };
    stuffed.keyboard = ProjectedKeyboard {
        modify_other_keys: U64::new(u64::MAX),
        primary: flags.clone(),
        alternate: flags,
    };
    let mut bare = stuffed.clone();
    bare.title_stack = Vec::new();
    bare.tab_stops = Vec::new();
    bare.palette.overrides = Vec::new();
    bare.hyperlink = Nullable::null();
    bare.saved_cursors = Vec::new();

    let mut table = String::from("MEASURE | the projection header\n");
    for (name, header) in [
        ("driven by a real screen", &driven),
        (
            "hand-built upper bound, every table at its bound, not an engine state",
            &stuffed,
        ),
        ("modes, keys and framing alone", &bare),
    ] {
        let frame = notice(PROJECTION_SNAPSHOT_EVENT, header);
        let charge = wire::measure(header)
            .expect("the codec represents a projection header")
            .bytes;
        table.push_str(&line(name, &shown(&frame), Some(charge)));
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
        "MEASURE | the hand-built upper-bound header (not an engine state): frame {stuffed_frame} | against the floor {FLOOR}: {} | against the transport's floor {TRANSPORT_FLOOR}: {}",
        signed_difference(stuffed_frame + FRAME_LENGTH_PREFIX_LEN, FLOOR),
        signed_difference(stuffed_frame + FRAME_LENGTH_PREFIX_LEN, TRANSPORT_FLOOR)
    )
    .expect("a string takes a write");
    assert_eq!(
        stuffed.saved_cursors.len(),
        2,
        "each buffer saves a cursor, and the header carries both"
    );
    assert!(
        stuffed.saved_cursors.iter().all(|cursor| cursor
            .hyperlink
            .0
            .as_ref()
            .is_some_and(|link| link.uri.len() + link.params.len() == LINK_BYTES - 1)),
        "each saved cursor carries the largest link the engine admits, {} bytes",
        LINK_BYTES - 1
    );
    assert!(
        stuffed.keyboard.primary.stack.len() == KEYBOARD_STACK_DEPTH
            && stuffed.keyboard.alternate.stack.len() == KEYBOARD_STACK_DEPTH,
        "each buffer's keyboard stack is at its depth of {KEYBOARD_STACK_DEPTH}"
    );
    assert!(
        stuffed_frame + FRAME_LENGTH_PREFIX_LEN <= FLOOR,
        "the hand-built upper-bound header is whole at the floor of {FLOOR}, found {stuffed_frame}"
    );
    assert!(
        payload_len(&stuffed) >= payload_len(&driven),
        "the stuffed header is the wider one"
    );

    // A row of two thousand and forty-eight cells, each its own run: the costs of a run are those of
    // styled ASCII cells, not of every rendition and text.
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
    // A run under a link of the largest size: each run carries its own copy of the link.
    let (few, many) = (first_row(&linked_cells(20)), first_row(&linked_cells(120)));
    let linked_run_items = (wire::row_cost(&many).items - wire::row_cost(&few).items) / 100;
    let linked_run_bytes = (wire::row_cost(&many).bytes - wire::row_cost(&few).bytes) / 100;
    let wide = first_row(&styled(cols));
    let plain_wide = first_row(b"xxxxxxxxxx");
    writeln!(
        table,
        "MEASURE | a run with default colours costs {default_run_items} values and {default_run_bytes} bytes; a run with every colour set costs {styled_run_items} values and {styled_run_bytes} bytes; a run with every colour set under a link of {LINK_BYTES} bytes costs {linked_run_items} values and {linked_run_bytes} bytes"
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
        linked_run_bytes > LINK_BYTES,
        "a run carries its own copy of its link, so it costs more than the link's {LINK_BYTES} bytes, found {linked_run_bytes}"
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
    for (name, frame) in [
        ("pair.redeem, a challenge", answer(&challenge)),
        ("pair.redeem, locked", answer(&locked)),
        ("pair.finish", answer(&finished)),
        ("pair.status, awaiting approval", answer(&status)),
    ] {
        widest_answer = widest_answer.max(frame_len(&frame));
        table.push_str(&line(name, &frame, None));
    }
    // Before a peer has said hello the door writes a bare `Response`, not a control frame around
    // one, which is a few bytes smaller; the widest answer then is an error answer.
    let bare = |outcome: Outcome| Response {
        request_id: RequestId::new(u64::MAX),
        outcome,
    };
    let bare_challenge = bare(Outcome::Ok(
        ParamsValue::from_typed(&challenge).expect("encodes"),
    ));
    let bare_refusal = bare(Outcome::Error(widest_error.clone()));
    assert!(
        encoder_accepts(&bare_challenge) && encoder_accepts(&bare_refusal),
        "the transport's encoder refuses a bare answer before hello at the compiled bound"
    );
    let bare_len =
        |response: &Response| encoded_len(&to_canonical_value(response).expect("a response"));
    let (bare_challenge, bare_refusal) = (bare_len(&bare_challenge), bare_len(&bare_refusal));
    writeln!(
        table,
        "MEASURE | before hello, a bare Response: a challenge {bare_challenge} | the widest error answer {bare_refusal}"
    )
    .expect("a string takes a write");
    let refusal_frame = frame_len(&refusal);
    table.push_str(&line(
        "the connection's refusal, as the door writes it",
        &refusal,
        None,
    ));
    table.push_str(&line(
        "a refusal by its type, with a diagnostic identifier and the fence flag",
        &typed_refusal,
        None,
    ));
    let epoch = InputLeaseEpoch::new(u64::MAX);
    let sequence = kr_protocol::ids::InputSequence::new(u64::MAX);
    let refused = kr_protocol::input::InputAck::Refused {
        epoch,
        sequence,
        accepted_through: Nullable::some(sequence),
        // The widest code with the longest message and a diagnostic identifier; the door removes the
        // fence flag before a device is shown the error, so it is not set.
        error: widest_error
            .clone()
            .with_diagnostic_id(DiagnosticId::new("d".repeat(256)).expect("a diagnostic")),
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
    // An acknowledgement is not a control frame, but the same encoder limits hold it.
    assert!(
        encoder_accepts(&refused) && small.iter().all(encoder_accepts),
        "the transport's encoder refuses an acknowledgement at the compiled bound"
    );
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
    assert!(
        bare_challenge.max(bare_refusal) < TRANSPORT_FLOOR,
        "the widest answer before hello is under the transport's floor of {TRANSPORT_FLOOR}, found {}",
        bare_challenge.max(bare_refusal)
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
    // The worker holds the refusal at its cut of 512 bytes; the door can show one up to the longest
    // an error's message may be, and the search reaches it.
    let longest_text = longest_refusal_shown();
    assert_eq!(longest_text.len(), 512, "the worker's cut of a refusal");
    assert_eq!(
        shown_refusal(&longest_text).len(),
        kr_protocol::error::MAX_ERROR_MESSAGE_LEN,
        "the door shows a refusal of 512 bytes at the longest an error's message may be"
    );
    let instance_longest = instance_event_of(instance_with(Some(longest_text)));
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
        (
            "agent instance, the refusal of 512 bytes that the door shows longest",
            &instance_longest,
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
    let longest_frame = frame_len(&shown(&notice(AGENT_INSTANCE_EVENT, &instance_longest)));
    assert!(
        longest_frame < AGENT_INSTANCE_BOUND,
        "an agent instance event with the refusal the door shows longest is under {AGENT_INSTANCE_BOUND} bytes, found {longest_frame}"
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
    // The one entry that carries a note, in the same form, so that the lists' bound is the budget
    // and that entry and not a figure of this case's own.
    let note_entry = {
        let with = frame_len(&shown(&notice(
            SESSION_CLOSED_EVENT,
            &closure(0, "/", CLOSURE_TEXT_BYTES / 2, 0),
        )));
        let without = frame_len(&shown(&notice(
            SESSION_CLOSED_EVENT,
            &closure(0, "/", 0, 0),
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
        &notification,
        Some(CLOSED_NOTICE_CHARGE),
    ));
    table.push_str(&line(
        "session.closed, as a device is shown it",
        &shown(&notification),
        Some(CLOSED_NOTICE_CHARGE),
    ));
    table.push_str(&line(
        "session.close answer, the record once",
        &shown(&once),
        None,
    ));
    table.push_str(&line(
        "session.close answer, the record twice (as the worker builds it today)",
        &shown(&twice),
        None,
    ));
    writeln!(
        table,
        "MEASURE | {survivors} survivors of {device_entry} bytes each and a note's entry of {note_entry} | lists as shown {lists} | members outside the lists with root_signal at {CLOSURE_TEXT_BYTES}: {fixed} | notification envelope {envelope}"
    )
    .expect("a string takes a write");
    println!("{table}");

    assert!(
        lists <= CLOSURE_LISTS_BOUND + note_entry,
        "the lists as a device is shown them are within the budget and the note's entry of {note_entry} bytes, found {lists}"
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
        payload_of(&shown(&notification)) > payload_len(&record),
        "the payload a device is shown is the rewritten record's, wider than the record the worker holds"
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
        &shown(&marker_frame),
        Some(OutputDelivery::Resync(marker()).len()),
    ));
    table.push_str(&line(
        "the reduced record",
        &shown(&reduced_frame),
        Some(CLOSED_NOTICE_CHARGE),
    ));
    table.push_str(&line(
        "the reduced record with a root_signal of 4,096 bytes",
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

/// A pending resource at its smallest: a one-byte upstream identifier and method, nothing set that
/// is optional, and the shortest of the kinds, classes, states and durabilities the types allow.
fn small_resource() -> kr_protocol::gateway::PendingResource {
    use kr_protocol::gateway::{
        DownstreamRequestId, NativeClassification, NativeMethodClass, PendingKind, PendingState,
    };
    let mut resource = pending_resource();
    resource.request = DownstreamRequestId::new(
        GatewayConnectionId::new(1),
        UpstreamRequestId::new("1".to_owned()).expect("an upstream identifier"),
    );
    resource.kind = narrowest(PendingKind::ALL.to_vec());
    resource.method = UpstreamMethod::new("m".to_owned()).expect("a method");
    resource.classification = NativeClassification {
        class: narrowest(NativeMethodClass::ALL.to_vec()),
        declared: true,
    };
    resource.source_generation = SourceGeneration::new(1);
    resource.state = narrowest(PendingState::ALL.to_vec());
    // `Durability` has no list of its variants, so the candidates are written by hand.
    resource.durability = narrowest(vec![Durability::Durable, Durability::Volatile]);
    resource.deadline_ms = Nullable::null();
    resource.recorded_at = TimestampMs::new(1);
    resource
}

/// `count` copies of `template`, with identifiers in the order a recovery copy is taken in.
fn resources_of(
    template: &kr_protocol::gateway::PendingResource,
    count: usize,
) -> Vec<kr_protocol::gateway::PendingResource> {
    (1..=count)
        .map(|index| {
            let mut bytes = [0_u8; 16];
            bytes[8..].copy_from_slice(&u64::try_from(index).expect("a count").to_be_bytes());
            let mut resource = template.clone();
            resource.resource_id =
                PendingResourceId::new(kr_protocol::scalars::Uuid::from_bytes(bytes));
            resource
        })
        .collect()
}

/// What the worker measures a recovery answer with before a resource is in it: no resource, and
/// every counter and the continuation at its widest. A copy of the worker's private constructor of
/// the same page.
fn no_resources() -> AgentResourceSnapshot {
    AgentResourceSnapshot {
        snapshot_id: U64::new(u64::MAX),
        stream_generation: U64::new(u64::MAX),
        cursor: U64::new(u64::MAX),
        resources: Vec::new(),
        continue_after: Nullable::some(PendingResourceId::new(
            kr_protocol::scalars::Uuid::from_bytes([0xff; 16]),
        )),
    }
}

/// The first page of a recovery, cut by the worker's own routine to `bytes` of resource.
fn cut_page(
    resources: Vec<kr_protocol::gateway::PendingResource>,
    bytes: usize,
) -> kr_worker::recovery::RecoveryPage {
    use kr_transport::clock::{ContinuousClock, ManualClock};
    kr_worker::recovery::RecoveryCopies::new().begin(
        ConnectionId::new(kr_protocol::scalars::Uuid::from_bytes([1; 16])),
        kr_worker::broker::ReplayCursor {
            generation: u64::MAX,
            sequence: u64::MAX,
        },
        resources,
        ManualClock::new().now(),
        kr_worker::recovery::PageBounds {
            resources: kr_worker::broker::MAX_SNAPSHOT_RESOURCES,
            bytes,
        },
        &|| true,
    )
}

/// How many live instances an answer carries at the floor before the door's frame is over, with the
/// page cut as the worker cuts it, and where the worker itself refuses the peer. Every count from
/// none to the worker's refusal is tried.
struct Fit {
    /// The count before the first at which the door's frame is over the bound: every count to it
    /// fits, and it is not the greatest count that fits. A page is cut to whole resources, so a
    /// larger count can fit again by the room a cut leaves.
    fit: usize,
    /// The most instances for which the worker still answers: one more and it refuses the peer
    /// because its frame cannot hold the answer and one resource.
    worker_limit: usize,
    /// The resources the page carries at `fit`.
    carried: usize,
    /// The frame at `fit`, and at the first count over the bound (0 where there is none).
    frames: (usize, usize),
    /// The counts above the first count over the bound, up to the worker's limit, at which the
    /// door's frame fits again.
    fits_again: Vec<usize>,
    /// The frames whose sizes are printed: the one at `fit` and the one at the first count over.
    printed: Vec<ControlFrame>,
}

/// The largest count in `0..=4_096` for which `holds` is true, taking it to be true up to a count
/// and false beyond (the worker's refusal of a peer is: a longer list only makes the answer larger).
fn largest_count(holds: impl Fn(usize) -> bool) -> usize {
    let (mut low, mut high) = (0_usize, 4_096_usize);
    while low < high {
        let middle = low + (high - low).div_ceil(2);
        if holds(middle) {
            low = middle;
        } else {
            high = middle - 1;
        }
    }
    low
}

/// The answer a worker builds for `count` live instances of `one` and the resources `resources`,
/// with the page cut to what is left of the frame the peer declared at the floor, the way the
/// worker works it out: the frame less the stream header, less the answer measured with no resource
/// in it. `None` where the worker refuses the peer.
fn worker_answer<T: Serialize>(
    make: &dyn Fn(AgentResourceSnapshot, AgentInstanceList) -> T,
    one: &AgentInstanceSummary,
    resources: &[kr_protocol::gateway::PendingResource],
    count: usize,
) -> Option<(ControlFrame, usize)> {
    let frame = FLOOR - kr_protocol::limits::MAX_STREAM_HEADER_LEN;
    let list = || AgentInstanceList {
        sequence: U64::new(u64::MAX),
        instances: vec![one.clone(); count],
    };
    // A count the codec cannot represent is measured as unbounded, as the worker measures it, and the
    // worker refuses the peer.
    let empty = wire::measure(&make(no_resources(), list()))?.bytes;
    if frame < empty.saturating_add(kr_worker::recovery::MAX_RECOVERY_RESOURCE_BYTES) {
        return None;
    }
    let page = cut_page(resources.to_vec(), frame - empty);
    let carried = page.resources.len();
    let result = make(
        AgentResourceSnapshot {
            snapshot_id: U64::new(page.snapshot),
            stream_generation: U64::new(page.cursor.generation),
            cursor: U64::new(page.cursor.sequence),
            resources: page.resources,
            continue_after: Nullable(page.continue_after),
        },
        list(),
    );
    let measured = wire::measure(&result).map_or(usize::MAX, |cost| cost.bytes);
    (measured <= frame).then(|| (answer(&result), carried))
}

fn fit_at_the_floor<T: Serialize>(
    make: &dyn Fn(AgentResourceSnapshot, AgentInstanceList) -> T,
    one: &AgentInstanceSummary,
    resources: &[kr_protocol::gateway::PendingResource],
) -> Fit {
    let bound = FLOOR - FRAME_LENGTH_PREFIX_LEN;
    // The answer as a device is shown it, and the pages it carries, at a count the worker answers.
    let shown_answer = |count: usize| {
        worker_answer(make, one, resources, count).map(|(frame, carried)| (shown(&frame), carried))
    };
    let worker_limit = largest_count(|count| worker_answer(make, one, resources, count).is_some());
    // The frame does not grow with the count alone, so every count is tried and none is skipped.
    let frames: Vec<Option<usize>> = (0..=worker_limit)
        .map(|count| shown_answer(count).map(|(frame, _)| frame_len(&frame)))
        .collect();
    let is_over = |count: usize| frames[count].is_some_and(|frame| frame > bound);
    let first_over = (0..=worker_limit).find(|count| is_over(*count));
    let fit = first_over.map_or(worker_limit, |count| count.saturating_sub(1));
    let fits_again = first_over.map_or_else(Vec::new, |count| {
        (count + 1..=worker_limit)
            .filter(|above| frames[*above].is_some_and(|frame| frame <= bound))
            .collect()
    });
    let (at_the_fit, carried) = shown_answer(fit).expect("the worker answers at the fit");
    let over_frame = first_over.map(|count| {
        shown_answer(count)
            .expect("the worker answers at the first count over")
            .0
    });
    Fit {
        fit,
        worker_limit,
        carried,
        frames: (
            frame_len(&at_the_fit),
            over_frame.as_ref().map_or(0, frame_len),
        ),
        fits_again,
        printed: std::iter::once(at_the_fit).chain(over_frame).collect(),
    }
}

/// The subscribe and agent-instances answers as a device receives them, and where they stop fitting.
///
/// Nothing caps the live instances a session has. The answer carries the instances, and beside them
/// a page of the agent resources that the worker cuts to what is left of the frame the peer
/// declared, measured with each refusal at the length the worker holds. The door then shows a
/// refusal at its own length, which can be longer, and checks the frame against the bound at the
/// floor. The case builds both answers with the page cut by the worker's own routine
/// (`RecoveryCopies::begin` with the bounds the service works out), for three forms of refusal and
/// for the widest and the smallest resources, with live instances. Every count of instances from none
/// to the worker's own refusal is tried, and the case records the count to which every count fits,
/// and the counts above the first one over that fit again.
#[test]
fn the_subscribe_and_agent_instances_answers_as_a_device_receives_them() {
    let subscribe = |agent_resources: AgentResourceSnapshot, agent_instances: AgentInstanceList| {
        EventsSubscribeResult {
            stream_id: StreamId::new(kr_worker::service::OUTPUT_STREAM).expect("a stream"),
            from_cursor: U64::new(u64::MAX),
            oldest_retained_cursor: U64::new(u64::MAX),
            gap: Nullable::some(gap()),
            agent_resources,
            agent_instances,
        }
    };
    let listing = |agent_resources: AgentResourceSnapshot, agent_instances: AgentInstanceList| {
        AgentInstancesResult {
            agent_resources,
            agent_instances,
        }
    };
    // Enough resources to cut a page at the worker's count limit or at its bytes.
    let supply = kr_worker::broker::MAX_SNAPSHOT_RESOURCES + 44;
    let widest_resources = resources_of(&pending_resource(), supply);
    let smallest_resources = resources_of(&small_resource(), supply);
    let longest_text = longest_refusal_shown();
    assert_eq!(
        shown_refusal(&longest_text).len(),
        kr_protocol::error::MAX_ERROR_MESSAGE_LEN,
        "the door shows the refusal of the cap at the longest an error's message may be"
    );
    let forms = [
        (
            "refusal of the cap, as the door shows it longest",
            Some(longest_text),
        ),
        ("short refusal that names the host", Some("/".to_owned())),
        ("no refusal", None),
    ];
    let mut table = String::from("MEASURE | the subscribe and agent.instances answers\n");
    let mut at_the_cap = Vec::new();
    let mut host_naming = Vec::new();
    for (form, refusal) in &forms {
        let one = live_instance(refusal.clone());
        for (resources_name, resources) in [
            ("widest resources", &widest_resources),
            ("smallest resources", &smallest_resources),
        ] {
            for (kind, found) in [
                ("subscribe", fit_at_the_floor(&subscribe, &one, resources)),
                (
                    "agent.instances",
                    fit_at_the_floor(&listing, &one, resources),
                ),
            ] {
                writeln!(
                    table,
                    "MEASURE | {kind}, {form}, {resources_name} | every count to {} fits at the floor | the worker refuses the peer from {} instances | page carries {} resources at that count | frame at that count {} | frame at the first count over {} | counts above the first count over that fit again, up to the worker's refusal: {:?}",
                    found.fit,
                    found.worker_limit + 1,
                    found.carried,
                    found.frames.0,
                    found.frames.1,
                    found.fits_again
                )
                .expect("a string takes a write");
                assert!(
                    found.printed.iter().all(encoder_accepts),
                    "the transport's encoder refuses a printed frame: {kind}, {form}, {resources_name}"
                );
                if refusal.as_ref().is_some_and(|text| text.len() == 512)
                    && resources_name == "widest resources"
                {
                    at_the_cap.push((kind, found.fit, found.carried));
                }
                if refusal.as_deref() == Some("/") && resources_name == "widest resources" {
                    host_naming.push((kind, found.fit, found.fits_again));
                }
            }
        }
    }
    let resource = pending_resource();
    let resource_payload = payload_len(&resource);
    let small_payload = payload_len(&small_resource());
    writeln!(
        table,
        "MEASURE | one pending resource at its widest {resource_payload} bytes, at its smallest {small_payload} bytes; the worker's own bound {}",
        kr_worker::recovery::MAX_RECOVERY_RESOURCE_BYTES
    )
    .expect("a string takes a write");
    println!("{table}");

    assert_eq!(
        small_payload, SMALL_RESOURCE_PAYLOAD,
        "the smallest pending resource is {SMALL_RESOURCE_PAYLOAD} bytes of payload"
    );

    assert!(
        resource_payload <= kr_worker::recovery::MAX_RECOVERY_RESOURCE_BYTES,
        "a pending resource is within the worker's bound, found {resource_payload}"
    );
    // The page was cut by the worker's routine and not by running out of resources.
    assert!(
        at_the_cap
            .iter()
            .all(|(_, _, carried)| *carried < supply && *carried > 0),
        "the page is cut by the bytes of the frame: {at_the_cap:?}"
    );
    // This holds today's fault: the worker cuts the page against each refusal at the length it
    // holds, and the door then shows a longer one, so with a page that fills the frame fewer than 64
    // instances fit at the floor. The change that makes the worker charge each refusal at the length
    // the door shows turns this assertion red, and replaces it with the figure that change gives.
    assert!(
        at_the_cap.iter().all(|(_, fit, _)| *fit < 64),
        "fewer than 64 instances fit at the floor beside a full page of resources with refusals of the cap: {at_the_cap:?}"
    );
    // The page is cut to whole resources, so the frame does not grow with the count alone: some
    // counts above the first count over fit again, and "every count to N fits" is not "N is the
    // most that fits". Beside a refusal that names the host, the room the cut leaves decides.
    assert!(
        host_naming
            .iter()
            .all(|(_, fit, again)| again.first().is_some_and(|first| *first > *fit + 1)),
        "counts above the first count over fit again beside a short refusal that names the host: {host_naming:?}"
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

    // The three names are copies of the sentences the worker's ownership module and the daemon's
    // close path write inline; neither has a constant to compare with. When a producer's sentence
    // changes or a producer is added, add it here: this case measures only the sentences it lists.
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

    // The queue's charge for a closure notice, read from a real closed delivery that a hub makes: a
    // hub that has closed delivers the closure to an attachment that subscribes afterwards.
    let mut hub = OutputHub::new();
    let attachment = AttachmentId::new(kr_ipc::new_uuid());
    hub.close(&closure(1, "/", 0, 0), [attachment]);
    let mut stream = hub.subscribe(attachment, QUEUE_FLOOR, Presentation::Direct);
    let delivery = stream
        .try_recv()
        .expect("a hub that has closed delivers the closure");
    assert!(
        matches!(delivery, OutputDelivery::Closed(_)),
        "the delivery is the closure"
    );
    assert_eq!(
        delivery.len(),
        CLOSED_NOTICE_CHARGE,
        "the queue charges a closure notice {CLOSED_NOTICE_CHARGE} bytes"
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
