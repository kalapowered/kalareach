//! What a worker serves: every method it answers, and every notification it sends.
//!
//! A control daemon, `kr`, `kr-client` and a paired device talk to a session's worker, and a worker
//! outlives the update of the host that started it, so the types of these exchanges are what a
//! level of the protocol fixes: a level is one surface. The generated schema lists the types and
//! none of this: which of them a worker takes as the parameters of a method, which it answers
//! with, and under which name it sends an event. This module is that record, in two tables, and the
//! worker is held to it.
//!
//! * [`served_methods`] has a row for each method the worker serves, with the parameters it reads
//!   and the result it writes. The worker refuses a method that has no row before it reads a
//!   parameter ([`serves`]), so a method added to the worker needs its row.
//! * Each notification is a typed [`WorkerEvent`], and the worker writes one only through such a
//!   value (the worker's `notification`), so an event has a row because it can be sent at all, and
//!   its payload is the type the row says.
//!
//! [`document`] renders both tables, with the roots they reach, as `crates/kr-protocol/
//! worker-surface.json`. `kr-protocol-gen` writes it and its `--check` holds it to this source, and
//! the in-level check compares it between releases, because a renamed event or a method the worker
//! stopped serving changes no definition of the schema.
//!
//! The shell bridge's `root.*` methods, the hook's registration and its private exchange are not
//! here: their peers are the shell package and the forwarder a session launched, which have
//! releases of their own.

use std::collections::BTreeMap;
use std::marker::PhantomData;
use std::sync::LazyLock;

use schemars::JsonSchema;

use crate::agent::{
    AgentApprovalInspectParams, AgentApprovalInspectResult, AgentApprovalRespondParams,
    AgentApprovalRespondResult, AgentCancelParams, AgentCapabilitiesParams,
    AgentCapabilitiesResult, AgentCommandsParams, AgentCommandsResult, AgentMutationResult,
    AgentPromptParams, AgentSnapshotParams, AgentSnapshotResult, AgentSteerParams,
    PluginActionInvokeParams, PluginActionInvokeResult,
};
use crate::attachment::{
    AttachmentConfigureParams, AttachmentViewportParams, AttachmentViewportResult, GeometryResult,
    SessionAttachParams, SessionAttachResult, SessionDetachParams, SessionDetachResult,
    TerminalGeometryTransferParams, TerminalResizeParams,
};
use crate::identity::{BridgeFrame, BridgeHello, BridgeHelloAck};
use crate::input::{
    InputAcquireParams, InputAcquireResult, InputInterruptParams, InputLeaseResult,
    InputReleaseParams, InputWriteParams, InputWriteResult,
};
use crate::method::Method;
use crate::projection::{
    AGENT_INSTANCE_EVENT, AGENT_RESOURCE_EVENT, AgentInstanceEvent, AgentResourceEvent,
    PROJECTION_DELTA_EVENT, PROJECTION_RESET_EVENT, PROJECTION_ROWS_EVENT,
    PROJECTION_SNAPSHOT_EVENT, ProjectionDelta, ProjectionReset, ProjectionRowPage,
    ProjectionSnapshot,
};
use crate::question::{
    AlertCreateParams, AlertCreateResult, QuestionAnswerParams, QuestionCancelOwnParams,
    QuestionCancelParams, QuestionCreateParams, QuestionCreateResult, QuestionOwnResult,
    QuestionReadOwnParams, QuestionReadParams, QuestionReadResult, QuestionResolveResult,
};
use crate::receipt::{ActionCancelParams, ActionCancelResult, ActionReadParams, ActionReadResult};
use crate::recovery::{
    AgentInstancesParams, AgentInstancesResult, EventsSnapshotParams, EventsSnapshotResult,
    EventsSubscribeParams, EventsSubscribeResult, HistoryGap, HistoryPageParams, HistoryPageResult,
    OutputEvent, ResyncRequired,
};
use crate::root::{EDITOR_BUSY_EVENT, EditorBusyEvent, ShellLaunchParams, ShellLaunchResult};
use crate::session::{
    ClosureRecord, SESSION_CLOSED_EVENT, SessionCloseParams, SessionCloseResult, SessionReadParams,
    SessionReadResult,
};
use crate::sharing::{SessionScreenPreviewParams, SessionScreenPreviewResult};

/// A notification a worker sends, and the type of its payload.
///
/// There is no way to make one outside the `worker_events!` list below, and the worker writes a
/// notification only from one, so the set of events a worker sends is the set of rows here.
pub struct WorkerEvent<T: ?Sized> {
    name: &'static str,
    payload: PhantomData<fn(&T)>,
}

impl<T: ?Sized> WorkerEvent<T> {
    const fn named(name: &'static str) -> Self {
        Self {
            name,
            payload: PhantomData,
        }
    }

    /// The event type the notification is sent under.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        self.name
    }
}

/// Makes each notification's constant and the table of them from one list, so that a notification
/// has a row because it can be sent at all: a [`WorkerEvent`] is made here and nowhere else.
macro_rules! worker_events {
    ($($(#[$doc:meta])* $constant:ident: $payload:ty = $name:expr;)+) => {
        $(
            $(#[$doc])*
            pub const $constant: WorkerEvent<$payload> = WorkerEvent::named($name);
        )+

        /// Every notification a worker sends, in the order of their names.
        #[must_use]
        pub fn sent_events() -> Vec<EventRow> {
            let mut rows = vec![$(event(&$constant)),+];
            rows.sort_by(|left, right| left.name.cmp(right.name));
            rows
        }
    };
}

worker_events! {
    /// The frames of the output stream: bytes of a session's terminal.
    SESSION_OUTPUT: OutputEvent = "session.output";
    /// The notice that opens a subscription whose start was not the one it asked for.
    SESSION_GAP: HistoryGap = "session.gap";
    /// A projected attachment's reset.
    PROJECTION_RESET: ProjectionReset = PROJECTION_RESET_EVENT;
    /// A projected attachment's snapshot header.
    PROJECTION_SNAPSHOT: ProjectionSnapshot = PROJECTION_SNAPSHOT_EVENT;
    /// One page of a projected snapshot's rows.
    PROJECTION_ROWS: ProjectionRowPage = PROJECTION_ROWS_EVENT;
    /// A projected attachment's delta.
    PROJECTION_DELTA: ProjectionDelta = PROJECTION_DELTA_EVENT;
    /// A change to a session's agent resources.
    SESSION_AGENT_RESOURCE: AgentResourceEvent = AGENT_RESOURCE_EVENT;
    /// A change to one of a session's agent instances.
    SESSION_AGENT_INSTANCE: AgentInstanceEvent = AGENT_INSTANCE_EVENT;
    /// The root shell's editor is busy.
    EDITOR_BUSY: EditorBusyEvent = EDITOR_BUSY_EVENT;
    /// The subscription cannot go on from where it was and has to read again.
    SESSION_RESYNC: ResyncRequired = "session.resync";
    /// The attachment has ended.
    SESSION_DETACHED: SessionDetachParams = "session.detached";
    /// The session has closed, and how.
    SESSION_CLOSED: ClosureRecord = SESSION_CLOSED_EVENT;
}

/// A method a worker serves, with the types of its parameters and its result, by schema name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServedMethod {
    /// The method.
    pub method: Method,
    /// The schema name of the parameters the worker reads.
    pub params: String,
    /// The schema name of the result the worker writes.
    pub result: String,
}

/// One notification of the table: its name and the schema name of its payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventRow {
    /// The event type.
    pub name: &'static str,
    /// The schema name of the payload.
    pub payload: String,
}

fn method<P: JsonSchema, R: JsonSchema>(method: Method) -> ServedMethod {
    ServedMethod {
        method,
        params: P::schema_name().into_owned(),
        result: R::schema_name().into_owned(),
    }
}

fn event<T: JsonSchema>(event: &WorkerEvent<T>) -> EventRow {
    EventRow {
        name: event.name(),
        payload: T::schema_name().into_owned(),
    }
}

fn table() -> Vec<ServedMethod> {
    vec![
        // The reads, and the keystrokes a client sends as requests.
        method::<SessionReadParams, SessionReadResult>(Method::SessionRead),
        method::<SessionScreenPreviewParams, SessionScreenPreviewResult>(
            Method::SessionScreenPreview,
        ),
        method::<EventsSnapshotParams, EventsSnapshotResult>(Method::EventsSnapshot),
        method::<AgentInstancesParams, AgentInstancesResult>(Method::AgentInstances),
        method::<HistoryPageParams, HistoryPageResult>(Method::HistoryPage),
        method::<EventsSubscribeParams, EventsSubscribeResult>(Method::EventsSubscribe),
        method::<ActionReadParams, ActionReadResult>(Method::ActionRead),
        method::<QuestionReadOwnParams, QuestionOwnResult>(Method::QuestionReadOwn),
        method::<QuestionReadParams, QuestionReadResult>(Method::QuestionRead),
        method::<AgentCapabilitiesParams, AgentCapabilitiesResult>(Method::AgentCapabilities),
        method::<AgentSnapshotParams, AgentSnapshotResult>(Method::AgentSnapshot),
        method::<AgentCommandsParams, AgentCommandsResult>(Method::AgentCommands),
        method::<AgentApprovalInspectParams, AgentApprovalInspectResult>(
            Method::AgentApprovalInspect,
        ),
        method::<InputWriteParams, InputWriteResult>(Method::InputWrite),
        // The mutations.
        method::<SessionAttachParams, SessionAttachResult>(Method::SessionAttach),
        method::<SessionDetachParams, SessionDetachResult>(Method::SessionDetach),
        method::<SessionCloseParams, SessionCloseResult>(Method::SessionClose),
        method::<AttachmentConfigureParams, GeometryResult>(Method::AttachmentConfigure),
        method::<TerminalResizeParams, GeometryResult>(Method::TerminalResize),
        method::<TerminalGeometryTransferParams, GeometryResult>(Method::TerminalGeometryTransfer),
        method::<InputAcquireParams, InputAcquireResult>(Method::InputAcquire),
        method::<InputReleaseParams, InputLeaseResult>(Method::InputRelease),
        method::<InputInterruptParams, InputLeaseResult>(Method::InputInterrupt),
        method::<ShellLaunchParams, ShellLaunchResult>(Method::ShellLaunch),
        method::<AttachmentViewportParams, AttachmentViewportResult>(Method::AttachmentViewport),
        method::<QuestionCreateParams, QuestionCreateResult>(Method::QuestionCreate),
        method::<QuestionCancelOwnParams, QuestionOwnResult>(Method::QuestionCancelOwn),
        method::<AlertCreateParams, AlertCreateResult>(Method::AlertCreate),
        method::<QuestionAnswerParams, QuestionResolveResult>(Method::QuestionAnswer),
        method::<QuestionCancelParams, QuestionResolveResult>(Method::QuestionCancel),
        method::<AgentPromptParams, AgentMutationResult>(Method::AgentPromptSubmit),
        method::<AgentPromptParams, AgentMutationResult>(Method::AgentPromptQueue),
        method::<AgentSteerParams, AgentMutationResult>(Method::AgentTurnSteer),
        method::<AgentCancelParams, AgentMutationResult>(Method::AgentTurnCancel),
        method::<AgentApprovalRespondParams, AgentApprovalRespondResult>(
            Method::AgentApprovalRespond,
        ),
        method::<PluginActionInvokeParams, PluginActionInvokeResult>(Method::PluginActionInvoke),
        method::<ActionCancelParams, ActionCancelResult>(Method::ActionCancel),
    ]
}

/// Every method a worker serves, in the order of their names.
#[must_use]
pub fn served_methods() -> &'static [ServedMethod] {
    static SERVED: LazyLock<Vec<ServedMethod>> = LazyLock::new(|| {
        let mut rows = table();
        rows.sort_by(|left, right| left.method.as_str().cmp(right.method.as_str()));
        rows
    });
    &SERVED
}

/// Whether a worker serves `method`.
#[must_use]
pub fn serves(method: Method) -> bool {
    static SERVED: LazyLock<BTreeMap<Method, ()>> = LazyLock::new(|| {
        served_methods()
            .iter()
            .map(|row| (row.method, ()))
            .collect()
    });
    SERVED.contains_key(&method)
}

/// The frames a bridge helper exchanges with a caller. They belong to `kr bridge`, which reaches a
/// worker's own host the way `kr` does.
fn bridge_frames() -> [String; 3] {
    [
        BridgeFrame::schema_name().into_owned(),
        BridgeHello::schema_name().into_owned(),
        BridgeHelloAck::schema_name().into_owned(),
    ]
}

/// The roots a worker's peers read besides [`crate::retained::SURFACE_ROOTS`]: the parameters and
/// result of each served method, the payload of each notification, and the bridge frames. Sorted,
/// each once.
#[must_use]
pub fn peer_roots() -> Vec<String> {
    let mut roots: Vec<String> = served_methods()
        .iter()
        .flat_map(|row| [row.params.clone(), row.result.clone()])
        .chain(sent_events().into_iter().map(|row| row.payload))
        .chain(bridge_frames())
        .collect();
    roots.sort();
    roots.dedup();
    roots
}

/// The document `crates/kr-protocol/worker-surface.json` holds: the roots of both lists and both
/// tables, written the way the generator writes every file, indented and ending in a newline.
///
/// # Panics
///
/// Never in practice: the document is made of text.
#[must_use]
pub fn document() -> String {
    let methods: Vec<serde_json::Value> = served_methods()
        .iter()
        .map(|row| {
            serde_json::json!({
                "name": row.method.as_str(),
                "params": row.params,
                "result": row.result,
            })
        })
        .collect();
    let events: Vec<serde_json::Value> = sent_events()
        .iter()
        .map(|row| serde_json::json!({ "name": row.name, "payload": row.payload }))
        .collect();
    let document = serde_json::json!({
        "surface_roots": crate::retained::SURFACE_ROOTS,
        "peer_roots": peer_roots(),
        "methods": methods,
        "events": events,
    });
    let mut text = serde_json::to_string_pretty(&document).expect("a document is text");
    text.push('\n');
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every row names a method the registry has, once, and every event type is one a notification
    /// can carry.
    #[test]
    fn every_row_is_a_method_of_the_registry_and_every_event_name_is_an_event_type() {
        let mut seen = std::collections::BTreeSet::new();
        for row in served_methods() {
            assert!(seen.insert(row.method), "{:?} twice", row.method);
            assert!(crate::method::lookup(row.method.as_str()).is_some());
        }
        let mut names = std::collections::BTreeSet::new();
        for row in sent_events() {
            assert!(names.insert(row.name), "{} twice", row.name);
            crate::ids::EventType::new(row.name).expect("an event type");
        }
    }

    /// The roots the tables reach are definitions of the generated schema, so the surface of the
    /// peers of a worker can be cut from it.
    #[test]
    fn every_peer_root_is_a_definition_of_the_schema() {
        let schema = crate::schema::protocol_schema();
        let roots = peer_roots();
        let roots: Vec<&str> = roots.iter().map(String::as_str).collect();
        crate::retained::Surface::cut(&schema, &roots).expect("every root is a definition");
    }
}
