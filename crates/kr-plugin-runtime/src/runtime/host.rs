//! The four host interfaces, and the state one call runs against.
//!
//! This is the whole of what a component can reach. Each interface is deliberately narrower than
//! the thing behind it:
//!
//! | Interface | What the host holds | What the component gets |
//! | --- | --- | --- |
//! | `source-events` | immutable upstream bytes and their provenance | the bytes behind a handle *this call* was given |
//! | `upstream` | the bound execution, its credentials and its connection | facts, and no function that sends |
//! | `attachments` | the transfer service | completed handles, never bytes, never an upload |
//! | `document` | the presentation queue | one bounded write of nodes from the closed union |
//!
//! # Scoping, and why a handle cannot be guessed
//!
//! A component cannot construct a [`crate::runtime::bindings::SourceEvent`]; it only receives a
//! handle. The host admits exactly the handles it passed into the current call, so a handle from
//! another call, another binding or another source generation reads as absent rather than as
//! someone else's bytes. `read` returning `none` is therefore the answer to a handle the component
//! was never given, and there is no way to enumerate what it was not given.
//!
//! # Immutability
//!
//! The bytes live behind an [`Arc`](std::sync::Arc) and there is no accessor that hands out a mutable reference.
//! The component model copies a `list<u8>` into the guest, so what a component mutates is its own
//! copy: reading a handle twice returns the same bytes however the component treated the first
//! read.

use kr_plugin_sdk::limits::OUTPUT_BYTES_PER_CALL;
use kr_plugin_service::vocabulary::{
    AttachmentFact, BindingActivity, BindingFacts, MAX_NODE_BYTES, NODE_OVERHEAD_BYTES,
    ScopedSourceEvent, SourceProvenance,
};

use crate::runtime::bindings::{Activity, Attachment, BindingState, Node, Provenance, SourceEvent};
use crate::runtime::limits::InstanceLimiter;

/// How many document nodes one call may emit.
///
/// The output budget and the per-node cost already bound this arithmetically. Stating it as well
/// makes the bound a number a person can check rather than a division.
pub const MAX_NODES_PER_CALL: usize = 4_096;

/// An event as the `source-events` interface hands it to a component.
fn source_event_of(event: &ScopedSourceEvent) -> SourceEvent {
    SourceEvent {
        handle: event.handle.as_str().to_owned(),
        provenance: provenance_of(event.provenance),
        observed_at: event.observed_at_ms,
        request_id: event.request_id.clone(),
        bytes: event.bytes.to_vec(),
    }
}

/// A provenance as the component's types name it.
const fn provenance_of(provenance: SourceProvenance) -> Provenance {
    match provenance {
        SourceProvenance::NativeProtocol => Provenance::NativeProtocol,
        SourceProvenance::MachineOutput => Provenance::MachineOutput,
        SourceProvenance::TerminalScrape => Provenance::TerminalScrape,
    }
}

/// A binding's facts as the `upstream` interface reports them to a component.
fn binding_state_of(facts: &BindingFacts) -> BindingState {
    BindingState {
        plugin_id: facts.plugin_id.clone(),
        binding_revision: facts.binding_revision,
        activity: activity_of(facts.activity),
        thread_id: facts.thread_id.clone(),
        turn_id: facts.turn_id.clone(),
        updated_at: facts.updated_at_ms,
    }
}

/// An activity as the component's types name it.
const fn activity_of(activity: BindingActivity) -> Activity {
    match activity {
        BindingActivity::Idle => Activity::Idle,
        BindingActivity::Running => Activity::Running,
        BindingActivity::AwaitingPerson => Activity::AwaitingPerson,
        BindingActivity::Ended => Activity::Ended,
    }
}

/// An attachment as the `attachments` interface hands it to a component.
fn attachment_of(fact: &AttachmentFact) -> Attachment {
    Attachment {
        attachment_id: fact.attachment_id.clone(),
        name: fact.name.clone(),
        media_type: fact.media_type.clone(),
        size_bytes: fact.size_bytes,
        completed_at: fact.completed_at_ms,
    }
}

/// One node a component emitted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EmittedNode {
    /// The node's stable identifier.
    pub node_id: String,
    /// The node's revision.
    pub node_revision: u64,
    /// The node body, as canonical JSON for that node kind.
    pub body_json: String,
}

impl EmittedNode {
    /// Returns the bytes this node spends of the call's output budget.
    ///
    /// Its strings plus a fixed cost for being a node at all, so a component cannot emit an
    /// unbounded number of empty ones.
    #[must_use]
    pub fn output_bytes(&self) -> u64 {
        NODE_OVERHEAD_BYTES + (self.node_id.len() + self.body_json.len()) as u64
    }
}

/// The bounded document output of one call.
#[derive(Debug)]
pub struct DocumentSink {
    nodes: Vec<EmittedNode>,
    used: u64,
    budget: u64,
    overran: bool,
}

impl DocumentSink {
    /// Builds a sink with the section 11 budget.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            nodes: Vec::new(),
            used: 0,
            budget: OUTPUT_BYTES_PER_CALL,
            overran: false,
        }
    }

    /// Returns how many bytes remain in this call's budget.
    #[must_use]
    pub const fn remaining(&self) -> u64 {
        self.budget.saturating_sub(self.used)
    }

    /// Returns true when the component tried to emit past its budget.
    #[must_use]
    pub const fn overran(&self) -> bool {
        self.overran
    }

    /// Returns the nodes emitted so far.
    #[must_use]
    pub fn nodes(&self) -> &[EmittedNode] {
        &self.nodes
    }

    /// Takes the nodes and resets the sink for the next call.
    pub fn take(&mut self) -> Vec<EmittedNode> {
        self.used = 0;
        self.overran = false;
        core::mem::take(&mut self.nodes)
    }

    /// Accepts one node, or says why it was refused.
    ///
    /// # Errors
    ///
    /// Returns the refusal text the component receives: the node is larger than one node may be,
    /// or it would take the call past its output budget.
    pub fn emit(&mut self, node: EmittedNode) -> Result<(), String> {
        let bytes = node.output_bytes();
        if bytes > MAX_NODE_BYTES {
            self.overran = true;
            return Err(format!(
                "a node of {bytes} bytes is over the {MAX_NODE_BYTES} byte bound for one node"
            ));
        }
        if self.nodes.len() >= MAX_NODES_PER_CALL {
            self.overran = true;
            return Err(format!(
                "this call has already emitted the {MAX_NODES_PER_CALL} nodes one call may emit"
            ));
        }
        if !self.charge(bytes) {
            return Err(format!(
                "this call has {} of its {} byte output budget left",
                self.remaining(),
                self.budget
            ));
        }
        self.nodes.push(node);
        Ok(())
    }

    /// Charges `bytes` against this call's output budget.
    ///
    /// The document is not the only output a call produces: a checkpoint, an encoded response and
    /// a decoded projection are all bytes the host has to hold and the protocol has to carry, and
    /// section 11's "1 MiB output per call" is one budget over all of them rather than one for the
    /// document and none for anything else.
    ///
    /// Returns false when the charge would take the call past its budget. The overrun is recorded
    /// either way, so the call is a fault.
    pub fn charge(&mut self, bytes: u64) -> bool {
        let Some(used) = self
            .used
            .checked_add(bytes)
            .filter(|used| *used <= self.budget)
        else {
            self.overran = true;
            return false;
        };
        self.used = used;
        true
    }

    /// Returns how many bytes of this call's budget are spent.
    #[must_use]
    pub const fn used(&self) -> u64 {
        self.used
    }
}

impl Default for DocumentSink {
    fn default() -> Self {
        Self::new()
    }
}

/// What one component instance runs against.
///
/// The store holds this. Everything a call may reach is here, and the call path replaces the
/// scoped events before each call and takes the document afterwards, so nothing leaks from one
/// call into the next.
#[derive(Debug)]
pub struct HostState {
    scoped: Vec<ScopedSourceEvent>,
    binding: BindingFacts,
    attachments: Vec<AttachmentFact>,
    document: DocumentSink,
    limiter: InstanceLimiter,
}

impl HostState {
    /// Builds the state for one binding.
    #[must_use]
    pub fn new(binding: BindingFacts, limiter: InstanceLimiter) -> Self {
        Self {
            scoped: Vec::new(),
            binding,
            attachments: Vec::new(),
            document: DocumentSink::new(),
            limiter,
        }
    }

    /// Returns the resource limiter, for the store to borrow.
    #[must_use]
    pub const fn limiter(&mut self) -> &mut dyn wasmtime::ResourceLimiter {
        &mut self.limiter
    }

    /// Returns the resource limiter for this host's own bookkeeping.
    #[must_use]
    pub const fn instance_limiter(&mut self) -> &mut InstanceLimiter {
        &mut self.limiter
    }

    /// Returns the resource limiter for inspection.
    #[must_use]
    pub const fn limits(&self) -> &InstanceLimiter {
        &self.limiter
    }

    /// Replaces the facts a component reads about its binding.
    pub fn set_binding(&mut self, binding: BindingFacts) {
        self.binding = binding;
    }

    /// Returns the facts a component reads about its binding.
    #[must_use]
    pub const fn binding(&self) -> &BindingFacts {
        &self.binding
    }

    /// Replaces the attachments the current draft holds.
    pub fn set_attachments(&mut self, attachments: Vec<AttachmentFact>) {
        self.attachments = attachments;
    }

    /// Scopes the handles one call may read.
    ///
    /// Anything the previous call could read stops being readable here, which is what makes a
    /// handle usable for exactly the call it arrived in.
    pub fn scope(&mut self, events: Vec<ScopedSourceEvent>) {
        self.scoped = events;
    }

    /// Removes every scoped handle.
    pub fn unscope(&mut self) {
        self.scoped.clear();
    }

    /// Returns the document output of the current call.
    #[must_use]
    pub const fn document(&self) -> &DocumentSink {
        &self.document
    }

    /// Returns the document output of the current call, to be charged or taken.
    #[must_use]
    pub const fn document_mut(&mut self) -> &mut DocumentSink {
        &mut self.document
    }

    /// Takes the document output and resets the budget for the next call.
    pub fn take_document(&mut self) -> Vec<EmittedNode> {
        self.document.take()
    }

    /// Returns true when the current call tried to emit past its output budget.
    #[must_use]
    pub const fn overran_output(&self) -> bool {
        self.document.overran()
    }
}

/// The type interface declares types and no functions, so there is nothing to implement. It is
/// here because every other interface in the package uses its records, and a world's imports are
/// satisfied as a set.
impl crate::runtime::bindings::kalareach::plugin::types::Host for HostState {}

impl crate::runtime::bindings::kalareach::plugin::source_events::Host for HostState {
    fn read(&mut self, handle: String) -> Option<SourceEvent> {
        self.scoped
            .iter()
            .find(|event| event.handle.as_str() == handle)
            .map(source_event_of)
    }
}

impl crate::runtime::bindings::kalareach::plugin::upstream::Host for HostState {
    fn state(&mut self) -> BindingState {
        binding_state_of(&self.binding)
    }

    fn held_rights(&mut self) -> Vec<String> {
        self.binding
            .held_rights
            .iter()
            .map(|right| right.as_str().to_owned())
            .collect()
    }
}

impl crate::runtime::bindings::kalareach::plugin::attachments::Host for HostState {
    fn current(&mut self) -> Vec<Attachment> {
        self.attachments.iter().map(attachment_of).collect()
    }
}

impl crate::runtime::bindings::kalareach::plugin::document::Host for HostState {
    fn emit(&mut self, value: Node) -> Result<(), String> {
        self.document.emit(EmittedNode {
            node_id: value.node_id,
            node_revision: value.node_revision,
            body_json: value.body_json,
        })
    }

    fn remaining_output_bytes(&mut self) -> u64 {
        self.document.remaining()
    }
}

#[cfg(test)]
mod tests {
    use kr_plugin_service::vocabulary::FRAME_ENVELOPE_BYTES;
    use kr_protocol::ids::SourceEventHandle;
    use kr_protocol::rights::ActionRight;

    use super::*;
    use crate::runtime::bindings::kalareach::plugin::attachments::Host as _;
    use crate::runtime::bindings::kalareach::plugin::document::Host as _;
    use crate::runtime::bindings::kalareach::plugin::source_events::Host as _;
    use crate::runtime::bindings::kalareach::plugin::upstream::Host as _;
    use crate::runtime::limits::InstanceLimiter;

    fn facts() -> BindingFacts {
        BindingFacts {
            plugin_id: "kalareach/example".to_owned(),
            binding_revision: 4,
            activity: BindingActivity::Running,
            thread_id: Some("t-1".to_owned()),
            turn_id: None,
            updated_at_ms: 1_700_000_000_000,
            held_rights: vec![ActionRight::SessionView],
        }
    }

    fn handle(text: &str) -> SourceEventHandle {
        SourceEventHandle::new(text).expect("a handle within the identifier bound")
    }

    fn state() -> HostState {
        HostState::new(facts(), InstanceLimiter::defaults())
    }

    #[test]
    fn a_component_reads_only_the_handles_this_call_was_given() {
        let mut state = state();
        state.scope(vec![ScopedSourceEvent::new(
            handle("se-1"),
            SourceProvenance::NativeProtocol,
            7,
            Some("req-1".to_owned()),
            b"hello".to_vec(),
        )]);

        let event = state
            .read("se-1".to_owned())
            .expect("the scoped handle reads");
        assert_eq!(event.bytes, b"hello");
        assert_eq!(event.request_id.as_deref(), Some("req-1"));
        assert_eq!(event.provenance, Provenance::NativeProtocol);

        // A handle from another call, another binding or another generation is simply absent.
        assert!(state.read("se-2".to_owned()).is_none());

        state.unscope();
        assert!(state.read("se-1".to_owned()).is_none());
    }

    #[test]
    fn the_bytes_behind_a_handle_do_not_change_between_reads() {
        let mut state = state();
        state.scope(vec![ScopedSourceEvent::new(
            handle("se-1"),
            SourceProvenance::TerminalScrape,
            7,
            None,
            b"original".to_vec(),
        )]);
        let mut first = state.read("se-1".to_owned()).expect("first read");
        // What the component holds is its own copy, so mutating it is not mutating the host's.
        first.bytes.fill(0);
        let second = state.read("se-1".to_owned()).expect("second read");
        assert_eq!(second.bytes, b"original");
    }

    #[test]
    fn the_upstream_interface_reports_facts_and_offers_no_way_to_send() {
        let mut state = state();
        let reported = state.state();
        assert_eq!(reported.binding_revision, 4);
        assert_eq!(reported.activity, Activity::Running);
        assert_eq!(state.held_rights(), vec!["session.view".to_owned()]);
    }

    #[test]
    fn attachments_are_handles_and_never_bytes() {
        let mut state = state();
        state.set_attachments(vec![AttachmentFact {
            attachment_id: "a-1".to_owned(),
            name: "diagram.png".to_owned(),
            media_type: "image/png".to_owned(),
            size_bytes: 4096,
            completed_at_ms: 9,
        }]);
        let current = state.current();
        assert_eq!(current.len(), 1);
        assert_eq!(current[0].size_bytes, 4096);
    }

    #[test]
    fn a_node_costs_something_even_when_its_strings_are_empty() {
        let mut state = state();
        let before = state.remaining_output_bytes();
        state
            .emit(Node {
                node_id: String::new(),
                node_revision: 1,
                body_json: String::new(),
            })
            .expect("an empty node is admitted");
        assert_eq!(before - state.remaining_output_bytes(), NODE_OVERHEAD_BYTES);
    }

    #[test]
    fn a_flood_of_empty_nodes_runs_out_of_budget_rather_than_running_for_ever() {
        let mut state = state();
        let mut emitted = 0_u64;
        let refusal = loop {
            let outcome = state.emit(Node {
                node_id: String::new(),
                node_revision: emitted,
                body_json: String::new(),
            });
            match outcome {
                Ok(()) => emitted += 1,
                Err(refusal) => break refusal,
            }
            assert!(
                emitted <= MAX_NODES_PER_CALL as u64,
                "a call emitted more than the {MAX_NODES_PER_CALL} nodes one call may emit"
            );
        };
        assert_eq!(emitted, MAX_NODES_PER_CALL as u64);
        assert!(refusal.contains("nodes one call may emit"), "{refusal}");
        assert!(state.overran_output());
    }

    #[test]
    fn a_returned_value_is_charged_against_the_same_budget_as_the_document() {
        let mut state = state();
        state
            .emit(Node {
                node_id: "n0".to_owned(),
                node_revision: 1,
                body_json: "x".repeat(600 * 1024),
            })
            .expect("a 600 KiB node fits");
        // A 600 KiB return value on top of it does not: one budget covers both.
        assert!(!state.document_mut().charge(600 * 1024));
        assert!(state.overran_output());
    }

    #[test]
    fn the_output_budget_is_one_mebibyte_per_call_and_resets() {
        let mut state = state();
        assert_eq!(state.remaining_output_bytes(), OUTPUT_BYTES_PER_CALL);

        let body = "x".repeat(400 * 1024);
        for index in 0..2 {
            state
                .emit(Node {
                    node_id: format!("n{index}"),
                    node_revision: 1,
                    body_json: body.clone(),
                })
                .expect("two 400 KiB nodes fit one call");
        }
        assert!(!state.overran_output());

        let refusal = state
            .emit(Node {
                node_id: "n2".to_owned(),
                node_revision: 1,
                body_json: body.clone(),
            })
            .expect_err("a third does not");
        assert!(refusal.contains("output budget"));
        assert!(state.overran_output());

        assert_eq!(state.take_document().len(), 2);
        assert_eq!(state.remaining_output_bytes(), OUTPUT_BYTES_PER_CALL);
        assert!(!state.overran_output());
    }

    #[test]
    fn one_node_may_not_be_larger_than_a_frame_can_carry() {
        let mut state = state();
        let refusal = state
            .emit(Node {
                node_id: "n0".to_owned(),
                node_revision: 1,
                body_json: "x".repeat(usize::try_from(MAX_NODE_BYTES).expect("a usize bound") + 1),
            })
            .expect_err("an oversized node is refused");
        assert!(refusal.contains("bound for one node"));
        assert!(state.overran_output());
        // A node is bounded below the call budget, so a node that fits one call always fits the
        // frame that carries it.
        // A node is bounded below the call budget by at least a frame's envelope, so a node that
        // fits one call is always one the protocol can deliver.
        const { assert!(MAX_NODE_BYTES + FRAME_ENVELOPE_BYTES <= OUTPUT_BYTES_PER_CALL) }
    }
}
