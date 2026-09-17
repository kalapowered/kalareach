//! One component instance, and the calls into it.
//!
//! An instance is not shared and is not `Sync`. It owns a store, and a store is a single thread's
//! object; [`crate::runtime::binding`] gives each binding a thread of its own and this is what
//! lives on it.
//!
//! # What every call does, in the same order
//!
//! 1. Replace the instance first if the last call trapped, because a trapped instance cannot be
//!    entered again.
//! 2. Scope the source-event handles this call may read; the previous call's become unreadable.
//! 3. Set the call's fuel, and its epoch deadline where the export has one.
//! 4. Register the call as in flight, so the epoch advances while it runs.
//! 5. Call the export.
//! 6. Charge what it returned against the same output budget as its document, take the document,
//!    clear the scope, and decide what the outcome was.
//!
//! Step 6 is where a trap is separated from an exhausted bound. Wasmtime reports all three as an
//! error from the call, so the store's remaining fuel and the limiter's recorded refusal are what
//! say which happened. Without that, a component that asked for a gigabyte and one that divided by
//! zero would produce the same disabled reason.
//!
//! # One output budget
//!
//! Section 11 gives a call 1 MiB of output. That is one budget over everything the call produces:
//! the document nodes it emitted and the value it returned. A checkpoint, an encoded response and
//! a decoded projection are all bytes this host holds and the protocol carries, so a budget that
//! covered only the document would bound the smaller half of the output.
//!
//! # After a fault
//!
//! A component instance that has trapped cannot be entered again: the component model makes a trap
//! terminal for the instance, and that includes a deadline or an exhausted fuel allowance, which
//! arrive as traps. So a faulted instance is replaced before the next call, from the component that
//! is already compiled, and `bind` runs again on the new one with the facts the host holds *now*
//! rather than the ones it held when the binding was created.
//!
//! Replacing it is what makes "three faults in one minute disable the binding" mean anything: the
//! first two are survivable, and surviving one means the next call has an instance to run in. The
//! component's own presentation state does not survive, which is what `snapshot` is for, so the
//! binding asks it for one before it delivers anything else.

use crate::runtime::bindings::{
    Binding as WireBinding, DecodedRequest, EffectPlan, EncodedResponse, Fault, Plugin,
    RequestSnapshot,
};
use crate::runtime::budget::{CallBudget, CallKind};
use crate::runtime::engine::RuntimeEngine;
use crate::runtime::error::{ExhaustedBound, RuntimeError, RuntimeResult};
use crate::runtime::host::{
    AttachmentFact, BindingFacts, EmittedNode, HostState, ScopedSourceEvent,
};
use crate::runtime::limits::InstanceLimiter;

/// The epoch deadline instantiation and `bind` run under.
///
/// Neither has one of section 11's call deadlines, and neither is unbounded: a component whose
/// constructors never return would otherwise hold a binding thread for ever.
fn setup_ticks() -> u64 {
    crate::runtime::budget::SETUP_DEADLINE_MS
        .div_ceil(crate::runtime::engine::EPOCH_TICK_MS)
        .saturating_add(1)
}

/// What a call produced.
///
/// The document travels with the answer, and with a failure, because a call's nodes are part of
/// what it produced. A component that emits three nodes and then refuses has still emitted three
/// nodes, and one that emits three and then breaks a bound has too; dropping them because of what
/// came afterwards would lose a presentation the person is entitled to see.
#[derive(Debug)]
pub struct CallOutcome<T> {
    /// The nodes the call emitted, whatever else it did.
    pub nodes: Vec<EmittedNode>,
    /// What the call produced: the component's value, the fault it declared, or a runtime failure.
    pub result: RuntimeResult<Result<T, Fault>>,
    /// How much of its fuel allowance it used.
    pub fuel_used: u64,
}

impl<T> CallOutcome<T> {
    /// Returns true when the component answered with a value.
    #[must_use]
    pub const fn answered(&self) -> bool {
        matches!(self.result, Ok(Ok(_)))
    }

    /// Returns the runtime failure, where the call failed rather than answered.
    #[must_use]
    pub const fn failure(&self) -> Option<&RuntimeError> {
        match &self.result {
            Err(error) => Some(error),
            Ok(_) => None,
        }
    }

    /// Returns the component's value or its declared fault, discarding the document.
    ///
    /// # Errors
    ///
    /// Returns the runtime failure.
    pub fn answer(self) -> RuntimeResult<Result<T, Fault>> {
        self.result
    }
}

/// What a returned value costs of the call's output budget.
///
/// Implemented for every type an export returns, so one budget covers the document and the value
/// rather than the document alone.
pub trait OutputSize {
    /// Returns the bytes this value spends of the call's output budget.
    fn output_size(&self) -> u64;
}

impl OutputSize for () {
    fn output_size(&self) -> u64 {
        0
    }
}

impl OutputSize for Vec<u8> {
    fn output_size(&self) -> u64 {
        self.len() as u64
    }
}

impl OutputSize for EncodedResponse {
    fn output_size(&self) -> u64 {
        (self.request_id.len() + self.bytes.len()) as u64
    }
}

impl OutputSize for DecodedRequest {
    fn output_size(&self) -> u64 {
        let decisions: usize = self.decisions.iter().map(String::len).sum();
        let presentation: usize = self.presentation.iter().map(String::len).sum();
        (self.request_id.len() + self.summary.len() + decisions + presentation) as u64
    }
}

impl OutputSize for EffectPlan {
    fn output_size(&self) -> u64 {
        use crate::runtime::bindings::{Argument, FieldSegment, PreparedOperation};

        fn argument_size(argument: &Argument) -> usize {
            match argument {
                Argument::Text(text) => text.len(),
                Argument::Choice(id) | Argument::AttachmentHandle(id) | Argument::NodeRef(id) => {
                    id.len()
                }
                Argument::Integer(_) | Argument::Boolean(_) => 8,
            }
        }

        let operation = match &self.operation {
            PreparedOperation::Present | PreparedOperation::UpstreamCancel => 0,
            PreparedOperation::UpstreamAttachment(id) => id.len(),
            PreparedOperation::TerminalText(text) => text.len(),
            PreparedOperation::UpstreamMethod(call) => {
                call.method.len()
                    + call
                        .fields
                        .iter()
                        .map(|field| {
                            field
                                .path
                                .iter()
                                .map(|segment| match segment {
                                    FieldSegment::Member(name) => name.len(),
                                    FieldSegment::Index(_) => 8,
                                })
                                .sum::<usize>()
                                + argument_size(&field.value)
                        })
                        .sum::<usize>()
            }
        };
        let arguments: usize = self
            .arguments
            .iter()
            .map(|argument| argument.name.len() + argument_size(&argument.value))
            .sum();
        (self.action_id.len() + operation + arguments) as u64
    }
}

/// One instantiated component.
pub struct Instance {
    engine: RuntimeEngine,
    component: wasmtime::component::Component,
    linker: wasmtime::component::Linker<HostState>,
    store: wasmtime::Store<HostState>,
    world: Plugin,
    /// The facts the host holds now, not the ones it held at the first instantiation.
    facts: BindingFacts,
    /// The attachments the host holds now.
    attachments: Vec<AttachmentFact>,
    limiter: InstanceLimiter,
    fuel_rate: u64,
    target: Option<WireBinding>,
    faulted: bool,
    replacements: u64,
}

impl core::fmt::Debug for Instance {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("Instance")
            .field("target", &self.engine.target())
            .field("faulted", &self.faulted)
            .field("replacements", &self.replacements)
            .finish_non_exhaustive()
    }
}

impl Instance {
    /// Instantiates a compiled component for one binding.
    ///
    /// The linker is given the four host interfaces and nothing else. An import outside them has
    /// already been refused by [`crate::runtime::imports::check`]; this would refuse it again, as
    /// an unsatisfied import, which is the belt to that braces.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError::Instantiation`] when the linker or the instantiation fails.
    pub fn new(
        engine: &RuntimeEngine,
        component: &wasmtime::component::Component,
        facts: BindingFacts,
        limiter: InstanceLimiter,
        fuel_rate: u64,
    ) -> RuntimeResult<Self> {
        let mut linker = wasmtime::component::Linker::new(engine.engine());
        Plugin::add_to_linker::<HostState, wasmtime::component::HasSelf<HostState>>(
            &mut linker,
            |state| state,
        )
        .map_err(RuntimeError::instantiation)?;

        let (store, world) = Self::instantiate(
            engine,
            component,
            &linker,
            facts.clone(),
            Vec::new(),
            limiter,
        )?;
        Ok(Self {
            engine: engine.clone(),
            component: component.clone(),
            linker,
            store,
            world,
            facts,
            attachments: Vec::new(),
            limiter,
            fuel_rate,
            target: None,
            faulted: false,
            replacements: 0,
        })
    }

    fn instantiate(
        engine: &RuntimeEngine,
        component: &wasmtime::component::Component,
        linker: &wasmtime::component::Linker<HostState>,
        facts: BindingFacts,
        attachments: Vec<AttachmentFact>,
        limiter: InstanceLimiter,
    ) -> RuntimeResult<(wasmtime::Store<HostState>, Plugin)> {
        let mut state = HostState::new(facts, limiter);
        state.set_attachments(attachments);
        let mut store = wasmtime::Store::new(engine.engine(), state);
        store.limiter(HostState::limiter);
        // Instantiation is part of binding preparation, so it runs under the setup allowance rather
        // than an observation's. A component whose constructors never finish runs out here rather
        // than on the terminal path.
        store
            .set_fuel(crate::runtime::budget::SETUP_FUEL)
            .map_err(RuntimeError::instantiation)?;

        let world = {
            let _in_flight = engine.in_flight();
            // Instantiation has no deadline of its own, and epoch interruption is on, so the store
            // needs a deadline it will not reach rather than none at all.
            store.set_epoch_deadline(setup_ticks());
            Plugin::instantiate(&mut store, component, linker)
                .map_err(RuntimeError::instantiation)?
        };
        Ok((store, world))
    }

    /// Returns true when the instance has faulted and will be replaced before the next call.
    #[must_use]
    pub const fn faulted(&self) -> bool {
        self.faulted
    }

    /// Returns how many times this instance has been replaced after a fault.
    #[must_use]
    pub const fn replacements(&self) -> u64 {
        self.replacements
    }

    /// Replaces a faulted instance with a fresh one, and binds it.
    ///
    /// The component is already compiled, so this is an instantiation and a `bind`, not a compile.
    /// The replacement is given the facts and attachments the host holds now, and is bound to the
    /// binding revision those facts carry, because binding a replacement to a revision that has
    /// moved on would tell the component something that is no longer true.
    ///
    /// The replacement starts with no presentation state, which is why the binding asks it for a
    /// snapshot before it delivers anything else. Returns whatever `bind` emitted.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError::Instantiation`] when the replacement cannot be created or bound.
    pub fn replace(&mut self) -> RuntimeResult<Vec<EmittedNode>> {
        let (store, world) = Self::instantiate(
            &self.engine,
            &self.component,
            &self.linker,
            self.facts.clone(),
            self.attachments.clone(),
            self.limiter,
        )?;
        self.store = store;
        self.world = world;
        self.faulted = false;
        self.replacements = self.replacements.saturating_add(1);
        let Some(mut target) = self.target.clone() else {
            return Ok(Vec::new());
        };
        // The revision the host holds now. A replacement told an old revision would be presenting
        // one execution's state against another's.
        target.binding_revision = self.facts.binding_revision;
        let outcome = self.bind(target);
        let nodes = outcome.nodes;
        match outcome.result {
            Ok(Ok(())) => Ok(nodes),
            Ok(Err(fault)) => Err(RuntimeError::Instantiation {
                detail: format!(
                    "the replacement declared a fault while binding: {}",
                    crate::runtime::binding::fault_text(&fault)
                ),
            }),
            Err(error) => Err(error),
        }
    }

    /// Replaces the facts a component reads about its binding.
    ///
    /// Kept on the instance as well as pushed into the store, so a replacement is given what the
    /// host holds now rather than what it held when the binding was created.
    pub fn set_binding_facts(&mut self, facts: BindingFacts) {
        self.facts = facts.clone();
        self.store.data_mut().set_binding(facts);
    }

    /// Replaces the attachments the current draft holds.
    pub fn set_attachments(&mut self, attachments: Vec<AttachmentFact>) {
        self.attachments = attachments.clone();
        self.store.data_mut().set_attachments(attachments);
    }

    /// Returns the facts the component is being told.
    #[must_use]
    pub const fn facts(&self) -> &BindingFacts {
        &self.facts
    }

    /// Returns the attachments the component is being told about.
    #[must_use]
    pub fn attachments(&self) -> &[AttachmentFact] {
        &self.attachments
    }

    /// Calls `bind`.
    pub fn bind(&mut self, target: WireBinding) -> CallOutcome<()> {
        // Kept so a replacement can be bound to the same target without the caller having to hold
        // it and hand it back.
        self.target = Some(target.clone());
        self.call(CallKind::Bind, Vec::new(), |world, store| {
            world.kalareach_plugin_adapter().call_bind(store, &target)
        })
    }

    /// Calls `observe` with one scoped event.
    pub fn observe(&mut self, event: ScopedSourceEvent) -> CallOutcome<()> {
        let handle = event.handle.as_str().to_owned();
        self.call(CallKind::Observe, vec![event], |world, store| {
            world
                .kalareach_plugin_adapter()
                .call_observe(store, &handle)
        })
    }

    /// Calls `snapshot`.
    pub fn snapshot(&mut self) -> CallOutcome<()> {
        self.call(CallKind::Snapshot, Vec::new(), |world, store| {
            world.kalareach_plugin_adapter().call_snapshot(store)
        })
    }

    /// Calls `prepare-action`.
    pub fn prepare_action(
        &mut self,
        token: crate::runtime::bindings::ActionToken,
        arguments: Vec<crate::runtime::bindings::NamedArgument>,
    ) -> CallOutcome<EffectPlan> {
        self.call(CallKind::PrepareAction, Vec::new(), |world, store| {
            world
                .kalareach_plugin_adapter()
                .call_prepare_action(store, &token, &arguments)
        })
    }

    /// Calls `decode-request` with one scoped event.
    pub fn decode_request(&mut self, event: ScopedSourceEvent) -> CallOutcome<DecodedRequest> {
        let handle = event.handle.as_str().to_owned();
        self.call(CallKind::DecodeRequest, vec![event], |world, store| {
            world
                .kalareach_plugin_adapter()
                .call_decode_request(store, &handle)
        })
    }

    /// Calls `encode-response` with the broker's own snapshot of the pending request.
    ///
    /// The snapshot's source event is scoped for the call, so an encoder may read the bytes the
    /// request arrived as. It still cannot send: the return value is the bytes, and the broker
    /// rechecks and dispatches them.
    pub fn encode_response(
        &mut self,
        request: RequestSnapshot,
        decision: String,
        event: Option<ScopedSourceEvent>,
    ) -> CallOutcome<EncodedResponse> {
        let scoped = event.map(|event| vec![event]).unwrap_or_default();
        self.call(CallKind::EncodeResponse, scoped, |world, store| {
            world
                .kalareach_plugin_adapter()
                .call_encode_response(store, &request, &decision)
        })
    }

    /// Calls `checkpoint`.
    pub fn checkpoint(&mut self) -> CallOutcome<Vec<u8>> {
        self.call(CallKind::Checkpoint, Vec::new(), |world, store| {
            world.kalareach_plugin_adapter().call_checkpoint(store)
        })
    }

    /// Calls `restore`.
    pub fn restore(&mut self, state: Vec<u8>) -> CallOutcome<()> {
        self.call(CallKind::Restore, Vec::new(), |world, store| {
            world.kalareach_plugin_adapter().call_restore(store, &state)
        })
    }

    fn call<T, F>(
        &mut self,
        kind: CallKind,
        scoped: Vec<ScopedSourceEvent>,
        invoke: F,
    ) -> CallOutcome<T>
    where
        T: OutputSize,
        F: FnOnce(&Plugin, &mut wasmtime::Store<HostState>) -> wasmtime::Result<Result<T, Fault>>,
    {
        let budget = CallBudget::with_fuel_rate(kind, self.fuel_rate);
        if budget.deadline_ms.is_some() && !self.engine.deadlines_enforceable() {
            // Without a ticker the epoch never advances, so an elapsed deadline could not be
            // enforced. This host will not run a call it cannot bound, and the failure is the
            // host's own rather than one the component is blamed for.
            return CallOutcome {
                nodes: Vec::new(),
                result: Err(RuntimeError::DeadlinesUnenforceable),
                fuel_used: 0,
            };
        }

        self.store.data_mut().scope(scoped);
        self.store.data_mut().instance_limiter().clear_refusal();
        if let Err(error) = self.store.set_fuel(budget.fuel) {
            return CallOutcome {
                nodes: Vec::new(),
                result: Err(RuntimeError::engine(error)),
                fuel_used: 0,
            };
        }
        match budget.epoch_ticks(crate::runtime::engine::EPOCH_TICK_MS) {
            Some(ticks) => self.store.set_epoch_deadline(ticks),
            // `bind`, which runs under the preparation deadline rather than a call's.
            None => self.store.set_epoch_deadline(setup_ticks()),
        }

        let called = {
            let _in_flight = self.engine.in_flight();
            invoke(&self.world, &mut self.store)
        };

        let remaining = self.store.get_fuel().unwrap_or(0);
        let fuel_used = budget.fuel.saturating_sub(remaining);
        // The value the call returned is output too, and it is charged against the same budget as
        // the document before the document is taken.
        if let Ok(Ok(value)) = &called {
            let size = value.output_size();
            // The refusal is recorded in the sink, which is what `overran` reads below.
            let _within_budget = self.store.data_mut().document_mut().charge(size);
        }
        // Read the overrun before taking the document: taking it resets the call's output budget
        // for the next call, and with it the record of whether this one tried to exceed it.
        let overran = self.store.data().document().overran();
        let nodes = self.store.data_mut().take_document();
        let refusal = self.store.data().limits().refusal();
        self.store.data_mut().unscope();
        self.store.data_mut().instance_limiter().clear_refusal();

        let result = match called {
            Ok(answer) => {
                // A component that tried to emit or return past its output budget has broken a
                // stated bound, whatever else it did. The nodes it produced travel with this
                // outcome; the call is a fault.
                if overran {
                    Err(RuntimeError::OutputBudget {
                        call: kind.as_str(),
                        limit: kr_plugin_sdk::limits::OUTPUT_BYTES_PER_CALL,
                    })
                } else {
                    Ok(answer)
                }
            }
            Err(error) => {
                // Whatever stopped the call, it stopped it with a trap, and this instance cannot be
                // entered again. The next call replaces it.
                self.faulted = true;
                // The bounds this host imposed come first, and in the order that leaves no room
                // for one to be reported as another: an interrupted call was stopped by its
                // deadline, a call with no fuel left ran out of work, and only then is a refused
                // allocation the reason. A refusal recorded earlier in a call that went on to fail
                // some other way would otherwise be blamed for it.
                if is_epoch_deadline(&error) {
                    Err(RuntimeError::Exhausted {
                        call: kind.as_str(),
                        bound: ExhaustedBound::Deadline,
                    })
                } else if remaining == 0 {
                    Err(RuntimeError::Exhausted {
                        call: kind.as_str(),
                        bound: ExhaustedBound::Fuel,
                    })
                } else if let Some(refusal) = refusal {
                    // A refused allocation is the most specific answer left: the component asked
                    // for more than its bound and the trap is the consequence.
                    Err(refusal)
                } else {
                    Err(RuntimeError::Trap {
                        call: kind.as_str(),
                        detail: trap_detail(&error),
                    })
                }
            }
        };
        CallOutcome {
            nodes,
            result,
            fuel_used,
        }
    }
}

fn is_epoch_deadline(error: &wasmtime::Error) -> bool {
    error
        .downcast_ref::<wasmtime::Trap>()
        .is_some_and(|trap| *trap == wasmtime::Trap::Interrupt)
}

fn trap_detail(error: &wasmtime::Error) -> String {
    // The trap itself, not the whole backtrace. A disabled reason a person reads wants "wasm
    // trap: integer divide by zero", and the backtrace belongs in the host's own diagnostics.
    error
        .downcast_ref::<wasmtime::Trap>()
        .map_or_else(|| error.to_string(), |trap| trap.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node() -> EmittedNode {
        EmittedNode {
            node_id: "n0".to_owned(),
            node_revision: 1,
            body_json: "{}".to_owned(),
        }
    }

    #[test]
    fn a_refusing_call_keeps_the_nodes_it_emitted() {
        let outcome: CallOutcome<()> = CallOutcome {
            nodes: vec![node()],
            result: Ok(Err(Fault::Refused("not mine".to_owned()))),
            fuel_used: 12,
        };
        assert!(!outcome.answered());
        assert!(outcome.failure().is_none());
        assert_eq!(outcome.nodes.len(), 1);
    }

    #[test]
    fn a_failing_call_keeps_them_too() {
        let outcome: CallOutcome<()> = CallOutcome {
            nodes: vec![node()],
            result: Err(RuntimeError::OutputBudget {
                call: "snapshot",
                limit: 1_048_576,
            }),
            fuel_used: 12,
        };
        assert!(!outcome.answered());
        assert!(matches!(
            outcome.failure(),
            Some(RuntimeError::OutputBudget { .. })
        ));
        assert_eq!(outcome.nodes.len(), 1);
    }

    #[test]
    fn a_returned_value_is_measured_by_what_it_carries() {
        assert_eq!(().output_size(), 0);
        assert_eq!(vec![0_u8; 4096].output_size(), 4096);
        assert_eq!(
            EncodedResponse {
                request_id: "req-1".to_owned(),
                bytes: vec![0; 100],
            }
            .output_size(),
            105
        );
        let decoded = DecodedRequest {
            request_id: "req-1".to_owned(),
            class: crate::runtime::bindings::MethodClass::Mutation,
            summary: "abcd".to_owned(),
            decisions: vec!["allow".to_owned(), "deny".to_owned()],
            presentation: vec!["{}".to_owned()],
        };
        assert_eq!(decoded.output_size(), 5 + 4 + 5 + 4 + 2);
    }

    #[test]
    fn an_effect_plan_is_measured_by_its_operation_and_its_arguments() {
        use crate::runtime::bindings::{
            Argument, EffectClass, NamedArgument, PreparedOperation, UpstreamCall,
        };

        let plan = EffectPlan {
            action_id: "send".to_owned(),
            class: EffectClass::UpstreamPrompt,
            operation: PreparedOperation::UpstreamMethod(UpstreamCall {
                method: "prompt.submit".to_owned(),
                fields: Vec::new(),
            }),
            arguments: vec![NamedArgument {
                name: "prompt".to_owned(),
                value: Argument::Text("run the tests".to_owned()),
            }],
        };
        assert_eq!(plan.output_size(), 4 + 13 + 6 + 13);

        let present = EffectPlan {
            action_id: "redraw".to_owned(),
            class: EffectClass::Observe,
            operation: PreparedOperation::Present,
            arguments: Vec::new(),
        };
        assert_eq!(present.output_size(), 6);
    }
}
