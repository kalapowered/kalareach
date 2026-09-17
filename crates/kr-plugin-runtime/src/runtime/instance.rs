//! One component instance, and the calls into it.
//!
//! An instance is not shared and is not `Sync`. It owns a store, and a store is a single thread's
//! object; [`crate::runtime::binding`] gives each binding a thread of its own and this is what
//! lives on it.
//!
//! # What every call does, in the same order
//!
//! 1. Refuse outright if the binding is disabled.
//! 2. Scope the source-event handles this call may read; the previous call's become unreadable.
//! 3. Set the call's fuel, and its epoch deadline where the export has one.
//! 4. Register the call as in flight, so the epoch advances while it runs.
//! 5. Call the export.
//! 6. Take the document output, clear the scope, and decide what the outcome was.
//!
//! Step 6 is where a trap is separated from an exhausted bound. Wasmtime reports all three as an
//! error from the call, so the store's remaining fuel and the limiter's recorded refusal are what
//! say which happened. Without that, a component that asked for a gigabyte and one that divided by
//! zero would produce the same disabled reason.
//!
//! # After a fault
//!
//! A component instance that has trapped cannot be entered again: the component model makes a trap
//! terminal for the instance, and that includes a deadline or an exhausted fuel allowance, which
//! arrive as traps. So a faulted instance is replaced before the next call, from the component that
//! is already compiled, and `bind` runs again on the new one.
//!
//! Replacing it is what makes "three faults in one minute disable the binding" mean anything: the
//! first two are survivable, and surviving one means the next call has an instance to run in. The
//! component's own presentation state does not survive, which is what `snapshot` is for, so a
//! replacement asks the binding for a fresh one.

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

/// The epoch deadline given to a call that has none.
///
/// Epoch interruption is on for the whole engine, so every store has a deadline whether its call
/// needs one or not. A delta this size is about thirty years of ticks: far enough away to mean
/// "no deadline" and small enough that adding it to the current epoch cannot overflow.
const NO_DEADLINE_TICKS: u64 = 1 << 40;

/// What a component returned, and what it emitted while returning it.
///
/// The document travels with the answer because a call's nodes are part of what it produced. A
/// component that emits three nodes and then refuses has still emitted three nodes, and dropping
/// them because of the refusal would lose a presentation the person is entitled to see.
#[derive(Debug)]
pub struct CallOutcome<T> {
    /// What the component answered: its value, or the fault it declared.
    pub answer: Result<T, Fault>,
    /// The nodes it emitted.
    pub nodes: Vec<EmittedNode>,
    /// How much of its fuel allowance it used.
    pub fuel_used: u64,
}

impl<T> CallOutcome<T> {
    /// Returns true when the component answered rather than declared a fault.
    #[must_use]
    pub const fn answered(&self) -> bool {
        self.answer.is_ok()
    }
}

/// One instantiated component.
pub struct Instance {
    engine: RuntimeEngine,
    component: wasmtime::component::Component,
    linker: wasmtime::component::Linker<HostState>,
    store: wasmtime::Store<HostState>,
    world: Plugin,
    facts: BindingFacts,
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

        let (store, world) = Self::instantiate(engine, component, &linker, facts.clone(), limiter)?;
        Ok(Self {
            engine: engine.clone(),
            component: component.clone(),
            linker,
            store,
            world,
            facts,
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
        limiter: InstanceLimiter,
    ) -> RuntimeResult<(wasmtime::Store<HostState>, Plugin)> {
        let mut store = wasmtime::Store::new(engine.engine(), HostState::new(facts, limiter));
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
            store.set_epoch_deadline(NO_DEADLINE_TICKS);
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
    /// The replacement starts with no presentation state, which is why a caller follows it with a
    /// snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError::Instantiation`] when the replacement cannot be created or bound.
    pub fn replace(&mut self) -> RuntimeResult<()> {
        let (store, world) = Self::instantiate(
            &self.engine,
            &self.component,
            &self.linker,
            self.facts.clone(),
            self.limiter,
        )?;
        self.store = store;
        self.world = world;
        self.faulted = false;
        self.replacements = self.replacements.saturating_add(1);
        if let Some(target) = self.target.clone() {
            let outcome = self.bind(target)?;
            if let Err(fault) = outcome.answer {
                return Err(RuntimeError::Instantiation {
                    detail: format!(
                        "the replacement declared a fault while binding: {}",
                        crate::runtime::binding::fault_text(&fault)
                    ),
                });
            }
        }
        Ok(())
    }

    /// Replaces the facts a component reads about its binding.
    pub fn set_binding_facts(&mut self, facts: BindingFacts) {
        self.store.data_mut().set_binding(facts);
    }

    /// Replaces the attachments the current draft holds.
    pub fn set_attachments(&mut self, attachments: Vec<AttachmentFact>) {
        self.store.data_mut().set_attachments(attachments);
    }

    /// Calls `bind`.
    ///
    /// # Errors
    ///
    /// Returns the runtime failure. A component that declares a fault has answered, and that
    /// arrives in the outcome rather than as an error.
    pub fn bind(&mut self, target: WireBinding) -> RuntimeResult<CallOutcome<()>> {
        // Kept so a replacement can be bound to the same target without the caller having to hold
        // it and hand it back.
        self.target = Some(target.clone());
        self.call(CallKind::Bind, Vec::new(), |world, store| {
            world.kalareach_plugin_adapter().call_bind(store, &target)
        })
    }

    /// Calls `observe` with one scoped event.
    ///
    /// # Errors
    ///
    /// Returns the runtime failure.
    pub fn observe(&mut self, event: ScopedSourceEvent) -> RuntimeResult<CallOutcome<()>> {
        let handle = event.handle.as_str().to_owned();
        self.call(CallKind::Observe, vec![event], |world, store| {
            world
                .kalareach_plugin_adapter()
                .call_observe(store, &handle)
        })
    }

    /// Calls `snapshot`.
    ///
    /// # Errors
    ///
    /// Returns the runtime failure.
    pub fn snapshot(&mut self) -> RuntimeResult<CallOutcome<()>> {
        self.call(CallKind::Snapshot, Vec::new(), |world, store| {
            world.kalareach_plugin_adapter().call_snapshot(store)
        })
    }

    /// Calls `prepare-action`.
    ///
    /// # Errors
    ///
    /// Returns the runtime failure.
    pub fn prepare_action(
        &mut self,
        token: crate::runtime::bindings::ActionToken,
        arguments: Vec<crate::runtime::bindings::NamedArgument>,
    ) -> RuntimeResult<CallOutcome<EffectPlan>> {
        self.call(CallKind::PrepareAction, Vec::new(), |world, store| {
            world
                .kalareach_plugin_adapter()
                .call_prepare_action(store, &token, &arguments)
        })
    }

    /// Calls `decode-request` with one scoped event.
    ///
    /// # Errors
    ///
    /// Returns the runtime failure.
    pub fn decode_request(
        &mut self,
        event: ScopedSourceEvent,
    ) -> RuntimeResult<CallOutcome<DecodedRequest>> {
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
    ///
    /// # Errors
    ///
    /// Returns the runtime failure.
    pub fn encode_response(
        &mut self,
        request: RequestSnapshot,
        decision: String,
        event: Option<ScopedSourceEvent>,
    ) -> RuntimeResult<CallOutcome<EncodedResponse>> {
        let scoped = event.map(|event| vec![event]).unwrap_or_default();
        self.call(CallKind::EncodeResponse, scoped, |world, store| {
            world
                .kalareach_plugin_adapter()
                .call_encode_response(store, &request, &decision)
        })
    }

    /// Calls `checkpoint`.
    ///
    /// # Errors
    ///
    /// Returns the runtime failure.
    pub fn checkpoint(&mut self) -> RuntimeResult<CallOutcome<Vec<u8>>> {
        self.call(CallKind::Checkpoint, Vec::new(), |world, store| {
            world.kalareach_plugin_adapter().call_checkpoint(store)
        })
    }

    /// Calls `restore`.
    ///
    /// # Errors
    ///
    /// Returns the runtime failure.
    pub fn restore(&mut self, state: Vec<u8>) -> RuntimeResult<CallOutcome<()>> {
        self.call(CallKind::Restore, Vec::new(), |world, store| {
            world.kalareach_plugin_adapter().call_restore(store, &state)
        })
    }

    fn call<T, F>(
        &mut self,
        kind: CallKind,
        scoped: Vec<ScopedSourceEvent>,
        invoke: F,
    ) -> RuntimeResult<CallOutcome<T>>
    where
        F: FnOnce(&Plugin, &mut wasmtime::Store<HostState>) -> wasmtime::Result<Result<T, Fault>>,
    {
        let budget = CallBudget::with_fuel_rate(kind, self.fuel_rate);
        if budget.deadline_ms.is_some() && !self.engine.deadlines_enforceable() {
            // Without a ticker the epoch never advances, so an elapsed deadline could not be
            // enforced. Reporting the bound as exhausted is the honest answer: this host will not
            // run a call it cannot bound.
            return Err(RuntimeError::Exhausted {
                call: kind.as_str(),
                bound: ExhaustedBound::Deadline,
            });
        }

        if self.faulted {
            // The component model makes a trap terminal for the instance, so there is nothing left
            // to enter. A replacement is what the next call runs in.
            self.replace()?;
        }
        self.store.data_mut().scope(scoped);
        self.store.data_mut().instance_limiter().clear_refusal();
        self.store
            .set_fuel(budget.fuel)
            .map_err(RuntimeError::engine)?;
        match budget.epoch_ticks(crate::runtime::engine::EPOCH_TICK_MS) {
            Some(ticks) => self.store.set_epoch_deadline(ticks),
            None => self.store.set_epoch_deadline(NO_DEADLINE_TICKS),
        }

        let result = {
            let _in_flight = self.engine.in_flight();
            invoke(&self.world, &mut self.store)
        };

        let remaining = self.store.get_fuel().unwrap_or(0);
        let fuel_used = budget.fuel.saturating_sub(remaining);
        // Read the overrun before taking the document: taking it resets the call's output budget
        // for the next call, and with it the record of whether this one tried to exceed it.
        let overran = self.store.data().document().overran();
        let nodes = self.store.data_mut().take_document();
        let refusal = self.store.data().limits().refusal();
        self.store.data_mut().unscope();
        self.store.data_mut().instance_limiter().clear_refusal();

        match result {
            Ok(answer) => {
                // A component that tried to emit past its output budget has broken a stated bound,
                // whatever it went on to return. The nodes it did emit stay in the presentation the
                // caller already received; the call itself is a fault.
                if overran {
                    return Err(RuntimeError::OutputBudget {
                        call: kind.as_str(),
                        limit: kr_plugin_sdk::limits::OUTPUT_BYTES_PER_CALL,
                    });
                }
                Ok(CallOutcome {
                    answer,
                    nodes,
                    fuel_used,
                })
            }
            Err(error) => {
                // Whatever stopped the call, it stopped it with a trap, and this instance cannot be
                // entered again. The next call replaces it.
                self.faulted = true;
                // A refused allocation is the most specific answer available: the component asked
                // for more than its bound and the trap is the consequence.
                if let Some(refusal) = refusal {
                    return Err(refusal);
                }
                if remaining == 0 {
                    return Err(RuntimeError::Exhausted {
                        call: kind.as_str(),
                        bound: ExhaustedBound::Fuel,
                    });
                }
                if is_epoch_deadline(&error) {
                    return Err(RuntimeError::Exhausted {
                        call: kind.as_str(),
                        bound: ExhaustedBound::Deadline,
                    });
                }
                Err(RuntimeError::Trap {
                    call: kind.as_str(),
                    detail: trap_detail(&error),
                })
            }
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

    #[test]
    fn a_call_outcome_keeps_the_nodes_a_refusing_call_emitted() {
        let outcome: CallOutcome<()> = CallOutcome {
            answer: Err(Fault::Refused("not mine".to_owned())),
            nodes: vec![EmittedNode {
                node_id: "n0".to_owned(),
                node_revision: 1,
                body_json: "{}".to_owned(),
            }],
            fuel_used: 12,
        };
        assert!(!outcome.answered());
        assert_eq!(outcome.nodes.len(), 1);
    }
}
