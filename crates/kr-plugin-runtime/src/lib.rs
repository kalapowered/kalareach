//! Executing KalaReach plugin components.
//!
//! The plugin SDK states the contract: what a package carries, what a component exports, what the
//! host imports supply and what limits everything runs under. This crate is the half that runs it.
//! It holds the component engine, the per-instance bounds, the compiled-code cache, the binding
//! lifecycle, and the client and protocol of the per-environment service that owns the instances.
//!
//! # What it holds
//!
//! [`runtime`] owns the engine, the generated bindings, the four host imports, the limiter, fuel
//! and deadlines, the fault counter, the compiled-code cache, lazy compilation and the binding
//! lifecycle.
//!
//! # What a component can reach
//!
//! Exactly four interfaces, all declared in the SDK's WIT package: `source-events`, `upstream`,
//! `attachments` and `document`. There is no ambient filesystem, network, process, environment,
//! clock or random import, and no import that sends anything anywhere. A component that asks for
//! one is refused before it is instantiated, by name, so the refusal says which import it was.
//!
//! # What this crate does not do
//!
//! It does not decide whether an effect happens. A component returns a plan; the broker checks the
//! actor, the grant, the binding revision and the declared effect class, then claims and
//! dispatches. Pending and dispatch state lives in the worker's broker ledger, never in a
//! component and never in this process.
//!
//! # Example
//!
//! ```no_run
//! use std::sync::Arc;
//!
//! use kr_plugin_runtime::runtime::{Runtime, RuntimeConfig};
//! use kr_plugin_runtime::runtime::binding::BindingRequest;
//!
//! # fn example(request: BindingRequest, wasm: Arc<[u8]>) -> Result<(), kr_plugin_runtime::RuntimeError> {
//! let runtime = Runtime::new(RuntimeConfig::new("/var/lib/kalareach/plugin-cache"))?;
//! let (events, received) = tokio::sync::mpsc::unbounded_channel();
//!
//! // Compilation happens on a background thread under its own budget, and the deadline here is
//! // the caller's own. No call deadline includes a compile.
//! let binding = runtime.prepare(
//!     request,
//!     wasm,
//!     core::time::Duration::from_secs(5),
//!     events,
//! )?;
//!
//! // Delivering an observation runs nothing and waits for nothing. Document nodes, gaps and
//! // faults arrive on `received`.
//! # let event = unimplemented!();
//! let admission = binding.enqueue_observation(event);
//! # let _ = (admission, received);
//! # Ok(())
//! # }
//! ```

pub mod runtime;

pub use crate::runtime::error::{RuntimeError, RuntimeResult};
