//! Hosting components: the engine, the bounds, the cache and the binding lifecycle.
//!
//! This is the broker-facing half of the crate. A broker prepares a binding, delivers scoped
//! source events to it, invokes controls, asks for interpretations, and takes checkpoints. It never
//! waits on a component to do any of it.
//!
//! # The shape of the API
//!
//! Every operation that runs a component is asynchronous and every one carries a deadline the
//! caller sets. Observation is stronger than that: it is a queue push that runs nothing at all. The
//! reason is section 11's requirement that PTY draining, terminal-query responses and the
//! presentation queues never wait for an observation callback. An API where delivering an event
//! could block would make that a matter of care rather than of structure.
//!
//! ```text
//! broker ──enqueue──▶ observation queue ──pump thread──▶ component
//!    │                                                      │
//!    └──────────────── document nodes, gaps, faults ◀────────┘
//! ```
//!
//! # Modules
//!
//! | Module | What it owns |
//! | --- | --- |
//! | [`engine`] | The engine configuration and the thread that advances its epoch |
//! | [`bindings`] | The bindings generated from the SDK's WIT text |
//! | [`host`] | The four host interfaces and the state one call runs against |
//! | [`limits`] | The per-instance resource bounds |
//! | [`budget`] | What each export may spend: its deadline and its fuel |
//! | [`imports`] | The import allowlist, checked before instantiation |
//! | [`cache`] | The compiled-code cache and what it refuses |
//! | [`compile`] | Lazy compilation at background priority, under its own budget |
//! | [`instance`] | One instance and the calls into it |
//! | [`queue`] | The bounded observation queue and its explicit gaps |
//! | [`binding`] | The binding lifecycle a broker works with |
//! | [`error`] | Every failure, and whether it counts as a fault |

pub mod binding;
pub mod bindings;
pub mod budget;
pub mod cache;
pub mod compile;
pub mod engine;
pub mod error;
pub mod faults;
pub mod host;
pub mod imports;
pub mod instance;
pub mod limits;
pub mod queue;

pub use crate::runtime::binding::{Runtime, RuntimeConfig};
