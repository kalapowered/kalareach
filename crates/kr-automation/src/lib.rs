//! The KalaReach automation engine: workflow definitions, runs, causal budgets and admission.
//!
//! Section 25 defines automation workflows as versioned JSON documents with an event trigger,
//! resource scope, typed action nodes, success/failure edges, deadlines, and an explicit grant
//! reference.
//!
//! # Core Architecture
//!
//! | Module | What it owns |
//! | --- | --- |
//! | [`definition`] | Parsing, validation, acyclicity checks, and registration constraints |
//! | [`causal`] | Causal contexts, causal roots, depth and parent tracking |
//! | [`budget`] | Persistent causal budgets, ceilings, exhaustion, and rearm |
//! | [`admission`] | Concurrency limits and host-wide/per-grant rate limiters |
//! | [`store`] | The SQLite workflow journal persisting triggers, runs, and receipts |
//! | [`engine`] | Topological node sequencing, dependency resolution, and outcomes |
//! | [`source_workflow`] | The completion-tests-reviewer workflow and evidence binding |
//! | [`service`] | The top-level automation service dispatching the `Automation` group |
//! | [`error`] | Error kinds and conversions to wire protocol errors |
//!
//! # Guarantees
//!
//! * **Acyclicity and typed safety.** Graph acyclicity is strictly enforced at install time.
//!   Nodes reference registered action kinds; arbitrary template evaluation is forbidden.
//! * **Persistent causal budgets.** Mutually triggering workflows cannot escape limits: every
//!   descendant run shares the causal root and burns from one persistent budget across restarts.
//! * **Atomicity.** Triggers, runs, deduplication keys, and budget reservations commit in one
//!   local database transaction.
//! * **Honest outcome handling.** A process exit does not prove later success. Unknown predecessor
//!   outcomes pause dependent nodes for review.

pub mod admission;
pub mod budget;
pub mod causal;
pub mod definition;
pub mod engine;
pub mod error;
pub mod service;
pub mod source_workflow;
pub mod store;

pub use crate::admission::AdmissionController;
pub use crate::budget::CausalBudget;
pub use crate::causal::CausalContext;
pub use crate::definition::{
    REGISTERED_ACTION_KINDS, create_workflow_definition, validate_definition,
};
pub use crate::engine::{ActionOutcome, ActionRunner, MockActionRunner, WorkflowEngine};
pub use crate::error::{AutomationError, Result};
pub use crate::service::AutomationService;
pub use crate::source_workflow::{
    QuiescenceManager, QuiescenceReservation, SourceWorkflowCoordinator,
};
pub use crate::store::WorkflowStore;

pub(crate) fn new_uuid() -> kr_protocol::scalars::Uuid {
    kr_protocol::scalars::Uuid::from_bytes(uuid::Uuid::new_v4().into_bytes())
}

pub(crate) fn parse_uuid(s: &str) -> std::result::Result<kr_protocol::scalars::Uuid, uuid::Error> {
    uuid::Uuid::parse_str(s).map(|u| kr_protocol::scalars::Uuid::from_bytes(u.into_bytes()))
}
