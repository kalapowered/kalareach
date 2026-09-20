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
//! | [`authority`] | The grant a workflow acts under, and the rights each action kind needs |
//! | [`definition`] | Parsing, validation, acyclicity checks, and registration constraints |
//! | [`causal`] | Causal contexts, causal roots, depth and parent tracking |
//! | [`budget`] | Persistent causal budgets, ceilings, exhaustion, and rearm |
//! | [`admission`] | Concurrency limits and host-wide/per-grant rate limiters |
//! | [`store`] | The SQLite workflow journal holding definitions, triggers, runs, receipts, budgets and the attention outbox |
//! | [`engine`] | Topological node sequencing, dependency resolution, and outcomes |
//! | [`source_workflow`] | The completion-tests-reviewer workflow and evidence binding |
//! | [`service`] | The top-level automation service dispatching the `Automation` group |
//! | [`error`] | Error kinds and conversions to wire protocol errors |
//!
//! # Four properties the design rests on
//!
//! **A definition is a document, not a program.** Acyclicity is settled at install time, every
//! node names an action kind this engine has registered, and a parameter that decodes to a
//! template marker is refused. Nothing in a definition is evaluated.
//!
//! **Authority is read, never supplied.** A definition names a grant; the host reads that grant
//! from its own store and reads it again immediately before every node it dispatches. A grant
//! that has expired, been revoked or never been redeemed stops the run where it stands, and a
//! node whose effect needs a right the grant does not carry is never dispatched at all.
//!
//! **Ancestry is the host's, not the caller's.** A request names a parent run and a parent node;
//! the causal root, the depth and the budget generation come from this host's own journal. That
//! is what stops event content from minting a root, resetting a depth or rejoining a rearmed
//! budget, and what makes an unauthenticated external callback a new external trigger under
//! host-wide limits rather than a member of a chain it did not earn.
//!
//! **One chain, one budget, one item.** Mutually triggering workflows share the root they
//! descend from, so the chain they form between them is counted once and survives a restart.
//! The exhaustion, the pause and the attention record commit in one transaction, so a chain
//! that ran out raises exactly one attention item however many refusals follow.
//!
//! **An unknown outcome stays unknown.** A process exit does not prove that a later review or
//! deployment succeeded. A node whose predecessor's outcome is not authoritative pauses for
//! review, and a cancelled node says the host stopped asking, not that the world is clean.

pub mod admission;
pub mod authority;
pub mod budget;
pub mod causal;
pub mod definition;
pub mod engine;
pub mod error;
pub mod service;
pub mod source_workflow;
pub mod store;

pub use crate::admission::AdmissionController;
pub use crate::authority::{AuthoritySource, GrantStanding, GrantTable};
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
pub use crate::store::{
    AttentionOutboxRecord, AttentionSubject, InstalledDefinition, StoredRunRecord, WorkflowStore,
};

pub(crate) fn new_uuid() -> kr_protocol::scalars::Uuid {
    kr_protocol::scalars::Uuid::from_bytes(uuid::Uuid::new_v4().into_bytes())
}

/// The clock the engine reads before each reservation.
///
/// A run dispatches its nodes over time, and a causal chain's lifetime can run out between two
/// of them, so the engine asks for the time again rather than reusing the moment the run was
/// admitted. Nothing else in the crate reads a clock: every other entry point takes the host's
/// reading from its caller.
pub trait HostClock: Send + Sync + std::fmt::Debug {
    /// Milliseconds since the Unix epoch, as the host reads them now.
    fn now_ms(&self) -> u64;
}

/// The host's own wall clock.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl HostClock for SystemClock {
    fn now_ms(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }
}

/// A clock its holder advances by hand.
///
/// Anything that has to decide what a chain's elapsed lifetime will do at a given moment, a
/// test of the ceilings among them, drives one of these instead of waiting an hour.
#[derive(Debug)]
pub struct ManualClock(std::sync::atomic::AtomicU64);

impl ManualClock {
    /// Starts a clock at `now_ms`.
    #[must_use]
    pub fn new(now_ms: u64) -> Self {
        Self(std::sync::atomic::AtomicU64::new(now_ms))
    }

    /// Moves the clock to `now_ms`.
    pub fn set(&self, now_ms: u64) {
        self.0.store(now_ms, std::sync::atomic::Ordering::SeqCst);
    }
}

impl HostClock for ManualClock {
    fn now_ms(&self) -> u64 {
        self.0.load(std::sync::atomic::Ordering::SeqCst)
    }
}

pub(crate) fn parse_uuid(s: &str) -> std::result::Result<kr_protocol::scalars::Uuid, uuid::Error> {
    uuid::Uuid::parse_str(s).map(|u| kr_protocol::scalars::Uuid::from_bytes(u.into_bytes()))
}
