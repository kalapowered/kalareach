//! The durability contract of the worker's private stores, made explicit.
//!
//! The journal has always been crash-durable. What this module adds is the part of section 24
//! that a reader of `journal.rs` had to infer: which store survives what, what may be evicted
//! under a byte cap and what may not, where the flushes are and where they deliberately are not,
//! what happens to the rest of the worker when durable writing stops, and how a database this
//! build did not write is brought forward.
//!
//! | Module | What it holds |
//! | --- | --- |
//! | [`contract`] | The commit points, the flush policy and the group that shares a flush |
//! | [`stores`] | Every store's durability, retention, content class, cleanup and reconciliation |
//! | [`fault`] | The journal-fault and recovery seam: fault detected, rich work fenced, gap committed |
//! | [`outbox`] | A state transition and its event in one transaction, with at-least-once idempotent fan-out |
//! | [`capacity`] | A full durable store refusing new mutations before dispatch, with the stated exceptions |
//! | [`migration`] | Forward-only transactional migrations and the explicit importer |
//! | [`retention`] | Seven-day output retention under the host and session caps, and what eviction leaves behind |

pub mod capacity;
pub mod contract;
pub mod fault;
pub mod migration;
pub mod outbox;
pub mod retention;
pub mod stores;

pub use crate::persistence::capacity::{Exception, StoreCapacity};
pub use crate::persistence::contract::{CommitGroup, CommitPoint, FlushPolicy, WriteKind};
pub use crate::persistence::fault::{
    DurabilityPosture, FaultKind, JournalCondition, JournalFault, JournalHealth, RecoveryGap,
    WorkClass,
};
pub use crate::persistence::outbox::{OutboxCursor, OutboxEvent, OutboxRecord};
pub use crate::persistence::retention::{Eviction, OutputRetention, RetentionLimit};
pub use crate::persistence::stores::{
    ContentClass, Durability, Reconciliation, Retention, STORES, StoreDescriptor,
};
