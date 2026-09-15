//! The limits a package is written against.
//!
//! Section 11 fixes these numbers. They live here rather than in the runtime because a package
//! author has to know them before writing a component, a reviewer has to check a manifest against
//! them, and the generated schema has to carry them to every other language. The runtime enforces
//! them; this module states them once.
//!
//! # Per-instance execution limits
//!
//! | Limit | Value |
//! | --- | --- |
//! | Linear memory | 64 MiB |
//! | `observe` and `prepare-action` deadline | 10 ms |
//! | `decode-request` and `encode-response` deadline | 50 ms |
//! | `snapshot` deadline | 100 ms |
//! | Output per call | 1 MiB |
//! | Broker observation queue | 4 MiB |
//! | Faults before the binding is disabled | 3 in 60 s |
//!
//! Compilation is not part of any call deadline. Modules compile lazily at binding preparation
//! under their own budget at background priority, and a call budget starts only once the instance
//! is ready, so a cold compile never looks like a slow observation.
//!
//! # Repository budgets
//!
//! Enrolment sets these before the first fetch. Exceeding one leaves the previous generation
//! usable and reports the exact resource that ran out; it never evicts a live-bound or pinned
//! payload to finish a sync.

use serde::{Deserialize, Serialize};

use crate::scalars::{Count, U64};

/// One mebibyte in bytes.
pub const MIB: u64 = 1024 * 1024;

/// Linear memory available to one component instance.
pub const INSTANCE_MEMORY_BYTES: u64 = 64 * MIB;

/// Deadline for `observe` and `prepare-action`.
pub const OBSERVATION_DEADLINE_MS: u64 = 10;

/// Deadline for `decode-request` and `encode-response`.
pub const INTERPRETATION_DEADLINE_MS: u64 = 50;

/// Deadline for `snapshot`.
pub const SNAPSHOT_DEADLINE_MS: u64 = 100;

/// Maximum bytes one component call may return.
pub const OUTPUT_BYTES_PER_CALL: u64 = MIB;

/// Size of the broker's bounded observation queue.
///
/// Overflow produces an explicit gap and a fresh snapshot. It never drops an authoritative
/// request, because a dropped request is a decision nobody made.
pub const OBSERVATION_QUEUE_BYTES: u64 = 4 * MIB;

/// Faults within [`FAULT_WINDOW_MS`] that disable a binding.
pub const FAULTS_BEFORE_DISABLE: u32 = 3;

/// The window the fault count is measured over.
pub const FAULT_WINDOW_MS: u64 = 60_000;

/// Default metadata budget for one repository.
pub const METADATA_BUDGET_BYTES: u64 = 64 * MIB;

/// Default index entry budget for one repository.
pub const METADATA_BUDGET_ENTRIES: u64 = 100_000;

/// Default cached payload budget for one repository.
///
/// A larger full mirror needs the explicit full-offline-mirror setting; it is not reached by
/// syncing more often.
pub const PAYLOAD_CACHE_BUDGET_BYTES: u64 = 1024 * MIB;

/// Maximum size of one manifest document.
pub const MANIFEST_BYTES: u64 = MIB;

/// The complete set of execution limits one component instance runs under.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct InstanceLimits {
    /// Linear memory in bytes.
    pub memory_bytes: U64,
    /// Deadline in milliseconds for `observe` and `prepare-action`.
    pub observation_deadline_ms: U64,
    /// Deadline in milliseconds for `decode-request` and `encode-response`.
    pub interpretation_deadline_ms: U64,
    /// Deadline in milliseconds for `snapshot`.
    pub snapshot_deadline_ms: U64,
    /// Maximum bytes one call may return.
    pub output_bytes_per_call: U64,
    /// Size in bytes of the bounded observation queue.
    pub observation_queue_bytes: U64,
    /// Faults within `fault_window_ms` that disable the binding.
    pub faults_before_disable: Count,
    /// The window the fault count is measured over.
    pub fault_window_ms: U64,
}

impl InstanceLimits {
    /// The section 11 defaults.
    #[must_use]
    pub const fn defaults() -> Self {
        Self {
            memory_bytes: U64::new(INSTANCE_MEMORY_BYTES),
            observation_deadline_ms: U64::new(OBSERVATION_DEADLINE_MS),
            interpretation_deadline_ms: U64::new(INTERPRETATION_DEADLINE_MS),
            snapshot_deadline_ms: U64::new(SNAPSHOT_DEADLINE_MS),
            output_bytes_per_call: U64::new(OUTPUT_BYTES_PER_CALL),
            observation_queue_bytes: U64::new(OBSERVATION_QUEUE_BYTES),
            faults_before_disable: Count::new(FAULTS_BEFORE_DISABLE),
            fault_window_ms: U64::new(FAULT_WINDOW_MS),
        }
    }
}

impl Default for InstanceLimits {
    fn default() -> Self {
        Self::defaults()
    }
}

/// The budgets a host sets when it enrols a repository.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct RepositoryBudgets {
    /// Maximum bytes of catalogue metadata.
    pub metadata_bytes: U64,
    /// Maximum number of index entries.
    pub metadata_entries: U64,
    /// Maximum bytes of cached payloads.
    pub payload_cache_bytes: U64,
    /// Whether every referenced payload is fetched rather than only what is installed.
    pub full_offline_mirror: bool,
}

impl RepositoryBudgets {
    /// The section 11 defaults.
    #[must_use]
    pub const fn defaults() -> Self {
        Self {
            metadata_bytes: U64::new(METADATA_BUDGET_BYTES),
            metadata_entries: U64::new(METADATA_BUDGET_ENTRIES),
            payload_cache_bytes: U64::new(PAYLOAD_CACHE_BUDGET_BYTES),
            full_offline_mirror: false,
        }
    }
}

impl Default for RepositoryBudgets {
    fn default() -> Self {
        Self::defaults()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_defaults_are_the_specified_numbers() {
        let limits = InstanceLimits::defaults();
        assert_eq!(limits.memory_bytes.get(), 67_108_864);
        assert_eq!(limits.observation_deadline_ms.get(), 10);
        assert_eq!(limits.interpretation_deadline_ms.get(), 50);
        assert_eq!(limits.snapshot_deadline_ms.get(), 100);
        assert_eq!(limits.output_bytes_per_call.get(), 1_048_576);
        assert_eq!(limits.observation_queue_bytes.get(), 4_194_304);
        assert_eq!(limits.faults_before_disable.get(), 3);
        assert_eq!(limits.fault_window_ms.get(), 60_000);

        let budgets = RepositoryBudgets::defaults();
        assert_eq!(budgets.metadata_bytes.get(), 67_108_864);
        assert_eq!(budgets.metadata_entries.get(), 100_000);
        assert_eq!(budgets.payload_cache_bytes.get(), 1_073_741_824);
        assert!(!budgets.full_offline_mirror);
    }
}
