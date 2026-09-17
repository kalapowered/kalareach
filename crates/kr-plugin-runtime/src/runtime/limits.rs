//! The per-instance resource bounds, and what a refused allocation is recorded as.
//!
//! Linear memory is the bound section 11 names: 64 MiB per **instance**. Per instance, not per
//! memory: a component may create several linear memories, and a bound that checked each one on its
//! own would let eight of them reach half a gigabyte between them. So the limiter tracks the total
//! across the store and refuses the growth that would take the total past the bound.
//!
//! Table elements, table counts, memory counts and instance counts are bounded too, because a
//! component that cannot grow its memory can still ask for a thousand tables.
//!
//! # Why a refusal is recorded and not only returned
//!
//! Wasmtime turns a `false` from [`wasmtime::ResourceLimiter::memory_growing`] into a failed
//! `memory.grow` inside the component, which the component may then turn into a trap. That trap
//! arrives at the call site looking like any other, so without a record the host could not tell a
//! component that divided by zero from one that asked for a gigabyte. The recorded refusal is what
//! names the second case in the disabled reason a person reads.
//!
//! A refusal is recorded only when *this host's* bound was the reason. A module whose own declared
//! maximum is smaller is refused by that maximum, and saying "over its bound of 67108864" about it
//! would be a lie.

use kr_plugin_sdk::limits::{INSTANCE_MEMORY_BYTES, InstanceLimits};

use crate::runtime::error::RuntimeError;

/// How many tables one instance may create.
///
/// A component of this shape needs one function table per instantiated core module. The bound is
/// generous for that and far below what an allocation loop would want.
pub const MAX_TABLES: usize = 32;

/// How many linear memories one instance may create.
pub const MAX_MEMORIES: usize = 8;

/// How many core instances one component instance may create.
pub const MAX_INSTANCES: usize = 64;

/// How many elements one table may hold.
pub const MAX_TABLE_ELEMENTS: usize = 100_000;

/// How many elements every table of one instance may hold between them.
///
/// The same reasoning as the memory bound: a per-table limit that thirty-two tables each reached
/// would be no limit at all.
pub const MAX_TOTAL_TABLE_ELEMENTS: usize = 400_000;

/// Which bound a component ran into.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefusedResource {
    /// Linear memory, in bytes, across every memory of the instance.
    LinearMemory,
    /// Table elements, across every table of the instance.
    TableElements,
}

impl RefusedResource {
    /// Returns the name used in the failure a person reads.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LinearMemory => "linear memory",
            Self::TableElements => "table elements",
        }
    }
}

/// The bounds one component instance runs under.
///
/// One limiter per store, so the totals it tracks are one instance's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InstanceLimiter {
    memory_bytes: u64,
    max_tables: usize,
    max_memories: usize,
    max_instances: usize,
    max_table_elements: usize,
    max_total_table_elements: usize,
    /// The sum of every linear memory's current size.
    allocated_bytes: u64,
    /// The sum of every table's current length.
    allocated_elements: usize,
    refused: Option<RefusedResource>,
}

impl InstanceLimiter {
    /// Builds the limiter with the section 11 defaults.
    #[must_use]
    pub const fn defaults() -> Self {
        Self {
            memory_bytes: INSTANCE_MEMORY_BYTES,
            max_tables: MAX_TABLES,
            max_memories: MAX_MEMORIES,
            max_instances: MAX_INSTANCES,
            max_table_elements: MAX_TABLE_ELEMENTS,
            max_total_table_elements: MAX_TOTAL_TABLE_ELEMENTS,
            allocated_bytes: 0,
            allocated_elements: 0,
            refused: None,
        }
    }

    /// Builds the limiter from a declared set of limits.
    #[must_use]
    pub const fn from_limits(limits: &InstanceLimits) -> Self {
        let mut limiter = Self::defaults();
        limiter.memory_bytes = limits.memory_bytes.get();
        limiter
    }

    /// Returns the linear memory bound in bytes, across every memory of the instance.
    #[must_use]
    pub const fn memory_bytes(&self) -> u64 {
        self.memory_bytes
    }

    /// Returns how many bytes of linear memory the instance holds.
    #[must_use]
    pub const fn allocated_bytes(&self) -> u64 {
        self.allocated_bytes
    }

    /// Returns the resource a refused allocation asked for, if one was refused.
    #[must_use]
    pub const fn refused(&self) -> Option<RefusedResource> {
        self.refused
    }

    /// Forgets any refusal, ready for the next call.
    ///
    /// The totals are not forgotten: they are the instance's, not the call's.
    pub const fn clear_refusal(&mut self) {
        self.refused = None;
    }

    /// Returns the failure a refused allocation should be reported as, if there was one.
    #[must_use]
    pub const fn refusal(&self) -> Option<RuntimeError> {
        match self.refused {
            Some(RefusedResource::LinearMemory) => Some(RuntimeError::ResourceRefused {
                resource: RefusedResource::LinearMemory.as_str(),
                limit: self.memory_bytes,
            }),
            Some(RefusedResource::TableElements) => Some(RuntimeError::ResourceRefused {
                resource: RefusedResource::TableElements.as_str(),
                limit: self.max_total_table_elements as u64,
            }),
            None => None,
        }
    }
}

impl Default for InstanceLimiter {
    fn default() -> Self {
        Self::defaults()
    }
}

impl wasmtime::ResourceLimiter for InstanceLimiter {
    fn memory_growing(
        &mut self,
        current: usize,
        desired: usize,
        maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        // `current` is this memory's size and `desired` is what it wants to become, so the total
        // after the growth is the instance's total with this memory's contribution replaced.
        let Ok(current) = u64::try_from(current) else {
            self.refused = Some(RefusedResource::LinearMemory);
            return Ok(false);
        };
        let Ok(desired) = u64::try_from(desired) else {
            self.refused = Some(RefusedResource::LinearMemory);
            return Ok(false);
        };
        let total = self
            .allocated_bytes
            .saturating_sub(current)
            .saturating_add(desired);
        if total > self.memory_bytes {
            self.refused = Some(RefusedResource::LinearMemory);
            return Ok(false);
        }
        // A module's own declared maximum is the module's business. Refusing on it is right, and
        // recording it as this host's bound would misname the reason.
        if maximum.is_some_and(|maximum| u64::try_from(maximum).is_ok_and(|max| desired > max)) {
            return Ok(false);
        }
        self.allocated_bytes = total;
        Ok(true)
    }

    fn table_growing(
        &mut self,
        current: usize,
        desired: usize,
        maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        let total = self
            .allocated_elements
            .saturating_sub(current)
            .saturating_add(desired);
        if desired > self.max_table_elements || total > self.max_total_table_elements {
            self.refused = Some(RefusedResource::TableElements);
            return Ok(false);
        }
        if maximum.is_some_and(|maximum| desired > maximum) {
            return Ok(false);
        }
        self.allocated_elements = total;
        Ok(true)
    }

    fn instances(&self) -> usize {
        self.max_instances
    }

    fn tables(&self) -> usize {
        self.max_tables
    }

    fn memories(&self) -> usize {
        self.max_memories
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasmtime::ResourceLimiter as _;

    #[test]
    fn the_memory_bound_is_the_specified_sixty_four_mebibytes() {
        let limiter = InstanceLimiter::defaults();
        assert_eq!(limiter.memory_bytes(), 67_108_864);
        assert_eq!(
            InstanceLimiter::from_limits(&InstanceLimits::defaults()).memory_bytes(),
            67_108_864
        );
    }

    #[test]
    fn growth_up_to_the_bound_is_allowed_and_past_it_is_refused() {
        let mut limiter = InstanceLimiter::defaults();
        assert!(
            limiter
                .memory_growing(0, 64 * 1024 * 1024, None)
                .expect("the limiter answers")
        );
        assert!(limiter.refused().is_none());
        assert_eq!(limiter.allocated_bytes(), 64 * 1024 * 1024);

        assert!(
            !limiter
                .memory_growing(64 * 1024 * 1024, 64 * 1024 * 1024 + 1, None)
                .expect("the limiter answers")
        );
        assert_eq!(limiter.refused(), Some(RefusedResource::LinearMemory));
        assert!(matches!(
            limiter.refusal(),
            Some(RuntimeError::ResourceRefused {
                resource: "linear memory",
                limit: 67_108_864
            })
        ));

        limiter.clear_refusal();
        assert!(limiter.refused().is_none());
        // Clearing a refusal does not forget what the instance holds.
        assert_eq!(limiter.allocated_bytes(), 64 * 1024 * 1024);
    }

    #[test]
    fn the_bound_is_the_instances_total_and_not_one_memory_at_a_time() {
        let mut limiter = InstanceLimiter::defaults();
        let forty = 40 * 1024 * 1024;
        // Each of these is inside the 64 MiB bound on its own. Together they are not.
        assert!(
            limiter
                .memory_growing(0, forty, None)
                .expect("the limiter answers")
        );
        assert!(
            !limiter
                .memory_growing(0, forty, None)
                .expect("the limiter answers"),
            "two 40 MiB memories were admitted against a 64 MiB bound"
        );
        assert_eq!(limiter.refused(), Some(RefusedResource::LinearMemory));
        assert_eq!(limiter.allocated_bytes(), forty as u64);

        // A second memory that fits in what is left is admitted.
        limiter.clear_refusal();
        assert!(
            limiter
                .memory_growing(0, 20 * 1024 * 1024, None)
                .expect("the limiter answers")
        );
        assert_eq!(limiter.allocated_bytes(), 60 * 1024 * 1024);
    }

    #[test]
    fn a_refused_growth_is_not_counted_against_the_total() {
        let mut limiter = InstanceLimiter::defaults();
        let bound = 64 * 1024 * 1024;
        assert!(
            !limiter
                .memory_growing(0, bound + 1, None)
                .expect("the limiter answers")
        );
        assert_eq!(limiter.allocated_bytes(), 0);
        limiter.clear_refusal();
        // The whole bound is still available, because nothing was allocated.
        assert!(
            limiter
                .memory_growing(0, bound, None)
                .expect("the limiter answers")
        );
    }

    #[test]
    fn a_growing_memory_replaces_its_own_contribution_rather_than_adding_to_it() {
        let mut limiter = InstanceLimiter::defaults();
        let step = 8 * 1024 * 1024;
        let mut size = 0;
        for _ in 0..8 {
            let next = size + step;
            assert!(
                limiter
                    .memory_growing(size, next, None)
                    .expect("the limiter answers"),
                "one memory growing to {next} was refused"
            );
            size = next;
        }
        assert_eq!(limiter.allocated_bytes(), 64 * 1024 * 1024);
        assert!(
            !limiter
                .memory_growing(size, size + 1, None)
                .expect("the limiter answers")
        );
    }

    #[test]
    fn a_table_past_its_bound_is_refused_and_named() {
        let mut limiter = InstanceLimiter::defaults();
        assert!(
            limiter
                .table_growing(0, MAX_TABLE_ELEMENTS, None)
                .expect("the limiter answers")
        );
        assert!(
            !limiter
                .table_growing(0, MAX_TABLE_ELEMENTS + 1, None)
                .expect("the limiter answers")
        );
        assert_eq!(limiter.refused(), Some(RefusedResource::TableElements));
        assert!(
            limiter
                .refusal()
                .expect("a refusal")
                .to_string()
                .contains("table elements")
        );
    }

    #[test]
    fn the_table_bound_is_the_instances_total_as_well() {
        let mut limiter = InstanceLimiter::defaults();
        for index in 0..4 {
            assert!(
                limiter
                    .table_growing(0, MAX_TABLE_ELEMENTS, None)
                    .expect("the limiter answers"),
                "table {index} was refused"
            );
        }
        assert!(
            !limiter
                .table_growing(0, 1, None)
                .expect("the limiter answers"),
            "a fifth full table was admitted past the instance's total"
        );
    }

    #[test]
    fn the_counts_are_bounded_as_well_as_the_bytes() {
        let limiter = InstanceLimiter::defaults();
        assert_eq!(limiter.tables(), MAX_TABLES);
        assert_eq!(limiter.memories(), MAX_MEMORIES);
        assert_eq!(limiter.instances(), MAX_INSTANCES);
    }

    #[test]
    fn a_modules_own_maximum_is_refused_without_being_blamed_on_this_hosts_bound() {
        let mut limiter = InstanceLimiter::defaults();
        assert!(
            !limiter
                .memory_growing(0, 1024, Some(512))
                .expect("the limiter answers")
        );
        // The refusal was the module's own declared maximum, so nothing is recorded against the
        // 64 MiB bound: a failure that said "over its bound of 67108864" would be untrue.
        assert!(limiter.refused().is_none());
        assert!(limiter.refusal().is_none());
        assert_eq!(limiter.allocated_bytes(), 0);
    }
}
