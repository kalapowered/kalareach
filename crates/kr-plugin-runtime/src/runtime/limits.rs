//! The per-instance resource bounds, and what a refused allocation is recorded as.
//!
//! Linear memory is the bound section 11 names: 64 MiB per instance. The table, memory and
//! instance counts are bounded too, because a component that cannot grow its memory can still ask
//! for a thousand tables, and a bound that only covered bytes would let it.
//!
//! A refusal is recorded rather than only returned. Wasmtime turns a `false` from
//! [`wasmtime::ResourceLimiter::memory_growing`] into a trap inside the component, which arrives at
//! the call site as an ordinary trap; without a record the host could not tell a component that
//! divided by zero from one that asked for a gigabyte. The recorded refusal is what names the
//! second case in the disabled reason a person reads.

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

/// Which bound a component ran into.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefusedResource {
    /// Linear memory, in bytes.
    LinearMemory,
    /// Table elements.
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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InstanceLimiter {
    memory_bytes: u64,
    max_tables: usize,
    max_memories: usize,
    max_instances: usize,
    max_table_elements: usize,
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
            refused: None,
        }
    }

    /// Builds the limiter from a declared set of limits.
    #[must_use]
    pub const fn from_limits(limits: &InstanceLimits) -> Self {
        Self {
            memory_bytes: limits.memory_bytes.get(),
            max_tables: MAX_TABLES,
            max_memories: MAX_MEMORIES,
            max_instances: MAX_INSTANCES,
            max_table_elements: MAX_TABLE_ELEMENTS,
            refused: None,
        }
    }

    /// Returns the linear memory bound in bytes.
    #[must_use]
    pub const fn memory_bytes(&self) -> u64 {
        self.memory_bytes
    }

    /// Returns the resource a refused allocation asked for, if one was refused.
    #[must_use]
    pub const fn refused(&self) -> Option<RefusedResource> {
        self.refused
    }

    /// Forgets any refusal, ready for the next call.
    pub fn clear_refusal(&mut self) {
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
                limit: self.max_table_elements as u64,
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
        _current: usize,
        desired: usize,
        maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        let allowed = u64::try_from(desired).is_ok_and(|desired| desired <= self.memory_bytes)
            && maximum.is_none_or(|maximum| desired <= maximum);
        if !allowed {
            self.refused = Some(RefusedResource::LinearMemory);
        }
        Ok(allowed)
    }

    fn table_growing(
        &mut self,
        _current: usize,
        desired: usize,
        maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        let allowed =
            desired <= self.max_table_elements && maximum.is_none_or(|maximum| desired <= maximum);
        if !allowed {
            self.refused = Some(RefusedResource::TableElements);
        }
        Ok(allowed)
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
    fn the_counts_are_bounded_as_well_as_the_bytes() {
        let limiter = InstanceLimiter::defaults();
        assert_eq!(limiter.tables(), MAX_TABLES);
        assert_eq!(limiter.memories(), MAX_MEMORIES);
        assert_eq!(limiter.instances(), MAX_INSTANCES);
    }

    #[test]
    fn an_engine_declared_maximum_below_the_bound_still_applies() {
        let mut limiter = InstanceLimiter::defaults();
        assert!(
            !limiter
                .memory_growing(0, 1024, Some(512))
                .expect("the limiter answers")
        );
        assert_eq!(limiter.refused(), Some(RefusedResource::LinearMemory));
    }
}
