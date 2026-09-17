//! What can go wrong while running a component, and what each failure means for the binding.
//!
//! The distinction that matters here is between a component *answering* and a component *failing*.
//! A component that returns `Fault::Refused` has answered: it read the input and declined. That is
//! not a fault against the binding and never counts towards disabling it. A component that traps,
//! runs past its deadline, exhausts its fuel, asks for memory beyond its bound or returns more
//! output than one call may produce has failed, and three such failures within a minute disable
//! the binding with the reason named here.
//!
//! Compilation is deliberately outside that count. Section 11 says a cold compile must not look
//! like a slow observation, so [`RuntimeError::CompilationTooSlow`] and
//! [`RuntimeError::CompilationPressure`] are reported to the caller and never counted as faults.

use std::fmt;

use kr_plugin_sdk::ids::PluginName;

/// The result of a runtime operation.
pub type RuntimeResult<T> = Result<T, RuntimeError>;

/// Which bound stopped a call.
///
/// Fuel and elapsed time are separate bounds and are never reported as each other. Fuel bounds the
/// work a call may do; it is not a measurement of processor time, and a call that ran out of fuel
/// is never described as having taken a duration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExhaustedBound {
    /// The call used its whole instruction allowance.
    Fuel,
    /// The call was still running at its elapsed deadline.
    Deadline,
}

impl ExhaustedBound {
    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fuel => "fuel",
            Self::Deadline => "deadline",
        }
    }
}

impl fmt::Display for ExhaustedBound {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A failure of the component runtime.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RuntimeError {
    /// The engine could not be configured or built.
    #[error("the component engine could not be built: {detail}")]
    Engine {
        /// What the engine reported.
        detail: String,
    },
    /// The component imports something outside the plugin interface.
    ///
    /// The name is in the message because "this component wants more than the sandbox offers" is
    /// not a usable answer to a publisher or to a person reading a disabled reason.
    #[error(
        "the component imports {import}, which is not one of the four plugin host interfaces; a component has no filesystem, network, process, environment, clock or random access"
    )]
    ForbiddenImport {
        /// The import the component asked for.
        import: String,
    },
    /// The component does not export what the plugin world requires.
    #[error("the component does not implement {missing}")]
    MissingExport {
        /// The export that is absent.
        missing: String,
    },
    /// The Wasm did not validate, or is not a component at all.
    #[error("the component did not validate: {detail}")]
    InvalidComponent {
        /// What validation reported.
        detail: String,
    },
    /// The component is larger than this host will compile.
    #[error("the component is {bytes} bytes, over the {limit} byte compilation bound")]
    ComponentTooLarge {
        /// The component's size.
        bytes: u64,
        /// The bound.
        limit: u64,
    },
    /// Compilation finished outside its budget, so its result was discarded.
    #[error("compiling the component took {elapsed_ms} ms, over its {budget_ms} ms budget")]
    CompilationTooSlow {
        /// How long the compile took.
        elapsed_ms: u64,
        /// The budget it was given.
        budget_ms: u64,
    },
    /// Every compilation slot is busy and the queue is full.
    #[error("the compilation queue is full at {queued} waiting components")]
    CompilationPressure {
        /// How many components are already waiting.
        queued: usize,
    },
    /// A cached artefact was refused.
    #[error("the compiled-code cache entry was refused: {detail}")]
    CacheRefused {
        /// Why it was refused.
        detail: String,
    },
    /// The cache directory could not be used.
    #[error("the compiled-code cache at {path} is unusable: {detail}")]
    CacheUnusable {
        /// The directory.
        path: String,
        /// What the filesystem reported.
        detail: String,
    },
    /// The instance could not be created.
    #[error("the component could not be instantiated: {detail}")]
    Instantiation {
        /// What instantiation reported.
        detail: String,
    },
    /// The component trapped.
    #[error("the component trapped during {call}: {detail}")]
    Trap {
        /// Which export was running.
        call: &'static str,
        /// The trap, as the engine described it.
        detail: String,
    },
    /// The call used up one of its bounds.
    #[error("{call} used its whole {bound} allowance")]
    Exhausted {
        /// Which export was running.
        call: &'static str,
        /// Which bound ran out.
        bound: ExhaustedBound,
    },
    /// The component asked for more linear memory, tables or instances than its bound allows.
    #[error("the component asked for more {resource} than its bound of {limit} allows")]
    ResourceRefused {
        /// The resource it asked for.
        resource: &'static str,
        /// The bound.
        limit: u64,
    },
    /// The call produced more output than one call may produce.
    #[error("{call} produced more than the {limit} byte output budget for one call")]
    OutputBudget {
        /// Which export was running.
        call: &'static str,
        /// The budget.
        limit: u64,
    },
    /// One emitted node is larger than a node may be.
    #[error("a document node of {bytes} bytes is over the {limit} byte bound for one node")]
    NodeTooLarge {
        /// The node's size.
        bytes: u64,
        /// The bound.
        limit: u64,
    },
    /// The binding is disabled and accepts no more calls.
    #[error("the binding is disabled: {reason}")]
    Disabled {
        /// Why it was disabled, in the words a person is shown.
        reason: String,
    },
    /// The binding does not exist, or no longer does.
    #[error("no binding {binding} is registered")]
    NoSuchBinding {
        /// The binding that was asked for.
        binding: String,
    },
    /// The component was handed a source-event handle it was not given.
    ///
    /// A component cannot construct a handle, so this is the host refusing a handle that belongs
    /// to another call, another binding or another generation.
    #[error("the source event handle is not one this call was given")]
    UnscopedHandle,
    /// The plugin-host process is unreachable.
    #[error("the plugin runtime service is unavailable: {detail}")]
    ServiceUnavailable {
        /// What the connection reported.
        detail: String,
    },
    /// The service answered something this client cannot read.
    #[error("the plugin runtime service answered with {detail}")]
    ServiceProtocol {
        /// What was wrong with the answer.
        detail: String,
    },
    /// A call did not answer inside the deadline the caller set.
    ///
    /// This is the caller's own deadline, not the component's. It exists so that nothing on the
    /// terminal path ever waits on a component: the caller gets this answer and carries on.
    #[error("the call did not answer within {deadline_ms} ms")]
    CallerDeadline {
        /// The deadline the caller set.
        deadline_ms: u64,
    },
}

impl RuntimeError {
    /// Returns true when this failure counts towards disabling the binding.
    ///
    /// Compilation failures do not. Section 11 requires that a cold compile cannot look like a
    /// slow observation, and a component that is slow to compile has not misbehaved at run time.
    /// Nor does a caller's own deadline: that measures the caller's patience, not the component.
    #[must_use]
    pub const fn counts_as_fault(&self) -> bool {
        matches!(
            self,
            Self::Trap { .. }
                | Self::Exhausted { .. }
                | Self::ResourceRefused { .. }
                | Self::OutputBudget { .. }
                | Self::NodeTooLarge { .. }
                | Self::UnscopedHandle
                | Self::Instantiation { .. }
        )
    }

    /// Renders the failure as a disabled reason a person reads.
    #[must_use]
    pub fn disabled_reason(&self, plugin: &PluginName) -> String {
        format!("{plugin} stopped responding correctly: {self}")
    }

    /// Wraps an engine failure.
    pub(crate) fn engine(detail: impl fmt::Display) -> Self {
        Self::Engine {
            detail: detail.to_string(),
        }
    }

    /// Wraps an instantiation failure.
    pub(crate) fn instantiation(detail: impl fmt::Display) -> Self {
        Self::Instantiation {
            detail: detail.to_string(),
        }
    }

    /// Wraps a cache refusal.
    pub(crate) fn cache_refused(detail: impl fmt::Display) -> Self {
        Self::CacheRefused {
            detail: detail.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_slow_compile_is_not_a_fault_against_the_binding() {
        let slow = RuntimeError::CompilationTooSlow {
            elapsed_ms: 40_000,
            budget_ms: 30_000,
        };
        assert!(!slow.counts_as_fault());
        assert!(!RuntimeError::CompilationPressure { queued: 8 }.counts_as_fault());
        assert!(!RuntimeError::CallerDeadline { deadline_ms: 10 }.counts_as_fault());
    }

    #[test]
    fn a_trap_a_deadline_and_a_refused_allocation_are_faults() {
        assert!(
            RuntimeError::Trap {
                call: "observe",
                detail: "unreachable".to_owned(),
            }
            .counts_as_fault()
        );
        assert!(
            RuntimeError::Exhausted {
                call: "observe",
                bound: ExhaustedBound::Deadline,
            }
            .counts_as_fault()
        );
        assert!(
            RuntimeError::ResourceRefused {
                resource: "linear memory",
                limit: 67_108_864,
            }
            .counts_as_fault()
        );
    }

    #[test]
    fn exhausting_fuel_is_never_described_as_elapsed_time() {
        let fuel = RuntimeError::Exhausted {
            call: "observe",
            bound: ExhaustedBound::Fuel,
        }
        .to_string();
        assert!(fuel.contains("fuel"));
        for word in ["ms", "millisecond", "second", "cpu", "processor", "time"] {
            assert!(
                !fuel.to_lowercase().contains(word),
                "a fuel exhaustion mentioned {word}"
            );
        }
    }

    #[test]
    fn a_forbidden_import_names_itself() {
        let error = RuntimeError::ForbiddenImport {
            import: "wasi:filesystem/types@0.2.9".to_owned(),
        };
        assert!(error.to_string().contains("wasi:filesystem/types@0.2.9"));
    }
}
