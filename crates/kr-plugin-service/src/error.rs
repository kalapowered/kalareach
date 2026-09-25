//! What the client reports when a request does not come back with what it asked for.
//!
//! The host is out of reach; the binding the request named is disabled; the host refused, or
//! answered with something this client cannot read; or the caller's deadline passed first. A call
//! that entered a component and came back with the component's declared fault has been answered,
//! and is none of these.

/// The result of a client operation.
pub type ServiceResult<T> = Result<T, ServiceError>;

/// A request to the plugin host that did not come back with what it asked for.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ServiceError {
    /// The plugin-host process is unreachable.
    #[error("the plugin runtime service is unavailable: {detail}")]
    Unavailable {
        /// What the connection reported.
        detail: String,
    },
    /// The binding is disabled and accepts no more calls.
    #[error("the binding is disabled: {reason}")]
    Disabled {
        /// Why it was disabled, in the words a person is shown.
        reason: String,
    },
    /// The service refused, or answered something this client cannot read.
    #[error("the plugin runtime service answered with {detail}")]
    Protocol {
        /// The refusal, or what was wrong with the answer.
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
