//! What can go wrong for a client.

use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::method::{Method, MethodVersion};

/// A client failure.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ClientError {
    /// The transport failed.
    #[error("{0}")]
    Transport(#[from] kr_transport::TransportError),
    /// The local socket or named pipe failed.
    #[error("{0}")]
    Ipc(#[from] kr_ipc::IpcError),
    /// The host answered with an error.
    #[error("{}: {}", .0.code.as_str(), .0.message)]
    Host(ProtocolError),
    /// A managed service refused the request, and said when the same one could be sent again.
    ///
    /// The refusal is the protocol error a caller branches on; the delay is what the service asked
    /// for, in seconds. It is separate from [`Self::Host`] because honouring it is the difference
    /// between backing off and being refused again, and a delay inside a message is a delay nothing
    /// can act on.
    #[error("{}: {} (retry after {retry_after_seconds}s)", .error.code.as_str(), .error.message)]
    Refused {
        /// What the service said was wrong.
        error: ProtocolError,
        /// Seconds to wait before sending the same request again.
        retry_after_seconds: u64,
    },
    /// A value could not be encoded or decoded as KR-CBOR-1.
    #[error("the message was not canonical: {0}")]
    Cbor(#[from] kr_cbor::CborError),
    /// The method's registry entry forbids this call shape.
    #[error("{method} is a {expected} and cannot be called as a {actual}")]
    WrongEffect {
        /// The method that was called.
        method: Method,
        /// What the registry says it is.
        expected: &'static str,
        /// How it was called.
        actual: &'static str,
    },
    /// This build does not implement the method at that version.
    #[error("{method} is version {supported}, not {requested}")]
    UnsupportedVersion {
        /// The method that was called.
        method: Method,
        /// The version this build implements.
        supported: MethodVersion,
        /// The version that was asked for.
        requested: MethodVersion,
    },
    /// The connection already has as many outstanding mutations as it is allowed.
    #[error("{limit} mutations are already outstanding")]
    TooManyOutstandingMutations {
        /// The negotiated bound.
        limit: usize,
    },
    /// This client already holds as many unresolved actions as it will track.
    ///
    /// An unresolved action is never forgotten, so a client that cannot reach its host eventually
    /// stops submitting rather than accumulating uncertainty without bound.
    #[error("{limit} actions are already unresolved")]
    TooManyUnresolvedActions {
        /// The bound.
        limit: usize,
    },
    /// The host has not issued an action window for this connection.
    #[error("no action window is current")]
    NoActionWindow,
    /// The connection ended before the request was answered.
    #[error("the connection ended before the request was answered")]
    ConnectionEnded,
    /// The connection ended after a mutation was sent, so its outcome is unknown.
    ///
    /// The action identifier is named because section 9 forbids dispatching it again: the client
    /// asks the host what became of this action, and shows the user that the outcome is uncertain.
    /// It never submits the same intent under a new identifier to find out.
    #[error("the outcome of action {action_id} is unknown: the connection ended after it was sent")]
    SubmissionUncertain {
        /// The action whose outcome is unknown.
        action_id: kr_protocol::ids::ActionId,
    },
    /// The host requires a fresh snapshot before it will serve this stream again.
    #[error("the host requires a resynchronisation")]
    ResyncRequired,
    /// No implementation of a managed service is configured.
    #[error("no managed service is configured for {0}")]
    ServiceNotConfigured(&'static str),
}

impl ClientError {
    /// Returns the stable code a caller reacts to.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::Host(error) | Self::Refused { error, .. } => error.code,
            Self::Transport(error) => error.to_protocol_error().code,
            Self::Ipc(error) => error.to_protocol_error().code,
            Self::Cbor(_) | Self::WrongEffect { .. } => ErrorCode::InvalidArgument,
            Self::UnsupportedVersion { .. } => ErrorCode::UnsupportedSchema,
            Self::TooManyOutstandingMutations { .. }
            | Self::TooManyUnresolvedActions { .. }
            | Self::NoActionWindow => ErrorCode::ResourceUnavailable,
            Self::ConnectionEnded => ErrorCode::ResourceUnavailable,
            Self::SubmissionUncertain { .. } => ErrorCode::OutcomeUnknown,
            Self::ResyncRequired => ErrorCode::ResyncRequired,
            Self::ServiceNotConfigured(_) => ErrorCode::HostNotConfigured,
        }
    }
}

impl From<ProtocolError> for ClientError {
    fn from(error: ProtocolError) -> Self {
        if error.code == ErrorCode::ResyncRequired {
            Self::ResyncRequired
        } else {
            Self::Host(error)
        }
    }
}

/// The result of a client operation.
pub type Result<T> = std::result::Result<T, ClientError>;
