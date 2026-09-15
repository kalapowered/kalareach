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
    /// The host answered with an error.
    #[error("{}: {}", .0.code.as_str(), .0.message)]
    Host(ProtocolError),
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
    /// The host has not issued an action window for this connection.
    #[error("no action window is current")]
    NoActionWindow,
    /// The connection ended before the request was answered.
    #[error("the connection ended before the request was answered")]
    ConnectionEnded,
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
            Self::Host(error) => error.code,
            Self::Transport(error) => error.to_protocol_error().code,
            Self::Cbor(_) | Self::WrongEffect { .. } => ErrorCode::InvalidArgument,
            Self::UnsupportedVersion { .. } => ErrorCode::UnsupportedSchema,
            Self::TooManyOutstandingMutations { .. } | Self::NoActionWindow => {
                ErrorCode::ResourceUnavailable
            }
            Self::ConnectionEnded => ErrorCode::ResourceUnavailable,
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
