//! What can go wrong on a KalaReach connection.

use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::frame::FrameError;

/// A transport failure.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TransportError {
    /// The configuration names a service the endpoint cannot be built from.
    #[error("{what} is not a usable {kind}: {reason}")]
    Configuration {
        /// The configured value.
        what: String,
        /// What it was meant to be.
        kind: &'static str,
        /// Why it was refused.
        reason: String,
    },
    /// The endpoint could not be bound.
    #[error("the iroh endpoint could not be bound: {0}")]
    Bind(String),
    /// A connection could not be established.
    #[error("the connection could not be established: {0}")]
    Connect(String),
    /// A stream could not be opened or accepted.
    #[error("the stream failed: {0}")]
    Stream(String),
    /// The peer closed the connection.
    #[error("the peer closed the connection: {0}")]
    Closed(String),
    /// A frame was malformed or exceeded its stream kind's bound.
    #[error("the frame was refused: {0}")]
    Frame(#[from] FrameError),
    /// A value could not be encoded or decoded as KR-CBOR-1.
    #[error("the message was not canonical: {0}")]
    Cbor(#[from] kr_cbor::CborError),
    /// The handshake failed. The peer receives the protocol error; this side keeps the detail.
    #[error("the handshake failed: {0}")]
    Handshake(ProtocolError),
    /// A cryptographic check failed.
    #[error("the connection proof failed: {0}")]
    Crypto(#[from] kr_crypto::CryptoError),
    /// The peer did not answer inside the inactivity threshold.
    #[error("the peer was silent for longer than the inactivity threshold")]
    Inactive,
    /// A limit this connection agreed to was exceeded.
    #[error("{what} exceeds its limit of {limit}")]
    LimitExceeded {
        /// The limit that was hit.
        what: &'static str,
        /// The configured bound.
        limit: usize,
    },
    /// The control stream ended, so every stream it authorised is revoked.
    #[error("the control stream ended, revoking every associated data stream")]
    ControlLost,
}

impl TransportError {
    /// Builds the handshake failure a peer is told about.
    #[must_use]
    pub fn handshake(code: ErrorCode, message: impl Into<String>) -> Self {
        Self::Handshake(ProtocolError::new(code, message))
    }

    /// Returns the protocol error to send to the peer.
    ///
    /// Every failure maps to a stable code, so a peer never has to read a message to decide what
    /// to do. Detail that would only help an attacker stays on this side of the connection.
    #[must_use]
    pub fn to_protocol_error(&self) -> ProtocolError {
        match self {
            Self::Handshake(error) => error.clone(),
            Self::Configuration { .. } | Self::Bind(_) => {
                ProtocolError::new(ErrorCode::HostNotConfigured, "the host is not configured")
            }
            Self::Connect(_) | Self::Closed(_) | Self::Stream(_) | Self::ControlLost => {
                ProtocolError::new(ErrorCode::ResourceUnavailable, "the connection ended")
            }
            Self::Frame(error) => ProtocolError::new(error.code(), "the message was refused"),
            Self::Cbor(error) => ProtocolError::new(
                kr_protocol::wire::refusal_code(error),
                "the message was refused",
            ),
            Self::Crypto(_) => ProtocolError::new(
                ErrorCode::PermissionDenied,
                "the connection proof was refused",
            ),
            Self::Inactive => ProtocolError::new(
                ErrorCode::ResourceUnavailable,
                "the transport is unavailable",
            ),
            Self::LimitExceeded { .. } => {
                ProtocolError::new(ErrorCode::ResourceUnavailable, "a connection limit was hit")
            }
        }
    }
}

/// The result of a transport operation.
pub type Result<T> = std::result::Result<T, TransportError>;
