//! What the host side of the bridge can fail at.

use kr_protocol::error::{ErrorCode, ProtocolError};

use crate::contract::qualification::QualificationReason;

/// A failure on the worker's side of the root-editor contract.
#[derive(Debug, thiserror::Error)]
pub enum HostError {
    /// The directory the endpoint would live in is not owner-only, or is not a directory at all.
    #[error("the bridge directory {path} is not an owner-only directory: {detail}")]
    Directory {
        /// The directory.
        path: String,
        /// What is wrong with it.
        detail: String,
    },
    /// The endpoint path itself cannot be used.
    #[error("the bridge endpoint cannot be used: {0}")]
    Endpoint(#[from] crate::contract::transport::EndpointFault),
    /// The local endpoint could not be created or served.
    #[error("the bridge endpoint failed: {0}")]
    Ipc(#[from] kr_ipc::IpcError),
    /// A secret could not be generated, or a proof could not be computed.
    #[error("the bridge handshake failed: {0}")]
    Crypto(#[from] kr_crypto::CryptoError),
    /// A frame could not be encoded or decoded canonically.
    #[error("a bridge frame is not canonical: {0}")]
    Frame(#[from] kr_cbor::CborError),
    /// The bridge sent a frame its role does not send.
    #[error("the bridge sent a frame it does not send: {frame}")]
    WrongDirection {
        /// The frame's variant name.
        frame: &'static str,
    },
    /// The bridge was refused registration.
    #[error("the bridge was refused: {}", .0.as_str())]
    Refused(QualificationReason),
    /// A root method arrived from something that is not this session's registered root integration.
    #[error("{method} is reachable only from this session's validated root registration")]
    NotRootIntegration {
        /// The method that was refused.
        method: &'static str,
    },
}

impl HostError {
    /// Returns the stable protocol code this failure is reported with.
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        match self {
            Self::Refused(reason) => reason.code(),
            Self::NotRootIntegration { .. } => ErrorCode::PermissionDenied,
            Self::Directory { .. } | Self::Ipc(_) | Self::Crypto(_) => {
                ErrorCode::ResourceUnavailable
            }
            Self::Endpoint(_) | Self::Frame(_) | Self::WrongDirection { .. } => {
                ErrorCode::InvalidArgument
            }
        }
    }

    /// Returns this failure as a protocol error.
    #[must_use]
    pub fn to_protocol_error(&self) -> ProtocolError {
        ProtocolError::new(self.code(), self.to_string())
    }
}

/// The host side's result type.
pub type Result<T> = std::result::Result<T, HostError>;
