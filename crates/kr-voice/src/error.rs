//! What the coordinator refuses, and the one protocol code each refusal becomes.

use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::voice::VoiceRefusal;

/// The result type of this crate.
pub type Result<T> = std::result::Result<T, VoiceError>;

/// Why the coordinator would not do something.
#[derive(Debug, thiserror::Error)]
pub enum VoiceError {
    /// A rule of section 15 refused a delegation or a context request.
    ///
    /// The reason is the one the paired client is told, and the sentence says what is missing
    /// rather than only that something was.
    #[error("{detail}")]
    Refused {
        /// Which rule refused it.
        reason: VoiceRefusal,
        /// What is missing, in a sentence a person can act on.
        detail: String,
    },
    /// The request was not one this coordinator serves.
    #[error("{0}")]
    InvalidArgument(String),
    /// This host has no managed voice service configured.
    #[error("{0}")]
    NotConfigured(String),
    /// The host's own side of a seam failed.
    #[error("{0}")]
    Host(ProtocolError),
    /// A signature could not be made or checked.
    #[error("{0}")]
    Crypto(#[from] kr_crypto::CryptoError),
    /// A value could not be encoded as KR-CBOR-1.
    #[error("{0}")]
    Cbor(#[from] kr_cbor::CborError),
    /// The managed broker could not be reached, or answered something unreadable.
    #[error("{0}")]
    Broker(#[from] kr_client::error::ClientError),
}

impl VoiceError {
    /// Builds a refusal.
    #[must_use]
    pub fn refused(reason: VoiceRefusal, detail: impl Into<String>) -> Self {
        Self::Refused {
            reason,
            detail: detail.into(),
        }
    }

    /// The stable protocol code this refusal becomes.
    ///
    /// Every rule of section 15 ¶13 answers `PERMISSION_DENIED`: which grant this host holds, and
    /// which confirmations it has issued, is not something a refused caller is told.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::Refused { .. } => ErrorCode::PermissionDenied,
            Self::InvalidArgument(_) | Self::Cbor(_) => ErrorCode::InvalidArgument,
            Self::NotConfigured(_) => ErrorCode::HostNotConfigured,
            Self::Host(error) => error.code,
            Self::Crypto(_) => ErrorCode::PermissionDenied,
            Self::Broker(error) => error.code(),
        }
    }

    /// The protocol error a caller receives.
    #[must_use]
    pub fn to_protocol_error(&self) -> ProtocolError {
        ProtocolError::new(self.code(), self.to_string())
    }

    /// The refusal reason, when this was one.
    #[must_use]
    pub const fn reason(&self) -> Option<VoiceRefusal> {
        match self {
            Self::Refused { reason, .. } => Some(*reason),
            _ => None,
        }
    }
}
