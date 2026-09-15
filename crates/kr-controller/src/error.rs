//! What the control daemon can fail with, and the protocol code each failure is reported under.

use kr_protocol::error::{ErrorCode, ProtocolError};

/// A control-daemon failure.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ControllerError {
    /// The registry could not be read or written.
    #[error("the environment registry is unavailable: {detail}")]
    RegistryUnavailable {
        /// What went wrong.
        detail: String,
    },
    /// Another controller already holds this environment.
    #[error("another control daemon already owns environment {environment}")]
    AlreadyRunning {
        /// The environment.
        environment: String,
    },
    /// The environment has reached its admission limit.
    #[error("environment {environment} already has {live} of {limit} sessions")]
    SessionLimit {
        /// The environment.
        environment: String,
        /// How many sessions are live or creating.
        live: u64,
        /// The configured limit.
        limit: u64,
    },
    /// A worker could not be started.
    #[error("could not start a worker: {detail}")]
    Supervision {
        /// What went wrong.
        detail: String,
    },
    /// A worker did not present a valid startup claim.
    #[error("the worker's startup claim was refused: {detail}")]
    RendezvousRefused {
        /// What went wrong.
        detail: String,
    },
    /// The named session is not in this environment.
    #[error("no session {session}")]
    UnknownSession {
        /// The identifier that was named.
        session: String,
    },
    /// The session has closed.
    #[error("session {session} has closed")]
    SessionClosed {
        /// The identifier that was named.
        session: String,
    },
    /// The freshness window this first admission is bound to is expired or unknown.
    #[error("{detail}")]
    WindowExpired {
        /// What went wrong.
        detail: String,
    },
    /// A create token was reused with a different request.
    #[error("create token {token} was already used with a different request")]
    IdConflict {
        /// The token that was reused.
        token: String,
    },
    /// The request is not valid.
    #[error("{0}")]
    InvalidArgument(String),
    /// Local IPC failed.
    #[error("{0}")]
    Ipc(#[from] kr_ipc::IpcError),
    /// A proof failed.
    #[error("{0}")]
    Verification(#[from] kr_ipc::verify::VerificationError),
    /// The host is not configured for this operation.
    #[error("{0}")]
    NotConfigured(String),
}

impl ControllerError {
    /// Builds a registry failure.
    pub fn registry(error: impl std::fmt::Display) -> Self {
        Self::RegistryUnavailable {
            detail: error.to_string(),
        }
    }

    /// Builds a supervision failure.
    pub fn supervision(detail: impl std::fmt::Display) -> Self {
        Self::Supervision {
            detail: detail.to_string(),
        }
    }

    /// Builds a rendezvous refusal.
    pub fn rendezvous(detail: impl std::fmt::Display) -> Self {
        Self::RendezvousRefused {
            detail: detail.to_string(),
        }
    }

    /// Returns the stable protocol code this failure is reported under.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::RegistryUnavailable { .. } => ErrorCode::StorageUnavailable,
            Self::AlreadyRunning { .. } => ErrorCode::ResourceUnavailable,
            Self::SessionLimit { .. } => ErrorCode::SessionLimit,
            Self::Supervision { .. } => ErrorCode::ResourceUnavailable,
            Self::RendezvousRefused { .. } | Self::Verification(_) | Self::WindowExpired { .. } => {
                ErrorCode::PermissionDenied
            }
            Self::UnknownSession { .. } => ErrorCode::UnknownSession,
            Self::SessionClosed { .. } => ErrorCode::SessionClosed,
            Self::IdConflict { .. } => ErrorCode::IdConflict,
            Self::InvalidArgument(_) => ErrorCode::InvalidArgument,
            Self::Ipc(error) => error.code(),
            Self::NotConfigured(_) => ErrorCode::HostNotConfigured,
        }
    }

    /// Renders the failure as a protocol error a client can be given.
    #[must_use]
    pub fn to_protocol_error(&self) -> ProtocolError {
        ProtocolError::new(self.code(), self.to_string())
    }
}

/// The result of a control-daemon operation.
pub type Result<T> = std::result::Result<T, ControllerError>;
