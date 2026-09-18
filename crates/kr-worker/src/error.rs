//! What a worker can fail with, and the protocol code each failure is reported under.

use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::session::DimensionsError;

/// A worker failure.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum WorkerError {
    /// A durable store could not be read or written.
    #[error("could not {operation}: {source}")]
    Storage {
        /// What was being attempted.
        operation: &'static str,
        /// The underlying failure.
        source: std::io::Error,
    },
    /// The receipt journal is unavailable.
    ///
    /// Ordinary typed mutations are refused before dispatch. An authorised stop is not: section 7
    /// requires `session.close` to proceed on the worker's current in-memory authority and report
    /// `durability=volatile`.
    #[error("the session journal is unavailable: {detail}")]
    JournalUnavailable {
        /// What went wrong.
        detail: String,
    },
    /// The pseudo-terminal could not be created or driven.
    #[error("{operation}: {detail}")]
    Pty {
        /// What was being attempted.
        operation: &'static str,
        /// What went wrong.
        detail: String,
    },
    /// A requested geometry violated one of the three dimension constraints.
    #[error("{0}")]
    Dimensions(#[from] DimensionsError),
    /// The named attachment does not exist.
    #[error("no attachment {attachment}")]
    UnknownAttachment {
        /// The identifier that was named.
        attachment: String,
    },
    /// The caller does not hold the input lease at the epoch it claimed.
    #[error("the input lease has moved on")]
    LeaseLost,
    /// The caller cannot supply the keyboard encoding the application has negotiated.
    #[error("the application negotiated {required}, and {offered}")]
    InputIncompatible {
        /// What the application expects its keys in.
        required: String,
        /// What this attachment can send.
        offered: String,
    },
    /// The presentation this attachment needs is not one this host can serve.
    #[error("{detail}")]
    PresentationUnsupported {
        /// What is missing, and what would make it work.
        detail: String,
    },
    /// The caller is not the geometry owner.
    #[error("only the geometry owner changes the session's size")]
    NotGeometryOwner,
    /// The session is closing or closed.
    #[error("the session is closed")]
    SessionClosed,
    /// An identifier was reused with a different payload.
    #[error("action {action} was already submitted with a different payload")]
    IdConflict {
        /// The identifier that was reused.
        action: String,
    },
    /// A controller connection no longer speaks for the generation this worker accepts.
    #[error("{detail}")]
    GenerationFenced {
        /// Which part of the binding failed.
        detail: String,
    },
    /// The freshness window this first admission is bound to is expired or unknown.
    #[error("{detail}")]
    WindowExpired {
        /// What went wrong.
        detail: String,
    },
    /// A resource this host needs was not available.
    #[error("{detail}")]
    ResourceUnavailable {
        /// What was unavailable.
        detail: String,
    },
    /// The subject preconditions the mutation requires did not hold.
    #[error("{detail}")]
    PreconditionFailed {
        /// Which precondition failed.
        detail: String,
    },
    /// The target named a session identity or epoch that is no longer current.
    #[error("{detail}")]
    StaleTarget {
        /// What disagreed.
        detail: String,
    },
    /// A resource limit this host configures was reached.
    #[error("{detail}")]
    QuotaExceeded {
        /// Which limit, and what it is.
        detail: String,
    },
    /// This host cannot prove what its wall clock reads, so the expiry cannot be decided.
    #[error("{detail}")]
    ClockUntrusted {
        /// What cannot be proved, and what would settle it.
        detail: String,
    },
    /// The caller holds no authority over what it named.
    #[error("{detail}")]
    PermissionDenied {
        /// What was refused, and why.
        detail: String,
    },
    /// The request is not valid.
    #[error("{0}")]
    InvalidArgument(String),
    /// Local IPC failed.
    #[error("{0}")]
    Ipc(#[from] kr_ipc::IpcError),
    /// A worker or controller proof failed.
    #[error("{0}")]
    Verification(#[from] kr_ipc::verify::VerificationError),
    /// A question could not be created, read or resolved.
    #[error("{0}")]
    Question(#[from] crate::questions::QuestionError),
}

impl WorkerError {
    /// Builds a storage failure.
    #[must_use]
    pub const fn storage(operation: &'static str, source: std::io::Error) -> Self {
        Self::Storage { operation, source }
    }

    /// Builds a pseudo-terminal failure.
    pub fn pty(operation: &'static str, detail: impl std::fmt::Display) -> Self {
        Self::Pty {
            operation,
            detail: detail.to_string(),
        }
    }

    /// Returns the stable protocol code this failure is reported under.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::Storage { .. } | Self::JournalUnavailable { .. } => ErrorCode::StorageUnavailable,
            Self::Pty { .. } | Self::ResourceUnavailable { .. } => ErrorCode::ResourceUnavailable,
            Self::Dimensions(_) | Self::InvalidArgument(_) => ErrorCode::InvalidArgument,
            Self::UnknownAttachment { .. } => ErrorCode::AmbiguousAttachment,
            Self::LeaseLost => ErrorCode::LeaseLost,
            Self::InputIncompatible { .. } => ErrorCode::InputIncompatible,
            Self::PresentationUnsupported { .. } => ErrorCode::UnsupportedCapability,
            Self::NotGeometryOwner => ErrorCode::GeometryNotOwner,
            Self::SessionClosed => ErrorCode::SessionClosed,
            Self::IdConflict { .. } => ErrorCode::IdConflict,
            Self::GenerationFenced { .. }
            | Self::WindowExpired { .. }
            | Self::PermissionDenied { .. } => ErrorCode::PermissionDenied,
            Self::QuotaExceeded { .. } => ErrorCode::QuotaExceeded,
            Self::ClockUntrusted { .. } => ErrorCode::ClockUntrusted,
            Self::PreconditionFailed { .. } => ErrorCode::DraftConflict,
            Self::StaleTarget { .. } => ErrorCode::StaleSession,
            Self::Ipc(error) => error.code(),
            Self::Verification(_) => ErrorCode::PermissionDenied,
            Self::Question(error) => error.code(),
        }
    }

    /// Renders the failure as a protocol error a client can be given.
    #[must_use]
    pub fn to_protocol_error(&self) -> ProtocolError {
        ProtocolError::new(self.code(), self.to_string())
    }
}

/// The result of a worker operation.
pub type Result<T> = std::result::Result<T, WorkerError>;
