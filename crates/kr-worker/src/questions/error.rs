//! What a question operation can fail with, and the protocol code it is reported under.

use kr_protocol::error::{ErrorCode, ProtocolError};

/// The instruction a caller outside a KalaReach session is given.
pub const SETUP_INSTRUCTION: &str =
    "start this agent inside a KalaReach session: run `kr new --attach` and launch it there";

/// A question failure.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum QuestionError {
    /// The caller could not be bound to a KalaReach session.
    ///
    /// Nothing is created. Section 11 forbids answering an unbound helper with a host-scoped
    /// question, so the caller is told how to get into a session instead.
    #[error("{detail}. {}", SETUP_INSTRUCTION)]
    NotInSession {
        /// Which part of the binding could not be established.
        detail: String,
    },
    /// The question has already reached a terminal state.
    #[error("this question is already {state}")]
    Resolved {
        /// The state it reached.
        state: kr_protocol::question::QuestionState,
    },
    /// The question expired before it was answered.
    #[error("this question expired at {at_ms}")]
    Expired {
        /// When it expired, in UTC milliseconds.
        at_ms: u64,
    },
    /// The same request identifier arrived from the same source with a different payload.
    #[error("request {request_id} was already used for a different question")]
    IdConflict {
        /// The identifier that was reused.
        request_id: String,
    },
    /// The caller's token does not belong to this question, or to this caller.
    #[error("{detail}")]
    TokenRejected {
        /// What did not match.
        detail: String,
    },
    /// No question with that identity exists in this session.
    #[error("no question {question_id} in this session")]
    Unknown {
        /// The identifier that was named.
        question_id: String,
    },
    /// The caller answered a revision that is no longer current.
    #[error("this question is at revision {current}, and the answer named {named}")]
    StaleRevision {
        /// The revision the caller named.
        named: u64,
        /// The revision the question is at.
        current: u64,
    },
    /// The payload does not satisfy the question contract.
    #[error("{0}")]
    Invalid(#[from] kr_protocol::question::QuestionFormError),
    /// A field was missing, malformed or out of range.
    #[error("{0}")]
    InvalidArgument(String),
    /// The durable store could not be read or written.
    #[error("the question ledger is unavailable: {detail}")]
    Unavailable {
        /// What went wrong.
        detail: String,
    },
}

impl QuestionError {
    /// Returns the stable protocol code this failure is reported under.
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        match self {
            Self::NotInSession { .. } => ErrorCode::NotInKrSession,
            Self::Resolved { .. } => ErrorCode::QuestionResolved,
            Self::Expired { .. } => ErrorCode::QuestionExpired,
            Self::IdConflict { .. } => ErrorCode::IdConflict,
            Self::TokenRejected { .. } | Self::Unknown { .. } => ErrorCode::PermissionDenied,
            Self::StaleRevision { .. } => ErrorCode::DraftConflict,
            Self::Invalid(_) | Self::InvalidArgument(_) => ErrorCode::InvalidArgument,
            Self::Unavailable { .. } => ErrorCode::StorageUnavailable,
        }
    }

    /// Renders the failure as a protocol error a client can be given.
    #[must_use]
    pub fn to_protocol_error(&self) -> ProtocolError {
        ProtocolError::new(self.code(), self.to_string())
    }

    /// Builds a store failure.
    pub fn unavailable(detail: impl std::fmt::Display) -> Self {
        Self::Unavailable {
            detail: detail.to_string(),
        }
    }

    /// Builds a binding failure.
    pub fn unbound(detail: impl std::fmt::Display) -> Self {
        Self::NotInSession {
            detail: detail.to_string(),
        }
    }
}

/// The result of a question operation.
pub type Result<T> = std::result::Result<T, QuestionError>;

/// An unknown question, named for the error.
#[must_use]
pub fn unknown(question_id: kr_protocol::ids::QuestionId) -> QuestionError {
    QuestionError::Unknown {
        question_id: question_id.to_string(),
    }
}
