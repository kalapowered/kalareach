//! What the transfer service can fail with, and the protocol code each failure is reported under.

use kr_protocol::error::{ErrorCode, ProtocolError};

/// A transfer-service failure.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TransferError {
    /// The transfer store could not be read or written.
    #[error("the transfer store is unavailable: {detail}")]
    StoreUnavailable {
        /// What went wrong.
        detail: String,
    },
    /// The staging area could not be prepared or used.
    #[error("the transfer staging area is unavailable: {detail}")]
    StagingUnavailable {
        /// What went wrong.
        detail: String,
    },
    /// The request names another environment.
    ///
    /// A handle, a scope and a staged file all belong to one environment. A Windows path and a WSL
    /// path are two environments, and neither one's identifiers mean anything in the other.
    #[error("{named} is not this environment; this service owns {owned}")]
    WrongEnvironment {
        /// The environment the request named.
        named: String,
        /// The environment this service owns.
        owned: String,
    },
    /// The named transfer does not exist here.
    #[error("no transfer {transfer}")]
    UnknownTransfer {
        /// The identifier that was named.
        transfer: String,
    },
    /// The named draft does not exist here.
    #[error("no draft {draft}")]
    UnknownDraft {
        /// The identifier that was named.
        draft: String,
    },
    /// The named read scope does not exist, or has been revoked.
    #[error("no read authority for scope {scope}")]
    UnknownScope {
        /// The identifier that was named.
        scope: String,
    },
    /// The transfer is not in a state that admits this call.
    #[error("transfer {transfer} is {state}, so {detail}")]
    WrongState {
        /// The transfer.
        transfer: String,
        /// Its state.
        state: &'static str,
        /// What cannot be done in that state.
        detail: String,
    },
    /// A chunk, a size or a whole-file digest did not verify.
    #[error("{detail}")]
    Integrity {
        /// What did not verify.
        detail: String,
    },
    /// The source changed, so this transfer cannot continue under the same identity.
    #[error("{detail}")]
    SourceChanged {
        /// What changed.
        detail: String,
    },
    /// A configured resource limit is reached.
    #[error("{detail}")]
    QuotaExceeded {
        /// Which limit, and what it is.
        detail: String,
    },
    /// The device already holds as many concurrent transfers as it may.
    #[error("{detail}")]
    Concurrency {
        /// Which limit, and what it is.
        detail: String,
    },
    /// The draft's revision is not the one the caller expected.
    #[error("{detail}")]
    DraftConflict {
        /// What the caller expected and what is current.
        detail: String,
    },
    /// The caller's authority does not reach this operation.
    #[error("{detail}")]
    PermissionDenied {
        /// What went wrong.
        detail: String,
    },
    /// An action identifier was reused with a different payload.
    #[error("action {action} was already used for {method} with a different payload")]
    IdConflict {
        /// The identifier that was reused.
        action: String,
        /// The method it was first used for.
        method: String,
    },
    /// The failure this action was recorded as, returned to a repeat of it.
    ///
    /// One action, one answer: a repeat of an action that failed is owed the failure it produced,
    /// under the code it produced, not a new decision made now.
    #[error("{detail}")]
    Retained {
        /// The code the failure was recorded under.
        code: ErrorCode,
        /// What it said.
        detail: String,
    },
    /// An action was claimed and its outcome is not recorded yet.
    ///
    /// A two-commit effect claims its action with the first commit and records its result with the
    /// second. A repeat that arrives between the two is owed this answer and not a guess: the
    /// caller asks again, and the host completes the record when the effect does.
    #[error("action {action} is under way and its outcome is not recorded yet")]
    OutcomeUnknown {
        /// The action that is under way.
        action: String,
    },
    /// A path escaped, or could have escaped, the directory that authorised it.
    #[error("{0}")]
    Escape(#[from] crate::authority::Escape),
    /// Local inter-process communication failed.
    #[error("{0}")]
    Ipc(#[from] kr_ipc::IpcError),
    /// The request is not valid.
    #[error("{0}")]
    InvalidArgument(String),
}

impl TransferError {
    /// Builds a store failure.
    pub fn store(error: impl std::fmt::Display) -> Self {
        Self::StoreUnavailable {
            detail: error.to_string(),
        }
    }

    /// Builds a staging failure.
    pub fn staging(error: impl std::fmt::Display) -> Self {
        Self::StagingUnavailable {
            detail: error.to_string(),
        }
    }

    /// Builds an integrity failure.
    pub fn integrity(detail: impl std::fmt::Display) -> Self {
        Self::Integrity {
            detail: detail.to_string(),
        }
    }

    /// Builds a source-changed failure.
    pub fn source_changed(detail: impl std::fmt::Display) -> Self {
        Self::SourceChanged {
            detail: detail.to_string(),
        }
    }

    /// Builds an invalid-argument failure.
    pub fn invalid(detail: impl std::fmt::Display) -> Self {
        Self::InvalidArgument(detail.to_string())
    }

    /// Returns the stable protocol code this failure is reported under.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::StoreUnavailable { .. } | Self::StagingUnavailable { .. } => {
                ErrorCode::StorageUnavailable
            }
            Self::WrongEnvironment { .. } => ErrorCode::EnvironmentUnavailable,
            // Section 23 has no distinct code for an identifier that names nothing, and inventing
            // one would tell a caller whether an identifier it guessed exists.
            Self::UnknownTransfer { .. } | Self::UnknownDraft { .. } => ErrorCode::InvalidArgument,
            Self::UnknownScope { .. } | Self::PermissionDenied { .. } => {
                ErrorCode::PermissionDenied
            }
            // A refusal about a name or an object is an authority answer; a failure the storage
            // decided is a storage answer. Reporting both the same way would tell a caller to
            // change its request when what it should do is wait, or the other way round.
            Self::Escape(escape) => match escape {
                crate::authority::Escape::Unopenable { .. } => ErrorCode::StorageUnavailable,
                crate::authority::Escape::WrongEnvironment { .. } => {
                    ErrorCode::EnvironmentUnavailable
                }
                _ => ErrorCode::PermissionDenied,
            },
            Self::WrongState { .. } => ErrorCode::ResourceUnavailable,
            Self::Integrity { .. } => ErrorCode::AttachmentIntegrity,
            Self::SourceChanged { .. } => ErrorCode::SourceChanged,
            Self::QuotaExceeded { .. } => ErrorCode::QuotaExceeded,
            // A concurrency ceiling clears when one of the caller's own transfers finishes, so it
            // is transient. A byte quota does not, which is why they report differently.
            Self::Concurrency { .. } => ErrorCode::ResourceUnavailable,
            Self::DraftConflict { .. } => ErrorCode::DraftConflict,
            Self::IdConflict { .. } => ErrorCode::IdConflict,
            Self::OutcomeUnknown { .. } => ErrorCode::OutcomeUnknown,
            Self::Retained { code, .. } => *code,
            Self::Ipc(error) => error.code(),
            Self::InvalidArgument(_) => ErrorCode::InvalidArgument,
        }
    }

    /// Renders the failure as a protocol error a client can be given.
    #[must_use]
    pub fn to_protocol_error(&self) -> ProtocolError {
        ProtocolError::new(self.code(), self.to_string())
    }
}

impl From<TransferError> for ProtocolError {
    /// A refusal reaches a caller under the code this service decided, never one a host chose for
    /// it: an integrity failure stays `ATTACHMENT_INTEGRITY`, a budget stays `QUOTA_EXCEEDED`.
    fn from(error: TransferError) -> Self {
        error.to_protocol_error()
    }
}

/// The result of a transfer-service operation.
pub type Result<T> = std::result::Result<T, TransferError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_byte_quota_does_not_retry_and_a_concurrency_ceiling_does() {
        let quota = TransferError::QuotaExceeded {
            detail: "full".to_owned(),
        };
        let concurrency = TransferError::Concurrency {
            detail: "busy".to_owned(),
        };
        assert_eq!(quota.code(), ErrorCode::QuotaExceeded);
        assert_eq!(
            quota.code().retry_category(),
            kr_protocol::error::RetryCategory::NoRetry
        );
        assert_eq!(concurrency.code(), ErrorCode::ResourceUnavailable);
        assert_eq!(
            concurrency.code().retry_category(),
            kr_protocol::error::RetryCategory::Transient
        );
    }

    #[test]
    fn a_name_refusal_is_a_permission_failure_and_a_storage_failure_is_not() {
        use crate::authority::Escape;

        for escape in [
            Escape::ParentSegment,
            Escape::Empty,
            Escape::NotFound {
                component: "absent".to_owned(),
            },
            Escape::Link {
                component: "alias".to_owned(),
            },
            Escape::WrongKind {
                detail: "a directory".to_owned(),
            },
            Escape::IdentityChanged {
                detail: "a different object".to_owned(),
            },
        ] {
            assert_eq!(
                TransferError::Escape(escape.clone()).code(),
                ErrorCode::PermissionDenied,
                "{escape:?}"
            );
        }
        assert_eq!(
            TransferError::Escape(Escape::Unopenable {
                component: "payload".to_owned(),
                detail: "no space left on device".to_owned(),
            })
            .code(),
            ErrorCode::StorageUnavailable
        );
        assert_eq!(
            TransferError::Escape(Escape::WrongEnvironment {
                holder: "a".to_owned(),
                named: "b".to_owned(),
            })
            .code(),
            ErrorCode::EnvironmentUnavailable
        );
    }
}
