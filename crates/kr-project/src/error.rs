//! What the project service can fail with, and the protocol code each failure is reported under.

use kr_protocol::error::{ErrorCode, ProtocolError};

/// A project-service failure.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ProjectError {
    /// The project store could not be read or written.
    #[error("the project store is unavailable: {detail}")]
    StoreUnavailable {
        /// What went wrong.
        detail: String,
    },
    /// The service's own directories could not be prepared or used.
    #[error("the project service's directories are unavailable: {detail}")]
    StagingUnavailable {
        /// What went wrong.
        detail: String,
    },
    /// The request names another environment.
    #[error("{named} is not this environment; this service owns {owned}")]
    WrongEnvironment {
        /// The environment the request named.
        named: String,
        /// The environment this service owns.
        owned: String,
    },
    /// The named repository does not exist here.
    #[error("no repository {project}")]
    UnknownProject {
        /// The identifier that was named.
        project: String,
    },
    /// The named workspace does not exist here.
    #[error("no workspace {workspace}")]
    UnknownWorkspace {
        /// The identifier that was named.
        workspace: String,
    },
    /// The named operation does not exist here.
    #[error("no repository operation {operation}")]
    UnknownOperation {
        /// The identifier that was named.
        operation: String,
    },
    /// The destination is not usable for this operation.
    #[error("{detail}")]
    Destination {
        /// What is wrong with it.
        detail: String,
    },
    /// The destination exists and the caller chose no adoption flow.
    ///
    /// Section 14 refuses a nonempty or existing destination unless the user explicitly chose an
    /// independently supported adoption flow, and never merges a clone into one.
    #[error("{detail}")]
    AdoptionRequired {
        /// What is at the destination, and what the caller would have to choose.
        detail: String,
    },
    /// The repository's stored identity no longer matches the object at its path.
    ///
    /// A rename, a replacement or an added worktree does not extend a grant, so the record is kept
    /// and nothing is served from it until the identity matches again.
    #[error("{detail}")]
    IdentityChanged {
        /// What was recorded and what is there now.
        detail: String,
    },
    /// A remote, a transport or a credential broker is not one this host will use.
    #[error("{detail}")]
    RemoteRejected {
        /// Which rule the remote breaks.
        detail: String,
    },
    /// The repository's own configuration names something this host will not execute.
    #[error("{detail}")]
    ConfigurationRejected {
        /// Which key, and why.
        detail: String,
    },
    /// Installed Git could not be used.
    #[error("{detail}")]
    GitUnavailable {
        /// What went wrong.
        detail: String,
    },
    /// A Git invocation failed, ran too long, or produced more output than the host accepts.
    #[error("{detail}")]
    GitFailed {
        /// The command, its status and its scrubbed output.
        detail: String,
    },
    /// The object or the workspace is not in a state that admits this call.
    #[error("{detail}")]
    WrongState {
        /// What state it is in, and what cannot be done in it.
        detail: String,
    },
    /// A workspace still has live bound sessions or runs.
    #[error("{detail}")]
    StillBound {
        /// Which sessions, and how many.
        detail: String,
    },
    /// The caller's authority does not reach this operation.
    #[error("{detail}")]
    PermissionDenied {
        /// What was refused.
        detail: String,
    },
    /// The same action identifier was reused for a different request.
    #[error("action {action} was already used for {method}")]
    IdConflict {
        /// The identifier.
        action: String,
        /// The method it was first used for.
        method: String,
    },
    /// This host cannot say whether an interrupted publication landed.
    #[error("{detail}")]
    OutcomeUnknown {
        /// What is known, and what is not.
        detail: String,
    },
    /// A retained failure, replayed under the code it was first produced with.
    #[error("{detail}")]
    Retained {
        /// The code the first attempt produced.
        code: ErrorCode,
        /// What it said.
        detail: String,
    },
    /// The operation's owner stopped it.
    ///
    /// Section 23's error table names no cancellation code, so a cancelled operation is reported
    /// as unavailable with a detail that says the owner stopped it: the repository the operation
    /// would have created does not exist, and asking again is a new operation rather than a retry.
    #[error("{detail}")]
    Cancelled {
        /// What was stopped.
        detail: String,
    },
    /// A configured resource limit is reached.
    #[error("{detail}")]
    QuotaExceeded {
        /// Which limit, and what it is.
        detail: String,
    },
    /// A request field is malformed.
    #[error("{0}")]
    InvalidArgument(String),
}

impl ProjectError {
    /// Wraps a store failure.
    pub fn store(error: impl std::fmt::Display) -> Self {
        Self::StoreUnavailable {
            detail: error.to_string(),
        }
    }

    /// Wraps a directory failure.
    pub fn staging(error: impl std::fmt::Display) -> Self {
        Self::StagingUnavailable {
            detail: error.to_string(),
        }
    }

    /// Returns the stable protocol code this failure is reported under.
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        match self {
            Self::StoreUnavailable { .. } => ErrorCode::StorageUnavailable,
            Self::StagingUnavailable { .. } => ErrorCode::StorageUnavailable,
            Self::WrongEnvironment { .. } => ErrorCode::EnvironmentUnavailable,
            Self::UnknownProject { .. }
            | Self::UnknownWorkspace { .. }
            | Self::UnknownOperation { .. } => ErrorCode::ResourceUnavailable,
            // A destination that is taken, a repository whose identity moved and a configuration
            // this host will not execute are all the same answer to a caller: change the thing you
            // named and ask again.
            Self::Destination { .. } => ErrorCode::InvalidArgument,
            Self::AdoptionRequired { .. } => ErrorCode::InvalidArgument,
            Self::IdentityChanged { .. } => ErrorCode::SourceChanged,
            Self::RemoteRejected { .. } => ErrorCode::RepositoryUntrusted,
            Self::ConfigurationRejected { .. } => ErrorCode::RepositoryUntrusted,
            Self::GitUnavailable { .. } => ErrorCode::HostNotConfigured,
            Self::GitFailed { .. } => ErrorCode::UpstreamUnavailable,
            Self::WrongState { .. } => ErrorCode::InvalidArgument,
            Self::StillBound { .. } => ErrorCode::ResourceUnavailable,
            Self::QuotaExceeded { .. } => ErrorCode::QuotaExceeded,
            Self::Cancelled { .. } => ErrorCode::ResourceUnavailable,
            Self::PermissionDenied { .. } => ErrorCode::PermissionDenied,
            Self::IdConflict { .. } => ErrorCode::IdConflict,
            Self::OutcomeUnknown { .. } => ErrorCode::OutcomeUnknown,
            Self::Retained { code, .. } => *code,
            Self::InvalidArgument(_) => ErrorCode::InvalidArgument,
        }
    }
}

impl From<ProjectError> for ProtocolError {
    fn from(error: ProjectError) -> Self {
        Self::new(error.code(), error.to_string())
    }
}

impl From<kr_transfer::Escape> for ProjectError {
    fn from(error: kr_transfer::Escape) -> Self {
        Self::Destination {
            detail: error.to_string(),
        }
    }
}

impl From<kr_transfer::TransferError> for ProjectError {
    fn from(error: kr_transfer::TransferError) -> Self {
        Self::StagingUnavailable {
            detail: error.to_string(),
        }
    }
}

/// The result type every project-service call returns.
pub type Result<T> = std::result::Result<T, ProjectError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_retained_failure_keeps_the_code_the_first_attempt_produced() {
        // A repeat of an action is owed what happened, not a fresh refusal in another category.
        let retained = ProjectError::Retained {
            code: ErrorCode::RepositoryUntrusted,
            detail: "the remote's transport is not one this host will use".to_owned(),
        };
        assert_eq!(retained.code(), ErrorCode::RepositoryUntrusted);
        let protocol: ProtocolError = retained.into();
        assert_eq!(protocol.code, ErrorCode::RepositoryUntrusted);
    }

    #[test]
    fn every_refusal_this_service_decides_carries_its_own_code() {
        // The daemon reports the code the service decided rather than mapping every failure to one
        // category, so each of these has to be distinct where the caller's next step differs.
        assert_eq!(
            ProjectError::AdoptionRequired {
                detail: "the destination holds a checkout".to_owned()
            }
            .code(),
            ErrorCode::InvalidArgument
        );
        assert_eq!(
            ProjectError::IdentityChanged {
                detail: "the repository was replaced".to_owned()
            }
            .code(),
            ErrorCode::SourceChanged
        );
        assert_eq!(
            ProjectError::ConfigurationRejected {
                detail: "core.fsmonitor names a program".to_owned()
            }
            .code(),
            ErrorCode::RepositoryUntrusted
        );
        assert_eq!(
            ProjectError::StillBound {
                detail: "one session is live".to_owned()
            }
            .code(),
            ErrorCode::ResourceUnavailable
        );
        assert_eq!(
            ProjectError::OutcomeUnknown {
                detail: "the publication cannot be resolved".to_owned()
            }
            .code(),
            ErrorCode::OutcomeUnknown
        );
    }
}
