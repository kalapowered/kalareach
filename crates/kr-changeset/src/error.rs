//! The failures this service returns, each under one stable protocol code.
//!
//! Every free-text field is a [`kr_project::Diagnostic`], whose only constructor puts the text
//! through the project service's rule. A consumer that matches on a variant and reads a field sees
//! what a consumer that prints the failure sees, because the field's own type is what applies the
//! rule rather than each producer remembering to. [`fmt::Display`] is the second bar: a failure
//! becomes text in exactly one place and the whole of it goes through the rule there.

use std::fmt;

use kr_protocol::error::{ErrorCode, ProtocolError};

use kr_project::{Diagnostic, ProjectError};

/// What a change-set call returns.
pub type Result<T> = std::result::Result<T, ChangeSetError>;

/// A change-set service failure.
#[non_exhaustive]
pub enum ChangeSetError {
    /// The change-set store could not be read or written.
    StoreUnavailable {
        /// What went wrong.
        detail: Diagnostic,
    },
    /// The service's own directories could not be prepared or used.
    StorageUnavailable {
        /// What went wrong.
        detail: Diagnostic,
    },
    /// The named change set or version does not exist here.
    UnknownVersion {
        /// What was named.
        detail: Diagnostic,
    },
    /// The named materialisation does not exist here.
    UnknownMaterialisation {
        /// What was named.
        detail: Diagnostic,
    },
    /// The source changed while this host was reading it, past the retry bound.
    ///
    /// Section 14 asks for concurrently changing files to be detected and retried within a bound
    /// **or rejected**. This is the rejection, and it is what a capture returns rather than
    /// producing a tree that holds two instants of the working tree.
    SourceChanged {
        /// Which paths kept changing, and how many times this host tried.
        detail: Diagnostic,
    },
    /// The destination is not what the request expected, and nothing was written.
    DraftConflict {
        /// Which paths differ, and how.
        detail: Diagnostic,
    },
    /// This host cannot say what the destination holds.
    OutcomeUnknown {
        /// What is known and what is not.
        detail: Diagnostic,
    },
    /// The object is not in a state that admits this call.
    WrongState {
        /// What state it is in, and what cannot be done in it.
        detail: Diagnostic,
    },
    /// A configured resource limit is reached.
    QuotaExceeded {
        /// Which limit, and what it is.
        detail: Diagnostic,
    },
    /// The same action identifier was reused for a different request.
    IdConflict {
        /// The identifier.
        action: Diagnostic,
        /// The method it was first used for.
        method: Diagnostic,
    },
    /// Another copy of this action holds its claim, so this one did nothing.
    ///
    /// One action, one effect: the copy that took the claim is the one that acts, and this one is
    /// answered from that copy's reply rather than performing the work a second time.
    ActionHeldElsewhere,
    /// A request field is malformed.
    InvalidArgument(Diagnostic),
    /// A faithful interpretation of the request needs something this host does not do.
    ///
    /// Section 14: when faithful interpretation requires an ungranted helper, expose the
    /// limitation instead of executing it under a read-only grant. This is that limitation
    /// reaching the caller.
    Unsupported {
        /// What this host does not do, and what it established before saying so.
        detail: Diagnostic,
    },
    /// The project service refused, and its own code and sentence are carried through.
    ///
    /// Reading a repository, resolving a workspace and every Git invocation belong to the project
    /// service. Its refusals reach the caller under the code it decided rather than under a code
    /// chosen here, so a repository whose identity moved is still `SOURCE_CHANGED` and a
    /// configuration this host will not execute is still `REPOSITORY_UNTRUSTED`.
    Project {
        /// The code the project service decided.
        code: ErrorCode,
        /// Its protected sentence.
        detail: Diagnostic,
    },
}

impl ChangeSetError {
    /// Returns the variant's own name.
    const fn name(&self) -> &'static str {
        match self {
            Self::StoreUnavailable { .. } => "StoreUnavailable",
            Self::StorageUnavailable { .. } => "StorageUnavailable",
            Self::UnknownVersion { .. } => "UnknownVersion",
            Self::UnknownMaterialisation { .. } => "UnknownMaterialisation",
            Self::SourceChanged { .. } => "SourceChanged",
            Self::DraftConflict { .. } => "DraftConflict",
            Self::OutcomeUnknown { .. } => "OutcomeUnknown",
            Self::WrongState { .. } => "WrongState",
            Self::QuotaExceeded { .. } => "QuotaExceeded",
            Self::ActionHeldElsewhere => "ActionHeldElsewhere",
            Self::IdConflict { .. } => "IdConflict",
            Self::InvalidArgument(_) => "InvalidArgument",
            Self::Unsupported { .. } => "Unsupported",
            Self::Project { .. } => "Project",
        }
    }

    /// Returns the sentence this host composed for the failure, before the rule.
    fn compose(&self) -> String {
        match self {
            Self::StoreUnavailable { detail } => {
                format!("the change-set store is unavailable: {detail}")
            }
            Self::StorageUnavailable { detail } => {
                format!("the change-set service's directories are unavailable: {detail}")
            }
            Self::ActionHeldElsewhere => {
                "another copy of this action holds it and has not said what it came to".to_owned()
            }
            Self::IdConflict { action, method } => {
                format!("action {action} was already used for {method}")
            }
            Self::UnknownVersion { detail }
            | Self::UnknownMaterialisation { detail }
            | Self::SourceChanged { detail }
            | Self::DraftConflict { detail }
            | Self::OutcomeUnknown { detail }
            | Self::WrongState { detail }
            | Self::QuotaExceeded { detail }
            | Self::InvalidArgument(detail)
            | Self::Unsupported { detail }
            | Self::Project { detail, .. } => detail.as_str().to_owned(),
        }
    }

    /// Wraps a store failure.
    pub fn store(error: impl fmt::Display) -> Self {
        Self::StoreUnavailable {
            detail: error.to_string().into(),
        }
    }

    /// Wraps a directory failure.
    pub fn storage(error: impl fmt::Display) -> Self {
        Self::StorageUnavailable {
            detail: error.to_string().into(),
        }
    }

    /// Returns the stable protocol code this failure is reported under.
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        match self {
            Self::StoreUnavailable { .. } | Self::StorageUnavailable { .. } => {
                ErrorCode::StorageUnavailable
            }
            Self::UnknownVersion { .. } | Self::UnknownMaterialisation { .. } => {
                ErrorCode::ResourceUnavailable
            }
            Self::SourceChanged { .. } => ErrorCode::SourceChanged,
            Self::DraftConflict { .. } => ErrorCode::DraftConflict,
            Self::OutcomeUnknown { .. } => ErrorCode::OutcomeUnknown,
            Self::WrongState { .. } => ErrorCode::ResourceUnavailable,
            Self::QuotaExceeded { .. } => ErrorCode::QuotaExceeded,
            Self::ActionHeldElsewhere => ErrorCode::OutcomeUnknown,
            Self::IdConflict { .. } => ErrorCode::IdConflict,
            Self::InvalidArgument(_) => ErrorCode::InvalidArgument,
            Self::Unsupported { .. } => ErrorCode::UnsupportedCapability,
            Self::Project { code, .. } => *code,
        }
    }
}

impl fmt::Debug for ChangeSetError {
    /// Writes the variant, its code and the protected sentence.
    ///
    /// A derived rendering would print the fields as they are, and a debug rendering is what a log
    /// line, a `Result::expect` and a failing test all use.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct(self.name())
            .field("code", &self.code())
            .field("message", &self.to_string())
            .finish()
    }
}

impl fmt::Display for ChangeSetError {
    /// Writes the failure as one protected sentence.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&kr_project::git::redact(&self.compose()))
    }
}

impl std::error::Error for ChangeSetError {}

impl From<ProjectError> for ChangeSetError {
    /// Carries the project service's own code and sentence through unchanged.
    fn from(error: ProjectError) -> Self {
        Self::Project {
            code: error.code(),
            // `ProjectError`'s `Display` is already the protected sentence, and the rule leaves
            // its own output alone, so this neither loses the project service's words nor repeats
            // anything it withheld.
            detail: error.to_string().into(),
        }
    }
}

impl From<kr_transfer::Escape> for ChangeSetError {
    /// Carries a filesystem-authority refusal through as a storage failure.
    fn from(escape: kr_transfer::Escape) -> Self {
        Self::StorageUnavailable {
            detail: escape.to_string().into(),
        }
    }
}

impl From<ChangeSetError> for ProtocolError {
    fn from(error: ChangeSetError) -> Self {
        Self::new(error.code(), error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A payload with every shape the redaction rule replaces: a URL with a credential in it, and
    /// a word made of characters this host does not repeat.
    const HOSTILE: &str = "https://user:SECRET-TOKEN@host.invalid/x?token=abc#frag";

    #[test]
    fn no_rendering_of_any_variant_repeats_what_a_caller_sent() {
        let variants = [
            ChangeSetError::StoreUnavailable {
                detail: HOSTILE.into(),
            },
            ChangeSetError::StorageUnavailable {
                detail: HOSTILE.into(),
            },
            ChangeSetError::UnknownVersion {
                detail: HOSTILE.into(),
            },
            ChangeSetError::UnknownMaterialisation {
                detail: HOSTILE.into(),
            },
            ChangeSetError::SourceChanged {
                detail: HOSTILE.into(),
            },
            ChangeSetError::DraftConflict {
                detail: HOSTILE.into(),
            },
            ChangeSetError::OutcomeUnknown {
                detail: HOSTILE.into(),
            },
            ChangeSetError::WrongState {
                detail: HOSTILE.into(),
            },
            ChangeSetError::QuotaExceeded {
                detail: HOSTILE.into(),
            },
            ChangeSetError::ActionHeldElsewhere,
            ChangeSetError::IdConflict {
                action: HOSTILE.into(),
                method: HOSTILE.into(),
            },
            ChangeSetError::InvalidArgument(HOSTILE.into()),
            ChangeSetError::Unsupported {
                detail: HOSTILE.into(),
            },
            ChangeSetError::Project {
                code: ErrorCode::RepositoryUntrusted,
                detail: HOSTILE.into(),
            },
        ];
        for error in &variants {
            // Every rendering a consumer can reach: the sentence, the debug forms, the field
            // itself and the wire object.
            let wire = ProtocolError::from(ChangeSetError::InvalidArgument(
                error.compose().as_str().into(),
            ));
            for text in [
                error.to_string(),
                format!("{error:?}"),
                format!("{error:#?}"),
                wire.message.clone(),
            ] {
                assert!(
                    !text.contains("SECRET-TOKEN"),
                    "{} repeated what a caller sent: {text}",
                    error.name()
                );
            }
        }
    }

    #[test]
    fn a_preflight_conflict_is_reported_as_draft_conflict() {
        // Section 14: a preflight conflict returns DRAFT_CONFLICT.
        let error = ChangeSetError::DraftConflict {
            detail: "one path differs".into(),
        };
        assert_eq!(error.code(), ErrorCode::DraftConflict);
        assert_eq!(
            ProtocolError::from(error).code,
            kr_protocol::error::ErrorCode::DraftConflict
        );
    }

    #[test]
    fn a_source_that_kept_changing_is_reported_as_source_changed() {
        let error = ChangeSetError::SourceChanged {
            detail: "one path changed four times".into(),
        };
        assert_eq!(error.code(), ErrorCode::SourceChanged);
    }

    #[test]
    fn a_project_refusal_keeps_the_code_the_project_service_decided() {
        // A repository whose identity moved is SOURCE_CHANGED wherever it is answered from, and a
        // configuration this host will not execute stays REPOSITORY_UNTRUSTED.
        let moved = ChangeSetError::from(ProjectError::IdentityChanged {
            detail: "the recorded object is not there".into(),
        });
        assert_eq!(moved.code(), ErrorCode::SourceChanged);
        let untrusted = ChangeSetError::from(ProjectError::ConfigurationRejected {
            detail: "a driver this host cannot neutralise".into(),
        });
        assert_eq!(untrusted.code(), ErrorCode::RepositoryUntrusted);
    }
}
