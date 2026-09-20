//! What the project service can fail with, and the protocol code each failure is reported under.

use std::fmt;

use kr_protocol::error::{ErrorCode, ProtocolError};

/// Free text inside a failure, as this host will repeat it.
///
/// The only way to make one applies the rule, so a field on a failure cannot hold what a caller or
/// a repository chose even when the sentence around it is never formatted. A consumer that reads
/// the field and a consumer that prints the failure are told the same thing.
///
/// The rule leaves its own output alone, so a fragment that was already replaced where the message
/// was composed comes through here unchanged, and this host's own words stay legible.
#[derive(Clone, PartialEq, Eq)]
pub struct Diagnostic(String);

impl Diagnostic {
    /// Puts one piece of text through the rule and keeps what it may repeat.
    #[must_use]
    pub fn new(text: impl AsRef<str>) -> Self {
        Self(crate::git::redact(text.as_ref()))
    }

    /// Returns the protected text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl fmt::Debug for Diagnostic {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.0, formatter)
    }
}

impl From<String> for Diagnostic {
    fn from(text: String) -> Self {
        Self::new(text)
    }
}

impl From<&str> for Diagnostic {
    fn from(text: &str) -> Self {
        Self::new(text)
    }
}

/// A project-service failure.
///
/// Every variant carries the sentence this host composed for it, and each place that composes one
/// puts the part it did not write itself through [`crate::git::redact`], which is what keeps the
/// host's own words legible. [`fmt::Display`] is the bar underneath that: a failure becomes text
/// in exactly one place, and the whole of it goes through the rule there. So a Rust caller, a log
/// line, the daemon's standard error and the wire all read the same protected message, and a
/// producer nobody thought about cannot reach any of them with something else. [`fmt::Debug`] goes
/// the same way, because a debug rendering is how most of a message reaches a log.
#[non_exhaustive]
pub enum ProjectError {
    /// The project store could not be read or written.
    StoreUnavailable {
        /// What went wrong.
        detail: Diagnostic,
    },
    /// The service's own directories could not be prepared or used.
    StagingUnavailable {
        /// What went wrong.
        detail: Diagnostic,
    },
    /// The request names another environment.
    WrongEnvironment {
        /// The environment the request named.
        named: Diagnostic,
        /// The environment this service owns.
        owned: Diagnostic,
    },
    /// The named repository does not exist here.
    UnknownProject {
        /// The identifier that was named.
        project: Diagnostic,
    },
    /// The named workspace does not exist here.
    UnknownWorkspace {
        /// The identifier that was named.
        workspace: Diagnostic,
    },
    /// The named operation does not exist here.
    UnknownOperation {
        /// The identifier that was named.
        operation: Diagnostic,
    },
    /// The destination is not usable for this operation.
    Destination {
        /// What is wrong with it.
        detail: Diagnostic,
    },
    /// The destination exists and the caller chose no adoption flow.
    ///
    /// Section 14 refuses a nonempty or existing destination unless the user explicitly chose an
    /// independently supported adoption flow, and never merges a clone into one.
    AdoptionRequired {
        /// What is at the destination, and what the caller would have to choose.
        detail: Diagnostic,
    },
    /// The repository's stored identity no longer matches the object at its path.
    ///
    /// A rename, a replacement or an added worktree does not extend a grant, so the record is kept
    /// and nothing is served from it until the identity matches again.
    IdentityChanged {
        /// What was recorded and what is there now.
        detail: Diagnostic,
    },
    /// A remote, a transport or a credential broker is not one this host will use.
    RemoteRejected {
        /// Which rule the remote breaks.
        detail: Diagnostic,
    },
    /// The repository's own configuration names something this host will not execute.
    ConfigurationRejected {
        /// Which key, and why.
        detail: Diagnostic,
    },
    /// Installed Git could not be used.
    GitUnavailable {
        /// What went wrong.
        detail: Diagnostic,
    },
    /// A Git invocation failed, ran too long, or produced more output than the host accepts.
    GitFailed {
        /// The command, its status and its scrubbed output.
        detail: Diagnostic,
    },
    /// The object or the workspace is not in a state that admits this call.
    WrongState {
        /// What state it is in, and what cannot be done in it.
        detail: Diagnostic,
    },
    /// A workspace still has live bound sessions or runs.
    StillBound {
        /// Which sessions, and how many.
        detail: Diagnostic,
    },
    /// The caller's authority does not reach this operation.
    PermissionDenied {
        /// What was refused.
        detail: Diagnostic,
    },
    /// The same action identifier was reused for a different request.
    IdConflict {
        /// The identifier.
        action: Diagnostic,
        /// The method it was first used for.
        method: Diagnostic,
    },
    /// This host cannot say whether an interrupted publication landed.
    OutcomeUnknown {
        /// What is known, and what is not.
        detail: Diagnostic,
    },
    /// The admission this mutation was accepted under no longer stood when its transaction
    /// reached the write.
    ///
    /// The daemon decides what lapsed and under which code, and this carries both rather than
    /// translating them: a revocation and an expiry are different answers to the caller, and the
    /// service is not the thing that knows which one happened.
    NotAdmitted {
        /// The code the daemon's admission decided.
        code: ErrorCode,
        /// What lapsed, in the daemon's own words.
        detail: Diagnostic,
    },
    /// A retained failure, replayed under the code it was first produced with.
    Retained {
        /// The code the first attempt produced.
        code: ErrorCode,
        /// What it said.
        detail: Diagnostic,
    },
    /// The operation's owner stopped it.
    ///
    /// Section 23's error table names no cancellation code, so a cancelled operation is reported
    /// as unavailable with a detail that says the owner stopped it: the repository the operation
    /// would have created does not exist, and asking again is a new operation rather than a retry.
    Cancelled {
        /// What was stopped.
        detail: Diagnostic,
    },
    /// A configured resource limit is reached.
    QuotaExceeded {
        /// Which limit, and what it is.
        detail: Diagnostic,
    },
    /// A request field is malformed.
    InvalidArgument(Diagnostic),
}

impl fmt::Debug for ProjectError {
    /// Writes the variant, the code it is reported under and the protected sentence.
    ///
    /// The derived rendering would print the fields as they are, and a debug rendering is what a
    /// log line, a `Result::expect` and a failing test all use. So it goes through the same
    /// sentence [`fmt::Display`] writes, and what it adds is the variant's own name, which is this
    /// host's word rather than anything a caller or a repository chose.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct(self.name())
            .field("code", &self.code())
            .field("message", &self.to_string())
            .finish()
    }
}

impl fmt::Display for ProjectError {
    /// Writes the failure as one protected sentence.
    ///
    /// This is the only place a `ProjectError` becomes text, so it is where the rule applies to
    /// the whole of it. A message whose untrusted fragments were already replaced where it was
    /// composed passes through unchanged, because the rule leaves its own output alone; a message
    /// that holds something this host will not repeat is replaced whole rather than repeated.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&crate::git::redact(&self.compose()))
    }
}

impl std::error::Error for ProjectError {}

impl ProjectError {
    /// Returns the variant's own name.
    const fn name(&self) -> &'static str {
        match self {
            Self::StoreUnavailable { .. } => "StoreUnavailable",
            Self::StagingUnavailable { .. } => "StagingUnavailable",
            Self::WrongEnvironment { .. } => "WrongEnvironment",
            Self::UnknownProject { .. } => "UnknownProject",
            Self::UnknownWorkspace { .. } => "UnknownWorkspace",
            Self::UnknownOperation { .. } => "UnknownOperation",
            Self::Destination { .. } => "Destination",
            Self::AdoptionRequired { .. } => "AdoptionRequired",
            Self::IdentityChanged { .. } => "IdentityChanged",
            Self::RemoteRejected { .. } => "RemoteRejected",
            Self::ConfigurationRejected { .. } => "ConfigurationRejected",
            Self::GitUnavailable { .. } => "GitUnavailable",
            Self::GitFailed { .. } => "GitFailed",
            Self::WrongState { .. } => "WrongState",
            Self::StillBound { .. } => "StillBound",
            Self::PermissionDenied { .. } => "PermissionDenied",
            Self::IdConflict { .. } => "IdConflict",
            Self::OutcomeUnknown { .. } => "OutcomeUnknown",
            Self::NotAdmitted { .. } => "NotAdmitted",
            Self::Retained { .. } => "Retained",
            Self::Cancelled { .. } => "Cancelled",
            Self::QuotaExceeded { .. } => "QuotaExceeded",
            Self::InvalidArgument(_) => "InvalidArgument",
        }
    }

    /// Returns the sentence this host composed for the failure, before the rule.
    fn compose(&self) -> String {
        match self {
            Self::StoreUnavailable { detail } => {
                format!("the project store is unavailable: {detail}")
            }
            Self::StagingUnavailable { detail } => {
                format!("the project service's directories are unavailable: {detail}")
            }
            Self::WrongEnvironment { named, owned } => {
                format!("{named} is not this environment; this service owns {owned}")
            }
            Self::UnknownProject { project } => format!("no repository {project}"),
            Self::UnknownWorkspace { workspace } => format!("no workspace {workspace}"),
            Self::UnknownOperation { operation } => format!("no repository operation {operation}"),
            Self::IdConflict { action, method } => {
                format!("action {action} was already used for {method}")
            }
            // The rest say what this host decided and nothing about their category, because the
            // category is the code the caller is answered under.
            Self::Destination { detail }
            | Self::AdoptionRequired { detail }
            | Self::IdentityChanged { detail }
            | Self::RemoteRejected { detail }
            | Self::ConfigurationRejected { detail }
            | Self::GitUnavailable { detail }
            | Self::GitFailed { detail }
            | Self::WrongState { detail }
            | Self::StillBound { detail }
            | Self::PermissionDenied { detail }
            | Self::OutcomeUnknown { detail }
            | Self::NotAdmitted { detail, .. }
            | Self::Retained { detail, .. }
            | Self::Cancelled { detail }
            | Self::QuotaExceeded { detail }
            | Self::InvalidArgument(detail) => detail.as_str().to_owned(),
        }
    }

    /// Wraps a store failure.
    pub fn store(error: impl std::fmt::Display) -> Self {
        Self::StoreUnavailable {
            detail: error.to_string().into(),
        }
    }

    /// Wraps a directory failure.
    pub fn staging(error: impl std::fmt::Display) -> Self {
        Self::StagingUnavailable {
            detail: error.to_string().into(),
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
            Self::NotAdmitted { code, .. } | Self::Retained { code, .. } => *code,
            Self::InvalidArgument(_) => ErrorCode::InvalidArgument,
        }
    }
}

impl From<ProjectError> for ProtocolError {
    /// Every project error becomes a wire error here, under the code the service decided.
    ///
    /// The message is [`fmt::Display`]'s, which is where the rule applies to the whole of it, so
    /// the wire and a Rust caller are told the same thing in the same words.
    fn from(error: ProjectError) -> Self {
        Self::new(error.code(), error.to_string())
    }
}

impl From<kr_transfer::Escape> for ProjectError {
    fn from(error: kr_transfer::Escape) -> Self {
        Self::Destination {
            // The refusal names the component it refused, which is text the caller supplied, so it
            // goes through the same rule as anything else this host did not choose. An ordinary
            // path comes back as it is; anything a credential is made of does not.
            detail: crate::git::redact(&error.to_string()).into(),
        }
    }
}

impl From<kr_transfer::TransferError> for ProjectError {
    fn from(error: kr_transfer::TransferError) -> Self {
        Self::StagingUnavailable {
            detail: error.to_string().into(),
        }
    }
}

/// The result type every project-service call returns.
pub type Result<T> = std::result::Result<T, ProjectError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_variant_can_put_what_this_host_will_not_repeat_in_front_of_a_caller() {
        // The rule is applied where each message is composed, which is what keeps the host's own
        // words legible. This is the bar underneath that: a producer that forgets cannot reach a
        // Rust caller, a log line or the wire with a fragment nobody looked at, because a failure
        // becomes text in one place and the whole of it goes through the rule there.
        const HOSTILE: &str = "https://user:BOUNDARYSECRET@host/x?access_token=BOUNDARYSECRET";
        let every = [
            ProjectError::store(HOSTILE),
            ProjectError::staging(HOSTILE),
            ProjectError::WrongEnvironment {
                named: HOSTILE.to_owned().into(),
                owned: HOSTILE.to_owned().into(),
            },
            ProjectError::UnknownProject {
                project: HOSTILE.to_owned().into(),
            },
            ProjectError::UnknownWorkspace {
                workspace: HOSTILE.to_owned().into(),
            },
            ProjectError::UnknownOperation {
                operation: HOSTILE.to_owned().into(),
            },
            ProjectError::Destination {
                detail: HOSTILE.to_owned().into(),
            },
            ProjectError::AdoptionRequired {
                detail: HOSTILE.to_owned().into(),
            },
            ProjectError::IdentityChanged {
                detail: HOSTILE.to_owned().into(),
            },
            ProjectError::RemoteRejected {
                detail: HOSTILE.to_owned().into(),
            },
            ProjectError::ConfigurationRejected {
                detail: HOSTILE.to_owned().into(),
            },
            ProjectError::GitUnavailable {
                detail: HOSTILE.to_owned().into(),
            },
            ProjectError::GitFailed {
                detail: HOSTILE.to_owned().into(),
            },
            ProjectError::WrongState {
                detail: HOSTILE.to_owned().into(),
            },
            ProjectError::StillBound {
                detail: HOSTILE.to_owned().into(),
            },
            ProjectError::PermissionDenied {
                detail: HOSTILE.to_owned().into(),
            },
            ProjectError::IdConflict {
                action: HOSTILE.to_owned().into(),
                method: HOSTILE.to_owned().into(),
            },
            ProjectError::OutcomeUnknown {
                detail: HOSTILE.to_owned().into(),
            },
            ProjectError::Retained {
                code: ErrorCode::RepositoryUntrusted,
                detail: HOSTILE.to_owned().into(),
            },
            ProjectError::Cancelled {
                detail: HOSTILE.to_owned().into(),
            },
            ProjectError::QuotaExceeded {
                detail: HOSTILE.to_owned().into(),
            },
            ProjectError::InvalidArgument(HOSTILE.to_owned().into()),
        ];
        for failure in every {
            let code = failure.code();
            let said = failure.to_string();
            assert!(
                !said.contains("BOUNDARYSECRET"),
                "a Rust caller is told no more than the wire is: {said}"
            );
            // A debug rendering is what a log line, a `Result::expect` and a failing test use, so
            // it is under the same bar. Both spellings, because `{:#?}` is its own formatter.
            let debugged = format!("{failure:?}");
            let expanded = format!("{failure:#?}");
            for rendering in [&debugged, &expanded] {
                assert!(
                    !rendering.contains("BOUNDARYSECRET"),
                    "and a debug rendering no more than either: {rendering}"
                );
            }
            assert!(
                debugged.starts_with(failure.name()),
                "while still saying which failure it is: {debugged}"
            );
            let wire: ProtocolError = failure.into();
            assert_eq!(wire.message, said, "and both are told the same thing");
            assert_eq!(wire.code, code, "under the code the service decided");
        }
    }

    #[test]
    fn a_failure_this_library_produces_carries_no_raw_text_in_its_own_fields() {
        // A consumer inside this host can read a failure's field rather than print the failure, and
        // the field is what the library it wrapped said. SQLite puts the file name it was asked for
        // into its own message, and that name is a path somebody chose. So the field holds what
        // this host will repeat and nothing else: the type of the field is the guarantee, rather
        // than every producer remembering.
        let refusal = crate::store::Store::open(
            std::path::Path::new("/dev/null/access_token=FIELDSECRET/projects.sqlite"),
            kr_protocol::ids::EnvironmentId::new(kr_protocol::scalars::Uuid::from_bytes([1; 16])),
        )
        .expect_err("a database beneath something that is not a directory cannot be opened");
        assert_eq!(refusal.code(), ErrorCode::StorageUnavailable);
        assert!(!refusal.to_string().contains("FIELDSECRET"));
        let ProjectError::StoreUnavailable { detail } = &refusal else {
            panic!("the store reports its own failure: {refusal:?}");
        };
        assert!(
            !detail.as_str().contains("FIELDSECRET"),
            "the field a consumer reads holds no more than the sentence does: {detail:?}"
        );
        assert!(
            detail.as_str().contains("does-not-repeat"),
            "and it says that something was replaced: {detail:?}"
        );
    }

    #[test]
    fn a_refused_subcommand_is_named_through_the_rule_in_every_rendering() {
        // The one producer the boundary above cannot answer for on its own: a refusal composed out
        // of the caller's own word. The fragment goes through the rule where the sentence is built,
        // so the sentence survives, and every rendering of the failure carries the same thing.
        let refusal =
            crate::git::check_arguments(&[std::ffi::OsStr::new("access_token=SUBCOMMANDSECRET")])
                .expect_err("a subcommand this service does not run is refused");
        let said = refusal.to_string();
        let debugged = format!("{refusal:?}");
        for rendering in [&said, &debugged, &format!("{refusal:#?}")] {
            assert!(
                !rendering.contains("SUBCOMMANDSECRET"),
                "no rendering repeats what the caller named: {rendering}"
            );
        }
        assert!(
            said.contains("is not a subcommand this service runs"),
            "and this host's own words survive: {said}"
        );
    }

    #[test]
    fn a_retained_failure_keeps_the_code_the_first_attempt_produced() {
        // A repeat of an action is owed what happened, not a fresh refusal in another category.
        let retained = ProjectError::Retained {
            code: ErrorCode::RepositoryUntrusted,
            detail: "the remote's transport is not one this host will use"
                .to_owned()
                .into(),
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
                detail: "the destination holds a checkout".to_owned().into()
            }
            .code(),
            ErrorCode::InvalidArgument
        );
        assert_eq!(
            ProjectError::IdentityChanged {
                detail: "the repository was replaced".to_owned().into()
            }
            .code(),
            ErrorCode::SourceChanged
        );
        assert_eq!(
            ProjectError::ConfigurationRejected {
                detail: "core.fsmonitor names a program".to_owned().into()
            }
            .code(),
            ErrorCode::RepositoryUntrusted
        );
        assert_eq!(
            ProjectError::StillBound {
                detail: "one session is live".to_owned().into()
            }
            .code(),
            ErrorCode::ResourceUnavailable
        );
        assert_eq!(
            ProjectError::OutcomeUnknown {
                detail: "the publication cannot be resolved".to_owned().into()
            }
            .code(),
            ErrorCode::OutcomeUnknown
        );
    }
}
