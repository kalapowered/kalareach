//! What a catalogue operation refuses with.
//!
//! Every refusal carries one stable protocol error code, because the reason a sync stopped is
//! something a person acts on: an untrusted root is a configuration change, an uncached payload
//! with no reachable repository is a transient absence, and an exhausted budget is a limit whose
//! exact resource has to be named before anybody can raise it.

use kr_plugin_sdk::capability::PluginCapability;
use kr_protocol::error::{ErrorCode, ProtocolError};

use crate::catalogue::budget::ResourceLimit;

/// The result of a catalogue operation.
pub type CatalogueResult<T> = Result<T, CatalogueError>;

/// Why a catalogue operation stopped.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CatalogueError {
    /// The repository's root, generation or signature is not trusted here.
    #[error("{detail}")]
    Untrusted {
        /// What was not trusted, in words a person acts on.
        detail: String,
    },
    /// The metadata this generation would be built from has expired.
    ///
    /// Expired metadata blocks a new generation. It does not disturb what is already installed:
    /// a pinned package stays usable offline under the grants it already has.
    #[error("{role} metadata expired at {expired_at}; the installed generation stays usable")]
    MetadataExpired {
        /// The role whose metadata expired first.
        role: String,
        /// When it expired.
        expired_at: String,
    },
    /// The payload is not cached here and no repository could supply it.
    #[error("{detail}")]
    UnavailableOffline {
        /// Which payload, and what would make it available.
        detail: String,
    },
    /// A budget the enrolment set would be exceeded.
    #[error("{0}")]
    ResourceLimit(#[from] ResourceLimit),
    /// A package's contents break an extraction rule.
    #[error("{detail}")]
    UnsafePackage {
        /// What the package did.
        detail: String,
    },
    /// A capability is outside the repository ceiling or has no grant.
    #[error("{capability} needs {requirement}")]
    GrantRequired {
        /// The capability that was refused.
        capability: PluginCapability,
        /// What would permit it.
        requirement: String,
    },
    /// The package is installed and disabled in this environment.
    #[error("{detail}")]
    Disabled {
        /// Which package, and where.
        detail: String,
    },
    /// The caller named something the catalogue does not hold.
    #[error("{detail}")]
    NotFound {
        /// What was asked for.
        detail: String,
    },
    /// The caller's arguments cannot be acted on.
    #[error("{detail}")]
    InvalidArgument {
        /// What was wrong with them.
        detail: String,
    },
    /// A durable store could not be read or written.
    #[error("{detail}")]
    StorageUnavailable {
        /// What failed, with the path it happened on.
        detail: String,
    },
    /// The bytes behind a content hash are not the bytes that hash names.
    #[error("{detail}")]
    Integrity {
        /// Which payload, and how it differed.
        detail: String,
    },
    /// A new root, or trust wider than the one already accepted, needs the owner to confirm it.
    #[error("{detail}")]
    OwnerConfirmationRequired {
        /// What the owner is being asked to accept.
        detail: String,
    },
    /// The operation was denied by admission or policy.
    #[error("{detail}")]
    PermissionDenied {
        /// What was denied.
        detail: String,
    },
    /// An authority outside the catalogue refused the operation, and its answer is carried as it
    /// was decided.
    ///
    /// A lapsed admission, a withdrawn registration and an expired confirmation are the daemon's
    /// decisions, each under its own code. The catalogue carries the decision rather than
    /// restating it, so a caller the daemon told "storage is unavailable" is not told "permission
    /// denied" by the catalogue.
    #[error("{}", .0.message)]
    Refused(ProtocolError),
    /// A change reached the store and whether it is durable is not known.
    ///
    /// This is not a refusal. Readers may already see the change, and what is uncertain is
    /// whether it survives a power loss, so the outcome travels as unknown rather than as a
    /// failure that did nothing.
    #[error("{detail}")]
    PublicationUncertain {
        /// What was being published, and what could not be confirmed.
        detail: String,
    },
}

impl CatalogueError {
    /// Returns the protocol error code this refusal travels under.
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        match self {
            Self::Untrusted { .. } | Self::MetadataExpired { .. } => ErrorCode::RepositoryUntrusted,
            Self::UnavailableOffline { .. } => ErrorCode::PackageUnavailableOffline,
            // An exhausted allowance, not a transient absence: a retry cannot succeed until the
            // enrolment's budget changes, which is exactly what this code means.
            Self::ResourceLimit(_) => ErrorCode::QuotaExceeded,
            // A package whose contents break an extraction rule is content this host will not
            // use, whatever signed it. Provenance is not safety.
            Self::UnsafePackage { .. } => ErrorCode::RepositoryUntrusted,
            Self::Integrity { .. } => ErrorCode::AttachmentIntegrity,
            Self::GrantRequired { .. } => ErrorCode::PluginGrantRequired,
            Self::Disabled { .. } => ErrorCode::PluginDisabled,
            Self::NotFound { .. } => ErrorCode::ResourceUnavailable,
            Self::InvalidArgument { .. } => ErrorCode::InvalidArgument,
            Self::StorageUnavailable { .. } => ErrorCode::StorageUnavailable,
            Self::OwnerConfirmationRequired { .. } => ErrorCode::OwnerConfirmationRequired,
            Self::PermissionDenied { .. } => ErrorCode::PermissionDenied,
            Self::Refused(error) => error.code,
            Self::PublicationUncertain { .. } => ErrorCode::OutcomeUnknown,
        }
    }

    /// Wraps an input-output failure on one path.
    pub(crate) fn storage(path: &std::path::Path, source: &std::io::Error) -> Self {
        Self::StorageUnavailable {
            detail: format!("{}: {source}", path.display()),
        }
    }
}

impl From<CatalogueError> for ProtocolError {
    fn from(error: CatalogueError) -> Self {
        match error {
            // Returned exactly as the authority that refused decided it.
            CatalogueError::Refused(refusal) => refusal,
            other => Self::new(other.code(), other.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_refusal_from_another_authority_reaches_the_wire_as_it_was_decided() {
        let decided = ProtocolError::new(
            ErrorCode::StorageUnavailable,
            "the registry could not be read",
        );
        let carried = CatalogueError::Refused(decided.clone());
        assert_eq!(carried.code(), ErrorCode::StorageUnavailable);
        assert_eq!(ProtocolError::from(carried), decided);
    }

    #[test]
    fn an_unconfirmed_publication_is_an_unknown_outcome_and_not_a_failure() {
        let uncertain = CatalogueError::PublicationUncertain {
            detail: "the state was renamed into place and its directory did not flush".to_owned(),
        };
        assert_eq!(uncertain.code(), ErrorCode::OutcomeUnknown);
    }
}
