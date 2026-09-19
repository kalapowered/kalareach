//! What the broker refuses, and the stable protocol code each refusal is reported under.
//!
//! The broker has refusals the rest of the worker does not: an upstream that cannot safely
//! continue, a rich method outside the closed table, a component asked to do something no grant of
//! its permits. Each one maps to a code section 23 already lists, so a client needs nothing new to
//! understand them.

use kr_protocol::broker::{CapabilityError, GrantError, TokenError, TrustError};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::gateway::{ArbitrationError, RichRejection, TableError};

/// A broker failure.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BrokerError {
    /// The binding does not hold the grant the operation needs.
    #[error("{0}")]
    Grant(#[from] GrantError),
    /// The action token does not authorise what was presented with it.
    #[error("{0}")]
    Token(#[from] TokenError),
    /// A decoding-trust record the broker will not act on.
    #[error("{0}")]
    Trust(#[from] TrustError),
    /// A capability record that breaks section 11's rules.
    #[error("{0}")]
    Capability(#[from] CapabilityError),
    /// A declarative or rich table the core will not interpret.
    #[error("{0}")]
    Table(#[from] TableError),
    /// A rich invocation the closed table refuses.
    #[error("{0}")]
    Rich(#[from] RichRejection),
    /// A transition a pending resource cannot make.
    #[error("{0}")]
    Arbitration(#[from] ArbitrationError),
    /// The framing connection cannot safely continue.
    ///
    /// Section 11 is explicit about the alternative: "do not open a hidden second backend or
    /// reconnect-and-replay an unknown request".
    #[error("{detail}")]
    UpstreamUnavailable {
        /// What went wrong, and what a person can do about it.
        detail: String,
    },
    /// A rich operation arrived while the journal was faulted.
    #[error("{detail}")]
    RichWorkFenced {
        /// Which fence refused it.
        detail: String,
    },
    /// The caller named a binding, instance or resource this broker does not hold.
    #[error("{detail}")]
    UnknownSubject {
        /// What was named.
        detail: String,
    },
    /// The caller's binding revision is not the one in force.
    #[error("{detail}")]
    StaleBinding {
        /// What disagreed.
        detail: String,
    },
    /// A draft or request precondition did not hold.
    #[error("{detail}")]
    PreconditionFailed {
        /// Which precondition failed.
        detail: String,
    },
    /// The capability this action needs is not usable here.
    #[error("{detail}")]
    UnsupportedCapability {
        /// Which capability, and why it cannot be used.
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
    /// The broker's durable records could not be read or written.
    #[error("the broker ledger is unavailable: {detail}")]
    LedgerUnavailable {
        /// What went wrong.
        detail: String,
    },
    /// A launch intent was refused.
    #[error("{0}")]
    Launch(#[from] kr_protocol::broker::LaunchRefusal),
}

impl BrokerError {
    /// Builds a ledger failure from anything that can describe itself.
    pub fn ledger(detail: impl std::fmt::Display) -> Self {
        Self::LedgerUnavailable {
            detail: detail.to_string(),
        }
    }

    /// Builds an invalid-argument failure.
    pub fn invalid(detail: impl std::fmt::Display) -> Self {
        Self::InvalidArgument(detail.to_string())
    }

    /// Builds a permission failure.
    pub fn denied(detail: impl std::fmt::Display) -> Self {
        Self::PermissionDenied {
            detail: detail.to_string(),
        }
    }

    /// Builds an unknown-subject failure.
    pub fn unknown(detail: impl std::fmt::Display) -> Self {
        Self::UnknownSubject {
            detail: detail.to_string(),
        }
    }

    /// Returns the stable protocol code this failure is reported under.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::Grant(_) | Self::Token(_) | Self::PermissionDenied { .. } => {
                ErrorCode::PermissionDenied
            }
            // A trust or capability record that breaks a rule is a record this build will not
            // store, which is an argument failure at the boundary that offered it.
            Self::Trust(_) | Self::Capability(_) | Self::InvalidArgument(_) => {
                ErrorCode::InvalidArgument
            }
            // A table qualified against another version, and a method outside the closed table,
            // are both "this build cannot do that", not "you may not".
            Self::Table(_) | Self::Rich(_) | Self::UnsupportedCapability { .. } => {
                ErrorCode::UnsupportedCapability
            }
            Self::Arbitration(error) => match error {
                ArbitrationError::AlreadyResolved { .. } | ArbitrationError::AlreadyClaimed => {
                    ErrorCode::QuestionResolved
                }
                ArbitrationError::ForbiddenTransition { .. } => ErrorCode::InvalidArgument,
            },
            Self::UpstreamUnavailable { .. } | Self::RichWorkFenced { .. } => {
                ErrorCode::UpstreamUnavailable
            }
            Self::UnknownSubject { .. } | Self::StaleBinding { .. } => ErrorCode::StaleSession,
            Self::PreconditionFailed { .. } => ErrorCode::DraftConflict,
            Self::LedgerUnavailable { .. } => ErrorCode::StorageUnavailable,
            Self::Launch(refusal) => match refusal {
                kr_protocol::broker::LaunchRefusal::ForegroundChanged
                | kr_protocol::broker::LaunchRefusal::PromptMoved => ErrorCode::DraftConflict,
                kr_protocol::broker::LaunchRefusal::ConversationAlreadyLive { .. } => {
                    ErrorCode::IdConflict
                }
            },
        }
    }

    /// Renders the failure as a protocol error a client can be given.
    #[must_use]
    pub fn to_protocol_error(&self) -> ProtocolError {
        ProtocolError::new(self.code(), self.to_string())
    }
}

/// The result of a broker operation.
pub type Result<T> = std::result::Result<T, BrokerError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_upstream_that_cannot_continue_is_upstream_unavailable() {
        let error = BrokerError::UpstreamUnavailable {
            detail: "the framing connection ended mid-frame".to_owned(),
        };
        assert_eq!(error.code(), ErrorCode::UpstreamUnavailable);
    }

    #[test]
    fn fenced_rich_work_is_reported_as_the_upstream_being_unavailable() {
        // Not `STORAGE_UNAVAILABLE`: what the caller needs to know is that this operation cannot
        // reach the upstream now, and that no second backend was opened to make it look as though
        // it did.
        let error = BrokerError::RichWorkFenced {
            detail: "the journal faulted and rich work is fenced".to_owned(),
        };
        assert_eq!(error.code(), ErrorCode::UpstreamUnavailable);
    }

    #[test]
    fn an_unknown_rich_method_is_an_unsupported_capability() {
        let error = BrokerError::Rich(RichRejection::Unknown {
            method: kr_protocol::ids::UpstreamMethod::new("vendor/x").expect("valid"),
        });
        assert_eq!(error.code(), ErrorCode::UnsupportedCapability);
    }
}
