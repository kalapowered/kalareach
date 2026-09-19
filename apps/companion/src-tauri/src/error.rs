//! What a command answers with when it cannot do what was asked.
//!
//! Every failure crossing into the WebView carries the protocol's own error code, so the interface
//! can translate the code into a direct action rather than showing an internal message. Section 23
//! fixes that vocabulary; nothing here invents a code of its own.

use kr_protocol::error::ErrorCode;
use serde::Serialize;

/// A failure the WebView receives.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CommandError {
    /// The protocol error code.
    pub code: ErrorCode,
    /// Plain text for a person or a log.
    pub message: String,
    /// What the person can do about it, where the client knows.
    pub user_action: String,
}

impl CommandError {
    /// Builds a failure with an explicit code.
    #[must_use]
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            user_action: kr_client::retry::user_action(code).as_str().into(),
        }
    }

    /// The failure for a request this application refuses to make at all.
    #[must_use]
    pub fn refused(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::PermissionDenied, message)
    }

    /// The failure for a parameter that cannot be what it claims to be.
    #[must_use]
    pub fn invalid(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidArgument, message)
    }

    /// The failure for a request that exceeded a bound this application applies.
    ///
    /// `QUOTA_EXCEEDED` is the protocol's word for an exhausted allowance, and the import limit is
    /// one: the same request will not succeed until the allowance changes.
    #[must_use]
    pub fn too_large(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::QuotaExceeded, message)
    }

    /// The failure for an operation that needs a host connection this application does not have.
    #[must_use]
    pub fn not_connected() -> Self {
        Self::new(
            ErrorCode::HostNotConfigured,
            "this application is not connected to a host",
        )
    }

    /// The failure for a step of this application that did not finish.
    ///
    /// There is no protocol code for a client's own internal failure, and inventing one would put
    /// a word on the wire that no host knows. `RESOURCE_UNAVAILABLE` is the honest nearest: a local
    /// resource this operation needed was not there, and trying again may work.
    #[must_use]
    pub fn local_failure(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::ResourceUnavailable, message)
    }

    /// The failure for a host, service or ceremony this device cannot reach right now.
    #[must_use]
    pub fn unavailable(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::ResourceUnavailable, message)
    }
}

impl std::fmt::Display for CommandError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.code.as_str(), self.message)
    }
}

impl std::error::Error for CommandError {}

impl From<kr_client::ClientError> for CommandError {
    fn from(error: kr_client::ClientError) -> Self {
        let code = error.code();
        Self {
            code,
            message: error.to_string(),
            user_action: error.user_action().as_str().into(),
        }
    }
}

impl From<kr_protocol::error::ProtocolError> for CommandError {
    fn from(error: kr_protocol::error::ProtocolError) -> Self {
        Self::new(error.code, error.message)
    }
}

/// The answer a command gives.
pub type Result<T> = std::result::Result<T, CommandError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_refusal_carries_the_protocol_code_and_a_named_action() {
        let error = CommandError::refused("that scheme is not approved");
        assert_eq!(error.code, ErrorCode::PermissionDenied);
        assert!(!error.user_action.is_empty());
    }

    #[test]
    fn a_size_refusal_is_an_exhausted_allowance_rather_than_an_internal_failure() {
        let error = CommandError::too_large("the image exceeds the import limit");
        assert_eq!(error.code, ErrorCode::QuotaExceeded);
    }
}
