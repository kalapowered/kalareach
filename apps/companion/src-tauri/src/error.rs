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
    /// Builds a failure with an explicit code, and the action the code maps to.
    ///
    /// The code says what a host, or this application, refused. What the person can do about it is
    /// what the code alone supports, which is right for a host's refusal and for a failure with no
    /// cause of this application's own. A refusal whose cause this application knows is built
    /// with [`Self::stated`] instead.
    #[must_use]
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            user_action: kr_client::retry::user_action(code).as_str().into(),
        }
    }

    /// Builds a failure this application refuses with, for a cause it knows, in words that say what
    /// is wrong.
    ///
    /// The action a code maps to is written for a host's refusal: an invalid argument there is two
    /// builds that disagree, so it names an update. Here the words already say what is wrong (which
    /// limit, which file, which input the program cannot read), and nothing they say is helped by
    /// an update, a wait or a change of setting, so the person is asked nothing more.
    #[must_use]
    pub fn stated(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            user_action: kr_client::retry::UserAction::Nothing.as_str().into(),
        }
    }

    /// The failure for something this application cannot do on this device or in this build.
    ///
    /// The words say what is missing and nothing the person does supplies it, so, as for any cause
    /// the application knows, they ask nothing more: waiting would not bring it.
    #[must_use]
    pub fn unsupported(message: impl Into<String>) -> Self {
        Self::stated(ErrorCode::ResourceUnavailable, message)
    }

    /// The failure for a request this application refuses to make at all.
    #[must_use]
    pub fn refused(message: impl Into<String>) -> Self {
        Self::stated(ErrorCode::PermissionDenied, message)
    }

    /// The failure for a parameter that cannot be what it claims to be.
    #[must_use]
    pub fn invalid(message: impl Into<String>) -> Self {
        Self::stated(ErrorCode::InvalidArgument, message)
    }

    /// The failure for a request that exceeded a bound this application applies.
    ///
    /// `QUOTA_EXCEEDED` is the protocol's word for an exhausted allowance, and the import limit is
    /// one: the same request will not succeed until the allowance changes, so waiting is not what
    /// the person is asked to do.
    #[must_use]
    pub fn too_large(message: impl Into<String>) -> Self {
        Self::stated(ErrorCode::QuotaExceeded, message)
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

    /// The action a failure names, as the page reads it.
    fn action(error: &CommandError) -> &str {
        &error.user_action
    }

    /// A file above the size limit is a limit that does not move: waiting does not lift it, and
    /// the words already say what to do.
    #[test]
    fn a_file_above_the_size_limit_asks_nothing_more_of_the_person() {
        let error = crate::transfers::HandedFile::new(
            vec![0; crate::transfers::MAX_HANDED_BYTES + 1],
            "movie.mov",
        )
        .expect_err("above the limit");
        assert_eq!(error.code, ErrorCode::QuotaExceeded);
        assert_eq!(action(&error), "nothing");
        assert_eq!(
            action(&CommandError::too_large("the image exceeds the limit")),
            "nothing"
        );
        // The limit is said in megabytes, and nothing on a phone points at a window to drop it on.
        assert!(
            error.message.contains("at most 64 MiB"),
            "{}",
            error.message
        );
        assert_eq!(
            error.message.contains("drop a larger one on the window"),
            !cfg!(mobile),
            "{}",
            error.message
        );
    }

    /// A dropped folder is not a file, and the words say so: an update would not change it.
    #[test]
    fn a_dropped_folder_asks_nothing_more_of_the_person() {
        let folder = tempfile::tempdir().expect("a folder");
        let error = crate::transfers::DroppedFile::open(folder.path()).expect_err("not a file");
        assert_eq!(error.code, ErrorCode::InvalidArgument);
        assert_eq!(action(&error), "nothing");
    }

    /// The application's own refusal of what it was handed says what is wrong in its words.
    #[test]
    fn a_refusal_the_application_makes_itself_asks_nothing_more_of_the_person() {
        let invalid = CommandError::invalid("that is not a session identifier");
        assert_eq!(
            (invalid.code, action(&invalid)),
            (ErrorCode::InvalidArgument, "nothing")
        );
        let refused = CommandError::refused("the scheme is not one this application opens");
        assert_eq!(
            (refused.code, action(&refused)),
            (ErrorCode::PermissionDenied, "nothing")
        );
        // Something this build cannot do keeps the code a host would give for what it cannot reach,
        // and asks no waiting for it.
        let unsupported = CommandError::unsupported("this build cannot open a voice call");
        assert_eq!(
            (unsupported.code, action(&unsupported)),
            (ErrorCode::ResourceUnavailable, "nothing")
        );
    }

    /// Controls: a failure with no cause of the application's own keeps the action its code maps
    /// to, whether a host sent it or the application named the code without a cause.
    #[test]
    fn a_failure_with_no_cause_of_its_own_keeps_the_action_its_code_maps_to() {
        for (code, expected) in [
            (ErrorCode::QuotaExceeded, "wait"),
            (ErrorCode::InvalidArgument, "update"),
            (ErrorCode::PermissionDenied, "fix_configuration"),
            (ErrorCode::InputIncompatible, "update"),
            (ErrorCode::OutcomeUnknown, "check_the_outcome"),
        ] {
            assert_eq!(
                action(&CommandError::new(code, "a plain message")),
                expected,
                "{code:?}"
            );
            let host = kr_protocol::error::ProtocolError::new(code, "the host's words");
            assert_eq!(
                action(&CommandError::from(host)),
                expected,
                "a host's {code:?}"
            );
        }
        assert_eq!(
            action(&CommandError::local_failure("a step did not finish")),
            "wait"
        );
        assert_eq!(
            action(&CommandError::unavailable("the host is not in contact")),
            "wait"
        );
        assert_eq!(action(&CommandError::not_connected()), "fix_configuration");
    }
}
