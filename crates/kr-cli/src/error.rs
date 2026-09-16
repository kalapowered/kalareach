//! What the command line can fail with, and the exit code each failure produces.
//!
//! Exit codes are part of the command's contract: a script can tell a usage mistake from a session
//! that does not exist from a host that is not running, without parsing text.

/// A command-line failure.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CliError {
    /// The arguments are not a valid request.
    #[error("{0}")]
    Usage(String),
    /// The host is not running, or is not configured.
    #[error("{0}")]
    HostUnavailable(String),
    /// The named session does not exist.
    #[error("no session {0}")]
    UnknownSession(String),
    /// A display number names sessions in more than one environment.
    #[error("{0} names a session in more than one environment; give the session identifier")]
    AmbiguousSession(String),
    /// The command must run inside a session and did not.
    #[error("this command needs a session; run it inside one or name the session")]
    NotInSession,
    /// The host does not implement the requested shell integration mode.
    #[error("{0}")]
    ShellIntegrationUnsupported(String),
    /// The command needs a terminal and does not have one.
    #[error("this command needs a terminal")]
    NotATerminal,
    /// No terminal application could be opened.
    #[error("{0}")]
    TerminalUnavailable(String),
    /// The terminal could not be read or changed.
    #[error("{0}")]
    Terminal(String),
    /// The outer terminal did not complete the bounded capability handshake.
    #[error("{0}")]
    TerminalProbeFailed(String),
    /// The host refused the request.
    #[error("{0}")]
    Refused(kr_protocol::error::ProtocolError),
    /// Local IPC failed.
    #[error("{0}")]
    Ipc(#[from] kr_ipc::IpcError),
    /// Something else failed.
    #[error("{0}")]
    Other(String),
}

impl CliError {
    /// Returns the exit code this failure produces.
    #[must_use]
    pub const fn exit_code(&self) -> u8 {
        match self {
            Self::Usage(_) => 2,
            Self::HostUnavailable(_) => 3,
            Self::UnknownSession(_) | Self::NotInSession => 4,
            Self::AmbiguousSession(_) => 5,
            Self::ShellIntegrationUnsupported(_) => 2,
            Self::NotATerminal | Self::Terminal(_) | Self::TerminalProbeFailed(_) => 6,
            Self::TerminalUnavailable(_) => 7,
            Self::Refused(_) => 8,
            Self::Ipc(_) => 3,
            Self::Other(_) => 1,
        }
    }

    /// Returns the stable code a `--json` failure carries.
    #[must_use]
    pub fn code(&self) -> String {
        match self {
            Self::Usage(_) => kr_protocol::error::ErrorCode::InvalidArgument
                .as_str()
                .to_owned(),
            Self::HostUnavailable(_) | Self::Ipc(_) => {
                kr_protocol::error::ErrorCode::HostNotConfigured
                    .as_str()
                    .to_owned()
            }
            Self::UnknownSession(_) => kr_protocol::error::ErrorCode::UnknownSession
                .as_str()
                .to_owned(),
            Self::NotInSession => kr_protocol::error::ErrorCode::NotInKrSession
                .as_str()
                .to_owned(),
            Self::ShellIntegrationUnsupported(_) => {
                kr_protocol::error::ErrorCode::ShellIntegrationUnsupported
                    .as_str()
                    .to_owned()
            }
            Self::AmbiguousSession(_) => kr_protocol::error::ErrorCode::AmbiguousSession
                .as_str()
                .to_owned(),
            Self::NotATerminal | Self::Terminal(_) | Self::TerminalProbeFailed(_) => {
                kr_protocol::error::ErrorCode::TerminalProbeFailed
                    .as_str()
                    .to_owned()
            }
            Self::TerminalUnavailable(_) => kr_protocol::error::ErrorCode::TerminalUnavailable
                .as_str()
                .to_owned(),
            Self::Refused(error) => error.code.as_str().to_owned(),
            Self::Other(_) => kr_protocol::error::ErrorCode::ResourceUnavailable
                .as_str()
                .to_owned(),
        }
    }
}

impl From<kr_protocol::error::ProtocolError> for CliError {
    fn from(error: kr_protocol::error::ProtocolError) -> Self {
        Self::Refused(error)
    }
}

/// The result of a command.
pub type Result<T> = std::result::Result<T, CliError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_failure_has_its_own_exit_code() {
        let codes = [
            CliError::Usage(String::new()).exit_code(),
            CliError::HostUnavailable(String::new()).exit_code(),
            CliError::UnknownSession(String::new()).exit_code(),
            CliError::AmbiguousSession(String::new()).exit_code(),
            CliError::NotATerminal.exit_code(),
            CliError::TerminalUnavailable(String::new()).exit_code(),
        ];
        let mut sorted = codes;
        sorted.sort_unstable();
        let unique = {
            let mut unique = sorted;
            let mut seen = unique.to_vec();
            seen.dedup();
            unique.sort_unstable();
            seen.len()
        };
        assert_eq!(unique, codes.len(), "the codes are distinguishable");
        assert!(
            codes.iter().all(|code| *code != 0),
            "a failure never exits zero"
        );
    }
}
