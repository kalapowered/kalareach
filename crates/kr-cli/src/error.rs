//! What the command line can fail with, and the exit code each failure produces.
//!
//! Exit codes are part of the command's contract: a script can tell a usage mistake from a session
//! that does not exist from a host that is not running, without parsing text.

use kr_client::retry::UserAction;
use kr_client::shown;
use kr_client::shown::{Said, Shown};

/// A command-line failure.
///
/// What it says is a [`Shown`], so neither its line on stderr nor its `--json` document carries
/// what a host, a file or the person's own arguments held: [`Said`] is its `Display` and its
/// `Debug`. Two variants hold another crate's value because the command matches on what is inside
/// ([`Self::Refused`] and [`Self::Ipc`]); each is rendered through its door or reducer, and neither
/// is this error's `source()`.
#[non_exhaustive]
pub enum CliError {
    /// The arguments are not a valid request.
    Usage(Shown),
    /// The host is not running, or is not configured.
    HostUnavailable(Shown),
    /// The named session does not exist.
    UnknownSession(Shown),
    /// A display number names sessions in more than one environment.
    AmbiguousSession(Shown),
    /// The command must run inside a session and did not.
    NotInSession,
    /// The host does not implement the requested shell integration mode.
    ShellIntegrationUnsupported(Shown),
    /// The command needs a terminal and does not have one.
    NotATerminal,
    /// No terminal application could be opened.
    TerminalUnavailable(Shown),
    /// The terminal could not be read or changed.
    Terminal(Shown),
    /// The outer terminal did not complete the bounded capability handshake.
    TerminalProbeFailed(Shown),
    /// The host refused the request.
    ///
    /// A person is told what the host said and the direct action its code calls for, and not the
    /// code: section 23 has the interface translate codes into actions and keep protocol internals
    /// out of what it shows. The code is in [`CliError::code`] and in a `--json` failure.
    Refused(kr_protocol::error::ProtocolError),
    /// A refusal that says itself what a person does about it, and the action it names is the one
    /// said, not the one the code calls for.
    ///
    /// A managed service knows more about its refusal than the code carries. A refusal this command
    /// makes in words that already say what to do is also said this way, with no action after it:
    /// [`CliError::refused_in_its_own_words`].
    ServiceRefused {
        /// What the service said was wrong.
        error: kr_protocol::error::ProtocolError,
        /// What a person does about it.
        action: kr_client::retry::UserAction,
    },
    /// The attached session closed, and not cleanly: its shell failed or something ended it.
    ///
    /// The attachment itself did what it was for, so this is no refusal and no lost host. It is
    /// the general failure, and the sentence carries what the closure record says.
    SessionClosed(Shown),
    /// The host acted and did not finish what was asked, such as an apply that wrote part of a
    /// change or one whose result it cannot establish, or what followed an action failed, such as
    /// reading the reply to an answer a worker took. The command's own output carries what the
    /// host reported.
    Unfinished {
        /// The stable code the failure carries.
        code: kr_protocol::error::ErrorCode,
        /// What did not finish, for a person.
        message: Shown,
    },
    /// A person's answer was not taken by its session's worker, or whether it was is not known, so
    /// it is kept on this device. `kr question drafts` shows it and `kr question send` sends it;
    /// nothing else does.
    AnswerKept {
        /// The stable code the failure carries.
        code: kr_protocol::error::ErrorCode,
        /// What happened to the answer, for a person.
        message: Shown,
    },
    /// Local IPC failed.
    Ipc(kr_ipc::IpcError),
    /// An update of this host waits: something live holds it, or another update is running. What
    /// it stopped runs again, and the sentence says what holds it and what to do.
    UpdateDeferred(Shown),
    /// Something else failed.
    Other(Shown),
}

impl Said for CliError {
    fn said(&self) -> Shown {
        match self {
            Self::Usage(said)
            | Self::HostUnavailable(said)
            | Self::ShellIntegrationUnsupported(said)
            | Self::TerminalUnavailable(said)
            | Self::Terminal(said)
            | Self::TerminalProbeFailed(said)
            | Self::SessionClosed(said)
            | Self::UpdateDeferred(said)
            | Self::Other(said)
            | Self::Unfinished { message: said, .. }
            | Self::AnswerKept { message: said, .. } => said.clone(),
            Self::UnknownSession(selector) => shown!("no session {}", selector.clone()),
            Self::AmbiguousSession(selector) => shown!(
                "{} names a session in more than one environment; give the session identifier",
                selector.clone()
            ),
            Self::NotInSession => {
                Shown::said("this command needs a session; run it inside one or name the session")
            }
            Self::NotATerminal => Shown::said("this command needs a terminal"),
            Self::Refused(error) => refusal_said(error, kr_client::retry::user_action(error.code)),
            Self::ServiceRefused { error, action } => refusal_said(error, *action),
            Self::Ipc(error) => Shown::ipc(error),
        }
    }
}

/// What a person is told of a refusal: what the refuser said, and the direct action after it where
/// there is one. A code that calls for nothing is said by its message alone.
fn refusal_said(error: &kr_protocol::error::ProtocolError, action: UserAction) -> Shown {
    match action {
        UserAction::Nothing => Shown::protocol(error),
        action => shown!(
            "{}\n{}",
            Shown::protocol(error),
            Shown::said(action.message())
        ),
    }
}

kr_client::display_as_said!(CliError);
kr_client::debug_as_display!(CliError);

/// No variant is this error's `source()`: what each says is in its own rendering, and the two
/// values another crate built are rendered through their door and reducer here, never whole.
impl std::error::Error for CliError {}

impl From<kr_ipc::IpcError> for CliError {
    fn from(error: kr_ipc::IpcError) -> Self {
        Self::Ipc(error)
    }
}

impl CliError {
    /// Builds a refusal this command made itself, in words that already say what a person does
    /// about it.
    ///
    /// A host's refusal knows nothing more than its code, so a person is also told the action the
    /// code calls for. A refusal made here is worded for the case it refuses, and adding an
    /// action chosen by its code would put a second, general instruction after the specific one.
    /// It is said by those words alone, and `--json` still carries its code.
    #[must_use]
    pub fn refused_in_its_own_words(
        code: kr_protocol::error::ErrorCode,
        message: impl Into<Shown>,
    ) -> Self {
        Self::ServiceRefused {
            error: kr_client::error::refusal(code, message.into()),
            action: UserAction::Nothing,
        }
    }

    /// Returns what a `--json` failure carries as its `message`.
    ///
    /// What a person is told of a refusal leaves its code out, and a script reads the code as a
    /// field beside the message. The message it has always been given for a refusal begins with
    /// that code, and is kept as it was.
    #[must_use]
    pub fn machine_message(&self) -> Shown {
        match self {
            Self::Refused(error) | Self::ServiceRefused { error, .. } => {
                shown!("{}: {}", error.code, Shown::protocol(error))
            }
            other => other.said(),
        }
    }

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
            Self::Refused(_) | Self::ServiceRefused { .. } => 8,
            Self::UpdateDeferred(_) => 9,
            Self::Ipc(_) | Self::AnswerKept { .. } => 3,
            Self::SessionClosed(_) | Self::Unfinished { .. } | Self::Other(_) => 1,
        }
    }

    /// Returns the stable code a `--json` failure carries.
    #[must_use]
    pub const fn code(&self) -> kr_protocol::error::ErrorCode {
        match self {
            Self::Usage(_) => kr_protocol::error::ErrorCode::InvalidArgument,
            Self::HostUnavailable(_) | Self::Ipc(_) => {
                kr_protocol::error::ErrorCode::HostNotConfigured
            }
            Self::UnknownSession(_) => kr_protocol::error::ErrorCode::UnknownSession,
            Self::NotInSession => kr_protocol::error::ErrorCode::NotInKrSession,
            Self::ShellIntegrationUnsupported(_) => {
                kr_protocol::error::ErrorCode::ShellIntegrationUnsupported
            }
            Self::AmbiguousSession(_) => kr_protocol::error::ErrorCode::AmbiguousSession,
            Self::NotATerminal | Self::Terminal(_) | Self::TerminalProbeFailed(_) => {
                kr_protocol::error::ErrorCode::TerminalProbeFailed
            }
            Self::TerminalUnavailable(_) => kr_protocol::error::ErrorCode::TerminalUnavailable,
            Self::Refused(error) | Self::ServiceRefused { error, .. } => error.code,
            Self::SessionClosed(_) => kr_protocol::error::ErrorCode::SessionClosed,
            Self::Unfinished { code, .. } | Self::AnswerKept { code, .. } => *code,
            Self::UpdateDeferred(_) | Self::Other(_) => {
                kr_protocol::error::ErrorCode::ResourceUnavailable
            }
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

    /// KR-REQ-07.50: every failure exits with a status other than zero, and each kind of failure
    /// with its own.
    #[test]
    fn each_failure_has_its_own_exit_code() {
        let codes = [
            CliError::Usage(Shown::said("")).exit_code(),
            CliError::HostUnavailable(Shown::said("")).exit_code(),
            CliError::UnknownSession(Shown::said("")).exit_code(),
            CliError::AmbiguousSession(Shown::said("")).exit_code(),
            CliError::NotATerminal.exit_code(),
            CliError::TerminalUnavailable(Shown::said("")).exit_code(),
            CliError::UpdateDeferred(Shown::said("")).exit_code(),
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
