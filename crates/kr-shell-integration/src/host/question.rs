//! The questions an install asks the PowerShell it found, and the ways a question ends.
//!
//! A question ends in exactly one of the ways of [`Ending`], and [`conclude`] says what the install
//! does for each question and each way: it goes on with the answer, or it ends with the refusal that
//! says what happened, or with this host's own failure. Nothing else chooses what is said, and the
//! match in [`conclude`] has no arm that stands for more than the ways it names, so a way added to
//! [`Ending`] is not compiled until each question has said what it does with it.

use std::path::{Path, PathBuf};

use crate::host::refusal::Refusal;

/// A question the install asks PowerShell.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Question {
    /// Where its two per-user profiles are.
    Profiles,
    /// Where an entry goes in a profile's text.
    Placement,
    /// The check of the profile with the entry in it.
    Check,
}

/// This host's own failure in a call that asks a question: the path that failed, and the system's
/// error. The path is a folder or file of the call, or the program that this host could not wait
/// for.
///
/// It is the failure of this host and not of PowerShell, so it is said as any failure of a file of
/// this host's is said, and not as a refusal. [`host_fault`] finds one in an error.
#[derive(Debug)]
pub struct HostFault {
    file: PathBuf,
    error: std::io::Error,
}

impl HostFault {
    /// The failure of `error` in `file`.
    #[must_use]
    pub fn new(file: PathBuf, error: std::io::Error) -> Self {
        Self { file, error }
    }
}

impl std::fmt::Display for HostFault {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.file.display(), self.error)
    }
}

impl std::error::Error for HostFault {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

impl From<HostFault> for std::io::Error {
    fn from(fault: HostFault) -> Self {
        Self::new(fault.error.kind(), fault)
    }
}

/// Returns the path and the system's error where `error` is this host's own failure in a call that
/// asked a question, which is not PowerShell's refusal or failure to answer.
#[must_use]
pub fn host_fault(error: &std::io::Error) -> Option<(&Path, &std::io::Error)> {
    let fault = error.get_ref()?.downcast_ref::<HostFault>()?;
    Some((&fault.file, &fault.error))
}

/// How a question ended.
#[derive(Debug)]
pub enum Ending<T> {
    /// The program ended with code 0 and its answer was read and understood: this is what it said.
    Used(T),
    /// The program ended with code 0 and its answer is longer than this host reads.
    TooLong,
    /// The program ended with code 0 and its answer is not text.
    NotText,
    /// The program ended with code 0 and its answer is text that the question does not take: none,
    /// or another form than the one it asked for.
    WrongForm,
    /// The program did not end in time: this host ended it, reaped it and read no answer.
    TimedOut,
    /// The program could not be started.
    NotStarted,
    /// The program ended with a code other than 0.
    Failed,
    /// The program was ended by a signal.
    Signalled,
    /// This host could not prepare the call: its folder, the file for the answer, a file for an
    /// input or one of the folders the program runs in. The program was not started.
    NotPrepared(HostFault),
    /// This host could not wait for the program: whether it answered, ended or still runs is not
    /// known, so no answer is read and the program is not ended. The failure names the program.
    WaitFailed(HostFault),
    /// The program ended with code 0, and this host could not read the file that holds its answer.
    Unread(HostFault),
}

/// Returns what a question that ended in `ending` gives: the value of an answer that was used, or the
/// error that ends the install.
///
/// A refusal ([`Refusal::of`]) where PowerShell did not answer, or answered what is not understood;
/// this host's own failure ([`host_fault`]) where it could not prepare the call, could not wait for
/// the program or could not read the answer.
///
/// # Errors
///
/// Returns the refusal or the failure of the way the question ended in, as above.
pub fn conclude<T>(question: Question, ending: Ending<T>) -> std::io::Result<T> {
    use Question::{Check, Placement, Profiles};

    match (question, ending) {
        (Profiles | Placement | Check, Ending::Used(value)) => Ok(value),
        (Profiles, Ending::TooLong | Ending::NotText | Ending::WrongForm) => {
            Err(Refusal::ProfilesNotUnderstood.into())
        }
        (Placement, Ending::TooLong | Ending::NotText | Ending::WrongForm) => {
            Err(Refusal::PlacementNotUnderstood.into())
        }
        (Check, Ending::TooLong | Ending::NotText | Ending::WrongForm) => {
            Err(Refusal::CheckNotUnderstood.into())
        }
        (Profiles, Ending::TimedOut | Ending::NotStarted | Ending::Failed | Ending::Signalled) => {
            Err(Refusal::ProfilesUnanswered.into())
        }
        (Placement, Ending::TimedOut | Ending::NotStarted | Ending::Failed | Ending::Signalled) => {
            Err(Refusal::PlacementUnanswered.into())
        }
        (Check, Ending::TimedOut | Ending::NotStarted | Ending::Failed | Ending::Signalled) => {
            Err(Refusal::CheckUnanswered.into())
        }
        (
            Profiles | Placement | Check,
            Ending::NotPrepared(fault) | Ending::WaitFailed(fault) | Ending::Unread(fault),
        ) => Err(fault.into()),
    }
}
