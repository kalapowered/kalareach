//! What a service answers an action with, and where the answer came from.
//!
//! A service that finds an action already in its own record answers from that record instead of
//! performing the action again. That answer is a copy of what an earlier submission produced, and
//! the network door tells a device a copy as it tells any answer it finds in a record: when the
//! device may not read the record, or the authority feed refuses before the answer is written, as
//! an outcome that is unknown, whatever the answer was. A device that may not read the record would
//! otherwise tell a result from a refusal by the word it is given. So every service says which of
//! the two an answer is, in the type it returns, and the door asks.

/// A service's answer to one action.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use = "the door tells a copy of a recorded answer differently from a fresh one"]
pub enum Given<T> {
    /// The answer to the submission that performed the action, or that was refused before it could.
    Fresh(T),
    /// The answer an earlier submission of the action left in the service's own record.
    Copied(T),
}

impl<T> Given<T> {
    /// `answer`, a copy of a record when `copied` says so.
    pub const fn of(answer: T, copied: bool) -> Self {
        if copied {
            Self::Copied(answer)
        } else {
            Self::Fresh(answer)
        }
    }

    /// Whether the service read this answer from the record of an earlier submission.
    #[must_use]
    pub const fn is_copied(&self) -> bool {
        matches!(self, Self::Copied(_))
    }

    /// The answer, without where it came from. For a caller that is told every answer whole.
    pub fn into_answer(self) -> T {
        match self {
            Self::Fresh(answer) | Self::Copied(answer) => answer,
        }
    }

    /// The same provenance on another form of the answer.
    pub fn map<U>(self, form: impl FnOnce(T) -> U) -> Given<U> {
        match self {
            Self::Fresh(answer) => Given::Fresh(form(answer)),
            Self::Copied(answer) => Given::Copied(form(answer)),
        }
    }
}
