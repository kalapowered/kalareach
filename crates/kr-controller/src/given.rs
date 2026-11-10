//! What a service answers an action with, and where the answer came from.
//!
//! A service that finds an action already in its own record answers from that record instead of
//! performing the action again. That answer is a copy of what an earlier submission produced, and
//! the network door tells a device a copy as it tells any answer it finds in a record: when the
//! device may not read the record, or the authority feed refuses before the answer is written, as
//! an outcome that is unknown, whatever the answer was. A device that may not read the record would
//! otherwise tell a result from a refusal by the word it is given. So every service says which of
//! the three an answer is, in the type it returns, and the door asks.

/// A service's answer to one action.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use = "the door tells a copy of a recorded answer differently from a fresh one"]
pub enum Given<T> {
    /// The answer to the submission that performed the action, or that was refused before it could.
    Fresh(T),
    /// The answer an earlier submission of the action left in the service's own record.
    Copied(T),
    /// The refusal of a copy the service read from its own record and would not give back, because
    /// the authority the copy arrived under no longer stands.
    ///
    /// It says nothing of what the record holds, which is not the copy's to be told, and nothing of
    /// whether the action took effect. A door that tells a device a recorded answer asks its own
    /// check once more; if that one passes, because the fence that stopped the service has gone
    /// meanwhile, a refusal told as the kept answer would say the action did not happen. So the door
    /// never tells this one as an answer: a device is told the outcome is not shown, whatever its
    /// authority is by then. The answer is what a caller that is told every answer whole is given.
    Withheld(T),
}

/// Where a door has found the answers it was given to come from.
///
/// Ordered by how much the door must hold back: an answer a service withheld outranks one it
/// copied, which outranks one it made.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub(crate) enum Origin {
    /// Every answer was made by the submission itself.
    #[default]
    Fresh,
    /// An answer was read from the record of an earlier submission.
    Copied,
    /// A service read an earlier submission's record and withheld it.
    Withheld,
}

impl Origin {
    /// Notes the origin of one more answer: the one that must be held back most stands.
    pub(crate) fn note(&mut self, answer: Self) {
        *self = (*self).max(answer);
    }
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

    /// `answer`, from where `origin` says the service found it.
    pub(crate) const fn from_origin(answer: T, origin: Origin) -> Self {
        match origin {
            Origin::Fresh => Self::Fresh(answer),
            Origin::Copied => Self::Copied(answer),
            Origin::Withheld => Self::Withheld(answer),
        }
    }

    /// Whether the service read this answer from the record of an earlier submission and gave it
    /// back.
    #[must_use]
    pub const fn is_copied(&self) -> bool {
        matches!(self, Self::Copied(_))
    }

    /// Whether the service read the record of an earlier submission and withheld what it holds.
    #[must_use]
    pub const fn is_withheld(&self) -> bool {
        matches!(self, Self::Withheld(_))
    }

    /// Where the answer came from, for a door that tells a device the answer.
    pub(crate) const fn origin(&self) -> Origin {
        match self {
            Self::Fresh(_) => Origin::Fresh,
            Self::Copied(_) => Origin::Copied,
            Self::Withheld(_) => Origin::Withheld,
        }
    }

    /// The refusal of a copy the service withheld, for a case that asks why a record was not given
    /// back. Panics when the service gave the record back or answered for itself.
    #[cfg(test)]
    pub(crate) fn into_withheld(self) -> T {
        match self {
            Self::Withheld(answer) => answer,
            Self::Fresh(_) => panic!("the service answered for itself and withheld nothing"),
            Self::Copied(_) => panic!("the service gave the record back"),
        }
    }

    /// The answer, without where it came from. For a caller that is told every answer whole.
    pub fn into_answer(self) -> T {
        match self {
            Self::Fresh(answer) | Self::Copied(answer) | Self::Withheld(answer) => answer,
        }
    }

    /// The same provenance on another form of the answer.
    pub fn map<U>(self, form: impl FnOnce(T) -> U) -> Given<U> {
        match self {
            Self::Fresh(answer) => Given::Fresh(form(answer)),
            Self::Copied(answer) => Given::Copied(form(answer)),
            Self::Withheld(answer) => Given::Withheld(form(answer)),
        }
    }
}

impl<T, E> Given<Result<T, E>> {
    /// `answer`, a copy of a record when `copied` says so, unless the authority `check` stops it:
    /// then the refusal of the check, as a copy the service withheld.
    ///
    /// The check is asked once the answer it would stop is in hand, so a refusal replaces what the
    /// record held and never the other way round. It is asked for a copy, and for an answer that
    /// says another request spent the action's identifier (`reused`), which names no result and is
    /// no copy but tells the caller of another attempt: the check's refusal then replaces it, told
    /// as the service's own.
    pub fn checked(
        answer: Result<T, E>,
        copied: bool,
        reused: bool,
        check: impl FnOnce() -> Result<(), E>,
    ) -> Self {
        if (copied || reused)
            && let Err(refusal) = check()
        {
            return if copied {
                Self::Withheld(Err(refusal))
            } else {
                Self::Fresh(Err(refusal))
            };
        }
        Self::of(answer, copied)
    }
}
