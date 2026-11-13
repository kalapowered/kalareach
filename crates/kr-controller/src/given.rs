//! What a service answers an action with, and where the answer came from.
//!
//! A service that finds an action already in its own record answers from that record instead of
//! performing the action again. That answer is a copy of what an earlier submission produced, and
//! the network door tells a device a copy as it tells any answer it finds in a record: when the
//! device may not read the record, or the authority feed refuses before the answer is written, as
//! an outcome that is unknown, whatever the answer was. A device that may not read the record would
//! otherwise tell a result from a refusal by the word it is given. So every service says which of
//! the three an answer is, in the type it returns, and the door asks.
//!
//! The representation of [`Given`] is private to this module, so that nothing outside it can take
//! the answer of a copy out and give the value again as an answer made now.

use kr_protocol::envelope::{ControlFrame, Outcome, Response};
use kr_protocol::error::{ErrorCode, ProtocolError, RetryCategory};
use kr_protocol::receipt::ReceiptState;

use crate::service::HostWithdrawal;

pub(crate) mod local_door;
pub(crate) mod network_door;

/// A service's answer to one action.
///
/// It is one of three: the answer to the submission that performed the action, or that was
/// refused before it could ([`Self::fresh`]); the answer an earlier submission of the action left
/// in the service's own record ([`Self::copied`]); or the refusal of a copy the service read from
/// its own record and would not give back, because the authority the copy arrived under no longer
/// stands ([`Self::withheld`]).
///
/// A withheld refusal says nothing of what the record holds, which is not the copy's to be told,
/// and nothing of whether the action took effect. A door that tells a device a recorded answer
/// asks its own check once more; if that one passes, because the fence that stopped the service
/// has gone meanwhile, a refusal told as the kept answer would say the action did not happen. So
/// the door never tells this one as an answer: a device is told the outcome is not shown, whatever
/// its authority is by then. The answer is what a caller that is told every answer whole is given.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use = "the door tells a copy of a recorded answer differently from a fresh one"]
pub struct Given<T> {
    origin: Origin,
    answer: T,
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
    /// The answer to the submission that performed the action, or that was refused before it
    /// could.
    pub const fn fresh(answer: T) -> Self {
        Self {
            origin: Origin::Fresh,
            answer,
        }
    }

    /// The answer an earlier submission of the action left in the service's own record.
    pub const fn copied(answer: T) -> Self {
        Self {
            origin: Origin::Copied,
            answer,
        }
    }

    /// The refusal of a copy the service read from its own record and would not give back.
    pub const fn withheld(answer: T) -> Self {
        Self {
            origin: Origin::Withheld,
            answer,
        }
    }

    /// `answer`, a copy of a record when `copied` says so.
    pub const fn of(answer: T, copied: bool) -> Self {
        if copied {
            Self::copied(answer)
        } else {
            Self::fresh(answer)
        }
    }

    /// `answer`, from where `origin` says the service found it.
    pub(crate) const fn from_origin(answer: T, origin: Origin) -> Self {
        Self { origin, answer }
    }

    /// Whether the service read this answer from the record of an earlier submission and gave it
    /// back.
    #[must_use]
    pub const fn is_copied(&self) -> bool {
        matches!(self.origin, Origin::Copied)
    }

    /// Whether the service read the record of an earlier submission and withheld what it holds.
    #[must_use]
    pub const fn is_withheld(&self) -> bool {
        matches!(self.origin, Origin::Withheld)
    }

    /// Where the answer came from, for a door that tells a device the answer.
    pub(crate) const fn origin(&self) -> Origin {
        self.origin
    }

    /// The answer, borrowed, for a service that records what it came to and then gives the
    /// answer on whole. It cannot be taken out of the provenance by this.
    pub(crate) const fn answer_ref(&self) -> &T {
        &self.answer
    }

    /// The refusal of a copy the service withheld, for a case that asks why a record was not given
    /// back. Panics when the service gave the record back or answered for itself.
    #[cfg(test)]
    pub(crate) fn into_withheld(self) -> T {
        match self.origin {
            Origin::Withheld => self.answer,
            Origin::Fresh => panic!("the service answered for itself and withheld nothing"),
            Origin::Copied => panic!("the service gave the record back"),
        }
    }

    /// The answer, without where it came from, for a case that asks what a service answered.
    #[cfg(any(test, feature = "testing"))]
    pub fn into_answer_for_test(self) -> T {
        self.answer
    }

    /// The answer, without where it came from. For a boundary that tells every answer whole.
    fn into_answer(self) -> T {
        self.answer
    }

    /// The same provenance on another form of the answer.
    pub fn map<U>(self, form: impl FnOnce(T) -> U) -> Given<U> {
        Given {
            origin: self.origin,
            answer: form(self.answer),
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
                Self::withheld(Err(refusal))
            } else {
                Self::fresh(Err(refusal))
            };
        }
        Self::of(answer, copied)
    }
}

impl<T> Given<Result<T, ProtocolError>> {
    /// Whether the strict check is owed to this answer once it is in hand: it is a copy, or it
    /// says another request spent the action's identifier.
    pub(crate) fn is_held_to_the_strict_check(&self) -> bool {
        self.is_copied()
            || (self.origin == Origin::Fresh
                && matches!(&self.answer, Err(refusal) if refusal.code == ErrorCode::IdConflict))
    }

    /// This answer replaced by `refusal`, which the strict check refused it with: a copy is
    /// withheld, and any other answer is the host's own refusal.
    pub(crate) fn refused_by(self, refusal: ProtocolError) -> Self {
        if self.is_copied() {
            Self::withheld(Err(refusal))
        } else {
            Self::fresh(Err(refusal))
        }
    }
}

/// What a local write came to: the service's answer, with where it came from.
///
/// The local door tells this and nothing else ([`local_door::told`]).
#[derive(Debug)]
#[must_use = "the local door tells a write only through `told`"]
pub(crate) struct Settled<T> {
    given: Given<T>,
    /// Evidence that the write's own effect raised the barrier that withdrew every connection of
    /// the host, this write's own included.
    withdrew: Option<HostWithdrawal>,
}

impl<T> Settled<T> {
    /// A write that came to `given`.
    pub(crate) const fn of(given: Given<T>) -> Self {
        Self {
            given,
            withdrew: None,
        }
    }

    /// A write that came to `given`, and that withdrew the whole host through its own barrier
    /// when `withdrew` says so.
    pub(crate) const fn withdrawing(given: Given<T>, withdrew: Option<HostWithdrawal>) -> Self {
        Self { given, withdrew }
    }

    /// The same write, its answer reshaped by `reshape`.
    pub(crate) fn map<U>(self, reshape: impl FnOnce(T) -> U) -> Settled<U> {
        Settled {
            given: self.given.map(reshape),
            withdrew: self.withdrew,
        }
    }

    /// What the write came to, for the network door, which asks of an answer what it asks of every
    /// one and has no connection of its own to withdraw.
    pub(crate) fn into_given(self) -> Given<T> {
        self.given
    }

    /// The answer, without where it came from, for a case that asks what a write came to.
    #[cfg(test)]
    pub(crate) fn into_answer_for_test(self) -> T {
        self.given.into_answer_for_test()
    }
}

/// What a client is told when this host will not show it what became of an action that was, or may
/// have been, carried out.
///
/// The refusal to show it is about what the client may be shown, not about the action. A client
/// takes a definite refusal for the host's word that nothing was done and drops the action, so the
/// person would be told the action did not happen when it did.
pub(crate) fn outcome_not_shown() -> ProtocolError {
    crate::error::ControllerError::outcome_not_shown().to_protocol_error()
}

/// Whether `refusal` is a definite word that the action it answers did not happen.
///
/// A client keeps an action it sent when the answer is `OUTCOME_UNKNOWN` or a transient failure,
/// and takes any other refusal as the host's word that nothing was done.
pub(crate) fn is_definite(refusal: &ProtocolError) -> bool {
    !matches!(
        refusal.code.retry_category(),
        RetryCategory::Transient | RetryCategory::OutcomeUnknown
    )
}

/// Whether `answer`, the host's answer to an action, leaves it possible that the action took
/// effect: its result, or a word that does not say it did not happen.
pub(crate) fn may_have_taken_effect(answer: &ControlFrame) -> bool {
    match answer {
        ControlFrame::Response(Response {
            outcome: Outcome::Ok(_),
            ..
        }) => true,
        ControlFrame::Response(Response {
            outcome: Outcome::Error(error),
            ..
        }) => !is_definite(error),
        // A receipt says what became of the action, and only a refusal or a rejection says that
        // nothing did.
        ControlFrame::Receipt(response) => !matches!(
            response.receipt.state,
            ReceiptState::Refused | ReceiptState::Rejected
        ),
        _ => false,
    }
}

/// What a client is told when this host refuses, after it holds `answer` to an action, to show it
/// that answer: [`outcome_not_shown`] when the answer leaves it possible that the action took
/// effect, and `refusal` when the answer says it did not.
pub(crate) fn after_the_outcome(answer: &ControlFrame, refusal: ProtocolError) -> ProtocolError {
    if may_have_taken_effect(answer) {
        outcome_not_shown()
    } else {
        refusal
    }
}

/// Whether `answer` says another request spent the identifier of this one. That is this host's
/// word about the identifier and names no result.
pub(crate) const fn names_a_reused_identifier(answer: &ControlFrame) -> bool {
    matches!(
        answer,
        ControlFrame::Response(Response {
            outcome: Outcome::Error(error),
            ..
        }) if matches!(error.code, kr_protocol::error::ErrorCode::IdConflict)
    )
}

/// What a lookup read from a record an earlier request, event or attempt left.
///
/// A value read from a record says what that record held, and the door that tells it to a caller
/// must ask the authority the caller still has before it does, whatever the record holds: an
/// answer, a refusal, an identifier another request spent, or a row that could not be read. So a
/// lookup returns its read in this type, whose field is private and which has no operation that
/// hands the value back. Each way out is a named operation that ends in a copy given back or a
/// copy withheld, and none takes a closure over the value.
#[derive(Debug)]
#[must_use = "a record that was read is told only through the operation that asks its check"]
pub struct Recorded<T>(T);

impl<T> Recorded<T> {
    /// What a lookup read, as the lookup's own return.
    pub(crate) const fn read(value: T) -> Self {
        Self(value)
    }

    /// An answer a record supplied, given back as a copy.
    pub(crate) fn copied(self) -> Given<T> {
        Given::copied(self.0)
    }

    /// What the lookup read, for a test in another crate that asks a lookup directly. A test
    /// inside this crate collapses the read as the door does, with `copied`.
    #[cfg(any(test, feature = "testing"))]
    pub fn into_answer_for_test(self) -> T {
        self.0
    }

    /// The check refused the record: `refusal` stands in its place, as a copy the service
    /// withheld. The record itself is dropped.
    pub(crate) fn refused_by(self, refusal: T) -> Given<T> {
        drop(self.0);
        Given::withheld(refusal)
    }
}

impl<T, E> Recorded<Result<T, E>> {
    /// The answer a record supplied, given back as a copy unless the authority `check` stops it:
    /// then the check's refusal, as a copy the service withheld. The check takes no value, so it
    /// cannot ask about what the record says.
    pub(crate) fn checked(self, check: impl FnOnce() -> Result<(), E>) -> Given<Result<T, E>> {
        Given::checked(self.0, true, false, check)
    }
}

impl<T> Recorded<Result<T, crate::error::ControllerError>> {
    /// [`Self::checked`], for a record that may hold the conflict a reused identifier meets: that
    /// answer is no copy of a result but the host's word about another request's use of the
    /// identifier, so a check that stops it is the host's own refusal, which is true: this request
    /// was not performed.
    pub(crate) fn checked_or_reused(
        self,
        check: impl FnOnce() -> Result<(), crate::error::ControllerError>,
    ) -> Given<Result<T, crate::error::ControllerError>> {
        let reused = matches!(
            self.0,
            Err(crate::error::ControllerError::IdConflict { .. })
        );
        Given::checked(self.0, !reused, reused, check)
    }
}

impl<T, E> Recorded<Result<Option<T>, E>> {
    /// The read, when a record was found. `Ok(None)` is the one exit that names no record: a read
    /// that failed stays inside the type, as the record that could not be read.
    pub(crate) fn present(self) -> Option<Recorded<Result<T, E>>> {
        match self.0 {
            Ok(None) => None,
            Ok(Some(found)) => Some(Recorded(Ok(found))),
            Err(error) => Some(Recorded(Err(error))),
        }
    }
}

impl Recorded<Result<kr_protocol::envelope::ParamsValue, crate::error::ControllerError>> {
    /// The read, framed as the answer to the request `id`.
    pub(crate) fn respond(self, id: kr_protocol::ids::RequestId) -> Recorded<ControlFrame> {
        Recorded(crate::service::respond(id, self.0))
    }

    /// The read framed as the answer to the request `id`, when it is an answer: a read that is a
    /// refusal gives nothing a door may go on with.
    pub(crate) fn answered(
        self,
        id: kr_protocol::ids::RequestId,
    ) -> Option<Recorded<ControlFrame>> {
        self.0
            .ok()
            .map(|answer| Recorded(crate::service::respond(id, Ok(answer))))
    }
}

impl Recorded<ControlFrame> {
    /// Whether the record says another request spent the identifier of this one. That is this
    /// host's word about the identifier and names no result.
    pub(crate) const fn names_a_reused_identifier(&self) -> bool {
        names_a_reused_identifier(&self.0)
    }
}

/// The boundary of a caller inside the daemon, which is told every answer whole.
pub(crate) mod host_context {
    use super::Given;

    /// The answer of the host's own workflow, which goes to no caller outside the daemon: it acts
    /// for its node under the node's own admission, so what it is given is the answer whatever
    /// its origin.
    pub(crate) fn whole<T>(_at: crate::service::AtTheHostsOwnWorkflow, given: Given<T>) -> T {
        given.into_answer()
    }
}

#[cfg(test)]
mod tests {
    use kr_protocol::envelope::{ControlFrame, Outcome, ParamsValue, Response};
    use kr_protocol::error::ErrorCode;
    use kr_protocol::ids::RequestId;

    use super::Recorded;
    use crate::error::ControllerError;

    fn refusal() -> ControllerError {
        ControllerError::PermissionDenied {
            detail: "the authority has been withdrawn".to_owned(),
        }
    }

    /// A record that was read is given back as a copy when the check passes, and is replaced by
    /// the check's refusal, withheld, when it does not.
    #[test]
    fn a_record_is_given_back_only_through_its_check() {
        let given = Recorded::read(Ok::<_, ControllerError>(7)).checked(|| Ok(()));
        assert!(given.is_copied());
        assert_eq!(given.into_answer_for_test().ok(), Some(7));

        let given = Recorded::read(Ok::<_, ControllerError>(7)).checked(|| Err(refusal()));
        assert!(given.is_withheld());
        assert!(matches!(
            given.into_answer_for_test(),
            Err(ControllerError::PermissionDenied { .. })
        ));
    }

    /// A read that found nothing names no record; a read that failed does, and stays inside.
    #[test]
    fn only_a_read_that_found_nothing_leaves_the_type_empty() {
        assert!(
            Recorded::read(Ok::<Option<u8>, ControllerError>(None))
                .present()
                .is_none()
        );
        let failed = Recorded::read(Err::<Option<u8>, _>(refusal()))
            .present()
            .expect("a read that failed names a record that could not be read");
        assert!(failed.checked(|| Ok(())).into_answer_for_test().is_err());
    }

    /// A record that names a reused identifier says so, and one that names any other refusal does
    /// not.
    #[test]
    fn a_record_that_names_a_reused_identifier_says_so() {
        let id = RequestId::new(3);
        let conflict = Recorded::read(ControlFrame::Response(Response {
            request_id: id,
            outcome: Outcome::Error(refusal_of(ErrorCode::IdConflict)),
        }));
        assert!(conflict.names_a_reused_identifier());
        assert!(
            !Recorded::read(ControlFrame::Response(Response {
                request_id: id,
                outcome: Outcome::Error(refusal_of(ErrorCode::PermissionDenied)),
            }))
            .names_a_reused_identifier()
        );
    }

    /// A read that is an answer is framed for the request and stays a record; a read that is a
    /// refusal gives nothing a door may go on with.
    #[test]
    fn a_read_that_is_a_refusal_gives_no_answer_to_go_on_with() {
        let id = RequestId::new(5);
        let answer = Recorded::read(Ok::<_, ControllerError>(ParamsValue::empty()))
            .answered(id)
            .expect("an answer is framed");
        assert!(matches!(
            answer.copied().into_answer_for_test(),
            ControlFrame::Response(Response {
                outcome: Outcome::Ok(_),
                ..
            })
        ));
        assert!(
            Recorded::read(Err::<ParamsValue, _>(refusal()))
                .answered(id)
                .is_none()
        );
    }

    fn refusal_of(code: ErrorCode) -> kr_protocol::error::ProtocolError {
        kr_protocol::error::ProtocolError::new(code, "refused")
    }
}
