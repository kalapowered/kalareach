//! What a service answers an action with, and where the answer came from.
//!
//! A service that finds an action already in its own record answers from that record instead of
//! performing the action again. That answer is a copy of what an earlier submission produced, and
//! the network door tells a device a copy as it tells any answer it finds in a record: when the
//! device may not read the record, or the authority feed refuses before the answer is written, as
//! an outcome that is unknown, whatever the answer was. A device that may not read the record would
//! otherwise tell a result from a refusal by the word it is given. So every service says which of
//! the three an answer is, in the type it returns, and the door asks.

use kr_protocol::envelope::{ControlFrame, Outcome, Response};

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

    /// The answer, without where it came from, for a caller that is told every answer whole except
    /// a copy the service withheld: `unknown` is then what the caller is told, in place of the
    /// service's refusal of the authority, which says what the caller may not be told, that the
    /// action did not happen.
    pub(crate) fn into_answer_or(self, unknown: impl FnOnce() -> T) -> T {
        match self {
            Self::Withheld(_) => unknown(),
            Self::Fresh(answer) | Self::Copied(answer) => answer,
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
        Given::Copied(self.0)
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
        Given::Withheld(refusal)
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
    /// The frame, given back as a copy unless the authority `check` stops it: then the check's
    /// refusal, as a frame for `id` that replaces the record's, as a copy the service withheld.
    pub(crate) fn checked_frame(
        self,
        id: kr_protocol::ids::RequestId,
        check: impl FnOnce() -> Result<(), crate::error::ControllerError>,
    ) -> Given<ControlFrame> {
        match check() {
            Ok(()) => Given::Copied(self.0),
            Err(refusal) => self.refused_by(crate::service::error_reply(
                id,
                refusal.code(),
                refusal.to_string(),
            )),
        }
    }

    /// Whether the record says another request spent the identifier of this one. That is this
    /// host's word about the identifier and names no result.
    pub(crate) const fn names_a_reused_identifier(&self) -> bool {
        matches!(
            &self.0,
            ControlFrame::Response(Response {
                outcome: Outcome::Error(error),
                ..
            }) if matches!(error.code, kr_protocol::error::ErrorCode::IdConflict)
        )
    }
}

/// The boundary of a caller inside the daemon, which is told every answer whole.
pub(crate) mod host_context {
    use super::Given;

    /// The answer of the host's own workflow, which goes to no caller outside the daemon: it acts
    /// for its node under the node's own admission, so what it is given is the answer whatever
    /// its origin.
    pub(crate) fn whole<T>(given: Given<T>) -> T {
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
        assert_eq!(given.into_answer().ok(), Some(7));

        let given = Recorded::read(Ok::<_, ControllerError>(7)).checked(|| Err(refusal()));
        assert!(given.is_withheld());
        assert!(matches!(
            given.into_answer(),
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
        assert!(failed.checked(|| Ok(())).into_answer().is_err());
    }

    /// A frame the check stops is replaced by a refusal frame for the request, and a record that
    /// names a reused identifier says so.
    #[test]
    fn a_frame_the_check_stops_is_replaced_by_the_refusal() {
        let id = RequestId::new(3);
        let conflict = Recorded::read(ControlFrame::Response(Response {
            request_id: id,
            outcome: Outcome::Error(refusal_of(ErrorCode::IdConflict)),
        }));
        assert!(conflict.names_a_reused_identifier());
        let given = conflict.checked_frame(id, || Err(refusal()));
        assert!(given.is_withheld());
        let ControlFrame::Response(Response {
            outcome: Outcome::Error(told),
            ..
        }) = given.into_answer()
        else {
            panic!("the refusal is an error frame");
        };
        assert_eq!(told.code, ErrorCode::PermissionDenied);
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
            answer.copied().into_answer(),
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
