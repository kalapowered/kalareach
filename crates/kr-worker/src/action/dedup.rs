//! De-duplication's two rules that are not about the payload digest.
//!
//! The digest rule lives in [`crate::journal`]: an exact duplicate returns the retained receipt,
//! and an identifier reused with a different payload is `ID_CONFLICT`. Two other rules keep the
//! same boundary honest, and both are here because both are decisions rather than lookups.
//!
//! * **A service cannot choose a new identifier to evade de-duplication.** Section 23: if an
//!   upstream result is uncertain, an explicit later user request needs a new action identifier and
//!   must *show* the earlier unknown result. So a fresh action for a subject that already carries
//!   an uncertain outcome is refused unless its preconditions name that action and the revision at
//!   which the caller saw it. A service that wanted to hide the uncertainty would have to name the
//!   receipt it was hiding.
//! * **Eight outstanding mutations per device and session.** A caller that keeps submitting
//!   without waiting is holding durable admissions this host has to revalidate and settle. The
//!   limit is section 9's, and the negotiated limit lowers it rather than raising it.

use kr_protocol::ids::ActionId;
use kr_protocol::limits::MAX_OUTSTANDING_MUTATIONS;

use crate::error::{Result, WorkerError};

/// What a fresh action showed about the uncertain outcome it supersedes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Supersession {
    /// The earlier action this request supersedes.
    pub action_id: ActionId,
    /// The receipt revision at which the caller saw that action's result.
    pub revision: u64,
}

/// The uncertain outcome that stands in a fresh action's way.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Uncertain {
    /// The action whose outcome is uncertain.
    pub action_id: ActionId,
    /// The revision its receipt currently stands at.
    pub revision: u64,
}

/// Decides whether a fresh action may be admitted for a subject that already carries an uncertain
/// outcome.
///
/// # Errors
///
/// Returns [`WorkerError::PreconditionFailed`] when a fresh action would silently take the place
/// of an uncertain one, and when it names the wrong action or a revision the caller cannot have
/// seen.
pub fn check_supersession(
    uncertain: Option<Uncertain>,
    declared: Option<Supersession>,
) -> Result<()> {
    match (uncertain, declared) {
        // Nothing uncertain stands in the way. A request that names one anyway is naming a fact
        // that is not true of this subject, which is what a precondition failure is for.
        (None, None) => Ok(()),
        (None, Some(declared)) => Err(WorkerError::PreconditionFailed {
            detail: format!(
                "action {} is not an uncertain outcome of this subject",
                declared.action_id
            ),
        }),
        (Some(uncertain), None) => Err(WorkerError::PreconditionFailed {
            detail: format!(
                "action {} for this subject has an uncertain outcome; a later request has to name \
                 it and the revision it was read at, so the earlier result is shown rather than \
                 replaced by a new identifier",
                uncertain.action_id
            ),
        }),
        (Some(uncertain), Some(declared)) if declared.action_id != uncertain.action_id => {
            Err(WorkerError::PreconditionFailed {
                detail: format!(
                    "the uncertain outcome of this subject is action {}, not {}",
                    uncertain.action_id, declared.action_id
                ),
            })
        }
        (Some(uncertain), Some(declared)) if declared.revision != uncertain.revision => {
            // The caller is quoting a revision other than the one the receipt stands at. Either it
            // has not read the current result or it is quoting one that does not exist; both mean
            // the earlier result has not been shown.
            Err(WorkerError::PreconditionFailed {
                detail: format!(
                    "action {} stands at revision {}, and this request was read at {}",
                    uncertain.action_id, uncertain.revision, declared.revision
                ),
            })
        }
        (Some(_), Some(_)) => Ok(()),
    }
}

/// Returns how many mutations one actor may hold admitted and unsettled at once.
///
/// Two bounds, and the smaller wins. Section 9's figure is what this build carries, and a peer
/// that offers a larger one is offering to send more than the host accepts. An offer of nought is
/// refused at the handshake rather than reached here, because a connection that admits nothing is
/// not a connection; the clamp below keeps this answer sound for any caller anyway.
///
/// This build has no configured host limit above section 9's default. When one arrives it replaces
/// the constant below rather than being compared against it.
#[must_use]
pub fn outstanding_limit(negotiated: u64) -> usize {
    let negotiated = usize::try_from(negotiated).unwrap_or(MAX_OUTSTANDING_MUTATIONS);
    negotiated.clamp(1, MAX_OUTSTANDING_MUTATIONS)
}

/// Returns whether a method's admission is bounded by the outstanding-mutation limit.
///
/// Two methods are not, and both for the same reason: each one *releases* what the limit counts.
/// `action.cancel` settles an undispatched intent, and `session.close` is the authorised stop
/// section 7 requires to proceed on the worker's current authority. An actor holding the limit
/// would otherwise be unable to reach either, and so unable to get below the limit again.
#[must_use]
pub const fn bounded_by_outstanding(method: kr_protocol::method::Method) -> bool {
    !matches!(
        method,
        kr_protocol::method::Method::ActionCancel | kr_protocol::method::Method::SessionClose
    )
}

/// Refuses a first admission that would exceed the outstanding-mutation limit.
///
/// # Errors
///
/// Returns [`WorkerError::QuotaExceeded`] when the actor already holds the limit.
pub fn check_outstanding(outstanding: usize, limit: usize) -> Result<()> {
    if outstanding >= limit {
        return Err(WorkerError::QuotaExceeded {
            detail: format!(
                "this actor already holds {outstanding} admitted mutations this host has not \
                 settled, and at most {limit} may be outstanding at once"
            ),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_protocol::scalars::Uuid;

    fn action(byte: u8) -> ActionId {
        ActionId::new(Uuid::from_bytes([byte; 16]))
    }

    #[test]
    fn a_subject_with_no_uncertain_outcome_admits_a_fresh_action() {
        assert!(check_supersession(None, None).is_ok());
    }

    #[test]
    fn a_new_identifier_cannot_quietly_take_an_uncertain_outcomes_place() {
        let uncertain = Uncertain {
            action_id: action(1),
            revision: 3,
        };
        let refused = check_supersession(Some(uncertain), None);
        assert!(matches!(
            refused,
            Err(WorkerError::PreconditionFailed { ref detail })
                if detail.contains(&action(1).to_string())
        ));
    }

    #[test]
    fn an_explicit_later_request_that_shows_the_earlier_result_is_admitted() {
        let uncertain = Uncertain {
            action_id: action(1),
            revision: 3,
        };
        let shown = Supersession {
            action_id: action(1),
            revision: 3,
        };
        assert!(check_supersession(Some(uncertain), Some(shown)).is_ok());
    }

    #[test]
    fn naming_another_action_does_not_show_this_subjects_result() {
        let uncertain = Uncertain {
            action_id: action(1),
            revision: 3,
        };
        let wrong = Supersession {
            action_id: action(2),
            revision: 3,
        };
        assert!(check_supersession(Some(uncertain), Some(wrong)).is_err());
    }

    #[test]
    fn quoting_a_revision_the_caller_cannot_have_read_does_not_show_it() {
        let uncertain = Uncertain {
            action_id: action(1),
            revision: 3,
        };
        for revision in [0, 2, 4] {
            let stale = Supersession {
                action_id: action(1),
                revision,
            };
            assert!(
                check_supersession(Some(uncertain), Some(stale)).is_err(),
                "{revision}"
            );
        }
    }

    #[test]
    fn naming_an_uncertain_outcome_that_does_not_exist_is_refused() {
        let invented = Supersession {
            action_id: action(1),
            revision: 3,
        };
        assert!(check_supersession(None, Some(invented)).is_err());
    }

    #[test]
    fn the_outstanding_limit_is_eight_and_the_smaller_bound_wins() {
        assert_eq!(MAX_OUTSTANDING_MUTATIONS, 8);
        assert_eq!(outstanding_limit(8), 8);
        assert_eq!(outstanding_limit(64), 8, "a larger offer does not raise it");
        assert_eq!(outstanding_limit(3), 3);
        assert_eq!(
            outstanding_limit(0),
            1,
            "the handshake refuses an offer of none; the clamp keeps this answer sound anyway"
        );
        assert_eq!(outstanding_limit(u64::MAX), 8);
    }

    #[test]
    fn the_two_methods_that_release_capacity_are_not_bounded_by_it() {
        use kr_protocol::method::Method;
        assert!(!bounded_by_outstanding(Method::ActionCancel));
        assert!(!bounded_by_outstanding(Method::SessionClose));
        for bounded in [
            Method::SessionAttach,
            Method::InputAcquire,
            Method::TerminalResize,
            Method::AgentApprovalRespond,
        ] {
            assert!(bounded_by_outstanding(bounded), "{bounded:?}");
        }
    }

    #[test]
    fn the_ninth_outstanding_mutation_is_refused() {
        for outstanding in 0..8 {
            assert!(check_outstanding(outstanding, 8).is_ok(), "{outstanding}");
        }
        let refused = check_outstanding(8, 8);
        assert!(matches!(refused, Err(WorkerError::QuotaExceeded { .. })));
        assert_eq!(
            refused.err().map(|error| error.code()),
            Some(kr_protocol::error::ErrorCode::QuotaExceeded)
        );
    }
}
