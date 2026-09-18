//! Who may cancel a pending action.
//!
//! Section 23's method row is two clauses: the same actor and current scope for its own
//! undispatched intent, **or** explicit host-owner authority. Post-dispatch cancellation is not
//! this method at all; it is a separate upstream action with its own receipt, and
//! [`crate::journal::Journal::cancel`] refuses it here rather than pretending to undo an effect
//! that may already have happened.
//!
//! What counts as host-owner authority at a worker is the authenticated operating-system caller.
//! A worker's private endpoint is reachable only by this user, whom the listener authenticates by
//! peer credentials, and a mutation forwarded by the control daemon carries the ingress it arrived
//! on. So the owner is the local ingress, and anything else is a caller acting for somebody else,
//! whose rights the daemon resolves before it forwards. Peer credentials prove an operating-system
//! identity rather than human intent, which is why this is authority over a pending intent and not
//! a route to anything that enlarges rights.

use kr_protocol::actor::ActorIngress;
use kr_protocol::ids::{ActionId, ActorId};

use crate::error::{Result, WorkerError};

/// Whose action a cancellation names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Subject {
    /// The caller's own intent.
    Own,
    /// Another actor's intent.
    OtherActor,
}

/// Returns whether an ingress carries host-owner authority at this worker.
#[must_use]
pub const fn holds_owner_authority(ingress: ActorIngress) -> bool {
    matches!(ingress, ActorIngress::LocalIpc)
}

/// Decides whether a caller may cancel an action.
///
/// # Errors
///
/// Returns [`WorkerError::PermissionDenied`] when the action belongs to another actor and the
/// caller does not hold host-owner authority.
pub fn check(
    subject: Subject,
    ingress: ActorIngress,
    caller: &ActorId,
    action_id: ActionId,
) -> Result<()> {
    match subject {
        Subject::Own => Ok(()),
        Subject::OtherActor if holds_owner_authority(ingress) => Ok(()),
        Subject::OtherActor => Err(WorkerError::PermissionDenied {
            detail: format!(
                "action {action_id} belongs to another actor, and {caller} holds no host \
                 management authority over it"
            ),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_protocol::scalars::Uuid;

    fn action() -> ActionId {
        ActionId::new(Uuid::from_bytes([1; 16]))
    }

    fn caller() -> ActorId {
        ActorId::new("device:phone").expect("a principal")
    }

    #[test]
    fn every_caller_may_cancel_its_own_undispatched_intent() {
        for ingress in ActorIngress::ALL {
            assert!(
                check(Subject::Own, *ingress, &caller(), action()).is_ok(),
                "{ingress:?}"
            );
        }
    }

    #[test]
    fn the_local_owner_may_cancel_another_actors_intent() {
        assert!(holds_owner_authority(ActorIngress::LocalIpc));
        assert!(
            check(
                Subject::OtherActor,
                ActorIngress::LocalIpc,
                &caller(),
                action()
            )
            .is_ok()
        );
    }

    #[test]
    fn nobody_else_may_cancel_another_actors_intent() {
        for ingress in ActorIngress::ALL
            .iter()
            .copied()
            .filter(|ingress| *ingress != ActorIngress::LocalIpc)
        {
            let refused = check(Subject::OtherActor, ingress, &caller(), action());
            assert!(
                matches!(refused, Err(WorkerError::PermissionDenied { .. })),
                "{ingress:?}"
            );
            assert_eq!(
                refused.err().map(|error| error.code()),
                Some(kr_protocol::error::ErrorCode::PermissionDenied)
            );
        }
    }
}
