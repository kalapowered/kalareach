//! Who may cancel a pending action.
//!
//! Section 23's method row is two clauses: the same actor and current scope for its own
//! undispatched intent, **or** explicit host-owner authority. Post-dispatch cancellation is not
//! this method at all; it is a separate upstream action with its own receipt, and
//! [`crate::journal::Journal::cancel`] refuses it here rather than pretending to undo an effect
//! that may already have happened.
//!
//! What counts as host-owner authority at a worker is the local owner: the operating-system caller
//! a local listener authenticated by peer credentials, acting under no grant
//! ([`crate::service::Caller::is_local_owner`]). A mutation forwarded by the control daemon carries
//! the ingress it arrived on and the grant it was checked against, and a caller the daemon heard on
//! its own local socket can still act under a grant, so the ingress alone does not say who the
//! owner is. Anything but the owner is a caller acting for somebody else, whose rights the daemon
//! resolves before it forwards. Peer credentials prove an operating-system identity rather than
//! human intent, which is why this is authority over a pending intent and not a route to anything
//! that enlarges rights.

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

/// Decides whether a caller may cancel an action.
///
/// `local_owner` is whether the caller is the local owner, which is the host-owner authority
/// another actor's intent needs.
///
/// # Errors
///
/// Returns [`WorkerError::PermissionDenied`] when the action belongs to another actor and the
/// caller is not the local owner.
pub fn check(
    subject: Subject,
    local_owner: bool,
    caller: &ActorId,
    action_id: ActionId,
) -> Result<()> {
    match subject {
        Subject::Own => Ok(()),
        Subject::OtherActor if local_owner => Ok(()),
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
        for local_owner in [true, false] {
            assert!(
                check(Subject::Own, local_owner, &caller(), action()).is_ok(),
                "local owner: {local_owner}"
            );
        }
    }

    #[test]
    fn the_local_owner_may_cancel_another_actors_intent() {
        assert!(check(Subject::OtherActor, true, &caller(), action()).is_ok());
    }

    #[test]
    fn nobody_else_may_cancel_another_actors_intent() {
        let refused = check(Subject::OtherActor, false, &caller(), action());
        assert!(matches!(refused, Err(WorkerError::PermissionDenied { .. })));
        assert_eq!(
            refused.err().map(|error| error.code()),
            Some(kr_protocol::error::ErrorCode::PermissionDenied)
        );
    }
}
