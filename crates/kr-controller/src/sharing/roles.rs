//! Roles compiled to grants, and the two rules that stop authority growing sideways.
//!
//! # Roles
//!
//! Section 25 gives four default roles and then says the host never authorises from a role label
//! alone. [`compile`] is where a role stops being a label: it turns a
//! [`RoleSelection`] into the explicit actions and history a
//! grant carries, and after that nothing in this host can see the role again, because
//! [`Grant`] has no field for one.
//!
//! # Delegation
//!
//! Section 19: "Delegation cannot grant rights that the delegating actor lacks." Section 10:
//! delegation "can narrow a parent's rights but cannot extend its lifetime, resources or actions".
//! One rule, and [`kr_protocol::grant::Grant::narrows`] is its definition. [`check_delegation`]
//! calls it and says which part failed, because "denied" is much less useful than "the child asks
//! for `terminal.input`, which the parent does not carry".
//!
//! # Indirection
//!
//! Section 19: "A view-only invitation cannot obtain terminal input through an attachment action,
//! plugin call or workflow." Nothing here decides that: each of the three is decided where it
//! acts, by the right its own class needs (the worker's check of a plugin action's class, the
//! automation service's check of a node's rights against the grant the workflow names, and the
//! method table's rights and the attachment's capability cut), and a share is no grant a workflow
//! acts under.

use kr_protocol::grant::{EnvironmentSelector, Grant, GrantExpiry, SessionSelector};
use kr_protocol::ids::SessionId;
use kr_protocol::pairing::ProposedGrant;
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{CanonicalSet, Nullable, TimestampMs};
use kr_protocol::sharing::{
    DEFAULT_INVITATION_LIFETIME_MS, MAX_INVITATION_LIFETIME_MS, RoleSelection, SessionRole,
};

use crate::error::{ControllerError, Result};

/// Compiles a role selection into the grant an invitation proposes.
///
/// `lifetime_ms` is the issuer's choice. `None` takes section 10's one-hour default; anything over
/// [`MAX_INVITATION_LIFETIME_MS`] is refused rather than clamped, because a silently shortened
/// invitation is an invitation whose issuer believes something untrue about it.
///
/// An owner-role selection is still an *invitation*: it expires. Section 10 keeps persistent
/// co-owner access to explicit owner pairing, so nothing here can produce a grant that never ends.
///
/// # Errors
///
/// Returns [`ControllerError::InvalidArgument`] when the lifetime is zero or over the bound.
pub fn compile(
    selection: &RoleSelection,
    session_id: SessionId,
    lifetime_ms: Option<u64>,
    now_ms: u64,
) -> Result<ProposedGrant> {
    let lifetime = lifetime_ms.unwrap_or(DEFAULT_INVITATION_LIFETIME_MS);
    if lifetime == 0 {
        return Err(ControllerError::InvalidArgument(
            "a session invitation lasts at least an instant".to_owned(),
        ));
    }
    if lifetime > MAX_INVITATION_LIFETIME_MS {
        return Err(ControllerError::InvalidArgument(
            "a session invitation lasts at most 30 days; persistent access needs owner pairing"
                .to_owned(),
        ));
    }
    // A viewer sees the selected live screen **and future events**. So an invitation with no
    // earlier cursor starts at the moment it is issued rather than at nothing: a null lower bound
    // means "no retained history at all", which for a session invitation would exclude the events
    // that have not happened yet as well as the ones that have.
    let mut history = selection.history();
    if history.lower_bound_ms.as_ref().is_none() {
        history.lower_bound_ms = Nullable::some(TimestampMs::new(now_ms));
    }
    Ok(ProposedGrant {
        parent_grant_id: Nullable::null(),
        environment_selector: EnvironmentSelector::Any,
        session_selector: SessionSelector::These {
            session_ids: [session_id].into_iter().collect(),
        },
        actions: selection.actions(),
        history,
        expiry: GrantExpiry::At {
            expires_at_ms: TimestampMs::new(now_ms.saturating_add(lifetime)),
        },
        organisation: Nullable::null(),
    })
}

/// Which role a set of actions is at least as wide as, for display beside a grant.
///
/// Returned for a person reading a grant, never for a decision. The host decides from the actions,
/// and this function exists so that a list of grants can say "controller" beside one without any
/// code being able to mistake that word for authority.
#[must_use]
pub fn describes(actions: &CanonicalSet<ActionRight>) -> Option<SessionRole> {
    SessionRole::ALL.into_iter().rev().find(|role| {
        role.default_actions()
            .iter()
            .all(|right| actions.contains(right))
    })
}

/// Checks that a child grant is a valid delegation of its parent.
///
/// # Errors
///
/// Returns [`ControllerError::PermissionDenied`] naming the part of the parent the child tried to
/// exceed.
pub fn check_delegation(child: &Grant, parent: &Grant) -> Result<()> {
    if child.parent_grant_id.as_ref() != Some(&parent.grant_id) {
        return Err(ControllerError::PermissionDenied {
            detail: "a delegated grant names the grant it was delegated from".to_owned(),
        });
    }
    if let Some(right) = child
        .actions
        .iter()
        .find(|right| !parent.actions.contains(*right))
    {
        return Err(ControllerError::PermissionDenied {
            detail: format!(
                "this delegation asks for {}, which the grant it delegates from does not carry",
                right.as_str()
            ),
        });
    }
    if !child
        .environment_selector
        .narrows(&parent.environment_selector)
    {
        return Err(ControllerError::PermissionDenied {
            detail: "this delegation reaches environments the grant it delegates from does not"
                .to_owned(),
        });
    }
    if !child.session_selector.narrows(&parent.session_selector) {
        return Err(ControllerError::PermissionDenied {
            detail: "this delegation reaches sessions the grant it delegates from does not"
                .to_owned(),
        });
    }
    if !child.history.narrows(&parent.history) {
        return Err(ControllerError::PermissionDenied {
            detail: "this delegation reaches history the grant it delegates from does not"
                .to_owned(),
        });
    }
    if !child.expiry.narrows(parent.expiry) {
        return Err(ControllerError::PermissionDenied {
            detail: "this delegation outlives the grant it delegates from".to_owned(),
        });
    }
    if parent.organisation.is_present() && child.organisation != parent.organisation {
        return Err(ControllerError::PermissionDenied {
            detail: "this delegation drops the organisation membership its parent requires"
                .to_owned(),
        });
    }
    // Everything above is a named case of the same rule, and the rule itself has the last word: a
    // future field added to a grant is covered by this line whether or not somebody remembers to
    // add a case above it.
    if child.narrows(parent) {
        Ok(())
    } else {
        Err(ControllerError::PermissionDenied {
            detail: "a delegated grant narrows its parent; it never extends one".to_owned(),
        })
    }
}
