//! Grants: the authority objects of section 10.
//!
//! A grant names its issuer and recipient, the authority revision it was issued under, the
//! environment and session it covers, the actions it permits, its history scope and its expiry.
//! Every grant names its parent; revoking a parent revokes its descendants.
//!
//! Delegation narrows. A child grant can never extend its parent's lifetime, resources or actions.
//! [`Grant::narrows`] states that rule as code so the controller and the tests share one
//! definition.

use std::collections::BTreeSet;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::ids::{
    ApprovalRequestId, AuthorityRevision, DeviceId, EnvironmentId, GrantId, OrganisationId,
    QuestionId, SessionId,
};
use crate::rights::ActionRight;
use crate::scalars::{Nullable, TimestampMs};

/// Which environments a grant covers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum EnvironmentSelector {
    /// Every environment on the host.
    Any,
    /// Only the named environments.
    These {
        /// The permitted environments.
        environment_ids: BTreeSet<EnvironmentId>,
    },
}

impl EnvironmentSelector {
    /// Returns true when the selector admits `environment_id`.
    #[must_use]
    pub fn admits(&self, environment_id: EnvironmentId) -> bool {
        match self {
            Self::Any => true,
            Self::These { environment_ids } => environment_ids.contains(&environment_id),
        }
    }

    /// Returns true when `self` selects no more than `parent`.
    #[must_use]
    pub fn narrows(&self, parent: &Self) -> bool {
        match (self, parent) {
            (_, Self::Any) => true,
            (Self::Any, Self::These { .. }) => false,
            (
                Self::These {
                    environment_ids: child,
                },
                Self::These {
                    environment_ids: parent,
                },
            ) => child.is_subset(parent),
        }
    }
}

/// Which sessions a grant covers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SessionSelector {
    /// Every session inside the selected environments.
    Any,
    /// Only the named sessions.
    These {
        /// The permitted sessions.
        session_ids: BTreeSet<SessionId>,
    },
    /// No session. The grant covers host-level effects only.
    None,
}

impl SessionSelector {
    /// Returns true when the selector admits `session_id`.
    #[must_use]
    pub fn admits(&self, session_id: SessionId) -> bool {
        match self {
            Self::Any => true,
            Self::These { session_ids } => session_ids.contains(&session_id),
            Self::None => false,
        }
    }

    /// Returns true when `self` selects no more than `parent`.
    #[must_use]
    pub fn narrows(&self, parent: &Self) -> bool {
        match (self, parent) {
            (Self::None, _) | (_, Self::Any) => true,
            (Self::Any, _) => false,
            (
                Self::These { session_ids: child },
                Self::These {
                    session_ids: parent,
                },
            ) => child.is_subset(parent),
            (Self::These { .. }, Self::None) => false,
        }
    }
}

/// How far back a grant may see, and which current resources it names explicitly.
///
/// The lower bound is enforced once, in shared host-side filtering used by event pages, snapshots,
/// loaded conversations, attachment references, exports, summaries, changed-since-last-visit and
/// voice context. A later snapshot or a freshly generated summary never makes older underlying
/// content newly authorised.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HistoryScope {
    /// The earliest content this grant may see. Null means no retained history at all.
    pub lower_bound_ms: Nullable<TimestampMs>,
    /// Whether the currently visible screen is included. This exception never grants inactive
    /// screen buffers, scrollback or the backing transcript.
    pub include_live_screen: bool,
    /// Current questions named explicitly, even when they were created before the lower bound.
    pub named_questions: BTreeSet<QuestionId>,
    /// Current approval requests named explicitly, on the same terms.
    pub named_approvals: BTreeSet<ApprovalRequestId>,
}

impl HistoryScope {
    /// Returns true when `self` sees no more than `parent`.
    #[must_use]
    pub fn narrows(&self, parent: &Self) -> bool {
        let bound_ok = match (self.lower_bound_ms.0, parent.lower_bound_ms.0) {
            (None, _) => true,
            (Some(_), None) => false,
            (Some(child), Some(parent)) => child.get() >= parent.get(),
        };
        bound_ok
            && (!self.include_live_screen || parent.include_live_screen)
            && self.named_questions.is_subset(&parent.named_questions)
            && self.named_approvals.is_subset(&parent.named_approvals)
    }
}

/// When a grant stops being valid.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum GrantExpiry {
    /// Valid until revoked. Personal owner grants use this so independent operation does not
    /// depend on a cloud lease.
    Never,
    /// Valid until an absolute UTC deadline. A previously expired grant never revives.
    At {
        /// The deadline in UTC milliseconds.
        expires_at_ms: TimestampMs,
    },
}

impl GrantExpiry {
    /// Returns true when the grant is still valid at `now_ms`.
    #[must_use]
    pub const fn is_valid_at(self, now_ms: u64) -> bool {
        match self {
            Self::Never => true,
            Self::At { expires_at_ms } => now_ms < expires_at_ms.get(),
        }
    }

    /// Returns true when `self` lasts no longer than `parent`.
    #[must_use]
    pub const fn narrows(self, parent: Self) -> bool {
        match (self, parent) {
            (_, Self::Never) => true,
            (Self::Never, Self::At { .. }) => false,
            (
                Self::At {
                    expires_at_ms: child,
                },
                Self::At {
                    expires_at_ms: parent,
                },
            ) => child.get() <= parent.get(),
        }
    }
}

/// An organisation membership requirement attached to a grant.
///
/// Organisation leases keep their stricter policy: expired membership blocks further
/// organisation-mediated reads and mutations even while the transport stays connected.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OrganisationRequirement {
    /// The organisation whose membership the recipient must hold.
    pub organisation_id: OrganisationId,
    /// The policy revision the host has pinned.
    pub policy_revision: AuthorityRevision,
}

/// A host-issued authority object.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    /// This grant's identity.
    pub grant_id: GrantId,
    /// The grant this one was delegated from. Revoking a parent revokes its descendants.
    pub parent_grant_id: Nullable<GrantId>,
    /// The device that issued it.
    pub issuer_device_id: DeviceId,
    /// The device it was issued to.
    pub recipient_device_id: DeviceId,
    /// The host authority revision it was issued under. The host intersects the grant with current
    /// policy on every request.
    pub authority_revision: AuthorityRevision,
    /// Which environments it covers.
    pub environment_selector: EnvironmentSelector,
    /// Which sessions it covers.
    pub session_selector: SessionSelector,
    /// The actions it permits.
    pub actions: BTreeSet<ActionRight>,
    /// How far back it may see.
    pub history: HistoryScope,
    /// When it stops being valid.
    pub expiry: GrantExpiry,
    /// An optional organisation membership requirement.
    pub organisation: Nullable<OrganisationRequirement>,
}

impl Grant {
    /// Returns true when this grant permits `right`.
    #[must_use]
    pub fn permits(&self, right: ActionRight) -> bool {
        self.actions.contains(&right)
    }

    /// Returns true when this grant is a valid delegation of `parent`.
    ///
    /// Delegation may narrow rights, resources, history and lifetime. It may never extend any of
    /// them, and it may not drop an organisation requirement the parent carries.
    #[must_use]
    pub fn narrows(&self, parent: &Self) -> bool {
        self.parent_grant_id == Nullable::some(parent.grant_id)
            && self.actions.is_subset(&parent.actions)
            && self
                .environment_selector
                .narrows(&parent.environment_selector)
            && self.session_selector.narrows(&parent.session_selector)
            && self.history.narrows(&parent.history)
            && self.expiry.narrows(parent.expiry)
            && (parent.organisation.0.is_none() || self.organisation == parent.organisation)
    }
}
