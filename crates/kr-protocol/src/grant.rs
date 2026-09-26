//! Grants: the authority objects of section 10.
//!
//! A grant names its issuer and recipient, the authority revision it was issued under, the
//! environment and session it covers, the actions it permits, its history scope and its expiry.
//! Every grant names its parent; revoking a parent revokes its descendants.
//!
//! Delegation narrows. A child grant can never extend its parent's lifetime, resources or actions.
//! [`Grant::narrows`] states that rule as code so the controller and the tests share one
//! definition.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::ids::{
    ApprovalRequestId, AuthorityRevision, DeviceId, EnvironmentId, GrantId, OrganisationId,
    QuestionId, SessionId,
};
use crate::rights::ActionRight;
use crate::scalars::{CanonicalSet, Nullable, TimestampMs};

/// Which environments a grant covers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum EnvironmentSelector {
    /// Every environment on the host.
    Any,
    /// Only the named environments.
    These {
        /// The permitted environments.
        environment_ids: CanonicalSet<EnvironmentId>,
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
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum SessionSelector {
    /// Every session inside the selected environments.
    Any,
    /// Only the named sessions.
    These {
        /// The permitted sessions.
        session_ids: CanonicalSet<SessionId>,
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
    pub named_questions: CanonicalSet<QuestionId>,
    /// Current approval requests named explicitly, on the same terms.
    pub named_approvals: CanonicalSet<ApprovalRequestId>,
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
#[serde(rename_all = "snake_case", deny_unknown_fields)]
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
    pub actions: CanonicalSet<ActionRight>,
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

#[cfg(test)]
mod tests {
    use super::HistoryScope;
    use crate::scalars::{CanonicalSet, Nullable, TimestampMs};

    /// A scope reaching back to 2 000 ms that names nothing, as a build that named approvals by
    /// upstream text encoded it. An empty set has the same bytes whatever its element is, so every
    /// row and message that names nothing keeps its bytes.
    const UNNAMED: &str = concat!(
        "a4",
        "6e6c6f7765725f626f756e645f6d73",
        "1907d0",
        "6f6e616d65645f617070726f76616c73",
        "80",
        "6f6e616d65645f7175657374696f6e73",
        "80",
        "73696e636c7564655f6c6976655f73637265656e",
        "f4",
    );

    /// The same scope naming two approvals by the broker's resource identity: a set of two
    /// 16-byte strings.
    const NAMED: &str = concat!(
        "a4",
        "6e6c6f7765725f626f756e645f6d73",
        "1907d0",
        "6f6e616d65645f617070726f76616c73",
        "82",
        "5011111111111111111111111111111111",
        "5022222222222222222222222222222222",
        "6f6e616d65645f7175657374696f6e73",
        "80",
        "73696e636c7564655f6c6976655f73637265656e",
        "f4",
    );

    /// The same scope naming one approval by an upstream's text identifier, `1`, which is what a
    /// set of that earlier element held.
    const NAMED_BY_TEXT: &str = concat!(
        "a4",
        "6e6c6f7765725f626f756e645f6d73",
        "1907d0",
        "6f6e616d65645f617070726f76616c73",
        "81",
        "6131",
        "6f6e616d65645f7175657374696f6e73",
        "80",
        "73696e636c7564655f6c6976655f73637265656e",
        "f4",
    );

    fn decode(text: &str) -> kr_cbor::Result<HistoryScope> {
        kr_cbor::from_canonical_slice(
            &hex::decode(text).expect("hexadecimal"),
            &kr_cbor::Limits::DEFAULT,
        )
    }

    fn encode(scope: &HistoryScope) -> String {
        hex::encode(kr_cbor::to_canonical_vec(scope).expect("encodes"))
    }

    #[test]
    fn a_scope_that_names_nothing_keeps_the_bytes_an_earlier_build_wrote() {
        let scope = HistoryScope {
            lower_bound_ms: Nullable::some(TimestampMs::new(2_000)),
            include_live_screen: false,
            named_questions: CanonicalSet::new(),
            named_approvals: CanonicalSet::new(),
        };
        assert_eq!(encode(&scope), UNNAMED);
        assert_eq!(decode(UNNAMED).expect("reads what it wrote"), scope);
    }

    #[test]
    fn a_scope_names_each_approval_by_its_resource_as_a_16_byte_string() {
        let named = decode(NAMED);
        assert!(
            named.is_ok(),
            "each named approval is a 16-byte resource identity: {named:?}"
        );
        let named = named.expect("decoded above");
        assert_eq!(encode(&named), NAMED);
        // In JSON a resource identity is its canonical hyphenated text, and the scope reads back.
        let json = serde_json::to_value(&named).expect("JSON");
        assert_eq!(
            json["named_approvals"],
            serde_json::json!([
                "11111111-1111-1111-1111-111111111111",
                "22222222-2222-2222-2222-222222222222",
            ])
        );
        let back: HistoryScope = serde_json::from_value(json).expect("reads its JSON back");
        assert_eq!(back, named);
    }

    #[test]
    fn a_scope_that_names_an_approval_by_upstream_text_is_refused() {
        let refused = decode(NAMED_BY_TEXT);
        assert!(
            refused.is_err(),
            "an upstream's text names no resource of this host: {refused:?}"
        );
    }
}
