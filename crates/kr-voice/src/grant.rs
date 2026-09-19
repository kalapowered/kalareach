//! The voice grant: separately created, intersected with the device's ordinary grant.
//!
//! Section 15 ¶7 makes the actor "that device under its ordinary grant intersected with a
//! separately created voice grant and session binding". Both halves are here.
//!
//! The grant is an ordinary [`Grant`] in the host's one authority store, because section 19 says
//! content is never authority and a second store would be a second answer. What makes it a voice
//! grant is the [`ActionRight::VoiceUse`] it carries, which the method registry demands of every
//! voice method that acts under one.
//!
//! Two grants exist per device, and the difference matters:
//!
//! * the **standing** voice grant, written by `voice.grant`. It says which voice actions this
//!   person has chosen to permit, and it survives calls;
//! * the **session-bound** voice grant, delegated from the standing one by `voice.start`. It
//!   narrows to the sessions the call may reach and to the call's own deadline, and stopping the
//!   call revokes it. Revoking a parent revokes its descendants, so withdrawing the standing grant
//!   ends any call running under it.

use kr_protocol::grant::{EnvironmentSelector, Grant, GrantExpiry, HistoryScope, SessionSelector};
use kr_protocol::ids::{AuthorityRevision, DeviceId, EnvironmentId, GrantId, SessionId};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{CanonicalSet, Nullable, TimestampMs};
use kr_protocol::voice::VoiceAction;

use crate::error::{Result, VoiceError};

/// A grant the coordinator has planned and the host is asked to write.
///
/// Planned rather than written here: this crate opens no store. Everything the store needs to
/// write the record is in one value, so the host writes what the coordinator decided rather than
/// re-deriving it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VoiceGrantPlan {
    /// The grant this one is delegated from, when it is a session-bound child.
    pub parent_grant_id: Option<GrantId>,
    /// The host device issuing it.
    pub issuer_device_id: DeviceId,
    /// The device it is issued to.
    pub recipient_device_id: DeviceId,
    /// The environment it covers.
    pub environment_id: EnvironmentId,
    /// The sessions it covers, or every session the parent covers when empty.
    pub session_ids: CanonicalSet<SessionId>,
    /// The voice actions it permits.
    pub actions: CanonicalSet<VoiceAction>,
    /// The rights those actions need, beside [`ActionRight::VoiceUse`].
    pub rights: CanonicalSet<ActionRight>,
    /// How far back it may see. Never wider than the device's own grant.
    pub history: HistoryScope,
    /// When it stops.
    pub expiry: GrantExpiry,
    /// The authority revision the host is at.
    pub authority_revision: AuthorityRevision,
}

impl VoiceGrantPlan {
    /// Builds the grant record this plan describes, under an identity the host allocated.
    #[must_use]
    pub fn grant(&self, grant_id: GrantId) -> Grant {
        Grant {
            grant_id,
            parent_grant_id: Nullable(self.parent_grant_id),
            issuer_device_id: self.issuer_device_id,
            recipient_device_id: self.recipient_device_id,
            authority_revision: self.authority_revision,
            environment_selector: EnvironmentSelector::These {
                environment_ids: [self.environment_id].into_iter().collect(),
            },
            session_selector: if self.session_ids.is_empty() {
                SessionSelector::Any
            } else {
                SessionSelector::These {
                    session_ids: self.session_ids.iter().copied().collect(),
                }
            },
            actions: self.rights.clone(),
            history: self.history.clone(),
            expiry: self.expiry,
            organisation: Nullable::null(),
        }
    }
}

/// What a person asked a voice grant to permit, and what their own grant allows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlannedVoiceGrant {
    /// The plan the host writes.
    pub plan: VoiceGrantPlan,
    /// Actions the request asked for that the device's own grant does not carry.
    ///
    /// Dropped rather than granted: a voice grant is intersected with the ordinary one, so asking
    /// for more narrows. Named, so nobody believes they granted something they did not.
    pub not_held_by_device: CanonicalSet<VoiceAction>,
}

/// Where a voice grant sits: whose it is, what it covers and how long it lasts.
///
/// One value rather than six arguments, because the standing grant and the session-bound child
/// differ only in these and a reader comparing the two calls should see exactly where.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrantBinding {
    /// The grant this one is delegated from, when it is a session-bound child.
    pub parent_grant_id: Option<GrantId>,
    /// The host device issuing it.
    pub issuer_device_id: DeviceId,
    /// The environment it covers.
    pub environment_id: EnvironmentId,
    /// The sessions it covers, or every session the device's grant covers when empty.
    pub session_ids: CanonicalSet<SessionId>,
    /// When it stops, bounded by the device's own grant.
    pub expiry: GrantExpiry,
    /// The authority revision the host is at.
    pub authority_revision: AuthorityRevision,
}

/// Plans a voice grant for one device.
///
/// `asked` is what the person chose, or the default scope of section 15 ¶13 when they chose
/// nothing. The result is the intersection with `device_grant`: an action whose ordinary right the
/// device does not hold is dropped and reported, and an action this release has no host effect for
/// is dropped for the same reason.
///
/// # Errors
///
/// Returns an error when the device's grant does not cover the environment the plan names, because
/// a voice grant cannot reach further than the grant it narrows.
pub fn plan_voice_grant(
    device_grant: &Grant,
    asked: Option<&CanonicalSet<VoiceAction>>,
    binding: &GrantBinding,
) -> Result<PlannedVoiceGrant> {
    let &GrantBinding {
        parent_grant_id,
        issuer_device_id,
        environment_id,
        ref session_ids,
        expiry,
        authority_revision,
    } = binding;
    let session_ids = session_ids.clone();
    if !device_grant.environment_selector.admits(environment_id) {
        return Err(VoiceError::InvalidArgument(
            "this device's grant does not cover this environment".to_owned(),
        ));
    }
    for session_id in session_ids.iter() {
        if !device_grant.session_selector.admits(*session_id) {
            return Err(VoiceError::InvalidArgument(
                "this device's grant does not cover one of the sessions named".to_owned(),
            ));
        }
    }

    let default = VoiceAction::default_scope();
    let asked = asked.unwrap_or(&default);
    let (permitted, dropped) = intersect(asked, device_grant);

    let mut plan_expiry = expiry;
    if !plan_expiry.narrows(device_grant.expiry) {
        // A voice grant never outlives the grant it narrows. Section 19: delegation cannot grant
        // rights the delegating actor lacks, and outliving is one of the things it cannot grant.
        plan_expiry = device_grant.expiry;
    }

    Ok(PlannedVoiceGrant {
        plan: VoiceGrantPlan {
            parent_grant_id,
            issuer_device_id,
            recipient_device_id: device_grant.recipient_device_id,
            environment_id,
            session_ids,
            rights: VoiceAction::rights_for(&permitted),
            actions: permitted,
            // Never wider than the device's own history scope: the selection intersects the
            // requesting device's scope, so the grant it is built from carries that scope.
            history: device_grant.history.clone(),
            expiry: plan_expiry,
            authority_revision,
        },
        not_held_by_device: dropped,
    })
}

/// Intersects the actions asked for with what the device's ordinary grant carries.
fn intersect(
    asked: &CanonicalSet<VoiceAction>,
    device_grant: &Grant,
) -> (CanonicalSet<VoiceAction>, CanonicalSet<VoiceAction>) {
    let mut permitted: CanonicalSet<VoiceAction> = CanonicalSet::from_iter([]);
    let mut dropped: CanonicalSet<VoiceAction> = CanonicalSet::from_iter([]);
    for action in asked.iter().copied() {
        match action.required_right() {
            // No host effect carries it in this release, so no grant can carry it either.
            None => {
                dropped.insert(action);
            }
            Some(right) if device_grant.permits(right) => {
                permitted.insert(action);
            }
            Some(_) => {
                dropped.insert(action);
            }
        }
    }
    (permitted, dropped)
}

/// The voice actions a live voice grant permits, read back from the rights it carries.
///
/// The grant is the authority and the action list is a view of it, rather than the other way
/// round: a record that stored an action list beside its rights would have two answers to keep in
/// step, and only one of them would be the one a check reads.
#[must_use]
pub fn permitted_actions(voice_grant: &Grant) -> CanonicalSet<VoiceAction> {
    if !voice_grant.permits(ActionRight::VoiceUse) {
        // Not a voice grant at all. An ordinary grant that happens to carry `agent.prompt` does
        // not permit speaking a prompt: the two are separate choices.
        return CanonicalSet::from_iter([]);
    }
    VoiceAction::ALL
        .iter()
        .copied()
        .filter(|action| {
            action
                .required_right()
                .is_some_and(|right| voice_grant.permits(right))
        })
        .collect()
}

/// Whether a voice action is permitted by both grants.
///
/// The intersection of section 15 ¶7, done at decision time rather than trusted from what a record
/// said when it was written. A voice grant that outlived a narrowing of the device's own grant
/// therefore stops permitting what the device may no longer do.
#[must_use]
pub fn permits(voice_grant: &Grant, device_grant: &Grant, action: VoiceAction) -> bool {
    let Some(right) = action.required_right() else {
        return false;
    };
    voice_grant.permits(ActionRight::VoiceUse)
        && voice_grant.permits(right)
        && device_grant.permits(right)
}

/// The expiry a session-bound voice grant takes from a call deadline.
#[must_use]
pub const fn call_expiry(closes_at_ms: u64) -> GrantExpiry {
    GrantExpiry::At {
        expires_at_ms: TimestampMs::new(closes_at_ms),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_protocol::scalars::Uuid;

    fn device(byte: u8) -> DeviceId {
        DeviceId::new(Uuid::from_bytes([byte; 16]))
    }

    fn environment() -> EnvironmentId {
        EnvironmentId::new(Uuid::from_bytes([0xe0; 16]))
    }

    fn binding(expiry: GrantExpiry) -> GrantBinding {
        GrantBinding {
            parent_grant_id: None,
            issuer_device_id: device(0xf0),
            environment_id: environment(),
            session_ids: CanonicalSet::from_iter([]),
            expiry,
            authority_revision: AuthorityRevision::new(1),
        }
    }

    fn grant_with(actions: &[ActionRight]) -> Grant {
        Grant {
            grant_id: GrantId::new(Uuid::from_bytes([1; 16])),
            parent_grant_id: Nullable::null(),
            issuer_device_id: device(0xf0),
            recipient_device_id: device(0xf1),
            authority_revision: AuthorityRevision::new(1),
            environment_selector: EnvironmentSelector::These {
                environment_ids: [environment()].into_iter().collect(),
            },
            session_selector: SessionSelector::Any,
            actions: actions.iter().copied().collect(),
            history: HistoryScope {
                lower_bound_ms: Nullable::some(TimestampMs::new(1_000)),
                include_live_screen: true,
                named_questions: CanonicalSet::from_iter([]),
                named_approvals: CanonicalSet::from_iter([]),
            },
            expiry: GrantExpiry::Never,
            organisation: Nullable::null(),
        }
    }

    #[test]
    fn the_default_plan_is_section_fifteens_four_actions() {
        let device_grant = grant_with(&[ActionRight::SessionView, ActionRight::AgentPrompt]);
        let planned =
            plan_voice_grant(&device_grant, None, &binding(GrantExpiry::Never)).expect("a plan");
        assert_eq!(planned.plan.actions, VoiceAction::default_scope());
        assert!(
            !planned.plan.actions.contains(&VoiceAction::SubmitPrompt),
            "holding agent.prompt does not put prompt submission in the default voice scope"
        );
        assert!(planned.plan.rights.contains(&ActionRight::VoiceUse));
    }

    #[test]
    fn broadening_beyond_the_device_grant_narrows_and_says_so() {
        let device_grant = grant_with(&[ActionRight::SessionView]);
        let asked: CanonicalSet<VoiceAction> = [
            VoiceAction::Navigate,
            VoiceAction::SubmitPrompt,
            VoiceAction::ShellInput,
        ]
        .into_iter()
        .collect();
        let planned = plan_voice_grant(&device_grant, Some(&asked), &binding(GrantExpiry::Never))
            .expect("a plan");
        assert_eq!(
            planned.plan.actions,
            [VoiceAction::Navigate].into_iter().collect()
        );
        assert!(
            planned
                .not_held_by_device
                .contains(&VoiceAction::ShellInput)
        );
        assert!(
            planned
                .not_held_by_device
                .contains(&VoiceAction::SubmitPrompt)
        );
    }

    #[test]
    fn a_voice_grant_never_outlives_the_grant_it_narrows() {
        let device_grant = Grant {
            expiry: GrantExpiry::At {
                expires_at_ms: TimestampMs::new(5_000),
            },
            ..grant_with(&[ActionRight::SessionView])
        };
        let planned =
            plan_voice_grant(&device_grant, None, &binding(GrantExpiry::Never)).expect("a plan");
        assert_eq!(
            planned.plan.expiry,
            GrantExpiry::At {
                expires_at_ms: TimestampMs::new(5_000)
            }
        );
    }

    #[test]
    fn the_intersection_is_taken_at_decision_time() {
        let voice_grant = grant_with(&[
            ActionRight::VoiceUse,
            ActionRight::SessionView,
            ActionRight::AgentPrompt,
        ]);
        let narrowed = grant_with(&[ActionRight::SessionView]);
        assert!(!permits(&voice_grant, &narrowed, VoiceAction::SubmitPrompt));
        assert!(permits(&voice_grant, &narrowed, VoiceAction::Navigate));
    }

    #[test]
    fn an_ordinary_grant_is_not_a_voice_grant() {
        let ordinary = grant_with(&[ActionRight::SessionView, ActionRight::AgentPrompt]);
        assert!(permitted_actions(&ordinary).is_empty());
        assert!(!permits(&ordinary, &ordinary, VoiceAction::Navigate));
    }
}
