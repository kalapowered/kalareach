//! What a delivery rule's grant lets its recipient read, answered from this host's grant store.
//!
//! Section 19 intersects an external message's content with the recipient's own authority, and
//! the recipient's authority is the grant the destination's rule names, intersected with this
//! host's current policy the way every other use of a grant is. So this answers from the grants
//! this host issued, as they stand at the moment of asking, and from the policy in force at that
//! moment: a grant revoked, expired, never redeemed, issued under an authority revision this host
//! has not reached, or for another environment admits nothing; so does one the policy will not
//! honour - an organisation grant whose recipient this host cannot attribute to a member with a
//! current lease, a personal grant on a host that is exclusively organisation-managed, a grant
//! used past the bounded offline-validity policy - and so does one whose rights, after that
//! intersection, no longer include viewing a session.
//!
//! A push destination never asks. Its recipient is the paired device and the content is sealed to
//! that device's own key, so the rule is the whole of its authority.

use std::sync::{Arc, Mutex};

use kr_delivery::destination::DeliveryRule;
use kr_delivery::producer::{RecipientAuthority, RecipientScope};
use kr_protocol::actor::ActorIngress;
use kr_protocol::ids::EnvironmentId;
use kr_protocol::method::Method;
use kr_protocol::rights::ActionRight;
use kr_protocol::sharing::GrantState;
use kr_worker::history_filter::ViewerScope;

use crate::grants::{AccessRequest, HostPolicy};
use crate::sharing::SharingService;

/// The grants this host issued, under its current policy, as a delivery rule's recipient
/// authority.
#[derive(Debug)]
pub struct GrantedRecipients {
    sharing: Arc<SharingService>,
    policy: Arc<Mutex<HostPolicy>>,
    environment_id: EnvironmentId,
    clock: fn() -> u64,
}

impl GrantedRecipients {
    /// Answers from `sharing`'s grants under `policy`, for the sessions of one environment.
    #[must_use]
    pub fn new(
        sharing: Arc<SharingService>,
        policy: Arc<Mutex<HostPolicy>>,
        environment_id: EnvironmentId,
    ) -> Self {
        Self::at(sharing, policy, environment_id, || kr_ipc::now_ms().get())
    }

    /// Answers against a clock of the caller's choosing, which is how a test holds a grant's
    /// expiry still.
    #[must_use]
    pub fn at(
        sharing: Arc<SharingService>,
        policy: Arc<Mutex<HostPolicy>>,
        environment_id: EnvironmentId,
        clock: fn() -> u64,
    ) -> Self {
        Self {
            sharing,
            policy,
            environment_id,
            clock,
        }
    }
}

impl RecipientAuthority for GrantedRecipients {
    fn scope_for(&self, rule: &DeliveryRule) -> Option<RecipientScope> {
        let grant_id = rule.grant_id?;
        // A store this host cannot read is a grant this host cannot show, and a grant it cannot
        // show admits nothing.
        let record = self.sharing.grants().record(grant_id).ok()??;
        // The policy as it stands now, read once for this answer. A copy, so the lock is not held
        // across the rest of the question.
        let policy = self.policy.lock().ok()?.clone();
        let now_ms = policy.settled_now((self.clock)());
        if record.state(now_ms) != GrantState::Active {
            return None;
        }
        let grant = &record.grant;
        if grant.authority_revision.get() > policy.authority_revision().get()
            || !grant.environment_selector.admits(self.environment_id)
        {
            return None;
        }
        // Content leaving this host for a recipient elsewhere is remote use of the grant, so it is
        // intersected the way a paired device's request is. This host attributes no account to
        // the recipient of an external message, so an organisation grant, whose lease is per
        // member, admits nothing rather than being answered by somebody else's lease.
        let effective = policy
            .intersect(
                grant,
                &AccessRequest {
                    method: Method::SessionRead,
                    ingress: ActorIngress::PairedDevice,
                    environment_id: self.environment_id,
                    session_id: None,
                    claims_geometry: false,
                    recipient_account: None,
                    own_subject: None,
                    now_ms,
                },
                now_ms,
            )
            .ok()?;
        if !effective.rights.contains(&ActionRight::SessionView) {
            return None;
        }
        Some(RecipientScope {
            viewer: ViewerScope::from_grant(grant),
            sessions: grant.session_selector.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grants::GrantRecord;
    use kr_protocol::grant::{
        EnvironmentSelector, Grant, GrantExpiry, HistoryScope, SessionSelector,
    };
    use kr_protocol::ids::{AuthorityRevision, DeviceId, GrantId, SessionId};
    use kr_protocol::scalars::{CanonicalSet, Nullable, Uuid};

    const NOW: u64 = 1_700_000_000_000;

    fn uuid(byte: u8) -> Uuid {
        Uuid::from_bytes([byte; 16])
    }

    fn environment() -> EnvironmentId {
        EnvironmentId::new(uuid(7))
    }

    fn host() -> DeviceId {
        DeviceId::new(uuid(1))
    }

    fn grant(byte: u8, sessions: SessionSelector, actions: &[ActionRight]) -> Grant {
        Grant {
            grant_id: GrantId::new(uuid(byte)),
            parent_grant_id: Nullable::null(),
            issuer_device_id: host(),
            recipient_device_id: DeviceId::new(uuid(2)),
            authority_revision: AuthorityRevision::new(1),
            environment_selector: EnvironmentSelector::These {
                environment_ids: [environment()].into_iter().collect(),
            },
            session_selector: sessions,
            actions: actions.iter().copied().collect(),
            history: HistoryScope {
                lower_bound_ms: Nullable::null(),
                include_live_screen: false,
                named_questions: CanonicalSet::new(),
                named_approvals: CanonicalSet::new(),
            },
            expiry: GrantExpiry::Never,
            organisation: Nullable::null(),
        }
    }

    fn issued(sharing: &SharingService, grant: Grant, activated: bool) {
        sharing
            .grants()
            .issue(
                &GrantRecord {
                    grant,
                    session_id: None,
                    issued_at_ms: NOW - 1_000,
                    activated_at_ms: activated.then_some(NOW - 500),
                    revoked_at_ms: None,
                    revoked_by_parent: None,
                },
                || Ok(()),
            )
            .expect("the grant is written");
    }

    fn rule(grant: Option<u8>) -> DeliveryRule {
        DeliveryRule {
            name: "on a failed command".to_owned(),
            grant_id: grant.map(|byte| GrantId::new(uuid(byte))),
        }
    }

    fn personal() -> Arc<Mutex<HostPolicy>> {
        Arc::new(Mutex::new(HostPolicy::personal(AuthorityRevision::new(1))))
    }

    fn recipients(sharing: &Arc<SharingService>) -> GrantedRecipients {
        GrantedRecipients::at(Arc::clone(sharing), personal(), environment(), || NOW)
    }

    #[test]
    fn a_redeemed_grant_answers_with_its_own_session_selector() {
        let sharing = Arc::new(SharingService::in_memory(host()).expect("a store"));
        issued(
            &sharing,
            grant(10, SessionSelector::Any, &[ActionRight::SessionView]),
            true,
        );
        let scope = recipients(&sharing)
            .scope_for(&rule(Some(10)))
            .expect("the grant is in force");
        assert_eq!(
            scope.sessions,
            SessionSelector::Any,
            "a grant over every session covers the ones created after it, so it is not a list"
        );
        let named = SessionSelector::These {
            session_ids: [SessionId::new(uuid(30))].into_iter().collect(),
        };
        issued(
            &sharing,
            grant(11, named.clone(), &[ActionRight::SessionView]),
            true,
        );
        assert_eq!(
            recipients(&sharing)
                .scope_for(&rule(Some(11)))
                .expect("the grant is in force")
                .sessions,
            named
        );
    }

    #[test]
    fn a_grant_that_is_not_in_force_or_does_not_view_sessions_admits_nothing() {
        let sharing = Arc::new(SharingService::in_memory(host()).expect("a store"));
        // Never redeemed: a proposal authorises nothing.
        issued(
            &sharing,
            grant(10, SessionSelector::Any, &[ActionRight::SessionView]),
            false,
        );
        // In force, and it does not let its holder view a session.
        issued(
            &sharing,
            grant(11, SessionSelector::Any, &[ActionRight::FilesRead]),
            true,
        );
        // Issued for another environment.
        let mut elsewhere = grant(12, SessionSelector::Any, &[ActionRight::SessionView]);
        elsewhere.environment_selector = EnvironmentSelector::These {
            environment_ids: [EnvironmentId::new(uuid(8))].into_iter().collect(),
        };
        issued(&sharing, elsewhere, true);
        // In force, and then revoked.
        issued(
            &sharing,
            grant(13, SessionSelector::Any, &[ActionRight::SessionView]),
            true,
        );
        sharing
            .grants()
            .revoke(GrantId::new(uuid(13)), NOW - 100, || Ok(()))
            .expect("the revocation is written");

        let recipients = recipients(&sharing);
        for byte in [10, 11, 12, 13, 14] {
            assert_eq!(
                recipients.scope_for(&rule(Some(byte))),
                None,
                "grant {byte} admits nothing"
            );
        }
        assert_eq!(
            recipients.scope_for(&rule(None)),
            None,
            "nor does a rule that names no grant"
        );
    }

    /// The grant is intersected with the policy as it stands at the moment of asking: a policy
    /// that stops honouring the grant after the message was admitted stops the message.
    #[test]
    fn a_grant_the_host_policy_no_longer_honours_admits_nothing() {
        let sharing = Arc::new(SharingService::in_memory(host()).expect("a store"));
        issued(
            &sharing,
            grant(10, SessionSelector::Any, &[ActionRight::SessionView]),
            true,
        );
        let policy = personal();
        let recipients = GrantedRecipients::at(
            Arc::clone(&sharing),
            Arc::clone(&policy),
            environment(),
            || NOW,
        );
        assert!(recipients.scope_for(&rule(Some(10))).is_some());

        // The host becomes exclusively organisation-managed: personal authority stops with the
        // organisation's, and an external recipient is nobody this host can attribute a lease to.
        policy
            .lock()
            .expect("the policy is not poisoned")
            .set_exclusively_managed(true);
        assert_eq!(recipients.scope_for(&rule(Some(10))), None);
    }

    /// An organisation grant's lease is per member, and this host attributes no member to the
    /// recipient of an external message, so the grant admits nothing rather than being answered by
    /// somebody else's lease.
    #[test]
    fn an_organisation_grant_admits_nothing_for_a_recipient_no_lease_answers_for() {
        let sharing = Arc::new(SharingService::in_memory(host()).expect("a store"));
        let mut organisational = grant(10, SessionSelector::Any, &[ActionRight::SessionView]);
        organisational.organisation = Nullable::some(kr_protocol::grant::OrganisationRequirement {
            organisation_id: kr_protocol::ids::OrganisationId::new(uuid(40)),
            policy_revision: AuthorityRevision::new(1),
        });
        issued(&sharing, organisational, true);
        assert_eq!(recipients(&sharing).scope_for(&rule(Some(10))), None);
    }
}
