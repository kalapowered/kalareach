//! Grants, the policy intersection, delegation, the revocation cascade and the authority feed.
//!
//! Section 10's grant rules, section 17's membership rule, section 19's delegation rule and
//! section 24's revalidation rule are all the same shape: something that was true when a grant was
//! issued stops being true, and the host has to notice on the next request rather than on the next
//! reconnection. So every test here changes one fact and then asks the host, rather than asking it
//! once and trusting the answer.
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-REQ-10.40 | `a_grant_carries_every_field_section_ten_names`, `the_host_intersects_the_grant_with_policy_on_every_request`, `a_delegation_narrows_and_never_extends`, `revoking_a_parent_revokes_every_descendant` |
//! | KR-REQ-10.41 | `a_method_is_decided_from_the_registry_table_and_never_from_a_capability` |
//! | KR-REQ-10.43 | `an_owner_grant_stays_valid_until_it_is_revoked`, `an_invitation_is_view_only_for_an_hour_and_bounded_at_thirty_days` |
//! | KR-REQ-10.44 | `the_offline_validity_policy_is_optional_and_bounded_when_it_is_chosen`, `an_expired_grant_is_refused_rather_than_downgraded_to_view_only` |
//! | KR-REQ-10.45 | `a_local_revocation_advances_the_revision_fences_the_leases_and_reports_per_worker` |
//! | KR-REQ-17.54 | `an_expired_membership_blocks_organisation_mediated_work_on_a_live_transport`, `personal_access_survives_an_organisation_outage_unless_the_host_is_exclusively_managed` |
//! | KR-REQ-19.02 | `a_delegation_cannot_grant_a_right_the_delegating_actor_lacks` |
//! | KR-REQ-23.27 | `a_local_revocation_advances_the_revision_fences_the_leases_and_reports_per_worker`, `a_device_revocation_takes_every_grant_that_device_held` |
//! | KR-REQ-24.15 | `expiry_is_revalidated_after_a_wake_and_a_restored_old_policy_cannot_revive_authority` |

use std::sync::Arc;
use std::time::Duration;

use kr_controller::grants::{
    AccessRequest, AuthorityFeed, FeedRefusal, GrantDirectory, GrantRecord, HostPolicy, Refusal,
    decide, rights_for, unconditional_rights_for,
};
use kr_controller::service::{Controller, ControllerSetup};
use kr_controller::supervision::{LaunchOutcome, WorkerLaunch, WorkerSupervisor};
use kr_crypto::store::{StoreSelection, open_store_in};
use kr_ipc::verify::ControllerIdentity;
use kr_protocol::account::{MembershipLease, MembershipLeasePayload, TeamRole};
use kr_protocol::actor::ActorIngress;
use kr_protocol::grant::{
    EnvironmentSelector, Grant, GrantExpiry, HistoryScope, OrganisationRequirement, SessionSelector,
};
use kr_protocol::ids::{
    AccountId, AuthorityRevision, BuildId, DeviceId, EnvironmentId, GrantId, OrganisationId,
    PolicyKeyRevision, RevocationRequestId, SessionId,
};
use kr_protocol::method::Method;
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{CanonicalSet, Nullable, Signature64, TimestampMs, Uuid};
use kr_protocol::sharing::{MembershipRefusal, OfflineValidityPolicy};

// ---------------------------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------------------------

fn grant_id(byte: u8) -> GrantId {
    GrantId::new(Uuid::from_bytes([byte; 16]))
}

fn device_id(byte: u8) -> DeviceId {
    DeviceId::new(Uuid::from_bytes([byte; 16]))
}

fn session_id(byte: u8) -> SessionId {
    SessionId::new(Uuid::from_bytes([byte; 16]))
}

fn environment_id(byte: u8) -> EnvironmentId {
    EnvironmentId::new(Uuid::from_bytes([byte; 16]))
}

fn no_history() -> HistoryScope {
    HistoryScope {
        lower_bound_ms: Nullable::null(),
        include_live_screen: false,
        named_questions: CanonicalSet::from_iter([]),
        named_approvals: CanonicalSet::from_iter([]),
    }
}

/// A grant with every field section 10 names filled in.
fn grant(id: u8, parent: Option<GrantId>, actions: &[ActionRight], expiry: GrantExpiry) -> Grant {
    Grant {
        grant_id: grant_id(id),
        parent_grant_id: Nullable(parent),
        issuer_device_id: device_id(0xf0),
        recipient_device_id: device_id(0xf1),
        authority_revision: AuthorityRevision::new(1),
        environment_selector: EnvironmentSelector::These {
            environment_ids: [environment_id(0xe0)].into_iter().collect(),
        },
        session_selector: SessionSelector::These {
            session_ids: [session_id(0xa0)].into_iter().collect(),
        },
        actions: actions.iter().copied().collect(),
        history: no_history(),
        expiry,
        organisation: Nullable::null(),
    }
}

/// A grant whose invitation has been redeemed, which is what a live grant is.
fn record(grant: Grant) -> GrantRecord {
    GrantRecord {
        session_id: Some(session_id(0xa0)),
        grant,
        issued_at_ms: 1_000,
        activated_at_ms: Some(1_000),
        revoked_at_ms: None,
        revoked_by_parent: None,
    }
}

/// A grant nobody has redeemed yet.
fn proposal(grant: Grant) -> GrantRecord {
    GrantRecord {
        activated_at_ms: None,
        ..record(grant)
    }
}

/// A grant that was written and never redeemed authorises nothing.
#[test]
fn a_grant_whose_invitation_was_never_redeemed_decides_nothing() {
    let held = grant(1, None, &[ActionRight::SessionView], GrantExpiry::Never);
    let mut policy = HostPolicy::personal(AuthorityRevision::new(1));
    assert_eq!(
        decide(
            &held,
            &proposal(held.clone()),
            &mut policy,
            request(Method::SessionRead, 1_000)
        ),
        Err(Refusal::NotRedeemed {
            grant_id: held.grant_id
        }),
        "a proposal is not authority"
    );
    // The same grant, redeemed, decides.
    decide(
        &held,
        &record(held.clone()),
        &mut policy,
        request(Method::SessionRead, 1_000),
    )
    .expect("a redeemed grant decides");
}

fn account() -> AccountId {
    AccountId::new("3c9f2b7a-5d18-4a62-9c07-1f5b8e2d4a90").expect("an account identifier")
}

fn request(method: Method, now_ms: u64) -> AccessRequest {
    AccessRequest {
        method,
        ingress: ActorIngress::PairedDevice,
        environment_id: environment_id(0xe0),
        session_id: Some(session_id(0xa0)),
        claims_geometry: false,
        own_subject: None,
        recipient_account: Some(account()),
        now_ms,
    }
}

fn lease(
    organisation_id: OrganisationId,
    key_revision: PolicyKeyRevision,
    expires_at_ms: u64,
    maximum: &[ActionRight],
) -> MembershipLease {
    lease_for(
        account(),
        organisation_id,
        key_revision,
        expires_at_ms,
        maximum,
    )
}

fn lease_for(
    account_id: AccountId,
    organisation_id: OrganisationId,
    key_revision: PolicyKeyRevision,
    expires_at_ms: u64,
    maximum: &[ActionRight],
) -> MembershipLease {
    MembershipLease {
        payload: MembershipLeasePayload {
            organisation_id,
            account_id,
            role: TeamRole::Controller,
            maximum_grants: maximum.iter().copied().collect(),
            issued_at_ms: TimestampMs::new(0),
            expires_at_ms: TimestampMs::new(expires_at_ms),
            key_revision,
        },
        // The signature is checked where a lease arrives from the policy service. What these tests
        // exercise is what the host does with a lease it has already accepted, and the rule they
        // are about is the clock rather than the key.
        signature: Signature64::from_bytes([0; 64]),
    }
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-10.40: the record, the intersection, delegation and the cascade
// ---------------------------------------------------------------------------------------------

#[test]
fn a_grant_carries_every_field_section_ten_names() {
    let held = Grant {
        organisation: Nullable::some(OrganisationRequirement {
            organisation_id: OrganisationId::new(Uuid::from_bytes([0x21; 16])),
            policy_revision: AuthorityRevision::new(4),
        }),
        ..grant(
            1,
            Some(grant_id(2)),
            &[ActionRight::SessionView],
            GrantExpiry::Never,
        )
    };
    let encoded = kr_cbor::to_canonical_vec(&held).expect("a grant encodes");
    let read: Grant = kr_cbor::from_canonical_slice(&encoded, &kr_cbor::Limits::DEFAULT)
        .expect("a grant decodes");
    assert_eq!(read, held);

    // The fields section 10 lists, each one present and each one read back.
    assert_eq!(read.grant_id, grant_id(1));
    assert_eq!(read.parent_grant_id.as_ref(), Some(&grant_id(2)));
    assert_eq!(read.issuer_device_id, device_id(0xf0));
    assert_eq!(read.recipient_device_id, device_id(0xf1));
    assert_eq!(read.authority_revision, AuthorityRevision::new(1));
    assert!(read.environment_selector.admits(environment_id(0xe0)));
    assert!(read.session_selector.admits(session_id(0xa0)));
    assert!(read.permits(ActionRight::SessionView));
    assert_eq!(read.expiry, GrantExpiry::Never);
    assert!(read.organisation.is_present());
}

#[test]
fn the_host_intersects_the_grant_with_policy_on_every_request() {
    let directory = GrantDirectory::in_memory().expect("a grant store");
    let held = grant(
        1,
        None,
        &[ActionRight::SessionView, ActionRight::TerminalInput],
        GrantExpiry::Never,
    );
    let stored = record(held.clone());
    directory.issue(&stored).expect("the grant is written");

    let organisation_id = OrganisationId::new(Uuid::from_bytes([0x21; 16]));
    let key_revision = PolicyKeyRevision::new(4);
    let organisation_grant = Grant {
        organisation: Nullable::some(OrganisationRequirement {
            organisation_id,
            policy_revision: AuthorityRevision::new(4),
        }),
        ..held.clone()
    };
    let mut policy = HostPolicy::personal(AuthorityRevision::new(1));
    policy.enrol(organisation_id, key_revision, AuthorityRevision::new(4));
    // The organisation's maximum for this role does not include terminal input.
    policy
        .install_lease(lease(
            organisation_id,
            key_revision,
            10_000,
            &[ActionRight::SessionView],
        ))
        .expect("the lease is inside every rule section 17 states");

    // The same grant, decided twice: once on its own, once against the organisation's maximum.
    let permitted = decide(
        &held,
        &stored,
        &mut HostPolicy::personal(AuthorityRevision::new(1)),
        request(Method::InputWrite, 5_000),
    )
    .expect("the personal grant carries terminal input");
    assert!(permitted.rights.contains(&ActionRight::TerminalInput));

    let refused = decide(
        &organisation_grant,
        &record(organisation_grant.clone()),
        &mut policy,
        request(Method::InputWrite, 5_000),
    )
    .expect_err("the organisation's maximum does not reach terminal input");
    assert_eq!(
        refused,
        Refusal::MissingRight {
            right: ActionRight::TerminalInput
        },
        "the intersection decides, not the grant on its own"
    );
}

#[test]
fn a_delegation_narrows_and_never_extends() {
    let directory = GrantDirectory::in_memory().expect("a grant store");
    let parent = grant(
        1,
        None,
        &[ActionRight::SessionView, ActionRight::FilesRead],
        GrantExpiry::At {
            expires_at_ms: TimestampMs::new(10_000),
        },
    );
    directory
        .issue(&record(parent.clone()))
        .expect("the parent");

    // Narrower in rights and in lifetime: accepted.
    let child = Grant {
        grant_id: grant_id(2),
        parent_grant_id: Nullable::some(parent.grant_id),
        actions: [ActionRight::SessionView].into_iter().collect(),
        expiry: GrantExpiry::At {
            expires_at_ms: TimestampMs::new(5_000),
        },
        ..parent.clone()
    };
    directory.issue(&record(child)).expect("a narrowing child");

    // Longer than its parent: refused.
    let outliving = Grant {
        grant_id: grant_id(3),
        parent_grant_id: Nullable::some(parent.grant_id),
        actions: [ActionRight::SessionView].into_iter().collect(),
        expiry: GrantExpiry::Never,
        ..parent.clone()
    };
    let error = directory
        .issue(&record(outliving))
        .expect_err("a child cannot outlive its parent");
    assert!(
        error.to_string().contains("narrows its parent"),
        "unexpected refusal: {error}"
    );

    // Reaching a session the parent does not: refused.
    let wider = Grant {
        grant_id: grant_id(4),
        parent_grant_id: Nullable::some(parent.grant_id),
        session_selector: SessionSelector::Any,
        ..parent.clone()
    };
    directory
        .issue(&record(wider))
        .expect_err("a child cannot reach a session its parent does not");
}

#[test]
fn revoking_a_parent_revokes_every_descendant() {
    let directory = GrantDirectory::in_memory().expect("a grant store");
    let root = grant(
        1,
        None,
        &[ActionRight::SessionView, ActionRight::FilesRead],
        GrantExpiry::Never,
    );
    let child = Grant {
        grant_id: grant_id(2),
        parent_grant_id: Nullable::some(root.grant_id),
        ..root.clone()
    };
    let grandchild = Grant {
        grant_id: grant_id(3),
        parent_grant_id: Nullable::some(child.grant_id),
        actions: [ActionRight::SessionView].into_iter().collect(),
        ..root.clone()
    };
    // A grant that is nobody's descendant, to prove the cascade stops.
    let stranger = Grant {
        grant_id: grant_id(9),
        parent_grant_id: Nullable::null(),
        ..root.clone()
    };
    for held in [&root, &child, &grandchild, &stranger] {
        directory.issue(&record(held.clone())).expect("written");
    }

    let revocation = directory.revoke(root.grant_id, 4_000).expect("revoked");
    assert_eq!(
        revocation.revoked.len(),
        3,
        "the whole subtree, however deep"
    );
    assert!(revocation.revoked.contains(&grandchild.grant_id));
    assert!(!revocation.revoked.contains(&stranger.grant_id));

    let grandchild_record = directory
        .record(grandchild.grant_id)
        .expect("readable")
        .expect("present");
    assert_eq!(grandchild_record.revoked_at_ms, Some(4_000));
    assert_eq!(
        grandchild_record.revoked_by_parent,
        Some(root.grant_id),
        "a descendant names the ancestor whose revocation took it"
    );
    let error = decide(
        &grandchild,
        &grandchild_record,
        &mut HostPolicy::personal(AuthorityRevision::new(1)),
        request(Method::SessionRead, 5_000),
    )
    .expect_err("a revoked descendant decides nothing");
    assert_eq!(
        error,
        Refusal::ParentRevoked {
            parent_grant_id: root.grant_id
        }
    );

    assert!(
        directory
            .record(stranger.grant_id)
            .expect("readable")
            .expect("present")
            .revoked_at_ms
            .is_none(),
        "the cascade follows the parent link and nothing else"
    );
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-10.41: the vocabulary, and capabilities never becoming authority
// ---------------------------------------------------------------------------------------------

#[test]
fn a_method_is_decided_from_the_registry_table_and_never_from_a_capability() {
    // The table is the registry's. Writing input needs terminal input; reading a session does not.
    assert_eq!(
        unconditional_rights_for(Method::InputWrite),
        vec![ActionRight::TerminalInput]
    );
    assert!(rights_for(Method::SessionRead).contains(&ActionRight::SessionView));
    assert!(
        !rights_for(Method::SessionRead).contains(&ActionRight::TerminalInput),
        "a read does not require the right that would let somebody type"
    );

    // A viewer holding every capability evidence there is still cannot write input, because a
    // capability describes feasibility and authority is the grant's.
    let viewer = grant(1, None, &[ActionRight::SessionView], GrantExpiry::Never);
    let error = decide(
        &viewer,
        &record(viewer.clone()),
        &mut HostPolicy::personal(AuthorityRevision::new(1)),
        request(Method::InputWrite, 5_000),
    )
    .expect_err("a viewer cannot write input");
    assert_eq!(
        error,
        Refusal::MissingRight {
            right: ActionRight::TerminalInput
        }
    );

    // Every right in the vocabulary is spelt the way the wire spells it, and resolves back.
    for right in ActionRight::ALL {
        assert_eq!(ActionRight::from_wire(right.as_str()), Some(*right));
    }
}

/// A decision that could not answer every requirement says which ones it left.
#[test]
fn a_permitted_decision_names_the_requirements_it_could_not_answer() {
    let owner = grant(
        1,
        None,
        &[ActionRight::SessionView, ActionRight::HostManage],
        GrantExpiry::Never,
    );
    let stored = record(owner.clone());
    let mut policy = HostPolicy::personal(AuthorityRevision::new(1));

    // `session.read` needs one right and nothing the subject has to resolve.
    let plain = decide(
        &owner,
        &stored,
        &mut policy,
        request(Method::SessionRead, 1_000),
    )
    .expect("permitted");
    assert!(
        plain.is_complete(),
        "nothing is owed: {:?}",
        plain.unresolved
    );

    // `action.read` needs the subject's own answer as well, and says so rather than letting a
    // caller read `Ok` as the whole answer.
    let receipt = decide(
        &owner,
        &stored,
        &mut policy,
        request(Method::ActionRead, 1_000),
    )
    .expect("permitted so far");
    assert!(
        !receipt.is_complete(),
        "an authority the subject resolves is still owed"
    );
    assert!(
        receipt
            .unresolved
            .contains(&kr_protocol::authority::RequiredAuthority::ResourceOwner),
        "and it is named: {:?}",
        receipt.unresolved
    );

    // A receipt for a host effect names no session, so present view authority over it is the
    // actor's read scope over the environment rather than `session.view`.
    let host_scope = AccessRequest {
        session_id: None,
        ..request(Method::ActionRead, 1_000)
    };
    let no_view = grant(2, None, &[ActionRight::HostManage], GrantExpiry::Never);
    decide(&no_view, &record(no_view.clone()), &mut policy, host_scope)
        .expect("a host effect's receipt is not a session read");

    // The same method for a session subject does need it.
    assert_eq!(
        decide(
            &no_view,
            &record(no_view.clone()),
            &mut policy,
            request(Method::ActionRead, 1_000)
        ),
        Err(Refusal::MissingRight {
            right: ActionRight::SessionView
        })
    );
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-10.43 and 10.44: lifetimes, the offline policy and what expiry does
// ---------------------------------------------------------------------------------------------

#[test]
fn an_owner_grant_stays_valid_until_it_is_revoked() {
    let directory = GrantDirectory::in_memory().expect("a grant store");
    let owner = grant(
        1,
        None,
        &[ActionRight::SessionView, ActionRight::TerminalInput],
        GrantExpiry::Never,
    );
    directory.issue(&record(owner.clone())).expect("written");
    let mut policy = HostPolicy::personal(AuthorityRevision::new(1));

    // A year later, with no feed anywhere, it still decides: independent operation does not depend
    // on a cloud lease.
    let far = 365 * 24 * 60 * 60 * 1000;
    let held = directory
        .record(owner.grant_id)
        .expect("read")
        .expect("present");
    decide(
        &owner,
        &held,
        &mut policy,
        request(Method::SessionRead, far),
    )
    .expect("an owner grant does not expire");

    directory.revoke(owner.grant_id, far).expect("revoked");
    let held = directory
        .record(owner.grant_id)
        .expect("read")
        .expect("present");
    assert_eq!(
        decide(
            &owner,
            &held,
            &mut policy,
            request(Method::SessionRead, far + 1)
        ),
        Err(Refusal::Revoked {
            grant_id: owner.grant_id
        }),
        "until revoked is exactly until revoked"
    );
}

#[test]
fn an_invitation_is_view_only_for_an_hour_and_bounded_at_thirty_days() {
    use kr_controller::sharing::roles;
    use kr_protocol::sharing::{
        DEFAULT_INVITATION_LIFETIME_MS, MAX_INVITATION_LIFETIME_MS, RoleSelection, SessionRole,
    };

    let default = roles::compile(
        &RoleSelection::plain(SessionRole::Viewer),
        session_id(0xa0),
        None,
        1_000,
    )
    .expect("the default invitation");
    assert_eq!(
        default.expiry,
        GrantExpiry::At {
            expires_at_ms: TimestampMs::new(1_000 + DEFAULT_INVITATION_LIFETIME_MS)
        },
        "an hour, when the issuer chooses nothing"
    );
    assert_eq!(
        default.actions.iter().copied().collect::<Vec<_>>(),
        vec![ActionRight::SessionView],
        "view-only, when the issuer chooses nothing"
    );

    roles::compile(
        &RoleSelection::plain(SessionRole::Viewer),
        session_id(0xa0),
        Some(60_000),
        1_000,
    )
    .expect("the issuer may choose a shorter duration");
    roles::compile(
        &RoleSelection::plain(SessionRole::Viewer),
        session_id(0xa0),
        Some(MAX_INVITATION_LIFETIME_MS),
        1_000,
    )
    .expect("thirty days is inside the bound");
    let error = roles::compile(
        &RoleSelection::plain(SessionRole::Viewer),
        session_id(0xa0),
        Some(MAX_INVITATION_LIFETIME_MS + 1),
        1_000,
    )
    .expect_err("a day past the bound is refused rather than clamped");
    assert!(
        error.to_string().contains("30 days"),
        "unexpected refusal: {error}"
    );
}

#[test]
fn the_offline_validity_policy_is_optional_and_bounded_when_it_is_chosen() {
    let owner = grant(
        1,
        None,
        &[ActionRight::SessionView, ActionRight::TerminalInput],
        GrantExpiry::Never,
    );
    let stored = record(owner.clone());

    // Off by default: the non-expiring owner grant is account-free and needs no feed.
    let mut default = HostPolicy::personal(AuthorityRevision::new(1));
    assert!(default.offline_validity().is_none());
    decide(
        &owner,
        &stored,
        &mut default,
        request(Method::SessionRead, 900_000),
    )
    .expect("no feed dependency by default");

    // Chosen: bounded from the last successful synchronisation, and visible.
    let mut bounded = HostPolicy::personal(AuthorityRevision::new(1));
    bounded.set_offline_validity(Some(OfflineValidityPolicy {
        maximum_offline_ms: kr_protocol::scalars::DurationMs::new(60_000),
        last_synchronised_at_ms: Nullable::null(),
    }));
    bounded.note_feed_synchronised(100_000);
    decide(
        &owner,
        &stored,
        &mut bounded,
        request(Method::SessionRead, 150_000),
    )
    .expect("inside the bound");
    assert_eq!(
        decide(
            &owner,
            &stored,
            &mut bounded,
            request(Method::SessionRead, 160_001)
        ),
        Err(Refusal::OfflineValidityLapsed {
            last_synchronised_at_ms: Some(100_000)
        }),
        "past the bound the owner chose, and the last sync is what it says"
    );
}

#[test]
fn an_expired_grant_is_refused_rather_than_downgraded_to_view_only() {
    let controller = grant(
        1,
        None,
        &[ActionRight::SessionView, ActionRight::TerminalInput],
        GrantExpiry::At {
            expires_at_ms: TimestampMs::new(5_000),
        },
    );
    let stored = record(controller.clone());
    let mut policy = HostPolicy::personal(AuthorityRevision::new(1));

    decide(
        &controller,
        &stored,
        &mut policy,
        request(Method::SessionRead, 4_999),
    )
    .expect("valid up to the deadline");

    // The read, which a downgrade would have kept serving.
    assert_eq!(
        decide(
            &controller,
            &stored,
            &mut policy,
            request(Method::SessionRead, 5_000)
        ),
        Err(Refusal::Expired {
            expired_at_ms: 5_000
        }),
        "continued reads still require valid authority"
    );
    // And the write, so nothing is left of the grant either way.
    assert_eq!(
        decide(
            &controller,
            &stored,
            &mut policy,
            request(Method::InputWrite, 5_000)
        ),
        Err(Refusal::Expired {
            expired_at_ms: 5_000
        })
    );
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-17.54: an expired membership on a live transport
// ---------------------------------------------------------------------------------------------

#[test]
fn an_expired_membership_blocks_organisation_mediated_work_on_a_live_transport() {
    let organisation_id = OrganisationId::new(Uuid::from_bytes([0x21; 16]));
    let key_revision = PolicyKeyRevision::new(4);
    let held = Grant {
        organisation: Nullable::some(OrganisationRequirement {
            organisation_id,
            policy_revision: AuthorityRevision::new(4),
        }),
        ..grant(
            1,
            None,
            &[ActionRight::SessionView, ActionRight::TerminalInput],
            GrantExpiry::Never,
        )
    };
    let stored = record(held.clone());

    let mut policy = HostPolicy::personal(AuthorityRevision::new(1));
    policy.enrol(organisation_id, key_revision, AuthorityRevision::new(4));
    policy
        .install_lease(lease(
            organisation_id,
            key_revision,
            10_000,
            &[ActionRight::SessionView, ActionRight::TerminalInput],
        ))
        .expect("the lease is inside every rule section 17 states");

    // Nothing about the transport changes between these two. Only the clock does.
    decide(
        &held,
        &stored,
        &mut policy,
        request(Method::SessionRead, 9_999),
    )
    .expect("inside the lease");
    assert_eq!(
        decide(
            &held,
            &stored,
            &mut policy,
            request(Method::SessionRead, 10_000)
        ),
        Err(Refusal::MembershipUnusable {
            refusal: MembershipRefusal::LeaseExpired
        }),
        "a connected transport does not extend a lease"
    );
    assert_eq!(
        decide(
            &held,
            &stored,
            &mut policy,
            request(Method::InputWrite, 10_000)
        ),
        Err(Refusal::MembershipUnusable {
            refusal: MembershipRefusal::LeaseExpired
        }),
        "reads and mutations alike"
    );

    // A lease signed under a policy-signing revision this host has not pinned is refused whatever
    // the clock says.
    let mut mismatched = HostPolicy::personal(AuthorityRevision::new(1));
    mismatched.enrol(organisation_id, key_revision, AuthorityRevision::new(4));
    assert_eq!(
        mismatched.install_lease(lease(
            organisation_id,
            PolicyKeyRevision::new(5),
            10_000,
            &[ActionRight::SessionView],
        )),
        Err(kr_controller::grants::LeaseRefused::WrongKeyRevision),
        "a lease signed under a key revision this host has not pinned is not installed at all"
    );
    // Because it was never installed, the decision finds no lease at all. That is the stronger
    // outcome: a host does not hold a lease it could not have accepted.
    assert_eq!(
        decide(
            &held,
            &stored,
            &mut mismatched,
            request(Method::SessionRead, 1_000)
        ),
        Err(Refusal::MembershipUnusable {
            refusal: MembershipRefusal::NoLease
        })
    );
}

#[test]
fn personal_access_survives_an_organisation_outage_unless_the_host_is_exclusively_managed() {
    let organisation_id = OrganisationId::new(Uuid::from_bytes([0x21; 16]));
    let key_revision = PolicyKeyRevision::new(4);
    let personal = grant(
        1,
        None,
        &[ActionRight::SessionView, ActionRight::TerminalInput],
        GrantExpiry::Never,
    );
    let stored = record(personal.clone());

    let mut ordinary = HostPolicy::personal(AuthorityRevision::new(1));
    ordinary.enrol(organisation_id, key_revision, AuthorityRevision::new(4));
    ordinary
        .install_lease(lease(
            organisation_id,
            key_revision,
            10_000,
            &[ActionRight::SessionView],
        ))
        .expect("the lease is installed");
    decide(
        &personal,
        &stored,
        &mut ordinary,
        request(Method::SessionRead, 900_000),
    )
    .expect("a personal grant is untouched by an organisation outage");

    let mut exclusive = HostPolicy::personal(AuthorityRevision::new(1));
    exclusive.enrol(organisation_id, key_revision, AuthorityRevision::new(4));
    exclusive.set_exclusively_managed(true);
    exclusive
        .install_lease(lease(
            organisation_id,
            key_revision,
            10_000,
            &[ActionRight::SessionView],
        ))
        .expect("the lease is installed");
    assert!(exclusive.is_exclusively_managed());
    assert_eq!(
        decide(
            &personal,
            &stored,
            &mut exclusive,
            request(Method::SessionRead, 900_000)
        ),
        Err(Refusal::MembershipUnusable {
            refusal: MembershipRefusal::LeaseExpired
        }),
        "a host enrolled as exclusively organisation-managed has no personal path left"
    );
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-19.02: delegation cannot grant what the delegating actor lacks
// ---------------------------------------------------------------------------------------------

#[test]
fn a_delegation_cannot_grant_a_right_the_delegating_actor_lacks() {
    use kr_controller::sharing::roles;

    let viewer = grant(1, None, &[ActionRight::SessionView], GrantExpiry::Never);
    let asking_for_input = Grant {
        grant_id: grant_id(2),
        parent_grant_id: Nullable::some(viewer.grant_id),
        actions: [ActionRight::SessionView, ActionRight::TerminalInput]
            .into_iter()
            .collect(),
        ..viewer.clone()
    };
    let error = roles::check_delegation(&asking_for_input, &viewer)
        .expect_err("a viewer cannot delegate terminal input");
    assert!(
        error.to_string().contains("terminal.input"),
        "the refusal names the right: {error}"
    );

    // And the store refuses it too, so the rule does not depend on a caller remembering to ask.
    let directory = GrantDirectory::in_memory().expect("a grant store");
    directory.issue(&record(viewer)).expect("the parent");
    directory
        .issue(&record(asking_for_input))
        .expect_err("the store applies the same rule");
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-24.15: revalidation after wake and reboot
// ---------------------------------------------------------------------------------------------

#[test]
fn expiry_is_revalidated_after_a_wake_and_a_restored_old_policy_cannot_revive_authority() {
    let held = grant(
        1,
        None,
        &[ActionRight::SessionView],
        GrantExpiry::At {
            expires_at_ms: TimestampMs::new(5_000),
        },
    );
    let stored = record(held.clone());
    let mut policy = HostPolicy::personal(AuthorityRevision::new(1));

    decide(
        &held,
        &stored,
        &mut policy,
        request(Method::SessionRead, 1_000),
    )
    .expect("valid before the machine sleeps");

    // The machine sleeps through the deadline. Waking is where expiry is decided again, and the
    // clock is what decides it: nothing is carried over from before the gap.
    policy.revalidate(900_000);
    assert_eq!(policy.revalidated_at_ms(), 900_000);
    assert_eq!(
        decide(
            &held,
            &stored,
            &mut policy,
            request(Method::SessionRead, 900_000)
        ),
        Err(Refusal::Expired {
            expired_at_ms: 5_000
        })
    );

    // A policy document restored from a backup names an older revision. It is refused, and the
    // revision in force does not move.
    policy.advance_authority_revision(AuthorityRevision::new(7));
    assert!(!policy.accept_policy(AuthorityRevision::new(3)));
    assert!(!policy.accept_policy(AuthorityRevision::new(7)));
    assert_eq!(policy.authority_revision(), AuthorityRevision::new(7));
    assert_eq!(policy.accepted_floor(), AuthorityRevision::new(7));
    assert!(policy.accept_policy(AuthorityRevision::new(8)));
    assert_eq!(policy.authority_revision(), AuthorityRevision::new(8));

    // A grant issued under an older revision still decides. Somebody else's revocation advancing
    // the host's revision is not a reason to stop honouring an untouched grant, and treating it as
    // one would make every revocation a host-wide expiry.
    let older = Grant {
        authority_revision: AuthorityRevision::new(2),
        expiry: GrantExpiry::Never,
        ..held
    };
    decide(
        &older,
        &record(older.clone()),
        &mut policy,
        request(Method::SessionRead, 1_000),
    )
    .expect("an untouched grant survives somebody else's revocation");

    // A grant claiming a revision this host has never issued is refused: nothing here could have
    // issued it.
    let invented = Grant {
        authority_revision: AuthorityRevision::new(99),
        ..older
    };
    assert_eq!(
        decide(
            &invented,
            &record(invented.clone()),
            &mut policy,
            request(Method::SessionRead, 1_000)
        ),
        Err(Refusal::UnissuedAuthority {
            grant_revision: AuthorityRevision::new(99),
            current_revision: AuthorityRevision::new(8)
        })
    );
}

/// A clock wound back past a deadline does not revive a grant the host has already refused.
#[test]
fn a_clock_that_goes_backwards_does_not_revive_an_expiry_the_host_already_decided() {
    let held = grant(
        1,
        None,
        &[ActionRight::SessionView],
        GrantExpiry::At {
            expires_at_ms: TimestampMs::new(5_000),
        },
    );
    let stored = record(held.clone());
    let mut policy = HostPolicy::personal(AuthorityRevision::new(1));

    // The host decides at 6,000 and refuses: the deadline has passed.
    policy.observe_utc(6_000);
    assert_eq!(
        decide(
            &held,
            &stored,
            &mut policy,
            request(Method::SessionRead, 6_000)
        ),
        Err(Refusal::Expired {
            expired_at_ms: 5_000
        })
    );

    // The clock is wound back to before the deadline. The floor is what decides, so the answer does
    // not change.
    assert_eq!(policy.settled_now(4_000), 6_000);
    assert_eq!(
        decide(
            &held,
            &stored,
            &mut policy,
            request(Method::SessionRead, 4_000)
        ),
        Err(Refusal::Expired {
            expired_at_ms: 5_000
        }),
        "an expiry already decided is not re-opened by a smaller reading"
    );
    assert_eq!(
        policy.utc_floor_ms(),
        6_000,
        "and the floor never went down"
    );
}

/// The stored policy is what a restarted host comes back with.
#[test]
fn a_restart_restores_the_restrictions_rather_than_an_unrestricted_host() {
    let directory = GrantDirectory::in_memory().expect("a grant store");
    let organisation_id = OrganisationId::new(Uuid::from_bytes([0x21; 16]));

    let mut policy = HostPolicy::personal(AuthorityRevision::new(3));
    policy.set_exclusively_managed(true);
    policy.enrol(
        organisation_id,
        PolicyKeyRevision::new(4),
        AuthorityRevision::new(4),
    );
    policy.set_offline_validity(Some(OfflineValidityPolicy {
        maximum_offline_ms: kr_protocol::scalars::DurationMs::new(60_000),
        last_synchronised_at_ms: Nullable::some(TimestampMs::new(100_000)),
    }));
    policy.observe_utc(500_000);
    policy.advance_authority_revision(AuthorityRevision::new(9));
    directory
        .store_policy(&policy.snapshot())
        .expect("the policy is written down");

    // A restart reads it back. The registry's own revision is lower, and the floor does not move
    // down to meet it.
    let stored = directory
        .stored_policy()
        .expect("readable")
        .expect("present");
    let mut restored = HostPolicy::restore(&stored, AuthorityRevision::new(3));
    assert!(
        restored.is_exclusively_managed(),
        "a restart is not an amnesty"
    );
    assert!(restored.offline_validity().is_some());
    assert!(restored.enrolment(organisation_id).is_some());
    assert_eq!(restored.accepted_floor(), AuthorityRevision::new(9));
    assert_eq!(restored.utc_floor_ms(), 500_000);
    assert!(
        !restored.accept_policy(AuthorityRevision::new(5)),
        "and a restored old policy still cannot revive authority"
    );

    // The lease is deliberately not restored: a fifteen-minute deadline the organisation may have
    // withdrawn is not a thing to bring back.
    assert!(
        restored
            .enrolment(organisation_id)
            .expect("enrolled")
            .leases
            .is_empty()
    );
}

/// One member's lease does not answer for another member.
#[test]
fn one_members_lease_does_not_sustain_another_members_access() {
    let organisation_id = OrganisationId::new(Uuid::from_bytes([0x21; 16]));
    let key_revision = PolicyKeyRevision::new(4);
    let held = Grant {
        organisation: Nullable::some(OrganisationRequirement {
            organisation_id,
            policy_revision: AuthorityRevision::new(4),
        }),
        ..grant(1, None, &[ActionRight::SessionView], GrantExpiry::Never)
    };
    let stored = record(held.clone());

    let mut policy = HostPolicy::personal(AuthorityRevision::new(1));
    policy.enrol(organisation_id, key_revision, AuthorityRevision::new(4));
    // A lease for somebody else entirely.
    policy
        .install_lease(lease_for(
            AccountId::new("8f14e45f-ea1e-4b9e-9f3a-0a3a9b0d2f61").expect("an account"),
            organisation_id,
            key_revision,
            10_000,
            &[ActionRight::SessionView],
        ))
        .expect("the lease is installed");

    assert_eq!(
        decide(
            &held,
            &stored,
            &mut policy,
            request(Method::SessionRead, 1_000)
        ),
        Err(Refusal::MembershipUnusable {
            refusal: MembershipRefusal::NoLease
        }),
        "a valid member's lease does not answer for a disabled one"
    );

    // With this recipient's own lease it decides, and dropping that one lease stops it again
    // without touching anybody else's.
    policy
        .install_lease(lease(
            organisation_id,
            key_revision,
            10_000,
            &[ActionRight::SessionView],
        ))
        .expect("the lease is installed");
    decide(
        &held,
        &stored,
        &mut policy,
        request(Method::SessionRead, 1_000),
    )
    .expect("this member's own lease answers");
    policy.drop_lease(organisation_id, &account());
    assert_eq!(
        decide(
            &held,
            &stored,
            &mut policy,
            request(Method::SessionRead, 1_000)
        ),
        Err(Refusal::MembershipUnusable {
            refusal: MembershipRefusal::NoLease
        })
    );

    // And a host that cannot name the account refuses rather than picking a lease.
    let unattributed = AccessRequest {
        recipient_account: None,
        ..request(Method::SessionRead, 1_000)
    };
    assert_eq!(
        decide(&held, &stored, &mut policy, unattributed),
        Err(Refusal::MembershipUnattributed)
    );
}

/// A grant answering to a policy revision this host has not pinned is refused.
#[test]
fn a_grant_naming_another_policy_revision_is_refused() {
    let organisation_id = OrganisationId::new(Uuid::from_bytes([0x21; 16]));
    let key_revision = PolicyKeyRevision::new(4);
    let held = Grant {
        organisation: Nullable::some(OrganisationRequirement {
            organisation_id,
            policy_revision: AuthorityRevision::new(3),
        }),
        ..grant(1, None, &[ActionRight::SessionView], GrantExpiry::Never)
    };
    let mut policy = HostPolicy::personal(AuthorityRevision::new(1));
    policy.enrol(organisation_id, key_revision, AuthorityRevision::new(4));
    policy
        .install_lease(lease(
            organisation_id,
            key_revision,
            10_000,
            &[ActionRight::SessionView],
        ))
        .expect("the lease is installed");
    assert_eq!(
        decide(
            &held,
            &record(held.clone()),
            &mut policy,
            request(Method::SessionRead, 1_000)
        ),
        Err(Refusal::MembershipUnusable {
            refusal: MembershipRefusal::WrongAuthority
        })
    );
}

/// Enrolling in a second organisation does not undo the exclusive-management restriction.
#[test]
fn a_second_enrolment_does_not_undo_exclusive_management() {
    let mut policy = HostPolicy::personal(AuthorityRevision::new(1));
    policy.set_exclusively_managed(true);
    policy.enrol(
        OrganisationId::new(Uuid::from_bytes([0x21; 16])),
        PolicyKeyRevision::new(4),
        AuthorityRevision::new(4),
    );
    policy.enrol(
        OrganisationId::new(Uuid::from_bytes([0x22; 16])),
        PolicyKeyRevision::new(5),
        AuthorityRevision::new(5),
    );
    assert!(policy.is_exclusively_managed());
}

/// A lease outside section 17's own rules is not installed at all.
#[test]
fn a_lease_outside_its_own_rules_is_refused_before_it_is_stored() {
    use kr_controller::grants::LeaseRefused;

    let organisation_id = OrganisationId::new(Uuid::from_bytes([0x21; 16]));
    let key_revision = PolicyKeyRevision::new(4);
    let mut policy = HostPolicy::personal(AuthorityRevision::new(1));

    assert_eq!(
        policy.install_lease(lease(
            organisation_id,
            key_revision,
            10_000,
            &[ActionRight::SessionView]
        )),
        Err(LeaseRefused::NotEnrolled)
    );

    policy.enrol(organisation_id, key_revision, AuthorityRevision::new(4));
    // Longer than the fifteen minutes section 17 permits.
    assert_eq!(
        policy.install_lease(lease(
            organisation_id,
            key_revision,
            HostPolicy::maximum_lease_lifetime_ms() + 1,
            &[ActionRight::SessionView]
        )),
        Err(LeaseRefused::TooLong)
    );
    // More than the role's own ceiling.
    assert_eq!(
        policy.install_lease(lease(
            organisation_id,
            key_revision,
            10_000,
            ActionRight::ALL
        )),
        Err(LeaseRefused::AboveRoleCeiling)
    );
}

// ---------------------------------------------------------------------------------------------
// The remote authority feed's host-side half
// ---------------------------------------------------------------------------------------------

#[test]
fn only_the_host_issues_ordered_revisions_and_records_are_retained_until_acknowledged() {
    use kr_protocol::pairing::{RevocationRequest, RevocationTarget};

    let host = device_id(0xf0);
    let mut feed = AuthorityFeed::new(host, AuthorityRevision::new(3));
    assert!(
        feed.synchronisation_owed(),
        "a host that has not heard from the feed owes a synchronisation before remote work"
    );

    let published = |byte: u8| RevocationRequest {
        request_id: RevocationRequestId::new(Uuid::from_bytes([byte; 16])),
        issuer_device_id: device_id(0xb0),
        host_device_id: host,
        target: RevocationTarget::Devices {
            device_ids: [device_id(0xc0)].into_iter().collect(),
        },
        issued_at_ms: TimestampMs::new(1_000),
        issuer_key_id: kr_protocol::scalars::KeyId::from_bytes([7; 32]),
        signature: Signature64::from_bytes([0; 64]),
    };

    // The request carries no revision at all. The host allocates the number, from the same
    // sequence its own revocations use.
    let issued = feed
        .apply(published(1), feed.next_revision(), 2_000)
        .expect("the host issues one");
    assert_eq!(issued, AuthorityRevision::new(4));
    assert_eq!(feed.accepted_revision(), AuthorityRevision::new(4));

    // A republished request is the same revocation, not a second one.
    assert_eq!(
        feed.apply(published(1), feed.next_revision(), 2_100)
            .expect("idempotent"),
        issued
    );
    assert_eq!(feed.accepted_revision(), AuthorityRevision::new(4));

    // A different request wearing an identity this host has already applied is refused rather
    // than answered with somebody else's revision.
    let impostor = RevocationRequest {
        issuer_device_id: device_id(0xbe),
        ..published(1)
    };
    assert_eq!(
        feed.apply(impostor, feed.next_revision(), 2_150),
        Err(FeedRefusal::AlreadyApplied)
    );

    // A request addressed to another host is refused.
    let elsewhere = RevocationRequest {
        host_device_id: device_id(0xee),
        ..published(2)
    };
    assert_eq!(
        feed.apply(elsewhere, feed.next_revision(), 2_200),
        Err(FeedRefusal::AnotherHost)
    );

    // A local revocation consumes a revision too, and the feed is told, so the next feed entry
    // cannot claim a number the registry has already used.
    feed.note_revision(AuthorityRevision::new(7));
    assert_eq!(feed.next_revision(), AuthorityRevision::new(8));

    // Retained until every enrolled host has acknowledged it.
    feed.enrol(device_id(0xd0));
    feed.enrol(device_id(0xd1));
    assert_eq!(feed.retained().len(), 1);
    let request_id = RevocationRequestId::new(Uuid::from_bytes([1; 16]));
    assert!(!feed.acknowledge(request_id, device_id(0xd0)));
    assert_eq!(feed.retained().len(), 1, "one of two is not every one");
    assert_eq!(
        feed.last_acknowledgement(device_id(0xd0)),
        Some(AuthorityRevision::new(4)),
        "the device list shows each host's last acknowledgement"
    );
    assert!(feed.acknowledge(request_id, device_id(0xd1)));
    assert!(
        feed.retained().is_empty(),
        "a settled record is no longer owed to anybody"
    );

    // Settling is not forgetting. The acknowledgement history survives it, and so does the
    // identity that stops the request being applied a second time.
    assert_eq!(feed.applied().len(), 1);
    assert_eq!(
        feed.last_acknowledgement(device_id(0xd1)),
        Some(AuthorityRevision::new(4)),
        "a settled record is still what that host acknowledged"
    );
    assert_eq!(
        feed.apply(published(1), feed.next_revision(), 3_000)
            .expect("still idempotent"),
        issued,
        "a republished request after settlement does not take a second revision"
    );

    // Reconnecting owes a synchronisation again, and an unreachable feed is stale rather than
    // silently current.
    feed.synchronised(3_000);
    assert!(!feed.synchronisation_owed());
    assert!(!feed.status().stale);
    assert_eq!(feed.next_poll_due_ms(), Some(33_000));
    feed.unreachable();
    assert!(feed.status().stale);
    assert!(
        !feed.synchronisation_owed(),
        "an unreachable feed is not a reason to stop serving work this host is authorised for"
    );
    feed.reconnected();
    assert!(feed.synchronisation_owed());

    // What is written down comes back, and a restarted host owes a synchronisation whatever it
    // last recorded.
    let stored = feed.snapshot();
    let restored = AuthorityFeed::restore(&stored);
    assert_eq!(restored.accepted_revision(), feed.accepted_revision());
    assert_eq!(restored.applied().len(), 1);
    assert_eq!(
        restored.last_acknowledgement(device_id(0xd0)),
        Some(AuthorityRevision::new(4))
    );
    assert!(restored.synchronisation_owed());
    assert!(restored.status().stale);
}

#[test]
fn a_feed_record_at_or_below_the_accepted_revision_is_refused() {
    use kr_protocol::pairing::AuthorityRevisionRecord;

    let host = device_id(0xf0);
    let mut feed = AuthorityFeed::new(host, AuthorityRevision::new(5));
    let replayed = AuthorityRevisionRecord {
        host_device_id: host,
        authority_revision: AuthorityRevision::new(4),
        previous_revision: AuthorityRevision::new(3),
        applied_requests: CanonicalSet::from_iter([]),
        issued_at_ms: TimestampMs::new(1_000),
        host_key_id: kr_protocol::scalars::KeyId::from_bytes([7; 32]),
        signature: Signature64::from_bytes([0; 64]),
    };
    assert_eq!(
        feed.accept(&replayed),
        Err(FeedRefusal::OutOfOrder {
            accepted: AuthorityRevision::new(5),
            offered: AuthorityRevision::new(4)
        })
    );
    let following = AuthorityRevisionRecord {
        authority_revision: AuthorityRevision::new(6),
        previous_revision: AuthorityRevision::new(5),
        ..replayed
    };
    feed.accept(&following).expect("the next one is accepted");
    assert_eq!(feed.accepted_revision(), AuthorityRevision::new(6));
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-10.45 and KR-REQ-23.27: a local revocation through the daemon
// ---------------------------------------------------------------------------------------------

/// A supervisor that starts nothing.
///
/// These tests are about grants rather than about sessions, so nothing here creates one. A
/// supervisor that refused by pretending to have started something would make a later failure
/// look like a grant problem.
#[derive(Debug)]
struct SilentSupervisor;

impl WorkerSupervisor for SilentSupervisor {
    fn start(&self, _launch: &WorkerLaunch) -> LaunchOutcome {
        LaunchOutcome::NotStarted {
            detail: "this test starts no worker".to_owned(),
        }
    }

    fn describe(&self) -> String {
        "a supervisor that starts nothing".to_owned()
    }
}

async fn daemon() -> (kr_ipc::testing::TempHost, Arc<Controller>) {
    let temp = kr_ipc::testing::TempHost::create();
    let environment = temp.environment();
    let environment_id = temp.environment_id();
    let secrets = environment.secrets_dir();
    let controller = Controller::start(ControllerSetup {
        paths: environment.clone(),
        environment_id,
        identity: Box::new(move || {
            let store = open_store_in(&secrets).expect("a secret store for the test environment");
            Ok(
                ControllerIdentity::open(store.store.as_ref(), environment_id, false)
                    .expect("an identity"),
            )
        }),
        secret_store: StoreSelection::File,
        boot_identity: kr_ipc::identity::boot_identity().expect("a boot identity"),
        supervisor: Box::new(SilentSupervisor),
        worker_program: std::path::PathBuf::from("/nonexistent/kr-worker"),
        build_id: BuildId::new("kr-test/0").expect("a build identifier"),
        release: "0".to_owned(),
    })
    .await
    .expect("the daemon starts");
    (temp, controller)
}

#[tokio::test]
async fn a_local_revocation_advances_the_revision_and_answers_through_the_barrier() {
    let (_temp, controller) = daemon().await;
    let before = controller.policy().authority_revision();

    let held = grant(
        1,
        None,
        &[ActionRight::SessionView, ActionRight::TerminalInput],
        GrantExpiry::Never,
    );
    controller
        .sharing()
        .grants()
        .issue(&record(held.clone()))
        .expect("the grant is written");

    let result = tokio::time::timeout(
        Duration::from_secs(20),
        controller.revoke_grant(held.grant_id),
    )
    .await
    .expect("the revocation completes")
    .expect("it succeeds");

    assert!(
        result.authority_revision.get() > before.get(),
        "a local revocation advances the authority revision"
    );
    assert!(result.revoked_grants.contains(&held.grant_id));
    assert_eq!(
        result.barrier.authority_revision, result.authority_revision,
        "the barrier reports the revision the revocation advanced to"
    );
    // This daemon has no workers, so there is nothing for the barrier to be pending on. What this
    // establishes is the daemon's half: the revision moved, the answer carries the per-worker
    // report rather than only the revision, and the policy every later request is decided against
    // moved with it. The worker half — a paused worker reporting `pending`, and what its fence
    // rejected — is `crates/kr-controller/tests/barrier.rs`, against a real worker.
    assert!(result.barrier.workers.is_empty());
    assert_eq!(
        controller.policy().authority_revision(),
        result.authority_revision,
    );

    // The grant decides nothing afterwards.
    let stored = controller
        .sharing()
        .grants()
        .record(held.grant_id)
        .expect("readable")
        .expect("present");
    assert_eq!(
        decide(
            &held,
            &stored,
            &mut HostPolicy::personal(before),
            request(Method::SessionRead, 1_000)
        ),
        Err(Refusal::Revoked {
            grant_id: held.grant_id
        })
    );

    // And the revision survives a restart of the policy, because it was written down.
    let restored = HostPolicy::restore(
        &controller
            .sharing()
            .grants()
            .stored_policy()
            .expect("readable")
            .expect("present"),
        before,
    );
    assert_eq!(restored.accepted_floor(), result.authority_revision);
}

/// Revoking the same grant twice withdraws nothing the second time, and fences nothing.
#[tokio::test]
async fn a_repeated_revocation_withdraws_nothing_and_advances_nothing() {
    let (_temp, controller) = daemon().await;
    let held = grant(1, None, &[ActionRight::SessionView], GrantExpiry::Never);
    controller
        .sharing()
        .grants()
        .issue(&record(held.clone()))
        .expect("written");

    let first = tokio::time::timeout(
        Duration::from_secs(20),
        controller.revoke_grant(held.grant_id),
    )
    .await
    .expect("completes")
    .expect("succeeds");
    assert!(!first.revoked_grants.is_empty());

    let second = tokio::time::timeout(
        Duration::from_secs(20),
        controller.revoke_grant(held.grant_id),
    )
    .await
    .expect("completes")
    .expect("succeeds");
    assert!(
        second.revoked_grants.is_empty(),
        "the second call withdrew nothing"
    );
    assert_eq!(
        second.authority_revision, first.authority_revision,
        "so it advanced no revision, and fenced nobody"
    );

    // The record of the first revocation is untouched: its moment and its ancestor stand.
    let stored = controller
        .sharing()
        .grants()
        .record(held.grant_id)
        .expect("readable")
        .expect("present");
    assert!(stored.revoked_at_ms.is_some());
}

#[tokio::test]
async fn a_device_revocation_takes_every_grant_that_device_held() {
    let (_temp, controller) = daemon().await;
    let recipient = device_id(0xf1);

    let first = grant(1, None, &[ActionRight::SessionView], GrantExpiry::Never);
    let second = grant(2, None, &[ActionRight::FilesRead], GrantExpiry::Never);
    let delegated = Grant {
        grant_id: grant_id(3),
        parent_grant_id: Nullable::some(first.grant_id),
        recipient_device_id: device_id(0xf2),
        ..first.clone()
    };
    for held in [&first, &second, &delegated] {
        controller
            .sharing()
            .grants()
            .issue(&record(held.clone()))
            .expect("written");
    }

    let result = tokio::time::timeout(
        Duration::from_secs(20),
        controller.revoke_device_authority(recipient),
    )
    .await
    .expect("the revocation completes")
    .expect("it succeeds");

    assert!(result.revoked_grants.contains(&first.grant_id));
    assert!(result.revoked_grants.contains(&second.grant_id));
    assert!(
        result.revoked_grants.contains(&delegated.grant_id),
        "a grant delegated from a revoked device's grant goes with it, wherever it landed"
    );
    assert_eq!(
        result.barrier.authority_revision, result.authority_revision,
        "the device method group completes through the dispatch barrier"
    );

    // A second revocation of the same device withdraws nothing and advances nothing.
    let again = tokio::time::timeout(
        Duration::from_secs(20),
        controller.revoke_device_authority(recipient),
    )
    .await
    .expect("completes")
    .expect("succeeds");
    assert!(again.revoked_grants.is_empty());
    assert_eq!(again.authority_revision, result.authority_revision);
}

/// A grant written while a revocation is reading its subtree does not escape the cascade.
#[test]
fn a_child_cannot_be_written_while_its_parent_is_being_revoked() {
    use std::sync::Arc;

    let directory = Arc::new(GrantDirectory::in_memory().expect("a grant store"));
    let parent = grant(
        1,
        None,
        &[ActionRight::SessionView, ActionRight::FilesRead],
        GrantExpiry::Never,
    );
    directory
        .issue(&record(parent.clone()))
        .expect("the parent");

    // Two threads: one revoking the parent, one delegating from it. Whichever order the store
    // settles them in, the outcome has to be consistent — either the child was written and the
    // cascade took it, or the child was refused because its parent had gone.
    let child = Grant {
        grant_id: grant_id(2),
        parent_grant_id: Nullable::some(parent.grant_id),
        actions: [ActionRight::SessionView].into_iter().collect(),
        ..parent.clone()
    };
    let revoking = {
        let directory = Arc::clone(&directory);
        let parent_id = parent.grant_id;
        std::thread::spawn(move || directory.revoke(parent_id, 4_000))
    };
    let issuing = {
        let directory = Arc::clone(&directory);
        let child = child.clone();
        std::thread::spawn(move || directory.issue(&record(child)))
    };
    let revocation = revoking.join().expect("the revoking thread finishes");
    let issued = issuing.join().expect("the issuing thread finishes");
    revocation.expect("the revocation succeeds");

    match directory.record(child.grant_id).expect("readable") {
        Some(written) => {
            assert!(
                issued.is_ok(),
                "a child that is in the store was written successfully"
            );
            assert!(
                written.revoked_at_ms.is_some(),
                "a child written before the cascade ran is revoked with its parent"
            );
        }
        None => assert!(
            issued.is_err(),
            "a child that is not in the store was refused"
        ),
    }
}
