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

fn record(grant: Grant) -> GrantRecord {
    GrantRecord {
        session_id: Some(session_id(0xa0)),
        grant,
        issued_at_ms: 1_000,
        revoked_at_ms: None,
        revoked_by_parent: None,
    }
}

fn request(method: Method, now_ms: u64) -> AccessRequest {
    AccessRequest {
        method,
        ingress: ActorIngress::PairedDevice,
        environment_id: environment_id(0xe0),
        session_id: Some(session_id(0xa0)),
        claims_geometry: false,
        own_subject: None,
        now_ms,
    }
}

fn lease(
    organisation_id: OrganisationId,
    key_revision: PolicyKeyRevision,
    expires_at_ms: u64,
    maximum: &[ActionRight],
) -> MembershipLease {
    MembershipLease {
        payload: MembershipLeasePayload {
            organisation_id,
            account_id: AccountId::new("3c9f2b7a-5d18-4a62-9c07-1f5b8e2d4a90")
                .expect("an account identifier"),
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
    policy.enrol(organisation_id, key_revision, false);
    // The organisation's maximum for this role does not include terminal input.
    policy.install_lease(lease(
        organisation_id,
        key_revision,
        10_000,
        &[ActionRight::SessionView],
    ));

    // The same grant, decided twice: once on its own, once against the organisation's maximum.
    let permitted = decide(
        &held,
        &stored,
        &HostPolicy::personal(AuthorityRevision::new(1)),
        request(Method::InputWrite, 5_000),
    )
    .expect("the personal grant carries terminal input");
    assert!(permitted.rights.contains(&ActionRight::TerminalInput));

    let refused = decide(
        &organisation_grant,
        &record(organisation_grant.clone()),
        &policy,
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
        &HostPolicy::personal(AuthorityRevision::new(1)),
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
        &HostPolicy::personal(AuthorityRevision::new(1)),
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
    let policy = HostPolicy::personal(AuthorityRevision::new(1));

    // A year later, with no feed anywhere, it still decides: independent operation does not depend
    // on a cloud lease.
    let far = 365 * 24 * 60 * 60 * 1000;
    let held = directory
        .record(owner.grant_id)
        .expect("read")
        .expect("present");
    decide(&owner, &held, &policy, request(Method::SessionRead, far))
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
            &policy,
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
    let default = HostPolicy::personal(AuthorityRevision::new(1));
    assert!(default.offline_validity().is_none());
    decide(
        &owner,
        &stored,
        &default,
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
        &bounded,
        request(Method::SessionRead, 150_000),
    )
    .expect("inside the bound");
    assert_eq!(
        decide(
            &owner,
            &stored,
            &bounded,
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
    let policy = HostPolicy::personal(AuthorityRevision::new(1));

    decide(
        &controller,
        &stored,
        &policy,
        request(Method::SessionRead, 4_999),
    )
    .expect("valid up to the deadline");

    // The read, which a downgrade would have kept serving.
    assert_eq!(
        decide(
            &controller,
            &stored,
            &policy,
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
            &policy,
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
    policy.enrol(organisation_id, key_revision, false);
    policy.install_lease(lease(
        organisation_id,
        key_revision,
        10_000,
        &[ActionRight::SessionView, ActionRight::TerminalInput],
    ));

    // Nothing about the transport changes between these two. Only the clock does.
    decide(&held, &stored, &policy, request(Method::SessionRead, 9_999)).expect("inside the lease");
    assert_eq!(
        decide(
            &held,
            &stored,
            &policy,
            request(Method::SessionRead, 10_000)
        ),
        Err(Refusal::MembershipUnusable {
            refusal: MembershipRefusal::LeaseExpired
        }),
        "a connected transport does not extend a lease"
    );
    assert_eq!(
        decide(&held, &stored, &policy, request(Method::InputWrite, 10_000)),
        Err(Refusal::MembershipUnusable {
            refusal: MembershipRefusal::LeaseExpired
        }),
        "reads and mutations alike"
    );

    // A lease signed under a policy-signing revision this host has not pinned is refused whatever
    // the clock says.
    let mut mismatched = HostPolicy::personal(AuthorityRevision::new(1));
    mismatched.enrol(organisation_id, key_revision, false);
    mismatched.install_lease(lease(
        organisation_id,
        PolicyKeyRevision::new(5),
        10_000,
        &[ActionRight::SessionView],
    ));
    assert_eq!(
        decide(
            &held,
            &stored,
            &mismatched,
            request(Method::SessionRead, 1_000)
        ),
        Err(Refusal::MembershipUnusable {
            refusal: MembershipRefusal::WrongAuthority
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
    ordinary.enrol(organisation_id, key_revision, false);
    ordinary.install_lease(lease(
        organisation_id,
        key_revision,
        10_000,
        &[ActionRight::SessionView],
    ));
    decide(
        &personal,
        &stored,
        &ordinary,
        request(Method::SessionRead, 900_000),
    )
    .expect("a personal grant is untouched by an organisation outage");

    let mut exclusive = HostPolicy::personal(AuthorityRevision::new(1));
    exclusive.enrol(organisation_id, key_revision, true);
    exclusive.install_lease(lease(
        organisation_id,
        key_revision,
        10_000,
        &[ActionRight::SessionView],
    ));
    assert!(exclusive.is_exclusively_managed());
    assert_eq!(
        decide(
            &personal,
            &stored,
            &exclusive,
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

    decide(&held, &stored, &policy, request(Method::SessionRead, 1_000))
        .expect("valid before the machine sleeps");

    // The machine sleeps through the deadline. Waking is where expiry is decided again, and the
    // clock is what decides it: nothing is carried over from before the gap.
    policy.revalidate(900_000);
    assert_eq!(policy.revalidated_at_ms(), 900_000);
    assert_eq!(
        decide(
            &held,
            &stored,
            &policy,
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

    // A grant issued under a revision this host has replaced decides nothing, which is what stops
    // a restored grant from coming back with a restored policy.
    let stale = Grant {
        authority_revision: AuthorityRevision::new(2),
        expiry: GrantExpiry::Never,
        ..held
    };
    assert_eq!(
        decide(
            &stale,
            &record(stale.clone()),
            &policy,
            request(Method::SessionRead, 1_000)
        ),
        Err(Refusal::StaleAuthority {
            grant_revision: AuthorityRevision::new(2),
            current_revision: AuthorityRevision::new(8)
        })
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

    // The request carries no revision at all. The host numbers it, and the number follows its own.
    let issued = feed
        .apply(published(1), 2_000)
        .expect("the host issues one");
    assert_eq!(issued, AuthorityRevision::new(4));
    assert_eq!(feed.accepted_revision(), AuthorityRevision::new(4));

    // A republished request is the same revocation, not a second one.
    assert_eq!(feed.apply(published(1), 2_100).expect("idempotent"), issued);
    assert_eq!(feed.accepted_revision(), AuthorityRevision::new(4));

    // A request addressed to another host is refused.
    let elsewhere = RevocationRequest {
        host_device_id: device_id(0xee),
        ..published(2)
    };
    assert_eq!(feed.apply(elsewhere, 2_200), Err(FeedRefusal::AnotherHost));

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
    assert!(feed.retained().is_empty());

    // Reconnecting owes a synchronisation again, and an unreachable feed is stale rather than
    // silently current.
    feed.synchronised(3_000);
    assert!(!feed.synchronisation_owed());
    assert!(!feed.status().stale);
    assert_eq!(feed.next_poll_due_ms(), Some(33_000));
    feed.unreachable();
    assert!(feed.status().stale);
    feed.reconnected();
    assert!(feed.synchronisation_owed());
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
async fn a_local_revocation_advances_the_revision_fences_the_leases_and_reports_per_worker() {
    let (_temp, controller) = daemon().await;
    let before = controller.policy().authority_revision();

    let recipient = device_id(0xf1);
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
    let _ = recipient;

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
    // This daemon has no workers, so the barrier is complete with nothing pending. What matters is
    // that the answer carries the per-worker report rather than only the revision.
    assert!(result.barrier.workers.is_empty());
    assert_eq!(
        controller.policy().authority_revision(),
        result.authority_revision,
        "the policy every later request intersects against moved with it"
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
            &HostPolicy::personal(before),
            request(Method::SessionRead, 1_000)
        ),
        Err(Refusal::Revoked {
            grant_id: held.grant_id
        })
    );
}

#[tokio::test]
async fn a_device_revocation_takes_every_grant_that_device_held() {
    let (_temp, controller) = daemon().await;
    let recipient = device_id(0xf1);

    let first = grant(1, None, &[ActionRight::SessionView], GrantExpiry::Never);
    let second = Grant {
        grant_id: grant_id(2),
        ..grant(2, None, &[ActionRight::FilesRead], GrantExpiry::Never)
    };
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
}
