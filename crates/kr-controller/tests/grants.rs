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
//! | KR-REQ-09.08 | `a_device_revocation_is_performed_once_however_long_its_first_attempt_waits`, `a_retry_while_a_device_revocation_runs_is_told_it_has_not_finished`, `a_share_whose_record_was_never_written_is_answered_from_what_it_wrote_after_a_restart`, `a_revocation_whose_record_was_never_written_is_answered_from_the_rows_after_a_restart`, `an_authority_change_whose_attempt_ended_unrecorded_is_not_performed_again`, `a_refused_authority_change_is_refused_the_same_way_when_it_is_sent_again`, `an_unfinished_key_registration_is_not_answered_with_another_actions_registration`, `an_unfinished_revocation_pays_the_fence_it_still_owes_before_it_is_answered`, `an_unfinished_revocation_of_a_grant_still_standing_is_unknown`, `an_unfinished_device_revocation_is_answered_only_once_the_device_record_is_revoked`, `a_revocation_answered_from_the_rows_names_only_what_it_withdrew`, `a_device_revocation_answered_from_the_rows_names_only_what_it_withdrew`, `an_unfinished_device_revocation_is_not_answered_while_the_device_holds_live_grants`, `a_device_revocation_on_a_floor_ahead_of_the_clock_names_only_what_it_withdrew`, `a_withdrawal_larger_than_one_message_is_read_back_and_its_fence_settled`, `an_unfinished_destination_credential_is_unknown`, `a_claim_excludes_every_other_attempt_and_is_never_taken_over`, `a_claimed_revocation_writes_what_it_withdrew_beside_its_claim`, `an_earlier_receipts_table_migrates_once_and_its_open_claims_are_unfinished` |
//! | KR-REQ-09.18 | `a_decision_that_reads_the_clock_waits_for_the_floor_whatever_the_grants_expiry`, `a_delegation_is_not_refused_as_expired_on_a_reading_this_host_could_not_write`, `a_paired_device_refused_while_the_floor_is_owed_is_told_storage_is_unavailable` |
//! | KR-REQ-10.40 | `a_grant_carries_every_field_section_ten_names`, `the_host_intersects_the_grant_with_policy_on_every_request`, `a_delegation_narrows_and_never_extends`, `revoking_a_parent_revokes_every_descendant` |
//! | KR-REQ-10.41 | `a_method_is_decided_from_the_registry_table_and_never_from_a_capability` |
//! | KR-REQ-10.43 | `an_owner_grant_stays_valid_until_it_is_revoked`, `an_invitation_is_view_only_for_an_hour_and_bounded_at_thirty_days` |
//! | KR-REQ-10.44 | `the_offline_validity_policy_is_optional_and_bounded_when_it_is_chosen`, `an_expired_grant_is_refused_rather_than_downgraded_to_view_only` |
//! | KR-REQ-10.45 | `a_local_revocation_advances_the_revision_fences_the_leases_and_reports_per_worker` |
//! | KR-REQ-17.54 | `an_expired_membership_blocks_organisation_mediated_work_on_a_live_transport`, `personal_access_survives_an_organisation_outage_unless_the_host_is_exclusively_managed` |
//! | KR-REQ-19.02 | `a_delegation_cannot_grant_a_right_the_delegating_actor_lacks` |
//! | KR-REQ-23.27 | `a_local_revocation_advances_the_revision_fences_the_leases_and_reports_per_worker`, `a_device_revocation_takes_every_grant_that_device_held` |
//! | KR-REQ-23.32 | `a_question_is_read_with_view_and_answered_only_with_the_respond_right` |
//! | KR-REQ-23.53 | `a_composite_method_needs_every_right_its_entry_lists` |
//! | KR-REQ-24.15 | `expiry_is_revalidated_after_a_wake_and_a_restored_old_policy_cannot_revive_authority` |

use std::sync::Arc;

use kr_controller::grants::policy::UtcFloor;
use std::time::Duration;

mod net_support;
mod organisation_support;

use kr_controller::grants::organisation::LeasePresentation;
use kr_controller::grants::{
    AccessRequest, AuthorityFeed, FeedRefusal, GrantDirectory, GrantRecord, HostPolicy, Refusal,
    decide, rights_for, unconditional_rights_for,
};
use kr_controller::service::{Controller, ControllerSetup};
use kr_controller::supervision::{LaunchOutcome, WorkerLaunch, WorkerSupervisor};
use kr_crypto::store::{StoreSelection, open_store_in};
use kr_ipc::verify::ControllerIdentity;
use kr_protocol::account::MembershipLease;
use kr_protocol::actor::ActorIngress;
use kr_protocol::authority::{CapabilityRequirement, EffectClass};
use kr_protocol::grant::{
    EnvironmentSelector, Grant, GrantExpiry, HistoryScope, OrganisationRequirement, SessionSelector,
};
use kr_protocol::ids::{
    AccountId, AuthorityRevision, BuildId, DeviceId, EnvironmentId, GrantId, OrganisationId,
    RevocationRequestId, SessionId,
};
use kr_protocol::method::{Method, lookup};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{CanonicalSet, Nullable, Signature64, TimestampMs, Uuid};
use kr_protocol::sharing::{MembershipRefusal, OfflineValidityPolicy};
use kr_transport::clock::{ContinuousClock as _, ManualClock};

use organisation_support::{Organisation, T, presented};

const DAY_MS: u64 = 24 * 60 * 60 * 1000;
const VIEW: &[ActionRight] = &[ActionRight::SessionView];

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

/// A withdrawal whose admission lapses while the store is waited for withdraws nothing.
///
/// The check a caller hands in runs inside the transaction, with the lock held, so what it decides
/// is what is true at the moment of the write rather than at the moment the request arrived.
#[test]
fn a_withdrawal_that_loses_its_admission_at_the_store_writes_nothing() {
    let directory = GrantDirectory::in_memory().expect("a grant store");
    let held = grant(1, None, &[ActionRight::SessionView], GrantExpiry::Never);
    let second = Grant {
        grant_id: grant_id(2),
        ..grant(2, None, &[ActionRight::FilesRead], GrantExpiry::Never)
    };
    directory
        .issue(&record(held.clone()), || Ok(()))
        .expect("written");
    directory
        .issue(&record(second.clone()), || Ok(()))
        .expect("written");

    let lapsed = || {
        Err(kr_controller::error::ControllerError::WindowExpired {
            detail: "the window shut while this waited for the store".to_owned(),
        })
    };

    let refused = directory
        .revoke(held.grant_id, 4_000, lapsed)
        .expect_err("a lapsed admission withdraws nothing");
    assert!(
        refused.to_string().contains("window"),
        "unexpected refusal: {refused}"
    );
    let stored = directory
        .record(held.grant_id)
        .expect("readable")
        .expect("present");
    assert!(
        stored.revoked_at_ms.is_none(),
        "the grant this would have withdrawn still stands"
    );
    assert!(
        directory.fence_owed().expect("readable").is_empty(),
        "and nothing is owed a fence, because nothing was withdrawn"
    );

    // The same of a device's whole set: the read happens, the withdrawal does not.
    let refused = directory
        .revoke_device(held.recipient_device_id, 4_100, lapsed, None)
        .expect_err("a lapsed admission withdraws nothing");
    assert!(
        refused.to_string().contains("window"),
        "unexpected refusal: {refused}"
    );
    for grant_id in [held.grant_id, second.grant_id] {
        assert!(
            directory
                .record(grant_id)
                .expect("readable")
                .expect("present")
                .revoked_at_ms
                .is_none(),
            "every grant that device holds still stands"
        );
    }

    // The check runs after the read, not before it: a revocation that names a grant this host does
    // not hold is refused by the read, and the check is never reached. Reading a subtree walks
    // every grant the host holds, so a check that ran before it would be a check with a read still
    // to come.
    let missing = directory.revoke(grant_id(9), 4_150, || {
        panic!("the check runs once the rows to withdraw have been read");
    });
    assert!(
        missing
            .expect_err("no such grant")
            .to_string()
            .contains("no such grant")
    );

    // And with an admission that still stands, the same call withdraws.
    directory
        .revoke(held.grant_id, 4_200, || Ok(()))
        .expect("revoked");
}

/// Every restrictive change writes one debt of its own, under an identity no other change writes,
/// in the transaction that is its restriction, and it survives the failure of the barrier that
/// would retire it. A revocation and a device's revocation each write one row however many grants
/// they withdraw; a repeat that withdraws nothing, and a proposal nobody redeemed, write none; and
/// two changes of the same authority write two rows, so neither can absorb the other.
#[test]
fn a_revocation_writes_its_fence_debt_down_before_the_fence_is_attempted() {
    let directory = GrantDirectory::in_memory().expect("a grant store");
    let held = grant(1, None, &[ActionRight::SessionView], GrantExpiry::Never);
    directory
        .issue(&record(held.clone()), || Ok(()))
        .expect("written");
    let child = grant(
        3,
        Some(held.grant_id),
        &[ActionRight::SessionView],
        GrantExpiry::Never,
    );
    directory.issue(&record(child), || Ok(())).expect("written");

    assert!(
        directory.fence_owed().expect("readable").is_empty(),
        "nothing is owed before anything is revoked"
    );
    let first = directory
        .revoke(held.grant_id, 4_000, || Ok(()))
        .expect("revoked")
        .debt
        .expect("a live withdrawal owes a fence");
    assert_eq!(
        directory.fence_owed().expect("readable"),
        vec![first],
        "one row for the whole subtree, written in the same transaction as the revocation"
    );
    assert_eq!(
        directory
            .revoke(held.grant_id, 4_050, || Ok(()))
            .expect("a repeat")
            .debt,
        None,
        "a repeat withdraws nothing and owes nothing more"
    );

    // A second revocation arrives while the first fence is still waiting. It owes a debt of its
    // own, and clearing what the first fence covered must not retire it.
    let second = grant(2, None, &[ActionRight::SessionView], GrantExpiry::Never);
    directory
        .issue(&record(second.clone()), || Ok(()))
        .expect("written");
    let second_debt = directory
        .revoke(second.grant_id, 4_100, || Ok(()))
        .expect("revoked")
        .debt
        .expect("a live withdrawal owes a fence");
    assert_ne!(second_debt, first);
    directory
        .fence_completed(&[first])
        .expect("the first fence finished");
    assert_eq!(
        directory.fence_owed().expect("readable"),
        vec![second_debt],
        "a revocation that arrived during a fence still owes one of its own"
    );
    directory
        .fence_completed(&[second_debt])
        .expect("the second fence finished");
    assert!(directory.fence_owed().expect("readable").is_empty());

    // A device's revocation withdraws both of its live grants under one row; a proposal nobody
    // redeemed takes nothing away and owes nothing.
    for (byte, live) in [(4, true), (5, true), (6, false)] {
        let held = grant(byte, None, &[ActionRight::SessionView], GrantExpiry::Never);
        let stored = if live { record(held) } else { proposal(held) };
        directory.issue(&stored, || Ok(())).expect("written");
    }
    let device = directory
        .revoke_device(device_id(0xf1), 4_200, || Ok(()), None)
        .expect("revoked");
    assert_eq!(device.revoked.len(), 3);
    assert_eq!(
        directory.fence_owed().expect("readable"),
        vec![device.debt.expect("a live withdrawal owes a fence")]
    );
    directory
        .fence_completed(&directory.fence_owed().expect("readable"))
        .expect("finished");

    // Two changes of the same thing, each writing its own debt before its restriction, are two
    // rows under two identities.
    let one = directory.owe_fence("a change", 4_300).expect("written");
    let other = directory.owe_fence("a change", 4_300).expect("written");
    assert_ne!(one, other);
    let owed: std::collections::BTreeSet<_> = directory
        .fence_owed()
        .expect("readable")
        .into_iter()
        .collect();
    assert_eq!(owed, [one, other].into_iter().collect());
}

/// A store an earlier build wrote keyed its fence debt by what it withdrew. That debt is still
/// owed: it comes forward as one debt under the identity it had, which a barrier retires like any
/// other, and a second opening changes nothing.
#[test]
fn a_fence_debt_an_earlier_build_wrote_is_still_owed() {
    let directory = tempfile::tempdir().expect("a directory");
    let path = directory.path().join("grants.sqlite3");
    {
        let earlier = rusqlite::Connection::open(&path).expect("opens");
        earlier
            .execute_batch(
                "CREATE TABLE fence_debt (
                     grant_id       BLOB PRIMARY KEY NOT NULL,
                     recorded_at_ms INTEGER NOT NULL
                 );
                 INSERT INTO fence_debt (grant_id, recorded_at_ms)
                     VALUES (x'07070707070707070707070707070707', 1000);",
            )
            .expect("the earlier shape");
    }
    let store = GrantDirectory::open(&path).expect("the store opens and comes forward");
    let owed = store.fence_owed().expect("readable");
    assert_eq!(owed.len(), 1, "the earlier debt is still owed");
    drop(store);
    let store = GrantDirectory::open(&path).expect("a second opening");
    assert_eq!(store.fence_owed().expect("readable"), owed);
    store.fence_completed(&owed).expect("a barrier retires it");
    assert!(store.fence_owed().expect("readable").is_empty());
}

/// A claim excludes every other attempt, however long its own attempt runs, and an attempt that
/// ends without recording what it did leaves the action unfinished: no later attempt is given the
/// claim, however long after.
#[test]
fn a_claim_excludes_every_other_attempt_and_is_never_taken_over() {
    use kr_controller::grants::{ActionClaim, ActionRecord};
    use kr_protocol::error::ErrorCode;
    use kr_protocol::ids::ActionId;

    let directory = GrantDirectory::in_memory().expect("a grant store");
    let actor = kr_protocol::ids::ActorId::new("device:phone").expect("a principal");
    let action = ActionId::new(Uuid::from_bytes([5; 16]));
    let digest = kr_protocol::scalars::Digest256::from_bytes([7; 32]);
    let recorded = |action: ActionId, at_ms: u64| match directory
        .claim_action(&actor, action, &digest, at_ms)
        .expect("readable")
    {
        ActionClaim::Recorded(record) => record,
        ActionClaim::Claimed { .. } => panic!("a later attempt was given the claim"),
    };

    let ActionClaim::Claimed { hold } = directory
        .claim_action(&actor, action, &digest, 1_000)
        .expect("claimed")
    else {
        panic!("the first attempt claims the action");
    };
    assert_eq!(
        recorded(action, 1_001),
        ActionRecord::InFlight,
        "a second attempt under one action identifier does not reach the effect"
    );
    assert_eq!(
        recorded(
            action,
            1_000 + kr_protocol::limits::MAX_MUTATION_TTL.get() + 1
        ),
        ActionRecord::InFlight,
        "an attempt running for longer than any mutation is admitted for still holds its claim"
    );

    // A different payload under the same identifier is a conflict, not a second attempt.
    let other = kr_protocol::scalars::Digest256::from_bytes([8; 32]);
    directory
        .claim_action(&actor, action, &other, 1_002)
        .expect_err("a reused identifier with a different payload");

    // The first attempt ends without recording what it did. It is never performed again.
    drop(hold);
    assert_eq!(recorded(action, u64::MAX / 2), ActionRecord::Unfinished);
    assert_eq!(
        directory
            .recorded_action(&actor, action, &digest)
            .expect("readable"),
        Some(ActionRecord::Unfinished)
    );

    // An action whose attempt recorded its result is answered with it, and the first answer is
    // never replaced.
    let answered = ActionId::new(Uuid::from_bytes([6; 16]));
    let ActionClaim::Claimed { hold } = directory
        .claim_action(&actor, answered, &digest, 2_000)
        .expect("claimed")
    else {
        panic!("the first attempt claims the action");
    };
    directory
        .retain_result(&hold, b"first", 2_001)
        .expect("recorded");
    directory
        .retain_result(&hold, b"second", 2_002)
        .expect("a completed receipt is not replaced");
    directory
        .retain_refusal(&hold, ErrorCode::PermissionDenied, "later", 2_003)
        .expect("nor replaced by a refusal");
    drop(hold);
    assert_eq!(
        recorded(answered, 2_004),
        ActionRecord::Answered {
            result: b"first".to_vec()
        }
    );

    // A refusal the action was decided against is its answer from then on.
    let refused = ActionId::new(Uuid::from_bytes([7; 16]));
    let ActionClaim::Claimed { hold } = directory
        .claim_action(&actor, refused, &digest, 3_000)
        .expect("claimed")
    else {
        panic!("the first attempt claims the action");
    };
    directory
        .retain_refusal(
            &hold,
            ErrorCode::PermissionDenied,
            "the parent has been revoked",
            3_001,
        )
        .expect("recorded");
    drop(hold);
    assert_eq!(
        directory
            .recorded_action(&actor, refused, &digest)
            .expect("readable"),
        Some(ActionRecord::Refused {
            code: ErrorCode::PermissionDenied,
            detail: "the parent has been revoked".to_owned(),
        })
    );
}

/// A revocation an action performs writes what it withdrew beside the action's claim, in the
/// transaction that withdraws: all of it, or nothing when the withdrawal is refused, and once.
#[test]
fn a_claimed_revocation_writes_what_it_withdrew_beside_its_claim() {
    use kr_controller::grants::ActionClaim;
    use kr_protocol::ids::ActionId;

    let directory = GrantDirectory::in_memory().expect("a grant store");
    let actor = kr_protocol::ids::ActorId::new("local:501").expect("a principal");
    let digest = kr_protocol::scalars::Digest256::from_bytes([3; 32]);
    let claimed = |byte: u8| {
        let action = ActionId::new(Uuid::from_bytes([byte; 16]));
        match directory
            .claim_action(&actor, action, &digest, 1_000)
            .expect("claimed")
        {
            ActionClaim::Claimed { hold } => (action, hold),
            ActionClaim::Recorded(record) => panic!("already claimed: {record:?}"),
        }
    };
    let parent = grant(1, None, &[ActionRight::SessionView], GrantExpiry::Never);
    let child = Grant {
        grant_id: grant_id(2),
        parent_grant_id: Nullable::some(parent.grant_id),
        recipient_device_id: device_id(0xf2),
        ..parent.clone()
    };
    let other = Grant {
        recipient_device_id: device_id(0xf3),
        ..grant(3, None, &[ActionRight::SessionView], GrantExpiry::Never)
    };
    for held in [&parent, &child, &other] {
        directory
            .issue(&record(held.clone()), || Ok(()))
            .expect("written");
    }

    // A withdrawal refused inside its transaction writes neither the rows nor the record.
    let (refused, hold) = claimed(0x10);
    directory
        .revoke_claimed(
            parent.grant_id,
            4_000,
            || {
                Err(kr_controller::error::ControllerError::PermissionDenied {
                    detail: "the admission lapsed".to_owned(),
                })
            },
            Some(&hold),
        )
        .expect_err("refused");
    drop(hold);
    assert_eq!(
        directory
            .recorded_withdrawal(&actor, refused)
            .expect("readable"),
        Some(Vec::new()),
        "a claim no revocation committed under withdrew nothing"
    );

    let (revoked, hold) = claimed(0x11);
    directory
        .revoke_claimed(parent.grant_id, 4_100, || Ok(()), Some(&hold))
        .expect("withdrawn");
    // One claim, one withdrawal: a second under the same claim is refused, and withdraws nothing.
    directory
        .revoke_claimed(other.grant_id, 4_200, || Ok(()), Some(&hold))
        .expect_err("the claim already records a withdrawal");
    drop(hold);
    assert_eq!(
        directory
            .recorded_withdrawal(&actor, revoked)
            .expect("readable"),
        Some(vec![parent.grant_id, child.grant_id])
    );
    assert!(
        directory
            .record(other.grant_id)
            .expect("readable")
            .expect("present")
            .revoked_at_ms
            .is_none()
    );

    let (device, hold) = claimed(0x12);
    directory
        .revoke_device(device_id(0xf3), 4_300, || Ok(()), Some(&hold))
        .expect("withdrawn");
    drop(hold);
    assert_eq!(
        directory
            .recorded_withdrawal(&actor, device)
            .expect("readable"),
        Some(vec![other.grant_id])
    );
}

/// A receipts table an earlier build wrote, with the lease column that let a later attempt take
/// over an old claim, is brought to this build's shape once: the column goes, every row stays, and
/// a claim that had no result is unfinished rather than one a later attempt can take. What such a
/// claim's revocation withdrew was never kept, so it reads as not known, not as nothing.
#[test]
fn an_earlier_receipts_table_migrates_once_and_its_open_claims_are_unfinished() {
    use kr_controller::grants::{ActionClaim, ActionRecord};
    use kr_protocol::ids::ActionId;

    let directory_path = tempfile::TempDir::new().expect("a directory on the internal disk");
    let path = directory_path.path().join("registry.sqlite3");
    let actor = kr_protocol::ids::ActorId::new("local:501").expect("a principal");
    let digest = kr_protocol::scalars::Digest256::from_bytes([9; 32]);
    let answered = ActionId::new(Uuid::from_bytes([1; 16]));
    let open = ActionId::new(Uuid::from_bytes([2; 16]));
    {
        let earlier = rusqlite::Connection::open(&path).expect("opens the store");
        earlier
            .execute_batch(
                "CREATE TABLE authority_receipts (
                     actor_id       TEXT NOT NULL,
                     action_id      BLOB NOT NULL,
                     payload_digest BLOB NOT NULL,
                     claimed_at_ms  INTEGER NOT NULL,
                     leased_at_ms   INTEGER NOT NULL,
                     result         BLOB,
                     recorded_at_ms INTEGER,
                     PRIMARY KEY (actor_id, action_id)
                 );",
            )
            .expect("the earlier shape");
        for (action, result) in [(answered, Some(b"done".to_vec())), (open, None)] {
            earlier
                .execute(
                    "INSERT INTO authority_receipts VALUES (?1, ?2, ?3, 1000, 1000, ?4, NULL)",
                    rusqlite::params![
                        actor.as_str(),
                        action.get().as_bytes().as_slice(),
                        digest.as_bytes().as_slice(),
                        result,
                    ],
                )
                .expect("a row an earlier build wrote");
        }
    }

    for _ in 0..2 {
        let directory = GrantDirectory::open(&path).expect("the store opens");
        assert_eq!(
            directory
                .recorded_action(&actor, answered, &digest)
                .expect("readable"),
            Some(ActionRecord::Answered {
                result: b"done".to_vec()
            })
        );
        match directory
            .claim_action(&actor, open, &digest, u64::MAX / 2)
            .expect("readable")
        {
            ActionClaim::Recorded(record) => assert_eq!(record, ActionRecord::Unfinished),
            ActionClaim::Claimed { .. } => panic!("an earlier build's open claim was taken over"),
        }
        assert_eq!(
            directory
                .recorded_withdrawal(&actor, open)
                .expect("readable"),
            None,
            "an earlier build kept no record of what the claim's revocation withdrew"
        );
    }
    let columns: Vec<String> = rusqlite::Connection::open(&path)
        .expect("opens the store")
        .prepare("SELECT name FROM pragma_table_info('authority_receipts') ORDER BY cid")
        .expect("the columns")
        .query_map([], |row| row.get(0))
        .expect("the columns")
        .collect::<rusqlite::Result<Vec<String>>>()
        .expect("the columns");
    assert!(
        !columns.iter().any(|column| column == "leased_at_ms"),
        "{columns:?}"
    );
    assert!(
        columns.iter().any(|column| column == "refusal_code"),
        "{columns:?}"
    );
    assert!(
        columns.iter().any(|column| column == "withdrawn"),
        "{columns:?}"
    );
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
        now_ms,
        continuous_now: ManualClock::new().now(),
    }
}

/// An organisation whose second revision took over a day before `T`, enrolled in `policy` at `T`.
fn enrolled_organisation(policy: &mut HostPolicy, byte: u8) -> Organisation {
    let mut organisation = Organisation::new(byte, T - 2 * DAY_MS);
    organisation.rotate(T - DAY_MS);
    organisation.enrol(policy, T);
    organisation
}

/// A grant held by the recipient device that requires membership of `organisation_id` under the
/// enrolment revision `policy_revision`.
fn organisation_grant(
    organisation_id: OrganisationId,
    policy_revision: u64,
    rights: &[ActionRight],
) -> Grant {
    Grant {
        organisation: Nullable::some(OrganisationRequirement {
            organisation_id,
            policy_revision: AuthorityRevision::new(policy_revision),
        }),
        ..grant(1, None, rights, GrantExpiry::Never)
    }
}

/// Installs a fifteen-minute lease, issued at `issued_ms` by revision 2, for `account` on a key of
/// its own, presented by `device`, which it binds to that account and key.
fn install_lease_for(
    policy: &mut HostPolicy,
    organisation: &Organisation,
    device: DeviceId,
    account: &AccountId,
    issued_ms: u64,
    rights: &[ActionRight],
) -> MembershipLease {
    let key = organisation_support::device();
    let lease = organisation.lease(2, account, *key.public(), issued_ms, rights);
    policy
        .install_lease(LeasePresentation {
            device_id: device,
            ..presented(
                &lease,
                key.public(),
                issued_ms.max(T),
                ManualClock::new().now(),
                1,
            )
        })
        .expect("the lease is inside every rule section 17 states");
    lease
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
    directory
        .issue(&stored, || Ok(()))
        .expect("the grant is written");

    let mut policy = HostPolicy::personal(AuthorityRevision::new(1));
    let organisation = enrolled_organisation(&mut policy, 0x21);
    let organisation_grant = Grant {
        organisation: Nullable::some(OrganisationRequirement {
            organisation_id: organisation.organisation_id,
            policy_revision: AuthorityRevision::new(1),
        }),
        ..held.clone()
    };
    // The organisation's maximum for this member does not include terminal input.
    install_lease_for(
        &mut policy,
        &organisation,
        device_id(0xf1),
        &account(),
        T,
        &[ActionRight::SessionView],
    );

    // The same grant, decided twice: once on its own, once against the organisation's maximum.
    let permitted = decide(
        &held,
        &stored,
        &mut HostPolicy::personal(AuthorityRevision::new(1)),
        request(Method::InputWrite, T + 5_000),
    )
    .expect("the personal grant carries terminal input");
    assert!(permitted.rights.contains(&ActionRight::TerminalInput));

    let refused = decide(
        &organisation_grant,
        &record(organisation_grant.clone()),
        &mut policy,
        request(Method::InputWrite, T + 5_000),
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
        .issue(&record(parent.clone()), || Ok(()))
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
    directory
        .issue(&record(child), || Ok(()))
        .expect("a narrowing child");

    // Longer than its parent: refused.
    let outliving = Grant {
        grant_id: grant_id(3),
        parent_grant_id: Nullable::some(parent.grant_id),
        actions: [ActionRight::SessionView].into_iter().collect(),
        expiry: GrantExpiry::Never,
        ..parent.clone()
    };
    let error = directory
        .issue(&record(outliving), || Ok(()))
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
        .issue(&record(wider), || Ok(()))
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
        directory
            .issue(&record(held.clone()), || Ok(()))
            .expect("written");
    }

    let revocation = directory
        .revoke(root.grant_id, 4_000, || Ok(()))
        .expect("revoked");
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

/// KR-REQ-06.10: a capability is evidence and never permission. A decision takes no capability at
/// all: `input.write`, which asks for terminal-input capability evidence, is refused to a grant
/// without the terminal-input right, and `plugin.capabilities`, a read that asks for package
/// evidence and names no right, is refused outside the environments the grant's scope admits.
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

    // A read that asks for capability evidence is still a scoped read: inside the grant's
    // environments it is permitted, and outside them it is refused.
    assert!(matches!(
        lookup("plugin.capabilities").map(|entry| (entry.effect, entry.capability)),
        Some((EffectClass::Read, CapabilityRequirement::Required { .. }))
    ));
    let inside = AccessRequest {
        session_id: None,
        ..request(Method::PluginCapabilities, 5_000)
    };
    let mut policy = HostPolicy::personal(AuthorityRevision::new(1));
    assert!(
        decide(
            &viewer,
            &record(viewer.clone()),
            &mut policy,
            inside.clone()
        )
        .is_ok()
    );
    assert_eq!(
        decide(
            &viewer,
            &record(viewer.clone()),
            &mut policy,
            AccessRequest {
                environment_id: environment_id(0xe1),
                ..inside
            },
        ),
        Err(Refusal::EnvironmentOutsideGrant)
    );

    // Every right in the vocabulary is spelt the way the wire spells it, and resolves back.
    for right in ActionRight::ALL {
        assert_eq!(ActionRight::from_wire(right.as_str()), Some(*right));
    }
}

/// KR-REQ-23.33: the agent-tools methods need the host owner at the machine. The authority
/// decision refuses all three to a paired device whatever its grant holds, host management
/// included.
#[test]
fn a_paired_device_cannot_reach_the_agent_tools_whatever_its_grant_holds() {
    let everything = grant(1, None, ActionRight::ALL, GrantExpiry::Never);
    let mut policy = HostPolicy::personal(AuthorityRevision::new(1));
    for method in [
        Method::AgentToolsInstall,
        Method::AgentToolsStatus,
        Method::AgentToolsRemove,
    ] {
        assert!(
            matches!(
                decide(
                    &everything,
                    &record(everything.clone()),
                    &mut policy,
                    AccessRequest {
                        session_id: None,
                        ..request(method, 5_000)
                    },
                ),
                Err(Refusal::MethodNotReachable { .. })
            ),
            "{method:?} is reachable from a paired device"
        );
    }
}

/// KR-REQ-23.53: a composite method needs every right its entry lists. Holding one of two is
/// refused for the other, whichever one is missing, and only a grant holding both is permitted.
#[test]
fn a_composite_method_needs_every_right_its_entry_lists() {
    let method = Method::AgentDraftAddAttachment;
    let required = unconditional_rights_for(method);
    assert!(
        required.contains(&ActionRight::FilesUpload)
            && required.contains(&ActionRight::AgentPrompt),
        "the entry lists both rights: {required:?}"
    );
    let mut policy = HostPolicy::personal(AuthorityRevision::new(1));
    for (held, missing) in [
        (ActionRight::FilesUpload, ActionRight::AgentPrompt),
        (ActionRight::AgentPrompt, ActionRight::FilesUpload),
    ] {
        let partial = grant(
            1,
            None,
            &[ActionRight::SessionView, held],
            GrantExpiry::Never,
        );
        assert_eq!(
            decide(
                &partial,
                &record(partial.clone()),
                &mut policy,
                request(method, 5_000)
            ),
            Err(Refusal::MissingRight { right: missing }),
            "holding {held} alone"
        );
    }
    let both = grant(
        1,
        None,
        &[
            ActionRight::SessionView,
            ActionRight::FilesUpload,
            ActionRight::AgentPrompt,
        ],
        GrantExpiry::Never,
    );
    decide(
        &both,
        &record(both.clone()),
        &mut policy,
        request(method, 5_000),
    )
    .expect("a grant holding every listed right");
}

/// KR-REQ-23.32: reading a question needs `session.view`; answering or cancelling one needs
/// `question.respond`, which viewing does not carry, and the respond right alone reads nothing.
#[test]
fn a_question_is_read_with_view_and_answered_only_with_the_respond_right() {
    let mut policy = HostPolicy::personal(AuthorityRevision::new(1));
    let viewer = grant(1, None, &[ActionRight::SessionView], GrantExpiry::Never);
    decide(
        &viewer,
        &record(viewer.clone()),
        &mut policy,
        request(Method::QuestionRead, 5_000),
    )
    .expect("a viewer reads the questions it may see");
    for method in [Method::QuestionAnswer, Method::QuestionCancel] {
        assert_eq!(
            decide(
                &viewer,
                &record(viewer.clone()),
                &mut policy,
                request(method, 5_000)
            ),
            Err(Refusal::MissingRight {
                right: ActionRight::QuestionRespond
            }),
            "viewing is not responding"
        );
    }

    let responder = grant(
        2,
        None,
        &[ActionRight::SessionView, ActionRight::QuestionRespond],
        GrantExpiry::Never,
    );
    for method in [Method::QuestionAnswer, Method::QuestionCancel] {
        decide(
            &responder,
            &record(responder.clone()),
            &mut policy,
            request(method, 5_000),
        )
        .expect("the respond right answers and cancels");
    }

    let respond_only = grant(3, None, &[ActionRight::QuestionRespond], GrantExpiry::Never);
    assert_eq!(
        decide(
            &respond_only,
            &record(respond_only.clone()),
            &mut policy,
            request(Method::QuestionRead, 5_000)
        ),
        Err(Refusal::MissingRight {
            right: ActionRight::SessionView
        })
    );
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
    directory
        .issue(&record(owner.clone()), || Ok(()))
        .expect("written");
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

    directory
        .revoke(owner.grant_id, far, || Ok(()))
        .expect("revoked");
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
    let mut policy = HostPolicy::personal(AuthorityRevision::new(1));
    let organisation = enrolled_organisation(&mut policy, 0x21);
    let held = organisation_grant(
        organisation.organisation_id,
        1,
        &[ActionRight::SessionView, ActionRight::TerminalInput],
    );
    let stored = record(held.clone());
    install_lease_for(
        &mut policy,
        &organisation,
        device_id(0xf1),
        &account(),
        T,
        &[ActionRight::SessionView, ActionRight::TerminalInput],
    );

    // Nothing about the transport changes between these two. Only the clock does.
    let ends = T + organisation_support::LEASE_MS;
    decide(
        &held,
        &stored,
        &mut policy,
        request(Method::SessionRead, ends - 1),
    )
    .expect("inside the lease");
    assert_eq!(
        decide(
            &held,
            &stored,
            &mut policy,
            request(Method::SessionRead, ends)
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
            request(Method::InputWrite, ends)
        ),
        Err(Refusal::MembershipUnusable {
            refusal: MembershipRefusal::LeaseExpired
        }),
        "reads and mutations alike"
    );

    // A lease signed by a revision this host has not authenticated is refused whatever the clock
    // says: revision 1 signed it while it was signing, but this host pinned revision 2.
    let mut other = HostPolicy::personal(AuthorityRevision::new(1));
    let second = enrolled_organisation(&mut other, 0x22);
    let device = organisation_support::device();
    let unauthenticated = second.lease(1, &account(), *device.public(), T - 2 * DAY_MS, VIEW);
    assert_eq!(
        other.install_lease(presented(
            &unauthenticated,
            device.public(),
            T,
            ManualClock::new().now(),
            1,
        )),
        Err(kr_controller::grants::LeaseRefused::UnauthenticatedRevision),
        "a lease by a revision this host has not authenticated is not installed at all"
    );
    // Because it was never installed, it bound nothing, and no lease answers for the grant's
    // device. That is the stronger outcome: a host does not hold a lease it could not have
    // accepted.
    let held = organisation_grant(second.organisation_id, 1, VIEW);
    assert_eq!(
        decide(
            &held,
            &record(held.clone()),
            &mut other,
            request(Method::SessionRead, T + 1_000)
        ),
        Err(Refusal::MembershipUnattributed)
    );
}

#[test]
fn personal_access_survives_an_organisation_outage_unless_the_host_is_exclusively_managed() {
    let personal = grant(
        1,
        None,
        &[ActionRight::SessionView, ActionRight::TerminalInput],
        GrantExpiry::Never,
    );
    let stored = record(personal.clone());
    let after_the_lease = T + organisation_support::LEASE_MS;

    let mut ordinary = HostPolicy::personal(AuthorityRevision::new(1));
    let organisation = enrolled_organisation(&mut ordinary, 0x21);
    install_lease_for(
        &mut ordinary,
        &organisation,
        device_id(0xf1),
        &account(),
        T,
        VIEW,
    );
    decide(
        &personal,
        &stored,
        &mut ordinary,
        request(Method::SessionRead, after_the_lease),
    )
    .expect("a personal grant is untouched by an organisation outage");

    let mut exclusive = HostPolicy::personal(AuthorityRevision::new(1));
    let organisation = enrolled_organisation(&mut exclusive, 0x21);
    exclusive.set_exclusively_managed(true);
    install_lease_for(
        &mut exclusive,
        &organisation,
        device_id(0xf1),
        &account(),
        T,
        VIEW,
    );
    assert!(exclusive.is_exclusively_managed());
    assert_eq!(
        decide(
            &personal,
            &stored,
            &mut exclusive,
            request(Method::SessionRead, after_the_lease)
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
    directory
        .issue(&record(viewer), || Ok(()))
        .expect("the parent");
    directory
        .issue(&record(asking_for_input), || Ok(()))
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

/// KR-REQ-09.18: a decision that reads this host's clock is not taken while the clock floor is owed
/// its record, whatever the grant's own expiry, and one that reads no clock is taken as before.
///
/// A grant that never expires reads the clock when this host bounds its use in time: remotely
/// under a bounded offline validity, or on a host enrolled as exclusively organisation-managed,
/// where a personal grant answers to a lease. Used from this machine, or with neither bound, it
/// reads no clock.
#[test]
fn a_decision_that_reads_the_clock_waits_for_the_floor_whatever_the_grants_expiry() {
    let lasting = grant(1, None, &[ActionRight::SessionView], GrantExpiry::Never);
    let stored = record(lasting.clone());
    let mut policy = HostPolicy::personal(AuthorityRevision::new(1));
    // A decision stood on the floor at 5,000 and its record has not been written.
    policy.utc_floor().owe(5_000);
    let local = || AccessRequest {
        ingress: ActorIngress::LocalIpc,
        ..request(Method::SessionRead, 1_000)
    };

    decide(
        &lasting,
        &stored,
        &mut policy,
        request(Method::SessionRead, 1_000),
    )
    .expect("a personal grant that never expires reads no clock");

    policy.set_offline_validity(Some(OfflineValidityPolicy {
        maximum_offline_ms: kr_protocol::scalars::DurationMs::new(60 * 60 * 1000),
        last_synchronised_at_ms: Nullable::some(TimestampMs::new(1_000)),
    }));
    assert_eq!(
        decide(
            &lasting,
            &stored,
            &mut policy,
            request(Method::SessionRead, 1_000)
        ),
        Err(Refusal::FloorUnrecorded),
        "remote use under an offline bound reads the clock"
    );
    decide(&lasting, &stored, &mut policy, local())
        .expect("the offline bound is about remote access");

    policy.set_offline_validity(None);
    policy.set_exclusively_managed(true);
    assert_eq!(
        decide(
            &lasting,
            &stored,
            &mut policy,
            request(Method::SessionRead, 1_000)
        ),
        Err(Refusal::FloorUnrecorded),
        "on an exclusively managed host a personal grant answers to a lease"
    );

    // Once the floor is written down, the decision is taken on its merits again.
    policy.utc_floor().wrote(5_000);
    assert_eq!(
        decide(
            &lasting,
            &stored,
            &mut policy,
            request(Method::SessionRead, 1_000)
        ),
        Err(Refusal::MembershipUnusable {
            refusal: MembershipRefusal::NoLease
        })
    );
}

/// KR-REQ-09.18: a paired device whose request reads the clock while this host's clock floor is
/// owed its record is refused with `STORAGE_UNAVAILABLE`: a transient failure of this host's store,
/// not a verdict on the device's authority, which the device may ask about again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_paired_device_refused_while_the_floor_is_owed_is_told_storage_is_unavailable() {
    let owner = kr_crypto::keys::DeviceKeys::generate().expect("owner keys");
    let host = net_support::Host::start(&owner).await;
    let device = net_support::Device::create().await;
    let paired = net_support::pair_with(
        &host,
        &device,
        &owner,
        net_support::proposal(&[ActionRight::SessionView]),
    )
    .await;
    let raw = net_support::RawDevice::connect(&host, &device, &paired).await;
    raw.claim();
    let listing = kr_protocol::session::SessionListParams {
        environment_id: Nullable::null(),
        include_closed: false,
    };
    raw.read(Method::SessionList, &listing)
        .await
        .expect("the device lists its sessions");

    // The owner bounds remote personal access in time, so the device's requests read the clock.
    host.controller()
        .update_policy(|policy| {
            policy.set_offline_validity(Some(OfflineValidityPolicy {
                maximum_offline_ms: kr_protocol::scalars::DurationMs::new(60 * 60 * 1000),
                last_synchronised_at_ms: Nullable::some(TimestampMs::new(kr_ipc::now_ms().get())),
            }));
        })
        .expect("the owner chooses an offline bound");
    raw.read(Method::SessionList, &listing)
        .await
        .expect("inside the bound");

    // The store refuses the policy, and a decision of the owner's stands on a floor it cannot write.
    let registry =
        rusqlite::Connection::open(host.registry_database()).expect("opens the registry");
    registry
        .busy_timeout(Duration::from_secs(5))
        .expect("waits for the daemon's writes");
    registry
        .execute_batch(
            "CREATE TRIGGER refuse_policy BEFORE INSERT ON host_authority
             WHEN NEW.key = 'policy'
             BEGIN SELECT RAISE(ABORT, 'no room'); END;",
        )
        .expect("the fault is in place");
    let mut client = host.client().await;
    client
        .request(
            Method::GrantList,
            &kr_protocol::sharing::GrantListParams {
                session_id: Nullable::null(),
                include_resolved: true,
            },
        )
        .await
        .expect("the daemon answers")
        .expect("the owner's listing is answered");

    let refusal = raw
        .read(Method::SessionList, &listing)
        .await
        .expect_err("a request that reads the clock waits for the floor's record");
    assert_eq!(
        refusal.code,
        kr_protocol::error::ErrorCode::StorageUnavailable,
        "{refusal:?}"
    );

    // The store recovers, and the owner's next decision writes the floor down.
    registry
        .execute_batch("DROP TRIGGER refuse_policy;")
        .expect("the fault is cleared");
    client
        .request(
            Method::GrantList,
            &kr_protocol::sharing::GrantListParams {
                session_id: Nullable::null(),
                include_resolved: true,
            },
        )
        .await
        .expect("the daemon answers")
        .expect("the owner's listing is answered");
    raw.read(Method::SessionList, &listing)
        .await
        .expect("once the floor is written down, the request is decided on its merits");
    raw.close();
    host.stop().await;
}

/// The stored policy is what a host reads back, and a restored old policy cannot revive authority.
///
/// The store is the durable path a restart takes; this exercises that path rather than restarting
/// a `Controller`, which would need a daemon and a worker directory to say nothing more about the
/// policy than this does.
#[test]
fn a_stored_policy_is_read_back_with_its_restrictions_and_its_floors() {
    let directory = GrantDirectory::in_memory().expect("a grant store");

    let mut policy = HostPolicy::personal(AuthorityRevision::new(3));
    policy.set_exclusively_managed(true);
    let organisation = enrolled_organisation(&mut policy, 0x21);
    let organisation_id = organisation.organisation_id;
    install_lease_for(
        &mut policy,
        &organisation,
        device_id(0xf1),
        &account(),
        T,
        VIEW,
    );
    policy.set_offline_validity(Some(OfflineValidityPolicy {
        maximum_offline_ms: kr_protocol::scalars::DurationMs::new(60_000),
        last_synchronised_at_ms: Nullable::some(TimestampMs::new(100_000)),
    }));
    policy.observe_utc(T + 500_000);
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
    let mut restored = HostPolicy::restore(
        &stored,
        AuthorityRevision::new(3),
        Arc::new(UtcFloor::at(stored.utc_floor_ms.get())),
    );
    assert!(
        restored.is_exclusively_managed(),
        "a restart is not an amnesty"
    );
    assert!(restored.offline_validity().is_some());
    assert!(restored.enrolment(organisation_id).is_some());
    assert_eq!(restored.accepted_floor(), AuthorityRevision::new(9));
    assert_eq!(restored.utc_floor_ms(), T + 500_000);
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
            .installed_for(&account())
            .next()
            .is_none()
    );
}

/// One member's lease does not answer for another member.
#[test]
fn one_members_lease_does_not_sustain_another_members_access() {
    let mut policy = HostPolicy::personal(AuthorityRevision::new(1));
    let organisation = enrolled_organisation(&mut policy, 0x21);
    let held = organisation_grant(organisation.organisation_id, 1, VIEW);
    let stored = record(held.clone());
    // A lease for somebody else entirely, on that member's own device.
    let other = AccountId::new("8f14e45f-ea1e-4b9e-9f3a-0a3a9b0d2f61").expect("an account");
    install_lease_for(&mut policy, &organisation, device_id(0xf2), &other, T, VIEW);

    assert_eq!(
        decide(
            &held,
            &stored,
            &mut policy,
            request(Method::SessionRead, T + 1_000)
        ),
        Err(Refusal::MembershipUnattributed),
        "a valid member's lease does not answer for a device bound to nobody"
    );

    // With this recipient's own lease it decides. Once that lease has run out it stops again,
    // while the other member's lease still has time on it.
    install_lease_for(
        &mut policy,
        &organisation,
        device_id(0xf1),
        &account(),
        T - 5 * 60 * 1000,
        VIEW,
    );
    decide(
        &held,
        &stored,
        &mut policy,
        request(Method::SessionRead, T + 1_000),
    )
    .expect("this member's own lease answers");
    assert_eq!(
        decide(
            &held,
            &stored,
            &mut policy,
            request(Method::SessionRead, T + 12 * 60 * 1000)
        ),
        Err(Refusal::MembershipUnusable {
            refusal: MembershipRefusal::LeaseExpired
        })
    );

    // And a grant whose device is bound to nobody is refused rather than answered by a lease
    // this host happens to hold.
    let unbound = Grant {
        recipient_device_id: device_id(0xf3),
        ..held.clone()
    };
    assert_eq!(
        decide(
            &unbound,
            &record(unbound.clone()),
            &mut policy,
            request(Method::SessionRead, T + 1_000)
        ),
        Err(Refusal::MembershipUnattributed)
    );
}

/// A delegated organisation grant answers to its own recipient's binding and lease, never to its
/// parent recipient's. The control: once the child's recipient binds on its own lease, the child
/// answers.
#[test]
fn a_delegated_organisation_grant_needs_its_own_recipients_lease() {
    let mut policy = HostPolicy::personal(AuthorityRevision::new(1));
    let organisation = enrolled_organisation(&mut policy, 0x21);
    let parent = organisation_grant(organisation.organisation_id, 1, VIEW);
    let child = Grant {
        grant_id: grant_id(2),
        parent_grant_id: Nullable::some(parent.grant_id),
        issuer_device_id: parent.recipient_device_id,
        recipient_device_id: device_id(0xf4),
        ..parent.clone()
    };
    assert!(
        child.narrows(&parent),
        "it inherits its parent's requirement"
    );
    install_lease_for(
        &mut policy,
        &organisation,
        device_id(0xf1),
        &account(),
        T,
        VIEW,
    );
    decide(
        &parent,
        &record(parent.clone()),
        &mut policy,
        request(Method::SessionRead, T + 1_000),
    )
    .expect("the parent's recipient holds a live lease");
    assert_eq!(
        decide(
            &child,
            &record(child.clone()),
            &mut policy,
            request(Method::SessionRead, T + 1_000)
        ),
        Err(Refusal::MembershipUnattributed),
        "the parent recipient's lease does not answer for the child's recipient"
    );

    let delegate = AccountId::new("5b0e1c7d-2f4a-4c1e-8d3b-6a9f0e2c4b71").expect("an account");
    install_lease_for(
        &mut policy,
        &organisation,
        device_id(0xf4),
        &delegate,
        T,
        VIEW,
    );
    decide(
        &child,
        &record(child.clone()),
        &mut policy,
        request(Method::SessionRead, T + 1_000),
    )
    .expect("the child's recipient's own lease answers");
}

/// The lease that answers for an organisation grant is found through its recipient device's
/// binding, by a workflow's dispatch and by a push rule alike, neither of which has a presenting
/// connection. A live lease of the same member for another device's key answers nothing for this
/// device. The control: this device's own lease answers both.
#[test]
fn the_intersection_finds_the_lease_through_the_bindings_key() {
    use kr_delivery::producer::RecipientAuthority as _;

    const AT_MS: u64 = T + 6 * 60 * 1000;
    let clock = ManualClock::new();
    let sharing = Arc::new(
        kr_controller::sharing::SharingService::in_memory(device_id(0xf0)).expect("a grant store"),
    );
    let mut policy = HostPolicy::personal(AuthorityRevision::new(1));
    let organisation = enrolled_organisation(&mut policy, 0x21);
    let held = organisation_grant(organisation.organisation_id, 1, VIEW);
    let stored = record(held.clone());
    sharing
        .grants()
        .issue(&stored, || Ok(()))
        .expect("the grant is written");

    // This device binds on a lease that ends five minutes after `T`; the same member's other
    // device holds a lease for its own key that runs to fifteen.
    let (phone, laptop) = (
        organisation_support::device(),
        organisation_support::device(),
    );
    let ending = organisation.lease(2, &account(), *phone.public(), T - 10 * 60 * 1000, VIEW);
    policy
        .install_lease(LeasePresentation {
            device_id: device_id(0xf1),
            ..presented(&ending, phone.public(), T, clock.now(), 1)
        })
        .expect("this device's lease installs");
    let other = organisation.lease(2, &account(), *laptop.public(), T, VIEW);
    policy
        .install_lease(LeasePresentation {
            device_id: device_id(0xf5),
            ..presented(&other, laptop.public(), T, clock.now(), 1)
        })
        .expect("the other device's lease installs");

    let standing = |policy: &mut HostPolicy| {
        kr_controller::grants::standing_at_dispatch(
            &stored,
            policy,
            environment_id(0xe0),
            ActorIngress::PairedDevice,
            AT_MS,
            clock.now(),
        )
    };
    assert_eq!(
        standing(&mut policy).map(|intersection| intersection.rights),
        Err(Refusal::MembershipUnusable {
            refusal: MembershipRefusal::LeaseExpired
        }),
        "the member's other device's live lease answers nothing for this device"
    );
    let shared = Arc::new(std::sync::Mutex::new(policy.clone()));
    let recipients = kr_controller::push::authority::GrantedRecipients::at(
        Arc::clone(&sharing),
        Arc::clone(&shared),
        environment_id(0xe0),
        Arc::new(clock.clone()),
        || AT_MS,
    );
    let rule = kr_delivery::destination::DeliveryRule {
        name: "on a question".to_owned(),
        grant_id: Some(held.grant_id),
    };
    assert!(
        recipients.scope_for(&rule).is_none(),
        "nor for a push rule naming its grant"
    );

    // The control: this device's own renewal answers both.
    let renewed = organisation.lease(2, &account(), *phone.public(), AT_MS, VIEW);
    policy
        .install_lease(LeasePresentation {
            device_id: device_id(0xf1),
            ..presented(&renewed, phone.public(), AT_MS, clock.now(), 1)
        })
        .expect("the renewal installs");
    let answered = standing(&mut policy).expect("this device's own lease answers");
    assert_eq!(answered.rights, VIEW.iter().copied().collect());
    assert_eq!(
        answered.lease.map(|lease| lease.expires_at_ms),
        Some(AT_MS + organisation_support::LEASE_MS),
        "and the decision carries that lease's deadlines"
    );
    *shared.lock().expect("the policy") = policy.clone();
    assert!(recipients.scope_for(&rule).is_some(), "and a push rule's");
}

/// A grant answering to an enrolment revision this host did not record is refused.
#[test]
fn a_grant_naming_another_policy_revision_is_refused() {
    let mut policy = HostPolicy::personal(AuthorityRevision::new(1));
    let organisation = enrolled_organisation(&mut policy, 0x21);
    let held = organisation_grant(organisation.organisation_id, 3, VIEW);
    install_lease_for(
        &mut policy,
        &organisation,
        device_id(0xf1),
        &account(),
        T,
        VIEW,
    );
    assert_eq!(
        decide(
            &held,
            &record(held.clone()),
            &mut policy,
            request(Method::SessionRead, T + 1_000)
        ),
        Err(Refusal::MembershipUnusable {
            refusal: MembershipRefusal::WrongAuthority
        })
    );
    // The control: the grant naming the revision this host enrolled at decides.
    let current = organisation_grant(organisation.organisation_id, 1, VIEW);
    decide(
        &current,
        &record(current.clone()),
        &mut policy,
        request(Method::SessionRead, T + 1_000),
    )
    .expect("the enrolment's own revision answers");
}

/// Enrolling in a second organisation does not undo the exclusive-management restriction.
#[test]
fn a_second_enrolment_does_not_undo_exclusive_management() {
    let mut policy = HostPolicy::personal(AuthorityRevision::new(1));
    policy.set_exclusively_managed(true);
    enrolled_organisation(&mut policy, 0x21);
    enrolled_organisation(&mut policy, 0x22);
    assert!(policy.is_exclusively_managed());
}

/// A lease outside section 17's own rules is not installed at all: not for an organisation this
/// host is not enrolled in, not longer than fifteen minutes, not above its role's ceiling.
#[test]
fn a_lease_outside_its_own_rules_is_refused_before_it_is_stored() {
    use kr_controller::grants::LeaseRefused;

    let mut policy = HostPolicy::personal(AuthorityRevision::new(1));
    let device = organisation_support::device();
    let now = ManualClock::new().now();
    let mut elsewhere = Organisation::new(0x22, T - DAY_MS);
    elsewhere.rotate(T - 60_000);
    let unenrolled = elsewhere.lease(2, &account(), *device.public(), T, VIEW);
    assert_eq!(
        policy.install_lease(presented(&unenrolled, device.public(), T, now, 1)),
        Err(LeaseRefused::NotEnrolled)
    );

    let organisation = enrolled_organisation(&mut policy, 0x21);
    assert_eq!(
        policy.install_lease(presented(&unenrolled, device.public(), T, now, 1)),
        Err(LeaseRefused::NotEnrolled),
        "another organisation's lease, while this host is enrolled in one"
    );
    // Longer than the fifteen minutes section 17 permits.
    let long = organisation.sign(
        2,
        organisation.payload(
            2,
            &account(),
            *device.public(),
            T,
            HostPolicy::maximum_lease_lifetime_ms() + 1,
            VIEW,
        ),
    );
    assert_eq!(
        policy.install_lease(presented(&long, device.public(), T, now, 1)),
        Err(LeaseRefused::TooLong)
    );
    // More than the role's own ceiling.
    let wide = organisation.lease(2, &account(), *device.public(), T, ActionRight::ALL);
    assert_eq!(
        policy.install_lease(presented(&wide, device.public(), T, now, 1)),
        Err(LeaseRefused::AboveRoleCeiling)
    );
    assert!(
        policy
            .lease_record(organisation.organisation_id, &account(), device.public())
            .is_none(),
        "nothing refused is recorded"
    );

    // The control: the conforming lease installs.
    let conforming = organisation.lease(2, &account(), *device.public(), T, VIEW);
    policy
        .install_lease(presented(&conforming, device.public(), T, now, 1))
        .expect("the conforming lease installs");
}

/// KR-REQ-17.53: a host that pinned an organisation's policy-signing authority installs only a
/// lease that authority signed. A lease that names an authenticated revision and is inside every
/// other rule, but whose signature that revision's key did not make, is refused before it is
/// stored; the same payload signed by that key installs.
#[test]
fn a_lease_the_pinned_policy_signing_authority_did_not_sign_is_refused() {
    use kr_controller::grants::LeaseRefused;

    let mut policy = HostPolicy::personal(AuthorityRevision::new(1));
    let organisation = enrolled_organisation(&mut policy, 0x21);
    let device = organisation_support::device();
    let now = ManualClock::new().now();
    let signed = organisation.lease(2, &account(), *device.public(), T, VIEW);

    let mut unsigned = signed.clone();
    unsigned.signature = Signature64::from_bytes([0; 64]);
    assert_eq!(
        policy.install_lease(presented(&unsigned, device.public(), T, now, 1)),
        Err(LeaseRefused::BadSignature),
        "a lease the pinned policy-signing authority did not sign is refused"
    );
    let forged = MembershipLease {
        signature: organisation_support::sign(
            &organisation_support::device(),
            kr_protocol::account::MEMBERSHIP_LEASE_DOMAIN,
            signed.payload.signing_input(),
        ),
        ..signed.clone()
    };
    assert_eq!(
        policy.install_lease(presented(&forged, device.public(), T, now, 1)),
        Err(LeaseRefused::BadSignature),
        "nor one another key signed over the same payload"
    );
    assert!(
        policy
            .lease_record(organisation.organisation_id, &account(), device.public())
            .is_none(),
        "nothing is recorded"
    );

    // The control: the same payload signed by the pinned revision's key installs.
    policy
        .install_lease(presented(&signed, device.public(), T, now, 1))
        .expect("the pinned authority's own signature installs");
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

    fn describe(&self) -> &'static str {
        "a supervisor that starts nothing"
    }
}

async fn daemon() -> (kr_ipc::testing::TempHost, Arc<Controller>) {
    let temp = kr_ipc::testing::TempHost::create();
    let controller = start_daemon(&temp).await;
    (temp, controller)
}

/// Starts a daemon over an environment tree that may already hold another daemon's records.
async fn start_daemon(temp: &kr_ipc::testing::TempHost) -> Arc<Controller> {
    let environment = temp.environment();
    let environment_id = temp.environment_id();
    let secrets = environment.secrets_dir();
    Controller::start(ControllerSetup {
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
        shell_packages: None,
        terminal: Box::new(kr_controller::supervision::NoTerminal),
    })
    .await
    .expect("the daemon starts")
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
        .issue(&record(held.clone()), || Ok(()))
        .expect("the grant is written");

    let result = tokio::time::timeout(
        Duration::from_secs(20),
        controller.revoke_grant(held.grant_id, None, None),
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
    let stored = controller
        .sharing()
        .grants()
        .stored_policy()
        .expect("readable")
        .expect("present");
    let restored = HostPolicy::restore(
        &stored,
        before,
        Arc::new(UtcFloor::at(stored.utc_floor_ms.get())),
    );
    assert_eq!(restored.accepted_floor(), result.authority_revision);
}

/// An authority change carrying an admission that no longer stands withdraws nothing.
#[tokio::test]
async fn a_revocation_whose_admission_no_longer_stands_withdraws_nothing() {
    let (_temp, controller) = daemon().await;
    let held = grant(1, None, &[ActionRight::SessionView], GrantExpiry::Never);
    controller
        .sharing()
        .grants()
        .issue(&record(held.clone()), || Ok(()))
        .expect("written");

    // An admission from a connection this daemon holds no registration for. Whatever the clock
    // says, it stands for nothing, and the withdrawal it was carrying does not happen.
    let lapsed = kr_controller::authority::AdmittedMutation {
        connection_id: kr_protocol::ids::ConnectionId::new(Uuid::from_bytes([1; 16])),
        admitted_revision: controller.policy().authority_revision(),
        deadline: None,
    };
    let refused = tokio::time::timeout(
        Duration::from_secs(20),
        controller.revoke_grant(held.grant_id, Some(&lapsed), None),
    )
    .await
    .expect("completes")
    .expect_err("an admission that no longer stands withdraws nothing");
    assert!(
        refused.to_string().contains("registration")
            || refused.to_string().contains("registered")
            || refused.to_string().contains("withdrawn"),
        "unexpected refusal: {refused}"
    );
    let stored = controller
        .sharing()
        .grants()
        .record(held.grant_id)
        .expect("readable")
        .expect("present");
    assert!(stored.revoked_at_ms.is_none(), "the grant still stands");
    assert!(
        controller
            .sharing()
            .grants()
            .fence_owed()
            .expect("readable")
            .is_empty(),
        "and nothing is owed a fence"
    );

    // The same revocation, carrying nothing, is the local owner's own and goes through.
    tokio::time::timeout(
        Duration::from_secs(20),
        controller.revoke_grant(held.grant_id, None, None),
    )
    .await
    .expect("completes")
    .expect("succeeds");
}

/// Revoking the same grant twice withdraws nothing the second time, and fences nothing.
#[tokio::test]
async fn a_repeated_revocation_withdraws_nothing_and_advances_nothing() {
    let (_temp, controller) = daemon().await;
    let held = grant(1, None, &[ActionRight::SessionView], GrantExpiry::Never);
    controller
        .sharing()
        .grants()
        .issue(&record(held.clone()), || Ok(()))
        .expect("written");

    let first = tokio::time::timeout(
        Duration::from_secs(20),
        controller.revoke_grant(held.grant_id, None, None),
    )
    .await
    .expect("completes")
    .expect("succeeds");
    assert!(!first.revoked_grants.is_empty());

    let second = tokio::time::timeout(
        Duration::from_secs(20),
        controller.revoke_grant(held.grant_id, None, None),
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

    // A revocation that withdraws nothing still answers with **one** revision. Something else
    // advances the host's revision here, which is what the network half does when it revokes a
    // device; the repeat that follows must not name one revision and carry a barrier for another.
    controller
        .revoke_authority()
        .await
        .expect("the host advances its own revision");
    let third = tokio::time::timeout(
        Duration::from_secs(20),
        controller.revoke_grant(held.grant_id, None, None),
    )
    .await
    .expect("completes")
    .expect("succeeds");
    assert!(third.revoked_grants.is_empty(), "still nothing to withdraw");
    assert_eq!(
        third.authority_revision, third.barrier.authority_revision,
        "the answer and its barrier are the same moment"
    );
    assert!(
        third.authority_revision.get() > first.authority_revision.get(),
        "and it is the revision now in force, not the one this daemon last wrote down"
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
            .issue(&record(held.clone()), || Ok(()))
            .expect("written");
    }

    let result = tokio::time::timeout(
        Duration::from_secs(20),
        controller.revoke_device_authority(recipient, None, None),
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
        controller.revoke_device_authority(recipient, None, None),
    )
    .await
    .expect("completes")
    .expect("succeeds");
    assert!(again.revoked_grants.is_empty());
    assert_eq!(again.authority_revision, result.authority_revision);
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-09.08: one action identifier, one withdrawal
// ---------------------------------------------------------------------------------------------

/// A daemon serving local clients on its own socket, for a test that submits an action the way a
/// caller does and then submits the same action again.
struct Serving {
    temp: kr_ipc::testing::TempHost,
    controller: Arc<Controller>,
    clients: tokio::task::JoinHandle<kr_controller::error::Result<()>>,
}

impl Serving {
    async fn start() -> Self {
        Self::start_on(kr_ipc::testing::TempHost::create()).await
    }

    async fn start_on(temp: kr_ipc::testing::TempHost) -> Self {
        let controller = start_daemon(&temp).await;
        let endpoint = temp
            .environment()
            .controller_endpoint()
            .expect("an endpoint");
        let listener = kr_ipc::endpoint::Listener::bind(&endpoint).expect("binds the endpoint");
        let clients = tokio::spawn(Arc::clone(&controller).serve_clients(listener));
        Self {
            temp,
            controller,
            clients,
        }
    }

    /// Stops this daemon and starts another on the same environment tree, the way a restart of the
    /// host does: every durable record stays, and nothing held in memory does.
    async fn restart(self) -> Self {
        let Self {
            temp,
            controller,
            clients,
        } = self;
        clients.abort();
        let _ = clients.await;
        // Each connection's task holds the daemon, and the daemon holds its environment's lock
        // until the last of them ends.
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while Arc::strong_count(&controller) > 1 {
            assert!(
                std::time::Instant::now() < deadline,
                "the stopped daemon is still held"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        drop(controller);
        Self::start_on(temp).await
    }

    /// Takes one action's recorded answer back out of the store, as a daemon that stopped between
    /// the action's effect and its record would have left it.
    fn forget_answer(&self, action_id: kr_protocol::ids::ActionId) {
        let registry = rusqlite::Connection::open(self.temp.environment().registry_database())
            .expect("opens the registry");
        registry
            .busy_timeout(Duration::from_secs(5))
            .expect("waits for the daemon's writes");
        let changed = registry
            .execute(
                "UPDATE authority_receipts SET result = NULL, recorded_at_ms = NULL
                  WHERE action_id = ?1",
                rusqlite::params![action_id.get().as_bytes().as_slice()],
            )
            .expect("the answer is taken out");
        assert_eq!(changed, 1, "one action's answer");
    }

    /// A local caller on the daemon's own socket.
    async fn client(&self) -> kr_ipc::client::LocalClient {
        kr_ipc::client::LocalClient::connect(
            &self
                .temp
                .environment()
                .controller_endpoint()
                .expect("an endpoint"),
            kr_protocol::local::LocalClientKind::Cli,
            BuildId::new("kr-test/0").expect("a build identifier"),
        )
        .await
        .expect("connects to the control endpoint")
    }

    /// The device revocation a local caller composes under `action_id`, and the claim the host's
    /// own dispatch takes for it, taken as a first attempt that did so at `claimed_at_ms` and has
    /// not gone on to its effect.
    async fn claim_first_revocation(
        &self,
        client: &mut kr_ipc::client::LocalClient,
        action_id: kr_protocol::ids::ActionId,
        device: DeviceId,
        claimed_at_ms: u64,
    ) -> (
        kr_protocol::envelope::MutationRequest,
        kr_controller::grants::ActionClaim,
    ) {
        let mutation = client
            .compose(
                Method::DeviceRevoke,
                action_id,
                kr_protocol::envelope::ActionTarget::environment(self.temp.environment_id()),
                &kr_protocol::sharing::DeviceRevokeParams { device_id: device },
            )
            .await
            .expect("the revocation is composed");
        // A caller on this machine acts as the operating-system account it runs under.
        let actor =
            kr_protocol::ids::ActorId::new(format!("local:{}", kr_ipc::paths::current_uid()))
                .expect("a principal");
        let digest =
            kr_protocol::digest::mutation_digest(&mutation, &actor).expect("the payload digest");
        let claim = self
            .controller
            .sharing()
            .grants()
            .claim_action(&actor, action_id, &digest, claimed_at_ms)
            .expect("the first attempt claims its action");
        (mutation, claim)
    }
}

/// KR-REQ-09.08: one action identifier never withdraws authority twice.
///
/// The first attempt at a device revocation claims its action and stops before its effect, as a
/// daemon task does when it is descheduled or waits on its store, and it stays stopped for longer
/// than any mutation may be admitted for. A retry of the same action is told the first attempt has
/// not finished and withdraws nothing. The device is granted something else meanwhile, and when
/// the first attempt goes on it withdraws both grants in one withdrawal: the revision moves once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_revocation_is_performed_once_however_long_its_first_attempt_waits() {
    let host = Serving::start().await;
    let controller = &host.controller;
    let recipient = device_id(0xf1);
    let held = grant(1, None, &[ActionRight::SessionView], GrantExpiry::Never);
    controller
        .sharing()
        .grants()
        .issue(&record(held.clone()), || Ok(()))
        .expect("written");
    let before = controller.policy().authority_revision();
    let mut client = host.client().await;
    let action_id = kr_protocol::ids::ActionId::new(Uuid::from_bytes([0x5a; 16]));

    let stopped_since =
        kr_ipc::now_ms().get() - kr_protocol::limits::MAX_MUTATION_TTL.get() - 1_000;
    let (mutation, first) = host
        .claim_first_revocation(&mut client, action_id, recipient, stopped_since)
        .await;
    let kr_controller::grants::ActionClaim::Claimed { hold: first } = first else {
        panic!("the first attempt claims its action: {first:?}");
    };

    let retried = client
        .repeat(&mutation)
        .await
        .expect("the daemon answers the retry");
    let after_the_retry = controller
        .sharing()
        .grants()
        .record(held.grant_id)
        .expect("readable")
        .expect("present");

    // Authority the device is given while the first attempt waits.
    let later = grant(2, None, &[ActionRight::FilesRead], GrantExpiry::Never);
    controller
        .sharing()
        .grants()
        .issue(&record(later.clone()), || Ok(()))
        .expect("written");

    // The first attempt goes on to its effect.
    let performed = tokio::time::timeout(
        Duration::from_secs(20),
        controller.revoke_device_authority(recipient, None, Some(&first)),
    )
    .await
    .expect("the revocation completes")
    .expect("it succeeds");
    drop(first);

    assert!(
        after_the_retry.revoked_at_ms.is_none(),
        "the retry withdrew nothing: {retried:?}"
    );
    let refusal = retried.expect_err("the retry is answered rather than performed");
    assert_eq!(
        refusal.code,
        kr_protocol::error::ErrorCode::ResourceUnavailable,
        "{refusal:?}"
    );
    assert!(performed.revoked_grants.contains(&held.grant_id));
    assert!(performed.revoked_grants.contains(&later.grant_id));
    assert_eq!(
        controller.policy().authority_revision().get(),
        before.get() + 1,
        "one action, one withdrawal"
    );
}

/// KR-REQ-09.08: a retry while the first attempt at a device revocation is running is told the
/// first attempt has not finished, and withdraws nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_retry_while_a_device_revocation_runs_is_told_it_has_not_finished() {
    let host = Serving::start().await;
    let controller = &host.controller;
    let recipient = device_id(0xf1);
    let held = grant(1, None, &[ActionRight::SessionView], GrantExpiry::Never);
    controller
        .sharing()
        .grants()
        .issue(&record(held.clone()), || Ok(()))
        .expect("written");
    let before = controller.policy().authority_revision();
    let mut client = host.client().await;
    let action_id = kr_protocol::ids::ActionId::new(Uuid::from_bytes([0x5b; 16]));

    let (mutation, first) = host
        .claim_first_revocation(&mut client, action_id, recipient, kr_ipc::now_ms().get())
        .await;
    assert!(
        matches!(first, kr_controller::grants::ActionClaim::Claimed { .. }),
        "{first:?}"
    );
    let refusal = client
        .repeat(&mutation)
        .await
        .expect("the daemon answers the retry")
        .expect_err("the retry is answered rather than performed");
    assert_eq!(
        refusal.code,
        kr_protocol::error::ErrorCode::ResourceUnavailable,
        "{refusal:?}"
    );
    let stored = controller
        .sharing()
        .grants()
        .record(held.grant_id)
        .expect("readable")
        .expect("present");
    assert!(stored.revoked_at_ms.is_none(), "nothing was withdrawn");
    assert_eq!(controller.policy().authority_revision(), before);
    drop(first);
}

/// The target a share names: the session it shares, in this environment.
fn shared_session(
    environment: EnvironmentId,
    session: SessionId,
) -> kr_protocol::envelope::ActionTarget {
    kr_protocol::envelope::ActionTarget {
        environment_id: environment,
        session_id: Nullable::some(session),
        session_epoch: Nullable::some(kr_protocol::ids::SessionEpoch::V1),
        application_instance_id: Nullable::null(),
        agent_binding_revision: Nullable::null(),
    }
}

/// What a local caller asks to share one session with one device, under the viewer role.
fn share_params(
    session: SessionId,
    recipient: DeviceId,
    parent: Option<GrantId>,
) -> kr_protocol::sharing::GrantCreateParams {
    let selection =
        kr_protocol::sharing::RoleSelection::plain(kr_protocol::sharing::SessionRole::Viewer);
    kr_protocol::sharing::GrantCreateParams {
        session_id: session,
        recipient_device_id: recipient,
        parent_grant_id: Nullable(parent),
        accepted_notices: kr_protocol::sharing::AuthorityNotice::for_actions(&selection.actions()),
        selection,
        lifetime_ms: Nullable::null(),
        owner_confirmation: Nullable::null(),
    }
}

/// KR-REQ-09.08: a share whose daemon stopped between its effect and its record is answered, after
/// a restart and with the freshness window it was sent under long gone, from the grant and the
/// invitation it wrote, and nothing is written again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_share_whose_record_was_never_written_is_answered_from_what_it_wrote_after_a_restart() {
    let host = Serving::start().await;
    let mut client = host.client().await;
    let action_id = kr_protocol::ids::ActionId::new(Uuid::from_bytes([0x61; 16]));
    let mutation = client
        .compose(
            Method::GrantCreate,
            action_id,
            shared_session(host.temp.environment_id(), session_id(0xa1)),
            &share_params(session_id(0xa1), device_id(0xf3), None),
        )
        .await
        .expect("the share is composed");
    let first: kr_protocol::sharing::GrantCreateResult = client
        .repeat(&mutation)
        .await
        .expect("the daemon answers")
        .expect("the grant and its invitation are written")
        .to_typed()
        .expect("a share result");
    drop(client);
    host.forget_answer(action_id);
    let written = host
        .controller
        .sharing()
        .grants()
        .records()
        .expect("readable")
        .len();

    let host = host.restart().await;
    let mut client = host.client().await;
    let again: kr_protocol::sharing::GrantCreateResult = client
        .repeat(&mutation)
        .await
        .expect("the daemon answers")
        .expect("the share is answered from what it wrote, not refused as stale")
        .to_typed()
        .expect("a share result");
    assert_eq!(
        again, first,
        "the answer the first attempt would have given"
    );
    assert_eq!(
        host.controller
            .sharing()
            .grants()
            .records()
            .expect("readable")
            .len(),
        written,
        "nothing was written again"
    );
}

/// KR-REQ-09.08: a revocation whose daemon stopped between its effect and its record is never
/// performed again. After a restart, and with the freshness window it was sent under long gone, its
/// retry is answered from the rows: the grant stands revoked, its fence ran, and the revision does
/// not move again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_revocation_whose_record_was_never_written_is_answered_from_the_rows_after_a_restart() {
    let host = Serving::start().await;
    let held = grant(1, None, &[ActionRight::SessionView], GrantExpiry::Never);
    host.controller
        .sharing()
        .grants()
        .issue(&record(held.clone()), || Ok(()))
        .expect("written");
    let mut client = host.client().await;
    let action_id = kr_protocol::ids::ActionId::new(Uuid::from_bytes([0x62; 16]));
    let mutation = client
        .compose(
            Method::GrantRevoke,
            action_id,
            kr_protocol::envelope::ActionTarget::environment(host.temp.environment_id()),
            &kr_protocol::sharing::GrantRevokeParams {
                grant_id: held.grant_id,
            },
        )
        .await
        .expect("the revocation is composed");
    let first: kr_protocol::sharing::RevocationResult = client
        .repeat(&mutation)
        .await
        .expect("the daemon answers")
        .expect("the grant is revoked")
        .to_typed()
        .expect("a revocation result");
    drop(client);
    host.forget_answer(action_id);

    let host = host.restart().await;
    let mut client = host.client().await;
    let again: kr_protocol::sharing::RevocationResult = client
        .repeat(&mutation)
        .await
        .expect("the daemon answers")
        .expect("the revocation is answered from the rows")
        .to_typed()
        .expect("a revocation result");
    assert!(again.revoked_grants.contains(&held.grant_id), "{again:?}");
    assert_eq!(
        again.authority_revision, first.authority_revision,
        "its fence ran, so the revision did not move again"
    );
    assert_eq!(
        again.barrier.authority_revision, again.authority_revision,
        "the answer and its barrier are one moment"
    );
}

/// KR-REQ-09.08 and 10.45: a revocation that withdrew more grants than one message's collection
/// bound, and ended before its fence, still has its withdrawal read back whole, and its retry
/// settles the fence it owes.
///
/// The attempt stops with the daemon that made it, and the next start raises that fence; the answer
/// a retry would carry names more grants than one control frame may hold, which the caller's
/// decoder refuses whatever produced it. What is asserted is the record and the fence, raised once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_withdrawal_larger_than_one_message_is_read_back_and_its_fence_settled() {
    let host = Serving::start().await;
    let controller = &host.controller;
    let parent = grant(1, None, &[ActionRight::SessionView], GrantExpiry::Never);
    controller
        .sharing()
        .grants()
        .issue(&record(parent.clone()), || Ok(()))
        .expect("written");
    let children = kr_cbor::Limits::DEFAULT.max_collection_len + 4;
    for index in 0..children {
        let child = Grant {
            grant_id: GrantId::new(Uuid::from_bytes(
                (0x1000_u128 + index as u128).to_be_bytes(),
            )),
            parent_grant_id: Nullable::some(parent.grant_id),
            recipient_device_id: device_id(0xf2),
            ..parent.clone()
        };
        controller
            .sharing()
            .grants()
            .issue(&record(child), || Ok(()))
            .expect("written");
    }
    let before = controller.policy().authority_revision();
    let mut client = host.client().await;
    let action_id = kr_protocol::ids::ActionId::new(Uuid::from_bytes([0x71; 16]));
    let mutation = client
        .compose(
            Method::GrantRevoke,
            action_id,
            kr_protocol::envelope::ActionTarget::environment(host.temp.environment_id()),
            &kr_protocol::sharing::GrantRevokeParams {
                grant_id: parent.grant_id,
            },
        )
        .await
        .expect("the revocation is composed");
    let actor = kr_protocol::ids::ActorId::new(format!("local:{}", kr_ipc::paths::current_uid()))
        .expect("a principal");
    let digest =
        kr_protocol::digest::mutation_digest(&mutation, &actor).expect("the payload digest");
    let kr_controller::grants::ActionClaim::Claimed { hold } = controller
        .sharing()
        .grants()
        .claim_action(&actor, action_id, &digest, kr_ipc::now_ms().get())
        .expect("the attempt claims its action")
    else {
        panic!("the attempt claims its action");
    };
    controller
        .sharing()
        .grants()
        .revoke_claimed(
            parent.grant_id,
            kr_ipc::now_ms().get(),
            || Ok(()),
            Some(&hold),
        )
        .expect("the rows are withdrawn");
    drop(hold);
    assert_eq!(
        controller
            .sharing()
            .grants()
            .recorded_withdrawal(&actor, action_id)
            .expect("the record reads back")
            .expect("the claim holds one")
            .len(),
        children + 1,
        "every grant the revocation withdrew"
    );

    drop(client);
    let host = host.restart().await;
    let controller = &host.controller;
    let mut client = host.client().await;
    let _ = client.repeat(&mutation).await;
    assert_eq!(
        controller.policy().authority_revision().get(),
        before.get() + 1,
        "the fence the withdrawal owed ran, once"
    );
    assert!(
        controller
            .sharing()
            .grants()
            .fence_owed()
            .expect("readable")
            .is_empty(),
        "and nothing is owed now"
    );
}

/// KR-REQ-09.08 and 10.45: a revocation whose attempt withdrew its grant and stopped before its
/// fence ran is answered once that fence has run. The attempt stops with the daemon that made it,
/// so the fence the withdrawal owed is raised by the next start, once, before anything is served;
/// the retry is answered from the rows, carries the revision that fence advanced to, and raises no
/// second one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unfinished_revocation_pays_the_fence_it_still_owes_before_it_is_answered() {
    let host = Serving::start().await;
    let controller = &host.controller;
    let parent = grant(1, None, &[ActionRight::SessionView], GrantExpiry::Never);
    let child = Grant {
        grant_id: grant_id(2),
        parent_grant_id: Nullable::some(parent.grant_id),
        recipient_device_id: device_id(0xf2),
        ..parent.clone()
    };
    for held in [&parent, &child] {
        controller
            .sharing()
            .grants()
            .issue(&record(held.clone()), || Ok(()))
            .expect("written");
    }
    let before = controller.policy().authority_revision();
    let mut client = host.client().await;
    let action_id = kr_protocol::ids::ActionId::new(Uuid::from_bytes([0x66; 16]));
    let mutation = client
        .compose(
            Method::GrantRevoke,
            action_id,
            kr_protocol::envelope::ActionTarget::environment(host.temp.environment_id()),
            &kr_protocol::sharing::GrantRevokeParams {
                grant_id: parent.grant_id,
            },
        )
        .await
        .expect("the revocation is composed");
    let actor = kr_protocol::ids::ActorId::new(format!("local:{}", kr_ipc::paths::current_uid()))
        .expect("a principal");
    let digest =
        kr_protocol::digest::mutation_digest(&mutation, &actor).expect("the payload digest");

    // The attempt claims, withdraws the rows with the fence they owe under its claim, and ends
    // before the fence.
    let kr_controller::grants::ActionClaim::Claimed { hold } = controller
        .sharing()
        .grants()
        .claim_action(&actor, action_id, &digest, kr_ipc::now_ms().get())
        .expect("the attempt claims its action")
    else {
        panic!("the attempt claims its action");
    };
    controller
        .sharing()
        .grants()
        .revoke_claimed(
            parent.grant_id,
            kr_ipc::now_ms().get(),
            || Ok(()),
            Some(&hold),
        )
        .expect("the rows are withdrawn");
    drop(hold);
    assert!(
        !controller
            .sharing()
            .grants()
            .fence_owed()
            .expect("readable")
            .is_empty(),
        "the withdrawal owes its fence"
    );
    // The attempt stops before its fence, with the daemon that made it.
    drop(client);
    let host = host.restart().await;
    let controller = &host.controller;
    assert_eq!(
        controller.policy().authority_revision().get(),
        before.get() + 1,
        "the start raised the fence the withdrawal owed"
    );

    let mut client = host.client().await;
    let answered: kr_protocol::sharing::RevocationResult = client
        .repeat(&mutation)
        .await
        .expect("the daemon answers")
        .expect("the revocation is answered from the rows")
        .to_typed()
        .expect("a revocation result");
    assert!(answered.revoked_grants.contains(&parent.grant_id));
    assert!(
        answered.revoked_grants.contains(&child.grant_id),
        "the named grant and its descendants"
    );
    assert_eq!(
        answered.authority_revision.get(),
        before.get() + 1,
        "the fence the withdrawal owed ran once, and not again for the answer"
    );
    assert!(
        controller
            .sharing()
            .grants()
            .fence_owed()
            .expect("readable")
            .is_empty(),
        "and nothing is owed now"
    );
}

/// KR-REQ-09.08: a revocation whose attempt ended before it withdrew anything is not performed
/// again: the grant it names still stands, and its retry is told the outcome is not known.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unfinished_revocation_of_a_grant_still_standing_is_unknown() {
    let host = Serving::start().await;
    let controller = &host.controller;
    let held = grant(1, None, &[ActionRight::SessionView], GrantExpiry::Never);
    controller
        .sharing()
        .grants()
        .issue(&record(held.clone()), || Ok(()))
        .expect("written");
    let before = controller.policy().authority_revision();
    let mut client = host.client().await;
    let action_id = kr_protocol::ids::ActionId::new(Uuid::from_bytes([0x67; 16]));
    let mutation = client
        .compose(
            Method::GrantRevoke,
            action_id,
            kr_protocol::envelope::ActionTarget::environment(host.temp.environment_id()),
            &kr_protocol::sharing::GrantRevokeParams {
                grant_id: held.grant_id,
            },
        )
        .await
        .expect("the revocation is composed");
    let actor = kr_protocol::ids::ActorId::new(format!("local:{}", kr_ipc::paths::current_uid()))
        .expect("a principal");
    let digest =
        kr_protocol::digest::mutation_digest(&mutation, &actor).expect("the payload digest");
    drop(
        controller
            .sharing()
            .grants()
            .claim_action(&actor, action_id, &digest, kr_ipc::now_ms().get())
            .expect("the attempt claims its action"),
    );

    let refusal = client
        .repeat(&mutation)
        .await
        .expect("the daemon answers")
        .expect_err("an unfinished revocation is not performed again");
    assert_eq!(
        refusal.code,
        kr_protocol::error::ErrorCode::OutcomeUnknown,
        "{refusal:?}"
    );
    let stored = controller
        .sharing()
        .grants()
        .record(held.grant_id)
        .expect("readable")
        .expect("present");
    assert!(stored.revoked_at_ms.is_none(), "nothing was withdrawn");
    assert_eq!(controller.policy().authority_revision(), before);
}

/// KR-REQ-09.08: an authority change whose attempt ended in this daemon without recording what it
/// did is not performed again. A retry under a fresh window is told the outcome is not known, and
/// nothing is withdrawn.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_authority_change_whose_attempt_ended_unrecorded_is_not_performed_again() {
    let host = Serving::start().await;
    let controller = &host.controller;
    let recipient = device_id(0xf1);
    let held = grant(1, None, &[ActionRight::SessionView], GrantExpiry::Never);
    controller
        .sharing()
        .grants()
        .issue(&record(held.clone()), || Ok(()))
        .expect("written");
    let before = controller.policy().authority_revision();
    let mut client = host.client().await;
    let action_id = kr_protocol::ids::ActionId::new(Uuid::from_bytes([0x63; 16]));
    let (mutation, first) = host
        .claim_first_revocation(&mut client, action_id, recipient, kr_ipc::now_ms().get())
        .await;
    assert!(
        matches!(first, kr_controller::grants::ActionClaim::Claimed { .. }),
        "{first:?}"
    );
    // The attempt ends, and records nothing.
    drop(first);

    let refusal = client
        .repeat(&mutation)
        .await
        .expect("the daemon answers the retry")
        .expect_err("the retry is answered rather than performed");
    assert_eq!(
        refusal.code,
        kr_protocol::error::ErrorCode::OutcomeUnknown,
        "{refusal:?}"
    );
    let stored = controller
        .sharing()
        .grants()
        .record(held.grant_id)
        .expect("readable")
        .expect("present");
    assert!(stored.revoked_at_ms.is_none(), "nothing was withdrawn");
    assert_eq!(controller.policy().authority_revision(), before);
}

/// One notification-preview key registration, as a paired device sends it.
fn key_registration(
    environment_id: EnvironmentId,
    action: u8,
    device: DeviceId,
    key: kr_protocol::scalars::NotificationPreviewKey,
    revision: u64,
) -> kr_protocol::envelope::MutationRequest {
    kr_protocol::envelope::MutationRequest {
        action_id: kr_protocol::ids::ActionId::new(Uuid::from_bytes([action; 16])),
        request_id: kr_protocol::ids::RequestId::new(u64::from(action)),
        method: Method::DevicePreviewKeyUpdate.into(),
        method_version: kr_protocol::method::MethodVersion::V1,
        grant_id: Nullable::null(),
        target: kr_protocol::envelope::ActionTarget::environment(environment_id),
        expected: kr_protocol::envelope::ParamsValue::empty(),
        action_window_id: kr_protocol::ids::ActionWindowId::new("window-1").expect("a window"),
        requested_ttl_ms: kr_protocol::scalars::DurationMs::new(30_000),
        params: kr_protocol::envelope::ParamsValue::from_typed(
            &kr_protocol::sharing::DevicePreviewKeyUpdateParams {
                device_id: device,
                notification_preview: key,
                revision: kr_protocol::ids::DeviceKeyRevision::new(revision),
            },
        )
        .expect("the parameters encode"),
    }
}

/// KR-REQ-09.08: a key registration whose attempt ended unrecorded is not answered with what
/// another action did. The first action's attempt claimed it and ended with nothing written, as an
/// attempt refused by the delivery journal does when the daemon stops before it records the
/// refusal. A second action then registers the same key at the same revision. The first action,
/// sent again, is told its outcome is not known: the device's record holds that key because of the
/// second action, and nothing this host keeps says the first one did anything.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unfinished_key_registration_is_not_answered_with_another_actions_registration() {
    let (temp, controller) = daemon().await;
    let environment_id = temp.environment_id();
    let device = device_id(0xd1);
    let actor = kr_transport::listener::device_principal(&device);
    let initial = kr_crypto::keys::NotificationPreviewKeyPair::generate().expect("a keypair");
    let rotated = kr_crypto::keys::NotificationPreviewKeyPair::generate().expect("a keypair");
    controller
        .devices()
        .commit(&kr_controller::service::net::devices::DeviceRecord {
            device_id: device,
            endpoint_id: kr_protocol::scalars::EndpointKey::from_bytes([1; 32]),
            device_key_revision: kr_protocol::ids::DeviceKeyRevision::new(1),
            authorisation: kr_protocol::scalars::AuthorisationKey::from_bytes([2; 32]),
            stored_envelope: None,
            device_name: kr_protocol::pairing::DeviceName::new("phone").expect("a name"),
            platform: kr_protocol::pairing::DevicePlatform::Ios,
            grant: Grant {
                recipient_device_id: device,
                ..grant(1, None, &[ActionRight::SessionView], GrantExpiry::Never)
            },
            paired_at_ms: TimestampMs::new(1_000),
            revoked_at_ms: None,
            expired_at_ms: None,
            committed_invitation_id: None,
            notification_preview: Some(*initial.public()),
        })
        .expect("a paired device");

    // The first action's attempt claims it and ends with nothing written and nothing recorded.
    let first = key_registration(environment_id, 0x71, device, *rotated.public(), 2);
    let digest = kr_protocol::digest::mutation_digest(&first, &actor).expect("a digest");
    let claimed = controller
        .sharing()
        .grants()
        .claim_action(&actor, first.action_id, &digest, kr_ipc::now_ms().get())
        .expect("the first attempt claims its action");
    assert!(
        matches!(claimed, kr_controller::grants::ActionClaim::Claimed { .. }),
        "{claimed:?}"
    );
    drop(claimed);

    // Another action registers the same key at the same revision.
    let second = key_registration(environment_id, 0x72, device, *rotated.public(), 2);
    controller
        .preview_key_update_action(&actor, &second)
        .await
        .expect("the second action registers the key");

    let refusal = controller
        .preview_key_update_action(&actor, &first)
        .await
        .expect_err("the first action is not answered with the second one's registration");
    assert_eq!(
        refusal.code(),
        kr_protocol::error::ErrorCode::OutcomeUnknown,
        "{refusal}"
    );
}

/// KR-REQ-09.18: a delegation from a parent the clock says has expired is not refused as expired
/// while this host cannot write down the reading that says so.
///
/// The store refuses every write of the host's policy, and with it the clock floor. The parent ran
/// out an hour ago by the wall clock, and the floor on disk says nothing about that hour. A
/// delegation from it is refused as unrecorded: were it refused as expired, a daemon that stopped
/// before the floor was written and started with its clock wound back would decide the other way.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_delegation_is_not_refused_as_expired_on_a_reading_this_host_could_not_write() {
    let host = Serving::start().await;
    let host_device = DeviceId::new(host.temp.environment_id().get());
    let now_ms = kr_ipc::now_ms().get();
    let parent = Grant {
        recipient_device_id: host_device,
        issuer_device_id: host_device,
        environment_selector: EnvironmentSelector::These {
            environment_ids: [host.temp.environment_id()].into_iter().collect(),
        },
        session_selector: SessionSelector::These {
            session_ids: [session_id(0xa1)].into_iter().collect(),
        },
        history: HistoryScope {
            lower_bound_ms: Nullable::some(TimestampMs::new(now_ms - 2 * 60 * 60 * 1000)),
            ..no_history()
        },
        authority_revision: host.controller.policy().authority_revision(),
        expiry: GrantExpiry::At {
            expires_at_ms: TimestampMs::new(now_ms - 60 * 60 * 1000),
        },
        ..grant(
            0x31,
            None,
            &[ActionRight::SessionView, ActionRight::SessionShare],
            GrantExpiry::Never,
        )
    };
    host.controller
        .sharing()
        .grants()
        .issue(
            &GrantRecord {
                issued_at_ms: now_ms - 2 * 60 * 60 * 1000,
                activated_at_ms: Some(now_ms - 2 * 60 * 60 * 1000),
                session_id: Some(session_id(0xa1)),
                ..record(parent.clone())
            },
            || Ok(()),
        )
        .expect("the parent");

    let registry = rusqlite::Connection::open(host.temp.environment().registry_database())
        .expect("opens the registry");
    registry
        .busy_timeout(Duration::from_secs(5))
        .expect("waits for the daemon's writes");
    registry
        .execute_batch(
            "CREATE TRIGGER refuse_policy BEFORE INSERT ON host_authority
             WHEN NEW.key = 'policy'
             BEGIN SELECT RAISE(ABORT, 'no room'); END;",
        )
        .expect("the fault is in place");

    let mut client = host.client().await;
    let refusal = client
        .mutate(
            Method::GrantCreate,
            kr_protocol::ids::ActionId::new(Uuid::from_bytes([0x65; 16])),
            shared_session(host.temp.environment_id(), session_id(0xa1)),
            &share_params(session_id(0xa1), device_id(0xf3), Some(parent.grant_id)),
        )
        .await
        .expect("the daemon answers")
        .expect_err("a delegation from an expired parent is refused");
    assert_eq!(
        refusal.code,
        kr_protocol::error::ErrorCode::StorageUnavailable,
        "{refusal:?}"
    );
    registry
        .execute_batch("DROP TRIGGER refuse_policy;")
        .expect("the fault is cleared");
}

/// A paired device's record, as this host commits one when a pairing completes.
fn paired_record(device: DeviceId) -> kr_controller::service::net::devices::DeviceRecord {
    kr_controller::service::net::devices::DeviceRecord {
        device_id: device,
        endpoint_id: kr_protocol::scalars::EndpointKey::from_bytes(kr_cbor::sha256(
            device.get().as_bytes(),
        )),
        device_key_revision: kr_protocol::ids::DeviceKeyRevision::new(1),
        authorisation: kr_protocol::scalars::AuthorisationKey::from_bytes([2; 32]),
        stored_envelope: None,
        device_name: kr_protocol::pairing::DeviceName::new("phone").expect("a name"),
        platform: kr_protocol::pairing::DevicePlatform::Ios,
        grant: Grant {
            recipient_device_id: device,
            ..grant(0x40, None, &[ActionRight::SessionView], GrantExpiry::Never)
        },
        paired_at_ms: TimestampMs::new(1_000),
        revoked_at_ms: None,
        expired_at_ms: None,
        committed_invitation_id: None,
        notification_preview: None,
    }
}

/// The device revocation a local caller composes under `action`, and the hold of the first attempt
/// that claimed it, which goes on to act under it.
async fn device_revocation_claimed(
    host: &Serving,
    client: &mut kr_ipc::client::LocalClient,
    action: u8,
    device: DeviceId,
) -> (
    kr_protocol::envelope::MutationRequest,
    kr_controller::grants::ClaimHold,
) {
    let (mutation, claimed) = host
        .claim_first_revocation(
            client,
            kr_protocol::ids::ActionId::new(Uuid::from_bytes([action; 16])),
            device,
            kr_ipc::now_ms().get(),
        )
        .await;
    let kr_controller::grants::ActionClaim::Claimed { hold } = claimed else {
        panic!("the first attempt claims its action: {claimed:?}");
    };
    (mutation, hold)
}

/// KR-REQ-09.08 and 23.27: a device revocation whose attempt ended unrecorded is answered from the
/// rows only once the device's own record stands revoked, its last write.
///
/// One attempt withdrew the device's grants and ended before its record: grants withdrawn beside a
/// record still live are not a finished withdrawal, and the retry is told the outcome is not
/// known. Another withdrew everything, its record too, and ended before its answer: the retry is
/// answered with what it withdrew.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unfinished_device_revocation_is_answered_only_once_the_device_record_is_revoked() {
    let host = Serving::start().await;
    let controller = &host.controller;
    let mut client = host.client().await;

    let partial = device_id(0xd2);
    let partial_grant = Grant {
        recipient_device_id: partial,
        ..grant(0x41, None, &[ActionRight::SessionView], GrantExpiry::Never)
    };
    controller
        .devices()
        .commit(&paired_record(partial))
        .expect("a paired device");
    controller
        .sharing()
        .grants()
        .issue(&record(partial_grant.clone()), || Ok(()))
        .expect("written");
    let (unfinished, hold) = device_revocation_claimed(&host, &mut client, 0x68, partial).await;
    controller
        .sharing()
        .grants()
        .revoke_device(partial, kr_ipc::now_ms().get(), || Ok(()), Some(&hold))
        .expect("the grants are withdrawn");
    drop(hold);
    let refusal = client
        .repeat(&unfinished)
        .await
        .expect("the daemon answers")
        .expect_err("a withdrawal short of the device's record is not called finished");
    assert_eq!(
        refusal.code,
        kr_protocol::error::ErrorCode::OutcomeUnknown,
        "{refusal:?}"
    );
    assert!(
        controller
            .devices()
            .record_for_device(partial)
            .expect("readable")
            .expect("present")
            .revoked_at_ms
            .is_none(),
        "and it is not finished for it"
    );

    let whole = device_id(0xd3);
    let whole_grant = Grant {
        recipient_device_id: whole,
        ..grant(0x42, None, &[ActionRight::SessionView], GrantExpiry::Never)
    };
    controller
        .devices()
        .commit(&paired_record(whole))
        .expect("a paired device");
    controller
        .sharing()
        .grants()
        .issue(&record(whole_grant.clone()), || Ok(()))
        .expect("written");
    let (finished, hold) = device_revocation_claimed(&host, &mut client, 0x69, whole).await;
    let performed = tokio::time::timeout(
        Duration::from_secs(20),
        controller.revoke_device_authority(whole, None, Some(&hold)),
    )
    .await
    .expect("the withdrawal completes")
    .expect("it succeeds");
    drop(hold);
    let mut client = host.client().await;
    let answered: kr_protocol::sharing::RevocationResult = client
        .repeat(&finished)
        .await
        .expect("the daemon answers")
        .expect("the revocation is answered from the rows")
        .to_typed()
        .expect("a revocation result");
    assert_eq!(
        answered.revoked_grants, performed.revoked_grants,
        "what the attempt withdrew"
    );
    assert!(answered.revoked_grants.contains(&whole_grant.grant_id));
    assert_eq!(
        answered.authority_revision, performed.authority_revision,
        "its fence ran, so the revision did not move again"
    );
}

/// KR-REQ-09.08 and 23.27: a device whose record was revoked some other way, with its grants still
/// standing, is not a finished device revocation. An unfinished revocation of it is told the
/// outcome is not known, and nothing is withdrawn.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unfinished_device_revocation_is_not_answered_while_the_device_holds_live_grants() {
    let host = Serving::start().await;
    let controller = &host.controller;
    let mut client = host.client().await;
    let device = device_id(0xd5);
    let held = Grant {
        recipient_device_id: device,
        ..grant(0x45, None, &[ActionRight::SessionView], GrantExpiry::Never)
    };
    controller
        .devices()
        .commit(&paired_record(device))
        .expect("a paired device");
    controller
        .sharing()
        .grants()
        .issue(&record(held.clone()), || Ok(()))
        .expect("written");
    let before = controller.policy().authority_revision();
    let (unfinished, hold) = device_revocation_claimed(&host, &mut client, 0x6e, device).await;
    drop(hold);
    // The record alone, as the network half's own revocation of a device writes it.
    assert!(
        controller
            .devices()
            .revoke(device, TimestampMs::new(kr_ipc::now_ms().get()))
            .expect("the record is written"),
        "the record is revoked"
    );

    let refusal = client
        .repeat(&unfinished)
        .await
        .expect("the daemon answers")
        .expect_err("a device holding live grants is not a finished revocation");
    assert_eq!(
        refusal.code,
        kr_protocol::error::ErrorCode::OutcomeUnknown,
        "{refusal:?}"
    );
    let stored = controller
        .sharing()
        .grants()
        .record(held.grant_id)
        .expect("readable")
        .expect("present");
    assert!(stored.revoked_at_ms.is_none(), "nothing was withdrawn");
    assert_eq!(controller.policy().authority_revision(), before);
}

/// KR-REQ-09.08 and 23.27: what a device revocation answered from its claim withdrew is told apart
/// from an earlier revocation by the claim, not by the moment. On a clock floor ahead of this
/// machine's clock, one of the device's grants withdrawn on its own and the device's revocation
/// carry the same moment; the retry names only what the device's revocation withdrew.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_revocation_on_a_floor_ahead_of_the_clock_names_only_what_it_withdrew() {
    let host = Serving::start().await;
    let controller = &host.controller;
    let device = device_id(0xd6);
    controller
        .devices()
        .commit(&paired_record(device))
        .expect("a paired device");
    let earlier = Grant {
        recipient_device_id: device,
        ..grant(0x46, None, &[ActionRight::SessionView], GrantExpiry::Never)
    };
    let later = Grant {
        recipient_device_id: device,
        ..grant(0x47, None, &[ActionRight::FilesRead], GrantExpiry::Never)
    };
    for held in [&earlier, &later] {
        controller
            .sharing()
            .grants()
            .issue(&record(held.clone()), || Ok(()))
            .expect("written");
    }
    // A reading an hour ahead of this machine's clock, so every reading after it is held there.
    let ahead = kr_ipc::now_ms().get() + 60 * 60 * 1000;
    controller
        .update_policy(|policy| policy.observe_utc(ahead))
        .expect("the floor is written");
    tokio::time::timeout(
        Duration::from_secs(20),
        controller.revoke_grant(earlier.grant_id, None, None),
    )
    .await
    .expect("the earlier revocation completes")
    .expect("it succeeds");

    let mut client = host.client().await;
    let action_id = kr_protocol::ids::ActionId::new(Uuid::from_bytes([0x6f; 16]));
    let mutation = client
        .compose(
            Method::DeviceRevoke,
            action_id,
            kr_protocol::envelope::ActionTarget::environment(host.temp.environment_id()),
            &kr_protocol::sharing::DeviceRevokeParams { device_id: device },
        )
        .await
        .expect("the revocation is composed");
    let first: kr_protocol::sharing::RevocationResult = client
        .repeat(&mutation)
        .await
        .expect("the daemon answers")
        .expect("the device is revoked")
        .to_typed()
        .expect("a revocation result");
    let moments: Vec<Option<u64>> = [&earlier, &later]
        .iter()
        .map(|held| {
            controller
                .sharing()
                .grants()
                .record(held.grant_id)
                .expect("readable")
                .expect("present")
                .revoked_at_ms
        })
        .collect();
    assert_eq!(moments[0], moments[1], "both withdrawals carry one moment");
    assert!(!first.revoked_grants.contains(&earlier.grant_id));
    drop(client);
    host.forget_answer(action_id);

    let mut client = host.client().await;
    let again: kr_protocol::sharing::RevocationResult = client
        .repeat(&mutation)
        .await
        .expect("the daemon answers")
        .expect("the revocation is answered from its claim")
        .to_typed()
        .expect("a revocation result");
    assert_eq!(
        again.revoked_grants, first.revoked_grants,
        "the answer the first attempt gave"
    );
    assert_eq!(again.authority_revision, first.authority_revision);
}

/// The claim a local caller's action takes, taken by a first attempt that then ended without
/// recording anything, as the host's own dispatch takes it.
fn claimed_and_left(host: &Serving, mutation: &kr_protocol::envelope::MutationRequest) {
    let actor = kr_protocol::ids::ActorId::new(format!("local:{}", kr_ipc::paths::current_uid()))
        .expect("a principal");
    let digest =
        kr_protocol::digest::mutation_digest(mutation, &actor).expect("the payload digest");
    let claimed = host
        .controller
        .sharing()
        .grants()
        .claim_action(&actor, mutation.action_id, &digest, kr_ipc::now_ms().get())
        .expect("the attempt claims its action");
    assert!(
        matches!(claimed, kr_controller::grants::ActionClaim::Claimed { .. }),
        "{claimed:?}"
    );
}

/// KR-REQ-09.08: a revocation answered from the rows names what the rows say it withdrew, which is
/// the answer its first attempt gave: not a descendant an earlier revocation had withdrawn already.
/// A revocation of a grant that went with its ancestor names nothing, as a repeat does.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_revocation_answered_from_the_rows_names_only_what_it_withdrew() {
    let host = Serving::start().await;
    let controller = &host.controller;
    let parent = grant(1, None, &[ActionRight::SessionView], GrantExpiry::Never);
    let earlier = Grant {
        grant_id: grant_id(2),
        parent_grant_id: Nullable::some(parent.grant_id),
        recipient_device_id: device_id(0xf2),
        ..parent.clone()
    };
    let later = Grant {
        grant_id: grant_id(3),
        parent_grant_id: Nullable::some(parent.grant_id),
        recipient_device_id: device_id(0xf3),
        ..parent.clone()
    };
    for held in [&parent, &earlier, &later] {
        controller
            .sharing()
            .grants()
            .issue(&record(held.clone()), || Ok(()))
            .expect("written");
    }
    tokio::time::timeout(
        Duration::from_secs(20),
        controller.revoke_grant(earlier.grant_id, None, None),
    )
    .await
    .expect("the earlier revocation completes")
    .expect("it succeeds");

    let mut client = host.client().await;
    let action_id = kr_protocol::ids::ActionId::new(Uuid::from_bytes([0x6b; 16]));
    let mutation = client
        .compose(
            Method::GrantRevoke,
            action_id,
            kr_protocol::envelope::ActionTarget::environment(host.temp.environment_id()),
            &kr_protocol::sharing::GrantRevokeParams {
                grant_id: parent.grant_id,
            },
        )
        .await
        .expect("the revocation is composed");
    let first: kr_protocol::sharing::RevocationResult = client
        .repeat(&mutation)
        .await
        .expect("the daemon answers")
        .expect("the grant is revoked")
        .to_typed()
        .expect("a revocation result");
    assert!(first.revoked_grants.contains(&parent.grant_id));
    assert!(first.revoked_grants.contains(&later.grant_id));
    assert!(!first.revoked_grants.contains(&earlier.grant_id));
    drop(client);
    host.forget_answer(action_id);

    // The fence the first attempt ran withdrew that connection's registration.
    let mut client = host.client().await;
    let again: kr_protocol::sharing::RevocationResult = client
        .repeat(&mutation)
        .await
        .expect("the daemon answers")
        .expect("the revocation is answered from the rows")
        .to_typed()
        .expect("a revocation result");
    assert_eq!(
        again.revoked_grants, first.revoked_grants,
        "the answer the first attempt gave"
    );
    assert_eq!(again.authority_revision, first.authority_revision);

    let action_id = kr_protocol::ids::ActionId::new(Uuid::from_bytes([0x6c; 16]));
    let mutation = client
        .compose(
            Method::GrantRevoke,
            action_id,
            kr_protocol::envelope::ActionTarget::environment(host.temp.environment_id()),
            &kr_protocol::sharing::GrantRevokeParams {
                grant_id: later.grant_id,
            },
        )
        .await
        .expect("the revocation is composed");
    claimed_and_left(&host, &mutation);
    let answered: kr_protocol::sharing::RevocationResult = client
        .repeat(&mutation)
        .await
        .expect("the daemon answers")
        .expect("the revocation is answered from the rows")
        .to_typed()
        .expect("a revocation result");
    assert!(
        answered.revoked_grants.is_empty(),
        "the grant went with its ancestor, so a revocation naming it withdrew nothing: \
         {answered:?}"
    );
    assert_eq!(
        answered.authority_revision, first.authority_revision,
        "and it advanced nothing"
    );
}

/// KR-REQ-09.08 and 23.27: a device revocation answered from the rows names the grants withdrawn
/// with the device's record, which is the answer its first attempt gave: not a grant of the
/// device's that an earlier revocation had withdrawn already.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_revocation_answered_from_the_rows_names_only_what_it_withdrew() {
    let host = Serving::start().await;
    let controller = &host.controller;
    let device = device_id(0xd4);
    controller
        .devices()
        .commit(&paired_record(device))
        .expect("a paired device");
    let earlier = Grant {
        recipient_device_id: device,
        ..grant(0x43, None, &[ActionRight::SessionView], GrantExpiry::Never)
    };
    let later = Grant {
        recipient_device_id: device,
        ..grant(0x44, None, &[ActionRight::FilesRead], GrantExpiry::Never)
    };
    for held in [&earlier, &later] {
        controller
            .sharing()
            .grants()
            .issue(&record(held.clone()), || Ok(()))
            .expect("written");
    }
    tokio::time::timeout(
        Duration::from_secs(20),
        controller.revoke_grant(earlier.grant_id, None, None),
    )
    .await
    .expect("the earlier revocation completes")
    .expect("it succeeds");

    let mut client = host.client().await;
    let action_id = kr_protocol::ids::ActionId::new(Uuid::from_bytes([0x6d; 16]));
    let mutation = client
        .compose(
            Method::DeviceRevoke,
            action_id,
            kr_protocol::envelope::ActionTarget::environment(host.temp.environment_id()),
            &kr_protocol::sharing::DeviceRevokeParams { device_id: device },
        )
        .await
        .expect("the revocation is composed");
    let first: kr_protocol::sharing::RevocationResult = client
        .repeat(&mutation)
        .await
        .expect("the daemon answers")
        .expect("the device is revoked")
        .to_typed()
        .expect("a revocation result");
    assert!(first.revoked_grants.contains(&later.grant_id));
    assert!(!first.revoked_grants.contains(&earlier.grant_id));
    drop(client);
    host.forget_answer(action_id);

    let mut client = host.client().await;
    let again: kr_protocol::sharing::RevocationResult = client
        .repeat(&mutation)
        .await
        .expect("the daemon answers")
        .expect("the revocation is answered from the rows")
        .to_typed()
        .expect("a revocation result");
    assert_eq!(
        again.revoked_grants, first.revoked_grants,
        "the answer the first attempt gave"
    );
    assert_eq!(again.authority_revision, first.authority_revision);
}

/// KR-REQ-09.08: a destination's credential whose attempt ended unrecorded is not set again.
/// Nothing this host keeps says which request set a credential, so the retry is told the outcome
/// is not known.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unfinished_destination_credential_is_unknown() {
    let host = Serving::start().await;
    let mut client = host.client().await;
    let action_id = kr_protocol::ids::ActionId::new(Uuid::from_bytes([0x6a; 16]));
    let mutation = client
        .compose(
            Method::DeliveryDestinationSecretSet,
            action_id,
            kr_protocol::envelope::ActionTarget::environment(host.temp.environment_id()),
            &kr_protocol::delivery::DeliveryDestinationSecretSetParams {
                destination_id: "alerts".to_owned(),
                secret: kr_protocol::delivery::DestinationSecret::Slack {
                    webhook_url: kr_protocol::delivery::SecretText::new(
                        "https://hooks.slack.com/services/T000/B000/XXXXXXXXXXXXXXXX",
                    )
                    .expect("a credential"),
                },
            },
        )
        .await
        .expect("the credential is composed");
    let actor = kr_protocol::ids::ActorId::new(format!("local:{}", kr_ipc::paths::current_uid()))
        .expect("a principal");
    let digest =
        kr_protocol::digest::mutation_digest(&mutation, &actor).expect("the payload digest");
    drop(
        host.controller
            .sharing()
            .grants()
            .claim_action(&actor, action_id, &digest, kr_ipc::now_ms().get())
            .expect("the attempt claims its action"),
    );

    let refusal = client
        .repeat(&mutation)
        .await
        .expect("the daemon answers")
        .expect_err("an unfinished credential is not set again");
    assert_eq!(
        refusal.code,
        kr_protocol::error::ErrorCode::OutcomeUnknown,
        "{refusal:?}"
    );
}

/// KR-REQ-09.08: an authority change refused before its effect is refused the same way when the
/// same action is sent again, rather than performed or reported as running.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refused_authority_change_is_refused_the_same_way_when_it_is_sent_again() {
    let host = Serving::start().await;
    let mut client = host.client().await;
    let action_id = kr_protocol::ids::ActionId::new(Uuid::from_bytes([0x64; 16]));
    // A delegation from a grant this host does not hold.
    let mutation = client
        .compose(
            Method::GrantCreate,
            action_id,
            shared_session(host.temp.environment_id(), session_id(0xa1)),
            &share_params(session_id(0xa1), device_id(0xf3), Some(grant_id(0x77))),
        )
        .await
        .expect("the share is composed");
    let first = client
        .repeat(&mutation)
        .await
        .expect("the daemon answers")
        .expect_err("a delegation from nothing is refused");
    assert_eq!(first.code, kr_protocol::error::ErrorCode::PermissionDenied);
    let again = client
        .repeat(&mutation)
        .await
        .expect("the daemon answers")
        .expect_err("the same action is refused again");
    assert_eq!(again.code, first.code, "{again:?}");
    assert_eq!(again.message, first.message);
    assert!(
        host.controller
            .sharing()
            .grants()
            .records()
            .expect("readable")
            .is_empty(),
        "nothing was written"
    );
}

/// Issuing and revoking the same subtree from two threads leaves a consistent store.
///
/// A smoke test rather than a regression test for the read-then-write gap: it starts two threads
/// and does not control which reaches the store first, so both serial orders pass. What the
/// property actually rests on is [`GrantDirectory`]'s immediate transaction, which holds the write
/// lock from before the subtree is read until after it is updated. This checks that the two orders
/// are both *consistent*, which is what a caller can observe.
#[test]
fn issuing_and_revoking_one_subtree_at_once_leaves_a_consistent_store() {
    use std::sync::Arc;

    let directory = Arc::new(GrantDirectory::in_memory().expect("a grant store"));
    let parent = grant(
        1,
        None,
        &[ActionRight::SessionView, ActionRight::FilesRead],
        GrantExpiry::Never,
    );
    directory
        .issue(&record(parent.clone()), || Ok(()))
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
        std::thread::spawn(move || directory.revoke(parent_id, 4_000, || Ok(())))
    };
    let issuing = {
        let directory = Arc::clone(&directory);
        let child = child.clone();
        std::thread::spawn(move || directory.issue(&record(child), || Ok(())))
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
