//! A feed request that names, or sits beside, a grants row that cannot be read.
//!
//! The request is carried out whatever the damage: a named grant whose row cannot be read is
//! marked revoked with what hangs below it, every target of a plan is attempted whatever an earlier
//! one returned, and a replay of a request the first pass carried out writes and scans nothing.

use kr_crypto::keys::AuthorisationKeyPair;
use kr_protocol::ids::{DeviceId, GrantId, RevocationRequestId};
use kr_protocol::pairing::{RevocationRequest, RevocationTarget};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{CanonicalSet, TimestampMs, Uuid};

use super::Controller;
use super::a_revocation_beside_a_row_that_cannot_be_read::{
    device_id, grant_id, is_live, issue, key,
};
use super::a_transfer_left_unanswered::daemon;
use super::a_voice_grant_on_the_floor::{paired, paired_signing_as};
use super::one_barrier_for_every_restriction::{beside, owed, revision};
use super::remote_revocation::Replay;

/// A request of the host's own, signed by `key` as `issuer`, naming `target`.
fn signed(
    controller: &Controller,
    key: &AuthorisationKeyPair,
    issuer: DeviceId,
    target: RevocationTarget,
    id: u8,
) -> RevocationRequest {
    kr_pairing::grants::sign_revocation_request(
        key,
        RevocationRequestId::new(Uuid::from_bytes([id; 16])),
        issuer,
        controller.host_device_id(),
        target,
        TimestampMs::new(1_000),
    )
    .expect("a signed request")
}

fn grants_of(grants: &[GrantId]) -> RevocationTarget {
    RevocationTarget::Grants {
        grant_ids: grants.iter().copied().collect::<CanonicalSet<_>>(),
    }
}

/// An owner that could manage the host, and its key.
fn an_owner(controller: &Controller) -> (AuthorisationKeyPair, DeviceId) {
    let owner_key = AuthorisationKeyPair::generate().expect("a key");
    let owner = paired_signing_as(
        controller,
        1,
        *owner_key.public(),
        &[ActionRight::HostManage],
        None,
    );
    (owner_key, owner.device_id)
}

/// A replay of a request naming a grant whose row cannot be read carries it out: the row is
/// marked revoked and what hangs below it is withdrawn, where a strict read of the named grant
/// would have stopped the pass.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_replayed_request_naming_a_damaged_grant_is_carried_out() {
    let (temp, controller) = daemon().await;
    let (owner_key, owner) = an_owner(&controller);
    let named = issue(&controller, 0x51, None, device_id(0xe1));
    let below = issue(&controller, 0x52, Some(0x51), device_id(0xe2));
    beside(&temp)
        .execute_batch(&format!(
            "UPDATE grants SET grant = X'00' WHERE grant_id = {};",
            key(named)
        ))
        .expect("the record no longer decodes");

    let request = signed(&controller, &owner_key, owner, grants_of(&[named]), 7);
    assert_eq!(
        controller
            .replay_feed_request(&request, 1)
            .await
            .expect("the request is carried out"),
        Replay::Done
    );
    assert!(!is_live(&temp, &key(named)), "the named row is marked");
    assert!(
        !is_live(&temp, &key(below)),
        "what hangs below it is withdrawn"
    );
}

/// A request that names a grant by a row whose record does not decode, and one that names an
/// alias (a row whose key is not the grant it holds) by either of its two identifiers, is carried
/// out: the row found by its key is kept, and the row found by the grant it holds is the same.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_request_naming_an_undecodable_row_by_its_key_and_an_alias_by_each_identifier_is_carried_out()
 {
    let (temp, controller) = daemon().await;
    let (owner_key, owner) = an_owner(&controller);
    // A row that does not decode, with a readable child that names its key.
    let undecodable = issue(&controller, 0x51, None, device_id(0xe1));
    let below = issue(&controller, 0x52, Some(0x51), device_id(0xe2));
    beside(&temp)
        .execute_batch(&format!(
            "UPDATE grants SET grant = X'00' WHERE grant_id = {};",
            key(undecodable)
        ))
        .expect("the record no longer decodes");
    // Two aliases: keyed 0x62 and 0x64, holding the grants 0x61 and 0x63.
    for (held_id, alias) in [(0x61, 0x62), (0x63, 0x64)] {
        let held = issue(&controller, held_id, None, device_id(0xe3));
        beside(&temp)
            .execute_batch(&format!(
                "UPDATE grants SET grant_id = {} WHERE grant_id = {};",
                key(grant_id(alias)),
                key(held)
            ))
            .expect("the row is re-keyed");
    }

    for (id, named) in [
        (7, undecodable),
        // By the key the alias stands under, and by the grant its record holds.
        (8, grant_id(0x62)),
        (9, grant_id(0x63)),
    ] {
        let request = signed(&controller, &owner_key, owner, grants_of(&[named]), id);
        assert_eq!(
            controller
                .replay_feed_request(&request, 1)
                .await
                .expect("the request is carried out"),
            Replay::Done,
            "{named}"
        );
    }
    assert!(!is_live(&temp, &key(undecodable)));
    assert!(
        !is_live(&temp, &key(below)),
        "what hangs below the undecodable row"
    );
    assert!(
        !is_live(&temp, &key(grant_id(0x62))),
        "the alias named by its key"
    );
    assert!(
        !is_live(&temp, &key(grant_id(0x64))),
        "the alias named by the grant it holds"
    );
}

/// A completed request that names a readable grant beside a row that cannot be read is carried out
/// by its first replay, which is before its issuer is revoked, and what it withdrew stays withdrawn
/// after the issuer's revocation.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_completed_request_naming_a_readable_grant_beside_a_damaged_row_is_withdrawn_before_its_issuer_is_revoked()
 {
    let (temp, controller) = daemon().await;
    let (owner_key, owner) = an_owner(&controller);
    let named = issue(&controller, 0x51, None, device_id(0xe1));
    let damaged = issue(&controller, 0x53, None, device_id(0xe2));
    beside(&temp)
        .execute_batch(&format!(
            "UPDATE grants SET parent_grant_id = X'00' WHERE grant_id = {};",
            key(damaged)
        ))
        .expect("the parent column no longer matches the record");
    let request = signed(&controller, &owner_key, owner, grants_of(&[named]), 7);

    controller
        .replay_feed_request(&request, 1)
        .await
        .expect("the first replay");
    assert!(!is_live(&temp, &key(named)), "withdrawn by the first pass");
    controller
        .devices
        .revoke(owner, TimestampMs::new(2_000))
        .expect("the issuer is revoked");
    controller
        .replay_feed_request(&request, 1)
        .await
        .expect("the second replay");
    assert!(
        !is_live(&temp, &key(named)),
        "and still after the issuer is revoked"
    );
}

/// A replay of a request the first pass carried out, which marked the row it names, finds the row
/// revoked and carries nothing out: the second replay reads only what the two probes of the named
/// grant read, and the authority revision does not move.
#[tokio::test(flavor = "current_thread")]
async fn a_replayed_record_naming_a_grant_the_first_pass_marked_is_not_carried_out_again() {
    let (temp, controller) = daemon().await;
    let (owner_key, owner) = an_owner(&controller);
    let named = issue(&controller, 0x51, None, device_id(0xe1));
    issue(&controller, 0x52, Some(0x51), device_id(0xe2));
    beside(&temp)
        .execute_batch(&format!(
            "UPDATE grants SET grant = X'00' WHERE grant_id = {};",
            key(named)
        ))
        .expect("the record no longer decodes");
    let request = signed(&controller, &owner_key, owner, grants_of(&[named]), 7);
    controller
        .replay_feed_request(&request, 1)
        .await
        .expect("the first replay carries it out");
    let after_the_first = revision(&controller).await;

    let before = crate::grants::store::grant_rows_read();
    controller
        .sharing()
        .grants()
        .probe(named)
        .expect("the probe reads");
    let one_probe = crate::grants::store::grant_rows_read() - before;
    let before = crate::grants::store::grant_rows_read();
    controller
        .replay_feed_request(&request, 1)
        .await
        .expect("the second replay");
    let replayed = crate::grants::store::grant_rows_read() - before;
    assert_eq!(
        replayed,
        2 * one_probe,
        "the plan's probe and the replay's, and no scan for a withdrawal"
    );
    assert_eq!(revision(&controller).await, after_the_first);
    assert!(owed(&controller).is_empty());
}

/// A request naming two devices attempts the second when the first fails for a reason of the
/// registry's own: the second is revoked, the revision it reached is noted, the first failure is
/// returned, and the retry revokes the first and moves the revision once.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_request_naming_two_devices_revokes_the_second_when_the_first_fails_for_another_reason() {
    let (temp, controller) = daemon().await;
    let (owner_key, owner) = an_owner(&controller);
    let first = paired(&controller, 2, None).device_id;
    let second = paired(&controller, 3, None).device_id;
    let first_grant = issue(&controller, 0x51, None, first);
    issue(&controller, 0x52, None, second);
    // Only the first device's withdrawal fails: the second stays writable by itself.
    beside(&temp)
        .execute_batch(&format!(
            "CREATE TRIGGER refuse_the_first BEFORE UPDATE OF revoked_at_ms ON grants
             WHEN NEW.grant_id = {} BEGIN SELECT RAISE(ABORT, 'no room'); END;",
            key(first_grant)
        ))
        .expect("the trigger is made");
    let request = signed(
        &controller,
        &owner_key,
        owner,
        RevocationTarget::Devices {
            device_ids: [first, second].into_iter().collect::<CanonicalSet<_>>(),
        },
        7,
    );
    let plan = controller.plan_of(&request).expect("the plan");
    let is_revoked = |device: DeviceId| {
        controller
            .devices
            .record_for_device(device)
            .expect("the directory reads")
            .expect("the device is recorded")
            .revoked_at_ms
            .is_some()
    };

    controller
        .apply_feed_plan(&plan)
        .await
        .expect_err("the first device's withdrawal fails");
    assert!(is_revoked(second), "the second device is revoked");
    assert!(!is_revoked(first), "the first is not");
    let reached = revision(&controller).await;
    assert!(
        controller
            .compared_revision
            .load(std::sync::atomic::Ordering::SeqCst)
            >= reached,
        "the revision the completed target reached is noted before the failure is returned"
    );

    beside(&temp)
        .execute_batch("DROP TRIGGER refuse_the_first;")
        .expect("the trigger goes");
    controller
        .apply_feed_plan(&plan)
        .await
        .expect("the retry revokes the first");
    assert!(is_revoked(first));
    assert_eq!(
        revision(&controller).await,
        reached + 1,
        "the revision moves once"
    );
}

/// A request that fails for a reason that is not a row's damage ends the pass: a grants table that
/// cannot be read at all is an error, not a grant that is absent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_request_that_fails_for_another_reason_still_ends_the_pass() {
    let (temp, controller) = daemon().await;
    let (owner_key, owner) = an_owner(&controller);
    let named = issue(&controller, 0x51, None, device_id(0xe1));
    let registry = beside(&temp);
    registry
        .execute_batch("ALTER TABLE grants RENAME TO grants_aside;")
        .expect("the grants cannot be read");
    let request = signed(&controller, &owner_key, owner, grants_of(&[named]), 7);
    let failed = controller.replay_feed_request(&request, 1).await;
    registry
        .execute_batch("ALTER TABLE grants_aside RENAME TO grants;")
        .expect("the grants can be read again");
    failed.expect_err("a registry that cannot read the grants stops the pass");
}
