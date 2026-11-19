//! A revocation never fails because some row cannot be read: it withdraws every grant it can read,
//! an owner's revocation also marks every row it cannot read, and a paired device's reaches only
//! the subtree it names.

use super::damaged_rows::{device_literal, held, key, run};
use super::*;

fn one<T: rusqlite::types::FromSql>(store: &GrantDirectory, sql: &str) -> T {
    store
        .with(|connection| connection.query_row(sql, [], |row| row.get(0)))
        .expect("the raw query reads")
}

/// The revocation moment of grant `number`, none while it is live.
fn revoked_at(store: &GrantDirectory, number: u32) -> Option<i64> {
    one(
        store,
        &format!(
            "SELECT revoked_at_ms FROM grants WHERE grant_id = {}",
            key(number)
        ),
    )
}

fn live(store: &GrantDirectory, number: u32) -> bool {
    revoked_at(store, number).is_none()
}

fn owner_revokes(store: &GrantDirectory, device: u8) -> GrantRevocation {
    store
        .revoke_device(device_of(device), 5_000, || Ok(()), None)
        .expect("the owner's revocation is not refused for a row it cannot read")
}

fn mark_unreadable(store: &GrantDirectory, number: u32) {
    run(
        store,
        &format!(
            "UPDATE grants SET parent_grant_id = X'00' WHERE grant_id = {};",
            key(number)
        ),
    );
}

fn debts(store: &GrantDirectory) -> i64 {
    one(store, "SELECT COUNT(*) FROM fence_debt")
}

#[test]
fn a_device_revocation_beside_a_damaged_row_withdraws_the_devices_grants_and_what_hangs_below() {
    let store = store_written_by_hand(&[
        held(1, None, DEVICE),
        held(2, Some(1), OTHER_DEVICE),
        held(3, None, OTHER_DEVICE),
    ]);
    mark_unreadable(&store, 3);
    let revocation = owner_revokes(&store, DEVICE);
    assert!(!live(&store, 1) && !live(&store, 2));
    assert!(
        !live(&store, 3),
        "the row that cannot be read is marked revoked"
    );
    assert_eq!(revocation.marked, 1);
}

#[test]
fn a_device_whose_row_does_not_decode_is_revoked_and_what_hangs_below_its_key_is_withdrawn() {
    let store = store_written_by_hand(&[held(1, None, DEVICE), held(2, Some(1), OTHER_DEVICE)]);
    run(
        &store,
        &format!(
            "UPDATE grants SET grant = X'00' WHERE grant_id = {};",
            key(1)
        ),
    );
    owner_revokes(&store, DEVICE);
    assert!(!live(&store, 1), "the damaged row is marked");
    assert!(!live(&store, 2), "what hangs below its key is withdrawn");
}

#[test]
fn a_device_whose_only_row_has_a_wrong_recipient_column_is_revoked_and_what_hangs_below_is_withdrawn()
 {
    let store = store_written_by_hand(&[held(1, None, DEVICE), held(2, Some(1), OTHER_DEVICE)]);
    run(
        &store,
        &format!(
            "UPDATE grants SET recipient_device_id = {} WHERE grant_id = {};",
            device_literal(OTHER_DEVICE),
            key(1)
        ),
    );
    owner_revokes(&store, DEVICE);
    assert!(
        !live(&store, 2),
        "the child of the damaged row is withdrawn"
    );
}

#[test]
fn a_grant_below_a_row_that_cannot_be_read_is_withdrawn_whoever_holds_it() {
    let store = store_written_by_hand(&[
        held(1, None, DEVICE),
        held(2, Some(1), DEVICE),
        held(3, Some(2), OTHER_DEVICE),
    ]);
    mark_unreadable(&store, 2);
    let revocation = owner_revokes(&store, DEVICE);
    assert!(!live(&store, 3));
    assert_eq!(revocation.withdrawn_unplaced, 1);
}

#[test]
fn a_grant_below_a_missing_row_is_withdrawn_by_an_owners_revocation() {
    let store = store_written_by_hand(&[held(1, None, DEVICE), held(2, Some(1), OTHER_DEVICE)]);
    run(
        &store,
        &format!("DELETE FROM grants WHERE grant_id = {};", key(1)),
    );
    owner_revokes(&store, DEVICE);
    assert!(!live(&store, 2));
}

#[test]
fn a_cycle_with_a_tail_is_withdrawn_once_each_and_overlapping_roots_take_each_row_once() {
    let store = store_written_by_hand(&[
        held(1, Some(3), OTHER_DEVICE),
        held(2, Some(1), OTHER_DEVICE),
        held(3, Some(2), OTHER_DEVICE),
        held(4, Some(3), OTHER_DEVICE),
        held(5, None, DEVICE),
        held(6, Some(5), DEVICE),
    ]);
    let scan = store.in_transaction(scan_all).expect("the scan reads");
    let plan = plan_withdrawal(&scan, Roots::Device(device_of(DEVICE)), Scope::Host)
        .expect("the plan is made");
    let mut taken: Vec<GrantId> = plan
        .subtrees
        .iter()
        .flat_map(|subtree| subtree.rows.iter().map(|row| row.grant.grant_id))
        .collect();
    taken.sort();
    let mut expected: Vec<GrantId> = (1..=6).map(id_of).collect();
    expected.sort();
    assert_eq!(taken, expected, "each row once");
    owner_revokes(&store, DEVICE);
    assert!((1..=6).all(|number| !live(&store, number)));
}

#[test]
fn a_live_grant_below_a_revoked_unplaced_row_is_withdrawn() {
    let store = store_written_by_hand(&[
        held(1, None, OTHER_DEVICE),
        held(2, Some(1), OTHER_DEVICE),
        held(3, Some(2), OTHER_DEVICE),
    ]);
    mark_unreadable(&store, 1);
    run(
        &store,
        &format!(
            "UPDATE grants SET parent_grant_id = {} WHERE grant_id = {};
        UPDATE grants SET revoked_at_ms = 9 WHERE grant_id = {};",
            key(1),
            key(2),
            key(2)
        ),
    );
    owner_revokes(&store, DEVICE);
    assert!(!live(&store, 3));
}

/// A guard: a named grant is walked below even when it is revoked, and a device's root that is
/// revoked is not a root.
#[test]
fn a_revoked_named_grant_is_walked_below_and_a_revoked_device_root_is_not_a_root() {
    let store = store_written_by_hand(&[held(1, None, DEVICE), held(2, Some(1), OTHER_DEVICE)]);
    run(
        &store,
        &format!(
            "UPDATE grants SET revoked_at_ms = 9 WHERE grant_id = {};",
            key(1)
        ),
    );
    let scan = store.in_transaction(scan_all).expect("the scan reads");
    let named = plan_withdrawal(&scan, Roots::Grant(id_of(1)), Scope::Host).expect("planned");
    assert_eq!(named.subtrees.len(), 1);
    assert_eq!(named.subtrees[0].rows.len(), 2);
    let device =
        plan_withdrawal(&scan, Roots::Device(device_of(DEVICE)), Scope::Host).expect("planned");
    assert!(device.subtrees.is_empty());
}

#[test]
fn an_unplaced_grants_revoked_by_parent_names_its_missing_parent_and_a_cycles_top_is_null() {
    let store = store_written_by_hand(&[
        held(1, None, OTHER_DEVICE),
        held(2, Some(1), OTHER_DEVICE),
        held(5, Some(6), OTHER_DEVICE),
        held(6, Some(5), OTHER_DEVICE),
        held(7, Some(6), OTHER_DEVICE),
    ]);
    run(
        &store,
        &format!("DELETE FROM grants WHERE grant_id = {};", key(1)),
    );
    owner_revokes(&store, DEVICE);
    let by_parent = |number: u32| -> Option<Vec<u8>> {
        one(
            &store,
            &format!(
                "SELECT revoked_by_parent FROM grants WHERE grant_id = {}",
                key(number)
            ),
        )
    };
    assert_eq!(by_parent(2), Some(id_of(1).get().as_bytes().to_vec()));
    assert_eq!(
        by_parent(5),
        None,
        "a loop's first row is revoked in its own right"
    );
    assert_eq!(by_parent(6), Some(id_of(5).get().as_bytes().to_vec()));
    assert_eq!(by_parent(7), Some(id_of(5).get().as_bytes().to_vec()));
}

#[test]
fn an_owners_revocation_marks_every_damaged_row_so_the_older_reader_reads_it_revoked() {
    let store = store_written_by_hand(
        &(1..=7)
            .map(|n| held(n, None, OTHER_DEVICE))
            .collect::<Vec<_>>(),
    );
    run(
        &store,
        &format!(
            "UPDATE grants SET grant_id = X'0102' WHERE grant_id = {};
             UPDATE grants SET issued_at_ms = 'text' WHERE grant_id = {};
             UPDATE grants SET recipient_device_id = {} WHERE grant_id = {};
             UPDATE grants SET parent_grant_id = {} WHERE grant_id = {};
             UPDATE grants SET revoked_at_ms = 3, parent_grant_id = {} WHERE grant_id = {};
             UPDATE grants SET revoked_at_ms = 'text' WHERE grant_id = {};",
            key(1),
            key(2),
            device_literal(DEVICE),
            key(3),
            key(7),
            key(4),
            key(7),
            key(5),
            key(6)
        ),
    );
    run(&store, &open_invitation_on(2));
    let revocation = owner_revokes(&store, DEVICE);
    assert_eq!(
        revocation.marked, 5,
        "the four unmarked rows and the one whose mark is text"
    );
    for number in [2, 3, 4, 6] {
        assert!(
            one::<i64>(
                &store,
                &format!(
                    "SELECT typeof(revoked_at_ms) = 'integer' FROM grants WHERE grant_id = {}",
                    key(number)
                )
            ) == 1,
            "row {number} reads as revoked to the release before this one"
        );
    }
    assert_eq!(
        revoked_at(&store, 5),
        Some(3),
        "a valid mark keeps its moment"
    );
    assert_eq!(
        one::<i64>(
            &store,
            &format!(
                "SELECT COUNT(*) FROM session_invitations WHERE state = 'open' AND grant_id = {}",
                key(2)
            )
        ),
        0,
        "the invitation of a marked row is cancelled"
    );
}

/// The statement that gives grant `number` an open invitation, for the cases that cancel one.
fn open_invitation_on(number: u32) -> String {
    format!(
        "INSERT INTO session_invitations (invitation_id, issuer_device_id, grant_id,
             recipient_device_id, preview, state, issued_at_ms, expires_at_ms)
         VALUES (X'{:02x}{}', {}, {}, {}, X'00', 'open', 1000, 9999999999);",
        number,
        "00".repeat(15),
        device_literal(0xf0),
        key(number),
        device_literal(OTHER_DEVICE)
    )
}

#[test]
fn a_damaged_alias_beside_a_readable_grant_leaves_that_grants_invitation_open_and_unfenced() {
    let store = store_written_by_hand(&[held(1, None, OTHER_DEVICE), held(2, None, OTHER_DEVICE)]);
    run(&store, &open_invitation_on(1));
    // Row 2 is an alias: its key is not the grant it holds, and the grant it holds is row 1.
    run(
        &store,
        &format!(
            "UPDATE grants SET grant = (SELECT grant FROM grants WHERE grant_id = {}) WHERE grant_id = {};",
            key(1),
            key(2)
        ),
    );
    let revocation = owner_revokes(&store, DEVICE);
    assert!(live(&store, 1), "the readable grant stays live");
    assert!(!live(&store, 2), "the alias is marked");
    assert_eq!(
        one::<i64>(
            &store,
            &format!(
                "SELECT COUNT(*) FROM session_invitations WHERE state = 'open' AND grant_id = {}",
                key(1)
            )
        ),
        1,
        "the readable grant's invitation stays open"
    );
    assert!(revocation.reached.contains(&id_of(2)) && !revocation.reached.contains(&id_of(1)));
}

#[test]
fn a_repeat_of_an_owners_revocation_writes_no_row_no_name_and_no_debt() {
    let store = store_written_by_hand(&[held(1, None, DEVICE), held(2, None, OTHER_DEVICE)]);
    mark_unreadable(&store, 2);
    owner_revokes(&store, DEVICE);
    let (before, debts_before) = (
        one::<String>(
            &store,
            "SELECT group_concat(hex(grant) || ifnull(revoked_at_ms, '')) FROM grants",
        ),
        debts(&store),
    );
    let again = owner_revokes(&store, DEVICE);
    assert!(again.revoked.is_empty() && again.debt.is_none() && again.marked == 0);
    assert!(!again.reaches_every_connection);
    assert_eq!(debts(&store), debts_before);
    assert_eq!(
        one::<String>(
            &store,
            "SELECT group_concat(hex(grant) || ifnull(revoked_at_ms, '')) FROM grants"
        ),
        before
    );
}

#[test]
fn a_nameless_damaged_row_alone_owes_one_debt_and_sets_the_host_flag() {
    let store = store_written_by_hand(&[held(1, None, OTHER_DEVICE)]);
    run(
        &store,
        "UPDATE grants SET grant_id = X'0102', grant = X'00';",
    );
    let revocation = owner_revokes(&store, DEVICE);
    assert!(revocation.reaches_every_connection);
    assert!(revocation.debt.is_some());
    assert_eq!(
        debts(&store),
        1,
        "one debt, counted at the store before any barrier retires it"
    );
}

/// A guard: a sound store with nothing to withdraw writes no debt.
#[test]
fn a_revocation_that_finds_nothing_beside_a_sound_store_writes_no_debt() {
    let store = store_written_by_hand(&[held(1, None, OTHER_DEVICE)]);
    let revocation = owner_revokes(&store, DEVICE);
    assert!(revocation.revoked.is_empty() && revocation.debt.is_none());
    assert_eq!(debts(&store), 0);
}

#[test]
fn a_devices_grant_revoke_beside_a_damaged_row_withdraws_only_its_subtree() {
    let store = store_written_by_hand(&[
        held(1, None, DEVICE),
        held(2, Some(1), DEVICE),
        held(3, Some(9), OTHER_DEVICE),
        held(4, None, OTHER_DEVICE),
    ]);
    mark_unreadable(&store, 4);
    let revocation = store
        .revoke_claimed(id_of(1), Scope::Subtree, 5_000, || Ok(()), None)
        .expect("a device's revocation is not refused for another's row");
    assert_eq!(revocation.revoked, vec![id_of(1), id_of(2)]);
    assert!(
        live(&store, 3),
        "another device's unplaced grant stays live"
    );
    assert!(live(&store, 4), "the damaged row stays unmarked");
    assert_eq!(revocation.marked, 0);
    assert!(!revocation.reaches_every_connection);
    assert_eq!(revocation.withdrawn_unplaced, 0);
    assert!(!revocation.reached.contains(&id_of(4)) && !revocation.reached.contains(&id_of(3)));
}

/// A guard: a device revoking a grant whose own row is damaged is refused, and nothing is written.
#[test]
fn a_device_revoking_a_grant_whose_row_is_damaged_is_refused_as_before() {
    let store = store_written_by_hand(&[held(1, None, DEVICE)]);
    mark_unreadable(&store, 1);
    let refusal = store
        .revoke_claimed(id_of(1), Scope::Subtree, 5_000, || Ok(()), None)
        .expect_err("the named row cannot be read");
    assert!(refusal.is_a_damaged_grants_row());
    assert!(live(&store, 1));
}

#[test]
fn a_person_revoking_a_grant_beside_a_damaged_row_withdraws_it_and_what_hangs_below() {
    let store = store_written_by_hand(&[
        held(1, None, DEVICE),
        held(2, Some(1), DEVICE),
        held(3, None, OTHER_DEVICE),
    ]);
    mark_unreadable(&store, 3);
    let revocation = store
        .revoke_claimed(id_of(1), Scope::Host, 5_000, || Ok(()), None)
        .expect("the owner's revocation is not refused");
    assert_eq!(revocation.revoked, vec![id_of(1), id_of(2)]);
    assert!(!live(&store, 3));
}

#[test]
fn a_revocation_of_a_named_grant_whose_row_is_damaged_marks_it_and_withdraws_what_is_below() {
    for by_decoded_id in [false, true] {
        let store = store_written_by_hand(&[held(1, None, DEVICE), held(2, Some(1), OTHER_DEVICE)]);
        if by_decoded_id {
            run(
                &store,
                &format!(
                    "UPDATE grants SET grant_id = X'0102' WHERE grant_id = {};",
                    key(1)
                ),
            );
        } else {
            mark_unreadable(&store, 1);
        }
        let revocation = store
            .revoke_claimed(id_of(1), Scope::Host, 5_000, || Ok(()), None)
            .expect("a named row that cannot be read is marked");
        assert!(
            revocation.marked == 1 && !live(&store, 2),
            "by decoded id: {by_decoded_id}"
        );
    }
}

/// A guard: a grant no row names still says so.
#[test]
fn a_revocation_of_a_grant_no_row_names_still_says_there_is_no_such_grant() {
    let store = store_written_by_hand(&[held(1, None, DEVICE)]);
    let refusal = store
        .revoke_claimed(id_of(9), Scope::Host, 5_000, || Ok(()), None)
        .expect_err("no such grant");
    assert_eq!(refusal.to_string(), "this host holds no such grant");
}

#[test]
fn a_named_revocation_and_a_repair_walk_read_each_row_once() {
    let store = store_written_by_hand(&[
        held(1, None, DEVICE),
        held(2, Some(1), DEVICE),
        held(3, Some(2), OTHER_DEVICE),
        held(4, None, OTHER_DEVICE),
    ]);
    mark_unreadable(&store, 4);
    let rows = 4;
    for scope in [Scope::Host, Scope::Subtree] {
        let before = grant_rows_read();
        store
            .in_transaction(|connection| {
                let scan = scan_all(connection)?;
                plan_withdrawal(&scan, Roots::None, scope).map(drop)
            })
            .expect("planned");
        assert_eq!(grant_rows_read() - before, rows, "{scope:?}: the plan");
    }
    let before = grant_rows_read();
    store
        .revoke_claimed(id_of(1), Scope::Host, 5_000, || Ok(()), None)
        .expect("revoked");
    assert_eq!(
        grant_rows_read() - before,
        rows,
        "a named revocation reads each row once"
    );
}
