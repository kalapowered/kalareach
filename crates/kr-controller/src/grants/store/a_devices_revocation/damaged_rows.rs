//! A grants row this build cannot read: every reader refuses it, one judgement decides which rows
//! those are, and the scan names them by place and class.

use super::*;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The key literal of the grant numbered `number`.
pub(super) fn key(number: u32) -> String {
    format!("X'{}'", hex(id_of(number).get().as_bytes()))
}

pub(super) fn device_literal(byte: u8) -> String {
    format!("X'{}'", hex(device_of(byte).get().as_bytes()))
}

/// Runs raw SQL against the store, past what the store's own writers take.
pub(super) fn run(store: &GrantDirectory, sql: &str) {
    store
        .in_transaction(|connection| {
            connection
                .execute_batch(sql)
                .map_err(ControllerError::registry)
        })
        .expect("the raw statement runs");
}

pub(super) fn held(number: u32, parent: Option<u32>, holder: u8) -> (Node, Option<u32>) {
    (
        Node {
            number,
            parent,
            holder,
        },
        None,
    )
}

/// The statement that gives grant `number` an open invitation to `device`.
fn open_invitation(number: u32, device: u8) -> String {
    format!(
        "INSERT INTO session_invitations (invitation_id, issuer_device_id, grant_id,
             recipient_device_id, preview, state, issued_at_ms, expires_at_ms)
         VALUES (X'{:02x}{}', {}, {}, {}, X'00', 'open', 1000, 9999999999);
         UPDATE grants SET activated_at_ms = NULL WHERE grant_id = {};",
        number,
        "00".repeat(15),
        device_literal(0xf0),
        key(number),
        device_literal(device),
        key(number)
    )
}

/// The class of damage a read refused with; `None` when the read succeeded or failed for another
/// reason, so that the caller's own assertion says which.
fn class_of<T>(read: Result<T>) -> Option<DamageClass> {
    read.err().and_then(|error| error.damage_class())
}

/// Every reader of a grants row, each asked for what the damaged rows of a store hold: `device` is
/// the holder the recipient column names, `offered` the holder of the open invitation.
fn readers(
    store: &GrantDirectory,
    grant: u32,
    device: u8,
    offered: u8,
) -> Vec<(&'static str, Result<()>)> {
    let device_id = device_of(device);
    let id = id_of(grant);
    vec![
        ("record", store.record(id).map(drop)),
        ("records", store.records().map(drop)),
        (
            "records_for_device",
            store.records_for_device(device_id).map(drop),
        ),
        (
            "offers_after",
            store.offers_after(device_of(offered), None, 10).map(drop),
        ),
        (
            "shares_after",
            store.shares_after(device_id, None, 10).map(drop),
        ),
        (
            "read_one",
            store
                .in_transaction(|connection| read_one(connection, id))
                .map(drop),
        ),
        ("read_all", store.in_transaction(read_all).map(drop)),
        (
            "read_for_device",
            store
                .in_transaction(|connection| read_for_device(connection, device_id))
                .map(drop),
        ),
    ]
}

/// The class of damage that each reader refuses with, by the reader's name; `None` for a reader
/// that read the row or failed for another reason. A case asserts on this itself, so that a
/// reader that stops judging the row fails the case's own assertion.
fn classes_of(
    readers: Vec<(&'static str, Result<()>)>,
) -> Vec<(&'static str, Option<DamageClass>)> {
    readers
        .into_iter()
        .map(|(name, read)| (name, class_of(read.map(|()| 0))))
        .collect()
}

#[test]
fn a_row_whose_recipient_column_names_another_device_is_refused_by_each_reader() {
    let store = store_written_by_hand(&[
        held(1, None, DEVICE),
        held(2, None, DEVICE),
        held(3, None, DEVICE),
    ]);
    run(&store, &open_invitation(1, DEVICE));
    run(
        &store,
        &format!(
            "UPDATE grants SET recipient_device_id = {} WHERE grant_id IN ({}, {});",
            device_literal(OTHER_DEVICE),
            key(1),
            key(2)
        ),
    );
    for (name, class) in classes_of(readers(&store, 1, OTHER_DEVICE, DEVICE)) {
        assert_eq!(
            class,
            Some(DamageClass::RecipientColumnDisagrees),
            "the reader {name} refuses the row"
        );
    }
}

#[test]
fn a_row_whose_parent_column_names_another_grant_is_refused_by_each_reader_and_by_the_tree_count() {
    let store = store_written_by_hand(&[
        held(1, None, DEVICE),
        held(4, Some(1), DEVICE),
        held(2, Some(1), DEVICE),
        held(3, Some(1), DEVICE),
    ]);
    run(&store, &open_invitation(2, DEVICE));
    run(
        &store,
        &format!(
            "UPDATE grants SET parent_grant_id = {} WHERE grant_id IN ({}, {});",
            key(4),
            key(2),
            key(3)
        ),
    );
    for (name, class) in classes_of(readers(&store, 2, DEVICE, DEVICE)) {
        assert_eq!(
            class,
            Some(DamageClass::ParentColumnDisagrees),
            "the reader {name} refuses the row"
        );
    }
    let counted = store.in_transaction(|connection| live_in_tree(connection, id_of(1)));
    assert_eq!(
        class_of(counted),
        Some(DamageClass::ParentColumnDisagrees),
        "the tree count refuses the row"
    );
}

#[test]
fn a_malformed_parent_column_is_not_read_as_null() {
    let store = store_written_by_hand(&[held(1, None, DEVICE)]);
    run(
        &store,
        &format!(
            "UPDATE grants SET parent_grant_id = X'00' WHERE grant_id = {};",
            key(1)
        ),
    );
    assert_eq!(
        class_of(store.record(id_of(1))),
        Some(DamageClass::ParentColumnDisagrees)
    );
}

#[test]
fn a_column_of_another_type_is_a_damaged_row_not_a_storage_failure() {
    let store = store_written_by_hand(&[
        held(1, None, DEVICE),
        held(2, None, DEVICE),
        held(3, None, DEVICE),
    ]);
    run(
        &store,
        &format!(
            "UPDATE grants SET issued_at_ms = 'text' WHERE grant_id = {};
             UPDATE grants SET grant = 'text' WHERE grant_id = {};
             UPDATE grants SET activated_at_ms = X'00' WHERE grant_id = {};",
            key(1),
            key(2),
            key(3)
        ),
    );
    for (number, column) in [(1, "issued_at_ms"), (2, "grant"), (3, "activated_at_ms")] {
        let refusal = store.record(id_of(number)).expect_err("the row is refused");
        assert_eq!(
            refusal.damage_class(),
            Some(DamageClass::ColumnOfAnotherType(column)),
            "grant {number}"
        );
        assert_eq!(
            refusal.code(),
            kr_protocol::error::ErrorCode::StorageUnavailable,
            "grant {number}: the code the base gave a column of another type"
        );
        assert!(
            refusal.to_string().ends_with(&format!(
                "its {column} column holds a value of the wrong type"
            )),
            "grant {number}: {refusal}"
        );
    }
}

#[test]
fn a_text_revoked_moment_in_one_row_does_not_stop_a_change_of_another() {
    let store = store_written_by_hand(&[held(1, None, DEVICE), held(2, None, DEVICE)]);
    run(
        &store,
        &format!(
            "UPDATE grants SET revoked_at_ms = 'text' WHERE grant_id = {};",
            key(1)
        ),
    );
    let moment = store
        .in_transaction(|connection| next_moment(connection, 5))
        .expect("the next moment is found beside the damaged row");
    assert_eq!(moment, 5);
}

/// A guard: the shared select reads a valid offer and a valid share, and its columns are not
/// ambiguous in the join.
#[test]
fn a_valid_offer_and_a_valid_share_still_read_through_the_shared_select() {
    let store = store_written_by_hand(&[held(1, None, DEVICE), held(2, None, DEVICE)]);
    run(&store, &open_invitation(1, DEVICE));
    let offers = store
        .offers_after(device_of(DEVICE), None, 10)
        .expect("the offer reads");
    assert_eq!(offers.len(), 1);
    assert_eq!(offers[0].grant.grant.grant_id, id_of(1));
    let shares = store
        .shares_after(device_of(DEVICE), None, 10)
        .expect("the share reads");
    assert_eq!(shares.len(), 1);
    assert_eq!(shares[0].grant.grant_id, id_of(2));
}

/// One row of each class, and the scan of it: place, class, and nothing of the record's own values.
#[test]
fn the_scan_names_each_damaged_row_by_place_and_class_and_never_a_payload_value() {
    let store = store_written_by_hand(&[
        held(1, None, DEVICE),
        held(2, None, DEVICE),
        held(3, None, DEVICE),
        held(4, None, DEVICE),
        held(5, Some(1), DEVICE),
        held(6, None, DEVICE),
    ]);
    run(
        &store,
        &format!(
            "UPDATE grants SET issued_at_ms = 'text' WHERE grant_id = {};
             UPDATE grants SET grant = X'00' WHERE grant_id = {};
             UPDATE grants SET grant_id = X'0102' WHERE grant_id = {};
             UPDATE grants SET recipient_device_id = {} WHERE grant_id = {};
             UPDATE grants SET parent_grant_id = {} WHERE grant_id = {};",
            key(1),
            key(2),
            key(3),
            device_literal(OTHER_DEVICE),
            key(4),
            key(6),
            key(5)
        ),
    );
    let scan = store
        .in_transaction(scan_all)
        .expect("the scan reads the table");
    let found: Vec<(u64, DamageClass)> = scan
        .damaged
        .iter()
        .map(|row| (row.place, row.damage.class))
        .collect();
    assert_eq!(
        found,
        vec![
            (1, DamageClass::ColumnOfAnotherType("issued_at_ms")),
            (2, DamageClass::RecordDoesNotDecode),
            (3, DamageClass::KeyNamesAnotherGrant),
            (4, DamageClass::RecipientColumnDisagrees),
            (5, DamageClass::ParentColumnDisagrees),
        ]
    );
    assert_eq!(scan.readable.len(), 1, "the sixth row reads");
    for row in &scan.damaged {
        let shown = row.damage.refusal().to_string();
        for value in [
            hex(device_of(DEVICE).get().as_bytes()),
            hex(device_of(0xf0).get().as_bytes()),
        ] {
            assert!(!shown.contains(&value), "no payload value in {shown}");
        }
    }
}

/// The scan and the readers cannot disagree: a store of one faulty row is refused by the reader of
/// the whole table with the class the scan names, and a sound store by neither.
#[test]
fn the_scan_and_the_readers_agree_on_every_row() {
    let faults: Vec<(&str, String, Option<DamageClass>)> = vec![
        ("sound", String::new(), None),
        (
            "type",
            format!(
                "UPDATE grants SET session_id = 'text' WHERE grant_id = {};",
                key(1)
            ),
            Some(DamageClass::ColumnOfAnotherType("session_id")),
        ),
        (
            "decode",
            format!(
                "UPDATE grants SET grant = X'00' WHERE grant_id = {};",
                key(1)
            ),
            Some(DamageClass::RecordDoesNotDecode),
        ),
        (
            "key",
            format!(
                "UPDATE grants SET grant_id = 'text' WHERE grant_id = {};",
                key(1)
            ),
            Some(DamageClass::KeyNamesAnotherGrant),
        ),
        (
            "recipient",
            format!(
                "UPDATE grants SET recipient_device_id = X'00' WHERE grant_id = {};",
                key(1)
            ),
            Some(DamageClass::RecipientColumnDisagrees),
        ),
        (
            "parent",
            format!(
                "UPDATE grants SET parent_grant_id = {} WHERE grant_id = {};",
                key(1),
                key(1)
            ),
            Some(DamageClass::ParentColumnDisagrees),
        ),
    ];
    for (name, sql, expected) in faults {
        let store = store_written_by_hand(&[held(1, None, DEVICE)]);
        run(&store, &sql);
        let scan = store.in_transaction(scan_all).expect("the scan reads");
        let scanned = scan.damaged.first().map(|row| row.damage.class);
        let read = store.records().err().and_then(|error| error.damage_class());
        assert_eq!(scanned, expected, "{name}: the scan");
        assert_eq!(read, expected, "{name}: the reader of the whole table");
    }
}

#[test]
fn the_scan_names_a_live_grant_whose_parent_no_row_holds() {
    let live = |store: &GrantDirectory| {
        let scan = store.in_transaction(scan_all).expect("the scan reads");
        let mut numbers: Vec<GrantId> = scan
            .unplaced_live()
            .iter()
            .map(|record| record.grant.grant_id)
            .collect();
        numbers.sort();
        numbers
    };
    let by_number = |numbers: &[u32]| {
        let mut ids: Vec<GrantId> = numbers.iter().map(|number| id_of(*number)).collect();
        ids.sort();
        ids
    };
    let deleted = store_written_by_hand(&[held(1, None, DEVICE), held(2, Some(1), DEVICE)]);
    run(
        &deleted,
        &format!("DELETE FROM grants WHERE grant_id = {};", key(1)),
    );
    assert_eq!(live(&deleted), by_number(&[2]), "a row deleted by SQL");
    let cycle = store_written_by_hand(&[held(1, Some(2), DEVICE), held(2, Some(1), DEVICE)]);
    assert_eq!(live(&cycle), by_number(&[1, 2]), "a cycle");
    let middle = store_written_by_hand(&[
        held(1, None, DEVICE),
        held(2, Some(1), DEVICE),
        held(3, Some(2), DEVICE),
    ]);
    run(
        &middle,
        &format!(
            "UPDATE grants SET parent_grant_id = X'00' WHERE grant_id = {};",
            key(2)
        ),
    );
    assert_eq!(
        live(&middle),
        by_number(&[3]),
        "a readable row below a damaged middle row"
    );
}

/// A cycle of parent columns above the member, with no root on the way down: only the way up
/// reaches the row whose copy column disagrees with its record.
#[test]
fn a_tree_with_a_wrong_parent_column_on_a_revoked_middle_row_is_not_counted_on_trust() {
    let store = store_written_by_hand(&[
        held(1, None, DEVICE),
        held(2, Some(1), DEVICE),
        held(3, Some(2), DEVICE),
    ]);
    run(
        &store,
        &format!(
            "UPDATE grants SET parent_grant_id = {} WHERE grant_id = {};
             UPDATE grants SET revoked_at_ms = 7 WHERE grant_id = {};",
            key(2),
            key(1),
            key(2)
        ),
    );
    let counted = store.in_transaction(|connection| live_in_tree(connection, id_of(3)));
    assert_eq!(
        class_of(counted),
        Some(DamageClass::ParentColumnDisagrees),
        "the count refuses the tree whose row disagrees with its record"
    );
}

#[test]
fn a_row_with_two_faults_keeps_the_code_the_base_gave_it() {
    use kr_protocol::error::ErrorCode::{InvalidArgument, StorageUnavailable};
    let cases: Vec<(&str, String, DamageClass, kr_protocol::error::ErrorCode)> = vec![
        (
            "a key that is text",
            "UPDATE grants SET grant_id = 'text';".to_owned(),
            DamageClass::KeyNamesAnotherGrant,
            InvalidArgument,
        ),
        (
            "a record that does not decode and an issue time of text",
            "UPDATE grants SET grant = X'00', issued_at_ms = 'text';".to_owned(),
            DamageClass::RecordDoesNotDecode,
            InvalidArgument,
        ),
        (
            "a key naming another grant and a session of text",
            format!(
                "UPDATE grants SET grant_id = {}, session_id = 'text';",
                key(9)
            ),
            DamageClass::KeyNamesAnotherGrant,
            InvalidArgument,
        ),
        (
            "an issue time of text alone",
            "UPDATE grants SET issued_at_ms = 'text';".to_owned(),
            DamageClass::ColumnOfAnotherType("issued_at_ms"),
            StorageUnavailable,
        ),
    ];
    for (name, sql, class, code) in cases {
        let store = store_written_by_hand(&[held(1, None, DEVICE)]);
        run(&store, &sql);
        let refusal = store.records().expect_err("the row is refused");
        assert!(refusal.is_a_damaged_grants_row(), "{name}");
        assert_eq!(refusal.damage_class(), Some(class), "{name}: the class");
        assert_eq!(refusal.code(), code, "{name}: the code");
    }
}

/// A guard: a record that does not decode is refused in the decoder's own words, as it always was.
#[test]
fn the_decode_class_keeps_the_decoders_sentence() {
    let store = store_written_by_hand(&[held(1, None, DEVICE)]);
    run(
        &store,
        &format!(
            "UPDATE grants SET grant = X'00' WHERE grant_id = {};",
            key(1)
        ),
    );
    let decoder = kr_cbor::from_canonical_slice::<Grant>(&[0], &kr_cbor::Limits::DEFAULT)
        .expect_err("one byte is no grant")
        .to_string();
    let refusal = store.record(id_of(1)).expect_err("the row is refused");
    assert_eq!(
        refusal.to_string(),
        format!(
            "the grants row of grant {} cannot be read: {decoder}",
            id_of(1)
        )
    );
}
