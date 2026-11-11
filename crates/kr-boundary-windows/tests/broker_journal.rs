//! The invocation's journal: what its rows say after a crash between any two of them, the order
//! rows may come in, a torn tail, and the file that writes each row through before the step it
//! protects.
//!
//! The reading half runs everywhere on bytes. The file half runs on Windows; the case that makes a
//! private root needs an elevated SYSTEM session and runs only in a disposable guest. The marker that
//! the `Begin` row carries is read from the installed service's key, which the installation case
//! reads.

use kr_boundary_windows::filekey::FileKey;
use kr_boundary_windows::journal::framing;
use kr_boundary_windows::journal::limits;
use kr_boundary_windows::journal::replay::{
    self, Applied, OrderError, Reading, RootState, Standing, Tracker,
};
use kr_boundary_windows::journal::rows::{
    DigestedFile, LeftoverClass, RootName, RootNameError, Row, SnapshotKind,
};

#[cfg(all(windows, feature = "testing"))]
mod common;

const BOOT: &str = "11111111-1111-1111-1111-111111111111";
const ID: &str = "000102030405060708090a0b0c0d0e0f";

fn key(n: u64) -> FileKey {
    FileKey::ntfs(0xabcd, n)
}

fn root_name(n: u8) -> RootName {
    RootName::from_bytes([n; 16])
}

fn begin() -> Row {
    Row::Begin {
        invocation: ID.to_owned(),
        boot_marker: BOOT.to_owned(),
        session_luid: 7,
        group_sid: "S-1-9-1-2-3-4".to_owned(),
        client_sid: "S-1-5-21-1-2-3-1000".to_owned(),
        client_pid: 4242,
        client_creation_time: 99,
        chain: vec![key(5), key(6)],
        tree_path: r"C:\work\tree".to_owned(),
    }
}

fn snapshot(id: u32, kind: SnapshotKind) -> Row {
    Row::RepositorySnapshot {
        id,
        kind,
        config_digest: "ab".repeat(32),
        hooks: vec![DigestedFile {
            name: "hooks/pre-commit".to_owned(),
            key: key(30),
            size: 12,
            sha256: "cd".repeat(32),
        }],
        info_attributes: None,
        absent_names: vec!["info/exclude.lock".to_owned()],
    }
}

fn started() -> Row {
    Row::ProcessStarted {
        pid: 12,
        creation_time: 34,
    }
}

/// The grant's completion for an invocation that granted nothing: a process may start after it.
fn grant_done() -> Row {
    Row::GrantComplete { count: 0 }
}

fn uncertain() -> Row {
    Row::EndUncertain {
        reason: "the session is still there".to_owned(),
    }
}

fn release_intent(n: u64) -> Row {
    Row::ReleaseIntent {
        key: key(n),
        rule: kr_boundary_windows::journal::rows::Rule::Owner,
        new_owner: Some("S-1-5-21-1-2-3-1000".to_owned()),
        new_dacl_bytes: vec![1, 2, 3, 4],
        label: kr_boundary_windows::journal::rows::Label::Keep,
        protected_target: false,
    }
}

fn released(n: u64) -> Row {
    Row::ObjectReleased {
        key: key(n),
        outcome: "released".to_owned(),
    }
}

fn file_of(rows: &[Row]) -> Vec<u8> {
    rows.iter()
        .flat_map(|row| framing::encode(&row.to_bytes()).unwrap())
        .collect()
}

fn invocation(bytes: &[u8], boot: &str) -> replay::Invocation {
    match replay::read_file(ID, bytes, boot) {
        Reading::Invocation(found) => *found,
        Reading::MadeNothing => panic!("the file holds an invocation"),
    }
}

#[test]
fn every_row_reads_back_as_written() {
    let rows = vec![
        begin(),
        snapshot(1, SnapshotKind::Initial),
        Row::RootIntent { name: root_name(1) },
        Row::RootMade {
            name: root_name(1),
            key: key(9),
        },
        Row::Grant {
            key: key(10),
            path: r"C:\work\tree\f".to_owned(),
            kind: kr_boundary_windows::journal::rows::ObjectKind::File,
            owner: "S-1-5-18".to_owned(),
            dacl_bytes: vec![0, 255, 7],
            control_flags: 0x8004,
            protected: true,
            link_count: 2,
            added_ace: "A;;FA;;;S-1-9-1-2-3-4".to_owned(),
        },
        Row::GrantComplete { count: 1 },
        Row::ProcessStarted {
            pid: 12,
            creation_time: 34,
        },
        Row::JobEnded,
        release_intent(10),
        released(10),
        Row::ReleaseVerified {
            objects: 1,
            leftovers: 0,
        },
        Row::RootRemoved,
        Row::End { root_leftovers: 0 },
    ];
    let found = invocation(&file_of(&rows), BOOT);
    assert_eq!(found.damage, None);
    assert_eq!(found.rows, rows);
    assert_eq!(found.standing, Standing::Finished);
}

#[test]
fn a_crash_after_the_root_intent_and_before_the_made_row_leaves_the_root_in_doubt() {
    let found = invocation(
        &file_of(&[begin(), Row::RootIntent { name: root_name(1) }]),
        BOOT,
    );
    assert_eq!(found.standing, Standing::Unfinished);
    assert_eq!(found.tracker.root(), &RootState::IntentOnly(root_name(1)));
    assert!(found.tracker.holds_the_slot());
}

#[test]
fn a_release_begun_and_not_written_is_pending_and_blocks_the_verification() {
    let found = invocation(
        &file_of(&[
            begin(),
            release_intent(10),
            released(10),
            release_intent(11),
        ]),
        BOOT,
    );
    assert_eq!(found.standing, Standing::Unfinished);
    assert_eq!(found.tracker.pending_releases(), vec![key(11)]);
    let mut tracker = found.tracker.clone();
    assert!(
        tracker
            .apply(&Row::ReleaseVerified {
                objects: 2,
                leftovers: 0
            })
            .is_err(),
        "the release is not verified while an object's release is not written"
    );
    tracker.apply(&released(11)).unwrap();
    tracker
        .apply(&Row::ReleaseVerified {
            objects: 2,
            leftovers: 0,
        })
        .unwrap();
}

#[test]
fn a_leftover_comes_before_the_end_and_an_end_out_of_order_is_refused() {
    let mut tracker = Tracker::new();
    tracker.apply(&begin()).unwrap();
    tracker.apply(&snapshot(1, SnapshotKind::Initial)).unwrap();
    assert!(
        tracker.apply(&Row::End { root_leftovers: 0 }).is_err(),
        "no end before the release was verified"
    );
    tracker.apply(&snapshot(2, SnapshotKind::Changed)).unwrap();
    tracker
        .apply(&Row::Leftover {
            object: "hooks/post-checkout".to_owned(),
            reason: "the hook changed".to_owned(),
            class: LeftoverClass::Repository,
            snapshot: Some(2),
        })
        .unwrap();
    assert!(
        tracker
            .apply(&Row::ReleaseVerified {
                objects: 0,
                leftovers: 0
            })
            .is_err(),
        "the release is not verified while a leftover is open"
    );
    assert!(
        tracker.apply(&Row::End { root_leftovers: 0 }).is_err(),
        "no end while a leftover that holds the slot is open"
    );
    assert!(tracker.holds_the_slot());
}

/// Rows that bring a tracker to the point a refusal is shown from, and the row that is refused there.
fn refused_after(rows: &[Row], refused: &Row) -> bool {
    let mut tracker = Tracker::new();
    for row in rows {
        tracker.apply(row).expect("the setup rows are in order");
    }
    tracker.apply(refused).is_err()
}

#[test]
fn every_row_that_comes_out_of_order_is_refused() {
    let intent = |n: u8| Row::RootIntent { name: root_name(n) };
    let verified = Row::ReleaseVerified {
        objects: 0,
        leftovers: 0,
    };
    let leftover = |class| Row::Leftover {
        object: "x".to_owned(),
        reason: "r".to_owned(),
        class,
        snapshot: None,
    };
    let cases: Vec<(&str, Vec<Row>, Row)> = vec![
        ("a first row that does not begin", vec![], intent(1)),
        ("a second beginning", vec![begin()], begin()),
        (
            "a snapshot written twice",
            vec![begin(), snapshot(1, SnapshotKind::Initial)],
            snapshot(1, SnapshotKind::Changed),
        ),
        ("a second root", vec![begin(), intent(1)], intent(2)),
        (
            "a root made without its intent",
            vec![begin()],
            Row::RootMade {
                name: root_name(1),
                key: key(9),
            },
        ),
        (
            "a root made under another name than its intent",
            vec![begin(), intent(1)],
            Row::RootMade {
                name: root_name(2),
                key: key(9),
            },
        ),
        (
            "an object granted after the grant was complete",
            vec![begin(), Row::GrantComplete { count: 0 }],
            Row::Grant {
                key: key(1),
                path: "p".to_owned(),
                kind: kr_boundary_windows::journal::rows::ObjectKind::File,
                owner: "o".to_owned(),
                dacl_bytes: vec![],
                control_flags: 0,
                protected: false,
                link_count: 1,
                added_ace: "a".to_owned(),
            },
        ),
        (
            "a grant complete twice",
            vec![begin(), Row::GrantComplete { count: 0 }],
            Row::GrantComplete { count: 0 },
        ),
        (
            "a grant that counts other objects than the rows hold",
            vec![begin()],
            Row::GrantComplete { count: 1 },
        ),
        (
            "a second primary process",
            vec![
                begin(),
                grant_done(),
                Row::ProcessStarted {
                    pid: 1,
                    creation_time: 2,
                },
            ],
            Row::ProcessStarted {
                pid: 3,
                creation_time: 4,
            },
        ),
        (
            "an uncertain end after the end",
            vec![begin(), verified.clone(), Row::End { root_leftovers: 0 }],
            Row::EndUncertain {
                reason: "r".to_owned(),
            },
        ),
        (
            "a release begun while the end is not proved",
            vec![
                begin(),
                Row::EndUncertain {
                    reason: "r".to_owned(),
                },
            ],
            release_intent(1),
        ),
        (
            "a release begun while a process that started has no proved end",
            vec![begin(), grant_done(), started()],
            release_intent(1),
        ),
        (
            "a release verified while the end is not proved (an uncertain end, then the verification)",
            vec![begin(), uncertain()],
            verified.clone(),
        ),
        (
            "a release verified while a process that started has no proved end",
            vec![begin(), grant_done(), started()],
            verified.clone(),
        ),
        (
            "a root removed while the end is not proved",
            vec![
                begin(),
                Row::RootIntent { name: root_name(1) },
                Row::RootMade {
                    name: root_name(1),
                    key: key(9),
                },
                uncertain(),
            ],
            Row::RootRemoved,
        ),
        (
            "an end while the end is not proved",
            vec![begin(), verified.clone(), uncertain()],
            Row::End { root_leftovers: 0 },
        ),
        (
            "an end after a release began that voided the verification",
            vec![begin(), verified.clone(), release_intent(1)],
            Row::End { root_leftovers: 0 },
        ),
        (
            "an end after a release that was begun and written, with no new verification",
            vec![begin(), verified.clone(), release_intent(1), released(1)],
            Row::End { root_leftovers: 0 },
        ),
        (
            "an object released without its intent",
            vec![begin()],
            released(1),
        ),
        (
            "a root removed that was not made",
            vec![begin()],
            Row::RootRemoved,
        ),
        (
            "a state accepted that no leftover names",
            vec![begin(), snapshot(1, SnapshotKind::Changed)],
            Row::AcceptedState {
                snapshot: 1,
                person: "p".to_owned(),
                time: 1,
            },
        ),
        (
            "a leftover cleared that was not open",
            vec![begin()],
            Row::LeftoverCleared {
                key: "x".to_owned(),
            },
        ),
        (
            "an end twice",
            vec![begin(), verified.clone(), Row::End { root_leftovers: 0 }],
            Row::End { root_leftovers: 0 },
        ),
        (
            "an end that counts other root leftovers than the rows hold",
            vec![begin(), verified, leftover(LeftoverClass::Root)],
            Row::End { root_leftovers: 0 },
        ),
    ];
    for (what, rows, row) in cases {
        assert!(refused_after(&rows, &row), "{what} is refused");
    }
}

/// Applies every row in turn, each of which must be accepted.
fn tracker_after(rows: &[Row]) -> Tracker {
    let mut tracker = Tracker::new();
    for row in rows {
        tracker
            .apply(row)
            .unwrap_or_else(|error| panic!("{row:?} is in order: {error}"));
    }
    tracker
}

#[test]
fn a_proved_end_is_required_after_a_process_started_or_an_uncertain_end_and_then_the_release_goes_on()
 {
    let verified = Row::ReleaseVerified {
        objects: 1,
        leftovers: 0,
    };
    // After a process started, the job's end is the proof.
    let tracker = tracker_after(&[
        begin(),
        Row::Grant {
            key: key(1),
            path: "p".to_owned(),
            kind: kr_boundary_windows::journal::rows::ObjectKind::File,
            owner: "o".to_owned(),
            dacl_bytes: vec![],
            control_flags: 0,
            protected: false,
            link_count: 1,
            added_ace: "a".to_owned(),
        },
        Row::GrantComplete { count: 1 },
        started(),
        Row::JobEnded,
        release_intent(1),
        released(1),
        verified.clone(),
        Row::End { root_leftovers: 0 },
    ]);
    assert_eq!(tracker.standing(), Standing::Finished);
    // After an uncertain end that a later try proved, the release is journalled.
    let tracker = tracker_after(&[begin(), grant_done(), started(), uncertain()]);
    assert_eq!(tracker.standing(), Standing::Uncertain);
    let tracker = tracker_after(&[
        begin(),
        grant_done(),
        started(),
        uncertain(),
        uncertain(),
        Row::JobEnded,
        release_intent(1),
        released(1),
        verified,
        Row::End { root_leftovers: 0 },
    ]);
    assert_eq!(tracker.standing(), Standing::Finished);
    // A job that never had a process needs no proof of its end.
    let tracker = tracker_after(&[
        begin(),
        Row::ReleaseVerified {
            objects: 0,
            leftovers: 0,
        },
        Row::End { root_leftovers: 0 },
    ]);
    assert_eq!(tracker.standing(), Standing::Finished);
}

#[test]
fn a_release_that_begins_after_the_verification_voids_it() {
    let verified = Row::ReleaseVerified {
        objects: 0,
        leftovers: 0,
    };
    let mut tracker = tracker_after(&[begin(), verified.clone(), release_intent(1)]);
    assert!(tracker.apply(&Row::End { root_leftovers: 0 }).is_err());
    tracker.apply(&released(1)).unwrap();
    assert!(tracker.apply(&Row::End { root_leftovers: 0 }).is_err());
    tracker.apply(&verified).unwrap();
    tracker.apply(&Row::End { root_leftovers: 0 }).unwrap();
}

fn grant(n: u64) -> Row {
    Row::Grant {
        key: key(n),
        path: format!(r"C:\work\tree\f{n}"),
        kind: kr_boundary_windows::journal::rows::ObjectKind::File,
        owner: "S-1-5-21-1-2-3-1000".to_owned(),
        dacl_bytes: vec![1, 2, 3, 4],
        control_flags: 0,
        protected: false,
        link_count: 1,
        added_ace: "A;;FA;;;S-1-9-1-2-3-4".to_owned(),
    }
}

fn verified(objects: u64) -> Row {
    Row::ReleaseVerified {
        objects,
        leftovers: 0,
    }
}

fn tree_leftover(object: &str) -> Row {
    Row::Leftover {
        object: object.to_owned(),
        reason: "in use".to_owned(),
        class: LeftoverClass::Tree,
        snapshot: None,
    }
}

#[test]
fn after_a_verification_no_grant_no_process_and_no_root_begins() {
    let intent = Row::RootIntent { name: root_name(1) };
    let made = Row::RootMade {
        name: root_name(1),
        key: key(9),
    };
    let cases: Vec<(&str, Vec<Row>, Row)> = vec![
        ("a grant", vec![begin(), verified(0)], grant(1)),
        (
            "a grant after a release began that voided the verification",
            vec![begin(), verified(0), release_intent(1)],
            grant(2),
        ),
        (
            "a grant after the verification was voided and written again",
            vec![
                begin(),
                verified(0),
                release_intent(1),
                released(1),
                verified(0),
            ],
            grant(2),
        ),
        (
            "the grant's completion",
            vec![begin(), verified(0)],
            grant_done(),
        ),
        (
            "a process",
            vec![begin(), grant_done(), verified(0)],
            started(),
        ),
        (
            "a root's intent",
            vec![begin(), verified(0)],
            intent.clone(),
        ),
        ("a root made", vec![begin(), intent, verified(0)], made),
    ];
    for (what, rows, row) in cases {
        assert!(
            refused_after(&rows, &row),
            "{what} after a verification is refused"
        );
    }
    // A verification with no grant, then a grant after it, would end in a finished invocation
    // with a granted key nobody releases; here it stops at the grant.
    let mut tracker = Tracker::new();
    for row in [begin(), verified(0)] {
        tracker.apply(&row).unwrap();
    }
    assert!(tracker.apply(&grant(1)).is_err());
    assert!(tracker.apply(&Row::End { root_leftovers: 0 }).is_ok());
}

#[test]
fn a_verification_is_refused_while_a_granted_key_has_neither_its_release_nor_a_tree_leftover() {
    let granted = |count: u64| {
        let mut rows = vec![begin()];
        rows.extend((1..=count).map(grant));
        rows.push(Row::GrantComplete { count });
        rows
    };
    // The second sequence: granted, started, ended, verified, and no row for the key.
    let mut rows = granted(1);
    rows.extend([started(), Row::JobEnded]);
    assert!(
        refused_after(&rows, &verified(0)),
        "the key was never released"
    );
    // One released and one not.
    let mut rows = granted(2);
    rows.extend([release_intent(1), released(1)]);
    assert!(
        refused_after(&rows, &verified(1)),
        "the second key was never released"
    );
    // The release of each key is the way through.
    let mut rows = granted(2);
    rows.extend([
        release_intent(1),
        released(1),
        release_intent(2),
        released(2),
    ]);
    let tracker = tracker_after(
        &[
            rows.clone(),
            vec![verified(2), Row::End { root_leftovers: 0 }],
        ]
        .concat(),
    );
    assert_eq!(tracker.standing(), Standing::Finished);
    // So is a leftover of the tree that names the key by its text or by its path, once cleared (an
    // open one refuses the verification by itself).
    for object in [key(1).to_string(), grant_path(1)] {
        let mut rows = granted(1);
        rows.push(tree_leftover(&object));
        assert!(
            refused_after(&rows, &verified(0)),
            "an open leftover refuses it"
        );
        rows.push(Row::LeftoverCleared { key: object });
        tracker_after(&[rows, vec![verified(0)]].concat());
    }
    // A leftover that names another object does not cover the key.
    let mut rows = granted(1);
    rows.extend([
        tree_leftover("somewhere else"),
        Row::LeftoverCleared {
            key: "somewhere else".to_owned(),
        },
    ]);
    assert!(refused_after(&rows, &verified(0)));
    // A leftover of the private root is not a leftover of the tree.
    let mut rows = granted(1);
    rows.push(Row::Leftover {
        object: key(1).to_string(),
        reason: "in use".to_owned(),
        class: LeftoverClass::Root,
        snapshot: None,
    });
    assert!(refused_after(&rows, &verified(0)));
}

#[test]
fn a_grant_after_a_release_of_the_same_key_needs_its_own_release_and_is_refused_while_a_release_is_pending()
 {
    let granted_twice = [
        begin(),
        grant(1),
        release_intent(1),
        released(1),
        grant(1),
        Row::GrantComplete { count: 2 },
        started(),
        Row::JobEnded,
    ];
    // The release that came before the second grant undid the first, so the verification does not
    // cover the key until a release follows the second grant.
    assert!(
        refused_after(&granted_twice, &verified(1)),
        "the second grant of the key was never released"
    );
    let mut rows = granted_twice.to_vec();
    rows.extend([release_intent(1), released(1)]);
    let mut tracker = tracker_after(&rows);
    tracker.apply(&verified(1)).unwrap();
    tracker.apply(&Row::End { root_leftovers: 0 }).unwrap();

    // A grant of a key whose release is begun and not written is refused.
    assert!(refused_after(
        &[begin(), grant(1), release_intent(1)],
        &grant(1)
    ));
    // Once written, the grant is accepted.
    tracker_after(&[begin(), grant(1), release_intent(1), released(1), grant(1)]);
}

#[test]
fn an_invocation_whose_root_still_stands_stays_in_the_recovery_after_its_last_leftover_is_cleared()
{
    let root_leftover = Row::Leftover {
        object: "tmp/held".to_owned(),
        reason: "in use".to_owned(),
        class: LeftoverClass::Root,
        snapshot: None,
    };
    let cleared = Row::LeftoverCleared {
        key: "tmp/held".to_owned(),
    };
    for (what, root) in [
        (
            "made",
            vec![
                Row::RootIntent { name: root_name(1) },
                Row::RootMade {
                    name: root_name(1),
                    key: key(9),
                },
            ],
        ),
        ("intended", vec![Row::RootIntent { name: root_name(1) }]),
    ] {
        let mut rows = vec![begin()];
        rows.extend(root);
        rows.extend([
            root_leftover.clone(),
            verified(0),
            Row::End { root_leftovers: 1 },
        ]);
        assert!(invocation(&file_of(&rows), BOOT).needs_recovery());
        // The crash prefix: the leftover was cleared and the row that records the removal of the
        // root did not reach the file.
        rows.push(cleared.clone());
        let found = invocation(&file_of(&rows), BOOT);
        assert_eq!(found.standing, Standing::Finished);
        assert!(found.tracker.leftovers().is_empty());
        assert!(
            found.needs_recovery(),
            "the root is still {what}, so the sweep has work to do"
        );
        // The removal is recorded: nothing is left.
        rows.push(Row::RootRemoved);
        assert!(!invocation(&file_of(&rows), BOOT).needs_recovery());
    }
}

#[test]
fn an_uncertain_end_after_a_verification_voids_it_and_it_is_written_again_after_the_end_is_proved()
{
    let rows = [begin(), grant_done(), started(), Row::JobEnded, verified(0)];
    let mut tracker = tracker_after(&rows);
    tracker.apply(&uncertain()).unwrap();
    tracker.apply(&Row::JobEnded).unwrap();
    assert!(
        tracker.apply(&Row::End { root_leftovers: 0 }).is_err(),
        "the end was in doubt after the verification, which no longer holds"
    );
    tracker.apply(&verified(0)).unwrap();
    tracker.apply(&Row::End { root_leftovers: 0 }).unwrap();
}

fn grant_path(n: u64) -> String {
    match grant(n) {
        Row::Grant { path, .. } => path,
        _ => unreachable!(),
    }
}

#[test]
fn a_process_starts_only_after_the_grant_is_complete() {
    assert!(refused_after(&[begin()], &started()), "no grant at all");
    assert!(
        refused_after(&[begin(), grant(1)], &started()),
        "a grant that is not complete"
    );
    tracker_after(&[
        begin(),
        grant(1),
        Row::GrantComplete { count: 1 },
        started(),
    ]);
}

#[test]
fn a_root_with_its_intent_alone_can_have_its_removal_recorded_and_no_end_leaves_a_root_standing() {
    let intent = Row::RootIntent { name: root_name(1) };
    let made = Row::RootMade {
        name: root_name(1),
        key: key(9),
    };
    let root_leftover = Row::Leftover {
        object: "tmp/held".to_owned(),
        reason: "in use".to_owned(),
        class: LeftoverClass::Root,
        snapshot: None,
    };
    // A recovery that finds the directory absent, or removes it, records the removal.
    let tracker = tracker_after(&[begin(), intent.clone(), Row::RootRemoved]);
    assert_eq!(tracker.root(), &RootState::Removed);
    // An end with the root standing and no leftover that says what is left is refused, whether the
    // root was made or only begun.
    assert!(refused_after(
        &[begin(), intent.clone(), verified(0)],
        &Row::End { root_leftovers: 0 }
    ));
    assert!(refused_after(
        &[begin(), intent.clone(), made.clone(), verified(0)],
        &Row::End { root_leftovers: 0 }
    ));
    // With the removal recorded, or with a leftover of the root, it comes.
    tracker_after(&[
        begin(),
        intent.clone(),
        made.clone(),
        Row::RootRemoved,
        verified(0),
        Row::End { root_leftovers: 0 },
    ]);
    // A sequence that can follow a crash after the directory was made: the directory may exist, its removal failed, the invocation ended
    // carrying the leftover, and a later sweep can still record the removal.
    let mut tracker = tracker_after(&[
        begin(),
        intent,
        Row::JobEnded,
        root_leftover,
        verified(0),
        Row::End { root_leftovers: 1 },
    ]);
    assert_eq!(tracker.standing(), Standing::Finished);
    tracker
        .apply(&Row::LeftoverCleared {
            key: "tmp/held".to_owned(),
        })
        .unwrap();
    tracker.apply(&Row::RootRemoved).unwrap();
    assert_eq!(tracker.root(), &RootState::Removed);
    assert!(
        refused_after(&[begin()], &Row::RootRemoved),
        "a root never begun"
    );
}

/// A path of the longest length a row takes, each unit of three bytes in a row, and a different one
/// for each `n`.
fn worst_path(n: u64) -> String {
    let tail = format!("{n:08}");
    format!(
        "{}{tail}",
        "\u{6f22}".repeat(limits::PATH_UNITS - tail.len())
    )
}

/// The longest identifier text a row takes.
fn worst_sid() -> String {
    format!("S-1-5-{}", "4294967295-".repeat(15))
        .trim_end_matches('-')
        .to_owned()
}

fn worst_grant(n: u64, list_bytes: usize) -> Row {
    Row::Grant {
        key: key(n),
        path: worst_path(n),
        kind: kr_boundary_windows::journal::rows::ObjectKind::File,
        owner: worst_sid(),
        dacl_bytes: vec![0xab; list_bytes],
        control_flags: u16::MAX,
        protected: true,
        link_count: u32::MAX,
        added_ace: "x".repeat(limits::TEXT_BYTES),
    }
}

fn worst_intent(n: u64, list_bytes: usize) -> Row {
    Row::ReleaseIntent {
        key: key(n),
        rule: kr_boundary_windows::journal::rows::Rule::Owner,
        new_owner: Some(worst_sid()),
        new_dacl_bytes: vec![0xcd; list_bytes],
        label: kr_boundary_windows::journal::rows::Label::Remove,
        protected_target: true,
    }
}

fn worst_released(n: u64) -> Row {
    Row::ObjectReleased {
        key: key(n),
        outcome: "o".repeat(limits::TEXT_BYTES),
    }
}

fn worst_leftover(object: String, class: LeftoverClass, snapshot: Option<u32>) -> Row {
    Row::Leftover {
        object,
        reason: "r".repeat(limits::TEXT_BYTES),
        class,
        snapshot,
    }
}

fn worst_begin() -> Row {
    Row::Begin {
        invocation: ID.to_owned(),
        boot_marker: BOOT.to_owned(),
        session_luid: u64::MAX,
        group_sid: worst_sid(),
        client_sid: worst_sid(),
        client_pid: u32::MAX,
        client_creation_time: u64::MAX,
        chain: (0..limits::CHAIN_KEYS as u64).map(key).collect(),
        tree_path: worst_path(0),
    }
}

fn worst_snapshot(id: u32) -> Row {
    let file = |n: u64| DigestedFile {
        name: "n".repeat(limits::NAME_BYTES),
        key: key(n),
        size: u64::MAX,
        sha256: "cd".repeat(32),
    };
    Row::RepositorySnapshot {
        id,
        kind: SnapshotKind::Changed,
        config_digest: "ab".repeat(32),
        hooks: (0..limits::HOOKS as u64).map(file).collect(),
        info_attributes: Some(file(7)),
        absent_names: vec!["a".repeat(limits::NAME_BYTES); limits::ABSENT_NAMES],
    }
}

#[test]
fn every_row_kind_has_an_enforced_largest_size_and_a_field_over_its_cap_is_refused_with_words() {
    // Each row at the caps of its fields is within its kind's largest size and is taken.
    let mut tracker = Tracker::new();
    for row in [
        worst_begin(),
        worst_snapshot(1),
        Row::RootIntent { name: root_name(1) },
        worst_grant(1, limits::LIST_BYTES),
        Row::GrantComplete { count: 1 },
        started(),
        Row::EndUncertain {
            reason: "e".repeat(limits::TEXT_BYTES),
        },
        Row::JobEnded,
        worst_intent(1, limits::LIST_BYTES),
        worst_released(1),
        worst_leftover(worst_path(2), LeftoverClass::Root, None),
    ] {
        row.check_caps()
            .unwrap_or_else(|why| panic!("{:?} at its caps: {why}", row.kind()));
        assert!(
            row.to_bytes().len() <= row.kind().max_encoded(),
            "{:?} takes {} bytes, over its largest size {}",
            row.kind(),
            row.to_bytes().len(),
            row.kind().max_encoded()
        );
        tracker
            .apply(&row)
            .unwrap_or_else(|why| panic!("{:?}: {why}", row.kind()));
    }
    // One step over a cap is refused, with words that say which cap, and nothing is changed.
    let mut long_path = worst_grant(1, 4);
    if let Row::Grant { path, .. } = &mut long_path {
        path.push('x');
    }
    let begun = |row: Row| {
        let mut tracker = Tracker::new();
        tracker.apply(&begin()).unwrap();
        tracker.apply(&row)
    };
    let text = begun(long_path).unwrap_err().to_string();
    assert!(text.contains("longer than 1024 characters"), "{text}");
    let text = begun(worst_grant(1, limits::LIST_BYTES + 1))
        .unwrap_err()
        .to_string();
    assert!(text.contains("4096"), "{text}");
    let text = begun(Row::ObjectReleased {
        key: key(1),
        outcome: "o".repeat(limits::TEXT_BYTES + 1),
    })
    .unwrap_err()
    .to_string();
    assert!(
        text.contains("an outcome is longer than 256 bytes"),
        "{text}"
    );
    let text = begun(Row::EndUncertain {
        reason: "e".repeat(limits::TEXT_BYTES + 1),
    })
    .unwrap_err()
    .to_string();
    assert!(text.contains("a reason is longer than 256 bytes"), "{text}");
    let text = begun(worst_intent(1, limits::LIST_BYTES + 1))
        .unwrap_err()
        .to_string();
    assert!(text.contains("4096"), "{text}");
    let mut chain = worst_begin();
    if let Row::Begin { chain, .. } = &mut chain {
        chain.push(key(999));
    }
    let text = Tracker::new().apply(&chain).unwrap_err().to_string();
    assert!(text.contains("256 directories"), "{text}");
    let mut many = worst_snapshot(1);
    if let Row::RepositorySnapshot { hooks, .. } = &mut many {
        hooks.push(hooks[0].clone());
    }
    let text = begun(many).unwrap_err().to_string();
    assert!(text.contains("more than 128 hooks"), "{text}");
    // A path with a control character is not one the journal records.
    let mut odd = worst_grant(1, 4);
    if let Row::Grant { path, .. } = &mut odd {
        *path = "C:\\a\u{7}b".to_owned();
    }
    assert!(
        begun(odd)
            .unwrap_err()
            .to_string()
            .contains("control character")
    );
    // What a writer builds goes through the cut, so a long message is never a refusal.
    let message = "m".repeat(5_000);
    let row = Row::EndUncertain {
        reason: limits::short(&message),
    };
    row.check_caps().unwrap();
}

/// A tracker with the rows applied, each of which must be taken.
fn writer_after(limit: usize, rows: &[Row]) -> Tracker {
    let mut tracker = Tracker::bounded(limit);
    for row in rows {
        tracker
            .apply(row)
            .unwrap_or_else(|error| panic!("{:?} is taken: {error}", row.kind()));
    }
    tracker
}

/// The rows a case's writer has had taken, with the tracker that took them, and the check that the
/// room of the rows of objects is never over its budget.
struct Driver {
    tracker: Tracker,
    rows: Vec<Row>,
    limit: usize,
}

impl Driver {
    fn new(limit: usize) -> Driver {
        Driver {
            tracker: Tracker::bounded(limit),
            rows: Vec::new(),
            limit,
        }
    }

    fn put(&mut self, row: Row) -> Result<Applied, OrderError> {
        let applied = self.tracker.apply(&row)?;
        if applied == Applied::Written {
            self.rows.push(row);
        }
        let (spent, kept) = self.tracker.budget();
        assert!(
            spent + kept <= self.limit,
            "the rows of objects ({spent}) and what is kept for them ({kept}) are over the budget {}",
            self.limit
        );
        assert!(
            self.tracker.ceiling() <= limits::MAX_FILE,
            "the file may become {} bytes, over {}",
            self.tracker.ceiling(),
            limits::MAX_FILE
        );
        Ok(applied)
    }

    fn put_ok(&mut self, row: Row) {
        let kind = row.kind();
        self.put(row)
            .unwrap_or_else(|error| panic!("{kind:?} is taken: {error}"));
    }
}

#[test]
fn a_writer_driven_to_its_limit_with_the_worst_rows_of_every_kind_makes_a_file_that_reads_back() {
    let mut finished = 0;
    for limit in [1_500_000_usize, 3_500_000, 6_000_000] {
        let mut driver = Driver::new(limit);
        driver.put_ok(worst_begin());
        for id in 1..=limits::SNAPSHOTS {
            driver.put_ok(worst_snapshot(id));
        }
        driver.put_ok(Row::RootIntent { name: root_name(1) });
        driver.put_ok(Row::RootMade {
            name: root_name(1),
            key: key(9),
        });

        // Grants of the longest paths, each with a full list or a short one, until the journal has
        // no room: the grant is refused before it is written, with words for the person.
        let mut granted = Vec::new();
        for n in 1_u64.. {
            let list = if n % 2 == 1 { limits::LIST_BYTES } else { 300 };
            match driver.put(worst_grant(n, list)) {
                Ok(_) => granted.push((n, list)),
                Err(OrderError::NoRoom(words)) => {
                    assert!(words.contains("too large for the journal"), "{words}");
                    break;
                }
                Err(other) => panic!("{other}"),
            }
        }
        assert!(granted.len() > 8, "{limit}: {} objects", granted.len());
        driver.put_ok(Row::GrantComplete {
            count: granted.len() as u64,
        });
        driver.put_ok(started());
        driver.put_ok(Row::JobEnded);

        // Each granted object is released in one of four ways, all at their worst.
        // The objects whose release records a leftover that names them by their longest path go
        // first, so that what they take is not hidden by the room that the other ways give back.
        let mut order = granted.clone();
        order.sort_by_key(|&(n, _)| (n % 4 != 2, n));
        let mut refused_list = 0;
        for &(n, list) in &order {
            match n % 4 {
                // A full list released: the intent at the cap, and the longest result.
                1 => {
                    driver.put_ok(worst_intent(n, list));
                    driver.put_ok(worst_released(n));
                }
                // A list that grew after its grant, past the room kept for it: the intent is
                // refused and the object keeps its state, recorded as a leftover that names it by
                // its path; the retry is a row that starts work and takes room only if there is
                // room, and a release that then comes is cleared.
                2 => {
                    match driver.put(worst_intent(n, list + limits::LIST_GROWTH + 100)) {
                        Err(OrderError::NoRoom(words)) => {
                            assert!(words.contains("has grown past the room"), "{words}");
                            refused_list += 1;
                        }
                        other => panic!("an intent over its room was not refused: {other:?}"),
                    }
                    driver.put_ok(worst_leftover(worst_path(n), LeftoverClass::Tree, None));
                    if driver.put(worst_intent(n, list)).is_ok() {
                        driver.put_ok(worst_released(n));
                    }
                }
                // A release that fails before its intent: a leftover that names the key.
                3 => {
                    driver.put_ok(worst_leftover(
                        key(n).to_string(),
                        LeftoverClass::Tree,
                        None,
                    ));
                }
                // A list at the edge of its room.
                _ => {
                    driver.put_ok(worst_intent(n, list + limits::LIST_GROWTH));
                    driver.put_ok(worst_released(n));
                }
            }
        }
        assert!(refused_list > 0, "a list that grew was refused");

        // Objects the invocation made have no grant row: their intents are paid from what the
        // grants left, until none is left. Every fifth fails once and is tried again, which
        // is a row that starts work and takes room only if there is room.
        let mut made_refused = 0;
        let mut unresolved = false;
        for m in 0_u64..10_000 {
            let n = 1_000_000 + m;
            match driver.put(worst_intent(n, 600)) {
                Ok(_) if m % 5 == 0 => {
                    driver.put_ok(worst_leftover(
                        key(n).to_string(),
                        LeftoverClass::Tree,
                        None,
                    ));
                    if driver.put(worst_intent(n, 600)).is_ok() {
                        driver.put_ok(worst_released(n));
                        driver.put_ok(Row::LeftoverCleared {
                            key: key(n).to_string(),
                        });
                    } else {
                        unresolved = true;
                        made_refused += 1;
                        break;
                    }
                }
                Ok(_) => driver.put_ok(worst_released(n)),
                Err(OrderError::NoRoom(words)) => {
                    assert!(words.contains("no room left"), "{words}");
                    made_refused += 1;
                    break;
                }
                Err(other) => panic!("{other}"),
            }
        }
        assert_eq!(
            made_refused, 1,
            "{limit}: the objects that were made use up the room"
        );
        // The release that could not be journalled is one leftover for the tree.
        driver.put_ok(worst_leftover(worst_path(0), LeftoverClass::Tree, None));

        // Everything open is cleared, the root is removed, and the invocation is verified and ends;
        // an object whose retry found no room keeps its release unwritten, so the invocation stays
        // unfinished with its tree blocked, which is what the rows say.
        let open: Vec<String> = driver
            .tracker
            .leftovers()
            .iter()
            .map(|leftover| leftover.object.clone())
            .collect();
        for object in open {
            driver.put_ok(Row::LeftoverCleared { key: object });
        }
        driver.put_ok(Row::RootRemoved);
        if unresolved {
            assert!(driver.put(verified(0)).is_err());
        } else {
            driver.put_ok(verified(0));
            driver.put_ok(Row::End { root_leftovers: 0 });
            finished += 1;
        }

        // The file that the writer made is within the bound, and the reader reads it back whole.
        let file = file_of(&driver.rows);
        assert!(
            file.len() <= limit + limits::CLOSING,
            "{limit}: the file is {} bytes, over its budget and the rows apart from objects",
            file.len()
        );
        assert!(file.len() <= limits::MAX_FILE);
        let found = invocation(&file, BOOT);
        assert_eq!(found.damage, None, "{limit}");
        assert_eq!(
            found.standing,
            if unresolved {
                Standing::Unfinished
            } else {
                Standing::Finished
            },
            "{limit}"
        );
        assert_eq!(found.rows.len(), driver.rows.len());
    }
    assert!(finished > 0, "a journal at its limit still reaches its end");
}

#[test]
fn a_refused_grant_changes_nothing_and_more_room_never_grants_fewer_objects() {
    let mut counts = Vec::new();
    for limit in (0..40).map(|step| step * 40_000_usize) {
        let mut tracker = Tracker::bounded(limit);
        tracker.apply(&begin()).unwrap();
        let mut granted = 0_u64;
        for n in 1..=200 {
            if tracker.apply(&grant(n)).is_err() {
                break;
            }
            granted += 1;
        }
        counts.push(granted);
        // The refusal left the tracker as it was: the grant is complete with what was granted.
        tracker
            .apply(&Row::GrantComplete { count: granted })
            .unwrap();
    }
    assert_eq!(
        counts[0], 0,
        "a bound too small for any object stops the grant"
    );
    assert_eq!(*counts.last().unwrap(), 200, "a roomy bound stops nothing");
    assert!(
        counts.windows(2).all(|pair| pair[0] <= pair[1]),
        "more room never grants fewer objects: {counts:?}"
    );
}

#[test]
fn a_tree_over_the_most_objects_the_journal_records_is_refused_with_words() {
    let mut tracker = Tracker::bounded(usize::MAX / 2);
    tracker.apply(&begin()).unwrap();
    let small = |n: u64| Row::Grant {
        key: key(n),
        path: "p".to_owned(),
        kind: kr_boundary_windows::journal::rows::ObjectKind::File,
        owner: "S-1-5-18".to_owned(),
        dacl_bytes: vec![],
        control_flags: 0,
        protected: false,
        link_count: 1,
        added_ace: String::new(),
    };
    for n in 1..=limits::OBJECTS_PER_TREE as u64 {
        tracker.apply(&small(n)).unwrap();
    }
    let refusal = tracker
        .apply(&small(limits::OBJECTS_PER_TREE as u64 + 1))
        .unwrap_err();
    assert!(matches!(&refusal, OrderError::NoRoom(words) if words.contains("100000 objects")));
}

#[test]
fn the_room_kept_for_an_object_is_exact_and_given_back_as_its_work_ends() {
    let framed = |row: &Row| row.to_bytes().len() + framing::FRAME_BYTES;
    // A leftover names the object by its path or its key as text: room is kept for the longer.
    let object = limits::json_bytes(&grant_path(1)).max(limits::KEY_TEXT_BYTES);
    let released_room = limits::released_room();
    // After the intent a leftover may come, then the result a recovery writes after it, then the
    // leftover's clearance.
    let after_intent = limits::leftover_room(object) + released_room + limits::cleared_room(object);
    let intent_room = limits::intent_room(4 + limits::LIST_GROWTH);
    assert!(framed(&release_intent(1)) <= intent_room);

    // Granted: the intent, and then the result or a leftover with its clearance, are kept.
    let mut tracker = writer_after(limits::WRITER_LIMIT, &[begin(), grant(1)]);
    assert_eq!(
        tracker.budget(),
        (framed(&grant(1)), intent_room + after_intent)
    );
    // The intent is written: its room is spent and what the result may take stays kept.
    tracker.apply(&release_intent(1)).unwrap();
    assert_eq!(
        tracker.budget(),
        (framed(&grant(1)) + framed(&release_intent(1)), after_intent)
    );
    // The result is written: nothing is kept.
    tracker.apply(&released(1)).unwrap();
    assert_eq!(
        tracker.budget(),
        (
            framed(&grant(1)) + framed(&release_intent(1)) + framed(&released(1)),
            0
        )
    );

    // A leftover that names the granted object by its path settles it: the room for the intent and
    // the result is given back, and the clearance stays kept until it is written.
    let path = grant_path(1);
    let mut tracker = writer_after(
        limits::WRITER_LIMIT,
        &[begin(), grant(1), tree_leftover(&path)],
    );
    assert_eq!(
        tracker.budget(),
        (
            framed(&grant(1)) + framed(&tree_leftover(&path)),
            limits::cleared_room(object)
        )
    );
    let cleared = Row::LeftoverCleared { key: path.clone() };
    tracker.apply(&cleared).unwrap();
    assert_eq!(tracker.budget().1, 0);
    // A leftover after the intent leaves the result admissible: its room stays kept with the
    // clearance, and is given back when the result is written.
    let mut tracker = writer_after(
        limits::WRITER_LIMIT,
        &[begin(), grant(1), release_intent(1), tree_leftover(&path)],
    );
    assert_eq!(
        tracker.budget().1,
        limits::cleared_room(object) + released_room
    );
    tracker.apply(&released(1)).unwrap();
    assert_eq!(tracker.budget().1, limits::cleared_room(object));
    // By its key as text, the same.
    let text = key(1).to_string();
    let tracker = writer_after(
        limits::WRITER_LIMIT,
        &[begin(), grant(1), tree_leftover(&text)],
    );
    assert_eq!(
        tracker.budget().1,
        limits::cleared_room(limits::KEY_TEXT_BYTES)
    );

    // An object the invocation made has no room kept before its intent; the intent keeps what its
    // result or its leftover may take.
    let made = limits::leftover_room(limits::KEY_TEXT_BYTES)
        + limits::cleared_room(limits::KEY_TEXT_BYTES);
    let tracker = writer_after(limits::WRITER_LIMIT, &[begin(), release_intent(99)]);
    assert_eq!(tracker.budget().1, released_room + made);
}

#[test]
fn a_leftover_longer_than_the_room_kept_for_its_object_is_not_paid_from_it() {
    // A journal of an earlier form can hold a leftover with a reason far over the cap. The reader
    // takes it and does not charge the object's room for it, since the room was not kept for that.
    let mut tracker = Tracker::reading();
    for row in [begin(), grant(1)] {
        tracker.apply(&row).unwrap();
    }
    let before = tracker.budget();
    tracker
        .apply(&Row::Leftover {
            object: grant_path(1),
            reason: "r".repeat(5_000),
            class: LeftoverClass::Tree,
            snapshot: None,
        })
        .unwrap();
    assert_eq!(tracker.budget(), before);
}

#[test]
fn a_row_over_its_kinds_largest_size_is_refused_whatever_field_made_it_long() {
    // The digest of a hook has no cap of its own; the row's largest size is what stops it.
    let mut snapshot = worst_snapshot(1);
    if let Row::RepositorySnapshot { hooks, .. } = &mut snapshot {
        hooks[0].sha256 = "f".repeat(200_000);
    }
    let text = snapshot.check_caps().unwrap_err();
    assert!(text.contains("bytes the journal allows"), "{text}");
}

#[test]
fn the_reader_takes_a_file_with_rows_above_the_writers_caps_by_order_and_gates_alone() {
    // A journal of an earlier form: a path of 10,000 characters, a list of 60,000 bytes, a reason of
    // 5,000, twenty end checks, ten snapshots and more leftovers than the writer takes.
    let long_path = "p".repeat(10_000);
    let mut rows = vec![begin()];
    rows.extend((1..=10).map(|id| snapshot(id, SnapshotKind::Changed)));
    rows.push(Row::Grant {
        key: key(1),
        path: long_path.clone(),
        kind: kr_boundary_windows::journal::rows::ObjectKind::File,
        owner: "S-1-5-18".to_owned(),
        dacl_bytes: vec![7; 60_000],
        control_flags: 0,
        protected: false,
        link_count: 1,
        added_ace: "a".repeat(2_000),
    });
    rows.push(Row::GrantComplete { count: 1 });
    rows.push(started());
    for _ in 0..20 {
        rows.push(Row::EndUncertain {
            reason: "u".repeat(5_000),
        });
        rows.push(Row::JobEnded);
    }
    rows.push(Row::ReleaseIntent {
        key: key(1),
        rule: kr_boundary_windows::journal::rows::Rule::Group,
        new_owner: None,
        new_dacl_bytes: vec![9; 60_000],
        label: kr_boundary_windows::journal::rows::Label::Keep,
        protected_target: false,
    });
    rows.push(Row::ObjectReleased {
        key: key(1),
        outcome: "o".repeat(5_000),
    });
    for n in 0..30 {
        rows.push(Row::Leftover {
            object: format!("left{n}"),
            reason: "l".repeat(5_000),
            class: LeftoverClass::Root,
            snapshot: None,
        });
    }
    for repeat in 0..20 {
        rows.push(verified(repeat));
        rows.push(Row::EndUncertain {
            reason: "again".to_owned(),
        });
        rows.push(Row::JobEnded);
    }
    // The writer refuses what the file holds; the reader takes every row.
    let refused = rows
        .iter()
        .filter(|row| Tracker::new().apply(row).is_err())
        .count();
    assert!(refused > 0);
    let mut writer = Tracker::new();
    assert!(
        rows.iter().any(|row| writer.apply(row).is_err()),
        "the writer's tracker stops at one of these rows"
    );
    let found = invocation(&file_of(&rows), BOOT);
    assert_eq!(
        found.damage, None,
        "the reader refuses no row for a cap or a count"
    );
    assert_eq!(found.rows.len(), rows.len());
    assert_eq!(found.standing, Standing::Unfinished);
    // Taken up for writing, the same tracker holds what was read to the writer's caps: a leftover
    // is cleared, which is the work that ends.
    let mut resumed = found.tracker.clone().into_writer();
    resumed
        .apply(&Row::LeftoverCleared {
            key: "left3".to_owned(),
        })
        .unwrap();
    assert!(
        resumed
            .apply(&Row::EndUncertain {
                reason: "x".to_owned()
            })
            .is_err()
    );
}

#[test]
fn the_next_row_over_a_count_is_not_lost_in_silence() {
    let start = [begin(), grant_done(), started()];
    let words = |error: OrderError| match error {
        OrderError::NoRoom(words) => words,
        other => panic!("{other:?}"),
    };
    // JobEnded and EndUncertain repeat what the journal already says: not written, and the caller
    // is told it is already recorded.
    let mut tracker = writer_after(limits::WRITER_LIMIT, &start);
    assert_eq!(tracker.apply(&uncertain()), Ok(Applied::Written));
    assert_eq!(tracker.apply(&uncertain()), Ok(Applied::AlreadyRecorded));
    assert_eq!(tracker.apply(&Row::JobEnded), Ok(Applied::Written));
    assert_eq!(tracker.apply(&Row::JobEnded), Ok(Applied::AlreadyRecorded));
    assert_eq!(tracker.apply(&verified(0)), Ok(Applied::Written));
    assert_eq!(tracker.apply(&verified(0)), Ok(Applied::AlreadyRecorded));

    // Sixteen end checks and sixteen proofs, and the seventeenth of either that changes the state
    // is refused with words; the caller records a leftover of class `Uncertain` for the tree.
    let mut tracker = writer_after(limits::WRITER_LIMIT, &start);
    for _ in 0..limits::END_CHECKS {
        tracker.apply(&uncertain()).unwrap();
        tracker.apply(&Row::JobEnded).unwrap();
    }
    let seventeenth = tracker.apply(&uncertain()).map_err(words).unwrap_err();
    assert!(seventeenth.contains("at most 16"), "{seventeenth}");
    // The state is what the last row said: proved. The caller says the end is in doubt with a
    // leftover, which holds the slot and which a person clears.
    let leftover = worst_leftover(r"C:\work\tree".to_owned(), LeftoverClass::Uncertain, None);
    assert_eq!(tracker.apply(&leftover), Ok(Applied::Written));
    assert!(tracker.holds_the_slot());
    // The proof side: after sixteen of each, one more proof of the end is refused.
    let mut tracker = writer_after(limits::WRITER_LIMIT, &start);
    tracker.apply(&Row::JobEnded).unwrap();
    for _ in 0..(limits::END_CHECKS - 1) {
        tracker.apply(&uncertain()).unwrap();
        tracker.apply(&Row::JobEnded).unwrap();
    }
    tracker.apply(&uncertain()).unwrap();
    let proof = tracker.apply(&Row::JobEnded).map_err(words).unwrap_err();
    assert!(proof.contains("at most 16"), "{proof}");
    assert_eq!(
        tracker.apply(&leftover),
        Ok(Applied::Written),
        "the end that cannot be recorded as proved is a leftover"
    );

    // Sixteen verifications, each voided by a release that began after it; the seventeenth is
    // refused, and the caller records a leftover for the tree.
    let mut tracker = writer_after(
        limits::WRITER_LIMIT,
        &[begin(), grant_done(), started(), Row::JobEnded],
    );
    for n in 0..limits::VERIFICATIONS as u64 {
        tracker.apply(&release_intent(100 + n)).unwrap();
        tracker.apply(&released(100 + n)).unwrap();
        tracker.apply(&verified(n)).unwrap();
    }
    tracker.apply(&release_intent(200)).unwrap();
    tracker.apply(&released(200)).unwrap();
    let seventeenth = tracker.apply(&verified(0)).map_err(words).unwrap_err();
    assert!(seventeenth.contains("more than 16 times"), "{seventeenth}");
    assert_eq!(
        tracker.apply(&worst_leftover(
            r"C:\work\tree".to_owned(),
            LeftoverClass::Tree,
            None
        )),
        Ok(Applied::Written)
    );

    // Four snapshots, and a fifth is refused with words.
    let mut tracker = writer_after(limits::WRITER_LIMIT, &[begin()]);
    for id in 1..=limits::SNAPSHOTS {
        tracker.apply(&snapshot(id, SnapshotKind::Changed)).unwrap();
    }
    let fifth = tracker
        .apply(&snapshot(5, SnapshotKind::Changed))
        .map_err(words)
        .unwrap_err();
    assert!(fifth.contains("at most 4 snapshots"), "{fifth}");

    // Four leftovers of the repository and four acceptances; the fifth of each is refused, and one
    // for a state that was already accepted is not written.
    let repository = |id: u32| Row::Leftover {
        object: format!("config{id}"),
        reason: "changed".to_owned(),
        class: LeftoverClass::Repository,
        snapshot: Some(id),
    };
    let accepted = |id: u32| Row::AcceptedState {
        snapshot: id,
        person: "S-1-5-21-1-2-3-1000".to_owned(),
        time: 5,
    };
    let mut tracker = writer_after(limits::WRITER_LIMIT, &[begin()]);
    for id in 1..=limits::SNAPSHOTS {
        tracker.apply(&snapshot(id, SnapshotKind::Changed)).unwrap();
        tracker.apply(&repository(id)).unwrap();
    }
    let fifth = tracker
        .apply(&Row::Leftover {
            object: "config5".to_owned(),
            reason: "changed".to_owned(),
            class: LeftoverClass::Repository,
            snapshot: Some(1),
        })
        .map_err(words)
        .unwrap_err();
    assert!(fifth.contains("at most 4 leftovers"), "{fifth}");
    assert_eq!(tracker.apply(&accepted(1)), Ok(Applied::Written));
    assert_eq!(tracker.apply(&accepted(1)), Ok(Applied::AlreadyRecorded));
    for id in [2, 1, 2] {
        tracker.apply(&accepted(id)).unwrap();
    }
    let fifth = tracker.apply(&accepted(1)).map_err(words).unwrap_err();
    assert!(fifth.contains("at most 4 acceptances"), "{fifth}");

    // Leftovers of the private root: the next one over the count is refused; and leftovers of an
    // object that nothing reserved room for: the ninth is refused, the eight before are taken.
    let mut tracker = writer_after(limits::WRITER_LIMIT, &[begin()]);
    for n in 0..limits::ROOT_LEFTOVERS {
        tracker
            .apply(&worst_leftover(
                format!("held{n}"),
                LeftoverClass::Root,
                None,
            ))
            .unwrap();
    }
    let next = tracker
        .apply(&worst_leftover(
            "held-more".to_owned(),
            LeftoverClass::Root,
            None,
        ))
        .map_err(words)
        .unwrap_err();
    assert!(next.contains("at most 1024 leftovers"), "{next}");
    let mut tracker = writer_after(limits::WRITER_LIMIT, &[begin()]);
    for n in 0..limits::OTHER_LEFTOVERS {
        tracker
            .apply(&worst_leftover(
                format!("tree{n}"),
                LeftoverClass::Tree,
                None,
            ))
            .unwrap();
    }
    let ninth = tracker
        .apply(&worst_leftover(
            "tree9".to_owned(),
            LeftoverClass::Tree,
            None,
        ))
        .map_err(words)
        .unwrap_err();
    assert!(ninth.contains("at most 8 leftovers"), "{ninth}");
}

#[test]
fn a_reason_is_cut_by_its_encoded_size_and_a_row_that_carries_the_cut_is_admitted() {
    // A backslash and a quote take two bytes in a row, a control character six, an accented
    // letter two: the text is 300 bytes and takes 720 once written.
    let text = "\\\"\u{1}é".repeat(60);
    assert!(text.len() > limits::TEXT_BYTES);
    let cut = limits::short(&text);
    assert!(text.starts_with(&cut));
    assert!(
        limits::json_bytes(&cut) <= limits::TEXT_BYTES,
        "the cut text takes {} bytes in a row",
        limits::json_bytes(&cut)
    );
    // It is cut where the next character would not fit, and not before.
    let next = text[cut.len()..].chars().next().unwrap();
    assert!(limits::json_bytes(&format!("{cut}{next}")) > limits::TEXT_BYTES);
    // A text that fits is kept whole.
    assert_eq!(limits::short("in use"), "in use");

    // Every row that carries a reason, an outcome or a name takes the cut text.
    Row::EndUncertain {
        reason: cut.clone(),
    }
    .check_caps()
    .unwrap();
    Row::ObjectReleased {
        key: key(1),
        outcome: cut.clone(),
    }
    .check_caps()
    .unwrap();
    let mut tracker = writer_after(limits::WRITER_LIMIT, &[begin(), grant(1)]);
    let leftover = Row::Leftover {
        object: grant_path(1),
        reason: cut,
        class: LeftoverClass::Tree,
        snapshot: None,
    };
    assert_eq!(tracker.apply(&leftover), Ok(Applied::Written));
}

#[test]
fn a_grant_after_a_cleared_leftover_of_the_same_object_is_not_covered_by_it() {
    let path = grant_path(1);
    for name in [path.clone(), key(1).to_string()] {
        let cleared = Row::LeftoverCleared { key: name.clone() };
        let regranted = [
            begin(),
            grant(1),
            tree_leftover(&name),
            cleared.clone(),
            grant(1),
            Row::GrantComplete { count: 2 },
            started(),
            Row::JobEnded,
        ];
        // The second grant of the key was never released, and the first one's leftover names the
        // first grant only.
        assert!(
            refused_after(&regranted, &verified(1)),
            "the leftover that was cleared covers the grant that came before it"
        );
        // A file that a writer without this rule made: it reads as an invocation that did not end.
        let mut rows = regranted.to_vec();
        rows.extend([verified(1), Row::End { root_leftovers: 0 }]);
        let found = invocation(&file_of(&rows), BOOT);
        assert_ne!(found.standing, Standing::Finished);
        assert!(found.needs_recovery());

        // The control: a leftover that comes after the one grant covers it, once cleared.
        let covered = [
            begin(),
            grant(1),
            tree_leftover(&name),
            cleared,
            Row::GrantComplete { count: 1 },
            started(),
            Row::JobEnded,
        ];
        tracker_after(&covered).apply(&verified(1)).unwrap();

        // A leftover that comes before the grant names something that was there before it.
        let before = [
            begin(),
            tree_leftover(&name),
            Row::LeftoverCleared { key: name.clone() },
            grant(1),
            Row::GrantComplete { count: 1 },
            started(),
            Row::JobEnded,
        ];
        assert!(refused_after(&before, &verified(1)));
    }
}

/// Two different paths to which the tracker's earlier unkeyed 64-bit hash of a name (SipHash with
/// zero keys) gave one value, 0x240a8f408c96ac02. They were found by a cycle search over
/// `hash(r"C:\work\tree\f{x:016x}")`.
fn colliding_paths() -> (String, String) {
    (
        r"C:\work\tree\f9a257281bbc9014f".to_owned(),
        r"C:\work\tree\f8d2dd84bb71df54c".to_owned(),
    )
}

#[test]
fn names_are_compared_whole_and_a_leftover_covers_only_the_object_it_names() {
    // Two granted paths of one length, and a third that no grant has.
    let path_of = |n: u64| grant_path(n);
    assert_eq!(path_of(1).len(), path_of(2).len());
    let run_the_process = |rows: &mut Vec<Row>| rows.extend([started(), Row::JobEnded]);
    let setup = vec![
        begin(),
        grant(1),
        grant(2),
        tree_leftover(&path_of(2)),
        Row::LeftoverCleared { key: path_of(2) },
        Row::GrantComplete { count: 2 },
    ];
    let mut rows = setup.clone();
    run_the_process(&mut rows);
    // The leftover names the second object: the first is not covered by it, and the second is.
    assert!(refused_after(&rows, &verified(2)));
    rows.extend([release_intent(1), released(1)]);
    tracker_after(&rows).apply(&verified(2)).unwrap();

    // A name that differs only by its case, by one character or by a prefix names another object.
    for other in [
        path_of(1).to_uppercase(),
        format!("{}x", path_of(1)),
        path_of(1)[..path_of(1).len() - 1].to_owned(),
        path_of(3),
    ] {
        let mut rows = vec![
            begin(),
            grant(1),
            tree_leftover(&other),
            Row::LeftoverCleared { key: other.clone() },
            Row::GrantComplete { count: 1 },
        ];
        run_the_process(&mut rows);
        assert!(
            refused_after(&rows, &verified(1)),
            "{other} is not {}",
            path_of(1)
        );
    }

    // A path that the old unkeyed 64-bit hash of the tracker gave to two names. Neither name covers
    // the other, and a leftover that names one is not charged to the object granted at the other.
    let (first, second) = colliding_paths();
    assert_ne!(first, second);
    let grant_at = |n: u64, path: &str| match grant(n) {
        Row::Grant {
            key,
            kind,
            owner,
            dacl_bytes,
            control_flags,
            protected,
            link_count,
            added_ace,
            ..
        } => Row::Grant {
            key,
            path: path.to_owned(),
            kind,
            owner,
            dacl_bytes,
            control_flags,
            protected,
            link_count,
            added_ace,
        },
        _ => unreachable!(),
    };
    let mut rows = vec![
        begin(),
        grant_at(1, &first),
        tree_leftover(&second),
        Row::LeftoverCleared {
            key: second.clone(),
        },
        Row::GrantComplete { count: 1 },
    ];
    run_the_process(&mut rows);
    assert!(
        refused_after(&rows, &verified(1)),
        "a leftover of {second} covers the object granted at {first}"
    );
    let before = writer_after(limits::WRITER_LIMIT, &[begin(), grant_at(1, &first)]);
    let mut charged = before.clone();
    charged.apply(&tree_leftover(&second)).unwrap();
    assert_eq!(
        charged.budget().1,
        before.budget().1,
        "the room of the object granted at {first} was given to a leftover of {second}"
    );

    // A key granted again at another path has no earlier path: a leftover that names the path it
    // had before covers nothing that is granted now.
    let mut rows = vec![
        begin(),
        grant(1),
        release_intent(1),
        released(1),
        grant_at(1, &path_of(7)),
        tree_leftover(&path_of(1)),
        Row::LeftoverCleared { key: path_of(1) },
        Row::GrantComplete { count: 2 },
    ];
    run_the_process(&mut rows);
    assert!(refused_after(&rows, &verified(2)));

    // The key's text names the key in the form the key prints and in no other form: the room kept
    // for its leftover is the room of that form.
    let text = key(1).to_string();
    let mut tracker = writer_after(limits::WRITER_LIMIT, &[begin(), grant(1)]);
    let before = tracker.budget();
    tracker.apply(&tree_leftover(&text.to_uppercase())).unwrap();
    assert_eq!(
        tracker.budget(),
        before,
        "{text} in capitals is another name"
    );
    tracker.apply(&tree_leftover(&text)).unwrap();
    assert_ne!(tracker.budget(), before, "{text} is the key's own name");
}

#[test]
fn the_ceiling_follows_each_row_by_what_it_took_and_what_it_still_owes() {
    let framed = |row: &Row| (row.to_bytes().len() + framing::FRAME_BYTES) as i64;
    let mut tracker = writer_after(limits::WRITER_LIMIT, &[begin()]);
    assert!(tracker.ceiling() <= limits::MAX_FILE);
    // A leftover of the private root that no object's room pays for: its row is in the file, one
    // leftover and its clearance fewer may still come, and its own clearance is owed.
    let leftover = worst_leftover("held".to_owned(), LeftoverClass::Root, None);
    let before = tracker.ceiling() as i64;
    tracker.apply(&leftover).unwrap();
    let after = tracker.ceiling() as i64;
    assert_eq!(
        after - before,
        framed(&leftover) - (limits::LEFTOVER_MAX + framing::FRAME_BYTES) as i64
    );
    // Its clearance is written: the row is in the file and nothing more is owed for it.
    let cleared = Row::LeftoverCleared {
        key: "held".to_owned(),
    };
    tracker.apply(&cleared).unwrap();
    assert_eq!(
        tracker.ceiling() as i64 - after,
        framed(&cleared) - (limits::CLEARED_MAX + framing::FRAME_BYTES) as i64
    );
}

#[test]
fn a_leftover_never_gives_away_the_room_of_a_result_that_is_still_admissible() {
    // After a release intent and a leftover of the same key, the key's release is still pending: a
    // recovery that applies the recorded intent writes its result. Other work that begins in the
    // room the leftover gave back must not take the room that result needs.
    let limit = 400_000;
    let mut driver = Driver::new(limit);
    driver.put_ok(begin());
    let granted = 20;
    for n in 1..=granted {
        driver.put_ok(grant(n));
    }
    driver.put_ok(Row::GrantComplete { count: granted });
    for n in 1..=granted {
        driver.put_ok(release_intent(n));
    }
    for n in 1..=granted {
        driver.put_ok(worst_leftover(grant_path(n), LeftoverClass::Tree, None));
    }
    // Objects the invocation made begin their releases until the journal has no room for more.
    let mut made = 1_000;
    while driver.put(release_intent(made)).is_ok() {
        made += 1;
    }
    assert!(
        made > 1_000,
        "the room a leftover gave back is used by other work"
    );
    // Every result is still admitted.
    for n in (1..=granted).chain(1_000..made) {
        driver.put_ok(released(n));
    }
}

fn grant_at(n: u64, path: &str) -> Row {
    let mut row = grant(n);
    if let Row::Grant { path: made, .. } = &mut row {
        *made = path.to_owned();
    }
    row
}

#[test]
fn each_open_leftover_gives_back_the_room_it_took_and_no_other() {
    // One key is granted at a short path, left over, granted again at a much longer path and left
    // over again. Clearing the first leftover gives back what the first took: the clearance of the
    // second is still owed, whatever the key's current grant would take.
    let short = r"C:\a";
    let long = format!(r"C:\{}", "b".repeat(limits::NAME_BYTES * 3));
    let mut driver = Driver::new(400_000);
    driver.put_ok(begin());
    driver.put_ok(grant_at(1, short));
    driver.put_ok(worst_leftover(short.to_owned(), LeftoverClass::Tree, None));
    driver.put_ok(grant_at(1, &long));
    driver.put_ok(worst_leftover(long.clone(), LeftoverClass::Tree, None));
    driver.put_ok(Row::LeftoverCleared {
        key: short.to_owned(),
    });

    let mut alone = Driver::new(400_000);
    alone.put_ok(begin());
    alone.put_ok(grant_at(1, &long));
    alone.put_ok(worst_leftover(long.clone(), LeftoverClass::Tree, None));
    assert_eq!(
        driver.tracker.budget().1,
        alone.tracker.budget().1,
        "the room kept for the long path's clearance is what it took, with the short one's cleared"
    );
}

/// The file's bytes with each record written as indented text, which a reader takes as it takes
/// the compact text that this build writes.
fn file_with_loose_records(rows: &[Row]) -> Vec<u8> {
    rows.iter()
        .flat_map(|row| framing::encode(&serde_json::to_vec_pretty(row).unwrap()).unwrap())
        .collect()
}

#[test]
fn the_reader_counts_the_bytes_that_are_really_in_the_file() {
    let rows = vec![begin(), grant(1), grant(2), grant(3)];
    let loose = file_with_loose_records(&rows);
    assert!(
        loose.len() > file_of(&rows).len(),
        "the records are longer than the build writes them"
    );
    let found = invocation(&loose, BOOT);
    assert_eq!(found.damage, None);
    assert_eq!(found.valid_len, loose.len());
    assert_eq!(
        found.tracker.bytes(),
        found.valid_len,
        "the tracker counts what is in the file, not what it would write"
    );
}

#[test]
fn a_root_is_not_begun_in_a_resumed_file_without_room_for_the_rows_that_record_it() {
    // A file of the most a correct writer makes, less a little: the intent alone would fit the
    // native bound, but the rows that record the root made and removed would not. (A file of this
    // length is counted by the size its record has: the case does not write 400 megabytes.)
    let mut reader = Tracker::reading();
    reader.apply(&begin()).unwrap();
    reader
        .apply_framed(
            &snapshot(1, SnapshotKind::Initial),
            limits::MAX_FILE - 4 * limits::ROOT_MAX,
        )
        .unwrap();
    assert!(
        reader.bytes() + framing::FRAME_BYTES + limits::ROOT_MAX < limits::MAX_FILE,
        "the intent fits the file's bound on its own"
    );
    let mut writer = reader.into_writer();
    let refused = writer.apply(&Row::RootIntent { name: root_name(1) });
    assert!(
        matches!(refused, Err(OrderError::NoRoom(_))),
        "a root whose made and removed rows cannot fit is not begun: {refused:?}"
    );
}

/// The bound that decides a root is the ceiling with the root's three rows counted: a file with
/// room for everything but the made and removed rows of the root refuses the intent, and a file
/// with room for all three does not. The ceiling grows one for one with the bytes in the file, so
/// the case puts it first exactly on the file's bound and then one byte over it.
#[test]
fn a_root_is_begun_only_when_the_file_has_room_for_every_row_that_records_it() {
    let resumed = |snapshot_bytes: usize| {
        let mut reader = Tracker::reading();
        reader.apply(&begin()).unwrap();
        reader
            .apply_framed(&snapshot(1, SnapshotKind::Initial), snapshot_bytes)
            .unwrap();
        reader.into_writer()
    };
    let probe = 1_000;
    let below = limits::MAX_FILE
        .checked_sub(resumed(probe).ceiling())
        .expect("a small file is within the bound");
    let at_the_bound = probe + below;

    let mut fits = resumed(at_the_bound);
    assert_eq!(fits.ceiling(), limits::MAX_FILE, "the file is on its bound");
    fits.apply(&Row::RootIntent { name: root_name(1) })
        .expect("room for the intent and for the made and removed rows");

    let mut over = resumed(at_the_bound + 1);
    assert!(
        matches!(
            over.apply(&Row::RootIntent { name: root_name(1) }),
            Err(OrderError::NoRoom(_))
        ),
        "a byte short of room for the root's rows: no root is begun"
    );
    // Once the intent is written, the two rows still to come keep their room.
    assert!(
        fits.ceiling() <= limits::MAX_FILE,
        "the file's ceiling stays within its bound after the intent"
    );
}

#[test]
fn a_writer_that_resumes_a_file_counts_the_bytes_that_are_in_it_and_what_it_still_owes() {
    // An earlier writer made ten snapshot rows of the size the framing allows. The reader takes
    // them, and they are far over what a correct writer spends on snapshots.
    let heavy = |id: u32| Row::RepositorySnapshot {
        id,
        kind: SnapshotKind::Changed,
        config_digest: "ab".repeat(32),
        hooks: (0..2_000)
            .map(|n| DigestedFile {
                name: "n".repeat(limits::NAME_BYTES),
                key: key(n),
                size: u64::MAX,
                sha256: "cd".repeat(32),
            })
            .collect(),
        info_attributes: None,
        absent_names: Vec::new(),
    };
    let mut reader = Tracker::reading();
    reader.apply(&begin()).unwrap();
    for id in 1..=10 {
        let row = heavy(id);
        assert!(row.to_bytes().len() <= framing::MAX_RECORD);
        reader.apply(&row).unwrap();
    }
    assert!(reader.bytes() > limits::CLOSING);
    let mut writer = reader.into_writer();

    // The writer takes objects until the journal has no room for more.
    let mut n = 0;
    loop {
        n += 1;
        assert!(n <= 200_000, "the writer takes objects without end");
        let list = limits::LIST_BYTES - limits::LIST_GROWTH;
        if writer.apply(&worst_grant(n, list)).is_err() {
            break;
        }
    }
    assert!(n > 1_000, "the writer took {n} objects");

    // What is in the file, what is kept for the rows of the work begun, and what the rows that are
    // not an object's may still add (each kind at its largest size and the count it has left) must
    // fit the bound the reader reads up to.
    let frame = framing::FRAME_BYTES;
    let closing_left = limits::CLOSING
        - (limits::BEGIN_MAX + frame)
        - limits::SNAPSHOTS as usize * (limits::SNAPSHOT_MAX + frame);
    let (_, kept) = writer.budget();
    assert!(writer.ceiling() <= limits::MAX_FILE);
    assert!(
        writer.bytes() + kept + closing_left <= limits::MAX_FILE,
        "the file ({}) with what is kept ({kept}) and what may still be added ({closing_left}) passes {}",
        writer.bytes(),
        limits::MAX_FILE
    );
}

#[test]
fn a_repeated_row_with_other_content_is_not_already_recorded() {
    // An acceptance of a state that was accepted: by the same person it is already recorded, at
    // whatever time; by another person it differs, and nothing of it is written.
    let accepted = |person: &str, time: u64| Row::AcceptedState {
        snapshot: 1,
        person: person.to_owned(),
        time,
    };
    let mut tracker = writer_after(
        limits::WRITER_LIMIT,
        &[
            begin(),
            snapshot(1, SnapshotKind::Changed),
            Row::Leftover {
                object: "config".to_owned(),
                reason: "changed".to_owned(),
                class: LeftoverClass::Repository,
                snapshot: Some(1),
            },
        ],
    );
    assert_eq!(
        tracker.apply(&accepted("S-1-5-21-1", 5)),
        Ok(Applied::Written)
    );
    let size = tracker.bytes();
    // The same row again says what the journal says; the same person at another time is another
    // row, whose time the journal does not hold.
    assert_eq!(
        tracker.apply(&accepted("S-1-5-21-1", 5)),
        Ok(Applied::AlreadyRecorded)
    );
    assert_eq!(
        tracker.apply(&accepted("S-1-5-21-1", 9)),
        Ok(Applied::Differs)
    );
    assert_eq!(
        tracker.apply(&accepted("S-1-5-21-2", 9)),
        Ok(Applied::Differs)
    );
    assert_eq!(tracker.bytes(), size);
    assert_eq!(tracker.accepted_snapshot(), Some(1));

    // An end that is not proved, said twice with another reason.
    let mut tracker = writer_after(
        limits::WRITER_LIMIT,
        &[begin(), grant_done(), started(), uncertain()],
    );
    let size = tracker.bytes();
    assert_eq!(tracker.apply(&uncertain()), Ok(Applied::AlreadyRecorded));
    let other = Row::EndUncertain {
        reason: "another reason".to_owned(),
    };
    assert_eq!(tracker.apply(&other), Ok(Applied::Differs));
    assert_eq!(tracker.bytes(), size);
    // It still counts as one check: the sixteen are not used up by a reason that changes.
    for _ in 0..40 {
        assert_eq!(tracker.apply(&other), Ok(Applied::Differs));
    }
    assert_eq!(tracker.apply(&Row::JobEnded), Ok(Applied::Written));

    // A verification said twice with another count of objects.
    let mut tracker = writer_after(
        limits::WRITER_LIMIT,
        &[begin(), grant_done(), started(), Row::JobEnded, verified(3)],
    );
    assert_eq!(tracker.apply(&verified(3)), Ok(Applied::AlreadyRecorded));
    assert_eq!(tracker.apply(&verified(4)), Ok(Applied::Differs));
}

#[test]
fn nothing_follows_the_end_but_the_clearing_of_root_leftovers_and_the_removal_of_the_root() {
    let root_leftover = Row::Leftover {
        object: "tmp/held".to_owned(),
        reason: "in use".to_owned(),
        class: LeftoverClass::Root,
        snapshot: None,
    };
    let finished = [
        begin(),
        Row::RootIntent { name: root_name(1) },
        Row::RootMade {
            name: root_name(1),
            key: key(9),
        },
        root_leftover,
        Row::ReleaseVerified {
            objects: 0,
            leftovers: 0,
        },
        Row::End { root_leftovers: 1 },
    ];
    for (what, row) in [
        ("a snapshot", snapshot(1, SnapshotKind::Initial)),
        ("a root intent", Row::RootIntent { name: root_name(2) }),
        ("a process", started()),
        ("a job end", Row::JobEnded),
        ("an uncertain end", uncertain()),
        ("a release intent", release_intent(1)),
        (
            "a verification",
            Row::ReleaseVerified {
                objects: 0,
                leftovers: 0,
            },
        ),
        ("a grant count", Row::GrantComplete { count: 0 }),
        ("a second end", Row::End { root_leftovers: 1 }),
        (
            "a new leftover",
            Row::Leftover {
                object: "x".to_owned(),
                reason: "r".to_owned(),
                class: LeftoverClass::Root,
                snapshot: None,
            },
        ),
    ] {
        assert!(
            refused_after(&finished, &row),
            "{what} after the end is refused"
        );
    }
    // The sweep's work is allowed: clear the leftover, then remove the root.
    let mut tracker = tracker_after(&finished);
    assert_eq!(tracker.standing(), Standing::Finished);
    assert!(!tracker.holds_the_slot());
    tracker
        .apply(&Row::LeftoverCleared {
            key: "tmp/held".to_owned(),
        })
        .unwrap();
    tracker.apply(&Row::RootRemoved).unwrap();
    assert!(tracker.leftovers().is_empty());
    assert_eq!(tracker.root(), &RootState::Removed);
}

#[test]
fn a_finished_invocation_with_a_root_leftover_is_kept_for_recovery_with_its_slot_free() {
    let mut rows = vec![
        begin(),
        Row::Leftover {
            object: "tmp/held".to_owned(),
            reason: "in use".to_owned(),
            class: LeftoverClass::Root,
            snapshot: None,
        },
        Row::ReleaseVerified {
            objects: 0,
            leftovers: 0,
        },
        Row::End { root_leftovers: 1 },
    ];
    let found = invocation(&file_of(&rows), BOOT);
    assert_eq!(found.standing, Standing::Finished);
    assert!(
        found.needs_recovery(),
        "the sweep still carries the leftover"
    );
    assert!(!found.tracker.holds_the_slot());
    assert_eq!(found.tracker.leftovers().len(), 1);
    rows.push(Row::LeftoverCleared {
        key: "tmp/held".to_owned(),
    });
    let found = invocation(&file_of(&rows), BOOT);
    assert!(!found.needs_recovery(), "nothing is left to do");
    // An invocation that is not finished is always kept.
    assert!(invocation(&file_of(&[begin()]), BOOT).needs_recovery());
}

#[test]
fn a_leftover_that_names_a_snapshot_never_written_is_refused() {
    let mut tracker = Tracker::new();
    tracker.apply(&begin()).unwrap();
    assert!(
        tracker
            .apply(&Row::Leftover {
                object: "config".to_owned(),
                reason: "changed".to_owned(),
                class: LeftoverClass::Repository,
                snapshot: Some(2),
            })
            .is_err()
    );
}

#[test]
fn a_row_that_arrives_out_of_order_in_a_file_makes_the_invocation_unreadable() {
    let found = invocation(&file_of(&[begin(), Row::End { root_leftovers: 0 }]), BOOT);
    assert_eq!(found.standing, Standing::Unreadable);
    assert!(found.damage.is_some());
    assert!(found.tracker.holds_the_slot());
}

#[test]
fn a_torn_tail_is_dropped_and_the_rows_before_it_stand() {
    let whole = file_of(&[begin(), snapshot(1, SnapshotKind::Initial)]);
    let next = framing::encode(&Row::RootIntent { name: root_name(1) }.to_bytes()).unwrap();
    let mut bytes = whole.clone();
    bytes.extend_from_slice(&next[..5]);
    let found = invocation(&bytes, BOOT);
    assert_eq!(found.damage, None);
    assert_eq!(found.rows.len(), 2);
    assert_eq!(found.torn_bytes, 5);
    assert_eq!(found.valid_len, whole.len());
    assert_eq!(found.standing, Standing::Unfinished);
}

#[test]
fn a_damaged_record_that_is_not_the_last_makes_the_invocation_unreadable_and_keeps_the_rows_before_it()
 {
    let mut bytes = file_of(&[begin(), snapshot(1, SnapshotKind::Initial), Row::JobEnded]);
    let first = framing::encode(&begin().to_bytes()).unwrap().len();
    bytes[first + 6] ^= 0xff;
    let found = invocation(&bytes, BOOT);
    assert_eq!(found.standing, Standing::Unreadable);
    assert!(found.damage.is_some());
    assert_eq!(
        found.rows,
        [begin()],
        "the Begin row and its chain are kept"
    );
    assert!(found.tracker.holds_the_slot());
    assert_eq!(found.valid_len, first);
    assert_eq!(found.torn_bytes, 0);
}

#[test]
fn a_length_that_runs_past_the_end_with_valid_records_after_it_is_damage_in_a_journal() {
    let mut bytes = file_of(&[begin(), snapshot(1, SnapshotKind::Initial), Row::JobEnded]);
    let first = framing::encode(&begin().to_bytes()).unwrap().len();
    let grown = u32::try_from(bytes.len()).unwrap();
    bytes[first..first + 4].copy_from_slice(&grown.to_le_bytes());
    let found = invocation(&bytes, BOOT);
    assert_eq!(found.standing, Standing::Unreadable);
    assert_eq!(found.rows, [begin()]);
    assert_eq!(found.tracker.leftovers().len(), 0);
}

#[test]
fn a_first_row_that_begins_another_invocation_than_the_files_name_is_damage() {
    let bytes = file_of(&[begin(), snapshot(1, SnapshotKind::Initial)]);
    let other = "ffffffffffffffffffffffffffffffff";
    let Reading::Invocation(found) = replay::read_file(other, &bytes, BOOT) else {
        panic!("the file holds an invocation");
    };
    assert_eq!(found.standing, Standing::Unreadable);
    assert_eq!(found.rows, [begin()], "the chain is kept");
    assert!(found.damage.unwrap().contains(other));
}

#[test]
fn a_file_longer_than_the_bound_is_read_up_to_it_and_is_unreadable() {
    let bytes = file_of(&[begin(), snapshot(1, SnapshotKind::Initial), Row::JobEnded]);
    let first = framing::encode(&begin().to_bytes()).unwrap().len();
    let Reading::Invocation(found) = replay::read_file_limited(ID, &bytes, BOOT, first + 1) else {
        panic!("the file holds an invocation");
    };
    assert_eq!(found.standing, Standing::Unreadable);
    assert_eq!(found.rows, [begin()]);
    assert!(found.damage.unwrap().contains("longer than"));
    // At exactly the bound it is read whole.
    let Reading::Invocation(whole) = replay::read_file_limited(ID, &bytes, BOOT, bytes.len())
    else {
        panic!("the file holds an invocation");
    };
    assert_eq!(whole.damage, None);
    assert_eq!(whole.rows.len(), 3);
}

#[test]
fn a_file_with_no_first_row_made_nothing() {
    assert!(matches!(
        replay::read_file(ID, &[], BOOT),
        Reading::MadeNothing
    ));
    let first = framing::encode(&begin().to_bytes()).unwrap();
    assert!(matches!(
        replay::read_file(ID, &first[..first.len() - 1], BOOT),
        Reading::MadeNothing
    ));
}

#[test]
fn the_boot_marker_now_is_compared_with_the_one_the_invocation_began_with() {
    let bytes = file_of(&[begin()]);
    assert!(invocation(&bytes, BOOT).same_boot);
    assert!(!invocation(&bytes, "another boot").same_boot);
}

#[test]
fn a_private_roots_name_is_exactly_thirty_two_lowercase_hexadecimal_digits() {
    let good = "0123456789abcdef0123456789abcdef";
    assert_eq!(RootName::parse(good).unwrap().as_str(), good);
    assert_eq!(RootName::from_bytes([0xab; 16]).as_str(), "ab".repeat(16));
    for bad in [
        "",
        "0123456789abcdef0123456789abcde",
        "0123456789abcdef0123456789abcdef0",
        "0123456789ABCDEF0123456789ABCDEF",
        "0123456789abcdef0123456789abcdeg",
        "..\\..\\..\\..\\..\\..\\..\\..\\..",
        r"C:\run\0123456789abcdef0123456789abcdef",
        "0123456789abcdef/123456789abcdef",
        "0123456789abcdef0123456789abcde\u{e9}",
    ] {
        assert_eq!(RootName::parse(bad), Err(RootNameError), "{bad:?}");
    }
}

#[test]
fn a_root_row_whose_name_is_not_a_name_is_refused_and_the_invocation_is_unreadable() {
    let good = Row::RootIntent { name: root_name(3) }.to_bytes();
    assert_eq!(
        Row::from_bytes(&good).unwrap(),
        Row::RootIntent { name: root_name(3) }
    );
    for name in [r"C:\run\a", "a", "ABCDEF0123456789ABCDEF0123456789", ".."] {
        let text = format!(
            r#"{{"row":"RootIntent","name":{}}}"#,
            serde_json::to_string(name).unwrap()
        );
        assert!(Row::from_bytes(text.as_bytes()).is_err(), "{name}");
        let text = format!(
            r#"{{"row":"RootMade","name":{},"key":{}}}"#,
            serde_json::to_string(name).unwrap(),
            serde_json::to_string(&key(9)).unwrap()
        );
        assert!(Row::from_bytes(text.as_bytes()).is_err(), "{name}");
        let mut bytes = file_of(&[begin()]);
        let framed = framing::encode(
            format!(
                r#"{{"row":"RootIntent","name":{}}}"#,
                serde_json::to_string(name).unwrap()
            )
            .as_bytes(),
        )
        .unwrap();
        bytes.extend_from_slice(&framed);
        let found = invocation(&bytes, BOOT);
        assert_eq!(found.standing, Standing::Unreadable, "{name}");
        assert_eq!(found.rows.len(), 1, "the Begin row is kept");
    }
}

#[cfg(windows)]
mod native {
    use std::path::PathBuf;

    use kr_boundary_windows::journal::replay::Standing;
    use kr_boundary_windows::journal::rows::{Row, SnapshotKind};
    use kr_boundary_windows::win::journal::{
        Journal, JournalError, file_name, replay as replay_dir,
    };
    use kr_boundary_windows::win::launch::InvocationId;

    use super::{BOOT, ID, begin, framing, root_name, snapshot};

    fn id() -> InvocationId {
        let mut bytes = [0_u8; 16];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::try_from(index).unwrap();
        }
        InvocationId(bytes)
    }

    struct Dir(PathBuf);

    impl Dir {
        fn new() -> Dir {
            let dir = std::env::temp_dir().join(format!(
                "krjournal-{}",
                &uuid::Uuid::new_v4().simple().to_string()[..12]
            ));
            std::fs::create_dir_all(&dir).unwrap();
            Dir(dir)
        }
    }

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn a_row_is_in_the_file_when_append_returns_and_a_row_out_of_order_never_reaches_it() {
        let dir = Dir::new();
        let mut journal = Journal::create(&dir.0, id()).unwrap();
        assert_eq!(journal.append(&begin()).unwrap().rows, 1);
        // Read through a second handle while the journal stays open: the row is already there.
        let path = dir.0.join(file_name(id()));
        let on_disk = std::fs::read(&path).unwrap();
        assert_eq!(framing::read_all(&on_disk).records.len(), 1);
        let refused = journal.append(&Row::End { root_leftovers: 0 });
        assert!(
            matches!(refused, Err(JournalError::Order(_))),
            "{refused:?}"
        );
        assert_eq!(
            std::fs::read(&path).unwrap(),
            on_disk,
            "nothing was written"
        );
        let again = journal.append(&begin());
        assert!(matches!(again, Err(JournalError::Order(_))), "{again:?}");
    }

    #[test]
    fn a_crash_between_rows_is_read_back_and_a_torn_tail_is_cut_before_more_rows() {
        let dir = Dir::new();
        {
            let mut journal = Journal::create(&dir.0, id()).unwrap();
            journal.append(&begin()).unwrap();
            journal.append(&snapshot(1, SnapshotKind::Initial)).unwrap();
            // The process ends here, between two rows, with half of the next one written.
        }
        let path = dir.0.join(file_name(id()));
        let next = framing::encode(&Row::RootIntent { name: root_name(1) }.to_bytes()).unwrap();
        let mut bytes = std::fs::read(&path).unwrap();
        let whole = bytes.len();
        bytes.extend_from_slice(&next[..7]);
        std::fs::write(&path, &bytes).unwrap();

        let unfinished = replay_dir(&dir.0, BOOT).unwrap();
        assert_eq!(unfinished.len(), 1);
        assert_eq!(unfinished[0].id, ID);
        assert_eq!(unfinished[0].rows.len(), 2);
        assert_eq!(unfinished[0].torn_bytes, 7);
        assert_eq!(unfinished[0].standing, Standing::Unfinished);

        let (mut journal, found) = Journal::resume(&dir.0, id(), BOOT).unwrap();
        assert_eq!(found.valid_len, whole);
        assert_eq!(std::fs::metadata(&path).unwrap().len(), whole as u64);
        journal
            .append(&Row::RootIntent { name: root_name(1) })
            .unwrap();
        let after = std::fs::read(&path).unwrap();
        let reading = framing::read_all(&after);
        assert_eq!(reading.records.len(), 3);
        assert_eq!(reading.torn_len(after.len()), 0);
    }

    #[test]
    fn replay_lists_the_invocations_that_did_not_finish_with_the_boot_comparison() {
        let dir = Dir::new();
        // One that finished.
        let mut finished_id = id();
        finished_id.0[15] = 0xf0;
        let mut finished = Journal::create(&dir.0, finished_id).unwrap();
        let mut begin_row = begin();
        if let Row::Begin { invocation, .. } = &mut begin_row {
            *invocation = hex::encode(finished_id.0);
        }
        finished.append(&begin_row).unwrap();
        finished
            .append(&Row::ReleaseVerified {
                objects: 0,
                leftovers: 0,
            })
            .unwrap();
        finished.append(&Row::End { root_leftovers: 0 }).unwrap();
        // One that did not.
        let mut open = Journal::create(&dir.0, id()).unwrap();
        open.append(&begin()).unwrap();
        // One that made nothing.
        let mut nothing_id = id();
        nothing_id.0[15] = 0xf1;
        std::fs::write(dir.0.join(file_name(nothing_id)), b"").unwrap();
        // A file that is not a journal.
        std::fs::write(dir.0.join("notes.txt"), b"x").unwrap();

        let same = replay_dir(&dir.0, BOOT).unwrap();
        assert_eq!(same.len(), 1, "only the unfinished invocation is returned");
        assert_eq!(same[0].id, ID);
        assert!(same[0].same_boot);
        let other = replay_dir(&dir.0, "another boot").unwrap();
        assert!(!other[0].same_boot);
    }

    #[test]
    fn replay_keeps_a_finished_invocation_that_still_has_a_root_leftover() {
        let dir = Dir::new();
        let mut journal = Journal::create(&dir.0, id()).unwrap();
        for row in [
            begin(),
            Row::Leftover {
                object: "tmp/held".to_owned(),
                reason: "in use".to_owned(),
                class: kr_boundary_windows::journal::rows::LeftoverClass::Root,
                snapshot: None,
            },
            Row::ReleaseVerified {
                objects: 0,
                leftovers: 0,
            },
            Row::End { root_leftovers: 1 },
        ] {
            journal.append(&row).unwrap();
        }
        let kept = replay_dir(&dir.0, BOOT).unwrap();
        assert_eq!(kept.len(), 1, "the sweep still carries the leftover");
        assert_eq!(kept[0].standing, Standing::Finished);
        assert!(!kept[0].tracker.holds_the_slot(), "the tree's slot is free");
        journal
            .append(&Row::LeftoverCleared {
                key: "tmp/held".to_owned(),
            })
            .unwrap();
        assert!(replay_dir(&dir.0, BOOT).unwrap().is_empty());
    }

    #[test]
    fn the_path_of_an_uncertain_end_then_the_proof_then_the_release_is_written_in_that_order() {
        let dir = Dir::new();
        let mut journal = Journal::create(&dir.0, id()).unwrap();
        journal.append(&begin()).unwrap();
        journal.append(&super::grant_done()).unwrap();
        journal
            .append(&Row::ProcessStarted {
                pid: 12,
                creation_time: 34,
            })
            .unwrap();
        journal
            .append(&Row::EndUncertain {
                reason: "the session is still there".to_owned(),
            })
            .unwrap();
        // No release, no verification, no removal of the root and no end while the end is not
        // proved, and none of the refusals reaches the file.
        let before = std::fs::metadata(journal.path()).unwrap().len();
        for row in [
            super::release_intent(1),
            Row::ReleaseVerified {
                objects: 0,
                leftovers: 0,
            },
            Row::End { root_leftovers: 0 },
        ] {
            assert!(
                matches!(journal.append(&row), Err(JournalError::Order(_))),
                "{row:?} is refused"
            );
        }
        assert_eq!(std::fs::metadata(journal.path()).unwrap().len(), before);
        let held = replay_dir(&dir.0, BOOT).unwrap();
        assert_eq!(held.len(), 1);
        assert_eq!(held[0].standing, Standing::Uncertain);
        // A later try finds the session gone and writes the proof; the release then goes on.
        journal.append(&Row::JobEnded).unwrap();
        journal.append(&super::release_intent(1)).unwrap();
        journal.append(&super::released(1)).unwrap();
        journal
            .append(&Row::ReleaseVerified {
                objects: 1,
                leftovers: 0,
            })
            .unwrap();
        journal.append(&Row::End { root_leftovers: 0 }).unwrap();
        assert!(replay_dir(&dir.0, BOOT).unwrap().is_empty());
    }

    #[test]
    fn a_file_longer_than_the_bound_is_read_up_to_it_and_is_unreadable() {
        let dir = Dir::new();
        {
            let mut journal = Journal::create(&dir.0, id()).unwrap();
            journal.append(&begin()).unwrap();
        }
        let path = dir.0.join(file_name(id()));
        let file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        file.set_len(kr_boundary_windows::journal::limits::MAX_FILE as u64 + 4096)
            .unwrap();
        drop(file);
        let found = replay_dir(&dir.0, BOOT).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].standing, Standing::Unreadable);
        assert_eq!(
            found[0].rows,
            [begin()],
            "the rows before the bound are kept"
        );
        assert!(Journal::resume(&dir.0, id(), BOOT).is_err());
    }

    #[cfg(feature = "testing")]
    #[test]
    fn a_failed_write_closes_the_journal_to_readers_of_its_tracker() {
        use kr_boundary_windows::win::journal::testing;
        let dir = Dir::new();
        let mut journal = Journal::create(&dir.0, id()).unwrap();
        journal.append(&begin()).unwrap();
        assert!(journal.tracker().is_ok());
        // The write fails after the tracker took the row: the tracker may be ahead of the file, so
        // it is not given out, and no more rows are taken.
        testing::fail_next_write();
        let failed = journal
            .append(&snapshot(1, SnapshotKind::Initial))
            .unwrap_err();
        assert!(matches!(failed, JournalError::Io(_)), "{failed}");
        assert!(matches!(journal.tracker(), Err(JournalError::Closed)));
        assert!(matches!(
            journal.append(&snapshot(2, SnapshotKind::Changed)),
            Err(JournalError::Closed)
        ));
        // The file says what is on the disk: the row that was not written is not there.
        let bytes = std::fs::read(journal.path()).unwrap();
        assert_eq!(framing::read_all(&bytes).records.len(), 1);
    }

    #[cfg(feature = "testing")]
    #[test]
    fn a_row_that_would_take_the_file_past_the_bound_is_refused_whatever_the_tracker_holds() {
        use kr_boundary_windows::journal::limits::MAX_FILE;
        use kr_boundary_windows::journal::replay::OrderError;
        use kr_boundary_windows::win::journal::testing;
        let dir = Dir::new();
        let mut journal = Journal::create(&dir.0, id()).unwrap();
        journal.append(&begin()).unwrap();
        let rows = std::fs::metadata(journal.path()).unwrap().len();
        // The file is as long as the reader reads, with rows the tracker does not know: the
        // tracker has room for the row and the file has none.
        testing::set_file_length(&journal, MAX_FILE as u64).unwrap();
        let refused = journal
            .append(&snapshot(1, SnapshotKind::Initial))
            .unwrap_err();
        assert!(
            matches!(refused, JournalError::Order(OrderError::NoRoom(_))),
            "{refused}"
        );
        assert_eq!(
            std::fs::metadata(journal.path()).unwrap().len(),
            MAX_FILE as u64,
            "nothing was written"
        );
        // A file that is shorter by the row's length takes it.
        testing::set_file_length(&journal, rows).unwrap();
        journal.append(&snapshot(1, SnapshotKind::Initial)).unwrap();
    }

    #[test]
    fn a_row_that_differs_from_the_recorded_one_is_not_written_and_is_not_taken_as_recorded() {
        use kr_boundary_windows::journal::rows::Row;
        let dir = Dir::new();
        let mut journal = Journal::create(&dir.0, id()).unwrap();
        for row in [
            begin(),
            Row::GrantComplete { count: 0 },
            Row::ProcessStarted {
                pid: 12,
                creation_time: 34,
            },
        ] {
            journal.append(&row).unwrap();
        }
        let uncertain = |reason: &str| Row::EndUncertain {
            reason: reason.to_owned(),
        };
        journal.append(&uncertain("the session is there")).unwrap();
        let length = std::fs::metadata(journal.path()).unwrap().len();
        assert!(matches!(
            journal.append(&uncertain("the session is there")),
            Err(JournalError::AlreadyRecorded)
        ));
        assert!(matches!(
            journal.append(&uncertain("another reason")),
            Err(JournalError::DiffersFromRecorded)
        ));
        assert_eq!(std::fs::metadata(journal.path()).unwrap().len(), length);
    }

    #[test]
    fn a_row_too_large_to_frame_is_refused_before_any_byte_is_written() {
        let dir = Dir::new();
        let mut journal = Journal::create(&dir.0, id()).unwrap();
        journal.append(&begin()).unwrap();
        let path = dir.0.join(file_name(id()));
        let before = std::fs::read(&path).unwrap();
        let huge = Row::Leftover {
            object: "x".repeat(framing::MAX_RECORD),
            reason: String::new(),
            class: kr_boundary_windows::journal::rows::LeftoverClass::Tree,
            snapshot: None,
        };
        let refused = journal.append(&huge);
        assert!(
            matches!(refused, Err(JournalError::Framing(_))),
            "{refused:?}"
        );
        assert_eq!(std::fs::read(&path).unwrap(), before);
        // A row refused before any byte was written does not close the journal.
        journal.append(&snapshot(1, SnapshotKind::Initial)).unwrap();
    }
}

/// Cases that make a private root or read the boot marker: elevated SYSTEM session, disposable guest.
#[cfg(all(windows, feature = "testing"))]
mod guest {
    use std::path::Path;

    use kr_boundary_windows::filekey::FileKey;
    use kr_boundary_windows::journal::framing;
    use kr_boundary_windows::journal::replay::RootState;
    use kr_boundary_windows::journal::rows::{RootName, Row};
    use kr_boundary_windows::win::journal::{Journal, file_name, replay as replay_dir};
    use kr_boundary_windows::win::launch::InvocationId;
    use kr_boundary_windows::win::privilege;
    use kr_boundary_windows::win::root::{RootError, RootRows, create_root, remove_root};

    use super::begin;
    use super::common::{Scratch, group, run_dir};

    fn id() -> InvocationId {
        InvocationId(*b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f")
    }

    /// The journal as the root's rows, checking that each row is on the disk at the right moment.
    struct Checked<'a> {
        journal: &'a mut Journal,
        run: &'a Path,
    }

    impl Checked<'_> {
        fn last_row(&self) -> Row {
            let bytes = std::fs::read(self.journal.path()).unwrap();
            let reading = framing::read_all(&bytes);
            Row::from_bytes(reading.records.last().unwrap()).unwrap()
        }
    }

    impl RootRows for Checked<'_> {
        fn intent(&mut self, name: &RootName) -> Result<(), RootError> {
            assert!(
                !self.run.join(name.as_str()).exists(),
                "the intent is durable before the directory exists"
            );
            self.journal.intent(name)?;
            assert_eq!(self.last_row(), Row::RootIntent { name: name.clone() });
            Ok(())
        }

        fn made(&mut self, name: &RootName, key: &FileKey) -> Result<(), RootError> {
            assert!(
                self.run.join(name.as_str()).exists(),
                "the root exists when it is recorded as made"
            );
            self.journal.made(name, key)?;
            assert!(matches!(self.last_row(), Row::RootMade { .. }));
            Ok(())
        }

        fn removed(&mut self) -> Result<(), RootError> {
            self.journal.removed()?;
            assert_eq!(self.last_row(), Row::RootRemoved);
            Ok(())
        }
    }

    #[test]
    #[ignore = "needs an elevated SYSTEM session in a disposable Windows guest"]
    fn the_private_roots_rows_go_through_the_journal_around_its_creation_and_its_removal() {
        let scratch = Scratch::new();
        let run = run_dir(&scratch);
        let journals = scratch.path("journal");
        std::fs::create_dir_all(&journals).unwrap();
        let mut journal = Journal::create(&journals, id()).unwrap();
        journal.append(&begin()).unwrap();
        let root = {
            let mut rows = Checked {
                journal: &mut journal,
                run: &run.path,
            };
            create_root(&run.dir, &run.path, &group(), &mut rows).expect("the root is made")
        };
        let unfinished = replay_dir(&journals, super::BOOT).unwrap();
        assert_eq!(unfinished.len(), 1);
        match unfinished[0].tracker.root() {
            RootState::Made(name, key) => {
                assert_eq!(run.path.join(name.as_str()), root.path());
                assert_eq!(*key, root.key());
            }
            other => panic!("the root is recorded as made: {other:?}"),
        }
        let guard = privilege::enter().expect("the walk's privileges can be enabled");
        let leftovers = {
            let mut rows = Checked {
                journal: &mut journal,
                run: &run.path,
            };
            remove_root(&root, &guard, &mut rows).expect("the removal runs")
        };
        drop(guard);
        assert!(leftovers.is_empty(), "{leftovers:?}");
        let unfinished = replay_dir(&journals, super::BOOT).unwrap();
        assert_eq!(unfinished[0].tracker.root(), &RootState::Removed);
        assert!(journals.join(file_name(id())).exists());
    }
}
