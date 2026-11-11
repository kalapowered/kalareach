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
use kr_boundary_windows::journal::replay::{self, Reading, RootState, Standing, Tracker};
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
    // The reviewers' first sequence ends in a finished invocation with a granted key nobody
    // releases; here it stops at the grant.
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
    // The reviewer's sequence: the directory may exist, its removal failed, the invocation ended
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

#[test]
fn a_grant_that_would_take_the_journal_past_its_bound_is_refused_before_it_is_written() {
    use kr_boundary_windows::journal::replay::ROWS_APART_FROM_OBJECTS;
    // For each bound, grant objects until one is refused, then release every granted object the
    // way the release does, and the whole file is within the bound.
    let mut stopped_at = Vec::new();
    for room in (0..60).map(|step| step * 2_000) {
        let limit = ROWS_APART_FROM_OBJECTS + room;
        let mut tracker = Tracker::bounded(limit);
        let mut rows = vec![begin()];
        tracker.apply(&begin()).unwrap();
        let mut granted = 0;
        for n in 1..=50 {
            match tracker.apply(&grant(n)) {
                Ok(()) => {
                    rows.push(grant(n));
                    granted += 1;
                }
                Err(_) => break,
            }
        }
        stopped_at.push(granted);
        rows.push(Row::GrantComplete { count: granted });
        tracker.apply(rows.last().unwrap()).unwrap();
        for n in 1..=granted {
            for row in [release_intent(n), released(n)] {
                tracker.apply(&row).unwrap();
                rows.push(row);
            }
        }
        for row in [verified(granted), Row::End { root_leftovers: 0 }] {
            tracker.apply(&row).unwrap();
            rows.push(row);
        }
        assert!(
            file_of(&rows).len() <= limit,
            "{granted} objects with their release rows fit a bound of {limit} bytes"
        );
    }
    assert!(
        stopped_at.contains(&0),
        "a bound too small for any object stops the grant"
    );
    assert!(stopped_at.contains(&50), "a roomy bound stops nothing");
    assert!(
        stopped_at.windows(2).all(|pair| pair[0] <= pair[1]),
        "more room never grants fewer objects: {stopped_at:?}"
    );
    // A refused grant changed nothing: the same tracker takes a row that fits.
    let mut tracker = Tracker::bounded(ROWS_APART_FROM_OBJECTS);
    tracker.apply(&begin()).unwrap();
    assert!(tracker.apply(&grant(1)).is_err());
    tracker.apply(&Row::GrantComplete { count: 0 }).unwrap();
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
        file.set_len(kr_boundary_windows::journal::replay::MAX_FILE as u64 + 4096)
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
