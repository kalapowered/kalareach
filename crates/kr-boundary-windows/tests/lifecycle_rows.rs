//! What the end of an invocation proves and the rows that close it, on facts alone: a proved end
//! needs the processes ended, a scan that reported nothing and a session that is gone; the rows that
//! close an invocation journal what is unresolved first, and only an invocation with nothing of its
//! tree, its repository or its end left is ended. Every row is applied to the journal's own tracker,
//! which refuses a row out of order.

use kr_boundary_windows::filekey::FileKey;
use kr_boundary_windows::frame::invocation::{
    Cleanup, ConfigurationState, EndedBy, InvocationReply, LeftoverClass as ReplyClass, RefusedKind,
};
use kr_boundary_windows::journal::replay::{Standing, Tracker};
use kr_boundary_windows::journal::rows::{
    DigestedFile, LeftoverClass, RootName, Row, SnapshotKind,
};
use kr_boundary_windows::lifecycle::{
    self, Closing, Ending, Evidence, Left, Session, Uncertainty, cleanup_of, closing_rows,
    configuration_of, ending_reply, root_object,
};

const BOOT: &str = "11111111-1111-1111-1111-111111111111";
const ID: &str = "000102030405060708090a0b0c0d0e0f";
/// An object of the private root as the ending names it: the root's path, then the name below it.
const FILE: &str = r"C:\ProgramData\Boundary\run\0a1b\x\file.lock";

fn key(n: u64) -> FileKey {
    FileKey::ntfs(0xabcd, n)
}

fn left(object: &str) -> Left {
    Left {
        object: object.to_owned(),
        reason: "a case's reason".to_owned(),
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
        absent_names: Vec::new(),
    }
}

/// An invocation whose process ended and whose private root was removed, as the ending function
/// leaves it just before it closes the journal.
fn ended_invocation() -> Tracker {
    ended_with_root_leftovers(&[])
}

/// The same, after an earlier end that left these objects of the private root open and did not
/// finish: the removal of the root has since succeeded, and the closing rows are still to come.
fn ended_with_root_leftovers(open: &[&str]) -> Tracker {
    let mut tracker = Tracker::new();
    let mut rows = vec![
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
        },
        snapshot(0, SnapshotKind::Initial),
        Row::RootIntent {
            name: RootName::from_bytes([3; 16]),
        },
        Row::RootMade {
            name: RootName::from_bytes([3; 16]),
            key: key(40),
        },
        Row::GrantComplete { count: 0 },
        Row::ProcessStarted {
            pid: 12,
            creation_time: 34,
        },
        Row::JobEnded,
    ];
    for object in open {
        rows.push(Row::Leftover {
            object: (*object).to_owned(),
            reason: "a case's reason".to_owned(),
            class: LeftoverClass::Root,
            snapshot: None,
        });
    }
    rows.push(Row::RootRemoved);
    for row in rows {
        tracker
            .apply(&row)
            .unwrap_or_else(|error| panic!("{row:?}: {error}"));
    }
    tracker
}

fn closing() -> Closing {
    Closing {
        objects_released: 0,
        tree: Vec::new(),
        repository: None,
        root: Vec::new(),
        root_recorded: Vec::new(),
    }
}

fn apply_all(tracker: &mut Tracker, rows: &[Row]) {
    for row in rows {
        tracker
            .apply(row)
            .unwrap_or_else(|error| panic!("{row:?}: {error}"));
    }
}

fn proved() -> Evidence {
    Evidence {
        processes_ended: true,
        process_reasons: Vec::new(),
        scan_reports: Vec::new(),
        session: Session::Absent,
    }
}

#[test]
fn an_end_is_proved_only_by_ended_processes_a_quiet_scan_and_an_absent_session() {
    assert_eq!(proved().uncertainty(), None);
}

#[test]
fn a_session_that_is_still_there_makes_the_end_uncertain_though_everything_else_is_quiet() {
    let evidence = Evidence {
        session: Session::Present,
        ..proved()
    };
    assert_eq!(evidence.uncertainty(), Some(Uncertainty::SessionPresent));
}

#[test]
fn a_scan_report_makes_the_end_uncertain_though_the_session_is_gone() {
    let evidence = Evidence {
        scan_reports: vec!["process 812 carries the group outside the job".to_owned()],
        ..proved()
    };
    assert!(matches!(
        evidence.uncertainty(),
        Some(Uncertainty::Scan(found)) if found.len() == 1
    ));
}

#[test]
fn a_session_that_cannot_be_read_is_no_absence() {
    let evidence = Evidence {
        session: Session::Unread("the list was refused".to_owned()),
        ..proved()
    };
    assert!(matches!(
        evidence.uncertainty(),
        Some(Uncertainty::SessionUnread(reason)) if reason.contains("refused")
    ));
}

#[test]
fn processes_that_were_not_seen_to_end_are_uncertain_whatever_the_session_says() {
    let evidence = Evidence {
        processes_ended: false,
        process_reasons: vec!["the job counts a process".to_owned()],
        ..proved()
    };
    let uncertainty = evidence.uncertainty().expect("uncertain");
    assert!(
        uncertainty.to_string().contains("the job counts a process"),
        "{uncertainty}"
    );
}

#[test]
fn a_clean_closing_verifies_the_release_and_ends_the_invocation() {
    let rows = closing_rows(&closing());
    assert_eq!(rows.len(), 2, "{rows:?}");
    let mut tracker = ended_invocation();
    apply_all(&mut tracker, &rows);
    assert_eq!(tracker.standing(), Standing::Finished);
    assert_eq!(cleanup_of(&closing()), Cleanup::Clean);
}

#[test]
fn a_leftover_of_the_tree_is_journalled_and_no_row_says_the_invocation_ended() {
    let closing = Closing {
        tree: vec![left(r"C:\work\tree\a.txt")],
        ..closing()
    };
    let rows = closing_rows(&closing);
    assert!(
        rows.iter()
            .all(|row| !matches!(row, Row::End { .. } | Row::ReleaseVerified { .. })),
        "{rows:?}"
    );
    let mut tracker = ended_invocation();
    apply_all(&mut tracker, &rows);
    assert_eq!(tracker.standing(), Standing::Unfinished);
    assert!(tracker.holds_the_slot());
    assert!(matches!(
        cleanup_of(&closing),
        Cleanup::Failed {
            class: ReplyClass::Tree,
            ..
        }
    ));
}

#[test]
fn a_leftover_of_the_private_root_comes_before_the_end_and_frees_the_slot() {
    let closing = Closing {
        root: vec![left(FILE)],
        ..closing()
    };
    let rows = closing_rows(&closing);
    let leftover_at = rows
        .iter()
        .position(|row| {
            matches!(
                row,
                Row::Leftover {
                    class: LeftoverClass::Root,
                    ..
                }
            )
        })
        .expect("the leftover is journalled");
    let end_at = rows
        .iter()
        .position(|row| matches!(row, Row::End { root_leftovers: 1 }))
        .expect("the end counts it");
    assert!(leftover_at < end_at, "{rows:?}");
    let mut tracker = ended_invocation();
    apply_all(&mut tracker, &rows);
    assert_eq!(tracker.standing(), Standing::Finished);
    assert!(!tracker.holds_the_slot());
    assert_eq!(tracker.leftovers().len(), 1);
    // The slot is free, and the reply still says what is left and where.
    assert_eq!(
        cleanup_of(&closing),
        Cleanup::Failed {
            object: FILE.to_owned(),
            class: ReplyClass::Root,
        }
    );
}

#[test]
fn an_object_of_the_private_root_is_named_by_the_root_and_the_root_itself_by_its_own_path() {
    let root = r"C:\ProgramData\Boundary\run\0a1b";
    assert_eq!(
        root_object(root, r"x\file.lock"),
        r"C:\ProgramData\Boundary\run\0a1b\x\file.lock"
    );
    assert_eq!(root_object(root, ""), root);
}

#[test]
fn a_root_leftover_that_an_earlier_end_left_open_is_cleared_when_the_removal_no_longer_finds_it() {
    // The earlier end crashed after the first leftover row of the private root; the removal now
    // finds nothing, so the end counts none and the tracker takes it.
    let closing = Closing {
        root_recorded: vec![FILE.to_owned()],
        ..closing()
    };
    let rows = closing_rows(&closing);
    assert!(
        rows.iter().any(|row| matches!(
            row,
            Row::LeftoverCleared { key } if key == FILE
        )),
        "{rows:?}"
    );
    assert!(
        rows.iter()
            .any(|row| matches!(row, Row::End { root_leftovers: 0 })),
        "{rows:?}"
    );
    let mut tracker = ended_with_root_leftovers(&[FILE]);
    apply_all(&mut tracker, &rows);
    assert_eq!(tracker.standing(), Standing::Finished);
    assert!(!tracker.holds_the_slot());
    assert!(tracker.leftovers().is_empty());
}

#[test]
fn a_root_leftover_that_the_removal_finds_again_is_not_journalled_twice_and_the_end_counts_it() {
    let closing = Closing {
        root: vec![left(FILE)],
        root_recorded: vec![FILE.to_owned()],
        ..closing()
    };
    let rows = closing_rows(&closing);
    assert!(
        rows.iter()
            .all(|row| !matches!(row, Row::Leftover { .. } | Row::LeftoverCleared { .. })),
        "{rows:?}"
    );
    let mut tracker = ended_with_root_leftovers(&[FILE]);
    apply_all(&mut tracker, &rows);
    assert_eq!(tracker.standing(), Standing::Finished);
    assert!(!tracker.holds_the_slot());
    assert_eq!(tracker.leftovers().len(), 1);
}

#[test]
fn the_end_counts_the_open_root_leftovers_after_a_clearance_and_a_new_leftover() {
    // Open from the earlier end: a and b. The removal finds b and c: a is cleared, c is new.
    let closing = Closing {
        root: vec![left("b"), left("c")],
        root_recorded: vec!["a".to_owned(), "b".to_owned()],
        ..closing()
    };
    let rows = closing_rows(&closing);
    let mut tracker = ended_with_root_leftovers(&["a", "b"]);
    apply_all(&mut tracker, &rows);
    assert_eq!(tracker.standing(), Standing::Finished);
    let mut open: Vec<&str> = tracker
        .leftovers()
        .iter()
        .map(|leftover| leftover.object.as_str())
        .collect();
    open.sort_unstable();
    assert_eq!(open, ["b", "c"]);
    assert!(
        rows.iter()
            .any(|row| matches!(row, Row::End { root_leftovers: 2 })),
        "{rows:?}"
    );
}

#[test]
fn a_changed_repository_is_journalled_as_a_snapshot_before_the_leftover_that_names_it() {
    let closing = Closing {
        repository: Some((
            snapshot(1, SnapshotKind::Changed),
            left(r"C:\work\tree\.git\hooks\pre-commit"),
        )),
        ..closing()
    };
    let rows = closing_rows(&closing);
    assert!(
        matches!(rows[0], Row::RepositorySnapshot { id: 1, .. }),
        "{rows:?}"
    );
    assert!(
        matches!(
            rows[1],
            Row::Leftover {
                class: LeftoverClass::Repository,
                snapshot: Some(1),
                ..
            }
        ),
        "{rows:?}"
    );
    assert!(
        rows.iter()
            .all(|row| !matches!(row, Row::End { .. } | Row::ReleaseVerified { .. })),
        "{rows:?}"
    );
    let mut tracker = ended_invocation();
    apply_all(&mut tracker, &rows);
    assert_eq!(tracker.standing(), Standing::Unfinished);
    assert!(matches!(
        cleanup_of(&closing),
        Cleanup::Failed {
            class: ReplyClass::Repository,
            ..
        }
    ));
}

#[test]
fn a_changed_repository_reaches_the_final_reply_as_a_changed_configuration() {
    let changed = Closing {
        repository: Some((
            snapshot(1, SnapshotKind::Changed),
            left(r"C:\work\tree\.git\hooks\pre-commit"),
        )),
        ..closing()
    };
    let configuration = configuration_of(&changed);
    assert_eq!(
        configuration,
        ConfigurationState::Changed {
            name: r"C:\work\tree\.git\hooks\pre-commit".to_owned()
        }
    );
    match ending_reply(
        None,
        EndedBy::Exit,
        Some(0),
        cleanup_of(&changed),
        configuration.clone(),
    ) {
        Ending::Finished(InvocationReply::Finished {
            configuration: said,
            cleanup,
            ..
        }) => {
            assert_eq!(said, configuration);
            assert!(matches!(
                cleanup,
                Cleanup::Failed {
                    class: ReplyClass::Repository,
                    ..
                }
            ));
        }
        other => panic!("{other:?}"),
    }
    // A configuration that is the same stays the same.
    assert_eq!(configuration_of(&closing()), ConfigurationState::Same);
}

#[test]
fn every_refusal_of_the_lifecycle_has_its_kind_and_a_printable_text_within_the_frame() {
    let refusals = [
        (lifecycle::busy(), RefusedKind::Busy),
        (
            lifecycle::leftover(r"C:\work\tree\a.txt"),
            RefusedKind::Leftover,
        ),
        (lifecycle::uncertain(), RefusedKind::Leftover),
        (lifecycle::maintenance(), RefusedKind::Maintenance),
        (lifecycle::not_connected(), RefusedKind::Transport),
        (
            lifecycle::not_started("the logon was refused"),
            RefusedKind::Operation,
        ),
    ];
    for (refusal, kind) in refusals {
        assert_eq!(refusal.kind, kind, "{refusal}");
        assert!(refusal.detail().len() <= 200, "{refusal}");
        assert!(
            refusal
                .detail()
                .bytes()
                .all(|byte| (0x20..0x7f).contains(&byte)),
            "{refusal}"
        );
    }
    let named = lifecycle::leftover(r"C:\work\tree\a.txt");
    assert!(named.detail().ends_with(r"C:\work\tree\a.txt"), "{named}");
    assert_eq!(
        lifecycle::uncertain().detail(),
        lifecycle::UNCERTAIN_END_WORDS
    );
}

#[test]
fn an_operation_that_did_not_start_is_a_refusal_when_nothing_is_left_and_says_so_when_something_is()
{
    let refusal = lifecycle::not_started("the logon was refused");
    assert_eq!(
        ending_reply(
            Some(refusal.clone()),
            EndedBy::Exit,
            None,
            Cleanup::Clean,
            ConfigurationState::Same,
        ),
        Ending::Refused(refusal.clone())
    );
    for cleanup in [
        Cleanup::Uncertain,
        Cleanup::Failed {
            object: "a.txt".to_owned(),
            class: ReplyClass::Tree,
        },
    ] {
        // Whatever ending the caller names, a failed start with something left says `not-started`
        // and carries no exit code.
        let reply = ending_reply(
            Some(refusal.clone()),
            EndedBy::Exit,
            Some(0),
            cleanup.clone(),
            ConfigurationState::Same,
        );
        match reply {
            Ending::Finished(InvocationReply::Finished {
                ended_by,
                exit,
                cleanup: said,
                ..
            }) => {
                assert_eq!(ended_by, EndedBy::NotStarted);
                assert_eq!(exit, None);
                assert_eq!(said, cleanup);
            }
            other => panic!("{other:?}"),
        }
    }
    // A real stop of the service began the ending: the reply keeps it, whatever else failed.
    match ending_reply(
        Some(refusal),
        EndedBy::Stop,
        None,
        Cleanup::Uncertain,
        ConfigurationState::Same,
    ) {
        Ending::Finished(InvocationReply::Finished { ended_by, exit, .. }) => {
            assert_eq!(ended_by, EndedBy::Stop);
            assert_eq!(exit, None);
        }
        other => panic!("{other:?}"),
    }
    // An ending that no failure began keeps the ending the caller names and its exit code.
    match ending_reply(
        None,
        EndedBy::Cancel,
        Some(3),
        Cleanup::Uncertain,
        ConfigurationState::Same,
    ) {
        Ending::Finished(InvocationReply::Finished { ended_by, exit, .. }) => {
            assert_eq!(ended_by, EndedBy::Cancel);
            assert_eq!(exit, Some(3));
        }
        other => panic!("{other:?}"),
    }
}
