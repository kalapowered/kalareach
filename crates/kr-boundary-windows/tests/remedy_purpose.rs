//! No ending of an object on the way to the installation's records (the folder above the data
//! directory, the data directory, the manifest, the journal and every other entry in it) tells an
//! administrator to move, rename or remove it, unless the run has a clearance, and only an
//! installation whose every read found nothing of the installation has one. One case walks every
//! finding for every object and every purpose, and fails where the words of a move stand for a
//! removal, a repair or a status report, or where a clearance exists for another state.

use std::cell::Cell;
use std::path::Path;

use kr_boundary_windows::remedy::{
    EntryKind, Grounds, Origin, ParentCure, Presence, Purpose, Record, Remedy, Stage, Standing,
    choose, data_ending, ending, parent_advice,
};

const PURPOSES: [Purpose; 4] = [
    Purpose::Install,
    Purpose::Repair,
    Purpose::Remove,
    Purpose::Status,
];

const STANDINGS: [Standing; 2] = [Standing::NothingFound, Standing::MayBeInstalled];

const KINDS: [EntryKind; 10] = [
    EntryKind::Manifest,
    EntryKind::Prior,
    EntryKind::Replacement,
    EntryKind::Staging,
    EntryKind::Journal,
    EntryKind::Run,
    EntryKind::JournalFile,
    EntryKind::NamedRoot,
    EntryKind::UnnamedRoot,
    EntryKind::Other,
];

fn origins() -> Vec<Origin> {
    vec![
        Origin::System,
        Origin::Foreign,
        Origin::Owned("S-1-5-21-1-2-3-1001".to_owned()),
        Origin::Held("Windows error 32".to_owned()),
        Origin::Refused("Windows error 5".to_owned()),
        Origin::Unknown("Windows error 1117".to_owned()),
        Origin::Changed("the identifier names another object".to_owned()),
    ]
}

fn lookups() -> [Presence; 3] {
    [
        Presence::Present,
        Presence::Absent,
        Presence::Unknown("Windows error 5".to_owned()),
    ]
}

/// Whether the words tell the reader to move, rename or remove something: the verb, in any form that
/// is an instruction, unless it is a prohibition ("do not remove it").
fn says_a_move(text: &str) -> bool {
    let lower = text.to_lowercase();
    let words: Vec<&str> = lower
        .split(|c: char| !c.is_alphabetic())
        .filter(|word| !word.is_empty())
        .collect();
    words.iter().enumerate().any(|(at, word)| {
        matches!(*word, "move" | "remove" | "rename") && !(at > 0 && words[at - 1] == "not")
    })
}

/// Every purpose with every answer that its reads could give, with a count of how often the reads
/// were made.
fn each_run(mut check: impl FnMut(Purpose, Standing, &Grounds<'_>, bool)) {
    for purpose in PURPOSES {
        for standing in STANDINGS {
            let asked = Cell::new(0_u32);
            let reads = || {
                asked.set(asked.get() + 1);
                standing
            };
            let grounds = Grounds::new(purpose, &reads);
            let moves = purpose == Purpose::Install && standing == Standing::NothingFound;
            check(purpose, standing, &grounds, moves);
            if purpose != Purpose::Install {
                assert_eq!(
                    asked.get(),
                    0,
                    "a {purpose:?} never asks what the reads found of the installation"
                );
            }
        }
    }
}

/// The clearance exists for one state alone: an installation whose reads found nothing.
#[test]
fn a_clearance_exists_only_for_an_installation_that_found_nothing() {
    each_run(|purpose, standing, grounds, moves| {
        assert_eq!(
            grounds.clearance().is_some(),
            moves,
            "{purpose:?} {standing:?}"
        );
        assert_eq!(grounds.purpose(), purpose);
    });
}

/// The words of a step that takes an object out of its place stand only with a clearance: for the
/// folder above the data directory never, for the data directory and for each entry only for an
/// installation whose reads found nothing.
#[test]
fn no_ending_of_any_object_tells_a_removal_a_repair_or_a_status_report_to_move_it() {
    // The folder above the data directory: no state of it carries a move, whatever the run does.
    let stages = [
        Stage::Before,
        Stage::After,
        Stage::AfterRepair {
            broker_stopped: true,
        },
        Stage::AfterRepair {
            broker_stopped: false,
        },
        Stage::DataParentMade,
        Stage::Rollback,
    ];
    let mut parents = vec![
        ParentCure::Close,
        ParentCure::Owned("S-1-5-21-1-2-3-1001".to_owned()),
        ParentCure::NotAFolder,
        ParentCure::Unreadable,
    ];
    parents.extend(lookups().map(ParentCure::Correct));
    parents.extend(stages.map(ParentCure::Link));
    for cure in &parents {
        let text = parent_advice(cure);
        assert!(!says_a_move(&text), "{cure:?}: {text}");
    }

    let mut moves_said = 0;
    each_run(|purpose, standing, grounds, moves| {
        // The data directory, for every state of its handle and its case flag.
        for origin in origins() {
            for case_sensitive in [false, true] {
                let text = data_ending(grounds, &origin, case_sensitive);
                let what = format!(
                    "data directory {origin:?} {case_sensitive} {purpose:?} {standing:?}: {text}"
                );
                if says_a_move(&text) {
                    assert!(moves, "{what}");
                    assert!(
                        matches!(origin, Origin::Foreign | Origin::Owned(_)),
                        "{what}"
                    );
                    moves_said += 1;
                } else if moves && matches!(origin, Origin::Foreign | Origin::Owned(_)) {
                    panic!("a clearance gives the move its words: {what}");
                }
            }
        }
        // Every entry of the data directory: each kind, state of the handle, lookup of the manifest
        // and state of the manifest's record of it.
        for kind in KINDS {
            for origin in origins() {
                for manifest in lookups() {
                    for record in [None, Some(Record::Recorded), Some(Record::NotRecorded)] {
                        let remedy = choose(grounds, kind, &origin, &manifest, record);
                        let text = ending(
                            Path::new(r"D:\data\entry"),
                            &remedy,
                            &origin,
                            kind,
                            &manifest,
                            record,
                        );
                        let what = format!(
                            "{kind:?} {origin:?} {manifest:?} {record:?} {purpose:?} {standing:?}: {remedy:?}: {text}"
                        );
                        if matches!(remedy, Remedy::MoveAside(_) | Remedy::Remove(_)) {
                            assert!(moves, "a move without a clearance: {what}");
                        }
                        if says_a_move(&text) {
                            assert!(moves, "{what}");
                            assert!(
                                matches!(remedy, Remedy::MoveAside(_) | Remedy::Remove(_)),
                                "{what}"
                            );
                            moves_said += 1;
                        }
                    }
                }
            }
        }
    });
    // The check is not empty: a clearance does give the words of a move.
    assert!(moves_said > 0, "the walk met no ending with a move");
}

/// The one step for an owner outside the class says all that it rests on, in the same words for the
/// folder above the data directory, the data directory and an entry that another account owns: that
/// the administrator made the change, that no program of that account could have changed what is in
/// it meanwhile, and that the ownership of the object and of everything in it is given back.
#[test]
fn the_owner_step_says_all_that_it_rests_on_for_the_folder_the_directory_and_an_entry() {
    let owner = "S-1-5-21-1-2-3-1001";
    let folder = parent_advice(&ParentCure::Owned(owner.to_owned()));
    let mut texts = vec![("the folder above".to_owned(), "this folder", folder)];
    each_run(|purpose, _, grounds, moves| {
        if moves {
            return;
        }
        let origin = Origin::Owned(owner.to_owned());
        texts.push((
            format!("the data directory, {purpose:?}"),
            "the data directory",
            data_ending(grounds, &origin, false),
        ));
        let remedy = choose(
            grounds,
            EntryKind::Manifest,
            &origin,
            &Presence::Present,
            None,
        );
        assert_eq!(remedy, Remedy::OwnerStep(owner.to_owned()), "{purpose:?}");
        let text = ending(
            Path::new(r"D:\data\manifest.json"),
            &remedy,
            &origin,
            EntryKind::Manifest,
            &Presence::Present,
            None,
        );
        texts.push((
            format!("the manifest, {purpose:?}"),
            "the data directory",
            text,
        ));
    });
    assert!(texts.len() > 2);
    for (which, what, text) in texts {
        for part in [
            "If you made that change, and ".to_owned(),
            format!(
                "you know that no program of that account could have changed {what} or anything in it while that account owned it, "
            ),
            format!(
                "give the ownership of {what} and of everything in it back to the Administrators group, then run the setup program again."
            ),
            owner.to_owned(),
        ] {
            assert!(text.contains(&part), "{which}: {part}: {text}");
        }
        assert!(!says_a_move(&text), "{which}: {text}");
    }
}

/// A step that rests on a read that failed does not exist for any purpose: where the origin is a
/// refused open, a failed read or an object that changed, the ending names the read and gives no
/// step, with or without a clearance.
#[test]
fn a_failed_read_gives_no_step_for_any_purpose() {
    let failed = [
        Origin::Refused("Windows error 5".to_owned()),
        Origin::Unknown("Windows error 1117".to_owned()),
        Origin::Changed("the identifier names another object".to_owned()),
    ];
    each_run(|purpose, standing, grounds, _| {
        for origin in &failed {
            let text = data_ending(grounds, origin, false);
            assert!(
                text.ends_with("The setup program names no step for it."),
                "{origin:?} {purpose:?} {standing:?}: {text}"
            );
            for kind in KINDS {
                let remedy = choose(grounds, kind, origin, &Presence::Present, None);
                assert_eq!(remedy, Remedy::NoStep, "{kind:?} {origin:?}");
            }
        }
    });
}
