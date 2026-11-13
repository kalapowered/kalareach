//! What the words of a refusal claim: nothing that no read showed. Each sentence says what a call
//! returned, a rule of the installation, or, for a folder that the installation makes, what to
//! correct. They run on every platform.

use std::path::Path;

use kr_boundary_windows::records::{Held, Look, next_step};
use kr_boundary_windows::remedy::{
    CASE_SENSITIVE_WHY, EntryKind, Grounds, Origin, ParentCure, Presence, Purpose, Standing,
    choose, data_ending, data_made_ending, ending, parent_advice, program_keeping,
    program_open_advice, unnamed_root_why,
};

/// An installation whose reads found nothing of the installation: the one run that may name a move.
fn at_install() -> Grounds<'static> {
    Grounds::new(Purpose::Install, &|| Standing::NothingFound)
}

/// Every purpose with each answer that its reads could give.
fn purposes_and_standings() -> Vec<(Purpose, Standing)> {
    let found =
        Standing::MayBeInstalled("a read of the accounts failed (Windows error 5)".to_owned());
    [
        Purpose::Install,
        Purpose::Repair,
        Purpose::Remove,
        Purpose::Status,
    ]
    .into_iter()
    .flat_map(|purpose| [(purpose, Standing::NothingFound), (purpose, found.clone())])
    .collect()
}

/// Every state that an entry's refusal can be told in.
fn every_state() -> Vec<(EntryKind, Origin, Presence)> {
    let kinds = [
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
    let origins = [
        Origin::System,
        Origin::Foreign,
        Origin::Owned("S-1-5-21-1-2-3-1001".to_owned()),
        Origin::Held("Windows error 32".to_owned()),
        Origin::Refused("Windows error 5".to_owned()),
        Origin::Unknown("Windows error 1".to_owned()),
        Origin::Changed("it was another object".to_owned()),
    ];
    let manifests = [
        Presence::Present,
        Presence::Absent,
        Presence::Unknown("Windows error 1".to_owned()),
    ];
    let mut states = Vec::new();
    for kind in kinds {
        for origin in &origins {
            for manifest in &manifests {
                states.push((kind, origin.clone(), manifest.clone()));
            }
        }
    }
    states
}

/// No ending says that the journal is there or what an entry holds: the lookup reads the manifest's
/// name alone, so only the manifest is said to stay, and only where that lookup found it.
#[test]
fn no_ending_of_an_entry_claims_the_journal_or_what_the_entry_holds() {
    for (kind, origin, manifest) in every_state() {
        let remedy = choose(&at_install(), kind, &origin, &manifest, None);
        let text = ending(
            Path::new(r"D:\data\entry"),
            &remedy,
            &origin,
            kind,
            &manifest,
            None,
        );
        let what = format!("{kind:?} {origin:?} {manifest:?}: {text}");
        assert!(!text.contains("stay where they are"), "{what}");
        assert!(!text.contains("record what is installed and"), "{what}");
        assert_eq!(
            text.contains("the entry at the manifest's name stays where it is"),
            text.starts_with("Remove ") && manifest == Presence::Present,
            "{what}"
        );
        // The entry that is corrected is one of the installation's own by its name, which may hold
        // records: nothing says that it does.
        if text.starts_with("Correct ") {
            assert!(
                text.contains(
                    "by its name it is one of the installation's own entries, which may hold records of what is installed"
                ),
                "{what}"
            );
        }
    }
}

/// The folder that holds the data directory, where an entry is at the data directory's name, is
/// not said to hold an installation: nothing read what the entry is, so the words say that
/// something is there and that it can hold the records.
#[test]
fn the_words_for_an_entry_at_the_data_directorys_name_claim_nothing_of_it() {
    let text = parent_advice(&ParentCure::Correct(Presence::Present));
    assert!(
        text.contains("something is at the data directory's name in it"),
        "{text}"
    );
    assert!(
        text.contains(
            "that can hold the manifest, the journals and the private roots of an installation"
        ),
        "{text}"
    );
    assert!(text.contains("Correct its list instead"), "{text}");
    assert!(!text.contains("it holds the data directory"), "{text}");
    assert!(!text.contains("what they say"), "{text}");
    // Where the lookup failed, the words say that it did and that the entry can hold the records.
    let unknown = parent_advice(&ParentCure::Correct(Presence::Unknown("e".to_owned())));
    assert!(unknown.contains("could not be read (e)"), "{unknown}");
    assert!(unknown.contains("it can hold the manifest"), "{unknown}");
}

/// The endings of the data directory say only what its handle and the run's reads showed. They name
/// what to correct only where the system's class owns it and say that nothing in it is removed: they
/// do not say that a manifest or a journal is there. The words that tell an administrator to move
/// the directory aside stand only at an installation where the handle shows what the installation
/// does not set (a link, another kind of object or an owner outside the class) and every read
/// found nothing of the installation; at a removal and a repair, and where a part of the
/// installation may be there, no ending takes the directory away and none forecasts that the
/// installation makes it new. An owner that was read is named. Where a read failed, the ending names
/// that read and its error and gives no step and no forecast.
#[test]
fn the_endings_of_the_data_directory_claim_nothing_of_what_it_holds() {
    let owner = "S-1-5-21-1-2-3-1001";
    for origin in [
        Origin::System,
        Origin::Foreign,
        Origin::Owned(owner.to_owned()),
        Origin::Held("the open of it: Windows error 32".to_owned()),
        Origin::Refused("the open of it: Windows error 5".to_owned()),
        Origin::Unknown("the owner: Windows error 1117".to_owned()),
        Origin::Changed("it was another object".to_owned()),
    ] {
        let not_set = matches!(origin, Origin::Foreign | Origin::Owned(_));
        for case_sensitive in [false, true] {
            // Every purpose with every answer of the reads: only an installation whose reads found
            // nothing has a clearance, and the answer of the reads is not even asked for any other
            // purpose.
            for (purpose, standing) in purposes_and_standings() {
                let reads = || standing.clone();
                let grounds = Grounds::new(purpose, &reads);
                let text = data_ending(&grounds, &origin, case_sensitive);
                let withheld = purpose == Purpose::Install && standing != Standing::NothingFound;
                let what = format!("{origin:?} {case_sensitive} {purpose:?} {standing:?}: {text}");
                assert!(!text.contains("stay where they are"), "{what}");
                assert!(!text.contains("The manifest and the journal"), "{what}");
                assert_eq!(
                    text.contains("Nothing in it is removed."),
                    origin == Origin::System,
                    "{what}"
                );
                let moved =
                    not_set && purpose == Purpose::Install && standing == Standing::NothingFound;
                assert_eq!(text.contains("Move it aside"), moved, "{what}");
                assert_eq!(
                    text.contains("the installation makes the directory new"),
                    moved,
                    "{what}"
                );
                assert_eq!(
                    text.contains(
                        "found no service of the installation's name, no account of the installation's two names and none that carries its comment, and none of its rules. They do not see an account that was renamed and whose comment was changed."
                    ),
                    moved,
                    "{what}"
                );
                assert_eq!(
                    text.contains(
                        "Move it aside only if you know that nothing of an installation is left"
                    ),
                    moved,
                    "{what}"
                );
                // An installation where a read found a part of the installation or failed says which
                // read, with its error, where a move would otherwise be named; no other purpose reads.
                assert_eq!(
                    text.contains("did not show that nothing of an installation is left: a read of the accounts failed (Windows error 5)."),
                    not_set && withheld,
                    "{what}"
                );
                if let Origin::Owned(read) = &origin {
                    assert!(text.contains(read.as_str()), "{what}");
                }
                // The owner is read only for an owner outside the class and for the system's class:
                // a link or another kind of object has no owner read, so nothing is said of one.
                if origin == Origin::Foreign {
                    assert!(!text.contains("Whoever"), "{what}");
                    assert!(!text.contains("owner"), "{what}");
                }
                if not_set && !moved {
                    for claim in ["move it aside", "Move", "rename", "makes the directory new"] {
                        assert!(!text.contains(claim), "{claim}: {what}");
                    }
                    assert!(text.contains("does not use the records in it"), "{what}");
                    assert_eq!(
                        text.contains(
                            "give the ownership of the data directory and of everything in it back to the Administrators group"
                        ),
                        matches!(origin, Origin::Owned(_)),
                        "{what}"
                    );
                    assert_eq!(
                        text.contains("while that account owns it"),
                        matches!(origin, Origin::Owned(_)),
                        "{what}"
                    );
                }
                if let Origin::Held(read) | Origin::Refused(read) | Origin::Unknown(read) = &origin
                {
                    assert!(text.contains(read.as_str()), "{what}");
                    for claim in [
                        "Move it aside",
                        "move it aside",
                        "rename",
                        "do not remove",
                        "Do not",
                        "Close the program",
                        "again",
                        "can hold",
                        "Whoever",
                        "another account",
                        "Turn the flag",
                        "Leave the system",
                    ] {
                        assert!(!text.contains(claim), "{claim}: {what}");
                    }
                }
            }
        }
    }
    let flag = data_ending(&at_install(), &Origin::System, true);
    assert!(flag.contains("setCaseSensitiveInfo"), "{flag}");
    let owner = data_ending(&at_install(), &Origin::System, false);
    assert!(
        owner.contains(
            "Leave the system and the Administrators group as the only entries of its list"
        ),
        "{owner}"
    );
    assert!(CASE_SENSITIVE_WHY.starts_with("it separates names that differ only by case"));
}

/// The ending of a data directory that this run made says what the run did with what it made and
/// names what stayed; it gives no step and no forecast, since a run that removed what it made
/// leaves nothing to move, to correct or to run against.
#[test]
fn the_ending_of_a_directory_this_run_made_says_what_was_removed_and_gives_no_step() {
    let gone = data_made_ending(true, &[]);
    assert!(gone.contains("removed what it made"), "{gone}");
    let stayed = data_made_ending(
        false,
        &["C:\\Kala (e)".to_owned(), "C:\\Kala\\Data (f)".to_owned()],
    );
    assert!(stayed.contains("could not remove what it made"), "{stayed}");
    assert!(
        stayed.contains("C:\\Kala (e); C:\\Kala\\Data (f)"),
        "{stayed}"
    );
    // The directory is gone and the folder above it stays: the words say that, and not that the
    // directory stays or that nothing is left.
    let folder_stays = data_made_ending(true, &["C:\\Kala (f)".to_owned()]);
    assert!(
        folder_stays.contains("removed the data directory that it made"),
        "{folder_stays}"
    );
    assert!(
        folder_stays.contains("could not remove the folder above it that it also made: C:\\Kala (f). That folder stays."),
        "{folder_stays}"
    );
    for wrong in ["could not remove what it made", "nothing of it is left"] {
        assert!(!folder_stays.contains(wrong), "{folder_stays}");
    }
    for text in [&gone, &stayed, &folder_stays] {
        for step in [
            "Move it aside",
            "Turn the flag",
            "Leave the system",
            "again",
        ] {
            assert!(!text.contains(step), "{text}");
        }
    }
}

/// A refusal in the program directory says that the manifest records the installation, which a read
/// of the manifest showed, and never that it records the entry, which no read showed.
#[test]
fn the_program_directorys_refusals_say_that_the_manifest_records_the_installation() {
    for whole in [false, true] {
        let recorded = program_keeping(true, whole);
        assert!(
            recorded.contains("the manifest records the installation and stays where it is"),
            "{recorded}"
        );
        assert!(!recorded.contains("records it"), "{recorded}");
        let unread = program_keeping(false, whole);
        assert!(!unread.contains("manifest"), "{unread}");
        assert_eq!(
            program_keeping(true, whole).contains("program directory"),
            whole
        );
    }
}

/// An entry that could not be opened is never said to be held by a program: every cause is a
/// condition, and the one that applies is for the person to find.
#[test]
fn an_entry_that_could_not_be_opened_is_not_said_to_be_held_by_a_program() {
    let text = program_open_advice(
        r"C:\Program Files\KalaReach\Boundary\x",
        program_keeping(true, true),
    );
    assert!(
        text.starts_with(
            r"If a program holds C:\Program Files\KalaReach\Boundary\x open, close that program."
        ),
        "{text}"
    );
    assert!(
        text.contains("If its list refuses the check, correct who may open it."),
        "{text}"
    );
    // An open that failed is no sign of a link or of a file: the advice names neither.
    assert!(!text.contains("link"), "{text}");
    assert!(!text.contains("not a folder"), "{text}");
    assert!(!text.starts_with("Close the program"), "{text}");
    assert!(text.ends_with(program_keeping(true, true)), "{text}");
}

/// A private root that no journal names is said to be named by none, and nothing is said of what the
/// broker is doing.
#[test]
fn a_root_that_no_journal_names_is_not_said_to_be_idle() {
    assert_eq!(
        unnamed_root_why(&[]),
        "no journal that could be read names it as unfinished work"
    );
}

/// A damaged journal is named, with what is wrong with it, and is said to be read only up to the
/// damage: a root that no journal names in the rows that were read is not said to be named by no
/// journal that could be read.
#[test]
fn a_damaged_journal_is_named_where_a_root_is_said_to_be_named_by_none() {
    let text = unnamed_root_why(&[("run-7", "record 3 is not a row: bad tag")]);
    assert!(
        text.contains(
            "the journal of the invocation run-7 is damaged (record 3 is not a row: bad tag)"
        ),
        "{text}"
    );
    assert!(
        text.contains("its rows after the damage were not read"),
        "{text}"
    );
    assert!(text.starts_with("no journal names it as unfinished work in the rows that were read"));
    assert!(!text.contains("could be read names"), "{text}");
    let two = unnamed_root_why(&[("a", "x"), ("b", "y")]);
    assert!(
        two.contains("the invocation a is damaged (x)")
            && two.contains("the invocation b is damaged (y)")
    );
}

/// A data directory that stayed empty is said to be held only as a condition.
#[test]
fn an_empty_data_directory_that_stayed_is_not_said_to_be_held() {
    let text = next_step(&Look::NotThere, &Held::Nothing);
    assert!(
        text.contains("if a program holds it (a console that has it as its current directory, for one), close that program"),
        "{text}"
    );
    assert!(!text.contains("close what holds it"), "{text}");
}
