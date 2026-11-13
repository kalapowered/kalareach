//! What the words of a refusal claim: nothing that no read showed. Each sentence says what a call
//! returned, a rule of the installation, or, for a folder that the installation makes, what to
//! correct. They run on every platform.

use std::path::Path;

use kr_boundary_windows::records::{Held, Look, next_step};
use kr_boundary_windows::remedy::{
    CASE_SENSITIVE_WHY, EntryKind, Origin, ParentCure, Presence, UNNAMED_ROOT_WHY, choose,
    data_ending, ending, parent_advice, program_keeping, program_open_advice,
};

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
        Origin::Held("Windows error 32".to_owned()),
        Origin::Refused("Windows error 5".to_owned()),
        Origin::Unknown("Windows error 1".to_owned()),
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
        let remedy = choose(kind, &origin, &manifest);
        let text = ending(
            Path::new(r"D:\data\entry"),
            remedy,
            &origin,
            kind,
            &manifest,
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

/// The endings of the data directory itself correct its owner and its list, or turn its flag off,
/// only where the system's class owns it, and say that nothing in it is removed: they do not say
/// that a manifest or a journal is there.
#[test]
fn the_endings_of_the_data_directory_claim_nothing_of_what_it_holds() {
    for origin in [
        Origin::System,
        Origin::Foreign,
        Origin::Held("e".to_owned()),
        Origin::Refused("e".to_owned()),
        Origin::Unknown("e".to_owned()),
    ] {
        for case_sensitive in [false, true] {
            let text = data_ending(&origin, case_sensitive);
            let what = format!("{origin:?} {case_sensitive}: {text}");
            assert!(!text.contains("stay where they are"), "{what}");
            assert!(!text.contains("The manifest and the journal"), "{what}");
            assert_eq!(
                text.contains("Nothing in it is removed."),
                origin == Origin::System,
                "{what}"
            );
        }
    }
    let flag = data_ending(&Origin::System, true);
    assert!(flag.contains("setCaseSensitiveInfo"), "{flag}");
    let owner = data_ending(&Origin::System, false);
    assert!(
        owner.contains("Make the Administrators group its owner"),
        "{owner}"
    );
    assert!(CASE_SENSITIVE_WHY.starts_with("it separates names that differ only by case"));
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
    assert!(
        text.contains("If it is a link, remove the link itself and not what it points to;"),
        "{text}"
    );
    assert!(!text.starts_with("Close the program"), "{text}");
    assert!(text.ends_with(program_keeping(true, true)), "{text}");
}

/// A private root that no journal names is said to be named by none, and nothing is said of what the
/// broker is doing.
#[test]
fn a_root_that_no_journal_names_is_not_said_to_be_idle() {
    assert_eq!(UNNAMED_ROOT_WHY, "no journal names it as unfinished work");
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
