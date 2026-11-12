//! The remedy that a refusal of an entry gives comes from what the entry's own handle showed and from
//! the lookup of the manifest, never from the words of the reason. An entry that the handle shows to
//! be another account's is moved out, one that could not be read is neither corrected nor removed,
//! and only the system's class is ever corrected into place.

use std::path::Path;

use kr_boundary_windows::remedy::{
    EntryKind, Origin, ParentCure, Presence, Remedy, Shape, choose, ending, origin_of_open_error,
    origin_of_shape, parent_advice,
};

const RECORDS: [EntryKind; 9] = [
    EntryKind::Manifest,
    EntryKind::Prior,
    EntryKind::Replacement,
    EntryKind::Staging,
    EntryKind::Journal,
    EntryKind::Run,
    EntryKind::JournalFile,
    EntryKind::NamedRoot,
    EntryKind::UnnamedRoot,
];

fn unknown() -> Origin {
    Origin::Unknown("Windows error 1117".to_owned())
}

fn held() -> Origin {
    Origin::Held("Windows error 32".to_owned())
}

fn lookups() -> [Presence; 3] {
    [
        Presence::Present,
        Presence::Absent,
        Presence::Unknown("Windows error 5".to_owned()),
    ]
}

#[test]
fn a_record_that_another_account_made_is_moved_out_whatever_the_manifest_says() {
    for kind in RECORDS {
        for manifest in lookups() {
            for origin in [
                Origin::Foreign,
                Origin::Refused("Windows error 5".to_owned()),
            ] {
                assert_eq!(
                    choose(kind, &origin, &manifest),
                    Remedy::MoveAside,
                    "{kind:?} {origin:?} {manifest:?}"
                );
            }
        }
    }
}

#[test]
fn a_record_that_could_not_be_read_is_never_corrected_or_removed_whatever_the_manifest_says() {
    for kind in RECORDS {
        for manifest in lookups() {
            assert_eq!(
                choose(kind, &held(), &manifest),
                Remedy::Unreadable,
                "{kind:?} {manifest:?}"
            );
            assert_eq!(
                choose(kind, &unknown(), &manifest),
                Remedy::MoveAside,
                "{kind:?} {manifest:?}"
            );
        }
    }
}

#[test]
fn a_record_of_the_systems_class_is_corrected_while_a_manifest_may_be_there_and_removed_without_one()
 {
    for kind in RECORDS {
        for manifest in [
            Presence::Present,
            // A lookup that failed does not confirm that nothing is installed.
            Presence::Unknown("Windows error 5".to_owned()),
        ] {
            let expected = if kind == EntryKind::UnnamedRoot {
                Remedy::Remove
            } else {
                Remedy::Correct
            };
            assert_eq!(
                choose(kind, &Origin::System, &manifest),
                expected,
                "{kind:?} {manifest:?}"
            );
        }
        assert_eq!(
            choose(kind, &Origin::System, &Presence::Absent),
            Remedy::Remove,
            "{kind:?}"
        );
    }
}

#[test]
fn a_name_that_the_layout_does_not_give_is_removed_whatever_its_handle_showed() {
    for origin in [Origin::System, Origin::Foreign, unknown(), held()] {
        for manifest in lookups() {
            assert_eq!(
                choose(EntryKind::Other, &origin, &manifest),
                Remedy::Remove,
                "{origin:?} {manifest:?}"
            );
        }
    }
}

/// A private root that no journal names is removed only when its own handle shows the system's
/// class, and a root of another account or one that cannot be read is neither.
#[test]
fn a_private_root_that_no_journal_names_takes_its_remedy_from_its_handle() {
    for manifest in lookups() {
        assert_eq!(
            choose(EntryKind::UnnamedRoot, &Origin::System, &manifest),
            Remedy::Remove
        );
        assert_eq!(
            choose(EntryKind::UnnamedRoot, &Origin::Foreign, &manifest),
            Remedy::MoveAside
        );
        assert_eq!(
            choose(EntryKind::UnnamedRoot, &unknown(), &manifest),
            Remedy::MoveAside
        );
        assert_eq!(
            choose(EntryKind::UnnamedRoot, &held(), &manifest),
            Remedy::Unreadable
        );
    }
}

/// An open that failed shows what its error shows: a list that refuses, a program that holds the
/// entry, or nothing.
#[test]
fn an_open_error_is_told_apart_by_what_it_shows() {
    assert!(matches!(origin_of_open_error(5, "e"), Origin::Refused(_)));
    assert!(matches!(origin_of_open_error(32, "e"), Origin::Held(_)));
    assert!(matches!(origin_of_open_error(33, "e"), Origin::Held(_)));
    assert!(matches!(
        origin_of_open_error(1117, "e"),
        Origin::Unknown(_)
    ));
}

fn said(kind: EntryKind, origin: &Origin, manifest: &Presence) -> (Remedy, String) {
    let remedy = choose(kind, origin, manifest);
    let text = ending(Path::new("D:\\data\\entry"), remedy, origin, kind, manifest);
    (remedy, text)
}

/// "The manifest and the journal stay where they are" is said only where a manifest is there and the
/// entry is not the journal; "the next run makes it new" only of what the installation makes.
#[test]
fn the_words_of_a_remedy_say_only_what_is_true_of_the_entry_and_the_state() {
    // A removal with the manifest there, of an entry that is not the journal.
    let (remedy, text) = said(EntryKind::Other, &Origin::System, &Presence::Present);
    assert_eq!(remedy, Remedy::Remove);
    assert!(text.contains("stay where they are"), "{text}");
    // With no manifest, nothing stays beside it; and the journal that is removed does not stay.
    for (kind, manifest) in [
        (EntryKind::Prior, Presence::Absent),
        (EntryKind::JournalFile, Presence::Absent),
        (EntryKind::UnnamedRoot, Presence::Unknown("e".to_owned())),
        (EntryKind::Journal, Presence::Absent),
    ] {
        let (remedy, text) = said(kind, &Origin::System, &manifest);
        assert_eq!(remedy, Remedy::Remove, "{kind:?}");
        assert!(!text.contains("stay where they are"), "{kind:?}: {text}");
    }
    // The journal is never said to stay where it is when it is the entry that is removed.
    let text = ending(
        Path::new("D:\\data\\journal"),
        Remedy::Remove,
        &Origin::System,
        EntryKind::Journal,
        &Presence::Present,
    );
    assert!(!text.contains("stay where they are"), "{text}");
    let (_, text) = said(EntryKind::UnnamedRoot, &Origin::System, &Presence::Present);
    assert!(text.contains("stay where they are"), "{text}");
    // Moved out: the next run makes new only what the installation makes.
    for (kind, makes_it) in [
        (EntryKind::Journal, true),
        (EntryKind::Staging, true),
        (EntryKind::Run, true),
        (EntryKind::Prior, true),
        (EntryKind::JournalFile, false),
        (EntryKind::NamedRoot, false),
        (EntryKind::UnnamedRoot, false),
        (EntryKind::Replacement, false),
    ] {
        let (remedy, text) = said(kind, &Origin::Foreign, &Presence::Present);
        assert_eq!(remedy, Remedy::MoveAside, "{kind:?}");
        assert_eq!(text.contains("makes it new"), makes_it, "{kind:?}: {text}");
        assert!(
            text.contains("out of the data directory"),
            "{kind:?}: {text}"
        );
        assert!(!text.contains("Remove "), "{kind:?}: {text}");
    }
    // Each state says its own basis, and one remedy.
    let (_, refused) = said(
        EntryKind::JournalFile,
        &Origin::Refused("Windows error 5".to_owned()),
        &Presence::Present,
    );
    assert!(
        refused.contains("refuses the Administrators group"),
        "{refused}"
    );
    let (_, read) = said(EntryKind::JournalFile, &unknown(), &Presence::Present);
    assert!(read.contains("Nothing shows who made"), "{read}");
    let (_, held_text) = said(EntryKind::JournalFile, &held(), &Presence::Present);
    assert!(
        held_text.contains("Close the program that holds it open"),
        "{held_text}"
    );
    for text in [&refused, &read, &held_text] {
        assert!(!text.contains("Remove "), "{text}");
        assert!(!text.contains("Correct what the reason names"), "{text}");
    }
}

/// The one remedy each state of a refused folder above the data directory is told: a held folder is
/// cured by closing the program, another account's by moving it aside, the system's own by
/// correcting its list, and one that holds no data directory by removing it. A text never offers a
/// second remedy beside its own.
#[test]
fn each_state_of_the_parent_folder_is_told_one_remedy() {
    const REMEDIES: [&str; 4] = [
        "Close the program",
        "Move the folder aside",
        "Correct it instead",
        "Remove the folder",
    ];
    let said = |text: &str| -> Vec<&str> {
        REMEDIES
            .iter()
            .copied()
            .filter(|remedy| text.contains(remedy))
            .collect()
    };
    let cases = [
        (ParentCure::Close, "Close the program"),
        (ParentCure::MoveAside, "Move the folder aside"),
        (ParentCure::Unreadable, "Move the folder aside"),
        (ParentCure::Correct(Presence::Present), "Correct it instead"),
        (
            ParentCure::Correct(Presence::Unknown("Windows error 5".to_owned())),
            "Correct it instead",
        ),
        (ParentCure::Correct(Presence::Absent), "Remove the folder"),
    ];
    for (cure, remedy) in cases {
        let text = parent_advice(&cure);
        assert_eq!(said(&text), vec![remedy], "{cure:?}: {text}");
    }
    // A folder that holds nothing is removed, and the text does not add that its list could be
    // corrected instead.
    let text = parent_advice(&ParentCure::Correct(Presence::Absent));
    assert!(!text.contains("give it to"), "{text}");
}

#[test]
fn a_folder_that_holds_the_data_directory_or_may_is_never_told_to_be_removed() {
    for cure in [
        ParentCure::Close,
        ParentCure::MoveAside,
        ParentCure::Unreadable,
        ParentCure::Correct(Presence::Present),
        ParentCure::Correct(Presence::Unknown("Windows error 5".to_owned())),
    ] {
        let text = parent_advice(&cure);
        assert!(!text.contains("Remove the folder"), "{cure:?}: {text}");
        assert!(!text.contains("remove the folder"), "{cure:?}: {text}");
        assert!(!text.contains("loses nothing"), "{cure:?}: {text}");
    }
}

/// The origin that an opened entry's handle gives is compared with what the layout gives at its
/// name: a directory at a record file's name and a plain file at a directory's name (a private
/// root's included) are not the installation's, so the owner is not read and the entry is the
/// not-made state; so are a link and a file with a second name at any name. What matches is read
/// for its owner, and a name that the layout does not give may be either kind.
#[test]
fn an_entry_of_another_kind_than_the_layout_gives_is_not_the_installations() {
    let files = [
        EntryKind::Manifest,
        EntryKind::Prior,
        EntryKind::Replacement,
        EntryKind::JournalFile,
    ];
    let directories = [
        EntryKind::Staging,
        EntryKind::Journal,
        EntryKind::Run,
        EntryKind::NamedRoot,
        EntryKind::UnnamedRoot,
    ];
    let system = || Origin::System;
    let refused_to_read = || panic!("the owner of an entry of the wrong kind is not read");
    for kind in files {
        assert_eq!(
            origin_of_shape(kind, Shape::Directory, &refused_to_read),
            Origin::Foreign,
            "{kind:?}: a directory at a file's name"
        );
        assert_eq!(
            origin_of_shape(kind, Shape::File { names: 1 }, &system),
            Origin::System,
            "{kind:?}"
        );
    }
    for kind in directories {
        assert_eq!(
            origin_of_shape(kind, Shape::File { names: 1 }, &refused_to_read),
            Origin::Foreign,
            "{kind:?}: a plain file at a directory's name"
        );
        assert_eq!(
            origin_of_shape(kind, Shape::Directory, &system),
            Origin::System,
            "{kind:?}"
        );
    }
    for kind in files
        .into_iter()
        .chain(directories)
        .chain([EntryKind::Other])
    {
        assert_eq!(
            origin_of_shape(kind, Shape::Link, &refused_to_read),
            Origin::Foreign,
            "{kind:?}: a link"
        );
        assert_eq!(
            origin_of_shape(kind, Shape::File { names: 2 }, &refused_to_read),
            Origin::Foreign,
            "{kind:?}: a second name"
        );
    }
    assert_eq!(
        origin_of_shape(EntryKind::Other, Shape::Directory, &system),
        Origin::System
    );
    assert_eq!(
        origin_of_shape(EntryKind::Other, Shape::File { names: 1 }, &system),
        Origin::System
    );
}
