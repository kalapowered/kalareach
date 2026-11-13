//! The remedy that a refusal of an entry gives comes from what the entry's own handle showed and from
//! the lookup of the manifest, never from the words of the reason. An entry that the handle shows to
//! be another account's is moved out, one that could not be read is neither corrected nor removed,
//! and only the system's class is ever corrected into place.

use std::path::Path;

use kr_boundary_windows::remedy::{
    EntryKind, Origin, ParentCure, Presence, Remedy, Shape, choose, ending, origin_of_open_error,
    origin_of_shape, parent_advice, program_removal_advice,
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

/// A name that the layout does not give is no record, and its own handle decides all the same: only
/// one that shows the system's class is removed; a link, another account's, a second name or a list
/// that refuses the check is moved aside, and one that a program holds is closed on.
#[test]
fn a_name_that_the_layout_does_not_give_takes_the_four_states_of_its_own_handle() {
    for manifest in lookups() {
        assert_eq!(
            choose(EntryKind::Other, &Origin::System, &manifest),
            Remedy::Remove,
            "{manifest:?}"
        );
        for origin in [
            Origin::Foreign,
            unknown(),
            Origin::Refused("Windows error 5".to_owned()),
        ] {
            assert_eq!(
                choose(EntryKind::Other, &origin, &manifest),
                Remedy::MoveAside,
                "{origin:?} {manifest:?}"
            );
        }
        assert_eq!(
            choose(EntryKind::Other, &held(), &manifest),
            Remedy::Unreadable,
            "{manifest:?}"
        );
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

/// That the entry at the manifest's name stays is said only where the lookup found one; the journal and
/// what an entry holds are never claimed, and "the next run makes it new" only of what the
/// installation makes.
#[test]
fn the_words_of_a_remedy_say_only_what_is_true_of_the_entry_and_the_state() {
    const STAYS: &str = "the entry at the manifest's name stays where it is";
    // A removal with the manifest there says that it stays, whichever entry is removed.
    for kind in [EntryKind::Other, EntryKind::UnnamedRoot] {
        let (remedy, text) = said(kind, &Origin::System, &Presence::Present);
        assert_eq!(remedy, Remedy::Remove, "{kind:?}");
        assert!(text.contains(STAYS), "{kind:?}: {text}");
    }
    let text = ending(
        Path::new("D:\\data\\journal"),
        Remedy::Remove,
        &Origin::System,
        EntryKind::Journal,
        &Presence::Present,
    );
    assert!(text.contains(STAYS), "{text}");
    // With no manifest, or none read, nothing is said to stay beside the entry.
    for (kind, manifest) in [
        (EntryKind::Prior, Presence::Absent),
        (EntryKind::JournalFile, Presence::Absent),
        (EntryKind::UnnamedRoot, Presence::Unknown("e".to_owned())),
        (EntryKind::Journal, Presence::Absent),
    ] {
        let (remedy, text) = said(kind, &Origin::System, &manifest);
        assert_eq!(remedy, Remedy::Remove, "{kind:?}");
        assert!(!text.contains(STAYS), "{kind:?}: {text}");
    }
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
    // An open that failed with error 5 names the error and gives a list that refuses the
    // Administrators group as one cause, beside a delete that is pending: it does not say that the
    // installation did not make the entry.
    assert!(refused.contains("(Windows error 5)"), "{refused}");
    assert!(
        refused
            .contains("A permission list that refuses the Administrators group gives that error"),
        "{refused}"
    );
    assert!(
        refused.contains("an entry with a delete pending gives it too"),
        "{refused}"
    );
    assert!(
        !refused.contains("so the installation did not make it"),
        "{refused}"
    );
    assert!(!refused.contains("The permission list of"), "{refused}");
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
        "remove or rename the folder",
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
        (
            ParentCure::Correct(Presence::Absent),
            "remove or rename the folder",
        ),
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

/// What a foreign manifest's refusal says the next run does is what the next run does with no
/// manifest: it reads each remaining entry on its own handle, and says remove, move aside or close
/// the program, never "names each to remove".
#[test]
fn the_forecast_after_a_foreign_manifest_is_moved_aside_is_the_next_runs_own_reading() {
    let (remedy, text) = said(EntryKind::Manifest, &Origin::Foreign, &Presence::Present);
    assert_eq!(remedy, Remedy::MoveAside);
    assert!(text.contains("on their own handles"), "{text}");
    assert!(text.contains("move it aside"), "{text}");
    assert!(
        text.contains("close the program that holds it open"),
        "{text}"
    );
    assert!(!text.contains("names each to remove"), "{text}");
}

/// The forecast says what the next run does for the state that run finds. After a manifest that
/// nothing shows the origin of (a handle that could not be read, or that changed while it was read)
/// is moved aside, the next run reads the first entry it finds and may move that aside too, because
/// its handle shows nothing either.
#[test]
fn the_forecast_after_a_manifest_covers_the_state_that_shows_nothing_of_who_made_an_entry() {
    let (remedy, text) = said(
        EntryKind::Manifest,
        &Origin::Unknown("access".to_owned()),
        &Presence::Present,
    );
    assert_eq!(remedy, Remedy::MoveAside);
    assert!(text.contains("shows nothing of who made it"), "{text}");
    assert!(text.contains("could not be read"), "{text}");
    assert!(
        text.contains("changed or moved while it was read"),
        "{text}"
    );
}

/// A name beside a moved-aside entry is a name that the layout does not give. The next run reads
/// it on its own handle like any entry and says what that shows: it does not promise "remove".
#[test]
fn the_parenthesis_about_a_new_name_beside_an_entry_does_not_promise_its_removal() {
    for kind in [
        EntryKind::Manifest,
        EntryKind::Prior,
        EntryKind::Staging,
        EntryKind::Journal,
        EntryKind::Run,
        EntryKind::Replacement,
        EntryKind::JournalFile,
        EntryKind::NamedRoot,
        EntryKind::UnnamedRoot,
        EntryKind::Other,
    ] {
        for origin in [
            Origin::Foreign,
            Origin::Refused("5".to_owned()),
            Origin::Unknown("x".to_owned()),
        ] {
            let (remedy, text) = said(kind, &origin, &Presence::Present);
            assert_eq!(remedy, Remedy::MoveAside, "{kind:?} {origin:?}");
            assert!(!text.contains("asks you to remove that"), "{text}");
            assert!(
                text.contains("the next run reads it on its own handle"),
                "{kind:?} {origin:?}: {text}"
            );
        }
    }
}

/// In the program directory only the system's class can write, so an unlisted name, a link and a
/// second name keep "Remove". For a link the words say to remove the link itself and not what it
/// points to, because the shell's recursive removal follows a junction into what it leads to.
#[test]
fn in_the_program_directory_a_link_is_removed_as_the_link_itself_and_not_what_it_leads_to() {
    let entry = r"D:\Program Files\KalaReach\Boundary\link";
    let link = program_removal_advice(entry, true, true);
    assert!(
        link.starts_with(&format!("Remove the link {entry} itself")),
        "{link}"
    );
    assert!(link.contains("not what it points to"), "{link}");
    assert!(link.contains("rmdir"), "{link}");
    assert!(link.contains("without `/s`"), "{link}");
    assert!(
        link.contains("A repair makes the program files again"),
        "{link}"
    );
    assert!(link.contains("run the setup program again"), "{link}");

    let other = program_removal_advice(entry, false, true);
    assert!(
        other.starts_with(&format!("Remove {entry}, and nothing else")),
        "{other}"
    );
    assert!(!other.contains("points to"), "{other}");
    assert!(
        other.contains("A repair makes the program files again"),
        "{other}"
    );
}
