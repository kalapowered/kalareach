//! The remedy that a refusal of an entry gives comes from what the entry's own handle showed and from
//! the lookup of the manifest, never from the words of the reason. An entry that the handle shows to
//! be another account's is moved out, one that could not be read is neither corrected nor removed,
//! and only the system's class is ever corrected into place.

use std::path::Path;

use kr_boundary_windows::remedy::{
    AncestorFault, EntryKind, Origin, ParentCure, Presence, Record, Remedy, Shape, Stage, Subject,
    Tree, ancestor_refusal, choose, ending, origin_of_open_error, origin_of_shape, parent_advice,
    program_removal_advice,
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
                    choose(kind, &origin, &manifest, None),
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
                choose(kind, &held(), &manifest, None),
                Remedy::Unreadable,
                "{kind:?} {manifest:?}"
            );
            assert_eq!(
                choose(kind, &unknown(), &manifest, None),
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
                choose(kind, &Origin::System, &manifest, None),
                expected,
                "{kind:?} {manifest:?}"
            );
        }
        assert_eq!(
            choose(kind, &Origin::System, &Presence::Absent, None),
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
            choose(EntryKind::Other, &Origin::System, &manifest, None),
            Remedy::Remove,
            "{manifest:?}"
        );
        for origin in [
            Origin::Foreign,
            unknown(),
            Origin::Refused("Windows error 5".to_owned()),
        ] {
            assert_eq!(
                choose(EntryKind::Other, &origin, &manifest, None),
                Remedy::MoveAside,
                "{origin:?} {manifest:?}"
            );
        }
        assert_eq!(
            choose(EntryKind::Other, &held(), &manifest, None),
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
            choose(EntryKind::UnnamedRoot, &Origin::System, &manifest, None),
            Remedy::Remove
        );
        assert_eq!(
            choose(EntryKind::UnnamedRoot, &Origin::Foreign, &manifest, None),
            Remedy::MoveAside
        );
        assert_eq!(
            choose(EntryKind::UnnamedRoot, &unknown(), &manifest, None),
            Remedy::MoveAside
        );
        assert_eq!(
            choose(EntryKind::UnnamedRoot, &held(), &manifest, None),
            Remedy::Unreadable
        );
    }
}

/// A refused entry's words say what the handle showed and no more: an entry that the handle shows
/// to be a link, a second name, another kind or another owner is named for what the installation
/// does not leave there, with no word about who made it; an entry that changed or moved while it
/// was read is not said to have been unreadable; an entry that cannot be opened because a delete is
/// pending is told to be freed by closing the program that holds it; and the words about the next
/// run are for an installation or a repair, which are the runs that make the entries.
#[test]
fn the_words_of_a_refused_entry_say_what_the_handle_showed_and_nothing_of_who_made_it() {
    let (remedy, foreign) = said(EntryKind::Staging, &Origin::Foreign, &Presence::Present);
    assert_eq!(remedy, Remedy::MoveAside);
    assert!(
        foreign.contains("shows what the installation does not leave there: an owner that is not the system or the Administrators group, a reparse point, a second name for a file, or another kind of object than its layout gives at that name"),
        "{foreign}"
    );
    assert!(!foreign.contains("did not make it"), "{foreign}");
    assert!(
        foreign.contains(
            "An installation or a repair run next finds the entry absent and makes it new."
        ),
        "{foreign}"
    );
    assert!(!foreign.contains("The next run"), "{foreign}");

    let (remedy, changed) = said(
        EntryKind::JournalFile,
        &Origin::Changed("the identifier names another object".to_owned()),
        &Presence::Present,
    );
    assert_eq!(remedy, Remedy::MoveAside);
    assert!(
        changed.contains(
            "it changed or moved while it was read (the identifier names another object)"
        ),
        "{changed}"
    );
    assert!(!changed.contains("could not be read"), "{changed}");
    assert!(!changed.contains("did not make it"), "{changed}");

    let (_, refused) = said(
        EntryKind::JournalFile,
        &Origin::Refused("Windows error 5".to_owned()),
        &Presence::Present,
    );
    assert!(
        refused.contains(
            "if its delete is pending, close the program that holds it, and the entry goes"
        ),
        "{refused}"
    );
}

/// An entry that the manifest holds no record of is moved aside whatever its owner shows, with a
/// basis of its own that says what was read: the manifest's record of it, and for a directory that
/// it holds entries. The manifest is never told to be removed: a removal reads it. The words that
/// follow are the standing ones of the entry's kind. An entry that the manifest records, or whose
/// record was not read, keeps the choice that its handle gives.
#[test]
fn an_entry_that_the_manifest_holds_no_record_of_is_moved_aside_with_the_basis_of_its_record() {
    let data = "D:/data";
    for origin in [Origin::System, Origin::Foreign, unknown(), held()] {
        for kind in [
            EntryKind::Manifest,
            EntryKind::Staging,
            EntryKind::Journal,
            EntryKind::Run,
        ] {
            let remedy = choose(kind, &origin, &Presence::Present, Some(Record::NotRecorded));
            assert_eq!(remedy, Remedy::MoveAside, "{kind:?} {origin:?}");
        }
    }
    // What the handle chooses is chosen again where the manifest records the entry or the record was
    // not read.
    for record in [None, Some(Record::Recorded)] {
        assert_eq!(
            choose(
                EntryKind::Staging,
                &Origin::System,
                &Presence::Absent,
                record
            ),
            Remedy::Remove
        );
        assert_eq!(
            choose(
                EntryKind::Manifest,
                &Origin::System,
                &Presence::Present,
                record
            ),
            Remedy::Correct
        );
    }

    // The manifest that holds no record of its own data directory: the text names the manifest and
    // the directory.
    let manifest = format!("{data}/manifest.json");
    let text = ending(
        Path::new(&manifest),
        Remedy::MoveAside,
        &Origin::System,
        EntryKind::Manifest,
        &Presence::Present,
        Some(Record::NotRecorded),
    );
    // The reason and the one fact that the read shows about the setup program: it names no step. No
    // remedy, no forecast of what a run after a change of the manifest says, and nothing of what the
    // directory holds.
    assert_eq!(
        text,
        format!(
            "The manifest in {data} holds no record of {data} itself. The setup program names no step for this state."
        )
    );
    for words in [
        "Move it aside",
        "Keep it",
        "Remove ",
        "nothing records",
        "next run",
    ] {
        assert!(!text.contains(words), "{words}: {text}");
    }

    // A directory that the manifest holds no record of and that holds entries.
    for (kind, next) in [
        (
            EntryKind::Staging,
            "An installation or a repair run next finds the entry absent and makes it new.",
        ),
        (
            EntryKind::Journal,
            "An installation or a repair run next finds the entry absent and makes it new.",
        ),
        (
            EntryKind::Run,
            "An installation or a repair run next finds the entry absent and makes it new.",
        ),
    ] {
        let entry = format!("{data}/child");
        let text = ending(
            Path::new(&entry),
            Remedy::MoveAside,
            &Origin::System,
            kind,
            &Presence::Present,
            Some(Record::NotRecorded),
        );
        assert!(
            text.starts_with(&format!(
                "The manifest holds no record of {entry}, and {entry} holds entries: nothing shows what wrote them."
            )),
            "{kind:?}: {text}"
        );
        assert!(
            text.contains("Move it aside: out of the data directory"),
            "{kind:?}: {text}"
        );
        assert!(text.ends_with(next), "{kind:?}: {text}");
        assert!(!text.contains("Keep it"), "{kind:?}: {text}");
        assert!(
            !text.contains("Correct what the reason names"),
            "{kind:?}: {text}"
        );
        assert!(!text.contains("Remove "), "{kind:?}: {text}");
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
    let remedy = choose(kind, origin, manifest, None);
    let text = ending(
        Path::new("D:\\data\\entry"),
        remedy,
        origin,
        kind,
        manifest,
        None,
    );
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
        None,
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
        "Correct its list instead",
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
        (
            ParentCure::Correct(Presence::Present),
            "Correct its list instead",
        ),
        (
            ParentCure::Correct(Presence::Unknown("Windows error 5".to_owned())),
            "Correct its list instead",
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

/// A reparse point at the folder that holds the data directory is told in the words of an own
/// folder of the program tree that is a reparse point: what the setup program does and does not
/// change, with no move, no removal and no change of a folder that other programs share. The two
/// trees share one form, so the stage names what the run had changed in both.
#[test]
fn a_link_at_the_folder_above_the_data_directory_is_told_as_one_at_an_own_folder_of_the_program_tree()
 {
    let stages = [
        Stage::Before,
        Stage::After,
        Stage::AfterRepair {
            broker_stopped: true,
        },
        Stage::DataParentMade,
        Stage::Rollback,
    ];
    for stage in stages {
        let parent = parent_advice(&ParentCure::Link(stage));
        let program = ancestor_refusal(
            &Subject::at(
                r"C:\Program Files\Kala",
                r"C:\Program Files",
                AncestorFault::Link,
            ),
            Tree::Program,
            stage,
        );
        assert!(
            program.contains(&parent),
            "the program tree's own-folder link form holds the data parent's words ({stage:?}):\n{parent}\n{program}"
        );
        for said in [
            "This layout is not supported.",
            "The setup program makes this folder itself, as a plain folder, in the system's own known folder.",
            "It does not follow or change a link or a mounted folder in its place, and it directs no change to a folder that other programs share.",
        ] {
            assert!(parent.contains(said), "{stage:?}: {parent}");
        }
        for never in [
            "Move the folder aside",
            "rename",
            "Remove ",
            "remove it",
            "remove the",
            "Correct its list",
            "did not make this folder",
        ] {
            assert!(!parent.contains(never), "{stage:?} {never}: {parent}");
        }
    }
}

/// The folder above the data directory is said to be made new only on a condition that the run
/// that follows can meet: the boundary is not installed (an installation then makes it; a removal
/// makes nothing, and an installed boundary stops the run before). The folder that the handle shows
/// with another owner is told by its owner; what is at a folder's name and is no folder is a thing
/// that is moved aside, with nothing said of what it holds.
#[test]
fn the_folder_above_the_data_directory_is_said_to_be_made_new_only_where_the_boundary_is_not_installed()
 {
    for cure in [
        ParentCure::Unreadable,
        ParentCure::MoveAside,
        ParentCure::NotAFolder,
    ] {
        let text = parent_advice(&cure);
        assert!(
            text.contains(
                "Where the boundary is not installed, the installation then makes the folder new."
            ),
            "{cure:?}: {text}"
        );
        assert!(
            !text.contains("again: the installation makes the folder new"),
            "{cure:?}: {text}"
        );
    }
    let owner = parent_advice(&ParentCure::MoveAside);
    assert!(
        owner.contains(
            "The handle of this folder shows an owner that is not the system or the Administrators group"
        ),
        "{owner}"
    );
    assert!(!owner.contains("did not make"), "{owner}");
    let file = parent_advice(&ParentCure::NotAFolder);
    assert!(
        file.contains("What is at this folder's name is not a folder"),
        "{file}"
    );
    for held in ["can hold", "keeps everything in it", "files that"] {
        assert!(!file.contains(held), "{held}: {file}");
    }
}

#[test]
fn a_folder_that_holds_the_data_directory_or_may_is_never_told_to_be_removed() {
    for cure in [
        ParentCure::Close,
        ParentCure::MoveAside,
        ParentCure::NotAFolder,
        ParentCure::Link(Stage::Before),
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
    // Any reparse tag is a reparse point here, not a link: the words say which they know.
    assert!(
        link.starts_with(&format!(
            "{entry} is a reparse point (a link, a mounted folder or another kind), which the installation does not make there. Remove {entry} itself"
        )),
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
