//! What the words of a refusal claim: nothing that no read showed. Each sentence says what a call
//! returned, a rule of the installation, or, for a folder that the installation makes, what to
//! correct. They run on every platform.

use std::path::Path;

use kr_boundary_windows::manifest::Outcome;
use kr_boundary_windows::records::{Held, Look, next_step};
use kr_boundary_windows::remedy::{
    CASE_SENSITIVE_WHY, EntryKind, FolderAct, FolderRead, FolderRecord, Grounds, IntentAct,
    IntentRead, NotProved, Origin, ParentCure, Presence, Purpose, RecordLeft, Standing, Taken,
    choose, data_ending, data_made_ending, ending, folder_act, folder_words, intent_words,
    is_this_trees_to_remove, left_alone, parent_advice, program_keeping, program_open_advice,
    residue_tail, rollback_ending, rollback_entry, rollback_failed, rollback_laid_stays,
    rollback_not_changed, service_program_is, unnamed_root_why,
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
                    // An object that is not a directory holds no records: its words say that it is
                    // not used as the data directory, and the owner's say that its records are not used.
                    assert!(
                        text.contains(if origin == Origin::Foreign {
                            "does not use it as the data directory, and does not use any record behind it"
                        } else {
                            "does not use the records in it"
                        }),
                        "{what}"
                    );
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
    let gone = data_made_ending(&Taken::Marked, DATA, &Taken::Marked, ABOVE);
    assert!(gone.contains("removed what it made"), "{gone}");
    let stayed = data_made_ending(
        &Taken::Stays("e".to_owned()),
        DATA,
        &Taken::Stays("the data directory in it stays".to_owned()),
        ABOVE,
    );
    assert!(stayed.contains("could not remove what it made"), "{stayed}");
    assert!(
        stayed.contains(&format!(
            "{DATA} (e); {ABOVE} (the data directory in it stays)"
        )),
        "{stayed}"
    );
    // The directory is gone and the folder above it stays: the words say that, and not that the
    // directory stays or that nothing is left.
    let folder_stays = data_made_ending(&Taken::Marked, DATA, &Taken::Stays("f".to_owned()), ABOVE);
    assert!(
        folder_stays.contains("removed the data directory that it made"),
        "{folder_stays}"
    );
    assert!(
        folder_stays.contains(&format!(
            "could not remove the folder above it that it also made: {ABOVE} (f). That folder stays."
        )),
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

const DATA: &str = r"C:\Kala\Data";
const ABOVE: &str = r"C:\Kala";

/// Every pair of what the cleanup came to for the directory and for the folder above it: the words
/// say that the data directory was removed only where this run made it and marked it, name each
/// object that stays and nothing else, say that nothing is left only where nothing stays or was not
/// found, and say of an object whose name was not found that it was not found at its name and that
/// the rollback did nothing with it, never that it stays. A run that made only the folder, and
/// whose mark was refused, is never told that it removed a data directory: it made none.
#[test]
fn the_ending_of_what_a_run_made_claims_each_object_only_where_the_cleanup_came_to_it() {
    let each = |why: &str| {
        [
            Taken::NotMade,
            Taken::Marked,
            Taken::NotFound,
            Taken::Stays(why.to_owned()),
        ]
    };
    for directory in each("d") {
        for folder in each("f") {
            let text = data_made_ending(&directory, DATA, &folder, ABOVE);
            let label = format!("{directory:?} {folder:?}: {text}");
            let directory_stays = matches!(directory, Taken::Stays(_));
            let folder_stays = matches!(folder, Taken::Stays(_));
            let directory_lost = directory == Taken::NotFound;
            let folder_lost = folder == Taken::NotFound;
            assert_eq!(
                text.contains("removed the data directory"),
                directory == Taken::Marked && (folder_stays || folder_lost),
                "{label}"
            );
            assert_eq!(
                text.contains("nothing of it is left"),
                !directory_stays && !folder_stays && !directory_lost && !folder_lost,
                "{label}"
            );
            assert_eq!(
                text.contains(&format!("{DATA}, was not found at its name")),
                directory_lost,
                "{label}"
            );
            assert_eq!(
                text.contains(&format!("{ABOVE}, was not found at its name")),
                folder_lost,
                "{label}"
            );
            assert_eq!(
                text.matches("the rollback did nothing with it").count(),
                usize::from(directory_lost) + usize::from(folder_lost),
                "{label}"
            );
            // "That folder stays." is said only of a folder whose answer was a reason that it stays,
            // after a data directory that was removed.
            assert_eq!(
                text.contains("That folder stays"),
                directory == Taken::Marked && folder_stays,
                "{label}"
            );
            assert_eq!(
                text.contains(&format!("{DATA} (d)")),
                directory_stays,
                "{label}"
            );
            assert_eq!(
                text.contains(&format!("{ABOVE} (f)")),
                folder_stays,
                "{label}"
            );
            assert_eq!(
                text.contains("could not remove what it made"),
                !directory_lost
                    && !folder_lost
                    && (directory_stays || (directory != Taken::Marked && folder_stays)),
                "{label}"
            );
        }
    }
}

/// An object whose name was not found at the cleanup's open is said to be not found at its name, and
/// the rollback is said to have done nothing with it: nothing was read that says that it stays or
/// that it is gone, and no step stands in the words.
#[test]
fn the_ending_of_an_object_whose_name_was_not_found_says_only_that_and_gives_no_step() {
    let folder = data_made_ending(&Taken::Marked, DATA, &Taken::NotFound, ABOVE);
    assert_eq!(
        folder,
        format!(
            "This run removed the data directory that it made. The folder that this run made above the data directory, {ABOVE}, was not found at its name, and the rollback did nothing with it."
        )
    );
    let directory = data_made_ending(&Taken::NotFound, DATA, &Taken::Stays("w".to_owned()), ABOVE);
    assert_eq!(
        directory,
        format!(
            "The data directory that this run made, {DATA}, was not found at its name, and the rollback did nothing with it. This run could not remove the rest of what it made: {ABOVE} (w)."
        )
    );
    let alone = data_made_ending(&Taken::NotFound, DATA, &Taken::NotMade, ABOVE);
    assert_eq!(
        alone,
        format!(
            "The data directory that this run made, {DATA}, was not found at its name, and the rollback did nothing with it."
        )
    );
    for text in [&folder, &directory, &alone] {
        for wrong in [
            "stays",
            "is gone",
            "nothing of it is left",
            "could not remove what it made",
            "Move it aside",
            "Turn the flag",
            "Leave the system",
            "again",
        ] {
            assert!(!text.contains(wrong), "{wrong}: {text}");
        }
    }
}

/// The rollback's list names an object that stays with the words that were read, an object whose
/// name was not found with the words of a name that was not found, and no object that was taken
/// away or that the run did not make.
#[test]
fn the_rollbacks_entry_for_an_object_says_what_the_cleanup_came_to_and_no_more() {
    assert_eq!(rollback_entry(&Taken::NotMade, DATA), None);
    assert_eq!(rollback_entry(&Taken::Marked, DATA), None);
    assert_eq!(
        rollback_entry(&Taken::Stays("w".to_owned()), DATA),
        Some(format!("{DATA} (w)"))
    );
    let lost = rollback_entry(&Taken::NotFound, DATA).unwrap();
    assert_eq!(
        lost,
        format!(
            "{DATA} (its name was not found in the directory that holds it, and the rollback did nothing with it)"
        )
    );
    for wrong in ["stays", "is gone", "nothing was marked"] {
        assert!(!lost.contains(wrong), "{wrong}: {lost}");
    }
    let ending = rollback_laid_stays(&[lost], &[]);
    assert!(ending.ends_with("did nothing with it)."), "{ending}");
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

/// The rollback's ending names each object that stays with the words that were read, and gives no
/// step: no instruction to move, remove, correct or delete anything stands in it.
#[test]
fn the_ending_of_a_rollback_that_could_not_take_away_all_names_each_object_and_gives_no_step() {
    let one = rollback_laid_stays(
        &[
            "C:\\Data (the platform refused to mark it for removal: Windows error 145; it holds a.txt)"
                .to_owned(),
        ],
        &[],
    );
    assert_eq!(
        one,
        "The rollback's steps that undo the policy, the service, the accounts and the program directory ended without a failure, but this run could not take away all that it laid in the data directory's place: C:\\Data (the platform refused to mark it for removal: Windows error 145; it holds a.txt)."
    );
    let two = rollback_laid_stays(
        &[
            "C:\\Data (another object stands at its name, so nothing was marked)".to_owned(),
            "C:\\Above (the data directory in it stays)".to_owned(),
        ],
        &["C:\\Data\\run".to_owned(), "C:\\Data\\journal".to_owned()],
    );
    assert!(two.contains("C:\\Data (another object stands at its name, so nothing was marked); C:\\Above (the data directory in it stays)."));
    assert!(
        two.ends_with(
            " It marked for removal, each through the identity that this run kept of it, and a read of its name afterwards found it gone: C:\\Data\\run; C:\\Data\\journal."
        ),
        "{two}"
    );
    // An ending that names a failure does not say that records are deleted.
    assert!(!two.contains("deleted"), "{two}");
    for text in [&one, &two] {
        for step in [
            "Remove",
            "remove it",
            "Move",
            "move it",
            "Delete",
            "delete it",
            "Correct",
            "run the",
            "Run the",
            "by hand",
        ] {
            assert!(!text.contains(step), "{step}: {text}");
        }
    }
}

/// The rollback's last words say that the records are deleted only where the run wrote records and
/// marked each of them, and say nothing of records where it wrote none. They name each object that
/// was marked, in order, and say that nothing was marked where the run held nothing that it made.
#[test]
fn the_ending_of_a_rollback_says_records_are_deleted_only_where_the_run_wrote_and_marked_them() {
    let marked = [format!("{DATA}\\run"), DATA.to_owned(), ABOVE.to_owned()];
    let with_records = rollback_ending(&marked, true);
    assert!(
        with_records
            .starts_with("the removal ended without a failure and its records are deleted. "),
        "{with_records}"
    );
    let without_records = rollback_ending(&marked, false);
    assert!(
        without_records.starts_with("the removal ended without a failure. "),
        "{without_records}"
    );
    for text in [&with_records, &without_records] {
        assert!(
            text.ends_with(&format!(
                "each through the identity that this run kept of it, and a read of its name afterwards found it gone: {DATA}\\run; {DATA}; {ABOVE}"
            )),
            "{text}"
        );
    }
    assert!(!without_records.contains("record"), "{without_records}");
    // Nothing was marked: there are no records to say anything of, whatever the flag says.
    for records in [false, true] {
        let nothing = rollback_ending(&[], records);
        assert_eq!(
            nothing,
            "the removal ended without a failure; this run held no object that it had made, so the rollback marked nothing for removal"
        );
        assert!(!nothing.contains("record"), "{nothing}");
    }
    for text in [&with_records, &without_records] {
        for step in [
            "Remove",
            "remove it",
            "Move",
            "move it",
            "Delete",
            "by hand",
        ] {
            assert!(!text.contains(step), "{step}: {text}");
        }
    }
}

#[test]
fn the_words_for_an_object_that_a_rollback_left_say_what_the_record_holds_and_give_no_step() {
    let words = [
        left_alone("account", "krb-checkout", None),
        left_alone("account", "krb-checkout", Some(Outcome::Found)),
        rollback_not_changed("the policy"),
    ];
    for text in &words {
        assert!(text.contains("left it as it is"), "{text}");
        // They name the record and the decision, never the object's own state, and tell nobody to
        // move, remove or correct anything.
        for forbidden in [
            "exists",
            "is gone",
            "deleted",
            "remove it",
            "delete it",
            "move",
        ] {
            assert!(!text.contains(forbidden), "{forbidden} in {text}");
        }
    }
    assert!(words[0].contains("holds no result that the step made it"));
    assert!(words[1].contains("found it where it looked and did not make it"));
    assert!(words[2].contains("holds no result that this run changed it"));
}

#[test]
fn the_removal_decides_about_an_intent_with_no_result_by_a_read_of_the_object() {
    let mark = "the comment that the installation gives its accounts";
    let read = |read: &IntentRead| intent_words("account", "krb-checkout", mark, read);
    // Nothing is there: nothing to remove, no failure.
    assert_eq!(IntentRead::NotThere.act(), IntentAct::Leave);
    assert!(read(&IntentRead::NotThere).contains("there is nothing to remove"));
    // It is there with the installation's mark: removed as one that the installation made.
    assert_eq!(IntentRead::Marked.act(), IntentAct::Remove);
    let marked = read(&IntentRead::Marked);
    assert!(marked.contains("no result of that step"), "{marked}");
    assert!(marked.contains(mark), "{marked}");
    assert!(marked.contains("removes it as it removes one that the installation made"));
    // It is there without the mark: left, and no failure.
    assert_eq!(IntentRead::Unmarked.act(), IntentAct::Leave);
    assert!(read(&IntentRead::Unmarked).contains("without the installation's mark"));
    // A read that fails leaves it and fails the removal, so that its records stay.
    let failed = IntentRead::Failed("Windows error 5".to_owned());
    assert_eq!(failed.act(), IntentAct::LeaveAndFail);
    let text = read(&failed);
    assert!(
        text.contains("a read of it failed (Windows error 5)"),
        "{text}"
    );
    assert!(text.contains("its records stay"), "{text}");
    // None of them tells anybody to remove, move or correct anything.
    for text in [
        read(&IntentRead::NotThere),
        marked,
        read(&IntentRead::Unmarked),
        text,
    ] {
        for forbidden in ["remove it by", "delete it", "move it", "rename"] {
            assert!(!text.contains(forbidden), "{forbidden} in {text}");
        }
    }
}

#[test]
fn the_service_is_the_installations_where_its_program_is_the_broker_in_the_program_directory() {
    let broker = r"C:\Program Files\KalaReach\Boundary\kr-boundary-broker.exe";
    // The service manager answers the path that the installation wrote, in quotation marks.
    assert!(service_program_is(&format!("\"{broker}\""), broker));
    assert!(service_program_is(
        &format!("\"{}\"", broker.to_ascii_uppercase()),
        broker
    ));
    assert!(service_program_is(broker, broker));
    // Another file of the same folder, a program elsewhere, an argument and nothing are not it.
    assert!(!service_program_is(
        "\"C:\\Program Files\\KalaReach\\Boundary\\kr-boundary-credential.exe\"",
        broker
    ));
    assert!(!service_program_is(
        "\"C:\\Windows\\System32\\notepad.exe\"",
        broker
    ));
    assert!(!service_program_is(&format!("\"{broker}\" -x"), broker));
    assert!(!service_program_is("", broker));
}

#[test]
fn the_ending_of_a_rollback_with_a_failed_step_says_what_became_of_the_run_s_record() {
    let failures = vec!["removing an account: Windows error 5".to_owned()];
    let proved = rollback_failed(
        &failures,
        &RecordLeft::Proved {
            manifest: "M".to_owned(),
        },
        "",
    );
    assert!(
        proved.contains("found the manifest that this run holds"),
        "{proved}"
    );
    assert!(
        proved.contains("the administrator's removal takes the rest"),
        "{proved}"
    );
    for found in [
        NotProved::Absent,
        NotProved::Differs,
        NotProved::Unread("Windows error 5".to_owned()),
    ] {
        let saved = rollback_failed(
            &failures,
            &RecordLeft::Saved {
                manifest: "M".to_owned(),
                found: found.clone(),
            },
            "",
        );
        assert!(saved.contains(&found.words()), "{saved}");
        assert!(saved.contains("wrote its record again at M"), "{saved}");
        assert!(
            saved.contains("the administrator's removal takes the rest"),
            "{saved}"
        );
        let unsaved = rollback_failed(
            &failures,
            &RecordLeft::NotSaved {
                found: found.clone(),
                why: "Windows error 112".to_owned(),
                stays: vec!["D".to_owned(), "F".to_owned()],
            },
            ". The earlier-state record was not read",
        );
        assert!(
            unsaved.contains("writing this run's record again failed (Windows error 112)"),
            "{unsaved}"
        );
        assert!(
            unsaved.contains("no record of this run is on disk"),
            "{unsaved}"
        );
        assert!(unsaved.contains("did not take away: D; F"), "{unsaved}");
        assert!(
            unsaved.ends_with(". The earlier-state record was not read"),
            "{unsaved}"
        );
        // No ending says that a record is kept or that the manifest stays where it is, since none
        // of them reads a record that it did not find, and no ending gives a step.
        for text in [&saved, &unsaved] {
            for forbidden in [
                "records are kept",
                "stays where it is",
                "Remove ",
                "remove it",
                "move it",
            ] {
                assert!(!text.contains(forbidden), "{forbidden} in {text}");
            }
        }
        assert!(
            !unsaved.contains("administrator's removal takes the rest"),
            "{unsaved}"
        );
    }
    let none = rollback_failed(
        &failures,
        &RecordLeft::NotSaved {
            found: NotProved::Absent,
            why: "w".to_owned(),
            stays: Vec::new(),
        },
        "",
    );
    assert!(
        none.contains("this run held no object that it had made"),
        "{none}"
    );
}

#[test]
fn the_removal_takes_the_folder_above_the_program_directory_only_where_the_installation_made_it() {
    // The record: a result of found is never read, with or without an identity; no identity means no
    // read; a made folder and an intent that holds an identity are read.
    assert_eq!(
        FolderRecord::of(Some(Outcome::Found), true),
        FolderRecord::Found
    );
    assert_eq!(
        FolderRecord::of(Some(Outcome::Found), false),
        FolderRecord::Found
    );
    assert_eq!(
        FolderRecord::of(Some(Outcome::Made), false),
        FolderRecord::NoIdentity
    );
    assert_eq!(FolderRecord::of(None, false), FolderRecord::NoIdentity);
    assert_eq!(
        FolderRecord::of(Some(Outcome::Made), true),
        FolderRecord::Made
    );
    assert_eq!(FolderRecord::of(None, true), FolderRecord::Intent);
    for (record, read) in [
        (FolderRecord::Made, true),
        (FolderRecord::Intent, true),
        (FolderRecord::NoIdentity, false),
        (FolderRecord::Found, false),
    ] {
        assert_eq!(record.is_read(), read, "{record:?}");
    }
    // The choice: removed only where the record names the folder, the read found that folder and
    // it holds nothing; every other record or read leaves it, and a failed read fails the removal.
    let reads = [
        FolderRead::NotThere,
        FolderRead::Other,
        FolderRead::Holds(1),
        FolderRead::Holds(3),
        FolderRead::Empty,
        FolderRead::Failed("x".to_owned()),
    ];
    for record in [
        FolderRecord::Made,
        FolderRecord::Intent,
        FolderRecord::NoIdentity,
        FolderRecord::Found,
    ] {
        for read in std::iter::once(None).chain(reads.iter().map(Some)) {
            let act = folder_act(record, read);
            let expected = match (record, read) {
                (FolderRecord::Made | FolderRecord::Intent, Some(FolderRead::Empty)) => {
                    FolderAct::Remove
                }
                (_, Some(FolderRead::Failed(_))) => FolderAct::LeaveAndFail,
                _ => FolderAct::Leave,
            };
            assert_eq!(act, expected, "{record:?} {read:?}");
        }
    }
    // The words say what the manifest holds and what was read, and give no step and no claim of a
    // removal that no read showed.
    let folder = "C:\\Program Files\\KalaReach";
    for record in [
        FolderRecord::Made,
        FolderRecord::Intent,
        FolderRecord::NoIdentity,
        FolderRecord::Found,
    ] {
        for read in std::iter::once(None).chain(reads.iter().map(Some)) {
            let text = folder_words(folder, record, read);
            assert!(text.starts_with(folder), "{text}");
            for forbidden in ["deleted", "is gone", "move it", "remove it", "by hand"] {
                assert!(!text.contains(forbidden), "{forbidden} in {text}");
            }
        }
    }
    let found = folder_words(folder, FolderRecord::Found, None);
    assert!(
        found.contains("stood there before the installation")
            && found.contains("also where it is empty"),
        "{found}"
    );
    let holds = folder_words(folder, FolderRecord::Made, Some(&FolderRead::Holds(1)));
    assert!(holds.contains("found 1 entry in it"), "{holds}");
    let other = folder_words(folder, FolderRecord::Made, Some(&FolderRead::Other));
    assert!(other.contains("another identity"), "{other}");
}

#[test]
fn the_check_after_a_removal_holds_to_gone_only_what_the_tree_acted_on() {
    // A rollback acts on an object that its own run made, and on no other: an account whose create
    // failed (an intent), one that the run found, and one that no record holds are not its leftover.
    assert!(is_this_trees_to_remove(true, Some(Outcome::Made), false));
    assert!(!is_this_trees_to_remove(true, None, false));
    assert!(!is_this_trees_to_remove(true, Some(Outcome::Found), false));
    // The ordinary removal acts on what the manifest holds by result; what a step read and left
    // alone is not its leftover in either tree.
    assert!(is_this_trees_to_remove(false, Some(Outcome::Found), false));
    assert!(is_this_trees_to_remove(false, None, false));
    assert!(!is_this_trees_to_remove(false, Some(Outcome::Made), true));
    assert!(!is_this_trees_to_remove(true, Some(Outcome::Made), true));
    // The clause is the same words as before where nothing stands, and says only what was read.
    let names = ["krb-checkout".to_owned(), "krb-connect".to_owned()];
    let accounts = "no account has the identifier that the manifest records for krb-checkout; no account has the identifier that the manifest records for krb-connect";
    let clean = residue_tail(accounts, &names, true, &[]);
    assert_eq!(
        clean,
        format!(
            "{accounts}, the sign-in list has no value for either name, the broker's service is not there or is marked for deletion, and the program directory is not there"
        )
    );
    // An account that stands and was left alone is named, its sign-in list and the service are not
    // claimed where no read held them, and the words give no step.
    let stands = ["the account krb-checkout stands there and this run did not make it".to_owned()];
    let text = residue_tail(
        "no account has the identifier that the manifest records for krb-connect",
        &names[1..],
        false,
        &stands,
    );
    assert!(text.contains("the account krb-checkout stands there and this run did not make it"));
    assert!(text.contains("the sign-in list has no value for krb-connect"));
    assert!(!text.contains("either name") && !text.contains("service is not there"));
    assert!(
        text.ends_with(", and the program directory is not there"),
        "{text}"
    );
    for forbidden in ["remove ", "delete ", "by hand", "move "] {
        assert!(!text.contains(forbidden), "{forbidden} in {text}");
    }
    assert_eq!(
        residue_tail("", &[], false, &[]),
        "the program directory is not there"
    );
}
