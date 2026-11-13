//! The words of the refusal of a folder above the installation's two trees: which folder, which
//! tree, what its list gives to whom and what to do, and the comparison that refuses a drive letter
//! that is no volume's root. They run on every platform.

use kr_boundary_windows::remedy::{
    AncestorFault, KnownFolder, ParentCure, Presence, Stage, Subject, Tree, ancestor_refusal,
    dos_path_of, identity_text, is_below, is_on_a_network_share, is_the_place_asked_for,
    is_the_volumes_own_root, known_folder_unreadable, parent_advice, program_removal_advice,
    rights_finding, rights_in_words, shape_refusal, supported_layout,
};

const DELETE_CHILD: u32 = 0x0000_0040;
const DELETE: u32 = 0x0001_0000;
const WRITE_DAC: u32 = 0x0004_0000;
const WRITE_OWNER: u32 = 0x0008_0000;
const GENERIC_ALL: u32 = 0x1000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const MAXIMUM_ALLOWED: u32 = 0x0200_0000;

/// The ending of a state that can pass.
const RETRY: &str = "Run the setup program again when it can be read.";

/// The sentence that ends the words of every folder that the installation does not make.
const CLOSING: &str = "The setup program directs no change to a folder that other programs share.";

/// The number of faults and of stages that the cases go through. A new variant needs an arm in
/// `fault_index` or `stage_index`: the match is exhaustive, so a variant with no arm does not
/// compile. The match does not force a place in the list, and the count does not either: a variant
/// that has an arm and no entry passes, so whoever adds a variant adds its entry to `every_fault`
/// or `every_stage` and raises the count beside it. The list is checked against its count, and each
/// entry against its index.
const FAULTS: usize = 12;
const STAGES: usize = 6;

fn fault_index(fault: &AncestorFault<'_>) -> usize {
    match fault {
        AncestorFault::Link => 0,
        AncestorFault::NotAFolder => 1,
        AncestorFault::VolumeRoot => 2,
        AncestorFault::Overlap(_) => 3,
        AncestorFault::Alias(_) => 4,
        AncestorFault::Volume(_) => 5,
        AncestorFault::Unreadable(_) => 6,
        AncestorFault::VolumeUnanswered(_) => 7,
        AncestorFault::RootMissing(_) => 8,
        AncestorFault::List(_) => 9,
        AncestorFault::Writable(_) => 10,
        AncestorFault::Leads(_) => 11,
    }
}

fn stage_index(stage: &Stage) -> usize {
    match stage {
        Stage::Before => 0,
        Stage::After => 1,
        Stage::AfterRepair {
            broker_stopped: true,
        } => 2,
        Stage::AfterRepair {
            broker_stopped: false,
        } => 3,
        Stage::DataParentMade => 4,
        Stage::Rollback => 5,
    }
}

/// Every fault that a folder which the installation does not make can have.
fn every_fault() -> Vec<AncestorFault<'static>> {
    let faults = vec![
        AncestorFault::Link,
        AncestorFault::NotAFolder,
        AncestorFault::VolumeRoot,
        AncestorFault::Overlap(r"C:\Data"),
        AncestorFault::Alias(r"C:\Shared\Backing"),
        AncestorFault::Volume("the volume uses FAT32"),
        AncestorFault::Unreadable("Windows error 32"),
        AncestorFault::VolumeUnanswered("Windows error 21"),
        AncestorFault::RootMissing("Windows error 3"),
        AncestorFault::List("S-1-5-32-545 is allowed the right named by its list"),
        AncestorFault::Writable("S-1-5-32-545 is allowed to add"),
        AncestorFault::Leads(r"C:\Shared\Target"),
    ];
    assert_eq!(faults.len(), FAULTS, "every fault is in the list");
    for (at, fault) in faults.iter().enumerate() {
        assert_eq!(fault_index(fault), at, "{fault:?}");
    }
    faults
}

/// Every point of a run at which a folder can be read again.
fn every_stage() -> Vec<Stage> {
    let stages = vec![
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
    assert_eq!(stages.len(), STAGES, "every stage is in the list");
    for (at, stage) in stages.iter().enumerate() {
        assert_eq!(stage_index(stage), at, "{stage:?}");
    }
    stages
}

/// The words that tell an administrator to change a folder: a move, another place, the end of a
/// substitution or a redirection, an owner, a list, the removal of a link or of what is in the way,
/// a rename, a delete, a mount, a command that does any of these. A second line behind the type:
/// compared without regard to case, and a word that starts with a letter only where no letter is
/// before it.
const INSTRUCTIONS: [&str; 25] = [
    "rename",
    "delete",
    "take ownership",
    "change its owner",
    "set its permissions",
    "unmount",
    "dismount",
    "subst",
    "icacls",
    "takeown",
    "mountvol",
    "move ",
    "remove or",
    "remove the link",
    "remove it",
    "remove that",
    "rmdir",
    "end the",
    "redirection of",
    "give the",
    "make the",
    "narrow",
    "correct",
    "re-point",
    "other place",
];

/// The instruction words that `text` holds.
fn instructions_in(text: &str) -> Vec<&'static str> {
    let lower = text.to_lowercase();
    INSTRUCTIONS
        .into_iter()
        .filter(|word| {
            lower.match_indices(word).any(|(at, _)| {
                at == 0
                    || !lower[..at]
                        .chars()
                        .next_back()
                        .is_some_and(char::is_alphabetic)
            })
        })
        .collect()
}

#[test]
fn each_right_that_lets_an_account_replace_a_folder_is_said_in_words() {
    assert!(rights_in_words(DELETE_CHILD).contains("delete or rename an entry in it"));
    assert!(rights_in_words(DELETE).contains("delete it"));
    assert!(rights_in_words(WRITE_DAC).contains("change its list"));
    assert!(rights_in_words(WRITE_OWNER).contains("take its ownership"));
    assert!(rights_in_words(GENERIC_WRITE).contains("change it"));
    for every in [GENERIC_ALL, MAXIMUM_ALLOWED] {
        assert!(rights_in_words(every).contains("every right"), "{every:x}");
    }
}

#[test]
fn several_rights_are_all_said_and_a_right_that_changes_nothing_is_not() {
    let words = rights_in_words(DELETE_CHILD | WRITE_DAC | WRITE_OWNER);
    for part in [
        "delete or rename an entry in it",
        "change its list",
        "take its ownership",
    ] {
        assert!(words.contains(part), "{part}: {words}");
    }
    assert!(!words.contains("delete it"), "{words}");
    // Add a file (0x2), add a subdirectory (0x4) and read (0x1) change no folder's identity.
    assert_eq!(rights_in_words(0x0000_0007), "");
}

#[test]
fn an_identity_is_named_by_its_account_and_its_identifier_beside_it() {
    assert_eq!(
        identity_text(Some(r"BUILTIN\Users"), "S-1-5-32-545"),
        r"BUILTIN\Users (S-1-5-32-545)"
    );
    assert_eq!(
        identity_text(None, "S-1-5-21-1-2-3-1001"),
        "S-1-5-21-1-2-3-1001"
    );
    assert_eq!(identity_text(Some(""), "S-1-5-11"), "S-1-5-11");
}

/// A folder that the installation does not make (a known folder itself, every folder above it up
/// to the root of its volume, a drive letter) has one form of words whatever its fault, its tree
/// and the point of the run: what was found, what a supported layout is or what to try that changes
/// no folder, what the run changed, and one closing sentence. No word of it tells the administrator
/// to change that folder.
#[test]
fn every_fault_of_a_folder_that_the_installation_does_not_make_has_the_one_form() {
    for tree in [Tree::Data, Tree::Program] {
        let below = match tree {
            Tree::Data => "the boundary's data directory",
            Tree::Program => "the boundary's program directory",
        };
        for fault in every_fault() {
            for stage in every_stage() {
                let text =
                    ancestor_refusal(&Subject::shared(r"C:\Shared", fault.clone()), tree, stage);
                let what = format!("{tree:?} {fault:?} {stage:?}: {text}");
                assert!(text.contains(r"C:\Shared"), "{what}");
                assert!(
                    text.contains(&format!("above {below}")) || text.contains("drive letter"),
                    "{what}"
                );
                assert!(text.ends_with(CLOSING), "{what}");
                assert_eq!(text.matches(CLOSING).count(), 1, "{what}");
                let layout = supported_layout(tree);
                let kept = text.contains("Do not remove the program directory.");
                assert_eq!(kept, tree == Tree::Program, "{what}");
                match fault {
                    AncestorFault::Unreadable(_)
                    | AncestorFault::VolumeUnanswered(_)
                    | AncestorFault::RootMissing(_) => {
                        assert!(!text.contains(&layout), "{what}");
                        assert!(text.contains(RETRY), "{what}");
                        assert!(!text.contains("Close the program"), "{what}");
                        assert!(!text.contains("did not answer"), "{what}");
                        assert!(!text.contains("holds it open"), "{what}");
                    }
                    _ => {
                        assert_eq!(text.matches(&layout).count(), 1, "{what}");
                        assert!(!text.contains("Close the program"), "{what}");
                    }
                }
                assert!(
                    layout.starts_with("This layout is not supported: "),
                    "{layout}"
                );
                assert!(instructions_in(&text).is_empty(), "{what}");
            }
        }
    }
}

/// The sentence that says where the boundary installs is one sentence of each tree's own known
/// folder, and no instruction.
#[test]
fn the_supported_layout_says_where_each_tree_installs() {
    let data = supported_layout(Tree::Data);
    assert!(data.contains("the boundary's data directory"), "{data}");
    assert!(data.contains("system's ProgramData folder"), "{data}");
    assert!(data.contains("fixed, local NTFS volume"), "{data}");
    assert!(
        data.contains("the path that the system gives for that folder is its own final path"),
        "{data}"
    );
    assert!(!data.contains("program directory"), "{data}");
    let program = supported_layout(Tree::Program);
    assert!(
        program.contains("the boundary's program directory"),
        "{program}"
    );
    assert!(
        program.contains("system's Program Files folder"),
        "{program}"
    );
    for text in [&data, &program] {
        assert_eq!(text.matches(". ").count(), 0, "one sentence: {text}");
        assert!(instructions_in(text).is_empty(), "{text}");
    }
}

/// The sentence of the list's refusal is the one that the native check makes (`rights_finding`),
/// and it stays in the words of a refusal of a known folder or of a folder above it, with what the
/// rights allow and what a supported layout is, and with no instruction to change the list.
#[test]
fn the_refusal_of_a_list_names_the_real_sentence_and_says_what_a_supported_layout_is() {
    let finding = rights_finding(
        &identity_text(Some(r"NT AUTHORITY\Authenticated Users"), "S-1-5-11"),
        DELETE | DELETE_CHILD,
    );
    assert_eq!(
        finding,
        r"NT AUTHORITY\Authenticated Users (S-1-5-11) is allowed the right to delete or rename an entry in it, the right to delete it (rights 0x10040)"
    );
    let text = ancestor_refusal(
        &Subject::shared(r"D:\ProgramData", AncestorFault::List(&finding)),
        Tree::Data,
        Stage::Before,
    );
    assert!(text.contains(r"D:\ProgramData"), "{text}");
    assert!(
        text.contains("a folder above the boundary's data directory"),
        "{text}"
    );
    assert!(text.contains(&finding), "{text}");
    assert!(text.contains("It is refused because"), "{text}");
    assert!(text.contains("Nothing was changed"), "{text}");
    assert!(
        text.contains(
            "could swap a folder below it for a link after the installation has read that folder"
        ),
        "{text}"
    );
    assert!(text.contains(&supported_layout(Tree::Data)), "{text}");
    assert!(!text.contains("program directory"), "{text}");
}

#[test]
fn the_refusal_of_a_folder_above_the_program_directory_names_that_tree() {
    let text = ancestor_refusal(
        &Subject::shared(r"C:\", AncestorFault::List("a reason")),
        Tree::Program,
        Stage::Before,
    );
    assert!(
        text.contains("a folder above the boundary's program directory"),
        "{text}"
    );
    assert!(!text.contains("data directory"), "{text}");
}

/// A link or a mounted folder above the trees is the administrator's own: a moved `ProgramData`, a
/// mounted volume. The words say that the installation does not go through one, that the layout is
/// not supported and where the boundary installs, and that nothing was changed. They never tell to
/// remove the link, which would remove the folder that the link replaced for every program, and they
/// direct no change of a folder that others share and claim nothing about what the folder holds,
/// which they do not know.
#[test]
fn the_refusal_of_a_link_or_a_mounted_folder_never_tells_an_administrator_to_remove_it() {
    for tree in [Tree::Data, Tree::Program] {
        let text = ancestor_refusal(
            &Subject::shared(r"C:\ProgramData", AncestorFault::Link),
            tree,
            Stage::Before,
        );
        assert!(text.contains(r"C:\ProgramData"), "{text}");
        assert!(text.contains("it is a link or a mounted folder"), "{text}");
        assert!(
            text.contains("does not go through a link or a mounted folder at or above its trees"),
            "{text}"
        );
        assert!(text.contains("Nothing was changed"), "{text}");
        assert!(text.contains(&supported_layout(tree)), "{text}");
        assert!(text.contains("This layout is not supported"), "{text}");
        let lower = text.to_lowercase();
        assert!(!lower.contains("remove the link"), "{text}");
        assert!(!lower.contains("rmdir"), "{text}");
        assert!(!text.contains("give the known folder"), "{text}");
        assert!(!lower.contains("holds other things"), "{text}");
        assert!(!lower.contains("do not remove or move it"), "{text}");
        assert!(
            !text.contains("The setup program makes this folder itself"),
            "{text}"
        );
    }
}

/// A folder that is read again after the run has made its first changes is refused without the claim
/// that nothing was changed, whatever the reason; read before any change it makes the claim.
#[test]
fn a_refusal_after_the_runs_changes_does_not_say_that_nothing_was_changed() {
    for fault in every_fault() {
        let subject = Subject::shared(r"C:\x", fault.clone());
        let before = ancestor_refusal(&subject, Tree::Program, Stage::Before);
        assert!(
            before.contains("Nothing was changed"),
            "{fault:?}: {before}"
        );
        let after = ancestor_refusal(&subject, Tree::Program, Stage::After);
        assert!(!after.contains("Nothing was changed"), "{fault:?}: {after}");
        assert!(
            after.contains("had already made changes"),
            "{fault:?}: {after}"
        );
        assert!(
            after.contains("the manifest records them"),
            "{fault:?}: {after}"
        );
        assert!(!after.contains("stays stopped"), "{fault:?}: {after}");
        let made = ancestor_refusal(&subject, Tree::Data, Stage::DataParentMade);
        assert!(!made.contains("Nothing was changed"), "{fault:?}: {made}");
        assert!(
            made.contains("had already made the folder that holds the data directory"),
            "{fault:?}: {made}"
        );
        assert!(!made.contains("the manifest records"), "{fault:?}: {made}");
    }
}

/// A repair has no rollback and its manifest records neither the sweep of staging nor the stop of
/// the broker. The words say that the broker stays stopped only where the repair stopped it or found
/// it stopped.
#[test]
fn a_repair_says_that_the_broker_stays_stopped_only_where_it_was_stopped() {
    for fault in every_fault() {
        let subject = Subject::shared(r"C:\x", fault.clone());
        let stopped = ancestor_refusal(
            &subject,
            Tree::Program,
            Stage::AfterRepair {
                broker_stopped: true,
            },
        );
        assert!(
            !stopped.contains("Nothing was changed"),
            "{fault:?}: {stopped}"
        );
        assert!(
            stopped.contains("had already made changes"),
            "{fault:?}: {stopped}"
        );
        assert!(
            stopped.contains("A repair has no rollback."),
            "{fault:?}: {stopped}"
        );
        assert!(
            stopped.contains("The broker stays stopped."),
            "{fault:?}: {stopped}"
        );
        assert!(!stopped.contains("manifest"), "{fault:?}: {stopped}");
        let running = ancestor_refusal(
            &subject,
            Tree::Program,
            Stage::AfterRepair {
                broker_stopped: false,
            },
        );
        assert!(
            running.contains("A repair has no rollback."),
            "{fault:?}: {running}"
        );
        assert!(!running.contains("stopped"), "{fault:?}: {running}");
        assert!(!running.contains("manifest"), "{fault:?}: {running}");
    }
}

/// The folder that holds the data directory is made by this run only where the run's own call made
/// it, and no words say what is in a folder before the code has looked.
#[test]
fn no_stage_says_that_a_folder_is_empty_and_the_data_parents_stage_says_what_the_run_made() {
    for fault in every_fault() {
        for stage in every_stage() {
            let text =
                ancestor_refusal(&Subject::shared(r"C:\x", fault.clone()), Tree::Data, stage);
            assert!(!text.contains("empty"), "{fault:?} {stage:?}: {text}");
        }
        let made = ancestor_refusal(
            &Subject::shared(r"C:\x", fault.clone()),
            Tree::Data,
            Stage::DataParentMade,
        );
        assert!(
            made.contains("This run had already made the folder that holds the data directory"),
            "{fault:?}: {made}"
        );
        assert!(made.contains("the folder stays"), "{fault:?}: {made}");
    }
}

/// A removal that undoes a failed installation has changed nothing when it reads a folder, and does
/// not say "Nothing was changed" of the installation that failed.
#[test]
fn the_removal_that_undoes_a_failed_installation_does_not_say_that_nothing_was_changed() {
    for fault in every_fault() {
        let text = ancestor_refusal(
            &Subject::shared(r"C:\x", fault.clone()),
            Tree::Program,
            Stage::Rollback,
        );
        assert!(!text.contains("Nothing was changed"), "{fault:?}: {text}");
        assert!(
            text.contains(
                "This removal, which undoes the installation that failed, had changed nothing"
            ),
            "{fault:?}: {text}"
        );
        assert!(
            text.contains("whatever that installation had already made is still there"),
            "{fault:?}: {text}"
        );
    }
}

#[test]
fn the_refusal_of_what_is_not_a_folder_or_cannot_be_read_says_what_a_layout_is_or_what_to_try() {
    let text = ancestor_refusal(
        &Subject::shared(r"C:\x", AncestorFault::NotAFolder),
        Tree::Data,
        Stage::Before,
    );
    assert!(text.contains("it is not a folder"), "{text}");
    assert!(text.contains("Nothing was changed"), "{text}");
    assert!(text.contains("This layout is not supported"), "{text}");
    assert!(!text.contains("Correct the path"), "{text}");
    let text = ancestor_refusal(
        &Subject::shared(r"C:\x", AncestorFault::Unreadable("Windows error 5")),
        Tree::Program,
        Stage::Before,
    );
    assert!(text.contains(r"C:\x"), "{text}");
    assert!(
        text.contains("could not be opened or read to be checked (Windows error 5)"),
        "{text}"
    );
    assert!(text.contains("program directory"), "{text}");
    assert!(text.contains(RETRY), "{text}");
    // No cause is named: the error can be any of many.
    for cause in [
        "Close the program",
        "holds it open",
        "correct who may open it",
    ] {
        assert!(!text.contains(cause), "{cause}: {text}");
    }
    assert!(!text.contains("This layout is not supported"), "{text}");
}

/// A volume that cannot be asked what it is, or a root that is not there, is refused for its volume
/// and not for a program that holds a folder open. The words say what the call returned, with the
/// platform's error, and name no cause that the error can contradict.
#[test]
fn a_volume_that_cannot_be_asked_is_refused_for_its_volume_and_names_no_cause() {
    for (tree, own) in [
        (Tree::Program, "program directory"),
        (Tree::Data, "data directory"),
    ] {
        let text = ancestor_refusal(
            &Subject::shared(r"Z:\", AncestorFault::VolumeUnanswered("Windows error 21")),
            tree,
            Stage::Before,
        );
        assert!(
            text.contains(&format!(r"Z:\ is a folder above the boundary's {own}")),
            "{text}"
        );
        assert!(
            text.contains("its volume could not be asked what it is (Windows error 21)"),
            "{text}"
        );
        assert!(text.contains("Nothing was changed"), "{text}");
        assert!(text.contains(RETRY), "{text}");
        for cause in [
            "Close the program",
            "holds it open",
            "being removed",
            "has failed",
            "did not answer",
        ] {
            assert!(!text.contains(cause), "{cause}: {text}");
        }
        let after = ancestor_refusal(
            &Subject::shared(r"Z:\", AncestorFault::VolumeUnanswered("Windows error 21")),
            tree,
            Stage::AfterRepair {
                broker_stopped: true,
            },
        );
        assert!(!after.contains("Nothing was changed"), "{after}");
    }
    let program = ancestor_refusal(
        &Subject::shared(r"Z:\", AncestorFault::VolumeUnanswered("Windows error 21")),
        Tree::Program,
        Stage::Before,
    );
    assert!(
        program.contains("Do not remove the program directory"),
        "{program}"
    );
}

/// The root of a volume that is not there did not answer a question: the installation never asked
/// the volume what it is, and its words say only that the root is not there, with the error.
#[test]
fn a_root_that_is_not_there_is_said_to_be_not_there_and_nothing_more() {
    for tree in [Tree::Program, Tree::Data] {
        let text = ancestor_refusal(
            &Subject::shared(r"Z:\", AncestorFault::RootMissing("Windows error 3")),
            tree,
            Stage::Before,
        );
        assert!(
            text.contains("the root of its volume is not there (Windows error 3)"),
            "{text}"
        );
        for word in ["asks", "asked", "did not answer", "removed", "failed"] {
            assert!(!text.contains(word), "{word}: {text}");
        }
        assert!(text.contains(RETRY), "{text}");
    }
}

#[test]
fn a_drive_letter_that_is_no_volumes_root_is_refused_with_the_letter_and_the_real_path() {
    for tree in [Tree::Data, Tree::Program] {
        let text = ancestor_refusal(
            &Subject::shared(r"X:\", AncestorFault::Alias(r"C:\Shared\Backing")),
            tree,
            Stage::Before,
        );
        assert!(
            text.contains(r"X:\ is a drive letter that is not the root of its volume"),
            "{text}"
        );
        assert!(text.contains(r"it leads to C:\Shared\Backing"), "{text}");
        assert!(text.contains("Nothing was changed"), "{text}");
        assert!(text.contains(&supported_layout(tree)), "{text}");
        assert!(!text.contains("substitution"), "{text}");
        assert!(!text.contains("redirection"), "{text}");
        assert!(!text.contains("a place on a volume"), "{text}");
        assert!(!text.contains("Install on the real path"), "{text}");
    }
}

/// The comparison that refuses an alias, over made paths: a volume's own root is what a drive
/// letter's final path says it is, whatever the case and the extended form, and a substituted or
/// redirected letter is a folder of another volume, or a root with another letter.
#[test]
fn a_drives_root_is_the_volumes_own_only_where_its_final_path_is_the_one_supplied() {
    assert!(is_the_volumes_own_root(r"C:\", r"C:\"));
    assert!(is_the_volumes_own_root(r"C:\", r"\\?\C:\"));
    assert!(is_the_volumes_own_root(r"c:\", r"C:\"));
    assert!(is_the_volumes_own_root(r"C:", r"C:\"));
    assert!(!is_the_volumes_own_root(r"X:\", r"C:\Shared\Backing\"));
    assert!(!is_the_volumes_own_root(r"X:\", r"\\?\C:\Shared\Backing\"));
    assert!(!is_the_volumes_own_root(r"X:\", r"D:\"));
    assert!(!is_the_volumes_own_root(r"C:\", r"C:\Windows"));
}

/// A folder above a tree that is on a volume that the installation does not use is refused for its
/// volume, with the reason that the volume check gave, in the words of the tree that it holds: the
/// layout is not supported, and the words never tell to correct an owner or a list, to close a
/// program or to remove a link.
#[test]
fn a_folder_on_a_volume_that_is_not_used_is_refused_for_its_volume() {
    let reason = "the volume uses FAT32, and only NTFS volumes are supported";
    for (tree, own) in [
        (Tree::Program, "program directory"),
        (Tree::Data, "data directory"),
    ] {
        let text = ancestor_refusal(
            &Subject::shared(r"Y:\", AncestorFault::Volume(reason)),
            tree,
            Stage::Before,
        );
        assert!(
            text.contains(&format!(r"Y:\ is a folder above the boundary's {own}")),
            "{text}"
        );
        assert!(
            text.contains("is on a volume that the installation does not use"),
            "{text}"
        );
        assert!(text.contains(reason), "{text}");
        assert!(text.contains("fixed, local NTFS volume"), "{text}");
        assert!(text.contains("Nothing was changed"), "{text}");
        assert!(!text.contains("Make the Administrators group"), "{text}");
        assert!(!text.contains("Close the program"), "{text}");
        assert!(!text.to_lowercase().contains("remove the link"), "{text}");
        assert!(text.contains("This layout is not supported"), "{text}");
        assert!(text.ends_with(CLOSING), "{text}");
        assert!(!text.contains("Move "), "{text}");
        assert!(!text.to_lowercase().contains("re-point"), "{text}");
    }
    let program = ancestor_refusal(
        &Subject::shared(r"Y:\", AncestorFault::Volume("a reason")),
        Tree::Program,
        Stage::Before,
    );
    assert!(
        program.contains("Do not remove the program directory"),
        "{program}"
    );
    assert!(program.contains("Program Files folder"), "{program}");
    // The anchor's own refusal of a volume says the same sentence.
    let anchor = supported_layout(Tree::Program);
    assert!(program.contains(&anchor), "{program}");
    assert!(!anchor.contains("Move "), "{anchor}");
    let data = ancestor_refusal(
        &Subject::shared(r"Y:\", AncestorFault::Volume("a reason")),
        Tree::Data,
        Stage::Before,
    );
    assert!(data.contains("ProgramData folder"), "{data}");
    assert!(!data.contains("program directory"), "{data}");
    // After the run's changes the words do not claim that nothing was changed.
    let after = ancestor_refusal(
        &Subject::shared(r"Y:\", AncestorFault::Volume("a reason")),
        Tree::Program,
        Stage::After,
    );
    assert!(!after.contains("Nothing was changed"), "{after}");
}

/// A known folder that an administrator gave a network path has the final path
/// `\\?\UNC\server\share\...`. Printing it for a person as `\\server\share\...` is for the text
/// alone: no comparison that decides a refusal takes that form, so a final path on a network share is
/// never a volume's root and never the place that was asked for, as the folders above a share are the
/// server's and not the ones that the installation read.
#[test]
fn a_final_path_on_a_network_share_is_never_the_place_that_was_asked_for() {
    assert!(is_on_a_network_share(r"\\?\UNC\server\share\"));
    assert!(is_on_a_network_share(r"\\?\unc\server\share\dir"));
    assert!(!is_on_a_network_share(r"\\?\C:\"));
    assert!(!is_on_a_network_share(r"C:\Unc\x"));
    // The root check refuses the share's root, whichever way the root was supplied.
    assert!(!is_the_volumes_own_root(
        r"\\server\share\",
        r"\\?\UNC\server\share\"
    ));
    assert!(!is_the_volumes_own_root(
        r"\\server\share",
        r"\\?\UNC\server\share\"
    ));
    assert!(!is_the_volumes_own_root(
        r"\\?\UNC\server\share\",
        r"\\?\UNC\server\share\"
    ));
    // The program walk's comparison refuses a folder on a share, and still accepts a local one.
    assert!(!is_the_place_asked_for(
        r"\\server\share\Top",
        r"\\?\UNC\server\share\Top"
    ));
    assert!(is_the_place_asked_for(
        r"C:\Program Files",
        r"\\?\C:\Program Files"
    ));
    assert!(is_the_place_asked_for(
        r"c:\program files",
        r"\\?\C:\Program Files"
    ));
    assert!(!is_the_place_asked_for(
        r"C:\Program Files",
        r"\\?\D:\Program Files"
    ));
    assert!(!is_the_place_asked_for(
        r"C:\Program Files\KalaReach",
        r"\\?\C:\Elsewhere\KalaReach"
    ));
    // What a person reads is the usable form, and it is the form that would have matched.
    assert_eq!(
        dos_path_of(r"\\?\UNC\server\share\Top"),
        r"\\server\share\Top"
    );
}

/// The walk from the program directory's top down reads the known folder itself and the folders
/// that the installation makes below it. The known folder is another program's: its words say what a
/// supported layout is, whatever its fault, and never tell to change its owner or its list or to
/// remove a link. A folder that the installation makes may be told what to correct, and claims
/// nothing of what is in it.
#[test]
fn the_known_folder_gets_the_words_of_a_shared_folder_and_the_products_own_folder_its_own() {
    let known = r"C:\Program Files";
    let own = r"C:\Program Files\KalaReach";
    for fault in [
        AncestorFault::Link,
        AncestorFault::NotAFolder,
        AncestorFault::Writable("S-1-5-32-545 is allowed to add"),
        AncestorFault::Unreadable("Windows error 5"),
    ] {
        let at_known = ancestor_refusal(
            &Subject::at(known, known, fault.clone()),
            Tree::Program,
            Stage::Before,
        );
        let shared = ancestor_refusal(
            &Subject::shared(known, fault.clone()),
            Tree::Program,
            Stage::Before,
        );
        assert_eq!(at_known, shared, "{fault:?}");
        assert!(at_known.ends_with(CLOSING), "{fault:?}: {at_known}");
        assert!(
            !at_known.contains("makes this folder itself"),
            "{fault:?}: {at_known}"
        );
        let below = ancestor_refusal(
            &Subject::at(own, known, fault.clone()),
            Tree::Program,
            Stage::Before,
        );
        let own_words = match fault {
            AncestorFault::Link | AncestorFault::NotAFolder => "makes this folder itself",
            AncestorFault::Writable(_) => "Make the Administrators group",
            _ => "If a program holds it open",
        };
        assert!(below.contains(own_words), "{fault:?}: {below}");
        assert!(!at_known.contains(own_words), "{fault:?}: {at_known}");
        // Nothing of what is in a folder that nothing read.
        for claim in ["holds other things", "loses nothing"] {
            assert!(!below.contains(claim), "{fault:?}: {below}");
        }
    }
    let text = ancestor_refusal(
        &Subject::at(
            known,
            known,
            AncestorFault::Writable("S-1-5-32-545 is allowed to add"),
        ),
        Tree::Program,
        Stage::Before,
    );
    assert!(
        text.contains(r"C:\Program Files is a folder above the boundary's program directory"),
        "{text}"
    );
    assert!(text.contains("S-1-5-32-545 is allowed to add"), "{text}");
    assert!(text.contains("Whoever owns it, or can add to it"), "{text}");
    assert!(
        text.contains("Do not remove the program directory"),
        "{text}"
    );
    assert!(!text.contains("the manifest records it"), "{text}");
    assert!(text.contains("Nothing was changed"), "{text}");
    assert!(instructions_in(&text).is_empty(), "{text}");
    let made = ancestor_refusal(
        &Subject::at(
            own,
            known,
            AncestorFault::Writable("S-1-5-32-545 is allowed to add"),
        ),
        Tree::Program,
        Stage::Before,
    );
    assert!(
        made.contains(
            "Make the Administrators group, the system or the installer service its owner"
        ),
        "{made}"
    );
    assert!(
        made.contains("Do not remove the program directory"),
        "{made}"
    );
    assert!(!made.to_lowercase().contains("remove the link"), "{made}");
}

/// Whose a folder of the program walk is: the known folder itself and every folder above it are
/// another program's, and only a folder strictly below the known folder is the installation's. The
/// comparison ignores case, a trailing backslash and the extended form, and a sibling that shares a
/// prefix with the known folder's name is no folder below it.
#[test]
fn only_a_folder_strictly_below_the_known_folder_is_the_installations_own() {
    let known = r"C:\Program Files";
    assert!(is_below(r"C:\Program Files\KalaReach", known));
    assert!(is_below(r"C:\Program Files\KalaReach\Boundary", known));
    assert!(is_below(r"c:\program files\kalareach\", known));
    assert!(is_below(r"\\?\C:\Program Files\KalaReach", known));
    assert!(!is_below(known, known));
    assert!(!is_below(r"c:\program files\", known));
    assert!(!is_below(r"C:\", known));
    assert!(!is_below(r"C:\Program Files (x86)", known));
    assert!(!is_below(r"C:\Program Files (x86)\KalaReach", known));
    assert!(!is_below(r"D:\Program Files\KalaReach", known));
    assert!(is_below(r"C:\Windows", r"C:\"));
    assert!(!is_below(r"C:\", r"C:\"));
    // The choice itself: the known folder is shared, a folder strictly below it is the product's own.
    let at = |folder| Subject::at(folder, known, AncestorFault::Link);
    assert!(!at(known).is_the_installations_own());
    assert!(at(r"C:\Program Files\KalaReach").is_the_installations_own());
    assert!(!at(r"C:\").is_the_installations_own());
    assert!(
        !Subject::shared(r"C:\Program Files\KalaReach", AncestorFault::Link)
            .is_the_installations_own()
    );
    // A forward slash is a backslash.
    assert!(is_below(r"C:/Program Files/KalaReach", known));
    assert!(is_below(r"C:\Program Files\KalaReach", r"C:/Program Files"));
    assert!(!is_below(r"C:/Program Files", known));
}

/// A link at the boundary's own folder above the program directory is not a known folder of another
/// computer: the words say that the layout is not supported and what the setup program does, and
/// never send the administrator to a computer whose known folders are plain, or to remove the link.
#[test]
fn a_link_at_the_boundarys_own_folder_sends_the_administrator_nowhere_else() {
    let text = ancestor_refusal(
        &Subject::at(
            r"C:\Program Files\KalaReach",
            r"C:\Program Files",
            AncestorFault::Link,
        ),
        Tree::Program,
        Stage::Before,
    );
    assert!(
        text.contains(
            r"C:\Program Files\KalaReach is a folder above the boundary's program directory"
        ),
        "{text}"
    );
    assert!(text.contains("it is a link or a mounted folder"), "{text}");
    assert!(text.contains("This layout is not supported"), "{text}");
    assert!(
        text.contains("The setup program makes this folder itself"),
        "{text}"
    );
    assert!(text.contains("Nothing was changed"), "{text}");
    assert!(
        text.contains("Do not remove the program directory"),
        "{text}"
    );
    assert!(!text.contains("computer"), "{text}");
    assert!(!text.contains("plain folders"), "{text}");
    assert!(!text.to_lowercase().contains("remove the link"), "{text}");
}

/// A folder strictly below the known folder whose final path is not the one asked for is said as what
/// it is, a path that leads elsewhere, and is never called a link: a short name or another spelling
/// leads elsewhere as well. Its words are the layout's, and no word tells to change anything.
#[test]
fn a_final_path_below_the_known_folder_that_is_not_the_one_asked_for_names_no_cause() {
    let known = r"C:\Program Files";
    let own = r"C:\Program Files\KalaReach";
    let text = ancestor_refusal(
        &Subject::at(own, known, AncestorFault::Leads(r"C:\Elsewhere\KalaReach")),
        Tree::Program,
        Stage::Before,
    );
    assert!(
        text.starts_with(&format!(
            "{own} is a folder above the boundary's program directory"
        )),
        "{text}"
    );
    assert!(
        text.contains(r"that folder's own path is C:\Elsewhere\KalaReach."),
        "{text}"
    );
    assert!(text.contains(&supported_layout(Tree::Program)), "{text}");
    assert!(text.ends_with(CLOSING), "{text}");
    assert!(!text.to_lowercase().contains("link"), "{text}");
    assert!(!text.contains("makes this folder itself"), "{text}");
    assert!(instructions_in(&text).is_empty(), "{text}");
}

/// What the setup program can do after a link at the program directory's name: a repair makes the
/// program files again only where an installation is recorded.
#[test]
fn a_repair_is_promised_only_where_an_installation_is_recorded() {
    let entry = r"C:\Program Files\KalaReach\Boundary";
    for link in [false, true] {
        let recorded = program_removal_advice(entry, link, true);
        assert!(
            recorded.contains("A repair makes the program files again"),
            "{recorded}"
        );
        let fresh = program_removal_advice(entry, link, false);
        assert!(!fresh.contains("repair"), "{fresh}");
        assert!(
            fresh.ends_with("Then run the setup program again."),
            "{fresh}"
        );
    }
}

/// A folder's final path is printed in a form that a person can use: the extended prefix goes, and a
/// network path is the network path.
#[test]
fn a_final_path_is_printed_as_a_person_can_use_it() {
    assert_eq!(dos_path_of(r"\\?\C:\Windows"), r"C:\Windows");
    assert_eq!(
        dos_path_of(r"\\?\UNC\server\share\dir"),
        r"\\server\share\dir"
    );
    assert_eq!(dos_path_of(r"C:\Windows"), r"C:\Windows");
    assert_eq!(dos_path_of(r"\\?\C:\"), r"C:\");
}

/// A known folder as the system gave it, whose open showed the final path `found`.
fn known<'a>(given: &'a str, found: &'a str) -> KnownFolder<'a> {
    KnownFolder {
        given,
        opened: Ok(found),
    }
}

/// A known folder whose open or whose read of the final path failed with `error`.
fn unopened<'a>(given: &'a str, error: &'a str) -> KnownFolder<'a> {
    KnownFolder {
        given,
        opened: Err(error),
    }
}

const PF: &str = r"C:\Program Files";
const PF_FINAL: &str = r"\\?\C:\Program Files";
const PD: &str = r"C:\ProgramData";
const PD_FINAL: &str = r"\\?\C:\ProgramData";

/// The words of a refusal that the shape check gives for a layout that is not supported: no
/// instruction, one closing sentence, and what the run changed.
fn shape_words(text: &str) {
    assert!(text.contains("This layout is not supported"), "{text}");
    assert!(text.contains("Nothing was changed"), "{text}");
    assert!(text.ends_with(CLOSING), "{text}");
    assert_eq!(text.matches(CLOSING).count(), 1, "{text}");
    assert!(instructions_in(text).is_empty(), "{text}");
}

/// A known folder whose path is not its own final path is refused first, in the shared form with the
/// layout ending, with what it leads to and no cause: a short name, a link or a mounted folder, a
/// forward slash, a substituted letter, a network path, an extended prefix, a trailing backslash and
/// another form of its letters all end here, for either tree.
#[test]
fn a_known_folder_that_is_not_its_own_final_path_is_refused_with_what_it_leads_to() {
    // (the path that the system gave, the final path of the folder that it opens, what it leads to)
    let forms = [
        (r"C:\SHARED~1", r"\\?\C:\Shared Data", r"C:\Shared Data"),
        (r"C:\PROGRA~3", PD_FINAL, PD),
        (
            r"C:\PF",
            r"\\?\C:\ProgramData\KalaReach",
            r"C:\ProgramData\KalaReach",
        ),
        (
            "C:/ProgramData/KalaReach",
            r"\\?\C:\ProgramData\KalaReach",
            r"C:\ProgramData\KalaReach",
        ),
        (
            "C:\\\u{dc}nder\\Data",
            "\\\\?\\C:\\\u{fc}nder\\Data",
            "C:\\\u{fc}nder\\Data",
        ),
        (
            r"X:\ProgramData",
            r"\\?\C:\Shared\ProgramData",
            r"C:\Shared\ProgramData",
        ),
        (
            r"\\server\share\Data",
            r"\\?\UNC\server\share\Data",
            r"\\server\share\Data",
        ),
        (PF_FINAL, PF_FINAL, PF),
        (r"C:\Program Files\", PF_FINAL, PF),
        ("E:", r"\\?\E:\", r"E:\"),
        ("E:/", r"\\?\E:\", r"E:\"),
        (r"\\?\Volume{0-1}\", r"\\?\E:\", r"E:\"),
        (
            r"\\server\share\",
            r"\\?\UNC\server\share\",
            r"\\server\share\",
        ),
    ];
    for (given, found, leads_to) in forms {
        for tree in [Tree::Program, Tree::Data] {
            // The refused folder may be either of the two, and the other is a good one.
            let (files, data) = match tree {
                Tree::Program => (known(given, found), known(PD, PD_FINAL)),
                Tree::Data => (known(PF, PF_FINAL), known(given, found)),
            };
            let text = shape_refusal(&files, &data, Stage::Before)
                .unwrap_or_else(|| panic!("{given} for {tree:?} is refused"));
            let above = match tree {
                Tree::Program => "above the boundary's program directory",
                Tree::Data => "above the boundary's data directory",
            };
            assert!(
                text.starts_with(&format!("{given} is a folder {above}")),
                "{given}: {text}"
            );
            assert!(
                text.contains(&format!("that folder's own path is {leads_to}.")),
                "{given}: {text}"
            );
            assert!(text.contains(&supported_layout(tree)), "{given}: {text}");
            assert!(!text.contains("root of a volume"), "{given}: {text}");
            assert!(!text.contains("overlaps"), "{given}: {text}");
            shape_words(&text);
            for cause in ["link", "short name", "subst", "alias", "mounted"] {
                assert!(
                    !text.to_lowercase().contains(cause),
                    "{given} {cause}: {text}"
                );
            }
        }
    }
}

/// The Codex pair: the system gave `C:\SHARED~1` for ProgramData, the short name of `C:\Shared Data`,
/// and `C:\Shared Data\KalaReach` for Program Files. The data walk would read that folder as the
/// installation's own and tell the administrator to remove or rename it: the shape check ends the run
/// first, with no instruction.
#[test]
fn a_short_name_for_a_known_folder_never_makes_the_other_known_folder_the_installations_own() {
    let text = shape_refusal(
        &known(r"C:\Shared Data\KalaReach", r"\\?\C:\Shared Data\KalaReach"),
        &known(r"C:\SHARED~1", r"\\?\C:\Shared Data"),
        Stage::Before,
    )
    .expect("refused");
    assert!(
        text.starts_with(r"C:\SHARED~1 is a folder above the boundary's data directory"),
        "{text}"
    );
    assert!(
        text.contains(r"that folder's own path is C:\Shared Data."),
        "{text}"
    );
    shape_words(&text);
    assert!(!text.contains("remove or rename"), "{text}");
}

/// The Claude pair, a junction: Program Files' path is `C:\PF`, which leads to the data tree's own
/// folder. The known folder is refused for where it leads, so the data walk never reads
/// `C:\ProgramData\KalaReach` as the installation's own folder under a shared known folder.
#[test]
fn a_junction_to_the_other_trees_folder_is_refused_for_where_it_leads() {
    let text = shape_refusal(
        &known(r"C:\PF", r"\\?\C:\ProgramData\KalaReach"),
        &known(PD, PD_FINAL),
        Stage::Before,
    )
    .expect("refused");
    assert!(
        text.contains(r"that folder's own path is C:\ProgramData\KalaReach."),
        "{text}"
    );
    assert!(!text.contains("overlaps"), "{text}");
    shape_words(&text);
}

/// A known folder that could not be opened, or whose final path could not be read, gets the words of
/// a folder that could not be opened or read, with the platform's error and the ending of a state
/// that can pass. It never gets a root or an overlap sentence, whatever its path says.
#[test]
fn a_known_folder_that_cannot_be_opened_gets_the_shared_words_for_that() {
    let error = "Windows error 3";
    for (files, data, folder, tree) in [
        (unopened(PF, error), known(PD, PD_FINAL), PF, "program"),
        (known(PF, PF_FINAL), unopened(PD, error), PD, "data"),
        (
            unopened(r"D:\", error),
            known(PD, PD_FINAL),
            r"D:\",
            "program",
        ),
    ] {
        let text = shape_refusal(&files, &data, Stage::Before).expect("refused");
        assert!(
            text.starts_with(&format!(
                "{folder} is a folder above the boundary's {tree} directory"
            )),
            "{text}"
        );
        assert!(
            text.contains(
                "It is refused because it could not be opened or read to be checked (Windows error 3)."
            ),
            "{text}"
        );
        assert!(!text.contains("root of a volume"), "{text}");
        assert!(!text.contains("overlaps"), "{text}");
        assert!(!text.contains("This layout is not supported"), "{text}");
        assert!(text.contains(RETRY), "{text}");
        assert!(text.contains("Nothing was changed."), "{text}");
        assert!(text.ends_with(CLOSING), "{text}");
        assert!(instructions_in(&text).is_empty(), "{text}");
    }
}

/// The root and the overlap are decided by the final paths alone, in the forms that the system gives
/// them: a known folder that is a plain root (a drive letter and a backslash, whichever the letter
/// case), known folders that are the same folder, or one at or below the other tree's own folder.
#[test]
fn the_root_and_the_overlap_compare_the_final_paths_alone() {
    // (Program Files: given and final, ProgramData: given and final, the refused folder, its tree)
    let refused = [
        ((r"D:\", r"\\?\D:\"), (PD, PD_FINAL), r"D:\", "program"),
        ((r"d:\", r"\\?\D:\"), (PD, PD_FINAL), r"d:\", "program"),
        ((PF, PF_FINAL), (r"e:\", r"\\?\E:\"), r"e:\", "data"),
        (
            (r"Volume{0-1}\", r"\\?\Volume{0-1}\"),
            (PD, PD_FINAL),
            r"Volume{0-1}\",
            "program",
        ),
        (
            (r"D:\Data", r"\\?\D:\Data"),
            (r"D:\Data", r"\\?\D:\Data"),
            r"D:\Data",
            "program",
        ),
        (
            (r"d:\data", r"\\?\D:\Data"),
            (r"D:\DATA", r"\\?\D:\Data"),
            r"d:\data",
            "program",
        ),
        (
            (r"D:\Data\KalaReach", r"\\?\D:\Data\KalaReach"),
            (r"D:\Data", r"\\?\D:\Data"),
            r"D:\Data\KalaReach",
            "program",
        ),
        (
            (r"D:\Data\KalaReach\x", r"\\?\D:\Data\KalaReach\x"),
            (r"D:\Data", r"\\?\D:\Data"),
            r"D:\Data\KalaReach\x",
            "program",
        ),
        (
            (r"D:\Data", r"\\?\D:\Data"),
            (r"D:\Data\KalaReach", r"\\?\D:\Data\KalaReach"),
            r"D:\Data",
            "program",
        ),
        (
            (r"D:\Data", r"\\?\D:\Data"),
            (r"D:\Data\KalaReach\sub", r"\\?\D:\Data\KalaReach\sub"),
            r"D:\Data",
            "program",
        ),
    ];
    for ((files, files_final), (data, data_final), folder, tree) in refused {
        let text = shape_refusal(
            &known(files, files_final),
            &known(data, data_final),
            Stage::Before,
        )
        .unwrap_or_else(|| panic!("{files} and {data} are refused"));
        assert!(
            text.starts_with(&format!(
                "{folder} is a folder above the boundary's {tree} directory"
            )),
            "{files} {data}: {text}"
        );
        assert!(
            text.contains("root of a volume") || text.contains("overlaps"),
            "{files} {data}: {text}"
        );
        shape_words(&text);
    }
}

/// The good layout passes, whatever the on-disk letter case of the final path, and so does a sibling
/// that only shares a prefix with the other tree's own folder.
#[test]
fn the_good_layout_and_a_sibling_pass() {
    assert_eq!(
        shape_refusal(&known(PF, PF_FINAL), &known(PD, PD_FINAL), Stage::Before),
        None
    );
    assert_eq!(
        shape_refusal(
            &known(r"C:\PROGRAM FILES", PF_FINAL),
            &known(r"c:\programdata", PD_FINAL),
            Stage::Before
        ),
        None
    );
    assert_eq!(
        shape_refusal(
            &known(PF, PF_FINAL),
            &known(r"C:\Program Files (x86)", r"\\?\C:\Program Files (x86)"),
            Stage::Before
        ),
        None
    );
    assert_eq!(
        shape_refusal(
            &known(r"D:\Data\KalaReach2", r"\\?\D:\Data\KalaReach2"),
            &known(r"D:\Data", r"\\?\D:\Data"),
            Stage::Before
        ),
        None
    );
}

/// A refusal of the shape says what the run changed: for the removal that undoes a failed
/// installation, nothing of its own, with what that installation made still there.
#[test]
fn the_shape_refusal_says_what_the_run_changed() {
    let (files, data) = (known(r"D:\", r"\\?\D:\"), known(PD, PD_FINAL));
    let before = shape_refusal(&files, &data, Stage::Before).expect("refused");
    assert!(before.contains("Nothing was changed."), "{before}");
    let rollback = shape_refusal(&files, &data, Stage::Rollback).expect("refused");
    assert!(!rollback.contains("Nothing was changed."), "{rollback}");
    assert!(
        rollback.contains("whatever that installation had already made is still there"),
        "{rollback}"
    );
    // A known folder that leads elsewhere, and one that could not be opened, say the same.
    for files in [
        known(r"C:\PF", r"\\?\C:\ProgramData\KalaReach"),
        unopened(PF, "Windows error 3"),
    ] {
        let text = shape_refusal(&files, &known(PD, PD_FINAL), Stage::Rollback).expect("refused");
        assert!(!text.contains("Nothing was changed."), "{text}");
        assert!(
            text.contains("whatever that installation had already made is still there"),
            "{text}"
        );
    }
}

/// The setup program's line for a known folder that cannot be read says the error and that nothing
/// was changed, and at a removal the limit that it has. It names no removal by hand.
#[test]
fn the_line_for_a_known_folder_that_cannot_be_read_says_the_limit_of_a_removal() {
    let error = "reading the system's Program Files folder: Windows error 3";
    let setup = known_folder_unreadable(error, false);
    assert!(setup.contains(error), "{setup}");
    assert!(setup.contains("Nothing was changed."), "{setup}");
    assert!(!setup.contains("manifest"), "{setup}");
    assert!(setup.ends_with(CLOSING), "{setup}");
    let removal = known_folder_unreadable(error, true);
    for part in [
        error,
        "Nothing was changed.",
        "reads what to remove from the manifest in the data directory",
        "checks the program directory before it deletes anything",
        "cannot go on while that folder cannot be read",
        "The broker's service, its two accounts and its rules in the policy stay.",
        "If the volume is gone for good, the setup program cannot remove them.",
    ] {
        assert!(removal.contains(part), "{part}: {removal}");
    }
    assert!(removal.ends_with(CLOSING), "{removal}");
    // No removal by hand: the policy's rules are shared with other programs.
    for by_hand in [
        "by hand",
        "remove the rules",
        "remove the service",
        "Remove ",
    ] {
        assert!(!removal.contains(by_hand), "{by_hand}: {removal}");
    }
}

/// What an own folder's words claim of contents that nothing read: nothing. The folder that holds
/// the data directory, where no data directory is, may be removed or renamed if nothing else needs
/// what is in it.
#[test]
fn the_words_for_a_parent_with_no_data_directory_claim_nothing_of_its_contents() {
    let text = parent_advice(&ParentCure::Correct(Presence::Absent));
    assert!(
        text.contains("It holds no data directory of the boundary."),
        "{text}"
    );
    assert!(
        text.contains("If nothing else needs what is in it, remove or rename the folder"),
        "{text}"
    );
    for claim in ["loses nothing", "holds other things"] {
        assert!(!text.contains(claim), "{claim}: {text}");
    }
}
