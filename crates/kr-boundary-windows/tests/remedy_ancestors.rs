//! The words of the refusal of a folder above the installation's two trees: which folder, which
//! tree, what its list gives to whom and what to do, and the comparison that refuses a drive letter
//! that is no volume's root. They run on every platform.

use kr_boundary_windows::remedy::{
    AncestorFault, MissingRoot, Purpose, Stage, Subject, Tree, ancestor_refusal, dos_path_of,
    identity_text, is_below, is_on_a_network_share, is_the_place_asked_for,
    is_the_volumes_own_root, missing_root, program_removal_advice, program_unreached,
    rights_finding, rights_in_words, supported_layout,
};

const DELETE_CHILD: u32 = 0x0000_0040;
const DELETE: u32 = 0x0001_0000;
const WRITE_DAC: u32 = 0x0004_0000;
const WRITE_OWNER: u32 = 0x0008_0000;
const GENERIC_ALL: u32 = 0x1000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const MAXIMUM_ALLOWED: u32 = 0x0200_0000;

/// The sentence that ends the words of every folder that the installation does not make.
const CLOSING: &str = "The setup program directs no change to a folder that other programs share.";

/// Every fault that a folder which the installation does not make can have. The match lists each
/// variant, so a new fault does not compile here until it is added to the cases below.
fn every_fault() -> Vec<AncestorFault<'static>> {
    let faults = vec![
        AncestorFault::Link,
        AncestorFault::NotAFolder,
        AncestorFault::Alias(r"C:\Shared\Backing"),
        AncestorFault::Volume("the volume uses FAT32"),
        AncestorFault::Unreadable("Windows error 32"),
        AncestorFault::VolumeUnanswered("Windows error 21"),
        AncestorFault::RootMissing("Windows error 3"),
        AncestorFault::List("S-1-5-32-545 is allowed the right to delete it"),
        AncestorFault::Writable("S-1-5-32-545 is allowed to add"),
    ];
    for fault in &faults {
        match fault {
            AncestorFault::Link
            | AncestorFault::NotAFolder
            | AncestorFault::Alias(_)
            | AncestorFault::Volume(_)
            | AncestorFault::Unreadable(_)
            | AncestorFault::VolumeUnanswered(_)
            | AncestorFault::RootMissing(_)
            | AncestorFault::List(_)
            | AncestorFault::Writable(_) => {}
        }
    }
    faults
}

/// Every point of a run at which a folder can be read again.
fn every_stage() -> Vec<Stage> {
    vec![
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
    ]
}

/// The words that tell an administrator to change a folder: a move, another place, the end of a
/// substitution or a redirection, an owner, a list, the removal of a link or of what is in the way.
/// Not one of them may be in the words of a folder that other programs share.
const INSTRUCTIONS: [&str; 15] = [
    "Move ",
    " move ",
    "Remove ",
    "remove or",
    "remove the link",
    "rmdir",
    "end the substitution",
    "redirection of",
    "give the",
    "Make the",
    "make the",
    "narrow",
    "Correct",
    "re-point",
    "other place",
];

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
                    ancestor_refusal(r"C:\Shared", tree, &Subject::Shared(fault.clone()), stage);
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
                    AncestorFault::Unreadable(_) => {
                        assert!(!text.contains(&layout), "{what}");
                        assert!(
                            text.contains("Close the program that holds it open"),
                            "{what}"
                        );
                    }
                    AncestorFault::VolumeUnanswered(_) | AncestorFault::RootMissing(_) => {
                        assert!(!text.contains(&layout), "{what}");
                        assert!(
                            text.contains("Check that the volume is there and answers"),
                            "{what}"
                        );
                        assert!(!text.contains("Close the program"), "{what}");
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
                for word in INSTRUCTIONS {
                    assert!(!text.contains(word), "{word:?} in {what}");
                }
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
        for word in INSTRUCTIONS {
            assert!(!text.contains(word), "{word:?} in {text}");
        }
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
        r"D:\ProgramData",
        Tree::Data,
        &Subject::Shared(AncestorFault::List(&finding)),
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
        r"C:\",
        Tree::Program,
        &Subject::Shared(AncestorFault::List("a reason")),
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
            r"C:\ProgramData",
            tree,
            &Subject::Shared(AncestorFault::Link),
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
        let subject = Subject::Shared(fault.clone());
        let before = ancestor_refusal(r"C:\x", Tree::Program, &subject, Stage::Before);
        assert!(
            before.contains("Nothing was changed"),
            "{fault:?}: {before}"
        );
        let after = ancestor_refusal(r"C:\x", Tree::Program, &subject, Stage::After);
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
        let made = ancestor_refusal(r"C:\x", Tree::Data, &subject, Stage::DataParentMade);
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
        let subject = Subject::Shared(fault.clone());
        let stopped = ancestor_refusal(
            r"C:\x",
            Tree::Program,
            &subject,
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
            r"C:\x",
            Tree::Program,
            &subject,
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
                ancestor_refusal(r"C:\x", Tree::Data, &Subject::Shared(fault.clone()), stage);
            assert!(!text.contains("empty"), "{fault:?} {stage:?}: {text}");
        }
        let made = ancestor_refusal(
            r"C:\x",
            Tree::Data,
            &Subject::Shared(fault.clone()),
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
            r"C:\x",
            Tree::Program,
            &Subject::Shared(fault.clone()),
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
        r"C:\x",
        Tree::Data,
        &Subject::Shared(AncestorFault::NotAFolder),
        Stage::Before,
    );
    assert!(text.contains("it is not a folder"), "{text}");
    assert!(text.contains("Nothing was changed"), "{text}");
    assert!(text.contains("This layout is not supported"), "{text}");
    assert!(!text.contains("Correct the path"), "{text}");
    let text = ancestor_refusal(
        r"C:\x",
        Tree::Program,
        &Subject::Shared(AncestorFault::Unreadable("Windows error 5")),
        Stage::Before,
    );
    assert!(text.contains(r"C:\x"), "{text}");
    assert!(
        text.contains("could not be opened or read to be checked (Windows error 5)"),
        "{text}"
    );
    assert!(text.contains("program directory"), "{text}");
    assert!(
        text.contains("Close the program that holds it open, or check that its volume is there and answers, then run the setup program again"),
        "{text}"
    );
    assert!(!text.contains("correct who may open it"), "{text}");
    assert!(!text.contains("This layout is not supported"), "{text}");
}

/// A volume that does not answer, or a root that is not there, is refused for its volume and not for
/// a program that holds a folder open: no program holds a volume that is going away, and closing one
/// cures nothing. The words say what was found, with the platform's error, and what to try that
/// changes no folder. They tell no one to move or change a folder that other programs share.
#[test]
fn a_volume_that_does_not_answer_is_refused_for_its_volume_and_not_for_an_open_program() {
    for (tree, own) in [
        (Tree::Program, "program directory"),
        (Tree::Data, "data directory"),
    ] {
        let text = ancestor_refusal(
            r"Z:\",
            tree,
            &Subject::Shared(AncestorFault::VolumeUnanswered("Windows error 21")),
            Stage::Before,
        );
        assert!(
            text.contains(&format!(r"Z:\ is a folder above the boundary's {own}")),
            "{text}"
        );
        assert!(
            text.contains("its volume did not answer (Windows error 21)"),
            "{text}"
        );
        assert!(text.contains("Nothing was changed"), "{text}");
        assert!(
            text.contains(
                "Check that the volume is there and answers, then run the setup program again"
            ),
            "{text}"
        );
        assert!(!text.contains("Close the program"), "{text}");
        assert!(!text.contains("holds it open"), "{text}");
        assert!(!text.contains("asks a volume"), "{text}");
        let after = ancestor_refusal(
            r"Z:\",
            tree,
            &Subject::Shared(AncestorFault::VolumeUnanswered("Windows error 21")),
            Stage::AfterRepair {
                broker_stopped: true,
            },
        );
        assert!(!after.contains("Nothing was changed"), "{after}");
    }
    let program = ancestor_refusal(
        r"Z:\",
        Tree::Program,
        &Subject::Shared(AncestorFault::VolumeUnanswered("Windows error 21")),
        Stage::Before,
    );
    assert!(
        program.contains("Do not remove the program directory"),
        "{program}"
    );
}

/// The root of a volume that is not there did not answer a question: the installation never asked
/// the volume what it is, and its words do not say so. An open of the root that fails for any other
/// reason is the volume's refusal too, and a folder above the root that fails to open is not.
#[test]
fn a_root_that_is_not_there_is_not_said_to_have_been_asked_what_it_is() {
    for tree in [Tree::Program, Tree::Data] {
        let text = ancestor_refusal(
            r"Z:\",
            tree,
            &Subject::Shared(AncestorFault::RootMissing("Windows error 3")),
            Stage::Before,
        );
        assert!(
            text.contains("the root of its volume is not there (Windows error 3)"),
            "{text}"
        );
        assert!(!text.contains("asks"), "{text}");
        assert!(!text.contains("asked"), "{text}");
        assert!(!text.contains("did not answer"), "{text}");
    }
    assert_eq!(
        AncestorFault::open_failed(true, "Windows error 21"),
        AncestorFault::VolumeUnanswered("Windows error 21")
    );
    assert_eq!(
        AncestorFault::open_failed(false, "Windows error 32"),
        AncestorFault::Unreadable("Windows error 32")
    );
    let root = ancestor_refusal(
        r"E:\",
        Tree::Program,
        &Subject::Shared(AncestorFault::open_failed(true, "Windows error 21")),
        Stage::Before,
    );
    assert!(root.contains("its volume did not answer"), "{root}");
    assert!(!root.contains("holds it open"), "{root}");
    assert!(!root.contains("asks"), "{root}");
}

#[test]
fn a_drive_letter_that_is_no_volumes_root_is_refused_with_the_letter_and_the_real_path() {
    for tree in [Tree::Data, Tree::Program] {
        let text = ancestor_refusal(
            r"X:\",
            tree,
            &Subject::Shared(AncestorFault::Alias(r"C:\Shared\Backing")),
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
            r"Y:\",
            tree,
            &Subject::Shared(AncestorFault::Volume(reason)),
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
        r"Y:\",
        Tree::Program,
        &Subject::Shared(AncestorFault::Volume("a reason")),
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
        r"Y:\",
        Tree::Data,
        &Subject::Shared(AncestorFault::Volume("a reason")),
        Stage::Before,
    );
    assert!(data.contains("ProgramData folder"), "{data}");
    assert!(!data.contains("program directory"), "{data}");
    // After the run's changes the words do not claim that nothing was changed.
    let after = ancestor_refusal(
        r"Y:\",
        Tree::Program,
        &Subject::Shared(AncestorFault::Volume("a reason")),
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
/// remove a link. A folder that the installation makes may be told what to correct.
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
            known,
            Tree::Program,
            &Subject::at(known, known, fault.clone()),
            Stage::Before,
        );
        let shared = ancestor_refusal(
            known,
            Tree::Program,
            &Subject::Shared(fault.clone()),
            Stage::Before,
        );
        assert_eq!(at_known, shared, "{fault:?}");
        assert!(at_known.ends_with(CLOSING), "{fault:?}: {at_known}");
        assert!(
            !at_known.contains("makes this folder itself"),
            "{fault:?}: {at_known}"
        );
        let below = ancestor_refusal(
            own,
            Tree::Program,
            &Subject::at(own, known, fault.clone()),
            Stage::Before,
        );
        let made = ancestor_refusal(
            own,
            Tree::Program,
            &Subject::Own(fault.clone()),
            Stage::Before,
        );
        assert_eq!(below, made, "{fault:?}");
        let own_words = match fault {
            AncestorFault::Link | AncestorFault::NotAFolder => "makes this folder itself",
            AncestorFault::Writable(_) => "Make the Administrators group",
            _ => "correct who may open it",
        };
        assert!(below.contains(own_words), "{fault:?}: {below}");
        assert!(!at_known.contains(own_words), "{fault:?}: {at_known}");
    }
    // The text of the writable known folder holds no instruction, and the text of the product's own
    // folder says what to correct.
    let text = ancestor_refusal(
        known,
        Tree::Program,
        &Subject::at(
            known,
            known,
            AncestorFault::Writable("S-1-5-32-545 is allowed to add"),
        ),
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
    assert!(!text.to_lowercase().contains("remove the link"), "{text}");
    for word in INSTRUCTIONS {
        assert!(!text.contains(word), "{word:?}: {text}");
    }
    let made = ancestor_refusal(
        own,
        Tree::Program,
        &Subject::at(
            own,
            known,
            AncestorFault::Writable("S-1-5-32-545 is allowed to add"),
        ),
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
    assert!(matches!(
        Subject::at(known, known, AncestorFault::Link),
        Subject::Shared(AncestorFault::Link)
    ));
    assert!(matches!(
        Subject::at(r"C:\Program Files\KalaReach", known, AncestorFault::Link),
        Subject::Own(AncestorFault::Link)
    ));
    assert!(matches!(
        Subject::at(r"C:\", known, AncestorFault::Link),
        Subject::Shared(AncestorFault::Link)
    ));
}

/// A link at the boundary's own folder above the program directory is not a known folder of another
/// computer: the words say that the layout is not supported and what the setup program does, and
/// never send the administrator to a computer whose known folders are plain, or to remove the link.
#[test]
fn a_link_at_the_boundarys_own_folder_sends_the_administrator_nowhere_else() {
    let text = ancestor_refusal(
        r"C:\Program Files\KalaReach",
        Tree::Program,
        &Subject::Own(AncestorFault::Link),
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

/// What a run does where the root of the program tree's volume is not there: an installation and a
/// repair refuse, since nothing can be made on a disk that is gone, and a removal goes on, since a
/// removal that refuses there can never finish. The data tree's root still refuses a removal.
#[test]
fn a_removal_goes_on_where_the_program_volumes_root_is_not_there_and_a_setup_does_not() {
    assert_eq!(
        missing_root(Purpose::Remove, Tree::Program),
        MissingRoot::GoOn
    );
    assert_eq!(
        missing_root(Purpose::Install, Tree::Program),
        MissingRoot::Refuse
    );
    assert_eq!(
        missing_root(Purpose::Remove, Tree::Data),
        MissingRoot::Refuse
    );
    assert_eq!(
        missing_root(Purpose::Install, Tree::Data),
        MissingRoot::Refuse
    );
}

/// The last words of a removal that went on past a root that is not there name the program
/// directory that it could not reach, and say what that leaves.
#[test]
fn the_removals_last_words_name_the_program_directory_that_it_could_not_reach() {
    let text = program_unreached(r"C:\Program Files\KalaReach\Boundary");
    assert!(
        text.contains(r"C:\Program Files\KalaReach\Boundary could not be reached"),
        "{text}"
    );
    assert!(
        text.contains("the root of its volume is not there"),
        "{text}"
    );
    assert!(
        text.contains("nothing in it was checked or removed"),
        "{text}"
    );
    assert!(!text.contains("Nothing was changed"), "{text}");
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
