//! The words of the refusal of a folder above the installation's two trees: which folder, which
//! tree, what its list gives to whom and what to do, and the comparison that refuses a drive letter
//! that is no volume's root. They run on every platform.

use kr_boundary_windows::remedy::{
    AncestorFault, Stage, Tree, ancestor_refusal, dos_path_of, identity_text,
    is_on_a_network_share, is_the_place_asked_for, is_the_volumes_own_root, program_removal_advice,
    rights_finding, rights_in_words, volume_layout,
};

const DELETE_CHILD: u32 = 0x0000_0040;
const DELETE: u32 = 0x0001_0000;
const WRITE_DAC: u32 = 0x0004_0000;
const WRITE_OWNER: u32 = 0x0008_0000;
const GENERIC_ALL: u32 = 0x1000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const MAXIMUM_ALLOWED: u32 = 0x0200_0000;

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

/// The sentence of the list's refusal is the one that the native check makes (`rights_finding`), and
/// what it tells the administrator to take away is every right that the check counts, so that
/// taking away what the text names gives no second refusal.
#[test]
fn the_refusal_of_a_list_names_the_real_sentence_and_every_right_that_the_check_counts() {
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
        &AncestorFault::List(&finding),
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
    for named in [
        "remove or narrow the entry that allows it, an inherited entry too (a denying entry does not cancel an allowing one for this check)",
        "no other identity has the right to delete the folder, to delete or rename an entry in it, to change its list or to take its ownership",
        "delete the folder",
        "delete or rename an entry in it",
        "change its list",
        "take its ownership",
        "generic write",
        "generic all",
        "maximum allowed",
        "make the system, the Administrators group or the installer service its owner",
        "the right to add an entry is what the system gives by default",
        "If it names an entry of a kind that the check does not read, replace that one entry with plain entries that the check reads, and keep every entry that denies something",
    ] {
        assert!(text.contains(named), "{named}: {text}");
    }
    // The advice never has the folder given a list of allowing entries only, which drops what the
    // list denies.
    assert!(!text.contains("plain allowing entries"), "{text}");
    assert!(text.contains("Do not remove or move it"), "{text}");
    assert!(!text.contains("program directory"), "{text}");
}

#[test]
fn the_refusal_of_a_folder_above_the_program_directory_names_that_tree() {
    let text = ancestor_refusal(
        r"C:\",
        Tree::Program,
        &AncestorFault::List("a reason"),
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
/// not supported, that nothing was changed and that the default places have none. They never tell to
/// remove the link, which would remove the folder that the link replaced for every program, and they
/// direct no change of a folder that others share and claim nothing about what the folder holds,
/// which they do not know.
#[test]
fn the_refusal_of_a_link_or_a_mounted_folder_never_tells_an_administrator_to_remove_it() {
    for tree in [Tree::Data, Tree::Program] {
        let text = ancestor_refusal(r"C:\ProgramData", tree, &AncestorFault::Link, Stage::Before);
        assert!(text.contains(r"C:\ProgramData"), "{text}");
        assert!(text.contains("it is a link or a mounted folder"), "{text}");
        assert!(
            text.contains("does not go through a link or a mounted folder at or above its trees"),
            "{text}"
        );
        assert!(text.contains("Nothing was changed"), "{text}");
        assert!(
            text.contains("The system's default places have none"),
            "{text}"
        );
        // What the setup program can do in that state: it installs only in the system's known
        // folders and cannot be pointed at another path.
        assert!(
            text.contains("installs only in the system's own known folders"),
            "{text}"
        );
        assert!(!text.contains("install on the real path"), "{text}");
        let lower = text.to_lowercase();
        assert!(!lower.contains("remove the link"), "{text}");
        assert!(!lower.contains("rmdir"), "{text}");
        assert!(text.contains("This layout is not supported"), "{text}");
        assert!(
            text.contains("directs no change to a folder that other programs share"),
            "{text}"
        );
        assert!(!text.contains("give the known folder"), "{text}");
        assert!(!lower.contains("holds other things"), "{text}");
        assert!(!lower.contains("do not remove or move it"), "{text}");
    }
}

/// A folder that is read again after the run has made its first changes is refused without the claim
/// that nothing was changed, whatever the reason; read before any change it makes the claim.
#[test]
fn a_refusal_after_the_runs_changes_does_not_say_that_nothing_was_changed() {
    for fault in [
        AncestorFault::Link,
        AncestorFault::NotAFolder,
        AncestorFault::Alias(r"C:\Shared\Backing"),
        AncestorFault::Volume("the volume uses FAT32"),
        AncestorFault::Unreadable("Windows error 32"),
        AncestorFault::List("a reason"),
        AncestorFault::Writable("a reason"),
    ] {
        let before = ancestor_refusal(r"C:\x", Tree::Program, &fault, Stage::Before);
        assert!(
            before.contains("Nothing was changed"),
            "{fault:?}: {before}"
        );
        let after = ancestor_refusal(r"C:\x", Tree::Program, &fault, Stage::After);
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
        // A repair has no rollback: the broker that it stopped stays stopped.
        let repair = ancestor_refusal(r"C:\x", Tree::Program, &fault, Stage::AfterRepair);
        assert!(
            !repair.contains("Nothing was changed"),
            "{fault:?}: {repair}"
        );
        assert!(
            repair.contains("has no rollback: the broker stays stopped"),
            "{fault:?}: {repair}"
        );
        // The folder that holds the data directory, made by this run before anything is recorded:
        // it is empty and stays, and no manifest records it.
        let made = ancestor_refusal(r"C:\x", Tree::Data, &fault, Stage::DataParentMade);
        assert!(!made.contains("Nothing was changed"), "{fault:?}: {made}");
        assert!(
            made.contains("had already made the folder that holds the data directory"),
            "{fault:?}: {made}"
        );
        assert!(made.contains("it is empty and stays"), "{fault:?}: {made}");
        assert!(!made.contains("the manifest records"), "{fault:?}: {made}");
    }
}

#[test]
fn the_refusal_of_what_is_not_a_folder_or_cannot_be_read_says_what_to_do() {
    let text = ancestor_refusal(
        r"C:\x",
        Tree::Data,
        &AncestorFault::NotAFolder,
        Stage::Before,
    );
    assert!(text.contains("it is not a folder"), "{text}");
    assert!(text.contains("Nothing was changed"), "{text}");
    let text = ancestor_refusal(
        r"C:\x",
        Tree::Program,
        &AncestorFault::Unreadable("Windows error 5"),
        Stage::Before,
    );
    assert!(text.contains(r"C:\x"), "{text}");
    assert!(
        text.contains("could not be opened or read to be checked (Windows error 5)"),
        "{text}"
    );
    assert!(text.contains("program directory"), "{text}");
    assert!(
        text.contains("Close the program that holds it open"),
        "{text}"
    );
}

/// A volume that does not answer, or a root that is not there, is refused for its volume and not for
/// a program that holds a folder open: no program holds a volume that is going away, and closing one
/// cures nothing. The words say that the volume did not answer, with the platform's error, and tell
/// no one to move or change a folder that other programs share.
#[test]
fn a_volume_that_does_not_answer_is_refused_for_its_volume_and_not_for_an_open_program() {
    for (tree, own) in [
        (Tree::Program, "program directory"),
        (Tree::Data, "data directory"),
    ] {
        let text = ancestor_refusal(
            r"Z:\",
            tree,
            &AncestorFault::VolumeUnanswered("Windows error 3"),
            Stage::Before,
        );
        assert!(
            text.contains(&format!(r"Z:\ is a folder above the boundary's {own}")),
            "{text}"
        );
        assert!(
            text.contains("its volume did not answer (Windows error 3)"),
            "{text}"
        );
        assert!(text.contains("Nothing was changed"), "{text}");
        assert!(text.contains("run the setup program again"), "{text}");
        assert!(!text.contains("Close the program"), "{text}");
        assert!(!text.contains("holds it open"), "{text}");
        assert!(!text.contains("Move "), "{text}");
        assert!(!text.contains("Make the Administrators group"), "{text}");
        assert!(!text.to_lowercase().contains("remove the link"), "{text}");
        let after = ancestor_refusal(
            r"Z:\",
            tree,
            &AncestorFault::VolumeUnanswered("Windows error 3"),
            Stage::AfterRepair,
        );
        assert!(!after.contains("Nothing was changed"), "{after}");
    }
    let program = ancestor_refusal(
        r"Z:\",
        Tree::Program,
        &AncestorFault::VolumeUnanswered("Windows error 3"),
        Stage::Before,
    );
    assert!(
        program.contains("Do not remove the program directory"),
        "{program}"
    );
}

#[test]
fn a_drive_letter_that_is_no_volumes_root_is_refused_with_the_letter_and_the_real_path() {
    for tree in [Tree::Data, Tree::Program] {
        let text = ancestor_refusal(
            r"X:\",
            tree,
            &AncestorFault::Alias(r"C:\Shared\Backing"),
            Stage::Before,
        );
        assert!(
            text.contains(r"X:\ is a drive letter that is not the root of its volume"),
            "{text}"
        );
        assert!(text.contains(r"it leads to C:\Shared\Backing"), "{text}");
        assert!(text.contains("Nothing was changed"), "{text}");
        assert!(
            text.contains("end the substitution or redirection of that letter"),
            "{text}"
        );
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
/// installation keeps each tree on a fixed, local NTFS volume, nothing in the folder cures it, and
/// the words never tell to correct an owner or a list, to close a program or to remove a link.
#[test]
fn a_folder_on_a_volume_that_is_not_used_is_refused_for_its_volume() {
    let reason = "the volume uses FAT32, and only NTFS volumes are supported";
    for (tree, own) in [
        (Tree::Program, "program directory"),
        (Tree::Data, "data directory"),
    ] {
        let text = ancestor_refusal(r"Y:\", tree, &AncestorFault::Volume(reason), Stage::Before);
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
        // The layout is not supported, and no folder that other programs share is to be moved,
        // re-pointed or changed.
        assert!(text.contains("This layout is not supported"), "{text}");
        assert!(
            text.contains("directs no change to a folder that other programs share"),
            "{text}"
        );
        assert!(!text.contains("Move "), "{text}");
        assert!(!text.to_lowercase().contains("re-point"), "{text}");
    }
    let program = ancestor_refusal(
        r"Y:\",
        Tree::Program,
        &AncestorFault::Volume("a reason"),
        Stage::Before,
    );
    assert!(
        program.contains("Do not remove the program directory"),
        "{program}"
    );
    assert!(program.contains("Program Files folder"), "{program}");
    // The anchor's own refusal of a volume ends with the same sentence.
    let anchor = volume_layout("Program Files");
    assert!(program.ends_with(&anchor), "{program}");
    assert!(anchor.contains("This layout is not supported"), "{anchor}");
    assert!(!anchor.contains("Move "), "{anchor}");
    let data = ancestor_refusal(
        r"Y:\",
        Tree::Data,
        &AncestorFault::Volume("a reason"),
        Stage::Before,
    );
    assert!(data.contains("ProgramData folder"), "{data}");
    assert!(!data.contains("program directory"), "{data}");
    // After the run's changes the words do not claim that nothing was changed.
    let after = ancestor_refusal(
        r"Y:\",
        Tree::Program,
        &AncestorFault::Volume("a reason"),
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

/// The walk from the program directory's top down reads a folder that must also refuse the right to
/// add to it, and its words say that, and never to remove a link (a moved `Program Files` is the
/// administrator's own, and the link at its top gets the words of any link above the trees).
#[test]
fn the_program_trees_own_walk_has_its_own_list_words_and_the_same_link_words() {
    let text = ancestor_refusal(
        r"C:\Program Files",
        Tree::Program,
        &AncestorFault::Writable("S-1-5-32-545 is allowed to add"),
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
    // A fresh installation has no manifest, so the words never say that the manifest records it.
    assert!(!text.contains("the manifest records it"), "{text}");
    assert!(text.contains("Nothing was changed"), "{text}");
    assert!(!text.to_lowercase().contains("remove the link"), "{text}");
    let link = ancestor_refusal(
        r"C:\Program Files",
        Tree::Program,
        &AncestorFault::Link,
        Stage::Before,
    );
    assert!(link.contains("it is a link or a mounted folder"), "{link}");
    assert!(!link.to_lowercase().contains("remove the link"), "{link}");
}

/// A link at the boundary's own folder above the program directory is not a known folder of another
/// computer: the words say that the layout is not supported and what the setup program does, and
/// never send the administrator to a computer whose known folders are plain, or to remove the link.
#[test]
fn a_link_at_the_boundarys_own_folder_sends_the_administrator_nowhere_else() {
    let text = ancestor_refusal(
        r"C:\Program Files\KalaReach",
        Tree::Program,
        &AncestorFault::OwnLink,
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
