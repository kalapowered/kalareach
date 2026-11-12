//! The words of the refusal of a folder above the installation's two trees: which folder, which
//! tree, what its list gives to whom and what to do, and the comparison that refuses a drive letter
//! that is no volume's root. They run on every platform.

use kr_boundary_windows::remedy::{
    AncestorFault, Tree, ancestor_refusal, identity_text, is_the_volumes_own_root, rights_finding,
    rights_in_words,
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
        "take away from every other identity the right to delete the folder, to delete or rename an entry in it, to change its list and to take its ownership",
        "delete the folder",
        "delete or rename an entry in it",
        "change its list",
        "take its ownership",
        "generic write",
        "generic all",
        "maximum allowed",
        "make the system, the Administrators group or the installer service its owner",
        "the right to add an entry is what the system gives by default",
    ] {
        assert!(text.contains(named), "{named}: {text}");
    }
    assert!(text.contains("Do not remove or move it"), "{text}");
    assert!(!text.contains("program directory"), "{text}");
}

#[test]
fn the_refusal_of_a_folder_above_the_program_directory_names_that_tree() {
    let text = ancestor_refusal(r"C:\", Tree::Program, &AncestorFault::List("a reason"));
    assert!(
        text.contains("a folder above the boundary's program directory"),
        "{text}"
    );
    assert!(!text.contains("data directory"), "{text}");
}

/// A link or a mounted folder above the trees is the administrator's own: a moved `ProgramData`, a
/// mounted volume. The words say that the installation does not go through one, that nothing was
/// changed and that the default places have none, and never tell to remove the link, which would
/// remove the folder that the link replaced for every program.
#[test]
fn the_refusal_of_a_link_or_a_mounted_folder_never_tells_an_administrator_to_remove_it() {
    for tree in [Tree::Data, Tree::Program] {
        let text = ancestor_refusal(r"C:\ProgramData", tree, &AncestorFault::Link);
        assert!(text.contains(r"C:\ProgramData"), "{text}");
        assert!(text.contains("it is a link or a mounted folder"), "{text}");
        assert!(
            text.contains("does not go through a link or a mounted folder above its trees"),
            "{text}"
        );
        assert!(text.contains("Nothing was changed"), "{text}");
        assert!(
            text.contains("The system's default places have none"),
            "{text}"
        );
        assert!(text.contains("install on the real path"), "{text}");
        let lower = text.to_lowercase();
        assert!(!lower.contains("remove the link"), "{text}");
        assert!(!lower.contains("rmdir"), "{text}");
        assert!(text.contains("Do not remove or move it"), "{text}");
    }
}

#[test]
fn the_refusal_of_what_is_not_a_folder_or_cannot_be_read_says_what_to_do() {
    let text = ancestor_refusal(r"C:\x", Tree::Data, &AncestorFault::NotAFolder);
    assert!(text.contains("it is not a folder"), "{text}");
    assert!(text.contains("Nothing was changed"), "{text}");
    let text = ancestor_refusal(
        r"C:\x",
        Tree::Program,
        &AncestorFault::Unreadable("Windows error 5"),
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

#[test]
fn a_drive_letter_that_is_no_volumes_root_is_refused_with_the_letter_and_the_real_path() {
    for tree in [Tree::Data, Tree::Program] {
        let text = ancestor_refusal(r"X:\", tree, &AncestorFault::Alias(r"C:\Shared\Backing"));
        assert!(
            text.contains(r"X:\ is a drive letter that is not the root of its volume"),
            "{text}"
        );
        assert!(text.contains(r"it leads to C:\Shared\Backing"), "{text}");
        assert!(text.contains("Nothing was changed"), "{text}");
        assert!(
            text.contains(r"Install on the real path, which is C:\Shared\Backing"),
            "{text}"
        );
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
