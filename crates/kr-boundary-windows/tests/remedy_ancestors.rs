//! The words of the refusal of a folder above the installation's two trees: which folder, which
//! tree, what its list gives and what to correct. They run on every platform.

use kr_boundary_windows::remedy::{Tree, ancestor_refusal, rights_in_words};

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
fn the_refusal_of_a_folder_above_the_data_directory_names_the_folder_the_tree_and_the_list() {
    let text = ancestor_refusal(
        r"C:\ProgramData",
        Tree::Data,
        "S-1-5-32-545 may delete or rename an entry in it (rights 0x40)",
    );
    assert!(text.contains(r"C:\ProgramData"), "{text}");
    assert!(
        text.contains("a folder above the boundary's data directory"),
        "{text}"
    );
    assert!(
        text.contains("S-1-5-32-545 may delete or rename an entry in it (rights 0x40)"),
        "{text}"
    );
    assert!(text.contains("is refused because"), "{text}");
    assert!(!text.contains("program directory"), "{text}");
}

#[test]
fn the_refusal_of_a_folder_above_the_program_directory_names_that_tree() {
    let text = ancestor_refusal(r"C:\", Tree::Program, "it is a link");
    assert!(
        text.contains("a folder above the boundary's program directory"),
        "{text}"
    );
    assert!(!text.contains("data directory"), "{text}");
}

#[test]
fn the_refusal_says_that_nothing_was_changed_and_never_offers_to_remove_or_move_the_folder() {
    for tree in [Tree::Data, Tree::Program] {
        let text = ancestor_refusal(r"C:\ProgramData", tree, "a reason");
        assert!(text.contains("Nothing was changed"), "{text}");
        assert!(text.contains("Do not remove or move it"), "{text}");
        assert!(text.contains("delete or rename an entry in it"), "{text}");
        assert!(text.contains("change its list"), "{text}");
        assert!(text.contains("take its ownership"), "{text}");
        assert!(text.contains("the right to add an entry"), "{text}");
        assert!(!text.contains("Remove the folder"), "{text}");
        assert!(!text.contains("Move the folder aside"), "{text}");
        assert!(text.contains("run the setup program again"), "{text}");
    }
}
