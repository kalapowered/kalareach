//! The remedy that a refusal of an entry gives comes from what the entry's own handle showed and from
//! the lookup of the manifest, never from the words of the reason. An entry that the handle shows to
//! be another account's is moved out, one that could not be read is neither corrected nor removed,
//! and only the system's class is ever corrected into place.

use kr_boundary_windows::remedy::{Origin, ParentCure, Presence, Remedy, choose, parent_advice};

fn unreadable() -> Origin {
    Origin::Unknown("Windows error 5".to_owned())
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
    for manifest in lookups() {
        assert_eq!(
            choose(true, &Origin::Foreign, &manifest),
            Remedy::MoveAside,
            "{manifest:?}"
        );
    }
}

#[test]
fn a_record_that_could_not_be_read_is_neither_corrected_nor_removed_whatever_the_manifest_says() {
    for manifest in lookups() {
        assert_eq!(
            choose(true, &unreadable(), &manifest),
            Remedy::Unreadable,
            "{manifest:?}"
        );
    }
}

#[test]
fn a_record_of_the_systems_class_is_corrected_while_a_manifest_may_be_there_and_removed_without_one()
 {
    assert_eq!(
        choose(true, &Origin::System, &Presence::Present),
        Remedy::Correct
    );
    // A lookup that failed does not confirm that nothing is installed.
    assert_eq!(
        choose(
            true,
            &Origin::System,
            &Presence::Unknown("Windows error 5".to_owned())
        ),
        Remedy::Correct
    );
    assert_eq!(
        choose(true, &Origin::System, &Presence::Absent),
        Remedy::Remove
    );
}

#[test]
fn a_name_that_the_layout_does_not_give_is_removed_whatever_its_handle_showed() {
    for origin in [Origin::System, Origin::Foreign, unreadable()] {
        for manifest in lookups() {
            assert_eq!(
                choose(false, &origin, &manifest),
                Remedy::Remove,
                "{origin:?} {manifest:?}"
            );
        }
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
