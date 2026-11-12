//! The remedy that a refusal of an entry gives comes from what the entry's own handle showed and from
//! the lookup of the manifest, never from the words of the reason. An entry that the handle shows to
//! be another account's is moved out, one that could not be read is neither corrected nor removed,
//! and only the system's class is ever corrected into place.

use kr_boundary_windows::remedy::{Origin, Presence, Remedy, choose};

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
