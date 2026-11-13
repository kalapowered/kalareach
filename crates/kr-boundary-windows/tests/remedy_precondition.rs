//! The words of the refusals that name a fact about the machine and the read behind it: what a read
//! that failed says, the policy that is not empty, a configuration file that is not empty, and the
//! removal's line on a start type that it puts nothing back for. They run on every platform; the
//! reads themselves are the guest's.

use std::io::{Error, ErrorKind};

use kr_boundary_windows::records::next_step;
use kr_boundary_windows::remedy::{
    CONFIG_NOT_EMPTY_WHY, Finding, appid_start_type_left, application_control_set,
    empty_config_advice, git_permissions_refusal, git_program_not_reached,
    payload_file_not_reached,
};

/// A read that failed for any reason but "not found" says that the read failed, with its error, and
/// never that the file is not there; a "not found" says that it is not there, and never that a read
/// failed.
#[test]
fn a_read_that_failed_says_so_and_absence_is_said_only_for_not_found() {
    let absent = Error::new(ErrorKind::NotFound, "The system cannot find the file");
    for error in [
        Error::new(
            ErrorKind::PermissionDenied,
            "Access is denied. (os error 5)",
        ),
        Error::other("The process cannot access the file (os error 32)"),
        Error::new(ErrorKind::InvalidData, "the data is invalid"),
    ] {
        let git = git_program_not_reached(r"C:\Program Files\Git\git.exe", &error);
        assert_eq!(
            git,
            format!(r"Git's program C:\Program Files\Git\git.exe could not be read: {error}")
        );
        let payload = payload_file_not_reached(r"C:\payload\broker.exe", &error);
        assert_eq!(
            payload,
            format!(r"C:\payload\broker.exe could not be read: {error}")
        );
        for text in [&git, &payload] {
            assert!(!text.contains("is not where"), "{text}");
            assert!(!text.contains("is not in the payload"), "{text}");
        }
    }
    assert_eq!(
        git_program_not_reached(r"C:\Program Files\Git\git.exe", &absent),
        r"Git's program C:\Program Files\Git\git.exe is not where the policy expects it"
    );
    assert_eq!(
        payload_file_not_reached(r"C:\payload\broker.exe", &absent),
        r"C:\payload\broker.exe is not in the payload directory"
    );
}

/// The refusal for a policy that is not empty says what the read showed: the collections that it
/// enforces and the collections that hold rules, apart; a policy that holds rules and enforces
/// nothing is not said to enforce. It says what the run had changed, and never that nothing was.
#[test]
fn a_policy_that_is_not_empty_is_refused_for_what_the_read_showed_and_what_was_changed() {
    let rules_only = application_control_set(&[], &["Exe", "Dll"]);
    assert!(
        rules_only.contains("it holds rules in Exe, Dll"),
        "{rules_only}"
    );
    assert!(!rules_only.contains("enforces"), "{rules_only}");
    let enforced_only = application_control_set(&["Exe"], &[]);
    assert!(
        enforced_only.contains("it enforces Exe."),
        "{enforced_only}"
    );
    assert!(!enforced_only.contains("holds rules"), "{enforced_only}");
    let both = application_control_set(&["Exe"], &["Dll"]);
    assert!(
        both.contains("it enforces Exe and it holds rules in Dll."),
        "{both}"
    );
    for text in [&rules_only, &enforced_only, &both] {
        assert!(
            text.starts_with("The effective application control policy is not empty: "),
            "{text}"
        );
        assert!(
            text.contains("This run had already made or protected the data directory"),
            "{text}"
        );
        assert!(text.ends_with("and the manifest records them."), "{text}");
        assert!(!text.contains("changes nothing"), "{text}");
        assert!(
            !text.contains("already enforces application control"),
            "{text}"
        );
    }
}

/// A configuration file that is not empty is said to be not empty, never to hold settings: its
/// size is the only thing that was read. The advice says that it may hold settings.
#[test]
fn a_configuration_file_that_is_not_empty_is_not_said_to_hold_settings() {
    assert!(
        CONFIG_NOT_EMPTY_WHY.starts_with("it is not empty"),
        "{CONFIG_NOT_EMPTY_WHY}"
    );
    assert!(
        !CONFIG_NOT_EMPTY_WHY.contains("settings"),
        "{CONFIG_NOT_EMPTY_WHY}"
    );
    let repair = empty_config_advice(r"C:\Program Files\KalaReach\git\config", true);
    let first = empty_config_advice(r"C:\Program Files\KalaReach\git\config", false);
    for text in [&repair, &first] {
        assert!(
            text.starts_with(r"Remove C:\Program Files\KalaReach\git\config, and nothing else"),
            "{text}"
        );
        assert!(
            text.contains("a configuration that is not empty may hold settings"),
            "{text}"
        );
        assert!(!text.contains("holds settings would"), "{text}");
        assert!(
            text.ends_with("Then run the setup program again."),
            "{text}"
        );
    }
    assert!(
        repair.contains("A repair makes it again, empty."),
        "{repair}"
    );
    assert!(!first.contains("A repair makes it again"), "{first}");
}

/// The line for a start type that is not put back says what the three values show: nobody changed a
/// value that is equal to the others, and a value that differs is said to differ, with both numbers.
#[test]
fn the_start_type_line_says_what_the_three_values_show() {
    let same = appid_start_type_left(2, Some("start=2"), 2);
    assert!(
        same.contains("start type is 2, the same as the installation recorded"),
        "{same}"
    );
    assert!(same.ends_with("there is nothing to put back"), "{same}");
    let differs = appid_start_type_left(3, Some("start=2"), 4);
    assert!(
        differs.contains("start type is 3, not the 2 that the installation recorded"),
        "{differs}"
    );
    assert!(differs.ends_with("so it is left alone"), "{differs}");
    let unrecorded = appid_start_type_left(3, None, 2);
    assert!(
        unrecorded.contains("recorded no start type for it"),
        "{unrecorded}"
    );
    let odd = appid_start_type_left(3, Some("start=x"), 2);
    assert!(
        odd.contains("not the x that the installation recorded"),
        "{odd}"
    );
    for text in [&same, &differs, &unrecorded, &odd] {
        assert!(!text.contains("someone else"), "{text}");
        assert!(!text.contains("was changed"), "{text}");
    }
}

/// What the removal says of the manifest rests on a lookup of its name: something is at the name,
/// and the words never say that the file there is a manifest.
#[test]
fn the_removals_next_step_says_what_the_lookup_found_at_the_manifests_name() {
    let stays = next_step(true, false);
    assert!(
        stays.starts_with("Something is at the manifest's name, and it stays with them."),
        "{stays}"
    );
    assert!(!stays.contains("The manifest stays"), "{stays}");
    for text in [next_step(false, true), next_step(false, false)] {
        assert!(!text.contains("manifest stays"), "{text}");
    }
}

/// The refusal for Git's permissions says that others can change or replace a file or a folder only
/// for a state that the check read and found to grant a right. A list that the check cannot evaluate
/// (an entry of a type that it does not interpret) is refused in words of its own, which say that
/// the setup program cannot tell, and never say that others can change or replace it.
#[test]
fn a_permission_list_that_the_check_cannot_evaluate_is_not_said_to_let_others_change_git() {
    let path = r"C:\Program Files\Git\cmd\git.exe";
    let granted = Finding::Granted("S-1-5-32-545 is allowed rights 0x2".to_owned());
    let unread = Finding::Unevaluated(
        "its permission list has an entry of type 9, which this check does not read".to_owned(),
    );
    for (replacement, said) in [(false, "changed"), (true, "replaced")] {
        let confirmed = git_permissions_refusal(path, &granted, replacement);
        assert_eq!(
            confirmed,
            format!("{path} can be {said} by others: S-1-5-32-545 is allowed rights 0x2")
        );
        let cannot = git_permissions_refusal(path, &unread, replacement);
        assert!(
            cannot.starts_with("The setup program cannot tell whether "),
            "{cannot}"
        );
        assert!(
            cannot.contains(&format!("can be {said} by others:")),
            "the question is named: {cannot}"
        );
        assert!(!cannot.starts_with(path), "{cannot}");
        assert!(cannot.contains("an entry of type 9"), "{cannot}");
    }
}
