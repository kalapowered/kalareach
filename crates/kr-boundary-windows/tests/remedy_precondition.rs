//! The words of the refusals that name a fact about the machine and the read behind it: what a read
//! that failed says, the policy that is not empty, a configuration file that is not empty, and the
//! removal's line on a start type that it puts nothing back for. They run on every platform; the
//! reads themselves are the guest's.

use std::io::{Error, ErrorKind};

use kr_boundary_windows::records::next_step;
use kr_boundary_windows::remedy::{
    CONFIG_NOT_EMPTY_WHY, Finding, appid_start_type_left, application_control_set,
    code_integrity_refusal, empty_config_advice, foreign_rules_refusal, git_permissions_refusal,
    git_program_not_reached, payload_file_not_reached, platform_error, smart_app_control_refusal,
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

/// The repair's refusal for rules in the executable collection that the installation did not make
/// names each identifier and says that the rules are there. It says nothing of who added a rule or
/// when: the read shows an identifier, not an author or a time.
#[test]
fn the_refusal_for_a_rule_that_the_installation_did_not_make_names_no_author_and_no_time() {
    let one = foreign_rules_refusal(&["11111111-1111-1111-1111-111111111111"]);
    let many = foreign_rules_refusal(&[
        "11111111-1111-1111-1111-111111111111",
        "22222222-2222-2222-2222-222222222222",
    ]);
    assert!(
        one.contains("11111111-1111-1111-1111-111111111111"),
        "{one}"
    );
    assert!(one.contains("is in the executable collection"), "{one}");
    assert!(
        many.contains("11111111-1111-1111-1111-111111111111, 22222222-2222-2222-2222-222222222222"),
        "{many}"
    );
    assert!(many.contains("are in the executable collection"), "{many}");
    for text in [&one, &many] {
        for author_or_time in [
            "administrator",
            "added",
            "since",
            "after",
            "later",
            "someone",
        ] {
            assert!(!text.contains(author_or_time), "{author_or_time}: {text}");
        }
        assert!(text.contains("did not make"), "{text}");
    }
}

/// Smart App Control's state is said to be on or evaluating only for the values that mean that (1
/// and 2); a value that the setup program does not know is refused as unknown, with the value, and
/// is not called a state.
#[test]
fn a_smart_app_control_value_that_is_not_known_is_refused_as_unknown() {
    assert_eq!(smart_app_control_refusal(Some(0)), None);
    for known in [1, 2] {
        let said = smart_app_control_refusal(Some(known)).unwrap();
        assert!(said.contains("on or evaluating"), "{said}");
        assert!(said.contains(&format!("state {known}")), "{said}");
    }
    for unknown in [3, 0xFFFF_FFFF] {
        let said = smart_app_control_refusal(Some(unknown)).unwrap();
        assert!(said.contains(&unknown.to_string()), "{said}");
        assert!(
            said.contains("which the setup program does not know"),
            "{said}"
        );
        assert!(!said.contains("on or evaluating"), "{said}");
    }
    let absent = smart_app_control_refusal(None).unwrap();
    assert!(absent.contains("could not be found"), "{absent}");
}

/// An entry of the code-integrity listing with a field that is missing or of another type is
/// refused as one that the setup program does not understand, with the field and its value: no
/// `false` or `true` stands in for a field that is not there.
#[test]
fn a_code_integrity_entry_with_a_missing_or_invalid_field_is_refused_as_not_understood() {
    use serde_json::json;
    let said = |entries: serde_json::Value| code_integrity_refusal(entries.as_array().unwrap());

    let empty = said(json!([{}])).unwrap();
    assert!(empty.contains("does not understand"), "{empty}");
    assert!(empty.contains("its IsSystemPolicy is missing"), "{empty}");
    assert!(!empty.contains("beyond the system's"), "{empty}");

    let wrong = said(json!([{"IsSystemPolicy": "yes", "FriendlyName": "x"}])).unwrap();
    assert!(
        wrong.contains("its IsSystemPolicy is \"yes\", not true or false"),
        "{wrong}"
    );

    let unnamed = said(json!([{"IsSystemPolicy": true}])).unwrap();
    assert!(unnamed.contains("its FriendlyName is missing"), "{unnamed}");

    let no_field =
        said(json!([{"IsSystemPolicy": true, "FriendlyName": "VerifiedAndReputable"}])).unwrap();
    assert!(no_field.contains("its IsEnforced is missing"), "{no_field}");
    assert!(!no_field.contains("is enforcing"), "{no_field}");
    let wrong_type = said(
        json!([{"IsSystemPolicy": true, "FriendlyName": "VerifiedAndReputable", "IsEnforced": 1}]),
    )
    .unwrap();
    assert!(
        wrong_type.contains("its IsEnforced is 1, not true or false"),
        "{wrong_type}"
    );

    // What it does refuse as before, and what it passes.
    let beyond = said(json!([{"IsSystemPolicy": false, "FriendlyName": "Mine"}])).unwrap();
    assert!(
        beyond.ends_with("beyond the system's is present: Mine"),
        "{beyond}"
    );
    let enforcing = said(
        json!([{"IsSystemPolicy": true, "FriendlyName": "VerifiedAndReputable", "IsEnforced": true}]),
    );
    assert_eq!(enforcing.as_deref(), Some("Smart App Control is enforcing"));
    assert_eq!(
        said(json!([
            {"IsSystemPolicy": true, "FriendlyName": "VerifiedAndReputable", "IsEnforced": false},
            {"IsSystemPolicy": true, "FriendlyName": "DefaultWindows"}
        ])),
        None
    );
    assert_eq!(said(json!([])), None);
}

/// A platform error is said with the number that a call returned; a failure that no call returned
/// (code 0) is said without a number, and is never called a Windows error.
#[test]
fn a_failure_that_no_call_returned_has_no_windows_error_number() {
    assert_eq!(
        platform_error("opening the service", 5),
        "opening the service: Windows error 5"
    );
    let none = platform_error("the descriptor has no permission list", 0);
    assert_eq!(none, "the descriptor has no permission list");
    assert!(!none.contains("Windows error"), "{none}");
}
