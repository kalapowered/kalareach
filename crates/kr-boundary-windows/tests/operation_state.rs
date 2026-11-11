//! What state of the repository a command needs, and what the readers' answers say about it.

use kr_boundary_windows::frame::invocation::RefusedKind;
use kr_boundary_windows::operation::state::{
    RULE_AMBIGUOUS_NAME, RULE_HEAD_UNCHECKED, RULE_OPERATION_IN_PROGRESS, RULE_SYMBOLIC_REF,
    STATE_NAMES, check_implicit_head, check_no_tag, check_not_symbolic, check_operation_state,
};
use kr_boundary_windows::refusal::Refusal;
use kr_boundary_windows::repository::head::HeadKind;
use kr_boundary_windows::repository::readers::{
    Exists, Output, RULE_READER_DEADLINE, RULE_READER_EXIT, RULE_READER_FRAMING, Symbolic,
    parse_r1c,
};

const OID: &str = "0123456789abcdef0123456789abcdef01234567";

fn branch(name: &str) -> HeadKind {
    HeadKind::Branch {
        name: name.to_owned(),
    }
}

fn detached() -> HeadKind {
    HeadKind::Detached {
        oid: OID.to_owned(),
    }
}

#[test]
fn the_states_that_stop_a_writing_command_are_these_eight_entries() {
    assert_eq!(
        STATE_NAMES,
        [
            "MERGE_HEAD",
            "CHERRY_PICK_HEAD",
            "REVERT_HEAD",
            "REBASE_HEAD",
            "BISECT_LOG",
            "rebase-merge",
            "rebase-apply",
            "sequencer",
        ]
    );
}

#[test]
fn each_state_entry_refuses_by_name_among_the_others_the_folder_holds() {
    let others = [
        "HEAD",
        "config",
        "index",
        "objects",
        "refs",
        "hooks",
        "info",
        "description",
    ];
    for state in STATE_NAMES {
        let mut entries: Vec<&str> = others.to_vec();
        entries.insert(3, state);
        let refusal = check_operation_state(&entries).unwrap_err();
        assert_eq!(refusal.kind, RefusedKind::Repository);
        assert_eq!(refusal.rule, RULE_OPERATION_IN_PROGRESS);
        assert_eq!(refusal.detail(), format!("operation in progress {state}"));
        // Alone, first and last.
        assert!(check_operation_state(&[state]).is_err());
        assert!(check_operation_state(&[state, "HEAD"]).is_err());
        assert!(check_operation_state(&["HEAD", state]).is_err());
    }
}

#[test]
fn a_state_entry_is_found_in_any_case_and_named_as_the_table_names_it() {
    for state in STATE_NAMES {
        for spelled in [state.to_ascii_lowercase(), state.to_ascii_uppercase()] {
            let refusal = check_operation_state(&[spelled.as_str()]).unwrap_err();
            assert_eq!(refusal.rule, RULE_OPERATION_IN_PROGRESS, "{spelled}");
            assert_eq!(refusal.detail(), format!("operation in progress {state}"));
        }
    }
    // Strings and string slices both do.
    let owned = vec!["MERGE_HEAD".to_owned()];
    assert!(check_operation_state(&owned).is_err());
}

#[test]
fn entries_that_only_look_like_a_state_and_an_empty_folder_pass() {
    let empty: [&str; 0] = [];
    assert!(check_operation_state(&empty).is_ok());
    assert!(
        check_operation_state(&[
            "MERGE_HEAD.orig",
            "MERGE_MSG",
            "MERGE_MODE",
            "ORIG_HEAD",
            "FETCH_HEAD",
            "CHERRY_PICK",
            "REVERT",
            "REBASE",
            "BISECT_START",
            "BISECT_LOG2",
            "rebase-merge-old",
            "rebase",
            "rebase-apply.bak",
            "sequencer-old",
            "xsequencer",
            "",
            " MERGE_HEAD",
            "MERGE_HEAD ",
        ])
        .is_ok()
    );
}

#[test]
fn when_two_states_are_present_the_first_of_the_table_is_named() {
    let refusal = check_operation_state(&["sequencer", "BISECT_LOG", "MERGE_HEAD"]).unwrap_err();
    assert_eq!(refusal.detail(), "operation in progress MERGE_HEAD");
}

#[test]
fn the_implicit_head_needs_the_reference_it_names_not_to_be_symbolic() {
    // A branch, and its reference is not symbolic or does not exist yet: allowed.
    assert!(check_implicit_head(&branch("main"), Some(Symbolic::No)).is_ok());
    assert!(check_implicit_head(&branch("feature/x"), Some(Symbolic::No)).is_ok());
    // A symbolic target is refused and names the reference.
    let refusal = check_implicit_head(&branch("main"), Some(Symbolic::Yes)).unwrap_err();
    assert_eq!(refusal.kind, RefusedKind::Operation);
    assert_eq!(refusal.rule, RULE_SYMBOLIC_REF);
    assert_eq!(refusal.detail(), "symbolic ref refs/heads/main");
    // A branch whose reference was not asked about is not passed.
    let refusal = check_implicit_head(&branch("main"), None).unwrap_err();
    assert_eq!(refusal.kind, RefusedKind::Repository);
    assert_eq!(refusal.rule, RULE_HEAD_UNCHECKED);
    // A detached HEAD writes no reference, and the answer, if any, is of no matter.
    for answer in [None, Some(Symbolic::No), Some(Symbolic::Yes)] {
        assert!(
            check_implicit_head(&detached(), answer).is_ok(),
            "{answer:?}"
        );
    }
}

#[test]
fn a_symbolic_reference_is_refused_by_name() {
    assert!(check_not_symbolic("refs/heads/a", Symbolic::No).is_ok());
    let refusal = check_not_symbolic("refs/heads/a", Symbolic::Yes).unwrap_err();
    assert_eq!(refusal.kind, RefusedKind::Operation);
    assert_eq!(refusal.rule, RULE_SYMBOLIC_REF);
    assert_eq!(refusal.detail(), "symbolic ref refs/heads/a");
}

fn lookup(exit: Option<u32>, stdout: &[u8]) -> Result<Exists, Refusal> {
    parse_r1c(&Output { exit, stdout })
}

#[test]
fn a_tag_of_the_same_name_makes_a_branch_name_ambiguous() {
    // Exit 0 is a tag that exists, whatever it names: Git answers the same for a tag of a commit,
    // of a blob and of a tree.
    let refusal = check_no_tag("main", &lookup(Some(0), b"")).unwrap_err();
    assert_eq!(refusal.kind, RefusedKind::Operation);
    assert_eq!(refusal.rule, RULE_AMBIGUOUS_NAME);
    assert_eq!(refusal.detail(), "ambiguous name main");
}

#[test]
fn no_tag_of_that_name_is_exit_2_with_nothing_printed() {
    assert!(check_no_tag("main", &lookup(Some(2), b"")).is_ok());
}

#[test]
fn a_lookup_that_did_not_find_nothing_is_never_taken_for_no_tag() {
    // A crash code, a fatal error, a failed lookup and an undocumented code are refusals of the
    // reader's own name, and so is partial output beside the one code that proves absence.
    for code in [1, 3, 128, 255, 3_221_225_781] {
        let result = lookup(Some(code), b"");
        let refusal = check_no_tag("main", &result).unwrap_err();
        assert_eq!(refusal.rule, RULE_READER_EXIT, "{code}");
        assert_eq!(refusal, result.unwrap_err());
    }
    for stdout in [&b"\n"[..], b"x", b"refs/tags/main\n"] {
        let result = lookup(Some(2), stdout);
        let refusal = check_no_tag("main", &result).unwrap_err();
        assert_eq!(refusal.rule, RULE_READER_FRAMING, "{stdout:?}");
        assert_eq!(refusal, result.unwrap_err());
    }
    let deadline = lookup(None, b"");
    let refusal = check_no_tag("main", &deadline).unwrap_err();
    assert_eq!(refusal.rule, RULE_READER_DEADLINE);
    assert_eq!(refusal, deadline.unwrap_err());
}
