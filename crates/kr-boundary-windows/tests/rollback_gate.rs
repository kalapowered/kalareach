//! The gate between the ordinary removal and the rollback of an installation that failed, read from
//! the source (the code is Windows-only, so these cases run on every platform):
//!
//! - only the failure branch of a new installation reaches the rollback, and a repair returns its
//!   failure with no rollback;
//! - the ordinary removal still inspects the data directory and begins from what that found before
//!   it undoes anything, and never reaches the rollback;
//! - the rollback reads no manifest, makes no inspection of the data directory and loads no
//!   earlier-state record from the disk: it acts on what the run laid and recorded;
//! - the two callers of the shared steps pass the data tree that is theirs.

use std::fs;

fn install_source() -> String {
    fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/win/install.rs")).unwrap()
}

/// The text of the function that starts with `signature`, to the closing brace at the start of a
/// line.
fn body_of<'a>(source: &'a str, signature: &str) -> &'a str {
    let start = source
        .find(signature)
        .unwrap_or_else(|| panic!("no function starts with {signature}"));
    let end = source[start..]
        .find("\n}\n")
        .unwrap_or_else(|| panic!("{signature} has no end"));
    &source[start..start + end]
}

/// The lines of code of `text`: no comment and no doc line.
fn code_of(text: &str) -> String {
    text.lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn count(text: &str, needle: &str) -> usize {
    text.matches(needle).count()
}

#[test]
fn only_the_failure_branch_of_a_new_installation_reaches_the_rollback() {
    let source = install_source();
    let code = code_of(&source);
    // The definition and the one call.
    assert_eq!(
        count(&code, "roll_back("),
        2,
        "roll_back( stands in more or fewer places"
    );
    let install = code_of(body_of(&source, "pub fn install("));
    assert_eq!(count(&install, "roll_back("), 1);
    // A repair returns its failure before the rollback is reached, and says that it has no rollback.
    let repair = install
        .find("if existing {\n")
        .expect("the failure branch tells a repair from an installation");
    let returned = install[repair..]
        .find("return Err(failure);")
        .map(|at| repair + at)
        .expect("a repair returns its failure");
    let rolled = install.find("roll_back(").unwrap();
    assert!(
        repair < returned && returned < rolled,
        "a repair must return before the rollback"
    );
    assert!(
        install[repair..returned].contains("a repair has no rollback"),
        "a repair says that it has no rollback"
    );
}

#[test]
fn the_ordinary_removal_inspects_and_begins_before_it_undoes_and_never_reaches_the_rollback() {
    let source = install_source();
    for name in ["pub fn remove(", "fn remove_at("] {
        let body = code_of(body_of(&source, name));
        assert!(!body.contains("roll_back("), "{name} reaches the rollback");
    }
    let removal = code_of(body_of(&source, "fn remove_at("));
    let at = |needle: &str| {
        removal
            .find(needle)
            .unwrap_or_else(|| panic!("remove_at holds no {needle}"))
    };
    assert!(at("check_shape(") < at("inspect_existing_data("));
    assert!(at("inspect_existing_data(") < at("records::begin("));
    assert!(at("records::begin(") < at("undo_recorded("));
    assert!(removal.contains("DataTree::ByName"));
    assert!(!removal.contains("DataTree::Laid"));
}

#[test]
fn the_rollback_reads_no_manifest_and_makes_no_inspection_of_the_data_directory() {
    let source = install_source();
    let rollback = code_of(body_of(&source, "fn roll_back("));
    for forbidden in [
        "inspect_existing_data(",
        "inspect_data_directory(",
        "check_data_parent",
        "records::begin(",
        "Prior::load(",
        "Manifest::load",
        "refuse_while_unfinished(",
        "remove_at(",
    ] {
        assert!(
            !rollback.contains(forbidden),
            "the rollback holds {forbidden}"
        );
    }
    assert!(rollback.contains("DataTree::Laid("));
    // The run's own manifest, in memory, is the record.
    assert!(rollback.contains("run.manifest.clone()"));
    // The earlier-state record of the rollback is the run's own value, never a load from the disk.
    let steps = code_of(body_of(&source, "fn undo_recorded("));
    let loaded = steps
        .find("Prior::load(")
        .expect("the ordinary removal loads the record");
    let own = steps
        .find("run.prior.clone()")
        .expect("the rollback has the record in memory");
    let tree = steps
        .find("DataTree::ByName => match")
        .expect("the load stands in the ordinary arm");
    assert!(
        own < tree && tree < loaded,
        "Prior::load is reachable only through DataTree::ByName"
    );
}

#[test]
fn the_shared_steps_have_two_callers_and_each_passes_its_own_data_tree() {
    let source = install_source();
    let code = code_of(&source);
    assert_eq!(
        count(&code, "undo_recorded("),
        3,
        "the definition and two callers"
    );
    let removal = code_of(body_of(&source, "fn remove_at("));
    let rollback = code_of(body_of(&source, "fn roll_back("));
    assert_eq!(count(&removal, "undo_recorded("), 1);
    assert_eq!(count(&rollback, "undo_recorded("), 1);
    // A rollback takes away what the run laid through its identities, and the ordinary removal
    // takes away the records it inspected by name; neither does the other's.
    let steps = code_of(body_of(&source, "fn undo_recorded("));
    assert!(steps.contains("DataTree::Laid(run) =>"));
    assert!(steps.contains("run.take_away()"));
    assert!(steps.contains("remove_approved_records(paths, &approved)"));
}
