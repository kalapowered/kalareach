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

#[test]
fn the_steps_act_on_an_account_the_service_and_the_identity_service_only_behind_a_result() {
    let source = install_source();
    let steps = code_of(body_of(&source, "fn undo_recorded("));
    // The accounts: the one step that deletes an account is behind the rule, and the rule's refusal
    // leaves the account before anything of it is read or changed.
    let gate = steps
        .find("let acts = if object.acted_on_by(rollback) {")
        .expect("the account step asks whether a result lets it act");
    let first_change = steps.find("account::revoke_all_rights(").unwrap();
    assert!(
        gate < first_change,
        "the rule stands before the first change"
    );
    assert!(steps[gate..first_change].contains("if !acts {"));
    assert!(steps[gate..first_change].contains("continue;"));
    // A rollback leaves an account that has no result of its own run; only the removal reads the
    // object for an intent with no result.
    assert!(steps[gate..first_change].contains("} else if rollback {"));
    assert!(steps[gate..first_change].contains("read_account_intent("));
    // The service: the maintenance step and the deletion both start from the same value.
    assert!(steps.contains("Some(object) if object.acted_on_by(rollback) => true,"));
    assert!(steps.contains("Some(object) if !rollback && object.outcome.is_none() => {"));
    // The policy and the Application Identity service's start type are put back by a rollback only
    // where its own write is on record.
    assert!(steps.contains(".any(|object| !rollback || object.acted_on_by(true));"));
    assert!(steps.contains("&& (!rollback || object.acted_on_by(true))"));
    assert_eq!(
        count(&steps, "if service_is_ours && let Some(service) ="),
        2
    );
    assert_eq!(count(&steps, "manager.open(SERVICE)"), 2);
    // The Application Identity service: the rollback's stop needs this run's own start on record.
    let stop = steps.find("Identity(&appid).stop()?").unwrap();
    let rule = steps
        .find("if rollback\n")
        .expect("the stop asks whether this is a rollback");
    assert!(rule < stop);
    assert!(steps[rule..stop].contains("ObjectKind::AppIdentityStarted"));
}

#[test]
fn the_installation_records_each_result_after_the_call_that_made_the_object() {
    let source = install_source();
    let lay = code_of(body_of(&source, "fn lay_down("));
    let at = |needle: &str| {
        lay.find(needle)
            .unwrap_or_else(|| panic!("lay_down has no {needle}"))
    };
    // An account: the intent, the platform's call that makes it alone, the result, then the read of
    // its identifier (a failed read of the identifier follows a made account).
    let intent = at("run.record(ObjectKind::Account, name, None)?;");
    let made = at("account::add(name)?;");
    let result = at("run.conclude(ObjectKind::Account, name, Outcome::Made)?;");
    let sid = at("account::sid_of(name)?");
    assert!(intent < made && made < result && result < sid);
    // The service: the intent, the call that makes it, the result.
    let intent = at("run.record(ObjectKind::Service, SERVICE, None)?;");
    let made = at("manager.create(");
    let result = at("run.conclude(ObjectKind::Service, SERVICE, Outcome::Made)?;");
    assert!(intent < made && made < result);
    // The policy's rules and the start type each get a result after the call that writes them.
    let write = at("channel.set(&wanted.render())?");
    let result =
        at("run.manifest\n            .conclude(ObjectKind::PolicyRule, id, Outcome::Made);");
    assert!(write < result);
    let set = at("Identity(&appid).set_automatic()?;");
    let result = at("run.conclude(ObjectKind::AppIdentity, APPID, Outcome::Made)?;");
    assert!(set < result);
    // The two points where a killed program leaves an intent with no result.
    let add = at("account::add(name)?;");
    let die = at("die_at(\"account\");");
    let made = at("run.conclude(ObjectKind::Account, name, Outcome::Made)?;");
    assert!(add < die && die < made);
    let create = at("manager.create(");
    let die = at("die_at(\"service\");");
    let made = at("run.conclude(ObjectKind::Service, SERVICE, Outcome::Made)?;");
    assert!(create < die && die < made);
    // The Application Identity service's start is recorded where the manager accepted the request.
    assert!(lay.contains(
        ".start(|| run.conclude(ObjectKind::AppIdentityStarted, APPID, Outcome::Made))?;"
    ));
}
