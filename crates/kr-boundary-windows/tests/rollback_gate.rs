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

/// The source of the installation's product code: the unit cases at the end of the file are left
/// out, since they call the steps they test.
fn install_source() -> String {
    let source =
        fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/win/install.rs")).unwrap();
    let end = source
        .find("\n#[cfg(test)]\nmod tests {")
        .expect("the file ends with its unit cases");
    source[..end].to_owned()
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
    assert!(steps.contains("let broker_is_there = match service_is_ours"));
    assert!(steps.contains("if service_is_ours\n                && let Some(manager) = &manager"));
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

#[test]
fn a_failed_early_read_ends_the_removal_and_is_kept_by_a_rollback() {
    let source = install_source();
    let steps = code_of(body_of(&source, "fn undo_recorded("));
    // The service manager's open: a rollback keeps the failure and the removal returns it, as it
    // always did, before it changes anything but its own staging directory.
    let opened = steps
        .find("let manager = match opened {")
        .expect("the service manager's open is matched");
    let kept = steps[opened..]
        .find("Err(error) if rollback => {")
        .expect("a rollback keeps the failure");
    let returned = steps[opened..]
        .find("Err(error) => return Err(error),")
        .expect("the removal returns it");
    assert!(kept < returned);
    assert!(steps[opened..opened + returned].contains("failures.push("));
    // The broker's first open and status read: the same two arms.
    let broker = steps
        .find("let broker_is_there = match")
        .expect("the broker's first open and status read are matched");
    let kept = steps[broker..]
        .find("Err(error) if rollback => {")
        .expect("a rollback keeps the failure");
    let returned = steps[broker..]
        .find("Err(error) => return Err(error),")
        .expect("the removal returns it");
    assert!(kept < returned);
    assert!(steps[broker..broker + returned].contains("keep("));
    // No read of the service manager stands outside those two matches or a step under `keep`.
    assert_eq!(count(&steps, "service::manager()"), 1);
    assert_eq!(count(&steps, "manager.open(SERVICE)?"), 2);
    assert_eq!(count(&steps, "manager.open(APPID)?"), 2);
}

#[test]
fn a_rollback_that_ends_with_a_failed_step_leaves_a_record_before_it_ends() {
    let source = install_source();
    let steps = code_of(body_of(&source, "fn undo_recorded("));
    // The failure ending of a rollback reads the manifest's name and writes the record again where
    // the read does not find it, before it builds its words; the removal's ending is its own.
    let ending = steps
        .find("DataTree::Laid(run) => {\n                let record = run.keep_record();")
        .expect("the rollback's failure ending keeps the record first");
    let words = steps[ending..]
        .find("remedy::rollback_failed(")
        .expect("and then says what became of it");
    assert!(words > 0);
    let keep = code_of(body_of(&source, "fn keep_record("));
    assert!(keep.contains("self.manifest_on_disk()"));
    assert!(keep.contains("self.save()"));
    // The program directory's check in a rollback is told whether the manifest is on disk by a
    // read, and not that it is.
    let roll = code_of(body_of(&source, "fn roll_back("));
    assert!(roll.contains("matches!(run.manifest_on_disk(), Ok(()))"));
    assert!(!roll.contains("check_program_directory(&paths, true,"));
}

#[test]
fn the_folder_above_the_program_directory_is_made_and_removed_only_as_the_run_that_made_it_records()
{
    let source = install_source();
    // The installation: the intent (with the identity that an earlier run recorded), the folder's
    // own creating call, the folder held in the run's value before any record is written, then the
    // identity and the result `made`; a folder that stood there gets the result `found`.
    let folder = code_of(body_of(&source, "fn make_program_folder("));
    let at = |needle: &str| {
        folder
            .find(needle)
            .unwrap_or_else(|| panic!("make_program_folder has no {needle}"))
    };
    let intent = at("run.record(ObjectKind::ProgramFolder, &id, earlier.as_deref())?;");
    let made = at("create_folder_above(folder, SdKind::AdminDir, readable)?");
    let held = at("ffi::locked(&run.laid).program_folder = Some(made);");
    let identity = at("run.record(ObjectKind::ProgramFolder, &id, Some(identity?.as_str()))?;");
    let result = at("run.conclude(ObjectKind::ProgramFolder, &id, Outcome::Made)");
    assert!(intent < made && made < held && held < identity && identity < result);
    assert!(folder.contains("run.conclude(ObjectKind::ProgramFolder, &id, Outcome::Found)"));
    // lay_down makes the folder after the check of the program directory's parents and before the
    // program directory.
    let lay = code_of(body_of(&source, "fn lay_down("));
    let check = lay.find("check_program_parents(&paths, after)?;").unwrap();
    let folder_at = lay
        .find("make_program_folder(run, &paths, &readable)?;")
        .unwrap();
    let program = lay
        .find("fresh::directory_all(&paths.program, SdKind::AdminDir, &readable)")
        .unwrap();
    assert!(check < folder_at && folder_at < program);
    // No step removes the folder above the program directory by its path: the rollback takes the
    // one that its run holds, and the ordinary removal the one that its manifest records.
    let steps = code_of(body_of(&source, "fn undo_recorded("));
    assert!(
        !steps.contains("fs::remove_dir(parent)"),
        "a step removes a folder by its path"
    );
    assert!(steps.contains(
        "if matches!(tree, DataTree::ByName) {\n        remove_program_folder(paths, &manifest, &mut failures);"
    ));
    let take = code_of(body_of(&source, "fn take_away(&mut self) -> Rolled"));
    assert!(take.contains("take(object(program_folder), folder, false);"));
    let removal = code_of(body_of(&source, "fn remove_program_folder("));
    assert!(removal.contains("remedy::FolderRecord::of(object.outcome, object.detail.is_some())"));
    assert!(
        removal.contains("remedy::folder_act(record, read.as_ref()) != remedy::FolderAct::Remove")
    );
}
