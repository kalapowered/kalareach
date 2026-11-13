//! Guest cases for the ordinary removal of a run that died after it made an account or the service,
//! for the rollback of a run that set no start type, and for the record that a rollback with a failed
//! step leaves. They run only in a disposable Windows guest, as SYSTEM, like the cases of
//! `windows_install.rs`.

#![cfg(all(windows, feature = "testing"))]

use std::io::Write as _;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::{Mutex, PoisonError};

use kr_boundary_windows::manifest::{Manifest, ObjectKind};
use kr_boundary_windows::policy::Policy;
use kr_boundary_windows::win::applocker::Channel;
use kr_boundary_windows::win::install::{CHECKOUT, CONNECT, Paths, SERVICE};
use kr_boundary_windows::win::pipe::Kind as Pipe;
use kr_boundary_windows::win::{account, registry, service, token};

const SPECIAL_ACCOUNTS: &str =
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList";

/// The start type "automatic" of a service, as the service manager answers it.
const AUTOMATIC: u32 = 2;

/// The cases change machine-wide state: one runs at a time.
static SERIAL: Mutex<()> = Mutex::new(());

/// What a case compares before and after: everything the installation may change.
#[derive(Debug, PartialEq, Eq)]
struct Snapshot {
    policy: Policy,
    appid_start: u32,
    appid_running: bool,
    accounts: [bool; 2],
    service: bool,
    program_dir: bool,
    data_dir: bool,
    data_parent: bool,
    pipes_gone: bool,
    hidden: Vec<String>,
}

fn snapshot() -> Snapshot {
    let paths = Paths::system().expect("the system's folders are read");
    let manager = service::manager().unwrap();
    let appid = manager
        .open("AppIDSvc")
        .unwrap()
        .expect("the Application Identity service exists");
    let (_, policy) = Channel::new(&std::env::temp_dir()).effective().unwrap();
    let mut hidden = registry::open(SPECIAL_ACCOUNTS)
        .unwrap()
        .map(|key| key.value_names().unwrap())
        .unwrap_or_default();
    hidden.sort();
    Snapshot {
        policy,
        appid_start: appid.configuration().unwrap().0,
        appid_running: appid.status().unwrap().running(),
        accounts: [
            account::find(CHECKOUT).unwrap().is_some(),
            account::find(CONNECT).unwrap().is_some(),
        ],
        // A service that is deleted but still listed because a handle to it is open is gone.
        service: manager
            .open(SERVICE)
            .unwrap()
            .is_some_and(|service| !service.marked_for_deletion().unwrap()),
        program_dir: paths.program.exists(),
        data_dir: paths.data.exists(),
        data_parent: paths.data_parent().exists(),
        pipes_gone: [Pipe::Persons, Pipe::Administrators]
            .iter()
            .all(|kind| std::fs::metadata(kind.name()).is_err()),
        hidden,
    }
}

/// Fails unless the machine holds nothing of an installation.
fn assert_clean(before: &Snapshot) {
    assert!(
        !before.service
            && before.accounts == [false, false]
            && !before.data_dir
            && !before.data_parent
            && !before.program_dir
            && before.pipes_gone,
        "the machine is not clean: {before:?}"
    );
}

/// Prints a line that a person reads in the run's output.
fn observed(line: &str) {
    println!("OBSERVED {line}");
}

fn bin_directory() -> PathBuf {
    PathBuf::from(
        std::env::var_os("KR_BOUNDARY_BIN")
            .expect("KR_BOUNDARY_BIN names the directory with the setup program and its payloads"),
    )
}

/// Runs the setup program with the payload of the guest's runner and "yes" on its input, to its end,
/// with the given variables. Returns its exit code and its output.
fn run_setup(arguments: &[&str], environment: &[(&str, &str)]) -> (Option<i32>, String) {
    let bin = bin_directory();
    let mut command = Command::new(bin.join("kr-boundary-setup.exe"));
    if let Some(("install", rest)) = arguments.split_first().map(|(first, rest)| (*first, rest)) {
        command
            .arg("install")
            .arg("--payload")
            .arg(bin.join("payload"))
            .args(rest);
    } else {
        command.args(arguments);
    }
    for (name, value) in environment {
        command.env(name, value);
    }
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().expect("the setup program starts");
    child.stdin.take().unwrap().write_all(b"yes\n").unwrap();
    let output = child.wait_with_output().unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    (output.status.code(), text)
}

/// A person's account made for a case, deleted when the case ends.
struct Person {
    name: String,
    sid: String,
}

impl Person {
    fn make() -> Person {
        let id = &uuid::Uuid::new_v4().simple().to_string()[..6];
        let name = format!("krperson{id}");
        let sid = account::create(&name)
            .expect("the person's account is made")
            .to_text()
            .unwrap();
        Person { name, sid }
    }
}

impl Drop for Person {
    fn drop(&mut self) {
        let _ = account::delete(&self.name);
    }
}

fn require_elevated() {
    assert!(
        token::current_is_administrator().unwrap(),
        "the case must run elevated"
    );
}

/// A new installation of the setup program for `person` with the given test variables.
fn install_with(person: &Person, environment: &[(&str, &str)]) -> (Option<i32>, String) {
    let (code, text) = run_setup(&["install", "--person", &person.sid], environment);
    println!("--- kr-boundary-setup install {environment:?} -> {code:?}\n{text}");
    (code, text)
}

/// The administrator's ordinary removal, with none of the test variables.
fn ordinary_removal() -> (Option<i32>, String) {
    let (code, text) = run_setup(&["remove"], &[]);
    println!("--- kr-boundary-setup remove -> {code:?}\n{text}");
    (code, text)
}

/// A setup program that was aborted at `point`, right after the call that made the first account (or
/// the service) returned and before its result was recorded: the exit code is not success, and no
/// rollback ran.
fn a_run_that_died_at(person: &Person, point: &str) -> String {
    let (code, text) = install_with(person, &[("KR_BOUNDARY_DIE_AT", point)]);
    assert_ne!(code, Some(0), "the run died at {point}: {text}");
    assert!(
        !text.contains("undoing what was done"),
        "a run that died ran no rollback: {text}"
    );
    text
}

/// The manifest of the run that died holds the object as an intent with no result.
fn the_record_holds_an_intent_with_no_result(kind: ObjectKind, name: &str) {
    let paths = Paths::system().unwrap();
    let manifest = Manifest::load(&paths.manifest).expect("the run's manifest is on disk");
    let object = manifest
        .find(kind, name)
        .unwrap_or_else(|| panic!("the manifest holds no {kind:?} {name}: {manifest:?}"));
    assert_eq!(
        object.outcome, None,
        "the manifest holds a result for {name}: {object:?}"
    );
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see windows_install.rs)"]
fn a_run_that_died_after_it_made_the_account_is_removed_by_a_read_of_the_account() {
    let _one_at_a_time = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    require_elevated();
    let before = snapshot();
    assert_clean(&before);
    let person = Person::make();
    let died = a_run_that_died_at(&person, "account");
    assert!(
        account::find(CHECKOUT).unwrap().is_some(),
        "the account that the run made stands after its death: {died}"
    );
    the_record_holds_an_intent_with_no_result(ObjectKind::Account, CHECKOUT);

    let (code, text) = ordinary_removal();
    observed(&format!("the removal after DIE_AT=account -> {code:?}"));
    for line in text.lines().filter(|line| line.contains(CHECKOUT)) {
        observed(&format!("removal line: {line}"));
    }
    let account_stands = account::find(CHECKOUT).unwrap().is_some();
    assert_eq!(code, Some(0), "the removal succeeds: {text}");
    assert!(
        text.contains(&format!(
            "{CHECKOUT}: the manifest records the step that was to make it and no result of that step, and a read found it with the installation's mark"
        )),
        "the removal does not say that it decided by a read that found the mark: {text}"
    );
    assert!(
        text.contains("without a failure") && text.contains("its records are deleted"),
        "the removal did not end without a failure with its records deleted: {text}"
    );
    assert!(
        !account_stands,
        "the account that the run made stands after the removal: {text}"
    );
    assert_eq!(
        snapshot(),
        before,
        "after the removal the computer is as it was: {text}"
    );
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see windows_install.rs)"]
fn a_run_that_died_after_it_made_the_service_is_removed_by_a_read_of_the_service() {
    let _one_at_a_time = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    require_elevated();
    let before = snapshot();
    assert_clean(&before);
    let person = Person::make();
    let died = a_run_that_died_at(&person, "service");
    assert!(
        service::manager()
            .unwrap()
            .open(SERVICE)
            .unwrap()
            .is_some_and(|service| !service.marked_for_deletion().unwrap()),
        "the service that the run made stands after its death: {died}"
    );
    the_record_holds_an_intent_with_no_result(ObjectKind::Service, SERVICE);

    let (code, text) = ordinary_removal();
    observed(&format!("the removal after DIE_AT=service -> {code:?}"));
    for line in text.lines().filter(|line| line.contains(SERVICE)) {
        observed(&format!("removal line: {line}"));
    }
    assert_eq!(code, Some(0), "the removal succeeds: {text}");
    assert!(
        text.contains(&format!(
            "{SERVICE}: the manifest records the step that was to make it and no result of that step, and a read found it with the installation's mark"
        )),
        "the removal does not say that it decided by a read that found the mark: {text}"
    );
    assert!(
        text.contains("without a failure") && text.contains("its records are deleted"),
        "the removal did not end without a failure with its records deleted: {text}"
    );
    assert_eq!(
        snapshot(),
        before,
        "after the removal the computer is as it was: {text}"
    );
}

/// An account of the given name made by hand: no comment, so without the installation's mark.
fn make_an_account_by_hand(name: &str) {
    // At most 14 characters: a longer password makes `net user` ask a question that nobody answers.
    let password = format!("Zq9!{}", &uuid::Uuid::new_v4().simple().to_string()[..10]);
    let made = Command::new("net.exe")
        .args(["user", name, &password, "/add"])
        .output()
        .unwrap();
    assert!(
        made.status.success(),
        "net user /add failed: {}{}",
        String::from_utf8_lossy(&made.stdout),
        String::from_utf8_lossy(&made.stderr)
    );
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see windows_install.rs)"]
fn an_intent_for_an_account_that_stands_without_the_installations_mark_leaves_it_in_the_removal() {
    let _one_at_a_time = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    require_elevated();
    let before = snapshot();
    assert_clean(&before);
    let person = Person::make();
    let _ = a_run_that_died_at(&person, "account");
    the_record_holds_an_intent_with_no_result(ObjectKind::Account, CHECKOUT);
    // The account that the run made goes, and an account of that name made by hand takes its place.
    account::delete(CHECKOUT).expect("the run's account is deleted by the case");
    make_an_account_by_hand(CHECKOUT);
    let by_hand = account::carrying_the_installation_comment().unwrap();
    assert!(
        !by_hand
            .iter()
            .any(|name| name.eq_ignore_ascii_case(CHECKOUT)),
        "the account made by hand carries the installation's comment: {by_hand:?}"
    );

    let (code, text) = ordinary_removal();
    let stands = account::find(CHECKOUT).unwrap().is_some();
    // The case's own cleanup: the account that the case made by hand.
    let _ = account::delete(CHECKOUT);
    observed(&format!("the removal with an unmarked account -> {code:?}"));
    for line in text.lines().filter(|line| line.contains(CHECKOUT)) {
        observed(&format!("removal line: {line}"));
    }
    assert_eq!(code, Some(0), "the removal ends without a failure: {text}");
    assert!(
        text.contains(&format!(
            "{CHECKOUT}: the manifest records the step that was to make it and no result of that step, and a read found it without the installation's mark"
        )),
        "the removal does not say that the account stood without the mark: {text}"
    );
    assert!(
        text.contains(
            "stands there and the manifest holds no result that the installation made it"
        ) && text.contains("its records are deleted"),
        "the removal's check does not say that the account stands there and was not made by the installation: {text}"
    );
    assert!(
        stands,
        "the removal took away an account that does not carry the installation's mark: {text}"
    );
    assert_eq!(
        snapshot(),
        before,
        "after the case's own cleanup the computer is as it was: {text}"
    );
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see windows_install.rs)"]
fn an_intent_for_an_account_that_is_not_there_leaves_nothing_to_remove_in_the_removal() {
    let _one_at_a_time = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    require_elevated();
    let before = snapshot();
    assert_clean(&before);
    let person = Person::make();
    let _ = a_run_that_died_at(&person, "account");
    the_record_holds_an_intent_with_no_result(ObjectKind::Account, CHECKOUT);
    account::delete(CHECKOUT).expect("the run's account is deleted by the case");

    let (code, text) = ordinary_removal();
    observed(&format!("the removal with no account -> {code:?}"));
    for line in text.lines().filter(|line| line.contains(CHECKOUT)) {
        observed(&format!("removal line: {line}"));
    }
    assert_eq!(code, Some(0), "the removal ends without a failure: {text}");
    assert!(
        text.contains(&format!(
            "{CHECKOUT}: the manifest records the step that was to make it and no result of that step, and a read found none of that name there, so there is nothing to remove"
        )),
        "the removal does not say that nothing of that name is there: {text}"
    );
    assert_eq!(
        snapshot(),
        before,
        "after the removal the computer is as it was: {text}"
    );
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see windows_install.rs)"]
fn a_rollback_of_a_run_that_set_no_start_type_says_that_it_left_the_start_type_as_it_is() {
    let _one_at_a_time = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    require_elevated();
    let before = snapshot();
    assert_clean(&before);
    assert!(
        before.appid_running && before.appid_start == AUTOMATIC,
        "the case needs the Application Identity service running and automatic before the run (c11-appid-running.ps1): {before:?}"
    );
    let person = Person::make();
    let (code, text) = install_with(&person, &[("KR_BOUNDARY_FAIL_AFTER", "appid")]);
    for line in text.lines().filter(|line| line.contains("start type")) {
        observed(&format!("rollback line: {line}"));
    }
    assert_ne!(code, Some(0), "{text}");
    assert!(
        text.contains("the removal after the failure finished") && !text.contains("also failed"),
        "the rollback did not end without a failure: {text}"
    );
    assert!(
        text.contains(
            "the Application Identity service's start type: this run's record holds no result that this run changed it, so the rollback left it as it is"
        ),
        "the rollback does not say that it left the start type as it is: {text}"
    );
    assert_eq!(
        snapshot(),
        before,
        "after the rollback the computer is as it was: {text}"
    );
}

/// A new installation that fails after the broker step, whose rollback also fails at its account
/// step, with the manifest damaged as `how` says (none: left as it is). The ending is printed in
/// full; then the administrator's removal, with none of the test variables, runs to its end.
fn a_rollback_with_a_failed_step(how: Option<&str>) -> String {
    let _one_at_a_time = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    require_elevated();
    let before = snapshot();
    assert_clean(&before);
    let person = Person::make();
    let mut environment = vec![
        ("KR_BOUNDARY_FAIL_AFTER", "broker"),
        ("KR_BOUNDARY_FAIL_UNDO", "account"),
    ];
    if let Some(how) = how {
        environment.push(("KR_BOUNDARY_DAMAGE_MANIFEST", how));
    }
    let label = how.unwrap_or("intact");
    let (code, text) = install_with(&person, &environment);
    let ending = text
        .find("undoing what was done")
        .map_or("(no rollback)", |at| &text[at..]);
    observed(&format!(
        "manifest {label}: the ending from \"undoing what was done\" to its end follows\n{ending}\nOBSERVED manifest {label}: the ending ends"
    ));
    assert_ne!(code, Some(0), "{label}: {text}");
    assert!(
        !text.contains("could not be damaged"),
        "{label}: the seam did not damage the manifest: {text}"
    );
    assert!(
        text.contains("the removal after the failure also failed")
            && text.contains("a failure was injected into the account step of the undoing"),
        "{label}: the rollback did not fail at its account step: {text}"
    );
    assert!(
        text.contains("the administrator's removal takes the rest"),
        "{label}: the ending does not say that the administrator's removal takes the rest: {text}"
    );
    assert!(
        !text.contains("records are kept") && !text.contains("stays where it is"),
        "{label}: the ending says that records are kept or that the manifest stays: {text}"
    );
    match how {
        Some("garbage") | Some("absent") => assert!(
            text.contains("wrote its record again at"),
            "{label}: the ending does not say that the run wrote its record again: {text}"
        ),
        _ => assert!(
            text.contains("found the manifest that this run holds"),
            "{label}: the ending does not say that the run's manifest was found: {text}"
        ),
    }
    // The record stands for the administrator's removal.
    let paths = Paths::system().unwrap();
    assert!(
        Manifest::load(&paths.manifest).is_ok(),
        "{label}: no manifest that the removal can read stands at {}: {text}",
        paths.manifest.display()
    );

    let (removal_code, removal) = ordinary_removal();
    assert_eq!(removal_code, Some(0), "{label}: {removal}");
    assert!(
        removal.contains("without a failure") && removal.contains("its records are deleted"),
        "{label}: the removal did not end without a failure with its records deleted: {removal}"
    );
    assert_eq!(
        snapshot(),
        before,
        "{label}: after the removal the computer is as it was: {removal}"
    );
    text
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see windows_install.rs)"]
fn a_rollback_with_a_failed_step_and_an_unreadable_manifest_leaves_a_record_for_the_removal() {
    a_rollback_with_a_failed_step(Some("garbage"));
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see windows_install.rs)"]
fn a_rollback_with_a_failed_step_and_an_absent_manifest_leaves_a_record_for_the_removal() {
    a_rollback_with_a_failed_step(Some("absent"));
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see windows_install.rs)"]
fn a_rollback_with_a_failed_step_and_an_intact_manifest_leaves_a_record_for_the_removal() {
    a_rollback_with_a_failed_step(None);
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see windows_install.rs)"]
fn a_removal_sweeps_the_entries_of_staging_that_stand_under_the_layouts_names() {
    let _one_at_a_time = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    require_elevated();
    let before = snapshot();
    assert_clean(&before);
    let person = Person::make();
    // A run that died leaves its staging directory. A file and a directory under the layout's names
    // stand there, as a failed run leaves them.
    let _ = a_run_that_died_at(&person, "account");
    let paths = Paths::system().unwrap();
    let hex = uuid::Uuid::new_v4().simple().to_string();
    let policy = paths.staging.join(format!("policy-{hex}.xml"));
    let proof = paths.staging.join(format!("proof-{hex}"));
    std::fs::write(&policy, b"<AppLockerPolicy/>").unwrap();
    std::fs::create_dir(&proof).unwrap();
    std::fs::write(proof.join("inside.txt"), b"x").unwrap();

    let (code, text) = ordinary_removal();
    observed(&format!(
        "after the removal: policy file stands {}, proof directory stands {}, exit {code:?}",
        policy.exists(),
        proof.exists()
    ));
    assert_eq!(code, Some(0), "the removal succeeds: {text}");
    assert!(
        !policy.exists() && !proof.exists(),
        "the removal left an entry that stands under the layout's names: {text}"
    );
    assert_eq!(
        snapshot(),
        before,
        "after the removal the computer is as it was: {text}"
    );
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see windows_install.rs)"]
fn a_removal_refuses_a_staging_directory_that_holds_a_name_that_the_layout_does_not_give() {
    let _one_at_a_time = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    require_elevated();
    let before = snapshot();
    assert_clean(&before);
    let person = Person::make();
    let _ = a_run_that_died_at(&person, "account");
    let paths = Paths::system().unwrap();
    let hex = uuid::Uuid::new_v4().simple().to_string();
    let policy = paths.staging.join(format!("policy-{hex}.xml"));
    let notes = paths.staging.join("notes.txt");
    std::fs::write(&policy, b"<AppLockerPolicy/>").unwrap();
    std::fs::write(&notes, b"put here by hand").unwrap();

    let (code, text) = ordinary_removal();
    let (policy_stands, notes_stand) = (policy.exists(), notes.exists());
    observed(&format!(
        "after the removal: policy file stands {policy_stands}, notes.txt stands {notes_stand}, exit {code:?}"
    ));
    // The case's own cleanup, so that the second removal can end the run's records.
    let _ = std::fs::remove_file(&notes);
    let _ = std::fs::remove_file(&policy);
    assert_ne!(code, Some(0), "the removal ended without a failure: {text}");
    assert!(
        text.contains("notes.txt") && notes_stand,
        "the removal does not refuse because of the file that it did not make: {text}"
    );
    let (second_code, second) = ordinary_removal();
    assert_eq!(
        second_code,
        Some(0),
        "the second removal succeeds: {second}"
    );
    assert_eq!(
        snapshot(),
        before,
        "after the second removal the computer is as it was: {second}"
    );
}

/// The folder directly above the program directory, which an installation makes where it is not there.
fn program_folder() -> PathBuf {
    Paths::system()
        .unwrap()
        .program
        .parent()
        .expect("the program directory has a folder above it")
        .to_path_buf()
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see windows_install.rs)"]
fn the_folder_above_the_program_directory_that_a_run_made_goes_with_its_rollback_and_with_its_removal()
 {
    let _one_at_a_time = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    require_elevated();
    let before = snapshot();
    assert_clean(&before);
    let folder = program_folder();
    assert!(
        !folder.exists(),
        "the folder above the program directory stands before the run: {}",
        folder.display()
    );
    let person = Person::make();
    // A failed new installation: the rollback takes the folder that the run made.
    let (code, text) = install_with(&person, &[("KR_BOUNDARY_FAIL_AFTER", "broker")]);
    assert_ne!(code, Some(0), "{text}");
    observed(&format!(
        "after the rollback the folder {} stands: {}",
        folder.display(),
        folder.exists()
    ));
    for line in text.lines().filter(|line| line.contains("Program Files")) {
        observed(&format!("rollback line: {line}"));
    }
    assert!(
        !folder.exists(),
        "the rollback left the folder that the run made: {text}"
    );
    assert_eq!(
        snapshot(),
        before,
        "after the rollback the computer is as it was: {text}"
    );
    // A good installation and the ordinary removal: the folder goes again.
    let (code, text) = install_with(&person, &[]);
    assert_eq!(code, Some(0), "the installation succeeds: {text}");
    assert!(folder.exists(), "the installation made no folder: {text}");
    let (code, removal) = ordinary_removal();
    for line in removal
        .lines()
        .filter(|line| line.contains("Program Files"))
    {
        observed(&format!("removal line: {line}"));
    }
    assert_eq!(code, Some(0), "the removal succeeds: {removal}");
    assert!(
        !folder.exists(),
        "the removal left the folder that the run made: {removal}"
    );
    assert!(
        removal.contains("marked for removal, and a read of its name afterwards found it gone"),
        "the removal does not say that a read of the folder's name found it gone: {removal}"
    );
    assert_eq!(
        snapshot(),
        before,
        "after the removal the computer is as it was: {removal}"
    );
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see windows_install.rs)"]
fn the_folder_that_a_run_made_stays_when_another_programs_entry_stands_in_it_at_the_removal() {
    let _one_at_a_time = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    require_elevated();
    let before = snapshot();
    assert_clean(&before);
    let folder = program_folder();
    assert!(
        !folder.exists(),
        "the folder above the program directory stands before the run: {}",
        folder.display()
    );
    let person = Person::make();
    let (code, text) = install_with(&person, &[]);
    assert_eq!(code, Some(0), "the installation succeeds: {text}");
    // Another program's entry is put into the folder that the run made.
    let other = folder.join("other-programs-entry.txt");
    std::fs::write(&other, b"not the installation's").unwrap();
    let (code, removal) = ordinary_removal();
    let folder_stands = folder.exists();
    let other_stands = other.exists();
    for line in removal
        .lines()
        .filter(|line| line.contains("Program Files"))
    {
        observed(&format!("removal line: {line}"));
    }
    // The case's own cleanup: the entry that the case put there and the folder that stays with it.
    let _ = std::fs::remove_file(&other);
    let _ = std::fs::remove_dir(&folder);
    assert_eq!(
        code,
        Some(0),
        "the removal ends without a failure: {removal}"
    );
    assert!(
        removal.contains("a read found 1 entry in it"),
        "the removal does not say that a read found one entry in the folder: {removal}"
    );
    assert!(
        folder_stands && other_stands,
        "the removal took away a folder that holds another program's entry: {removal}"
    );
    assert_eq!(
        snapshot(),
        before,
        "after the case's own cleanup the computer is as it was: {removal}"
    );
}

/// A good installation for `person`. Returns the output of the setup program.
fn a_good_installation(person: &Person) -> String {
    let (code, text) = install_with(person, &[]);
    assert_eq!(code, Some(0), "the installation succeeds: {text}");
    text
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see windows_install.rs)"]
fn an_ordinary_removal_says_that_its_records_are_deleted_only_after_a_read_of_their_names() {
    let _one_at_a_time = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    require_elevated();
    let before = snapshot();
    assert_clean(&before);
    let person = Person::make();
    a_good_installation(&person);
    let (code, removal) = ordinary_removal();
    for line in removal.lines().filter(|line| line.contains("deleted")) {
        observed(&format!("removal line: {line}"));
    }
    assert_eq!(code, Some(0), "the removal succeeds: {removal}");
    assert!(
        removal.contains(
            "its records are deleted (a read of the name of each afterwards found it gone)"
        ),
        "the removal does not say that a read of the name of each record found it gone: {removal}"
    );
    assert_eq!(
        snapshot(),
        before,
        "after the removal the computer is as it was: {removal}"
    );
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see windows_install.rs)"]
fn a_record_that_cannot_be_deleted_ends_the_removal_with_the_platforms_words_and_keeps_the_record()
{
    use std::os::windows::fs::OpenOptionsExt as _;
    let _one_at_a_time = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    require_elevated();
    let before = snapshot();
    assert_clean(&before);
    let paths = Paths::system().unwrap();
    let person = Person::make();
    a_good_installation(&person);
    // The case holds the manifest open and shares read and write, so nobody can delete it.
    let held = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(0x1 | 0x2)
        .open(&paths.manifest)
        .expect("the case opens the manifest without sharing delete");
    let (code, removal) = ordinary_removal();
    for line in removal.lines().filter(|line| {
        line.contains("manifest") || line.contains("did not finish") || line.contains("deleted")
    }) {
        observed(&format!("removal line: {line}"));
    }
    let manifest_stands = paths.manifest.exists();
    drop(held);
    assert_ne!(
        code,
        Some(0),
        "the removal ended without a failure: {removal}"
    );
    assert!(
        manifest_stands,
        "the manifest is gone although the case held it: {removal}"
    );
    assert!(
        !removal.contains("its records are deleted"),
        "the removal says that records are deleted although one could not be: {removal}"
    );
    // The case has let go: the second removal runs to its end.
    let (second_code, second) = ordinary_removal();
    assert_eq!(
        second_code,
        Some(0),
        "the second removal succeeds: {second}"
    );
    assert_eq!(
        snapshot(),
        before,
        "after the second removal the computer is as it was: {second}"
    );
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see windows_install.rs)"]
fn a_removal_sweeps_the_brokers_journal_names_after_the_stop_and_leaves_other_names() {
    let _one_at_a_time = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    require_elevated();
    let before = snapshot();
    assert_clean(&before);
    let person = Person::make();
    a_good_installation(&person);
    let paths = Paths::system().unwrap();
    let hex = uuid::Uuid::new_v4().simple().to_string();
    let brokers = paths.journal.join(format!("{hex}.journal"));
    std::fs::write(&brokers, b"journal of a run").unwrap();
    // Names that are not the broker's form: they stay.
    let others: Vec<String> = vec![
        "a.journal".to_owned(),
        format!("{}.journal", "AB".repeat(16)),
        format!("{hex}.journal.old"),
        format!("{hex}.txt"),
    ];
    for other in &others {
        std::fs::write(paths.journal.join(other), b"put here by hand").unwrap();
    }
    let (code, removal) = ordinary_removal();
    let remaining: std::collections::BTreeSet<String> = std::fs::read_dir(&paths.journal)
        .map(|entries| {
            entries
                .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    observed(&format!(
        "after the removal the journal directory holds {remaining:?}, exit {code:?}"
    ));
    for line in removal.lines().filter(|line| line.contains("a.journal")) {
        observed(&format!("removal line: {line}"));
    }
    // The case's own cleanup, so that a second removal can end the run's records.
    for other in &others {
        let _ = std::fs::remove_file(paths.journal.join(other));
    }
    let _ = std::fs::remove_file(&brokers);
    assert!(
        !remaining.contains(&format!("{hex}.journal")),
        "the removal left a file that stands under the broker's journal names: {removal}"
    );
    assert_eq!(
        remaining,
        others.iter().cloned().collect(),
        "the removal took away a file that is not under the broker's journal names: {removal}"
    );
    assert!(
        removal.contains("a.journal"),
        "the removal does not name the file that it left in the journal directory: {removal}"
    );
    if paths.data.exists() {
        let (second_code, second) = ordinary_removal();
        assert_eq!(
            second_code,
            Some(0),
            "the second removal succeeds: {second}"
        );
    }
    assert_eq!(
        snapshot(),
        before,
        "after the second removal the computer is as it was: {removal}"
    );
}
