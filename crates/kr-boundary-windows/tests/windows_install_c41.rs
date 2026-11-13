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
