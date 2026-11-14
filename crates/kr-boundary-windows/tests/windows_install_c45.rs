//! Guest cases for a service that another party made at the broker's name (before a new
//! installation, between its steps, and under a repair), for the record that a run leaves when it
//! fails before its first record and its rollback fails a step, and for a repair of the folder above
//! the program directory. They run only in a disposable Windows guest, as SYSTEM, like the cases of
//! `windows_install.rs`.

#![cfg(all(windows, feature = "testing"))]

use std::io::Write as _;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use kr_boundary_windows::manifest::{Manifest, ObjectKind};
use kr_boundary_windows::policy::Policy;
use kr_boundary_windows::win::applocker::Channel;
use kr_boundary_windows::win::install::{CHECKOUT, CONNECT, Paths, SERVICE};
use kr_boundary_windows::win::pipe::Kind as Pipe;
use kr_boundary_windows::win::{account, registry, service, token};

const SPECIAL_ACCOUNTS: &str =
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList";

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
    if let Some((first @ ("install" | "repair"), rest)) =
        arguments.split_first().map(|(first, rest)| (*first, rest))
    {
        command
            .arg(first)
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

/// A repair of the installation that the manifest records, for `person`, with the given test
/// variables.
fn repair_with(person: &Person, environment: &[(&str, &str)]) -> (Option<i32>, String) {
    let (code, text) = run_setup(&["repair", "--person", &person.sid], environment);
    println!("--- kr-boundary-setup repair {environment:?} -> {code:?}\n{text}");
    (code, text)
}

/// The administrator's ordinary removal, with none of the test variables.
fn ordinary_removal() -> (Option<i32>, String) {
    let (code, text) = run_setup(&["remove"], &[]);
    println!("--- kr-boundary-setup remove -> {code:?}\n{text}");
    (code, text)
}

/// The words of the installer's entry check for a service that stands at the broker's name when a
/// new installation starts and that no manifest records.
fn entry_refusal() -> String {
    format!("a service named {SERVICE} exists, and no manifest of the installation records it")
}

/// The words of a new installation's first look and of its service step for a service that stands
/// at the broker's name where the run was to make it.
fn first_look_refusal() -> String {
    format!(
        "a service named {SERVICE} stood on this computer when this run was to make it; this run did not make it and has not changed it"
    )
}

/// The clause of the removal's check after its steps for a service that stands at the broker's name
/// where the manifest holds no result that the installation made it.
const STANDS_NOT_MADE: &str = "the broker's service stands there and the manifest holds no result that the installation made it";

/// A service at the broker's name that another party made, as a case makes it or as the test seam
/// makes it. The case deletes it when it ends, and says so.
struct StrangersService;

impl StrangersService {
    /// A service that the case makes before the installation, with a program that is no part of
    /// the installation, left stopped.
    fn stopped() -> StrangersService {
        let manager = service::manager().unwrap();
        assert!(
            manager.open(SERVICE).unwrap().is_none(),
            "a service stands at the broker's name before the case"
        );
        manager
            .create(
                SERVICE,
                "Boundary case service",
                r"C:\Windows\System32\cmd.exe",
            )
            .unwrap();
        StrangersService
    }

    /// A service that the installer's test seam made during the run.
    fn made_by_the_seam() -> StrangersService {
        assert!(
            the_service_at_the_brokers_name().is_some(),
            "the seam made no service at the broker's name"
        );
        StrangersService
    }
}

impl Drop for StrangersService {
    fn drop(&mut self) {
        if let Ok(manager) = service::manager()
            && let Ok(Some(service)) = manager.open(SERVICE)
        {
            if service.status().is_ok_and(|status| status.running()) {
                let _ = service.stop();
                let _ = service.wait_for(true, Duration::from_secs(60));
            }
            let _ = service.delete();
        }
        observed("the case deleted the service that stood at the broker's name");
    }
}

/// Whether a service stands at the broker's name, and whether it runs.
fn the_service_at_the_brokers_name() -> Option<bool> {
    service::manager()
        .unwrap()
        .open(SERVICE)
        .unwrap()
        .filter(|service| !service.marked_for_deletion().unwrap())
        .map(|service| service.status().unwrap().running())
}

/// The outcome that the manifest on disk holds for the broker's service, as the manifest prints it.
fn service_outcome(paths: &Paths) -> String {
    let manifest = Manifest::load(&paths.manifest).expect("a manifest that the removal can read");
    let object = manifest
        .find(ObjectKind::Service, SERVICE)
        .unwrap_or_else(|| panic!("the manifest holds no Service entry: {manifest:?}"));
    format!("{:?}", object.outcome)
}

fn a_good_installation(person: &Person) -> String {
    let (code, text) = install_with(person, &[]);
    assert_eq!(code, Some(0), "the installation succeeds: {text}");
    text
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see windows_install.rs)"]
fn a_service_at_the_brokers_name_that_stands_before_a_new_installation_is_refused_and_left_as_it_is()
 {
    let _one_at_a_time = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    require_elevated();
    let before = snapshot();
    assert_clean(&before);
    let person = Person::make();
    let made = StrangersService::stopped();
    let (code, text) = install_with(&person, &[]);
    let paths = Paths::system().unwrap();
    observed(&format!(
        "the service stands {:?} after the run; the data directory stands {}; exit {code:?}",
        the_service_at_the_brokers_name(),
        paths.data.exists()
    ));
    assert_ne!(code, Some(0), "the run did not refuse the service: {text}");
    assert!(
        text.contains(&entry_refusal()),
        "the run does not say that the service stands and no manifest records it: {text}"
    );
    assert_eq!(
        the_service_at_the_brokers_name(),
        Some(false),
        "the service's state changed: {text}"
    );
    assert!(
        !paths.data.exists() && !paths.program.exists() && !paths.manifest.exists(),
        "the run made a directory or a record: {text}"
    );
    drop(made);
    assert_eq!(
        snapshot(),
        before,
        "after the case deleted its service the computer is as it was: {text}"
    );
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see windows_install.rs)"]
fn a_service_that_appears_after_the_accounts_step_is_refused_and_the_removal_leaves_it_alone() {
    let _one_at_a_time = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    require_elevated();
    let before = snapshot();
    assert_clean(&before);
    let person = Person::make();
    let (code, text) = install_with(
        &person,
        &[
            ("KR_BOUNDARY_MAKE_AFTER", "accounts:service"),
            ("KR_BOUNDARY_FAIL_UNDO", "account"),
        ],
    );
    let made = StrangersService::made_by_the_seam();
    assert_ne!(code, Some(0), "the run did not refuse the service: {text}");
    assert!(
        text.contains(&first_look_refusal()),
        "the run does not say that the service stood where it was to make it: {text}"
    );
    assert!(
        text.contains("the removal after the failure also failed")
            && text.contains("a failure was injected into the account step of the undoing"),
        "the rollback did not fail at its account step: {text}"
    );
    let paths = Paths::system().unwrap();
    let outcome = service_outcome(&paths);
    observed(&format!("the record holds the Service entry as {outcome}"));
    assert_eq!(
        outcome, "Some(Refused)",
        "the record does not hold the service as refused: {text}"
    );
    let (removal_code, removal) = ordinary_removal();
    observed(&format!(
        "after the removal the service stands {:?}; exit {removal_code:?}",
        the_service_at_the_brokers_name()
    ));
    assert_eq!(
        removal_code,
        Some(0),
        "the removal ends with a failure: {removal}"
    );
    assert_eq!(
        the_service_at_the_brokers_name(),
        Some(false),
        "the removal stopped or deleted the service that it did not make: {removal}"
    );
    assert!(
        removal.contains(STANDS_NOT_MADE),
        "the removal's ending does not name the service that stands: {removal}"
    );
    drop(made);
    assert_eq!(
        snapshot(),
        before,
        "after the case deleted its service the computer is as it was: {removal}"
    );
}

/// A new installation whose service appears after the `directories` step and before the first look
/// of the step that makes the service, with the undoing of the service failing: the record that the
/// failed rollback leaves. Returns the installation's text.
fn a_refused_service_after_the_directories_step(person: &Person) -> String {
    let (code, text) = install_with(
        person,
        &[
            ("KR_BOUNDARY_MAKE_AFTER", "directories:service"),
            ("KR_BOUNDARY_FAIL_UNDO", "service"),
        ],
    );
    assert_ne!(code, Some(0), "the run did not refuse the service: {text}");
    assert!(
        text.contains(&first_look_refusal()),
        "the run does not say that the service stood where it was to make it: {text}"
    );
    assert!(
        text.contains("the removal after the failure also failed")
            && text.contains("a failure was injected into the service step of the undoing"),
        "the rollback did not fail at its service step: {text}"
    );
    text
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see windows_install.rs)"]
fn a_service_that_appears_after_the_directories_step_is_refused_at_the_first_look_before_any_program_step()
 {
    let _one_at_a_time = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    require_elevated();
    let before = snapshot();
    assert_clean(&before);
    let person = Person::make();
    let text = a_refused_service_after_the_directories_step(&person);
    let made = StrangersService::made_by_the_seam();
    let paths = Paths::system().unwrap();
    let manifest = Manifest::load(&paths.manifest).expect("a manifest that the removal can read");
    observed(&format!("the record left by the rollback: {manifest:?}"));
    assert_eq!(
        service_outcome(&paths),
        "Some(Refused)",
        "the record does not hold the service as refused: {text}"
    );
    // The first look refuses before the program directory and the folder above it are made: the
    // run goes on to them where the first look does not refuse.
    assert!(
        manifest
            .find(ObjectKind::Directory, &paths.program.display().to_string())
            .is_none()
            && manifest.of_kind(ObjectKind::ProgramFolder).next().is_none(),
        "the record holds the program directory or the folder above it: {manifest:?}"
    );
    let (removal_code, removal) = ordinary_removal();
    assert_eq!(
        removal_code,
        Some(0),
        "the removal ends with a failure: {removal}"
    );
    assert_eq!(
        the_service_at_the_brokers_name(),
        Some(false),
        "the removal stopped or deleted the service that it did not make: {removal}"
    );
    drop(made);
    assert_eq!(
        snapshot(),
        before,
        "after the case deleted its service the computer is as it was: {removal}"
    );
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see windows_install.rs)"]
fn a_repair_of_a_refused_service_that_stands_is_refused_at_its_first_look() {
    let _one_at_a_time = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    require_elevated();
    let before = snapshot();
    assert_clean(&before);
    let person = Person::make();
    a_refused_service_after_the_directories_step(&person);
    let made = StrangersService::made_by_the_seam();
    let paths = Paths::system().unwrap();
    // The repair of that record, with the service still standing and stopped.
    let (code, text) = repair_with(&person, &[]);
    observed(&format!(
        "after the repair the service stands {:?}; the record holds it as {}; exit {code:?}",
        the_service_at_the_brokers_name(),
        service_outcome(&paths)
    ));
    assert_ne!(
        code,
        Some(0),
        "the repair did not refuse the service: {text}"
    );
    assert!(
        text.contains(&first_look_refusal()),
        "the repair does not refuse as the first run did: {text}"
    );
    assert_eq!(
        the_service_at_the_brokers_name(),
        Some(false),
        "the repair changed the state of the service: {text}"
    );
    assert_eq!(
        service_outcome(&paths),
        "Some(Refused)",
        "the repair changed the result that the record holds for the service: {text}"
    );
    let (removal_code, removal) = ordinary_removal();
    assert_eq!(
        removal_code,
        Some(0),
        "the removal ends with a failure: {removal}"
    );
    assert_eq!(
        the_service_at_the_brokers_name(),
        Some(false),
        "the removal stopped or deleted the service that it did not make: {removal}"
    );
    drop(made);
    assert_eq!(
        snapshot(),
        before,
        "after the case deleted its service the computer is as it was: {removal}"
    );
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see windows_install.rs)"]
fn a_repair_of_a_refused_service_that_is_gone_makes_the_service_and_the_record_says_made() {
    let _one_at_a_time = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    require_elevated();
    let before = snapshot();
    assert_clean(&before);
    let person = Person::make();
    a_refused_service_after_the_directories_step(&person);
    // The service that the seam made is deleted before the repair.
    drop(StrangersService::made_by_the_seam());
    assert!(!snapshot().service, "the case did not delete its service");
    let (repair_code, text) = repair_with(&person, &[]);
    assert_eq!(repair_code, Some(0), "the repair succeeds: {text}");
    let paths = Paths::system().unwrap();
    assert_eq!(
        service_outcome(&paths),
        "Some(Made)",
        "the repair did not record the service as made: {text}"
    );
    let (code, removal) = ordinary_removal();
    assert_eq!(code, Some(0), "the removal succeeds: {removal}");
    assert_eq!(
        snapshot(),
        before,
        "after the removal the computer is as it was: {removal}"
    );
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see windows_install.rs)"]
fn a_repair_over_a_refused_record_that_dies_after_the_creation_leaves_an_intent() {
    let _one_at_a_time = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    require_elevated();
    let before = snapshot();
    assert_clean(&before);
    let person = Person::make();
    a_refused_service_after_the_directories_step(&person);
    // The service that stood there is deleted by the case before the repair.
    drop(StrangersService::made_by_the_seam());
    assert!(!snapshot().service, "the case did not delete its service");
    // A repair that is aborted right after the call that made the service returned.
    let (code, text) = repair_with(&person, &[("KR_BOUNDARY_DIE_AT", "service")]);
    assert_ne!(code, Some(0), "the repair did not die: {text}");
    let paths = Paths::system().unwrap();
    let manifest = Manifest::load(&paths.manifest).expect("a manifest that the removal can read");
    let object = manifest
        .find(ObjectKind::Service, SERVICE)
        .unwrap_or_else(|| panic!("the manifest holds no Service entry: {manifest:?}"));
    observed(&format!("the record holds the Service entry as {object:?}"));
    assert_eq!(
        object.outcome, None,
        "the record still holds a result for a service that the repair made: {object:?}"
    );
    assert!(
        the_service_at_the_brokers_name().is_some(),
        "the repair made no service before it died: {text}"
    );
    // The removal takes the service that the repair made, as the intent shows.
    let (removal_code, removal) = ordinary_removal();
    assert_eq!(removal_code, Some(0), "the removal succeeds: {removal}");
    assert_eq!(
        snapshot(),
        before,
        "after the removal the computer is as it was: {removal}"
    );
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see windows_install.rs)"]
fn a_repair_whose_creation_of_the_service_fails_puts_the_refusal_back_in_the_record() {
    let _one_at_a_time = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    require_elevated();
    let before = snapshot();
    assert_clean(&before);
    let person = Person::make();
    a_refused_service_after_the_directories_step(&person);
    // The service that stood there is deleted by the case before the repair.
    drop(StrangersService::made_by_the_seam());
    assert!(!snapshot().service, "the case did not delete its service");
    // A repair over the record of that refusal, with a service made at the broker's name between
    // the service step's open and its creation: the creation fails.
    let (code, text) = repair_with(
        &person,
        &[("KR_BOUNDARY_MAKE_AFTER", "service-open:service")],
    );
    let made = StrangersService::made_by_the_seam();
    let paths = Paths::system().unwrap();
    observed(&format!(
        "after the repair the record holds the Service entry as {}; exit {code:?}",
        service_outcome(&paths)
    ));
    assert_ne!(code, Some(0), "the repair did not fail: {text}");
    assert!(
        text.to_lowercase().contains("already exist"),
        "the repair does not end with the creation's own error: {text}"
    );
    assert_eq!(
        service_outcome(&paths),
        "Some(Refused)",
        "the record does not hold the refusal after the failed creation: {text}"
    );
    // A later repair refuses at its first look and does not touch the service.
    let (later_code, later) = repair_with(&person, &[]);
    assert_ne!(
        later_code,
        Some(0),
        "the later repair did not refuse: {later}"
    );
    assert!(
        later.contains(&first_look_refusal()),
        "the later repair does not refuse as the first run did: {later}"
    );
    assert_eq!(
        the_service_at_the_brokers_name(),
        Some(false),
        "the later repair changed the state of the service: {later}"
    );
    let (removal_code, removal) = ordinary_removal();
    assert_eq!(
        removal_code,
        Some(0),
        "the removal ends with a failure: {removal}"
    );
    drop(made);
    assert_eq!(
        snapshot(),
        before,
        "after the case deleted its service the computer is as it was: {removal}"
    );
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see windows_install.rs)"]
fn a_run_that_fails_before_its_first_record_and_whose_rollback_fails_leaves_a_record_that_the_removal_accepts()
 {
    let _one_at_a_time = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    require_elevated();
    let before = snapshot();
    assert_clean(&before);
    let person = Person::make();
    let (code, text) = install_with(
        &person,
        &[
            ("KR_BOUNDARY_FAIL_AFTER", "directories"),
            ("KR_BOUNDARY_FAIL_UNDO", "service"),
        ],
    );
    let ending = text
        .find("undoing what was done")
        .map_or("(no rollback)", |at| &text[at..]);
    observed(&format!(
        "the ending from \"undoing what was done\" to its end follows\n{ending}\nOBSERVED the ending ends"
    ));
    assert_ne!(code, Some(0), "{text}");
    assert!(
        text.contains("a failure was injected into the service step of the undoing"),
        "the rollback did not fail at its service step: {text}"
    );
    let paths = Paths::system().unwrap();
    let manifest = Manifest::load(&paths.manifest).unwrap_or_else(|why| {
        panic!("no manifest that the removal can read stands: {why:?}: {text}")
    });
    assert!(
        manifest
            .find(ObjectKind::Directory, &paths.data.display().to_string())
            .is_some(),
        "the record that the run left holds no entry of the data directory: {manifest:?}"
    );
    let (removal_code, removal) = ordinary_removal();
    assert_eq!(removal_code, Some(0), "the removal succeeds: {removal}");
    assert_eq!(
        snapshot(),
        before,
        "after the removal the computer is as it was: {removal}"
    );
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see windows_install.rs)"]
fn a_repair_keeps_the_result_of_the_folder_that_an_earlier_run_made_and_the_removal_takes_the_folder()
 {
    let _one_at_a_time = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    require_elevated();
    let before = snapshot();
    assert_clean(&before);
    let folder = paths_program_folder();
    assert!(
        !folder.exists(),
        "the folder above the program directory stands before the run: {}",
        folder.display()
    );
    let person = Person::make();
    a_good_installation(&person);
    let paths = Paths::system().unwrap();
    let recorded = |paths: &Paths| {
        let manifest =
            Manifest::load(&paths.manifest).expect("a manifest that the removal can read");
        let object = manifest
            .of_kind(ObjectKind::ProgramFolder)
            .next()
            .unwrap_or_else(|| panic!("the manifest holds no ProgramFolder entry: {manifest:?}"))
            .clone();
        format!("{:?} {:?}", object.outcome, object.detail)
    };
    let first = recorded(&paths);
    observed(&format!(
        "after the installation the record holds the folder as: {first}"
    ));
    // A repair: the folder stands, and the run writes no result for it.
    let (repair_code, text) = repair_with(&person, &[]);
    assert_eq!(repair_code, Some(0), "the repair succeeds: {text}");
    let second = recorded(&paths);
    observed(&format!(
        "after the repair the record holds the folder as: {second}"
    ));
    assert_eq!(
        first, second,
        "the repair changed what the record holds for the folder: {text}"
    );
    assert!(
        first.starts_with("Some(Made)"),
        "the run did not make the folder: {first}"
    );
    let (code, removal) = ordinary_removal();
    assert_eq!(code, Some(0), "the removal succeeds: {removal}");
    assert!(
        !folder.exists(),
        "the removal left the folder that the first run made: {removal}"
    );
    assert_eq!(
        snapshot(),
        before,
        "after the removal the computer is as it was: {removal}"
    );
}

/// The folder directly above the program directory.
fn paths_program_folder() -> PathBuf {
    Paths::system()
        .unwrap()
        .program
        .parent()
        .expect("the program directory has a folder above it")
        .to_path_buf()
}
