//! Guest cases for where the installation's records are written and for what a failure of its first
//! steps leaves. They run only in a disposable Windows guest, as SYSTEM, like the cases of
//! `windows_install.rs`.

#![cfg(all(windows, feature = "testing"))]

use std::collections::BTreeSet;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Mutex, PoisonError};

use kr_boundary_windows::manifest::{Manifest, forced};
use kr_boundary_windows::policy::Policy;
use kr_boundary_windows::win::applocker::Channel;
use kr_boundary_windows::win::install::{self, CHECKOUT, CONNECT, Options, Paths, SERVICE};
use kr_boundary_windows::win::pipe::Kind as Pipe;
use kr_boundary_windows::win::{account, registry, service, token};

const SPECIAL_ACCOUNTS: &str =
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList";

/// The cases change the process's current directory and the point where a failure is forced, which
/// are the process's own: one runs at a time.
static SERIAL: Mutex<()> = Mutex::new(());

/// The names that a folder holds.
fn names_in(folder: &Path) -> BTreeSet<String> {
    std::fs::read_dir(folder)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect()
}

#[test]
#[ignore = "needs a disposable Windows guest, as SYSTEM (see windows_install.rs)"]
fn the_manifest_stands_in_the_data_directory_and_in_no_other_place_after_a_save_from_another_current_directory()
 {
    let _one_at_a_time = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let id = &uuid::Uuid::new_v4().simple().to_string()[..8];
    let top = std::env::temp_dir().join(format!("krsave-{id}"));
    let data = top.join("Boundary");
    let elsewhere = top.join("elsewhere");
    std::fs::create_dir_all(&data).unwrap();
    std::fs::create_dir(&elsewhere).unwrap();
    let started_in = std::env::current_dir().unwrap();
    let started_names = names_in(&started_in);
    std::env::set_current_dir(&elsewhere).unwrap();
    let path = data.join("manifest.json");

    // A new record, then a replacement of the record that is there: both are saves.
    let mut manifest = Manifest::begin();
    for persons in [Vec::new(), vec!["S-1-5-21-1-2-3-1001".to_owned()]] {
        manifest.persons = persons;
        manifest.save(&path).unwrap();
        assert_eq!(
            Manifest::load(&path).unwrap(),
            manifest,
            "the record in the data directory is not what was saved"
        );
        assert_eq!(
            names_in(&data),
            BTreeSet::from(["manifest.json".to_owned()]),
            "the data directory holds something else than the record after a save"
        );
        assert_eq!(
            names_in(&elsewhere),
            BTreeSet::new(),
            "the current directory holds a new file after a save"
        );
        assert_eq!(
            names_in(&top),
            BTreeSet::from(["Boundary".to_owned(), "elsewhere".to_owned()]),
            "the folder above the data directory holds a new file after a save"
        );
    }
    std::env::set_current_dir(&started_in).unwrap();
    assert_eq!(
        names_in(&started_in),
        started_names,
        "the folder that the process started in holds a new file after a save"
    );
    let _ = std::fs::remove_dir_all(&top);
}

/// The installation's places under names of their own in the system's known folders, so that the
/// run makes the folder above the data directory and the data directory itself.
fn paths_of_its_own(id: &str) -> Paths {
    let system = Paths::system().unwrap();
    let name = format!("KalaReachC37{id}");
    let data = system
        .data_parent()
        .parent()
        .unwrap()
        .join(&name)
        .join("Boundary");
    let program = system.program_top.join(&name).join("Boundary");
    Paths {
        git: program.join("git"),
        program_top: system.program_top.clone(),
        program,
        staging: data.join("staging"),
        journal: data.join("journal"),
        run: data.join("run"),
        manifest: data.join("manifest.json"),
        prior: data.join("prior.json"),
        data,
    }
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see windows_install.rs)"]
fn a_failure_after_the_folder_and_the_data_directory_were_made_leaves_nothing_of_the_run() {
    let _one_at_a_time = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let options = Options {
        payload: std::env::temp_dir(),
        person: None,
    };
    // The three points: the protection of the directory, the first record, and the write of that
    // record after its replacement file was made.
    for point in ["protect", "record", "replacement"] {
        let id = &uuid::Uuid::new_v4().simple().to_string()[..8];
        let paths = paths_of_its_own(id);
        let above = paths.data_parent().to_owned();
        assert!(!above.exists(), "the folder above is there before the run");
        forced::fail_the_next(point);
        let result = install::install(&paths, &options, false);
        // A point that was not reached must not stay forced for the next case.
        forced::fail_the_next("none");
        let text = result
            .expect_err("the forced failure stops the installation")
            .to_string();
        assert!(
            text.contains(&format!("a failure forced for a case at the step {point}")),
            "{point}: {text}"
        );
        assert!(
            !paths.data.exists(),
            "{point}: the data directory stays: {text}"
        );
        assert!(!above.exists(), "{point}: the folder above stays: {text}");
        assert!(
            !paths.program.exists() && !paths.program.parent().unwrap().exists(),
            "{point}: something of the program tree was made: {text}"
        );
    }
}

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

/// Runs the setup program with the payload of the guest's runner and "yes" on its input, from the
/// given working directory, with the given variables. Returns its exit code and its output.
fn run_setup(
    arguments: &[&str],
    environment: &[(&str, &str)],
    working_directory: Option<&Path>,
) -> (Option<i32>, String) {
    let bin = PathBuf::from(
        std::env::var_os("KR_BOUNDARY_BIN")
            .expect("KR_BOUNDARY_BIN names the directory with the setup program and its payloads"),
    );
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
    if let Some(directory) = working_directory {
        command.current_dir(directory);
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

/// A new installation of the setup program that fails after the named step with the manifest
/// damaged as `how` says, from a working directory of its own. Returns the exit code and the
/// output, and checks that the rollback restored the earlier state and that no manifest stands in
/// any other place than the data directory's.
fn a_late_failure_with_a_damaged_manifest(how: &str) -> String {
    let _one_at_a_time = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    assert!(
        token::current_is_administrator().unwrap(),
        "the case must run elevated"
    );
    let before = snapshot();
    assert!(
        !before.service
            && before.accounts == [false, false]
            && !before.data_dir
            && !before.data_parent
            && !before.program_dir
            && before.pipes_gone,
        "the machine is not clean: {before:?}"
    );
    let id = &uuid::Uuid::new_v4().simple().to_string()[..6];
    let person_name = format!("krperson{id}");
    let person = account::create(&person_name).expect("the person's account is made");
    let elsewhere: PathBuf = std::env::temp_dir().join(format!("krcurrent-{id}"));
    std::fs::create_dir(&elsewhere).unwrap();
    let (code, text) = run_setup(
        &["install", "--person", &person.to_text().unwrap()],
        &[
            ("KR_BOUNDARY_FAIL_AFTER", "broker"),
            ("KR_BOUNDARY_DAMAGE_MANIFEST", how),
        ],
        Some(&elsewhere),
    );
    println!(
        "--- kr-boundary-setup install, failure after the broker step, manifest {how} -> {code:?}\n{text}"
    );
    let _ = account::delete(&person_name);
    assert_ne!(code, Some(0), "{how}: {text}");
    assert!(
        text.contains("a failure was injected after the broker step"),
        "{how}: {text}"
    );
    assert!(
        !text.contains("could not be damaged"),
        "{how}: the seam did not damage the manifest: {text}"
    );
    assert!(
        text.contains("undoing what was done"),
        "{how}: the rollback did not start: {text}"
    );
    assert!(
        text.contains("the removal after the failure finished") && !text.contains("also failed"),
        "{how}: the rollback did not end without a failure: {text}"
    );
    assert_eq!(
        snapshot(),
        before,
        "{how}: after the rollback the computer is as it was: {text}"
    );
    // No manifest stands anywhere that it should not: not in the working directory of the setup
    // program, and not in the folder above the data directory, which is gone.
    assert_eq!(
        names_in(&elsewhere),
        BTreeSet::new(),
        "{how}: the setup program's working directory holds a file: {text}"
    );
    let _ = std::fs::remove_dir_all(&elsewhere);
    text
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see windows_install.rs)"]
fn a_new_installation_that_fails_late_with_an_unreadable_manifest_is_rolled_back_to_the_earlier_state()
 {
    a_late_failure_with_a_damaged_manifest("garbage");
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see windows_install.rs)"]
fn a_new_installation_that_fails_late_with_an_absent_manifest_is_rolled_back_to_the_earlier_state()
{
    a_late_failure_with_a_damaged_manifest("absent");
}

/// Prints a line that a person reads in the run's output.
fn observed(line: &str) {
    println!("OBSERVED {line}");
}

/// What stands on the disk at the folder above the data directory and in it.
fn disk_of_the_data_tree(paths: &Paths) -> String {
    let above = paths.data_parent();
    let listing = |folder: &Path| {
        if folder.exists() {
            format!("{:?}", names_in(folder))
        } else {
            "not there".to_owned()
        }
    };
    format!(
        "folder above {} ({}); data directory {} ({}); manifest {}",
        if above.exists() { "stands" } else { "is gone" },
        listing(above),
        if paths.data.exists() {
            "stands"
        } else {
            "is gone"
        },
        listing(&paths.data),
        if paths.manifest.exists() {
            "stands"
        } else {
            "is gone"
        }
    )
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see windows_install.rs)"]
fn a_new_installation_that_fails_before_any_record_prints_its_ending_and_leaves_what_the_disk_shows()
 {
    let _one_at_a_time = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let options = Options {
        payload: std::env::temp_dir(),
        person: None,
    };
    let paths = Paths::system().unwrap();
    for point in ["protect", "record"] {
        observed(&format!(
            "A {point}: before the run: {}",
            disk_of_the_data_tree(&paths)
        ));
        println!("OBSERVED A {point}: the setup program's own lines follow");
        forced::fail_the_next(point);
        let result = install::install(&paths, &options, false);
        forced::fail_the_next("none");
        println!("OBSERVED A {point}: the setup program's own lines end");
        observed(&format!(
            "A {point}: install returned: {}",
            result
                .as_ref()
                .err()
                .map_or_else(|| "Ok".to_owned(), ToString::to_string)
        ));
        observed(&format!(
            "A {point}: after the run: {}",
            disk_of_the_data_tree(&paths)
        ));
        // A folder that the run left stays for the guest's restore; a later run of the loop starts
        // from what the disk shows, and says so above.
        assert!(
            result.is_err(),
            "{point}: the forced failure did not stop the installation"
        );
    }
}

/// The folder that holds the program directory, made by hand and taken away by hand at the end of
/// a case whatever the case did.
struct ParentMadeByHand(PathBuf);

impl Drop for ParentMadeByHand {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir(&self.0);
    }
}

/// Makes the program directory's parent by hand, as the account that runs the case makes a folder
/// in `Program Files`, and prints its owner and its list.
fn make_the_program_parent_by_hand(paths: &Paths) -> ParentMadeByHand {
    let parent = paths
        .program
        .parent()
        .expect("the program directory has a parent")
        .to_owned();
    assert!(!parent.exists(), "the program directory's parent is there");
    std::fs::create_dir(&parent).unwrap();
    let owner = Command::new("powershell")
        .args(["-NoProfile", "-Command"])
        .arg(format!(
            "(Get-Acl -LiteralPath '{}').Owner",
            parent.display()
        ))
        .output()
        .unwrap();
    let list = Command::new("icacls").arg(&parent).output().unwrap();
    observed(&format!(
        "B: made by hand with std::fs::create_dir: {} (owner {}; list {})",
        parent.display(),
        String::from_utf8_lossy(&owner.stdout).trim(),
        String::from_utf8_lossy(&list.stdout)
            .split_whitespace()
            .skip(1)
            .collect::<Vec<_>>()
            .join(" ")
    ));
    ParentMadeByHand(parent)
}

/// One run of the setup program for the observation of the program directory's parent.
fn the_program_parent_after(failing: bool) {
    let _one_at_a_time = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    assert!(
        token::current_is_administrator().unwrap(),
        "the case must run elevated"
    );
    let before = snapshot();
    assert!(
        !before.service
            && before.accounts == [false, false]
            && !before.data_dir
            && !before.data_parent
            && !before.program_dir
            && before.pipes_gone,
        "the machine is not clean: {before:?}"
    );
    let paths = Paths::system().unwrap();
    let parent = make_the_program_parent_by_hand(&paths);
    let id = &uuid::Uuid::new_v4().simple().to_string()[..6];
    let person_name = format!("krperson{id}");
    let person = account::create(&person_name).expect("the person's account is made");
    let person_text = person.to_text().unwrap();
    let environment: &[(&str, &str)] = if failing {
        &[("KR_BOUNDARY_FAIL_AFTER", "broker")]
    } else {
        &[]
    };
    let (code, text) = run_setup(&["install", "--person", &person_text], environment, None);
    println!("--- kr-boundary-setup install -> {code:?}\n{text}");
    let mut stands = parent.0.exists();
    let what = if failing {
        "B1: after the rollback of a failure after the broker step"
    } else {
        "B2: after a good installation"
    };
    observed(&format!(
        "{what}: the program directory's parent {}",
        if stands { "stands" } else { "is gone" }
    ));
    let mut after_removal = None;
    if failing {
        assert_ne!(code, Some(0), "{text}");
        assert!(
            text.contains("the removal after the failure finished")
                && !text.contains("also failed"),
            "{text}"
        );
    } else {
        assert_eq!(code, Some(0), "the installation succeeds: {text}");
        assert!(
            parent.0.exists(),
            "the parent is gone after an installation"
        );
        let (removal_code, removal) = run_setup(&["remove"], &[], None);
        println!("--- kr-boundary-setup remove -> {removal_code:?}\n{removal}");
        stands = parent.0.exists();
        after_removal = Some(stands);
        observed(&format!(
            "B2: after the ordinary removal: the program directory's parent {}",
            if stands { "stands" } else { "is gone" }
        ));
        assert_eq!(removal_code, Some(0), "{removal}");
    }
    let _ = account::delete(&person_name);
    assert_eq!(
        snapshot(),
        before,
        "after the run the computer is as it was (the program directory's parent aside)"
    );
    // The folder was made by hand and the run did not make it.
    assert!(
        after_removal.unwrap_or(stands),
        "the run took away a folder that it did not make: {}",
        parent.0.display()
    );
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see windows_install.rs)"]
fn a_program_parent_made_by_hand_stands_after_the_rollback_of_a_late_failure() {
    the_program_parent_after(true);
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see windows_install.rs)"]
fn a_program_parent_made_by_hand_stands_after_a_good_installation_and_its_removal() {
    the_program_parent_after(false);
}
