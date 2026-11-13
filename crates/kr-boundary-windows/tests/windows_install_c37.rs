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

/// Starts the setup program with the payload of the guest's runner and "yes" on its input, from
/// the given working directory, with the given variables.
fn start_setup(
    arguments: &[&str],
    environment: &[(&str, &str)],
    working_directory: Option<&Path>,
) -> std::process::Child {
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
    child
}

/// The exit code and the output of a setup program that ended.
fn ended(output: &std::process::Output) -> (Option<i32>, String) {
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    (output.status.code(), text)
}

/// Runs the setup program (see [`start_setup`]) to its end. Returns its exit code and its output.
fn run_setup(
    arguments: &[&str],
    environment: &[(&str, &str)],
    working_directory: Option<&Path>,
) -> (Option<i32>, String) {
    let output = start_setup(arguments, environment, working_directory)
        .wait_with_output()
        .unwrap();
    ended(&output)
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
    assert_clean(&before);
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
    if how == "absent" {
        // A manifest that is not at its name is not a record that the rollback marked: the ending
        // lists it with the words of a name that was not found, and does not say that records are
        // deleted.
        assert!(
            text.contains("the removal after the failure also failed")
                && text.contains(
                    "manifest.json (its name was not found in the directory that holds it, and the rollback did nothing with it)"
                )
                && !text.contains("its records are deleted"),
            "{how}: the ending does not name the manifest as not found: {text}"
        );
    } else {
        assert!(
            text.contains("the removal after the failure finished")
                && !text.contains("also failed"),
            "{how}: the rollback did not end without a failure: {text}"
        );
    }
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
    assert_clean(&before);
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

/// Fails if a file that a write of a record made and did not rename stands in the data directory:
/// the names are the record's stem, 32 hexadecimal digits and `.new`.
fn no_replacement_file_stands(paths: &Paths, when: &str) {
    let names = names_in(&paths.data);
    observed(&format!("the data directory {when} holds {names:?}"));
    let left: Vec<&String> = names.iter().filter(|name| name.ends_with(".new")).collect();
    assert!(
        left.is_empty(),
        "{when}: a replacement file stands: {left:?}"
    );
}

/// Fails unless another program can open the manifest and the earlier-state record for reading,
/// writing and deleting, sharing everything: the run keeps no restrictive handle of either.
fn both_records_open_for_read_write_and_delete(paths: &Paths, when: &str) {
    use std::os::windows::fs::OpenOptionsExt as _;
    const DELETE: u32 = 0x0001_0000;
    const FILE_GENERIC_READ_WRITE: u32 = 0x0012_0089 | 0x0012_0116;
    for path in [&paths.manifest, &paths.prior] {
        let opened = std::fs::OpenOptions::new()
            .access_mode(FILE_GENERIC_READ_WRITE | DELETE)
            .share_mode(7)
            .open(path);
        observed(&format!(
            "{when}: opening {} for read, write and delete: {}",
            path.display(),
            opened.as_ref().map_or_else(
                |error| format!("{error} ({:?})", error.raw_os_error()),
                |_| "ok".to_owned()
            )
        ));
        assert!(
            opened.is_ok(),
            "{when}: {} cannot be opened for read, write and delete: {opened:?}",
            path.display()
        );
    }
}

/// The directory that holds the setup program and its signed payloads.
fn bin_directory() -> PathBuf {
    PathBuf::from(
        std::env::var_os("KR_BOUNDARY_BIN")
            .expect("KR_BOUNDARY_BIN names the directory with the setup program and its payloads"),
    )
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see windows_install.rs)"]
fn a_repair_whose_proof_read_fails_after_the_rename_keeps_the_new_record_and_the_removal_then_runs_to_its_end()
 {
    let _one_at_a_time = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    assert!(
        token::current_is_administrator().unwrap(),
        "the case must run elevated"
    );
    let before = snapshot();
    assert_clean(&before);
    let paths = Paths::system().unwrap();
    let id = &uuid::Uuid::new_v4().simple().to_string()[..6];
    let first_name = format!("krperson{id}a");
    let second_name = format!("krperson{id}b");
    let first = account::create(&first_name).expect("the first person's account is made");
    let second = account::create(&second_name).expect("the second person's account is made");
    let (first_text, second_text) = (first.to_text().unwrap(), second.to_text().unwrap());

    // A good installation for the first person.
    let (code, text) = run_setup(&["install", "--person", &first_text], &[], None);
    println!("--- kr-boundary-setup install -> {code:?}\n{text}");
    assert_eq!(code, Some(0), "the installation succeeds: {text}");
    let installed = Manifest::load(&paths.manifest).unwrap();
    assert!(installed.persons.contains(&first_text));
    assert!(!installed.persons.contains(&second_text));
    no_replacement_file_stands(&paths, "after a good installation");
    both_records_open_for_read_write_and_delete(&paths, "after a good installation");

    // A repair that enrols the second person, whose first write of the manifest renames for real
    // and then cannot read what stands at the record's name.
    let options = Options {
        payload: bin_directory().join("payload"),
        person: Some(second_text.clone()),
    };
    forced::fail_the_next("proof");
    let result = install::install(&paths, &options, true);
    forced::fail_the_next("none");
    let failure = result
        .expect_err("the forced failure of the read stops the repair")
        .to_string();
    observed(&format!("repair: install returned: {failure}"));
    assert!(
        failure.contains("was not marked for removal and was left where the rename put it"),
        "the failure does not say that the record was left: {failure}"
    );

    // The record at its name is readable and is the new one: it lists the second person, whom the
    // earlier record did not.
    let kept = Manifest::load(&paths.manifest)
        .expect("the manifest at its name is readable after the failed read");
    assert!(
        kept.persons.contains(&second_text),
        "the manifest at its name is not the one that the repair wrote: {kept:?}"
    );
    assert!(
        kept.persons.contains(&first_text),
        "the new manifest lost the first person: {kept:?}"
    );

    no_replacement_file_stands(&paths, "after the repair whose read failed");

    // A repair by the same person with nothing forced, with the broker running, runs to its end.
    let repaired = install::install(&paths, &options, true);
    observed(&format!(
        "repair with nothing forced: install returned: {}",
        repaired
            .as_ref()
            .err()
            .map_or_else(|| "Ok".to_owned(), ToString::to_string)
    ));
    no_replacement_file_stands(&paths, "after the repair with nothing forced");
    both_records_open_for_read_write_and_delete(&paths, "after the repair with nothing forced");

    // The administrator's removal runs to its end and the computer is as it was.
    let (code, text) = run_setup(&["remove"], &[], None);
    println!("--- kr-boundary-setup remove -> {code:?}\n{text}");
    let _ = account::delete(&first_name);
    let _ = account::delete(&second_name);
    assert!(repaired.is_ok(), "the repair with nothing forced failed");
    assert_eq!(code, Some(0), "the removal succeeds: {text}");
    assert_eq!(
        snapshot(),
        before,
        "after the removal the computer is as it was: {text}"
    );
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see windows_install.rs)"]
fn a_new_installation_that_fails_after_the_broker_step_is_rolled_back_and_prints_its_one_ending() {
    let _one_at_a_time = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    assert!(
        token::current_is_administrator().unwrap(),
        "the case must run elevated"
    );
    let before = snapshot();
    assert_clean(&before);
    let id = &uuid::Uuid::new_v4().simple().to_string()[..6];
    let person_name = format!("krperson{id}");
    let person = account::create(&person_name).expect("the person's account is made");
    let (code, text) = run_setup(
        &["install", "--person", &person.to_text().unwrap()],
        &[("KR_BOUNDARY_FAIL_AFTER", "broker")],
        None,
    );
    println!("--- kr-boundary-setup install, failure after the broker step -> {code:?}\n{text}");
    let _ = account::delete(&person_name);
    assert_ne!(code, Some(0), "{text}");
    assert!(
        text.contains("undoing what was done")
            && text.contains("the removal after the failure finished")
            && !text.contains("also failed"),
        "the rollback did not end without a failure: {text}"
    );
    assert_eq!(
        snapshot(),
        before,
        "after the rollback the computer is as it was: {text}"
    );
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see windows_install.rs)"]
fn a_rollback_that_cannot_mark_the_data_directory_names_what_stays_and_does_not_say_it_finished() {
    use std::os::windows::fs::OpenOptionsExt as _;
    let _one_at_a_time = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    assert!(
        token::current_is_administrator().unwrap(),
        "the case must run elevated"
    );
    let before = snapshot();
    assert_clean(&before);
    let paths = Paths::system().unwrap();
    let id = &uuid::Uuid::new_v4().simple().to_string()[..6];
    let person_name = format!("krperson{id}");
    let person = account::create(&person_name).expect("the person's account is made");
    let child = start_setup(
        &["install", "--person", &person.to_text().unwrap()],
        &[("KR_BOUNDARY_FAIL_AFTER", "broker")],
        None,
    );
    let reader = std::thread::spawn(move || child.wait_with_output().unwrap());
    // Once the run has made its directories and the manifest, a file of this case's own is made in
    // the data directory and held open with no sharing of delete across the whole rollback.
    let stray = paths.data.join("stray-of-the-case.txt");
    let mut held = None;
    let give_up = std::time::Instant::now() + std::time::Duration::from_secs(600);
    while !reader.is_finished() && std::time::Instant::now() < give_up {
        if held.is_none() && paths.data.join("run").exists() && paths.manifest.exists() {
            held = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .share_mode(1)
                .open(&stray)
                .ok();
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    let output = reader.join().unwrap();
    let (code, text) = ended(&output);
    println!(
        "--- kr-boundary-setup install, failure after the broker step, a file held in the data directory -> {code:?}\n{text}"
    );
    let made_the_stray = held.is_some();
    drop(held);
    observed(&format!(
        "after the rollback: {}",
        disk_of_the_data_tree(&paths)
    ));
    // Back to the earlier state: the file goes, and the administrator's removal runs to its end.
    let _ = std::fs::remove_file(&stray);
    let (removal_code, removal) = run_setup(&["remove"], &[], None);
    println!("--- kr-boundary-setup remove -> {removal_code:?}\n{removal}");
    let _ = account::delete(&person_name);
    assert!(
        made_the_stray,
        "the case made no file in the data directory: {text}"
    );
    assert_ne!(code, Some(0), "{text}");
    assert!(
        text.contains("the removal after the failure also failed"),
        "the rollback did not say that it failed: {text}"
    );
    assert!(
        !text.contains("the removal after the failure finished")
            && !text.contains("records are deleted"),
        "the rollback says it finished or deleted records: {text}"
    );
    assert_eq!(
        removal_code,
        Some(0),
        "the removal after it succeeds: {removal}"
    );
    assert_eq!(
        snapshot(),
        before,
        "after the removal the computer is as it was: {removal}"
    );
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see windows_install.rs)"]
fn a_failure_of_the_earlier_state_record_in_a_new_installation_is_rolled_back_clean() {
    let _one_at_a_time = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    assert!(
        token::current_is_administrator().unwrap(),
        "the case must run elevated"
    );
    let options = Options {
        payload: bin_directory().join("payload"),
        person: None,
    };
    let paths = Paths::system().unwrap();
    // The write of the record, its flush and the taking of its identity each fail once.
    for point in ["prior", "prior-flush", "prior-identity"] {
        let before = snapshot();
        assert_clean(&before);
        println!("OBSERVED prior {point}: the setup program's own lines follow");
        forced::fail_the_next(point);
        let result = install::install(&paths, &options, false);
        forced::fail_the_next("none");
        println!("OBSERVED prior {point}: the setup program's own lines end");
        let failure = result
            .expect_err("the forced failure stops the installation")
            .to_string();
        observed(&format!("prior {point}: install returned: {failure}"));
        observed(&format!(
            "prior {point}: after the run: {}",
            disk_of_the_data_tree(&paths)
        ));
        assert!(
            failure.contains(&format!(
                "the earlier-state record could not be written: a failure forced for a case at the step {point}"
            )),
            "{point}: {failure}"
        );
        assert!(
            !paths.data_parent().exists() && !paths.data.exists(),
            "{point}: the data directory or the folder above it stands: {failure}"
        );
        assert_eq!(
            snapshot(),
            before,
            "{point}: after the rollback the computer is as it was: {failure}"
        );
    }
}

/// One installation by the setup program, for a person made for the run, with the given test
/// variables. Returns the exit code and the output; the person is deleted again.
fn an_installation_with(environment: &[(&str, &str)]) -> (Option<i32>, String) {
    let id = &uuid::Uuid::new_v4().simple().to_string()[..6];
    let person_name = format!("krperson{id}");
    let person = account::create(&person_name).expect("the person's account is made");
    let (code, text) = run_setup(
        &["install", "--person", &person.to_text().unwrap()],
        environment,
        None,
    );
    println!("--- kr-boundary-setup install {environment:?} -> {code:?}\n{text}");
    let _ = account::delete(&person_name);
    (code, text)
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see windows_install.rs)"]
fn a_failure_after_the_application_identity_step_leaves_that_service_as_it_was_before_the_run() {
    let _one_at_a_time = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    assert!(
        token::current_is_administrator().unwrap(),
        "the case must run elevated"
    );
    let before = snapshot();
    assert_clean(&before);
    observed(&format!(
        "before the run the Application Identity service runs: {}, start type {}",
        before.appid_running, before.appid_start
    ));
    let (code, text) = an_installation_with(&[("KR_BOUNDARY_FAIL_AFTER", "appid")]);
    assert_ne!(code, Some(0), "{text}");
    assert!(
        text.contains("a failure was injected after the appid step")
            && text.contains("the removal after the failure finished")
            && !text.contains("also failed"),
        "the rollback did not end without a failure: {text}"
    );
    observed(&format!(
        "after the rollback the Application Identity service runs: {}",
        snapshot().appid_running
    ));
    assert_eq!(
        snapshot(),
        before,
        "after the rollback the computer is as it was: {text}"
    );
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see windows_install.rs)"]
fn an_account_that_stood_at_its_name_when_the_run_made_it_is_not_undone_by_the_rollback() {
    let _one_at_a_time = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    assert!(
        token::current_is_administrator().unwrap(),
        "the case must run elevated"
    );
    let before = snapshot();
    assert_clean(&before);
    let (code, text) = an_installation_with(&[("KR_BOUNDARY_MAKE_AFTER", "payload:account")]);
    let account_stands = account::find(CHECKOUT).unwrap().is_some();
    observed(&format!(
        "after the rollback the account {CHECKOUT} stands: {account_stands}"
    ));
    // The case's own cleanup: the account that the case made through the test seam.
    let _ = account::delete(CHECKOUT);
    assert_ne!(code, Some(0), "{text}");
    assert!(
        text.contains("making the account") && text.contains("2224"),
        "the run did not end at the making of the account with error 2224: {text}"
    );
    assert!(
        !text.contains(&format!("account {CHECKOUT} is removed")),
        "the rollback says that it removed an account that it did not make: {text}"
    );
    assert!(
        account_stands,
        "the rollback took away an account that the run did not make: {text}"
    );
    // The rollback's check says that the account stands there and that this run did not make it, and
    // the rollback ends without a failure: the data directory and the folder above it are gone.
    assert!(
        text.contains(&format!(
            "the account {CHECKOUT} stands there and this run did not make it"
        )) && text.contains("the removal after the failure finished")
            && !text.contains("also failed"),
        "the rollback did not end cleanly with the account left: {text}"
    );
    assert_eq!(
        snapshot(),
        before,
        "after the case's own cleanup the computer is as it was: {text}"
    );
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see windows_install.rs)"]
fn a_service_that_stood_at_the_brokers_name_when_the_run_made_it_is_not_undone_by_the_rollback() {
    let _one_at_a_time = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    assert!(
        token::current_is_administrator().unwrap(),
        "the case must run elevated"
    );
    let before = snapshot();
    assert_clean(&before);
    let (code, text) = an_installation_with(&[("KR_BOUNDARY_MAKE_AFTER", "accounts:service")]);
    let service_stands = service::manager()
        .unwrap()
        .open(SERVICE)
        .unwrap()
        .is_some_and(|service| !service.marked_for_deletion().unwrap());
    observed(&format!(
        "after the rollback the service {SERVICE} stands: {service_stands}"
    ));
    // The case's own cleanup: the service that the case made through the test seam.
    let removed = Command::new("sc.exe")
        .args(["delete", SERVICE])
        .output()
        .unwrap();
    observed(&format!(
        "sc delete: {}",
        String::from_utf8_lossy(&removed.stdout).trim()
    ));
    assert_ne!(code, Some(0), "{text}");
    assert!(
        text.contains(&format!(
            "a service named {SERVICE} stood on this computer when this run was to make it"
        )),
        "the run did not end at the service that stood there: {text}"
    );
    assert!(
        service_stands,
        "the rollback took away a service that the run did not make: {text}"
    );
    assert!(
        text.contains("the broker's service stands there and this run did not make it")
            && text.contains("the removal after the failure finished")
            && !text.contains("also failed"),
        "the rollback did not end cleanly with the service left: {text}"
    );
    assert_eq!(
        snapshot(),
        before,
        "after the case's own cleanup the computer is as it was: {text}"
    );
}
