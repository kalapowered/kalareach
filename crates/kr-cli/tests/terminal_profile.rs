//! The optional terminal profile, KR-REQ-01.21 and KR-REQ-07.42: one profile named `KalaReach`
//! in one terminal application's own profile mechanism, whose command is `kr new --attach
//! --hold-on-failure`, written without touching the person's other profiles or their shell startup
//! files, and taken out again by the record alone.
//!
//! Two kinds of case. The writer cases call the library with a home description of their own and
//! run on every platform, so the formats are checked wherever the suite runs. The command cases
//! run the real `kr` and only for the terminal applications of their platform.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use kr_shell_integration::host::terminal_profile::record::{
    PROFILE_RECORD_NAME, PROFILE_WRITTEN, ProfileRecord, Wrote,
};
use kr_shell_integration::host::terminal_profile::{
    self as profile, Place, ProfileError, ProfileHome, ProfileTerminal, Removed,
};

mod support;

/// The command a profile runs in these cases: a `kr` in a directory whose name holds a space, as
/// the macOS store's does.
fn command_in(directory: &Path) -> Vec<String> {
    [
        directory
            .join("kr dir")
            .join("kr")
            .to_str()
            .expect("a path that is text"),
        "new",
        "--attach",
        "--hold-on-failure",
    ]
    .map(str::to_owned)
    .to_vec()
}

/// What a person has on their machine: a home, the directories programs are found in, and the
/// installation's own directories.
struct Person {
    /// The host's directories, which hold the record.
    tree: kr_ipc::testing::TempHost,
    /// The home directory.
    home: PathBuf,
    /// A directory a `konsole` program stands in, when the person has Konsole.
    programs: PathBuf,
}

impl Person {
    /// A person with a home of their own and no terminal application installed.
    fn new() -> Self {
        let tree = kr_ipc::testing::TempHost::create();
        let home = tree.root().join("home");
        let programs = tree.root().join("programs");
        for directory in [&home, &programs] {
            std::fs::create_dir_all(directory).expect("a directory");
        }
        Self {
            tree,
            home,
            programs,
        }
    }

    /// The same person, with Konsole installed.
    fn with_konsole() -> Self {
        let person = Self::new();
        std::fs::write(person.programs.join("konsole"), b"#!/bin/sh\n").expect("a program");
        person
    }

    fn places(&self) -> ProfileHome {
        ProfileHome::under(&self.home, vec![self.programs.clone()])
    }

    fn record(&self) -> ProfileRecord {
        ProfileRecord::in_state_directory(self.tree.paths().state_root())
    }

    /// The Konsole profile file.
    fn konsole_profile(&self) -> PathBuf {
        self.home.join(".local/share/konsole/KalaReach.profile")
    }

    /// Everything under the home and the state directory, with each file's contents.
    fn everything(&self) -> BTreeMap<PathBuf, Option<Vec<u8>>> {
        let mut found = BTreeMap::new();
        for root in [&self.home, self.tree.paths().state_root()] {
            collect(root, root, &mut found);
        }
        found
    }

    /// The home alone.
    fn home_only(&self) -> BTreeMap<PathBuf, Option<Vec<u8>>> {
        let mut found = BTreeMap::new();
        collect(&self.home, &self.home, &mut found);
        found
    }

    /// Installs the Konsole profile as the command does: the writers' lock and the record held
    /// for the whole install.
    fn install(&self, command: &[String]) -> Result<(), ProfileError> {
        // An application that is not there is refused before anything is held or written.
        if !profile::is_present(ProfileTerminal::Konsole, &self.places()) {
            return Err(ProfileError::NotInstalled(ProfileTerminal::Konsole));
        }
        let writers = kr_cli::barrier::hold(self.tree.paths()).expect("the writers' lock");
        let permit = kr_cli::barrier::permit(&writers, &PROFILE_WRITTEN).expect("a permit");
        let record = self.record();
        let held = record.hold(&permit).expect("holds the record");
        let recorded = held.profile(ProfileTerminal::Konsole)?;
        let plan = profile::plan(
            ProfileTerminal::Konsole,
            &self.places(),
            command,
            recorded.as_ref(),
        )?;
        profile::install(&held, &plan)
    }

    /// Removes the Konsole profile as the command does.
    fn remove(&self) -> Result<Removed, ProfileError> {
        let writers = kr_cli::barrier::hold(self.tree.paths()).expect("the writers' lock");
        let permit = kr_cli::barrier::permit(&writers, &PROFILE_WRITTEN).expect("a permit");
        let record = self.record();
        let held = record.hold(&permit).expect("holds the record");
        profile::remove(&held, ProfileTerminal::Konsole, &self.places())
    }
}

/// Every file and directory under `directory`, by its path from `root`; a file with its bytes.
fn collect(root: &Path, directory: &Path, found: &mut BTreeMap<PathBuf, Option<Vec<u8>>>) {
    for entry in std::fs::read_dir(directory).into_iter().flatten().flatten() {
        let path = entry.path();
        let relative = path
            .strip_prefix(root)
            .expect("under the root")
            .to_path_buf();
        if path.is_dir() {
            found.insert(relative, None);
            collect(root, &path, found);
        } else {
            found.insert(
                relative,
                Some(std::fs::read(&path).expect("a readable file")),
            );
        }
    }
}

/// What the person's own Konsole holds: a profile of their own and a default that is not ours.
fn seed_konsole(person: &Person) {
    let konsole = person.home.join(".local/share/konsole");
    std::fs::create_dir_all(&konsole).expect("Konsole's directory");
    std::fs::write(konsole.join("Shell.profile"), "[General]\nName=Shell\n").expect("a profile");
    std::fs::create_dir_all(person.home.join(".config")).expect("a directory");
    std::fs::write(
        person.home.join(".config/konsolerc"),
        "[Desktop Entry]\nDefaultProfile=Shell.profile\n",
    )
    .expect("Konsole's settings");
}

/// KR-REQ-01.21, KR-REQ-07.42: an install adds the profile file and nothing else to a home that
/// has Konsole profiles of its own, leaves those profiles and the default as they were, records
/// what it wrote, and a removal puts the home back as it was.
#[test]
fn an_install_adds_one_file_and_a_removal_puts_the_home_back() {
    let person = Person::with_konsole();
    seed_konsole(&person);
    let command = command_in(person.tree.root());
    let before = person.home_only();

    person.install(&command).expect("installs");

    let mut expected = before.clone();
    let profile_text = std::fs::read(person.konsole_profile()).expect("the profile is written");
    expected.insert(
        PathBuf::from(".local/share/konsole/KalaReach.profile"),
        Some(profile_text),
    );
    assert_eq!(
        person.home_only(),
        expected,
        "the home gains the profile file alone"
    );
    let recorded = person.record().profiles().expect("the record reads");
    assert_eq!(recorded.len(), 1);
    assert_eq!(recorded[0].command, command);
    assert!(matches!(recorded[0].wrote, Wrote::File(_)));
    assert!(
        person
            .tree
            .paths()
            .state_root()
            .join(PROFILE_RECORD_NAME)
            .is_file(),
        "the record is in the state root"
    );
    assert!(
        person
            .tree
            .paths()
            .state_root()
            .join(format!(".{PROFILE_RECORD_NAME}.kalareach-lock"))
            .is_file(),
        "and its lock beside it"
    );

    assert_eq!(person.remove().expect("removes"), Removed::Removed);
    assert_eq!(person.home_only(), before, "the home is as it was");
    assert!(person.record().profiles().expect("reads").is_empty());
}

/// KR-REQ-01.21: a home that has no Konsole directory yet gets it made for the profile, and a
/// removal takes the directory away again with the profile, because kr made it and it is empty.
#[test]
fn a_directory_the_install_made_goes_with_the_profile() {
    let person = Person::with_konsole();
    let before = person.home_only();
    person
        .install(&command_in(person.tree.root()))
        .expect("installs");
    assert!(person.konsole_profile().is_file());
    assert_eq!(person.remove().expect("removes"), Removed::Removed);
    assert_eq!(person.home_only(), before, "no directory is left behind");
}

/// A directory the install made is not removed once the person has put something in it.
#[test]
fn a_directory_with_the_persons_own_file_in_it_stays() {
    let person = Person::with_konsole();
    person
        .install(&command_in(person.tree.root()))
        .expect("installs");
    let theirs = person.home.join(".local/share/konsole/Mine.profile");
    std::fs::write(&theirs, "[General]\nName=Mine\n").expect("a profile of their own");
    assert_eq!(person.remove().expect("removes"), Removed::Removed);
    assert!(theirs.is_file(), "their profile is theirs");
    assert!(!person.konsole_profile().exists());
}

/// KR-REQ-01.21: a terminal application that is not installed is refused, and nothing is written,
/// not even a directory.
#[test]
fn a_terminal_application_that_is_not_installed_is_refused_with_nothing_written() {
    let person = Person::new();
    let before = person.everything();
    let refused = person.install(&command_in(person.tree.root()));
    assert!(
        matches!(
            refused,
            Err(ProfileError::NotInstalled(ProfileTerminal::Konsole))
        ),
        "{refused:?}"
    );
    let planned = profile::plan(
        ProfileTerminal::Konsole,
        &person.places(),
        &command_in(person.tree.root()),
        None,
    );
    assert!(matches!(planned, Err(ProfileError::NotInstalled(_))));
    assert_eq!(person.everything(), before);
}

/// A file at the profile's place that kr did not write is refused and left as it is, and the
/// record names nothing for it.
#[test]
fn a_profile_by_hand_at_the_place_is_refused_and_left() {
    let person = Person::with_konsole();
    seed_konsole(&person);
    std::fs::write(
        person.konsole_profile(),
        "[General]\nName=KalaReach\nCommand=/bin/zsh\n",
    )
    .expect("a profile by hand");
    let before = person.home_only();
    let refused = person.install(&command_in(person.tree.root()));
    assert!(
        matches!(refused, Err(ProfileError::Foreign { .. })),
        "{refused:?}"
    );
    assert_eq!(person.home_only(), before);
    assert!(person.record().profiles().expect("reads").is_empty());
    // Nor does a removal touch it: the record names nothing.
    assert_eq!(person.remove().expect("removes"), Removed::NotRecorded);
    assert_eq!(person.home_only(), before);
}

/// KR-REQ-01.21: a profile that was changed after kr wrote it is left, named, and forgotten by the
/// record; an install over it is refused until it is gone.
#[test]
fn a_profile_changed_after_it_was_written_is_left_and_forgotten() {
    let person = Person::with_konsole();
    let command = command_in(person.tree.root());
    person.install(&command).expect("installs");
    std::fs::write(
        person.konsole_profile(),
        "[General]\nName=KalaReach\nCommand=/bin/zsh\n",
    )
    .expect("the person edits it");
    let before = person.home_only();

    let refused = person.install(&command);
    assert!(
        matches!(refused, Err(ProfileError::Changed { .. })),
        "{refused:?}"
    );
    assert_eq!(
        person.home_only(),
        before,
        "an install over it writes nothing"
    );

    let removed = person.remove().expect("removes");
    assert!(matches!(removed, Removed::Changed { .. }), "{removed:?}");
    assert_eq!(
        person.home_only(),
        before,
        "the changed file is as the person left it"
    );
    assert!(person.record().profiles().expect("reads").is_empty());
}

/// A profile that is gone is forgotten by a removal and written again by an install.
#[test]
fn a_profile_that_is_gone_is_forgotten_and_can_be_written_again() {
    let person = Person::with_konsole();
    let command = command_in(person.tree.root());
    person.install(&command).expect("installs");
    std::fs::remove_file(person.konsole_profile()).expect("the person deletes it");
    // Written again, with the record still naming it.
    person.install(&command).expect("installs again");
    assert!(person.konsole_profile().is_file());
    std::fs::remove_file(person.konsole_profile()).expect("deleted again");
    assert_eq!(person.remove().expect("removes"), Removed::AlreadyGone);
    assert!(person.record().profiles().expect("reads").is_empty());
}

/// KR-REQ-01.21: a profile that is Konsole's default is left on removal and the record keeps it,
/// and is taken out once another profile is the default.
#[test]
fn a_profile_that_is_the_default_is_left_and_kept_in_the_record() {
    let person = Person::with_konsole();
    seed_konsole(&person);
    person
        .install(&command_in(person.tree.root()))
        .expect("installs");
    let settings = person.home.join(".config/konsolerc");
    std::fs::write(
        &settings,
        "[Desktop Entry]\nDefaultProfile=KalaReach.profile\n",
    )
    .expect("the person makes it the default");
    assert_eq!(person.remove().expect("removes"), Removed::Default);
    assert!(person.konsole_profile().is_file(), "the profile is left");
    assert_eq!(
        person.record().profiles().expect("reads").len(),
        1,
        "and kept in the record"
    );

    std::fs::write(&settings, "[Desktop Entry]\nDefaultProfile=Shell.profile\n").expect("changed");
    assert_eq!(person.remove().expect("removes"), Removed::Removed);
    assert!(!person.konsole_profile().exists());
}

/// An install again over an unchanged profile rewrites it, for a different command, and the record
/// follows the file.
#[test]
fn an_install_again_over_an_unchanged_profile_rewrites_it() {
    let person = Person::with_konsole();
    person
        .install(&command_in(person.tree.root()))
        .expect("installs");
    let other = command_in(&person.tree.root().join("elsewhere"));
    person.install(&other).expect("installs again");
    let text = std::fs::read_to_string(person.konsole_profile()).expect("the profile");
    assert!(text.contains("elsewhere"), "{text}");
    assert_eq!(person.record().profiles().expect("reads")[0].command, other);
    assert_eq!(
        person.remove().expect("removes"),
        Removed::Removed,
        "the record matches the file"
    );
}

/// KR-REQ-01.21: installs and removals at once leave a profile if and only if the record names it.
#[test]
fn installs_and_removals_at_once_leave_no_profile_the_record_does_not_name() {
    let person = Person::with_konsole();
    let command = command_in(person.tree.root());
    std::thread::scope(|scope| {
        for round in 0..8 {
            let (person, command) = (&person, &command);
            scope.spawn(move || {
                for _ in 0..4 {
                    if round % 2 == 0 {
                        // Another thread may have installed already, which is a refusal of its own
                        // kind only when the file is not ours; here it is, and the install
                        // rewrites it.
                        person.install(command).expect("installs");
                    } else {
                        person.remove().expect("removes");
                    }
                }
            });
        }
    });
    let named = !person.record().profiles().expect("reads").is_empty();
    assert_eq!(
        person.konsole_profile().exists(),
        named,
        "a profile exists if the record names it"
    );
    if named {
        person.remove().expect("removes");
    }
    assert!(!person.konsole_profile().exists());
}

/// What a plan says it writes is the file.
#[test]
fn the_plan_names_the_file_it_writes() {
    let person = Person::with_konsole();
    let plan = profile::plan(
        ProfileTerminal::Konsole,
        &person.places(),
        &command_in(person.tree.root()),
        None,
    )
    .expect("a plan");
    assert_eq!(plan.place(), Place::File(&person.konsole_profile()));
}

#[cfg(target_os = "linux")]
mod command {
    //! The real `kr`, for the terminal applications Linux has.

    use super::*;

    /// A `kr host terminal-profile` run for a person, with their home and the host's directories,
    /// and the programs they have on their path.
    fn run(person: &Person, arguments: &[&str]) -> (std::process::Output, String) {
        let output = std::process::Command::new(support::kr())
            .args(["host", "terminal-profile"])
            .args(arguments)
            .env_clear()
            // Only the person's own programs: what the machine this runs on has installed is not
            // what is being asked about.
            .env("PATH", &person.programs)
            .env("HOME", &person.home)
            .env("SHELL", "/bin/sh")
            .env("KR_RUNTIME_DIR", person.tree.paths().runtime_root())
            .env("KR_STATE_DIR", person.tree.paths().state_root())
            .current_dir(&person.home)
            .stdin(std::process::Stdio::null())
            .output()
            .expect("kr runs");
        let said = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        (output, said)
    }

    /// The JSON a run printed.
    fn document(output: &std::process::Output) -> serde_json::Value {
        serde_json::from_slice(&output.stdout).expect("a JSON document")
    }

    /// KR-REQ-01.21, KR-REQ-26.04: the command installs the Konsole profile and writes nothing else
    /// of its own: no shell startup file, no record of startup entries, no service definition.
    /// Status reads it, a dry run writes nothing, and the removal puts the home back.
    #[test]
    fn the_command_installs_reads_and_removes_the_konsole_profile_alone() {
        let person = Person::with_konsole();
        seed_konsole(&person);
        let before = person.everything();

        let (output, said) = run(&person, &["status", "--json"]);
        assert!(output.status.success(), "{said}");
        let status = document(&output);
        assert_eq!(status["terminals"][0]["terminal"], "konsole");
        assert_eq!(status["terminals"][0]["installed"], true);
        assert_eq!(status["terminals"][0]["profile"], "none");
        assert_eq!(person.everything(), before, "status writes nothing");

        let (output, said) = run(&person, &["install", "konsole", "--dry-run", "--json"]);
        assert!(output.status.success(), "{said}");
        assert_eq!(document(&output)["dry_run"], true);
        assert_eq!(person.everything(), before, "a dry run writes nothing");

        let (output, said) = run(&person, &["install", "konsole", "--json"]);
        assert!(output.status.success(), "{said}");
        let installed = document(&output);
        assert_eq!(installed["terminal"], "konsole");
        assert_eq!(installed["default"], false);
        let program = installed["command"][0].as_str().expect("the program");
        assert_eq!(installed["command"][1], "new");
        assert_eq!(installed["command"][2], "--attach");
        assert_eq!(installed["command"][3], "--hold-on-failure");
        assert!(
            std::fs::read_to_string(person.konsole_profile())
                .expect("the profile")
                .contains(program),
            "the profile runs the command the output names"
        );
        let after = person.everything();
        let added: Vec<_> = after
            .keys()
            .filter(|path| !before.contains_key(*path))
            .map(|path| path.display().to_string())
            .collect();
        assert!(
            added.iter().all(|path| path.ends_with("KalaReach.profile")
                || path.ends_with(PROFILE_RECORD_NAME)
                || path.ends_with(&format!(".{PROFILE_RECORD_NAME}.kalareach-lock"))
                || path.ends_with("konsole")),
            "an install adds the profile, its record and the record's lock: {added:?}"
        );
        assert!(
            !after.keys().any(|path| {
                let path = path.display().to_string();
                path.contains("shell-entries")
                    || path.contains(".zshrc")
                    || path.contains(".bashrc")
            }),
            "and no shell startup entry or its record"
        );
        for (path, contents) in &before {
            assert_eq!(
                after.get(path),
                Some(contents),
                "{} is as it was",
                path.display()
            );
        }

        let (output, said) = run(&person, &["status", "--json"]);
        assert!(output.status.success(), "{said}");
        assert_eq!(document(&output)["terminals"][0]["profile"], "matches");

        let (output, said) = run(&person, &["remove", "--json"]);
        assert!(output.status.success(), "{said}");
        assert_eq!(document(&output)["profiles"][0]["result"], "removed");
        assert_eq!(person.home_only(), {
            let mut home = BTreeMap::new();
            collect(&person.home, &person.home, &mut home);
            home
        });
        assert!(!person.konsole_profile().exists());
        assert!(person.record().profiles().expect("reads").is_empty());
    }

    /// KR-REQ-01.21: Konsole not installed is refused with a message, an application of another
    /// platform is refused as a usage mistake, and neither writes anything.
    #[test]
    fn the_command_refuses_what_is_not_installed_and_what_is_not_on_this_platform() {
        let person = Person::new();
        let before = person.everything();
        let (output, said) = run(&person, &["install", "konsole"]);
        assert_eq!(output.status.code(), Some(7), "{said}");
        assert!(said.contains("Konsole is not installed"), "{said}");
        let (output, said) = run(&person, &["install", "iterm2"]);
        assert_eq!(output.status.code(), Some(2), "{said}");
        let (output, said) = run(&person, &["install", "xterm"]);
        assert_eq!(output.status.code(), Some(2), "{said}");
        assert_eq!(person.everything(), before, "nothing was written");
    }

    /// KR-REQ-01.21: an edited profile is left by `remove`, which says so and exits as a success,
    /// and a profile by hand at the place is refused by `install`.
    #[test]
    fn the_command_leaves_what_the_person_changed_and_refuses_what_is_not_kr_s() {
        let person = Person::with_konsole();
        std::fs::create_dir_all(person.konsole_profile().parent().expect("a directory"))
            .expect("Konsole's directory");
        std::fs::write(person.konsole_profile(), "[General]\nName=KalaReach\n").expect("by hand");
        let (output, said) = run(&person, &["install", "konsole"]);
        assert_eq!(output.status.code(), Some(2), "{said}");
        assert!(said.contains("kr did not write it"), "{said}");
        std::fs::remove_file(person.konsole_profile()).expect("removed");

        let (output, said) = run(&person, &["install", "konsole"]);
        assert!(output.status.success(), "{said}");
        std::fs::write(
            person.konsole_profile(),
            "[General]\nName=KalaReach\nCommand=x\n",
        )
        .expect("edited");
        let (output, said) = run(&person, &["remove"]);
        assert!(output.status.success(), "{said}");
        assert!(said.contains("no longer kr's to remove"), "{said}");
        assert!(
            person.konsole_profile().is_file(),
            "the edited file is left"
        );
    }
}
