//! The optional terminal profile, KR-REQ-01.21 and KR-REQ-07.42: one profile named `KalaReach`
//! in one terminal application's own profile mechanism, whose command is `kr new --attach
//! --hold-on-failure`, written without touching the person's other profiles or their shell startup
//! files, and taken out again by the record alone.
//!
//! Two kinds of case. The writer cases call the library with a home description of their own, for
//! each terminal application whose profile is a file, and run on every platform, so the formats are
//! checked wherever the suite runs. The command cases run the real `kr` and only for the terminal
//! application of their platform.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use kr_shell_integration::host::terminal_profile::record::{
    PROFILE_RECORD_NAME, PROFILE_WRITTEN, ProfileRecord, Wrote,
};
use kr_shell_integration::host::terminal_profile::{
    self as profile, Place, ProfileError, ProfileHome, ProfileTerminal, Removed,
};

mod support;

/// A terminal application whose profile is a file, and what a test does to its places.
struct Application {
    terminal: ProfileTerminal,
    /// Puts the application on the person's machine.
    install: fn(&Person),
    /// The profile file the application reads.
    profile: fn(&Person) -> PathBuf,
    /// A profile of the person's own, and the default it leaves.
    seed: fn(&Person),
    /// Makes the profile kr wrote the application's default, or puts the default back to the
    /// person's own; `None` where this platform cannot do it for the application.
    default: Option<fn(&Person, bool)>,
}

/// Makes the iTerm2 profile kr wrote iTerm2's default, or the person's own profile its default.
///
/// The preference is written to a file of this test's own, by path, which is not the person's
/// domain.
fn iterm2_default(person: &Person, ours: bool) {
    let preferences = person.home.join("domains/com.googlecode.iterm2");
    std::fs::create_dir_all(preferences.parent().expect("a directory")).expect("a directory");
    let guid = if ours {
        let text = std::fs::read_to_string(
            person
                .home
                .join("Library/Application Support/iTerm2/DynamicProfiles/KalaReach.json"),
        )
        .expect("the profile");
        let document: serde_json::Value = serde_json::from_str(&text).expect("JSON");
        document["Profiles"][0]["Guid"]
            .as_str()
            .expect("a Guid")
            .to_owned()
    } else {
        "THE-PERSONS-OWN".to_owned()
    };
    let status = std::process::Command::new("/usr/bin/defaults")
        .args(["write"])
        .arg(&preferences)
        .args(["Default Bookmark Guid", "-string", &guid])
        .status()
        .expect("defaults runs");
    assert!(
        status.success(),
        "defaults wrote the file of this test's own"
    );
}

/// Every application whose profile is a file, on every platform.
fn applications() -> Vec<Application> {
    vec![
        Application {
            terminal: ProfileTerminal::Konsole,
            install: |person| {
                std::fs::write(person.programs.join("konsole"), b"#!/bin/sh\n").expect("a program");
            },
            profile: |person| person.home.join(".local/share/konsole/KalaReach.profile"),
            seed: |person| {
                let konsole = person.home.join(".local/share/konsole");
                std::fs::create_dir_all(&konsole).expect("Konsole's directory");
                std::fs::write(konsole.join("Shell.profile"), "[General]\nName=Shell\n")
                    .expect("a profile");
                std::fs::create_dir_all(person.home.join(".config")).expect("a directory");
                std::fs::write(
                    person.home.join(".config/konsolerc"),
                    "[Desktop Entry]\nDefaultProfile=Shell.profile\n",
                )
                .expect("Konsole's settings");
            },
            default: Some(|person, ours| {
                let which = if ours {
                    "KalaReach.profile"
                } else {
                    "Shell.profile"
                };
                std::fs::write(
                    person.home.join(".config/konsolerc"),
                    format!("[Desktop Entry]\nDefaultProfile={which}\n"),
                )
                .expect("Konsole's settings");
            }),
        },
        Application {
            terminal: ProfileTerminal::Iterm2,
            install: |person| {
                std::fs::create_dir_all(person.home.join("Applications/iTerm.app"))
                    .expect("the application");
            },
            profile: |person| {
                person
                    .home
                    .join("Library/Application Support/iTerm2/DynamicProfiles/KalaReach.json")
            },
            seed: |person| {
                let folder = person
                    .home
                    .join("Library/Application Support/iTerm2/DynamicProfiles");
                std::fs::create_dir_all(&folder).expect("iTerm2's folder");
                std::fs::write(folder.join("mine.json"), "{\"Profiles\":[]}\n").expect("a profile");
            },
            default: if cfg!(target_os = "macos") {
                Some(iterm2_default)
            } else {
                None
            },
        },
        Application {
            terminal: ProfileTerminal::WindowsTerminal,
            install: |person| {
                std::fs::write(person.programs.join("wt.exe"), b"").expect("a program");
            },
            profile: |person| {
                person.home.join(
                    "AppData/Local/Microsoft/Windows Terminal/Fragments/KalaReach/kalareach.json",
                )
            },
            seed: |person| {
                let other = person
                    .home
                    .join("AppData/Local/Microsoft/Windows Terminal/Fragments/Other");
                std::fs::create_dir_all(&other).expect("a fragment folder");
                std::fs::write(other.join("other.json"), "{\"profiles\":[]}\n")
                    .expect("a fragment");
                std::fs::write(
                    person
                        .home
                        .join("AppData/Local/Microsoft/Windows Terminal/settings.json"),
                    "{\"defaultProfile\": \"Ubuntu\"}\n",
                )
                .expect("settings");
            },
            default: Some(|person, ours| {
                let which = if ours { "KalaReach" } else { "Ubuntu" };
                std::fs::write(
                    person
                        .home
                        .join("AppData/Local/Microsoft/Windows Terminal/settings.json"),
                    format!("// the person's settings\n{{\"defaultProfile\": \"{which}\"}}\n"),
                )
                .expect("settings");
            }),
        },
    ]
}

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
    /// A directory a stand-in for a program is put in.
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

    /// The same person, with the application installed.
    fn with(application: &Application) -> Self {
        let person = Self::new();
        (application.install)(&person);
        person
    }

    fn places(&self) -> ProfileHome {
        ProfileHome::under(&self.home, vec![self.programs.clone()])
    }

    fn record(&self) -> ProfileRecord {
        ProfileRecord::in_state_directory(self.tree.paths().state_root())
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

    /// Installs a profile as the command does: the writers' lock and the record held for the whole
    /// install.
    fn install(&self, terminal: ProfileTerminal, command: &[String]) -> Result<(), ProfileError> {
        // An application that is not there is refused before anything is held or written.
        if !profile::is_present(terminal, &self.places()) {
            return Err(ProfileError::NotInstalled(terminal));
        }
        let writers = kr_cli::barrier::hold(self.tree.paths()).expect("the writers' lock");
        let permit = kr_cli::barrier::permit(&writers, &PROFILE_WRITTEN).expect("a permit");
        let record = self.record();
        let held = record.hold(&permit).expect("holds the record");
        let recorded = held.profile(terminal)?;
        let plan = profile::plan(terminal, &self.places(), command, recorded.as_ref())?;
        profile::install(&held, &plan)
    }

    /// Removes a profile as the command does.
    fn remove(&self, terminal: ProfileTerminal) -> Result<Removed, ProfileError> {
        let writers = kr_cli::barrier::hold(self.tree.paths()).expect("the writers' lock");
        let permit = kr_cli::barrier::permit(&writers, &PROFILE_WRITTEN).expect("a permit");
        let record = self.record();
        let held = record.hold(&permit).expect("holds the record");
        profile::remove(&held, terminal, &self.places())
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

/// KR-REQ-01.21, KR-REQ-07.42: an install adds the profile file and nothing else to a home that
/// has profiles of its own, leaves those profiles and the default as they were, records what it
/// wrote, and a removal puts the home back as it was.
#[test]
fn an_install_adds_one_file_and_a_removal_puts_the_home_back() {
    for application in applications() {
        let person = Person::with(&application);
        (application.seed)(&person);
        let command = command_in(person.tree.root());
        let before = person.home_only();

        person
            .install(application.terminal, &command)
            .expect("installs");

        let mut expected = before.clone();
        let file = (application.profile)(&person);
        let text = std::fs::read(&file).expect("the profile is written");
        let relative = file
            .strip_prefix(&person.home)
            .expect("in the home")
            .to_path_buf();
        // The directories the install made on the way to the file are new too.
        for directory in relative.ancestors().skip(1) {
            if !directory.as_os_str().is_empty() && !before.contains_key(directory) {
                expected.insert(directory.to_path_buf(), None);
            }
        }
        expected.insert(relative, Some(text));
        assert_eq!(
            person.home_only(),
            expected,
            "{:?}: the home gains the profile file alone",
            application.terminal
        );
        let recorded = person.record().profiles().expect("the record reads");
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].terminal, application.terminal);
        assert_eq!(recorded[0].command, command);
        assert!(matches!(recorded[0].wrote, Wrote::File(_)));
        let state = person.tree.paths().state_root().to_path_buf();
        assert!(
            state.join(PROFILE_RECORD_NAME).is_file(),
            "the record is in the state root"
        );
        assert!(
            state
                .join(format!(".{PROFILE_RECORD_NAME}.kalareach-lock"))
                .is_file(),
            "and its lock beside it"
        );

        assert_eq!(
            person.remove(application.terminal).expect("removes"),
            Removed::Removed
        );
        assert_eq!(
            person.home_only(),
            before,
            "{:?}: the home is as it was",
            application.terminal
        );
        assert!(person.record().profiles().expect("reads").is_empty());
    }
}

/// KR-REQ-01.21: a home that has none of the application's directories gets them made for the
/// profile, and a removal takes them away again with the profile, because kr made them and they
/// are empty.
#[test]
fn directories_the_install_made_go_with_the_profile() {
    for application in applications() {
        let person = Person::with(&application);
        let before = person.home_only();
        person
            .install(application.terminal, &command_in(person.tree.root()))
            .expect("installs");
        assert!((application.profile)(&person).is_file());
        assert_eq!(
            person.remove(application.terminal).expect("removes"),
            Removed::Removed
        );
        assert_eq!(
            person.home_only(),
            before,
            "{:?}: nothing is left behind",
            application.terminal
        );
    }
}

/// A directory the install made is not removed once the person has put something in it.
#[test]
fn a_directory_with_the_persons_own_file_in_it_stays() {
    for application in applications() {
        let person = Person::with(&application);
        person
            .install(application.terminal, &command_in(person.tree.root()))
            .expect("installs");
        let theirs = (application.profile)(&person)
            .parent()
            .expect("a directory")
            .join("theirs.txt");
        std::fs::write(&theirs, "theirs").expect("a file of their own");
        assert_eq!(
            person.remove(application.terminal).expect("removes"),
            Removed::Removed
        );
        assert!(
            theirs.is_file(),
            "{:?}: their file is theirs",
            application.terminal
        );
        assert!(!(application.profile)(&person).exists());
    }
}

/// KR-REQ-01.21: a terminal application that is not installed is refused, and nothing is written,
/// not even a directory.
#[test]
fn a_terminal_application_that_is_not_installed_is_refused_with_nothing_written() {
    for application in applications() {
        let person = Person::new();
        let before = person.everything();
        let command = command_in(person.tree.root());
        let refused = person.install(application.terminal, &command);
        assert!(
            matches!(refused, Err(ProfileError::NotInstalled(terminal)) if terminal == application.terminal),
            "{refused:?}"
        );
        let planned = profile::plan(application.terminal, &person.places(), &command, None);
        assert!(matches!(planned, Err(ProfileError::NotInstalled(_))));
        assert_eq!(person.everything(), before);
    }
}

/// A file at the profile's place that kr did not write is refused and left as it is, and the
/// record names nothing for it.
#[test]
fn a_profile_by_hand_at_the_place_is_refused_and_left() {
    for application in applications() {
        let person = Person::with(&application);
        (application.seed)(&person);
        let file = (application.profile)(&person);
        std::fs::create_dir_all(file.parent().expect("a directory")).expect("a directory");
        std::fs::write(&file, "by hand").expect("a profile by hand");
        let before = person.home_only();
        let refused = person.install(application.terminal, &command_in(person.tree.root()));
        assert!(
            matches!(refused, Err(ProfileError::Foreign { .. })),
            "{refused:?}"
        );
        assert_eq!(person.home_only(), before);
        assert!(person.record().profiles().expect("reads").is_empty());
        // Nor does a removal touch it: the record names nothing.
        assert_eq!(
            person.remove(application.terminal).expect("removes"),
            Removed::NotRecorded
        );
        assert_eq!(person.home_only(), before);
    }
}

/// KR-REQ-01.21: a profile that was changed after kr wrote it is left, named, and forgotten by the
/// record; an install over it is refused.
#[test]
fn a_profile_changed_after_it_was_written_is_left_and_forgotten() {
    for application in applications() {
        let person = Person::with(&application);
        let command = command_in(person.tree.root());
        person
            .install(application.terminal, &command)
            .expect("installs");
        std::fs::write((application.profile)(&person), "the person edits it").expect("edited");
        let before = person.home_only();

        let refused = person.install(application.terminal, &command);
        assert!(
            matches!(refused, Err(ProfileError::Changed { .. })),
            "{refused:?}"
        );
        assert_eq!(
            person.home_only(),
            before,
            "an install over it writes nothing"
        );

        let removed = person.remove(application.terminal).expect("removes");
        assert!(matches!(removed, Removed::Changed { .. }), "{removed:?}");
        assert_eq!(
            person.home_only(),
            before,
            "the changed file is as the person left it"
        );
        assert!(person.record().profiles().expect("reads").is_empty());
    }
}

/// A profile that is gone is written again by an install and forgotten by a removal.
#[test]
fn a_profile_that_is_gone_is_forgotten_and_can_be_written_again() {
    for application in applications() {
        let person = Person::with(&application);
        let command = command_in(person.tree.root());
        person
            .install(application.terminal, &command)
            .expect("installs");
        std::fs::remove_file((application.profile)(&person)).expect("the person deletes it");
        // Written again, with the record still naming it.
        person
            .install(application.terminal, &command)
            .expect("installs again");
        assert!((application.profile)(&person).is_file());
        std::fs::remove_file((application.profile)(&person)).expect("deleted again");
        assert_eq!(
            person.remove(application.terminal).expect("removes"),
            Removed::AlreadyGone
        );
        assert!(person.record().profiles().expect("reads").is_empty());
    }
}

/// KR-REQ-01.21: a profile that is the application's default is left on removal and the record
/// keeps it, and is taken out once another profile is the default.
#[test]
fn a_profile_that_is_the_default_is_left_and_kept_in_the_record() {
    for application in applications() {
        let Some(make_default) = application.default else {
            continue;
        };
        let person = Person::with(&application);
        (application.seed)(&person);
        person
            .install(application.terminal, &command_in(person.tree.root()))
            .expect("installs");
        make_default(&person, true);
        assert_eq!(
            person.remove(application.terminal).expect("removes"),
            Removed::Default
        );
        assert!(
            (application.profile)(&person).is_file(),
            "the profile is left"
        );
        assert_eq!(
            person.record().profiles().expect("reads").len(),
            1,
            "and kept in the record"
        );

        make_default(&person, false);
        assert_eq!(
            person.remove(application.terminal).expect("removes"),
            Removed::Removed
        );
        assert!(!(application.profile)(&person).exists());
    }
}

/// KR-REQ-01.21: Windows Terminal's settings name the default profile by the identifier its
/// settings page writes, in a file with comments and trailing commas. Such a default is left on
/// removal. Settings that do not read stop the removal, with the profile left and the record kept:
/// what cannot be read is not taken to name another profile.
#[test]
fn windows_terminal_s_default_is_found_by_its_identifier_and_unreadable_settings_stop_a_removal() {
    let application = applications()
        .into_iter()
        .find(|application| application.terminal == ProfileTerminal::WindowsTerminal)
        .expect("Windows Terminal is in the list");
    let person = Person::with(&application);
    (application.seed)(&person);
    person
        .install(application.terminal, &command_in(person.tree.root()))
        .expect("installs");
    let file = (application.profile)(&person);
    let fragment: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&file).expect("the fragment")).expect("JSON");
    let guid = fragment["profiles"][0]["guid"]
        .as_str()
        .expect("an identifier")
        .to_owned();
    let settings = person
        .home
        .join("AppData/Local/Microsoft/Windows Terminal/settings.json");

    std::fs::write(
        &settings,
        format!(
            "\u{feff}// mine\n{{\n  /* the default */ \"defaultProfile\": \"{}\", // set in the page\n  \"list\": [1,],\n}}\n",
            guid.to_uppercase()
        ),
    )
    .expect("settings");
    assert_eq!(
        person.remove(application.terminal).expect("removes"),
        Removed::Default
    );
    assert!(file.is_file(), "the profile is left");
    assert_eq!(person.record().profiles().expect("reads").len(), 1);

    std::fs::write(&settings, "this is not json").expect("settings");
    let refused = person.remove(application.terminal);
    assert!(
        matches!(refused, Err(ProfileError::DefaultUnknown { .. })),
        "{refused:?}"
    );
    assert!(file.is_file(), "the profile is left");
    assert_eq!(
        person.record().profiles().expect("reads").len(),
        1,
        "and the record keeps it"
    );

    std::fs::write(&settings, "{\"defaultProfile\": \"Ubuntu\"}").expect("settings");
    assert_eq!(
        person.remove(application.terminal).expect("removes"),
        Removed::Removed
    );
    assert!(!file.exists());
}

/// KR-REQ-01.21: a profile the person saves between the plan of an install again and its write is
/// not overwritten: the write finds it changed, puts it back as it was, and the record keeps what
/// it named before.
#[test]
fn a_profile_saved_between_the_plan_and_the_write_is_not_overwritten() {
    for application in applications() {
        let person = Person::with(&application);
        (application.seed)(&person);
        person
            .install(application.terminal, &command_in(person.tree.root()))
            .expect("installs");
        let recorded_before = person.record().profiles().expect("reads");

        let writers = kr_cli::barrier::hold(person.tree.paths()).expect("the writers' lock");
        let permit = kr_cli::barrier::permit(&writers, &PROFILE_WRITTEN).expect("a permit");
        let record = person.record();
        let held = record.hold(&permit).expect("holds the record");
        let recorded = held.profile(application.terminal).expect("reads");
        let mut other_command = command_in(person.tree.root());
        other_command.push("--elsewhere".to_owned());
        let plan = profile::plan(
            application.terminal,
            &person.places(),
            &other_command,
            recorded.as_ref(),
        )
        .expect("a plan");
        // The person saves their own change after the plan.
        let file = (application.profile)(&person);
        std::fs::write(&file, "saved by the person after the plan").expect("saved");

        let written = profile::install(&held, &plan);
        assert!(
            matches!(written, Err(ProfileError::Changed { .. })),
            "{:?}: {written:?}",
            application.terminal
        );
        assert_eq!(
            std::fs::read_to_string(&file).expect("the file"),
            "saved by the person after the plan",
            "{:?}: the person's save is as they left it",
            application.terminal
        );
        drop(held);
        assert_eq!(
            person.record().profiles().expect("reads"),
            recorded_before,
            "{:?}: the record names what it did",
            application.terminal
        );
        let left: Vec<_> = person
            .home_only()
            .into_keys()
            .filter(|path| {
                path.file_name()
                    .is_some_and(|name| name.to_string_lossy().starts_with(".kalareach-"))
            })
            .collect();
        assert!(left.is_empty(), "no temporary file is left: {left:?}");
    }
}

/// KR-REQ-01.21: what cannot be read is not taken for an answer. Konsole's settings that are there
/// and do not read stop a removal, which leaves the profile and keeps the record; so does a profile
/// file that cannot be read.
#[cfg(unix)]
#[test]
fn what_cannot_be_read_stops_a_removal_and_keeps_the_record() {
    use std::os::unix::fs::PermissionsExt as _;

    let application = applications()
        .into_iter()
        .find(|application| application.terminal == ProfileTerminal::Konsole)
        .expect("Konsole is in the list");
    let person = Person::with(&application);
    (application.seed)(&person);
    person
        .install(application.terminal, &command_in(person.tree.root()))
        .expect("installs");
    let file = (application.profile)(&person);

    // The settings that name the default are a directory: there, and unreadable as a file.
    let settings = person.home.join(".config/konsolerc");
    std::fs::remove_file(&settings).expect("removed");
    std::fs::create_dir(&settings).expect("a directory");
    let refused = person.remove(application.terminal);
    assert!(
        matches!(refused, Err(ProfileError::DefaultUnknown { .. })),
        "{refused:?}"
    );
    assert!(file.is_file(), "the profile is left");
    assert_eq!(person.record().profiles().expect("reads").len(), 1);
    std::fs::remove_dir(&settings).expect("removed");

    // The profile file itself cannot be read.
    if !rustix::process::getuid().is_root() {
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o000)).expect("mode");
        let refused = person.remove(application.terminal);
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).expect("mode");
        assert!(
            matches!(refused, Err(ProfileError::Io { .. })),
            "{refused:?}"
        );
        assert!(file.is_file(), "the profile is left");
        assert_eq!(person.record().profiles().expect("reads").len(), 1);
    }
    assert_eq!(
        person.remove(application.terminal).expect("removes"),
        Removed::Removed
    );
}

/// An install again over an unchanged profile rewrites it, for a different command, and the record
/// follows the file.
#[test]
fn an_install_again_over_an_unchanged_profile_rewrites_it() {
    for application in applications() {
        let person = Person::with(&application);
        person
            .install(application.terminal, &command_in(person.tree.root()))
            .expect("installs");
        let other = command_in(&person.tree.root().join("elsewhere"));
        person
            .install(application.terminal, &other)
            .expect("installs again");
        let text = std::fs::read_to_string((application.profile)(&person)).expect("the profile");
        assert!(text.contains("elsewhere"), "{text}");
        assert_eq!(person.record().profiles().expect("reads")[0].command, other);
        assert_eq!(
            person.remove(application.terminal).expect("removes"),
            Removed::Removed,
            "the record matches the file"
        );
    }
}

/// iTerm2 keeps the identifier of a profile that is written again, because the profile is the same
/// profile to it.
#[test]
fn iterm2_keeps_the_identifier_of_a_profile_written_again() {
    let application = applications()
        .into_iter()
        .find(|application| application.terminal == ProfileTerminal::Iterm2)
        .expect("iTerm2 is listed");
    let person = Person::with(&application);
    let guid = |person: &Person| -> String {
        let text = std::fs::read_to_string((application.profile)(person)).expect("the profile");
        let document: serde_json::Value = serde_json::from_str(&text).expect("JSON");
        document["Profiles"][0]["Guid"]
            .as_str()
            .expect("a Guid")
            .to_owned()
    };
    person
        .install(ProfileTerminal::Iterm2, &command_in(person.tree.root()))
        .expect("installs");
    let first = guid(&person);
    person
        .install(
            ProfileTerminal::Iterm2,
            &command_in(&person.tree.root().join("elsewhere")),
        )
        .expect("installs again");
    assert_eq!(guid(&person), first);
    assert!(!first.is_empty());
}

/// KR-REQ-01.21: installs and removals at once leave a profile if and only if the record names it.
#[test]
fn installs_and_removals_at_once_leave_no_profile_the_record_does_not_name() {
    let application = applications().remove(0);
    let person = Person::with(&application);
    let command = command_in(person.tree.root());
    std::thread::scope(|scope| {
        for round in 0..8 {
            let (person, command) = (&person, &command);
            scope.spawn(move || {
                for _ in 0..4 {
                    if round % 2 == 0 {
                        // Another thread may have installed already; the file is kr's, so the
                        // install rewrites it.
                        person
                            .install(ProfileTerminal::Konsole, command)
                            .expect("installs");
                    } else {
                        person.remove(ProfileTerminal::Konsole).expect("removes");
                    }
                }
            });
        }
    });
    let named = !person.record().profiles().expect("reads").is_empty();
    assert_eq!(
        (application.profile)(&person).exists(),
        named,
        "a profile exists if the record names it"
    );
    if named {
        person.remove(ProfileTerminal::Konsole).expect("removes");
    }
    assert!(!(application.profile)(&person).exists());
}

/// What a plan says it writes is the file.
#[test]
fn the_plan_names_the_file_it_writes() {
    for application in applications() {
        let person = Person::with(&application);
        let plan = profile::plan(
            application.terminal,
            &person.places(),
            &command_in(person.tree.root()),
            None,
        )
        .expect("a plan");
        assert_eq!(plan.place(), Place::File(&(application.profile)(&person)));
    }
}

/// The terminal application of this platform, for the command cases, and what a person's machine
/// needs for it to be found by the real `kr`.
mod command {
    use super::*;

    /// The first application of this platform whose profile is a file, which the command cases
    /// write for. On Linux that is Konsole: GNOME Terminal and Ptyxis keep theirs in settings, and
    /// `terminal_profile_settings.rs` runs them.
    fn application() -> Option<Application> {
        ProfileTerminal::on_this_platform()
            .iter()
            .find_map(|terminal| {
                applications()
                    .into_iter()
                    .find(|application| application.terminal == *terminal)
            })
    }

    /// The id the command takes for that application.
    fn this_platform() -> Option<&'static str> {
        application().map(|application| application.terminal.id())
    }

    /// What `status --json` says of one application.
    fn listed<'a>(status: &'a serde_json::Value, id: &str) -> &'a serde_json::Value {
        status["terminals"]
            .as_array()
            .and_then(|terminals| terminals.iter().find(|each| each["terminal"] == id))
            .unwrap_or_else(|| panic!("{id} is listed: {status}"))
    }

    /// A `kr host terminal-profile` run for a person, with their home and the host's directories,
    /// and the programs they have on their path.
    fn run(person: &Person, arguments: &[&str]) -> (std::process::Output, String) {
        let mut command = std::process::Command::new(support::kr());
        command
            .args(["host", "terminal-profile"])
            .args(arguments)
            .env_clear()
            // Only the person's own programs: what the machine this runs on has installed is not
            // what is being asked about.
            .env("PATH", &person.programs)
            .env("HOME", &person.home)
            .env("USERPROFILE", &person.home)
            .env("LOCALAPPDATA", person.home.join("AppData/Local"))
            .env("SHELL", "/bin/sh")
            .env("KR_RUNTIME_DIR", person.tree.paths().runtime_root())
            .env("KR_STATE_DIR", person.tree.paths().state_root())
            .current_dir(&person.home)
            .stdin(std::process::Stdio::null());
        let output = command.output().expect("kr runs");
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

    /// KR-REQ-01.21, KR-REQ-26.04: the command installs the profile and writes nothing else of its
    /// own: no shell startup file, no record of startup entries, no service definition. Status
    /// reads it, a dry run writes nothing, and the removal puts the home back.
    #[test]
    fn the_command_installs_reads_and_removes_the_profile_alone() {
        let Some(application) = application() else {
            return;
        };
        let id = application.terminal.id();
        let person = Person::with(&application);
        (application.seed)(&person);
        let before = person.everything();

        let (output, said) = run(&person, &["status", "--json"]);
        assert!(output.status.success(), "{said}");
        let status = document(&output);
        assert_eq!(listed(&status, id)["installed"], true);
        assert_eq!(listed(&status, id)["profile"], "none");
        assert_eq!(person.everything(), before, "status writes nothing");

        let (output, said) = run(&person, &["install", id, "--dry-run", "--json"]);
        assert!(output.status.success(), "{said}");
        assert_eq!(document(&output)["dry_run"], true);
        assert_eq!(person.everything(), before, "a dry run writes nothing");

        let (output, said) = run(&person, &["install", id, "--json"]);
        assert!(output.status.success(), "{said}");
        let installed = document(&output);
        assert_eq!(installed["terminal"], id);
        assert_eq!(installed["default"], false);
        assert_eq!(installed["command"][1], "new");
        assert_eq!(installed["command"][2], "--attach");
        assert_eq!(installed["command"][3], "--hold-on-failure");
        let file = (application.profile)(&person);
        assert!(file.is_file());
        let after = person.everything();
        let added: Vec<String> = after
            .keys()
            .filter(|path| !before.contains_key(*path))
            .map(|path| path.display().to_string())
            .collect();
        let state = person.tree.paths().state_root();
        assert!(
            added.iter().all(|path| {
                path.ends_with(PROFILE_RECORD_NAME)
                    || path.ends_with(&format!(".{PROFILE_RECORD_NAME}.kalareach-lock"))
                    || file.strip_prefix(&person.home).is_ok_and(|profile| {
                        Path::new(path).starts_with(profile) || profile.starts_with(path)
                    })
            }),
            "an install adds the profile, its record and the record's lock: {added:?} (state {})",
            state.display()
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
        assert_eq!(listed(&document(&output), id)["profile"], "matches");

        let (output, said) = run(&person, &["remove", "--json"]);
        assert!(output.status.success(), "{said}");
        assert_eq!(document(&output)["profiles"][0]["result"], "removed");
        assert!(!file.exists());
        assert!(person.record().profiles().expect("reads").is_empty());
        let mut seeded_again = BTreeMap::new();
        collect(&person.home, &person.home, &mut seeded_again);
        for (path, contents) in before.iter().filter(|(path, _)| !path.starts_with("state")) {
            if let Some(found) = seeded_again.get(path) {
                assert_eq!(found, contents, "{} is as it was", path.display());
            }
        }
    }

    /// KR-REQ-01.21: an application that is not installed is refused with a message, an
    /// application of another platform is refused as a usage mistake, and neither writes anything.
    #[test]
    fn the_command_refuses_what_is_not_installed_and_what_is_not_on_this_platform() {
        let Some(id) = this_platform() else {
            return;
        };
        let person = Person::new();
        // The command looks for an application in the system's own folders too, which a test cannot
        // empty: where this machine has the application, there is nothing to refuse.
        let mut theirs = ProfileHome::of_this_user().expect("a home");
        theirs.programs = vec![person.programs.clone()];
        theirs
            .applications
            .retain(|folder| !folder.starts_with(&theirs.home));
        let terminal = ProfileTerminal::from_id(id).expect("a known application");
        if profile::is_present(terminal, &theirs) {
            eprintln!("skipped: {id} is installed on this machine, and the command would find it");
            return;
        }
        let before = person.everything();
        let (output, said) = run(&person, &["install", id]);
        assert_eq!(output.status.code(), Some(7), "{said}");
        assert!(said.contains("is not installed"), "{said}");
        let elsewhere = ProfileTerminal::ALL
            .iter()
            .find(|terminal| !ProfileTerminal::on_this_platform().contains(terminal))
            .expect("some application is of another platform");
        let (output, said) = run(&person, &["install", elsewhere.id()]);
        assert_eq!(output.status.code(), Some(2), "{said}");
        let (output, said) = run(&person, &["install", "xterm"]);
        assert_eq!(output.status.code(), Some(2), "{said}");
        assert_eq!(person.everything(), before, "nothing was written");
    }

    /// KR-REQ-01.21: an edited profile is left by `remove`, which says so and exits as a success,
    /// and a profile by hand at the place is refused by `install`.
    #[test]
    fn the_command_leaves_what_the_person_changed_and_refuses_what_is_not_kr_s() {
        let Some(application) = application() else {
            return;
        };
        let id = application.terminal.id();
        let person = Person::with(&application);
        let file = (application.profile)(&person);
        std::fs::create_dir_all(file.parent().expect("a directory")).expect("a directory");
        std::fs::write(&file, "by hand").expect("by hand");
        let (output, said) = run(&person, &["install", id]);
        assert_eq!(output.status.code(), Some(2), "{said}");
        assert!(said.contains("kr did not write it"), "{said}");
        std::fs::remove_file(&file).expect("removed");

        let (output, said) = run(&person, &["install", id]);
        assert!(output.status.success(), "{said}");
        std::fs::write(&file, "edited").expect("edited");
        let (output, said) = run(&person, &["remove"]);
        assert!(output.status.success(), "{said}");
        assert!(said.contains("no longer kr's to remove"), "{said}");
        assert!(file.is_file(), "the edited file is left");
    }

    /// KR-REQ-26.04: a removal that cannot take a profile out says so once. With `--json` the
    /// output is one document and the failure is the exit status; the record keeps the entry, and
    /// the next removal finishes the job.
    #[cfg(unix)]
    #[test]
    fn a_removal_that_fails_prints_one_document_and_keeps_the_record() {
        use std::os::unix::fs::PermissionsExt as _;

        /// Gives a directory its mode back when it goes, so the test's own tree can be removed.
        struct Restore(PathBuf);
        impl Drop for Restore {
            fn drop(&mut self) {
                let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o755));
            }
        }

        let Some(application) = application() else {
            return;
        };
        if rustix::process::getuid().is_root() {
            // A directory without write permission stops nobody who is root.
            return;
        }
        let id = application.terminal.id();
        let person = Person::with(&application);
        (application.seed)(&person);
        let (output, said) = run(&person, &["install", id, "--json"]);
        assert!(output.status.success(), "{said}");

        // The folder a removal moves the file aside into cannot be written to.
        let file = (application.profile)(&person);
        let staging = file
            .parent()
            .and_then(Path::parent)
            .expect("the folder above the watched one")
            .to_path_buf();
        std::fs::set_permissions(&staging, std::fs::Permissions::from_mode(0o555))
            .expect("read-only");
        let restore = Restore(staging);
        let (output, said) = run(&person, &["remove", "--json"]);
        assert_eq!(output.status.code(), Some(1), "{said}");
        let one: serde_json::Value = serde_json::from_slice(&output.stdout)
            .unwrap_or_else(|error| panic!("one document: {error}: {said}"));
        assert_eq!(one["ok"], false);
        assert_eq!(one["profiles"][0]["result"], "failed");
        assert!(
            output.stderr.is_empty(),
            "nothing more is said: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(file.is_file(), "the profile is left");
        assert_eq!(person.record().profiles().expect("reads").len(), 1);

        drop(restore);
        let (output, said) = run(&person, &["remove", "--json"]);
        assert!(output.status.success(), "{said}");
        assert_eq!(document(&output)["profiles"][0]["result"], "removed");
        assert!(!file.exists());
    }
}

/// Terminal.app, whose profile is an entry of its preferences' dictionary of profiles. These run
/// on macOS, where `defaults` and `plutil` are, and only ever against a preferences file of the
/// test's own, named by its path: the person's own preferences are not reachable from them.
#[cfg(target_os = "macos")]
mod terminal_app {
    use super::*;

    /// The preferences of a person who has Terminal's two usual profiles and chose `Pro`, whose font
    /// and colours are data, as Terminal keeps them: JSON cannot hold those.
    const PREFERENCES: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Default Window Settings</key><string>Pro</string>
  <key>Startup Window Settings</key><string>Pro</string>
  <key>Window Settings</key>
  <dict>
    <key>Basic</key><dict><key>name</key><string>Basic</string><key>type</key><string>Window Settings</string><key>ProfileCurrentVersion</key><real>2.07</real></dict>
    <key>Pro</key><dict><key>name</key><string>Pro</string><key>type</key><string>Window Settings</string><key>ProfileCurrentVersion</key><real>2.07</real><key>BackgroundBlur</key><real>0.5</real><key>Font</key><data>YnBsaXN0MDDUAQIDBAUGBwpYJHZlcnNpb25ZJGFyY2hpdmVyVCR0b3BYJG9iamVjdHM=</data><key>BackgroundColor</key><data>AAECAwQF</data><key>when</key><date>2026-01-01T00:00:00Z</date></dict>
  </dict>
</dict>
</plist>
"#;

    /// A person who has Terminal and preferences of their own.
    fn person() -> (Person, PathBuf) {
        let person = Person::new();
        std::fs::create_dir_all(person.home.join("Applications/Terminal.app"))
            .expect("the application");
        let domain = person.home.join("domains/com.apple.Terminal");
        std::fs::create_dir_all(domain.parent().expect("a directory")).expect("a directory");
        std::fs::write(plist(&domain), PREFERENCES).expect("preferences");
        (person, domain)
    }

    /// The preferences file the domain names: `defaults` appends `.plist` to the path it is given,
    /// after any extension the name has (`com.apple.Terminal` has one that is not a file type).
    fn plist(domain: &Path) -> PathBuf {
        let mut path = domain.as_os_str().to_owned();
        path.push(".plist");
        PathBuf::from(path)
    }

    /// The value at a key path of the preferences file, in the format `plutil` writes with its keys
    /// in order and holds every type, or `None` where there is none.
    fn xml(domain: &Path, key_path: &str) -> Option<String> {
        let output = std::process::Command::new("/usr/bin/plutil")
            .args(["-extract", key_path, "xml1", "-o", "-"])
            .arg(plist(domain))
            .output()
            .expect("plutil runs");
        output
            .status
            .success()
            .then(|| String::from_utf8_lossy(&output.stdout).into_owned())
    }

    /// The value at a key path as `plutil` prints it raw (a string as it is, data in base 64).
    fn raw(domain: &Path, key_path: &str) -> String {
        let output = std::process::Command::new("/usr/bin/plutil")
            .args(["-extract", key_path, "raw", "-o", "-"])
            .arg(plist(domain))
            .output()
            .expect("plutil runs");
        assert!(output.status.success(), "{key_path}");
        String::from_utf8_lossy(&output.stdout).trim().to_owned()
    }

    /// The whole preferences file in the format `plutil` writes, without the entry kr writes.
    fn without_the_entry(domain: &Path) -> String {
        let converted = std::process::Command::new("/usr/bin/plutil")
            .args(["-convert", "xml1", "-o", "-"])
            .arg(plist(domain))
            .output()
            .expect("plutil runs");
        assert!(converted.status.success());
        let mut removing = std::process::Command::new("/usr/bin/plutil")
            .args(["-remove", "Window Settings.KalaReach", "-o", "-", "-"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("plutil runs");
        use std::io::Write as _;
        let _ = removing
            .stdin
            .take()
            .expect("a pipe")
            .write_all(&converted.stdout);
        let removed = removing.wait_with_output().expect("plutil ends");
        // Where there is no entry to remove, the file is what it is.
        String::from_utf8_lossy(if removed.status.success() {
            &removed.stdout
        } else {
            &converted.stdout
        })
        .into_owned()
    }

    /// Edits the preferences file as the person would, with `plutil`.
    fn edit(domain: &Path, arguments: &[&str]) {
        let status = std::process::Command::new("/usr/bin/plutil")
            .args(arguments)
            .arg(plist(domain))
            .status()
            .expect("plutil runs");
        assert!(status.success(), "{arguments:?}");
    }

    /// KR-REQ-01.21: an install adds one entry to the dictionary of profiles, a copy of the profile
    /// the person opens windows with (its font and colours too, which are data) and with a command
    /// of its own; nothing else in the preferences moves; a removal puts the preferences back as
    /// they were.
    #[test]
    fn an_install_adds_one_entry_copied_from_the_default_profile_and_a_removal_takes_it_out() {
        let (person, domain) = person();
        let before = without_the_entry(&domain);
        let command = command_in(person.tree.root());
        person
            .install(ProfileTerminal::AppleTerminal, &command)
            .expect("installs");

        assert_eq!(raw(&domain, "Window Settings.KalaReach.name"), "KalaReach");
        assert_eq!(
            raw(&domain, "Window Settings.KalaReach.RunCommandAsShell"),
            "true"
        );
        for copied in ["BackgroundBlur", "Font", "BackgroundColor"] {
            assert_eq!(
                raw(&domain, &format!("Window Settings.KalaReach.{copied}")),
                raw(&domain, &format!("Window Settings.Pro.{copied}")),
                "{copied} is copied from the person's default profile as it is"
            );
        }
        let command_string = raw(&domain, "Window Settings.KalaReach.CommandString");
        assert!(
            command_string.ends_with("kr dir/kr' new --attach --hold-on-failure"),
            "the command is quoted for the shell that runs it: {command_string}"
        );
        assert_eq!(
            without_the_entry(&domain),
            before,
            "nothing else in the preferences moved"
        );

        assert_eq!(
            person
                .remove(ProfileTerminal::AppleTerminal)
                .expect("removes"),
            Removed::Removed
        );
        assert_eq!(without_the_entry(&domain), before);
        assert!(xml(&domain, "Window Settings.KalaReach").is_none());
        assert!(person.record().profiles().expect("reads").is_empty());
    }

    /// An entry that holds data is read whole: one the person changes by a font or a colour is a
    /// changed entry, left by a removal and named, and not one that is gone; and one of the
    /// profiles' name that holds data and that kr did not write is refused and left as it is.
    #[test]
    fn an_entry_that_holds_data_is_changed_when_its_data_is_and_foreign_when_kr_did_not_write_it() {
        let (person, domain) = person();
        let command = command_in(person.tree.root());
        person
            .install(ProfileTerminal::AppleTerminal, &command)
            .expect("installs");
        edit(
            &domain,
            &[
                "-replace",
                "Window Settings.KalaReach.BackgroundColor",
                "-data",
                "AAEC",
            ],
        );
        let recorded = person
            .record()
            .profiles()
            .expect("reads")
            .into_iter()
            .find(|profile| profile.terminal == ProfileTerminal::AppleTerminal);
        let status = profile::status(ProfileTerminal::AppleTerminal, &person.places(), recorded);
        assert_eq!(status.standing, Some(profile::Standing::Changed));
        let removed = person
            .remove(ProfileTerminal::AppleTerminal)
            .expect("removes");
        assert!(matches!(removed, Removed::Changed { .. }), "{removed:?}");
        assert_eq!(
            raw(&domain, "Window Settings.KalaReach.BackgroundColor"),
            "AAEC"
        );
        edit(&domain, &["-remove", "Window Settings.KalaReach"]);

        let by_hand = r#"<dict><key>name</key><string>KalaReach</string><key>Font</key><data>AAEC</data></dict>"#;
        edit(
            &domain,
            &["-insert", "Window Settings.KalaReach", "-xml", by_hand],
        );
        let entry_before = xml(&domain, "Window Settings.KalaReach");
        let refused = person.install(ProfileTerminal::AppleTerminal, &command);
        assert!(
            matches!(refused, Err(ProfileError::ForeignProfile(_))),
            "{refused:?}"
        );
        assert_eq!(xml(&domain, "Window Settings.KalaReach"), entry_before);
        assert!(person.record().profiles().expect("reads").is_empty());
    }

    /// An entry of the profiles' name that kr did not write is refused and left; one the person
    /// changed is left and forgotten; one that is gone is forgotten; the default is left.
    #[test]
    fn a_foreign_entry_is_refused_and_a_changed_one_is_left_and_a_default_one_is_kept() {
        let (person, domain) = person();
        let command = command_in(person.tree.root());

        edit(
            &domain,
            &[
                "-insert",
                "Window Settings.KalaReach",
                "-dictionary",
                "-o",
                &plist(&domain).display().to_string(),
            ],
        );
        let refused = person.install(ProfileTerminal::AppleTerminal, &command);
        assert!(
            matches!(refused, Err(ProfileError::ForeignProfile(_))),
            "{refused:?}"
        );
        assert!(person.record().profiles().expect("reads").is_empty());
        edit(&domain, &["-remove", "Window Settings.KalaReach"]);

        person
            .install(ProfileTerminal::AppleTerminal, &command)
            .expect("installs");
        // The default: the person chooses it.
        edit(
            &domain,
            &[
                "-replace",
                "Default Window Settings",
                "-string",
                "KalaReach",
            ],
        );
        assert_eq!(
            person
                .remove(ProfileTerminal::AppleTerminal)
                .expect("removes"),
            Removed::Default
        );
        assert!(xml(&domain, "Window Settings.KalaReach").is_some());
        assert_eq!(
            person.record().profiles().expect("reads").len(),
            1,
            "the entry stays"
        );
        edit(
            &domain,
            &["-replace", "Default Window Settings", "-string", "Pro"],
        );

        // A change.
        edit(
            &domain,
            &[
                "-replace",
                "Window Settings.KalaReach.name",
                "-string",
                "Mine now",
            ],
        );
        let removed = person
            .remove(ProfileTerminal::AppleTerminal)
            .expect("removes");
        assert!(matches!(removed, Removed::Changed { .. }), "{removed:?}");
        assert!(xml(&domain, "Window Settings.KalaReach").is_some());
        assert!(person.record().profiles().expect("reads").is_empty());
        edit(&domain, &["-remove", "Window Settings.KalaReach"]);

        // Gone.
        person
            .install(ProfileTerminal::AppleTerminal, &command)
            .expect("installs");
        edit(&domain, &["-remove", "Window Settings.KalaReach"]);
        assert_eq!(
            person
                .remove(ProfileTerminal::AppleTerminal)
                .expect("removes"),
            Removed::AlreadyGone
        );
    }

    /// Preferences with no dictionary of profiles are refused and left, so that the one entry kr
    /// writes is not the only profile Terminal has.
    #[test]
    fn preferences_with_no_profiles_are_refused_with_nothing_written() {
        let (person, domain) = person();
        edit(&domain, &["-remove", "Window Settings"]);
        let before = std::fs::read(plist(&domain)).expect("preferences");
        let refused = person.install(
            ProfileTerminal::AppleTerminal,
            &command_in(person.tree.root()),
        );
        assert!(
            matches!(refused, Err(ProfileError::NoProfiles(_))),
            "{refused:?}"
        );
        assert_eq!(std::fs::read(plist(&domain)).expect("preferences"), before);
    }

    /// An entry of the profiles' name that appears between the plan of an install and its write is
    /// not written over: the write checks again on what is there then, and the person's entry is
    /// as they left it.
    #[test]
    fn an_entry_that_appears_between_the_plan_and_the_write_is_not_overwritten() {
        let (person, domain) = person();
        let command = command_in(person.tree.root());
        let writers = kr_cli::barrier::hold(person.tree.paths()).expect("the writers' lock");
        let permit = kr_cli::barrier::permit(&writers, &PROFILE_WRITTEN).expect("a permit");
        let record = person.record();
        let held = record.hold(&permit).expect("holds the record");
        let plan = profile::plan(
            ProfileTerminal::AppleTerminal,
            &person.places(),
            &command,
            None,
        )
        .expect("a plan");
        let by_hand = r#"<dict><key>name</key><string>KalaReach</string><key>Font</key><data>AAEC</data></dict>"#;
        edit(
            &domain,
            &["-insert", "Window Settings.KalaReach", "-xml", by_hand],
        );
        let entry_before = xml(&domain, "Window Settings.KalaReach");

        let written = profile::install(&held, &plan);
        assert!(
            matches!(written, Err(ProfileError::ForeignProfile(_))),
            "{written:?}"
        );
        assert_eq!(xml(&domain, "Window Settings.KalaReach"), entry_before);
        drop(held);
        assert!(person.record().profiles().expect("reads").is_empty());
    }

    /// Preferences that cannot be written are left as they are, and so is the record: an install
    /// that could not write records nothing, and a removal that could not write keeps its entry,
    /// and the next one finishes once the preferences can be written.
    #[test]
    fn preferences_that_cannot_be_written_are_left_and_so_is_the_record() {
        use std::os::unix::fs::PermissionsExt as _;

        /// Gives a directory its mode back when it goes, so the test's own tree can be removed.
        struct Restore(PathBuf);
        impl Drop for Restore {
            fn drop(&mut self) {
                let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o755));
            }
        }

        let (person, domain) = person();
        if rustix::process::getuid().is_root() {
            return;
        }
        let command = command_in(person.tree.root());
        let folder = domain.parent().expect("a directory").to_path_buf();
        let before = std::fs::read(plist(&domain)).expect("preferences");

        std::fs::set_permissions(&folder, std::fs::Permissions::from_mode(0o555))
            .expect("read-only");
        let restore = Restore(folder.clone());
        let refused = person.install(ProfileTerminal::AppleTerminal, &command);
        assert!(
            matches!(refused, Err(ProfileError::ToolFailed { .. })),
            "{refused:?}"
        );
        assert!(person.record().profiles().expect("reads").is_empty());
        assert_eq!(std::fs::read(plist(&domain)).expect("preferences"), before);
        drop(restore);

        person
            .install(ProfileTerminal::AppleTerminal, &command)
            .expect("installs");
        let installed = std::fs::read(plist(&domain)).expect("preferences");
        std::fs::set_permissions(&folder, std::fs::Permissions::from_mode(0o555))
            .expect("read-only");
        let restore = Restore(folder);
        let failed = person.remove(ProfileTerminal::AppleTerminal);
        assert!(
            matches!(failed, Err(ProfileError::ToolFailed { .. })),
            "{failed:?}"
        );
        assert_eq!(person.record().profiles().expect("reads").len(), 1);
        assert_eq!(
            std::fs::read(plist(&domain)).expect("preferences"),
            installed
        );
        drop(restore);
        assert_eq!(
            person
                .remove(ProfileTerminal::AppleTerminal)
                .expect("finishes"),
            Removed::Removed
        );
    }

    /// A process called `Terminal` is the person's own Terminal running, and the command refuses a
    /// removal while it is, keeping the record's entry; it removes once it is not.
    #[test]
    fn the_command_refuses_while_terminal_is_running() {
        let (person, domain) = person();
        person
            .install(
                ProfileTerminal::AppleTerminal,
                &command_in(person.tree.root()),
            )
            .expect("installs");
        // A link to `sleep` called Terminal stands in for the application: the system's own
        // programs do not run as copies, and a process is named for the path it was started by.
        let stand_in = person.tree.root().join("running").join("Terminal");
        std::fs::create_dir_all(stand_in.parent().expect("a directory")).expect("a directory");
        std::os::unix::fs::symlink("/bin/sleep", &stand_in).expect("a link");
        let mut running = std::process::Command::new(&stand_in)
            .arg("600")
            .spawn()
            .expect("starts");
        let ready = profile::is_running(ProfileTerminal::AppleTerminal);
        let output = std::process::Command::new(support::kr())
            .args(["host", "terminal-profile", "remove", "apple-terminal"])
            .env_clear()
            .env("HOME", &person.home)
            .env("PATH", &person.programs)
            .env("KR_RUNTIME_DIR", person.tree.paths().runtime_root())
            .env("KR_STATE_DIR", person.tree.paths().state_root())
            .output()
            .expect("kr runs");
        running.kill().expect("ends the stand-in by its own handle");
        running.wait().expect("collects it");
        assert!(ready, "a process called Terminal is a running Terminal");
        let said = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!output.status.success(), "{said}");
        assert!(said.contains("is running"), "{said}");
        assert!(xml(&domain, "Window Settings.KalaReach").is_some());
        assert_eq!(
            person.record().profiles().expect("reads").len(),
            1,
            "the entry stays"
        );
    }
}
