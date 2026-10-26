//! The terminal profile of GNOME Terminal and Ptyxis, KR-REQ-01.21 and KR-REQ-07.42: keys in the
//! settings database, and a place in a list that the application's own preferences window shares.
//!
//! These run the real `gsettings` against the schemas installed on the machine, with a keyfile of
//! the test's own as the backend, so nothing here reaches the person's settings. A machine without
//! `gsettings` or the application's schema skips them loudly, unless `KR_REQUIRE_LINUX_TERMINALS`
//! is set, which makes it a failure: the build box sets it.
//!
//! The list is shared and has no compare-and-set, so the cases that matter most are the
//! interleavings: another writer appending to it between kr's two reads, and another writer
//! overwriting it from a stale read after kr's write. A `gsettings` wrapper on the program path
//! plays the other writer at the call that is asked for, and another fails each call in turn, so
//! an install interrupted at any point is shown to leave nothing behind.

#![cfg(unix)]

use std::path::{Path, PathBuf};

use kr_shell_integration::host::terminal_profile::record::{PROFILE_WRITTEN, ProfileRecord, Wrote};
use kr_shell_integration::host::terminal_profile::{
    self as profile, Gsettings, Place, ProfileError, ProfileHome, ProfileTerminal, Removed,
};

/// How one of the two applications keeps its profiles.
struct Application {
    terminal: ProfileTerminal,
    program: &'static str,
    list_schema: &'static str,
    list_key: &'static str,
    default_key: &'static str,
    profile_schema: &'static str,
    profile_path: fn(&str) -> String,
    name_key: &'static str,
    /// The identifier of the profile the person has used the application with.
    theirs: &'static str,
}

const GNOME: Application = Application {
    terminal: ProfileTerminal::GnomeTerminal,
    program: "gnome-terminal",
    list_schema: "org.gnome.Terminal.ProfilesList",
    list_key: "list",
    default_key: "default",
    profile_schema: "org.gnome.Terminal.Legacy.Profile",
    profile_path: |uuid| format!("/org/gnome/terminal/legacy/profiles:/:{uuid}/"),
    name_key: "visible-name",
    theirs: "b1dcc9dd-5262-4d8d-a863-c897e6d979b9",
};

const PTYXIS: Application = Application {
    terminal: ProfileTerminal::Ptyxis,
    program: "ptyxis",
    list_schema: "org.gnome.Ptyxis",
    list_key: "profile-uuids",
    default_key: "default-profile-uuid",
    profile_schema: "org.gnome.Ptyxis.Profile",
    profile_path: |uuid| format!("/org/gnome/Ptyxis/Profiles/{uuid}/"),
    name_key: "label",
    theirs: "0123456789abcdef0123456789abcdef",
};

/// A person with a home, a keyfile settings backend of their own, and the application's program.
struct Person {
    tree: kr_ipc::testing::TempHost,
    home: PathBuf,
    programs: PathBuf,
    application: &'static Application,
}

impl Person {
    /// A person who has the application, or `None` where this machine cannot run the case.
    fn new(application: &'static Application) -> Option<Self> {
        let tree = kr_ipc::testing::TempHost::create();
        let home = tree.root().join("home");
        let programs = tree.root().join("programs");
        for directory in [&home, &programs] {
            std::fs::create_dir_all(directory).expect("a directory");
        }
        std::fs::write(programs.join(application.program), b"#!/bin/sh\n").expect("a program");
        let person = Self {
            tree,
            home,
            programs,
            application,
        };
        // A profile's keys are a relocatable schema, which `list-schemas` leaves out.
        let schemas = [
            person.gsettings(&["list-schemas"]),
            person.gsettings(&["list-relocatable-schemas"]),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join("\n");
        let ready = schemas.lines().any(|line| line == application.list_schema)
            && schemas
                .lines()
                .any(|line| line == application.profile_schema);
        if !ready {
            assert!(
                std::env::var_os("KR_REQUIRE_LINUX_TERMINALS").is_none(),
                "KR_REQUIRE_LINUX_TERMINALS is set, and {} is not installed with gsettings here",
                application.program
            );
            eprintln!(
                "skipped: gsettings or the schema of {} is not installed here",
                application.program
            );
            return None;
        }
        person.seed();
        Some(person)
    }

    fn places(&self) -> ProfileHome {
        ProfileHome::under(&self.home, vec![self.programs.clone()])
    }

    /// The places, with `gsettings` replaced by the wrapper and the variables it reads.
    fn places_through(&self, wrapper: &Path, knobs: &[(&str, String)]) -> ProfileHome {
        let mut places = self.places();
        let real = places.settings.clone();
        places.settings = Gsettings {
            program: wrapper.to_path_buf(),
            environment: real
                .environment
                .into_iter()
                .chain(
                    knobs
                        .iter()
                        .map(|(name, value)| ((*name).to_owned(), value.clone())),
                )
                .collect(),
        };
        places
    }

    fn record(&self) -> ProfileRecord {
        ProfileRecord::in_state_directory(self.tree.paths().state_root())
    }

    /// Runs the real `gsettings` against this person's backend and returns what it printed.
    fn gsettings(&self, arguments: &[&str]) -> Option<String> {
        let tool = &self.places().settings;
        let output = std::process::Command::new(&tool.program)
            .args(arguments)
            .envs(tool.environment.iter().map(|(name, value)| (name, value)))
            .stdin(std::process::Stdio::null())
            .output()
            .ok()?;
        output
            .status
            .success()
            .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
    }

    fn get(&self, target: &str, key: &str) -> String {
        self.gsettings(&["get", target, key])
            .unwrap_or_else(|| panic!("gsettings get {target} {key}"))
    }

    fn set(&self, target: &str, key: &str, value: &str) {
        self.gsettings(&["set", target, key, value])
            .unwrap_or_else(|| panic!("gsettings set {target} {key}"));
    }

    /// The identifiers in the list.
    fn list(&self) -> Vec<String> {
        let text = self.get(self.application.list_schema, self.application.list_key);
        text.trim_start_matches("@as ")
            .trim_matches(['[', ']'])
            .split(',')
            .map(|item| item.trim().trim_matches('\'').to_owned())
            .filter(|item| !item.is_empty())
            .collect()
    }

    fn default(&self) -> String {
        self.get(self.application.list_schema, self.application.default_key)
    }

    /// A profile's keys as one text, to compare two states of it.
    fn keys_of(&self, uuid: &str) -> String {
        let target = format!(
            "{}:{}",
            self.application.profile_schema,
            (self.application.profile_path)(uuid)
        );
        self.gsettings(&["list-recursively", &target])
            .unwrap_or_default()
    }

    /// The application once the person has used it: one profile of their own, which is the
    /// default.
    fn seed(&self) {
        let application = self.application;
        self.set(
            application.list_schema,
            application.list_key,
            &format!("['{}']", application.theirs),
        );
        self.set(
            application.list_schema,
            application.default_key,
            &format!("'{}'", application.theirs),
        );
        self.set(
            &format!(
                "{}:{}",
                application.profile_schema,
                (application.profile_path)(application.theirs)
            ),
            application.name_key,
            "'Mine'",
        );
    }

    fn command(&self) -> Vec<String> {
        [
            self.tree
                .root()
                .join("kr dir")
                .join("kr")
                .to_str()
                .expect("text"),
            "new",
            "--attach",
            "--hold-on-failure",
        ]
        .map(str::to_owned)
        .to_vec()
    }

    /// Installs as the command does.
    fn install(&self, places: &ProfileHome) -> Result<(), ProfileError> {
        let terminal = self.application.terminal;
        if !profile::is_present(terminal, places) {
            return Err(ProfileError::NotInstalled(terminal));
        }
        let writers = kr_cli::barrier::hold(self.tree.paths()).expect("the writers' lock");
        let permit = kr_cli::barrier::permit(&writers, &PROFILE_WRITTEN).expect("a permit");
        let record = self.record();
        let held = record.hold(&permit).expect("holds the record");
        let recorded = held.profile(terminal)?;
        let plan = profile::plan(terminal, places, &self.command(), recorded.as_ref())?;
        profile::install(&held, &plan)
    }

    /// Removes as the command does.
    fn remove(&self, places: &ProfileHome) -> Result<Removed, ProfileError> {
        let writers = kr_cli::barrier::hold(self.tree.paths()).expect("the writers' lock");
        let permit = kr_cli::barrier::permit(&writers, &PROFILE_WRITTEN).expect("a permit");
        let record = self.record();
        let held = record.hold(&permit).expect("holds the record");
        profile::remove(&held, self.application.terminal, places)
    }

    /// The identifier the record names for the application, if it names one.
    fn recorded_uuid(&self) -> Option<String> {
        self.record()
            .profiles()
            .expect("the record reads")
            .into_iter()
            .find_map(|recorded| match recorded.wrote {
                Wrote::Settings(wrote) => Some(wrote.list.member),
                _ => None,
            })
    }
}

/// Runs a case for each application this machine can run it for.
fn for_each_application(case: impl Fn(&Person)) {
    for application in [&GNOME, &PTYXIS] {
        if let Some(person) = Person::new(application) {
            case(&person);
        }
    }
}

/// KR-REQ-01.21: an install writes the profile's keys and one place in the list, leaves the
/// person's own profiles and the default as they were, and records what it wrote; a removal takes
/// it out and leaves the settings as they were.
#[test]
fn an_install_adds_a_profile_and_a_place_in_the_list_and_a_removal_takes_them_out() {
    for_each_application(|person| {
        let places = person.places();
        let list_before = person.list();
        let default_before = person.default();
        let theirs_before: Vec<_> = list_before
            .iter()
            .map(|uuid| person.keys_of(uuid))
            .collect();

        person.install(&places).expect("installs");
        let uuid = person
            .recorded_uuid()
            .expect("the record names the profile");
        let list = person.list();
        let mut expected = list_before.clone();
        expected.push(uuid.clone());
        assert_eq!(list, expected, "the list gains one element, at the end");
        assert_eq!(
            person.default(),
            default_before,
            "the default is not touched"
        );
        for (before, now) in theirs_before
            .iter()
            .zip(list_before.iter().map(|u| person.keys_of(u)))
        {
            assert_eq!(*before, now, "the person's own profiles are as they were");
        }
        let target = format!(
            "{}:{}",
            person.application.profile_schema,
            (person.application.profile_path)(&uuid)
        );
        assert_eq!(
            person.get(&target, person.application.name_key),
            "'KalaReach'",
            "the profile is named"
        );
        assert_eq!(person.get(&target, "use-custom-command"), "true");
        let command = person.get(&target, "custom-command");
        assert!(
            command.contains("new --attach --hold-on-failure"),
            "{command}"
        );
        assert!(command.contains("kr dir"), "{command}");

        assert_eq!(person.remove(&places).expect("removes"), Removed::Removed);
        assert_eq!(person.list(), list_before, "the list is as it was");
        assert_eq!(person.default(), default_before);
        // `list-recursively` prints every key of the schema with its default, so a profile with
        // nothing set reads as one that was never there.
        assert_eq!(
            person.keys_of(&uuid),
            person.keys_of("ffffffffffffffffffffffffffffffff"),
            "none of the profile's keys is set any more"
        );
        assert!(person.record().profiles().expect("reads").is_empty());
    });
}

/// KR-REQ-01.21: a list with no default, or whose default is not in it, is refused with nothing
/// written; a profile of the person's own named like ours is refused.
#[test]
fn a_list_with_no_default_and_a_profile_with_our_name_are_refused_with_nothing_written() {
    for_each_application(|person| {
        let places = person.places();
        let application = person.application;

        // The default is a profile that is not in the list.
        let default = person.default();
        person.set(
            application.list_schema,
            application.default_key,
            "'not-in-the-list'",
        );
        let list = person.list();
        let refused = person.install(&places);
        assert!(
            matches!(refused, Err(ProfileError::NoDefaultProfile(_))),
            "{refused:?}"
        );
        assert_eq!(person.list(), list, "nothing was written to the list");
        assert!(person.recorded_uuid().is_none());
        person.set(application.list_schema, application.default_key, &default);

        // A profile of the person's own with our name.
        let theirs = list.first().expect("a profile of their own").clone();
        let target = format!(
            "{}:{}",
            application.profile_schema,
            (application.profile_path)(&theirs)
        );
        let name = person.get(&target, application.name_key);
        person.set(&target, application.name_key, "'KalaReach'");
        let refused = person.install(&places);
        assert!(
            matches!(refused, Err(ProfileError::ForeignProfile(_))),
            "{refused:?}"
        );
        assert_eq!(person.list(), list);
        person.set(&target, application.name_key, &name);
    });
}

/// A settings database that keeps a write only in the process that made it is refused, and what
/// the install wrote is taken back.
#[test]
fn a_backend_that_does_not_persist_is_refused() {
    for_each_application(|person| {
        // The memory backend keeps nothing between two `gsettings` runs: the schema defaults are
        // what the install reads, and what it writes is gone when the next process looks. Ptyxis's
        // schema defaults name no default profile, so the case is GNOME Terminal's.
        if person.application.terminal != ProfileTerminal::GnomeTerminal {
            return;
        }
        let mut places = person.places();
        for (name, value) in &mut places.settings.environment {
            if name == "GSETTINGS_BACKEND" {
                *value = "memory".to_owned();
            }
        }
        let refused = person.install(&places);
        assert!(
            matches!(refused, Err(ProfileError::NotPersisted(_))),
            "{refused:?}"
        );
        assert!(person.record().profiles().expect("reads").is_empty());
    });
}

/// A profile changed after kr wrote it is left, with its place in the list, and forgotten by the
/// record; a profile that is the default is left and kept in the record.
#[test]
fn a_changed_profile_is_left_and_a_default_profile_is_kept() {
    for_each_application(|person| {
        let places = person.places();
        let application = person.application;
        person.install(&places).expect("installs");
        let uuid = person.recorded_uuid().expect("recorded");
        let target = format!(
            "{}:{}",
            application.profile_schema,
            (application.profile_path)(&uuid)
        );
        let list = person.list();

        // The default.
        let default = person.default();
        person.set(
            application.list_schema,
            application.default_key,
            &format!("'{uuid}'"),
        );
        assert_eq!(person.remove(&places).expect("removes"), Removed::Default);
        assert_eq!(person.list(), list);
        assert!(person.recorded_uuid().is_some(), "the entry stays");
        person.set(application.list_schema, application.default_key, &default);

        // A change: the person restyles the profile.
        person.set(&target, "use-custom-command", "false");
        let removed = person.remove(&places).expect("removes");
        assert!(matches!(removed, Removed::Changed { .. }), "{removed:?}");
        assert_eq!(
            person.list(),
            list,
            "the profile keeps its place in the list"
        );
        assert_eq!(
            person.get(&target, "use-custom-command"),
            "false",
            "and is as the person left it"
        );
        assert!(person.recorded_uuid().is_none(), "the record forgot it");
    });
}

/// A profile whose keys and place are gone is forgotten by a removal.
#[test]
fn a_profile_that_is_gone_is_forgotten() {
    for_each_application(|person| {
        let places = person.places();
        person.install(&places).expect("installs");
        let uuid = person.recorded_uuid().expect("recorded");
        let target = format!(
            "{}:{}",
            person.application.profile_schema,
            (person.application.profile_path)(&uuid)
        );
        let kept: Vec<String> = person.list().into_iter().filter(|u| *u != uuid).collect();
        let quoted: Vec<String> = kept.iter().map(|u| format!("'{u}'")).collect();
        person.set(
            person.application.list_schema,
            person.application.list_key,
            &format!("[{}]", quoted.join(", ")),
        );
        for key in [
            person.application.name_key,
            "use-custom-command",
            "custom-command",
        ] {
            person.gsettings(&["reset", &target, key]).expect("resets");
        }
        assert_eq!(
            person.remove(&places).expect("removes"),
            Removed::AlreadyGone
        );
        assert!(person.record().profiles().expect("reads").is_empty());
    });
}

/// The wrapper that plays another writer of the shared list. It counts the calls, fails the one it
/// is told to, appends an element to the list just before the read it is told to, and overwrites
/// the list from a stale read just after the write it is told to.
fn wrapper(directory: &Path) -> PathBuf {
    let path = directory.join("gsettings-wrapper");
    std::fs::write(
        &path,
        r#"#!/bin/sh
real="$KR_TEST_REAL_GSETTINGS"
count_file="$KR_TEST_COUNTS/calls"
calls=$(cat "$count_file" 2>/dev/null || echo 0)
calls=$((calls + 1))
echo "$calls" > "$count_file"
if [ "$KR_TEST_FAIL_AT" = "$calls" ]; then
  exit 1
fi
if [ "$1" = get ] && [ "$2" = "$KR_TEST_LIST_SCHEMA" ] && [ "$3" = "$KR_TEST_LIST_KEY" ]; then
  reads=$(cat "$KR_TEST_COUNTS/reads" 2>/dev/null || echo 0)
  reads=$((reads + 1))
  echo "$reads" > "$KR_TEST_COUNTS/reads"
  if [ "$KR_TEST_APPEND_AT_READ" = "$reads" ]; then
    current=$("$real" get "$KR_TEST_LIST_SCHEMA" "$KR_TEST_LIST_KEY")
    current=${current#@as }
    current=${current%]}
    "$real" set "$KR_TEST_LIST_SCHEMA" "$KR_TEST_LIST_KEY" "${current}, 'another-writer']"
  fi
fi
"$real" "$@"
status=$?
if [ "$1" = set ] && [ "$2" = "$KR_TEST_LIST_SCHEMA" ] && [ "$3" = "$KR_TEST_LIST_KEY" ]; then
  sets=$(cat "$KR_TEST_COUNTS/sets" 2>/dev/null || echo 0)
  sets=$((sets + 1))
  echo "$sets" > "$KR_TEST_COUNTS/sets"
  if [ "$KR_TEST_OVERWRITE_AT_SET" = "$sets" ]; then
    "$real" set "$KR_TEST_LIST_SCHEMA" "$KR_TEST_LIST_KEY" "$KR_TEST_STALE"
  fi
fi
exit $status
"#,
    )
    .expect("the wrapper");
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("executable");
    path
}

/// The places through the wrapper, with a directory of its own for its counts.
fn through_the_wrapper(person: &Person, knobs: &[(&str, String)]) -> ProfileHome {
    let directory = tempfile::tempdir().expect("a directory");
    let counts = directory.path().to_path_buf();
    let real = person
        .places()
        .settings
        .program
        .to_str()
        .expect("text")
        .to_owned();
    let real = String::from_utf8(
        std::process::Command::new("sh")
            .args(["-c", &format!("command -v {real}")])
            .output()
            .expect("sh runs")
            .stdout,
    )
    .expect("text")
    .trim()
    .to_owned();
    let wrapper_path = wrapper(&person.programs);
    let mut all = vec![
        ("KR_TEST_REAL_GSETTINGS", real),
        ("KR_TEST_COUNTS", counts.display().to_string()),
        (
            "KR_TEST_LIST_SCHEMA",
            person.application.list_schema.to_owned(),
        ),
        ("KR_TEST_LIST_KEY", person.application.list_key.to_owned()),
    ];
    all.extend(knobs.iter().map(|(name, value)| (*name, value.clone())));
    // The counts directory outlives this call, with the person.
    std::mem::forget(directory);
    person.places_through(&wrapper_path, &all)
}

/// KR-REQ-01.21: another writer appends to the shared list between kr's two reads. Every element is
/// in the list afterwards, and so is the profile.
#[test]
fn a_writer_appending_between_our_reads_loses_nothing() {
    for_each_application(|person| {
        let list_before = person.list();
        let places = through_the_wrapper(person, &[("KR_TEST_APPEND_AT_READ", "2".to_owned())]);
        person.install(&places).expect("installs");
        let list = person.list();
        for uuid in &list_before {
            assert!(list.contains(uuid), "{uuid} is still in {list:?}");
        }
        assert!(list.contains(&"another-writer".to_owned()), "{list:?}");
        let ours = person.recorded_uuid().expect("recorded");
        assert!(list.contains(&ours), "{list:?}");
        // And the removal finds the other writer's element too, and leaves it.
        let places = through_the_wrapper(person, &[]);
        assert_eq!(person.remove(&places).expect("removes"), Removed::Removed);
        let list = person.list();
        assert!(list.contains(&"another-writer".to_owned()), "{list:?}");
        assert!(!list.contains(&ours));
    });
}

/// KR-REQ-01.21: another writer overwrites the list from a stale read just after kr wrote it. The
/// write is found missing by another process's read and done again; nothing of the other writer's
/// or the person's is lost.
#[test]
fn a_writer_overwriting_from_a_stale_read_after_our_write_loses_nothing() {
    for_each_application(|person| {
        let list_before = person.list();
        let quoted: Vec<String> = list_before.iter().map(|u| format!("'{u}'")).collect();
        let stale = format!("[{}, 'another-writer']", quoted.join(", "));
        let places = through_the_wrapper(
            person,
            &[
                ("KR_TEST_OVERWRITE_AT_SET", "1".to_owned()),
                ("KR_TEST_STALE", stale),
            ],
        );
        person.install(&places).expect("installs");
        let list = person.list();
        for uuid in &list_before {
            assert!(list.contains(uuid), "{uuid} is still in {list:?}");
        }
        assert!(list.contains(&"another-writer".to_owned()), "{list:?}");
        let ours = person.recorded_uuid().expect("recorded");
        assert!(list.contains(&ours), "{list:?}");
    });
}

/// KR-REQ-01.21: an install interrupted at any call of `gsettings` leaves no key of the profile,
/// nothing in the list that was not there, and no entry in the record. The case fails each call in
/// turn.
#[test]
fn an_install_interrupted_at_any_call_leaves_nothing() {
    for_each_application(|person| {
        // How many calls a clean install makes, counted through the wrapper.
        let counting = through_the_wrapper(person, &[]);
        person.install(&counting).expect("installs");
        let counts = counting
            .settings
            .environment
            .iter()
            .find(|(name, _)| name == "KR_TEST_COUNTS")
            .map(|(_, value)| PathBuf::from(value))
            .expect("the counts");
        let calls: u32 = std::fs::read_to_string(counts.join("calls"))
            .expect("the count")
            .trim()
            .parse()
            .expect("a number");
        let places = person.places();
        assert_eq!(person.remove(&places).expect("removes"), Removed::Removed);
        assert!(calls > 3, "an install makes several calls: {calls}");

        let list_before = person.list();
        for failing in 1..=calls {
            let through = through_the_wrapper(person, &[("KR_TEST_FAIL_AT", failing.to_string())]);
            let outcome = person.install(&through);
            if outcome.is_ok() {
                // The call that failed was one an install can do without (a check that is made
                // again): the profile is written and goes out again, as any other.
                assert_eq!(person.remove(&places).expect("removes"), Removed::Removed);
                continue;
            }
            assert_eq!(
                person.list(),
                list_before,
                "call {failing}: the list is as it was"
            );
            assert!(
                person.recorded_uuid().is_none(),
                "call {failing}: the record names nothing"
            );
            let keyfile =
                std::fs::read_to_string(person.home.join(".config/glib-2.0/settings/keyfile"))
                    .unwrap_or_default();
            assert!(
                !keyfile.contains("KalaReach"),
                "call {failing}: no key of the profile is left: {keyfile}"
            );
        }
    });
}

/// The plan names the settings it writes.
#[test]
fn the_plan_names_the_settings_it_writes() {
    for_each_application(|person| {
        let plan = profile::plan(
            person.application.terminal,
            &person.places(),
            &person.command(),
            None,
        )
        .expect("a plan");
        match plan.place() {
            Place::Settings { schema, path } => {
                assert_eq!(schema, person.application.profile_schema);
                assert!(path.starts_with("/org/gnome/"), "{path}");
            }
            Place::File(_) | Place::Preferences { .. } => panic!("settings, not a file"),
        }
    });
}
