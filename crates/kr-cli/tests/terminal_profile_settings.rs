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
        self.install_command(places, &self.command())
    }

    /// Installs a profile that runs `command`, as the command does.
    fn install_command(
        &self,
        places: &ProfileHome,
        command: &[String],
    ) -> Result<(), ProfileError> {
        let terminal = self.application.terminal;
        if !profile::is_present(terminal, places) {
            return Err(ProfileError::NotInstalled(terminal));
        }
        let writers = kr_cli::barrier::hold(self.tree.paths()).expect("the writers' lock");
        let permit = kr_cli::barrier::permit(&writers, &PROFILE_WRITTEN).expect("a permit");
        let record = self.record();
        let held = record.hold(&permit).expect("holds the record");
        let recorded = held.profile(terminal)?;
        let plan = profile::plan(terminal, places, command, recorded.as_ref())?;
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

/// The wrapper that plays another writer of the shared list, and a settings service that goes. It
/// counts the calls, fails the one it is told to, fails every call from the first write of a
/// profile's key on, says that every reset worked and does none, says the same of every write of
/// a profile's key after the first, sets a key of the profile as the person would just after the
/// read of a profile it is told to has been answered or just after the first write of a key, shows
/// no schemas, appends an element to the list just after the read it is
/// told to has been answered (so that the answer is stale), and overwrites the list from a stale
/// read just after the write it is told to.
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
if [ -n "$KR_TEST_FAIL_FROM_FIRST_SET" ] && [ "$1" = set ]; then
  : > "$KR_TEST_COUNTS/gone"
fi
if [ -e "$KR_TEST_COUNTS/gone" ]; then
  exit 1
fi
if [ -n "$KR_TEST_SWALLOW_RESETS" ] && [ "$1" = reset ]; then
  exit 0
fi
if [ -n "$KR_TEST_SWALLOW_AFTER_FIRST_KEY_SET" ] && { [ "$1" = set ] || [ "$1" = reset ]; }; then
  case "$2" in
    *:/*)
      if [ -e "$KR_TEST_COUNTS/first-key-set" ]; then
        exit 0
      fi
      if [ "$1" = set ]; then
        : > "$KR_TEST_COUNTS/first-key-set"
      fi
      ;;
  esac
fi
if [ "$1" = get ] && [ -n "$KR_TEST_PERSON_AFTER_KEY_GET" ]; then
  case "$2" in
    *:/*)
      gets=$(cat "$KR_TEST_COUNTS/key-gets" 2>/dev/null || echo 0)
      gets=$((gets + 1))
      echo "$gets" > "$KR_TEST_COUNTS/key-gets"
      "$real" "$@"
      status=$?
      if [ "$KR_TEST_PERSON_AFTER_KEY_GET" = "$gets" ]; then
        "$real" set "$2" "$KR_TEST_PERSON_NAME_KEY" "'Mine'"
        "$real" set "$2" custom-command "'/bin/theirs'"
      fi
      exit $status
      ;;
  esac
fi
if [ "$1" = list-recursively ] && [ -n "$KR_TEST_PERSON_AFTER_DUMP" ]; then
  dumps=$(cat "$KR_TEST_COUNTS/dumps" 2>/dev/null || echo 0)
  dumps=$((dumps + 1))
  echo "$dumps" > "$KR_TEST_COUNTS/dumps"
  "$real" "$@"
  status=$?
  if [ "$KR_TEST_PERSON_AFTER_DUMP" = "$dumps" ]; then
    "$real" set "$KR_TEST_PERSON_TARGET" "$KR_TEST_PERSON_KEY" "$KR_TEST_PERSON_VALUE"
  fi
  exit $status
fi
if [ -n "$KR_TEST_HIDE_SCHEMAS" ] && { [ "$1" = list-schemas ] || [ "$1" = list-relocatable-schemas ]; }; then
  exit 0
fi
if [ "$1" = get ] && [ "$2" = "$KR_TEST_LIST_SCHEMA" ] && [ "$3" = "$KR_TEST_LIST_KEY" ]; then
  reads=$(cat "$KR_TEST_COUNTS/reads" 2>/dev/null || echo 0)
  reads=$((reads + 1))
  echo "$reads" > "$KR_TEST_COUNTS/reads"
  if [ "$KR_TEST_APPEND_AFTER_READ" = "$reads" ]; then
    answer=$("$real" "$@")
    status=$?
    current=${answer#@as }
    current=${current%]}
    "$real" set "$KR_TEST_LIST_SCHEMA" "$KR_TEST_LIST_KEY" "${current}, 'another-writer']"
    echo "$answer"
    exit $status
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
if [ "$1" = set ] && [ -n "$KR_TEST_PERSON_AFTER_KEY_SET" ]; then
  case "$2" in
    *:/*)
      if [ ! -e "$KR_TEST_COUNTS/person-set" ]; then
        : > "$KR_TEST_COUNTS/person-set"
        "$real" set "$2" "$3" "$KR_TEST_PERSON_VALUE"
      fi
      ;;
  esac
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

/// KR-REQ-01.21: another writer appends to the shared list just after kr has read it, before kr
/// reads it again and writes (the plan reads the list once, so the first read the write makes is
/// the second). Every element is in the list afterwards, and so is the profile: the second read
/// finds the list changed and starts over, so the write does not overwrite the other writer's
/// element.
#[test]
fn a_writer_appending_between_our_reads_loses_nothing() {
    for_each_application(|person| {
        let list_before = person.list();
        let places = through_the_wrapper(person, &[("KR_TEST_APPEND_AFTER_READ", "2".to_owned())]);
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

/// How many calls the wrapper counted.
fn calls_of(places: &ProfileHome) -> u32 {
    let counts = places
        .settings
        .environment
        .iter()
        .find(|(name, _)| name == "KR_TEST_COUNTS")
        .map(|(_, value)| PathBuf::from(value))
        .expect("the counts");
    std::fs::read_to_string(counts.join("calls"))
        .expect("the count")
        .trim()
        .parse()
        .expect("a number")
}

/// KR-REQ-01.21: a removal that is interrupted at any call of `gsettings` is a failure, and keeps
/// what the record names: a call that does not answer is not a profile that has gone or changed,
/// and a profile that cannot be read is never taken for one that is not the default. The next
/// removal finishes the job. The case fails each call of a removal in turn.
#[test]
fn a_removal_interrupted_at_any_call_keeps_the_record_and_the_next_one_finishes() {
    for_each_application(|person| {
        let places = person.places();
        let list_before = person.list();
        person.install(&places).expect("installs");
        let counting = through_the_wrapper(person, &[]);
        assert_eq!(person.remove(&counting).expect("removes"), Removed::Removed);
        let calls = calls_of(&counting);
        assert!(calls > 5, "a removal makes several calls: {calls}");

        for failing in 1..=calls {
            person.install(&places).expect("installs");
            let through = through_the_wrapper(person, &[("KR_TEST_FAIL_AT", failing.to_string())]);
            let outcome = person.remove(&through);
            assert!(
                outcome.is_err(),
                "call {failing}: a call that fails does not make a removal that succeeded: {outcome:?}"
            );
            assert!(
                person.recorded_uuid().is_some(),
                "call {failing}: the record keeps the entry"
            );
            // The last call reads back the last key's reset: when it is the one that fails, the
            // profile is already out and the record is all that is left.
            let expected = if failing == calls {
                Removed::AlreadyGone
            } else {
                Removed::Removed
            };
            assert_eq!(
                person.remove(&places).expect("finishes"),
                expected,
                "call {failing}: the next removal finishes the job"
            );
            assert_eq!(person.list(), list_before, "call {failing}");
            assert!(person.recorded_uuid().is_none(), "call {failing}");
        }
    });
}

/// KR-REQ-01.21: an install again that fails at any call of `gsettings` leaves the profile kr wrote
/// as it was: its keys, its place in the list and the record are what they were, and the command it
/// runs still works.
#[test]
fn an_install_again_that_fails_leaves_the_profile_as_it_was() {
    for_each_application(|person| {
        let places = person.places();
        let command = |round: &str| {
            let mut command = person.command();
            command.push(round.to_owned());
            command
        };
        person
            .install_command(&places, &command("first"))
            .expect("installs");
        let uuid = person.recorded_uuid().expect("recorded");
        let counting = through_the_wrapper(person, &[]);
        person
            .install_command(&counting, &command("counting"))
            .expect("installs again");
        let calls = calls_of(&counting);
        assert!(calls > 5, "an install again makes several calls: {calls}");

        for failing in 1..=calls {
            let keys = person.keys_of(&uuid);
            let list = person.list();
            let record = person.record().profiles().expect("reads");
            let through = through_the_wrapper(person, &[("KR_TEST_FAIL_AT", failing.to_string())]);
            let outcome = person.install_command(&through, &command(&format!("round {failing}")));
            if outcome.is_ok() {
                continue;
            }
            assert_eq!(
                person.keys_of(&uuid),
                keys,
                "call {failing}: the profile's keys are as they were"
            );
            assert_eq!(person.list(), list, "call {failing}: the list");
            assert_eq!(
                person.record().profiles().expect("reads"),
                record,
                "call {failing}: the record"
            );
        }
        assert_eq!(person.remove(&places).expect("removes"), Removed::Removed);
    });
}

/// A profile that is not in the list the application reads is reported as such, a removal takes its
/// keys out, and an install again puts it back in the list.
#[test]
fn a_profile_out_of_the_list_is_unlisted_and_a_removal_or_an_install_deals_with_it() {
    for_each_application(|person| {
        let places = person.places();
        let list_before = person.list();
        for removing in [true, false] {
            person.install(&places).expect("installs");
            let uuid = person.recorded_uuid().expect("recorded");
            let quoted: Vec<String> = list_before.iter().map(|u| format!("'{u}'")).collect();
            person.set(
                person.application.list_schema,
                person.application.list_key,
                &format!("[{}]", quoted.join(", ")),
            );
            let recorded = person
                .record()
                .profiles()
                .expect("reads")
                .into_iter()
                .next();
            let status = profile::status(person.application.terminal, &places, recorded);
            assert_eq!(status.standing, Some(profile::Standing::Unlisted));
            if removing {
                assert_eq!(person.remove(&places).expect("removes"), Removed::Removed);
                assert_eq!(person.keys_of(&uuid), person.keys_of("not-a-profile"));
            } else {
                person.install(&places).expect("installs again");
                assert!(person.list().contains(&uuid), "put back in the list");
                assert_eq!(person.remove(&places).expect("removes"), Removed::Removed);
            }
            assert_eq!(person.list(), list_before);
            assert!(person.recorded_uuid().is_none());
        }
    });
}

/// A `gsettings` that is not there is a profile that cannot be read, which is neither gone nor
/// changed: `status` says so, a removal fails and keeps the record, and a removal with the program
/// back takes the profile out.
#[test]
fn a_gsettings_that_is_not_there_does_not_make_a_profile_forgotten() {
    for_each_application(|person| {
        let places = person.places();
        person.install(&places).expect("installs");
        let mut without = person.places();
        without.settings.program = PathBuf::from("/nonexistent/gsettings");
        let recorded = person
            .record()
            .profiles()
            .expect("reads")
            .into_iter()
            .next();
        let status = profile::status(person.application.terminal, &without, recorded);
        assert_eq!(status.standing, Some(profile::Standing::Unreadable));
        let outcome = person.remove(&without);
        assert!(
            matches!(outcome, Err(ProfileError::ToolMissing(_))),
            "{outcome:?}"
        );
        assert!(person.recorded_uuid().is_some(), "the record keeps it");
        assert_eq!(person.remove(&places).expect("removes"), Removed::Removed);
    });
}

/// KR-REQ-01.21: an install again that cannot take itself back, because the settings service is
/// gone from its first write on, leaves a profile the record still names: the record holds both
/// what was to be written and what the profile held, so the profile reads as kr's, `status` does
/// not call it changed, and a removal with the service back takes it out.
#[test]
fn an_install_again_that_cannot_take_itself_back_leaves_a_profile_the_record_still_names() {
    for_each_application(|person| {
        let places = person.places();
        let list_before = person.list();
        let command = |round: &str| {
            let mut command = person.command();
            command.push(round.to_owned());
            command
        };
        person
            .install_command(&places, &command("first"))
            .expect("installs");
        let uuid = person.recorded_uuid().expect("recorded");
        let keys = person.keys_of(&uuid);

        let gone = through_the_wrapper(person, &[("KR_TEST_FAIL_FROM_FIRST_SET", "1".to_owned())]);
        let outcome = person.install_command(&gone, &command("second"));
        assert!(outcome.is_err(), "{outcome:?}");
        assert_eq!(
            person.keys_of(&uuid),
            keys,
            "nothing could be written, so the profile is as it was"
        );
        let recorded = person
            .record()
            .profiles()
            .expect("reads")
            .into_iter()
            .next();
        let status = profile::status(person.application.terminal, &places, recorded);
        assert_eq!(
            status.standing,
            Some(profile::Standing::Matches),
            "the profile reads as kr's, not as changed"
        );
        assert_eq!(person.remove(&places).expect("removes"), Removed::Removed);
        assert_eq!(person.list(), list_before);
        assert!(person.recorded_uuid().is_none());
    });
}

/// KR-REQ-01.21: an application whose settings schema is gone (it was uninstalled) is a profile that
/// cannot be read, which is neither gone nor changed: `status` says so, a removal says why and keeps
/// the record, and a removal with the schema back takes the profile out.
#[test]
fn an_application_whose_schema_is_gone_keeps_its_record_and_says_why() {
    for_each_application(|person| {
        let places = person.places();
        person.install(&places).expect("installs");
        let hidden = through_the_wrapper(person, &[("KR_TEST_HIDE_SCHEMAS", "1".to_owned())]);
        let recorded = person
            .record()
            .profiles()
            .expect("reads")
            .into_iter()
            .next();
        let status = profile::status(person.application.terminal, &hidden, recorded);
        assert_eq!(status.standing, Some(profile::Standing::Unreadable));
        let outcome = person.remove(&hidden);
        assert!(
            matches!(outcome, Err(ProfileError::SchemaAbsent(_))),
            "{outcome:?}"
        );
        assert!(person.recorded_uuid().is_some(), "the record keeps it");
        assert_eq!(person.remove(&places).expect("removes"), Removed::Removed);
    });
}

/// The target of a profile's keys.
fn target_of(person: &Person, uuid: &str) -> String {
    format!(
        "{}:{}",
        person.application.profile_schema,
        (person.application.profile_path)(uuid)
    )
}

/// The places through a wrapper in which the person sets the profile's command just after the
/// `after`th read of a profile's keys.
fn through_a_person_who_changes_the_command(
    person: &Person,
    uuid: &str,
    after: u32,
) -> ProfileHome {
    through_the_wrapper(
        person,
        &[
            ("KR_TEST_PERSON_AFTER_DUMP", after.to_string()),
            ("KR_TEST_PERSON_TARGET", target_of(person, uuid)),
            ("KR_TEST_PERSON_KEY", "custom-command".to_owned()),
            ("KR_TEST_PERSON_VALUE", "'/bin/theirs'".to_owned()),
        ],
    )
}

/// KR-REQ-01.21: a key the person changed after the plan, or between kr's last read and its write,
/// is not written over. The write stops with what the person put there still there, the keys it had
/// already written are back, and the record still names the profile as before.
#[test]
fn a_key_the_person_changed_before_the_write_is_not_written_over() {
    for_each_application(|person| {
        let places = person.places();
        person.install(&places).expect("installs");
        let uuid = person.recorded_uuid().expect("recorded");
        let target = target_of(person, &uuid);
        let name = person.get(&target, person.application.name_key);
        let command_before = person.get(&target, "custom-command");
        // The plan reads the profile's keys twice (the keys, then their defaults), and the write
        // reads them again. The person changes the command after the plan's last read (2), and
        // after the write's first (3).
        for after in [2, 3] {
            let mut again = person.command();
            again.push(format!("round {after}"));
            let changing = through_a_person_who_changes_the_command(person, &uuid, after);
            let outcome = person.install_command(&changing, &again);
            assert!(
                matches!(outcome, Err(ProfileError::Changed { .. })),
                "after read {after}: {outcome:?}"
            );
            assert_eq!(
                person.get(&target, "custom-command"),
                "'/bin/theirs'",
                "after read {after}: what the person put there stays"
            );
            assert_eq!(person.get(&target, person.application.name_key), name);
            assert_eq!(person.recorded_uuid().as_deref(), Some(uuid.as_str()));
            // The person puts the command back to kr's, for the next round.
            person.set(&target, "custom-command", &command_before);
        }
        assert_eq!(person.remove(&places).expect("removes"), Removed::Removed);
    });
}

/// KR-REQ-01.21: a removal reads each key before it resets it. A key the person changed after the
/// removal's read is left with what they put there, and the removal says the profile was changed.
#[test]
fn a_key_the_person_changed_during_a_removal_is_left_as_it_is() {
    for_each_application(|person| {
        let places = person.places();
        for after in [2, 3] {
            person.install(&places).expect("installs");
            let uuid = person.recorded_uuid().expect("recorded");
            let target = target_of(person, &uuid);
            let changing = through_a_person_who_changes_the_command(person, &uuid, after);
            let removed = person.remove(&changing).expect("answers");
            assert!(
                matches!(removed, Removed::Changed { .. }),
                "after read {after}: {removed:?}"
            );
            assert_eq!(
                person.get(&target, "custom-command"),
                "'/bin/theirs'",
                "after read {after}: what the person put there stays"
            );
            // A change that came after the list was written leaves the profile as it was found:
            // in the list, with the keys kr had already reset back.
            assert!(
                person.list().contains(&uuid),
                "after read {after}: the profile is in the list"
            );
            assert_eq!(
                person.get(&target, person.application.name_key),
                "'KalaReach'",
                "after read {after}: and still named"
            );
            // Put the settings back for the next round.
            for key in [
                "custom-command",
                "use-custom-command",
                person.application.name_key,
            ] {
                let _ = person.gsettings(&["reset", &target, key]);
            }
            let list: Vec<String> = person
                .list()
                .into_iter()
                .filter(|member| *member != uuid)
                .collect();
            let quoted: Vec<String> = list.iter().map(|member| format!("'{member}'")).collect();
            person.set(
                person.application.list_schema,
                person.application.list_key,
                &format!("[{}]", quoted.join(", ")),
            );
        }
    });
}

/// KR-REQ-01.21: a reset that the settings say worked and did not keep is not a removal: the record
/// keeps the profile, and a removal once the settings keep their resets takes it out.
#[test]
fn a_removal_the_settings_did_not_keep_keeps_the_record() {
    for_each_application(|person| {
        let places = person.places();
        let before = person.list();
        person.install(&places).expect("installs");
        let uuid = person.recorded_uuid().expect("recorded");
        let target = target_of(person, &uuid);
        let swallowing = through_the_wrapper(person, &[("KR_TEST_SWALLOW_RESETS", "1".to_owned())]);
        let outcome = person.remove(&swallowing);
        assert!(
            matches!(outcome, Err(ProfileError::NotPersisted(_))),
            "{outcome:?}"
        );
        assert_eq!(person.recorded_uuid().as_deref(), Some(uuid.as_str()));
        assert_eq!(person.get(&target, "use-custom-command"), "true");
        assert_eq!(person.remove(&places).expect("removes"), Removed::Removed);
        assert_eq!(person.list(), before);
        assert!(person.recorded_uuid().is_none());
    });
}

/// KR-REQ-01.21: an install that cannot take back what it wrote, because the settings say a reset
/// worked and did not keep it, leaves the record naming the profile, so that a removal finishes it.
#[test]
fn an_install_whose_take_back_is_not_kept_keeps_the_record() {
    for_each_application(|person| {
        let places = person.places();
        let before = person.list();
        let swallowing = through_the_wrapper(
            person,
            &[("KR_TEST_SWALLOW_AFTER_FIRST_KEY_SET", "1".to_owned())],
        );
        let outcome = person.install(&swallowing);
        assert!(outcome.is_err(), "{outcome:?}");
        let uuid = person
            .recorded_uuid()
            .expect("the first key stays, so the record names the profile");
        assert_eq!(
            person.get(&target_of(person, &uuid), person.application.name_key),
            "'KalaReach'"
        );
        assert_eq!(person.remove(&places).expect("removes"), Removed::Removed);
        assert_eq!(person.list(), before);
        assert!(person.recorded_uuid().is_none());
    });
}

/// KR-REQ-01.21: a second install that fails, after a first that could not take itself back, keeps
/// the values the profile held before both: the profile still reads as kr's and a removal takes it
/// out.
#[test]
fn a_second_failed_install_keeps_the_values_the_first_left() {
    for_each_application(|person| {
        let places = person.places();
        let list_before = person.list();
        let command = |round: &str| {
            let mut command = person.command();
            command.push(round.to_owned());
            command
        };
        person
            .install_command(&places, &command("first"))
            .expect("installs");
        for _ in 0..2 {
            let gone =
                through_the_wrapper(person, &[("KR_TEST_FAIL_FROM_FIRST_SET", "1".to_owned())]);
            assert!(person.install_command(&gone, &command("second")).is_err());
        }
        let recorded = person
            .record()
            .profiles()
            .expect("reads")
            .into_iter()
            .next();
        let status = profile::status(person.application.terminal, &places, recorded);
        assert_eq!(status.standing, Some(profile::Standing::Matches));
        assert_eq!(person.remove(&places).expect("removes"), Removed::Removed);
        assert_eq!(person.list(), list_before);
        assert!(person.recorded_uuid().is_none());
    });
}

/// KR-REQ-01.21: a key the person changed right after kr wrote it is not put back when the write
/// is taken back: the install fails with the person's value in it, and the keys that are kr's are
/// back.
#[test]
fn a_key_the_person_changed_after_the_write_is_not_taken_back_over() {
    for_each_application(|person| {
        let places = person.places();
        person.install(&places).expect("installs");
        let uuid = person.recorded_uuid().expect("recorded");
        let target = target_of(person, &uuid);
        let command_before = person.get(&target, "custom-command");
        let changing = through_the_wrapper(
            person,
            &[
                ("KR_TEST_PERSON_AFTER_KEY_SET", "1".to_owned()),
                ("KR_TEST_PERSON_VALUE", "'Mine'".to_owned()),
            ],
        );
        let mut again = person.command();
        again.push("another".to_owned());
        let outcome = person.install_command(&changing, &again);
        assert!(
            matches!(outcome, Err(ProfileError::Changed { .. })),
            "a value that is neither kr's nor the earlier one is the person's: {outcome:?}"
        );
        assert_eq!(
            person.get(&target, person.application.name_key),
            "'Mine'",
            "what the person put there stays"
        );
        assert_eq!(
            person.get(&target, "custom-command"),
            command_before,
            "and the keys that are kr's are back"
        );
        assert_eq!(person.recorded_uuid().as_deref(), Some(uuid.as_str()));
    });
}

/// KR-REQ-01.21: a removal that finds a key changed after it began puts back what it had reset, and
/// leaves a key the person changed since: the person who changed the name and the command at once
/// keeps both, the profile is back in the list, and the record forgets it.
#[test]
fn a_removal_that_stops_leaves_every_key_the_person_changed() {
    for_each_application(|person| {
        let places = person.places();
        person.install(&places).expect("installs");
        let uuid = person.recorded_uuid().expect("recorded");
        let target = target_of(person, &uuid);
        // The profile's keys are read before each reset and after it; the person writes after the
        // read back of the first reset (the second read of a key of the profile).
        let changing = through_the_wrapper(
            person,
            &[
                ("KR_TEST_PERSON_AFTER_KEY_GET", "2".to_owned()),
                (
                    "KR_TEST_PERSON_NAME_KEY",
                    person.application.name_key.to_owned(),
                ),
            ],
        );
        let removed = person.remove(&changing).expect("answers");
        assert!(matches!(removed, Removed::Changed { .. }), "{removed:?}");
        assert_eq!(person.get(&target, person.application.name_key), "'Mine'");
        assert_eq!(person.get(&target, "custom-command"), "'/bin/theirs'");
        assert_eq!(person.get(&target, "use-custom-command"), "true");
        assert!(
            person.list().contains(&uuid),
            "the profile is back in the list"
        );
        assert!(person.recorded_uuid().is_none());
    });
}
