//! The record of the terminal profiles `kr host terminal-profile install` wrote.
//!
//! Removal works from this record and from nothing else: not from where a profile would go now,
//! and not from a search of the person's files. The record is written before the profile, so a
//! crash between the two leaves an entry whose destination is missing or different, which removal
//! reads as gone or changed, and never a profile that no record names.
//!
//! It is one owner-only file in the installation's state directory, replaced whole by every change,
//! and changed only while it is held for a whole install or removal ([`ProfileRecord::hold`]).

use std::path::{Path, PathBuf};

use kr_ipc::install::{Permit, WriteRefused, Written};
use serde::{Deserialize, Serialize};

use super::ProfileTerminal;
use crate::host::startup::{FileLock, decoded, encoded};

/// The name of the record in the installation's state directory.
pub const PROFILE_RECORD_NAME: &str = "terminal-profiles.json";

/// The longest record this build reads: far more than a record of every emulator there is.
const PROFILE_RECORD_LIMIT: u64 = 1024 * 1024;

/// The format of the record this build writes, recorded in it as `version`. A record that states
/// none, or a later one, is not a record this build writes, and is refused and left as it is.
pub const PROFILE_RECORD_VERSION: u32 = 1;

/// The record, as a release's manifest lists it and at the version this build writes it.
pub const PROFILE_WRITTEN: Written =
    Written::new("terminal-profiles", PROFILE_RECORD_VERSION as u64);

/// Why the record could not be used.
#[derive(Debug, thiserror::Error)]
pub enum RecordError {
    /// The record, or the directory it is kept in, could not be read or written as this user's
    /// own.
    #[error("{0}")]
    Store(#[from] kr_ipc::IpcError),
    /// The file there is not a record this build writes.
    #[error("the file is not a record of terminal profiles")]
    NotARecord,
    /// The file there is a record of a later format than this build writes.
    #[error(
        "the record is of format {found}, and this build writes format {PROFILE_RECORD_VERSION}"
    )]
    Later {
        /// The format the record states.
        found: u32,
    },
    /// The release this host is on does not read the record at the version this build writes it,
    /// or an update is switching releases.
    #[error("{0}")]
    Barred(#[source] WriteRefused),
}

/// What the record holds.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Recorded {
    /// The format of the record.
    version: u32,
    /// Each profile an install wrote, one for each emulator.
    profiles: Vec<RecordedProfile>,
}

/// One profile an install wrote, and what it wrote for it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordedProfile {
    /// The emulator the profile is for.
    pub terminal: ProfileTerminal,
    /// The argument vector the profile runs.
    pub command: Vec<String>,
    /// What was written.
    pub wrote: Wrote,
}

/// What an install wrote: a file, settings keys or a preferences entry.
///
/// An install records what it *intends* to write, before it writes it, so the contents are known
/// ahead: a file with the digest of the text it will hold, the keys with the values they will
/// take, an entry in the canonical text its preference is read back as.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Wrote {
    /// A file, in the emulator's own watched place.
    File(FileWrote),
    /// A set of keys of a settings schema, and a member of the list that names the profile.
    Settings(SettingsWrote),
    /// An entry of a preferences dictionary.
    Preferences(PreferencesWrote),
}

/// A file an install wrote.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileWrote {
    /// The file's path as its own bytes in hexadecimal.
    pub path: String,
    /// The SHA-256 of the text the file holds, in hexadecimal.
    pub sha256: String,
    /// The directories this install made on the way to the file, outermost first, each as its own
    /// bytes in hexadecimal. Removal takes one out only when it is empty.
    pub made: Vec<String>,
}

/// Settings keys an install wrote.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SettingsWrote {
    /// The schema the profile's keys belong to.
    pub schema: String,
    /// The path the profile's keys live at.
    pub path: String,
    /// Each key written and the value it was given, in the settings tool's own text form.
    pub keys: Vec<RecordedKey>,
    /// The shared list that names the profile.
    pub list: RecordedList,
}

/// One key written.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordedKey {
    /// The key.
    pub key: String,
    /// The value it was given.
    pub value: String,
}

/// The shared list a profile is a member of.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordedList {
    /// The schema of the list.
    pub schema: String,
    /// The key of the list.
    pub key: String,
    /// The member this install added.
    pub member: String,
}

/// A preferences entry an install wrote.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreferencesWrote {
    /// The preferences domain, or the path of a preferences file.
    pub domain: String,
    /// The key of the dictionary the entry is in.
    pub key: String,
    /// The entry's name in that dictionary.
    pub entry: String,
    /// The entry as the preferences are read back as JSON text.
    pub canonical: String,
}

impl FileWrote {
    /// The file's path.
    ///
    /// # Errors
    ///
    /// Returns [`RecordError::NotARecord`] for text that is not a path the record writes.
    pub fn file(&self) -> Result<PathBuf, RecordError> {
        decoded(&self.path).ok_or(RecordError::NotARecord)
    }

    /// The directories the install made, outermost first.
    ///
    /// # Errors
    ///
    /// Returns [`RecordError::NotARecord`] for text that is not a path the record writes.
    pub fn made_directories(&self) -> Result<Vec<PathBuf>, RecordError> {
        self.made
            .iter()
            .map(|directory| decoded(directory).ok_or(RecordError::NotARecord))
            .collect()
    }

    /// What an install of `path` intends to write: the file, the digest of its text and the
    /// directories it will make.
    #[must_use]
    pub fn intending(path: &Path, text: &str, made: &[PathBuf]) -> Self {
        Self {
            path: encoded(path),
            sha256: sha256_hex(text.as_bytes()),
            made: made.iter().map(|directory| encoded(directory)).collect(),
        }
    }
}

/// The SHA-256 of `bytes`, in lower-case hexadecimal.
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest as _, Sha256};

    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// The record kept in an installation's state directory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProfileRecord {
    /// The owner-only directory the record is kept in.
    directory: PathBuf,
    /// The record itself.
    path: PathBuf,
}

impl ProfileRecord {
    /// The record kept in an installation's state directory.
    #[must_use]
    pub fn in_state_directory(state: &Path) -> Self {
        Self {
            directory: state.to_path_buf(),
            path: state.join(PROFILE_RECORD_NAME),
        }
    }

    /// Where the record is kept.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The profiles the record names, in the order they were recorded, as the record is now:
    /// what a dry run and `status` report from, since they write nothing and hold nothing.
    ///
    /// # Errors
    ///
    /// Returns [`RecordError::Store`] when the record cannot be read as this user's own,
    /// [`RecordError::NotARecord`] when what is there is not a record, and [`RecordError::Later`]
    /// when it is of a later format.
    pub fn profiles(&self) -> Result<Vec<RecordedProfile>, RecordError> {
        Ok(self.read()?.profiles)
    }

    /// Holds the record for one whole install or removal, waiting while another holds it.
    ///
    /// An install records its profile and writes it, and a removal reads the record, removes the
    /// profile and forgets the entry, all while the record is held; a second `kr` waits for the
    /// first to let go. A removal can therefore never read the record between an install's
    /// recording a profile and its writing it, find nothing there and forget the entry, which
    /// would leave a profile the record does not name.
    ///
    /// `permit` is the release's leave to write the record at the version this build writes it
    /// ([`PROFILE_WRITTEN`]), and the hold lasts no longer than it. A record that exists is read
    /// first, so an unreadable one or one of a later format stops the install or removal before it
    /// does anything.
    ///
    /// # Errors
    ///
    /// Returns [`RecordError::Store`] when the directory cannot be made this user's own or another
    /// `kr` held the record for the whole of the wait, [`RecordError::Barred`] when the permit is
    /// for another record, and what [`Self::profiles`] returns for a record that exists and cannot
    /// be used.
    pub fn hold<'a>(&'a self, permit: &'a Permit<'a>) -> Result<HeldProfiles<'a>, RecordError> {
        permit
            .require(&PROFILE_WRITTEN)
            .map_err(RecordError::Barred)?;
        kr_ipc::paths::create_private_tree(&self.directory, &self.directory)?;
        let lock = FileLock::take(&self.path)
            .map_err(|error| kr_ipc::IpcError::io("lock", &self.path, error))?;
        let held = HeldProfiles {
            record: self,
            _permit: permit,
            _lock: lock,
        };
        if std::fs::symlink_metadata(&self.path).is_ok() {
            self.read()?;
        }
        Ok(held)
    }

    /// Reads the record; there being none is a record that names nothing.
    fn read(&self) -> Result<Recorded, RecordError> {
        match kr_ipc::paths::read_owner_only_file(&self.path, PROFILE_RECORD_LIMIT)? {
            None => Ok(Recorded {
                version: PROFILE_RECORD_VERSION,
                profiles: Vec::new(),
            }),
            Some(bytes) => {
                let recorded = serde_json::from_slice::<Recorded>(&bytes)
                    .map_err(|_| RecordError::NotARecord)?;
                if recorded.version > PROFILE_RECORD_VERSION {
                    return Err(RecordError::Later {
                        found: recorded.version,
                    });
                }
                if recorded.version != PROFILE_RECORD_VERSION {
                    return Err(RecordError::NotARecord);
                }
                Ok(recorded)
            }
        }
    }
}

/// The record, held for one whole install or removal ([`ProfileRecord::hold`]); it is let go when
/// this is dropped.
#[derive(Debug)]
pub struct HeldProfiles<'a> {
    /// The record held.
    record: &'a ProfileRecord,
    /// The leave to write it, which the hold cannot outlast.
    _permit: &'a Permit<'a>,
    /// The lock that holds it, beside the record in the same directory. Dropping it lets go.
    _lock: FileLock,
}

impl HeldProfiles<'_> {
    /// The profiles the record names, in the order they were recorded.
    ///
    /// # Errors
    ///
    /// Returns what [`ProfileRecord::profiles`] returns.
    pub fn profiles(&self) -> Result<Vec<RecordedProfile>, RecordError> {
        self.record.profiles()
    }

    /// The profile the record names for `terminal`, if it names one.
    ///
    /// # Errors
    ///
    /// Returns what [`ProfileRecord::profiles`] returns.
    pub fn profile(
        &self,
        terminal: ProfileTerminal,
    ) -> Result<Option<RecordedProfile>, RecordError> {
        Ok(self
            .record
            .profiles()?
            .into_iter()
            .find(|profile| profile.terminal == terminal))
    }

    /// Records `profile`, in place of what the record named for its emulator.
    ///
    /// # Errors
    ///
    /// Returns what [`Self::profiles`] returns, and [`RecordError::Store`] when the record cannot
    /// be written.
    pub fn put(&self, profile: RecordedProfile) -> Result<(), RecordError> {
        self.change(|profiles| {
            match profiles
                .iter_mut()
                .find(|recorded| recorded.terminal == profile.terminal)
            {
                Some(recorded) => *recorded = profile,
                None => profiles.push(profile),
            }
        })
    }

    /// Takes `terminal` out of what the record names.
    ///
    /// # Errors
    ///
    /// Returns what [`Self::put`] returns.
    pub fn forget(&self, terminal: ProfileTerminal) -> Result<(), RecordError> {
        self.change(|profiles| profiles.retain(|profile| profile.terminal != terminal))
    }

    /// Reads the record, changes it and writes it back whole.
    fn change(&self, edit: impl FnOnce(&mut Vec<RecordedProfile>)) -> Result<(), RecordError> {
        let mut recorded = self.record.read()?;
        edit(&mut recorded.profiles);
        recorded.version = PROFILE_RECORD_VERSION;
        let bytes = serde_json::to_vec(&recorded).map_err(|_| RecordError::NotARecord)?;
        kr_ipc::paths::write_owner_only_file(&self.record.path, &bytes)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Holds `record` as a program outside a store does, which holds nothing else.
    fn hold_the_record(record: &ProfileRecord) -> Result<HeldProfiles<'_>, RecordError> {
        static WRITERS: std::sync::OnceLock<kr_ipc::install::Writers> = std::sync::OnceLock::new();
        static PERMIT: std::sync::OnceLock<Permit<'static>> = std::sync::OnceLock::new();
        let writers = WRITERS.get_or_init(|| {
            kr_ipc::install::hold_writers(
                &kr_ipc::install::Writing::in_roots(std::env::temp_dir(), std::env::temp_dir()),
                &mut || {},
            )
            .expect("a test outside a store holds nothing")
        });
        let permit = PERMIT.get_or_init(|| writers.permit(&PROFILE_WRITTEN).expect("permitted"));
        record.hold(permit)
    }

    fn a_file_profile() -> RecordedProfile {
        RecordedProfile {
            terminal: ProfileTerminal::Konsole,
            command: [
                "/opt/kr/current/bin/kr",
                "new",
                "--attach",
                "--hold-on-failure",
            ]
            .map(str::to_owned)
            .to_vec(),
            wrote: Wrote::File(FileWrote::intending(
                Path::new("/home/someone/.local/share/konsole/KalaReach.profile"),
                "[General]\n",
                &[PathBuf::from("/home/someone/.local/share/konsole")],
            )),
        }
    }

    fn a_settings_profile() -> RecordedProfile {
        RecordedProfile {
            terminal: ProfileTerminal::GnomeTerminal,
            command: vec!["/opt/kr/current/bin/kr".to_owned(), "new".to_owned()],
            wrote: Wrote::Settings(SettingsWrote {
                schema: "org.gnome.Terminal.Legacy.Profile".to_owned(),
                path: "/org/gnome/terminal/legacy/profiles:/:11111111-2222-4333-8444-555555555555/"
                    .to_owned(),
                keys: vec![RecordedKey {
                    key: "visible-name".to_owned(),
                    value: "'KalaReach'".to_owned(),
                }],
                list: RecordedList {
                    schema: "org.gnome.Terminal.ProfilesList".to_owned(),
                    key: "list".to_owned(),
                    member: "11111111-2222-4333-8444-555555555555".to_owned(),
                },
            }),
        }
    }

    /// The record is the shape the plan and the stored-formats lock describe: each profile names
    /// its emulator, its command and what was written, and a profile written again takes the
    /// place of the one before.
    #[test]
    fn the_record_round_trips_each_kind_of_write_and_keeps_one_profile_for_each_emulator() {
        let root = tempfile::tempdir().expect("a directory");
        let record = ProfileRecord::in_state_directory(&root.path().join("state"));
        assert!(
            record.profiles().expect("reads").is_empty(),
            "no record names nothing"
        );

        let held = hold_the_record(&record).expect("holds");
        held.put(a_file_profile()).expect("records");
        held.put(a_settings_profile()).expect("records");
        let mut again = a_file_profile();
        again.command.push("--extra".to_owned());
        held.put(again.clone()).expect("records");
        assert_eq!(
            record.profiles().expect("reads"),
            vec![again, a_settings_profile()],
            "an emulator has one profile, in the order first recorded"
        );
        drop(held);

        let written: serde_json::Value =
            serde_json::from_slice(&std::fs::read(record.path()).expect("the record"))
                .expect("JSON");
        assert_eq!(written["version"], PROFILE_RECORD_VERSION);
        assert_eq!(written["profiles"][0]["terminal"], "konsole");
        assert!(written["profiles"][0]["wrote"]["file"]["sha256"].is_string());
        assert_eq!(written["profiles"][1]["terminal"], "gnome-terminal");
        assert_eq!(
            written["profiles"][1]["wrote"]["settings"]["list"]["member"],
            "11111111-2222-4333-8444-555555555555"
        );

        let held = hold_the_record(&record).expect("holds again");
        held.forget(ProfileTerminal::Konsole).expect("forgets");
        assert_eq!(held.profiles().expect("reads"), vec![a_settings_profile()]);
        assert_eq!(
            held.profile(ProfileTerminal::Konsole).expect("reads"),
            None,
            "a forgotten emulator has none"
        );
    }

    /// A record that cannot be used stops everything and is left as it was: a later format, a file
    /// that is not a record, and one that states no format are each refused, and none is written
    /// over.
    #[test]
    fn a_record_that_cannot_be_used_is_refused_and_left_as_it_was() {
        let root = tempfile::tempdir().expect("a directory");
        let record = ProfileRecord::in_state_directory(&root.path().join("state"));
        drop(hold_the_record(&record).expect("holds"));

        for (text, later) in [
            (
                format!(
                    "{{\"version\":{},\"profiles\":[]}}",
                    PROFILE_RECORD_VERSION + 1
                ),
                true,
            ),
            ("not json".to_owned(), false),
            ("{\"profiles\":[]}".to_owned(), false),
            (
                "{\"version\":1,\"profiles\":[],\"extra\":true}".to_owned(),
                false,
            ),
        ] {
            kr_ipc::paths::write_owner_only_file(record.path(), text.as_bytes())
                .expect("rewritten");
            let refused = hold_the_record(&record).expect_err("an unusable record stops the hold");
            assert_eq!(
                matches!(refused, RecordError::Later { .. }),
                later,
                "{text}: {refused}"
            );
            assert!(record.profiles().is_err(), "{text}");
            assert_eq!(
                std::fs::read_to_string(record.path()).expect("the file"),
                text
            );
        }
    }
}
