//! The record a command that ends the control daemon keeps of its attempt, for the next command to
//! read.
//!
//! A command that was killed between asking the daemon to stop and seeing it end leaves no word of
//! what it did, and a person who finds no daemon cannot tell a daemon that was never started from
//! one that a command stopped. So each attempt writes one small file, named with the attempt's own
//! identity, in the environment's state directory before it asks, and its commands read the files
//! wherever they say that no control daemon runs.
//!
//! Who writes, rewrites and removes a file is fixed:
//!
//! - A command writes, rewrites and removes only its own file, and removes it once it has seen its
//!   own result.
//! - A control daemon of this build that has bound its endpoints removes the files that do not name
//!   it as the daemon to stop, among the first [`CLEAN_LIMIT`] entries it reads, and leaves the rest
//!   ([`remove_those_that_stop_another_daemon`]): a daemon that serves is a daemon that some
//!   command's attempt did not leave without one.
//! - A command at its start reads the files of attempts whose process has gone, and removes those
//!   only after its own result has been written and has put them out ([`Recorded::remove`]).
//! - A reader of a message that no control daemon runs removes nothing.
//!
//! No rule goes by a file's time, and the lock file's time says nothing: a daemon that takes the
//! lock and fails leaves the same file as one that serves. A file is "under way" only where a live
//! process has the start identity the file names; otherwise it is the last phase its command
//! recorded and the time of that phase, a record and not a claim of what happened after it.
//!
//! A file that cannot be read or parsed is read as none: no release needs another's file, and a
//! file holds no text or data of a person.

use std::path::{Path, PathBuf};

use kr_ipc::identity::ProcessState;
use kr_ipc::paths::EnvironmentPaths;
use kr_protocol::identity::ProcessStartIdentity;
use serde::{Deserialize, Serialize};

/// The directory in an environment's state directory that holds one file for each attempt.
pub const DIRECTORY: &str = "host-attempts";

/// The most a file is read for: a file this host wrote is far smaller.
const READ_LIMIT: u64 = 4096;

/// The most entries of the attempts' directory that a daemon reads at its start. A file is the
/// record of one command that was killed, and a command removes its own, so a real folder holds a
/// handful; the daemon does not spend its start on a folder that holds more. What it leaves, a
/// later daemon or a command reads.
pub const CLEAN_LIMIT: usize = 64;

/// The command that made an attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Command {
    /// `kr host stop`.
    Stop,
}

/// How far an attempt had come when it last wrote its file.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    /// The command is about to ask the daemon to stop, or has asked and not been answered.
    Asking,
    /// The daemon answered that it takes the stop, or the answer is unknown and the daemon is
    /// waited for as one that does.
    Told,
}

/// What an attempt's file holds.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Attempt {
    /// The command.
    pub command: Command,
    /// The last phase it recorded.
    pub phase: Phase,
    /// The command's own process, with its start identity.
    pub process: ProcessStartIdentity,
    /// The time of that phase, in milliseconds since the epoch.
    pub at_ms: u64,
    /// The daemon the attempt stops, where it could be named before the stop was asked.
    pub daemon: Option<ProcessStartIdentity>,
}

/// The directory of an environment's attempts.
fn directory(environment: &EnvironmentPaths) -> PathBuf {
    environment.state_dir().join(DIRECTORY)
}

/// A command's own file: the one it wrote, which it alone rewrites and removes.
#[derive(Debug)]
pub struct Marker {
    path: PathBuf,
    attempt: Attempt,
}

impl Marker {
    /// Writes a command's file for an attempt that is about to ask, naming the daemon it stops
    /// where it is known.
    ///
    /// # Errors
    ///
    /// Returns the failure to write it, or to read this process's own start identity.
    pub fn begin(
        environment: &EnvironmentPaths,
        command: Command,
        daemon: Option<ProcessStartIdentity>,
    ) -> kr_ipc::Result<Self> {
        let directory = directory(environment);
        kr_ipc::paths::create_private_directory(&directory)?;
        let marker = Self {
            path: directory.join(kr_ipc::new_uuid().to_string()),
            attempt: Attempt {
                command,
                phase: Phase::Asking,
                process: kr_ipc::identity::current_process_start_identity()?,
                at_ms: kr_ipc::now_ms().get(),
                daemon,
            },
        };
        marker.write()?;
        Ok(marker)
    }

    /// Records that the daemon has been told to stop, with the time.
    ///
    /// # Errors
    ///
    /// Returns the failure to write the file.
    pub fn told(&mut self) -> kr_ipc::Result<()> {
        self.attempt.phase = Phase::Told;
        self.attempt.at_ms = kr_ipc::now_ms().get();
        self.write()
    }

    /// Removes the file. A file that is already gone is the daemon's removal at its start or the
    /// command's own earlier one, and is not a failure.
    pub fn remove(&self) {
        let _ = std::fs::remove_file(&self.path);
    }

    /// What the file holds.
    #[must_use]
    pub const fn attempt(&self) -> &Attempt {
        &self.attempt
    }

    fn write(&self) -> kr_ipc::Result<()> {
        let bytes = serde_json::to_vec(&self.attempt).map_err(|error| {
            kr_ipc::IpcError::io(
                "encode",
                &self.path,
                std::io::Error::new(std::io::ErrorKind::InvalidData, error),
            )
        })?;
        kr_ipc::paths::write_owner_only_file(&self.path, &bytes)
    }
}

/// An attempt's file as another command finds it.
#[derive(Clone, Debug)]
pub struct Recorded {
    path: PathBuf,
    /// What the file holds.
    pub attempt: Attempt,
}

/// Whether the process that wrote an attempt's file is still the one that wrote it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Standing {
    /// A live process has the file's start identity: the attempt is under way.
    UnderWay,
    /// No process has it: the process has ended, or its number belongs to another process now,
    /// which is what a restart of the machine leaves.
    Gone,
    /// The system did not say.
    Unknown,
}

impl Recorded {
    /// Whether the attempt's own process lives.
    #[must_use]
    pub fn standing(&self) -> Standing {
        match kr_ipc::identity::process_state(&self.attempt.process) {
            ProcessState::Running => Standing::UnderWay,
            ProcessState::Ended => Standing::Gone,
            ProcessState::Unknown { .. } => Standing::Unknown,
        }
    }

    /// Removes the file: the removal of a command that has put it out in its own result.
    pub fn remove(&self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Every attempt's file of an environment that can be read, in the order of their times. A file
/// that cannot be read, parsed or trusted is none.
#[must_use]
pub fn recorded(environment: &EnvironmentPaths) -> Vec<Recorded> {
    found(environment, usize::MAX)
}

/// The files among the first `at_most` entries of the environment's directory that can be read.
fn found(environment: &EnvironmentPaths, at_most: usize) -> Vec<Recorded> {
    let Ok(entries) = std::fs::read_dir(directory(environment)) else {
        return Vec::new();
    };
    let mut found: Vec<Recorded> = entries
        .take(at_most)
        .filter_map(std::result::Result::ok)
        .filter_map(|entry| read(&entry.path()))
        .collect();
    found.sort_by_key(|recorded| recorded.attempt.at_ms);
    found
}

fn read(path: &Path) -> Option<Recorded> {
    // A temporary file of a write under way is not an attempt's file.
    if path
        .file_name()
        .and_then(|name| name.to_str())
        .is_none_or(|name| name.starts_with('.'))
    {
        return None;
    }
    let bytes = kr_ipc::paths::read_owner_only_file(path, READ_LIMIT)
        .ok()
        .flatten()?;
    let attempt = serde_json::from_slice(&bytes).ok()?;
    Some(Recorded {
        path: path.to_path_buf(),
        attempt,
    })
}

/// Removes the attempts' files of an environment that do not name `daemon` as the daemon to stop,
/// among the first [`CLEAN_LIMIT`] entries of its directory, and says how many it removed. A
/// control daemon calls it right after it has bound its endpoints: it serves, so no attempt that
/// named another daemon is a stop that is still to come, and an attempt that names this daemon is
/// a stop of this daemon that is under way. The entries past the limit are left.
pub fn remove_those_that_stop_another_daemon(
    environment: &EnvironmentPaths,
    daemon: &ProcessStartIdentity,
) -> usize {
    found(environment, CLEAN_LIMIT)
        .into_iter()
        .filter(|recorded| recorded.attempt.daemon.as_ref() != Some(daemon))
        .map(|recorded| recorded.remove())
        .count()
}

#[cfg(test)]
mod tests {
    use kr_protocol::identity::ProcessStartIdentity;

    use super::*;

    fn temp() -> kr_ipc::testing::TempHost {
        kr_ipc::testing::TempHost::create()
    }

    fn own() -> ProcessStartIdentity {
        kr_ipc::identity::current_process_start_identity().expect("an identity")
    }

    /// A process that is not this one, with an identity of its own, for a daemon that is named.
    fn another(start: u64) -> ProcessStartIdentity {
        let mut identity = own();
        identity.start_value = kr_protocol::scalars::U64::new(identity.start_value.get() + start);
        identity
    }

    /// Writes a record as a command of another process would have left it.
    fn left_by(
        environment: &EnvironmentPaths,
        name: &str,
        process: ProcessStartIdentity,
        at_ms: u64,
        daemon: Option<ProcessStartIdentity>,
    ) {
        let directory = directory(environment);
        kr_ipc::paths::create_private_directory(&directory).expect("the directory");
        let attempt = Attempt {
            command: Command::Stop,
            phase: Phase::Told,
            process,
            at_ms,
            daemon,
        };
        kr_ipc::paths::write_owner_only_file(
            &directory.join(name),
            &serde_json::to_vec(&attempt).expect("encodes"),
        )
        .expect("writes the record");
    }

    /// An attempt is under way only where a live process has the identity its file names, whatever
    /// the file's age: a process that holds the number under another start, which is what a restart
    /// of the machine leaves, is gone, and so is one that ended. No rule goes by a time.
    #[test]
    fn an_attempt_is_under_way_only_where_a_live_process_has_its_identity() {
        let host = temp();
        let environment = host.environment();
        left_by(&environment, "alive-and-old", own(), 1, None);
        left_by(
            &environment,
            "same-number-after-a-restart",
            another(1),
            2,
            None,
        );
        left_by(
            &environment,
            "ended",
            kr_ipc::identity::ended_process_identity(std::process::id()),
            3,
            None,
        );
        let found = recorded(&environment);
        let standing = |at_ms: u64| {
            found
                .iter()
                .find(|recorded| recorded.attempt.at_ms == at_ms)
                .expect("the record is read")
                .standing()
        };
        assert_eq!(standing(1), Standing::UnderWay);
        assert_eq!(standing(2), Standing::Gone);
        assert_eq!(standing(3), Standing::Gone);
    }

    /// Two commands at once keep a file each, a command rewrites and removes only its own, and
    /// reading removes nothing.
    #[test]
    fn two_commands_keep_a_file_each_and_each_removes_only_its_own() {
        let host = temp();
        let environment = host.environment();
        let mut first =
            Marker::begin(&environment, Command::Stop, Some(another(7))).expect("first");
        let second = Marker::begin(&environment, Command::Stop, None).expect("second");
        assert_eq!(recorded(&environment).len(), 2);
        first.told().expect("rewrites its own");
        let found = recorded(&environment);
        assert_eq!(found.len(), 2, "rewriting writes no other file");
        assert_eq!(
            found
                .iter()
                .filter(|recorded| recorded.attempt.phase == Phase::Told)
                .count(),
            1,
            "only the one that was rewritten is told"
        );
        let _ = recorded(&environment);
        first.remove();
        let left = recorded(&environment);
        assert_eq!(left.len(), 1, "the second command's file stands");
        assert_eq!(left[0].attempt.phase, Phase::Asking);
        assert_eq!(left[0].attempt, *second.attempt());
    }

    /// A daemon that serves removes every file that does not name it as the daemon to stop, and the
    /// control: the file that names it stays, because that stop is still to come.
    #[test]
    fn a_daemon_removes_the_files_that_do_not_name_it_and_leaves_the_one_that_does() {
        let host = temp();
        let environment = host.environment();
        let this_daemon = another(100);
        left_by(
            &environment,
            "names-it",
            own(),
            1,
            Some(this_daemon.clone()),
        );
        left_by(&environment, "names-an-older", own(), 2, Some(another(5)));
        left_by(&environment, "names-none", own(), 3, None);
        let removed = remove_those_that_stop_another_daemon(&environment, &this_daemon);
        assert_eq!(removed, 2);
        let left = recorded(&environment);
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].attempt.daemon.as_ref(), Some(&this_daemon));
    }

    /// The daemon's clean-up at its start reads a bounded number of entries and leaves the rest,
    /// which a later reader still finds.
    #[test]
    fn a_daemon_reads_a_bounded_number_of_entries_and_leaves_the_rest() {
        let host = temp();
        let environment = host.environment();
        let this_daemon = another(100);
        for number in 0..CLEAN_LIMIT + 5 {
            left_by(&environment, &format!("file-{number}"), own(), 1, None);
        }
        let removed = remove_those_that_stop_another_daemon(&environment, &this_daemon);
        assert_eq!(removed, CLEAN_LIMIT);
        assert_eq!(recorded(&environment).len(), 5, "the rest is left");
    }

    /// A file that cannot be parsed is none, and is not removed by reading it.
    #[test]
    fn a_file_that_cannot_be_read_is_none_and_reading_removes_nothing() {
        let host = temp();
        let environment = host.environment();
        let directory = directory(&environment);
        kr_ipc::paths::create_private_directory(&directory).expect("the directory");
        kr_ipc::paths::write_owner_only_file(&directory.join("garbage"), b"not a record")
            .expect("writes");
        assert!(recorded(&environment).is_empty());
        assert!(
            directory.join("garbage").exists(),
            "reading removed nothing"
        );
    }

    /// A stop's record keeps its bytes, and a record of that form is read as it was.
    #[test]
    fn a_stops_record_keeps_its_bytes_and_a_record_of_that_form_is_read() {
        let process = ProcessStartIdentity::new(
            4242,
            kr_protocol::identity::ProcessStartSource::LinuxProcStat,
            99,
        );
        let daemon = ProcessStartIdentity::new(
            77,
            kr_protocol::identity::ProcessStartSource::MacosProcBsdInfo,
            5,
        );
        for (command, phase, daemon, bytes) in [
            (
                Command::Stop,
                Phase::Asking,
                None,
                r#"{"command":"stop","phase":"asking","process":{"pid":"4242","source":"linux_proc_stat","start_value":"99"},"at_ms":1700000000000,"daemon":null}"#,
            ),
            (
                Command::Stop,
                Phase::Told,
                Some(daemon.clone()),
                r#"{"command":"stop","phase":"told","process":{"pid":"4242","source":"linux_proc_stat","start_value":"99"},"at_ms":1700000000000,"daemon":{"pid":"77","source":"macos_proc_bsd_info","start_value":"5"}}"#,
            ),
        ] {
            let attempt = Attempt {
                command,
                phase,
                process: process.clone(),
                at_ms: 1_700_000_000_000,
                daemon,
            };
            assert_eq!(
                String::from_utf8(serde_json::to_vec(&attempt).expect("encodes")).expect("text"),
                bytes
            );
            let host = temp();
            let environment = host.environment();
            let directory = directory(&environment);
            kr_ipc::paths::create_private_directory(&directory).expect("the directory");
            kr_ipc::paths::write_owner_only_file(
                &directory.join("an-old-record"),
                bytes.as_bytes(),
            )
            .expect("writes");
            let read = recorded(&environment);
            assert_eq!(read.len(), 1, "a record of the old form is read");
            assert_eq!(read[0].attempt, attempt);
        }
    }

    /// A file whose command or phase is a value this release does not know is read as none, and
    /// neither a command's read nor a daemon's clean-up removes it: what any release does with the
    /// file of a command that it does not have.
    #[test]
    fn a_record_of_a_value_this_release_does_not_know_is_none_and_nothing_removes_it() {
        let host = temp();
        let environment = host.environment();
        let directory = directory(&environment);
        kr_ipc::paths::create_private_directory(&directory).expect("the directory");
        let process = r#"{"pid":"4242","source":"linux_proc_stat","start_value":"99"}"#;
        for (name, command, phase) in [
            ("another-command", "hibernate", "told"),
            ("another-phase", "stop", "sleeping"),
            // The control: the same shape with values that this release has.
            ("a-known-one", "stop", "told"),
        ] {
            let text = format!(
                r#"{{"command":"{command}","phase":"{phase}","process":{process},"at_ms":1,"daemon":null}}"#
            );
            kr_ipc::paths::write_owner_only_file(&directory.join(name), text.as_bytes())
                .expect("writes");
        }
        assert_eq!(
            recorded(&environment).len(),
            1,
            "only the record of known values is read"
        );
        assert_eq!(
            remove_those_that_stop_another_daemon(&environment, &another(1)),
            1,
            "the clean-up removes the one it read"
        );
        for name in ["another-command", "another-phase"] {
            assert!(directory.join(name).exists(), "{name} stands");
        }
        assert!(!directory.join("a-known-one").exists());
    }
}
