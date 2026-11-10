//! What an environment's daemon and workers created, for the tests that say nothing was.
//!
//! A test that shows nothing ran beside an idle session cannot look at the process table for it: a
//! process that has ended, one that started after the last look, and one that gave up its parent,
//! its directory and its environment are not in a table read at one moment. This is the other
//! way: the places that create a process for a session (the worker's root shell, backend server,
//! backend probe, platform questions and desktop checks, and the daemon's description process)
//! write one line here before they create it, so a creation that fails is a line too. On Windows
//! the same places write, and so do the worker's check of the kernel's clock and, as a platform
//! question, its query of the time service (the starts that are made through the system's own
//! create rather than through [`std::process::Command`] name their words, [`note_words_here`]).
//! Other places write none. A test reads the lines once it can say, by a condition of its own, that
//! those places have nothing more to be asked for.
//!
//! The record is a file in the environment's state directory, so the daemon and every worker of
//! the environment write to the one list. It exists only where a test made it ([`begin`]); a
//! creation where there is none writes nothing. A worker is told where the record is when it
//! starts ([`here`]). A daemon a test runs in its own process is found by the runtime it runs on:
//! the helpers it shares with the worker (a platform question, a backend's probe) write to the
//! record of the runtime that is current, from any task or blocking thread of it, so a call from
//! a place nobody listed is recorded too. A thread the daemon makes outside its runtime is not
//! found, and writes nothing unless it names the state directory ([`note_in`]). Each line holds the process that wrote it, the
//! kind of creation, the program and its arguments, separated by tabs, with a tab, a line end and
//! a backslash in a field written as a backslash and a letter.
//!
//! This module is compiled only with the `testing` feature, which no shipped build enables, and
//! every call to it is behind the same feature.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock, PoisonError};

/// The name of the record, in an environment's state directory.
pub const FILE: &str = "created-processes";

/// One process that a daemon or a worker created, or was about to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Created {
    /// The process that created it.
    pub by: u32,
    /// What it was created as: the name of the place that creates it.
    pub what: String,
    /// The program, as the creating process named it.
    pub program: String,
    /// Its arguments.
    pub arguments: Vec<String>,
}

/// The record of the process this is, once it has been told where it is.
static HERE: OnceLock<PathBuf> = OnceLock::new();

/// The record of each runtime a test made one on. A test runs one environment's daemon on the
/// runtime it is run by, so the runtime says which environment a call of the daemon's belongs to.
static BY_RUNTIME: Mutex<Vec<(tokio::runtime::Id, PathBuf)>> = Mutex::new(Vec::new());

/// Makes the environment's record, empty, owner-only: from here on what the daemon and its
/// workers create is written to it. Called from the runtime that runs the environment's daemon,
/// it is also the record of every call that runtime's tasks and blocking threads make; a runtime
/// has one record, the last one made on it.
///
/// # Errors
///
/// Returns why the file could not be made.
pub fn begin(state_dir: &Path) -> std::io::Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;

        options.mode(0o600);
    }
    options.open(state_dir.join(FILE))?;
    if let Ok(runtime) = tokio::runtime::Handle::try_current() {
        let mut made = BY_RUNTIME.lock().unwrap_or_else(PoisonError::into_inner);
        made.retain(|(id, _)| *id != runtime.id());
        made.push((runtime.id(), state_dir.join(FILE)));
    }
    Ok(())
}

/// Tells this process where its environment's record is. The first telling is the one that counts:
/// a worker serves one environment.
pub fn here(state_dir: &Path) {
    let _ = HERE.set(state_dir.join(FILE));
}

/// Writes that this process is about to create `command`, as `what`, to the record this process
/// was told of by [`here`], or else to the record of the runtime the call is made on. Nothing is
/// written where there is neither.
///
/// # Panics
///
/// Panics when a record that exists cannot be written: a creation that is not in the record
/// would pass for one that did not happen.
pub fn note_here(what: &str, command: &std::process::Command) {
    let (program, arguments) = words_of(command);
    note_words_here(what, &program, &arguments);
}

/// Writes that this process is about to create a process named by `program` and `arguments`, as
/// `what`, where [`note_here`] would. For a creation that does not go through
/// [`std::process::Command`], such as a Windows start that calls the system's own create; the
/// place says the words it hands the system.
///
/// # Panics
///
/// As [`note_here`].
pub fn note_words_here(what: &str, program: &str, arguments: &[String]) {
    let file = HERE.get().cloned().or_else(|| {
        let runtime = tokio::runtime::Handle::try_current().ok()?;
        BY_RUNTIME
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .find(|(id, _)| *id == runtime.id())
            .map(|(_, file)| file.clone())
    });
    if let Some(file) = file {
        append(&file, what, program, arguments);
    }
}

/// Writes that this process is about to create `command`, as `what`, to the record of the
/// environment whose state directory is `state_dir`, where a test made one.
///
/// # Panics
///
/// As [`note_here`].
pub fn note_in(state_dir: &Path, what: &str, command: &std::process::Command) {
    let (program, arguments) = words_of(command);
    append(&state_dir.join(FILE), what, &program, &arguments);
}

/// The program of a command and its arguments, as text.
fn words_of(command: &std::process::Command) -> (String, Vec<String>) {
    (
        command.get_program().to_string_lossy().into_owned(),
        command
            .get_args()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect(),
    )
}

fn append(file: &Path, what: &str, program: &str, arguments: &[String]) {
    let mut line = format!("{}", std::process::id());
    for field in [what, program]
        .into_iter()
        .chain(arguments.iter().map(String::as_str))
    {
        line.push('\t');
        escape_into(&mut line, field);
    }
    line.push('\n');
    // Not created: a record exists only where a test made it. One write, so that two processes
    // appending at once do not mix their lines.
    let opened = std::fs::OpenOptions::new().append(true).open(file);
    match opened {
        Ok(mut record) => record.write_all(line.as_bytes()).unwrap_or_else(|error| {
            panic!(
                "the creation record {} cannot be written: {error}",
                file.display()
            )
        }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => panic!(
            "the creation record {} cannot be opened: {error}",
            file.display()
        ),
    }
}

/// Everything the environment's daemon and workers have written to its record, in the order
/// written.
///
/// # Errors
///
/// Returns why the record could not be read, or a line of it is not one this module wrote.
pub fn read(state_dir: &Path) -> Result<Vec<Created>, String> {
    let file = state_dir.join(FILE);
    let text = std::fs::read_to_string(&file).map_err(|error| {
        format!(
            "the creation record {} cannot be read: {error}",
            file.display()
        )
    })?;
    text.lines()
        .map(|line| {
            let mut fields = line.split('\t').map(unescape);
            let by = fields
                .next()
                .and_then(|pid| pid.parse().ok())
                .ok_or_else(|| {
                    format!("a line of the creation record names no process: {line:?}")
                })?;
            let (Some(what), Some(program)) = (fields.next(), fields.next()) else {
                return Err(format!("a line of the creation record is short: {line:?}"));
            };
            Ok(Created {
                by,
                what,
                program,
                arguments: fields.collect(),
            })
        })
        .collect()
}

fn escape_into(line: &mut String, field: &str) {
    for character in field.chars() {
        match character {
            '\\' => line.push_str("\\\\"),
            '\t' => line.push_str("\\t"),
            '\n' => line.push_str("\\n"),
            '\r' => line.push_str("\\r"),
            other => line.push(other),
        }
    }
}

fn unescape(field: &str) -> String {
    let mut text = String::with_capacity(field.len());
    let mut characters = field.chars();
    while let Some(character) = characters.next() {
        if character != '\\' {
            text.push(character);
            continue;
        }
        match characters.next() {
            Some('t') => text.push('\t'),
            Some('n') => text.push('\n'),
            Some('r') => text.push('\r'),
            Some(other) => text.push(other),
            None => text.push('\\'),
        }
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A call on the runtime a record was made on, from one of its tasks or one of its blocking
    /// threads, is written to that record; a call on a thread that has no runtime, and one on
    /// another runtime with no record of its own, is written to none.
    #[tokio::test]
    async fn a_call_is_written_to_the_record_of_the_runtime_it_is_made_on() {
        let host = crate::testing::TempHost::create();
        let state = host.environment().state_dir().to_path_buf();
        begin(&state).expect("makes the record");
        let named = |name: &str| std::process::Command::new(name);
        note_here("task", &named("on-the-runtime"));
        note_words_here("words", "by-its-words", &["one".to_owned()]);
        tokio::task::spawn_blocking(|| {
            note_here("blocking", &std::process::Command::new("blocking"))
        })
        .await
        .expect("the blocking thread ends");
        std::thread::spawn(|| note_here("thread", &std::process::Command::new("no-runtime")))
            .join()
            .expect("the thread ends");
        std::thread::spawn(|| {
            tokio::runtime::Builder::new_current_thread()
                .build()
                .expect("another runtime")
                .block_on(async { note_here("other", &std::process::Command::new("elsewhere")) });
        })
        .join()
        .expect("the thread ends");
        let written: Vec<String> = read(&state)
            .expect("reads the record")
            .into_iter()
            .map(|created| created.program)
            .collect();
        assert_eq!(written, ["on-the-runtime", "by-its-words", "blocking"]);
    }

    /// A record that was made is read back as it was written, whatever a field holds, and a
    /// creation where no record was made is not written anywhere.
    #[test]
    fn a_creation_is_read_back_as_written_and_is_written_only_where_a_record_was_made() {
        let host = crate::testing::TempHost::create();
        let state = host.environment().state_dir().to_path_buf();
        let mut command = std::process::Command::new("a program");
        command.args(["one\ttwo", "line\nend", "back\\slash", ""]);
        note_in(&state, "unrecorded", &command);
        assert!(
            read(&state).is_err(),
            "a creation with no record made writes none"
        );
        begin(&state).expect("makes the record");
        note_in(&state, "question", &command);
        note_in(&state, "shell", &std::process::Command::new("sh"));
        assert_eq!(
            read(&state).expect("reads the record"),
            [
                Created {
                    by: std::process::id(),
                    what: "question".to_owned(),
                    program: "a program".to_owned(),
                    arguments: ["one\ttwo", "line\nend", "back\\slash", ""]
                        .map(str::to_owned)
                        .to_vec(),
                },
                Created {
                    by: std::process::id(),
                    what: "shell".to_owned(),
                    program: "sh".to_owned(),
                    arguments: Vec::new(),
                },
            ]
        );
    }
}
