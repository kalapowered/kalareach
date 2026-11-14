//! What the report keeps of a program a step could not run.
//!
//! A step that fails because the system refused to start a program (Cargo's "could not execute
//! process", the runner's "could not start", or exit 126 with the shell's "cannot execute binary
//! file") has its failure recorded as it is: the step ran once and stays failed. This module only
//! records what the program's file looked like at that moment, read once and with bounds, so that a
//! person can tell a file the linker left empty or cut short from one that is whole. It decides
//! nothing, removes nothing, and starts no program.

use std::fs::{File, Metadata, OpenOptions};
use std::io::{self, BufRead, BufReader, ErrorKind, Read};
use std::path::Path;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Serialize;

/// How many bytes of a program's start are read: the header and room for its load commands.
const HEAD_BYTES: usize = 65_536;

/// The size of a page, below which a program is cut short and whose first bytes are never all zero
/// in a program that was written whole.
const PAGE: usize = 4096;

/// How long the read of one file may take before it is given up.
const READ_LIMIT: Duration = Duration::from_secs(10);

/// How many programs one step's observation names.
const MOST_PROGRAMS: usize = 8;

/// How many lines after Cargo's "could not execute process" line are kept with it, for the cause
/// Cargo gives under "Caused by:".
const CAUSE_LINES: usize = 5;

/// The longest line of a log that is read whole.
const LONGEST_LINE: u64 = 8192;

/// A Mach-O header of a 64-bit program, read as a little-endian word.
const MACH_O_64: u32 = 0xfeed_facf;

/// The load command of a 64-bit segment.
const SEGMENT_64: u32 = 0x19;

/// What a step's log says about programs the system would not start.
#[derive(Clone, Debug, Serialize)]
pub struct Observed {
    /// Why the log was not read, when it was not: what was found at its path in place of a regular
    /// file, or why it could not be read. No program is then named.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log: Option<Found>,
    /// Each program, in the order the log names them.
    pub programs: Vec<Program>,
    /// Whether the log also shows a test that ran and failed. Such a step failed for more than a
    /// program that could not be run, whatever the programs show.
    pub test_failed: bool,
    /// Whether the log shows a failure that no program named accounts for: a program that ended
    /// without being refused, a target with a harness of its own that exited with a failure, or a
    /// build that did not compile.
    pub unexplained_failure: bool,
    /// Whether the log names more programs than the record holds.
    pub incomplete: bool,
}

impl Observed {
    /// Whether the step fits a program written damaged: its log was read whole, no test ran and
    /// failed, no failure is left that a refused program does not account for, the record names
    /// every program that was refused, and every one of them shows damage.
    #[must_use]
    pub fn damage_seen(&self) -> bool {
        self.log.is_none()
            && !self.test_failed
            && !self.unexplained_failure
            && !self.incomplete
            && !self.programs.is_empty()
            && self.programs.iter().all(|program| {
                matches!(
                    &program.file,
                    Found::Read {
                        damage: Some(_),
                        ..
                    }
                )
            })
    }
}

/// One program a step could not run, and what its file looked like when the step ended.
#[derive(Clone, Debug, Serialize)]
pub struct Program {
    /// The path as the log names it.
    pub path: String,
    /// The log's own lines about it.
    pub lines: Vec<String>,
    /// Whether the runner recorded, in a file of its own that no program is told of, that it could
    /// not start the program. The log's lines say the same for people and do not decide this.
    pub said_by_runner: bool,
    /// When the file was looked at, in seconds since the epoch.
    pub observed_at: u64,
    /// What was found.
    pub file: Found,
}

/// What was found at a program's path.
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum Found {
    /// A regular file, read.
    Read {
        /// Its length.
        size: u64,
        /// Its first 32 bytes, in hexadecimal.
        first_bytes: String,
        /// When it was last written, in seconds since the epoch, when the system says.
        modified: Option<u64>,
        /// When it was made, in seconds since the epoch, when the system says.
        created: Option<u64>,
        /// The damage its first bytes and length show, or none when none is seen.
        damage: Option<String>,
    },
    /// A link or another kind of object: it is named and not read.
    Other {
        /// What the object is.
        kind: String,
    },
    /// Nothing could be read.
    NotRead {
        /// Why.
        reason: String,
    },
}

impl std::fmt::Display for Found {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Read {
                size,
                damage: Some(damage),
                ..
            } => write!(formatter, "{size} bytes, damage seen: {damage}"),
            Self::Read { size, .. } => write!(formatter, "{size} bytes, no damage seen"),
            Self::Other { kind } => write!(formatter, "{kind}, not read"),
            Self::NotRead { reason } => write!(formatter, "not read: {reason}"),
        }
    }
}

/// One program the text of a log says could not be run, before its file is looked at.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Refusal {
    path: String,
    lines: Vec<String>,
}

/// Whether a line opens or closes a test's captured output in the standard harness's summary.
fn opens_test_output(line: &str) -> bool {
    line.starts_with("---- ") && (line.ends_with(" stdout ----") || line.ends_with(" stderr ----"))
}

/// What a log shows besides the programs it names.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Facts {
    /// A test ran and failed.
    test_failed: bool,
    /// The log shows a failure that none of the programs named accounts for: a program that ended
    /// without being refused, or a build that did not compile.
    unexplained_failure: bool,
    /// Another program was refused than the cap lets the record name.
    incomplete: bool,
}

/// How many commands that a failed step names are kept to be matched with the programs.
const MOST_FAILED_COMMANDS: usize = 64;

/// The programs a log says could not be run, from the report's and Cargo's own lines and not from
/// what a test printed: a test's captured output, which the harness prints between its
/// `---- <name> stdout ----` line and the line `failures:` or `successes:`, is passed over. The
/// second value says what else the log shows.
fn refusals(lines: impl Iterator<Item = String>) -> (Vec<Refusal>, Facts) {
    let mut found: Vec<Refusal> = Vec::new();
    // The shell's lines, as many distinct programs as a step can name: no more can be used.
    let mut shell: Vec<(String, String)> = Vec::new();
    let mut facts = Facts::default();
    let mut saw_126 = false;
    let mut shell_left_out = false;
    let mut compile_failed = false;
    let mut failed_commands: Vec<String> = Vec::new();
    let mut in_test_output = false;
    let mut cause: Option<(usize, usize)> = None;
    for line in lines {
        let trimmed = line.trim();
        if trimmed.starts_with("test result: FAILED")
            || (trimmed.starts_with("test ") && trimmed.ends_with(" ... FAILED"))
        {
            facts.test_failed = true;
        }
        if opens_test_output(trimmed) {
            in_test_output = true;
            cause = None;
            continue;
        }
        if in_test_output {
            if trimmed == "failures:" || trimmed == "successes:" || trimmed.starts_with("---- ") {
                in_test_output = false;
            }
            continue;
        }
        if trimmed.starts_with("error: could not compile") || trimmed.starts_with("error[") {
            compile_failed = true;
        }
        if let Some((_, rest)) = trimmed.split_once("process didn't exit successfully: `") {
            if failed_commands.len() < MOST_FAILED_COMMANDS {
                failed_commands.push(rest.split('`').next().unwrap_or_default().to_owned());
            } else {
                facts.unexplained_failure = true;
            }
        }
        if let Some((index, left)) = cause {
            let another = cargo_refusal(trimmed).is_some()
                || runner_refusal(trimmed).is_some()
                || shell_refusal(trimmed).is_some();
            if left > 0 && !another {
                found[index].lines.push(trimmed.to_owned());
                cause = Some((index, left - 1));
                continue;
            }
            cause = None;
        }
        if trimmed.contains("exit status: 126") || trimmed.contains("(exit 126)") {
            saw_126 = true;
        }
        let named = cargo_refusal(trimmed)
            .map(|path| (path, true))
            .or_else(|| runner_refusal(trimmed).map(|path| (path, false)));
        if let Some((path, from_cargo)) = named {
            if found.iter().any(|known| known.path == path) {
                continue;
            }
            if found.len() >= MOST_PROGRAMS {
                facts.incomplete = true;
                continue;
            }
            found.push(Refusal {
                path,
                lines: vec![trimmed.to_owned()],
            });
            if from_cargo {
                cause = Some((found.len() - 1, CAUSE_LINES));
            }
        } else if let Some(path) = shell_refusal(trimmed)
            && !shell.iter().any(|(known, _)| *known == path)
        {
            if shell.len() < MOST_PROGRAMS {
                shell.push((path, trimmed.to_owned()));
            } else {
                shell_left_out = true;
            }
        }
    }
    if saw_126 {
        facts.incomplete |= shell_left_out;
        for (path, line) in shell {
            if found.iter().any(|known| known.path == path) {
                continue;
            }
            if found.len() >= MOST_PROGRAMS {
                facts.incomplete = true;
                continue;
            }
            found.push(Refusal {
                path,
                lines: vec![line],
            });
        }
    }
    for refusal in &mut found {
        while refusal.lines.last().is_some_and(String::is_empty) {
            refusal.lines.pop();
        }
    }
    facts.unexplained_failure |= compile_failed
        || failed_commands
            .iter()
            .any(|command| !found.iter().any(|known| command.contains(&known.path)));
    (found, facts)
}

/// The program in Cargo's "could not execute process `<program> <arguments>`".
fn cargo_refusal(line: &str) -> Option<String> {
    let (_, rest) = line.split_once("could not execute process `")?;
    let (command, _) = rest.split_once('`')?;
    command.split_whitespace().next().map(str::to_owned)
}

/// The program in the runner's "<runner>: <program> could not start: <error>".
fn runner_refusal(line: &str) -> Option<String> {
    let rest = line
        .strip_prefix("kr-conformance run-one: ")
        .or_else(|| line.strip_prefix("kr-conformance list-one: "))?;
    let (path, _) = rest.split_once(" could not start: ")?;
    Some(path.to_owned())
}

/// The program in the shell's "<program>: <program>: cannot execute binary file".
fn shell_refusal(line: &str) -> Option<String> {
    let body = line.strip_suffix(": cannot execute binary file")?;
    let (first, second) = body.split_once(": ")?;
    (first == second && !first.is_empty()).then(|| first.to_owned())
}

/// What a step's log, read at the moment the step ended, says of the programs it could not run.
/// `records` is the directory in which the runner records a program that it could not start.
/// `None` when the log names none and was read whole, or when there is no log. A log that is a link
/// or another object that is not a regular file, or that cannot be read in ten seconds, or whose
/// read failed part of the way, is recorded as such, and what it names before that is kept.
#[must_use]
pub fn observe_log(log: &Path, records: &Path, now: SystemTime) -> Option<Observed> {
    if matches!(std::fs::symlink_metadata(log), Err(error) if error.kind() == ErrorKind::NotFound) {
        return None;
    }
    let unread = |found| {
        Some(Observed {
            log: Some(found),
            programs: Vec::new(),
            test_failed: false,
            unexplained_failure: false,
            incomplete: false,
        })
    };
    let seen = match examine(log) {
        Ok(seen) => seen,
        Err(found) => return unread(found),
    };
    let owned = log.to_path_buf();
    let read = match bounded(READ_LIMIT, move || read_log(&owned, &seen)) {
        Ok(Ok(read)) => read,
        Ok(Err(found)) => return unread(found),
        Err(reason) => return unread(Found::NotRead { reason }),
    };
    observed(read, records, now)
}

/// The observation of what a log held, or `None` when it named no program and was read whole.
fn observed(read: LogRead, records: &Path, now: SystemTime) -> Option<Observed> {
    if read.refused.is_empty() && read.error.is_none() {
        return None;
    }
    Some(Observed {
        log: read.error.map(|error| Found::NotRead {
            reason: format!("the log could not be read past its position: {error}"),
        }),
        programs: read
            .refused
            .into_iter()
            .map(|refusal| Program {
                file: observe_file(Path::new(&refusal.path)),
                said_by_runner: recorded_by_runner(records, &refusal.path),
                path: refusal.path,
                lines: refusal.lines,
                observed_at: epoch(now).unwrap_or(0),
            })
            .collect(),
        test_failed: read.facts.test_failed,
        unexplained_failure: read.facts.unexplained_failure,
        incomplete: read.facts.incomplete,
    })
}

/// Whether the runner recorded in `records` that it could not start `program`: a file named for the
/// program's last path part whose first line is the program's path.
fn recorded_by_runner(records: &Path, program: &str) -> bool {
    let name = crate::run::file_name(program);
    if matches!(name.as_str(), "" | "." | "..") {
        return false;
    }
    let path = records.join(name);
    if !std::fs::symlink_metadata(&path).is_ok_and(|seen| seen.is_file()) {
        return false;
    }
    let mut text = String::new();
    File::open(&path)
        .and_then(|file| file.take(4096).read_to_string(&mut text))
        .is_ok()
        && text.lines().next() == Some(program)
}

/// What a log that was opened holds.
#[derive(Debug)]
struct LogRead {
    refused: Vec<Refusal>,
    facts: Facts,
    /// Why the read stopped before the end of the log, when it did.
    error: Option<String>,
}

/// The programs a log that was opened names, and what else it shows.
fn read_log(log: &Path, seen: &Metadata) -> Result<LogRead, Found> {
    let (file, _) = open_looked(log, seen)?;
    Ok(read_lines(file))
}

/// The programs a log names, and what else it shows, read from `reader` to its end or its failure.
fn read_lines(reader: impl Read) -> LogRead {
    let mut lines = Lines {
        reader: BufReader::new(reader),
        error: None,
    };
    let (refused, facts) = refusals(&mut lines);
    LogRead {
        refused,
        facts,
        error: lines.error,
    }
}

/// The lines of a log, none longer than [`LONGEST_LINE`] bytes, with invalid text replaced.
struct Lines<R> {
    reader: BufReader<R>,
    /// The error that stopped the read, when one did: the end of the lines is then not the end of
    /// the log.
    error: Option<String>,
}

impl<R: Read> Iterator for Lines<R> {
    type Item = String;

    fn next(&mut self) -> Option<String> {
        let mut bytes = Vec::new();
        let read = match self
            .reader
            .by_ref()
            .take(LONGEST_LINE)
            .read_until(b'\n', &mut bytes)
        {
            Ok(read) => read,
            Err(error) => {
                self.error = Some(error.to_string());
                return None;
            }
        };
        (read > 0).then(|| String::from_utf8_lossy(&bytes).trim_end().to_owned())
    }
}

fn epoch(time: SystemTime) -> Option<u64> {
    time.duration_since(UNIX_EPOCH)
        .ok()
        .map(|since| since.as_secs())
}

/// Runs `work` on a thread of its own and waits `limit` for what it returns. A thread that cannot
/// be made, or work that does not end in time, is an error that says so; the caller is not held,
/// and the thread is left to end by itself.
fn bounded<T: Send + 'static>(
    limit: Duration,
    work: impl FnOnce() -> T + Send + 'static,
) -> Result<T, String> {
    let (sender, receiver) = mpsc::channel();
    std::thread::Builder::new()
        .name("observation".to_owned())
        .spawn(move || {
            let _ = sender.send(work());
        })
        .map_err(|error| format!("a thread to read it could not be made: {error}"))?;
    receiver.recv_timeout(limit).map_err(|error| match error {
        RecvTimeoutError::Timeout => {
            format!("the read did not end in {} seconds", limit.as_secs_f64())
        }
        RecvTimeoutError::Disconnected => "the read ended with no result".to_owned(),
    })
}

/// Whether two descriptions are of one file object.
#[cfg(unix)]
fn same_object(a: &Metadata, b: &Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    a.dev() == b.dev() && a.ino() == b.ino()
}

/// Windows offers no stable identity of an open file, so a regular file that replaced the one
/// that was examined is not told apart here: only a link is.
#[cfg(not(unix))]
fn same_object(_a: &Metadata, _b: &Metadata) -> bool {
    true
}

/// Windows' attribute of a link, a junction or a mount point.
#[cfg(windows)]
const REPARSE_POINT: u32 = 0x400;

/// Windows' flag that opens a link itself and not the object it leads to.
#[cfg(windows)]
const OPEN_REPARSE_POINT: u32 = 0x0020_0000;

/// Whether the system marks the object as a link that the path leads through.
#[cfg(windows)]
fn redirects(metadata: &Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    metadata.file_attributes() & REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn redirects(_metadata: &Metadata) -> bool {
    false
}

/// What an object is when it is not a regular file, or none when it is one.
fn irregular(metadata: &Metadata) -> Option<&'static str> {
    let kind = metadata.file_type();
    if kind.is_symlink() || redirects(metadata) {
        Some("a link")
    } else if kind.is_dir() {
        Some("a directory")
    } else if kind.is_file() {
        None
    } else {
        Some("an object that is not a regular file")
    }
}

/// Opens the file at `path` for reading without following a link at its last part, and without
/// waiting for a writer when it is a pipe.
#[cfg(unix)]
fn open_without_following(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
}

#[cfg(windows)]
fn open_without_following(path: &Path) -> io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    OpenOptions::new()
        .read(true)
        .custom_flags(OPEN_REPARSE_POINT)
        .open(path)
}

/// Looks at `path` without following a link: its description when it is a regular file, or what
/// was found, to be recorded in place of a read.
fn examine(path: &Path) -> Result<Metadata, Found> {
    let seen = std::fs::symlink_metadata(path).map_err(|error| Found::NotRead {
        reason: format!("the path could not be examined: {error}"),
    })?;
    match irregular(&seen) {
        Some(kind) => Err(Found::Other {
            kind: kind.to_owned(),
        }),
        None => Ok(seen),
    }
}

/// Opens the regular file that [`examine`] described, and takes it only if the object opened is
/// that file: a link put at the name since, or any other object, is what is found instead.
fn open_looked(path: &Path, seen: &Metadata) -> Result<(File, Metadata), Found> {
    let file = match open_without_following(path) {
        Ok(file) => file,
        Err(error) => {
            return Err(match std::fs::symlink_metadata(path) {
                Ok(now) if irregular(&now) == Some("a link") => Found::Other {
                    kind: "a link".to_owned(),
                },
                _ => Found::NotRead {
                    reason: format!("the file could not be opened: {error}"),
                },
            });
        }
    };
    let opened = file.metadata().map_err(|error| Found::NotRead {
        reason: format!("the file could not be described: {error}"),
    })?;
    if let Some(kind) = irregular(&opened) {
        return Err(Found::Other {
            kind: kind.to_owned(),
        });
    }
    if !same_object(seen, &opened) {
        return Err(Found::NotRead {
            reason: "the path no longer leads to the file that was looked at".to_owned(),
        });
    }
    Ok((file, opened))
}

/// What is at `path`: looked at with `lstat` first, opened without following a link, and read only
/// when it is a regular file.
#[must_use]
pub fn observe_file(path: &Path) -> Found {
    let seen = match examine(path) {
        Ok(seen) => seen,
        Err(found) => return found,
    };
    let owned = path.to_path_buf();
    match bounded(READ_LIMIT, move || read_head(&owned, &seen)) {
        Ok(Ok((head, opened))) => Found::Read {
            size: opened.len(),
            first_bytes: head
                .iter()
                .take(32)
                .map(|byte| format!("{byte:02x}"))
                .collect::<Vec<_>>()
                .join(" "),
            modified: opened.modified().ok().and_then(epoch),
            created: opened.created().ok().and_then(epoch),
            damage: damage_of(&head, opened.len()),
        },
        Ok(Err(found)) => found,
        Err(reason) => Found::NotRead { reason },
    }
}

/// The first bytes of the file `seen` described, and what the opened file is, when the path still
/// leads to that regular file.
fn read_head(path: &Path, seen: &Metadata) -> Result<(Vec<u8>, Metadata), Found> {
    let (file, opened) = open_looked(path, seen)?;
    let mut head = Vec::new();
    file.take(HEAD_BYTES as u64)
        .read_to_end(&mut head)
        .map_err(|error| Found::NotRead {
            reason: format!("the file could not be read: {error}"),
        })?;
    Ok((head, opened))
}

fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    let word = bytes.get(at..at.checked_add(4)?)?;
    Some(u32::from_le_bytes(word.try_into().ok()?))
}

fn u64_at(bytes: &[u8], at: usize) -> Option<u64> {
    let word = bytes.get(at..at.checked_add(8)?)?;
    Some(u64::from_le_bytes(word.try_into().ok()?))
}

/// The damage a program's first bytes and length show, or none when none is seen: it is shorter
/// than a page, its first page is all zeros, or its load commands run past its end. A script, a
/// program of another system and a universal binary are not read for damage.
#[must_use]
pub fn damage_of(head: &[u8], length: u64) -> Option<String> {
    if head.starts_with(b"#!")
        || head.starts_with(b"\x7fELF")
        || head.starts_with(b"MZ")
        || head.starts_with(&[0xca, 0xfe, 0xba, 0xbe])
        || head.starts_with(&[0xca, 0xfe, 0xba, 0xbf])
    {
        return None;
    }
    if length == 0 {
        return Some("the file is empty".to_owned());
    }
    if length < PAGE as u64 {
        return Some(format!(
            "the file is {length} bytes, shorter than a page ({PAGE} bytes)"
        ));
    }
    if head.len() >= PAGE && head[..PAGE].iter().all(|byte| *byte == 0) {
        return Some(format!("the first page ({PAGE} bytes) is all zeros"));
    }
    if u32_at(head, 0) != Some(MACH_O_64) {
        return None;
    }
    let (Some(commands), Some(size)) = (u32_at(head, 16), u32_at(head, 20)) else {
        return None;
    };
    let commands_end = 32 + u64::from(size);
    if commands_end > length {
        return Some(format!(
            "its load commands end at byte {commands_end}, past the end of the file at {length}"
        ));
    }
    let mut at = 32_usize;
    for _ in 0..commands {
        let (Some(command), Some(command_size)) = (u32_at(head, at), u32_at(head, at + 4)) else {
            break;
        };
        if command_size < 8 {
            return Some(format!(
                "a load command at byte {at} is {command_size} bytes"
            ));
        }
        if at as u64 + u64::from(command_size) > length {
            return Some(format!(
                "a load command at byte {at} ends past the end of the file at {length}"
            ));
        }
        if command == SEGMENT_64
            && let (Some(offset), Some(filled)) = (u64_at(head, at + 40), u64_at(head, at + 48))
            && offset.saturating_add(filled) > length
        {
            return Some(format!(
                "a segment ends at byte {}, past the end of the file at {length}",
                offset.saturating_add(filled)
            ));
        }
        at += command_size as usize;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(lines: &[&str]) -> std::vec::IntoIter<String> {
        lines
            .iter()
            .map(|line| (*line).to_owned())
            .collect::<Vec<_>>()
            .into_iter()
    }

    /// A 64-bit Mach-O file of `length` bytes with one segment command that ends at `segment_end`
    /// and `load` bytes of load commands in all.
    fn mach_o(length: usize, load: u32, segment_end: u64) -> Vec<u8> {
        let mut bytes = vec![1_u8; length];
        bytes[0..4].copy_from_slice(&MACH_O_64.to_le_bytes());
        bytes[16..20].copy_from_slice(&1_u32.to_le_bytes());
        bytes[20..24].copy_from_slice(&load.to_le_bytes());
        bytes[32..36].copy_from_slice(&SEGMENT_64.to_le_bytes());
        bytes[36..40].copy_from_slice(&72_u32.to_le_bytes());
        bytes[72..80].copy_from_slice(&0_u64.to_le_bytes());
        bytes[80..88].copy_from_slice(&segment_end.to_le_bytes());
        bytes
    }

    #[test]
    fn the_three_signatures_name_the_program_and_keep_the_errors_own_lines() {
        let (found, facts) = refusals(text(&[
            "error: failed to run custom build command for `x v0.1.0`",
            "Caused by:",
            "  could not execute process `/t/debug/build/x-1/build-script-build` (never executed)",
            "",
            "Caused by:",
            "  Exec format error (os error 8)",
            "kr-conformance run-one: /t/debug/deps/a-0123 could not start: Exec format error (os error 8)",
            "kr-conformance list-one: /t/debug/deps/b-0123 ended with exit status: 126",
            "/t/debug/deps/b-0123: /t/debug/deps/b-0123: cannot execute binary file",
        ]));
        assert!(!facts.test_failed);
        let paths: Vec<&str> = found.iter().map(|found| found.path.as_str()).collect();
        assert_eq!(
            paths,
            [
                "/t/debug/build/x-1/build-script-build",
                "/t/debug/deps/a-0123",
                "/t/debug/deps/b-0123"
            ]
        );
        assert!(
            found[0]
                .lines
                .iter()
                .any(|line| line.contains("Exec format error")),
            "{:?}",
            found[0].lines
        );
    }

    #[test]
    fn the_shell_s_words_count_only_where_the_log_holds_exit_126() {
        let (found, _) = refusals(text(&["/t/a: /t/a: cannot execute binary file"]));
        assert!(found.is_empty(), "{found:?}");
        let (found, _) = refusals(text(&[
            "/t/a: /t/a: cannot execute binary file",
            "process didn't exit successfully: `/t/a` (exit status: 126)",
        ]));
        assert_eq!(found.len(), 1);
    }

    #[test]
    fn what_a_test_prints_is_not_a_program_the_step_could_not_run() {
        let (found, facts) = refusals(text(&[
            "running 1 test",
            "test a ... FAILED",
            "failures:",
            "---- a stdout ----",
            "could not execute process `/t/x` (never executed)",
            "kr-conformance run-one: /t/y could not start: Exec format error (os error 8)",
            "/t/z: /t/z: cannot execute binary file",
            "process didn't exit successfully: `/t/z` (exit status: 126)",
            "",
            "failures:",
            "    a",
            "",
            "test result: FAILED. 0 passed; 1 failed",
        ]));
        assert!(found.is_empty(), "{found:?}");
        assert!(facts.test_failed);
    }

    #[test]
    fn a_step_counts_as_one_with_damage_seen_only_when_every_program_it_names_shows_damage_and_no_test_failed()
     {
        let program = |damage: Option<&str>| Program {
            path: "/t/a".to_owned(),
            lines: Vec::new(),
            said_by_runner: false,
            observed_at: 0,
            file: Found::Read {
                size: 0,
                first_bytes: String::new(),
                modified: None,
                created: None,
                damage: damage.map(str::to_owned),
            },
        };
        let observed = |programs: Vec<Program>, test_failed: bool| Observed {
            log: None,
            programs,
            test_failed,
            unexplained_failure: false,
            incomplete: false,
        };
        let damaged = || program(Some("the file is empty"));
        assert!(observed(vec![damaged()], false).damage_seen());
        assert!(observed(vec![damaged(), damaged()], false).damage_seen());
        assert!(!observed(vec![damaged()], true).damage_seen());
        assert!(
            !observed(vec![damaged(), program(None)], false).damage_seen(),
            "a whole program beside a damaged one"
        );
        assert!(!observed(vec![program(None)], false).damage_seen());
        assert!(!observed(Vec::new(), false).damage_seen());
    }

    #[test]
    fn damage_is_a_file_shorter_than_a_page_a_zero_first_page_or_load_commands_past_the_end() {
        assert_eq!(damage_of(&[], 0).as_deref(), Some("the file is empty"));
        let short = mach_o(300, 72, 0);
        assert!(
            damage_of(&short, 300)
                .unwrap()
                .contains("shorter than a page")
        );
        let zeros = vec![0_u8; 8192];
        assert!(damage_of(&zeros, 8192).unwrap().contains("first page"));
        let whole = mach_o(8192, 72, 4096);
        assert_eq!(damage_of(&whole, 8192), None, "no damage seen");
        let past = mach_o(8192, 20_000, 4096);
        assert!(
            damage_of(&past, 8192)
                .unwrap()
                .contains("load commands end at byte"),
            "{:?}",
            damage_of(&past, 8192)
        );
        let cut = mach_o(8192, 72, 20_000);
        assert!(
            damage_of(&cut, 8192)
                .unwrap()
                .contains("a segment ends at byte")
        );
        let overrun = {
            let mut bytes = mach_o(8192, 72, 0);
            bytes[36..40].copy_from_slice(&90_000_u32.to_le_bytes());
            bytes
        };
        assert!(
            damage_of(&overrun, 8192)
                .unwrap()
                .contains("load command at byte 32 ends past")
        );
    }

    #[test]
    fn a_load_command_shorter_than_eight_bytes_is_damage_and_is_not_stepped_over() {
        // A header that claims three commands whose first has size 0 would otherwise stay at one
        // offset for as many commands as it claims, which a damaged file can set to 2^32 - 1.
        let mut empty = mach_o(8192, 72, 100);
        empty[16..20].copy_from_slice(&3_u32.to_le_bytes());
        for size in [0_u32, 7] {
            empty[36..40].copy_from_slice(&size.to_le_bytes());
            let found = damage_of(&empty, 8192);
            assert!(
                found
                    .as_deref()
                    .is_some_and(|text| text.contains(&format!("at byte 32 is {size} bytes"))),
                "{found:?}"
            );
        }
    }

    #[test]
    fn damage_is_not_seen_where_a_member_was_not_read_or_the_record_is_not_whole() {
        let program = |file: Found| Program {
            path: "/t/a".to_owned(),
            lines: Vec::new(),
            said_by_runner: false,
            observed_at: 0,
            file,
        };
        let damaged = || Found::Read {
            size: 0,
            first_bytes: String::new(),
            modified: None,
            created: None,
            damage: Some("the file is empty".to_owned()),
        };
        let observed = |programs: Vec<Program>| Observed {
            log: None,
            programs,
            test_failed: false,
            unexplained_failure: false,
            incomplete: false,
        };
        assert!(observed(vec![program(damaged())]).damage_seen());
        for other in [
            Found::NotRead {
                reason: "no".to_owned(),
            },
            Found::Other {
                kind: "a link".to_owned(),
            },
        ] {
            let mixed = observed(vec![program(damaged()), program(other)]);
            assert!(!mixed.damage_seen(), "{mixed:?}");
        }
        let mut whole = observed(vec![program(damaged())]);
        whole.unexplained_failure = true;
        assert!(!whole.damage_seen());
        whole.unexplained_failure = false;
        whole.incomplete = true;
        assert!(!whole.damage_seen());
        whole.incomplete = false;
        whole.log = Some(Found::NotRead {
            reason: "no".to_owned(),
        });
        assert!(!whole.damage_seen());
    }

    #[test]
    fn a_failure_that_no_refused_program_accounts_for_is_unexplained() {
        let refused = "kr-conformance run-one: /t/a could not start: no";
        let accounted = "  process didn't exit successfully: `/r run-one /t/a` (exit status: 1)";
        let killed = "  process didn't exit successfully: `/r run-one /t/b` (signal: 6, SIGABRT)";
        let facts = |lines: &[&str]| refusals(text(lines)).1;
        assert!(!facts(&[refused, accounted]).unexplained_failure);
        assert!(facts(&[refused, accounted, killed]).unexplained_failure);
        assert!(
            facts(&[refused, "error: could not compile `x` (lib) due to 1 error"])
                .unexplained_failure
        );
        assert!(facts(&[refused, "error[E0308]: mismatched types"]).unexplained_failure);
        assert!(facts(&[killed]).unexplained_failure);
    }

    #[test]
    fn a_ninth_refused_program_makes_the_record_incomplete() {
        let lines = |count: usize| -> Vec<String> {
            (0..count)
                .map(|n| format!("kr-conformance run-one: /t/p{n} could not start: no"))
                .collect()
        };
        assert!(!refusals(lines(MOST_PROGRAMS).into_iter()).1.incomplete);
        let (found, facts) = refusals(lines(MOST_PROGRAMS + 1).into_iter());
        assert_eq!(found.len(), MOST_PROGRAMS);
        assert!(facts.incomplete);
        let mut shell: Vec<String> = (0..=MOST_PROGRAMS)
            .map(|n| format!("/t/s{n}: /t/s{n}: cannot execute binary file"))
            .collect();
        shell.push("process didn't exit successfully: `/t/s0` (exit status: 126)".to_owned());
        assert!(refusals(shell.into_iter()).1.incomplete);
    }

    /// A reader that gives its bytes and then fails.
    struct FailsAfter(std::io::Cursor<Vec<u8>>);

    impl Read for FailsAfter {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            match self.0.read(buffer)? {
                0 => Err(io::Error::other("the disk failed")),
                read => Ok(read),
            }
        }
    }

    #[test]
    fn a_log_that_fails_to_read_part_of_the_way_says_so_keeps_what_it_read_and_shows_no_damage() {
        let first = "kr-conformance run-one: /t/a could not start: no\n";
        let read = read_lines(FailsAfter(std::io::Cursor::new(first.as_bytes().to_vec())));
        assert_eq!(read.refused.len(), 1);
        let seen = observed(read, Path::new("/no-such-records"), SystemTime::now())
            .expect("a log that failed is recorded");
        let Some(Found::NotRead { reason }) = &seen.log else {
            panic!("{seen:?}");
        };
        assert!(
            reason.contains("past its position") && reason.contains("the disk failed"),
            "{reason}"
        );
        assert_eq!(seen.programs.len(), 1);
        assert!(!seen.damage_seen());
        let whole = read_lines("running 1 test\n".as_bytes());
        assert!(observed(whole, Path::new("/no-such-records"), SystemTime::now()).is_none());
    }

    #[test]
    fn a_short_script_or_a_program_of_another_system_is_not_shown_to_be_damaged() {
        assert_eq!(damage_of(b"#!/bin/sh\nexit 1\n", 17), None);
        assert_eq!(damage_of(b"\x7fELF\x02\x01", 6), None);
        assert_eq!(damage_of(&[0xca, 0xfe, 0xba, 0xbe, 0, 0], 6), None);
        assert_eq!(damage_of(&[0xca, 0xfe, 0xba, 0xbf, 0, 0], 6), None);
    }

    #[test]
    fn the_shell_s_lines_are_kept_for_eight_programs_and_still_name_those_the_other_lines_did_not()
    {
        let mut lines = vec![
            "kr-conformance run-one: /t/p could not start: no".to_owned(),
            "process didn't exit successfully: `/t/p` (exit status: 126)".to_owned(),
        ];
        lines.extend((0..40).map(|_| "/t/p: /t/p: cannot execute binary file".to_owned()));
        lines.extend(
            ["q", "r"].map(|name| format!("/t/{name}: /t/{name}: cannot execute binary file")),
        );
        let (found, _) = refusals(lines.into_iter());
        let paths: Vec<&str> = found.iter().map(|refusal| refusal.path.as_str()).collect();
        assert_eq!(paths, ["/t/p", "/t/q", "/t/r"]);
    }

    #[test]
    fn a_log_names_at_most_eight_programs() {
        let lines: Vec<String> = (0..20)
            .map(|n| format!("kr-conformance run-one: /t/p{n} could not start: no"))
            .collect();
        assert_eq!(refusals(lines.into_iter()).0.len(), MOST_PROGRAMS);
    }
}

#[cfg(test)]
mod files {
    use super::*;

    #[test]
    fn a_regular_file_is_read_for_its_size_first_bytes_times_and_damage() {
        let held = tempfile::tempdir().unwrap();
        let path = held.path().join("program");
        std::fs::write(&path, vec![0_u8; 9000]).unwrap();
        let Found::Read {
            size,
            first_bytes,
            modified,
            damage,
            ..
        } = observe_file(&path)
        else {
            panic!("a regular file is read");
        };
        assert_eq!(size, 9000);
        assert!(first_bytes.starts_with("00 00 00 00"), "{first_bytes}");
        assert!(modified.is_some());
        assert!(damage.unwrap().contains("first page"));
    }

    #[cfg(unix)]
    #[test]
    fn a_path_that_no_longer_leads_to_the_file_that_was_looked_at_is_not_read() {
        let held = tempfile::tempdir().unwrap();
        let looked_at = held.path().join("looked-at");
        let now = held.path().join("now");
        std::fs::write(&looked_at, vec![1_u8; 5000]).unwrap();
        std::fs::write(&now, vec![0_u8; 9000]).unwrap();
        let seen = std::fs::symlink_metadata(&looked_at).unwrap();
        let Found::NotRead { reason } = read_head(&now, &seen).unwrap_err() else {
            panic!("another file is not read");
        };
        assert!(reason.contains("no longer leads"), "{reason}");
        assert!(read_head(&looked_at, &seen).is_ok());
    }

    #[test]
    fn a_missing_path_is_not_read_and_says_why() {
        let held = tempfile::tempdir().unwrap();
        let Found::NotRead { reason } = observe_file(&held.path().join("gone")) else {
            panic!("nothing is there");
        };
        assert!(reason.contains("could not be examined"), "{reason}");
    }

    #[test]
    fn a_directory_is_named_and_not_read() {
        let held = tempfile::tempdir().unwrap();
        let Found::Other { kind } = observe_file(held.path()) else {
            panic!("a directory is not read");
        };
        assert_eq!(kind, "a directory");
    }

    #[cfg(unix)]
    #[test]
    fn a_link_is_named_and_the_file_it_leads_to_is_not_read() {
        let held = tempfile::tempdir().unwrap();
        let target = held.path().join("real");
        std::fs::write(&target, vec![0_u8; 9000]).unwrap();
        let link = held.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let Found::Other { kind } = observe_file(&link) else {
            panic!("a link is not read");
        };
        assert_eq!(kind, "a link");
    }

    #[cfg(unix)]
    #[test]
    fn a_pipe_is_named_and_the_read_does_not_wait_for_a_writer() {
        let held = tempfile::tempdir().unwrap();
        let pipe = held.path().join("pipe");
        let made = std::process::Command::new("mkfifo")
            .arg(&pipe)
            .status()
            .unwrap();
        assert!(made.success());
        let began = std::time::Instant::now();
        let Found::Other { kind } = observe_file(&pipe) else {
            panic!("a pipe is not read");
        };
        assert!(kind.contains("not a regular file"), "{kind}");
        assert!(began.elapsed() < READ_LIMIT);
    }

    /// Makes a pipe at `path`.
    #[cfg(unix)]
    fn pipe(path: &Path) {
        let made = std::process::Command::new("mkfifo")
            .arg(path)
            .status()
            .unwrap();
        assert!(made.success());
    }

    /// Moves the file at `name` to `moved` and puts a link at `name` to it. Windows lets an account
    /// make a link only with a privilege, so this says whether the link was made.
    fn replaced_by_a_link(name: &Path, moved: &Path) -> bool {
        std::fs::rename(name, moved).unwrap();
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(moved, name).unwrap();
            true
        }
        #[cfg(windows)]
        {
            std::os::windows::fs::symlink_file(moved, name).is_ok()
        }
    }

    #[test]
    fn a_link_put_at_the_name_after_the_look_is_named_and_the_bytes_it_leads_to_are_not_read() {
        let held = tempfile::tempdir().unwrap();
        let name = held.path().join("program");
        std::fs::write(&name, vec![7_u8; 9000]).unwrap();
        let seen = examine(&name).unwrap();
        if !replaced_by_a_link(&name, &held.path().join("moved")) {
            eprintln!("this account cannot make a link, so the case did not run");
            return;
        }
        let Err(Found::Other { kind }) = read_head(&name, &seen) else {
            panic!("a link is not read");
        };
        assert_eq!(kind, "a link");
    }

    #[cfg(unix)]
    #[test]
    fn a_pipe_put_at_the_name_after_the_look_is_named_and_not_waited_for() {
        let held = tempfile::tempdir().unwrap();
        let name = held.path().join("program");
        std::fs::write(&name, vec![7_u8; 9000]).unwrap();
        let seen = examine(&name).unwrap();
        std::fs::remove_file(&name).unwrap();
        pipe(&name);
        // The read is given a generous wait only so that a regression ends this case.
        let read = bounded(Duration::from_secs(5), move || read_head(&name, &seen));
        let Ok(Err(Found::Other { kind })) = read else {
            panic!("the open of a pipe waited for a writer: {read:?}");
        };
        assert!(kind.contains("not a regular file"), "{kind}");
    }

    #[cfg(unix)]
    #[test]
    fn a_log_that_is_a_link_is_named_and_its_lines_are_not_read() {
        let held = tempfile::tempdir().unwrap();
        let real = held.path().join("real.log");
        std::fs::write(
            &real,
            "kr-conformance run-one: /t/p could not start: Exec format error (os error 8)\n",
        )
        .unwrap();
        let log = held.path().join("step.log");
        std::os::unix::fs::symlink(&real, &log).unwrap();
        let observed = observe_log(&log, Path::new("/no-such-records"), SystemTime::now())
            .expect("the log is recorded");
        assert!(matches!(&observed.log, Some(Found::Other { kind }) if kind == "a link"));
        assert!(observed.programs.is_empty());
        assert!(!observed.damage_seen());
    }

    #[cfg(unix)]
    #[test]
    fn a_log_that_is_a_pipe_is_named_and_not_waited_for() {
        let held = tempfile::tempdir().unwrap();
        let log = held.path().join("step.log");
        pipe(&log);
        // The call is given a generous wait only so that a regression ends this case.
        let read = bounded(Duration::from_secs(5), move || {
            observe_log(&log, Path::new("/no-such-records"), SystemTime::now())
        });
        let Ok(Some(observed)) = read else {
            panic!("the read of a pipe waited for a writer: {read:?}");
        };
        assert!(
            matches!(&observed.log, Some(Found::Other { kind }) if kind.contains("not a regular file")),
            "{observed:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_link_or_a_pipe_put_at_the_log_s_name_after_the_look_is_not_read() {
        let held = tempfile::tempdir().unwrap();
        let log = held.path().join("step.log");
        std::fs::write(&log, "kr-conformance run-one: /t/p could not start: no\n").unwrap();
        let seen = examine(&log).unwrap();
        assert!(replaced_by_a_link(&log, &held.path().join("moved.log")));
        let Err(Found::Other { kind }) = read_log(&log, &seen) else {
            panic!("a link is not read");
        };
        assert_eq!(kind, "a link");
        std::fs::remove_file(&log).unwrap();
        pipe(&log);
        let read = bounded(Duration::from_secs(5), move || read_log(&log, &seen));
        let Ok(Err(Found::Other { kind })) = read else {
            panic!("the open of a pipe waited for a writer: {read:?}");
        };
        assert!(kind.contains("not a regular file"), "{kind}");
    }

    #[test]
    fn work_that_does_not_end_gives_the_caller_an_error_and_does_not_hold_it() {
        let (_keep, wait) = mpsc::channel::<()>();
        let (_unused, never) = mpsc::channel::<()>();
        drop(wait);
        let error = bounded(Duration::from_millis(100), move || never.recv()).unwrap_err();
        assert!(error.contains("did not end"), "{error}");
    }

    #[test]
    fn a_log_without_a_refusal_has_no_observation_and_a_log_that_is_missing_has_none_either() {
        let held = tempfile::tempdir().unwrap();
        let log = held.path().join("step.log");
        std::fs::write(&log, "running 1 test\ntest a ... ok\n").unwrap();
        assert!(observe_log(&log, Path::new("/no-such-records"), SystemTime::now()).is_none());
        assert!(
            observe_log(
                &held.path().join("gone.log"),
                Path::new("/no-such-records"),
                SystemTime::now()
            )
            .is_none()
        );
    }

    #[test]
    fn a_log_that_names_a_damaged_program_gives_an_observation_of_it_as_it_is_now() {
        let held = tempfile::tempdir().unwrap();
        let program = held.path().join("build-script-build");
        std::fs::write(&program, b"").unwrap();
        let log = held.path().join("step.log");
        std::fs::write(
            &log,
            format!(
                "kr-conformance run-one: {} could not start: Exec format error (os error 8)\n",
                program.display()
            ),
        )
        .unwrap();
        let observed = observe_log(&log, Path::new("/no-such-records"), SystemTime::now())
            .expect("one program");
        assert!(observed.damage_seen());
        assert_eq!(observed.programs[0].path, program.to_string_lossy());
    }
}
