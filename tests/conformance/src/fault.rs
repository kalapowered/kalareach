//! A program the linker wrote that the system then refuses to start.
//!
//! A hosted macOS runner's data volume has returned I/O errors in bursts while a build ran. The
//! linker writes its output through a memory map, so a page that could not be written is lost
//! without an error: the build finishes, and the file reads as zeros or ends early. The first start
//! of it then ends with exit status 126 and the shell's words "cannot execute binary file", and
//! Cargo goes on treating the file as built, so every later step that needs it fails the same way.
//!
//! A step that ends in that way is run once more, after the damaged files and Cargo's records of
//! having built them are removed. The report never counts such a run as a plain pass: the result
//! names the step, both runs' logs and the files, and says what the evidence shows about the cause.
//! The cause is named the runner's disk only where the evidence says so: the file is empty, cut
//! short or its signature does not check, or the kernel logged a storage error in the minutes
//! before. A file that is whole and validly signed with no storage error in the kernel's log is not
//! the runner's doing as far as anything here can show, and the step fails.

use std::fs::File;
use std::io::Read;
use std::path::{Component, Path, PathBuf};
#[cfg(unix)]
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::Serialize;

use crate::libtest::Outcome;
use crate::plan::Step;
use crate::run::{self, Executed, Place};
use crate::workspace::Package;

/// What the shell says when the system refuses to start a file, after the file's own name twice.
const SHELL_WORDS: &str = ": cannot execute binary file";

/// A Mach-O header of a 64-bit program, read as a little-endian word.
const MACH_O_64: u32 = 0xfeed_facf;

/// The load command of a 64-bit segment.
const SEGMENT_64: u32 = 0x19;

/// The load command that points at the file's code signature.
const CODE_SIGNATURE: u32 = 0x1d;

/// How much of a file's start is read to check its Mach-O header: the header, and room for the
/// load commands of any program the build makes.
const HEAD_BYTES: usize = 65_536;

/// How much time, in all, the report spends on the second runs of steps, counted by what each
/// second run took, and the most any one second run is given: a second run is ended when the time
/// left is up. A step is not run again when nothing is left, or when its first run took longer than
/// what is left, which is the least its second run takes. Five minutes is under the 10.5 that the
/// slowest night, which ran the report to 276 of its 287 minutes, left.
pub const RERUN_BUDGET: Duration = Duration::from_secs(5 * 60);

/// What the report keeps back, at the end of the time its job gives it, to write its result: a
/// second run is ended this long before the job's own limit would end the report with no result.
pub const RESULT_RESERVE: Duration = Duration::from_secs(2 * 60);

/// The variable in which the workflow gives the moment its limit ends the report, in whole
/// seconds since the epoch.
pub const DEADLINE_VARIABLE: &str = "KR_REPORT_DEADLINE";

/// What a step's error says when its second run was ended at its deadline.
pub const PASSED_ITS_TIME: &str = "the second run passed its time";

/// The time the report leaves for second runs: an account of [`RERUN_BUDGET`] that each second run
/// takes its time from, and, where the workflow gives it, the moment the job's limit ends the
/// report, less [`RESULT_RESERVE`].
#[derive(Clone, Copy, Debug)]
pub struct Budget {
    left: Duration,
    report_ends: Option<SystemTime>,
}

impl Budget {
    /// An account of `left`, with no limit of the job's.
    #[must_use]
    pub fn of(left: Duration) -> Self {
        Self {
            left,
            report_ends: None,
        }
    }

    /// The same account, with the report ended by the job's limit at `ends`.
    #[must_use]
    pub fn until(self, ends: SystemTime) -> Self {
        Self {
            report_ends: Some(ends),
            ..self
        }
    }

    /// The account of [`RERUN_BUDGET`] and the job's limit that [`DEADLINE_VARIABLE`] names. A
    /// value that is not a number of seconds is a limit that has already passed, so that no step
    /// is run again on a workflow that gave one that could not be read.
    #[must_use]
    pub fn from_environment() -> Self {
        Self::from_deadline(std::env::var(DEADLINE_VARIABLE).ok().as_deref())
    }

    /// The same, with the variable's value, where it is set, given.
    fn from_deadline(value: Option<&str>) -> Self {
        let account = Self::of(RERUN_BUDGET);
        value.map_or(account, |text| {
            account.until(text.trim().parse::<u64>().map_or(UNIX_EPOCH, |seconds| {
                UNIX_EPOCH + Duration::from_secs(seconds)
            }))
        })
    }

    /// What is left of the account.
    #[must_use]
    pub fn left(&self) -> Duration {
        self.left
    }

    /// How long a second run that starts at `now` may take: what is left of the account, or what
    /// the job's limit leaves after [`RESULT_RESERVE`], whichever is less.
    #[must_use]
    pub fn allowed(&self, now: SystemTime) -> Duration {
        self.report_ends.map_or(self.left, |ends| {
            ends.duration_since(now)
                .unwrap_or_default()
                .saturating_sub(RESULT_RESERVE)
                .min(self.left)
        })
    }

    /// Takes the time a second run took from the account.
    fn charge(&mut self, took: Duration) {
        self.left = self.left.saturating_sub(took);
    }
}

/// How long a program that was asked to end is given before it is killed.
#[cfg(target_os = "macos")]
const GRACE: Duration = Duration::from_secs(5);

/// The words of the kernel's lines that say the storage under a volume failed to take a write.
const STORAGE_WORDS: [&str; 4] = [
    "I/O error",
    "cluster_pageout",
    "cluster_push() failed",
    "trim_list failed",
];

/// The filter of the log read, in the log's own predicate language.
#[cfg(target_os = "macos")]
const STORAGE_PREDICATE: &str = "process == \"kernel\" AND (eventMessage CONTAINS \"I/O error\" \
    OR eventMessage CONTAINS \"cluster_pageout\" OR eventMessage CONTAINS \"cluster_push() \
    failed\" OR eventMessage CONTAINS \"trim_list failed\")";

/// How long the kernel's log is read before the read is given up.
#[cfg(target_os = "macos")]
const LOG_LIMIT: Duration = Duration::from_secs(90);

/// The longest stretch of the kernel's log that is read, in minutes.
const LOG_MINUTES: u64 = 90;

/// How long before the earliest of the files was written, and after the latest, the kernel's log
/// is read, in seconds: a write that the disk loses is the storage's error of that minute.
const LOG_PADDING: u64 = 180;

/// The free space, in KiB, under which a volume is taken for full: 2 GiB. A hosted macOS runner's
/// data volume had 36 GiB or more free on every night read, so the floor is far under what a
/// healthy night leaves, and above what a link needs. A disk that a test of the suite filled
/// damages programs the same way a failing disk does, and is not the runner's.
pub const FREE_FLOOR_KIB: u64 = 2 * 1024 * 1024;

/// What the evidence says about the cause of a file that could not be started.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Cause {
    /// The kernel logged a storage error in the minutes the files were written, and the volume
    /// had room: the free space never fell under [`FREE_FLOOR_KIB`].
    RunnerDisk,
    /// Anything else: no kernel line, a kernel log that could not be read, a volume that was full
    /// or whose free space could not be read. A file that is damaged is not enough.
    Unexplained,
}

/// A step that was run again after a file it linked could not be started.
#[derive(Clone, Debug, Serialize)]
pub struct Rerun {
    /// The log of the first run, relative to the evidence directory.
    pub first_log: String,
    /// The first run's exit status.
    pub first_exit: Option<i32>,
    /// Why the first run could not be run or read, when it could not.
    pub first_error: Option<String>,
    /// The files that could not be started, relative to the repository.
    pub files: Vec<String>,
    /// What the evidence says about the cause.
    pub cause: Cause,
    /// The evidence, in a sentence.
    pub reason: String,
    /// The file that holds each file's facts and the count of the kernel's storage lines, relative
    /// to the evidence directory; the lines themselves are in the file beside it that ends in
    /// `.kernel.txt`.
    pub facts: String,
    /// How many files and directories were removed before the second run.
    pub removed: usize,
}

/// What is known of one file that could not be started.
#[derive(Clone, Debug)]
pub struct FileFacts {
    /// Its path.
    pub path: PathBuf,
    /// Its size, when it could be read.
    pub size: Option<u64>,
    /// How long before the check it was last written.
    pub age: Option<Duration>,
    /// Its first bytes, in hexadecimal.
    pub head: String,
    /// What is wrong with its Mach-O header, when something is.
    pub shape: Option<String>,
    /// The result of the system's check of its signature, when the check ran: it runs on a
    /// Mach-O program whose header is whole, and on nothing else.
    pub signature: Option<Result<(), String>>,
    /// Why the file could not be read, when it could not. A file that could not be read is not
    /// shown to be damaged.
    pub unread: Option<String>,
}

impl FileFacts {
    /// Whether the file is empty, cut short or badly signed.
    #[must_use]
    pub fn damaged(&self) -> bool {
        self.shape.is_some() || matches!(self.signature, Some(Err(_)))
    }
}

/// The target directory the build writes to.
#[must_use]
pub fn target_directory(root: &Path, environment: &[(String, String)]) -> PathBuf {
    let named = environment
        .iter()
        .find(|(name, _)| name == "CARGO_TARGET_DIR")
        .map(|(_, value)| PathBuf::from(value))
        .or_else(|| std::env::var_os("CARGO_TARGET_DIR").map(PathBuf::from));
    match named {
        Some(path) if path.is_absolute() => path,
        Some(path) => root.join(path),
        None => root.join("target"),
    }
}

/// The files under `target` that a log says could not be started: a line that gives a file's path
/// twice and then the shell's words, in a log that also holds exit status 126. A path that steps
/// up with `..` is not under `target` whatever it starts with, and is not named.
#[must_use]
pub fn named_files(log: &str, target: &Path) -> Vec<PathBuf> {
    if !log.contains("exit status: 126") && !log.contains("(exit 126)") {
        return Vec::new();
    }
    let mut files: Vec<PathBuf> = Vec::new();
    for line in log.lines() {
        let Some(body) = line.trim().strip_suffix(SHELL_WORDS) else {
            continue;
        };
        let Some((first, second)) = body.split_once(": ") else {
            continue;
        };
        let path = Path::new(first);
        if first == second
            && path.is_absolute()
            && path.starts_with(target)
            && !path
                .components()
                .any(|component| component == Component::ParentDir)
            && !files.iter().any(|file| file == path)
        {
            files.push(path.to_path_buf());
        }
    }
    files
}

fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    let word = bytes.get(at..at.checked_add(4)?)?;
    Some(u32::from_le_bytes(word.try_into().ok()?))
}

fn u64_at(bytes: &[u8], at: usize) -> Option<u64> {
    let word = bytes.get(at..at.checked_add(8)?)?;
    Some(u64::from_le_bytes(word.try_into().ok()?))
}

/// What is wrong with a Mach-O program from its first bytes and its length, when something is: it
/// is empty, its first bytes are zeros, or a segment, the signature or its load commands lie
/// beyond the end of the file. A script, a program of another system and any other file are not
/// read.
#[must_use]
pub fn macho_problem(head: &[u8], length: u64) -> Option<String> {
    if length == 0 {
        return Some("the file is empty".to_owned());
    }
    if head.starts_with(b"#!")
        || head.starts_with(b"\x7fELF")
        || head.starts_with(b"MZ")
        || head.starts_with(&[0xca, 0xfe, 0xba, 0xbe])
    {
        return None;
    }
    if u32_at(head, 0) != Some(MACH_O_64) {
        // A page the disk lost reads as zeros. Any other file is not one the linker wrote here,
        // and is not shown to be damaged.
        return head
            .iter()
            .take(32)
            .all(|byte| *byte == 0)
            .then(|| "the first 32 bytes are all zero".to_owned());
    }
    let (Some(commands), Some(size)) = (u32_at(head, 16), u32_at(head, 20)) else {
        return Some(format!(
            "the file is {length} bytes, too short for a Mach-O header"
        ));
    };
    let commands_end = 32 + u64::from(size);
    if commands_end > length {
        return Some(format!(
            "its load commands end at byte {commands_end}, past the end of the file at {length}"
        ));
    }
    let mut at = 32usize;
    for _ in 0..commands {
        let (Some(command), Some(command_size)) = (u32_at(head, at), u32_at(head, at + 4)) else {
            break;
        };
        if command_size < 8 {
            return Some(format!(
                "a load command at byte {at} is {command_size} bytes"
            ));
        }
        if command == SEGMENT_64 {
            if let (Some(offset), Some(filled)) = (u64_at(head, at + 40), u64_at(head, at + 48)) {
                let end = offset.saturating_add(filled);
                if end > length {
                    let name = String::from_utf8_lossy(&head[at + 8..at + 24]);
                    return Some(format!(
                        "segment {} ends at byte {end}, past the end of the file at {length}",
                        name.trim_end_matches('\0')
                    ));
                }
            }
        } else if command == CODE_SIGNATURE
            && let (Some(offset), Some(filled)) = (u32_at(head, at + 8), u32_at(head, at + 12))
        {
            let end = u64::from(offset) + u64::from(filled);
            if filled == 0 || end > length {
                return Some(format!(
                    "its signature ends at byte {end}, past the end of the file at {length}"
                ));
            }
        }
        at += command_size as usize;
    }
    None
}

/// The first bytes of a file, as many as the check of its header reads.
fn head_of(path: &Path) -> std::io::Result<(Vec<u8>, u64)> {
    let file = File::open(path)?;
    let length = file.metadata()?.len();
    let mut head = Vec::new();
    file.take(HEAD_BYTES as u64).read_to_end(&mut head)?;
    Ok((head, length))
}

/// The system's check of a program's signature, on a system that has one.
#[cfg(target_os = "macos")]
fn signature_check(path: &Path) -> Option<Result<(), String>> {
    let output = Command::new("/usr/bin/codesign")
        .args(["--verify", "--strict"])
        .arg(path)
        .stdin(Stdio::null())
        .output()
        .ok()?;
    if output.status.success() {
        return Some(Ok(()));
    }
    let said = String::from_utf8_lossy(&output.stderr);
    let first = said.lines().next().unwrap_or("it refused the file");
    Some(Err(first.replace(&path.display().to_string(), "the file")))
}

#[cfg(not(target_os = "macos"))]
fn signature_check(_path: &Path) -> Option<Result<(), String>> {
    None
}

/// What is known of `path` now.
#[must_use]
pub fn facts_of(path: &Path, now: SystemTime) -> FileFacts {
    let age = std::fs::metadata(path)
        .and_then(|metadata| metadata.modified())
        .ok()
        .and_then(|written| now.duration_since(written).ok());
    match head_of(path) {
        Ok((head, length)) => {
            let shape = macho_problem(&head, length);
            let signature = if shape.is_none() && u32_at(&head, 0) == Some(MACH_O_64) {
                signature_check(path)
            } else {
                None
            };
            FileFacts {
                path: path.to_path_buf(),
                size: Some(length),
                age,
                head: head
                    .iter()
                    .take(32)
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<Vec<_>>()
                    .join(" "),
                shape,
                signature,
                unread: None,
            }
        }
        Err(error) => FileFacts {
            path: path.to_path_buf(),
            size: None,
            age,
            head: String::new(),
            shape: None,
            signature: None,
            unread: Some(format!("the file could not be read: {error}")),
        },
    }
}

/// How many of the kernel's lines say a write to storage failed.
#[must_use]
pub fn count_storage_errors(text: &str) -> usize {
    text.lines()
        .filter(|line| line.contains("kernel["))
        .filter(|line| STORAGE_WORDS.iter().any(|word| line.contains(word)))
        .count()
}

/// The stretch of the kernel's log that is read, in seconds since the epoch: from `LOG_PADDING`
/// before the earliest of the files that could not be started was written to `LOG_PADDING` after
/// the latest, and not past now, in no more than `LOG_MINUTES`. Neither the length of the step nor
/// the time the build then waited for other jobs is part of it: a storage error from before the
/// file was written, or long after, says nothing of it.
fn window_of(files: &[FileFacts], now: SystemTime) -> (u64, u64) {
    let now = now
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs());
    let written = |file: &FileFacts| now.saturating_sub(file.age.map_or(0, |age| age.as_secs()));
    let first = files.iter().map(written).min().unwrap_or(now);
    let last = files.iter().map(written).max().unwrap_or(now);
    let end = (last + LOG_PADDING).min(now);
    let start = first
        .saturating_sub(LOG_PADDING)
        .max(end.saturating_sub(LOG_MINUTES * 60));
    (start, end)
}

/// Asks a process to end, and kills it when it has not ended after `GRACE`. A process that runs
/// as root, which `sudo` is, takes a signal from root only, so the request is made through `sudo`
/// then; `sudo` passes a request to end on to the program it runs, and cannot pass on a kill.
#[cfg(target_os = "macos")]
fn end_process(child: &mut std::process::Child, as_root: bool) {
    let pid = child.id().to_string();
    let signal = |name: &str| {
        let mut command = if as_root {
            let mut command = Command::new("sudo");
            command.args(["-n", "/bin/kill"]);
            command
        } else {
            Command::new("/bin/kill")
        };
        command
            .arg(name)
            .arg(&pid)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
    };
    let asked = signal("-TERM");
    let asked_at = std::time::Instant::now();
    while asked && asked_at.elapsed() < GRACE {
        if child.try_wait().is_ok_and(|status| status.is_some()) {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    if as_root {
        signal("-KILL");
    }
    let _ = child.kill();
    let _ = child.wait();
}

/// The local time at `epoch` seconds, in the form the kernel's log reads a date in.
#[cfg(target_os = "macos")]
fn local_time(epoch: u64) -> Result<String, String> {
    let output = Command::new("/bin/date")
        .args(["-r", &epoch.to_string(), "+%Y-%m-%d %H:%M:%S"])
        .stdin(Stdio::null())
        .output()
        .map_err(|error| error.to_string())?;
    if !output.status.success() {
        return Err("the date could not be formatted".to_owned());
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

/// Writes the kernel's storage lines from `start` to `end`, in seconds since the epoch, to `out`.
#[cfg(target_os = "macos")]
fn storage_log(start: u64, end: u64, out: &Path) -> Result<(), String> {
    let (start, end) = (local_time(start)?, local_time(end)?);
    for with_sudo in [true, false] {
        let mut command = if with_sudo {
            let mut command = Command::new("sudo");
            command.args(["-n", "/usr/bin/log"]);
            command
        } else {
            Command::new("/usr/bin/log")
        };
        command.args([
            "show",
            "--start",
            &start,
            "--end",
            &end,
            "--style",
            "compact",
            "--predicate",
            STORAGE_PREDICATE,
        ]);
        let file = File::create(out).map_err(|error| error.to_string())?;
        let mut child = command
            .stdin(Stdio::null())
            .stdout(Stdio::from(file))
            .stderr(Stdio::null())
            .spawn()
            .map_err(|error| format!("the kernel's log could not be started: {error}"))?;
        let started = std::time::Instant::now();
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) if started.elapsed() > LOG_LIMIT => {
                    end_process(&mut child, with_sudo);
                    return Err("the kernel's log was not read in time".to_owned());
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(200)),
                Err(error) => return Err(error.to_string()),
            }
        };
        if status.success() {
            return Ok(());
        }
    }
    Err("the kernel's log could not be read".to_owned())
}

#[cfg(not(target_os = "macos"))]
fn storage_log(_start: u64, _end: u64, _out: &Path) -> Result<(), String> {
    Err("the kernel's log is read on macOS only".to_owned())
}

/// Where the file of free-space samples that `scripts/disk-report.sh` keeps is: its `state`
/// directory, named by the same variables in the same order.
fn samples_path() -> PathBuf {
    let base = std::env::var_os("RUNNER_TEMP")
        .or_else(|| std::env::var_os("TMPDIR"))
        .map_or_else(|| PathBuf::from("/tmp"), PathBuf::from);
    base.join("kr-disk-report").join("samples")
}

/// The longest stretch, in seconds, that may pass without a sample before the samples are taken for
/// not covering the time. The disk report samples every two seconds and skips a sample it cannot
/// write, so a gap is what a volume with no room leaves.
const MAX_SAMPLE_GAP: u64 = 30;

/// The lowest free space, in KiB, among the samples of `text` taken from `from` to `until`, in
/// seconds since the epoch. A sample is a line `S <epoch> <KiB>`; the marks and anything else are
/// passed over. The samples have to cover the whole stretch: a stretch with none, or one with a gap
/// of more than [`MAX_SAMPLE_GAP`] seconds, including before the first and after the last, is an
/// error, because what the volume held in the gap is not known.
fn lowest_sample(text: &str, from: u64, until: u64) -> Result<u64, String> {
    let mut samples: Vec<(u64, u64)> = text
        .lines()
        .filter_map(|line| {
            let mut words = line.split_whitespace();
            if words.next()? != "S" {
                return None;
            }
            let at: u64 = words.next()?.parse().ok()?;
            let free: u64 = words.next()?.parse().ok()?;
            (from..=until).contains(&at).then_some((at, free))
        })
        .collect();
    samples.sort_unstable();
    let Some(lowest) = samples.iter().map(|(_, free)| *free).min() else {
        return Err("no free-space sample was taken in the stretch".to_owned());
    };
    let times: Vec<u64> = std::iter::once(from)
        .chain(samples.iter().map(|(at, _)| *at))
        .chain(std::iter::once(until))
        .collect();
    if let Some(gap) = times
        .windows(2)
        .map(|pair| pair[1].saturating_sub(pair[0]))
        .find(|gap| *gap > MAX_SAMPLE_GAP)
    {
        return Err(format!(
            "the free-space samples have a gap of {gap} s in the stretch"
        ));
    }
    Ok(lowest)
}

/// The free space of the volume that holds `path`, in KiB, as the system's `df` says now.
#[cfg(unix)]
fn free_now(path: &Path) -> Result<u64, String> {
    let output = Command::new("/bin/df")
        .arg("-Pk")
        .arg(path)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .map_err(|error| format!("df could not be run: {error}"))?;
    if !output.status.success() {
        return Err("df could not read the volume".to_owned());
    }
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .nth(1)
        .and_then(|line| line.split_whitespace().nth(3))
        .and_then(|word| word.parse().ok())
        .ok_or_else(|| "df's answer could not be read".to_owned())
}

#[cfg(not(unix))]
fn free_now(_path: &Path) -> Result<u64, String> {
    Err("the free space of a volume is read on Unix only".to_owned())
}

/// The lowest free space, in KiB, that the volume holding `target` had from `from` to `until`: the
/// lowest sample the disk report took in that stretch, and the volume as it is now, whichever is
/// lower. Both have to be read: the samples have to cover the stretch, and the volume has to be
/// readable now.
///
/// # Errors
///
/// Returns why either could not be read.
pub fn lowest_free_kib(target: &Path, from: u64, until: u64) -> Result<u64, String> {
    let samples = std::fs::read_to_string(samples_path())
        .map_err(|error| format!("the free-space samples were not read: {error}"));
    lowest_free_of(samples, free_now(target), from, until)
}

/// [`lowest_free_kib`] over what was read: the text of the samples and the volume's free space now.
fn lowest_free_of(
    samples: Result<String, String>,
    now: Result<u64, String>,
    from: u64,
    until: u64,
) -> Result<u64, String> {
    let sampled = lowest_sample(&samples?, from, until)?;
    Ok(sampled.min(now?))
}

/// Writes the kernel's storage lines from the first time to the second, in seconds since the
/// epoch, to the file.
pub type KernelLog = Box<dyn Fn(u64, u64, &Path) -> Result<(), String>>;

/// The lowest free space, in KiB, of the volume that holds the path, from the first time to the
/// second.
pub type FreeSpace = Box<dyn Fn(&Path, u64, u64) -> Result<u64, String>>;

/// Where the evidence of a cause is read from. [`Reads::system`] is this machine's own; a case
/// gives others.
pub struct Reads {
    /// The kernel's log.
    pub kernel_log: KernelLog,
    /// The volume's free space.
    pub free_space: FreeSpace,
}

impl Reads {
    /// The kernel's log and the volume of this machine.
    #[must_use]
    pub fn system() -> Self {
        Self {
            kernel_log: Box::new(storage_log),
            free_space: Box::new(lowest_free_kib),
        }
    }
}

/// What the evidence says. The runner's disk needs the system's own word for it: the kernel
/// logged a storage error in the window of the files' writing, and the volume was not so full
/// that the suite's own writes could have filled it (its lowest free space is at
/// [`FREE_FLOOR_KIB`] or over). A damaged file says what the file is, not why: a program of ours
/// that wrote to a wrong path, or a test that filled the volume, damages one as well. Where the
/// log could not be read, or the volume's free space could not, nothing shows it, and the cause is
/// unexplained.
#[must_use]
pub fn cause_of(storage: &Result<usize, String>, free: &Result<u64, String>) -> Cause {
    match (storage, free) {
        (Ok(lines), Ok(kib)) if *lines > 0 && *kib >= FREE_FLOOR_KIB => Cause::RunnerDisk,
        _ => Cause::Unexplained,
    }
}

/// The evidence in a sentence.
fn reason_for(
    cause: Cause,
    files: &[FileFacts],
    storage: &Result<usize, String>,
    free: &Result<u64, String>,
    root: &Path,
) -> String {
    let named = |file: &FileFacts| {
        file.path
            .strip_prefix(root)
            .unwrap_or(&file.path)
            .display()
            .to_string()
    };
    let mut parts: Vec<String> = Vec::new();
    for file in files {
        parts.push(if let Some(shape) = &file.shape {
            format!("{}: {shape}", named(file))
        } else if let Some(why) = &file.unread {
            format!("{}: {why}", named(file))
        } else if let Some(Err(why)) = &file.signature {
            format!("{}: its signature does not check ({why})", named(file))
        } else {
            format!(
                "{}: no damage found, its signature is {}",
                named(file),
                if matches!(file.signature, Some(Ok(()))) {
                    "valid"
                } else {
                    "not checked"
                }
            )
        });
    }
    match storage {
        Ok(count) if *count > 0 => parts.push(format!(
            "the kernel logged {count} storage error lines in the minutes before"
        )),
        Ok(_) => parts.push("the kernel logged no storage error".to_owned()),
        Err(why) => parts.push(format!("the kernel's log was not read: {why}")),
    }
    match free {
        Ok(kib) if *kib >= FREE_FLOOR_KIB => {
            parts.push(format!("the volume had {} MiB free or more", kib / 1024));
        }
        Ok(kib) => parts.push(format!(
            "the volume was full: its free space fell to {} MiB, under the floor of {} MiB",
            kib / 1024,
            FREE_FLOOR_KIB / 1024
        )),
        Err(why) => parts.push(format!("the volume's free space was not read: {why}")),
    }
    match cause {
        Cause::RunnerDisk => format!("the runner's disk: {}", parts.join("; ")),
        Cause::Unexplained => {
            format!("not shown to be the runner's disk: {}", parts.join("; "))
        }
    }
}

/// Whether the file was written at or after `began`.
fn written_since(path: &Path, began: SystemTime) -> bool {
    std::fs::metadata(path)
        .and_then(|metadata| metadata.modified())
        .is_ok_and(|written| written >= began)
}

#[cfg(unix)]
fn is_executable(metadata: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn is_executable(_metadata: &std::fs::Metadata) -> bool {
    false
}

/// The profile directories of a target directory, which are the directories one level down, or two
/// where the build names a target triple, that hold Cargo's records of what it built.
fn profiles_of(target: &Path) -> Vec<PathBuf> {
    let is_directory =
        |entry: &std::fs::DirEntry| entry.file_type().is_ok_and(|kind| kind.is_dir());
    let mut found = Vec::new();
    let Ok(entries) = std::fs::read_dir(target) else {
        return found;
    };
    for entry in entries.flatten().filter(is_directory) {
        let path = entry.path();
        if path.join(".fingerprint").is_dir() {
            found.push(path);
        } else if let Ok(inner) = std::fs::read_dir(&path) {
            found.extend(
                inner
                    .flatten()
                    .filter(is_directory)
                    .map(|deeper| deeper.path())
                    .filter(|deeper| deeper.join(".fingerprint").is_dir()),
            );
        }
    }
    found
}

/// The profile directory that holds `file` as a program of Cargo's making: the file is in the
/// profile directory itself (a linked program), in its `deps` (a unit's output), or in a unit's
/// directory under its `build` (a build script). A file anywhere else under the target directory
/// is not one that a build wrote.
fn profile_of_output(target: &Path, file: &Path) -> Option<PathBuf> {
    // A profile directory is one level below the target directory, or two with a target triple.
    let is_profile = |directory: &Path| {
        directory
            .strip_prefix(target)
            .is_ok_and(|rest| (1..=2).contains(&rest.components().count()))
            && directory.join(".fingerprint").is_dir()
    };
    let parent = file.parent()?;
    if is_profile(parent) {
        return Some(parent.to_path_buf());
    }
    let above = parent.parent()?;
    if parent.file_name().is_some_and(|name| name == "deps") && is_profile(above) {
        return Some(above.to_path_buf());
    }
    let profile = above.parent()?;
    (above.file_name().is_some_and(|name| name == "build") && is_profile(profile))
        .then(|| profile.to_path_buf())
}

/// Whether Cargo has a record of having built `file`, a program in `profile`: a build script has
/// the records of the unit its directory is named for; a unit's file in `deps` has the records of
/// the unit its hash names; a program in the profile directory is a link to a file in `deps` that
/// has them. A program that something other than Cargo wrote there has none.
fn has_cargo_record(profile: &Path, file: &Path) -> bool {
    let records = profile.join(".fingerprint");
    let recorded = |hash: &str| {
        std::fs::read_dir(&records).is_ok_and(|entries| {
            entries.flatten().any(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .ends_with(&format!("-{hash}"))
            })
        })
    };
    let Some(parent) = file.parent() else {
        return false;
    };
    if parent
        .parent()
        .is_some_and(|above| above == profile.join("build"))
    {
        return parent
            .file_name()
            .is_some_and(|unit| records.join(unit).is_dir());
    }
    if parent == profile.join("deps") {
        return file
            .file_name()
            .and_then(|name| hash_of(&name.to_string_lossy()).map(recorded))
            .unwrap_or(false);
    }
    let Ok(own) = std::fs::metadata(file) else {
        return false;
    };
    std::fs::read_dir(profile.join("deps")).is_ok_and(|entries| {
        entries.flatten().any(|entry| {
            entry
                .metadata()
                .is_ok_and(|metadata| same_file(&own, &metadata))
                && hash_of(&entry.file_name().to_string_lossy()).is_some_and(recorded)
        })
    })
}

/// Adds the programs of `directory`, written at or after `began`, whose Mach-O header shows them
/// empty or cut short.
fn scan(directory: &Path, began: SystemTime, found: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(directory) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if !entry.file_type().is_ok_and(|kind| kind.is_file()) || path.extension().is_some() {
            continue;
        }
        let Ok(metadata) = entry.metadata() else {
            continue;
        };
        let recent = metadata.modified().is_ok_and(|written| written >= began);
        if recent
            && is_executable(&metadata)
            && head_of(&path).is_ok_and(|(head, length)| macho_problem(&head, length).is_some())
        {
            found.push(path);
        }
    }
}

/// The programs written since `began` whose Mach-O header shows them empty or cut short, in the
/// places a build puts programs: each profile directory, its `deps` and each unit's directory
/// under its `build`. They are the files of the same burst that no log named yet.
#[must_use]
pub fn damaged_since(target: &Path, began: SystemTime) -> Vec<PathBuf> {
    let mut found = Vec::new();
    for profile in profiles_of(target) {
        scan(&profile, began, &mut found);
        scan(&profile.join("deps"), began, &mut found);
        if let Ok(units) = std::fs::read_dir(profile.join("build")) {
            for unit in units.flatten() {
                if unit.file_type().is_ok_and(|kind| kind.is_dir()) {
                    scan(&unit.path(), began, &mut found);
                }
            }
        }
    }
    found.sort();
    found
}

/// The sixteen hexadecimal digits Cargo ends a unit's file names with, in `name`.
fn hash_of(name: &str) -> Option<&str> {
    let stem = name.split('.').next()?;
    let (_, hash) = stem.rsplit_once('-')?;
    (hash.len() == 16 && hash.bytes().all(|byte| byte.is_ascii_hexdigit())).then_some(hash)
}

/// Whether `path` is in a directory that lies inside `target`, with every link on the way to it
/// followed: a removal of something in a directory that a link leads out of would remove what the
/// link points at.
fn within(target: &Path, path: &Path) -> bool {
    let (Ok(real), Some(parent)) = (target.canonicalize(), path.parent()) else {
        return false;
    };
    parent
        .canonicalize()
        .is_ok_and(|parent| parent.starts_with(real))
}

/// What a removal takes: a directory with all that is in it, or one file.
enum Taken {
    Tree(PathBuf),
    File(PathBuf),
}

/// Adds the files of the unit with `hash` in the profile directory's `deps`, and the unit's records
/// of having been built, to `taken`.
fn takes_unit(profile: &Path, hash: &str, taken: &mut Vec<Taken>) {
    let suffix = format!("-{hash}");
    if let Ok(entries) = std::fs::read_dir(profile.join("deps")) {
        for entry in entries.flatten() {
            if entry.file_name().to_string_lossy().contains(&suffix) {
                taken.push(Taken::File(entry.path()));
            }
        }
    }
    if let Ok(entries) = std::fs::read_dir(profile.join(".fingerprint")) {
        for entry in entries.flatten() {
            if entry.file_name().to_string_lossy().ends_with(&suffix) {
                taken.push(Taken::Tree(entry.path()));
            }
        }
    }
}

#[cfg(unix)]
fn same_file(a: &std::fs::Metadata, b: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    a.dev() == b.dev() && a.ino() == b.ino()
}

#[cfg(not(unix))]
fn same_file(_a: &std::fs::Metadata, _b: &std::fs::Metadata) -> bool {
    false
}

/// What it takes to make Cargo build a damaged program again: for a build script, its directory
/// and the unit's records; for a program or test binary with a hash in its name, every file of
/// that unit and its records; for a program linked into the profile directory, the file in `deps`
/// it is a link to, that unit, and the program. A file that is not a program of Cargo's making is
/// taken for nothing.
fn takes_for(target: &Path, file: &Path) -> Vec<Taken> {
    let mut taken = Vec::new();
    let Some(profile) = profile_of_output(target, file) else {
        return taken;
    };
    let unit_directory = file.parent().filter(|parent| {
        parent
            .parent()
            .is_some_and(|above| above == profile.join("build"))
    });
    if let Some(unit) = unit_directory {
        if let Some(name) = unit.file_name() {
            taken.push(Taken::Tree(profile.join(".fingerprint").join(name)));
        }
        taken.push(Taken::Tree(unit.to_path_buf()));
        return taken;
    }
    let name = file
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    if let Some(hash) = hash_of(&name) {
        takes_unit(&profile, hash, &mut taken);
    } else if let Ok(own) = std::fs::metadata(file)
        && let Ok(entries) = std::fs::read_dir(profile.join("deps"))
    {
        let linked: Vec<String> = entries
            .flatten()
            .filter(|entry| {
                entry
                    .metadata()
                    .is_ok_and(|metadata| same_file(&own, &metadata))
            })
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect();
        for hash in linked.iter().filter_map(|name| hash_of(name)) {
            takes_unit(&profile, hash, &mut taken);
        }
    }
    taken.push(Taken::File(file.to_path_buf()));
    taken
}

/// The device a path is on, where the system says one.
#[cfg(unix)]
#[must_use]
pub fn volume_of(path: &Path) -> Option<u64> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(path).ok().map(|metadata| metadata.dev())
}

/// The device a path is on. Windows is held to no link or reparse point instead.
#[cfg(not(unix))]
#[must_use]
pub fn volume_of(_path: &Path) -> Option<u64> {
    None
}

/// Whether the entry is a link, or on Windows any reparse point (a link, a junction, a mount): a
/// removal that entered it would take what it leads to.
#[cfg(windows)]
fn redirects(metadata: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const REPARSE_POINT: u32 = 0x400;
    metadata.file_type().is_symlink() || metadata.file_attributes() & REPARSE_POINT != 0
}

/// Whether the entry is a link, which a removal would follow to what it leads to.
#[cfg(not(windows))]
fn redirects(metadata: &std::fs::Metadata) -> bool {
    metadata.file_type().is_symlink()
}

/// The device of an entry, where the system says one.
#[cfg(unix)]
fn device_of(metadata: &std::fs::Metadata) -> Option<u64> {
    use std::os::unix::fs::MetadataExt;
    Some(metadata.dev())
}

#[cfg(not(unix))]
fn device_of(_metadata: &std::fs::Metadata) -> Option<u64> {
    None
}

/// Walks `path`, adding what a removal of it takes to `entries` in the order it takes it (a
/// directory after what is in it), or says why it may not. It enters a directory only where the
/// directory is on `device`, the device of the build's output; it follows no link and enters no
/// reparse point; and it takes a file only where the file was written at or after `began`, because
/// a file older than the step is not one the step's build made. A directory is taken by the
/// record that names it (the unit's), and so is not held to a time. A path that is not there is
/// nothing to take. With `as_tree` false a directory is left alone, which is where a file was
/// looked for.
fn gather(
    path: &Path,
    as_tree: bool,
    device: Option<u64>,
    began: SystemTime,
    entries: &mut Vec<(PathBuf, bool)>,
) -> Result<(), String> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(format!("{} could not be read: {error}", path.display())),
    };
    if redirects(&metadata) {
        return Err(format!("{} is a link", path.display()));
    }
    if let (Some(want), Some(have)) = (device, device_of(&metadata))
        && want != have
    {
        return Err(format!(
            "{} is on another device than the build's output",
            path.display()
        ));
    }
    if metadata.is_dir() {
        if as_tree {
            let children = std::fs::read_dir(path)
                .map_err(|error| format!("{} could not be read: {error}", path.display()))?;
            for child in children {
                let child = child
                    .map_err(|error| format!("{} could not be read: {error}", path.display()))?;
                gather(&child.path(), true, device, began, entries)?;
            }
            entries.push((path.to_path_buf(), true));
        }
        return Ok(());
    }
    if !metadata.is_file() {
        return Err(format!(
            "{} is neither a file nor a directory",
            path.display()
        ));
    }
    match metadata.modified() {
        Ok(written) if written >= began => {
            entries.push((path.to_path_buf(), false));
            Ok(())
        }
        Ok(_) => Err(format!(
            "{} was not written since the step began",
            path.display()
        )),
        Err(error) => Err(format!(
            "when {} was written could not be read: {error}",
            path.display()
        )),
    }
}

/// What the removal for some damaged programs takes, checked before any of it is taken.
#[derive(Debug)]
pub struct Removal {
    /// Each thing taken, with the files and directories in it, in the order they go.
    parts: Vec<(PathBuf, Vec<(PathBuf, bool)>)>,
    /// The device of the build's output, which each entry is on.
    device: Option<u64>,
    /// When the step began: a file is older than it is not the step's.
    began: SystemTime,
}

impl Removal {
    /// Whether `path` is still what the plan found: not a link or reparse point, on the build's
    /// device, and, where it is a file, written since the step began, and its directory too is no
    /// link and on the device. It is read now, entry by entry, so that a change since the plan
    /// (a link put in place of a directory, a volume mounted on it) is seen.
    fn holds(&self, path: &Path, directory: bool) -> bool {
        let sound = |path: &Path| {
            std::fs::symlink_metadata(path).ok().filter(|metadata| {
                !redirects(metadata)
                    && match (self.device, device_of(metadata)) {
                        (Some(want), Some(have)) => want == have,
                        _ => true,
                    }
            })
        };
        let Some(metadata) = sound(path) else {
            return false;
        };
        if !directory
            && metadata
                .modified()
                .map_or(true, |written| written < self.began)
        {
            return false;
        }
        path.parent().is_some_and(|parent| sound(parent).is_some())
    }

    /// Takes what the removal holds, entry by entry, with no walk of its own: a directory goes
    /// when it is empty. Every entry is read again first, and where any of them is no longer what
    /// the plan found, nothing is taken at all. Returns what went whole: each directory or file the
    /// removal was for.
    ///
    /// # Errors
    ///
    /// Returns the first entry that is no longer what the plan found, and takes nothing.
    pub fn carry_out(self) -> Result<Vec<PathBuf>, String> {
        let changed = self
            .parts
            .iter()
            .flat_map(|(_, entries)| entries.iter())
            .find(|(path, directory)| !self.holds(path, *directory));
        if let Some((path, _)) = changed {
            return Err(format!(
                "{} is no longer what the plan found, so nothing is removed",
                path.display()
            ));
        }
        let mut removed = Vec::new();
        for (root, entries) in self.parts {
            let mut whole = true;
            for (path, directory) in entries {
                let taken = if directory {
                    std::fs::remove_dir(&path)
                } else {
                    std::fs::remove_file(&path)
                };
                whole &= taken.is_ok();
            }
            if whole {
                removed.push(root);
            }
        }
        Ok(removed)
    }
}

/// What it takes to make Cargo build the damaged programs `files` again, or why that may not be
/// taken. Nothing is taken here. The removal is for the files of Cargo's making that its records
/// name, in `target`, and stops at the first thing it may not take: a link or reparse point below
/// a unit, a directory that is on another device than `device` (the build's output, from
/// [`volume_of`]), a path that is not inside `target` once every link on the way is followed, or
/// a file that was written before `began`. Then nothing of any of the units is taken, so that a
/// file the step did not write, and what is on another volume, stays where it is.
///
/// # Errors
///
/// Returns the first thing that may not be taken, with its path.
pub fn removal_of(
    target: &Path,
    device: Option<u64>,
    began: SystemTime,
    files: &[PathBuf],
) -> Result<Removal, String> {
    let mut parts = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for file in files {
        for taken in takes_for(target, file) {
            let (root, as_tree) = match &taken {
                Taken::Tree(path) => (path, true),
                Taken::File(path) => (path, false),
            };
            if !seen.insert(root.clone()) {
                continue;
            }
            if !within(target, root) {
                return Err(format!(
                    "{} is not inside the target directory",
                    root.display()
                ));
            }
            let mut entries = Vec::new();
            gather(root, as_tree, device, began, &mut entries)?;
            if !entries.is_empty() {
                parts.push((root.clone(), entries));
            }
        }
    }
    Ok(Removal {
        parts,
        device,
        began,
    })
}

/// What a rerun's facts file says.
struct Account<'a> {
    step: &'a Step,
    number: usize,
    root: &'a Path,
    files: &'a [FileFacts],
    swept: &'a [PathBuf],
    storage: &'a Result<usize, String>,
    free: &'a Result<u64, String>,
    cause: Cause,
    reason: &'a str,
    removed: &'a [PathBuf],
}

/// The text of the file that keeps a rerun's facts.
fn facts_text(account: &Account<'_>) -> String {
    let Account {
        step,
        number,
        root,
        files,
        swept,
        storage,
        free,
        cause,
        reason,
        removed,
    } = *account;
    let relative = |path: &Path| {
        path.strip_prefix(root)
            .unwrap_or(path)
            .display()
            .to_string()
    };
    let mut text = format!(
        "step {number}: {}\ncause: {cause:?}: {reason}\n\n",
        step.command.join(" ")
    );
    for file in files {
        text.push_str(&format!("file: {}\n", relative(&file.path)));
        text.push_str(&format!(
            "  size: {}\n  written: {}\n  first bytes: {}\n  Mach-O header: {}\n  signature: {}\n",
            file.size
                .map_or_else(|| "unknown".to_owned(), |size| format!("{size} bytes")),
            file.age.map_or_else(
                || "unknown".to_owned(),
                |age| format!("{} s before the check", age.as_secs())
            ),
            if file.head.is_empty() {
                "none"
            } else {
                &file.head
            },
            file.shape
                .as_deref()
                .or(file.unread.as_deref())
                .unwrap_or("no damage found"),
            match &file.signature {
                None => "not checked".to_owned(),
                Some(Ok(())) => "valid".to_owned(),
                Some(Err(why)) => format!("refused: {why}"),
            }
        ));
    }
    text.push_str(&format!(
        "\nstorage error lines in the kernel's log: {}\n",
        match storage {
            Ok(count) => count.to_string(),
            Err(why) => format!("not read: {why}"),
        }
    ));
    text.push_str(&format!(
        "lowest free space of the volume (floor {} KiB): {}\n",
        FREE_FLOOR_KIB,
        match free {
            Ok(kib) => format!("{kib} KiB"),
            Err(why) => format!("not read: {why}"),
        }
    ));
    text.push_str(&format!(
        "\nother programs of this step found empty or cut short: {}\n",
        swept.len()
    ));
    for path in swept {
        text.push_str(&format!("  {}\n", relative(path)));
    }
    text.push_str(&format!(
        "\nremoved before the second run: {}\n",
        removed.len()
    ));
    for path in removed {
        text.push_str(&format!("  {}\n", relative(path)));
    }
    text
}

/// Whether a test of the step's run failed, or its outcomes cannot be read: a step in which one
/// did has a failure of its own, which a second run could hide.
fn has_failed_test(done: &Executed) -> bool {
    done.binaries.iter().any(|(_, binary)| {
        binary.problem.is_some()
            || binary.summary.is_some_and(|summary| summary[1] > 0)
            || binary
                .tests
                .values()
                .any(|outcome| matches!(outcome, Outcome::Failed))
    })
}

/// Runs `step`, and once more when its first run ended in a file the linker wrote that the system
/// would not start.
///
/// The second run is the step's result, with the first run's log kept beside its own and the
/// facts in [`Rerun`]. Where the evidence does not show the runner's disk, the step has an error
/// and the report fails, and so it does where the first run's evidence could not be kept. The file
/// has to be a program of Cargo's making that the step wrote. A step in which a test failed is not
/// run again, and neither is one whose first run took longer than what `budget`, the time the
/// report leaves for second runs, still holds. Nor is a step run again when what its removal would
/// take cannot all be taken (see [`removal_of`]): it ends red with the reason and nothing of its
/// units is removed.
///
/// The second run has a deadline: what `budget` allows when the run starts. At it every process of
/// the step is ended, and the step ends red with [`PASSED_ITS_TIME`] and its log as far as it was
/// written, so that the report goes on to write its result. What the second run took is taken from
/// `budget`.
#[must_use]
pub fn execute(
    step: &Step,
    number: usize,
    place: &Place<'_>,
    packages: &[Package],
    budget: &mut Budget,
    reads: &Reads,
    progress: &mut dyn FnMut(&str),
) -> Executed {
    let began = SystemTime::now();
    let mut first = run::execute(step, number, place, packages, None);
    if first.error.is_none() && first.exit == Some(0) {
        return first;
    }
    let target = target_directory(place.root, place.environment);
    let Ok(bytes) = std::fs::read(place.evidence.join(&first.log)) else {
        return first;
    };
    let built_by_cargo = |path: &PathBuf| {
        written_since(path, began)
            && profile_of_output(&target, path)
                .is_some_and(|profile| has_cargo_record(&profile, path))
    };
    let named: Vec<PathBuf> = named_files(&String::from_utf8_lossy(&bytes), &target)
        .into_iter()
        .filter(built_by_cargo)
        .collect();
    if named.is_empty() {
        return first;
    }
    let took = Duration::from_secs(first.seconds);
    let swept: Vec<PathBuf> = damaged_since(&target, began)
        .into_iter()
        .filter(|path| !named.contains(path) && built_by_cargo(path))
        .collect();
    let doomed: Vec<PathBuf> = named.iter().chain(swept.iter()).cloned().collect();
    let removal = removal_of(&target, volume_of(&target), began, &doomed);
    let allowed = budget.allowed(SystemTime::now());
    let refusal = if has_failed_test(&first) {
        Some("a test of the step failed".to_owned())
    } else if allowed.is_zero() || took > allowed {
        Some(format!(
            "its first run took {} s and {} s are left for a second run",
            took.as_secs(),
            allowed.as_secs()
        ))
    } else {
        removal
            .as_ref()
            .err()
            .map(|why| format!("nothing of its units is removed, because {why}"))
    };
    if let Some(why) = refusal {
        let said = format!(
            "a file the step linked could not be started, and the step is not run again: {why}"
        );
        progress(&format!("  {said}"));
        first.error = Some(match first.error.take() {
            Some(error) => format!("{error}; {said}"),
            None => said,
        });
        return first;
    }
    let now = SystemTime::now();
    let files: Vec<FileFacts> = named.iter().map(|path| facts_of(path, now)).collect();
    // The refusal above took a removal that may not be made.
    if removal.is_err() {
        return first;
    }
    let stem = Path::new(&first.log)
        .file_stem()
        .map(|stem| stem.to_string_lossy().into_owned())
        .unwrap_or_default();
    let mut unkept: Vec<String> = Vec::new();
    let faults = place.evidence.join("conformance").join("faults");
    if let Err(error) = std::fs::create_dir_all(&faults) {
        unkept.push(format!("{} was not made: {error}", faults.display()));
    }
    let kernel = faults.join(format!("{stem}.kernel.txt"));
    let (from, until) = window_of(&files, now);
    let storage = (reads.kernel_log)(from, until, &kernel).and_then(|()| {
        std::fs::read_to_string(&kernel)
            .map(|text| count_storage_errors(&text))
            .map_err(|error| error.to_string())
    });
    let free = (reads.free_space)(&target, from, until);
    let cause = cause_of(&storage, &free);
    let reason = reason_for(cause, &files, &storage, &free, place.root);
    // The plan that is carried out is the one made now, not the one made before the evidence was
    // read, which took time (the kernel's log alone up to a minute and a half): a process of the
    // first run could have changed what lies under a unit since. Each entry is read again as the
    // removal goes (see `Removal::carry_out`).
    let removed = match removal_of(&target, volume_of(&target), began, &doomed)
        .and_then(Removal::carry_out)
    {
        Ok(removed) => removed,
        Err(why) => {
            let said = format!(
                "a file the step linked could not be started, and the step is not run again: nothing of its units is removed, because {why}"
            );
            progress(&format!("  {said}"));
            first.error = Some(match first.error.take() {
                Some(error) => format!("{error}; {said}"),
                None => said,
            });
            return first;
        }
    };
    let facts = format!("conformance/faults/{stem}.txt");
    if let Err(error) = std::fs::write(
        place.evidence.join(&facts),
        facts_text(&Account {
            step,
            number,
            root: place.root,
            files: &files,
            swept: &swept,
            storage: &storage,
            free: &free,
            cause,
            reason: &reason,
            removed: &removed,
        }),
    ) {
        unkept.push(format!("{facts} was not written: {error}"));
    }
    let logs = place.evidence.join("conformance").join("logs");
    let first_log = format!("conformance/logs/{stem}.first-run.log");
    let moved = std::fs::rename(
        place.evidence.join(&first.log),
        place.evidence.join(&first_log),
    );
    if let Err(error) = std::fs::rename(
        logs.join(format!("{stem}.records")),
        logs.join(format!("{stem}.first-run.records")),
    ) && error.kind() != std::io::ErrorKind::NotFound
    {
        unkept.push(format!("the first run's records were not kept: {error}"));
    }
    let first_log = match moved {
        Ok(()) => first_log,
        Err(error) => {
            unkept.push(format!("the first run's log was not kept: {error}"));
            first.log.clone()
        }
    };
    let relative: Vec<String> = named
        .iter()
        .map(|path| {
            path.strip_prefix(place.root)
                .unwrap_or(path)
                .display()
                .to_string()
        })
        .collect();
    progress(&format!(
        "  a file the step linked could not be started: {}; {reason}; the step is run again",
        relative.join(", ")
    ));
    // The second run is given what is left when it starts, which the evidence read before it has
    // taken from what was left when it was allowed.
    let deadline = run::Deadline {
        at: Instant::now() + budget.allowed(SystemTime::now()),
        says: PASSED_ITS_TIME,
    };
    let mut second = run::execute(step, number, place, packages, Some(&deadline));
    budget.charge(Duration::from_secs(second.seconds));
    if cause == Cause::Unexplained {
        let said = format!(
            "a file the step linked could not be started, and it was {reason}: the cause may be this repository's"
        );
        second.error = Some(match second.error.take() {
            Some(error) => format!("{error}; {said}"),
            None => said,
        });
    }
    if !unkept.is_empty() {
        let said = format!(
            "the first run's evidence was not kept: {}",
            unkept.join("; ")
        );
        second.error = Some(match second.error.take() {
            Some(error) => format!("{error}; {said}"),
            None => said,
        });
    }
    second.rerun = Some(Rerun {
        first_log,
        first_exit: first.exit,
        first_error: first.error,
        files: relative,
        cause,
        reason,
        facts,
        removed: removed.len(),
    });
    second
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A line from a step's log of a night's run, with the file's own path twice.
    const REFUSED: &str = "/Users/runner/work/kalareach/kalareach/target/release/build/serde_json-1ad93a6e71728a74/build-script-build: /Users/runner/work/kalareach/kalareach/target/release/build/serde_json-1ad93a6e71728a74/build-script-build: cannot execute binary file";

    #[test]
    fn a_file_under_the_target_directory_is_named_by_the_shells_words_and_exit_126() {
        let log = format!(
            "error: failed to run custom build command for `serde_json v1.0.151`\n\nCaused by:\n  process didn't exit successfully: `x/build-script-build` (exit status: 126)\n  --- stderr\n  {REFUSED}\nwarning: build failed\n"
        );
        let target = Path::new("/Users/runner/work/kalareach/kalareach/target");
        assert_eq!(
            named_files(&log, target),
            vec![PathBuf::from(REFUSED.split_once(": ").unwrap().0)]
        );
        assert!(named_files(&log, Path::new("/elsewhere/target")).is_empty());
        let without_the_exit = log.replace("(exit status: 126)", "(exit status: 1)");
        assert!(named_files(&without_the_exit, target).is_empty());
        let stepping_out = format!(
            "{log}  /Users/runner/work/kalareach/kalareach/target/../src/lib.rs: /Users/runner/work/kalareach/kalareach/target/../src/lib.rs: cannot execute binary file\n"
        );
        assert_eq!(
            named_files(&stepping_out, target),
            vec![PathBuf::from(REFUSED.split_once(": ").unwrap().0)],
            "a path that steps up out of the target directory is not named"
        );
    }

    /// A Mach-O header of one segment of `segment_end` bytes, in a file of `length` bytes.
    fn header(segment_end: u64) -> Vec<u8> {
        let mut bytes = Vec::new();
        for word in [MACH_O_64, 0x0100_000c, 0, 2, 1, 72, 0, 0] {
            bytes.extend_from_slice(&word.to_le_bytes());
        }
        bytes.extend_from_slice(&SEGMENT_64.to_le_bytes());
        bytes.extend_from_slice(&72u32.to_le_bytes());
        bytes.extend_from_slice(b"__TEXT\0\0\0\0\0\0\0\0\0\0");
        for word in [0u64, 0, 0, segment_end] {
            bytes.extend_from_slice(&word.to_le_bytes());
        }
        bytes.extend_from_slice(&[0; 16]);
        bytes
    }

    #[test]
    fn a_header_is_empty_zero_cut_short_or_whole() {
        assert!(macho_problem(&[], 0).unwrap().contains("empty"));
        assert!(macho_problem(&[0; 64], 4096).unwrap().contains("all zero"));
        let mut cut = MACH_O_64.to_le_bytes().to_vec();
        cut.extend_from_slice(&[7; 6]);
        assert!(macho_problem(&cut, 10).unwrap().contains("too short"));
        assert_eq!(
            macho_problem(b"not a program", 13),
            None,
            "a file that is not a Mach-O program is not shown to be damaged"
        );
        let whole = header(4096);
        assert_eq!(macho_problem(&whole, 4096), None);
        assert!(
            macho_problem(&whole, 2048)
                .unwrap()
                .contains("segment __TEXT ends at byte 4096")
        );
        assert_eq!(macho_problem(b"#!/bin/sh\nexit 0\n", 17), None);
    }

    #[test]
    fn the_kernels_log_is_read_around_the_time_the_files_were_written() {
        let now = UNIX_EPOCH + Duration::from_secs(1_000_000);
        let at = |seconds: u64| 1_000_000 - seconds;
        let aged = |seconds: u64| FileFacts {
            age: Some(Duration::from_secs(seconds)),
            ..facts(None, None)
        };
        // One file written 30 seconds ago: from three minutes before to now.
        assert_eq!(
            window_of(&[aged(30)], now),
            (at(30) - LOG_PADDING, 1_000_000)
        );
        // Files written ten minutes and half a minute ago.
        assert_eq!(
            window_of(&[aged(30), aged(600)], now),
            (at(600) - LOG_PADDING, 1_000_000)
        );
        // A file written an hour ago, and the build then waited: the window ends three minutes
        // after the write, and the storage errors of the last hour are not part of it.
        assert_eq!(
            window_of(&[aged(3600)], now),
            (at(3600) - LOG_PADDING, at(3600) + LOG_PADDING)
        );
        // Files hours apart are read no further back than the longest stretch.
        let (from, until) = window_of(&[aged(5 * 3600), aged(60)], now);
        assert_eq!(until, 1_000_000);
        assert_eq!(until - from, LOG_MINUTES * 60);
    }

    #[test]
    fn a_program_is_one_cargo_built_only_where_cargo_has_a_record_of_it() {
        let directory = tempfile::tempdir().unwrap();
        let profile = directory.path().join("target/debug");
        let script = profile.join("build/serde_json-1ad93a6e71728a74/build-script-build");
        write(&script, b"");
        assert!(!has_cargo_record(&profile, &script), "no record yet");
        write(
            &profile.join(".fingerprint/serde_json-1ad93a6e71728a74/invoked.timestamp"),
            b"",
        );
        assert!(has_cargo_record(&profile, &script));
        let other = profile.join("build/serde_json-0000000000000000/build-script-build");
        write(&other, b"");
        assert!(!has_cargo_record(&profile, &other));

        let unit = profile.join("deps/report-f1d5e145b44f9f2d");
        write(&unit, b"");
        assert!(!has_cargo_record(&profile, &unit));
        write(
            &profile.join(".fingerprint/kr-conformance-f1d5e145b44f9f2d/test"),
            b"",
        );
        assert!(has_cargo_record(&profile, &unit));
        assert!(!has_cargo_record(
            &profile,
            &profile.join("deps/report-aaaaaaaaaaaaaaaa")
        ));

        // A program in the profile directory is one Cargo linked where it is a link to a unit's
        // file that has records, and not where something else wrote it.
        let stray = profile.join("helper");
        write(&stray, b"");
        assert!(!has_cargo_record(&profile, &stray));
        #[cfg(unix)]
        {
            let linked = profile.join("kr-conformance");
            std::fs::hard_link(&unit, &linked).unwrap();
            assert!(has_cargo_record(&profile, &linked));
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_file_that_cannot_be_read_is_said_to_be_unread_and_is_not_damaged() {
        let directory = tempfile::tempdir().unwrap();
        let facts = facts_of(directory.path(), SystemTime::now());
        assert!(facts.unread.is_some(), "{facts:?}");
        assert_eq!(facts.shape, None);
        assert!(!facts.damaged());
    }

    #[test]
    fn the_kernels_storage_lines_are_counted() {
        let text = "Timestamp Ty Process\n2026-11-07 09:33:56 E  kernel[0]: (IOStorageFamily) disk2s5: I/O error.\n2026-11-07 09:33:57 E  kernel[0]: apfs_fsync_internal_ext: disk2s5 cluster_push() failed with 5\nunrelated line\n";
        assert_eq!(count_storage_errors(text), 2);
        let asked = "2026-11-13 19:49:41.486 Df log[82133:461de93] [com.apple.log:] args: '--predicate' 'eventMessage CONTAINS \"I/O error\"'\n";
        assert_eq!(
            count_storage_errors(asked),
            0,
            "the query's own line is not a storage error"
        );
        assert_eq!(count_storage_errors(""), 0);
    }

    fn facts(shape: Option<&str>, signature: Option<Result<(), String>>) -> FileFacts {
        FileFacts {
            path: PathBuf::from("/r/target/debug/x"),
            size: Some(10),
            age: None,
            head: String::new(),
            shape: shape.map(str::to_owned),
            signature,
            unread: None,
        }
    }

    #[test]
    fn the_cause_is_the_runners_disk_only_where_the_kernel_says_so_and_the_volume_had_room() {
        let room = Ok(FREE_FLOOR_KIB);
        assert_eq!(cause_of(&Ok(3), &room), Cause::RunnerDisk);
        assert_eq!(
            cause_of(&Ok(0), &room),
            Cause::Unexplained,
            "no line of the kernel's log"
        );
        assert_eq!(
            cause_of(&Err("no sudo".to_owned()), &room),
            Cause::Unexplained,
            "the kernel's log could not be read"
        );
        assert_eq!(
            cause_of(&Ok(3), &Ok(FREE_FLOOR_KIB - 1)),
            Cause::Unexplained,
            "a volume under the floor is full"
        );
        assert_eq!(
            cause_of(&Ok(3), &Err("no df".to_owned())),
            Cause::Unexplained,
            "a volume whose free space was not read is not shown to have had room"
        );
    }

    /// A file that is damaged says what the file is and not why, so the reason names the missing
    /// evidence whatever the file looks like.
    #[test]
    fn the_reason_names_the_evidence_that_is_missing_whatever_the_file_looks_like() {
        let root = Path::new("/r");
        let damaged = [facts(Some("the file is empty"), None)];
        let room = Ok(FREE_FLOOR_KIB);
        let reason = reason_for(Cause::Unexplained, &damaged, &Ok(0), &room, root);
        assert!(
            reason.starts_with("not shown to be the runner's disk"),
            "{reason}"
        );
        assert!(reason.contains("the file is empty"), "{reason}");
        assert!(
            reason.contains("the kernel logged no storage error"),
            "{reason}"
        );
        let full = Ok(FREE_FLOOR_KIB - 1024);
        let reason = reason_for(Cause::Unexplained, &damaged, &Ok(4), &full, root);
        assert!(reason.contains("the volume was full"), "{reason}");
        assert!(reason.contains("2047 MiB"), "{reason}");
        let unread = Err("the kernel's log could not be read".to_owned());
        let reason = reason_for(Cause::Unexplained, &damaged, &unread, &room, root);
        assert!(reason.contains("the kernel's log was not read"), "{reason}");
        let reason = reason_for(Cause::RunnerDisk, &damaged, &Ok(4), &room, root);
        assert!(reason.starts_with("the runner's disk: "), "{reason}");
    }

    #[test]
    fn the_free_space_is_the_lowest_sample_in_a_stretch_that_the_samples_cover() {
        let text = "M 100 begin\nS 100 9000000\nS 110 1500000\nS 120 8000000\nS 130 7000000\nS 200 10\nS x y\n";
        assert_eq!(lowest_sample(text, 100, 130), Ok(1_500_000));
        assert_eq!(
            lowest_sample(text, 105, 125),
            Ok(1_500_000),
            "a few seconds of slack at each end"
        );
    }

    /// A volume with no room leaves a gap in the samples, not a low one: the disk report skips a
    /// sample it cannot write. A stretch the samples do not cover has no free space known.
    #[test]
    fn the_samples_that_do_not_cover_the_stretch_say_nothing_of_the_free_space() {
        let text = "S 100 9000000\nS 110 9000000\nS 200 9000000\nS 210 9000000\n";
        let why = lowest_sample(text, 100, 210).unwrap_err();
        assert!(why.contains("gap of 90 s"), "{why}");
        let why = lowest_sample(text, 60, 110).unwrap_err();
        assert!(
            why.contains("gap of 40 s"),
            "before the first sample: {why}"
        );
        let why = lowest_sample(text, 100, 150).unwrap_err();
        assert!(why.contains("gap of 40 s"), "after the last sample: {why}");
        let why = lowest_sample(text, 111, 119).unwrap_err();
        assert!(why.contains("no free-space sample"), "{why}");
        assert!(lowest_sample("", 0, 10).is_err());
    }

    /// The free space is known only where the samples cover the stretch and the volume can be read
    /// now: a high sample does not stand for a volume that cannot be read, and a volume that reads
    /// well now does not stand for samples that are missing or have a gap.
    #[test]
    fn the_free_space_needs_the_samples_and_the_volume_both() {
        let covering = || Ok("S 100 9000000\nS 110 1500000\nS 120 8000000\n".to_owned());
        let room = || Ok(30 * 1024 * 1024_u64);
        assert_eq!(lowest_free_of(covering(), room(), 100, 120), Ok(1_500_000));
        assert_eq!(
            lowest_free_of(covering(), Ok(1_000_000), 100, 120),
            Ok(1_000_000),
            "the volume now, where it is the lower"
        );
        let why = lowest_free_of(covering(), Err("no df".to_owned()), 100, 120).unwrap_err();
        assert_eq!(
            why, "no df",
            "a high sample does not stand for an unread volume"
        );
        let why = lowest_free_of(Err("no samples".to_owned()), room(), 100, 120).unwrap_err();
        assert_eq!(
            why, "no samples",
            "the volume now does not stand for absent samples"
        );
        let gap = Ok("S 100 9000000\nS 200 9000000\n".to_owned());
        let why = lowest_free_of(gap, room(), 100, 200).unwrap_err();
        assert!(why.contains("gap of 100 s"), "{why}");
    }

    #[test]
    fn a_second_run_is_allowed_what_the_account_and_the_jobs_limit_both_leave() {
        let now = UNIX_EPOCH + Duration::from_secs(1_000_000);
        let seconds = Duration::from_secs;
        let account = Budget::of(seconds(300));
        assert_eq!(account.allowed(now), seconds(300), "no limit is given");
        assert_eq!(
            account.until(now + seconds(3600)).allowed(now),
            seconds(300)
        );
        assert_eq!(
            account
                .until(now + RESULT_RESERVE + seconds(40))
                .allowed(now),
            seconds(40),
            "the limit, less what the report keeps for its result, is the sooner"
        );
        assert_eq!(
            account.until(now + seconds(30)).allowed(now),
            Duration::ZERO
        );
        assert_eq!(account.until(now - seconds(5)).allowed(now), Duration::ZERO);
    }

    #[test]
    fn the_jobs_limit_is_read_from_the_variable_and_one_that_cannot_be_read_allows_nothing() {
        let now = UNIX_EPOCH + Duration::from_secs(1_000_000);
        assert_eq!(Budget::from_deadline(None).allowed(now), RERUN_BUDGET);
        assert_eq!(
            Budget::from_deadline(Some("1010000")).allowed(now),
            RERUN_BUDGET
        );
        assert_eq!(
            Budget::from_deadline(Some("1000130")).allowed(now),
            Duration::from_secs(10)
        );
        assert_eq!(
            Budget::from_deadline(Some("soon")).allowed(now),
            Duration::ZERO
        );
    }

    fn write(path: &Path, bytes: &[u8]) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, bytes).unwrap();
    }

    /// What the removal for `file` takes, with everything counted as written since the step began.
    fn removal(target: &Path, file: &Path) -> Result<Vec<PathBuf>, String> {
        removal_of(target, volume_of(target), UNIX_EPOCH, &[file.to_path_buf()])
            .and_then(Removal::carry_out)
    }

    #[test]
    fn a_build_script_is_removed_with_its_directory_and_its_records() {
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("target");
        let profile = target.join("release");
        let script = profile.join("build/serde_json-1ad93a6e71728a74/build-script-build");
        write(&script, b"");
        write(
            &profile.join("build/serde_json-1ad93a6e71728a74/build_script_build-1ad93a6e71728a74"),
            b"",
        );
        write(
            &profile.join(".fingerprint/serde_json-1ad93a6e71728a74/invoked.timestamp"),
            b"",
        );
        write(
            &profile.join(".fingerprint/serde_json-0000000000000000/invoked.timestamp"),
            b"",
        );
        write(
            &profile.join("build/serde_json-0000000000000000/output"),
            b"kept",
        );
        let removed = removal(&target, &script).unwrap();
        assert_eq!(removed.len(), 2);
        assert!(!profile.join("build/serde_json-1ad93a6e71728a74").exists());
        assert!(
            !profile
                .join(".fingerprint/serde_json-1ad93a6e71728a74")
                .exists()
        );
        assert!(
            profile
                .join(".fingerprint/serde_json-0000000000000000")
                .exists()
        );
        assert!(
            profile
                .join("build/serde_json-0000000000000000/output")
                .exists()
        );
    }

    #[test]
    fn a_test_binary_is_removed_with_its_unit() {
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("target");
        let profile = target.join("debug");
        let binary = profile.join("deps/report-f1d5e145b44f9f2d");
        write(&binary, b"");
        write(&profile.join("deps/report-f1d5e145b44f9f2d.d"), b"d");
        write(&profile.join("deps/report-aaaaaaaaaaaaaaaa"), b"other");
        write(
            &profile
                .join(".fingerprint/kr-conformance-f1d5e145b44f9f2d/test-integration-test-report"),
            b"",
        );
        write(
            &profile
                .join(".fingerprint/kr-conformance-aaaaaaaaaaaaaaaa/test-integration-test-report"),
            b"",
        );
        let removed = removal(&target, &binary).unwrap();
        assert_eq!(removed.len(), 3);
        assert!(profile.join("deps/report-aaaaaaaaaaaaaaaa").exists());
        assert!(
            profile
                .join(".fingerprint/kr-conformance-aaaaaaaaaaaaaaaa")
                .exists()
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_program_linked_into_the_profile_directory_takes_its_deps_file_and_unit_with_it() {
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("target");
        let profile = target.join("debug");
        let real = profile.join("deps/kr_conformance-f1d5e145b44f9f2d");
        write(&real, b"");
        write(
            &profile.join(".fingerprint/kr-conformance-f1d5e145b44f9f2d/bin-kr-conformance"),
            b"",
        );
        let linked = profile.join("kr-conformance");
        std::fs::hard_link(&real, &linked).unwrap();
        let removed = removal(&target, &linked).unwrap();
        assert_eq!(removed.len(), 3);
        assert!(!linked.exists());
        assert!(!real.exists());
        assert!(
            !profile
                .join(".fingerprint/kr-conformance-f1d5e145b44f9f2d")
                .exists()
        );
    }

    #[cfg(unix)]
    #[test]
    fn the_sweep_finds_only_recent_programs_that_are_empty_or_cut_short() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("target");
        let profile = target.join("release");
        let began = SystemTime::now() - Duration::from_secs(5);
        let program = |path: &Path, bytes: &[u8]| {
            write(path, bytes);
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
        };
        std::fs::create_dir_all(profile.join(".fingerprint")).unwrap();
        // A program under the target directory outside the places a build puts programs is not
        // one a build wrote, whether or not it looks cut short.
        program(&target.join("fixtures/helper"), b"");
        program(&profile.join("examples/helper"), b"");
        program(
            &profile.join("build/a-1111111111111111/build-script-build"),
            b"",
        );
        program(
            &profile.join("deps/b-2222222222222222"),
            &header(4096)[..80],
        );
        program(&profile.join("deps/c-3333333333333333"), &header(80));
        write(&profile.join("deps/d-4444444444444444.rlib"), b"");
        write(&profile.join("deps/e-5555555555555555"), b"");
        let found = damaged_since(&target, began);
        assert_eq!(
            found,
            vec![
                profile.join("build/a-1111111111111111/build-script-build"),
                profile.join("deps/b-2222222222222222"),
            ]
        );
        assert!(damaged_since(&target, SystemTime::now() + Duration::from_secs(60)).is_empty());
    }

    #[test]
    fn only_a_program_of_cargos_making_is_taken_for_one_a_build_wrote() {
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("target");
        let profile = target.join("debug");
        std::fs::create_dir_all(profile.join(".fingerprint")).unwrap();
        assert_eq!(
            profile_of_output(&target, &profile.join("kr-conformance")),
            Some(profile.clone())
        );
        assert_eq!(
            profile_of_output(&target, &profile.join("deps/a-1111111111111111")),
            Some(profile.clone())
        );
        assert_eq!(
            profile_of_output(
                &target,
                &profile.join("build/a-1111111111111111/build-script-build")
            ),
            Some(profile.clone())
        );
        for elsewhere in [
            target.join("fixtures/helper"),
            profile.join("examples/helper"),
            profile.join("build/helper"),
            directory.path().join("src/lib"),
        ] {
            assert_eq!(
                profile_of_output(&target, &elsewhere),
                None,
                "{}",
                elsewhere.display()
            );
        }
        let triple = target.join("aarch64-apple-darwin/release");
        std::fs::create_dir_all(triple.join(".fingerprint")).unwrap();
        assert_eq!(
            profile_of_output(&target, &triple.join("deps/b-2222222222222222")),
            Some(triple)
        );
    }

    #[test]
    fn a_file_that_is_not_cargos_output_is_not_removed() {
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("target");
        let profile = target.join("debug");
        std::fs::create_dir_all(profile.join(".fingerprint")).unwrap();
        let helper = profile.join("examples/helper");
        write(&helper, b"");
        assert!(removal(&target, &helper).unwrap().is_empty());
        assert!(helper.exists());
    }

    #[cfg(unix)]
    #[test]
    fn a_link_below_a_unit_or_in_its_way_stops_the_removal_and_nothing_of_the_unit_is_taken() {
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("target");
        let profile = target.join("debug");
        std::fs::create_dir_all(profile.join(".fingerprint")).unwrap();
        let outside = directory.path().join("outside");
        write(&outside.join("victim-1111111111111111"), b"kept");
        write(&outside.join("unit-1111111111111111/records"), b"kept");
        write(&profile.join("deps/own-2222222222222222"), b"");
        // The profile's `deps` is a link to a directory outside the target directory.
        std::fs::remove_dir_all(profile.join("deps")).unwrap();
        std::os::unix::fs::symlink(&outside, profile.join("deps")).unwrap();
        let why = removal(&target, &profile.join("deps/victim-1111111111111111")).unwrap_err();
        assert!(why.contains("is not inside the target directory"), "{why}");
        assert!(outside.join("victim-1111111111111111").exists());
        // The directory of a unit under `build` is a link: the link stays too, and what it leads
        // to.
        std::fs::create_dir_all(profile.join("build")).unwrap();
        let linked = profile.join("build/linked-1111111111111111");
        std::os::unix::fs::symlink(&outside, &linked).unwrap();
        let why = removal(&target, &linked.join("script")).unwrap_err();
        assert!(why.contains("is a link"), "{why}");
        assert!(linked.symlink_metadata().is_ok(), "the link is not removed");
        assert!(outside.join("unit-1111111111111111/records").exists());
        // The unit's records are in a directory that a link leads out to: the program stays too.
        let release = target.join("release");
        std::fs::create_dir_all(&release).unwrap();
        write(&release.join("deps/own-3333333333333333"), b"");
        write(&outside.join("own-3333333333333333/records"), b"kept");
        std::os::unix::fs::symlink(&outside, release.join(".fingerprint")).unwrap();
        let why = removal(&target, &release.join("deps/own-3333333333333333")).unwrap_err();
        assert!(why.contains("is not inside the target directory"), "{why}");
        assert!(release.join("deps/own-3333333333333333").exists());
        assert!(outside.join("own-3333333333333333/records").exists());
    }

    /// A link inside a unit's own directory, which stays inside the target directory, is still a
    /// link: the removal follows none, and takes nothing of the unit where it meets one.
    #[cfg(unix)]
    #[test]
    fn a_link_inside_a_units_directory_stops_the_removal_of_the_unit() {
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("target");
        let profile = target.join("debug");
        let unit = profile.join("build/x-0123456789abcdef");
        let script = unit.join("build-script-build");
        write(&script, b"");
        write(
            &profile.join(".fingerprint/x-0123456789abcdef/invoked.timestamp"),
            b"",
        );
        std::os::unix::fs::symlink(&script, unit.join("alias")).unwrap();
        let why = removal(&target, &script).unwrap_err();
        assert!(why.contains("alias"), "{why}");
        assert!(why.contains("is a link"), "{why}");
        assert!(script.exists());
        assert!(
            profile
                .join(".fingerprint/x-0123456789abcdef/invoked.timestamp")
                .exists()
        );
    }

    /// A directory below a unit that is on another device than the build's output is a mount of
    /// something else: it is not entered, and nothing of the unit is taken. The device the build's
    /// output is on is given, so that a device that is not the files' own stands for the mount; the
    /// removal over a real mount is the macOS case in `tests/rerun.rs`.
    #[cfg(unix)]
    #[test]
    fn a_directory_on_another_device_below_a_unit_stops_the_removal_of_the_unit() {
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("target");
        let profile = target.join("debug");
        let unit = profile.join("build/x-0123456789abcdef");
        let script = unit.join("build-script-build");
        write(&script, b"");
        write(&unit.join("out/data"), b"kept");
        write(
            &profile.join(".fingerprint/x-0123456789abcdef/invoked.timestamp"),
            b"",
        );
        let device = volume_of(&target).unwrap();
        let removal_on = |device: u64| {
            removal_of(
                &target,
                Some(device),
                UNIX_EPOCH,
                std::slice::from_ref(&script),
            )
        };
        let why = removal_on(device + 1).unwrap_err();
        assert!(why.contains("is on another device"), "{why}");
        assert!(script.exists());
        assert!(unit.join("out/data").exists());
        // On the files' own device the same removal takes the unit.
        let removed = removal_on(device).unwrap().carry_out().unwrap();
        assert_eq!(removed.len(), 2);
        assert!(!unit.exists());
    }

    /// The plan is read again as it is carried out: an entry that a link took the place of, that is
    /// on another device, or that is older than the step is no longer what the plan found, and
    /// nothing of the removal is taken.
    #[cfg(unix)]
    #[test]
    fn a_removal_takes_nothing_where_an_entry_is_no_longer_what_the_plan_found() {
        let make = || {
            let directory = tempfile::tempdir().unwrap();
            let target = directory.path().join("target");
            let unit = target.join("debug/build/x-0123456789abcdef");
            let script = unit.join("build-script-build");
            write(&script, b"");
            write(&unit.join("out/data"), b"");
            write(
                &target.join("debug/.fingerprint/x-0123456789abcdef/invoked.timestamp"),
                b"",
            );
            (directory, target, unit, script)
        };
        let plan = |target: &Path, script: &Path| {
            removal_of(
                target,
                volume_of(target),
                UNIX_EPOCH,
                std::slice::from_ref(&script.to_path_buf()),
            )
            .unwrap()
        };
        // A link where a directory was.
        let (directory, target, unit, script) = make();
        let removal = plan(&target, &script);
        let outside = directory.path().join("outside");
        write(&outside.join("kept"), b"kept");
        std::fs::remove_file(unit.join("out/data")).unwrap();
        std::fs::remove_dir(unit.join("out")).unwrap();
        std::os::unix::fs::symlink(&outside, unit.join("out")).unwrap();
        let why = removal.carry_out().unwrap_err();
        assert!(why.contains("no longer what the plan found"), "{why}");
        assert!(script.exists() && outside.join("kept").exists());
        // Another device than the plan's.
        let (_directory, target, unit, script) = make();
        let mut removal = plan(&target, &script);
        removal.device = removal.device.map(|device| device + 1);
        assert!(removal.carry_out().is_err());
        assert!(script.exists() && unit.join("out/data").exists());
        // A file older than the step began.
        let (_directory, target, unit, script) = make();
        let mut removal = plan(&target, &script);
        removal.began = SystemTime::now() + Duration::from_secs(60);
        assert!(removal.carry_out().is_err());
        assert!(script.exists() && unit.join("out/data").exists());
    }

    /// A file of a unit that is older than the step is not one the step's build made, so the
    /// unit is left whole.
    #[test]
    fn a_file_of_a_unit_that_is_older_than_the_step_stops_the_removal_of_the_unit() {
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("target");
        let profile = target.join("debug");
        let unit = profile.join("build/x-0123456789abcdef");
        let script = unit.join("build-script-build");
        write(&script, b"");
        let records = profile.join(".fingerprint/x-0123456789abcdef/invoked.timestamp");
        write(&records, b"");
        let day = Duration::from_secs(24 * 60 * 60);
        std::fs::File::options()
            .write(true)
            .open(&records)
            .unwrap()
            .set_modified(SystemTime::now() - day)
            .unwrap();
        let began = SystemTime::now() - Duration::from_secs(60);
        let why = removal_of(
            &target,
            volume_of(&target),
            began,
            std::slice::from_ref(&script),
        )
        .unwrap_err();
        assert!(why.contains("invoked.timestamp"), "{why}");
        assert!(
            why.contains("was not written since the step began"),
            "{why}"
        );
        assert!(script.exists());
        assert!(records.exists());
    }

    #[test]
    fn a_step_in_which_a_test_failed_is_not_one_that_a_second_run_may_settle() {
        use crate::libtest::Binary;
        use crate::plan::Group;
        let done = |outcome: Option<Outcome>| Executed {
            step: Step::cargo(Group::Rust, "tests", &["test"]),
            exit: Some(101),
            seconds: 0,
            log: "conformance/logs/01-tests.log".to_owned(),
            binaries: outcome
                .map(|outcome| {
                    (
                        None,
                        Binary {
                            tests: [("a_test".to_owned(), outcome)].into(),
                            ..Binary::default()
                        },
                    )
                })
                .into_iter()
                .collect(),
            built: Vec::new(),
            listed: std::collections::BTreeMap::new(),
            vitest: None,
            lane: None,
            tools: Vec::new(),
            error: None,
            rerun: None,
        };
        assert!(!has_failed_test(&done(None)));
        assert!(!has_failed_test(&done(Some(Outcome::Passed))));
        assert!(has_failed_test(&done(Some(Outcome::Failed))));
    }
}
