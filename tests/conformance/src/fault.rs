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
use std::path::{Path, PathBuf};
#[cfg(target_os = "macos")]
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime};

use serde::Serialize;

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

/// How deep below the target directory a file is looked for: the target triple, the profile, the
/// build scripts' directory and the directory of one script.
const DEPTH: usize = 4;

/// Directories of the target directory that hold no program the linker wrote.
const SKIPPED: [&str; 3] = ["incremental", "out", "native"];

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

/// What the evidence says about the cause of a file that could not be started.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Cause {
    /// A file is empty, cut short or badly signed, or the kernel logged a storage error.
    RunnerDisk,
    /// The file is whole and validly signed and the kernel logged no storage error, or the
    /// evidence could not be read.
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
    /// The file that holds each file's facts and the kernel's lines, relative to the evidence
    /// directory.
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
    /// The result of the system's check of its signature, when the check ran.
    pub signature: Option<Result<(), String>>,
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
/// twice and then the shell's words, in a log that also holds exit status 126.
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
/// is empty, its header is zeros or something else, or a segment, the signature or its load
/// commands lie beyond the end of the file. A script, or a program of another system, is not read.
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
    let (Some(magic), Some(commands), Some(size)) =
        (u32_at(head, 0), u32_at(head, 16), u32_at(head, 20))
    else {
        return Some(format!(
            "the file is {length} bytes, too short for a Mach-O header"
        ));
    };
    if magic != MACH_O_64 {
        return Some(if head.iter().take(32).all(|byte| *byte == 0) {
            "the first 32 bytes are all zero".to_owned()
        } else {
            format!("the first four bytes, {magic:08x}, are not a Mach-O header")
        });
    }
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
            let signature = if shape.is_none() {
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
            }
        }
        Err(error) => FileFacts {
            path: path.to_path_buf(),
            size: None,
            age,
            head: String::new(),
            shape: Some(format!("the file could not be read: {error}")),
            signature: None,
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

/// Writes the kernel's storage lines of the last `minutes` to `out`.
#[cfg(target_os = "macos")]
fn storage_log(minutes: u64, out: &Path) -> Result<(), String> {
    let window = format!("{minutes}m");
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
            "--last",
            &window,
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
                    let _ = child.kill();
                    let _ = child.wait();
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
fn storage_log(_minutes: u64, _out: &Path) -> Result<(), String> {
    Err("the kernel's log is read on macOS only".to_owned())
}

/// What the evidence says: the runner's disk where a file is damaged or the kernel logged a
/// storage error, and unexplained otherwise.
#[must_use]
pub fn cause_of(files: &[FileFacts], storage_errors: Option<usize>) -> Cause {
    if files.iter().any(FileFacts::damaged) || storage_errors.is_some_and(|count| count > 0) {
        Cause::RunnerDisk
    } else {
        Cause::Unexplained
    }
}

/// The evidence in a sentence.
fn reason_for(
    cause: Cause,
    files: &[FileFacts],
    storage: &Result<usize, String>,
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
        if let Some(shape) = &file.shape {
            parts.push(format!("{}: {shape}", named(file)));
        } else if let Some(Err(why)) = &file.signature {
            parts.push(format!(
                "{}: its signature does not check ({why})",
                named(file)
            ));
        }
    }
    match storage {
        Ok(count) if *count > 0 => parts.push(format!(
            "the kernel logged {count} storage error lines in the minutes before"
        )),
        Ok(_) => parts.push("the kernel logged no storage error".to_owned()),
        Err(why) => parts.push(format!("the kernel's log was not read: {why}")),
    }
    match cause {
        Cause::RunnerDisk => format!("the runner's disk: {}", parts.join("; ")),
        Cause::Unexplained => format!(
            "not shown to be the runner's disk: the file is whole and its signature is {}; {}",
            if files
                .iter()
                .all(|file| matches!(file.signature, Some(Ok(()))))
            {
                "valid"
            } else {
                "not checked"
            },
            parts.join("; ")
        ),
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

fn walk(dir: &Path, depth: usize, began: SystemTime, found: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(kind) = entry.file_type() else {
            continue;
        };
        if kind.is_dir() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if depth < DEPTH && !name.starts_with('.') && !SKIPPED.contains(&name.as_ref()) {
                walk(&path, depth + 1, began, found);
            }
        } else if kind.is_file() && path.extension().is_none() {
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
}

/// The programs under `target` written since `began` whose Mach-O header shows them empty or cut
/// short: the files of the same burst that no log named yet.
#[must_use]
pub fn damaged_since(target: &Path, began: SystemTime) -> Vec<PathBuf> {
    let mut found = Vec::new();
    walk(target, 0, began, &mut found);
    found.sort();
    found
}

/// The sixteen hexadecimal digits Cargo ends a unit's file names with, in `name`.
fn hash_of(name: &str) -> Option<&str> {
    let stem = name.split('.').next()?;
    let (_, hash) = stem.rsplit_once('-')?;
    (hash.len() == 16 && hash.bytes().all(|byte| byte.is_ascii_hexdigit())).then_some(hash)
}

fn remove_tree(path: &Path, removed: &mut Vec<PathBuf>) {
    if std::fs::remove_dir_all(path).is_ok() {
        removed.push(path.to_path_buf());
    }
}

fn remove_one(path: &Path, removed: &mut Vec<PathBuf>) {
    if std::fs::remove_file(path).is_ok() {
        removed.push(path.to_path_buf());
    }
}

/// Removes every file of the unit with `hash` in the profile directory's `deps`, and the unit's
/// records of having been built.
fn remove_unit(profile: &Path, hash: &str, removed: &mut Vec<PathBuf>) {
    let suffix = format!("-{hash}");
    if let Ok(entries) = std::fs::read_dir(profile.join("deps")) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            if name.to_string_lossy().contains(&suffix) {
                remove_one(&entry.path(), removed);
            }
        }
    }
    if let Ok(entries) = std::fs::read_dir(profile.join(".fingerprint")) {
        for entry in entries.flatten() {
            if entry.file_name().to_string_lossy().ends_with(&suffix) {
                remove_tree(&entry.path(), removed);
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

/// Removes a damaged program and what makes Cargo take it for built, so that the next build makes
/// it again: for a build script, its directory and the unit's records; for a program or test
/// binary with a hash in its name, every file of that unit and its records; for a program linked
/// into the profile directory, the file in `deps` it is a link to, and that unit.
pub fn remove_damage(target: &Path, file: &Path) -> Vec<PathBuf> {
    let mut removed = Vec::new();
    let profile = file
        .ancestors()
        .skip(1)
        .take_while(|ancestor| ancestor.starts_with(target))
        .find(|ancestor| ancestor.join(".fingerprint").is_dir());
    let Some(profile) = profile else {
        remove_one(file, &mut removed);
        return removed;
    };
    let unit_directory = file.parent().filter(|parent| {
        parent
            .parent()
            .is_some_and(|above| above == profile.join("build"))
    });
    if let Some(unit) = unit_directory {
        if let Some(name) = unit.file_name() {
            remove_tree(&profile.join(".fingerprint").join(name), &mut removed);
        }
        remove_tree(unit, &mut removed);
        return removed;
    }
    let name = file
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    if let Some(hash) = hash_of(&name) {
        remove_unit(profile, hash, &mut removed);
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
            remove_unit(profile, hash, &mut removed);
        }
    }
    remove_one(file, &mut removed);
    removed
}

/// What a rerun's facts file says.
struct Account<'a> {
    step: &'a Step,
    number: usize,
    root: &'a Path,
    files: &'a [FileFacts],
    swept: &'a [PathBuf],
    storage: &'a Result<usize, String>,
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
            file.shape.as_deref().unwrap_or("whole"),
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

/// Runs `step`, and once more when its first run ended in a file the linker wrote that the system
/// would not start.
///
/// The second run is the step's result, with the first run's log kept beside its own and the
/// facts in [`Rerun`]. Where the evidence does not show the runner's disk, the step has an error
/// and the report fails.
#[must_use]
pub fn execute(
    step: &Step,
    number: usize,
    place: &Place<'_>,
    packages: &[Package],
    progress: &mut dyn FnMut(&str),
) -> Executed {
    let began = SystemTime::now();
    let first = run::execute(step, number, place, packages);
    if first.error.is_none() && first.exit == Some(0) {
        return first;
    }
    let target = target_directory(place.root, place.environment);
    let Ok(bytes) = std::fs::read(place.evidence.join(&first.log)) else {
        return first;
    };
    let named: Vec<PathBuf> = named_files(&String::from_utf8_lossy(&bytes), &target)
        .into_iter()
        .filter(|path| written_since(path, began))
        .collect();
    if named.is_empty() {
        return first;
    }
    let now = SystemTime::now();
    let files: Vec<FileFacts> = named.iter().map(|path| facts_of(path, now)).collect();
    let swept: Vec<PathBuf> = damaged_since(&target, began)
        .into_iter()
        .filter(|path| !named.contains(path))
        .collect();
    let stem = Path::new(&first.log)
        .file_stem()
        .map(|stem| stem.to_string_lossy().into_owned())
        .unwrap_or_default();
    let faults = place.evidence.join("conformance").join("faults");
    let _ = std::fs::create_dir_all(&faults);
    let kernel = faults.join(format!("{stem}.kernel.txt"));
    let earliest = files
        .iter()
        .filter_map(|file| file.age)
        .chain(std::iter::once(
            now.duration_since(began).unwrap_or_default(),
        ))
        .max()
        .unwrap_or_default();
    let minutes = (earliest.as_secs() / 60 + 3).min(LOG_MINUTES);
    let storage = storage_log(minutes, &kernel).and_then(|()| {
        std::fs::read_to_string(&kernel)
            .map(|text| count_storage_errors(&text))
            .map_err(|error| error.to_string())
    });
    let cause = cause_of(&files, storage.as_ref().ok().copied());
    let reason = reason_for(cause, &files, &storage, place.root);
    let mut removed = Vec::new();
    for path in named.iter().chain(swept.iter()) {
        removed.extend(remove_damage(&target, path));
    }
    let facts = format!("conformance/faults/{stem}.txt");
    let _ = std::fs::write(
        place.evidence.join(&facts),
        facts_text(&Account {
            step,
            number,
            root: place.root,
            files: &files,
            swept: &swept,
            storage: &storage,
            cause,
            reason: &reason,
            removed: &removed,
        }),
    );
    let logs = place.evidence.join("conformance").join("logs");
    let first_log = format!("conformance/logs/{stem}.first-run.log");
    let moved = std::fs::rename(
        place.evidence.join(&first.log),
        place.evidence.join(&first_log),
    );
    let _ = std::fs::rename(
        logs.join(format!("{stem}.records")),
        logs.join(format!("{stem}.first-run.records")),
    );
    let first_log = if moved.is_ok() {
        first_log
    } else {
        first.log.clone()
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
    let mut second = run::execute(step, number, place, packages);
    if cause == Cause::Unexplained {
        let said = format!(
            "a file the step linked could not be started, and it was {reason}: the cause may be this repository's"
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
        assert!(
            macho_problem(b"not a program", 13)
                .unwrap()
                .contains("too short")
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
        }
    }

    #[test]
    fn the_cause_is_the_runners_disk_only_where_the_evidence_says_so() {
        let whole = facts(None, Some(Ok(())));
        assert_eq!(
            cause_of(std::slice::from_ref(&whole), Some(0)),
            Cause::Unexplained
        );
        assert_eq!(
            cause_of(std::slice::from_ref(&whole), None),
            Cause::Unexplained
        );
        assert_eq!(
            cause_of(std::slice::from_ref(&whole), Some(3)),
            Cause::RunnerDisk
        );
        assert_eq!(
            cause_of(&[facts(Some("the file is empty"), None)], Some(0)),
            Cause::RunnerDisk
        );
        assert_eq!(
            cause_of(&[facts(None, Some(Err("invalid".to_owned())))], None),
            Cause::RunnerDisk
        );
        assert_eq!(
            cause_of(&[whole, facts(Some("cut"), None)], None),
            Cause::RunnerDisk
        );
    }

    fn write(path: &Path, bytes: &[u8]) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, bytes).unwrap();
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
        let removed = remove_damage(&target, &script);
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
        let removed = remove_damage(&target, &binary);
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
        let removed = remove_damage(&target, &linked);
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
}
