//! The launch commands this host saves, in a store of their own.
//!
//! A saved launch command is a label, a program and separate arguments. The list is kept in
//! `launch-commands.json` beside the registry and not in the registry or the configuration
//! document: an earlier release reads those and has no place for it, so a list kept there could
//! not be read when the host goes back to that release. That release does not name this file, so
//! it leaves it alone, and its launch buttons offer the installed agents only. A host that has
//! saved no command has no file.
//!
//! The file holds a format number, a revision and the commands in the order they were first saved.
//! The revision is a random non-zero number made for each change, compared for equality only; 0 is
//! the revision of a host with no file. An emptied list stays a file with a fresh revision, so a
//! revision never stands for two different lists even after a person moves a damaged file away.
//!
//! A write names the revision it read. A request against a revision the list has left writes
//! nothing and is answered with the list as it stands. The check of a command is one function in
//! this module ([`check`]): it runs when a command is saved and again when the file is read, so a
//! file that breaks a rule is refused whole. The host is the only authority on it: the command line
//! tool prints the host's refusal and the page's own check is feedback only.
//!
//! A write that fails is decided by reading the file back: with the earlier file standing, nothing
//! was written; with the new bytes in place, or with a file that cannot be read, what became of
//! the write is not known and the caller is told so, even when a later read finds the new bytes.

use std::ops::RangeInclusive;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

use serde::{Deserialize, Serialize};
use unicode_general_category::{GeneralCategory, get_general_category};

use kr_protocol::launch_commands::NamedLaunch;

use crate::error::{ControllerError, Result};

/// The name this store has in a release's list of the stores it reads, which the updater looks for
/// before it switches to a release.
pub const STORE_NAME: &str = "launch-commands";

/// The format of the file this build writes, recorded in it as `version`. A file that records
/// another is refused: an earlier one was never written, and a later one holds what this build
/// would write back without.
pub const RECORD_VERSION: u32 = 1;

/// The file's name in the environment's state directory.
pub const FILE_NAME: &str = "launch-commands.json";

/// The largest file this host will read or write, in bytes.
pub const MAX_RECORD_LEN: u64 = 256 * 1024;

/// The most commands a host holds.
pub const MAX_COMMANDS: usize = 32;

/// The most characters a label has once trimmed.
pub const MAX_LABEL_CHARACTERS: usize = 48;

/// The most bytes a program has, and each argument.
pub const MAX_FIELD_BYTES: usize = 512;

/// The most arguments a command has.
pub const MAX_ARGUMENTS: usize = 16;

/// The most bytes a command uses across its label, program and arguments.
pub const MAX_COMMAND_BYTES: usize = 3072;

const LABEL_RULE: &str =
    "A label has 1 to 48 characters, with no control, format, invisible or line-break characters.";
const PROGRAM_RULE: &str =
    "A program has 1 to 512 bytes, with no control, format, invisible or line-break characters.";
const ARGUMENT_RULE: &str = "A command has at most 16 arguments of at most 512 bytes each, with no control, format, invisible or line-break characters. An argument may be empty.";
const TOTAL_RULE: &str = "A command may use at most 3,072 bytes in all, label included.";
const FULL_RULE: &str = "This host holds 32 launch commands. Replace one or remove one first.";

/// The code points that have the Unicode property Default_Ignorable_Code_Point, as the ranges of
/// `DerivedCoreProperties.txt` of Unicode 16.0.0 give them, which is the version of
/// `unicode-general-category` 1.1.0. Some of them are not format characters: a variation selector,
/// a combining grapheme joiner, a Hangul filler and the reserved code points of the property are
/// letters, marks or unassigned. A person cannot see any of them, whether or not a font draws one.
/// The fixture the check is held against (`tests/fixtures/launch-command-rows.json`) names the
/// ends of each range.
const DEFAULT_IGNORABLE: [RangeInclusive<char>; 17] = [
    '\u{ad}'..='\u{ad}',
    '\u{34f}'..='\u{34f}',
    '\u{61c}'..='\u{61c}',
    '\u{115f}'..='\u{1160}',
    '\u{17b4}'..='\u{17b5}',
    '\u{180b}'..='\u{180f}',
    '\u{200b}'..='\u{200f}',
    '\u{202a}'..='\u{202e}',
    '\u{2060}'..='\u{206f}',
    '\u{3164}'..='\u{3164}',
    '\u{fe00}'..='\u{fe0f}',
    '\u{feff}'..='\u{feff}',
    '\u{ffa0}'..='\u{ffa0}',
    '\u{fff0}'..='\u{fff8}',
    '\u{1bca0}'..='\u{1bca3}',
    '\u{1d173}'..='\u{1d17a}',
    '\u{e0000}'..='\u{e0fff}',
];

/// One command as the file holds it. It has no wire type: a later change of the wire never moves
/// the store's digest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredLaunchCommand {
    /// What the button shows.
    pub label: String,
    /// The program.
    pub program: String,
    /// The arguments, as written.
    pub arguments: Vec<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    version: u32,
    revision: u64,
    commands: Vec<StoredLaunchCommand>,
}

/// The list as the file holds it: no file is revision 0 and no commands.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Stored {
    /// The revision of the list.
    pub revision: u64,
    /// The commands, in the order they were first saved.
    pub commands: Vec<StoredLaunchCommand>,
}

/// What a write decided.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outcome {
    /// Whether the request was decided against the current revision. False: nothing was written.
    pub applied: bool,
    /// Whether the list changed.
    pub changed: bool,
    /// Whether a save took the place of a command with the same label.
    pub replaced: bool,
    /// The list after the request.
    pub stored: Stored,
}

impl From<&StoredLaunchCommand> for NamedLaunch {
    fn from(command: &StoredLaunchCommand) -> Self {
        Self {
            label: command.label.clone(),
            program: command.program.clone(),
            arguments: command.arguments.clone(),
        }
    }
}

impl From<&NamedLaunch> for StoredLaunchCommand {
    fn from(command: &NamedLaunch) -> Self {
        Self {
            label: command.label.clone(),
            program: command.program.clone(),
            arguments: command.arguments.clone(),
        }
    }
}

static LOCK: Mutex<()> = Mutex::new(());

/// Takes the store's lock, which every write holds from the read of the list to the publication of
/// the new one. Reads do not take it: a publication is one rename, so a read finds the list as it
/// was or as it is.
pub fn lock() -> MutexGuard<'static, ()> {
    LOCK.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn file_in(state_dir: &Path) -> PathBuf {
    state_dir.join(FILE_NAME)
}

/// Whether the rules refuse the character: a control, format, line or paragraph separator, or a
/// default ignorable code point.
fn is_refused(character: char) -> bool {
    matches!(
        get_general_category(character),
        GeneralCategory::Control
            | GeneralCategory::Format
            | GeneralCategory::LineSeparator
            | GeneralCategory::ParagraphSeparator
    ) || DEFAULT_IGNORABLE
        .iter()
        .any(|range| range.contains(&character))
}

/// The first refused character of `text` and its position, counted in characters from 1.
fn first_refused(text: &str) -> Option<(usize, char)> {
    text.chars()
        .enumerate()
        .find(|(_, character)| is_refused(*character))
        .map(|(index, character)| (index + 1, character))
}

fn refusal(rule: &str, whose: &str, found: Option<(usize, char)>) -> ControllerError {
    ControllerError::InvalidArgument(match found {
        Some((position, character)) => format!(
            "{rule} Character {position} of {whose} is U+{:04X}, which is not allowed.",
            u32::from(character)
        ),
        None => rule.to_owned(),
    })
}

/// Checks a command against the rules and returns it with its label trimmed.
///
/// The forbidden characters are looked for before the label is trimmed, since a line or paragraph
/// separator is white space and trimming would strip it. Sizes are counted after that: the label in
/// characters, the program and each argument in UTF-8 bytes, and the command in bytes across all
/// three.
///
/// # Errors
///
/// Returns [`ControllerError::InvalidArgument`] with the sentence of the rule the command breaks.
/// When the cause is a character, the sentence names the first one by its code point and its
/// position.
pub fn check(command: &NamedLaunch) -> Result<NamedLaunch> {
    if let Some(found) = first_refused(&command.label) {
        return Err(refusal(LABEL_RULE, "the label", Some(found)));
    }
    let label = command.label.trim();
    if label.is_empty() || label.chars().count() > MAX_LABEL_CHARACTERS {
        return Err(refusal(LABEL_RULE, "the label", None));
    }
    if let Some(found) = first_refused(&command.program) {
        return Err(refusal(PROGRAM_RULE, "the program", Some(found)));
    }
    if command.program.is_empty() || command.program.len() > MAX_FIELD_BYTES {
        return Err(refusal(PROGRAM_RULE, "the program", None));
    }
    if command.arguments.len() > MAX_ARGUMENTS {
        return Err(refusal(ARGUMENT_RULE, "the arguments", None));
    }
    for (index, argument) in command.arguments.iter().enumerate() {
        let whose = format!("argument {}", index + 1);
        if let Some(found) = first_refused(argument) {
            return Err(refusal(ARGUMENT_RULE, &whose, Some(found)));
        }
        if argument.len() > MAX_FIELD_BYTES {
            return Err(refusal(ARGUMENT_RULE, &whose, None));
        }
    }
    let total = label.len()
        + command.program.len()
        + command.arguments.iter().map(String::len).sum::<usize>();
    if total > MAX_COMMAND_BYTES {
        return Err(ControllerError::InvalidArgument(TOTAL_RULE.to_owned()));
    }
    Ok(NamedLaunch {
        label: label.to_owned(),
        program: command.program.clone(),
        arguments: command.arguments.clone(),
    })
}

fn damaged(state_dir: &Path, why: impl std::fmt::Display) -> ControllerError {
    ControllerError::Storage {
        operation: "read the saved launch commands",
        detail: format!("{}: {why}", file_in(state_dir).display()),
    }
}

fn parse(state_dir: &Path, bytes: Option<&[u8]>) -> Result<Stored> {
    let Some(bytes) = bytes else {
        return Ok(Stored::default());
    };
    let record: Record =
        serde_json::from_slice(bytes).map_err(|error| damaged(state_dir, error))?;
    if record.version != RECORD_VERSION {
        return Err(damaged(
            state_dir,
            format!(
                "it is of format {}, and this build reads format {RECORD_VERSION}",
                record.version
            ),
        ));
    }
    if record.revision == 0 {
        return Err(damaged(
            state_dir,
            "it records revision 0, which stands for no file",
        ));
    }
    if record.commands.len() > MAX_COMMANDS {
        return Err(damaged(
            state_dir,
            format!("it holds more than {MAX_COMMANDS} commands"),
        ));
    }
    let mut labels = std::collections::BTreeSet::new();
    for stored in &record.commands {
        let named = NamedLaunch::from(stored);
        let checked = check(&named).map_err(|error| damaged(state_dir, error))?;
        if checked != named {
            return Err(damaged(
                state_dir,
                format!("the label {:?} is not trimmed", stored.label),
            ));
        }
        if !labels.insert(stored.label.to_lowercase()) {
            return Err(damaged(
                state_dir,
                format!("the label {:?} is held twice", stored.label),
            ));
        }
    }
    Ok(Stored {
        revision: record.revision,
        commands: record.commands,
    })
}

fn raw(state_dir: &Path) -> Result<Option<Vec<u8>>> {
    kr_ipc::paths::read_owner_only_file(&file_in(state_dir), MAX_RECORD_LEN)
        .map_err(|error| damaged(state_dir, error))
}

/// Reads the list.
///
/// # Errors
///
/// Returns a storage error when the file exists and cannot be read, or breaks a rule: the host
/// still starts, `list` answers the error, and a write refuses and never replaces the file.
pub fn read(state_dir: &Path) -> Result<Stored> {
    parse(state_dir, raw(state_dir)?.as_deref())
}

fn fresh_revision(current: u64) -> Result<u64> {
    loop {
        let mut bytes = [0u8; 8];
        kr_crypto::random_bytes(&mut bytes).map_err(|error| ControllerError::Storage {
            operation: "make a revision for the saved launch commands",
            detail: error.to_string(),
        })?;
        let revision = u64::from_le_bytes(bytes);
        if revision != 0 && revision != current {
            return Ok(revision);
        }
    }
}

/// Where a test makes the next write fail.
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Failure {
    /// The write fails and the earlier file stands.
    BeforeTheRename,
    /// The write fails after the new file was renamed into place.
    AfterTheRename,
}

#[cfg(test)]
thread_local! {
    static FAILURE: std::cell::Cell<Option<Failure>> = const { std::cell::Cell::new(None) };
}

fn write(state_dir: &Path, bytes: &[u8]) -> std::result::Result<(), String> {
    let path = file_in(state_dir);
    #[cfg(test)]
    match FAILURE.with(std::cell::Cell::take) {
        Some(Failure::BeforeTheRename) => return Err("a write failed before the rename".to_owned()),
        Some(Failure::AfterTheRename) => {
            kr_ipc::paths::write_owner_only_file(&path, bytes)
                .map_err(|error| error.to_string())?;
            return Err("a write failed after the rename".to_owned());
        }
        None => {}
    }
    kr_ipc::paths::write_owner_only_file(&path, bytes).map_err(|error| error.to_string())
}

/// Writes `commands` as the next revision, and decides what a failure means by reading the file
/// back: the earlier file standing is a write that did not happen; anything else is not known.
fn publish(
    state_dir: &Path,
    earlier: Option<&[u8]>,
    current: u64,
    commands: Vec<StoredLaunchCommand>,
) -> Result<Stored> {
    let record = Record {
        version: RECORD_VERSION,
        revision: fresh_revision(current)?,
        commands,
    };
    let bytes = serde_json::to_vec_pretty(&record).map_err(|error| ControllerError::Storage {
        operation: "write down the saved launch commands",
        detail: error.to_string(),
    })?;
    if bytes.len() as u64 > MAX_RECORD_LEN {
        return Err(ControllerError::Storage {
            operation: "write down the saved launch commands",
            detail: format!(
                "they take {} bytes, and a start reads at most {MAX_RECORD_LEN}",
                bytes.len()
            ),
        });
    }
    if let Err(error) = write(state_dir, &bytes) {
        return Err(match raw(state_dir) {
            Ok(found) if found.as_deref() == earlier => ControllerError::Storage {
                operation: "write down the saved launch commands",
                detail: error,
            },
            _ => ControllerError::Uncertain {
                detail: format!(
                    "the saved launch commands may or may not have been written: {error}"
                ),
            },
        });
    }
    Ok(Stored {
        revision: record.revision,
        commands: record.commands,
    })
}

/// Saves `command` against the revision the caller read: a new label goes last, a label already
/// held is replaced in its place with the new spelling, and a save that asks for what the list
/// already holds changes nothing and says so. The caller holds [`lock`].
///
/// # Errors
///
/// Returns the refusal of [`check`], a refusal when a new label would be the 33rd, a storage error
/// when the file cannot be read (it is never replaced), and a storage error or an uncertain
/// outcome when the write fails.
pub fn save(state_dir: &Path, expected_revision: u64, command: &NamedLaunch) -> Result<Outcome> {
    let command = StoredLaunchCommand::from(&check(command)?);
    let earlier = raw(state_dir)?;
    let current = parse(state_dir, earlier.as_deref())?;
    if current.revision != expected_revision {
        return Ok(Outcome {
            applied: false,
            changed: false,
            replaced: false,
            stored: current,
        });
    }
    let held = current
        .commands
        .iter()
        .position(|held| held.label.to_lowercase() == command.label.to_lowercase());
    let mut commands = current.commands.clone();
    let replaced = match held {
        Some(index) if commands[index] == command => {
            return Ok(Outcome {
                applied: true,
                changed: false,
                replaced: false,
                stored: current,
            });
        }
        Some(index) => {
            commands[index] = command;
            true
        }
        None => {
            if commands.len() >= MAX_COMMANDS {
                return Err(ControllerError::InvalidArgument(FULL_RULE.to_owned()));
            }
            commands.push(command);
            false
        }
    };
    let stored = publish(state_dir, earlier.as_deref(), current.revision, commands)?;
    Ok(Outcome {
        applied: true,
        changed: true,
        replaced,
        stored,
    })
}

/// Removes the command with `label` (compared in lower case) against the revision the caller read.
/// A label no command has changes nothing. The caller holds [`lock`].
///
/// # Errors
///
/// Returns a storage error when the file cannot be read (it is never replaced), and a storage
/// error or an uncertain outcome when the write fails.
pub fn remove(state_dir: &Path, expected_revision: u64, label: &str) -> Result<Outcome> {
    let earlier = raw(state_dir)?;
    let current = parse(state_dir, earlier.as_deref())?;
    if current.revision != expected_revision {
        return Ok(Outcome {
            applied: false,
            changed: false,
            replaced: false,
            stored: current,
        });
    }
    let wanted = label.trim().to_lowercase();
    let Some(index) = current
        .commands
        .iter()
        .position(|held| held.label.to_lowercase() == wanted)
    else {
        return Ok(Outcome {
            applied: true,
            changed: false,
            replaced: false,
            stored: current,
        });
    };
    let mut commands = current.commands.clone();
    commands.remove(index);
    let stored = publish(state_dir, earlier.as_deref(), current.revision, commands)?;
    Ok(Outcome {
        applied: true,
        changed: true,
        replaced: false,
        stored,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn command(label: &str, program: &str, arguments: &[&str]) -> NamedLaunch {
        NamedLaunch {
            label: label.to_owned(),
            program: program.to_owned(),
            arguments: arguments.iter().map(|word| (*word).to_owned()).collect(),
        }
    }

    fn directory() -> kr_ipc::testing::PrivateTempDir {
        kr_ipc::testing::PrivateTempDir::create()
    }

    fn labels(stored: &Stored) -> Vec<&str> {
        stored
            .commands
            .iter()
            .map(|held| held.label.as_str())
            .collect()
    }

    /// The rows the check is held to, which the page's own feedback reads too.
    fn fixture_rows() -> Vec<serde_json::Value> {
        let text = include_str!("../../../tests/fixtures/launch-command-rows.json");
        let document: serde_json::Value = serde_json::from_str(text).expect("the fixture parses");
        document["rows"].as_array().expect("rows").clone()
    }

    /// KR-REQ-13.11: a host that has saved no command has no file, and its list is empty at
    /// revision 0.
    #[test]
    fn a_store_with_no_file_holds_no_commands_at_revision_0() {
        let dir = directory();
        let stored = read(dir.path()).expect("reads");
        assert_eq!(stored, Stored::default());
        assert_eq!(stored.revision, 0);
        assert!(!file_in(dir.path()).exists());
    }

    /// KR-REQ-13.11: what is saved is read back in order with every argument exact.
    #[test]
    fn what_is_saved_is_read_back_in_order_with_its_arguments_exact() {
        let dir = directory();
        let first = command(
            "Claude Code",
            "claude",
            &[
                "--resume",
                "two words",
                "a\"b",
                "$HOME",
                "back\\slash",
                "",
                "C:\\tools\\agent.exe",
            ],
        );
        let second = command("Caf\u{e9} \u{2615}", "C:\\tools\\agent.exe", &[""]);
        let saved = save(dir.path(), 0, &first).expect("saves");
        assert!(saved.applied && saved.changed && !saved.replaced);
        let saved = save(dir.path(), saved.stored.revision, &second).expect("saves");
        let read = read(dir.path()).expect("reads");
        assert_eq!(read, saved.stored);
        assert_eq!(labels(&read), ["Claude Code", "Caf\u{e9} \u{2615}"]);
        assert_eq!(NamedLaunch::from(&read.commands[0]), first);
        assert_eq!(NamedLaunch::from(&read.commands[1]), second);
    }

    /// KR-REQ-13.11: a revision is random and non-zero, and no change repeats the revision it
    /// was made from, whether or not the file was moved away between them.
    #[test]
    fn a_revision_is_random_and_never_repeats_after_a_file_is_moved_away() {
        let dir = directory();
        let mut seen = std::collections::BTreeSet::new();
        let mut revision = 0;
        for index in 0..8 {
            let saved = save(
                dir.path(),
                revision,
                &command(&format!("c{index}"), "p", &[]),
            )
            .expect("saves");
            assert_ne!(saved.stored.revision, 0);
            assert_ne!(saved.stored.revision, revision);
            assert!(seen.insert(saved.stored.revision), "a revision came twice");
            revision = saved.stored.revision;
        }
        // A person moves the file away: the next list starts from nothing, at a revision that was
        // not used before.
        std::fs::rename(file_in(dir.path()), dir.path().join("moved.json")).expect("moved");
        assert_eq!(read(dir.path()).expect("reads").revision, 0);
        let saved = save(dir.path(), 0, &command("again", "p", &[])).expect("saves");
        assert!(seen.insert(saved.stored.revision), "a revision came twice");
    }

    /// KR-REQ-13.11: an emptied list stays a file, with a fresh revision.
    #[test]
    fn an_emptied_list_keeps_the_file_with_a_fresh_revision() {
        let dir = directory();
        let saved = save(dir.path(), 0, &command("one", "p", &[])).expect("saves");
        let removed = remove(dir.path(), saved.stored.revision, "ONE").expect("removes");
        assert!(removed.applied && removed.changed);
        assert!(removed.stored.commands.is_empty());
        assert_ne!(removed.stored.revision, 0);
        assert_ne!(removed.stored.revision, saved.stored.revision);
        assert!(file_in(dir.path()).exists(), "the empty list stays a file");
        assert_eq!(read(dir.path()).expect("reads"), removed.stored);
    }

    /// KR-REQ-13.11: every row of the fixture is accepted or refused as the row says, and a refused
    /// row names the field, the first refused character's position and its code point in the
    /// host's words.
    #[test]
    fn a_record_or_command_that_breaks_a_rule_is_refused() {
        for row in fixture_rows() {
            let name = row["name"].as_str().expect("a name");
            let arguments: Vec<String> = row["arguments"]
                .as_array()
                .expect("arguments")
                .iter()
                .map(|word| word.as_str().expect("a word").to_owned())
                .collect();
            let candidate = NamedLaunch {
                label: row["label"].as_str().expect("a label").to_owned(),
                program: row["program"].as_str().expect("a program").to_owned(),
                arguments,
            };
            let outcome = check(&candidate);
            let Some(refused) = row.get("refused") else {
                let checked = outcome.unwrap_or_else(|error| panic!("{name}: {error}"));
                assert_eq!(checked.label, candidate.label.trim(), "{name}");
                continue;
            };
            let words = match outcome {
                Err(ControllerError::InvalidArgument(words)) => words,
                other => panic!("{name}: expected a refusal, got {other:?}"),
            };
            if let Some(code_point) = refused.get("code_point") {
                let whose = match refused["field"].as_str().expect("a field") {
                    "label" => "the label".to_owned(),
                    "program" => "the program".to_owned(),
                    _ => format!("argument {}", refused["argument"]),
                };
                let sentence = format!(
                    "Character {} of {whose} is {}, which is not allowed.",
                    refused["position"],
                    code_point.as_str().expect("a code point"),
                );
                assert!(words.ends_with(&sentence), "{name}: {words}");
            } else {
                assert!(!words.contains("Character "), "{name}: {words}");
            }
        }
    }

    /// KR-REQ-13.11: the three rules of a record that no command breaks: more than 32 commands, a
    /// repeated label by case, an unknown member, a format number that is not 1, revision 0, an
    /// untrimmed label and a torn file are each refused whole when the file is read.
    #[test]
    fn a_file_that_breaks_a_rule_is_refused_when_it_is_read() {
        let dir = directory();
        let good = serde_json::json!({"label": "a", "program": "p", "arguments": []});
        let files = [
            serde_json::json!({"version": 1, "revision": 5, "commands": vec![good.clone(); 33]}),
            serde_json::json!({"version": 1, "revision": 5, "commands": [
                {"label": "Same", "program": "p", "arguments": []},
                {"label": "same", "program": "p", "arguments": []}]}),
            serde_json::json!({"version": 1, "revision": 5, "commands": [], "extra": 1}),
            serde_json::json!({"version": 0, "revision": 5, "commands": []}),
            serde_json::json!({"version": 2, "revision": 5, "commands": []}),
            serde_json::json!({"version": 1, "revision": 0, "commands": []}),
            serde_json::json!({"version": 1, "revision": 5, "commands": [
                {"label": " padded ", "program": "p", "arguments": []}]}),
            serde_json::json!({"version": 1, "revision": 5, "commands": [
                {"label": "bad\u{200b}", "program": "p", "arguments": []}]}),
        ];
        for file in files {
            std::fs::write(file_in(dir.path()), file.to_string()).expect("written");
            assert!(read(dir.path()).is_err(), "{file} is refused");
        }
        std::fs::write(file_in(dir.path()), b"{\"version\": 1, \"revi").expect("written");
        assert!(read(dir.path()).is_err(), "a torn file is refused");
        std::fs::write(file_in(dir.path()), vec![b' '; MAX_RECORD_LEN as usize + 1])
            .expect("written");
        assert!(read(dir.path()).is_err(), "a file over 256 KiB is refused");
    }

    /// KR-REQ-13.11: 32 commands at the largest size, with every character one that a JSON string
    /// must escape, fit the file and a control frame.
    #[test]
    fn thirty_two_commands_at_the_largest_size_with_every_escape_fit_the_file_and_the_frame() {
        let dir = directory();
        let mut revision = 0;
        for index in 0..MAX_COMMANDS {
            // 3,072 bytes in all: a label, a program and arguments of `"` and `\`, which JSON
            // writes as two bytes each.
            let label = format!("{index:02}{}", "\"".repeat(MAX_LABEL_CHARACTERS - 2));
            let rest = MAX_COMMAND_BYTES - label.len();
            let program = "\\".repeat(MAX_FIELD_BYTES);
            let mut left = rest - program.len();
            let mut arguments = Vec::new();
            while left > 0 {
                let size = left.min(MAX_FIELD_BYTES);
                arguments.push("\"".repeat(size));
                left -= size;
            }
            assert!(arguments.len() <= MAX_ARGUMENTS);
            let saved = save(
                dir.path(),
                revision,
                &NamedLaunch {
                    label,
                    program,
                    arguments,
                },
            )
            .unwrap_or_else(|error| panic!("{index}: {error}"));
            revision = saved.stored.revision;
        }
        let bytes = std::fs::metadata(file_in(dir.path()))
            .expect("the file")
            .len();
        assert!(bytes <= MAX_RECORD_LEN, "the file takes {bytes} bytes");
        let stored = read(dir.path()).expect("reads");
        assert_eq!(stored.commands.len(), MAX_COMMANDS);
        // The list as the wire carries it, in JSON, is under a control frame.
        let list = kr_protocol::launch_commands::ShellLaunchCommandsListResult {
            revision: kr_protocol::scalars::U64::new(stored.revision),
            commands: stored.commands.iter().map(NamedLaunch::from).collect(),
        };
        let wire = serde_json::to_vec(&list).expect("encodes");
        assert!(
            wire.len() < kr_protocol::limits::MAX_CONTROL_FRAME_LEN,
            "a full list takes {} bytes on the wire",
            wire.len()
        );
    }

    /// KR-REQ-13.11: a save replaces by label, case-insensitively, keeps the command's place and
    /// takes the new spelling; a new label goes last.
    #[test]
    fn a_save_replaces_by_label_keeps_the_place_and_appends_a_new_label() {
        let dir = directory();
        let mut revision = 0;
        for label in ["first", "second", "third"] {
            revision = save(dir.path(), revision, &command(label, "p", &[]))
                .expect("saves")
                .stored
                .revision;
        }
        let replaced = save(dir.path(), revision, &command("SECOND", "q", &["x"])).expect("saves");
        assert!(replaced.applied && replaced.changed && replaced.replaced);
        assert_eq!(labels(&replaced.stored), ["first", "SECOND", "third"]);
        assert_eq!(replaced.stored.commands[1].program, "q");
        let added = save(
            dir.path(),
            replaced.stored.revision,
            &command("fourth", "p", &[]),
        )
        .expect("saves");
        assert!(added.changed && !added.replaced);
        assert_eq!(
            labels(&added.stored),
            ["first", "SECOND", "third", "fourth"]
        );
    }

    /// KR-REQ-13.11: at 32 commands a replacement is allowed and a new label is refused.
    #[test]
    fn a_replacement_at_32_commands_is_allowed_and_a_new_label_is_refused() {
        let dir = directory();
        let mut revision = 0;
        for index in 0..MAX_COMMANDS {
            revision = save(
                dir.path(),
                revision,
                &command(&format!("c{index}"), "p", &[]),
            )
            .expect("saves")
            .stored
            .revision;
        }
        let replaced = save(dir.path(), revision, &command("C7", "q", &[])).expect("replaces");
        assert!(replaced.changed && replaced.replaced);
        let refused = save(
            dir.path(),
            replaced.stored.revision,
            &command("one more", "p", &[]),
        )
        .expect_err("the 33rd is refused");
        assert!(
            matches!(&refused, ControllerError::InvalidArgument(words)
                if words == "This host holds 32 launch commands. Replace one or remove one first."),
            "{refused:?}"
        );
        assert_eq!(read(dir.path()).expect("reads"), replaced.stored);
    }

    /// KR-REQ-13.11: a save that asks for what the list already holds, at the current revision,
    /// changes nothing, keeps the revision and says so.
    #[test]
    fn a_save_that_asks_for_what_the_list_holds_changes_nothing_and_says_so() {
        let dir = directory();
        let first = save(dir.path(), 0, &command("one", "p", &["a"])).expect("saves");
        let again = save(
            dir.path(),
            first.stored.revision,
            &command("one", "p", &["a"]),
        )
        .expect("saves");
        assert!(again.applied && !again.changed && !again.replaced);
        assert_eq!(again.stored, first.stored);
        assert_eq!(read(dir.path()).expect("reads"), first.stored);
    }

    /// KR-REQ-13.11: a removal of a label no command has changes nothing.
    #[test]
    fn a_remove_of_an_absent_label_changes_nothing() {
        let dir = directory();
        let first = save(dir.path(), 0, &command("one", "p", &[])).expect("saves");
        let removed = remove(dir.path(), first.stored.revision, "two").expect("removes");
        assert!(removed.applied && !removed.changed);
        assert_eq!(removed.stored, first.stored);
    }

    /// KR-REQ-13.11: a save made against an old revision writes nothing and cannot restore a
    /// command a later change removed.
    #[test]
    fn an_old_save_cannot_restore_an_earlier_command() {
        let dir = directory();
        let first = save(dir.path(), 0, &command("one", "p", &[])).expect("saves");
        let gone = remove(dir.path(), first.stored.revision, "one").expect("removes");
        let old =
            save(dir.path(), first.stored.revision, &command("one", "p", &[])).expect("answers");
        assert!(!old.applied && !old.changed);
        assert_eq!(old.stored, gone.stored);
        assert!(read(dir.path()).expect("reads").commands.is_empty());
    }

    /// KR-REQ-13.11: a removal made against an old revision cannot delete a command that was
    /// created again since.
    #[test]
    fn an_old_remove_cannot_delete_a_recreated_command() {
        let dir = directory();
        let first = save(dir.path(), 0, &command("one", "p", &[])).expect("saves");
        let gone = remove(dir.path(), first.stored.revision, "one").expect("removes");
        let again =
            save(dir.path(), gone.stored.revision, &command("one", "q", &[])).expect("saves");
        let old = remove(dir.path(), first.stored.revision, "one").expect("answers");
        assert!(!old.applied && !old.changed);
        assert_eq!(old.stored, again.stored);
        assert_eq!(labels(&read(dir.path()).expect("reads")), ["one"]);
    }

    /// KR-REQ-13.11: two saves made against one revision land once, and the second is answered with
    /// the list the first left and writes nothing.
    #[test]
    fn two_saves_against_one_revision_land_once_and_the_second_is_answered_with_the_list_the_first_left()
     {
        let dir = directory();
        let base = save(dir.path(), 0, &command("base", "p", &[])).expect("saves");
        let landed = save(
            dir.path(),
            base.stored.revision,
            &command("first", "p", &[]),
        )
        .expect("saves");
        let conflict = save(
            dir.path(),
            base.stored.revision,
            &command("second", "p", &[]),
        )
        .expect("answers");
        assert!(landed.applied && landed.changed);
        assert!(!conflict.applied && !conflict.changed);
        assert_eq!(conflict.stored, landed.stored);
        assert_eq!(labels(&read(dir.path()).expect("reads")), ["base", "first"]);
    }

    /// KR-REQ-13.11: a write that fails before the rename leaves the earlier file and is a storage
    /// failure that says nothing was written.
    #[test]
    fn a_write_that_fails_before_the_rename_leaves_the_earlier_file_and_says_nothing_changed() {
        let dir = directory();
        let first = save(dir.path(), 0, &command("one", "p", &[])).expect("saves");
        FAILURE.with(|failure| failure.set(Some(Failure::BeforeTheRename)));
        let failed = save(dir.path(), first.stored.revision, &command("two", "p", &[]))
            .expect_err("the write fails");
        assert!(
            matches!(failed, ControllerError::Storage { .. }),
            "{failed:?}"
        );
        assert_eq!(read(dir.path()).expect("reads"), first.stored);
    }

    /// KR-REQ-13.11: a write that fails after the rename is an unknown outcome, even though the
    /// file holds the new bytes, and a later read finds them.
    #[test]
    fn a_write_that_fails_after_the_rename_answers_outcome_unknown_even_when_the_file_holds_the_new_bytes()
     {
        let dir = directory();
        let first = save(dir.path(), 0, &command("one", "p", &[])).expect("saves");
        FAILURE.with(|failure| failure.set(Some(Failure::AfterTheRename)));
        let failed = save(dir.path(), first.stored.revision, &command("two", "p", &[]))
            .expect_err("the write fails");
        assert!(
            matches!(failed, ControllerError::Uncertain { .. }),
            "{failed:?}"
        );
        let found = read(dir.path()).expect("reads");
        assert_eq!(labels(&found), ["one", "two"], "the new bytes are in place");
    }

    /// KR-REQ-13.11: a save never replaces a file it could not read, and a write that follows
    /// finds the file as it was.
    #[test]
    fn a_save_never_replaces_a_file_it_could_not_read() {
        let dir = directory();
        let damaged = b"not json at all";
        std::fs::write(file_in(dir.path()), damaged).expect("written");
        assert!(save(dir.path(), 0, &command("one", "p", &[])).is_err());
        assert!(remove(dir.path(), 0, "one").is_err());
        assert_eq!(std::fs::read(file_in(dir.path())).expect("read"), damaged);
    }

    /// KR-REQ-13.11: a damaged file is a storage failure for the list, which the daemon answers as
    /// `STORAGE_UNAVAILABLE`, and it does not stop the host.
    #[test]
    fn a_damaged_file_does_not_stop_the_host_and_list_answers_storage_unavailable() {
        let dir = directory();
        std::fs::write(file_in(dir.path()), b"{").expect("written");
        let failed = read(dir.path()).expect_err("damaged");
        assert_eq!(
            failed.code(),
            kr_protocol::error::ErrorCode::StorageUnavailable
        );
        assert!(failed.to_string().contains(FILE_NAME), "{failed}");
    }
}
