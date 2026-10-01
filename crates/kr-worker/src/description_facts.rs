//! What one session was doing, as its worker records it for the control daemon's descriptions.
//!
//! A description of a session is built from facts the session itself produced: the directory a
//! command ran in, the program it ran, how it ended, the prompt an agent was given, the thread the
//! agent selected and the last few semantic events. This module is where the worker keeps them,
//! one small record per session, and where the daemon's request for them is answered from.
//!
//! # What is never here
//!
//! A keystroke, an application's output and the answer to a terminal query never reach this
//! record: its capture points are the places the worker already decides something happened (a
//! command block the shell integration reported, a prompt the worker admitted, an observation an
//! admitted bridge sent), and no input, resize or query path calls any of them. A command line is
//! reduced to its program name before it is stored, because its arguments are what a person typed.
//! Every text is clipped to [`MAX_DESCRIPTION_FACT_CODEPOINTS`] and stripped of control
//! characters.
//!
//! # Privacy mode
//!
//! While privacy mode is on nothing is captured, and enabling it clears the record in the same
//! step as every other subsystem's fence: [`DescriptionFactsPrivacy`] is the subsystem the caller
//! that enables privacy mode drives. Each record carries the generation it was captured under, so
//! a daemon holding facts from before a transition can tell they are from before it.
//!
//! # The repository
//!
//! The repository name and branch are read from the `.git` directory above the command's
//! directory, on a thread of its own: the hook that reported the command never waits for the
//! read. The walk is bounded in steps and in bytes, and a read that is slow leaves the facts as
//! they were until it answers; at most one read runs at a time, and a newer directory replaces the
//! one waiting.

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use kr_protocol::describe::{
    DescriptionCompletion, DescriptionEvent, DescriptionEventKind, DescriptionFacts as FactsRecord,
    DescriptionRepository, MAX_DESCRIPTION_FACT_CODEPOINTS, MAX_DESCRIPTION_FACT_EVENTS,
};
use kr_protocol::root::RootCommandBlockParams;
use kr_protocol::scalars::{Nullable, U64};

use crate::privacy::{
    Cancelled, Fenced, PrivacyGeneration, PrivacySubsystem, Removed, Unavailable,
};

/// How many directories above the command's the repository walk looks at.
const REPOSITORY_WALK_STEPS: usize = 64;

/// The most bytes of a repository's `HEAD` the walk reads.
const HEAD_BYTES: u64 = 4_096;

/// The facts a session has, shared between the places that capture them and the connection that
/// serves them.
#[derive(Clone, Debug)]
pub struct DescriptionFacts {
    shared: Arc<Shared>,
}

struct Shared {
    state: Mutex<State>,
    /// Woken after every change, for the request the daemon has had held.
    changed: tokio::sync::Notify,
    /// How the repository and the directory a read names are found: the file system's, and in this
    /// module's own tests one a test holds.
    reader: Reader,
}

impl std::fmt::Debug for Shared {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Shared")
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

type Reader = Arc<dyn Fn(&Read) -> Found + Send + Sync>;

#[derive(Debug)]
struct State {
    /// The privacy generation the session holds.
    generation: u64,
    /// Whether privacy mode is on, or this host cannot say it is not.
    private: bool,
    /// Moves with every change to any fact and with every privacy transition.
    revision: u64,
    record: Record,
    /// The working directory the newest command ran in, in full: the repository is read for it.
    cwd: Option<String>,
    /// How many events have been recorded, which is the next event's place.
    events_recorded: u64,
    /// How many times privacy mode was enabled or disabled: what a read began under, so that one
    /// that began before a transition is never applied after it.
    epoch: u64,
    /// How many command blocks were recorded: a read applies only when no later block has come,
    /// since a later block says where the session is now.
    blocks: u64,
    /// The directory read that is running, and the one waiting behind it.
    probe: Probe,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct Record {
    directory: Option<String>,
    repository: Option<Repository>,
    application: Option<String>,
    completion: Option<DescriptionCompletion>,
    intent: Option<String>,
    thread: Option<String>,
    events: VecDeque<Event>,
}

/// A repository, as it is named.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Repository {
    /// The directory that holds its `.git`.
    name: String,
    /// The branch its `HEAD` names, when it names one.
    branch: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Event {
    cursor: u64,
    kind: DescriptionEventKind,
    summary: String,
}

#[derive(Debug, Default)]
enum Probe {
    #[default]
    Idle,
    /// A read is running, and this one is waiting behind it, when one is.
    Running(Option<Read>),
}

/// One read of the directory and repository a command block names.
#[derive(Clone, Debug)]
struct Read {
    /// How many privacy transitions the session had had when the read was asked for.
    epoch: u64,
    /// How many command blocks it had recorded, this one included.
    block: u64,
    /// The directory the block says the command ran in.
    directory: PathBuf,
    /// The root shell's process, when the block says a command has ended and the shell is back at
    /// its prompt: the directory it is in now is read from the operating system.
    shell: Option<u64>,
}

/// What one read found.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Found {
    /// The directory the session is in.
    directory: PathBuf,
    /// The repository that directory is inside, when it is inside one.
    repository: Option<Repository>,
}

/// What one reading of the record says.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reading {
    /// The privacy generation the session holds.
    pub privacy_generation: u64,
    /// Whether privacy mode is on.
    pub private: bool,
    /// The facts, when their revision is past the one asked after and privacy mode is off.
    pub facts: Option<FactsRecord>,
    /// Whether a request that named `after` and `generation` is answered now rather than held.
    pub answerable: bool,
}

impl DescriptionFacts {
    /// Starts an empty record for a session that holds `generation`, with privacy mode on when
    /// `private`.
    #[must_use]
    pub fn new(private: bool, generation: PrivacyGeneration) -> Self {
        Self::reading_with(private, generation, Arc::new(read_from_disk))
    }

    fn reading_with(private: bool, generation: PrivacyGeneration, reader: Reader) -> Self {
        Self {
            shared: Arc::new(Shared {
                reader,
                state: Mutex::new(State {
                    generation: generation.get(),
                    private,
                    revision: 0,
                    record: Record::default(),
                    cwd: None,
                    events_recorded: 0,
                    epoch: 0,
                    blocks: 0,
                    probe: Probe::Idle,
                }),
                changed: tokio::sync::Notify::new(),
            }),
        }
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.shared
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Applies one change, and moves the revision and wakes the held request when it changed
    /// anything. Nothing is applied while privacy mode is on.
    fn change(&self, edit: impl FnOnce(&mut State) -> bool) {
        let moved = {
            let mut state = self.state();
            if state.private {
                return;
            }
            let moved = edit(&mut state);
            if moved {
                state.revision += 1;
            }
            moved
        };
        if moved {
            self.shared.changed.notify_waiters();
        }
    }

    /// Records a command block the shell integration reported: the directory it ran in, its
    /// program name and, when it has ended, how.
    ///
    /// A command starting is also an event, with its program name for a summary. The repository the
    /// directory is in is read on a thread of its own.
    pub fn note_command(&self, block: &RootCommandBlockParams, shell: Option<u64>) {
        let directory = last_component(&block.cwd);
        let application = program_of(&block.command);
        let finished = block.finished();
        let completion = block.exit_status.0.map(|status| {
            if status.get() == 0 {
                DescriptionCompletion::Succeeded
            } else {
                DescriptionCompletion::Failed
            }
        });
        // A command that has ended leaves the shell at its prompt, where the directory it is in now
        // is the one to describe: the block says where the command began, which after a `cd` is
        // not it.
        let shell = shell.filter(|_| finished);
        let mut read = None;
        self.change(|state| {
            state.blocks += 1;
            let mut moved = false;
            let moved_directory = state.cwd.as_deref() != Some(block.cwd.as_str());
            if moved_directory {
                state.cwd = Some(block.cwd.clone());
                // A repository belongs to the directory it was read for.
                moved |= state.record.repository.take().is_some();
            }
            // The directory is read at every ending as well as at every change: a branch can be
            // switched in the directory the session is already in.
            if moved_directory || finished {
                read = Some(Read {
                    epoch: state.epoch,
                    block: state.blocks,
                    directory: PathBuf::from(&block.cwd),
                    shell,
                });
            }
            if state.record.directory != directory {
                state.record.directory = directory;
                moved = true;
            }
            if state.record.application != application {
                state.record.application.clone_from(&application);
                moved = true;
            }
            // A command that has not ended has no completion; one that has, has its own.
            let completion = if finished { completion } else { None };
            if state.record.completion != completion {
                state.record.completion = completion;
                moved = true;
            }
            if !finished {
                let cursor = state.events_recorded;
                state.events_recorded += 1;
                push_event(
                    &mut state.record,
                    cursor,
                    DescriptionEventKind::CommandAccepted,
                    application.as_deref().unwrap_or_default(),
                );
                moved = true;
            }
            moved
        });
        if let Some(read) = read {
            self.read_directory(read);
        }
    }

    /// Records the prompt an agent in the session was last given.
    pub fn note_intent(&self, prompt: &str) {
        let intent = clip(prompt);
        self.change(|state| {
            if state.record.intent == intent {
                return false;
            }
            state.record.intent = intent;
            true
        });
    }

    /// Records the thread the session's agent selected, or that it selected none.
    pub fn note_thread(&self, thread: Option<&str>) {
        let thread = thread.and_then(clip);
        self.change(|state| {
            if state.record.thread == thread {
                return false;
            }
            state.record.thread = thread;
            true
        });
    }

    /// Records one semantic event, newest first, keeping the most recent
    /// [`MAX_DESCRIPTION_FACT_EVENTS`].
    pub fn note_event(&self, kind: DescriptionEventKind, summary: &str) {
        self.change(|state| {
            let cursor = state.events_recorded;
            state.events_recorded += 1;
            push_event(&mut state.record, cursor, kind, summary);
            true
        });
    }

    /// Turns capture off and clears the record, for the generation privacy mode was enabled at.
    pub fn fence(&self, generation: PrivacyGeneration) {
        {
            let mut state = self.state();
            state.private = true;
            state.generation = generation.get();
            state.start_over();
        }
        self.shared.changed.notify_waiters();
    }

    /// Turns capture on again, for the generation privacy mode was disabled at. The record starts
    /// empty: nothing captured before is brought back.
    pub fn release(&self, generation: PrivacyGeneration) {
        {
            let mut state = self.state();
            state.private = false;
            state.generation = generation.get();
            state.start_over();
        }
        self.shared.changed.notify_waiters();
    }

    /// Reads the record for a request that has read up to `after` and has recorded `named` as the
    /// session's privacy generation.
    #[must_use]
    pub fn read(&self, after: u64, named: Option<u64>) -> Reading {
        let state = self.state();
        let moved = state.revision > after;
        let behind = named != Some(state.generation);
        let facts = (moved && !state.private).then(|| state.facts());
        Reading {
            privacy_generation: state.generation,
            private: state.private,
            facts,
            // A private session answers once, to say it is private, and then holds: the daemon
            // names the generation it learned and asks again.
            answerable: behind || (moved && !state.private),
        }
    }

    /// Returns the future that completes at the next change after it was made.
    ///
    /// Made before a reading and awaited after it, so a change between the two is not missed.
    pub fn changed(&self) -> tokio::sync::futures::Notified<'_> {
        self.shared.changed.notified()
    }

    /// Starts a read, or queues it behind the one that runs, replacing the one already waiting.
    fn read_directory(&self, read: Read) {
        {
            let mut state = self.state();
            match &mut state.probe {
                Probe::Running(waiting) => {
                    *waiting = Some(read);
                    return;
                }
                Probe::Idle => state.probe = Probe::Running(None),
            }
        }
        let facts = self.clone();
        let started = std::thread::Builder::new()
            .name("describe-repository".to_owned())
            .spawn(move || facts.run_reads(read));
        if started.is_err() {
            // No thread: the facts go without it, and the next command tries again.
            self.state().probe = Probe::Idle;
        }
    }

    /// Does the read it was given and then each one that was queued behind it, applying what each
    /// finds to the record it was asked for, and to no other.
    fn run_reads(&self, mut read: Read) {
        loop {
            let found = (self.shared.reader)(&read);
            let next = {
                let mut state = self.state();
                // A read applies under the privacy transition it began in and the newest block it
                // was asked for: a transition between the two, or a newer block, says what it found
                // is about something else.
                let current =
                    !state.private && state.epoch == read.epoch && state.blocks == read.block;
                let moved = current && state.apply_found(&found);
                let next = match &mut state.probe {
                    Probe::Running(waiting) => waiting.take(),
                    Probe::Idle => None,
                };
                if next.is_none() {
                    state.probe = Probe::Idle;
                }
                drop(state);
                if moved {
                    self.shared.changed.notify_waiters();
                }
                next
            };
            match next {
                Some(next) => read = next,
                None => return,
            }
        }
    }
}

impl State {
    /// Begins a record of its own at a privacy transition: nothing from before comes with it, and
    /// no read that began before it applies to it.
    fn start_over(&mut self) {
        self.record = Record::default();
        self.cwd = None;
        self.revision += 1;
        self.epoch += 1;
        if let Probe::Running(waiting) = &mut self.probe {
            *waiting = None;
        }
    }

    /// Takes what a read found into the record, and says whether anything moved and the revision
    /// with it.
    fn apply_found(&mut self, found: &Found) -> bool {
        let mut moved = false;
        let directory = found.directory.to_string_lossy().into_owned();
        if self.cwd.as_deref() != Some(directory.as_str()) {
            self.record.directory = last_component(&directory);
            self.cwd = Some(directory);
            moved = true;
        }
        if self.record.repository != found.repository {
            self.record.repository.clone_from(&found.repository);
            moved = true;
        }
        if moved {
            self.revision += 1;
        }
        moved
    }

    fn facts(&self) -> FactsRecord {
        FactsRecord {
            revision: U64::new(self.revision),
            generation: U64::new(self.generation),
            directory: Nullable(self.record.directory.clone()),
            repository: Nullable(self.record.repository.as_ref().map(|repository| {
                DescriptionRepository {
                    name: repository.name.clone(),
                    branch: Nullable(repository.branch.clone()),
                }
            })),
            application: Nullable(self.record.application.clone()),
            completion: Nullable(self.record.completion),
            intent: Nullable(self.record.intent.clone()),
            thread: Nullable(self.record.thread.clone()),
            events: self
                .record
                .events
                .iter()
                .map(|event| DescriptionEvent {
                    cursor: U64::new(event.cursor),
                    kind: event.kind,
                    summary: event.summary.clone(),
                })
                .collect(),
        }
    }
}

/// Adds an event at the front, newest first, and drops the oldest past the bound.
fn push_event(record: &mut Record, cursor: u64, kind: DescriptionEventKind, summary: &str) {
    record.events.push_front(Event {
        cursor,
        kind,
        summary: clip(summary).unwrap_or_default(),
    });
    record.events.truncate(MAX_DESCRIPTION_FACT_EVENTS);
}

/// Clips text to [`MAX_DESCRIPTION_FACT_CODEPOINTS`] without control characters, and returns none
/// when nothing is left.
fn clip(text: &str) -> Option<String> {
    let cleaned: String = text
        .chars()
        .filter(|character| !character.is_control())
        .take(MAX_DESCRIPTION_FACT_CODEPOINTS)
        .collect();
    let trimmed = cleaned.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_owned())
}

/// The last component of a path, clipped; a path with none, such as a root, is its own name.
fn last_component(path: &str) -> Option<String> {
    let path = Path::new(path);
    path.file_name()
        .and_then(|name| name.to_str())
        .and_then(clip)
        .or_else(|| path.to_str().and_then(clip))
}

/// The program a command line runs, and nothing else of it.
///
/// This reads a closed grammar and nothing more. A line is blanks, any number of variable
/// assignments (`NAME=value`, `NAME+=value`), and then the program word; the program word's last
/// component is the name. Every word is made of characters whose meaning is the same in every
/// shell this product runs (letters, digits and `_ . / : + , @ % ~ - =`, a backslash in front of
/// one of them, and quoted parts whose contents hold no character a shell treats specially inside
/// quotes), and the words are separated by spaces and tabs alone. Anything else, wherever it is
/// before the program word ends, means this reader does not know what the shell will run, and
/// the line names no program: a redirection, an operator, a substitution, a group, a comment, an
/// escaped blank or quote, an unterminated quote, a newline before the program, a name that is not
/// a variable's. Nothing after the program word is read. A missing name is no harm, and a wrong
/// one is a leak of what a person typed, so no syntax is ever modelled: it is refused.
fn program_of(command: &str) -> Option<String> {
    let mut rest = command.trim_start_matches(is_blank);
    loop {
        let (word, after) = scan_word(rest)?;
        if word.is_assignment() {
            // What it is for follows after blanks. A newline or the end of the line makes the
            // assignment a command of its own: the next word is then empty, and names nothing.
            rest = after.trim_start_matches(is_blank);
            continue;
        }
        // A word that holds an `=` and is not an assignment is not one this reader knows.
        if word.raw.contains('=') {
            return None;
        }
        let name = word.text.rsplit(['/', '\\']).next().unwrap_or(&word.text);
        return clip(name);
    }
}

/// One word of a command line: as it was typed, and with its quotes taken off.
struct Word<'a> {
    raw: &'a str,
    text: String,
}

impl Word<'_> {
    /// Whether the word sets a variable for the command after it: an unquoted name that starts
    /// with a letter or an underscore, an optional `+`, an `=`, and a value with no backslash.
    fn is_assignment(&self) -> bool {
        let Some((name, _value)) = self.raw.split_once('=') else {
            return false;
        };
        let name = name.strip_suffix('+').unwrap_or(name);
        name.chars()
            .next()
            .is_some_and(|first| first.is_ascii_alphabetic() || first == '_')
            && name.chars().all(is_variable_character)
            && !self.raw.contains('\\')
    }
}

/// A space or a tab: the only characters that separate the words of a line.
const fn is_blank(character: char) -> bool {
    matches!(character, ' ' | '\t')
}

/// A character that means the same in every shell, outside quotes.
fn is_plain(character: char) -> bool {
    character.is_alphanumeric()
        || matches!(
            character,
            '_' | '.' | '/' | ':' | '+' | ',' | '@' | '%' | '~' | '-' | '='
        )
}

/// Whether a quoted part may hold `character`: nothing a shell reads specially inside the quote
/// it is in (a backslash, and in double quotes `$`, a backtick and `!`), no control character, and
/// no quote of the kind that closes it, which the search for the closing quote has already ruled
/// out.
fn is_quotable(character: char, quote: char) -> bool {
    !character.is_control()
        && character != '\\'
        && (quote == '\'' || !matches!(character, '$' | '`' | '!'))
}

/// Reads the word at the start of `rest` and returns it with what follows it: the blank or newline
/// that ended it, or nothing. None when the word holds anything outside the closed grammar.
fn scan_word(rest: &str) -> Option<(Word<'_>, &str)> {
    let mut text = String::new();
    let mut at = 0;
    while let Some(character) = rest[at..].chars().next() {
        match character {
            blank if is_blank(blank) || blank == '\n' => break,
            quote @ ('\'' | '"') => {
                let from = at + 1;
                let close = from + rest[from..].find(quote)?;
                let inside = &rest[from..close];
                if !inside.chars().all(|inside| is_quotable(inside, quote)) {
                    return None;
                }
                text.push_str(inside);
                at = close + 1;
                continue;
            }
            // A backslash is a Windows path's separator or a shell's escape of the next character,
            // and which it is depends on the shell: only before a character of the closed set does
            // it say the same thing in both, a word that goes on.
            '\\' => {
                let next = rest[at + 1..].chars().next()?;
                if !(is_plain(next) || next == '\\') {
                    return None;
                }
                text.push(character);
            }
            plain if is_plain(plain) => text.push(plain),
            _ => return None,
        }
        at += character.len_utf8();
    }
    Some((
        Word {
            raw: &rest[..at],
            text,
        },
        &rest[at..],
    ))
}

const fn is_variable_character(character: char) -> bool {
    character.is_ascii_alphanumeric() || character == '_'
}

/// Reads what the file system says of one read: the directory it names, and the repository above.
fn read_from_disk(read: &Read) -> Found {
    // The block's directory is the shell's own spelling of it; the operating system spells a link
    // out. Where both name one directory, the shell's spelling stays, so a link is not a move.
    let directory = match read.shell.and_then(shell_directory) {
        Some(now) if !same_directory(&now, &read.directory) => now,
        _ => read.directory.clone(),
    };
    Found {
        repository: repository_above(&directory),
        directory,
    }
}

/// Whether two paths name one directory.
#[cfg(unix)]
fn same_directory(first: &Path, second: &Path) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    match (std::fs::metadata(first), std::fs::metadata(second)) {
        (Ok(first), Ok(second)) => first.dev() == second.dev() && first.ino() == second.ino(),
        _ => false,
    }
}

/// Whether two paths name one directory: where this platform cannot say, they do not.
#[cfg(not(unix))]
fn same_directory(_first: &Path, _second: &Path) -> bool {
    false
}

/// The directory a shell process is in, as the operating system keeps it, where this platform
/// can say.
#[cfg(target_os = "linux")]
fn shell_directory(pid: u64) -> Option<PathBuf> {
    std::fs::read_link(format!("/proc/{pid}/cwd")).ok()
}

/// The directory a shell process is in, as the operating system keeps it, where this platform
/// can say.
#[cfg(target_os = "macos")]
fn shell_directory(pid: u64) -> Option<PathBuf> {
    crate::broker::commands::working_directory_path_of(pid)
}

/// No platform record of a shell's directory is read here: the block's own stands.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
const fn shell_directory(_pid: u64) -> Option<PathBuf> {
    None
}

/// Reads the repository a directory is inside: the directory that holds a `.git`, as its name,
/// and the branch its `HEAD` names.
fn repository_above(directory: &Path) -> Option<Repository> {
    let mut candidate = Some(directory);
    for _ in 0..REPOSITORY_WALK_STEPS {
        let current = candidate?;
        let marker = current.join(".git");
        if let Some(head) = head_of(&marker, current) {
            let name = current.file_name()?.to_str().and_then(clip)?;
            return Some(Repository {
                name,
                branch: branch_of(&head),
            });
        }
        candidate = current.parent();
    }
    None
}

/// Reads a repository's `HEAD`, from a `.git` directory or from the directory a `.git` file
/// points at. A marker that is neither is not a repository.
fn head_of(marker: &Path, owner: &Path) -> Option<String> {
    let metadata = std::fs::metadata(marker).ok()?;
    let git_directory = if metadata.is_dir() {
        marker.to_path_buf()
    } else {
        let pointer = read_bounded(marker)?;
        let target = pointer.trim().strip_prefix("gitdir:")?.trim();
        let target = Path::new(target);
        if target.is_absolute() {
            target.to_path_buf()
        } else {
            owner.join(target)
        }
    };
    read_bounded(&git_directory.join("HEAD"))
}

/// Reads at most [`HEAD_BYTES`] of a regular file as text. Anything else a directory can hold under
/// that name, a pipe or a device, is not read: opening one can wait for ever for a writer, and the
/// read that waits is the only one this session would ever make.
fn read_bounded(path: &Path) -> Option<String> {
    use std::io::Read as _;

    if !std::fs::metadata(path).ok()?.is_file() {
        return None;
    }
    let file = std::fs::File::open(path).ok()?;
    let mut text = String::new();
    file.take(HEAD_BYTES).read_to_string(&mut text).ok()?;
    Some(text)
}

/// The branch a `HEAD` names, when it names one: a detached `HEAD` names none.
fn branch_of(head: &str) -> Option<String> {
    let reference = head.trim().strip_prefix("ref:")?.trim();
    clip(reference.strip_prefix("refs/heads/")?)
}

/// The privacy subsystem of a session's description facts: its fence stops capture and clears the
/// record at the moment privacy mode is enabled, and there is nothing else retained to remove.
#[derive(Clone, Debug)]
pub struct DescriptionFactsPrivacy {
    facts: DescriptionFacts,
}

impl DescriptionFactsPrivacy {
    /// Builds the subsystem over a session's facts.
    #[must_use]
    pub const fn over(facts: DescriptionFacts) -> Self {
        Self { facts }
    }
}

impl PrivacySubsystem for DescriptionFactsPrivacy {
    fn name(&self) -> &'static str {
        "description_facts"
    }

    fn fence(&mut self, generation: PrivacyGeneration) -> Result<Fenced, Unavailable> {
        self.facts.fence(generation);
        Ok(Fenced {
            queues: 1,
            items: 0,
        })
    }

    fn cancel_undispatched(
        &mut self,
        _generation: PrivacyGeneration,
    ) -> Result<Cancelled, Unavailable> {
        Ok(Cancelled::default())
    }

    fn remove_retained(&mut self, generation: PrivacyGeneration) -> Result<Removed, Unavailable> {
        // The fence cleared it; clearing again at the same generation changes nothing.
        self.facts.fence(generation);
        Ok(Removed::default())
    }

    fn outstanding(&self) -> Result<u64, Unavailable> {
        Ok(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_protocol::ids::SessionId;
    use kr_protocol::root::{CwdRevision, PromptGeneration};
    use kr_protocol::scalars::{DurationMs, TimestampMs, Uuid};

    fn block(command: &str, cwd: &str, status: Option<u64>) -> RootCommandBlockParams {
        RootCommandBlockParams {
            session_id: SessionId::new(Uuid::from_bytes([1; 16])),
            prompt_generation: PromptGeneration::new(1),
            command: command.to_owned(),
            started_at_ms: TimestampMs::new(1),
            duration_ms: Nullable(status.map(|_| DurationMs::new(1))),
            exit_status: Nullable(status.map(U64::new)),
            cwd: cwd.to_owned(),
            cwd_revision: CwdRevision::new(0),
        }
    }

    fn facts() -> DescriptionFacts {
        DescriptionFacts::new(false, PrivacyGeneration::new(0))
    }

    fn read(facts: &DescriptionFacts) -> FactsRecord {
        facts.read(0, Some(0)).facts.expect("facts are there")
    }

    /// A command line is reduced to its program: variable assignments, arguments and the
    /// directory it was named by never reach the record.
    #[test]
    fn a_command_line_is_reduced_to_its_program_name() {
        for (line, program) in [
            ("cargo test --all", Some("cargo")),
            ("FOO=1 BAR=two /usr/bin/git status", Some("git")),
            ("  \"/opt/tools/rg\" secret-needle", Some("rg")),
            ("C:\\tools\\node.exe app.js", Some("node.exe")),
            ("A=1", None),
            ("", None),
        ] {
            assert_eq!(program_of(line).as_deref(), program, "{line:?}");
        }
        let facts = facts();
        facts.note_command(
            &block("TOKEN=hunter2 deploy --key abc", "/home/a/work", None),
            None,
        );
        let record = read(&facts);
        assert_eq!(record.application.0.as_deref(), Some("deploy"));
        let encoded = serde_json::to_string(&record).expect("facts encode");
        assert!(
            !encoded.contains("hunter2") && !encoded.contains("abc"),
            "{encoded}"
        );
    }

    /// The program is read from a closed grammar: assignments, then the program word, in
    /// characters that mean the same in every shell. Quoted values stay inside their assignment;
    /// every other syntax, wherever it is before the program, names no program at all.
    #[test]
    fn a_program_is_named_only_from_the_closed_grammar_and_every_other_syntax_names_none() {
        for (line, program) in [
            // Named: assignments of plain or quoted values, then the program word.
            ("TOKEN='first secret' cargo test", Some("cargo")),
            ("TOKEN=\"first secret\" cargo test", Some("cargo")),
            ("A='x y' B=\"p q\" C=r /usr/bin/make all", Some("make")),
            ("NAME='it'\"'\"'s a secret' deploy", Some("deploy")),
            ("TOKEN+=s3cret deploy", Some("deploy")),
            ("RUSTFLAGS+=\" -D warnings\" cargo build", Some("cargo")),
            ("TOKEN=a=b\tcargo test", Some("cargo")),
            ("\"/Applications/My App/run\" --flag", Some("run")),
            ("'/opt/tools/rg' secret-needle", Some("rg")),
            ("cargo\nrm -rf secret", Some("cargo")),
            ("C:\\tools\\node.exe app.js", Some("node.exe")),
            ("~/bin/tool --now", Some("tool")),
            // Not named: a redirection, in any spelling, before the program.
            ("> out.log cargo build", None),
            (">out.log cargo build", None),
            ("2>&1 cargo build", None),
            ("2> err.log TOKEN='a b' cargo build", None),
            (">| out.log cargo build", None),
            ("<<- END cat", None),
            ("<<<text cat", None),
            (">&- cargo build", None),
            (">! out.log cargo build", None),
            ("<<EOF\nbody secret\nEOF", None),
            // Not named: an operator or a separator inside or after an assignment.
            ("TOKEN=x;deploy prod", None),
            ("2>/dev/null&&deploy --key k1", None),
            ("TOKEN=x|deploy prod", None),
            ("TOKEN=x\ndeploy prod", None),
            ("TOKEN=x\u{a0}secret cmd", None),
            // Not named: a quote this reader would read differently from the shell.
            ("MSG=$'it\\'s done' git commit -m 'fix it'", None),
            ("MSG='it\\'s done' git commit -m 'fix it'", None),
            ("echo\\\"hello secret\"", None),
            ("TOKEN='first secret cargo test", None),
            ("TOKEN=\"first secret cargo test", None),
            ("TOKEN=\"$HOME secret\" cargo test", None),
            // Not named: a substitution, an expansion, a group, a comment.
            ("X=$(echo a b) cargo test", None),
            ("X=$(echo a b cargo test", None),
            ("$(pick-a-tool) --now", None),
            ("`pick-a-tool` --now", None),
            ("$TOOL --now", None),
            ("(cd /x && run) --now", None),
            ("#note secret text", None),
            ("TOKEN=x #note", None),
            // Not named: an escaped blank or backslash, a name that is not a variable's, and a
            // line with no program.
            ("TOKEN=first\\ secret cargo test", None),
            ("A=x\\\\ y cmd", None),
            ("ls\\ secret", None),
            ("1A=x cmd", None),
            ("pasted=secret", None),
            ("TOKEN+=s3cret", None),
            ("TOKEN='only a secret'", None),
            ("A=1", None),
            ("", None),
            ("   ", None),
            // Not named: a backslash in a quote, which a shell may read as an escape, and so as
            // a different word than this reader would.
            ("\"C:\\Program Files\\x.exe\" arg", None),
            ("'a\\b' secret", None),
        ] {
            assert_eq!(program_of(line).as_deref(), program, "{line:?}");
        }
        let facts = facts();
        facts.note_command(
            &block("TOKEN='first secret' cargo test", "/home/a/work", None),
            None,
        );
        let record = read(&facts);
        assert_eq!(record.application.0.as_deref(), Some("cargo"));
        assert_eq!(record.events[0].summary, "cargo");
        let encoded = serde_json::to_string(&record).expect("facts encode");
        assert!(!encoded.contains("secret"), "{encoded}");
    }

    /// Whatever a line starts with, nothing past the point where one command ends and the next
    /// begins is ever named: every line of up to four characters from a set of the characters
    /// shells treat specially, followed by each way of ending one command and starting the next,
    /// never names the word that comes after.
    #[test]
    fn nothing_after_what_a_line_starts_with_is_ever_named() {
        const CHARACTERS: [char; 20] = [
            '\'', '"', '\\', ' ', '$', ';', '=', '#', 'a', '<', '>', '\n', '\u{a0}', '&', '|', '(',
            '`', '!', '{', '\t',
        ];
        const TAILS: [&str; 5] = [
            " cmd SECRET",
            "\ncmd SECRET",
            ";cmd SECRET",
            "&&cmd SECRET",
            "|cmd SECRET",
        ];
        let mut prefixes = vec![String::new()];
        let mut all = vec![String::new()];
        for _ in 0..4 {
            let mut longer = Vec::new();
            for prefix in &prefixes {
                for character in CHARACTERS {
                    let mut next = prefix.clone();
                    next.push(character);
                    longer.push(next);
                }
            }
            all.extend(longer.iter().cloned());
            prefixes = longer;
        }
        for prefix in &all {
            for tail in TAILS {
                let line = format!("{prefix}{tail}");
                if let Some(named) = program_of(&line) {
                    assert!(!named.contains("SECRET"), "{line:?} named {named:?}");
                }
            }
        }
    }

    /// A root directory has a name of its own, so `cd /` replaces the directory the session left.
    #[test]
    fn the_root_directory_is_named_and_a_move_to_it_is_a_move() {
        let facts = facts();
        facts.note_command(&block("ls", "/home/a/kalareach", None), None);
        assert_eq!(read(&facts).directory.0.as_deref(), Some("kalareach"));
        facts.note_command(&block("ls", "/", None), None);
        assert_eq!(read(&facts).directory.0.as_deref(), Some("/"));
    }

    /// A link to the directory the shell is in is that directory: the shell's spelling stays, and
    /// where the shell is now replaces a directory it is not in.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn a_link_to_the_shells_directory_is_not_a_move() {
        let here = std::env::current_dir().expect("a working directory");
        let root = tempfile::tempdir().expect("a directory");
        let link = root.path().join("link");
        std::os::unix::fs::symlink(&here, &link).expect("a link");
        let shell = Some(u64::from(std::process::id()));
        let found = read_from_disk(&Read {
            epoch: 0,
            block: 1,
            directory: link.clone(),
            shell,
        });
        assert_eq!(found.directory, link, "the shell's spelling stays");

        let other = root.path().join("other");
        std::fs::create_dir(&other).expect("another directory");
        let found = read_from_disk(&Read {
            epoch: 0,
            block: 1,
            directory: other,
            shell,
        });
        assert_eq!(
            found.directory.canonicalize().expect("it exists"),
            here.canonicalize().expect("it exists"),
            "a directory the shell is not in is replaced by where it is"
        );
    }

    /// A pipe where a repository's `.git` or `HEAD` should be is not read: the read returns at
    /// once and finds no repository, where opening it would wait for a writer that never comes.
    /// The control is a regular file in the same place, which is read.
    #[cfg(unix)]
    #[test]
    fn a_pipe_named_git_or_head_is_not_opened() {
        let root = tempfile::tempdir().expect("a directory");
        let fifo = |path: &std::path::Path| {
            let made = std::process::Command::new("mkfifo")
                .arg(path)
                .status()
                .expect("mkfifo runs");
            assert!(made.success(), "a pipe");
        };
        let as_found = |directory: std::path::PathBuf| {
            let (done, returned) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let _ = done.send(repository_above(&directory));
            });
            returned
                .recv_timeout(std::time::Duration::from_secs(30))
                .expect("the read returned: it did not wait on a pipe")
        };

        let marker = root.path().join("marker");
        std::fs::create_dir_all(&marker).expect("a directory");
        fifo(&marker.join(".git"));
        assert_eq!(as_found(marker), None, "a pipe named .git");

        let head = root.path().join("head");
        std::fs::create_dir_all(head.join(".git")).expect("a git directory");
        fifo(&head.join(".git/HEAD"));
        assert_eq!(as_found(head), None, "a pipe named HEAD");

        let control = root.path().join("control");
        std::fs::create_dir_all(control.join(".git")).expect("a git directory");
        std::fs::write(control.join(".git/HEAD"), "ref: refs/heads/main\n").expect("a HEAD");
        assert_eq!(
            as_found(control).map(|repository| repository.name),
            Some("control".to_owned())
        );
    }

    /// A command that has started has no completion, one that has ended has its own, and only
    /// the start is an event: the same command's end is not a second one.
    #[test]
    fn a_command_has_a_completion_only_once_it_has_ended_and_is_one_event() {
        let facts = facts();
        facts.note_command(&block("cargo test", "/home/a/kalareach", None), None);
        let started = read(&facts);
        assert_eq!(started.directory.0.as_deref(), Some("kalareach"));
        assert_eq!(started.completion.0, None);
        assert_eq!(started.events.len(), 1);
        assert_eq!(
            started.events[0].kind,
            DescriptionEventKind::CommandAccepted
        );
        assert_eq!(started.events[0].summary, "cargo");

        facts.note_command(&block("cargo test", "/home/a/kalareach", Some(1)), None);
        let ended = read(&facts);
        assert_eq!(ended.completion.0, Some(DescriptionCompletion::Failed));
        assert_eq!(ended.events.len(), 1, "the end is not a second event");
        assert!(ended.revision.get() > started.revision.get());

        facts.note_command(&block("make", "/home/a/kalareach", None), None);
        assert_eq!(
            read(&facts).completion.0,
            None,
            "a new command has not ended"
        );
    }

    /// Text is clipped to its bound and stripped of control characters, events keep the newest
    /// eight, and a change that changes nothing does not move the revision.
    #[test]
    fn texts_and_events_are_bounded_and_an_unchanged_fact_moves_no_revision() {
        let facts = facts();
        facts.note_intent(&format!("check\u{1b}[31m the flow {}", "x".repeat(300)));
        let record = read(&facts);
        let intent = record.intent.0.expect("an intent");
        assert_eq!(intent.chars().count(), MAX_DESCRIPTION_FACT_CODEPOINTS);
        assert!(!intent.contains('\u{1b}'));
        let revision = record.revision;
        facts.note_intent(&format!("check\u{1b}[31m the flow {}", "x".repeat(300)));
        assert_eq!(read(&facts).revision, revision, "the same prompt again");

        for number in 0..20 {
            facts.note_event(DescriptionEventKind::TaskStarted, &format!("task {number}"));
        }
        let record = read(&facts);
        assert_eq!(record.events.len(), MAX_DESCRIPTION_FACT_EVENTS);
        assert_eq!(record.events[0].summary, "task 19", "newest first");
        assert_eq!(record.events[7].summary, "task 12");
        facts.note_thread(Some("thread-1"));
        assert_eq!(read(&facts).thread.0.as_deref(), Some("thread-1"));
        facts.note_thread(None);
        assert_eq!(read(&facts).thread.0, None);
    }

    /// While privacy mode is on nothing is captured, the fence clears what was there, and
    /// releasing it starts a record of its own under the new generation.
    #[test]
    fn nothing_is_captured_while_private_and_a_release_starts_a_new_record() {
        let facts = facts();
        facts.note_intent("before");
        let before = read(&facts);
        facts.fence(PrivacyGeneration::new(1));
        assert_eq!(
            facts.state().record,
            Record::default(),
            "the fence cleared what was there"
        );
        let revision = facts.state().revision;
        facts.note_intent("while private");
        facts.note_command(&block("ls", "/home/a/x", None), None);
        facts.note_event(DescriptionEventKind::TaskStarted, "while private");
        facts.note_thread(Some("while private"));
        let held = facts.state();
        assert_eq!(
            (held.record.clone(), held.revision),
            (Record::default(), revision),
            "nothing was recorded, and nothing woke a request"
        );
        drop(held);
        let private = facts.read(0, Some(1));
        assert!(private.private);
        assert_eq!(private.privacy_generation, 1);
        assert_eq!(private.facts, None, "no facts are served while private");
        assert!(!private.answerable, "named, so it holds");
        assert!(
            facts.read(0, Some(0)).answerable,
            "behind, so it says so at once"
        );

        facts.release(PrivacyGeneration::new(2));
        let after = read_at(&facts, 2);
        assert_eq!(after.generation.get(), 2);
        assert_eq!(after.intent.0, None, "nothing from before comes back");
        assert!(after.revision.get() > before.revision.get());
        facts.note_intent("after");
        assert_eq!(read_at(&facts, 2).intent.0.as_deref(), Some("after"));
    }

    fn read_at(facts: &DescriptionFacts, generation: u64) -> FactsRecord {
        facts
            .read(0, Some(generation))
            .facts
            .expect("facts are there")
    }

    /// A request is answered at once when the facts moved past it or the daemon is behind the
    /// session's generation, and held otherwise.
    #[test]
    fn a_request_is_held_unless_the_facts_moved_or_the_daemon_is_behind() {
        let facts = facts();
        facts.note_intent("one");
        let revision = read(&facts).revision.get();
        assert!(facts.read(0, Some(0)).answerable, "past the cursor");
        let current = facts.read(revision, Some(0));
        assert!(
            !current.answerable,
            "nothing newer, and the daemon is current"
        );
        assert_eq!(current.facts, None);
        assert!(
            facts.read(revision, None).answerable,
            "the daemon has recorded nothing"
        );
        assert!(
            facts.read(revision, Some(7)).answerable,
            "or something else"
        );
    }

    /// The repository is the directory that holds a `.git`, named by that directory, with the
    /// branch its `HEAD` names; a detached `HEAD` names none, a `.git` file points at the real
    /// one, and a directory outside any repository has none.
    #[test]
    fn the_repository_is_read_from_the_git_directory_above() {
        let root = tempfile::tempdir().expect("a directory");
        let repo = root.path().join("kalareach");
        let nested = repo.join("crates/kr-worker");
        std::fs::create_dir_all(repo.join(".git")).expect("a git directory");
        std::fs::create_dir_all(&nested).expect("a nested directory");
        std::fs::write(repo.join(".git/HEAD"), "ref: refs/heads/feature/x\n").expect("a HEAD");
        assert_eq!(
            repository_above(&nested),
            Some(Repository {
                name: "kalareach".to_owned(),
                branch: Some("feature/x".to_owned())
            })
        );

        std::fs::write(
            repo.join(".git/HEAD"),
            "0123456789abcdef0123456789abcdef01234567\n",
        )
        .expect("a detached HEAD");
        assert_eq!(
            repository_above(&nested).expect("a repository").branch,
            None
        );

        let worktree = root.path().join("linked");
        std::fs::create_dir_all(&worktree).expect("a worktree");
        let real = root.path().join("real-git");
        std::fs::create_dir_all(&real).expect("a git directory elsewhere");
        std::fs::write(real.join("HEAD"), "ref: refs/heads/linked-branch\n").expect("a HEAD");
        std::fs::write(
            worktree.join(".git"),
            format!("gitdir: {}\n", real.display()),
        )
        .expect("a .git file");
        assert_eq!(
            repository_above(&worktree),
            Some(Repository {
                name: "linked".to_owned(),
                branch: Some("linked-branch".to_owned())
            })
        );

        let outside = root.path().join("elsewhere");
        std::fs::create_dir_all(&outside).expect("a directory outside");
        // The temporary directory sits inside no repository, so nothing is found above it either.
        assert_eq!(repository_above(&outside), None);
    }

    // -----------------------------------------------------------------------------------------
    // Reads of the directory and the repository, stepped by the test
    // -----------------------------------------------------------------------------------------

    /// How long a test waits for a condition it is sure will come.
    const WAIT: std::time::Duration = std::time::Duration::from_secs(20);

    /// Waits until `condition` holds, and says what it waited for when it never does.
    fn until(what: &str, condition: impl Fn() -> bool) {
        let deadline = std::time::Instant::now() + WAIT;
        while !condition() {
            assert!(
                std::time::Instant::now() < deadline,
                "waited {WAIT:?} for {what}, and it did not happen"
            );
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
    }

    /// Facts whose reads are the test's: each read announces itself on `entered` and waits for the
    /// test to hand it what it finds.
    struct Stepped {
        facts: DescriptionFacts,
        entered: std::sync::mpsc::Receiver<Read>,
        hand_over: std::sync::mpsc::Sender<Found>,
    }

    impl Stepped {
        fn new() -> Self {
            let (entered_tx, entered) = std::sync::mpsc::channel();
            let (hand_over, handed) = std::sync::mpsc::channel::<Found>();
            let handed = Mutex::new(handed);
            let reader: Reader = Arc::new(move |read: &Read| {
                entered_tx
                    .send(read.clone())
                    .expect("the test is listening");
                handed
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .recv_timeout(WAIT)
                    .expect("the test hands the read what it finds")
            });
            Self {
                facts: DescriptionFacts::reading_with(false, PrivacyGeneration::new(0), reader),
                entered,
                hand_over,
            }
        }

        /// Waits for the next read to begin, and returns what it was asked to read.
        fn next_read(&self) -> Read {
            self.entered
                .recv_timeout(WAIT)
                .expect("a read began within the wait")
        }

        fn hand_over(&self, directory: &str, repository: Option<(&str, Option<&str>)>) {
            self.hand_over
                .send(Found {
                    directory: PathBuf::from(directory),
                    repository: repository.map(|(name, branch)| Repository {
                        name: name.to_owned(),
                        branch: branch.map(str::to_owned),
                    }),
                })
                .expect("the read is waiting");
        }
    }

    /// A read that began before privacy mode was enabled never applies after it was disabled: what
    /// it found is from before the transition, and the record it would join belongs to the
    /// generation after it. It is refused when nothing new has been reported since, which is what
    /// the privacy transition alone says, and when the next command names the same directory. The
    /// read that began after the transition is the one that applies.
    #[test]
    fn a_read_that_began_before_a_privacy_transition_never_applies_after_it() {
        // Nothing is reported after the transition: only the transition says the read is old.
        let step = Stepped::new();
        let facts = &step.facts;
        facts.note_command(&block("make", "/w/app", None), None);
        assert_eq!(step.next_read().directory, PathBuf::from("/w/app"));
        facts.fence(PrivacyGeneration::new(1));
        facts.release(PrivacyGeneration::new(2));
        step.hand_over("/w/app", Some(("from-before", Some("main"))));
        until("the read to be dealt with", || {
            matches!(facts.state().probe, Probe::Idle)
        });
        let record = read_at(facts, 2);
        assert_eq!(record.repository.0, None, "from before the transition");
        assert_eq!(record.directory.0, None, "from before the transition");

        // The next command names the same directory: the first read is refused, the second applies.
        let step = Stepped::new();
        let facts = &step.facts;
        facts.note_command(&block("make", "/w/app", None), None);
        assert_eq!(step.next_read().directory, PathBuf::from("/w/app"));
        facts.fence(PrivacyGeneration::new(1));
        facts.release(PrivacyGeneration::new(2));
        facts.note_command(&block("make", "/w/app", None), None);

        // The first read answers now, from before the transition. The second begins only once the
        // first has been dealt with, so its beginning is the point to look from.
        step.hand_over("/w/app", Some(("from-before", Some("main"))));
        assert_eq!(step.next_read().directory, PathBuf::from("/w/app"));
        assert_eq!(
            read_at(facts, 2).repository.0,
            None,
            "what the first read found is from before the transition"
        );

        step.hand_over("/w/app", Some(("after", Some("main"))));
        until("the read that began after the transition to apply", || {
            read_at(facts, 2).repository.0.is_some()
        });
        assert_eq!(
            read_at(facts, 2).repository.0.expect("a repository").name,
            "after"
        );
    }

    /// A read for an older command block never applies once a newer block has arrived: it would put
    /// the directory the session has left back over the one it is in.
    #[test]
    fn a_read_for_an_older_block_is_refused_when_a_newer_block_has_arrived() {
        let step = Stepped::new();
        let facts = &step.facts;
        facts.note_command(&block("ls", "/w/a", None), None);
        assert_eq!(step.next_read().directory, PathBuf::from("/w/a"));
        facts.note_command(&block("ls", "/w/b", Some(0)), None);

        step.hand_over("/w/a", Some(("a", None)));
        assert_eq!(step.next_read().directory, PathBuf::from("/w/b"));
        let record = read(facts);
        assert_eq!(record.directory.0.as_deref(), Some("b"));
        assert_eq!(record.repository.0, None, "the first read was refused");

        step.hand_over("/w/b", Some(("b", None)));
        until("the newer read to apply", || {
            read(facts).repository.0.is_some()
        });
        assert_eq!(read(facts).directory.0.as_deref(), Some("b"));
    }

    /// A command that ended in another directory than it began in is followed there: the block
    /// says where it began, and the directory the shell is in now is read when the command has
    /// ended, so nothing more has to be typed for the facts to be right. The control is a command
    /// that has only begun, which is not followed anywhere.
    #[test]
    fn a_command_that_changed_directory_is_followed_to_where_the_shell_is_now() {
        let (entered_tx, entered) = std::sync::mpsc::channel();
        let reader: Reader = Arc::new(move |read: &Read| {
            entered_tx
                .send(read.clone())
                .expect("the test is listening");
            Found {
                directory: if read.shell == Some(7) {
                    PathBuf::from("/w/new")
                } else {
                    read.directory.clone()
                },
                repository: None,
            }
        });
        let facts = DescriptionFacts::reading_with(false, PrivacyGeneration::new(0), reader);

        facts.note_command(&block("cd /w/new", "/w/old", None), Some(7));
        let started = entered.recv_timeout(WAIT).expect("a read for the start");
        assert_eq!(
            started.shell, None,
            "a command that has begun asks no shell"
        );
        until("the start's read to apply", || {
            facts.state().record.directory.as_deref() == Some("old")
        });

        facts.note_command(&block("cd /w/new", "/w/old", Some(0)), Some(7));
        let ended = entered.recv_timeout(WAIT).expect("a read for the end");
        assert_eq!(
            ended.shell,
            Some(7),
            "a command that has ended asks the shell"
        );
        until("the directory the shell is in now", || {
            facts.state().record.directory.as_deref() == Some("new")
        });
        assert_eq!(read(&facts).directory.0.as_deref(), Some("new"));
    }

    /// The repository is read again when a command ends, not only when the directory changes: a
    /// branch switched in place is the branch the facts name next.
    #[test]
    fn a_branch_switched_in_place_is_the_branch_the_facts_name_when_the_command_ends() {
        let root = tempfile::tempdir().expect("a directory");
        let repo = root.path().join("kalareach");
        std::fs::create_dir_all(repo.join(".git")).expect("a git directory");
        std::fs::write(repo.join(".git/HEAD"), "ref: refs/heads/main\n").expect("a HEAD");
        let cwd = repo.display().to_string();

        let facts = facts();
        facts.note_command(&block("git switch topic", &cwd, None), None);
        facts.note_command(&block("git switch topic", &cwd, Some(0)), None);
        until("the repository to be read", || {
            read(&facts).repository.0.is_some()
        });
        assert_eq!(
            read(&facts).repository.0.expect("a repository").branch.0,
            Some("main".to_owned())
        );

        std::fs::write(repo.join(".git/HEAD"), "ref: refs/heads/topic\n").expect("a new HEAD");
        facts.note_command(&block("git status", &cwd, None), None);
        facts.note_command(&block("git status", &cwd, Some(0)), None);
        until("the branch the command left", || {
            read(&facts)
                .repository
                .0
                .is_some_and(|repository| repository.branch.0.as_deref() == Some("topic"))
        });
    }
}
