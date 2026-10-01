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

#[derive(Debug)]
struct Shared {
    state: Mutex<State>,
    /// Woken after every change, for the request the daemon has had held.
    changed: tokio::sync::Notify,
}

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
    /// The repository read that is running, and the directory waiting behind it.
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct Repository {
    name: String,
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
    /// A read is running, and this directory is waiting behind it, when one is.
    Running(Option<PathBuf>),
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
        Self {
            shared: Arc::new(Shared {
                state: Mutex::new(State {
                    generation: generation.get(),
                    private,
                    revision: 0,
                    record: Record::default(),
                    cwd: None,
                    events_recorded: 0,
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
    pub fn note_command(&self, block: &RootCommandBlockParams) {
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
        let mut probe = None;
        self.change(|state| {
            let mut moved = false;
            if state.cwd.as_deref() != Some(block.cwd.as_str()) {
                state.cwd = Some(block.cwd.clone());
                probe = Some(PathBuf::from(&block.cwd));
                // A repository belongs to the directory it was read for.
                moved |= state.record.repository.take().is_some();
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
        if let Some(directory) = probe {
            self.read_repository(directory);
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
            state.record = Record::default();
            state.cwd = None;
            state.revision += 1;
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
            state.record = Record::default();
            state.cwd = None;
            state.revision += 1;
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

    /// Starts reading the repository above `directory`, or queues it behind the read that runs.
    fn read_repository(&self, directory: PathBuf) {
        {
            let mut state = self.state();
            match &mut state.probe {
                Probe::Running(waiting) => {
                    *waiting = Some(directory);
                    return;
                }
                Probe::Idle => state.probe = Probe::Running(None),
            }
        }
        let facts = self.clone();
        let started = std::thread::Builder::new()
            .name("describe-repository".to_owned())
            .spawn(move || facts.run_reads(directory));
        if started.is_err() {
            // No thread: the facts go without a repository, and the next directory tries again.
            self.state().probe = Probe::Idle;
        }
    }

    /// Reads the directory it was given and then each one that was queued behind it.
    fn run_reads(&self, mut directory: PathBuf) {
        loop {
            let found = repository_above(&directory);
            let next = {
                let mut state = self.state();
                // Applied only to the directory it was read for.
                let apply =
                    !state.private && state.cwd.as_deref() == Some(&*directory.to_string_lossy());
                let moved = apply && state.record.repository != found;
                if moved {
                    state.record.repository = found;
                    state.revision += 1;
                }
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
                Some(next) => directory = next,
                None => return,
            }
        }
    }
}

impl State {
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

/// The last component of a path, clipped.
fn last_component(path: &str) -> Option<String> {
    Path::new(path)
        .file_name()
        .and_then(|name| name.to_str())
        .and_then(clip)
}

/// The program a command line runs: its first word that is not a variable assignment, without the
/// directory it was named by, and nothing of its arguments.
fn program_of(command: &str) -> Option<String> {
    let word = command.split_whitespace().find(|word| {
        // `NAME=value` sets a variable for the command that follows it.
        !word
            .split_once('=')
            .is_some_and(|(name, _)| !name.is_empty() && name.chars().all(is_variable_character))
    })?;
    let word = word.trim_matches(|character| matches!(character, '"' | '\''));
    let name = word.rsplit(['/', '\\']).next().unwrap_or(word);
    clip(name)
}

const fn is_variable_character(character: char) -> bool {
    character.is_ascii_alphanumeric() || character == '_'
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

/// Reads at most [`HEAD_BYTES`] of a file as text.
fn read_bounded(path: &Path) -> Option<String> {
    use std::io::Read as _;

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
        facts.note_command(&block(
            "TOKEN=hunter2 deploy --key abc",
            "/home/a/work",
            None,
        ));
        let record = read(&facts);
        assert_eq!(record.application.0.as_deref(), Some("deploy"));
        let encoded = serde_json::to_string(&record).expect("facts encode");
        assert!(
            !encoded.contains("hunter2") && !encoded.contains("abc"),
            "{encoded}"
        );
    }

    /// A command that has started has no completion, one that has ended has its own, and only
    /// the start is an event: the same command's end is not a second one.
    #[test]
    fn a_command_has_a_completion_only_once_it_has_ended_and_is_one_event() {
        let facts = facts();
        facts.note_command(&block("cargo test", "/home/a/kalareach", None));
        let started = read(&facts);
        assert_eq!(started.directory.0.as_deref(), Some("kalareach"));
        assert_eq!(started.completion.0, None);
        assert_eq!(started.events.len(), 1);
        assert_eq!(
            started.events[0].kind,
            DescriptionEventKind::CommandAccepted
        );
        assert_eq!(started.events[0].summary, "cargo");

        facts.note_command(&block("cargo test", "/home/a/kalareach", Some(1)));
        let ended = read(&facts);
        assert_eq!(ended.completion.0, Some(DescriptionCompletion::Failed));
        assert_eq!(ended.events.len(), 1, "the end is not a second event");
        assert!(ended.revision.get() > started.revision.get());

        facts.note_command(&block("make", "/home/a/kalareach", None));
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
        facts.note_command(&block("ls", "/home/a/x", None));
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
}
