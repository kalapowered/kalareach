//! What a description is built from, and what advances the revision.
//!
//! This module is the only door into the description queue, and that is the point. Section 22 says
//! *no inference lies on the shell's input/query/resize path*, and the way this crate holds to it
//! is not a measurement: [`ContextSignal`] has no variant for a keystroke, a terminal query or a
//! resize, so there is nothing for the shell's hot path to call. A path that cannot express the
//! request cannot be on it.
//!
//! # The revision, and why it moves as slowly as it does
//!
//! Section 22 advances the context revision on *meaningful CWD, foreground application, selected
//! thread, task-intent and completion changes, not individual tokens/spinners*, and then asks for
//! those events to be coalesced *so a long active turn can receive useful text without invalidating
//! every job*.
//!
//! Those two sentences pull against each other unless the coalescing is what advances the revision,
//! so that is how it is built. [`ContextTracker::observe`] records a change and moves nothing. The
//! revision advances once, in [`ContextTracker::settle`], when the debounce has elapsed **since the
//! first pending change** rather than since the last one. A quiet session settles two seconds after
//! its one change. A session changing continuously settles every two seconds, not never, and a job
//! admitted at one revision survives the whole of that window.
//!
//! # What may be in a context, and what may not
//!
//! Section 22 bounds the input to *directory/repository metadata and authorised recent semantic
//! events* and excludes *raw keystrokes, hidden input, environment values, file bodies and full
//! histories*. [`InputClass`] is that list, [`admits`] is the decision, and
//! [`ContextBuilder`] is the only way to build a context, so an excluded class has no route in.
//!
//! Project text - a repository name, a branch, a task intent somebody typed - is *treated as data*.
//! It is carried, because a title without it would be useless, and it is carried as data:
//! [`ProjectText`] marks it, the prompt puts it in a delimited data section, and the grammar bounds
//! what the model may produce whatever the text says. An instruction inside a branch name is a
//! branch name.

use kr_protocol::ids::{EnvironmentId, SessionEpoch, SessionId};
use serde::{Deserialize, Serialize};

use crate::metadata::RepositoryFacts;
use crate::time::Reading;

/// The most recent semantic events one context may carry.
pub const MAX_RECENT_EVENTS: usize = 8;

/// The longest summary one semantic event may carry, in Unicode codepoints.
pub const MAX_EVENT_SUMMARY_CODEPOINTS: usize = 120;

/// The longest piece of project text one context may carry, in Unicode codepoints.
pub const MAX_PROJECT_TEXT_CODEPOINTS: usize = 120;

/// A context revision.
///
/// It is per session and it only ever increases. A result carries the revision it was produced
/// under, and a result whose revision is not the one in force describes a session that has since
/// moved on.
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct ContextRevision(u64);

impl ContextRevision {
    /// The revision a session starts at.
    pub const INITIAL: Self = Self(0);

    /// Wraps a raw revision.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the raw revision.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Returns the next revision.
    #[must_use]
    pub const fn next(self) -> Self {
        Self(self.0.saturating_add(1))
    }
}

/// The binding a description was built under.
///
/// A session is bound to a desktop, an application and an epoch. Generated text about a session in
/// one binding says nothing about the same session in another, so the binding travels with the job
/// and a result whose binding has changed is refused rather than shown against the new one.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ContextBinding(String);

impl ContextBinding {
    /// Names a binding.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }

    /// Returns the binding's name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A meaningful change to what a session is doing.
///
/// The five variants are section 22's five, and there are no others. A token arriving, a spinner
/// turning, a key being pressed, a terminal answering a device query and a window being resized are
/// all absent, which is the whole of how this crate stays off the input path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ContextSignal {
    /// The working directory changed.
    WorkingDirectory {
        /// The directory's last component.
        directory: String,
        /// The repository it is inside, when it is inside one.
        repository: Option<RepositoryFacts>,
    },
    /// The foreground application changed.
    ForegroundApplication(String),
    /// The selected thread changed.
    SelectedThread(String),
    /// The task intent changed: what this session has been asked to do.
    TaskIntent(String),
    /// Work completed, or failed, as the host recorded it.
    Completion(Completion),
}

impl ContextSignal {
    /// Returns the stable name this kind of signal is reported under.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::WorkingDirectory { .. } => "working_directory",
            Self::ForegroundApplication(_) => "foreground_application",
            Self::SelectedThread(_) => "selected_thread",
            Self::TaskIntent(_) => "task_intent",
            Self::Completion(_) => "completion",
        }
    }
}

/// How work ended, as the host recorded it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Completion {
    /// It finished.
    Succeeded,
    /// It failed.
    Failed,
}

/// A class of input, and whether a description context may carry it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum InputClass {
    /// The working directory's own name.
    DirectoryMetadata,
    /// The repository's name and branch.
    RepositoryMetadata,
    /// An authorised recent semantic event.
    SemanticEvent,
    /// Text that came from the project: a repository name, a branch, an intent somebody typed.
    ProjectText,
    /// Raw keystrokes.
    RawKeystrokes,
    /// Input the terminal was hiding: a password prompt, a hidden field.
    HiddenInput,
    /// An environment variable's value.
    EnvironmentValue,
    /// The contents of a file.
    FileBody,
    /// A whole session history.
    FullHistory,
}

impl InputClass {
    /// Returns the stable name this class is reported under.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DirectoryMetadata => "directory_metadata",
            Self::RepositoryMetadata => "repository_metadata",
            Self::SemanticEvent => "semantic_event",
            Self::ProjectText => "project_text",
            Self::RawKeystrokes => "raw_keystrokes",
            Self::HiddenInput => "hidden_input",
            Self::EnvironmentValue => "environment_value",
            Self::FileBody => "file_body",
            Self::FullHistory => "full_history",
        }
    }
}

/// What a class of input may do in a description context.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Admits {
    /// It is carried as it is.
    AsMetadata,
    /// It is carried inside a data section, and never as an instruction.
    AsData,
    /// It is excluded. Section 22 names it, and there is no configuration that lets it in.
    Never,
}

/// Returns what a class of input may do.
///
/// The five exclusions are absolute. They are not a default somebody may change, and they are not
/// subject to a grant: there is no authority in this product that admits a keystroke into a
/// description, because a description is about what a session is doing rather than about what
/// somebody typed.
#[must_use]
pub const fn admits(class: InputClass) -> Admits {
    match class {
        InputClass::DirectoryMetadata
        | InputClass::RepositoryMetadata
        | InputClass::SemanticEvent => Admits::AsMetadata,
        InputClass::ProjectText => Admits::AsData,
        InputClass::RawKeystrokes
        | InputClass::HiddenInput
        | InputClass::EnvironmentValue
        | InputClass::FileBody
        | InputClass::FullHistory => Admits::Never,
    }
}

/// Text that came from the project, carried as data.
///
/// Wrapping it in a type is what makes the prompt's data section unavoidable: a
/// [`DescriptionContext`] has nowhere to put a bare string, so project text cannot arrive as
/// anything but data. It is deliberately not decodable from the wire: a derived decoder would
/// build one without its bounds or its filtering, which is the one way a caller could get project
/// text into a context without going through [`ProjectText::new`].
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProjectText(String);

impl ProjectText {
    /// Takes project text, bounding it and removing control characters.
    ///
    /// Text that is empty once bounded gives [`None`].
    #[must_use]
    pub fn new(text: &str) -> Option<Self> {
        let cleaned: String = text
            .chars()
            .filter(|character| !character.is_control())
            .take(MAX_PROJECT_TEXT_CODEPOINTS)
            .collect();
        let trimmed = cleaned.trim();
        (!trimmed.is_empty()).then(|| Self(trimmed.to_owned()))
    }

    /// Returns the text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// An authorised recent semantic event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SemanticEvent {
    /// The cursor this event sits at in the session's semantic stream.
    pub cursor: u64,
    /// What kind of event it is.
    pub kind: SemanticEventKind,
    /// A bounded summary, carried as data.
    pub summary: ProjectText,
}

/// The kinds of semantic event a description may be built from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SemanticEventKind {
    /// A command was accepted.
    CommandAccepted,
    /// A task started.
    TaskStarted,
    /// A task finished.
    TaskCompleted,
    /// An approval was requested.
    ApprovalRequested,
    /// A file changed. The path is carried; the contents are not.
    FileChanged,
}

/// The interval of the session's semantic stream a description was built from.
///
/// Section 22 requires the source cursor interval in the result, and it is here rather than
/// reconstructed later: a description is about a range of events, and a reader who cannot see which
/// range cannot tell whether it is about work that has since finished.
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(deny_unknown_fields)]
pub struct CursorInterval {
    /// The first cursor covered.
    pub from: u64,
    /// The last cursor covered.
    pub to: u64,
}

impl CursorInterval {
    /// Builds an interval, ordering its ends.
    #[must_use]
    pub const fn new(from: u64, to: u64) -> Self {
        if from <= to {
            Self { from, to }
        } else {
            Self { from: to, to: from }
        }
    }
}

/// The bounded, filtered input one description is built from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DescriptionContext {
    environment_id: EnvironmentId,
    session_id: SessionId,
    session_epoch: SessionEpoch,
    binding: ContextBinding,
    revision: ContextRevision,
    directory: Option<ProjectText>,
    repository: Option<ProjectText>,
    branch: Option<ProjectText>,
    application: Option<ProjectText>,
    thread: Option<ProjectText>,
    intent: Option<ProjectText>,
    events: Vec<SemanticEvent>,
    cursor: CursorInterval,
}

impl DescriptionContext {
    /// Returns the environment this context belongs to.
    #[must_use]
    pub const fn environment_id(&self) -> &EnvironmentId {
        &self.environment_id
    }

    /// Returns the session.
    #[must_use]
    pub const fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    /// Returns the session epoch.
    #[must_use]
    pub const fn session_epoch(&self) -> SessionEpoch {
        self.session_epoch
    }

    /// Returns the binding.
    #[must_use]
    pub const fn binding(&self) -> &ContextBinding {
        &self.binding
    }

    /// Returns the revision this context is at.
    #[must_use]
    pub const fn revision(&self) -> ContextRevision {
        self.revision
    }

    /// Returns the semantic events this context carries.
    #[must_use]
    pub fn events(&self) -> &[SemanticEvent] {
        &self.events
    }

    /// Returns the cursor interval this context covers.
    #[must_use]
    pub const fn cursor(&self) -> CursorInterval {
        self.cursor
    }

    /// Returns the directory's name, when it has one.
    #[must_use]
    pub fn directory(&self) -> Option<&str> {
        self.directory.as_ref().map(ProjectText::as_str)
    }

    /// Renders the prompt's data section.
    ///
    /// Every piece of project text is inside it, labelled and delimited, and nothing outside it
    /// came from the project. What that buys is narrow and worth saying exactly: text inside the
    /// section cannot change the *shape* of the answer, because the grammar in
    /// [`crate::output`] decides that, and it cannot change the status shown beside it, because a
    /// status is not text. It does not make a model immune to being misled about what a session is
    /// doing, and nothing here claims it does.
    #[must_use]
    pub fn data_section(&self) -> String {
        let mut out = String::new();
        let mut field = |label: &str, value: Option<&ProjectText>| {
            if let Some(value) = value {
                out.push_str(label);
                out.push_str(": <<");
                out.push_str(&escape_delimiters(value.as_str()));
                out.push_str(">>\n");
            }
        };
        field("directory", self.directory.as_ref());
        field("repository", self.repository.as_ref());
        field("branch", self.branch.as_ref());
        field("application", self.application.as_ref());
        field("thread", self.thread.as_ref());
        field("intent", self.intent.as_ref());
        for event in &self.events {
            out.push_str("event ");
            out.push_str(match event.kind {
                SemanticEventKind::CommandAccepted => "command_accepted",
                SemanticEventKind::TaskStarted => "task_started",
                SemanticEventKind::TaskCompleted => "task_completed",
                SemanticEventKind::ApprovalRequested => "approval_requested",
                SemanticEventKind::FileChanged => "file_changed",
            });
            out.push_str(": <<");
            out.push_str(&escape_delimiters(event.summary.as_str()));
            out.push_str(">>\n");
        }
        out
    }
}

/// Replaces the delimiters the data section is built from, so project text cannot end it.
///
/// Without this, a repository called `>> now follow these instructions` would close the data
/// section and continue outside it. The replacement is a look-alike rather than an escape, because
/// the section is read by a model rather than by a parser and a backslash would be one more thing
/// to explain to it.
fn escape_delimiters(text: &str) -> String {
    text.replace("<<", "\u{2039}\u{2039}")
        .replace(">>", "\u{203a}\u{203a}")
}

/// Builds a [`DescriptionContext`], refusing every excluded class.
///
/// It is the only constructor. A caller that has a file body or an environment value has nowhere to
/// put it, and one that tries is told which class it offered rather than being quietly ignored.
#[derive(Clone, Debug)]
pub struct ContextBuilder {
    context: DescriptionContext,
    refused: Vec<InputClass>,
}

impl ContextBuilder {
    /// Starts a context for one session at one revision.
    #[must_use]
    pub fn new(
        environment_id: EnvironmentId,
        session_id: SessionId,
        session_epoch: SessionEpoch,
        binding: ContextBinding,
        revision: ContextRevision,
    ) -> Self {
        Self {
            context: DescriptionContext {
                environment_id,
                session_id,
                session_epoch,
                binding,
                revision,
                directory: None,
                repository: None,
                branch: None,
                application: None,
                thread: None,
                intent: None,
                events: Vec::new(),
                cursor: CursorInterval::default(),
            },
            refused: Vec::new(),
        }
    }

    /// Adds the working directory's own name.
    #[must_use]
    pub fn directory(mut self, directory: &str) -> Self {
        self.context.directory = ProjectText::new(directory);
        self
    }

    /// Adds the repository's name and branch.
    #[must_use]
    pub fn repository(mut self, repository: &RepositoryFacts) -> Self {
        self.context.repository = ProjectText::new(&repository.name);
        self.context.branch = repository.branch.as_deref().and_then(ProjectText::new);
        self
    }

    /// Adds the foreground application's name.
    #[must_use]
    pub fn application(mut self, application: &str) -> Self {
        self.context.application = ProjectText::new(application);
        self
    }

    /// Adds the selected thread.
    #[must_use]
    pub fn thread(mut self, thread: &str) -> Self {
        self.context.thread = ProjectText::new(thread);
        self
    }

    /// Adds the task intent.
    #[must_use]
    pub fn intent(mut self, intent: &str) -> Self {
        self.context.intent = ProjectText::new(intent);
        self
    }

    /// Adds an authorised recent semantic event, keeping at most the newest
    /// [`MAX_RECENT_EVENTS`] of them.
    #[must_use]
    pub fn event(mut self, event: SemanticEvent) -> Self {
        self.context.events.push(event);
        self.context.events.sort_by_key(|event| event.cursor);
        while self.context.events.len() > MAX_RECENT_EVENTS {
            self.context.events.remove(0);
        }
        let first = self.context.events.first().map_or(0, |event| event.cursor);
        let last = self.context.events.last().map_or(0, |event| event.cursor);
        self.context.cursor = CursorInterval::new(first, last);
        self
    }

    /// Offers an input of some class, which is carried only when section 22 admits it.
    ///
    /// This is the entry point a host with an unclassified input uses. An excluded class is
    /// recorded and dropped: the context is still built, because a description with less in it is
    /// better than no description, and [`Self::refused`] says what was left out.
    #[must_use]
    pub fn offer(mut self, class: InputClass, value: &str) -> Self {
        match admits(class) {
            Admits::Never => {
                self.refused.push(class);
                self
            }
            Admits::AsMetadata | Admits::AsData => match class {
                InputClass::DirectoryMetadata => self.directory(value),
                InputClass::RepositoryMetadata => {
                    self.context.repository = ProjectText::new(value);
                    self
                }
                InputClass::ProjectText => self.intent(value),
                InputClass::SemanticEvent => self,
                InputClass::RawKeystrokes
                | InputClass::HiddenInput
                | InputClass::EnvironmentValue
                | InputClass::FileBody
                | InputClass::FullHistory => self,
            },
        }
    }

    /// Returns the classes this builder refused.
    #[must_use]
    pub fn refused(&self) -> &[InputClass] {
        &self.refused
    }

    /// Returns the context.
    #[must_use]
    pub fn build(self) -> DescriptionContext {
        self.context
    }
}

/// What observing a signal did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Observed {
    /// The signal repeated what the tracker already held. Nothing changed and nothing is pending.
    Unchanged,
    /// The change was recorded and is waiting for the debounce to elapse. The revision has not
    /// moved, so a job admitted at the current revision is still valid.
    Pending,
    /// Privacy mode is on for this session. Nothing was recorded at all.
    ///
    /// Section 24 disables description processing *prospectively*, and capture is the first part
    /// of it: a context kept while private would be private content waiting for the fence to drop.
    Fenced,
}

/// What settling did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Settled {
    /// Nothing was pending, or the debounce has not elapsed. The revision is unchanged.
    NotYet,
    /// The pending changes became one revision.
    Advanced {
        /// The revision now in force.
        revision: ContextRevision,
        /// How many changes it covers.
        coalesced: usize,
    },
}

/// Tracks one session's context and decides when its revision moves.
#[derive(Clone, Debug)]
pub struct ContextTracker {
    revision: ContextRevision,
    debounce_ms: u64,
    directory: Option<String>,
    repository: Option<RepositoryFacts>,
    application: Option<String>,
    thread: Option<String>,
    intent: Option<String>,
    completion: Option<Completion>,
    pending: usize,
    pending_since_ms: Option<u64>,
}

impl ContextTracker {
    /// Builds a tracker with a debounce.
    #[must_use]
    pub const fn new(debounce_ms: u64) -> Self {
        Self {
            revision: ContextRevision::INITIAL,
            debounce_ms,
            directory: None,
            repository: None,
            application: None,
            thread: None,
            intent: None,
            completion: None,
            pending: 0,
            pending_since_ms: None,
        }
    }

    /// Returns the revision in force.
    #[must_use]
    pub const fn revision(&self) -> ContextRevision {
        self.revision
    }

    /// Returns how many changes are waiting to be coalesced.
    #[must_use]
    pub const fn pending(&self) -> usize {
        self.pending
    }

    /// Returns the facts this tracker holds, for a context or a deterministic title.
    #[must_use]
    pub fn facts(&self) -> crate::metadata::SessionFacts {
        crate::metadata::SessionFacts {
            display_number: None,
            directory: self.directory.clone(),
            repository: self.repository.clone(),
            application: self.application.clone(),
        }
    }

    /// Returns the completion the host last recorded, when it has recorded one.
    #[must_use]
    pub const fn completion(&self) -> Option<Completion> {
        self.completion
    }

    /// Forgets every piece of context this tracker was holding.
    ///
    /// The revision does not move, and that is deliberate: a result produced before this still
    /// carries an older revision and is still refused as stale. What goes is the content - the
    /// directory, the repository, the application, the thread, the intent, the completion and every
    /// pending change - so nothing captured before this moment can reach a later job.
    pub fn forget(&mut self) {
        self.directory = None;
        self.repository = None;
        self.application = None;
        self.thread = None;
        self.intent = None;
        self.completion = None;
        self.pending = 0;
        self.pending_since_ms = None;
    }

    /// Returns the task intent this session was last given.
    #[must_use]
    pub fn intent(&self) -> Option<&str> {
        self.intent.as_deref()
    }

    /// Returns the thread this session has selected.
    #[must_use]
    pub fn thread(&self) -> Option<&str> {
        self.thread.as_deref()
    }

    /// Records a signal.
    ///
    /// A signal that repeats what the tracker already holds changes nothing at all, which is what
    /// stops a shell that re-announces its working directory every prompt from advancing anything.
    pub fn observe(&mut self, signal: ContextSignal, now: Reading) -> Observed {
        let changed = match signal {
            ContextSignal::WorkingDirectory {
                directory,
                repository,
            } => {
                let changed = self.directory.as_deref() != Some(directory.as_str())
                    || self.repository != repository;
                if changed {
                    self.directory = Some(directory);
                    self.repository = repository;
                }
                changed
            }
            ContextSignal::ForegroundApplication(application) => {
                let changed = self.application.as_deref() != Some(application.as_str());
                if changed {
                    self.application = Some(application);
                }
                changed
            }
            ContextSignal::SelectedThread(thread) => {
                let changed = self.thread.as_deref() != Some(thread.as_str());
                if changed {
                    self.thread = Some(thread);
                }
                changed
            }
            ContextSignal::TaskIntent(intent) => {
                let changed = self.intent.as_deref() != Some(intent.as_str());
                if changed {
                    self.intent = Some(intent);
                    // A new intent is a new task, so whatever the last one finished as no longer
                    // describes this session. Without this, a second task that succeeded after a
                    // first that succeeded would record no change at all.
                    self.completion = None;
                }
                changed
            }
            ContextSignal::Completion(completion) => {
                let changed = self.completion != Some(completion);
                if changed {
                    self.completion = Some(completion);
                }
                changed
            }
        };
        if !changed {
            return Observed::Unchanged;
        }
        self.pending += 1;
        // The window starts at the *first* pending change and is never extended. A session that
        // changes continuously therefore settles every debounce rather than never, which is what
        // section 22's "a long active turn can receive useful text" asks for.
        self.pending_since_ms.get_or_insert(now.monotonic_ms());
        Observed::Pending
    }

    /// Advances the revision when the debounce has elapsed since the first pending change.
    pub fn settle(&mut self, now: Reading) -> Settled {
        let Some(since) = self.pending_since_ms else {
            return Settled::NotYet;
        };
        if now.since_ms(since) < self.debounce_ms {
            return Settled::NotYet;
        }
        let coalesced = self.pending;
        self.pending = 0;
        self.pending_since_ms = None;
        self.revision = self.revision.next();
        Settled::Advanced {
            revision: self.revision,
            coalesced,
        }
    }
}
