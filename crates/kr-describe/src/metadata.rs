//! Deterministic titles and verified status, which need no model at all.
//!
//! Section 22 opens with the part that is true of every host: *deterministic directory, repository
//! and application titles and verified status appear immediately on every host*. They are the
//! product's floor. A host that never enables inference, a mobile device that never runs a model,
//! a WSL distribution with no data-access choice, a machine whose weights are missing and a session
//! being described right now all have a title and a status from this module, and it is computed
//! from facts the host already holds.
//!
//! Two properties are worth stating plainly, because the rest of the crate depends on them.
//!
//! **A title here is a pure function of the facts.** The same facts give the same title on every
//! host, in any order, at any time. Nothing is cached, nothing is learned and nothing is
//! asynchronous, so "immediately" is not a latency claim about a fast path; there is no other path.
//!
//! **Verified status is not text.** [`VerifiedStatus`] is built from lifecycle, reachability and
//! the host's own record of pending approvals and completion. It has no constructor that takes a
//! string, which is how section 22's rule that a model cannot *issue an instruction as verified
//! status* is expressed: there is no door for generated text to come through.

use kr_protocol::session::DisplayNumber;

/// The longest title this product shows, in Unicode codepoints.
///
/// Section 22 fixes it for generated titles. Deterministic ones use the same bound, so a title's
/// length never depends on how it was produced.
pub const MAX_TITLE_CODEPOINTS: usize = 64;

/// The longest activity text this product shows, in Unicode codepoints.
pub const MAX_ACTIVITY_CODEPOINTS: usize = 160;

/// What a host knows about a session without asking a model anything.
///
/// Every field is metadata the host holds for its own reasons: the working directory it started
/// the shell in, the repository that directory is inside, the application in the foreground. None
/// of it is content, and none of it is a transcript.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SessionFacts {
    /// The session's local display number, when it has one.
    pub display_number: Option<DisplayNumber>,
    /// The last component of the working directory.
    pub directory: Option<String>,
    /// The repository the working directory is inside.
    pub repository: Option<RepositoryFacts>,
    /// The foreground application's name.
    pub application: Option<String>,
}

/// The repository facts a title can be built from.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RepositoryFacts {
    /// The repository's own name, which is its directory's name.
    pub name: String,
    /// The checked-out branch, when the host knows it.
    pub branch: Option<String>,
}

/// A bounded, control-character-free label.
///
/// Every title in this product is one of these, however it was produced. Building one is the only
/// way to get a title, and it normalises: control characters are removed rather than escaped, runs
/// of whitespace become one space, and the result is truncated on a codepoint boundary.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Title(String);

impl Title {
    /// Builds a title from text, normalising and bounding it.
    ///
    /// Text that is empty once normalised gives [`None`], because an empty title is not a title.
    #[must_use]
    pub fn new(text: &str) -> Option<Self> {
        let cleaned = normalise(text, MAX_TITLE_CODEPOINTS);
        (!cleaned.is_empty()).then_some(Self(cleaned))
    }

    /// Returns the title's text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the title's length in Unicode codepoints.
    #[must_use]
    pub fn codepoints(&self) -> usize {
        self.0.chars().count()
    }
}

impl std::fmt::Display for Title {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Bounded activity text, normalised the same way a [`Title`] is.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ActivityText(String);

impl ActivityText {
    /// Builds activity text, normalising and bounding it.
    #[must_use]
    pub fn new(text: &str) -> Option<Self> {
        let cleaned = normalise(text, MAX_ACTIVITY_CODEPOINTS);
        (!cleaned.is_empty()).then_some(Self(cleaned))
    }

    /// Returns the text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the text's length in Unicode codepoints.
    #[must_use]
    pub fn codepoints(&self) -> usize {
        self.0.chars().count()
    }
}

impl std::fmt::Display for ActivityText {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Removes control characters, collapses whitespace and bounds the result by codepoints.
fn normalise(text: &str, limit: usize) -> String {
    let mut out = String::with_capacity(text.len().min(limit * 4));
    let mut codepoints = 0;
    let mut pending_space = false;
    for character in text.chars() {
        // A control character is removed rather than replaced: replacing it with a space would let
        // a caller pad a title with invisible bytes, and escaping it would put its name in the
        // title. Every C0 and C1 code, the line and paragraph separators and the directional
        // overrides go, which is what stops a right-to-left override reordering what is shown.
        if character.is_control()
            || matches!(character, '\u{2028}' | '\u{2029}' | '\u{200e}' | '\u{200f}')
            || ('\u{202a}'..='\u{202e}').contains(&character)
            || ('\u{2066}'..='\u{2069}').contains(&character)
        {
            continue;
        }
        if character.is_whitespace() {
            pending_space = !out.is_empty();
            continue;
        }
        if pending_space {
            if codepoints + 1 >= limit {
                break;
            }
            out.push(' ');
            codepoints += 1;
            pending_space = false;
        }
        if codepoints >= limit {
            break;
        }
        out.push(character);
        codepoints += 1;
    }
    out
}

/// A session's state, as the host and its adapters record it.
///
/// Section 22: *lifecycle, reachability, approval/input requests and completion/failure remain
/// host/adapter facts*. This is that list, and nothing outside the host writes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum VerifiedStatus {
    /// The session is being created.
    Starting,
    /// The session is running and reachable.
    Running,
    /// The host cannot reach the session's worker.
    Unreachable,
    /// An approval request is outstanding.
    AwaitingApproval,
    /// The session is waiting for input.
    AwaitingInput,
    /// Work finished, as the host recorded it.
    Completed,
    /// Work failed, as the host recorded it.
    Failed,
    /// The session has closed.
    Closed,
}

impl VerifiedStatus {
    /// Returns the stable name this status is reported under.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Starting => "starting",
            Self::Running => "running",
            Self::Unreachable => "unreachable",
            Self::AwaitingApproval => "awaiting_approval",
            Self::AwaitingInput => "awaiting_input",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Closed => "closed",
        }
    }

    /// Builds the status from the host's own facts.
    ///
    /// The order is the order a person needs: a session nobody can reach is reported as
    /// unreachable whatever it was doing, and something waiting for a person comes before
    /// something that finished, because the waiting is what they can act on.
    #[must_use]
    pub const fn of(facts: &LifecycleFacts) -> Self {
        if facts.closed {
            Self::Closed
        } else if !facts.reachable {
            Self::Unreachable
        } else if facts.approval_outstanding {
            Self::AwaitingApproval
        } else if facts.input_requested {
            Self::AwaitingInput
        } else if facts.failed {
            Self::Failed
        } else if facts.completed {
            Self::Completed
        } else if facts.started {
            Self::Running
        } else {
            Self::Starting
        }
    }
}

/// The host facts a verified status is built from.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LifecycleFacts {
    /// The session's worker has started.
    pub started: bool,
    /// The host can reach the session.
    pub reachable: bool,
    /// An approval request is outstanding.
    pub approval_outstanding: bool,
    /// The session has asked for input.
    pub input_requested: bool,
    /// The host recorded the work as complete.
    pub completed: bool,
    /// The host recorded the work as failed.
    pub failed: bool,
    /// The session has closed.
    pub closed: bool,
}

/// Where a session's shown title came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LabelSource {
    /// A person pinned it. It is never overwritten.
    Pinned,
    /// Deterministic metadata. Always available, on every host.
    Metadata,
    /// A model produced it. It is labelled as generated wherever it is shown.
    Generated,
}

impl LabelSource {
    /// Returns the stable name this source is reported under.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pinned => "pinned",
            Self::Metadata => "metadata",
            Self::Generated => "generated",
        }
    }

    /// Returns whether text from this source is labelled generated where it is shown.
    #[must_use]
    pub const fn is_generated(self) -> bool {
        matches!(self, Self::Generated)
    }
}

/// Builds the deterministic title for a session.
///
/// The order is repository, then directory, then application, then the display number, because
/// that is the order of how much a person can tell two sessions apart by. A repository with a
/// branch names both; a directory names itself; an application names itself; and a session with
/// none of those is named by the number a person types to reach it.
#[must_use]
pub fn deterministic_title(facts: &SessionFacts) -> Title {
    if let Some(repository) = &facts.repository {
        let text = match &repository.branch {
            Some(branch) if !branch.is_empty() => format!("{} ({branch})", repository.name),
            _ => repository.name.clone(),
        };
        if let Some(title) = Title::new(&text) {
            return title;
        }
    }
    if let Some(directory) = &facts.directory
        && let Some(title) = Title::new(directory)
    {
        return title;
    }
    if let Some(application) = &facts.application
        && let Some(title) = Title::new(application)
    {
        return title;
    }
    if let Some(number) = facts.display_number
        && let Some(title) = Title::new(&format!("Session {number}"))
    {
        return title;
    }
    Title(String::from("Session"))
}

/// The label and status a host shows for one session.
///
/// This is the whole answer `session.describe` gives, and every part of it is decided here rather
/// than by whatever produced the text: a pinned name wins, generated text is marked, and the status
/// beside it is the host's, not the model's.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionLabel {
    /// The title to show.
    pub title: Title,
    /// Where it came from.
    pub source: LabelSource,
    /// The activity line, when there is one. A metadata label has none.
    pub activity: Option<ActivityText>,
    /// The host's own status.
    pub status: VerifiedStatus,
}

impl SessionLabel {
    /// Builds the label a host with no generated text shows.
    #[must_use]
    pub fn from_metadata(facts: &SessionFacts, status: VerifiedStatus) -> Self {
        Self {
            title: deterministic_title(facts),
            source: LabelSource::Metadata,
            activity: None,
            status,
        }
    }
}
