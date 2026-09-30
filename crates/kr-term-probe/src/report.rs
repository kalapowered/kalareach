//! The record of one run against one terminal build.

use serde::Serialize;

use crate::run::{Identity, Outcome};

/// What a run found, in a form to keep beside the terminal's version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Report {
    /// The record's format.
    pub probe: &'static str,
    /// What the launcher read about the terminal outside its own answers: the application, its
    /// version and its configuration, exactly as the launcher recorded them.
    pub launcher: serde_json::Value,
    /// The terminal's own answers about itself.
    pub terminal: Identity,
    /// The window the corpus was built for, as `[columns, rows]`.
    pub window: (u32, u32),
    /// The pinned terminal library the canonical grid is built on.
    pub canonical_library: &'static str,
    /// One outcome for each step.
    pub steps: Vec<Outcome>,
    /// The counts.
    pub summary: Summary,
}

/// How many steps agreed, differed and went unanswered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Summary {
    /// Steps in the corpus.
    pub steps: usize,
    /// Steps where the terminal's cursor is where the canonical grid's is.
    pub agree: usize,
    /// Steps where it answered and the two differ.
    pub differ: usize,
    /// Steps the terminal gave no cursor position for.
    pub unanswered: usize,
}

impl Summary {
    /// Counts `steps`.
    #[must_use]
    pub fn of(steps: &[Outcome]) -> Self {
        let unanswered = steps.iter().filter(|step| step.terminal.is_none()).count();
        let agree = steps.iter().filter(|step| step.agrees).count();
        Self {
            steps: steps.len(),
            agree,
            differ: steps.len() - agree - unanswered,
            unanswered,
        }
    }
}

impl Report {
    /// Builds the record for a run.
    #[must_use]
    pub fn new(
        launcher: serde_json::Value,
        terminal: Identity,
        window: (u32, u32),
        steps: Vec<Outcome>,
    ) -> Self {
        Self {
            probe: "kr-term-probe/1",
            launcher,
            terminal,
            window,
            canonical_library: kr_term::unicode::LIBRARY.revision,
            summary: Summary::of(&steps),
            steps,
        }
    }
}
