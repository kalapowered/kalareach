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
    /// One outcome for each step measured.
    pub steps: Vec<Outcome>,
    /// Why the run ended before the corpus did, when it did.
    pub stopped: Option<String>,
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

/// The launcher's facts with what identifies the account taken out, so a record can be kept in a
/// repository.
///
/// A record names programs and application bundles. It does not name a home directory, a user or a
/// session. The programs the window descends from are written as their names alone, and the home
/// directory, where one is written, becomes `~`. An application's own directory, such as
/// `/Applications/iTerm.app`, stays: every installation of that application has it.
#[must_use]
pub fn keep_private(mut launcher: serde_json::Value, home: Option<&str>) -> serde_json::Value {
    if let Some(ancestors) = launcher
        .get_mut("ancestors")
        .and_then(serde_json::Value::as_array_mut)
    {
        for ancestor in ancestors {
            if let Some(path) = ancestor.as_str() {
                *ancestor = serde_json::Value::String(program_name(path).to_owned());
            }
        }
    }
    if let Some(home) = home.filter(|home| home.len() > 1) {
        write_home_as_tilde(&mut launcher, home);
    }
    launcher
}

/// The last component of the path to a program, leaving a login shell's leading `-` where the
/// program was started as one.
fn program_name(path: &str) -> &str {
    path.rsplit(['/', '\\']).next().unwrap_or(path)
}

fn write_home_as_tilde(value: &mut serde_json::Value, home: &str) {
    match value {
        serde_json::Value::String(text) if text.contains(home) => {
            *text = text.replace(home, "~");
        }
        serde_json::Value::Array(items) => {
            for item in items {
                write_home_as_tilde(item, home);
            }
        }
        serde_json::Value::Object(fields) => {
            for field in fields.values_mut() {
                write_home_as_tilde(field, home);
            }
        }
        _ => {}
    }
}

impl Report {
    /// Builds the record for a run.
    #[must_use]
    pub fn new(
        launcher: serde_json::Value,
        terminal: Identity,
        window: (u32, u32),
        measured: crate::run::Measured,
    ) -> Self {
        let steps = measured.outcomes;
        Self {
            probe: "kr-term-probe/1",
            launcher,
            terminal,
            window,
            canonical_library: kr_term::unicode::LIBRARY.revision,
            summary: Summary::of(&steps),
            steps,
            stopped: measured.stopped,
        }
    }
}
