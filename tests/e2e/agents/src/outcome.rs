//! The one line a part appends to the result file.
//!
//! A part that ran to its end appends `passed`, or `not_run` with its reason when the build gives it
//! nothing to run against, such as an agent that shows no composer without an account. A part that
//! failed appends nothing: its test panicked, and the harness reads the failure from the test's own
//! output and exit status. What the line carries as evidence is what the part observed, its
//! control included, so the record says what was checked as well as how it came out.

use std::io::Write;
use std::path::Path;

use serde::Serialize;

/// One part's outcome.
#[derive(Clone, Debug, Serialize)]
pub struct Outcome {
    /// The part, as the record names it: `2b`, `5a`, `6a`, `8a` or `14.03a`.
    pub part: String,
    /// The test that is the part.
    pub test: String,
    /// `passed` or `not_run`.
    pub outcome: String,
    /// Why the part did not run, when it did not.
    pub reason: Option<String>,
    /// What the part observed.
    pub evidence: serde_json::Value,
}

impl Outcome {
    /// A part that ran and held.
    #[must_use]
    pub fn passed(part: &str, test: &str, evidence: serde_json::Value) -> Self {
        Self {
            part: part.to_owned(),
            test: test.to_owned(),
            outcome: "passed".to_owned(),
            reason: None,
            evidence,
        }
    }

    /// A part the build gives nothing to run against.
    #[must_use]
    pub fn not_run(part: &str, test: &str, reason: &str, evidence: serde_json::Value) -> Self {
        Self {
            part: part.to_owned(),
            test: test.to_owned(),
            outcome: "not_run".to_owned(),
            reason: Some(reason.to_owned()),
            evidence,
        }
    }

    /// Appends the line, and says so.
    ///
    /// # Panics
    ///
    /// Panics when the result file cannot be written: an outcome nobody can read is not one.
    pub fn append(&self, result: &Path) {
        let mut line = serde_json::to_vec(self).expect("an outcome is JSON");
        line.push(b'\n');
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(result)
            .and_then(|mut file| file.write_all(&line))
            .unwrap_or_else(|error| panic!("the result file {}: {error}", result.display()));
        println!(
            "part {}: {}{}",
            self.part,
            self.outcome,
            self.reason
                .as_ref()
                .map_or_else(String::new, |reason| format!(" ({reason})"))
        );
    }
}
