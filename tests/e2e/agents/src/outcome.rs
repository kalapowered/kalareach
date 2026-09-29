//! The one line a part appends to the result file.
//!
//! A part that ran to its end appends `passed`, or `not_run` with its reason when the build gives it
//! nothing to run against, such as an agent that shows no composer without an account. A part that
//! measured a failure it can describe, such as a launch the host did not detect, appends `failed`
//! with its reason and what it observed, and its test then fails. A part whose check failed on the
//! way appends nothing: its test panicked, and the harness reads the failure from the test's own
//! output and exit status. What the line carries as evidence is what the part observed, its
//! control included, so the record says what was checked as well as how it came out.
//!
//! A failure also goes on the line as a code and what varies in it ([`Failure`]). The text that
//! described a failure can hold what the agent, its screen or the person's files said, so a record
//! of a part run with the person's login publishes the codes, and says each in words of its own,
//! and the text stays in the part's log.

use std::io::Write;
use std::path::Path;

use serde::Serialize;
use serde_json::{Value, json};

/// The key of a part's evidence that holds its failures' codes, in the order they were found.
pub const FAILURE_CODES: &str = "failure_codes";

/// One failure of a part as a code and what varies in it, the form a record publishes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Failure {
    /// A paired device's `upload.begin` was refused with this code of the protocol.
    UploadRefused(String),
    /// A paired device's `upload.begin` was accepted, and the image given was not the one it
    /// transferred.
    UploadTransferredAnotherImage,
    /// The host did not detect a manual launch as section 12 requires: `announced` live instances
    /// were announced where one was wanted. `session` names the launch where a part has two.
    LaunchNotDetected {
        /// Which launch, `A` or `B`, where the part made two.
        session: Option<&'static str>,
        /// How many live instances the host announced.
        announced: usize,
    },
    /// The agent forks a saved conversation for a second process, so two executions on one
    /// conversation's identifier were not shown.
    ResumeForks,
    /// The reply reached the device before the agent recorded the prompt, or whether it had could
    /// not be told, so no moment between them was shown.
    ReplyBeforeRecord,
    /// The session ran something other than the pinned build.
    NotPinned,
    /// The directory that held the login's key was not searched whole, or is not gone.
    KeyScanIncomplete,
    /// The part stopped on a check whose text is in its log.
    PartFailed,
    /// The agent stops here, for a reason of this class.
    AgentStops(&'static str),
}

impl Failure {
    /// The failure as its code and parameters.
    #[must_use]
    pub fn evidence(&self) -> Value {
        match self {
            Self::UploadRefused(refused) => json!({ "code": "upload_refused", "refused": refused }),
            Self::UploadTransferredAnotherImage => {
                json!({ "code": "upload_transferred_another_image" })
            }
            Self::LaunchNotDetected { session, announced } => {
                json!({ "code": "launch_not_detected", "session": session, "announced": announced })
            }
            Self::ResumeForks => json!({ "code": "resume_forks" }),
            Self::ReplyBeforeRecord => json!({ "code": "reply_before_record" }),
            Self::NotPinned => json!({ "code": "not_pinned" }),
            Self::KeyScanIncomplete => json!({ "code": "key_scan_incomplete" }),
            Self::PartFailed => json!({ "code": "part_failed" }),
            Self::AgentStops(class) => json!({ "code": "agent_stops", "class": class }),
        }
    }
}

/// One part's outcome.
#[derive(Clone, Debug, Serialize)]
pub struct Outcome {
    /// The part, as the record names it: `2b`, `5a`, `6a`, `8a` or `14.03a`.
    pub part: String,
    /// The test that is the part.
    pub test: String,
    /// `passed`, `failed` or `not_run`.
    pub outcome: String,
    /// Why the part did not run, when it did not.
    pub reason: Option<String>,
    /// What the part observed.
    pub evidence: serde_json::Value,
}

impl Outcome {
    /// The outcome with `failures` added to its evidence's failure codes, each once.
    #[must_use]
    pub fn with_failures(mut self, failures: &[Failure]) -> Self {
        if !self.evidence.is_object() {
            self.evidence = json!({});
        }
        if let Some(evidence) = self.evidence.as_object_mut() {
            let codes = evidence.entry(FAILURE_CODES).or_insert_with(|| json!([]));
            if let Some(codes) = codes.as_array_mut() {
                for failure in failures {
                    let code = failure.evidence();
                    if !codes.contains(&code) {
                        codes.push(code);
                    }
                }
            }
        }
        self
    }

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

    /// A part that measured a failure it can describe, with what it observed.
    #[must_use]
    pub fn failed(part: &str, test: &str, reason: &str, evidence: serde_json::Value) -> Self {
        Self {
            part: part.to_owned(),
            test: test.to_owned(),
            outcome: "failed".to_owned(),
            reason: Some(reason.to_owned()),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failures_join_the_evidence_as_codes_each_once() {
        let outcome = Outcome::failed(
            "1",
            "a test",
            "a text that can hold anything",
            json!({ "login_held": true }),
        )
        .with_failures(&[
            Failure::UploadRefused("INVALID_ARGUMENT".to_owned()),
            Failure::LaunchNotDetected {
                session: None,
                announced: 0,
            },
        ])
        .with_failures(&[Failure::UploadRefused("INVALID_ARGUMENT".to_owned())]);
        assert_eq!(
            outcome.evidence,
            json!({
                "login_held": true,
                "failure_codes": [
                    { "code": "upload_refused", "refused": "INVALID_ARGUMENT" },
                    { "code": "launch_not_detected", "session": null, "announced": 0 }
                ]
            })
        );
        assert!(
            !outcome.evidence.to_string().contains("anything"),
            "no text of the failure goes to the evidence"
        );
    }

    #[test]
    fn a_part_without_evidence_still_carries_its_codes() {
        let outcome = Outcome::not_run("4", "a test", "why", json!(null))
            .with_failures(&[Failure::AgentStops("guarded_file_changed")]);
        assert_eq!(
            outcome.evidence,
            json!({ "failure_codes": [{ "code": "agent_stops", "class": "guarded_file_changed" }] })
        );
    }
}
