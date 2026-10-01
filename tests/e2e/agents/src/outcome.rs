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
    /// The host did not detect a manual launch as section 12 requires, for `cause` (one of
    /// [`crate::detect::Undetected::CAUSES`]) with `announced` live instances announced. `session`
    /// names the launch where a part has two.
    LaunchNotDetected {
        /// Which launch, `A` or `B`, where the part made two.
        session: Option<&'static str>,
        /// Why it was not detected.
        cause: &'static str,
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
    /// The session's environment held a variable the build list clears.
    EnvironmentNotClear,
    /// The names of the variables the session's shell exports could not be read, so that none the
    /// build list clears is exported was not established.
    EnvironmentNotRead,
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
            Self::LaunchNotDetected {
                session,
                cause,
                announced,
            } => {
                json!({ "code": "launch_not_detected", "session": session, "cause": cause, "announced": announced })
            }
            Self::ResumeForks => json!({ "code": "resume_forks" }),
            Self::ReplyBeforeRecord => json!({ "code": "reply_before_record" }),
            Self::NotPinned => json!({ "code": "not_pinned" }),
            Self::EnvironmentNotClear => json!({ "code": "environment_not_clear" }),
            Self::EnvironmentNotRead => json!({ "code": "environment_not_read" }),
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

/// What replaces a string of a result that held one of a login's strings.
const HELD: &str = "a text that held a string of the login's files, which is not kept";

/// What a result is when nothing of it can be kept.
const NOT_KEPT: &str = "the part's result held a string of the login's files, so it is not kept";

/// Whether any string or key of `value`, at any depth, is held by `held`.
fn holds_decoded(value: &serde_json::Value, held: &impl Fn(&str) -> bool) -> bool {
    match value {
        serde_json::Value::String(text) => held(text),
        serde_json::Value::Array(items) => items.iter().any(|item| holds_decoded(item, held)),
        serde_json::Value::Object(members) => members
            .iter()
            .any(|(key, item)| held(key) || holds_decoded(item, held)),
        _ => false,
    }
}

/// Replaces each string and key of `value` that `held` says holds a value by [`HELD`], keys made
/// distinct by a number so two replaced keys do not become one.
fn scrub(value: &mut serde_json::Value, held: &impl Fn(&str) -> bool) {
    match value {
        serde_json::Value::String(text) => {
            if held(text) {
                *text = HELD.to_owned();
            }
        }
        serde_json::Value::Array(items) => items.iter_mut().for_each(|item| scrub(item, held)),
        serde_json::Value::Object(members) => {
            let old = std::mem::take(members);
            for (index, (key, mut item)) in old.into_iter().enumerate() {
                scrub(&mut item, held);
                let key = if held(&key) {
                    format!("{HELD} ({index})")
                } else {
                    key
                };
                members.insert(key, item);
            }
        }
        _ => {}
    }
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

    /// Whether this outcome holds any of `values`, the strings of a login's files, which no record
    /// may hold: in a string or an object's key at any depth, as it is decoded (the line it writes
    /// escapes quotes, backslashes and line ends, and what is printed of its reason does not), and in
    /// the line itself.
    #[must_use]
    pub fn mentions(&self, values: &[String]) -> bool {
        let line = serde_json::to_string(self).unwrap_or_default();
        let held = |text: &str| {
            values
                .iter()
                .any(|value| !value.is_empty() && text.contains(value.as_str()))
        };
        held(&line)
            || held(&self.part)
            || held(&self.test)
            || held(&self.outcome)
            || self.reason.as_deref().is_some_and(held)
            || holds_decoded(&self.evidence, &held)
    }

    /// This outcome, or, where it holds one of `values`, the same outcome with each string that
    /// holds one replaced by a fixed text, wherever it is (the reason, a key or a value of the
    /// evidence, at any depth), the stop recorded and the failure's class added: what the part
    /// observed and the other stops stay, and nothing it printed of what a tool showed. Where what
    /// is left still holds one (the part's name or a fixed text colliding with a value), a result
    /// of nothing but the stop.
    #[must_use]
    pub fn without(mut self, values: &[String]) -> Self {
        if !self.mentions(values) {
            return self;
        }
        let held = |text: &str| {
            values
                .iter()
                .any(|value| !value.is_empty() && text.contains(value.as_str()))
        };
        if self.reason.as_deref().is_some_and(held) {
            self.reason = Some(HELD.to_owned());
        }
        scrub(&mut self.evidence, &held);
        if !self.evidence.is_object() {
            self.evidence = json!({});
        }
        if let Some(evidence) = self.evidence.as_object_mut() {
            evidence.insert("stop_agent".to_owned(), json!(true));
        }
        let mut kept = self.with_failures(&[Failure::AgentStops("secret_found")]);
        if kept.mentions(values) {
            kept = Self {
                part: "?".to_owned(),
                test: "?".to_owned(),
                outcome: "failed".to_owned(),
                reason: Some(NOT_KEPT.to_owned()),
                evidence: json!({ "stop_agent": true }),
            };
        }
        kept
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
                cause: "not_one_instance",
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
                    { "code": "launch_not_detected", "session": null, "cause": "not_one_instance", "announced": 0 }
                ]
            })
        );
        assert!(
            !outcome.evidence.to_string().contains("anything"),
            "no text of the failure goes to the evidence"
        );
    }

    #[test]
    fn a_result_that_holds_a_logins_string_loses_that_string_wherever_it_is_and_keeps_the_rest() {
        let secret = "sk-0123456789abcdefghij".to_owned();
        let quoting = Outcome::failed(
            "3",
            "a test",
            &format!("the screen showed {secret} and more"),
            json!({
                "login_held": true,
                "provenance": { "pids": [41, 42], "executed": [{ "command": format!("run {secret}") }] },
                "failure_codes": [{ "code": "part_failed" }],
            }),
        );
        assert!(quoting.mentions(std::slice::from_ref(&secret)));
        assert!(!quoting.mentions(&["something else long".to_owned()]));
        let kept = quoting.without(std::slice::from_ref(&secret));
        assert!(!kept.mentions(std::slice::from_ref(&secret)));
        assert_eq!(kept.outcome, "failed");
        assert_eq!(kept.evidence["stop_agent"], true);
        assert_eq!(
            kept.evidence["provenance"]["pids"],
            json!([41, 42]),
            "what else it observed stays"
        );
        assert_eq!(
            kept.evidence["failure_codes"],
            json!([{ "code": "part_failed" }, { "code": "agent_stops", "class": "secret_found" }]),
            "the codes it had stay, and the stop is added"
        );
        assert_eq!(kept.reason.as_deref(), Some(HELD));
        // In a key, and in the evidence of a part that passed.
        let in_key = Outcome::passed("1", "a test", json!({ secret.clone(): 1, "b": 2 }));
        let kept = in_key.without(std::slice::from_ref(&secret));
        assert!(!kept.mentions(std::slice::from_ref(&secret)));
        assert_eq!(kept.evidence["b"], 2);
        assert_eq!(
            kept.outcome, "passed",
            "a passed part keeps its outcome; the stop is what is recorded"
        );
        // A part that holds none is returned as it was.
        let clean = Outcome::passed("1", "a test", json!({ "a": 1 }));
        assert_eq!(
            clean
                .clone()
                .without(std::slice::from_ref(&secret))
                .evidence,
            json!({ "a": 1 })
        );
        assert_eq!(clean.without(&[]).evidence, json!({ "a": 1 }));
    }

    #[test]
    fn a_value_with_a_quote_a_backslash_or_a_line_end_is_found_as_it_is_decoded() {
        // The line a result writes escapes these, so the raw value is not in it.
        for secret in [
            "abc\"def-0123456789",
            "abc\\def-0123456789",
            "abc\ndef-0123456789xyz",
        ] {
            let outcome = Outcome::failed(
                "3",
                "a test",
                &format!("the screen showed {secret} and more"),
                json!({ "note": format!("left {secret}") }),
            );
            let line = serde_json::to_string(&outcome).expect("JSON");
            assert!(!line.contains(secret), "the line escapes it: {line}");
            let values = [secret.to_owned()];
            assert!(outcome.mentions(&values), "{secret:?}");
            let kept = outcome.without(&values);
            assert!(!kept.mentions(&values), "{secret:?}");
            assert!(
                kept.reason
                    .as_deref()
                    .is_some_and(|reason| !reason.contains(secret))
            );
        }
    }

    #[test]
    fn a_value_that_collides_with_a_fixed_text_leaves_a_result_of_nothing_but_the_stop() {
        // A value that is the part's name or the replacement's own text cannot be removed from them.
        let colliding = HELD.to_owned();
        let outcome = Outcome::failed(
            "3",
            "a test",
            &format!("x {colliding} y"),
            json!({ "a": 1 }),
        );
        let kept = outcome.without(std::slice::from_ref(&colliding));
        assert!(!kept.mentions(std::slice::from_ref(&colliding)));
        assert_eq!(kept.evidence, json!({ "stop_agent": true }));
        let named = Outcome::failed(&"p".repeat(20), "a test", "why", json!({}));
        let kept = named.without(&["p".repeat(20)]);
        assert!(!kept.mentions(&["p".repeat(20)]));
        assert_eq!(kept.reason.as_deref(), Some(NOT_KEPT));
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
