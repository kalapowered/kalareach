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
    /// The second prompt of a queued-prompt part was entered when the agent was not shown to be
    /// running its turn (a fast model can finish it first, and a screen can fail to show one that
    /// goes on), so the prompt was not shown to wait for a turn that was still running.
    QueuedPromptNotDuringTurn,
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
            Self::QueuedPromptNotDuringTurn => json!({ "code": "queued_prompt_not_during_turn" }),
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

/// What replaces a string, or a key, of a result that held one of a login's strings.
const HELD: &str = "a text that held a string of the login's files, which is not kept";

/// The reason of a result that held one of a login's strings and has none of its own to keep.
const REASON: &str = "the part's result held a string of the login's files, so it is not kept";

/// What stands where neither text above can, because the string searched for is part of it: shorter
/// than the shortest string searched for, so no such string can be part of it.
const SHORT: &str = "not kept";

/// Whether `held` says a text holds a string searched for.
fn holding(values: &[String]) -> impl Fn(&str) -> bool + '_ {
    move |text| {
        values
            .iter()
            .any(|value| !value.is_empty() && text.contains(value.as_str()))
    }
}

/// `text`, or, where it holds a string searched for (a string that is part of the text itself),
/// [`SHORT`], or where that does too, nothing: no string that is not empty is part of nothing.
fn fixed(text: &'static str, held: &impl Fn(&str) -> bool) -> &'static str {
    [text, SHORT, ""]
        .into_iter()
        .find(|candidate| !held(candidate))
        .unwrap_or("")
}

/// Whether any string, key or number of `value`, at any depth, is held by `held`.
fn holds_decoded(value: &serde_json::Value, held: &impl Fn(&str) -> bool) -> bool {
    match value {
        serde_json::Value::String(text) => held(text),
        serde_json::Value::Number(number) => held(&number.to_string()),
        serde_json::Value::Array(items) => items.iter().any(|item| holds_decoded(item, held)),
        serde_json::Value::Object(members) => members
            .iter()
            .any(|(key, item)| held(key) || holds_decoded(item, held)),
        _ => false,
    }
}

/// Replaces each string of `value` that `held` says holds a value by `text`, and each key that does
/// by a name made of `text` and a number that no other member of the object has and that holds none;
/// a member for which no such name is found is dropped.
fn scrub(value: &mut serde_json::Value, held: &impl Fn(&str) -> bool, text: &str) {
    match value {
        serde_json::Value::String(string) => {
            if held(string) {
                text.clone_into(string);
            }
        }
        serde_json::Value::Array(items) => {
            items.iter_mut().for_each(|item| scrub(item, held, text))
        }
        serde_json::Value::Object(members) => {
            let old = std::mem::take(members);
            let count = old.len();
            let mut used: std::collections::BTreeSet<String> =
                old.keys().filter(|key| !held(key)).cloned().collect();
            for (key, mut item) in old {
                scrub(&mut item, held, text);
                if !held(&key) {
                    members.insert(key, item);
                    continue;
                }
                let name = (0..=count)
                    .map(|number| format!("{text} ({number})"))
                    .find(|name| !held(name) && !used.contains(name));
                if let Some(name) = name {
                    used.insert(name.clone());
                    members.insert(name, item);
                }
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
    /// may hold: in a string, a number or an object's key at any depth, as it is decoded (the line it
    /// writes escapes quotes, backslashes and line ends, and what is printed of its reason does not),
    /// and in the line itself.
    #[must_use]
    pub fn mentions(&self, values: &[String]) -> bool {
        let held = holding(values);
        let line = serde_json::to_string(self).unwrap_or_default();
        held(&line)
            || held(&self.part)
            || held(&self.test)
            || held(&self.outcome)
            || self.reason.as_deref().is_some_and(&held)
            || holds_decoded(&self.evidence, &held)
    }

    /// This outcome, or, where it holds one of `values`, a failure: each string and key that holds
    /// one replaced, the reason kept where it holds none and says why the part failed, else a reason
    /// of the replacement's, what the part observed and the other stops kept, and the stop and its
    /// class added. A part that passed or did not run is a failure then, so its test fails and the
    /// record says why the agent stops.
    ///
    /// Where what is left still holds one (a number's digits, the process numbers, or the part's
    /// own name), a result of the part, its process numbers and the stop alone, or, where that holds
    /// one too, of the stop alone with the part and test named `?`: that last form holds none of any
    /// string a search can be run for, which [`crate::confine::searchable`] holds to a text no such
    /// string is part of.
    #[must_use]
    pub fn without(mut self, values: &[String]) -> Self {
        if !self.mentions(values) {
            return self;
        }
        let held = holding(values);
        let said = self
            .reason
            .take()
            .filter(|reason| self.outcome == "failed" && !held(reason))
            .unwrap_or_else(|| fixed(REASON, &held).to_owned());
        let pids = self
            .evidence
            .pointer("/provenance/pids")
            .filter(|pids| {
                pids.as_array()
                    .is_some_and(|pids| pids.iter().all(Value::is_number))
            })
            .cloned();
        scrub(&mut self.evidence, &held, fixed(HELD, &held));
        if !self.evidence.is_object() {
            self.evidence = json!({});
        }
        if let Some(evidence) = self.evidence.as_object_mut() {
            evidence.insert("stop_agent".to_owned(), json!(true));
        }
        self.reason = Some(said);
        "failed".clone_into(&mut self.outcome);
        let stop = [Failure::AgentStops("secret_found")];
        let kept = self.clone().with_failures(&stop);
        if !kept.mentions(values) {
            return kept;
        }
        // What is left holds one still: the part's name or the process numbers, or the digits of a
        // number. The result then keeps the part and its process numbers where it can, so the
        // harness can still read it, and else nothing a string could be part of.
        let terminal = |part: &str, test: &str, pids: Option<&Value>| {
            let mut evidence = json!({ "stop_agent": true });
            if let (Some(pids), Some(evidence)) = (pids, evidence.as_object_mut()) {
                evidence.insert("provenance".to_owned(), json!({ "pids": pids }));
            }
            Self {
                part: part.to_owned(),
                test: test.to_owned(),
                outcome: "failed".to_owned(),
                reason: Some(fixed(SHORT, &held).to_owned()),
                evidence,
            }
            .with_failures(&stop)
        };
        let part = if held(&kept.part) { "?" } else { &kept.part };
        let test = if held(&kept.test) { "?" } else { &kept.test };
        let result = terminal(part, test, pids.as_ref());
        if !result.mentions(values) {
            return result;
        }
        // Every string a search is run for ([`crate::confine::searchable`]) holds none of the quotes,
        // braces and brackets this text is made of, and its longest run between them is shorter than
        // any such string: none can be part of it. The harness, which finds a part's process numbers
        // by the part's name, then stops everything, as it does for a result with none.
        terminal("?", "?", None)
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
    fn a_result_that_holds_a_logins_string_loses_that_string_wherever_it_is_and_is_a_failure() {
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
        assert_eq!(kept.reason.as_deref(), Some(REASON));
        // A failure whose own reason holds none keeps it, and the stop joins its codes.
        let clean_reason = Outcome::failed(
            "3",
            "a test",
            "the composer never showed",
            json!({ "note": secret.clone() }),
        );
        let kept = clean_reason.without(std::slice::from_ref(&secret));
        assert_eq!(kept.reason.as_deref(), Some("the composer never showed"));
        assert_eq!(kept.evidence["note"], HELD);
        // A part that passed, or did not run, is a failure once its result held one: the part's test
        // fails with the reason, and the record says why the agent stops.
        let in_key = Outcome::passed("1", "a test", json!({ secret.clone(): 1, "b": 2 }));
        let kept = in_key.without(std::slice::from_ref(&secret));
        assert!(!kept.mentions(std::slice::from_ref(&secret)));
        assert_eq!(kept.evidence["b"], 2);
        assert_eq!(kept.outcome, "failed", "a held result is a failure");
        assert_eq!(kept.reason.as_deref(), Some(REASON));
        assert_eq!(kept.evidence["stop_agent"], true);
        let not_run = Outcome::not_run("4", "a test", "no composer", json!([secret.clone()]));
        let kept = not_run.without(std::slice::from_ref(&secret));
        assert_eq!(kept.outcome, "failed");
        assert_eq!(kept.reason.as_deref(), Some(REASON));
        assert!(!kept.mentions(std::slice::from_ref(&secret)));
        // A part that holds none is returned as it was.
        let clean = Outcome::passed("1", "a test", json!({ "a": 1 }));
        let same = clean.clone().without(std::slice::from_ref(&secret));
        assert_eq!(same.evidence, json!({ "a": 1 }));
        assert_eq!(same.outcome, "passed");
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
    fn a_value_that_is_part_of_a_fixed_text_is_not_left_in_what_replaces_it() {
        // Both of the replacement's texts hold this, and so would a result that was replaced twice.
        let in_both = "a string of the login's files".to_owned();
        let outcome = Outcome::failed(
            "3",
            "a test",
            &format!("x {in_both} y"),
            json!({ "pids": [7], "note": format!("{in_both}!"), "provenance": { "pids": [41, 42] } }),
        );
        let kept = outcome.without(std::slice::from_ref(&in_both));
        assert!(!kept.mentions(std::slice::from_ref(&in_both)));
        assert_eq!(kept.outcome, "failed");
        assert_eq!(
            kept.part, "3",
            "the part stays, so the harness can read its result"
        );
        assert_eq!(kept.evidence["provenance"]["pids"], json!([41, 42]));
        assert_eq!(kept.evidence["stop_agent"], true);
        assert!(kept.reason.is_some(), "a failure says why");
        // The shortest text holds it too.
        let shortest = SHORT.to_owned();
        let kept = Outcome::passed("1", "a test", json!({ "a": format!("see {shortest}") }))
            .without(std::slice::from_ref(&shortest));
        assert!(!kept.mentions(std::slice::from_ref(&shortest)));
        assert_eq!(kept.outcome, "failed");
    }

    #[test]
    fn a_name_a_member_is_given_instead_of_a_key_that_held_a_value_is_not_one_in_use() {
        let secret = "sk-0123456789abcdefghij".to_owned();
        // A key that is already what the first replacement would be called, and another that is
        // already the second: both members must survive, and the held one is kept under a third.
        let first = format!("{HELD} (0)");
        let second = format!("{HELD} (1)");
        let outcome = Outcome::passed(
            "1",
            "a test",
            json!({ first.clone(): "first", second.clone(): "second", secret.clone(): "held" }),
        );
        let kept = outcome.without(std::slice::from_ref(&secret));
        let members = kept.evidence.as_object().expect("an object");
        assert_eq!(members[&first], "first");
        assert_eq!(members[&second], "second");
        assert_eq!(
            members.values().filter(|value| *value == "held").count(),
            1,
            "the held key's member is kept, under a name that was not in use"
        );
        assert!(!kept.mentions(std::slice::from_ref(&secret)));
    }

    #[test]
    fn what_cannot_be_removed_from_a_result_leaves_its_part_and_its_process_numbers_and_the_stop() {
        // A value that is a number's digits cannot be taken out by replacing a string, and one that
        // is the part's own name cannot be taken out of the part.
        let digits = "12345678901234567890".to_owned();
        let outcome = Outcome::passed(
            "3",
            "a test",
            json!({ "provenance": { "pids": [41, 42] }, "big": 12_345_678_901_234_567_890_u64 }),
        );
        let kept = outcome.without(std::slice::from_ref(&digits));
        assert!(!kept.mentions(std::slice::from_ref(&digits)));
        assert_eq!(kept.part, "3");
        assert_eq!(kept.outcome, "failed");
        assert_eq!(
            kept.evidence,
            json!({
                "stop_agent": true,
                "provenance": { "pids": [41, 42] },
                "failure_codes": [{ "code": "agent_stops", "class": "secret_found" }],
            })
        );
        let named = Outcome::failed(&"p".repeat(20), "a test", "why", json!({}));
        let kept = named.without(&["p".repeat(20)]);
        assert!(!kept.mentions(&["p".repeat(20)]));
        assert_eq!(kept.part, "?");
        assert_eq!(kept.outcome, "failed");
        assert_eq!(kept.evidence["stop_agent"], true);
    }

    #[test]
    fn a_result_is_written_in_the_form_that_holds_none_and_the_last_form_holds_none_by_construction()
     {
        // Digits and commas are a string a search can be run for, and the process numbers are such
        // a string: the result without the part's name and the process numbers is the last form.
        let digits = "41,42,43,44,45,46".to_owned();
        assert!(crate::confine::searchable(&digits));
        let outcome = Outcome::passed(
            "3",
            "a test",
            json!({ "provenance": { "pids": [41, 42, 43, 44, 45, 46, 47] }, "note": format!("x{digits}") }),
        );
        let kept = outcome.without(std::slice::from_ref(&digits));
        assert!(!kept.mentions(std::slice::from_ref(&digits)));
        assert_eq!(kept.outcome, "failed");
        assert_eq!(kept.part, "?");
        assert_eq!(
            kept.evidence,
            json!({
                "stop_agent": true,
                "failure_codes": [{ "code": "agent_stops", "class": "secret_found" }],
            })
        );
        // Every string a search can be run for lies inside one token of the last form's text or
        // crosses a quote, a brace or a bracket, which the form is made of: so none can be part of
        // it. This is the text; the longest run between such characters is shorter than the
        // shortest string searched for.
        let last = serde_json::to_string(&kept).expect("JSON");
        let longest = last
            .split(['{', '}', '[', ']', '"', '\\'])
            .map(|run| run.chars().count())
            .max()
            .unwrap_or(0);
        assert!(longest < crate::confine::SECRET_LENGTH, "{last}");
    }

    #[test]
    fn a_queued_prompt_entered_with_no_turn_shown_running_is_a_code_of_its_own() {
        assert_eq!(
            Failure::QueuedPromptNotDuringTurn.evidence(),
            json!({ "code": "queued_prompt_not_during_turn" })
        );
        let outcome = Outcome::failed("2a", "a test", "why", json!({ "login_held": true }))
            .with_failures(&[Failure::QueuedPromptNotDuringTurn]);
        assert_eq!(
            outcome.evidence["failure_codes"],
            json!([{ "code": "queued_prompt_not_during_turn" }])
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
