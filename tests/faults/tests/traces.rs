//! Retained traces, replayed on simulated time against a session whose peers are scripted.
//!
//! Each kept trace has a test of its own, which names the race it reproduces. A control
//! contradicts every expectation a kept trace states, one at a time, and the replay must then stop
//! at that step, so no expectation is counted that could not fail. The minimiser is tested on a
//! planted failing trace.

use kr_faults::restore::Strategy;
use kr_faults::trace::{self, Batch, Cause, Step, Trace};
use kr_protocol::projection::ProjectedBuffer;

/// The kept traces, each with the test below that replays it.
const KEPT: [&str; 5] = [
    "attach-inside-a-1049-switch",
    "clipboard-before-and-after-an-attach",
    "lone-escape-and-the-paste-recogniser",
    "takeover-during-a-paste",
    "time-rollback-and-suspension",
];

fn load(name: &str) -> Trace {
    Trace::load(&trace::directory().join(format!("{name}.json")))
        .unwrap_or_else(|error| panic!("{error}"))
}

fn replays(name: &str) {
    if let Err(stopped) = trace::replay(&load(name)) {
        panic!("{stopped}");
    }
}

/// KR-REQ-29.03: a takeover during a bracketed paste, replayed from its retained trace with both
/// clients scripted: the paste is reported closed and its unwritten bytes counted, the first
/// client's rest of the paste is refused, and the second client's keys are queued under its own
/// lease with no paste delimiter.
#[test]
fn a_takeover_during_a_paste_closes_it_and_refuses_the_rest_of_it() {
    replays("takeover-during-a-paste");
}

/// KR-REQ-29.03: a suspension between two expiry reads and two wall-clock rollbacks, replayed
/// from their retained trace on simulated time: the sleep counts against a continuous deadline
/// whichever read sees it first, a rollback inside the tolerance gives a UTC deadline nothing back,
/// one past it leaves UTC deadlines unproven, and nothing expired revives.
#[test]
fn a_suspension_between_expiry_reads_and_a_rollback_past_the_tolerance() {
    replays("time-rollback-and-suspension");
}

/// KR-REQ-29.03: clients attaching between the bytes of a switch into the alternate screen,
/// replayed from the retained trace: each holds the session's screen before the switch completes,
/// after it, and after the application leaves.
#[test]
fn a_client_attaching_inside_a_1049_switch_holds_the_screen_on_each_side_of_it() {
    replays("attach-inside-a-1049-switch");
}

/// KR-REQ-29.03: clipboard writes and bells before and after an attach, replayed from the
/// retained trace: a terminal performs only what came after it arrived, once, and only while it
/// holds the input lease.
#[test]
fn a_clipboard_write_before_an_attach_is_never_performed_and_one_after_it_is_once() {
    replays("clipboard-before-and-after-an-attach");
}

/// KR-REQ-29.03: a lone escape and the paste recogniser, replayed from the retained trace on
/// simulated time: forwarded at once while the application has not asked for bracketed paste, and
/// held after it has until the recogniser's deadline passes, then released by its timer with no
/// further keystroke.
#[test]
fn a_lone_escape_is_held_only_while_it_could_start_a_paste_and_only_until_its_deadline() {
    replays("lone-escape-and-the-paste-recogniser");
}

#[test]
fn every_kept_trace_has_a_test_of_its_own() {
    let names: Vec<String> = Trace::all()
        .unwrap_or_else(|error| panic!("{error}"))
        .into_iter()
        .map(|trace| trace.name)
        .collect();
    assert_eq!(
        names, KEPT,
        "a trace without a test, or a test without a trace"
    );
}

/// The same step with its expectation turned into one the product does not meet, or nothing when
/// the step states none that a trace can contradict.
fn contradicted(step: &Step) -> Option<Step> {
    let mut step = step.clone();
    match &mut step {
        Step::Acquire {
            expect: Some(expect),
            ..
        } => expect.closed_open_paste = !expect.closed_open_paste,
        Step::Input { refused, .. } => {
            *refused = match refused {
                Some(_) => None,
                None => Some("LEASE_LOST".to_owned()),
            };
        }
        Step::TakeInput { expect } => {
            if expect.pop().is_none() {
                expect.push(Batch::LeaseChanged);
            }
        }
        Step::ObserveTime { expect } => {
            if expect.is_empty() {
                expect.push(trace::Moved::Suspended);
            } else {
                expect.clear();
            }
        }
        Step::Validity { expect, .. } => {
            *expect = if expect == "valid" {
                "unproven".to_owned()
            } else {
                "valid".to_owned()
            };
        }
        Step::Screen { active, .. } => {
            *active = match active {
                ProjectedBuffer::Primary => ProjectedBuffer::Alternate,
                ProjectedBuffer::Alternate => ProjectedBuffer::Primary,
            };
        }
        Step::Effects { expect, .. } => expect.push("bell".to_owned()),
        _ => return None,
    }
    Some(step)
}

#[test]
fn every_expectation_a_kept_trace_states_fails_when_it_is_contradicted() {
    for name in KEPT {
        let kept = load(name);
        let mut contradictions = 0;
        for (index, step) in kept.steps.iter().enumerate() {
            let Some(contradiction) = contradicted(step) else {
                continue;
            };
            let mut planted = kept.clone();
            planted.steps[index] = contradiction;
            let stopped = trace::replay(&planted).expect_err(&format!(
                "trace {name} replayed with step {index} contradicted"
            ));
            assert_eq!(
                (stopped.step, stopped.cause),
                (Some(index), Cause::Expectation),
                "{stopped}"
            );
            contradictions += 1;
        }
        assert!(
            contradictions > 0,
            "trace {name} states no expectation a contradiction could test"
        );
    }
}

#[test]
fn a_restoration_that_replays_the_output_fails_the_first_check_of_the_client_it_restored() {
    let kept = load("clipboard-before-and-after-an-attach");
    let stopped = trace::replay_with(&kept, Strategy::Replay).expect_err("a replayed restoration");
    assert_eq!(
        (stopped.step, stopped.cause),
        (Some(4), Cause::Expectation),
        "{stopped}"
    );
    assert!(stopped.what.contains("clipboard write"), "{stopped}");
}

/// A trace with a planted failure: the first client's keys after the second took the lease are
/// expected to be accepted. Every step but four is noise to the failure.
const PLANTED: &str = r#"{
  "format": "kalareach.trace/1",
  "name": "planted",
  "about": "the first client's keys after a takeover are expected to be accepted",
  "columns": 20,
  "rows": 3,
  "wall_ms": 1790000000000,
  "steps": [
    { "do": "output", "text": "$ " },
    { "do": "attach", "client": "a", "form": "direct" },
    { "do": "advance", "ms": 1000 },
    { "do": "acquire", "client": "a" },
    { "do": "input", "client": "a", "text": "echo one\r" },
    { "do": "attach", "client": "p", "form": "projected" },
    { "do": "output", "text": "one\r\n$ " },
    { "do": "attach", "client": "b", "form": "direct" },
    { "do": "holds", "client": "p" },
    { "do": "acquire", "client": "b" },
    { "do": "suspend", "ms": 5000 },
    { "do": "input", "client": "b", "text": "x" },
    { "do": "input", "client": "a", "text": "y" },
    { "do": "output", "text": "never read" }
  ]
}"#;

/// KR-REQ-29.03: a failing trace is minimised to the steps its failure needs, and what is kept
/// still fails at the same step and reads back as the same trace.
#[test]
fn a_failing_trace_is_minimised_to_the_steps_its_failure_needs() {
    let planted = Trace::parse(PLANTED).unwrap_or_else(|error| panic!("{error}"));
    let stopped = trace::replay(&planted).expect_err("the planted trace fails");
    assert_eq!(
        (stopped.step, stopped.cause),
        (Some(12), Cause::Expectation),
        "{stopped}"
    );
    assert!(stopped.what.contains("LEASE_LOST"), "{stopped}");
    let minimised = trace::minimise(&planted).unwrap_or_else(|error| panic!("{error}"));
    let kept: Vec<Step> = [1, 3, 7, 9, 12]
        .into_iter()
        .map(|index| planted.steps[index].clone())
        .collect();
    assert_eq!(minimised.steps, kept);
    let again = trace::replay(&minimised).expect_err("the minimised trace fails");
    assert_eq!(
        (again.step, again.cause),
        (Some(4), Cause::Expectation),
        "{again}"
    );
    assert_eq!(Trace::parse(&minimised.to_json()), Ok(minimised));
}

#[test]
fn a_trace_that_replays_or_cannot_be_run_has_nothing_to_minimise() {
    let passing = load("takeover-during-a-paste");
    assert!(trace::minimise(&passing).is_err_and(|error| error.contains("nothing to minimise")));
    let mut malformed = passing;
    malformed.steps.insert(
        0,
        Step::Detach {
            client: "nobody".to_owned(),
        },
    );
    let stopped = trace::replay(&malformed).expect_err("a client that never attached");
    assert_eq!(
        (stopped.step, stopped.cause),
        (Some(0), Cause::Malformed),
        "{stopped}"
    );
    assert!(
        stopped
            .to_string()
            .contains("trace takeover-during-a-paste, step 0"),
        "{stopped}"
    );
    assert!(trace::minimise(&malformed).is_err_and(|error| error.contains("no client nobody")));
}
