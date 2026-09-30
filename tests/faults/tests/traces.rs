//! Retained traces, replayed on simulated time against a session whose peers are scripted.
//!
//! Each kept trace has a test of its own, which names the race it reproduces. A control
//! contradicts every expectation a kept trace states, one at a time, and the replay must then stop
//! at that step, so no expectation is counted that could not fail. The minimiser is tested on a
//! planted failing trace.

use kr_faults::restore::Strategy;
use kr_faults::trace::{self, Acquired, Batch, Cause, Moved, PasteEdge, Step, Trace};
use kr_protocol::projection::ProjectedBuffer;

/// The kept traces, each with the test below that replays it.
const KEPT: [&str; 6] = [
    "attach-inside-a-1049-switch",
    "clipboard-before-and-after-an-attach",
    "full-journal-keeps-native-input",
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

/// KR-REQ-27.05, a full store; KR-REQ-29.03: a session's journal filling while a client holds the
/// keys, replayed from the retained trace against a kept journal: the store refuses the next
/// durable write, rich work is fenced and the client's typing still reaches the application, and
/// the interval is recorded once the store may grow again, and only once.
#[test]
fn a_full_journal_fences_rich_work_keeps_native_input_and_records_its_gap_once() {
    replays("full-journal-keeps-native-input");
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

/// Every way of contradicting what the step asserts, one field at a time; nothing for a step that
/// asserts nothing a trace can contradict.
fn contradictions(step: &Step) -> Vec<Step> {
    let mut found = Vec::new();
    match step {
        Step::Acquire {
            client,
            expect: Some(expect),
        } => {
            for changed in [
                Acquired {
                    closed_open_paste: !expect.closed_open_paste,
                    ..*expect
                },
                Acquired {
                    discarded_bytes: expect.discarded_bytes + 1,
                    ..*expect
                },
            ] {
                found.push(Step::Acquire {
                    client: client.clone(),
                    expect: Some(changed),
                });
            }
        }
        Step::Input {
            client,
            text,
            hex,
            refused,
        } => {
            let refusals = match refused {
                None => vec![Some("LEASE_LOST".to_owned())],
                Some(_) => vec![None, Some("SESSION_CLOSED".to_owned())],
            };
            for refused in refusals {
                found.push(Step::Input {
                    client: client.clone(),
                    text: text.clone(),
                    hex: hex.clone(),
                    refused,
                });
            }
        }
        Step::TakeInput { expect } => {
            for index in 0..expect.len() {
                let mut dropped = expect.clone();
                dropped.remove(index);
                found.push(Step::TakeInput { expect: dropped });
                for changed in batch_contradictions(&expect[index]) {
                    let mut batches = expect.clone();
                    batches[index] = changed;
                    found.push(Step::TakeInput { expect: batches });
                }
            }
            let mut extra = expect.clone();
            extra.push(Batch::LeaseChanged);
            found.push(Step::TakeInput { expect: extra });
        }
        Step::ObserveTime { expect } => {
            for moved in [Moved::Suspended, Moved::Rebooted, Moved::RolledBack] {
                let mut toggled = expect.clone();
                match toggled.iter().position(|was| *was == moved) {
                    Some(at) => {
                        toggled.remove(at);
                    }
                    None => toggled.push(moved),
                }
                found.push(Step::ObserveTime { expect: toggled });
            }
        }
        Step::Validity { object, expect } => {
            for decision in [
                "valid",
                "expired: continuous_deadline",
                "expired: trusted_utc_deadline",
                "unproven",
                "revalidation owed",
            ] {
                if decision != expect {
                    found.push(Step::Validity {
                        object: object.clone(),
                        expect: decision.to_owned(),
                    });
                }
            }
        }
        Step::Screen {
            active,
            lines,
            other,
        } => {
            let flipped = match active {
                ProjectedBuffer::Primary => ProjectedBuffer::Alternate,
                ProjectedBuffer::Alternate => ProjectedBuffer::Primary,
            };
            found.push(Step::Screen {
                active: flipped,
                lines: lines.clone(),
                other: other.clone(),
            });
            for changed in rows_contradicted(lines) {
                found.push(Step::Screen {
                    active: *active,
                    lines: changed,
                    other: other.clone(),
                });
            }
            if let Some(other) = other {
                for changed in rows_contradicted(other) {
                    found.push(Step::Screen {
                        active: *active,
                        lines: lines.clone(),
                        other: Some(changed),
                    });
                }
            }
        }
        Step::FillJournal { expect } => found.push(Step::FillJournal {
            expect: format!("{expect}X"),
        }),
        Step::Journal { expect, rich_work } => {
            found.push(Step::Journal {
                expect: if expect == "healthy" {
                    "full".to_owned()
                } else {
                    "healthy".to_owned()
                },
                rich_work: *rich_work,
            });
            found.push(Step::Journal {
                expect: expect.clone(),
                rich_work: !rich_work,
            });
        }
        Step::ReleaseJournal { expect } => found.push(Step::ReleaseJournal {
            expect: match expect {
                Some(_) => None,
                None => Some("full".to_owned()),
            },
        }),
        Step::Effects { client, expect } => {
            for changed in rows_contradicted(expect) {
                found.push(Step::Effects {
                    client: client.clone(),
                    expect: changed,
                });
            }
            for index in 0..expect.len() {
                let mut dropped = expect.clone();
                dropped.remove(index);
                found.push(Step::Effects {
                    client: client.clone(),
                    expect: dropped,
                });
            }
        }
        _ => {}
    }
    found
}

/// Each entry of `rows` changed in turn, and one more entry after them.
fn rows_contradicted(rows: &[String]) -> Vec<Vec<String>> {
    let mut found: Vec<Vec<String>> = (0..rows.len())
        .map(|index| {
            let mut changed = rows.to_vec();
            changed[index].push('x');
            changed
        })
        .collect();
    let mut extra = rows.to_vec();
    extra.push("x".to_owned());
    found.push(extra);
    found
}

/// Each field of one batch changed in turn.
fn batch_contradictions(batch: &Batch) -> Vec<Batch> {
    let changed = |text: &Option<String>, hex: &Option<String>| match (text, hex) {
        (Some(text), _) => (Some(format!("{text}x")), None),
        (None, Some(hex)) => (None, Some(format!("{hex}78"))),
        (None, None) => (Some("x".to_owned()), None),
    };
    match batch {
        Batch::Input {
            client,
            text,
            hex,
            paste,
        } => {
            let (other_text, other_hex) = changed(text, hex);
            vec![
                Batch::Input {
                    client: format!("{client}x"),
                    text: text.clone(),
                    hex: hex.clone(),
                    paste: paste.clone(),
                },
                Batch::Input {
                    client: client.clone(),
                    text: other_text,
                    hex: other_hex,
                    paste: paste.clone(),
                },
                Batch::Input {
                    client: client.clone(),
                    text: text.clone(),
                    hex: hex.clone(),
                    paste: if paste.is_empty() {
                        vec![PasteEdge::Opens]
                    } else {
                        Vec::new()
                    },
                },
            ]
        }
        Batch::Reply { text, hex } => {
            let (text, hex) = changed(text, hex);
            vec![Batch::Reply { text, hex }]
        }
        Batch::LeaseChanged => vec![Batch::Reply {
            text: Some("x".to_owned()),
            hex: None,
        }],
    }
}

#[test]
fn every_field_of_every_expectation_a_kept_trace_states_fails_when_it_is_contradicted() {
    for name in KEPT {
        let kept = load(name);
        let mut contradicted = 0;
        for (index, step) in kept.steps.iter().enumerate() {
            for contradiction in contradictions(step) {
                let mut planted = kept.clone();
                planted.steps[index] = contradiction.clone();
                let stopped = trace::replay(&planted).expect_err(&format!(
                    "trace {name} replayed with step {index} contradicted as {contradiction:?}"
                ));
                assert_eq!(
                    (stopped.step, stopped.cause),
                    (Some(index), Cause::Expectation),
                    "{stopped}"
                );
                contradicted += 1;
            }
        }
        assert!(
            contradicted > 0,
            "trace {name} states no expectation a contradiction could test"
        );
    }
}

#[test]
fn a_terminal_handed_the_raw_output_from_where_it_arrived_fails_the_next_holds() {
    let kept = load("attach-inside-a-1049-switch");
    let stopped =
        trace::replay_with(&kept, Strategy::RawFromOffset).expect_err("a raw-output terminal");
    assert_eq!(
        (stopped.step, stopped.cause),
        (Some(10), Cause::Expectation),
        "{stopped}"
    );
    assert!(stopped.what.contains("its terminal"), "{stopped}");
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

/// A trace that turns its input into a bracketed paste and then asks the terminal where its cursor
/// is, or asks nothing more while the paste is open.
fn asking(while_pasting: bool) -> Trace {
    let paste = if while_pasting {
        r#"{ "do": "input", "client": "a", "text": "\u001b[200~pasted" },"#
    } else {
        ""
    };
    Trace::parse(&format!(
        r#"{{
  "format": "kalareach.trace/1",
  "name": "asking",
  "about": "a question asked with the input side open or holding a paste",
  "columns": 20,
  "rows": 3,
  "wall_ms": 1790000000000,
  "steps": [
    {{ "do": "output", "text": "\u001b[?2004h$ " }},
    {{ "do": "attach", "client": "a", "form": "direct" }},
    {{ "do": "acquire", "client": "a" }},
    {paste}
    {{ "do": "output", "text": "\u001b[6n" }}
  ]
}}"#
    ))
    .unwrap_or_else(|error| panic!("{error}"))
}

#[test]
fn a_question_asked_while_a_paste_holds_its_reply_back_is_refused_as_decided_on_the_hosts_clock() {
    let stopped = trace::replay(&asking(true)).expect_err("the reply waits on the host's clock");
    assert_eq!(
        (stopped.step, stopped.cause),
        (Some(4), Cause::Malformed),
        "{stopped}"
    );
    assert!(stopped.what.contains("host's own clock"), "{stopped}");
    let open = trace::replay(&asking(false));
    assert!(open.is_ok(), "{open:?}");
}

#[test]
fn a_trace_that_asks_more_questions_than_the_session_answers_in_a_second_is_refused() {
    let many = "\\u001b[5n".repeat(257);
    let trace = Trace::parse(&format!(
        r#"{{"format":"kalareach.trace/1","name":"many","about":"257 questions","columns":20,
            "rows":3,"wall_ms":1790000000000,"steps":[{{"do":"output","text":"{many}"}}]}}"#
    ))
    .unwrap_or_else(|error| panic!("{error}"));
    let stopped = trace::replay(&trace).expect_err("too many questions");
    assert_eq!(
        (stopped.step, stopped.cause),
        (Some(0), Cause::Malformed),
        "{stopped}"
    );
    assert!(stopped.what.contains("257 questions"), "{stopped}");
}
