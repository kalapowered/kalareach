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

/// KR-REQ-27.05, an ownership transfer during a paste; KR-REQ-29.03: a takeover during a bracketed
/// paste, replayed from its retained trace with both clients scripted: the paste is reported closed
/// and its unwritten bytes counted, the first client's rest of the paste is refused, and the second
/// client's keys are queued under its own lease with no paste delimiter.
#[test]
fn a_takeover_during_a_paste_closes_it_and_refuses_the_rest_of_it() {
    replays("takeover-during-a-paste");
}

/// KR-REQ-27.05, clock rollback; KR-REQ-29.03: a suspension between two expiry reads and two
/// wall-clock rollbacks, replayed from their retained trace on simulated time: the sleep counts
/// against a continuous deadline whichever read sees it first, a rollback inside the tolerance
/// gives a UTC deadline nothing back, one past it leaves UTC deadlines unproven, and nothing
/// expired revives. The objects are the time contract's own; a grant store's expiry is the
/// product's grant tests'.
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
/// simulated time: forwarded at once while the application has not asked for
/// bracketed paste, and held after it has until the recogniser's deadline passes, then released by
/// its timer with no further keystroke.
#[test]
fn a_lone_escape_is_held_only_while_it_could_start_a_paste_and_only_until_its_deadline() {
    replays("lone-escape-and-the-paste-recogniser");
}

/// KR-REQ-27.05, a full store; KR-REQ-29.03: a session's journal filling while a client holds the
/// keys, replayed from the retained trace against a kept journal: the store refuses the next
/// durable write, rich work is fenced by the posture, the client's typing is still queued under its
/// lease for the application, and the interval is recorded once the store may grow again, and only
/// once, as the session and a reader that opens the file afresh both read it. The worker service's
/// own refusal of a rich mutation is the product's, in the worker's persistence tests.
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

/// What the profile answers to `query`, as the session's own engine words it.
fn reply_to(query: &[u8]) -> Vec<u8> {
    let mut engine = kr_term::engine::Engine::new(kr_term::engine::EngineConfig {
        size: kr_term::budget::GridSize { cols: 20, rows: 3 },
        ..kr_term::engine::EngineConfig::DEFAULT
    })
    .unwrap_or_else(|error| panic!("{error}"));
    let _ = engine.feed(query, 0);
    let open = kr_term::lane::LaneGate::default();
    engine
        .lane_mut()
        .drain(open, usize::MAX, 0)
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("the profile answers {query:?}"))
        .bytes()
        .to_vec()
}

/// A bytes as the hexadecimal a trace spells it in.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A reply batch a trace expects the terminal's writer to take.
fn reply(bytes: &[u8]) -> String {
    format!(r#"{{"batch":"reply","hex":"{}"}}"#, hex(bytes))
}

/// A trace in which the application turns bracketed paste on, a person starts pasting, the
/// application asks where the cursor is, `between` happens while the question waits behind the
/// paste, and the person ends the paste. The writer then takes the end of the paste and, when the
/// reply is still owed, the reply.
fn waiting_behind_a_paste(between: &str, answered: bool) -> Trace {
    let owed = if answered {
        format!(",{}", reply(b"\x1b[1;3R"))
    } else {
        String::new()
    };
    Trace::parse(&format!(
        r#"{{
  "format": "kalareach.trace/1",
  "name": "waiting-behind-a-paste",
  "about": "a question asked while the person's paste is open, answered when it ends",
  "columns": 20,
  "rows": 3,
  "wall_ms": 1790000000000,
  "steps": [
    {{ "do": "output", "text": "\u001b[?2004h$ " }},
    {{ "do": "attach", "client": "a", "form": "direct" }},
    {{ "do": "acquire", "client": "a" }},
    {{ "do": "input", "client": "a", "text": "\u001b[200~pasted" }},
    {{ "do": "take_input", "expect": [
      {{ "batch": "lease_changed" }},
      {{ "batch": "input", "client": "a", "text": "\u001b[200~pasted", "paste": ["opens"] }} ] }},
    {{ "do": "output", "text": "\u001b[6n" }},
    {{ "do": "take_input", "expect": [] }},
    {between}
    {{ "do": "input", "client": "a", "text": "\u001b[201~" }},
    {{ "do": "take_input", "expect": [
      {{ "batch": "input", "client": "a", "text": "\u001b[201~", "paste": ["closes"] }}{owed} ] }}
  ]
}}"#
    ))
    .unwrap_or_else(|error| panic!("{error}"))
}

fn replays_as_written(trace: &Trace) {
    if let Err(stopped) = trace::replay(trace) {
        panic!("{stopped}");
    }
}

/// KR-REQ-08.48, KR-REQ-08.49: a reply held behind the person's open paste is written when the
/// paste ends, so long as it has waited less than two seconds on the clock the session decides by.
#[test]
fn a_reply_held_behind_a_paste_is_written_when_the_paste_ends_within_two_seconds() {
    replays_as_written(&waiting_behind_a_paste(
        r#"{ "do": "advance", "ms": 1900 },"#,
        true,
    ));
}

/// KR-REQ-08.48, KR-REQ-08.49: and dropped, not written into a conversation that has moved on, once
/// it has waited longer than that.
#[test]
fn a_reply_held_behind_a_paste_is_dropped_when_it_has_waited_over_two_seconds() {
    replays_as_written(&waiting_behind_a_paste(
        r#"{ "do": "advance", "ms": 2100 },"#,
        false,
    ));
}

/// Section 9: a step of the wall clock moves neither decision. A reply that has waited half a second
/// is still owed after the wall clock is stepped an hour forward, which a lane measuring on the wall
/// clock would read as an hour and drop; and one that has waited 2.5 s is dropped although the wall
/// clock was stepped back by ten seconds, which such a lane would read as no time at all.
#[test]
fn a_step_of_the_wall_clock_neither_drops_a_held_reply_nor_keeps_it_longer() {
    replays_as_written(&waiting_behind_a_paste(
        r#"{ "do": "step_wall", "ms": 3600000 },
    { "do": "advance", "ms": 500 },"#,
        true,
    ));
    replays_as_written(&waiting_behind_a_paste(
        r#"{ "do": "step_wall", "ms": -10000 },
    { "do": "advance", "ms": 2500 },"#,
        false,
    ));
}

/// KR-REQ-08.48: a reply held behind a delimiter the person's input may be starting, a lone escape
/// after the application turned bracketed paste on, waits until the escape is released and is then
/// written, with the escape first. The same rule that holds it behind an open paste, on the same
/// clock.
#[test]
fn a_reply_held_behind_a_lone_escape_is_written_when_the_escape_is_released() {
    let trace = Trace::parse(&format!(
        r#"{{
  "format": "kalareach.trace/1",
  "name": "waiting-behind-an-escape",
  "about": "a question asked while a lone escape may begin a paste delimiter",
  "columns": 20,
  "rows": 3,
  "wall_ms": 1790000000000,
  "steps": [
    {{ "do": "output", "text": "\u001b[?2004h$ " }},
    {{ "do": "attach", "client": "a", "form": "direct" }},
    {{ "do": "acquire", "client": "a" }},
    {{ "do": "input", "client": "a", "text": "\u001b" }},
    {{ "do": "take_input", "expect": [ {{ "batch": "lease_changed" }} ] }},
    {{ "do": "output", "text": "\u001b[6n" }},
    {{ "do": "take_input", "expect": [] }},
    {{ "do": "advance", "ms": 24 }},
    {{ "do": "take_input", "expect": [] }},
    {{ "do": "advance", "ms": 1 }},
    {{ "do": "take_input", "expect": [
      {{ "batch": "input", "client": "a", "text": "\u001b", "paste": [] }},
      {}
    ] }}
  ]
}}"#,
        // The cursor is after the prompt, in the third column.
        reply(b"\x1b[1;3R")
    ))
    .unwrap_or_else(|error| panic!("{error}"));
    replays_as_written(&trace);
}

/// KR-REQ-08.49: the replies one drain of the lane writes are bounded to 4 KiB, and the rest wait
/// for a later drain and are written, in order, while they are inside the two seconds they may wait.
#[test]
fn replies_past_one_drains_budget_are_written_by_later_drains_while_they_are_fresh() {
    let answer = reply_to(b"\x1b[>q");
    let per_read = 4096 / answer.len();
    let asked = 200;
    assert!(
        per_read < asked,
        "{asked} questions are more than one drain writes, {per_read}"
    );
    let batch = |count: usize| vec![reply(&answer); count].join(",");
    let mut steps = vec![format!(
        r#"{{ "do": "output", "text": "{}" }}"#,
        "\\u001b[>q".repeat(asked)
    )];
    let mut owed = asked;
    while owed > 0 {
        let now = owed.min(per_read);
        steps.push(format!(
            r#"{{ "do": "take_input", "expect": [{}] }}"#,
            batch(now)
        ));
        owed -= now;
        steps.push(r#"{ "do": "advance", "ms": 100 }"#.to_owned());
        steps.push(r#"{ "do": "settle" }"#.to_owned());
    }
    steps.push(r#"{ "do": "take_input", "expect": [] }"#.to_owned());
    let trace = Trace::parse(&format!(
        r#"{{"format":"kalareach.trace/1","name":"replies-past-a-read","about":"{asked} questions",
            "columns":20,"rows":3,"wall_ms":1790000000000,"steps":[{}]}}"#,
        steps.join(",")
    ))
    .unwrap_or_else(|error| panic!("{error}"));
    replays_as_written(&trace);
}

/// KR-REQ-08.49: and the ones that have waited past two seconds are dropped, not written by the
/// drain that comes after.
#[test]
fn replies_past_one_drains_budget_are_dropped_when_the_next_drain_comes_after_two_seconds() {
    let answer = reply_to(b"\x1b[>q");
    let per_read = 4096 / answer.len();
    let asked = 200;
    let trace = Trace::parse(&format!(
        r#"{{"format":"kalareach.trace/1","name":"replies-past-a-read","about":"{asked} questions",
            "columns":20,"rows":3,"wall_ms":1790000000000,"steps":[
              {{ "do": "output", "text": "{}" }},
              {{ "do": "take_input", "expect": [{}] }},
              {{ "do": "advance", "ms": 2500 }},
              {{ "do": "settle" }},
              {{ "do": "take_input", "expect": [] }}
            ]}}"#,
        "\\u001b[>q".repeat(asked),
        vec![reply(&answer); per_read].join(",")
    ))
    .unwrap_or_else(|error| panic!("{error}"));
    replays_as_written(&trace);
}

/// KR-REQ-08.49: the session answers 256 questions a second. A 257th in the same moment is dropped
/// and so is one asked straight after, and one asked once the clock has moved a second is answered.
#[test]
fn the_257th_question_in_a_second_is_dropped_and_the_next_second_answers_again() {
    let answer = reply_to(b"\x1b[5n");
    let trace = Trace::parse(&format!(
        r#"{{"format":"kalareach.trace/1","name":"questions-a-second","about":"257 questions",
            "columns":20,"rows":3,"wall_ms":1790000000000,"steps":[
              {{ "do": "output", "text": "{}" }},
              {{ "do": "take_input", "expect": [{}] }},
              {{ "do": "output", "text": "\u001b[5n" }},
              {{ "do": "take_input", "expect": [] }},
              {{ "do": "advance", "ms": 1000 }},
              {{ "do": "output", "text": "\u001b[5n" }},
              {{ "do": "take_input", "expect": [{}] }}
            ]}}"#,
        "\\u001b[5n".repeat(257),
        vec![reply(&answer); 256].join(","),
        reply(&answer)
    ))
    .unwrap_or_else(|error| panic!("{error}"));
    replays_as_written(&trace);
}
