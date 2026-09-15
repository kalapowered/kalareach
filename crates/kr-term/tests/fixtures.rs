//! The committed fixtures and the invariants that hold across every case in them.
//!
//! Two jobs. The first is change detection: each fixture is rebuilt from the corpus and compared
//! with the committed file, so a change in behaviour arrives with the fixture that records it. The
//! second is the part a diff cannot do for you: the properties that must hold for *every* case, no
//! matter which case someone adds next.

use std::path::{Path, PathBuf};

use kr_term::class::SequenceClass;
use kr_term::conformance::{
    ADMISSION_CASES, BROKER_CASES, BYTE_POLICY_CASES, CLASS_CASES, Case, SNAPSHOT_CASES,
    WIDTH_CASES, summarise, summarise_admission, summarise_grid,
};
use serde_json::Value;

fn fixtures_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("fixtures")
        .join("terminal")
}

fn load(name: &str) -> Value {
    let path = fixtures_dir().join(name);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

fn cases_of(value: &Value) -> &Vec<Value> {
    value["cases"]
        .as_array()
        .unwrap_or_else(|| panic!("fixture has no cases array"))
}

fn find<'a>(fixture: &'a Value, id: &str) -> &'a Value {
    cases_of(fixture)
        .iter()
        .find(|case| case["id"] == id)
        .unwrap_or_else(|| panic!("fixture has no case {id}"))
}

/// Compares one rebuilt case with the committed one, ignoring the two annotation fields.
fn assert_case_matches(committed: &Value, rebuilt: &Value, id: &str) {
    for (key, value) in rebuilt.as_object().expect("case is an object") {
        assert_eq!(
            committed.get(key),
            Some(value),
            "case {id} field {key} differs from the committed fixture; \
             run `cargo run -p kr-term --bin kr-term-fixtures`"
        );
    }
}

fn check_lex_fixture(name: &str, cases: &[Case]) {
    let fixture = load(name);
    assert_eq!(
        cases_of(&fixture).len(),
        cases.len(),
        "{name} has a different number of cases than the corpus"
    );
    for case in cases {
        assert_case_matches(find(&fixture, case.id), &summarise(case), case.id);
    }
}

#[test]
fn class_fixture_is_current() {
    check_lex_fixture("classes.json", CLASS_CASES);
}

#[test]
fn byte_policy_fixture_is_current() {
    check_lex_fixture("byte-policy.json", BYTE_POLICY_CASES);
}

#[test]
fn broker_fixture_is_current() {
    check_lex_fixture("broker.json", BROKER_CASES);
}

#[test]
fn width_fixture_is_current() {
    let fixture = load("width.json");
    for case in WIDTH_CASES {
        assert_case_matches(find(&fixture, case.id), &summarise_grid(case), case.id);
    }
}

#[test]
fn snapshot_fixture_is_current() {
    let fixture = load("snapshot.json");
    for case in SNAPSHOT_CASES {
        assert_case_matches(find(&fixture, case.id), &summarise_grid(case), case.id);
    }
}

#[test]
fn admission_fixture_is_current() {
    let fixture = load("admission.json");
    assert_eq!(
        cases_of(&fixture).len(),
        ADMISSION_CASES.len(),
        "admission.json has a different number of cases than the corpus"
    );
    for case in ADMISSION_CASES {
        assert_case_matches(find(&fixture, case.id), &summarise_admission(case), case.id);
    }
}

/// Every admitted geometry fits the budget, every refused one names the bound that refused it, and
/// the two bounds are told apart: dimensions outside the three constraints are a malformed request,
/// and a geometry inside them that this session cannot hold is a resource that is not available.
#[test]
fn every_admission_case_names_the_bound_that_answered() {
    let fixture = load("admission.json");
    let budget = fixture["budget"]["session_bytes"]
        .as_u64()
        .expect("the fixture records the budget");
    for case in cases_of(&fixture) {
        let id = case["id"].as_str().unwrap_or_default();
        for step in [Some(case), case.get("resize")].into_iter().flatten() {
            if step["admitted"] == Value::Bool(true) {
                let total = step["footprint"]["total"]
                    .as_u64()
                    .unwrap_or_else(|| panic!("case {id} records no footprint"));
                assert!(
                    total <= budget,
                    "case {id} was admitted at {total} bytes against a {budget}-byte budget"
                );
                continue;
            }
            let code = step["code"].as_str().unwrap_or_default();
            assert!(
                code == "RESOURCE_UNAVAILABLE" || code == "INVALID_ARGUMENT",
                "case {id} was refused as {code}"
            );
            let cells = step["requested"]["cells"].as_u64().unwrap_or_default();
            let dimension_bound = cells > 262_144
                || step["requested"]["cols"].as_u64().unwrap_or_default() > 2_048
                || step["requested"]["rows"].as_u64().unwrap_or_default() > 1_024;
            let expected = if dimension_bound {
                "INVALID_ARGUMENT"
            } else {
                "RESOURCE_UNAVAILABLE"
            };
            assert_eq!(code, expected, "case {id} was refused as the wrong kind");
        }
    }
}

/// A refused resize changes nothing: the session keeps the geometry it had.
#[test]
fn a_refused_resize_keeps_the_geometry_it_had() {
    let fixture = load("admission.json");
    for case in cases_of(&fixture) {
        let Some(resize) = case.get("resize") else {
            continue;
        };
        if resize["admitted"] == Value::Bool(true) {
            assert_eq!(resize["size_after"], resize["requested"]);
            continue;
        }
        assert_eq!(
            resize["size_after"], case["requested"],
            "case {} kept the wrong geometry after a refused resize",
            case["id"]
        );
    }
}

#[test]
fn profile_fixture_is_current() {
    let fixture = load("profile.json");
    assert_eq!(fixture["term"], kr_term::profile::TERM);
    assert_eq!(fixture["identity"], kr_term::profile::XTVERSION_IDENTITY);
    assert_eq!(
        fixture["grid_library"]["revision"],
        kr_term::unicode::LIBRARY.revision
    );
}

/// Every class-table row is represented, and every case names what it covers.
#[test]
fn every_case_names_its_requirement() {
    for case in CLASS_CASES
        .iter()
        .chain(BYTE_POLICY_CASES)
        .chain(BROKER_CASES)
    {
        assert!(
            case.covers.contains("KR-"),
            "case {} does not name a requirement",
            case.id
        );
    }
    let mut letters: Vec<char> = CLASS_CASES
        .iter()
        .flat_map(|case| {
            let mut lexer = kr_term::lexer::Lexer::new();
            let mut events = Vec::new();
            lexer.feed(case.input, &mut events);
            lexer.close(&mut events);
            events
                .into_iter()
                .map(|event| event.class.letter())
                .collect::<Vec<_>>()
        })
        .collect();
    letters.sort_unstable();
    letters.dedup();
    assert_eq!(
        letters,
        vec!['D', 'M', 'Q', 'S', 'X'],
        "the class corpus does not exercise all five classes"
    );
}

/// KR-ACC-001 and KR-ACC-024 across the whole corpus.
///
/// No `Q`, `S` or `X` event ever contributes a forwarded byte, the grid library never writes
/// anything, and it never fails to recognise a sequence the engine approved.
#[test]
fn no_query_or_side_effect_escapes_in_any_case() {
    for name in ["classes.json", "byte-policy.json", "broker.json"] {
        let fixture = load(name);
        for case in cases_of(&fixture) {
            let id = case["id"].as_str().unwrap_or("?");
            assert_eq!(
                case["grid_writes"], 0,
                "{name} case {id}: the grid library wrote bytes; the broker is the only responder"
            );
            assert_eq!(
                case["grid_unrecognised"], 0,
                "{name} case {id}: the grid library did not recognise an approved sequence"
            );
            let forwarded: u64 = case["forward"]
                .as_array()
                .map(|spans| {
                    spans
                        .iter()
                        .map(|span| {
                            let start = span[0].as_u64().unwrap_or(0);
                            let end = span[1].as_u64().unwrap_or(0);
                            end - start
                        })
                        .sum()
                })
                .unwrap_or(0);
            let forwardable: u64 = case["events"]
                .as_array()
                .map(|events| {
                    events
                        .iter()
                        .filter(|event| event["disposition"] == "Forward")
                        .map(|event| {
                            let span = &event["span"];
                            span[1].as_u64().unwrap_or(0) - span[0].as_u64().unwrap_or(0)
                        })
                        .sum()
                })
                .unwrap_or(0);
            assert!(
                forwarded <= forwardable,
                "{name} case {id}: more bytes were forwarded than the events allow"
            );
        }
    }
}

/// Every query in the broker corpus is answered here, and no query byte travels onwards.
#[test]
fn every_query_case_is_answered_here() {
    let fixture = load("broker.json");
    for case in cases_of(&fixture) {
        let id = case["id"].as_str().unwrap_or("?");
        let events = case["events"].as_array().expect("events");
        // Every case is something the worker answers itself. Most are queries; the clipboard read
        // is a side effect the profile answers with an empty response rather than asking a client.
        assert!(
            events
                .iter()
                .any(|event| event["class"] == "Q" || event["class"] == "S"),
            "broker case {id} is neither a query nor an answered side effect"
        );
        assert!(
            case["responses"].as_array().is_some_and(|r| !r.is_empty()),
            "broker case {id} produced no reply"
        );
        let spans: Vec<(u64, u64)> = case["forward"]
            .as_array()
            .map(|spans| {
                spans
                    .iter()
                    .map(|span| (span[0].as_u64().unwrap_or(0), span[1].as_u64().unwrap_or(0)))
                    .collect()
            })
            .unwrap_or_default();
        for event in events {
            if event["class"] == "D" || event["class"] == "M" {
                continue;
            }
            let start = event["span"][0].as_u64().unwrap_or(0);
            let end = event["span"][1].as_u64().unwrap_or(0);
            assert!(
                !spans.iter().any(|(a, b)| *a < end && start < *b),
                "broker case {id}: a forwarded span overlaps a consumed sequence"
            );
        }
    }
}

/// The class letters in the fixtures match what the classifier says today.
#[test]
fn committed_classes_match_the_classifier() {
    let fixture = load("classes.json");
    for case in CLASS_CASES {
        let committed = find(&fixture, case.id);
        let mut lexer = kr_term::lexer::Lexer::new();
        let mut events = Vec::new();
        lexer.feed(case.input, &mut events);
        lexer.close(&mut events);
        let actual: Vec<String> = events
            .iter()
            .map(|event| event.class.letter().to_string())
            .collect();
        let expected: Vec<String> = committed["events"]
            .as_array()
            .expect("events")
            .iter()
            .map(|event| event["class"].as_str().unwrap_or("?").to_owned())
            .collect();
        assert_eq!(actual, expected, "case {} classes differ", case.id);
    }
}

/// The five classes round-trip through their letters.
#[test]
fn class_letters_round_trip() {
    for class in [
        SequenceClass::Display,
        SequenceClass::Mode,
        SequenceClass::Query,
        SequenceClass::SideEffect,
        SequenceClass::Extension,
    ] {
        assert_eq!(SequenceClass::from_letter(class.letter()), Some(class));
    }
}
