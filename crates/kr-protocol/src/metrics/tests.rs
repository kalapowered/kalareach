//! The host metrics' declaration, the vector written from it and the recorder that counts them.

use std::time::Duration;

use serde_json::{Value, json};

use super::{
    Adapter, AdapterFailure, Environment, Fault, HOST_METRICS, MetricOutcome, MetricsReport,
    ParseFault, ReconnectAttempt, ReconnectTime, Recorder, Shape, Transport, VECTOR_FILE_NAME,
    WorkerAdapterCount, WorkerFaultCount, WorkerMetrics, vector,
};
use crate::scalars::U64;

/// The committed vector is the one the declaration writes, so the service's suite and this one
/// hold their declarations to the same document.
#[test]
fn the_committed_vector_is_the_one_the_declaration_writes() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/metrics")
        .join(VECTOR_FILE_NAME);
    let committed: Value = serde_json::from_str(
        &std::fs::read_to_string(&path).expect("the vector is committed under fixtures/metrics"),
    )
    .expect("the vector is JSON");
    assert_eq!(committed, vector());
}

/// The vector names each host metric once, in the order section 26 names them, with the labels it
/// may carry, and gives every label that any of them carries its shape and every value it may take.
#[test]
fn the_vector_lists_each_metric_and_every_value_each_of_its_labels_may_take() {
    let vector = vector();
    let names: Vec<&str> = vector["metrics"]
        .as_array()
        .expect("a list")
        .iter()
        .map(|metric| metric["name"].as_str().expect("a name"))
        .collect();
    assert_eq!(
        names,
        ["reconnect.time", "terminal.parse_fault", "adapter.failure"]
    );
    assert_eq!(
        vector["metrics"][0],
        json!({
            "name": "reconnect.time",
            "kind": "duration",
            "unit": "milliseconds",
            "where": "host",
            "labels": ["transport", "attempt", "outcome", "environment"],
        })
    );
    assert_eq!(vector["metrics"][1]["kind"], "counter");
    assert_eq!(vector["metrics"][1]["unit"], "events");

    for declaration in HOST_METRICS {
        for key in declaration.labels {
            assert!(
                vector["labels"].get(*key).is_some(),
                "{} carries {key}, which the vector must list",
                declaration.name
            );
        }
    }
    assert_eq!(
        vector["labels"]["attempt"],
        json!({ "kind": "bucket", "buckets": ["1", "2-3", "4-8", "9+"] })
    );
    assert_eq!(
        vector["labels"]["fault"],
        json!({
            "kind": "enumerated",
            "values": [
                "unterminated_sequence",
                "invalid_encoding",
                "oversized_frame",
                "unknown_control"
            ],
        })
    );
    assert_eq!(ReconnectAttempt::SHAPE, Shape::Bucket);
    assert_eq!(Transport::SHAPE, Shape::Enumerated);
}

/// An attempt falls in the range that holds its ordinal, and a zero is the first.
#[test]
fn an_attempt_falls_in_the_range_that_holds_it() {
    for (ordinal, bucket) in [
        (0, ReconnectAttempt::One),
        (1, ReconnectAttempt::One),
        (2, ReconnectAttempt::TwoToThree),
        (3, ReconnectAttempt::TwoToThree),
        (4, ReconnectAttempt::FourToEight),
        (8, ReconnectAttempt::FourToEight),
        (9, ReconnectAttempt::NineOrMore),
        (u64::MAX, ReconnectAttempt::NineOrMore),
    ] {
        assert_eq!(ReconnectAttempt::of(ordinal), bucket, "attempt {ordinal}");
    }
}

/// A package is one of the bundled adapters only by its exact identifier, and the adapters are the
/// agent connectors the product bundles: a package that merely ends in one of their names, or
/// belongs to another publisher, counts under no name.
#[test]
fn a_package_is_an_adapter_only_by_its_exact_identifier() {
    assert_eq!(
        Adapter::of_package("kalareach/claude-code"),
        Some(Adapter::ClaudeCode)
    );
    assert_eq!(
        Adapter::of_package("kalareach/opencode-attach"),
        Some(Adapter::OpencodeAttach)
    );
    for not_one in [
        "kalareach/claude-code-fork",
        "someone/claude-code",
        "kalareach/",
        "claude-code",
        "kalareach/example-declarative",
        "kalareach/CLAUDE-CODE",
    ] {
        assert_eq!(Adapter::of_package(not_one), None, "{not_one}");
    }

    let bundled = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../bundled-plugins/targets/packages/kalareach");
    let mut connectors: Vec<String> = std::fs::read_dir(&bundled)
        .expect("the bundled packages are in the repository")
        .map(|entry| {
            entry
                .expect("an entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        // The declarative example is a package for authors to read, not an agent's adapter.
        .filter(|name| name != "example-declarative")
        .collect();
    connectors.sort();
    let mut declared: Vec<&str> = Adapter::ALL
        .iter()
        .map(|adapter| adapter.as_str())
        .collect();
    declared.sort_unstable();
    assert_eq!(
        connectors, declared,
        "the adapter label names every agent connector the product bundles, and no other"
    );
}

/// The recorder counts each series apart, adds what repeats, keeps the longest gap, and reports in
/// a fixed order under the environment it was made for.
#[test]
fn a_recorder_counts_each_series_and_reports_them_in_a_fixed_order() {
    let recorder = Recorder::new(Environment::Development);
    recorder.reconnected(
        Transport::Relay,
        ReconnectAttempt::One,
        MetricOutcome::Ok,
        Duration::from_millis(1_500),
    );
    recorder.reconnected(
        Transport::Relay,
        ReconnectAttempt::One,
        MetricOutcome::Ok,
        Duration::from_millis(4_000),
    );
    recorder.reconnected(
        Transport::Direct,
        ReconnectAttempt::TwoToThree,
        MetricOutcome::Refused,
        Duration::from_millis(10),
    );
    recorder.parse_faulted(Fault::InvalidEncoding, 3);
    recorder.parse_faulted(Fault::InvalidEncoding, 2);
    recorder.parse_faulted(Fault::UnknownControl, 0);
    recorder.adapter_failed(Adapter::Codex, MetricOutcome::Timeout);

    let report = recorder.report();
    assert_eq!(
        report.reconnect_time,
        [
            ReconnectTime {
                transport: Transport::Direct,
                attempt: ReconnectAttempt::TwoToThree,
                outcome: MetricOutcome::Refused,
                environment: Environment::Development,
                count: U64::new(1),
                total_ms: U64::new(10),
                longest_ms: U64::new(10),
            },
            ReconnectTime {
                transport: Transport::Relay,
                attempt: ReconnectAttempt::One,
                outcome: MetricOutcome::Ok,
                environment: Environment::Development,
                count: U64::new(2),
                total_ms: U64::new(5_500),
                longest_ms: U64::new(4_000),
            },
        ]
    );
    assert_eq!(
        report.terminal_parse_fault,
        [ParseFault {
            fault: Fault::InvalidEncoding,
            environment: Environment::Development,
            count: U64::new(5),
        }],
        "a class that was counted zero times is not a series"
    );
    assert_eq!(
        report.adapter_failure,
        [AdapterFailure {
            adapter: Adapter::Codex,
            outcome: MetricOutcome::Timeout,
            environment: Environment::Development,
            count: U64::new(1),
        }]
    );
    assert_eq!(report.events(), 9);
    assert!(!report.is_empty());
    assert!(Recorder::new(Environment::Production).report().is_empty());
}

/// A report is made of this build's own words, so one that names something else does not parse:
/// there is nowhere in it for a line of output, a prompt or a file's name to go.
#[test]
fn a_report_naming_a_word_this_build_does_not_have_does_not_parse() {
    let ok = json!({
        "reconnect_time": [],
        "terminal_parse_fault": [{
            "fault": "invalid_encoding",
            "environment": "production",
            "count": "1",
        }],
        "adapter_failure": [],
    });
    serde_json::from_value::<MetricsReport>(ok.clone())
        .expect("a report made of this build's words");
    for (pointer, planted) in [
        (
            "/terminal_parse_fault/0/fault",
            "the line the program printed",
        ),
        ("/terminal_parse_fault/0/environment", "/Users/someone/work"),
    ] {
        let mut changed = ok.clone();
        *changed.pointer_mut(pointer).expect("a member") = json!(planted);
        assert!(
            serde_json::from_value::<MetricsReport>(changed).is_err(),
            "{pointer} = {planted}"
        );
    }
    let mut extra = ok;
    extra["terminal_parse_fault"][0]["note"] = json!("a member of nobody's");
    assert!(serde_json::from_value::<MetricsReport>(extra).is_err());
}

/// Reports from several places join into one: the same series add up, the others stay apart, and
/// two joins of the same totals are the same report.
#[test]
fn reports_from_several_places_join_into_one() {
    let one = Recorder::new(Environment::Production);
    one.parse_faulted(Fault::OversizedFrame, 2);
    one.adapter_failed(Adapter::GeminiCli, MetricOutcome::Unavailable);
    one.reconnected(
        Transport::Relay,
        ReconnectAttempt::One,
        MetricOutcome::Ok,
        Duration::from_millis(100),
    );
    let other = Recorder::new(Environment::Production);
    other.parse_faulted(Fault::OversizedFrame, 3);
    other.reconnected(
        Transport::Relay,
        ReconnectAttempt::One,
        MetricOutcome::Ok,
        Duration::from_millis(900),
    );

    let joined = MetricsReport::joined([one.report(), other.report()]);
    assert_eq!(
        joined,
        MetricsReport::joined([other.report(), one.report()])
    );
    assert_eq!(joined.terminal_parse_fault.len(), 1);
    assert_eq!(joined.terminal_parse_fault[0].count.get(), 5);
    assert_eq!(joined.adapter_failure.len(), 1);
    assert_eq!(joined.reconnect_time.len(), 1);
    assert_eq!(joined.reconnect_time[0].count.get(), 2);
    assert_eq!(joined.reconnect_time[0].total_ms.get(), 1_000);
    assert_eq!(joined.reconnect_time[0].longest_ms.get(), 900);
    assert_eq!(joined.events(), 8);
}

/// A worker says its counts in words and the daemon keeps the ones this build has: each word of
/// this build's own lists comes back as the value it spells, in the daemon's environment, and a
/// word it has not is left out, so a list that grows on one side does not break the other.
#[test]
fn what_a_worker_says_is_read_against_this_builds_own_lists() {
    let recorder = Recorder::new(Environment::Production);
    recorder.parse_faulted(Fault::OversizedFrame, 4);
    recorder.adapter_failed(Adapter::OpencodeAttach, MetricOutcome::Unavailable);
    let said = WorkerMetrics::of(&recorder.report());
    assert!(!said.is_empty());
    assert!(WorkerMetrics::default().is_empty());

    let read = said.read(Environment::Development);
    assert_eq!(read.terminal_parse_fault.len(), 1);
    assert_eq!(read.terminal_parse_fault[0].fault, Fault::OversizedFrame);
    assert_eq!(read.terminal_parse_fault[0].count.get(), 4);
    assert_eq!(
        read.terminal_parse_fault[0].environment,
        Environment::Development,
        "the environment a count was made in is the daemon's to say"
    );
    assert_eq!(read.adapter_failure[0].adapter, Adapter::OpencodeAttach);

    let mut later = said;
    later.adapter_failure.push(WorkerAdapterCount {
        adapter: "a-connector-bundled-later".to_owned(),
        outcome: "timeout".to_owned(),
        count: U64::new(1),
    });
    later.terminal_parse_fault.push(WorkerFaultCount {
        fault: "a-class-added-later".to_owned(),
        count: U64::new(1),
    });
    assert_eq!(
        later.read(Environment::Development),
        read,
        "a word this build has no entry for changes nothing it reads"
    );
}
