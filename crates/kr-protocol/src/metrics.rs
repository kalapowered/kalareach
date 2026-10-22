//! What a host measures about itself, declared once.
//!
//! Section 26 asks a product to report connection setup, route selection, reconnect time, queue
//! pressure, terminal parse faults, adapter failures, push acceptance and action-receipt latency,
//! and never to place terminal content, provider keys, prompts or attachment filenames in a
//! metric's labels. Three of the eight are a host's to report about itself: reconnect time, terminal
//! parse faults and adapter failures. They are declared here, and the declaration is the only list:
//! the report a host gives (`kr doctor`, the support bundle) is built from these types, and
//! `fixtures/metrics/host.json` is written from them. The service repository declares the same
//! metrics in its own language, and both repositories' suites hold their declaration to that vector,
//! so a name, a kind, a unit or a permitted label value cannot move on one side alone.
//!
//! # Why a label cannot carry content
//!
//! Every label is a closed enumeration. There is no type here that holds a string a caller chose,
//! so there is nowhere for a line of output, a prompt or a filename to go: a report that tried to
//! carry one would not parse. Adding a value is a change to this file, to the vector, and to the
//! service's declaration.
//!
//! # What these are not
//!
//! Local diagnostics. A host keeps its totals in memory for the life of the process, reports them
//! to its owner and into a support bundle the owner chooses to write, and sends them nowhere. A
//! total starts again when the process that counted it does.

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::Duration;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::scalars::U64;

/// Declares one closed label: its enumeration, the key it is reported under, how its values are
/// spelled and the shape the service declares for it.
macro_rules! closed_label {
    (
        $(#[$meta:meta])*
        $name:ident, $key:literal, $shape:ident, {
            $($(#[$variant_meta:meta])* $variant:ident => $text:literal),+ $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(
            Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
            JsonSchema,
        )]
        pub enum $name {
            $($(#[$variant_meta])* #[serde(rename = $text)] $variant),+
        }

        impl $name {
            /// The key this label is reported under.
            pub const KEY: &'static str = $key;

            /// Whether the label names one of a fixed list of words or a range.
            pub const SHAPE: Shape = Shape::$shape;

            /// Every value, in declaration order.
            pub const ALL: &'static [Self] = &[$(Self::$variant),+];

            /// Returns the spelling this value has on the wire and in the vector.
            #[must_use]
            pub const fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $text),+
                }
            }
        }
    };
}

/// How a label's values are chosen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Shape {
    /// One of a fixed list of words.
    Enumerated,
    /// A range rather than a figure, for the cases where the label is a magnitude.
    Bucket,
}

impl Shape {
    /// The word the vector uses for this shape.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Enumerated => "enumerated",
            Self::Bucket => "bucket",
        }
    }

    /// The member of a label's entry in the vector that lists its values.
    #[must_use]
    pub const fn values_member(self) -> &'static str {
        match self {
            Self::Enumerated => "values",
            Self::Bucket => "buckets",
        }
    }
}

closed_label! {
    /// How the two ends of a connection reached each other.
    Transport, "transport", Enumerated, {
        /// A direct path between the two.
        Direct => "direct",
        /// Through a relay.
        Relay => "relay",
        /// On this machine.
        Local => "local",
    }
}

closed_label! {
    /// Which attempt ended a reconnection, as a range rather than a number.
    ReconnectAttempt, "attempt", Bucket, {
        /// The first.
        One => "1",
        /// The second or third.
        TwoToThree => "2-3",
        /// The fourth to the eighth.
        FourToEight => "4-8",
        /// The ninth or later.
        NineOrMore => "9+",
    }
}

impl ReconnectAttempt {
    /// The range the `ordinal`th attempt falls in. Attempts count from one: a zero is the first.
    #[must_use]
    pub const fn of(ordinal: u64) -> Self {
        match ordinal {
            0..=1 => Self::One,
            2..=3 => Self::TwoToThree,
            4..=8 => Self::FourToEight,
            _ => Self::NineOrMore,
        }
    }
}

closed_label! {
    /// How something ended. Never why, in the words of whatever failed.
    MetricOutcome, "outcome", Enumerated, {
        /// It worked.
        Ok => "ok",
        /// The host refused it.
        Refused => "refused",
        /// It was not answered in time.
        Timeout => "timeout",
        /// Nothing was there to answer it.
        Unavailable => "unavailable",
        /// What it needed ran out.
        Exhausted => "exhausted",
        /// It was not valid.
        Invalid => "invalid",
    }
}

closed_label! {
    /// A class of fault in the bytes a terminal's program wrote. Never the bytes that caused it.
    Fault, "fault", Enumerated, {
        /// A control string that was abandoned before its terminator, or a sequence cut short.
        UnterminatedSequence => "unterminated_sequence",
        /// Text that was not valid in the encoding the terminal is read in.
        InvalidEncoding => "invalid_encoding",
        /// A control string, or a sequence, that went past a bound and was discarded whole.
        OversizedFrame => "oversized_frame",
        /// A sequence with no class in the profile.
        UnknownControl => "unknown_control",
    }
}

closed_label! {
    /// An adapter, from the connectors this product bundles. An adapter nobody bundled is counted
    /// under no name at all.
    Adapter, "adapter", Enumerated, {
        /// Claude Code.
        ClaudeCode => "claude-code",
        /// Codex.
        Codex => "codex",
        /// Gemini CLI.
        GeminiCli => "gemini-cli",
        /// Kimi CLI.
        KimiCli => "kimi-cli",
        /// Kimi Code CLI.
        KimiCodeCli => "kimi-code-cli",
        /// OpenCode.
        Opencode => "opencode",
        /// OpenCode attached to a running server.
        OpencodeAttach => "opencode-attach",
        /// Qoder CLI.
        QoderCli => "qoder-cli",
    }
}

impl Adapter {
    /// The adapter a package is, by its identifier as `publisher/plugin`, where it is one of the
    /// connectors this product bundles. The match is exact: a package that merely ends in one of
    /// these names is not that adapter.
    #[must_use]
    pub fn of_package(package: &str) -> Option<Self> {
        let plugin = package.strip_prefix("kalareach/")?;
        Self::ALL
            .iter()
            .copied()
            .find(|adapter| adapter.as_str() == plugin)
    }
}

closed_label! {
    /// Which environment produced a measurement.
    Environment, "environment", Enumerated, {
        /// A build that is not a release.
        Development => "development",
        /// A staging deployment. A host never reports it.
        Staging => "staging",
        /// A released build.
        Production => "production",
    }
}

/// What kind of figure a metric carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// How long something took, in milliseconds.
    Duration,
    /// How many times something happened.
    Counter,
}

impl Kind {
    /// The word the vector uses for this kind.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Duration => "duration",
            Self::Counter => "counter",
        }
    }

    /// The unit its figure is in.
    #[must_use]
    pub const fn unit(self) -> &'static str {
        match self {
            Self::Duration => "milliseconds",
            Self::Counter => "events",
        }
    }
}

/// One metric a host reports about itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Declaration {
    /// The name it is reported under.
    pub name: &'static str,
    /// What kind of figure it carries.
    pub kind: Kind,
    /// The label keys it may carry, in the order they are reported.
    pub labels: &'static [&'static str],
    /// What it measures, for the person reading the guide.
    pub reports: &'static str,
}

/// The metrics a host reports about itself, in the order section 26 names them.
pub const HOST_METRICS: &[Declaration] = &[
    Declaration {
        name: "reconnect.time",
        kind: Kind::Duration,
        labels: &[
            Transport::KEY,
            ReconnectAttempt::KEY,
            MetricOutcome::KEY,
            Environment::KEY,
        ],
        reports: "how long a paired device was without a connection to this host, and which \
                  attempt ended it",
    },
    Declaration {
        name: "terminal.parse_fault",
        kind: Kind::Counter,
        labels: &[Fault::KEY, Environment::KEY],
        reports: "a sequence a session's terminal parser could not make sense of, by class of \
                  fault",
    },
    Declaration {
        name: "adapter.failure",
        kind: Kind::Counter,
        labels: &[Adapter::KEY, MetricOutcome::KEY, Environment::KEY],
        reports: "an adapter that did not answer, by the adapter and by how it ended",
    },
];

/// The values one label may take, as the vector lists them.
fn values_of(key: &str) -> Option<(Shape, Vec<&'static str>)> {
    fn all<T: Copy>(
        shape: Shape,
        values: &'static [T],
        text: fn(T) -> &'static str,
    ) -> Option<(Shape, Vec<&'static str>)> {
        Some((shape, values.iter().copied().map(text).collect()))
    }
    match key {
        Transport::KEY => all(Transport::SHAPE, Transport::ALL, Transport::as_str),
        ReconnectAttempt::KEY => all(
            ReconnectAttempt::SHAPE,
            ReconnectAttempt::ALL,
            ReconnectAttempt::as_str,
        ),
        MetricOutcome::KEY => all(
            MetricOutcome::SHAPE,
            MetricOutcome::ALL,
            MetricOutcome::as_str,
        ),
        Fault::KEY => all(Fault::SHAPE, Fault::ALL, Fault::as_str),
        Adapter::KEY => all(Adapter::SHAPE, Adapter::ALL, Adapter::as_str),
        Environment::KEY => all(Environment::SHAPE, Environment::ALL, Environment::as_str),
        _ => None,
    }
}

/// The name of the file the vector is written to, under `fixtures/metrics`.
pub const VECTOR_FILE_NAME: &str = "host.json";

/// The vector both repositories' suites hold their declaration to: each host metric with its kind,
/// its unit and its labels, and each of those labels with its shape and every value it may take.
///
/// # Panics
///
/// Panics when a declared label has no entry, which a test of this module prevents.
#[must_use]
pub fn vector() -> Value {
    let metrics: Vec<Value> = HOST_METRICS
        .iter()
        .map(|declaration| {
            json!({
                "name": declaration.name,
                "kind": declaration.kind.as_str(),
                "unit": declaration.kind.unit(),
                "where": "host",
                "labels": declaration.labels,
            })
        })
        .collect();
    let mut labels = serde_json::Map::new();
    for key in HOST_METRICS
        .iter()
        .flat_map(|declaration| declaration.labels.iter().copied())
    {
        let (shape, values) = values_of(key).expect("every declared label has its values");
        labels.insert(
            key.to_owned(),
            json!({ "kind": shape.as_str(), shape.values_member(): values }),
        );
    }
    json!({
        "document": "kalareach host metrics",
        "version": 1,
        "metrics": metrics,
        "labels": labels,
    })
}

/// One reconnect.time series: how long a paired device was without a connection, counted under the
/// labels that say how the connection that ended the gap reached the host and how it ended.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReconnectTime {
    /// How the connection that ended the gap reached the host.
    pub transport: Transport,
    /// Which attempt, among the connections the host saw from the device since its last one ended,
    /// is the one reported.
    pub attempt: ReconnectAttempt,
    /// How that attempt ended.
    pub outcome: MetricOutcome,
    /// Which environment measured it.
    pub environment: Environment,
    /// How many gaps this series counts.
    pub count: U64,
    /// The sum of their lengths, in milliseconds.
    pub total_ms: U64,
    /// The longest of them, in milliseconds.
    pub longest_ms: U64,
}

/// One terminal.parse_fault series.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ParseFault {
    /// The class of fault.
    pub fault: Fault,
    /// Which environment measured it.
    pub environment: Environment,
    /// How many times it happened.
    pub count: U64,
}

/// One adapter.failure series.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AdapterFailure {
    /// The adapter.
    pub adapter: Adapter,
    /// How it ended.
    pub outcome: MetricOutcome,
    /// Which environment measured it.
    pub environment: Environment,
    /// How many times it happened.
    pub count: U64,
}

/// What a host reports of the metrics it measures about itself.
///
/// Closed in every member: a report is made of this build's own words, so one that was read back
/// from elsewhere naming anything else does not parse, and there is nowhere in it for a line of
/// output, a prompt or a filename to go.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MetricsReport {
    /// Every reconnect.time series, in a fixed order.
    #[serde(default)]
    pub reconnect_time: Vec<ReconnectTime>,
    /// Every terminal.parse_fault series, in a fixed order.
    #[serde(default)]
    pub terminal_parse_fault: Vec<ParseFault>,
    /// Every adapter.failure series, in a fixed order.
    #[serde(default)]
    pub adapter_failure: Vec<AdapterFailure>,
}

impl MetricsReport {
    /// How many events the report counts, across every series.
    #[must_use]
    pub fn events(&self) -> u64 {
        let reconnects: u64 = self
            .reconnect_time
            .iter()
            .map(|series| series.count.get())
            .sum();
        let faults: u64 = self
            .terminal_parse_fault
            .iter()
            .map(|series| series.count.get())
            .sum();
        let failures: u64 = self
            .adapter_failure
            .iter()
            .map(|series| series.count.get())
            .sum();
        reconnects.saturating_add(faults).saturating_add(failures)
    }

    /// Whether nothing has been counted.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.reconnect_time.is_empty()
            && self.terminal_parse_fault.is_empty()
            && self.adapter_failure.is_empty()
    }

    /// Joins reports from several places into one: the same series add up, the others stay apart,
    /// and the result is in a fixed order, so two reports of the same totals are the same report.
    #[must_use]
    pub fn joined(parts: impl IntoIterator<Item = Self>) -> Self {
        let mut reconnects: BTreeMap<_, ReconnectTime> = BTreeMap::new();
        let mut faults: BTreeMap<_, ParseFault> = BTreeMap::new();
        let mut failures: BTreeMap<_, AdapterFailure> = BTreeMap::new();
        for part in parts {
            for series in part.reconnect_time {
                let key = (
                    series.transport,
                    series.attempt,
                    series.outcome,
                    series.environment,
                );
                reconnects
                    .entry(key)
                    .and_modify(|held| {
                        held.count = U64::new(held.count.get().saturating_add(series.count.get()));
                        held.total_ms =
                            U64::new(held.total_ms.get().saturating_add(series.total_ms.get()));
                        held.longest_ms =
                            U64::new(held.longest_ms.get().max(series.longest_ms.get()));
                    })
                    .or_insert(series);
            }
            for series in part.terminal_parse_fault {
                faults
                    .entry((series.fault, series.environment))
                    .and_modify(|held| {
                        held.count = U64::new(held.count.get().saturating_add(series.count.get()));
                    })
                    .or_insert(series);
            }
            for series in part.adapter_failure {
                failures
                    .entry((series.adapter, series.outcome, series.environment))
                    .and_modify(|held| {
                        held.count = U64::new(held.count.get().saturating_add(series.count.get()));
                    })
                    .or_insert(series);
            }
        }
        Self {
            reconnect_time: reconnects.into_values().collect(),
            terminal_parse_fault: faults.into_values().collect(),
            adapter_failure: failures.into_values().collect(),
        }
    }
}

/// What a series counts under: its metric and every label it carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Key {
    Reconnect(Transport, ReconnectAttempt, MetricOutcome),
    ParseFault(Fault),
    AdapterFailure(Adapter, MetricOutcome),
}

/// What a series has counted.
#[derive(Clone, Copy, Debug, Default)]
struct Totals {
    count: u64,
    total_ms: u64,
    longest_ms: u64,
}

/// A place that counts the host's measurements.
///
/// It is bounded by the closed labels: there are as many series as there are combinations of their
/// values and no more, whatever is measured and however often. Recording never fails and never
/// waits for anything but its own short lock.
#[derive(Debug)]
pub struct Recorder {
    environment: Environment,
    series: Mutex<BTreeMap<Key, Totals>>,
}

impl Recorder {
    /// A recorder that reports its measurements as taken in `environment`.
    #[must_use]
    pub const fn new(environment: Environment) -> Self {
        Self {
            environment,
            series: Mutex::new(BTreeMap::new()),
        }
    }

    fn add(&self, key: Key, count: u64, took_ms: u64) {
        let mut series = self
            .series
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let totals = series.entry(key).or_default();
        totals.count = totals.count.saturating_add(count);
        totals.total_ms = totals.total_ms.saturating_add(took_ms);
        totals.longest_ms = totals.longest_ms.max(took_ms);
    }

    /// Records that a device was without a connection for `took`, and that the attempt ended it
    /// by reaching the host over `transport` and ended as `outcome`.
    pub fn reconnected(
        &self,
        transport: Transport,
        attempt: ReconnectAttempt,
        outcome: MetricOutcome,
        took: Duration,
    ) {
        let took_ms = u64::try_from(took.as_millis()).unwrap_or(u64::MAX);
        self.add(Key::Reconnect(transport, attempt, outcome), 1, took_ms);
    }

    /// Records `count` more sequences of the class `fault`.
    pub fn parse_faulted(&self, fault: Fault, count: u64) {
        if count > 0 {
            self.add(Key::ParseFault(fault), count, 0);
        }
    }

    /// Records one failure of `adapter` that ended as `outcome`.
    pub fn adapter_failed(&self, adapter: Adapter, outcome: MetricOutcome) {
        self.add(Key::AdapterFailure(adapter, outcome), 1, 0);
    }

    /// Returns what has been counted, in a fixed order.
    #[must_use]
    pub fn report(&self) -> MetricsReport {
        let environment = self.environment;
        let series = self
            .series
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut report = MetricsReport::default();
        for (key, totals) in series.iter() {
            match *key {
                Key::Reconnect(transport, attempt, outcome) => {
                    report.reconnect_time.push(ReconnectTime {
                        transport,
                        attempt,
                        outcome,
                        environment,
                        count: U64::new(totals.count),
                        total_ms: U64::new(totals.total_ms),
                        longest_ms: U64::new(totals.longest_ms),
                    });
                }
                Key::ParseFault(fault) => report.terminal_parse_fault.push(ParseFault {
                    fault,
                    environment,
                    count: U64::new(totals.count),
                }),
                Key::AdapterFailure(adapter, outcome) => {
                    report.adapter_failure.push(AdapterFailure {
                        adapter,
                        outcome,
                        environment,
                        count: U64::new(totals.count),
                    });
                }
            }
        }
        report
    }
}

#[cfg(test)]
mod tests;
