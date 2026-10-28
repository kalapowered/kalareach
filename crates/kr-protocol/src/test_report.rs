//! What this host read out of the test reports a suite wrote, and the method that answers it.
//!
//! A suite that runs in a workflow declares the paths it writes besides the source it was given.
//! When one of them is a report in a format this host documents (JUnit XML, or the event stream of
//! `go test -json`), the host reads it after the suite has ended and keeps what it found beside the
//! result it already records for the run.
//!
//! * **`parsed` is the label.** A [`TestReport`] whose [`ReportReading`] is `parsed` says the host
//!   read the document as the named format, against that format's documented elements, and counted
//!   its cases itself: the totals come from the cases, never from the counts the tool wrote in its
//!   own header. It says nothing about a reading of a runner's human output, which this host does
//!   not make.
//! * **Names and outcomes, never text.** A case holds its name, its group and what became of it.
//!   The failure message, the stack trace and the output of the case are text the code under test
//!   produced, can carry a value the test printed, and stay in the session's retained history.
//! * **A report is bound to the result.** It names the run, the declared path and the digest of the
//!   file the result already records as an output reference, so a report that does not match the
//!   result it describes is not served.
//! * **The answer is bounded.** A report lists at most [`MAX_REPORT_CASES`] cases with names of at
//!   most [`MAX_REPORT_NAME_BYTES`] bytes, so it encodes in under 20 KiB, and an answer holds at
//!   most [`MAX_REPORTS_PER_ANSWER`] reports and counts the rest in [`TestReportsResult::omitted`].

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::ids::{ChangeSetId, ChangeSetVersion, MaterialisationId};
use crate::scalars::{Digest256, Nullable, TimestampMs, U64};

/// How many cases a report lists before it counts the rest in [`ReportReading::Parsed::cases_omitted`].
///
/// Only the cases that did not pass plainly are listed: those that failed, errored, were skipped or
/// passed after a rerun. The totals count every case.
pub const MAX_REPORT_CASES: usize = 50;

/// The longest name or group a case keeps, in bytes, cut at a character boundary.
pub const MAX_REPORT_NAME_BYTES: usize = 128;

/// How many reports one answer holds, the newest result's first.
pub const MAX_REPORTS_PER_ANSWER: usize = 32;

/// The documented format a report was read as.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ReportFormat {
    /// JUnit XML as the Jenkins plugin documents it: `testsuites` or `testsuite` holding
    /// `testcase` elements, each with an optional `failure`, `error` or `skipped`, and the rerun
    /// and flaky elements of the tools that write them.
    JunitXml,
    /// The event stream `go test -json` writes: `TestEvent` objects, and the `BuildEvent` objects
    /// the go command interleaves with them.
    GoTestJson,
}

/// What became of a case that did not pass plainly.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ReportOutcome {
    /// The test ran and its assertion failed.
    Failed,
    /// The test or its setup met an unexpected problem, or the package or build it belongs to
    /// failed.
    Errored,
    /// The test did not run.
    Skipped,
    /// The test failed and then passed on a rerun.
    Flaky,
}

/// Why a document a suite wrote in a documented format was not read.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum UnreadableReason {
    /// The file is longer than this host reads of one report, or the run's reports together are.
    OverSize,
    /// The document nests deeper than this host reads.
    TooDeep,
    /// The document holds more elements, events or lines than this host reads.
    TooLarge,
    /// The document uses something this host does not read: a document type declaration, or an
    /// encoding other than UTF-8.
    NotSupported,
    /// The document is not well formed in the format its opening showed.
    Malformed,
}

/// What a case count says, counted from the cases themselves.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReportTotals {
    /// Every case.
    pub tests: U64,
    /// The cases that passed, those that passed after a rerun included.
    pub passed: U64,
    /// The cases that failed.
    pub failed: U64,
    /// The cases that errored.
    pub errored: U64,
    /// The cases that were skipped.
    pub skipped: U64,
    /// The cases that passed only after a rerun. They are also in `passed`.
    pub flaky: U64,
}

/// One case that did not pass plainly.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReportCase {
    /// The test's name as the tool wrote it, at most [`MAX_REPORT_NAME_BYTES`] bytes. It is report
    /// content: a parameterised test's name can carry the value it ran with.
    pub name: String,
    /// The class, suite or package the tool put it in, bounded in the same way.
    pub group: Nullable<String>,
    /// What became of it.
    pub outcome: ReportOutcome,
    /// How long it ran, in milliseconds, when the tool said.
    pub duration_ms: Nullable<U64>,
}

/// What this host made of the document.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum ReportReading {
    /// The host read the document as its format and counted the cases itself.
    Parsed {
        /// The counts, taken from the cases.
        totals: ReportTotals,
        /// The first [`MAX_REPORT_CASES`] cases that did not pass plainly, in document order.
        cases: Vec<ReportCase>,
        /// How many such cases there were beyond those listed.
        cases_omitted: U64,
    },
    /// The document opened as a documented format and could not be read as one.
    Unreadable {
        /// Why.
        reason: UnreadableReason,
    },
}

/// What this host read out of one declared output of one run.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TestReport {
    /// The run it belongs to: the materialisation the suite ran in, which names the version.
    pub materialisation_id: MaterialisationId,
    /// The declared output the document was, relative to the copy's root.
    pub output_path: String,
    /// The digest of the file, as the run's result records it for this output.
    pub output_digest: Digest256,
    /// The file's length in bytes.
    pub output_bytes: U64,
    /// The format the document opened as.
    pub format: ReportFormat,
    /// What this host made of it.
    pub reading: ReportReading,
    /// When this host recorded it.
    pub recorded_at_ms: TimestampMs,
}

/// Parameters of `changeset.test_reports`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TestReportsParams {
    /// The change set to read.
    pub change_set_id: ChangeSetId,
    /// The version to read, or nothing for the latest.
    pub version: Nullable<ChangeSetVersion>,
    /// One run of the version, to read the reports of that run alone, or nothing for the newest
    /// runs of the version.
    pub materialisation_id: Nullable<MaterialisationId>,
}

/// Result of `changeset.test_reports`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TestReportsResult {
    /// The version that was asked for.
    pub version: crate::changeset::VersionRef,
    /// The reports of the version's runs, the newest result's first, at most
    /// [`MAX_REPORTS_PER_ANSWER`].
    pub reports: Vec<TestReport>,
    /// How many reports the version has beyond those listed.
    pub omitted: U64,
}
