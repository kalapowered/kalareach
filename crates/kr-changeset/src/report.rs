//! Reading the test reports a suite wrote, in the formats their tools document.
//!
//! The document is written by code under test, so it is hostile input in the daemon's own
//! process. Every reading here is iterative, never recurses on the document's depth, and holds
//! nothing of a case but its name, its group and what became of it: the failure text, the stack
//! trace and the output of a case are not read into memory at all.
//!
//! * **JUnit XML**, as the Jenkins plugin documents it (`testsuites` or `testsuite`, holding
//!   `testcase` elements, each with an optional `failure`, `error` or `skipped`), with the rerun
//!   and flaky elements the tools that retry add. A document type declaration is refused, and the
//!   only entities read are the five predefined ones and numeric character references: nothing is
//!   expanded, so a document cannot grow when it is read.
//! * **`go test -json`**, the event stream `go help buildjson` and `go doc cmd/test2json`
//!   document: `TestEvent` objects and the `BuildEvent` objects the go command interleaves with
//!   them, told apart by their `Action`.
//!
//! The format is recognised from the document's opening, so an owner declares nothing: a file that
//! opens as neither is not a report, and leaves no record.
//!
//! Totals are counted from the cases, never taken from the counts a tool wrote in its own header,
//! which disagree between tools. How a case counts is stated on [`ReportTotals`] and in the guide.

use std::collections::HashSet;

use kr_protocol::scalars::{Nullable, U64};
use kr_protocol::test_report::{
    MAX_REPORT_CASES, MAX_REPORT_NAME_BYTES, ReportCase, ReportFormat, ReportOutcome,
    ReportReading, ReportTotals, UnreadableReason,
};
use quick_xml::XmlVersion;
use quick_xml::events::{BytesStart, Event};
use quick_xml::reader::Reader;
use serde::Deserialize;

/// The deepest element nesting of a JUnit document this host reads.
pub const MAX_XML_DEPTH: usize = 24;

/// The most events (tags, text, comments) of a JUnit document this host reads.
pub const MAX_XML_EVENTS: usize = 2_000_000;

/// The most attributes of one element this host looks at.
pub const MAX_ATTRIBUTES: usize = 64;

/// The most lines of a `go test -json` stream this host reads.
pub const MAX_GO_LINES: usize = 2_000_000;

/// The longest line of a `go test -json` stream this host reads, in bytes.
pub const MAX_GO_LINE_BYTES: usize = 1024 * 1024;

/// The most lines of a `go test -json` stream that may be something other than an event before
/// the stream is taken for malformed: the go command writes error text to standard error, which a
/// suite that redirects both into its report mixes in.
pub const MAX_GO_STRAY_LINES: usize = 1_000;

/// The most packages a `go test -json` stream may fail a test in.
pub const MAX_GO_PACKAGES: usize = 20_000;

/// Reads a declared output as a report.
///
/// `bytes` is the whole file when `complete` and its opening otherwise. Returns nothing when the
/// opening shows no documented format, which is every file that is not a report. A file that
/// shows one and is not the whole file is refused as over the size this host reads.
#[must_use]
pub fn read(bytes: &[u8], complete: bool) -> Option<(ReportFormat, ReportReading)> {
    let format = recognise(bytes)?;
    if !complete {
        return Some((
            format,
            ReportReading::Unreadable {
                reason: UnreadableReason::OverSize,
            },
        ));
    }
    let read = match format {
        ReportFormat::JunitXml => read_junit(bytes),
        ReportFormat::GoTestJson => read_go(bytes),
    };
    Some((
        format,
        read.unwrap_or_else(|reason| ReportReading::Unreadable { reason }),
    ))
}

/// The format the start of a document shows, if it shows one this host reads.
#[must_use]
pub fn recognise(bytes: &[u8]) -> Option<ReportFormat> {
    let opening = &bytes[..bytes.len().min(crate::materialise::OPENING_BYTES)];
    let text = valid_prefix(opening);
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    match text.trim_start().chars().next()? {
        '<' => recognise_xml(text),
        '{' => recognise_go(text),
        _ => None,
    }
}

/// The longest prefix of `bytes` that is UTF-8: an opening cut inside a character is still text.
fn valid_prefix(bytes: &[u8]) -> &str {
    match std::str::from_utf8(bytes) {
        Ok(text) => text,
        Err(error) => std::str::from_utf8(&bytes[..error.valid_up_to()]).unwrap_or(""),
    }
}

fn recognise_xml(text: &str) -> Option<ReportFormat> {
    let mut reader = Reader::from_str(text);
    for _ in 0..1_000 {
        match reader.read_event().ok()? {
            Event::Start(element) | Event::Empty(element) => {
                return matches!(element.name().as_ref(), "testsuites" | "testsuite")
                    .then_some(ReportFormat::JunitXml);
            }
            Event::Eof => return None,
            _ => {}
        }
    }
    None
}

/// The `Action` words of the events `go test -json` writes: the nine of a test event, and the two
/// of a build event.
const GO_ACTIONS: [&str; 11] = [
    "start",
    "run",
    "pause",
    "cont",
    "pass",
    "bench",
    "fail",
    "output",
    "skip",
    "build-output",
    "build-fail",
];

fn recognise_go(text: &str) -> Option<ReportFormat> {
    let line = text.lines().find(|line| !line.trim().is_empty())?;
    let event: GoEvent = serde_json::from_str(line).ok()?;
    GO_ACTIONS
        .contains(&event.action.as_deref()?)
        .then_some(ReportFormat::GoTestJson)
}

/// What the cases of one document add up to, and the first of them that did not pass plainly.
#[derive(Default)]
struct Tally {
    tests: u64,
    passed: u64,
    failed: u64,
    errored: u64,
    skipped: u64,
    flaky: u64,
    cases: Vec<ReportCase>,
    omitted: u64,
}

impl Tally {
    /// A case that passed and says nothing more.
    fn passed_plainly(&mut self) {
        self.tests += 1;
        self.passed += 1;
    }

    /// A case that did not pass plainly. The first [`MAX_REPORT_CASES`] are kept by name.
    fn count(&mut self, case: ReportCase) {
        self.tests += 1;
        match case.outcome {
            ReportOutcome::Failed => self.failed += 1,
            ReportOutcome::Errored => self.errored += 1,
            ReportOutcome::Skipped => self.skipped += 1,
            ReportOutcome::Flaky => {
                self.passed += 1;
                self.flaky += 1;
            }
        }
        if self.cases.len() < MAX_REPORT_CASES {
            self.cases.push(case);
        } else {
            self.omitted += 1;
        }
    }

    fn finish(self) -> ReportReading {
        ReportReading::Parsed {
            totals: ReportTotals {
                tests: U64::new(self.tests),
                passed: U64::new(self.passed),
                failed: U64::new(self.failed),
                errored: U64::new(self.errored),
                skipped: U64::new(self.skipped),
                flaky: U64::new(self.flaky),
            },
            cases: self.cases,
            cases_omitted: U64::new(self.omitted),
        }
    }
}

/// A name kept as the record keeps it: cut at a character boundary within
/// [`MAX_REPORT_NAME_BYTES`], with a control character replaced.
fn kept(text: &str) -> String {
    let mut name = String::new();
    for character in text.chars() {
        let character = if character.is_control() {
            '?'
        } else {
            character
        };
        if name.len() + character.len_utf8() > MAX_REPORT_NAME_BYTES {
            break;
        }
        name.push(character);
    }
    name
}

fn milliseconds(seconds: f64) -> Nullable<U64> {
    if seconds.is_finite() && seconds >= 0.0 {
        // A duration of more than u64::MAX milliseconds saturates, which a float cast does.
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        Nullable::some(U64::new((seconds * 1000.0).round() as u64))
    } else {
        Nullable::null()
    }
}

// ----- JUnit XML ---------------------------------------------------------------------------------

/// A `testcase` element being read.
struct OpenCase {
    /// How deep the element is, so that only its own children say what became of it.
    depth: usize,
    name: String,
    group: Option<String>,
    duration: Nullable<U64>,
    failed: bool,
    errored: bool,
    skipped: bool,
    retried_to_a_pass: bool,
}

fn read_junit(bytes: &[u8]) -> Result<ReportReading, UnreadableReason> {
    let text = std::str::from_utf8(bytes).map_err(|_| UnreadableReason::Malformed)?;
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut reader = Reader::from_str(text);
    let mut tally = Tally::default();
    let mut depth = 0_usize;
    let mut events = 0_usize;
    // The elements at the top of the document: a well-formed document has one, and a case outside
    // it is no part of the report.
    let mut roots = 0_usize;
    // The names of the `testsuite` elements around the element being read, innermost last, as
    // the group of a case that names no class.
    let mut suites: Vec<(usize, String)> = Vec::new();
    let mut case: Option<OpenCase> = None;
    loop {
        events += 1;
        if events > MAX_XML_EVENTS {
            return Err(UnreadableReason::TooLarge);
        }
        match reader
            .read_event()
            .map_err(|_| UnreadableReason::Malformed)?
        {
            Event::Eof => break,
            Event::DocType(_) => return Err(UnreadableReason::NotSupported),
            Event::Decl(declaration) => {
                if let Some(encoding) = declaration.encoding() {
                    let encoding = encoding.map_err(|_| UnreadableReason::Malformed)?;
                    if !encoding.eq_ignore_ascii_case("utf-8") {
                        return Err(UnreadableReason::NotSupported);
                    }
                }
            }
            Event::Start(element) => {
                roots += usize::from(depth == 0);
                if roots > 1 {
                    return Err(UnreadableReason::Malformed);
                }
                depth += 1;
                if depth > MAX_XML_DEPTH {
                    return Err(UnreadableReason::TooDeep);
                }
                open_element(&element, depth, &mut suites, &mut case)?;
            }
            Event::Empty(element) => {
                roots += usize::from(depth == 0);
                if roots > 1 {
                    return Err(UnreadableReason::Malformed);
                }
                if depth + 1 > MAX_XML_DEPTH {
                    return Err(UnreadableReason::TooDeep);
                }
                open_element(&element, depth + 1, &mut suites, &mut case)?;
                close_element(
                    element.name().as_ref(),
                    depth + 1,
                    &mut suites,
                    &mut case,
                    &mut tally,
                );
            }
            Event::End(element) => {
                // The reader refuses an end that does not match its start, so this never
                // underflows.
                close_element(
                    element.name().as_ref(),
                    depth,
                    &mut suites,
                    &mut case,
                    &mut tally,
                );
                depth = depth.saturating_sub(1);
            }
            // Text, a CDATA section or a reference outside the root element is no part of an
            // XML document; white space between the markup is.
            Event::Text(text) if depth == 0 => {
                if text
                    .bytes()
                    .any(|byte| !matches!(byte, b' ' | b'\t' | b'\r' | b'\n'))
                {
                    return Err(UnreadableReason::Malformed);
                }
            }
            Event::CData(_) | Event::GeneralRef(_) if depth == 0 => {
                return Err(UnreadableReason::Malformed);
            }
            _ => {}
        }
    }
    if depth != 0 || roots != 1 {
        return Err(UnreadableReason::Malformed);
    }
    Ok(tally.finish())
}

fn open_element(
    element: &BytesStart<'_>,
    depth: usize,
    suites: &mut Vec<(usize, String)>,
    case: &mut Option<OpenCase>,
) -> Result<(), UnreadableReason> {
    match element.name().as_ref() {
        "testsuite" => {
            let mut name = String::new();
            for attribute in element.attributes().with_checks(false).take(MAX_ATTRIBUTES) {
                let attribute = attribute.map_err(|_| UnreadableReason::Malformed)?;
                if attribute.key.as_ref() == "name" {
                    name = kept(&value_of(&attribute)?);
                }
            }
            suites.push((depth, name));
        }
        "testcase" if case.is_none() => {
            let mut open = OpenCase {
                depth,
                name: String::new(),
                group: None,
                duration: Nullable::null(),
                failed: false,
                errored: false,
                skipped: false,
                retried_to_a_pass: false,
            };
            for attribute in element.attributes().with_checks(false).take(MAX_ATTRIBUTES) {
                let attribute = attribute.map_err(|_| UnreadableReason::Malformed)?;
                match attribute.key.as_ref() {
                    "name" => open.name = kept(&value_of(&attribute)?),
                    "classname" => {
                        let class = kept(&value_of(&attribute)?);
                        open.group = (!class.is_empty()).then_some(class);
                    }
                    "time" => {
                        // A Surefire report may group the thousands of a duration with commas.
                        let seconds = value_of(&attribute)?.replace(',', "");
                        open.duration = seconds
                            .trim()
                            .parse()
                            .map_or(Nullable::null(), milliseconds);
                    }
                    _ => {}
                }
            }
            *case = Some(open);
        }
        // What became of a case is said by its own children, and no deeper element.
        "failure" | "error" | "skipped" | "flakyFailure" | "flakyError" => {
            if let Some(open) = case.as_mut()
                && depth == open.depth + 1
            {
                match element.name().as_ref() {
                    "failure" => open.failed = true,
                    "error" => open.errored = true,
                    "skipped" => open.skipped = true,
                    _ => open.retried_to_a_pass = true,
                }
            }
        }
        _ => {}
    }
    Ok(())
}

fn close_element(
    name: &str,
    depth: usize,
    suites: &mut Vec<(usize, String)>,
    case: &mut Option<OpenCase>,
    tally: &mut Tally,
) {
    match name {
        "testsuite" => {
            if suites.last().is_some_and(|(at, _)| *at == depth) {
                suites.pop();
            }
        }
        "testcase" => {
            if case.as_ref().is_some_and(|open| open.depth == depth)
                && let Some(open) = case.take()
            {
                let outcome = if open.failed {
                    Some(ReportOutcome::Failed)
                } else if open.errored {
                    Some(ReportOutcome::Errored)
                } else if open.skipped {
                    Some(ReportOutcome::Skipped)
                } else if open.retried_to_a_pass {
                    Some(ReportOutcome::Flaky)
                } else {
                    None
                };
                match outcome {
                    Some(outcome) => {
                        let group = open
                            .group
                            .or_else(|| suites.last().map(|(_, name)| name.clone()))
                            .filter(|group| !group.is_empty());
                        tally.count(ReportCase {
                            name: open.name,
                            group: Nullable(group),
                            outcome,
                            duration_ms: open.duration,
                        });
                    }
                    None => tally.passed_plainly(),
                }
            }
        }
        _ => {}
    }
}

fn value_of(
    attribute: &quick_xml::events::attributes::Attribute<'_>,
) -> Result<String, UnreadableReason> {
    attribute
        .normalized_value(XmlVersion::Implicit1_0)
        .map(std::borrow::Cow::into_owned)
        .map_err(|_| UnreadableReason::Malformed)
}

// ----- go test -json -----------------------------------------------------------------------------

/// The members of a `TestEvent` or a `BuildEvent` this host reads. The others, `Output` among
/// them, are skipped as they are read and never held.
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct GoEvent {
    action: Option<String>,
    package: Option<String>,
    test: Option<String>,
    elapsed: Option<f64>,
    import_path: Option<String>,
    failed_build: Option<String>,
}

fn read_go(bytes: &[u8]) -> Result<ReportReading, UnreadableReason> {
    let mut tally = Tally::default();
    // The packages a test failed in, which a package's own failure is the consequence of. A
    // package is told apart by the digest of its whole name, and not by the name that is kept for
    // display, which is cut: two packages whose names agree up to the cut are two packages.
    let mut failed_in: HashSet<kr_protocol::scalars::Digest256> = HashSet::new();
    let mut stray = 0_usize;
    for (index, line) in bytes.split(|byte| *byte == b'\n').enumerate() {
        if index >= MAX_GO_LINES {
            return Err(UnreadableReason::TooLarge);
        }
        if line.len() > MAX_GO_LINE_BYTES {
            return Err(UnreadableReason::TooLarge);
        }
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let event = match serde_json::from_slice::<GoEvent>(line) {
            Ok(event) if event.action.is_some() => event,
            _ => {
                stray += 1;
                if stray > MAX_GO_STRAY_LINES {
                    return Err(UnreadableReason::Malformed);
                }
                continue;
            }
        };
        let group = event.package.as_deref().map(kept);
        let package = event
            .package
            .as_deref()
            .map(|name| crate::objects::digest_of(name.as_bytes()));
        match (event.action.as_deref(), event.test.as_deref()) {
            (Some("pass"), Some(_)) => tally.passed_plainly(),
            (Some(action @ ("fail" | "skip")), Some(test)) => {
                let outcome = if action == "fail" {
                    if let Some(package) = package
                        && !failed_in.contains(&package)
                    {
                        if failed_in.len() >= MAX_GO_PACKAGES {
                            return Err(UnreadableReason::TooLarge);
                        }
                        failed_in.insert(package);
                    }
                    ReportOutcome::Failed
                } else {
                    ReportOutcome::Skipped
                };
                tally.count(ReportCase {
                    name: kept(test),
                    group: Nullable(group),
                    outcome,
                    duration_ms: event.elapsed.map_or(Nullable::null(), milliseconds),
                });
            }
            // A package that failed, with no name of a test: the consequence of a failed test, the
            // consequence of a build that failed (which names it, and has a case of its own), or a
            // failure of the package itself. The package's own events come before this last one,
            // so a package with no failed test by now failed by itself, and its case stands where
            // the failure is in the stream.
            (Some("fail"), None) if event.failed_build.is_none() => {
                if let (Some(name), Some(package)) = (group, package)
                    && !failed_in.contains(&package)
                {
                    tally.count(ReportCase {
                        name,
                        group: Nullable::null(),
                        outcome: ReportOutcome::Errored,
                        duration_ms: Nullable::null(),
                    });
                }
            }
            (Some("build-fail"), _) => tally.count(ReportCase {
                name: event.import_path.as_deref().map(kept).unwrap_or_default(),
                group: Nullable::null(),
                outcome: ReportOutcome::Errored,
                duration_ms: Nullable::null(),
            }),
            _ => {}
        }
    }
    Ok(tally.finish())
}
