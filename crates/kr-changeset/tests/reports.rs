//! KR-REQ-25.06: test reports in a documented format are parsed, and said to be parsed.
//!
//! The reader is held to what real tools wrote (`tests/fixtures/reports`, each recorded from the
//! tool its name gives) and to the documents a hostile suite could write instead.

use kr_changeset::report::{self, MAX_GO_LINE_BYTES};
use kr_protocol::test_report::{
    MAX_REPORT_CASES, MAX_REPORT_NAME_BYTES, ReportCase, ReportFormat, ReportOutcome,
    ReportReading, UnreadableReason,
};

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/reports")
            .join(name),
    )
    .expect("the fixture is there")
}

/// What the reader made of a whole document.
fn read(bytes: &[u8]) -> Option<(ReportFormat, ReportReading)> {
    report::read(bytes, true)
}

fn parsed(bytes: &[u8]) -> (ReportFormat, [u64; 6], Vec<ReportCase>, u64) {
    match read(bytes).expect("the document opens as a report") {
        (
            format,
            ReportReading::Parsed {
                totals,
                cases,
                cases_omitted,
            },
        ) => (
            format,
            [
                totals.tests.get(),
                totals.passed.get(),
                totals.failed.get(),
                totals.errored.get(),
                totals.skipped.get(),
                totals.flaky.get(),
            ],
            cases,
            cases_omitted.get(),
        ),
        (_, ReportReading::Unreadable { reason }) => {
            panic!("the document was not read: {reason:?}")
        }
    }
}

fn refused(bytes: &[u8]) -> UnreadableReason {
    match read(bytes).expect("the document opens as a report") {
        (_, ReportReading::Unreadable { reason }) => reason,
        (_, ReportReading::Parsed { .. }) => panic!("the document was read"),
    }
}

fn names(cases: &[ReportCase]) -> Vec<(String, ReportOutcome)> {
    cases
        .iter()
        .map(|case| (case.name.clone(), case.outcome))
        .collect()
}

use ReportOutcome::{Errored, Failed, Flaky, Skipped};

/// Each tool's report decodes to the counts and the cases the tool itself states: totals are the
/// cases', and a case that passed after a rerun is a pass that is also flaky.
#[test]
fn a_report_decodes_to_what_its_tool_says() {
    // tests, passed, failed, errored, skipped, flaky
    let (format, totals, cases, omitted) = parsed(&fixture("nextest-0.9.146.junit.xml"));
    assert_eq!(format, ReportFormat::JunitXml);
    assert_eq!(totals, [5, 2, 2, 0, 1, 1]);
    assert_eq!(omitted, 0);
    assert_eq!(
        names(&cases),
        [
            ("tests::is_ignored".to_owned(), Skipped),
            ("tests::fails_an_assertion".to_owned(), Failed),
            ("tests::passes_on_the_third_attempt".to_owned(), Flaky),
            ("tests::panics_on_purpose".to_owned(), Failed),
        ]
    );
    assert_eq!(cases[1].group.0.as_deref(), Some("sample"));

    // The class a case names is its group, with the name of the file the suite is in as it
    // wrote it; the case's duration is in milliseconds.
    let (format, totals, cases, _) = parsed(&fixture("vitest-5.0.5.junit.xml"));
    assert_eq!(format, ReportFormat::JunitXml);
    assert_eq!(totals, [6, 2, 2, 0, 2, 0]);
    assert_eq!(
        names(&cases),
        [
            ("arithmetic > fails an assertion".to_owned(), Failed),
            ("arithmetic > is skipped".to_owned(), Skipped),
            ("arithmetic > is a todo".to_owned(), Skipped),
            ("arithmetic > table 2".to_owned(), Failed),
        ]
    );
    assert_eq!(cases[0].group.0.as_deref(), Some("sample.test.js"));
    assert!(cases[0].duration_ms.0.is_some());

    // An error in a fixture is an error, an expected failure is skipped, and the tool's own
    // header says seven tests with two failed, one errored and two skipped.
    let (_, totals, cases, _) = parsed(&fixture("pytest-9.2.0.junit.xml"));
    assert_eq!(totals, [7, 2, 2, 1, 2, 0]);
    assert!(
        names(&cases).contains(&("test_errors_in_setup".to_owned(), Errored)),
        "{cases:?}"
    );

    // `go test`'s own summary: two passes, three failures (a subtest and its parent among them)
    // and a skip.
    let (format, totals, cases, _) = parsed(&fixture("go-1.27.1.pass-fail-skip.json"));
    assert_eq!(format, ReportFormat::GoTestJson);
    assert_eq!(totals, [6, 2, 3, 0, 1, 0]);
    assert_eq!(
        names(&cases),
        [
            ("TestFails".to_owned(), Failed),
            ("TestSkips".to_owned(), Skipped),
            ("TestTable/b".to_owned(), Failed),
            ("TestTable".to_owned(), Failed),
        ]
    );
    assert_eq!(cases[0].group.0.as_deref(), Some("example.test/sample/ok"));
}

/// A package that does not build is a stream whose first events are the go command's build events,
/// and it is one errored case, not one for the build and another for the package it left failed.
#[test]
fn a_go_package_that_did_not_build_is_one_errored_case() {
    let (format, totals, cases, _) = parsed(&fixture("go-1.27.1.build-failure.json"));
    assert_eq!(format, ReportFormat::GoTestJson);
    assert_eq!(totals, [7, 2, 3, 1, 1, 0]);
    assert_eq!(
        names(&cases)[0],
        (
            "example.test/sample/broken [example.test/sample/broken.test]".to_owned(),
            Errored
        )
    );
}

/// A package that failed with no test failing is a case of its own, named by the package, and a
/// package that failed because a test did is not counted twice.
#[test]
fn a_package_failure_with_no_failed_test_is_a_case_of_its_own() {
    let stream = concat!(
        r#"{"Action":"start","Package":"a"}"#,
        "\n",
        r#"{"Action":"fail","Package":"a","Elapsed":0.1}"#,
        "\n",
        r#"{"Action":"start","Package":"b"}"#,
        "\n",
        r#"{"Action":"fail","Package":"b","Test":"TestX","Elapsed":0}"#,
        "\n",
        r#"{"Action":"fail","Package":"b","Elapsed":0.1}"#,
        "\n",
        "go: a line the go command wrote to standard error\n",
    );
    let (_, totals, cases, _) = parsed(stream.as_bytes());
    assert_eq!(totals, [2, 0, 1, 1, 0, 0]);
    assert_eq!(
        names(&cases),
        [("TestX".to_owned(), Failed), ("a".to_owned(), Errored)]
    );
}

/// A document that is not a report leaves no record, and one that opens as a report and cannot
/// be read says why.
#[test]
fn what_is_not_a_report_is_not_one_and_what_cannot_be_read_says_why() {
    for not_a_report in [
        &b"<project><name>sample</name></project>"[..],
        br#"{"name":"package.json","version":"1.0.0"}"#,
        b"plain text, a log",
        b"",
        br#"{"Action":"unheard-of","Package":"a"}"#,
        b"<?xml version=\"1.0\"?><!-- a comment only -->",
    ] {
        assert!(read(not_a_report).is_none(), "{not_a_report:?}");
    }

    // An entity declared in the document is never expanded: the document is refused before it
    // could grow.
    let laughs = br#"<?xml version="1.0"?>
<!DOCTYPE testsuites [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">]>
<testsuites><testsuite name="&b;"><testcase name="t"/></testsuite></testsuites>"#;
    assert_eq!(refused(laughs), UnreadableReason::NotSupported);

    // A document of another encoding is not read as UTF-8 by guess.
    let latin = b"<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><testsuite><testcase name=\"t\"/></testsuite>";
    assert_eq!(refused(latin), UnreadableReason::NotSupported);

    assert_eq!(
        refused(b"<testsuite><testcase name=\"caf\xe9\"/></testsuite>"),
        UnreadableReason::Malformed
    );
    assert_eq!(
        refused(b"<testsuite><testcase name=\"a\"><failure>"),
        UnreadableReason::Malformed
    );
    assert_eq!(
        refused(b"<testsuite><testcase name=\"a&nothing;\"/></testsuite>"),
        UnreadableReason::Malformed
    );
    assert_eq!(
        refused(b"<testsuite><testcase name=\"a\"/></testcase></testsuite>"),
        UnreadableReason::Malformed
    );

    // A file longer than a run keeps is recognised from its opening and refused as over size.
    let opening = &fixture("nextest-0.9.146.junit.xml")[..4096];
    assert_eq!(
        report::read(opening, false).map(|(format, reading)| (
            format,
            matches!(
                reading,
                ReportReading::Unreadable {
                    reason: UnreadableReason::OverSize
                }
            )
        )),
        Some((ReportFormat::JunitXml, true))
    );
    assert!(report::read(b"not a report", false).is_none());
}

/// Nothing a document nests or repeats can make this host recurse, allocate without bound or
/// follow it past a limit: the cases that would abort a recursive reader are read to a refusal.
#[test]
fn a_hostile_document_is_refused_and_never_followed() {
    let mut nested = String::from("<testsuites>");
    nested.push_str(&"<testsuite>".repeat(10_000));
    nested.push_str(&"</testsuite>".repeat(10_000));
    nested.push_str("</testsuites>");
    assert_eq!(refused(nested.as_bytes()), UnreadableReason::TooDeep);

    // A thousand attributes on one element are looked at 64 at a time and no more.
    let mut wide = String::from("<testsuite><testcase name=\"kept\"");
    for index in 0..100_000 {
        wide.push_str(&format!(" a{index}=\"x\""));
    }
    wide.push_str("/></testsuite>");
    let (_, totals, _, _) = parsed(wide.as_bytes());
    assert_eq!(totals[0], 1);

    // A line longer than the stream may hold, and a deeply nested value in a member the reader
    // does not read: the first is refused, the second is skipped without growing the stack.
    let mut long = b"{\"Action\":\"start\",\"Package\":\"p\"}\n".to_vec();
    long.extend_from_slice(br#"{"Action":"pass","Package":"p","Test":"t","Output":""#);
    long.extend(std::iter::repeat_n(b'x', MAX_GO_LINE_BYTES));
    long.extend_from_slice(b"\"}\n");
    assert_eq!(refused(&long), UnreadableReason::TooLarge);

    let mut deep = b"{\"Action\":\"start\",\"Package\":\"p\"}\n".to_vec();
    deep.extend_from_slice(br#"{"Action":"pass","Package":"p","Test":"t","Extra":"#);
    deep.extend(std::iter::repeat_n(b'[', 100_000));
    deep.extend(std::iter::repeat_n(b']', 100_000));
    deep.extend_from_slice(b"}\n");
    let (format, totals, _, _) = parsed(&deep);
    assert_eq!(format, ReportFormat::GoTestJson);
    assert_eq!(totals[0], 1);

    // More lines of the go command's own error text than a stream may mix in.
    let mut stray = String::from(r#"{"Action":"start","Package":"p"}"#);
    stray.push('\n');
    for _ in 0..1_001 {
        stray.push_str("go: error\n");
    }
    assert_eq!(refused(stray.as_bytes()), UnreadableReason::Malformed);
}

/// A report that lists more than it keeps counts what it leaves out and keeps the totals exact; a
/// name is cut at a character boundary, and a duration a tool wrote with a grouping comma is read.
#[test]
fn a_long_report_keeps_exact_totals_and_bounded_names() {
    let mut xml = String::from("<testsuites><testsuite name=\"suite\">");
    for index in 0..(MAX_REPORT_CASES + 20) {
        xml.push_str(&format!(
            "<testcase name=\"case {index}\" classname=\"c\" time=\"1,234.5\"><failure/></testcase>"
        ));
    }
    xml.push_str("<testcase name=\"fine\"/>");
    let long_name = "é".repeat(MAX_REPORT_NAME_BYTES);
    xml.push_str(&format!(
        "<testcase name=\"{long_name}\"><skipped/></testcase>"
    ));
    xml.push_str("</testsuite></testsuites>");
    let (_, totals, cases, omitted) = parsed(xml.as_bytes());
    let failing = (MAX_REPORT_CASES + 20) as u64;
    assert_eq!(totals, [failing + 2, 1, failing, 0, 1, 0]);
    assert_eq!(cases.len(), MAX_REPORT_CASES);
    assert_eq!(omitted, 21);
    assert_eq!(
        cases[0].duration_ms.0.map(|duration| duration.get()),
        Some(1_234_500)
    );

    let (_, _, cases, _) = parsed(
        format!("<testsuite><testcase name=\"{long_name}\"><skipped/></testcase></testsuite>")
            .as_bytes(),
    );
    assert_eq!(cases[0].name.len(), MAX_REPORT_NAME_BYTES);
    assert_eq!(cases[0].name, "é".repeat(MAX_REPORT_NAME_BYTES / 2));
}
