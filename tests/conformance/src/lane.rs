//! The results of the phone applications' unit tests: the Kotlin tests Gradle runs and the Swift
//! tests Xcode runs.
//!
//! The report does not build these languages' tests. A lane's script runs them and leaves what the
//! tool wrote: the JUnit files Gradle writes, one for each test class, or the test tree
//! `xcresulttool` prints for the result bundle of an Xcode run. This module reads those into one
//! list of cases and holds them to the rules a result has to keep before the report believes it:
//! the files agree with their own counts, a failed suite has a failed case, no case is reported
//! twice, and the tool's exit status agrees with the cases. A source file belongs to the cases of
//! the classes it declares.

use std::path::Path;

use quick_xml::XmlVersion;
use quick_xml::events::{BytesStart, Event};
use quick_xml::reader::Reader;
use serde_json::Value;

use crate::libtest::Outcome;

/// One test a lane's tool reported.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Case {
    /// The class that holds it: a Kotlin class by its full name, a Swift class by its name.
    pub class: String,
    /// Its name.
    pub name: String,
    /// What names it to the tool that ran it, to run it alone: `Class.method` for Gradle's
    /// `--tests`, `Bundle/Class/method` for Xcode's `-only-testing`.
    pub selector: String,
    /// What it came to.
    pub outcome: Outcome,
    /// Why it came to that, when the tool said more than the outcome: an expected failure is a
    /// failure here, and the status of a tool that passes it is no sign that a case failed.
    pub note: Option<String>,
}

/// Reads the JUnit files Gradle wrote into `directory`, one for each test class.
///
/// # Errors
///
/// Returns why the files cannot be believed: there are none, one is not JUnit XML, one disagrees
/// with the counts it states about itself, or a case is reported twice.
pub fn read_junit(directory: &Path) -> Result<Vec<Case>, String> {
    let mut files: Vec<_> = std::fs::read_dir(directory)
        .map_err(|error| format!("{} could not be read: {error}", directory.display()))?
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|extension| extension == "xml"))
        .collect();
    files.sort();
    if files.is_empty() {
        return Err(format!("{} holds no JUnit file", directory.display()));
    }
    let mut cases = Vec::new();
    for file in files {
        let text = std::fs::read_to_string(&file)
            .map_err(|error| format!("{} could not be read: {error}", file.display()))?;
        cases.extend(parse_junit(&text).map_err(|error| format!("{}: {error}", file.display()))?);
    }
    refuse_repeats(&cases)?;
    Ok(cases)
}

/// Refuses a case reported twice: the report keeps one record for a name, and a repeat that failed
/// after a first that passed would be lost.
fn refuse_repeats(cases: &[Case]) -> Result<(), String> {
    let mut seen = std::collections::BTreeSet::new();
    for case in cases {
        if !seen.insert((&case.class, &case.name)) {
            return Err(format!("{}.{} is reported twice", case.class, case.name));
        }
    }
    Ok(())
}

/// What a `testsuite` element says about itself.
#[derive(Default)]
struct Stated {
    tests: Option<usize>,
    skipped: Option<usize>,
    failures: Option<usize>,
    errors: Option<usize>,
}

fn attribute(element: &BytesStart<'_>, name: &str) -> Result<Option<String>, String> {
    for attribute in element.attributes() {
        let attribute = attribute.map_err(|error| error.to_string())?;
        if attribute.key.as_ref() == name {
            let value = attribute
                .normalized_value(XmlVersion::Implicit1_0)
                .map_err(|error| error.to_string())?;
            return Ok(Some(value.into_owned()));
        }
    }
    Ok(None)
}

fn count(element: &BytesStart<'_>, name: &str) -> Result<Option<usize>, String> {
    attribute(element, name)?
        .map(|value| {
            value
                .parse()
                .map_err(|_| format!("{name}=\"{value}\" is not a count"))
        })
        .transpose()
}

/// Reads one JUnit file.
///
/// # Errors
///
/// Returns why it is not JUnit XML, or how its cases differ from the counts its test suite states.
pub fn parse_junit(text: &str) -> Result<Vec<Case>, String> {
    let mut reader = Reader::from_str(text);
    let mut cases: Vec<Case> = Vec::new();
    let mut stated = Stated::default();
    let mut suites = 0_usize;
    // The case whose children are being read, and whether a child has already judged it.
    let mut open: Option<usize> = None;
    let (mut failed, mut errors, mut skipped) = (0_usize, 0_usize, 0_usize);
    loop {
        let event = reader
            .read_event()
            .map_err(|error| format!("not XML: {error}"))?;
        let (element, closes) = match &event {
            Event::Start(element) => (Some(element), false),
            Event::Empty(element) => (Some(element), true),
            Event::End(end) if end.name().as_ref() == "testcase" => {
                open = None;
                (None, false)
            }
            Event::Eof => break,
            _ => (None, false),
        };
        let Some(element) = element else { continue };
        match element.name().as_ref() {
            "testsuite" => {
                suites += 1;
                if suites > 1 {
                    return Err("holds more than one test suite".to_owned());
                }
                stated = Stated {
                    tests: count(element, "tests")?,
                    skipped: count(element, "skipped")?,
                    failures: count(element, "failures")?,
                    errors: count(element, "errors")?,
                };
            }
            "testcase" => {
                let class =
                    attribute(element, "classname")?.ok_or("a test case without a class")?;
                let name = attribute(element, "name")?.ok_or("a test case without a name")?;
                cases.push(Case {
                    selector: format!("{class}.{name}"),
                    class,
                    name,
                    outcome: Outcome::Passed,
                    note: None,
                });
                open = (!closes).then_some(cases.len() - 1);
            }
            child @ ("failure" | "error" | "skipped") => {
                let Some(at) = open else { continue };
                match child {
                    "failure" => {
                        failed += 1;
                        cases[at].outcome = Outcome::Failed;
                    }
                    "error" => {
                        errors += 1;
                        cases[at].outcome = Outcome::Failed;
                    }
                    _ => {
                        skipped += 1;
                        if cases[at].outcome == Outcome::Passed {
                            cases[at].outcome = Outcome::Skipped("skipped".to_owned());
                        }
                    }
                }
            }
            _ => {}
        }
    }
    if suites == 0 {
        return Err("holds no test suite".to_owned());
    }
    let agree = |what: &str, stated: Option<usize>, found: usize| match stated {
        Some(stated) if stated != found => Err(format!(
            "its test suite states {stated} {what} and the file holds {found}"
        )),
        _ => Ok(()),
    };
    agree("tests", stated.tests, cases.len())?;
    agree("skipped tests", stated.skipped, skipped)?;
    agree("failures", stated.failures, failed)?;
    agree("errors", stated.errors, errors)?;
    Ok(cases)
}

/// Reads the test tree `xcrun xcresulttool get test-results tests` printed.
///
/// # Errors
///
/// Returns why the file cannot be believed: it is not that tool's JSON, a case has a result this
/// module does not know, no case ran, a case is reported twice, or a suite failed with no failed
/// case under it.
pub fn read_xcode(file: &Path) -> Result<Vec<Case>, String> {
    let text = std::fs::read_to_string(file)
        .map_err(|error| format!("{} could not be read: {error}", file.display()))?;
    let value: Value = serde_json::from_str(&text)
        .map_err(|error| format!("{} is not JSON: {error}", file.display()))?;
    parse_xcode(&value).map_err(|error| format!("{}: {error}", file.display()))
}

/// Reads a test tree that has been parsed.
///
/// # Errors
///
/// Returns what makes the tree unbelievable, as [`read_xcode`] states it.
pub fn parse_xcode(value: &Value) -> Result<Vec<Case>, String> {
    let nodes = value["testNodes"]
        .as_array()
        .ok_or("the tree has no test nodes")?;
    let mut cases = Vec::new();
    for node in nodes {
        walk(node, "", "", &mut cases)?;
    }
    if cases.is_empty() {
        return Err("no test case ran".to_owned());
    }
    refuse_repeats(&cases)?;
    Ok(cases)
}

/// Collects the cases under `node`, and returns whether any of them failed.
fn walk(node: &Value, bundle: &str, suite: &str, cases: &mut Vec<Case>) -> Result<bool, String> {
    let kind = node["nodeType"].as_str().unwrap_or_default();
    let name = node["name"]
        .as_str()
        .ok_or("a node without a name")?
        .to_owned();
    let result = node["result"].as_str();
    if kind == "Test Case" {
        let mut note = None;
        let outcome = match result {
            Some("Passed") => Outcome::Passed,
            Some("Failed") => Outcome::Failed,
            Some("Expected Failure") => {
                note = Some(
                    "the case expected to fail, and a case that fails is not a pass".to_owned(),
                );
                Outcome::Failed
            }
            Some("Skipped") => Outcome::Skipped("skipped".to_owned()),
            other => {
                return Err(format!(
                    "{suite}/{name} has the result {other:?}, which this report does not read"
                ));
            }
        };
        let method = name.trim_end_matches("()").to_owned();
        let failed = outcome == Outcome::Failed;
        cases.push(Case {
            selector: format!("{bundle}/{suite}/{method}"),
            class: suite.to_owned(),
            name,
            outcome,
            note,
        });
        return Ok(failed);
    }
    let (bundle, suite) = match kind {
        "Unit test bundle" | "UI test bundle" => (name.as_str(), ""),
        "Test Suite" => (bundle, name.as_str()),
        _ => (bundle, suite),
    };
    let mut any_failed = false;
    for child in node["children"].as_array().into_iter().flatten() {
        any_failed |= walk(child, bundle, suite, cases)?;
    }
    if matches!(kind, "Test Suite" | "Unit test bundle" | "UI test bundle")
        && result == Some("Failed")
        && !any_failed
    {
        return Err(format!(
            "{name} is recorded as failed and no case under it failed"
        ));
    }
    Ok(any_failed)
}

/// Holds a tool's exit status to the cases it reported.
///
/// # Errors
///
/// Returns the disagreement: a failed case under a status of 0, or a status that is not 0 with no
/// failed case to account for it.
pub fn agree_with_exit(exit: Option<i32>, cases: &[Case]) -> Result<(), String> {
    // A case that expected to fail and did is a failure here and leaves the tool's status at 0.
    let failed = cases
        .iter()
        .filter(|case| case.outcome == Outcome::Failed && case.note.is_none())
        .count();
    match (exit, failed) {
        (Some(0), 0) => Ok(()),
        (Some(0), failed) => Err(format!(
            "the tool ended with status 0 and the results hold {failed} failed tests"
        )),
        (exit, 0) => Err(format!(
            "the tool ended with status {} and the results hold no failed test",
            exit.map_or_else(|| "none".to_owned(), |code| code.to_string())
        )),
        (_, _) => Ok(()),
    }
}

/// The classes a Kotlin, Java or Swift source file declares at its top level, as the tool that runs
/// its tests names them: a Kotlin or Java class by its full name, a Swift class by its name.
///
/// A declaration is a line that begins with modifiers and attributes and then `class`, outside every
/// brace, comment and string. A word in a comment or a string, `class func`, `class var` and
/// `Foo::class` are none. A class nested in another is not listed: a JVM names it `Outer$Inner`,
/// which [`declares`] gives to the file of `Outer`, and a nested Swift class is a helper of the
/// test around it.
///
/// # Errors
///
/// Returns that the file cannot be read for its classes: its braces do not balance once comments
/// and strings are blanked, so a class after the place it went wrong could be missed, or a class
/// is declared whose name is in backticks or on the next line.
pub fn declared_classes(file: &str, source: &str) -> Result<Vec<String>, String> {
    const MODIFIERS: &[&str] = &[
        "public",
        "private",
        "fileprivate",
        "internal",
        "protected",
        "open",
        "final",
        "abstract",
        "sealed",
        "data",
        "inner",
        "enum",
        "annotation",
        "value",
        "static",
        "strictfp",
        "expect",
        "actual",
        "external",
        "inline",
        "nonisolated",
        "package",
    ];
    const NOT_CLASSES: &[&str] = &["func", "var", "let", "init", "subscript", "deinit"];
    let swift = file.ends_with(".swift");
    let masked = mask(source, swift);
    let mut package = String::new();
    let mut found = Vec::new();
    let mut depth = 0_i64;
    for (number, line) in masked.lines().enumerate() {
        let at_top = depth == 0;
        for c in line.chars() {
            match c {
                '{' => depth += 1,
                '}' => depth -= 1,
                _ => {}
            }
            if depth < 0 {
                return Err(format!(
                    "a brace on line {} closes what was never opened",
                    number + 1
                ));
            }
        }
        let line = line.trim();
        if !at_top || line.is_empty() {
            continue;
        }
        if !swift && let Some(rest) = line.strip_prefix("package ") {
            package = rest.trim().trim_end_matches(';').trim().to_owned();
            continue;
        }
        let mut words = line.split_whitespace();
        // Attributes are modifiers too, and one may carry arguments with spaces in them.
        let mut parentheses = 0_i32;
        let mut declared = None;
        while let Some(word) = words.next() {
            if parentheses > 0 || word.starts_with('@') {
                parentheses += i32::try_from(word.matches('(').count()).unwrap_or(0)
                    - i32::try_from(word.matches(')').count()).unwrap_or(0);
                continue;
            }
            if MODIFIERS.contains(&word) {
                continue;
            }
            if word == "class" {
                declared = Some(
                    words
                        .next()
                        .map(|name| {
                            name.chars()
                                .take_while(|c| c.is_alphanumeric() || *c == '_')
                                .collect::<String>()
                        })
                        .unwrap_or_default(),
                );
            }
            break;
        }
        // A class name in backticks is blanked with the other quoted identifiers, which leaves a
        // backtick where the name was, so what follows `class` is no name: the file cannot be read.
        if declared.as_ref().is_some_and(String::is_empty) {
            return Err(format!(
                "line {} declares a class whose name cannot be read",
                number + 1
            ));
        }
        if let Some(name) =
            declared.filter(|name| !name.is_empty() && !NOT_CLASSES.contains(&name.as_str()))
        {
            found.push(if swift || package.is_empty() {
                name
            } else {
                format!("{package}.{name}")
            });
        }
    }
    if depth != 0 {
        return Err(format!("the file ends with braces still open ({depth})"));
    }
    Ok(found)
}

/// The source with every comment, string, character literal and quoted identifier blanked out, each newline kept: what
/// is left is code, so a brace or a keyword in it is one. Block comments nest (Java's do not, and no
/// lane holds a Java file). A triple-quoted string spans lines; a Kotlin one has no escapes, and a
/// Swift one does. A Swift raw string (`#"..."#`) ends at its own number of `#`, and an expression
/// interpolated into a string (`\(...)` in Swift, `${...}` in Kotlin) is blanked with the strings
/// and comments inside it.
fn mask(source: &str, swift: bool) -> String {
    let mut masker = Masker {
        chars: source.chars().collect(),
        at: 0,
        out: String::with_capacity(source.len()),
        swift,
    };
    while masker.at < masker.chars.len() {
        masker.code();
    }
    masker.out
}

struct Masker {
    chars: Vec<char>,
    at: usize,
    out: String,
    swift: bool,
}

impl Masker {
    fn starts(&self, text: &str) -> bool {
        text.chars()
            .enumerate()
            .all(|(i, c)| self.chars.get(self.at + i) == Some(&c))
    }

    /// Blanks `count` characters, keeping newlines.
    fn blank(&mut self, count: usize) {
        for _ in 0..count {
            if let Some(&c) = self.chars.get(self.at) {
                self.out.push(if c == '\n' { '\n' } else { ' ' });
                self.at += 1;
            }
        }
    }

    /// One piece of code: a character it keeps, or a comment, string, literal or quoted identifier
    /// it blanks.
    fn code(&mut self) {
        if !self.blanked() {
            self.out.push(self.chars[self.at]);
            self.at += 1;
        }
    }

    /// Blanks a comment, string, literal or quoted identifier that starts here, and says whether
    /// there was one.
    fn blanked(&mut self) -> bool {
        let c = self.chars[self.at];
        if self.swift && c == '#' && self.raw_string() {
            return true;
        }
        if self.starts("//") {
            while self.at < self.chars.len() && self.chars[self.at] != '\n' {
                self.blank(1);
            }
        } else if self.starts("/*") {
            let mut depth = 0_usize;
            while self.at < self.chars.len() {
                if self.starts("/*") {
                    depth += 1;
                    self.blank(2);
                } else if self.starts("*/") {
                    depth -= 1;
                    self.blank(2);
                    if depth == 0 {
                        break;
                    }
                } else {
                    self.blank(1);
                }
            }
        } else if self.starts("\"\"\"") {
            self.blank(3);
            self.string(true, 0);
        } else if c == '"' {
            self.blank(1);
            self.string(false, 0);
        } else if c == '`' {
            // A quoted identifier (a Kotlin test name with spaces, a Swift keyword used as a
            // name) ends at the next backtick or the end of the line.
            self.blank(1);
            while self.at < self.chars.len() && !matches!(self.chars[self.at], '`' | '\n') {
                self.blank(1);
            }
            // The closing backtick stays, so that what follows `class` is not a name.
            if self.chars.get(self.at) == Some(&'`') {
                self.out.push('`');
                self.at += 1;
            }
        } else if c == '\''
            && (self.chars.get(self.at + 2) == Some(&'\'')
                || (self.chars.get(self.at + 1) == Some(&'\\')
                    && self.chars.get(self.at + 3) == Some(&'\'')))
        {
            self.blank(if self.chars.get(self.at + 1) == Some(&'\\') {
                4
            } else {
                3
            });
        } else {
            return false;
        }
        true
    }

    /// A Swift raw string: the hashes, the quotes, and the text up to the quotes and as many
    /// hashes. Returns whether one starts here.
    fn raw_string(&mut self) -> bool {
        let hashes = self.chars[self.at..]
            .iter()
            .take_while(|&&c| c == '#')
            .count();
        if self.chars.get(self.at + hashes) != Some(&'"') {
            return false;
        }
        let triple = self.chars.get(self.at + hashes + 1) == Some(&'"')
            && self.chars.get(self.at + hashes + 2) == Some(&'"');
        self.blank(hashes + if triple { 3 } else { 1 });
        self.string(triple, hashes);
        true
    }

    /// The body of a string, after its opening quotes, up to and including the closing ones. A
    /// Swift raw string (`hashes` above 0) takes escapes and interpolations only after that many
    /// hashes.
    fn string(&mut self, triple: bool, hashes: usize) {
        let close: String = format!(
            "{}{}",
            if triple { "\"\"\"" } else { "\"" },
            "#".repeat(hashes)
        );
        let escape: String = format!("\\{}", "#".repeat(hashes));
        // A Kotlin raw string has no escapes, so a backslash in it is text, and it closes on the
        // last three of a run of quotes. Java's text blocks keep their escapes, and no lane holds
        // a Java file.
        let kotlin_raw = triple && !self.swift;
        while self.at < self.chars.len() {
            if kotlin_raw && self.starts("\"\"\"") {
                let run = self.chars[self.at..]
                    .iter()
                    .take_while(|&&c| c == '"')
                    .count();
                self.blank(run);
                return;
            }
            if self.starts(&close) {
                self.blank(close.chars().count());
                return;
            }
            if !triple && self.chars[self.at] == '\n' {
                return;
            }
            if !kotlin_raw && self.starts(&escape) {
                self.blank(escape.chars().count());
                if self.swift && self.chars.get(self.at) == Some(&'(') {
                    self.blank(1);
                    self.interpolation('(', ')');
                } else {
                    self.blank(1);
                }
            } else if !self.swift && self.starts("${") {
                self.blank(2);
                self.interpolation('{', '}');
            } else {
                self.blank(1);
            }
        }
    }

    /// An expression interpolated into a string, after its opening bracket, up to and including the
    /// bracket that closes it. Strings and comments inside it are blanked like any other.
    fn interpolation(&mut self, open: char, close: char) {
        let mut depth = 1_usize;
        while self.at < self.chars.len() && depth > 0 {
            if self.blanked() {
                continue;
            }
            let c = self.chars[self.at];
            if c == open {
                depth += 1;
            } else if c == close {
                depth -= 1;
            }
            self.blank(1);
        }
    }
}

/// Whether the class a tool reported is one the source file declares: the class itself, or a class
/// nested in one of them, which a JVM names `Outer$Inner`.
#[must_use]
pub fn declares(declared: &[String], class: &str) -> bool {
    declared.iter().any(|name| {
        class == name
            || class
                .strip_prefix(name.as_str())
                .is_some_and(|rest| rest.starts_with('$'))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_classes_of_a_file_are_the_top_level_ones_in_code() {
        let kotlin = "package to.kala.reach.companion.mobile\n\nimport org.junit.Test\n\n/*\n * class InAComment\n */\n// class AlsoAComment\nval raw = \"\"\"\nclass InAString {\n\"\"\"\nclass VoiceCaptureGateTest {\n    private class Switches : VoiceMediaSwitches {\n        val kind = Switches::class\n    }\n    val open = \"{\"\n    val alsoOpen = '{'\n    @Test fun a() {}\n}\n\nclass SoftwareSealer : Sealer\n";
        assert_eq!(
            declared_classes("A.kt", kotlin).expect("balanced"),
            [
                "to.kala.reach.companion.mobile.VoiceCaptureGateTest",
                "to.kala.reach.companion.mobile.SoftwareSealer",
            ]
        );
        let swift = "import XCTest\n\n@MainActor\nfinal class A: XCTestCase {\n    override class func setUp() {}\n    class var shared: Int { 0 }\n    private final class Helper {}\n}\n@available(iOS 17, *) final class B: XCTestCase {}\n";
        assert_eq!(
            declared_classes("A.swift", swift).expect("balanced"),
            ["A", "B"]
        );
    }

    #[test]
    fn an_expression_inside_a_string_is_blanked_with_the_strings_in_it() {
        // A brace in a string inside an interpolated expression is no brace, and the classes after
        // it are still found.
        let kotlin = "class A {\n    val s = \"${a[\"{\"]}\" + \"x\"\n}\nclass B\n";
        assert_eq!(
            declared_classes("A.kt", kotlin).expect("balanced"),
            ["A", "B"]
        );
        let swift = "final class A: XCTestCase {\n    let s = \"\\(f(\"{\")) // \\(g(\"/*\"))\"\n    let r = #\"a \"{\" b\"#\n}\nfinal class B: XCTestCase {}\n";
        assert_eq!(
            declared_classes("A.swift", swift).expect("balanced"),
            ["A", "B"]
        );
    }

    #[test]
    fn a_file_whose_braces_do_not_balance_is_not_read() {
        assert!(declared_classes("A.kt", "class A {\n").is_err());
        assert!(declared_classes("A.kt", "}\nclass A\n").is_err());
        // The order within a line counts: the first brace closes nothing.
        assert!(declared_classes("A.kt", "}{\nclass A {}\n").is_err());
    }

    #[test]
    fn a_kotlin_raw_string_has_no_escapes_and_closes_on_the_last_of_its_quotes() {
        let classes = |source: &str| declared_classes("A.kt", source).expect("balanced");
        // A backslash before the closing quotes is text.
        assert_eq!(classes("val root = \"\"\"C:\\\"\"\"\nclass B {}\n"), ["B"]);
        let body = "class A {\n    val root = \"\"\"C:\\\"\"\"\n}\nclass B {}\n";
        assert_eq!(classes(body), ["A", "B"]);
        // Four quotes close on the last three and keep the first as text.
        let quotes = "class A {\n    val l = listOf(\"\"\"a\"\"\"\", \"{\")\n}\nclass B {}\n";
        assert_eq!(classes(quotes), ["A", "B"]);
        // A raw string still keeps a quoted string in an interpolation from ending it; the test
        // below puts a raw string in one.
        let template = "class A {\n    val s = \"\"\"x ${f(\"{\")} y\"\"\"\n}\nclass B {}\n";
        assert_eq!(classes(template), ["A", "B"]);
    }

    #[test]
    fn a_swift_string_keeps_its_escapes_and_a_raw_string_its_hashes() {
        let classes = |source: &str| declared_classes("A.swift", source).expect("balanced");
        // `\"""` inside a multi-line string is an escaped quote, not the end of it.
        let multiline = "final class A {\n    let s = \"\"\"\n    a \\\"\"\" {\n    \"\"\"\n}\nfinal class B {}\n";
        assert_eq!(classes(multiline), ["A", "B"]);
        // In a raw string `\#(` interpolates and `\(` does not.
        let raw = "final class A {\n    let t = #\"\\#(f(\"a\\\"#{\"))\"#\n    let r = #\"\\(x\"#\n}\nfinal class B {}\n";
        assert_eq!(classes(raw), ["A", "B"]);
    }

    #[test]
    fn a_quoted_identifier_is_blanked_whatever_braces_it_holds() {
        let kotlin = "class A {\n    @Test fun `opens a {`() {}\n}\nclass B {\n    @Test fun `closes a }`() {}\n}\nexpect class C\n";
        assert_eq!(
            declared_classes("A.kt", kotlin).expect("balanced"),
            ["A", "B", "C"]
        );
    }

    #[test]
    fn a_class_whose_name_cannot_be_read_stops_the_reading() {
        // A quoted name, followed by a word that would pass for one, and a name on the next line.
        assert!(declared_classes("A.kt", "class `A` constructor() {}\n").is_err());
        assert!(declared_classes("A.kt", "class /* c */ `A` constructor() {}\n").is_err());
        assert!(declared_classes("A.kt", "class`A` constructor() {}\n").is_err());
        // A backtick or the word class in a comment after a readable declaration is no stop.
        assert_eq!(
            declared_classes("A.kt", "class A {} // Example: class `B`\n").expect("readable"),
            ["A"]
        );
        // The error names the line.
        let error = declared_classes("A.kt", "class A\n\nclass `B` {}\n").expect_err("quoted");
        assert!(error.contains("line 3"), "{error}");
        let error = declared_classes("A.kt", "class A {}\n}\n").expect_err("a stray brace");
        assert!(error.contains("line 2"), "{error}");
        assert!(declared_classes("A.kt", "class `Login test` {\n}\n").is_err());
        assert!(declared_classes("A.kt", "class\nA {\n}\n").is_err());
        // The words around a class that are not a name stay as they were.
        assert_eq!(
            declared_classes("A.swift", "nonisolated final class B: XCTestCase {}\n")
                .expect("balanced"),
            ["B"]
        );
        assert_eq!(
            declared_classes("A.swift", "package final class P: XCTestCase {}\n")
                .expect("balanced"),
            ["P"]
        );
        assert_eq!(
            declared_classes("A.swift", "final class C {\n    class func make() {}\n}\n")
                .expect("balanced"),
            ["C"]
        );
    }

    #[test]
    fn an_interpolation_in_a_kotlin_raw_string_is_an_expression_even_after_a_backslash() {
        let source = "class A {\n    val s = \"\"\"\\${\"\"\"{\"\"\"}\"\"\"\n}\nclass B {}\n";
        assert_eq!(
            declared_classes("A.kt", source).expect("balanced"),
            ["A", "B"]
        );
    }

    #[test]
    fn comments_are_blanked_wherever_they_start() {
        let kotlin =
            "/*\nclass InAComment {\n*/\n// {\nclass A { // }\n    /* class Inner { */\n}\n";
        assert_eq!(declared_classes("A.kt", kotlin).expect("balanced"), ["A"]);
    }

    #[test]
    fn a_nested_jvm_class_belongs_to_the_file_of_the_class_around_it() {
        let declared = ["p.Outer".to_owned()];
        assert!(declares(&declared, "p.Outer"));
        assert!(declares(&declared, "p.Outer$Inner"));
        assert!(!declares(&declared, "p.OuterOther"));
    }

    #[test]
    fn a_status_is_held_to_the_failures_the_results_hold() {
        let case = |outcome| Case {
            class: "C".to_owned(),
            name: "t".to_owned(),
            selector: "C.t".to_owned(),
            outcome,
            note: None,
        };
        assert!(agree_with_exit(Some(0), &[case(Outcome::Passed)]).is_ok());
        assert!(agree_with_exit(Some(1), &[case(Outcome::Failed)]).is_ok());
        assert!(agree_with_exit(Some(1), &[case(Outcome::Passed)]).is_err());
        assert!(agree_with_exit(None, &[case(Outcome::Passed)]).is_err());
        assert!(agree_with_exit(Some(0), &[case(Outcome::Failed)]).is_err());
    }
}
