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
    Ok(scan(file, source, false)?
        .classes
        .into_iter()
        .map(|class| class.name)
        .collect())
}

/// What a source file declares, for the keys its comments carry: its classes, the tests of those
/// classes, and where the lines of each are. Lines count from 1.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Declared {
    /// The classes at the top level, as [`declared_classes`] names them.
    pub classes: Vec<DeclaredClass>,
    /// The tests of those classes, in the order the file declares them.
    pub tests: Vec<DeclaredTest>,
    /// The line of the first thing in the file that is code, or 0 for a file with none: a comment
    /// before it heads the file.
    first_code: usize,
    /// For each line, whether it holds a comment and nothing else.
    comment_only: Vec<bool>,
}

/// A class at the top level of a source file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeclaredClass {
    /// Its name, as [`declared_classes`] gives it.
    pub name: String,
    /// The first line of its declaration, the attributes above `class` included.
    pub first: usize,
    /// The line its body closes on.
    pub last: usize,
}

/// A test function of a class, as the tool that runs it names it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeclaredTest {
    /// The class that holds it, named as [`DeclaredClass`] names it.
    pub class: String,
    /// Its name as the tool reports the case: a Kotlin function's name (the text between the
    /// backticks of a quoted one), a Swift method's name with the `()` Xcode puts after it.
    pub name: String,
    /// The first line of its declaration, the attributes above it included.
    pub first: usize,
    /// The line its body closes on.
    pub last: usize,
}

/// How much of a source file a key covers.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Part {
    /// One test: the class that holds it, and its name as the tool reports the case.
    Case {
        /// The class, named as [`DeclaredClass`] names it.
        class: String,
        /// The case's name, as [`DeclaredTest`] gives it.
        name: String,
    },
    /// Every test of one class.
    Class(String),
    /// Every test of every class the file declares.
    File,
}

/// Where a comment stands, which is what makes it key what it keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stands {
    /// Directly above the declaration it keys, with nothing but comments between.
    Above,
    /// Inside the body of the test it keys.
    Inside,
    /// Before the first line of code of the file.
    Head,
}

impl Declared {
    /// What the comment on lines `first` to `last` keys, and how it stands to it, or nothing when
    /// it keys no test.
    ///
    /// * a comment inside the body of a test, or directly above its declaration (the attributes
    ///   included), keys that test;
    /// * a comment directly above a class keys every test of the class;
    /// * a comment before the first line of code keys every test of the file;
    /// * any other comment, in a class between its tests or in a helper, keys nothing.
    ///
    /// "Directly above" allows other comments between and no blank line.
    #[must_use]
    pub fn scope_of(&self, first: usize, last: usize) -> Option<(Part, Stands)> {
        let case = |test: &DeclaredTest| Part::Case {
            class: test.class.clone(),
            name: test.name.clone(),
        };
        if let Some(test) = self
            .tests
            .iter()
            .find(|test| test.first <= first && last <= test.last)
        {
            return Some((case(test), Stands::Inside));
        }
        if let Some(test) = self
            .tests
            .iter()
            .find(|test| self.directly_above(last, test.first))
        {
            return Some((case(test), Stands::Above));
        }
        if let Some(class) = self
            .classes
            .iter()
            .find(|class| self.directly_above(last, class.first))
        {
            return Some((Part::Class(class.name.clone()), Stands::Above));
        }
        (self.first_code != 0 && last < self.first_code).then_some((Part::File, Stands::Head))
    }

    /// Whether only comments lie between line `last` and the declaration that starts on `target`.
    fn directly_above(&self, last: usize, target: usize) -> bool {
        last < target
            && (last + 1..target).all(|line| self.comment_only.get(line - 1).copied() == Some(true))
    }
}

/// Reads the classes of a source file, and with `tests` its test functions.
fn scan(file: &str, source: &str, tests: bool) -> Result<Declared, String> {
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
    let originals: Vec<Vec<char>> = source.lines().map(|line| line.chars().collect()).collect();
    let mut declared = Declared::default();
    let mut package = String::new();
    let mut depth = 0_i64;
    // The class whose body is open, the test whose body is open and whether its first brace has
    // been seen, and the first line of the attributes waiting for the declaration they belong to.
    let mut open_class: Option<usize> = None;
    let mut open_test: Option<(usize, bool)> = None;
    let mut class_attributes: Option<usize> = None;
    let mut test_attributes: Option<usize> = None;
    let mut test_attribute = false;
    // The parentheses an attribute's arguments, or a test's signature, have left open.
    let mut attribute_parens = 0_i32;
    let mut signature_parens = 0_i32;
    // Where on the declaration line the signature of a test begins: what stands before it is the
    // arguments of an attribute, whose parentheses and `=` are none of the signature's.
    let mut signature_from = 0_usize;
    // Whether the top-level declaration whose body is open is a Swift extension.
    let mut in_extension = false;
    for (index, line) in masked.lines().enumerate() {
        let number = index + 1;
        let chars: Vec<char> = line.chars().collect();
        let blank = chars.iter().all(|c| c.is_whitespace());
        declared.comment_only.push(
            blank
                && originals
                    .get(index)
                    .is_some_and(|original| original.iter().any(|c| !c.is_whitespace())),
        );
        if !blank && declared.first_code == 0 {
            declared.first_code = number;
        }
        let at_top = depth == 0;
        let in_class_body = depth == 1 && open_class.is_some() && open_test.is_none();
        if tests {
            if swift {
                if line.trim_start().starts_with("import") && has_word(&chars, "Testing") {
                    return Err(format!(
                        "line {number} imports the Swift Testing framework, which this reading does not follow"
                    ));
                }
                if annotation_names(&chars, "Test") {
                    return Err(format!(
                        "line {number} declares a Swift Testing test, which this reading does not follow"
                    ));
                }
            } else if !in_class_body && open_test.is_none() && annotation_names(&chars, "Test") {
                return Err(format!(
                    "line {number} declares a test outside the body of a top-level class, which this reading does not follow"
                ));
            }
        }
        let trimmed = line.trim();
        let (names, rest_at, open_after) = leading_attributes(&chars, attribute_parens);
        let rest = &chars[rest_at..];
        let rest_blank = rest.iter().all(|c| c.is_whitespace());
        // A test whose body has not opened yet may only go on with its signature. Another
        // declaration reached first means it has no block body, and the braces that follow could
        // not be given to the test they belong to.
        if tests
            && depth == 1
            && matches!(open_test, Some((_, false)))
            && signature_parens <= 0
            && (!names.is_empty() || declares_something(rest))
        {
            return Err(format!(
                "line {number} comes before the body of the test above it opens, which this reading does not follow"
            ));
        }
        if tests && in_class_body {
            let class = open_class.map(|class| declared.classes[class].name.clone());
            let keyword = if swift { "func" } else { "fun" };
            if !names.is_empty() || attribute_parens > 0 {
                test_attributes.get_or_insert(number);
            }
            if names.iter().any(|name| name == "Test") {
                test_attribute = true;
            }
            attribute_parens = open_after;
            if attribute_parens == 0 && !rest_blank {
                let at = find_word(rest, keyword).map(|at| rest_at + at);
                let test = at.and_then(|at| {
                    if swift {
                        let before: String = chars[..at].iter().collect();
                        let skipped = before
                            .split_whitespace()
                            .any(|word| word == "static" || word == "class");
                        match (!skipped).then(|| swift_test_name(&chars, at)) {
                            Some(SwiftTest::Case(name)) => Some(Ok(name)),
                            Some(SwiftTest::Unclear) => Some(Err(format!(
                                "line {number} declares a test method whose signature goes over several lines, which this reading does not follow"
                            ))),
                            _ => None,
                        }
                    } else {
                        test_attribute.then(|| {
                            kotlin_name(originals.get(index).map_or(&[][..], Vec::as_slice), at)
                                .ok_or_else(|| {
                                    format!("line {number} declares a test whose name cannot be read")
                                })
                        })
                    }
                });
                match test {
                    Some(name) => {
                        declared.tests.push(DeclaredTest {
                            class: class.unwrap_or_default(),
                            name: name?,
                            first: test_attributes.take().unwrap_or(number),
                            last: number,
                        });
                        open_test = Some((declared.tests.len() - 1, false));
                        signature_parens = 0;
                        signature_from = at.unwrap_or(0);
                    }
                    None => {
                        if test_attribute && at.is_none() {
                            return Err(format!(
                                "line {number} declares something other than a function after a test attribute, which this reading does not follow"
                            ));
                        }
                    }
                }
                test_attributes = None;
                test_attribute = false;
            }
        }
        // Swift runs the tests of an extension of a test class too, and a reading that finds the
        // class's own tests only would leave them out of every key.
        if tests && swift && at_top && !blank {
            in_extension = has_word(&chars, "extension");
        }
        if tests
            && swift
            && in_extension
            && depth == 1
            && find_word(&chars, "func").is_some_and(|at| {
                let before: String = chars[..at].iter().collect();
                !before
                    .split_whitespace()
                    .any(|word| word == "static" || word == "class")
                    && matches!(
                        swift_test_name(&chars, at),
                        SwiftTest::Case(_) | SwiftTest::Unclear
                    )
            })
        {
            return Err(format!(
                "line {number} declares a test method in an extension, which this reading does not follow"
            ));
        }
        if at_top && !blank {
            if let Some(class) =
                class_declared(trimmed, swift, MODIFIERS, NOT_CLASSES, &mut package, number)?
            {
                declared.classes.push(DeclaredClass {
                    name: class,
                    first: class_attributes.take().unwrap_or(number),
                    last: number,
                });
                open_class = Some(declared.classes.len() - 1);
            } else if trimmed.starts_with('@') {
                class_attributes.get_or_insert(number);
            } else {
                class_attributes = None;
            }
        }
        for (column, c) in chars.iter().enumerate() {
            match c {
                '(' if depth == 1
                    && column >= signature_from
                    && matches!(open_test, Some((_, false))) =>
                {
                    signature_parens += 1;
                }
                ')' if depth == 1
                    && column >= signature_from
                    && matches!(open_test, Some((_, false))) =>
                {
                    signature_parens -= 1;
                }
                // An `=` outside the parentheses of a signature starts an expression body, which
                // has no brace of its own for the test to end on.
                '=' if depth == 1
                    && column >= signature_from
                    && matches!(open_test, Some((_, false)))
                    && signature_parens == 0
                    && column.checked_sub(1).and_then(|before| chars.get(before)) != Some(&'=')
                    && chars.get(column + 1) != Some(&'=') =>
                {
                    return Err(format!(
                        "line {number} declares a test with an expression body, which this reading does not follow"
                    ));
                }
                '{' => {
                    depth += 1;
                    if depth == 2
                        && signature_parens <= 0
                        && let Some((_, opened)) = open_test.as_mut()
                    {
                        *opened = true;
                    }
                }
                '}' => {
                    depth -= 1;
                    if depth < 0 {
                        return Err(format!(
                            "a brace on line {number} closes what was never opened"
                        ));
                    }
                    if depth == 0 && matches!(open_test, Some((_, false))) {
                        return Err(format!(
                            "the class ends on line {number} before the body of its last test opens, which this reading does not follow"
                        ));
                    }
                    if depth == 1
                        && let Some((at, true)) = open_test
                    {
                        declared.tests[at].last = number;
                        open_test = None;
                    }
                    if depth == 0
                        && let Some(at) = open_class.take()
                    {
                        declared.classes[at].last = number;
                    }
                }
                _ => {}
            }
        }
        signature_from = 0;
    }
    if depth != 0 {
        return Err(format!("the file ends with braces still open ({depth})"));
    }
    Ok(declared)
}

/// The class a top-level line declares, if it declares one, with the package qualification a
/// Kotlin or Java class takes. A `package` line is taken for the qualification of what follows.
fn class_declared(
    line: &str,
    swift: bool,
    modifiers: &[&str],
    not_classes: &[&str],
    package: &mut String,
    number: usize,
) -> Result<Option<String>, String> {
    if !swift && let Some(rest) = line.strip_prefix("package ") {
        *package = rest.trim().trim_end_matches(';').trim().to_owned();
        return Ok(None);
    }
    let mut words = line.split_whitespace();
    // Attributes are modifiers too, and one may carry arguments with spaces in them.
    let mut parentheses = 0_i32;
    let mut declared = None;
    while let Some(word) = words.next() {
        // A quoted name after an annotation's `@` is part of the annotation; the masker leaves
        // its closing backtick as a word of its own.
        if parentheses > 0 || word.starts_with('@') || word.starts_with('`') {
            parentheses += i32::try_from(word.matches('(').count()).unwrap_or(0)
                - i32::try_from(word.matches(')').count()).unwrap_or(0);
            continue;
        }
        if modifiers.contains(&word) {
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
            "line {number} declares a class whose name cannot be read"
        ));
    }
    Ok(declared
        .filter(|name| !name.is_empty() && !not_classes.contains(&name.as_str()))
        .map(|name| {
            if swift || package.is_empty() {
                name
            } else {
                format!("{package}.{name}")
            }
        }))
}

fn is_word(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// Where `word` stands in `chars` as a word of its own, if it does.
fn find_word(chars: &[char], word: &str) -> Option<usize> {
    let word: Vec<char> = word.chars().collect();
    (0..chars.len().saturating_sub(word.len() - 1)).find(|&at| {
        chars[at..].starts_with(&word)
            && (at == 0 || !is_word(chars[at - 1]))
            && chars.get(at + word.len()).is_none_or(|c| !is_word(*c))
    })
}

fn has_word(chars: &[char], word: &str) -> bool {
    find_word(chars, word).is_some()
}

/// Whether an attribute in `chars` is named `name`, qualified or not (`@Test`, `@org.junit.Test`).
fn annotation_names(chars: &[char], name: &str) -> bool {
    let mut at = 0;
    while at < chars.len() {
        if chars[at] != '@' {
            at += 1;
            continue;
        }
        let mut end = at + 1;
        while end < chars.len() && (is_word(chars[end]) || chars[end] == '.') {
            end += 1;
        }
        let path: String = chars[at + 1..end].iter().collect();
        if path.rsplit('.').next() == Some(name) {
            return true;
        }
        at = end.max(at + 1);
    }
    false
}

/// The name of the Kotlin function whose `fun` stands at `at` in the line as written: the word
/// after it, or the text between the backticks of a quoted name.
fn kotlin_name(original: &[char], at: usize) -> Option<String> {
    let mut i = at + 3;
    while original.get(i).is_some_and(|c| c.is_whitespace()) {
        i += 1;
    }
    let name: String = if original.get(i) == Some(&'`') {
        original[i + 1..]
            .iter()
            .take_while(|c| **c != '`')
            .collect()
    } else {
        original
            .get(i..)?
            .iter()
            .take_while(|c| is_word(**c))
            .collect()
    };
    (!name.is_empty()).then_some(name)
}

/// What a Swift `func` is to the tool that runs the tests of a class.
#[derive(Debug, PartialEq, Eq)]
enum SwiftTest {
    /// A test: its name begins with `test` and it takes nothing. The tool prints `()` after it.
    Case(String),
    /// Not a test: another name, or arguments, which the tool never runs.
    NotACase,
    /// A test method whose parameters start on one line and end on another.
    Unclear,
}

/// Reads the Swift method whose `func` stands at `at`.
fn swift_test_name(chars: &[char], at: usize) -> SwiftTest {
    let skip = |mut i: usize| {
        while chars.get(i).is_some_and(|c| c.is_whitespace()) {
            i += 1;
        }
        i
    };
    let start = skip(at + 4);
    let mut end = start;
    while chars.get(end).is_some_and(|c| is_word(*c)) {
        end += 1;
    }
    let name: String = chars[start..end].iter().collect();
    if !name.starts_with("test") {
        return SwiftTest::NotACase;
    }
    let open = skip(end);
    if chars.get(open) != Some(&'(') {
        return SwiftTest::NotACase;
    }
    let close = skip(open + 1);
    match chars.get(close) {
        Some(')') => SwiftTest::Case(format!("{name}()")),
        None => SwiftTest::Unclear,
        Some(_) => SwiftTest::NotACase,
    }
}

/// The attributes a line begins with, where the rest of it starts, and the parentheses an
/// attribute's arguments have left open at its end. `open` is what an earlier line left open: the
/// line then begins inside those arguments. An attribute's name is the last word of its path, past
/// a use-site target (`@get:Rule`, `@org.junit.Test`).
fn leading_attributes(chars: &[char], mut open: i32) -> (Vec<String>, usize, i32) {
    let mut names = Vec::new();
    let mut at = 0;
    let arguments = |at: &mut usize, open: &mut i32| {
        while *at < chars.len() && *open > 0 {
            match chars[*at] {
                '(' => *open += 1,
                ')' => *open -= 1,
                _ => {}
            }
            *at += 1;
        }
    };
    arguments(&mut at, &mut open);
    while open == 0 {
        while chars.get(at).is_some_and(|c| c.is_whitespace()) {
            at += 1;
        }
        if chars.get(at) != Some(&'@') {
            break;
        }
        let start = at + 1;
        at = start;
        while chars
            .get(at)
            .is_some_and(|c| is_word(*c) || *c == '.' || *c == ':')
        {
            at += 1;
        }
        let path: String = chars[start..at].iter().collect();
        names.push(
            path.rsplit(['.', ':'])
                .next()
                .unwrap_or_default()
                .to_owned(),
        );
        if chars.get(at) == Some(&'(') {
            open = 1;
            at += 1;
            arguments(&mut at, &mut open);
        }
    }
    (names, at, open)
}

/// Whether `rest`, the part of a line after its attributes, begins a declaration of something
/// other than the signature of the function above it.
fn declares_something(rest: &[char]) -> bool {
    [
        "fun",
        "func",
        "val",
        "var",
        "let",
        "class",
        "object",
        "interface",
        "init",
        "struct",
        "enum",
        "typealias",
        "companion",
    ]
    .iter()
    .any(|word| has_word(rest, word))
}

/// Reads a source file for its classes and its tests.
///
/// # Errors
///
/// Returns that the file cannot be read, as [`declared_classes`] states it, or that it declares a
/// test this reading does not follow: a Kotlin test anywhere but in the body of a top-level class,
/// a test whose name is not readable, a test with an expression body or one that another
/// declaration follows before any block, an attribute of a test that no function follows, a Swift
/// test method in an extension or with its parentheses over several lines, or a Swift Testing test.
pub fn declared(file: &str, source: &str) -> Result<Declared, String> {
    scan(file, source, true)
}

/// The source with every comment, string, character literal and quoted identifier blanked out, each
/// newline kept: what is left is code, so a brace or a keyword in it is one. A quoted identifier
/// keeps its closing backtick, so that what follows `class` is not read as a name. Block comments
/// nest (Java's do not, and no lane holds a Java file). A triple-quoted string spans lines; a
/// Kotlin one has no escapes, and a Swift one does. A Swift raw string (`#"..."#`) ends at its own
/// number of `#`, and an expression interpolated into a string (`\(...)` in Swift, `${...}` in
/// Kotlin) is blanked with the strings and comments inside it.
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
    /// it blanks (a quoted identifier keeps its closing backtick).
    fn code(&mut self) {
        if !self.blanked() {
            self.out.push(self.chars[self.at]);
            self.at += 1;
        }
    }

    /// Blanks a comment, string, literal or quoted identifier that starts here, and says whether
    /// there was one. A quoted identifier keeps its closing backtick.
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
        // A quoted annotation name before `class` is part of the annotation.
        assert_eq!(
            declared_classes("A.kt", "@`Slow` class FooTest {}\n").expect("readable"),
            ["FooTest"]
        );
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

    /// What the first comment of `source` keys: its first and last line go to `scope_of`.
    fn keyed_by_comment_at(file: &str, source: &str, line: usize) -> Option<(Part, Stands)> {
        let declared = declared(file, source).expect("readable");
        let comment = crate::clike::comments(source)
            .into_iter()
            .find(|comment| comment.line == line)
            .expect("a comment starts on that line");
        declared.scope_of(
            comment.line,
            comment.line + comment.text.matches('\n').count(),
        )
    }

    fn case(class: &str, name: &str) -> Part {
        Part::Case {
            class: class.to_owned(),
            name: name.to_owned(),
        }
    }

    const KOTLIN: &str = "package p\n\nimport org.junit.Test\n\n/** The class's own words. */\nclass AuthenticatorsTest {\n    private val helper = 1\n\n    /** A key on a case. */\n    @Test\n    fun the_first_case() {\n        // A remark inside it.\n        assertEquals(1, 1)\n    }\n\n    // Not above a case: a blank line stands between.\n\n    @Test\n    fun `the second case, with spaces`() {\n    }\n}\n";

    #[test]
    fn a_comment_above_a_kotlin_test_keys_that_test_and_no_other() {
        let declared = declared("A.kt", KOTLIN).expect("readable");
        let class = "p.AuthenticatorsTest";
        assert_eq!(
            declared
                .tests
                .iter()
                .map(|test| (
                    test.class.as_str(),
                    test.name.as_str(),
                    test.first,
                    test.last
                ))
                .collect::<Vec<_>>(),
            [
                (class, "the_first_case", 10, 14),
                (class, "the second case, with spaces", 18, 20),
            ]
        );
        // The KDoc above `@Test`, and a remark inside the body, key the first case alone.
        assert_eq!(
            keyed_by_comment_at("A.kt", KOTLIN, 9),
            Some((case(class, "the_first_case"), Stands::Above))
        );
        assert_eq!(
            keyed_by_comment_at("A.kt", KOTLIN, 12),
            Some((case(class, "the_first_case"), Stands::Inside))
        );
        // A comment a blank line away from the next case keys nothing.
        assert_eq!(keyed_by_comment_at("A.kt", KOTLIN, 16), None);
    }

    #[test]
    fn a_comment_above_a_class_keys_the_tests_of_that_class() {
        assert_eq!(
            keyed_by_comment_at("A.kt", KOTLIN, 5),
            Some((
                Part::Class("p.AuthenticatorsTest".to_owned()),
                Stands::Above
            ))
        );
    }

    #[test]
    fn a_comment_before_the_first_line_of_code_keys_the_whole_file() {
        let swift = "//\n//  Voice.swift\n//  KR-REQ-15.36: the head of the file.\n\nimport XCTest\n\nfinal class VoiceTests: XCTestCase {\n    /// KR-REQ-15.34: on a case.\n    func testOne() {}\n}\n";
        assert_eq!(
            keyed_by_comment_at("A.swift", swift, 1),
            Some((Part::File, Stands::Head))
        );
        assert_eq!(
            keyed_by_comment_at("A.swift", swift, 8),
            Some((case("VoiceTests", "testOne()"), Stands::Above))
        );
        // A header with nothing between it and the class is the class's.
        let adjacent = "// The class.\nfinal class A: XCTestCase {\n    func testOne() {}\n}\n";
        assert_eq!(
            keyed_by_comment_at("A.swift", adjacent, 1),
            Some((Part::Class("A".to_owned()), Stands::Above))
        );
    }

    #[test]
    fn a_file_with_no_comment_is_read_for_its_tests_and_keys_nothing() {
        let kotlin = "package p\n\nimport org.junit.Test\n\nclass A {\n    @Test fun one() {}\n    @Test\n    fun two() {\n    }\n    fun helper() {}\n}\n";
        let read = declared("A.kt", kotlin).expect("readable");
        assert_eq!(
            read.tests
                .iter()
                .map(|test| test.name.as_str())
                .collect::<Vec<_>>(),
            ["one", "two"]
        );
        assert_eq!((read.tests[0].first, read.tests[0].last), (6, 6));
        assert_eq!((read.tests[1].first, read.tests[1].last), (7, 9));
        assert!(crate::clike::comments(kotlin).is_empty());
        assert_eq!(declared("A.kt", "").expect("readable"), Declared::default());
    }

    #[test]
    fn a_swift_test_is_a_method_named_test_that_takes_nothing() {
        let swift = "import XCTest\n\n@MainActor\nfinal class A: XCTestCase {\n    @MainActor\n    func testOne() async throws {\n    }\n    func testWithAnArgument(_ x: Int) {}\n    func helper() {}\n    static func testStatic() {}\n    override func setUp() {}\n}\n\nfinal class B: XCTestCase {\n    func testTwo() {}\n}\n";
        let read = declared("A.swift", swift).expect("readable");
        assert_eq!(
            read.classes
                .iter()
                .map(|class| (class.name.as_str(), class.first, class.last))
                .collect::<Vec<_>>(),
            [("A", 3, 12), ("B", 14, 16)]
        );
        assert_eq!(
            read.tests
                .iter()
                .map(|test| (
                    test.class.as_str(),
                    test.name.as_str(),
                    test.first,
                    test.last
                ))
                .collect::<Vec<_>>(),
            [("A", "testOne()", 5, 7), ("B", "testTwo()", 15, 15)]
        );
    }

    #[test]
    fn a_signature_over_several_lines_has_its_body_where_the_braces_say() {
        let kotlin = "class A {\n    @Test\n    @Ignore(\"later\")\n    fun one(\n        a: Int,\n    ) {\n        val x = \"}\"\n        // }\n    }\n    @Test fun two() { }\n}\n";
        let read = declared("A.kt", kotlin).expect("readable");
        assert_eq!(
            read.tests
                .iter()
                .map(|test| (test.name.as_str(), test.first, test.last))
                .collect::<Vec<_>>(),
            [("one", 2, 9), ("two", 10, 10)]
        );
    }

    #[test]
    fn a_test_this_reading_does_not_follow_stops_it() {
        // A test in a nested class, a test outside any class, a name that cannot be read, and the
        // Swift Testing framework.
        let nested = "class A {\n    class Inner {\n        @Test fun one() {}\n    }\n}\n";
        assert!(declared("A.kt", nested).is_err());
        assert!(declared("A.kt", "@Test fun top() {}\n").is_err());
        assert!(declared("A.kt", "class A {\n    @Test fun `` () {}\n}\n").is_err());
        assert!(declared("A.swift", "import Testing\n\nstruct A {}\n").is_err());
        assert!(declared("A.swift", "final class A {\n    @Test func one() {}\n}\n").is_err());
        // The classes of such a file are still read.
        assert_eq!(declared_classes("A.kt", nested).expect("readable"), ["A"]);
    }

    #[test]
    fn a_test_without_a_block_body_stops_the_reading_and_never_lends_its_end_to_the_next() {
        // An expression body has no brace of its own, so the next test's braces would have been
        // taken for its.
        let expression = "class A {\n    @Test fun zero() {\n    }\n\n    @Test fun one() = assertEquals(1, 1)\n}\n\nclass B {\n    /** KR-REQ-15.35: about three. */\n    @Test fun three() {\n        assertEquals(3, 3)\n    }\n}\n";
        let error = declared("A.kt", expression).expect_err("no block body");
        assert!(error.contains("line 5"), "{error}");
        // The same test followed by another in the same class.
        let followed = "class A {\n    @Test fun one() = assertEquals(1, 1)\n\n    /** A remark. */\n    @Test fun two() {\n    }\n}\n";
        let error = declared("A.kt", followed).expect_err("no block body");
        assert!(error.contains("line 2"), "{error}");
        // A declaration that comes before any body: a property whose lambda would have been taken
        // for the test's, a nested class, and a test with no body at all.
        for next in [
            "private val unused = { assertTrue(false) }",
            "private class Fake {\n    }",
            "@Test fun two() {\n    }",
        ] {
            let source = format!(
                "class A {{\n    @Test fun one(): Unit\n    // KR-REQ-15.35\n    {next}\n}}\n"
            );
            assert!(declared("A.kt", &source).is_err(), "{next}");
        }
        // A signature over several lines, with a lambda for a default value, has its body where the
        // braces after the parentheses say.
        let signature = "class A {\n    @Test fun one(\n        run: () -> Unit = { },\n    ) {\n        assertEquals(1, 1)\n    }\n    @Test fun two() {\n    }\n}\n";
        let read = declared("A.kt", signature).expect("readable");
        assert_eq!(
            read.tests
                .iter()
                .map(|test| (test.name.as_str(), test.first, test.last))
                .collect::<Vec<_>>(),
            [("one", 2, 6), ("two", 7, 8)]
        );
    }

    #[test]
    fn an_attribute_over_several_lines_and_a_property_with_one_are_told_apart() {
        // The arguments of `@Test` go over three lines and the function comes after them.
        let multiline = "class A {\n    /** KR-REQ-15.35: about one. */\n    @Test(\n        expected = IllegalStateException::class\n    )\n    fun one() {\n    }\n}\n";
        let read = declared("A.kt", multiline).expect("readable");
        assert_eq!(
            read.tests
                .iter()
                .map(|test| (test.name.as_str(), test.first, test.last))
                .collect::<Vec<_>>(),
            [("one", 3, 7)]
        );
        // A property with an attribute is not an attribute of the test below it.
        let property = "class A {\n    /** A remark about the folder. */\n    @get:Rule val folder = 1\n    @Test fun one() {\n    }\n}\n";
        let read = declared("A.kt", property).expect("readable");
        assert_eq!((read.tests[0].first, read.tests[0].last), (4, 5));
        assert!(read.scope_of(2, 2).is_none());
        // The arguments end on the line that holds the function, or another attribute, after them.
        let closing = "class A {\n    /** KR-REQ-15.35: about one. */\n    @Test(\n        timeout = 10) fun one() {\n    }\n    @Config(\n        sdk = [28]) @Test fun two() {\n    }\n    @Test fun three() {\n    }\n}\n";
        let read = declared("A.kt", closing).expect("readable");
        assert_eq!(
            read.tests
                .iter()
                .map(|test| (test.name.as_str(), test.first, test.last))
                .collect::<Vec<_>>(),
            [("one", 3, 5), ("two", 6, 8), ("three", 9, 10)]
        );
        // A helper with an attribute is not an attribute of the test below it.
        let helper = "class A {\n    // About the fake.\n    @Suppress(\"unused\") private class Fake {\n        val x = 1\n    }\n    @Test fun one() {\n    }\n}\n";
        let read = declared("A.kt", helper).expect("readable");
        assert_eq!((read.tests[0].first, read.tests[0].last), (6, 7));
        assert!(read.scope_of(2, 2).is_none());
        // A test attribute with no function after it, as in a Java file, stops the reading.
        let java = "class A {\n    @Test\n    public void one() {\n    }\n}\n";
        assert!(declared("A.java", java).is_err());
        assert!(declared("A.kt", "class A {\n    @Test\n    val x = 1\n}\n").is_err());
    }

    #[test]
    fn a_swift_test_method_the_reading_cannot_place_stops_it() {
        // In an extension, which declares no class of its own; in a struct it is no test.
        let extension = "final class A: XCTestCase {\n    func testOne() {}\n}\n\nextension A {\n    func testTwo() {}\n}\n";
        let error = declared("A.swift", extension).expect_err("a test in an extension");
        assert!(error.contains("line 6"), "{error}");
        let helper = "final class A: XCTestCase {\n    func testOne() {}\n}\n\nprivate struct Probe {\n    func testConnection() -> Bool { true }\n    static func testStatic() {}\n}\n";
        assert_eq!(
            declared("A.swift", helper).expect("readable").tests.len(),
            1
        );
        // The arguments of an attribute over several lines, before the method.
        let available = "final class A: XCTestCase {\n    // About one.\n    @available(\n        iOS 17, *\n    )\n    func testOne() {}\n}\n";
        let read = declared("A.swift", available).expect("readable");
        assert_eq!((read.tests[0].first, read.tests[0].last), (3, 6));
        // A helper with an attribute is not an attribute of the test below it.
        let nested = "final class A: XCTestCase {\n    // About the helper.\n    @MainActor private final class Helper {\n    }\n    func testOne() {}\n}\n";
        assert_eq!(
            declared("A.swift", nested).expect("readable").tests[0].first,
            5
        );
        // With its parentheses over two lines.
        assert!(
            declared(
                "A.swift",
                "final class A: XCTestCase {\n    func testOne(\n    ) {}\n}\n"
            )
            .is_err()
        );
        // A method the tool does not run as a test is none, whatever its name.
        let read = declared(
            "A.swift",
            "final class A: XCTestCase {\n    func testWith(_ x: Int) {}\n    func testOne() {}\n}\n",
        )
        .expect("readable");
        assert_eq!(read.tests.len(), 1);
        // A property with an attribute is not an attribute of the test below it.
        let read = declared(
            "A.swift",
            "final class A: XCTestCase {\n    // About x.\n    @MainActor var x = 1\n    func testOne() {}\n}\n",
        )
        .expect("readable");
        assert_eq!(read.tests[0].first, 4);
    }

    #[test]
    fn an_attribute_counts_by_its_last_name_and_a_remark_about_one_does_not() {
        let line = |text: &str| text.chars().collect::<Vec<_>>();
        assert!(annotation_names(&line("@Test"), "Test"));
        assert!(annotation_names(&line("@org.junit.Test fun a()"), "Test"));
        assert!(!annotation_names(&line("@TestFactory"), "Test"));
        assert!(!annotation_names(&line("@Ignore(\"Test\")"), "Test"));
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
