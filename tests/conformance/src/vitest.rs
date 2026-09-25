//! Reads a vitest JSON report: each test's file, the line its call starts on, and its status.

use std::collections::BTreeMap;
use std::path::Path;

use serde_json::Value;

use crate::libtest::Outcome;

/// One package's results, by the file relative to the repository and the line each test's call
/// starts on. A table of tests declared by one call has one entry per test at the same line.
pub type Results = BTreeMap<(String, usize), Vec<Outcome>>;

/// Reads the report at `path`, whose test files are named relative to the repository at `root`.
///
/// # Errors
///
/// Returns why the report could not be read.
pub fn read(path: &Path, root: &Path) -> Result<Results, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|error| format!("{} could not be read: {error}", path.display()))?;
    let value: Value = serde_json::from_str(&text)
        .map_err(|error| format!("{} is not JSON: {error}", path.display()))?;
    parse(&value, root)
}

/// Reads a report that has been parsed.
///
/// # Errors
///
/// Returns the field that is missing.
pub fn parse(value: &Value, root: &Path) -> Result<Results, String> {
    let root = std::fs::canonicalize(root).unwrap_or_else(|_| root.to_owned());
    let mut results = Results::new();
    for file in value["testResults"]
        .as_array()
        .ok_or("the report has no test results")?
    {
        let name = file["name"].as_str().ok_or("a test file without a name")?;
        let path = Path::new(name);
        let path = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_owned());
        let relative = path
            .strip_prefix(&root)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        for test in file["assertionResults"]
            .as_array()
            .ok_or("a file without results")?
        {
            let line = test["location"]["line"]
                .as_u64()
                .and_then(|line| usize::try_from(line).ok())
                .ok_or("a test without a location; the report needs --includeTaskLocation")?;
            let outcome = match test["status"].as_str() {
                Some("passed") => Outcome::Passed,
                Some("failed") => Outcome::Failed,
                Some(status) => Outcome::Ignored(Some(format!("{status} in its suite"))),
                None => Outcome::Failed,
            };
            results
                .entry((relative.clone(), line))
                .or_default()
                .push(outcome);
        }
    }
    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_test_is_read_by_its_file_and_line() {
        let value = serde_json::json!({
            "testResults": [{
                "name": "/repository/apps/companion/test/a.test.ts",
                "assertionResults": [
                    { "status": "passed", "location": { "line": 7, "column": 3 } },
                    { "status": "skipped", "location": { "line": 12, "column": 3 } },
                    { "status": "failed", "location": { "line": 12, "column": 3 } }
                ]
            }]
        });
        let results = parse(&value, Path::new("/repository")).expect("parses");
        assert_eq!(
            results[&("apps/companion/test/a.test.ts".to_owned(), 7)],
            [Outcome::Passed]
        );
        assert_eq!(
            results[&("apps/companion/test/a.test.ts".to_owned(), 12)],
            [
                Outcome::Ignored(Some("skipped in its suite".to_owned())),
                Outcome::Failed
            ]
        );
    }

    #[test]
    fn a_report_without_locations_is_refused() {
        let value = serde_json::json!({
            "testResults": [{ "name": "/r/a.test.ts", "assertionResults": [{ "status": "passed" }] }]
        });
        assert!(parse(&value, Path::new("/r")).is_err());
    }
}
