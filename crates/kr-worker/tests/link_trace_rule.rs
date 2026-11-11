//! The link's account of its own work is compiled only where the `testing` feature is on.
//!
//! A shipped worker holds none of it: not the module, and not a call into it. The module is
//! declared under the feature, and so is every statement outside its file that names it, so a
//! build without the feature has nothing to refuse. This reads the worker's sources and fails at
//! the first mention that the feature does not cover.

use std::path::{Path, PathBuf};

/// The name every mention carries: the module's, and the alias the link imports it as.
const NAME: &str = "link_trace";

/// The attribute that has to stand on the line above a statement that mentions the module.
const ATTRIBUTE: &str = "#[cfg(feature = \"testing\")]";

fn sources(directory: &Path, found: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(directory).expect("the source directory reads") {
        let path = entry.expect("an entry").path();
        if path.is_dir() {
            sources(&path, found);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            found.push(path);
        }
    }
}

/// The line without its trailing comment and its indentation.
fn code(line: &str) -> &str {
    line.split("//").next().unwrap_or("").trim()
}

/// Whether `line` carries on the statement the line above it began.
fn continues(above: &str, line: &str) -> bool {
    let above = code(above);
    let line = code(line);
    ["(", ",", "=", "{", "||", "&&"]
        .iter()
        .any(|ending| above.ends_with(ending))
        || [")", ".", "}", "else"]
            .iter()
            .any(|start| line.starts_with(start))
}

#[test]
fn every_statement_outside_the_links_account_that_names_it_is_compiled_only_with_the_testing_feature()
 {
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    sources(&source, &mut files);
    let mut mentions = 0usize;
    let mut uncovered = Vec::new();
    for file in files {
        if file
            .file_name()
            .is_some_and(|name| name == "plugin_link_trace.rs")
        {
            continue;
        }
        let text = std::fs::read_to_string(&file).expect("a source reads");
        let lines: Vec<&str> = text.lines().collect();
        for (at, line) in lines.iter().enumerate() {
            if line.trim_start().starts_with("//") || !code(line).contains(NAME) {
                continue;
            }
            mentions += 1;
            let mut start = at;
            while start > 0 && continues(lines[start - 1], lines[start]) {
                start -= 1;
            }
            if start == 0 || lines[start - 1].trim() != ATTRIBUTE {
                uncovered.push(format!("{}:{}", file.display(), at + 1));
            }
        }
    }
    assert!(mentions > 0, "the link no longer names its account");
    assert!(
        uncovered.is_empty(),
        "these statements name the link's account without the testing feature above them: {uncovered:?}"
    );
}
