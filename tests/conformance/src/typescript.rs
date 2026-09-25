//! TypeScript and JavaScript tests, and the identifiers their comments and titles name.
//!
//! `tests/conformance/typescript-facts.mjs` reads each file with the TypeScript compiler the
//! packages already depend on and says where its test calls and comments are. This module decides
//! what each comment keys, with the same rules as Rust source:
//!
//! * a comment inside a test's body keys that test;
//! * a comment directly above a test call, with no blank line between them, keys that test, and one
//!   directly above a `describe` keys every test inside it;
//! * a comment before the file's first statement keys every test in the file;
//! * a test's title keys it, and a `describe`'s title keys every test inside it;
//! * any other comment is a reference, not a test.

use std::path::Path;
use std::process::Command;

use serde::Deserialize;

/// One test call or suite call.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct Call {
    /// `test` or `suite`.
    pub kind: String,
    /// The title, when it is a plain string.
    pub title: Option<String>,
    /// The title's source text, whatever it is.
    #[serde(rename = "titleText")]
    pub title_text: String,
    /// The line the call starts on.
    pub line: usize,
    /// The column the call starts at, from 1.
    pub column: usize,
    /// The line the call ends on.
    pub end: usize,
    /// The line a test run reports the call at: where its callee ends and its arguments open.
    pub reported: usize,
    /// The suite call this one is inside, by index.
    pub parent: Option<usize>,
}

/// One comment.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct CommentFact {
    /// The line it starts on.
    pub line: usize,
    /// The line it ends on.
    #[serde(rename = "endLine")]
    pub end_line: usize,
    /// Its text, markers included.
    pub text: String,
    /// The line of the code that follows it.
    pub next: usize,
}

/// What one file holds.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct FileFacts {
    /// The file, relative to the repository.
    pub file: String,
    /// Its test and suite calls.
    pub calls: Vec<Call>,
    /// Its comments.
    pub comments: Vec<CommentFact>,
    /// The line of its first statement.
    #[serde(rename = "firstStatement")]
    pub first_statement: Option<usize>,
}

#[derive(Deserialize)]
struct Facts {
    files: Vec<FileFacts>,
}

/// Reads `files` (relative to `root`) with the TypeScript compiler.
///
/// # Errors
///
/// Returns why the compiler could not be run or what it wrote could not be read.
pub fn read(root: &Path, files: &[String]) -> Result<Vec<FileFacts>, String> {
    if files.is_empty() {
        return Ok(Vec::new());
    }
    // The script beside this crate, which reads a tree with its own repository's compiler.
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("typescript-facts.mjs");
    let output = Command::new("node")
        .arg(&script)
        .arg(root)
        .args(files)
        .output()
        .map_err(|error| {
            format!("node could not be started to read the TypeScript sources: {error}")
        })?;
    if !output.status.success() {
        return Err(format!(
            "the TypeScript sources could not be read: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let facts: Facts = serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("the TypeScript facts are not what was expected: {error}"))?;
    Ok(facts.files)
}

/// What one comment or title keys.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Keys {
    /// These test calls, by index, and how.
    Tests(Vec<usize>, TsBinding),
    /// No test: the comment is a reference.
    Nothing,
}

/// How a TypeScript test was keyed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TsBinding {
    /// A comment inside its body.
    Inside,
    /// A comment directly above it or above its suite.
    Attached,
    /// A comment before the file's first statement.
    File,
    /// Its title or its suite's.
    Title,
}

impl FileFacts {
    /// Every test call inside the call at `index`, or that call itself when it is a test.
    #[must_use]
    pub fn tests_under(&self, index: usize) -> Vec<usize> {
        if self.calls[index].kind == "test" {
            return vec![index];
        }
        (0..self.calls.len())
            .filter(|candidate| {
                self.calls[*candidate].kind == "test" && self.is_inside(*candidate, index)
            })
            .collect()
    }

    fn is_inside(&self, call: usize, suite: usize) -> bool {
        let mut parent = self.calls[call].parent;
        while let Some(index) = parent {
            if index == suite {
                return true;
            }
            parent = self.calls[index].parent;
        }
        false
    }

    /// Every test in the file.
    #[must_use]
    pub fn tests(&self) -> Vec<usize> {
        (0..self.calls.len())
            .filter(|index| self.calls[*index].kind == "test")
            .collect()
    }

    /// The last line of the block of comments `comment` starts or continues: comments on
    /// consecutive lines are one block, as a `//` comment of several lines is.
    fn block_end(&self, comment: &CommentFact) -> usize {
        let mut end = comment.end_line;
        for other in &self.comments {
            if other.line > comment.line && other.line <= end + 1 {
                end = end.max(other.end_line);
            }
        }
        end
    }

    /// What `comment` keys.
    #[must_use]
    pub fn keyed_by_comment(&self, comment: &CommentFact) -> Keys {
        // The innermost test whose body holds it.
        let inside = (0..self.calls.len())
            .filter(|index| {
                let call = &self.calls[*index];
                call.kind == "test"
                    && ((call.line < comment.line && comment.line <= call.end)
                        || (call.line == comment.line && comment.next != call.line))
            })
            .min_by_key(|index| self.calls[*index].end - self.calls[*index].line);
        if let Some(index) = inside {
            return Keys::Tests(vec![index], TsBinding::Inside);
        }
        // Directly above a call: no blank line between the comment's block and the code that
        // follows.
        let end = self.block_end(comment);
        if comment.next <= end + 1
            && let Some(index) = self.calls.iter().position(|call| call.line == comment.next)
        {
            return Keys::Tests(self.tests_under(index), TsBinding::Attached);
        }
        if self.first_statement.is_some_and(|first| end < first) {
            return Keys::Tests(self.tests(), TsBinding::File);
        }
        Keys::Nothing
    }

    /// The title a test is known by: its suites' titles and its own, as the test runner joins them.
    #[must_use]
    pub fn full_title(&self, index: usize) -> String {
        let mut titles = Vec::new();
        let mut current = Some(index);
        while let Some(at) = current {
            let call = &self.calls[at];
            titles.push(
                call.title
                    .clone()
                    .unwrap_or_else(|| call.title_text.clone()),
            );
            current = call.parent;
        }
        titles.reverse();
        titles.join(" ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts() -> FileFacts {
        FileFacts {
            file: "test/a.test.ts".to_owned(),
            calls: vec![
                Call {
                    kind: "suite".into(),
                    title: Some("the renderer".into()),
                    title_text: String::new(),
                    line: 5,
                    column: 1,
                    end: 30,
                    reported: 5,
                    parent: None,
                },
                Call {
                    kind: "test".into(),
                    title: Some("draws".into()),
                    title_text: String::new(),
                    line: 7,
                    column: 3,
                    end: 12,
                    reported: 7,
                    parent: Some(0),
                },
                Call {
                    kind: "test".into(),
                    title: Some("refuses".into()),
                    title_text: String::new(),
                    line: 15,
                    column: 3,
                    end: 20,
                    reported: 15,
                    parent: Some(0),
                },
            ],
            comments: Vec::new(),
            first_statement: Some(3),
        }
    }

    fn comment(line: usize, end_line: usize, next: usize) -> CommentFact {
        CommentFact {
            line,
            end_line,
            text: String::new(),
            next,
        }
    }

    #[test]
    fn a_comment_in_a_body_keys_that_test_and_one_above_keys_the_next() {
        let facts = facts();
        assert_eq!(
            facts.keyed_by_comment(&comment(9, 9, 10)),
            Keys::Tests(vec![1], TsBinding::Inside)
        );
        assert_eq!(
            facts.keyed_by_comment(&comment(14, 14, 15)),
            Keys::Tests(vec![2], TsBinding::Attached)
        );
        assert_eq!(
            facts.keyed_by_comment(&comment(4, 4, 5)),
            Keys::Tests(vec![1, 2], TsBinding::Attached)
        );
    }

    #[test]
    fn a_blank_line_after_a_comment_leaves_it_a_reference_and_a_header_keys_the_file() {
        let facts = facts();
        assert_eq!(facts.keyed_by_comment(&comment(13, 13, 15)), Keys::Nothing);
        assert_eq!(
            facts.keyed_by_comment(&comment(1, 2, 3)),
            Keys::Tests(vec![1, 2], TsBinding::File)
        );
    }

    #[test]
    fn a_comment_of_several_lines_is_one_block_above_its_test() {
        let mut facts = facts();
        facts.comments = vec![comment(13, 13, 15), comment(14, 14, 15)];
        let first = facts.comments[0].clone();
        assert_eq!(
            facts.keyed_by_comment(&first),
            Keys::Tests(vec![2], TsBinding::Attached)
        );
    }

    #[test]
    fn a_full_title_joins_the_suites_titles() {
        assert_eq!(facts().full_title(2), "the renderer refuses");
    }
}
