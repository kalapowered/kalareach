//! A test that returns early for want of something it needs says so on a line the report reads.
//!
//! The report counts a test that passed by returning early as not run only when the test wrote a
//! line that starts `skipped:`, `skipping:` or `not exercised`, or that names itself first and then
//! says `: skipped, because `. A test that returns after a print worded some other way reads as one
//! that passed, in the report and in every log that shows no output. Nothing but a reading of the
//! sources sees it, so this one reads them.
//!
//! Two things are read, in the Rust files the repository tracks, as Rust is read: a comment, a raw
//! string and a character are passed over, and a literal that wraps over lines with a backslash is
//! joined as the compiler joins it.
//!
//! - By its words: a `println!`, `eprintln!`, `print!` or `eprint!` whose first literal speaks of
//!   something that did not run (`skip`, `not run`, `cannot run`, `could not run`, `not exercised`,
//!   `not tested`) is wherever it stands in the repository, because a message of that kind that the
//!   report cannot read is the fault.
//! - By its shape: in test code, a print that a `return` or a `continue` follows later in the same
//!   block, at the print's own depth, is a test that stops where it stands, whatever it says. Test
//!   code is a file under a `tests` or a `testing` folder, a file named `tests.rs` or `testing.rs`,
//!   each item under `#[cfg(test)]` (a `cfg` that holds `test` outside a `not`), and each module
//!   that such an item or file declares with `mod name;`, by its `#[path]` or its `name.rs` or
//!   `name/mod.rs`, and the modules that module declares in turn. A program under `src/bin`, and a
//!   `src/main.rs`, is not test code.
//!
//! Each such print starts with a marker of [`EARLY_RETURN`], or holds [`EARLY_RETURN_NAMED`], or is
//! on the list below with its reason. A test that skips only part of its case says
//! `not exercised:`, so that the report reads the whole case as not run: it claims too little and
//! never too much.
//!
//! The limits: a print that goes through a variable or a helper, a write to a stream that is not a
//! print macro, a `return;` with no print before it, a conditional `return` in a block of its own
//! after the print, a block that ends in a value where a `return` would stand, an early return by
//! `process::exit` or `break`, and a print whose first literal is made by a macro are not seen.
//! Review holds those.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use kr_conformance::libtest::{EARLY_RETURN, EARLY_RETURN_NAMED, says_early_return};
use kr_conformance::rust_lex::{Tok, Token, lex};

/// The macros that write a line to a test's captured output.
const PRINTS: &[&str] = &["println", "eprintln", "print", "eprint"];

/// What a print says when it speaks of something that did not run, in lower case.
const WORDS: &[&str] = &[
    "skip",
    "not run",
    "cannot run",
    "could not run",
    "not exercised",
    "not tested",
];

/// A print that is not an early return of a test, or is one that stands where only the person
/// reading the output needs its words, with the reason.
struct Allowed {
    /// The file, from the repository's root.
    path: &'static str,
    /// What the print's first literal starts with.
    said: &'static str,
    /// Why the print is not a test's early return.
    reason: &'static str,
}

/// The prints that are on the list.
const ALLOWED: &[Allowed] = &[
    Allowed {
        path: "apps/companion/src-tauri/tests/host_events.rs",
        said: "host_events: a task panicked: ",
        reason: "the helper's failure report, which it ends with exit status 1",
    },
    Allowed {
        path: "crates/kr-cli/src/attach.rs",
        said: "kr-probe:lost:",
        reason: "the child half of the case, a program the case starts: it prints the marker the case reads and ends, and the case fails for the marker",
    },
    Allowed {
        path: "crates/kr-cli/tests/upgrade.rs",
        said: "inside the level: no kept release",
        reason: "the helper that finds the release runs once for the program; each case that needs it says on its own line that it did not run",
    },
    Allowed {
        path: "crates/kr-controller/src/net/rendezvous.rs",
        said: "attempt ",
        reason: "an attempt that does not count is made again, in a loop that goes on to the next one",
    },
    Allowed {
        path: "crates/kr-controller/tests/network_project.rs",
        said: "{INNER_NOT_EXERCISED}",
        reason: "the half of the case that runs inside the namespace; the half outside reads the line and says `not exercised:` itself",
    },
    Allowed {
        path: "crates/kr-controller/tests/network_project.rs",
        said: "{INNER_ASSERTED}",
        reason: "the half of the case that runs inside the namespace; the half outside reads the line",
    },
    Allowed {
        path: "crates/kr-controller/tests/teardown_jobs.rs",
        said: "run {run} of {RUNS}",
        reason: "a run that shows nothing is not counted, in a loop that goes on to the next run",
    },
    Allowed {
        path: "crates/kr-describe-model/src/bin/kr-describe-bench.rs",
        said: "whole_product_rss_cpu:",
        reason: "a figure line of the benchmark program, which says what the run does not measure",
    },
    Allowed {
        path: "crates/kr-describe/src/testing.rs",
        said: "kr-describe-stub",
        reason: "the stand-in description program's own output and error lines, before it ends",
    },
    Allowed {
        path: "crates/kr-describe/src/testing.rs",
        said: "usage: kr-describe-stub",
        reason: "the stand-in description program's usage line",
    },
    Allowed {
        path: "crates/kr-ipc/src/testing.rs",
        said: "the drop returned",
        reason: "the child half of the case, which the case starts: it prints a line the case reads, and the assertions after it decide",
    },
    Allowed {
        path: "crates/kr-plugin-runtime/tests/bundled.rs",
        said: "{REQUIRE_NO_NETWORK} is not set",
        reason: "the helper says which path the run exercises, and the case goes on and runs it",
    },
    Allowed {
        path: "crates/kr-project/src/boundary/macho.rs",
        said: "KR_MACHO_CHILD checked ",
        reason: "the child half of a case, whose output the half that started it reads",
    },
    Allowed {
        path: "crates/kr-shell-integration/src/host/startup.rs",
        said: "edition {name}: not on the search path",
        reason: "the case is for each edition that is found, and runs by hand on the Windows machine with `--ignored`",
    },
    Allowed {
        path: "crates/kr-transfer/tests/authority.rs",
        said: "{}: {} lookups skipped",
        reason: "a count line that names the other platform's cases",
    },
    Allowed {
        path: "crates/kr-transfer/tests/authority.rs",
        said: "hdiutil refused for a moment",
        reason: "a refused attempt is made again, in a loop that goes on to the next attempt and returns the last refusal as an error",
    },
    Allowed {
        path: "crates/kr-worker/src/diagnostics.rs",
        said: "{DONE}",
        reason: "the child half of a case, whose output the half that started it reads",
    },
    Allowed {
        path: "crates/kr-worker/src/diagnostics.rs",
        said: "a write that waits for a reader was drained",
        reason: "the child half of a case, whose output the half that started it reads",
    },
    Allowed {
        path: "crates/kr-worker/tests/input_lease.rs",
        said: "{stalled:?}: attempt",
        reason: "an attempt that does not count is made again, in a loop that goes on to the next one",
    },
    Allowed {
        path: "crates/kr-worker/tests/persistence.rs",
        said: "said ",
        reason: "the child half of a case, whose output the half that started it reads",
    },
    Allowed {
        path: "crates/kr-worker/tests/windows.rs",
        said: "{} is left in the temporary folder",
        reason: "a Drop's report of a folder it could not remove, which it follows with a panic unless the case is already failing",
    },
    Allowed {
        path: "tests/conformance/src/main.rs",
        said: "{} identifiers:",
        reason: "the report's own summary line",
    },
    Allowed {
        path: "tests/conformance/src/main.rs",
        said: "  could not run ",
        reason: "the report's own list of the programs it could not run",
    },
    Allowed {
        path: "tests/conformance/src/main.rs",
        said: "not run: ",
        reason: "the report's own list of the terminals it did not run",
    },
    Allowed {
        path: "tests/conformance/src/run.rs",
        said: "kr-conformance list-one:",
        reason: "the report's runner program's own usage error",
    },
    Allowed {
        path: "tests/conformance/src/run.rs",
        said: "kr-conformance run-one:",
        reason: "the report's runner program's own usage error",
    },
    Allowed {
        path: "tests/e2e/m1b/tests/checkpoint.rs",
        said: "a new candidate was served no record",
        reason: "the helper says what the room did and returns what it found, which the leg records",
    },
    Allowed {
        path: "tests/support/artifacts/src/lib.rs",
        said: "directory={}",
        reason: "the child half of a case, whose output the half that started it reads",
    },
    Allowed {
        path: "tests/support/codex-stand-in/src/keyboard.rs",
        said: "{line}",
        reason: "the stand-in terminal's own output line, written where no keyboard is read, as the \
                 program it stands in writes it",
    },
    Allowed {
        path: "tests/support/codex-stand-in/src/server.rs",
        said: "stand-in: ",
        reason: "the stand-in program's own error line before it ends",
    },
    Allowed {
        path: "tests/support/codex-stand-in/src/terminal.rs",
        said: "stand-in: ",
        reason: "the stand-in program's own error line before it ends",
    },
];

fn repository() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..")
}

/// The Rust files the repository tracks, as their paths from its root.
fn tracked_sources(root: &Path) -> Vec<String> {
    let listed = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["ls-files", "-z", "--", "*.rs"])
        .output()
        .expect("git starts");
    assert!(
        listed.status.success(),
        "git lists the tracked sources: {}",
        String::from_utf8_lossy(&listed.stderr)
    );
    listed
        .stdout
        .split(|byte| *byte == 0)
        .filter(|name| !name.is_empty())
        .map(|name| String::from_utf8(name.to_vec()).expect("a file name that is text"))
        .collect()
}

/// The tokens of `source`, the file at `path`, without its comments, which the reading of the
/// code never looks at.
///
/// # Errors
///
/// Returns where the source cannot be read as Rust.
fn code_tokens(path: &str, source: &str) -> Result<Vec<Token>, String> {
    let tokens = lex(source).map_err(|error| format!("{path}:{}: {}", error.line, error.what))?;
    Ok(tokens
        .into_iter()
        .filter(|token| !token.is_comment())
        .collect())
}

/// Where the token at `open`, one of `(`, `[` and `{`, closes.
fn closing(tokens: &[Token], open: usize) -> Option<usize> {
    let mut depth = 0_usize;
    for (at, token) in tokens.iter().enumerate().skip(open) {
        match token.tok {
            Tok::Punct('(' | '[' | '{') => depth += 1,
            Tok::Punct(')' | ']' | '}') => {
                depth -= 1;
                if depth == 0 {
                    return Some(at);
                }
            }
            _ => {}
        }
    }
    None
}

/// Whether a `return` or a `continue` comes in `rest`, the tokens that follow a print, before the
/// block that holds the print closes: one at the print's own depth, whatever statements stand
/// between. One in a deeper block is a conditional return and is not read.
fn returns_in_block(rest: &[Token]) -> bool {
    let mut depth = 0_usize;
    for token in rest {
        match token.tok {
            Tok::Punct('(' | '[' | '{') => depth += 1,
            Tok::Punct(')' | ']' | '}') => match depth.checked_sub(1) {
                Some(outer) => depth = outer,
                None => return false,
            },
            _ if depth == 0 && matches!(token.ident(), Some("return" | "continue")) => {
                return true;
            }
            _ => {}
        }
    }
    false
}

/// One print of a source.
#[derive(Debug, PartialEq, Eq)]
struct Print {
    /// The line the macro starts on.
    line: usize,
    /// Its first literal, with the escapes and the wrapped line breaks decoded.
    said: String,
    /// Whether a `return` or a `continue` follows it later in its block, at its own depth.
    leaves: bool,
}

/// Every print macro of `tokens`.
fn prints(tokens: &[Token]) -> Vec<Print> {
    let mut found = Vec::new();
    for (at, token) in tokens.iter().enumerate() {
        let Some(name) = token.ident() else {
            continue;
        };
        if !PRINTS.contains(&name) || !tokens.get(at + 1).is_some_and(|next| next.is_punct('!')) {
            continue;
        }
        // A macro takes any of the three delimiters.
        let Some(Tok::Punct(delimiter @ ('(' | '[' | '{'))) =
            tokens.get(at + 2).map(|next| &next.tok)
        else {
            continue;
        };
        let Some(close) = closing(tokens, at + 2) else {
            continue;
        };
        // The first literal of the macro's own arguments, not of one nested in a call.
        let mut depth = 0_usize;
        let mut said = String::new();
        for inside in &tokens[at + 3..close] {
            match &inside.tok {
                Tok::Punct('(' | '[' | '{') => depth += 1,
                Tok::Punct(')' | ']' | '}') => depth -= 1,
                Tok::Str(value, _) if depth == 0 => {
                    said.clone_from(value);
                    break;
                }
                _ => {}
            }
        }
        // A brace macro in the place of a statement needs no semicolon; the others do.
        let after = match tokens.get(close + 1) {
            Some(next) if next.is_punct(';') => Some(close + 2),
            _ if *delimiter == '{' => Some(close + 1),
            _ => None,
        };
        let leaves = after.is_some_and(|next| returns_in_block(&tokens[next..]));
        found.push(Print {
            line: token.line,
            said,
            leaves,
        });
    }
    found
}

/// Whether `attribute`, the tokens between the brackets of an attribute, is a `cfg` that holds
/// `test` outside every `not(..)`: `cfg(test)` and `cfg(all(test, not(windows)))` do, and
/// `cfg(not(test))` does not.
fn is_test_cfg(attribute: &[Token]) -> bool {
    if attribute.first().and_then(Token::ident) != Some("cfg") {
        return false;
    }
    // For each open parenthesis: whether what stands inside it is under an odd number of `not`s.
    let mut negated = vec![false];
    let mut word = None;
    for token in attribute {
        if token.is_punct('(') {
            let outer = negated.last().copied().unwrap_or(false);
            negated.push(outer != (word == Some("not")));
        } else if token.is_punct(')') {
            negated.pop();
        } else if token.ident() == Some("test") && !negated.last().copied().unwrap_or(false) {
            return true;
        }
        word = token.ident();
    }
    false
}

/// The line ranges of `tokens` that are test code by their attribute: each item under
/// `#[cfg(test)]` (or a `cfg` that holds `test` outside a `not`), and the whole file under
/// `#![cfg(test)]`.
fn cfg_test_lines(tokens: &[Token]) -> Vec<(usize, usize)> {
    let mut found = Vec::new();
    let mut at = 0;
    while at < tokens.len() {
        if !tokens[at].is_punct('#') {
            at += 1;
            continue;
        }
        let inner = tokens.get(at + 1).is_some_and(|next| next.is_punct('!'));
        let open = at + 1 + usize::from(inner);
        if !tokens.get(open).is_some_and(|next| next.is_punct('[')) {
            at += 1;
            continue;
        }
        let Some(close) = closing(tokens, open) else {
            break;
        };
        let attribute = &tokens[open + 1..close];
        let is_test = is_test_cfg(attribute);
        if is_test && inner {
            return vec![(0, usize::MAX)];
        }
        if is_test {
            // The item runs to its closing brace, or to the semicolon that ends it.
            let mut depth = 0_usize;
            for item in close + 1..tokens.len() {
                match tokens[item].tok {
                    Tok::Punct('(' | '[') => depth += 1,
                    Tok::Punct(')' | ']') => depth = depth.saturating_sub(1),
                    Tok::Punct('{') if depth == 0 => {
                        if let Some(end) = closing(tokens, item) {
                            found.push((tokens[at].line, tokens[end].end_line));
                        }
                        break;
                    }
                    Tok::Punct(';') if depth == 0 => break,
                    _ => {}
                }
            }
        }
        at = close + 1;
    }
    found
}

/// A module declared as `mod name;`, which lives in a file of its own.
#[derive(Debug)]
struct OutOfLine {
    /// The line the declaration is on.
    line: usize,
    /// Whether the attributes of the declaration hold `test`.
    attributed: bool,
    /// The files the module can be, from the repository's root.
    files: Vec<String>,
}

/// The `#[path = ".."]` among `attributes`.
fn renamed<'a>(attributes: &[&'a [Token]]) -> Option<&'a str> {
    attributes.iter().find_map(|attribute| match *attribute {
        [name, equals, token] if name.ident() == Some("path") && equals.is_punct('=') => {
            match &token.tok {
                Tok::Str(value, _) => Some(value.as_str()),
                _ => None,
            }
        }
        _ => None,
    })
}

/// Whether the file at `path` is a root of its module tree, or a `mod.rs`: its modules are in its
/// own folder. A file that is not one keeps its modules in a folder named for it.
fn is_crate_root(path: &str) -> bool {
    let (folder, file) = path.rsplit_once('/').unwrap_or(("", path));
    matches!(file, "lib.rs" | "main.rs" | "mod.rs" | "build.rs")
        || matches!(
            folder.rsplit('/').next(),
            Some("tests" | "benches" | "examples" | "bin")
        )
}

/// `tail` below `folder`, with its `.` and `..` parts taken out.
fn joined(folder: &[&str], tail: &str) -> String {
    let mut parts = folder.to_vec();
    for part in tail.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            other => parts.push(other),
        }
    }
    parts.join("/")
}

/// The files that `mod name;` can be when the file at `path` declares it inside the inline
/// modules `inline`, with the `#[path]` it carries, if any.
fn module_files(path: &str, inline: &[&str], name: &str, renamed: Option<&str>) -> Vec<String> {
    let (folder, file) = path.rsplit_once('/').unwrap_or(("", path));
    let beside: Vec<&str> = folder.split('/').filter(|part| !part.is_empty()).collect();
    let mut modules = beside.clone();
    if !is_crate_root(path) {
        modules.push(file.strip_suffix(".rs").unwrap_or(file));
    }
    modules.extend(inline);
    if let Some(renamed) = renamed {
        // A `#[path]` outside an inline module starts at the file's own folder.
        let from = if inline.is_empty() { &beside } else { &modules };
        return vec![joined(from, renamed)];
    }
    vec![
        joined(&modules, &format!("{name}.rs")),
        joined(&modules, &format!("{name}/mod.rs")),
    ]
}

/// The modules that `tokens`, the source of the file at `path`, declares with `mod name;`.
fn out_of_line(path: &str, tokens: &[Token]) -> Vec<OutOfLine> {
    let mut found = Vec::new();
    // The inline modules the reading stands in, each with where its brace closes.
    let mut inline: Vec<(&str, usize)> = Vec::new();
    // The attributes of the item that comes next.
    let mut attributes: Vec<&[Token]> = Vec::new();
    let mut at = 0;
    while at < tokens.len() {
        while inline.last().is_some_and(|(_, end)| at > *end) {
            inline.pop();
        }
        let token = &tokens[at];
        if token.is_punct('#') {
            let inner = tokens.get(at + 1).is_some_and(|next| next.is_punct('!'));
            let open = at + 1 + usize::from(inner);
            if tokens.get(open).is_some_and(|next| next.is_punct('['))
                && let Some(close) = closing(tokens, open)
            {
                if !inner {
                    attributes.push(&tokens[open + 1..close]);
                }
                at = close + 1;
                continue;
            }
        }
        if token.ident() == Some("mod")
            && let Some(name) = tokens.get(at + 1).and_then(Token::ident)
            && let Some(after) = tokens.get(at + 2)
        {
            if after.is_punct(';') {
                let inside: Vec<&str> = inline.iter().map(|(inside, _)| *inside).collect();
                found.push(OutOfLine {
                    line: token.line,
                    attributed: attributes.iter().any(|attribute| is_test_cfg(attribute)),
                    files: module_files(path, &inside, name, renamed(&attributes)),
                });
                attributes.clear();
                at += 3;
                continue;
            }
            if after.is_punct('{')
                && let Some(end) = closing(tokens, at + 2)
            {
                inline.push((name, end));
                attributes.clear();
                at += 3;
                continue;
            }
        }
        if matches!(token.tok, Tok::Punct(';' | '{' | '}')) {
            attributes.clear();
        }
        at += 1;
    }
    found
}

/// The files of `sources`, each as its path from the repository's root and its text, that are test
/// code because a module declaration says so: a `mod name;` under an attribute that holds `test`
/// or inside an item that has one, or in a file that is test code, with the file it names; and,
/// the same way, the files those declare. The second part holds a line for each such declaration
/// that names no file among `sources`, but not in a tree of planted sources under a `fixtures`
/// folder, which holds such declarations on purpose. A source that cannot be read as Rust
/// declares nothing.
fn declared_test_files(sources: &[(String, String)]) -> (HashSet<String>, Vec<String>) {
    let known: HashSet<&str> = sources.iter().map(|(path, _)| path.as_str()).collect();
    let mut declarations = Vec::new();
    for (path, source) in sources {
        let Ok(tokens) = code_tokens(path, source) else {
            continue;
        };
        let under_attribute = cfg_test_lines(&tokens);
        for declared in out_of_line(path, &tokens) {
            let in_test_item = declared.attributed
                || under_attribute
                    .iter()
                    .any(|(from, to)| (*from..=*to).contains(&declared.line));
            declarations.push((path.as_str(), in_test_item, declared));
        }
    }
    let mut test_files: HashSet<String> = HashSet::new();
    loop {
        let before = test_files.len();
        for (path, in_test_item, declared) in &declarations {
            if *in_test_item || is_test_file(path) || test_files.contains(*path) {
                for file in &declared.files {
                    if known.contains(file.as_str()) {
                        test_files.insert(file.clone());
                    }
                }
            }
        }
        if test_files.len() == before {
            break;
        }
    }
    let missing = declarations
        .iter()
        .filter(|(path, in_test_item, declared)| {
            (*in_test_item || is_test_file(path) || test_files.contains(*path))
                && !path.split('/').any(|part| part == "fixtures")
                && !declared
                    .files
                    .iter()
                    .any(|file| known.contains(file.as_str()))
        })
        .map(|(path, _, declared)| {
            format!(
                "{path}:{}: a module declared for tests has none of the files {}",
                declared.line,
                declared.files.join(", ")
            )
        })
        .collect();
    (test_files, missing)
}

/// Whether the file at `path` is a test's: under a `tests` or a `testing` folder, or named for one.
fn is_test_file(path: &str) -> bool {
    path.split('/')
        .any(|part| matches!(part, "tests" | "testing" | "tests.rs" | "testing.rs"))
}

/// Whether the file at `path` is a program: under `src/bin`, or a `src/main.rs`.
fn is_program(path: &str) -> bool {
    path.contains("/src/bin/") || path.ends_with("/src/main.rs")
}

/// Why a print is read as an early return.
#[derive(Debug, PartialEq, Eq)]
enum Why {
    /// Its words speak of something that did not run.
    Words,
    /// It stands in test code and a `return` or a `continue` follows it in its block.
    Shape,
}

/// A print that is an early return, and whether it carries what the report reads.
#[derive(Debug, PartialEq, Eq)]
struct Candidate {
    line: usize,
    said: String,
    why: Why,
    marked: bool,
}

/// Every print of `source`, the file at `path`, that is read as an early return. `test_files` are
/// the files that module declarations make test code.
///
/// # Errors
///
/// Returns where the source cannot be read as Rust.
fn candidates(
    path: &str,
    source: &str,
    test_files: &HashSet<String>,
) -> Result<Vec<Candidate>, String> {
    let tokens = code_tokens(path, source)?;
    let under_attribute = cfg_test_lines(&tokens);
    let found = prints(&tokens)
        .into_iter()
        .filter_map(|print| {
            let lower = print.said.to_lowercase();
            let by_words = WORDS.iter().any(|word| lower.contains(word));
            let in_test_code = !is_program(path)
                && (is_test_file(path)
                    || test_files.contains(path)
                    || under_attribute
                        .iter()
                        .any(|(from, to)| (*from..=*to).contains(&print.line)));
            let why = if by_words {
                Why::Words
            } else if print.leaves && in_test_code {
                Why::Shape
            } else {
                return None;
            };
            Some(Candidate {
                marked: print.said.lines().any(says_early_return),
                line: print.line,
                said: print.said,
                why,
            })
        })
        .collect();
    Ok(found)
}

/// No test of the repository returns early after a print the report cannot read.
#[test]
fn every_early_return_of_a_test_says_so_on_a_line_the_report_reads() {
    let root = repository();
    let files = tracked_sources(&root);
    assert!(
        files.len() > 1000,
        "the reading reaches the repository's sources: {} files",
        files.len()
    );
    let sources: Vec<(String, String)> = files
        .iter()
        .filter_map(|path| {
            std::fs::read_to_string(root.join(path))
                .ok()
                .map(|source| (path.clone(), source))
        })
        .collect();
    let (test_files, missing) = declared_test_files(&sources);
    assert!(
        missing.is_empty(),
        "test modules whose file the reading does not find:\n{}",
        missing.join("\n")
    );
    assert!(
        test_files.len() > 50,
        "the reading reaches the test modules that live in files of their own: {}",
        test_files.len()
    );
    let mut unread = Vec::new();
    let mut unmarked = Vec::new();
    let mut marked = 0_usize;
    let mut listed = vec![false; ALLOWED.len()];
    for (path, source) in &sources {
        let found = match candidates(path, source, &test_files) {
            Ok(found) => found,
            Err(error) => {
                unread.push(error);
                continue;
            }
        };
        for candidate in found {
            if candidate.marked {
                marked += 1;
                continue;
            }
            let allowed = ALLOWED
                .iter()
                .position(|entry| entry.path == path && candidate.said.starts_with(entry.said));
            if let Some(entry) = allowed {
                listed[entry] = true;
                continue;
            }
            let said = candidate.said.escape_debug();
            unmarked.push(match candidate.why {
                Why::Words => format!("{path}:{}: speaks of a skip: \"{said}\"", candidate.line),
                Why::Shape => format!(
                    "{path}:{}: returns after the print: \"{said}\"",
                    candidate.line
                ),
            });
        }
    }
    assert!(
        unread.is_empty(),
        "sources the reading cannot read:\n{}",
        unread.join("\n")
    );
    assert!(
        marked > 40,
        "the reading finds the early returns that carry the report's words: {marked}"
    );
    let stale: Vec<String> = ALLOWED
        .iter()
        .zip(&listed)
        .filter(|(_, used)| !**used)
        .map(|(entry, _)| format!("{}: \"{}\" ({})", entry.path, entry.said, entry.reason))
        .collect();
    assert!(
        stale.is_empty(),
        "a print on the list is no longer in the source:\n{}",
        stale.join("\n")
    );
    assert!(
        unmarked.is_empty(),
        "a test returns early after a print that does not start with {EARLY_RETURN:?} and does not \
         hold {EARLY_RETURN_NAMED:?}, so the report reads it as one that passed:\n{}",
        unmarked.join("\n")
    );
}

/// What the reading finds in the planted files `files`, each as its path and its source: the
/// path, the line, why, and whether it is marked.
fn found_in(files: &[(&str, &str)]) -> Vec<(String, usize, Why, bool)> {
    let sources: Vec<(String, String)> = files
        .iter()
        .map(|(path, source)| ((*path).to_owned(), (*source).to_owned()))
        .collect();
    let (test_files, missing) = declared_test_files(&sources);
    assert!(missing.is_empty(), "{missing:?}");
    let mut all = Vec::new();
    for (path, source) in &sources {
        for candidate in candidates(path, source, &test_files).expect("the planted source is read")
        {
            all.push((
                path.clone(),
                candidate.line,
                candidate.why,
                candidate.marked,
            ));
        }
    }
    all
}

/// What the reading finds in `source` as the file at `path` alone: the line, why, and whether it
/// is marked.
fn found(path: &str, source: &str) -> Vec<(usize, Why, bool)> {
    found_in(&[(path, source)])
        .into_iter()
        .map(|(_, line, why, marked)| (line, why, marked))
        .collect()
}

/// The control: the reading names a print that speaks of a skip, wherever it stands, and a print
/// that stops a test where it stands, and it passes what carries the report's words and what is
/// neither.
#[test]
fn the_reading_names_a_print_that_says_a_skip_or_stops_a_test_and_passes_the_rest() {
    let product = "crates/x/src/lib.rs";
    let target = "crates/x/tests/a.rs";

    // By its words, in a file that is not test code.
    assert_eq!(
        found(
            product,
            "fn f() { eprintln!(\"skipping the leg: nothing\"); }"
        ),
        [(1, Why::Words, false)]
    );
    // Marked, in each of the forms the report reads.
    for said in [
        "skipped: the leg",
        "skipping: the leg",
        "not exercised: the leg",
        "{suite}: skipped, because {why}",
    ] {
        assert_eq!(
            found(product, &format!("fn f() {{ eprintln!(\"{said}\"); }}")),
            [(1, Why::Words, true)],
            "{said}"
        );
    }

    // By its shape, in a test file: a `return`, a `return None` and a `continue` that follow.
    for leaving in ["return;", "return None;", "continue;"] {
        assert_eq!(
            found(
                target,
                &format!("fn f() {{ if no {{ eprintln!(\"no IPv6 here\"); {leaving} }} }}")
            ),
            [(1, Why::Shape, false)],
            "{leaving}"
        );
    }
    // Marked, it is read and passes.
    assert_eq!(
        found(
            target,
            "fn f() { eprintln!(\"skipped: no IPv6 here\"); return; }"
        ),
        [(1, Why::Words, true)]
    );
    // A print that the test goes on after is not an early return, and neither is the same print
    // outside test code, in a program, or in a module that is not for tests.
    let leaving = "fn f() { eprintln!(\"no IPv6 here\"); return; }";
    assert!(found(target, "fn f() { eprintln!(\"going on\"); go(); }").is_empty());
    assert!(found(product, leaving).is_empty());
    assert!(found("crates/x/src/bin/p.rs", leaving).is_empty());
    assert!(found("crates/x/src/main.rs", leaving).is_empty());
    assert!(
        found(
            product,
            "#[cfg(not(test))]\nmod real {\n    fn f() { eprintln!(\"no IPv6 here\"); return; }\n}"
        )
        .is_empty()
    );

    // A module under `#[cfg(test)]` is test code, and what follows it is not.
    assert_eq!(
        found(
            product,
            "#[cfg(test)]\nmod tests {\n    #[test]\n    fn f() {\n        eprintln!(\"no IPv6 here\");\n        return;\n    }\n}\nfn g() { eprintln!(\"no IPv6 here\"); return; }"
        ),
        [(5, Why::Shape, false)]
    );
    // So is the file under `#![cfg(test)]`.
    assert_eq!(
        found(
            product,
            "#![cfg(test)]\nfn f() { eprintln!(\"no IPv6 here\"); return; }"
        ),
        [(2, Why::Shape, false)]
    );

    // A comment and a string that hold the words are not a print.
    assert!(
        found(
            target,
            "// eprintln!(\"skipping the leg\"); return;\nfn f() { let said = \"eprintln!(\\\"skipping\\\")\"; }"
        )
        .is_empty()
    );
}

/// The control: a message that wraps over lines is read as the compiler joins it, so words that a
/// line break falls inside are found, and the decoded message is the one shown.
#[test]
fn a_message_that_wraps_over_lines_is_read_as_the_compiler_joins_it() {
    let wrapped = "fn f() {\n    eprintln!(\"this host could not \\\n        run the leg\");\n}";
    let read = candidates("crates/x/src/lib.rs", wrapped, &HashSet::new())
        .expect("the planted source is read");
    assert_eq!(read.len(), 1, "{read:?}");
    assert_eq!(read[0].said, "this host could not run the leg");
    assert_eq!(
        (read[0].line, &read[0].why, read[0].marked),
        (2, &Why::Words, false)
    );
    // Joined, a marker that the break falls inside is the marker.
    assert_eq!(
        found(
            "crates/x/src/lib.rs",
            "fn f() { eprintln!(\"skipped: this host \\\n    could not run it\"); }"
        ),
        [(1, Why::Words, true)]
    );
}

/// The limits that stay: a print through a helper or a variable, and a `return;` with no print
/// before it, are not seen.
#[test]
fn the_reading_does_not_see_a_print_through_a_helper_or_a_return_with_nothing_before_it() {
    let target = "crates/x/tests/a.rs";
    assert!(found(target, "fn f() { say(\"skipping the leg\"); return; }").is_empty());
    assert!(
        found(
            target,
            "fn f() { let said = \"skipping\"; say(said); return; }"
        )
        .is_empty()
    );
    assert!(found(target, "fn f() { if no { return; } }").is_empty());
}

/// The control: a print is read whatever its delimiters.
#[test]
fn the_reading_takes_each_delimiter_of_a_print() {
    let product = "crates/x/src/lib.rs";
    let target = "crates/x/tests/a.rs";

    // By its words, with a bracket and with a brace, which needs no semicolon after it.
    assert_eq!(
        found(
            product,
            "fn f() { eprintln! { \"skipping the leg\" } done(); }"
        ),
        [(1, Why::Words, false)]
    );
    assert_eq!(
        found(product, "fn f() { eprintln![\"skipping the leg\"]; }"),
        [(1, Why::Words, false)]
    );
    // By its shape: the brace with and without a semicolon, and the bracket.
    for printing in [
        "eprintln! { \"no IPv6 here\" };",
        "eprintln! { \"no IPv6 here\" }",
        "eprintln![\"no IPv6 here\"];",
    ] {
        assert_eq!(
            found(target, &format!("fn f() {{ {printing} return; }}")),
            [(1, Why::Shape, false)],
            "{printing}"
        );
    }
    // A paren or a bracket macro with no semicolon is part of a larger expression, not a statement.
    assert!(found(target, "fn f() { eprintln!(\"no IPv6 here\") return; }").is_empty());
}

/// The control: a comment between the tokens of a print, or after it and before the `return`,
/// does not hide it, and one inside it is not its literal.
#[test]
fn the_reading_passes_over_comments_between_the_tokens_of_a_print() {
    let product = "crates/x/src/lib.rs";
    let target = "crates/x/tests/a.rs";

    // A comment after the print, before the `return`.
    assert_eq!(
        found(
            target,
            "fn f() {\n    eprintln!(\"no IPv6 here\"); // The host has no suitable address.\n    return;\n}"
        ),
        [(2, Why::Shape, false)]
    );
    assert_eq!(
        found(
            target,
            "fn f() {\n    eprintln!(\"no IPv6 here\");\n    /* Nothing to do. */\n    continue;\n}"
        ),
        [(2, Why::Shape, false)]
    );
    // A comment between the print's closing token and its semicolon.
    assert_eq!(
        found(
            target,
            "fn f() { eprintln!(\"no IPv6 here\") /* why */; return; }"
        ),
        [(1, Why::Shape, false)]
    );
    // A print inside a comment is no print, and a comment inside a print is not its literal.
    assert!(
        found(
            target,
            "/* eprintln! { \"skipping\" }; return; */\nfn f() {}"
        )
        .is_empty()
    );
    assert_eq!(
        found(
            product,
            "fn f() { eprintln!(/* skipping: not this */ \"skipped: the leg\"); }"
        ),
        [(1, Why::Words, true)]
    );
}

/// The control: a `return` or a `continue` that comes later in the block of the print, at its own
/// depth, is the print's early return, with statements between them; one in a block that closes
/// first, or in a deeper block, is not.
#[test]
fn the_reading_takes_a_return_that_follows_a_print_later_in_its_block() {
    let target = "crates/x/tests/a.rs";

    // A statement, or several, between the print and the `return` or the `continue`.
    assert_eq!(
        found(
            target,
            "fn f() {\n    eprintln!(\"no IPv6 here\");\n    cleanup();\n    return;\n}"
        ),
        [(2, Why::Shape, false)]
    );
    assert_eq!(
        found(
            target,
            "fn f() { for a in all { eprintln!(\"no IPv6 here\"); let seen = 1; note(seen); continue; } }"
        ),
        [(1, Why::Shape, false)]
    );
    // A block between them does not hide it: the `return` is at the print's own depth.
    assert_eq!(
        found(
            target,
            "fn f() { eprintln!(\"no IPv6 here\"); if again { work(); } return None; }"
        ),
        [(1, Why::Shape, false)]
    );
    // Marked, it is read and passes.
    assert_eq!(
        found(
            target,
            "fn f() { eprintln!(\"not exercised: no IPv6 here\"); cleanup(); return; }"
        ),
        [(1, Why::Words, true)]
    );

    // The print's block closes before the `return`: the print is on one branch, the `return` on
    // another.
    assert!(
        found(
            target,
            "fn f() { if no { eprintln!(\"no IPv6 here\"); } return; }"
        )
        .is_empty()
    );
    assert!(
        found(
            target,
            "fn f() { if no { eprintln!(\"no IPv6 here\"); } else { return; } }"
        )
        .is_empty()
    );
    // A `return` in a deeper block is a conditional one, which stays a limit.
    assert!(
        found(
            target,
            "fn f() { eprintln!(\"no IPv6 here\"); if no { return; } }"
        )
        .is_empty()
    );
    // The next function's `return` is another block.
    assert!(
        found(
            target,
            "fn f() { eprintln!(\"no IPv6 here\"); }\nfn g() { return; }"
        )
        .is_empty()
    );
}

/// The control: a module that a `#[cfg(test)]` declaration puts in a file of its own is test code,
/// in each place its file can stand, and so is each module that file declares; a module that is
/// not declared for tests is not.
#[test]
fn the_reading_takes_a_module_declared_out_of_line_for_tests_as_test_code() {
    const SHAPE: &str = "fn f() { eprintln!(\"no IPv6 here\"); return; }";

    // The file of a module declared in a crate's root, and in a module file named for its module.
    for (declaring, module) in [
        ("crates/x/src/lib.rs", "crates/x/src/cases.rs"),
        ("crates/x/src/net.rs", "crates/x/src/net/cases.rs"),
        ("crates/x/src/net/mod.rs", "crates/x/src/net/cases.rs"),
        ("crates/x/src/net/mod.rs", "crates/x/src/net/cases/mod.rs"),
    ] {
        assert_eq!(
            found_in(&[(declaring, "#[cfg(test)]\nmod cases;\n"), (module, SHAPE)]),
            [(module.to_owned(), 1, Why::Shape, false)],
            "{declaring} {module}"
        );
    }
    // A `#[path]`, with the attributes in either order and the declaration public.
    for declared in [
        "#[cfg(test)]\n#[path = \"../shared/cases.rs\"]\nmod cases;\n",
        "#[path = \"../shared/cases.rs\"]\n#[cfg(test)]\npub(crate) mod cases;\n",
        "#[cfg(all(test, not(windows)))]\n#[path = \"../shared/cases.rs\"]\n// Shared with the other crate.\nmod cases;\n",
    ] {
        assert_eq!(
            found_in(&[
                ("crates/x/src/lib.rs", declared),
                ("crates/x/shared/cases.rs", SHAPE)
            ]),
            [("crates/x/shared/cases.rs".to_owned(), 1, Why::Shape, false)],
            "{declared}"
        );
    }
    // The module's own declarations are test code, however far down.
    assert_eq!(
        found_in(&[
            ("crates/x/src/lib.rs", "#[cfg(test)]\nmod cases;\n"),
            ("crates/x/src/cases.rs", "mod more;\n"),
            ("crates/x/src/cases/more.rs", "mod deeper;\n"),
            ("crates/x/src/cases/more/deeper.rs", SHAPE),
        ]),
        [(
            "crates/x/src/cases/more/deeper.rs".to_owned(),
            1,
            Why::Shape,
            false
        )]
    );
    // A declaration inside a test module, and inside an inline module in a root.
    assert_eq!(
        found_in(&[
            (
                "crates/x/src/lib.rs",
                "#[cfg(test)]\nmod outer {\n    mod inner;\n}\n"
            ),
            ("crates/x/src/outer/inner.rs", SHAPE),
        ]),
        [(
            "crates/x/src/outer/inner.rs".to_owned(),
            1,
            Why::Shape,
            false
        )]
    );

    // A module that is not declared for tests is product code, and so is one that is declared
    // for builds that are not tests.
    for declared in [
        "mod real;\n",
        "#[cfg(not(test))]\nmod real;\n",
        "#[cfg(unix)]\nmod real;\n",
        "#[cfg(all(unix, not(test)))]\nmod real;\n",
    ] {
        assert!(
            found_in(&[
                ("crates/x/src/lib.rs", declared),
                ("crates/x/src/real.rs", SHAPE)
            ])
            .is_empty(),
            "{declared}"
        );
    }
}

/// The control: a `cfg` that holds `test` and also a `not` of something else is test code; one that
/// holds `test` only under a `not` is not.
#[test]
fn the_reading_takes_a_cfg_that_holds_test_beside_a_not_as_test_code() {
    assert_eq!(
        found_in(&[(
            "crates/x/src/lib.rs",
            "#[cfg(all(test, not(windows)))]\nmod tests {\n    fn f() { eprintln!(\"no IPv6 here\"); return; }\n}\n"
        )]),
        [("crates/x/src/lib.rs".to_owned(), 3, Why::Shape, false)]
    );
    assert!(
        found_in(&[(
            "crates/x/src/lib.rs",
            "#[cfg(all(unix, not(test)))]\nmod real {\n    fn f() { eprintln!(\"no IPv6 here\"); return; }\n}\n"
        )])
        .is_empty()
    );
}

/// The control: a module declared for tests whose file is not among the sources is named, so that
/// a declaration the reading cannot follow does not pass as read.
#[test]
fn a_module_declared_for_tests_that_has_no_file_is_named() {
    let sources = vec![(
        "crates/x/src/lib.rs".to_owned(),
        "#[cfg(test)]\nmod gone;\nmod product;\n".to_owned(),
    )];
    let (test_files, missing) = declared_test_files(&sources);
    assert!(test_files.is_empty());
    assert_eq!(
        missing,
        [
            "crates/x/src/lib.rs:2: a module declared for tests has none of the files \
             crates/x/src/gone.rs, crates/x/src/gone/mod.rs"
        ]
    );
    // A tree of planted sources holds such a declaration on purpose.
    let fixture = vec![(
        "crates/x/tests/fixtures/a/src/lib.rs".to_owned(),
        "#[cfg(test)]\nmod gone;\n".to_owned(),
    )];
    assert!(declared_test_files(&fixture).1.is_empty());
}
