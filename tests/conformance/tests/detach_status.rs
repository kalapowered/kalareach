//! A test of this repository takes a disk image off through the shared helper, and no test runs
//! `hdiutil detach` itself.
//!
//! A forced detach unmounts the volume and then can fail to eject the disk when something else
//! holds the disk's device open, which leaves the image attached with nothing mounted from it. A
//! detach by the mount point that is asked again finds nothing mounted, so the one detach that
//! reads this right is `kr_ipc::testing::volumes::detach_attached`, which asks by the disk until
//! the system lets it go and returns why it did not. A case that detaches by its own command line
//! reads the status wrong (it ignores it, or it only prints it) and passes with the image still
//! attached. Nothing but a reading of the sources sees it, so this one reads them.
//!
//! In every Rust file the repository tracks under a `tests` folder that names `hdiutil` in a
//! literal, a literal that is `detach`, or that holds `hdiutil` and `detach` in one piece, is the
//! command run. The sources are read as Rust is: a comment, a raw string and a character are
//! passed over, and a literal that wraps over lines is joined as the compiler joins it.
//!
//! The limits: a command line made in a variable or a helper, and a file that does not name
//! `hdiutil` in a literal, are not seen.

use std::path::{Path, PathBuf};
use std::process::Command;

use kr_conformance::rust_lex::{Tok, lex};

/// The tool and the verb of the command, each put together here so that this file's own literals
/// are neither the tool's name nor the verb, and the reading below passes this file.
const TOOL: &str = concat!("hdiu", "til");
const VERB: &str = concat!("de", "tach");

/// Whether `text` holds the tool's name and the verb as two words in a row, as a shell line does.
fn runs_it_in_words(text: &str) -> bool {
    let words: Vec<&str> = text.split_whitespace().collect();
    words.windows(2).any(|pair| pair == [TOOL, VERB])
}

/// A file under a `tests` folder that runs `hdiutil detach` on purpose, with the number of
/// literals that do and the reason.
struct Allowed {
    /// The file, from the repository's root.
    path: &'static str,
    /// How many literals of the file name the command.
    literals: usize,
    /// Why the file runs it.
    reason: &'static str,
}

/// The files that are on the list.
const ALLOWED: &[Allowed] = &[Allowed {
    path: "crates/kr-transfer/tests/authority.rs",
    literals: 2,
    reason: "a case there replaces the tool with a stand-in; the function that releases an image a refused creation left attached runs the tool it is given by its own command line, and returns the failure as an error that the case reports by name, and the case checks the stand-in's recorded calls for the verb",
}];

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

/// The lines of `source`, the file at `path`, that hold a literal which runs `hdiutil detach`,
/// with the literal. None for a file that is not under a `tests` folder.
///
/// # Errors
///
/// Returns where the source cannot be read as Rust.
fn detach_runs(path: &str, source: &str) -> Result<Vec<(usize, String)>, String> {
    if !path.split('/').any(|part| part == "tests") {
        return Ok(Vec::new());
    }
    let tokens = lex(source).map_err(|error| format!("{path}:{}: {}", error.line, error.what))?;
    let literals: Vec<(usize, &str)> = tokens
        .iter()
        .filter_map(|token| match &token.tok {
            Tok::Str(value, _) => Some((token.line, value.as_str())),
            _ => None,
        })
        .collect();
    if !literals.iter().any(|(_, value)| value.contains(TOOL)) {
        return Ok(Vec::new());
    }
    Ok(literals
        .into_iter()
        .filter(|(_, value)| *value == VERB || runs_it_in_words(value))
        .map(|(line, value)| (line, value.to_owned()))
        .collect())
}

/// No test file runs `hdiutil detach` itself, but the ones on the list.
#[test]
fn no_file_in_a_tests_folder_runs_hdiutil_detach_itself() {
    let root = repository();
    let files = tracked_sources(&root);
    assert!(
        files.len() > 1000,
        "the reading reaches the repository's sources: {} files",
        files.len()
    );
    let mut unread = Vec::new();
    let mut found = Vec::new();
    let mut seen = vec![false; ALLOWED.len()];
    let mut naming = 0_usize;
    for path in &files {
        let Ok(source) = std::fs::read_to_string(root.join(path)) else {
            continue;
        };
        let runs = match detach_runs(path, &source) {
            Ok(runs) => runs,
            Err(error) => {
                unread.push(error);
                continue;
            }
        };
        if source.contains(TOOL) && path.split('/').any(|part| part == "tests") {
            naming += 1;
        }
        if runs.is_empty() {
            continue;
        }
        if let Some(entry) = ALLOWED.iter().position(|entry| entry.path == path) {
            seen[entry] = true;
            if runs.len() == ALLOWED[entry].literals {
                continue;
            }
        }
        for (line, literal) in runs {
            found.push(format!(
                "{path}:{line}: runs it: \"{}\"",
                literal.escape_debug()
            ));
        }
    }
    assert!(
        unread.is_empty(),
        "sources the reading cannot read:\n{}",
        unread.join("\n")
    );
    assert!(
        naming >= 3,
        "the reading reaches the test files that handle a disk image: {naming}"
    );
    let stale: Vec<String> = ALLOWED
        .iter()
        .zip(&seen)
        .filter(|(_, seen)| !**seen)
        .map(|(entry, _)| format!("{}: {}", entry.path, entry.reason))
        .collect();
    assert!(
        stale.is_empty(),
        "a file on the list no longer runs the command:\n{}",
        stale.join("\n")
    );
    assert!(
        found.is_empty(),
        "a test runs `{TOOL} {VERB}` itself; it takes its image off with \
         `kr_ipc::testing::volumes::detach_attached`, which asks again by the disk until the \
         system lets it go and returns why it did not:\n{}",
        found.join("\n")
    );
}

/// What `detach_runs` finds in `source` as the file at `path`, by line.
fn lines(path: &str, source: &str) -> Vec<usize> {
    detach_runs(path, source)
        .expect("the planted source is read")
        .into_iter()
        .map(|(line, _)| line)
        .collect()
}

/// The control: the reading names a command that detaches an image in each form a case writes it,
/// and passes a file that does not name the tool, a tool's other verbs and a file outside a
/// `tests` folder.
#[test]
fn the_reading_names_each_form_of_the_detach_command_and_passes_what_is_not_it() {
    let (tool, verb) = (TOOL, VERB);
    let target = "crates/x/tests/a.rs";

    let by_argument = format!(
        "fn f() {{\n    Command::new(\"/usr/bin/{tool}\")\n        .arg(\"{verb}\")\n        .arg(&at);\n}}"
    );
    assert_eq!(lines(target, &by_argument), [3]);
    let by_arguments =
        format!("fn f() {{ Command::new(\"/usr/bin/{tool}\").args([\"{verb}\", \"-force\"]); }}");
    assert_eq!(lines(target, &by_arguments), [1]);
    let by_shell = format!("fn f() {{ sh(\"{tool} {verb} -force /dev/disk4\"); }}");
    assert_eq!(lines(target, &by_shell), [1]);

    // A message that holds both words and runs nothing.
    let said =
        format!("fn f() {{ let said = \"the image did not {verb} ({tool} ended with 1)\"; }}");
    assert!(lines(target, &said).is_empty());

    // The tool's other verbs.
    let other = format!(
        "fn f() {{ Command::new(\"/usr/bin/{tool}\").args([\"create\", \"-size\", \"2m\"]); }}"
    );
    assert!(lines(target, &other).is_empty());
    // A verb of that name where the tool is not named: the command line's own `{verb}`.
    let elsewhere = format!("fn f() {{ kr().args([\"{verb}\", &session]); }}");
    assert!(lines(target, &elsewhere).is_empty());
    // A file outside a `tests` folder, the shared helper among them.
    assert!(lines("crates/kr-ipc/src/testing/volumes.rs", &by_arguments).is_empty());
    // A comment holds the words and runs nothing.
    let comment = format!("// {tool} {verb}\nfn f() {{ let said = \"{tool} create\"; }}");
    assert!(lines(target, &comment).is_empty());
}
