//! The rules that keep a Mac test run out of the account's own launchd, read from the sources.
//!
//! Two readings, each by tokens, so that a name inside a comment is not a use:
//!
//! 1. No test source runs `launchctl` by naming it. A string that is `launchctl` or ends in
//!    `/launchctl` stands only in the helper that decides whether a command may run
//!    (`kr_ipc::testing::account_launchd`), or in a source on [`NAMED_NOT_RUN`], which says how
//!    many such strings it holds and why none of them starts the program.
//! 2. The control daemon a suite starts is the build that refuses a launchd command the run did not
//!    ask for: the bin `kr-controller-held` is built only with the `testing` feature from a file of
//!    its own, no suite outside the daemon's own picks the plain `kr-controller` by name, and the
//!    update suite maps the daemon of a release to the held build.
//!
//! What the readings cannot see: a program named by a string a macro builds, and a path made at run
//! time. The refusal itself is held by the cases of `kr-ipc`, `kr-controller` and `kr-cli`.

use std::path::{Path, PathBuf};

use kr_conformance::rust_lex::{Tok, Token, lex};

/// The one source that may name `launchctl`: the helper that runs it.
const HELPER: &str = "crates/kr-ipc/src/testing/account_launchd.rs";

/// This file names the program in its own fixtures.
const THIS_FILE: &str = "tests/conformance/tests/account_launchd_gates.rs";

/// The sources that name `launchctl` without running it, by how many strings each holds and what
/// the strings are. A new string in one of them, or a source not listed, is refused.
const NAMED_NOT_RUN: [(&str, usize, &str); 5] = [
    (
        "crates/kr-cli/tests/startup.rs",
        7,
        "the list of tools a recording stand-in answers for, its own table of commands to compare, and the name of the stand-in program a case writes",
    ),
    (
        "crates/kr-ipc/tests/account_launchd.rs",
        3,
        "the programs the decision case is shown for, which it never starts",
    ),
    (
        "crates/kr-cli/tests/doctor.rs",
        1,
        "the list of service tools a recording stand-in answers for",
    ),
    (
        "crates/kr-worker/tests/fence.rs",
        1,
        "the list of tools a recording stand-in answers for",
    ),
    (
        "crates/kr-worker/tests/host.rs",
        1,
        "a match arm that tells a platform question from other commands, which runs nothing",
    ),
];

/// The repository's root.
fn repository() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// The Rust files under `directory`, as paths relative to the repository, leaving out build output.
fn rust_files(directory: &Path, found: &mut Vec<String>) {
    let Ok(entries) = std::fs::read_dir(directory) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        if path.is_dir() {
            if !matches!(name.to_str(), Some("target" | "node_modules" | ".git")) {
                rust_files(&path, found);
            }
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            let relative = path
                .strip_prefix(repository())
                .unwrap_or(&path)
                .to_string_lossy()
                .replace('\\', "/");
            found.push(relative);
        }
    }
}

/// The test sources: what a suite is made of, and no product source.
fn test_sources() -> Vec<String> {
    let mut all = Vec::new();
    for top in ["crates", "tests", "apps"] {
        rust_files(&repository().join(top), &mut all);
    }
    all.retain(|file| {
        let in_tests = file.starts_with("tests/")
            || file
                .split('/')
                .enumerate()
                .any(|(depth, part)| depth > 0 && part == "tests");
        in_tests && !file.starts_with("tests/conformance/src/") && file != THIS_FILE
    });
    all.sort();
    all
}

/// The lines of the strings in `source` that are `launchctl` or end in `/launchctl`.
fn launchctl_strings(source: &str) -> Vec<usize> {
    lex(source)
        .expect("a source that lexes")
        .iter()
        .filter_map(|token| match &token.tok {
            Tok::Str(value, _) if value == "launchctl" || value.ends_with("/launchctl") => {
                Some(token.line)
            }
            _ => None,
        })
        .collect()
}

/// A test source that starts `launchctl` does it through the helper, which decides
/// whether the run may. A string that names the program stands only where it is on the list of what
/// names it without running it.
#[test]
fn no_test_source_runs_the_launchctl_program_outside_the_shared_helper() {
    let mut wrong = Vec::new();
    let mut seen = Vec::new();
    for file in test_sources() {
        if file == HELPER {
            continue;
        }
        let text = std::fs::read_to_string(repository().join(&file))
            .unwrap_or_else(|error| panic!("{file}: {error}"));
        let lines = launchctl_strings(&text);
        let allowed = NAMED_NOT_RUN
            .iter()
            .find(|(listed, ..)| *listed == file)
            .map(|(_, count, _)| *count);
        match allowed {
            Some(count) => {
                seen.push(file.clone());
                if lines.len() != count {
                    wrong.push(format!(
                        "{file} holds {} strings that name launchctl and the list says {count}",
                        lines.len()
                    ));
                }
            }
            None => {
                for line in lines {
                    wrong.push(format!("{file}:{line} names launchctl and is on no list"));
                }
            }
        }
    }
    for (listed, ..) in NAMED_NOT_RUN {
        if !seen.iter().any(|file| file == listed) {
            wrong.push(format!("{listed} is on the list and is no test source"));
        }
    }
    assert!(
        wrong.is_empty(),
        "these test sources run or name launchctl themselves: {wrong:#?}"
    );
}

/// The scan finds a string that is the program in each spelling, and no other.
#[test]
fn the_launchctl_scan_finds_a_program_named_launchctl_in_each_spelling_and_only_those() {
    let found = |source: &str| launchctl_strings(source).len();
    assert_eq!(found(r#"let c = Command::new("/bin/launchctl");"#), 1);
    assert_eq!(found(r#"let c = Command::new("launchctl");"#), 1);
    assert_eq!(found(r#"let c = dir.join("sub/launchctl");"#), 1);
    assert_eq!(found(r#"const N: &str = "/usr/bin/launchctl";"#), 1);
    assert_eq!(found("// Command::new(\"/bin/launchctl\")\nfn f() {}"), 0);
    assert_eq!(found("/* \"launchctl\" */ fn f() {}"), 0);
    assert_eq!(found(r#"let note = "launchctl bootout failed";"#), 0);
    assert_eq!(found(r#"let name = "launchctl-calls";"#), 0);
    assert_eq!(found(r#"let name = "not-launchctl";"#), 0);
    assert_eq!(found("fn launchctl() {}\nlet x = launchctl();"), 0);
}

/// The tokens of a source, without its comments.
fn code_tokens(source: &str) -> Vec<Token> {
    lex(source)
        .expect("a source that lexes")
        .into_iter()
        .filter(|token| !matches!(token.tok, Tok::Comment(..)))
        .collect()
}

/// The lines where a call of one of `pickers` has the string `name` as an argument, as
/// `beside_this_test("kr-controller")` does, and the lines of the string `CARGO_BIN_EXE_<name>`
/// that cargo's `env!` takes. The same string anywhere else (a fixture) is not a pick.
fn picks_of(source: &str, pickers: &[&str], name: &str) -> Vec<usize> {
    let tokens = code_tokens(source);
    let mut lines = Vec::new();
    for (at, token) in tokens.iter().enumerate() {
        let in_env = at >= 3
            && tokens[at - 1].is_punct('(')
            && tokens[at - 2].is_punct('!')
            && matches!(tokens[at - 3].ident(), Some("env" | "option_env"));
        if in_env
            && matches!(&token.tok, Tok::Str(value, _) if *value == format!("CARGO_BIN_EXE_{name}"))
        {
            lines.push(token.line);
        }
        let Some(ident) = token.ident() else { continue };
        let is_call = pickers.contains(&ident)
            && tokens.get(at + 1).is_some_and(|next| next.is_punct('('))
            && at.checked_sub(1).and_then(|before| tokens[before].ident()) != Some("fn");
        if is_call {
            let mut depth = 0_i32;
            for inside in &tokens[at + 1..] {
                match &inside.tok {
                    Tok::Punct('(') => depth += 1,
                    Tok::Punct(')') => {
                        depth -= 1;
                        if depth == 0 {
                            break;
                        }
                    }
                    Tok::Str(value, _) if value == name => lines.push(inside.line),
                    _ => {}
                }
            }
        }
    }
    lines
}

/// The plain daemon's name, spelled so that no source of this file names a program it starts.
fn plain_daemon() -> String {
    ["kr", "controller"].join("-")
}

/// The callers that choose a daemon program by its name. `built_binary` is the Windows task
/// starter's, which holds nothing on that platform, and is not one of them.
const PICKERS: [&str; 4] = ["beside_this_test", "beside", "built_program", "binary"];

/// The sources that the suites of a platform other than the ones the refusal holds on include, by
/// the folder they stand in.
const WINDOWS_ONLY_FOLDERS: [&str; 1] = ["crates/kr-cli/tests/windows_session/"];

/// The daemon a suite starts is the build with the refusal. The held bin exists only
/// with the `testing` feature and has a source file of its own; no suite outside the daemon's own,
/// and none that runs on a platform where the refusal holds, takes the plain `kr-controller` by
/// name; and the update suite takes the held build for the daemon of a release.
#[test]
fn the_daemon_the_suites_start_is_the_one_built_with_the_hold() {
    let manifest = std::fs::read_to_string(repository().join("crates/kr-controller/Cargo.toml"))
        .expect("the daemon's manifest");
    let stanza = manifest
        .split("[[bin]]")
        .find(|stanza| stanza.contains("name = \"kr-controller-held\""))
        .expect("the daemon's manifest declares the held bin");
    assert!(
        stanza.contains("required-features = [\"testing\"]"),
        "the held bin is built only with the testing feature"
    );
    assert!(
        stanza.contains("path = \"src/bin/kr-controller-held.rs\""),
        "the held bin has a source file of its own"
    );

    let mut wrong = Vec::new();
    for file in test_sources() {
        // The daemon's own suites run the plain bin that the package builds for them with the
        // feature on; the end-to-end legs start shipped programs by design; a file for Windows
        // starts a daemon on a platform the refusal does not hold.
        if file.starts_with("crates/kr-controller/tests/")
            || file.starts_with("tests/e2e/")
            || WINDOWS_ONLY_FOLDERS
                .iter()
                .any(|folder| file.starts_with(folder))
        {
            continue;
        }
        let text = std::fs::read_to_string(repository().join(&file))
            .unwrap_or_else(|error| panic!("{file}: {error}"));
        if text.contains("#![cfg(windows)]") {
            continue;
        }
        for line in picks_of(&text, &PICKERS, &plain_daemon()) {
            wrong.push(format!("{file}:{line}"));
        }
    }
    assert!(
        wrong.is_empty(),
        "these suites pick the plain kr-controller, not kr-controller-held: {wrong:#?}"
    );

    let harness =
        std::fs::read_to_string(repository().join("crates/kr-cli/tests/support/update_harness.rs"))
            .expect("the update harness");
    let tokens = code_tokens(&harness);
    let strs: Vec<&str> = tokens
        .iter()
        .filter_map(|token| match &token.tok {
            Tok::Str(value, _) => Some(value.as_str()),
            _ => None,
        })
        .collect();
    let maps = strs
        .windows(2)
        .any(|pair| pair == [plain_daemon().as_str(), "kr-controller-held"]);
    assert!(
        maps,
        "the update harness does not map the daemon of a release to kr-controller-held"
    );
}

/// The scan of the pickers finds a plain pick in each form and not a held one or a comment.
#[test]
fn the_picker_scan_finds_a_plain_daemon_pick_and_only_that() {
    // NAME stands for the daemon's plain name, which a source of this file does not spell out.
    let found = |source: &str| {
        picks_of(
            &source.replace("NAME", &plain_daemon()),
            &PICKERS,
            &plain_daemon(),
        )
        .len()
    };
    assert_eq!(found(r#"let p = beside_this_test("NAME");"#), 1);
    assert_eq!(found(r#"let p = beside("NAME").unwrap();"#), 1);
    assert_eq!(found(r#"let p = env!("CARGO_BIN_EXE_NAME");"#), 1);
    assert_eq!(found(r#"let p = built_binary("NAME");"#), 0);
    assert_eq!(found(r#"let all = ["CARGO_BIN_EXE_NAME"];"#), 0);
    assert_eq!(found(r#"let p = env!("CARGO_BIN_EXE_NAME-held");"#), 0);
    assert_eq!(found(r#"let p = beside_this_test("NAME-held");"#), 0);
    assert_eq!(found(r#"let p = beside_this_test("kr-worker");"#), 0);
    assert_eq!(found("// beside_this_test(\"NAME\")\nfn f() {}"), 0);
    assert_eq!(
        found(r#"fn beside_this_test(name: &str) -> PathBuf { }"#),
        0
    );
}
