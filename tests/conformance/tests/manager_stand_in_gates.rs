//! The rule that a test run's stand-in service manager has no way round it, read from the sources.
//!
//! Product code starts a service manager through three runners only: the command line's
//! (`run_within`), the desktop reader's (`run`) and the control daemon's (`command_within`). Two
//! readings, each by tokens, so that a name inside a comment is not a use:
//!
//! 1. Each runner calls the seam's refusal before it starts a program, and a runner that has a
//!    stand-in to give a command calls the seam's substitution before that.
//! 2. Every source outside a test folder that names `launchctl` as a program stands on a list by
//!    function, and the list says which of those functions are the runners: a new site is refused
//!    until it is listed, and a listed one that names none is refused too.
//!
//! What the readings cannot see: a program named by a string a macro builds, a path made at run
//! time, and a command inside shell text. The behaviour of each runner is shown by its own cases,
//! each in a child of its own with the variable and the marker in the state the case names.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use kr_conformance::rust_lex::{Tok, Token, lex};

/// The runners: the source, the function, and whether the function has a stand-in to give.
const RUNNERS: [(&str, &str, bool); 3] = [
    ("crates/kr-cli/src/service_manager.rs", "run_within", true),
    ("crates/kr-worker/src/desktop/platform.rs", "run", true),
    (
        "crates/kr-controller/src/supervision.rs",
        "command_within",
        false,
    ),
];

/// The sources outside a test folder that name `launchctl` as a program, by the functions that hold
/// the strings, how many each holds, and why none of them starts the program outside a runner.
type Entry = (&'static str, usize, &'static str);

/// The one source that may name the program for every test: the helper that decides whether a run
/// may start it.
const HELPER: &str = "crates/kr-ipc/src/testing/account_launchd.rs";

/// The sources that name `launchctl`, outside the helper.
const NAMED: [(&str, &[Entry]); 4] = [
    (
        "crates/kr-cli/src/service_manager.rs",
        &[(
            "",
            1,
            "the program the command line's runner is given, which only that runner starts, after its substitution and its refusal",
        )],
    ),
    (
        "crates/kr-controller/src/net/device_errors.rs",
        &[(
            "",
            1,
            "a list of words an error text is held not to repeat, which runs nothing",
        )],
    ),
    (
        "crates/kr-controller/src/supervision.rs",
        &[
            (
                "launchctl_within",
                1,
                "the program the daemon's runner is given, which only that runner starts, after its refusal",
            ),
            (
                "start_job",
                2,
                "the program of a worker job's bootstrap and kickstart commands, which go to the daemon's runner",
            ),
        ],
    ),
    (
        "crates/kr-worker/src/desktop/platform.rs",
        &[(
            "read_login",
            1,
            "the program of the graphical login reading, which goes to the desktop reader's runner",
        )],
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

/// The product sources under `crates`: a source in a folder named `src`, and none in a folder named
/// `tests`.
fn product_sources() -> Vec<String> {
    let mut all = Vec::new();
    rust_files(&repository().join("crates"), &mut all);
    all.retain(|file| {
        let parts: Vec<&str> = file.split('/').collect();
        parts.contains(&"src") && !parts.contains(&"tests")
    });
    all.sort();
    all
}

/// The tokens of a source, without its comments.
fn code_tokens(source: &str) -> Vec<Token> {
    lex(source)
        .expect("a source that lexes")
        .into_iter()
        .filter(|token| !matches!(token.tok, Tok::Comment(..)))
        .collect()
}

/// A function of a source: its name, and the tokens of its body between the braces.
struct Function {
    name: String,
    body: std::ops::Range<usize>,
}

/// The index of the `}` that closes the `{` at `open`.
fn closing_brace(tokens: &[Token], open: usize) -> usize {
    let mut depth = 0_i32;
    for (at, token) in tokens.iter().enumerate().skip(open) {
        match token.tok {
            Tok::Punct('{') => depth += 1,
            Tok::Punct('}') => {
                depth -= 1;
                if depth == 0 {
                    return at;
                }
            }
            _ => {}
        }
    }
    tokens.len() - 1
}

/// Every function that has a body, by its own name.
fn functions(tokens: &[Token]) -> Vec<Function> {
    let mut found = Vec::new();
    for (at, token) in tokens.iter().enumerate() {
        if token.ident() != Some("fn") {
            continue;
        }
        let Some(name) = tokens.get(at + 1).and_then(Token::ident) else {
            continue;
        };
        let mut depth = 0_i32;
        let mut open = None;
        for (index, inside) in tokens.iter().enumerate().skip(at + 2) {
            match inside.tok {
                Tok::Punct('(' | '[') => depth += 1,
                Tok::Punct(')' | ']') => depth -= 1,
                Tok::Punct(';') if depth == 0 => break,
                Tok::Punct('{') if depth == 0 => {
                    open = Some(index);
                    break;
                }
                _ => {}
            }
        }
        let Some(open) = open else { continue };
        found.push(Function {
            name: name.to_owned(),
            body: open + 1..closing_brace(tokens, open),
        });
    }
    found
}

/// Whether a string names the program `launchctl`.
fn names_launchctl(value: &str) -> bool {
    value == "launchctl" || value.ends_with("/launchctl")
}

/// The strings of `source` that name the program, counted by the innermost function that holds each,
/// and by the empty name when none does.
fn strings_by_function(source: &str) -> BTreeMap<String, usize> {
    let tokens = code_tokens(source);
    let all = functions(&tokens);
    let mut found = BTreeMap::new();
    for (at, token) in tokens.iter().enumerate() {
        let Tok::Str(value, _) = &token.tok else {
            continue;
        };
        if !names_launchctl(value) {
            continue;
        }
        let owner = all
            .iter()
            .filter(|function| function.body.contains(&at))
            .min_by_key(|function| function.body.len())
            .map_or("", |function| function.name.as_str());
        *found.entry(owner.to_owned()).or_insert(0) += 1;
    }
    found
}

/// What is wrong with the strings of a source against its list: a function that holds more or
/// fewer than its count, one that is on no list, and a listed one that holds none.
fn roster_problems(found: &BTreeMap<String, usize>, roster: &[Entry]) -> Vec<String> {
    let said = |function: &str| {
        if function.is_empty() {
            "a string outside every function".to_owned()
        } else {
            function.to_owned()
        }
    };
    let mut problems = Vec::new();
    for (function, count) in found {
        match roster.iter().find(|entry| entry.0 == function) {
            Some(entry) if entry.1 == *count => {}
            Some(entry) => problems.push(format!(
                "{} holds {count} and the list says {}",
                said(function),
                entry.1
            )),
            None => problems.push(format!(
                "{} holds {count} and is on no list",
                said(function)
            )),
        }
    }
    for entry in roster {
        if !found.contains_key(entry.0) {
            problems.push(format!("{} is on the list and holds none", said(entry.0)));
        }
    }
    problems
}

/// The index in `tokens`, within `body`, of the first call of `name` that goes through the seam
/// module's path, as `manager_stand_in::name(` does.
fn seam_call(tokens: &[Token], body: &std::ops::Range<usize>, name: &str) -> Option<usize> {
    body.clone().find(|&at| {
        tokens[at].ident() == Some("manager_stand_in")
            && tokens.get(at + 1).is_some_and(|token| token.is_punct(':'))
            && tokens.get(at + 2).is_some_and(|token| token.is_punct(':'))
            && tokens.get(at + 3).and_then(Token::ident) == Some(name)
            && tokens.get(at + 4).is_some_and(|token| token.is_punct('('))
    })
}

/// The index in `tokens`, within `body`, of the first start of a program: the call `.spawn(` or
/// `.output(`.
fn first_start(tokens: &[Token], body: &std::ops::Range<usize>) -> Option<usize> {
    body.clone().find(|&at| {
        tokens[at].is_punct('.')
            && matches!(
                tokens.get(at + 1).and_then(Token::ident),
                Some("spawn" | "output" | "status")
            )
    })
}

/// The source of the startup suite that holds a host on the stand-in service manager.
const HOST_FILE: &str = "crates/kr-cli/tests/support/manager_stand_in.rs";

/// The function that builds a command in the host's source: the one that runs the stand-in.
const HOST_COMMAND_FUNCTION: &str = "command";

/// The function of `source` that holds each `Command::new(`, one entry for each, innermost function
/// first, and the empty name for one outside every function.
fn command_builders(source: &str) -> Vec<String> {
    let tokens = code_tokens(source);
    let all = functions(&tokens);
    (0..tokens.len())
        .filter(|&at| {
            tokens[at].ident() == Some("Command")
                && tokens.get(at + 1).is_some_and(|token| token.is_punct(':'))
                && tokens.get(at + 2).is_some_and(|token| token.is_punct(':'))
                && tokens.get(at + 3).and_then(Token::ident) == Some("new")
        })
        .map(|at| {
            all.iter()
                .filter(|function| function.body.contains(&at))
                .min_by_key(|function| function.body.len())
                .map_or_else(String::new, |function| function.name.clone())
        })
        .collect()
}

/// What is wrong with the runner `function` of `source`: the calls it lacks, and the order of
/// those it has. A runner with a stand-in to give substitutes before it refuses, and refuses before
/// it starts a program.
fn runner_problems(source: &str, function: &str, substitutes: bool) -> Vec<String> {
    let tokens = code_tokens(source);
    let all = functions(&tokens);
    let Some(found) = all.iter().find(|candidate| candidate.name == function) else {
        return vec![format!("{function} is not a function of this source")];
    };
    let mut problems = Vec::new();
    let refusal = seam_call(&tokens, &found.body, "refusal_after");
    let substitution = seam_call(&tokens, &found.body, "substituted");
    let start = first_start(&tokens, &found.body);
    let Some(refusal) = refusal else {
        problems.push(format!(
            "{function} never calls the refusal after its substitution"
        ));
        return problems;
    };
    match (start, refusal) {
        (None, _) => problems.push(format!(
            "{function} starts no program, so this reading is moot"
        )),
        (Some(start), refusal) if refusal > start => {
            problems.push(format!(
                "{function} starts a program before it calls the refusal"
            ));
        }
        _ => {}
    }
    match (substitutes, substitution) {
        (true, None) => problems.push(format!("{function} never substitutes the stand-in")),
        (true, Some(substitution)) if substitution > refusal => {
            problems.push(format!(
                "{function} calls the refusal before it substitutes"
            ));
        }
        (false, Some(_)) => problems.push(format!(
            "{function} substitutes, and the list says it has no stand-in to give"
        )),
        _ => {}
    }
    problems
}

/// Each runner of a service manager calls the refusal of the seam before it starts a program, and
/// a runner that has a stand-in to give calls the substitution first.
#[test]
fn each_runner_refuses_after_its_substitution_and_before_it_starts_a_program() {
    let mut wrong = Vec::new();
    for (file, function, substitutes) in RUNNERS {
        let text = std::fs::read_to_string(repository().join(file))
            .unwrap_or_else(|error| panic!("{file}: {error}"));
        wrong.extend(
            runner_problems(&text, function, substitutes)
                .into_iter()
                .map(|problem| format!("{file}: {problem}")),
        );
    }
    assert!(wrong.is_empty(), "these runners are not held: {wrong:#?}");
}

/// Every source outside a test folder that names `launchctl` as a program stands on the list, by
/// function and count; each runner's function is on it.
#[test]
fn every_product_source_that_names_launchctl_stands_on_the_list() {
    let mut wrong = Vec::new();
    let mut seen = Vec::new();
    for file in product_sources() {
        if file == HELPER {
            continue;
        }
        let text = std::fs::read_to_string(repository().join(&file))
            .unwrap_or_else(|error| panic!("{file}: {error}"));
        let roster: &[Entry] =
            NAMED
                .iter()
                .find(|(listed, _)| *listed == file)
                .map_or(&[], |(_, entries)| {
                    seen.push(file.clone());
                    entries
                });
        wrong.extend(
            roster_problems(&strings_by_function(&text), roster)
                .into_iter()
                .map(|problem| format!("{file}: {problem}")),
        );
    }
    for (listed, _) in NAMED {
        if !seen.iter().any(|file| file == listed) {
            wrong.push(format!("{listed} is on the list and is no product source"));
        }
    }
    assert!(
        wrong.is_empty(),
        "these product sources name launchctl and are not on the list: {wrong:#?}"
    );
}

/// The reading finds a runner that lacks a call, or has them in the wrong order, and only that.
#[test]
fn the_runner_reading_finds_a_missing_call_and_a_wrong_order_and_only_those() {
    let held = "fn run() { let p = manager_stand_in::substituted(a); \
                if manager_stand_in::refusal_after(&p).is_some() { return; } c.spawn(); }";
    assert!(runner_problems(held, "run", true).is_empty());
    let no_substitution = "fn run() { if manager_stand_in::refusal_after(&p).is_some() { return; } \
                           c.spawn(); }";
    assert_eq!(runner_problems(no_substitution, "run", true).len(), 1);
    let no_refusal = "fn run() { let p = manager_stand_in::substituted(a); c.spawn(); }";
    assert_eq!(runner_problems(no_refusal, "run", true).len(), 1);
    let refusal_late = "fn run() { let p = manager_stand_in::substituted(a); c.spawn(); \
                        manager_stand_in::refusal_after(&p); }";
    assert_eq!(runner_problems(refusal_late, "run", true).len(), 1);
    let substitution_late = "fn run() { manager_stand_in::refusal_after(&p); \
                             let p = manager_stand_in::substituted(a); c.spawn(); }";
    assert_eq!(runner_problems(substitution_late, "run", true).len(), 1);
    let comment_only = "fn run() { // manager_stand_in::refusal_after(&p)\n c.spawn(); }";
    assert_eq!(runner_problems(comment_only, "run", false).len(), 1);
    let no_stand_in = "fn run() { if manager_stand_in::refusal_after(&p).is_some() { return; } \
                       c.spawn(); }";
    assert!(runner_problems(no_stand_in, "run", false).is_empty());
    assert_eq!(runner_problems(held, "run", false).len(), 1);
    assert_eq!(runner_problems(held, "other", true).len(), 1);
}

/// The startup suite's host on the stand-in builds a command in one function only, the one that
/// runs the stand-in with the tree's own environment, so that no other command of the host can
/// reach a service manager.
#[test]
fn the_stand_in_host_builds_a_command_in_one_function_only() {
    let text = std::fs::read_to_string(repository().join(HOST_FILE))
        .unwrap_or_else(|error| panic!("{HOST_FILE}: {error}"));
    assert_eq!(
        command_builders(&text),
        [HOST_COMMAND_FUNCTION],
        "{HOST_FILE} builds a command in the one function {HOST_COMMAND_FUNCTION} and nowhere else"
    );
}

/// The reading finds a second command, in another function or outside any, and no comment.
#[test]
fn the_command_reading_finds_each_command_and_no_comment() {
    assert_eq!(
        command_builders(
            "fn command() { Command::new(a); } fn other() { std::process::Command::new(b); }"
        ),
        ["command", "other"]
    );
    assert_eq!(command_builders("static X: C = Command::new(a);"), [""]);
    assert!(command_builders("fn command() { // Command::new(a)\n run(); }").is_empty());
}

/// The source of the startup suite, which holds the host on the service manager and the steps of the
/// case that runs on it.
const STARTUP_FILE: &str = "crates/kr-cli/tests/startup.rs";

/// The case that runs on the stand-in and the steps it calls, none of which may start a program or
/// name the account's launchd.
const CASE_FUNCTIONS: [&str; 4] = [
    "the_headless_host_case",
    "the_stand_in_saw_the_install",
    "the_stand_in_started_the_daemon",
    "the_stand_in_saw_nothing_end",
];

/// The index range of the tokens between the braces of `impl <name> {`.
fn impl_block(tokens: &[Token], name: &str) -> Option<std::ops::Range<usize>> {
    (0..tokens.len()).find_map(|at| {
        let opens = tokens[at].ident() == Some("impl")
            && tokens.get(at + 1).and_then(Token::ident) == Some(name)
            && tokens.get(at + 2).is_some_and(|token| token.is_punct('{'));
        opens.then(|| at + 3..closing_brace(tokens, at + 2))
    })
}

/// The index of each `account_launchd::<item>` in `range`, followed by `(` where `call` is set. With
/// no item it is each `account_launchd::`.
fn account_launchd_paths(
    tokens: &[Token],
    range: &std::ops::Range<usize>,
    item: Option<&str>,
    call: bool,
) -> Vec<usize> {
    range
        .clone()
        .filter(|&at| {
            tokens[at].ident() == Some("account_launchd")
                && tokens.get(at + 1).is_some_and(|token| token.is_punct(':'))
                && tokens.get(at + 2).is_some_and(|token| token.is_punct(':'))
                && item.is_none_or(|item| tokens.get(at + 3).and_then(Token::ident) == Some(item))
                && (!call || tokens.get(at + 4).is_some_and(|token| token.is_punct('(')))
        })
        .collect()
}

/// What is wrong with the startup suite's source: the account's launchd is reached by one function
/// of `impl ServiceHost` for its command and one for its program path, and the case and its steps
/// start no program and name nothing of it.
fn startup_problems(source: &str) -> Vec<String> {
    let tokens = code_tokens(source);
    let all = functions(&tokens);
    let mut problems = Vec::new();
    let Some(host) = impl_block(&tokens, "ServiceHost") else {
        return vec!["there is no `impl ServiceHost` in this source".to_owned()];
    };
    for (item, call, only) in [
        ("command", true, "launchctl"),
        ("LAUNCHCTL", false, "create"),
    ] {
        let uses = account_launchd_paths(&tokens, &host, Some(item), call);
        if uses.is_empty() {
            problems.push(format!(
                "`impl ServiceHost` never uses account_launchd::{item}, so this reading is moot"
            ));
        }
        for at in uses {
            let holder = all
                .iter()
                .filter(|function| function.body.contains(&at))
                .min_by_key(|function| function.body.len())
                .map_or("", |function| function.name.as_str());
            if holder != only {
                problems.push(format!(
                    "{holder:?} uses account_launchd::{item}, and only {only} may"
                ));
            }
        }
    }
    let builders = command_builders(source);
    for name in CASE_FUNCTIONS {
        let Some(found) = all.iter().find(|function| function.name == name) else {
            problems.push(format!("{name} is not a function of this source"));
            continue;
        };
        if builders.iter().any(|builder| builder == name) {
            problems.push(format!("{name} builds a command"));
        }
        if !account_launchd_paths(&tokens, &found.body, None, false).is_empty() {
            problems.push(format!("{name} names the account's launchd"));
        }
    }
    problems
}

/// The startup suite reaches the account's own launchd in one place for its command and one for its
/// program path, and the headless-host case and its steps on the stand-in neither start a program
/// nor name the account's launchd, so that no step can bypass the host's one `launchctl`.
#[test]
fn the_startup_suite_reaches_the_accounts_launchd_only_where_the_host_chooses_it() {
    let text = std::fs::read_to_string(repository().join(STARTUP_FILE))
        .unwrap_or_else(|error| panic!("{STARTUP_FILE}: {error}"));
    let problems = startup_problems(&text);
    assert!(
        problems.is_empty(),
        "{STARTUP_FILE} reaches the account's launchd where it must not: {problems:#?}"
    );
}

/// The startup reading finds a use in the wrong function, a use that is missing, a command built in
/// the case or one of its steps, and a mention of the account's launchd there, and nothing else.
#[test]
fn the_startup_reading_finds_each_wrong_place_and_only_those() {
    let steps = "fn the_headless_host_case() {} fn the_stand_in_saw_the_install() {} \
                 fn the_stand_in_started_the_daemon() {} fn the_stand_in_saw_nothing_end() {}";
    let host = "impl ServiceHost { fn create() { account_launchd::LAUNCHCTL; } \
                fn launchctl() { account_launchd::command(a); } }";
    assert!(startup_problems(&format!("{host} {steps}")).is_empty());
    let wrong_command = "impl ServiceHost { fn create() { account_launchd::LAUNCHCTL; } \
                         fn kr_from() { account_launchd::command(a); } \
                         fn launchctl() { account_launchd::command(a); } }";
    assert_eq!(
        startup_problems(&format!("{wrong_command} {steps}")).len(),
        1
    );
    let wrong_program = "impl ServiceHost { fn create() { account_launchd::LAUNCHCTL; } \
                         fn launchctl() { account_launchd::command(a); account_launchd::LAUNCHCTL; } }";
    assert_eq!(
        startup_problems(&format!("{wrong_program} {steps}")).len(),
        1
    );
    let moot = "impl ServiceHost { fn create() {} fn launchctl() {} }";
    assert_eq!(startup_problems(&format!("{moot} {steps}")).len(), 2);
    let builds = "fn the_headless_host_case() { Command::new(a); } fn the_stand_in_saw_the_install() {} \
                  fn the_stand_in_started_the_daemon() {} fn the_stand_in_saw_nothing_end() {}";
    assert_eq!(startup_problems(&format!("{host} {builds}")).len(), 1);
    let names = "fn the_headless_host_case() {} fn the_stand_in_saw_the_install() {} \
                 fn the_stand_in_started_the_daemon() { x(kr_ipc::testing::account_launchd::VARIABLE); } \
                 fn the_stand_in_saw_nothing_end() {}";
    assert_eq!(startup_problems(&format!("{host} {names}")).len(), 1);
    let comment = "impl ServiceHost { fn create() { account_launchd::LAUNCHCTL; } \
                   fn launchctl() { account_launchd::command(a); } \
                   fn other() { // account_launchd::command(b)\n } }";
    assert!(startup_problems(&format!("{comment} {steps}")).is_empty());
    assert_eq!(startup_problems("fn other() {}").len(), 1);
}
