//! The rules that keep a Mac test run out of the account's own launchd, read from the sources.
//!
//! Two readings, each by tokens, so that a name inside a comment is not a use:
//!
//! 1. No test source runs `launchctl` by naming it. A string that is `launchctl` or ends in
//!    `/launchctl` stands only in the helper that decides whether a command may run
//!    (`kr_ipc::testing::account_launchd`), or in a function on [`NAMED_NOT_RUN`], which says how
//!    many such strings that function holds and why none of them starts the program.
//! 2. The control daemon a suite starts is the build that refuses a launchd command the run did not
//!    ask for: the bin `kr-controller-held` is built only with the `testing` feature from a file of
//!    its own, no test source names the plain `kr-controller` by a string outside a function on
//!    [`PLAIN_DAEMON_NAMES`], and the update suite's selection of a release's daemon is the
//!    held build.
//!
//! What the readings cannot see: a program named by a string a macro builds, a path made at run
//! time, and a command inside shell text (`/bin/sh -c "launchctl bootstrap .."` names the program
//! in a string that is neither `launchctl` nor ends in `/launchctl`, and the shell it starts is not
//! held). The daemon's own suites (`crates/kr-controller/tests`) run the daemon cargo builds for
//! them, `CARGO_BIN_EXE_kr-controller`, which is the build with the `testing` feature only while
//! cargo builds the test program: a plain `cargo build -p kr-controller` followed by a run of a test
//! program by its path runs the plain daemon. `kr-plugin-host`, `tests/perf` and `tests/faults` link
//! the controller without the feature when they are built alone, and are safe only because the
//! daemon they start supervises through the detached process. The refusal itself is held by the
//! cases of `kr-ipc`, `kr-controller` and `kr-cli`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use kr_conformance::rust_lex::{Tok, Token, lex};

/// The one source that may name `launchctl`: the helper that runs it.
const HELPER: &str = "crates/kr-ipc/src/testing/account_launchd.rs";

/// This file names the program in its own fixtures.
const THIS_FILE: &str = "tests/conformance/tests/account_launchd_gates.rs";

/// What a roster says of one function of a source: its name (`Type::name` inside an `impl`, the
/// empty name for a string outside every function), how many strings it holds, and why none of them
/// starts the program.
type Entry = (&'static str, usize, &'static str);

/// The sources that name `launchctl` without running it, by the functions that hold the strings.
/// A new string, in a function that is not listed or beyond its count, is refused, so a string in
/// one place cannot make room for a launch in another.
const NAMED_NOT_RUN: [(&str, &[Entry]); 5] = [
    (
        "crates/kr-cli/tests/startup.rs",
        &[
            ("", 1, "the list of tools a recording stand-in answers for"),
            (
                "allowed",
                1,
                "the table of calls the standalone start may make, which it compares and never runs",
            ),
            (
                "the_allow_list_refuses_every_mutating_or_privileged_call",
                4,
                "calls the table is shown to refuse, which it never starts",
            ),
            (
                "a_run_that_did_not_ask_for_the_accounts_launchd_gets_no_host_and_runs_no_launchctl",
                1,
                "the name of the stand-in program the case writes, to show that nothing runs it",
            ),
        ],
    ),
    (
        "crates/kr-ipc/tests/account_launchd.rs",
        &[(
            "a_launchctl_command_that_changes_the_service_manager_is_refused_unless_the_run_asked_exactly_one",
            3,
            "the programs the decision case is shown for, which it never starts",
        )],
    ),
    (
        "crates/kr-cli/tests/doctor.rs",
        &[(
            "creating_with_no_host_says_what_to_set_up_and_installs_nothing",
            1,
            "the list of service tools a recording stand-in answers for",
        )],
    ),
    (
        "crates/kr-worker/tests/fence.rs",
        &[(
            "",
            1,
            "the name a stand-in for the login manager is planted under, which it records and never runs",
        )],
    ),
    (
        "crates/kr-worker/tests/host.rs",
        &[(
            "is_a_platform_question",
            1,
            "a match arm that tells a platform question from other commands, which runs nothing",
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

/// Whether a string names the program `launchctl`.
fn names_launchctl(value: &str) -> bool {
    value == "launchctl" || value.ends_with("/launchctl")
}

/// The strings of `source` that `holds` accepts, counted by the function that holds each: the
/// innermost function whose body has it, named `Type::name` inside an `impl`, and the empty name
/// for a string outside every function.
fn strings_by_function(source: &str, holds: impl Fn(&str) -> bool) -> BTreeMap<String, usize> {
    let tokens = code_tokens(source);
    let all = functions(&tokens);
    let mut found = BTreeMap::new();
    for (at, token) in tokens.iter().enumerate() {
        let Tok::Str(value, _) = &token.tok else {
            continue;
        };
        if !holds(value) {
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

/// What is wrong with the strings of a source, counted by function, against its roster: a function
/// that holds more or fewer than its count, one that is on no list, and a listed one that holds
/// none.
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

/// A test source that starts `launchctl` does it through the helper, which decides whether the run
/// may. A string that names the program stands only in a function that is on the list of what names
/// it without running it, as many times as the list says.
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
        let roster: &[Entry] = NAMED_NOT_RUN
            .iter()
            .find(|(listed, _)| *listed == file)
            .map_or(&[], |(_, entries)| {
                seen.push(file.clone());
                entries
            });
        wrong.extend(
            roster_problems(&strings_by_function(&text, names_launchctl), roster)
                .into_iter()
                .map(|problem| format!("{file}: {problem}")),
        );
    }
    for (listed, _) in NAMED_NOT_RUN {
        if !seen.iter().any(|file| file == listed) {
            wrong.push(format!("{listed} is on the list and is no test source"));
        }
    }
    assert!(
        wrong.is_empty(),
        "these test sources run or name launchctl themselves: {wrong:#?}"
    );
}

/// A roster holds a string to its function and not to its file: the same count in another function
/// is refused, as is one more string in a listed function, and a method and a string outside every
/// function are named as the roster names them.
#[test]
fn a_roster_holds_a_string_to_its_function_and_not_to_its_file() {
    let roster: &[Entry] = &[("a", 1, "a fixture")];
    let problems =
        |source: &str| roster_problems(&strings_by_function(source, names_launchctl), roster);
    assert!(problems(r#"fn a() { let n = "launchctl"; } fn b() {}"#).is_empty());
    // The same count of strings in another function: the listed one holds none, the other is unlisted.
    assert_eq!(
        problems(r#"fn a() {} fn b() { let c = Command::new("/bin/launchctl"); }"#).len(),
        2
    );
    // One more string in the listed function.
    assert_eq!(
        problems(r#"fn a() { let n = "launchctl"; let c = Command::new("/bin/launchctl"); }"#)
            .len(),
        1
    );
    // A string in a comment is none.
    assert!(
        problems("fn a() { let n = \"launchctl\"; }\n// \"/bin/launchctl\"\nfn b() {}").is_empty()
    );
    let found = strings_by_function(
        r#"const T: &str = "launchctl"; impl X { fn run(&self) { f("/x/launchctl"); } }"#,
        names_launchctl,
    );
    assert_eq!(found.get(""), Some(&1));
    assert_eq!(found.get("X::run"), Some(&1));
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

/// Whether a string is the plain daemon's name: `kr-controller`, a path that ends in it, or the name
/// of the variable cargo sets for the program.
fn names_plain_daemon(value: &str) -> bool {
    let plain = plain_daemon();
    value == plain
        || value.ends_with(&format!("/{plain}"))
        || value == format!("CARGO_BIN_EXE_{plain}")
}

/// The test sources that hold the plain daemon's name as a string, by the functions that hold it and
/// why none of them starts the plain daemon: the held build is placed under the installed name, and
/// a fixture or a message holds the name without running anything. A string in any other function,
/// or beyond a listed count, is refused.
const PLAIN_DAEMON_NAMES: [(&str, &[Entry]); 15] = [
    (
        "crates/kr-cli/tests/bridged_session.rs",
        &[
            (
                "Container::serve",
                1,
                "the path the held daemon is mounted at in a container, under the installed name",
            ),
            (
                "World::start_with",
                1,
                "the held daemon, or the script that hands over to it, placed under the installed name; nothing starts the plain build",
            ),
            (
                "installation",
                1,
                "the held daemon, or the script that hands over to it, placed under the installed name; nothing starts the plain build",
            ),
            (
                "programs_for_a_container",
                1,
                "the held daemon, or the script that hands over to it, placed under the installed name; nothing starts the plain build",
            ),
        ],
    ),
    (
        "crates/kr-cli/tests/pair.rs",
        &[(
            "Host::start",
            1,
            "the held daemon, or the script that hands over to it, placed under the installed name; nothing starts the plain build",
        )],
    ),
    (
        "crates/kr-cli/tests/session_commands.rs",
        &[(
            "Host::start",
            1,
            "the held daemon, or the script that hands over to it, placed under the installed name; nothing starts the plain build",
        )],
    ),
    (
        "crates/kr-cli/tests/startup.rs",
        &[
            (
                "Standalone::start_a_daemon_by_hand",
                1,
                "the held daemon, or the script that hands over to it, placed under the installed name; nothing starts the plain build",
            ),
            (
                "a_daemon_started_inside_a_service_asks_for_one_scope_and_is_the_process_kr_started",
                1,
                "the held daemon, or the script that hands over to it, placed under the installed name; nothing starts the plain build",
            ),
            (
                "a_daemon_that_cannot_leave_the_service_it_started_in_is_named_by_the_doctor",
                1,
                "the held daemon, or the script that hands over to it, placed under the installed name; nothing starts the plain build",
            ),
            (
                "a_process_named_kr_controller",
                1,
                "a copy of a program that holds still, named as a daemon so that a lock file can name it; it is not the daemon",
            ),
            (
                "installation",
                1,
                "the held daemon, or the script that hands over to it, placed under the installed name; nothing starts the plain build",
            ),
            (
                "kr_host_stop_says_when_no_daemon_runs_and_names_a_holder_that_does_not_answer",
                1,
                "a path or a name in a fixture, compared and never run",
            ),
            (
                "service_installation",
                2,
                "the held daemon, or the script that hands over to it, placed under the installed name; nothing starts the plain build",
            ),
            (
                "the_allow_list_refuses_every_mutating_or_privileged_call",
                7,
                "a path or a name in a fixture, compared and never run",
            ),
        ],
    ),
    (
        "crates/kr-cli/tests/support/update_harness.rs",
        &[
            (
                "",
                1,
                "the names of the programs a release is assembled from; the daemon's file is the held build",
            ),
            (
                "Assembled::whose_daemon_cannot_start",
                1,
                "takes the bytes of the release's daemon as the harness selects them, which are the held build's, or a stand-in of the case's own",
            ),
            (
                "Assembled::whose_daemon_cannot_start_in",
                2,
                "takes the bytes of the release's daemon as the harness selects them, which are the held build's, or a stand-in of the case's own",
            ),
            (
                "Assembled::whose_daemon_cannot_start_while",
                2,
                "takes the bytes of the release's daemon as the harness selects them, which are the held build's, or a stand-in of the case's own",
            ),
            (
                "Assembled::whose_daemon_states",
                2,
                "takes the bytes of the release's daemon as the harness selects them, which are the held build's, or a stand-in of the case's own",
            ),
            (
                "built_as",
                1,
                "the map from the installed name to the held build",
            ),
            (
                "crate_of",
                1,
                "the crate whose sources a program is built from, by the program's name",
            ),
        ],
    ),
    (
        "crates/kr-cli/tests/update.rs",
        &[
            (
                "a_daemon_the_task_cannot_start_after_the_switch_keeps_the_update_for_the_next_run",
                1,
                "bytes of a file that is not a program",
            ),
            (
                "a_program_not_built_from_this_tree_is_refused",
                10,
                "a name given to the function that tells a program built from another tree, on a file the case writes; nothing starts it",
            ),
            (
                "stating_with_keys_in_files",
                2,
                "takes the bytes of the release's daemon as the harness selects them, which are the held build's, or a stand-in of the case's own",
            ),
        ],
    ),
    (
        "crates/kr-cli/tests/upgrade.rs",
        &[
            (
                "",
                1,
                "the programs of the release before, which `Previous::built` builds plain behind its guard",
            ),
            (
                "build_previous",
                1,
                "the package of the release before, built plain behind `Previous::built`'s guard",
            ),
        ],
    ),
    (
        "crates/kr-ipc/tests/account_launchd.rs",
        &[(
            "a_create_is_the_first_word_that_is_no_option_and_is_new_or_its_alias_or_workflow",
            1,
            "a program name the decision case is shown for, which it never starts",
        )],
    ),
    (
        "crates/kr-ipc/tests/started_environment_rule.rs",
        &[(
            "the_reading_finds_a_start_that_gives_no_environment_however_it_is_written",
            1,
            "a source the reading is shown, which no case runs",
        )],
    ),
    (
        "crates/kr-shell-integration/tests/qualification.rs",
        &[(
            "what_this_qualification_cannot_reach_is_recorded_with_its_reason_and_its_owner",
            1,
            "a name in the text of a recorded reason",
        )],
    ),
    (
        "crates/kr-worker/tests/controller_kill.rs",
        &[(
            "a_daemon_killed_during_output_leaves_local_work_running_and_a_reconnect_finds_it",
            1,
            "the Windows task starter's program (`supervision::windows::testing::built_binary`), on a platform the hold does not cover",
        )],
    ),
    (
        "crates/kr-worker/tests/desktop.rs",
        &[
            (
                "Host::create",
                1,
                "the Windows task starter's program (`supervision::windows::testing::built_binary`), on a platform the hold does not cover",
            ),
            (
                "per_user_startup_names_the_platform_service_mechanism_and_reports_what_a_logout_does_to_it",
                1,
                "the supervisor the platform chooses for a program of that name, which starts nothing",
            ),
        ],
    ),
    (
        "crates/kr-worker/tests/host.rs",
        &[(
            "Host::create",
            1,
            "the Windows task starter's program (`supervision::windows::testing::built_binary`), on a platform the hold does not cover",
        )],
    ),
    (
        "crates/kr-worker/tests/performance.rs",
        &[(
            "host",
            1,
            "the Windows task starter's program (`supervision::windows::testing::built_binary`), on a platform the hold does not cover",
        )],
    ),
    (
        "crates/kr-worker/tests/trusted_core.rs",
        &[(
            "neither_process_serving_a_shell_links_a_wasm_engine_or_a_model_runtime",
            1,
            "the names of the processes whose dependencies the case reads, which it never starts",
        )],
    ),
];

/// Whether the sources that decide which daemon a suite starts are the files the rule reads: the
/// daemon's own suites run the plain bin that the package builds for them with the feature on; the
/// end-to-end legs start shipped programs by design; a file for Windows starts a daemon on a
/// platform the refusal does not hold.
fn is_read_for_the_daemon(file: &str, text: &str) -> bool {
    !(file.starts_with("crates/kr-controller/tests/")
        || file.starts_with("tests/e2e/")
        || WINDOWS_ONLY_FOLDERS
            .iter()
            .any(|folder| file.starts_with(folder))
        || text.contains("#![cfg(windows)]"))
}

/// Whether the function `selecting` of the update harness takes the name a program is looked for by
/// from `mapping`: it holds `let name = mapping(name);` and, after it, a string that is built from
/// that `name`, which is the file's name. A call whose result is dropped, or a `name` that stays the
/// argument, is no selection.
fn selects_through(tokens: &[Token], selecting: &Function, mapping: &str) -> bool {
    let body = &tokens[selecting.body.clone()];
    let Some(at) = body.windows(8).position(|window| {
        window[0].ident() == Some("let")
            && window[1].ident() == Some("name")
            && window[2].is_punct('=')
            && window[3].ident() == Some(mapping)
            && window[4].is_punct('(')
            && window[5].ident() == Some("name")
            && window[6].is_punct(')')
            && window[7].is_punct(';')
    }) else {
        return false;
    };
    body[at + 8..]
        .iter()
        .any(|token| matches!(&token.tok, Tok::Str(value, _) if value.contains("{name}")))
}

/// Whether the harness source maps the plain name to the held build in `mapping`, and selects every
/// program through `mapping` in `selecting`.
fn harness_selects_the_held_daemon(source: &str, mapping: &str, selecting: &str) -> bool {
    let tokens = code_tokens(source);
    let found = functions(&tokens);
    let Some(map) = found.iter().find(|function| function.name == mapping) else {
        return false;
    };
    let maps = tokens[map.body.clone()].windows(4).any(|window| {
        matches!(&window[0].tok, Tok::Str(value, _) if *value == plain_daemon())
            && window[1].is_punct('=')
            && window[2].is_punct('>')
            && matches!(&window[3].tok, Tok::Str(value, _) if value == "kr-controller-held")
    });
    maps && found
        .iter()
        .filter(|function| function.name == selecting)
        .all(|function| selects_through(&tokens, function, mapping))
        && found.iter().any(|function| function.name == selecting)
}

/// The daemon a suite starts is the build with the refusal. The held bin exists only with the
/// `testing` feature and has a source file of its own; no test source that runs on a platform where
/// the refusal holds names the plain `kr-controller` by a string outside a listed function, and none
/// picks it by name through a picker; and the update harness's own selection of a release's daemon,
/// the function that builds the file's path, takes the held build.
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
    let mut seen = Vec::new();
    for file in test_sources() {
        let text = std::fs::read_to_string(repository().join(&file))
            .unwrap_or_else(|error| panic!("{file}: {error}"));
        if !is_read_for_the_daemon(&file, &text) {
            continue;
        }
        for line in picks_of(&text, &PICKERS, &plain_daemon()) {
            wrong.push(format!("{file}:{line} picks the plain daemon by name"));
        }
        let roster: &[Entry] = PLAIN_DAEMON_NAMES
            .iter()
            .find(|(listed, _)| *listed == file)
            .map_or(&[], |(_, entries)| {
                seen.push(file.clone());
                entries
            });
        wrong.extend(
            roster_problems(&strings_by_function(&text, names_plain_daemon), roster)
                .into_iter()
                .map(|problem| format!("{file}: {problem}")),
        );
    }
    for (listed, _) in PLAIN_DAEMON_NAMES {
        if !seen.iter().any(|file| file == listed) {
            wrong.push(format!(
                "{listed} is on the list and is no source this rule reads"
            ));
        }
    }
    assert!(
        wrong.is_empty(),
        "these suites hold the plain kr-controller, not kr-controller-held: {wrong:#?}"
    );

    let harness = read("crates/kr-cli/tests/support/update_harness.rs");
    assert!(
        harness_selects_the_held_daemon(&harness, "built_as", "programs"),
        "the update harness does not select the daemon of a release through the map to \
         kr-controller-held"
    );
}

/// The reading of the harness's selection finds a call that selects through the map, and refuses a
/// map that is not called, a call whose result is dropped, and a name that stays the argument.
#[test]
fn the_harness_selection_reading_finds_a_selection_through_the_map_and_only_that() {
    // NAME stands for the daemon's plain name, which a source of this file does not spell out.
    let selected = |source: &str| {
        harness_selects_the_held_daemon(
            &source.replace("NAME", &plain_daemon()),
            "built_as",
            "programs",
        )
    };
    let map = r#"fn built_as(program: &str) -> &str { match program { "NAME" => "kr-controller-held", other => other } }"#;
    let programs =
        |body: &str| format!("fn programs() {{ let beside = |name: &str| {{ {body} }}; }}");
    let through = r#"let name = built_as(name); let c = profile.join(format!("{name}{}", S));"#;
    assert!(selected(&format!("{map}\n{}", programs(through))));
    for (what, body) in [
        (
            "a result that is dropped",
            r#"let _ = built_as(name); let c = profile.join(format!("{name}{}", S));"#,
        ),
        (
            "a name that stays the argument",
            r#"let name = name; let c = profile.join(format!("{name}{}", S));"#,
        ),
        (
            "a path built from no name",
            r#"let name = built_as(name); let c = profile.join("kr-controller");"#,
        ),
    ] {
        assert!(!selected(&format!("{map}\n{}", programs(body))), "{what}");
    }
    // The map that maps nothing, the map in a comment, and no selecting function at all.
    let unmapped = r#"fn built_as(program: &str) -> &str { program }"#;
    assert!(!selected(&format!("{unmapped}\n{}", programs(through))));
    assert!(!selected(&format!("// {map}\n{}", programs(through))));
    assert!(!selected(map));
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
    assert_eq!(found(r#"let p = beside_this_test("other");"#), 0);
    assert_eq!(found("// beside_this_test(\"NAME\")\nfn f() {}"), 0);
    assert_eq!(
        found(r#"fn beside_this_test(name: &str) -> PathBuf { }"#),
        0
    );
}

// ---------------------------------------------------------------------------------------------
// The programs this rule does not hold.
//
// A test program built with a crate's `testing` feature refuses a launchd command by itself. The
// end-to-end legs build the programs they run alone, with no feature, so the functions that start
// one of them or run `kr new` guard the launch instead: the first statement of the function (or,
// for a case that holds the launch itself, a statement of the case's own body before the launch)
// is `account_launchd::require(..)`, which refuses a Mac run that did not ask. Both readings are by
// tokens, so a guard named in a comment, in a string, in a closure or in a branch is not one.
// ---------------------------------------------------------------------------------------------

/// Where a funnel's guard stands: the first statement of the function, or a statement of the
/// function's own body before the first launch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Way {
    First,
    Before,
}

/// The funnels of the programs that are built without the hold: file, function (`Type::name` inside
/// an `impl`), the way its guard stands, and why it is a funnel.
const FUNNELS: [(&str, &str, Way, &str); 8] = [
    (
        "tests/e2e/m1b/src/host.rs",
        "Host::start_prepared",
        Way::First,
        "the only constructor of the host, which starts its daemon",
    ),
    (
        "tests/e2e/m1b/src/host.rs",
        "Host::start_daemon_once",
        Way::First,
        "spawns the daemon, and is the restart's start too",
    ),
    (
        "tests/e2e/agents/src/stage.rs",
        "default_keychain_of_a_session",
        Way::First,
        "runs `kr new` in a window of its own",
    ),
    (
        "tests/e2e/agents/src/stage.rs",
        "names_a_session_exports",
        Way::First,
        "runs `kr new` in a window of its own",
    ),
    (
        "tests/e2e/agents/src/stage.rs",
        "open_session",
        Way::First,
        "runs `kr new` in a window of its own",
    ),
    (
        "tests/e2e/agents/src/stage.rs",
        "Replacement::start",
        Way::First,
        "spawns a second daemon over a host's tree",
    ),
    (
        "crates/kr-cli/tests/upgrade.rs",
        "Previous::built",
        Way::First,
        "builds an earlier release's plain daemon and `kr`, which the suite then starts",
    ),
    (
        "tests/e2e/m1b/tests/checkpoint.rs",
        "a_device_uses_an_agent_in_a_managed_shell_and_reattaches_to_the_screen_kr_attach_draws",
        Way::Before,
        "a case that runs `kr new` on a terminal of its own",
    ),
];

/// The functions of a gated file that hold a launch form and start nothing themselves: file,
/// function, and the call (`Type::name`) that reaches the funnel, which holds the guard.
const THROUGH_A_FUNNEL: [(&str, &str, &str); 2] = [
    (
        "crates/kr-cli/tests/upgrade.rs",
        "a_stored_apply_node_is_admitted_across_an_update_and_a_rollback",
        "Updated::prepare",
    ),
    (
        "crates/kr-cli/tests/upgrade.rs",
        "a_report_store_the_release_before_ignores_is_kept_across_a_rollback_and_an_update",
        "Updated::prepare",
    ),
];

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

/// The body of each `impl` item, with its self type: the identifier after `for`, else the first one.
fn impl_blocks(tokens: &[Token]) -> Vec<(std::ops::Range<usize>, String)> {
    let mut found = Vec::new();
    for (at, token) in tokens.iter().enumerate() {
        let is_item = token.ident() == Some("impl")
            && at.checked_sub(1).is_none_or(|before| {
                matches!(tokens[before].tok, Tok::Punct('}' | ';' | ']' | '{'))
            });
        if !is_item {
            continue;
        }
        let (mut open, mut angle) = (at + 1, 0_i32);
        let (mut first, mut after_for, mut self_type) = (None, false, None);
        while open < tokens.len() && !(angle == 0 && tokens[open].is_punct('{')) {
            match &tokens[open].tok {
                Tok::Punct('<') => angle += 1,
                Tok::Punct('>') => angle -= 1,
                Tok::Ident(name) if angle == 0 => {
                    if name == "for" {
                        after_for = true;
                    } else if after_for && self_type.is_none() {
                        self_type = Some(name.clone());
                    } else if first.is_none() {
                        first = Some(name.clone());
                    }
                }
                _ => {}
            }
            open += 1;
        }
        if open < tokens.len() {
            found.push((
                open..closing_brace(tokens, open),
                self_type.or(first).unwrap_or_default(),
            ));
        }
    }
    found
}

/// Every function that has a body, named `Type::name` inside an `impl` and `name` outside one.
fn functions(tokens: &[Token]) -> Vec<Function> {
    let impls = impl_blocks(tokens);
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
        let owner = impls
            .iter()
            .filter(|(range, _)| range.contains(&at))
            .min_by_key(|(range, _)| range.len())
            .map(|(_, owner)| owner.as_str());
        found.push(Function {
            name: owner.map_or_else(|| name.to_owned(), |owner| format!("{owner}::{name}")),
            body: open + 1..closing_brace(tokens, open),
        });
    }
    found
}

/// The top-level statements of a body: each ends at a `;` or at the `}` of a block statement, and
/// what lies inside a block, a call or a closure is part of its statement.
fn statements(tokens: &[Token], body: &std::ops::Range<usize>) -> Vec<std::ops::Range<usize>> {
    let mut found = Vec::new();
    let (mut start, mut depth) = (body.start, 0_i32);
    for at in body.clone() {
        match tokens[at].tok {
            Tok::Punct('{' | '(' | '[') => depth += 1,
            Tok::Punct(')' | ']') => depth -= 1,
            Tok::Punct('}') => {
                depth -= 1;
                let continues = tokens
                    .get(at + 1)
                    .filter(|_| at + 1 < body.end)
                    .is_some_and(|next| {
                        matches!(next.tok, Tok::Punct(';' | '.' | '?' | ','))
                            || next.ident() == Some("else")
                    });
                if depth == 0 && !continues {
                    found.push(start..at + 1);
                    start = at + 1;
                }
            }
            Tok::Punct(';') if depth == 0 => {
                found.push(start..at + 1);
                start = at + 1;
            }
            _ => {}
        }
    }
    if start < body.end {
        found.push(start..body.end);
    }
    found
}

/// The functions of the helper that refuse a launch where the run did not ask: each with the number
/// of arguments it takes and whether its call is followed by `?`, since it returns the refusal
/// rather than panicking.
const GUARDS: [(&str, usize, bool); 5] = [
    ("require", 1, false),
    ("require_for_command", 3, false),
    ("require_for_arguments", 2, false),
    ("require_for_text", 2, false),
    ("require_given", 3, true),
];

/// The tokens of each argument of the call whose `(` is `tokens[open]`, split at the commas of its
/// own level, with what follows its `)`.
fn call_arguments(tokens: &[Token], open: usize) -> Option<(Vec<&[Token]>, &[Token])> {
    let mut depth = 0_i32;
    let mut arguments = Vec::new();
    let mut from = open + 1;
    for (at, token) in tokens.iter().enumerate().skip(open) {
        match token.tok {
            Tok::Punct('(' | '[' | '{') => depth += 1,
            Tok::Punct(')' | ']' | '}') => {
                depth -= 1;
                if depth == 0 {
                    if from < at {
                        arguments.push(&tokens[from..at]);
                    }
                    return Some((arguments, &tokens[at + 1..]));
                }
            }
            Tok::Punct(',') if depth == 1 => {
                arguments.push(&tokens[from..at]);
                from = at + 1;
            }
            _ => {}
        }
    }
    None
}

/// Whether a statement is a call of one of the helper's guard functions, by the path that names the
/// module, with the arguments the function takes and the end it has: a string for what would load a
/// job, and for `require_given` a value that is not none, `true` or the platform's own test for the
/// Mac, and a `?` that returns its refusal. A statement that is not one call, a call in a closure, a
/// `let ... else` and a call with another end (`.unwrap()`, `.ok()`) are no guard.
fn is_guard(tokens: &[Token], statement: &std::ops::Range<usize>) -> bool {
    let statement = &tokens[statement.clone()];
    let mut path = Vec::new();
    let mut at = 0;
    while let Some(name) = statement.get(at).and_then(Token::ident) {
        path.push(name);
        let separated = statement.get(at + 1).is_some_and(|next| next.is_punct(':'))
            && statement.get(at + 2).is_some_and(|next| next.is_punct(':'));
        at += if separated { 3 } else { 1 };
        if !separated {
            break;
        }
    }
    let named = match path.as_slice() {
        ["account_launchd", name] | ["kr_ipc", "testing", "account_launchd", name] => *name,
        _ => return false,
    };
    let Some(&(_, arity, question)) = GUARDS.iter().find(|guard| guard.0 == named) else {
        return false;
    };
    if !statement.get(at).is_some_and(|open| open.is_punct('(')) {
        return false;
    }
    let Some((arguments, after)) = call_arguments(statement, at) else {
        return false;
    };
    let ending = if question { "?;" } else { ";" };
    let ends: String = after
        .iter()
        .filter_map(|token| match token.tok {
            Tok::Punct(c) => Some(c),
            _ => None,
        })
        .collect();
    if arguments.len() != arity || ends != ending || after.len() != ending.len() {
        return false;
    }
    let is_str =
        |argument: &[Token]| matches!(argument, [token] if matches!(token.tok, Tok::Str(..)));
    if named == "require_given" {
        let value_given = !matches!(arguments[0], [first, ..] if first.ident() == Some("None") || first.ident() == Some("Some"));
        let on_a_mac = match arguments[1] {
            [only] => only.ident() == Some("true"),
            [
                cfg,
                bang,
                open,
                target,
                equals,
                Token {
                    tok: Tok::Str(system, _),
                    ..
                },
                close,
            ] => {
                cfg.ident() == Some("cfg")
                    && bang.is_punct('!')
                    && open.is_punct('(')
                    && target.ident() == Some("target_os")
                    && equals.is_punct('=')
                    && system == "macos"
                    && close.is_punct(')')
            }
            _ => false,
        };
        value_given && on_a_mac && is_str(arguments[2])
    } else {
        is_str(arguments[0])
    }
}

/// The token where each launch form of a body stands: the string `new`, `n` or `workflow` in a body
/// that also holds the string `kr` (a `kr` that makes a session), a session method, and a start of the
/// plain daemon by `Command::new`.
fn launch_forms(tokens: &[Token], body: &std::ops::Range<usize>) -> Vec<usize> {
    let has = |wanted: &str| {
        tokens[body.clone()]
            .iter()
            .any(|token| matches!(&token.tok, Tok::Str(value, _) if value == wanted))
    };
    let makes_a_session = has("kr");
    let daemon = plain_daemon();
    let mut forms = Vec::new();
    for at in body.clone() {
        let named = |offset: usize, wanted: &str| {
            tokens.get(at + offset).and_then(Token::ident) == Some(wanted)
        };
        match &tokens[at].tok {
            Tok::Str(value, _)
                if makes_a_session && matches!(value.as_str(), "new" | "n" | "workflow") =>
            {
                forms.push(at);
            }
            Tok::Ident(name)
                if name == "Method"
                    && tokens.get(at + 1).is_some_and(|next| next.is_punct(':'))
                    && (named(3, "SessionCreate")
                        || named(3, "WorkflowRun")
                        || named(3, "WorkflowEnable")) =>
            {
                forms.push(at);
            }
            Tok::Ident(name)
                if name == "Command"
                    && tokens.get(at + 1).is_some_and(|next| next.is_punct(':'))
                    && named(3, "new") =>
            {
                let mut depth = 0_i32;
                for inside in &tokens[at + 4..body.end] {
                    match &inside.tok {
                        Tok::Punct('(') => depth += 1,
                        Tok::Punct(')') => {
                            depth -= 1;
                            if depth == 0 {
                                break;
                            }
                        }
                        Tok::Str(value, _) if *value == daemon => {
                            forms.push(at);
                            break;
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }
    forms
}

/// What is wrong with the guard of every definition of `function` in `source`, or nothing.
fn guard_problems(source: &str, function: &str, way: Way) -> Vec<String> {
    let tokens = code_tokens(source);
    let found: Vec<Function> = functions(&tokens)
        .into_iter()
        .filter(|candidate| candidate.name == function)
        .collect();
    if found.is_empty() {
        return vec![format!("{function} is no longer in the source")];
    }
    let mut problems = Vec::new();
    for definition in found {
        let list = statements(&tokens, &definition.body);
        let first = list
            .iter()
            .position(|statement| {
                !matches!(tokens[statement.start].ident(), Some("use"))
                    && !tokens[statement.start].is_punct('#')
            })
            .unwrap_or(list.len());
        let guarded = match way {
            Way::First => list
                .get(first)
                .is_some_and(|statement| is_guard(&tokens, statement)),
            Way::Before => {
                let at = launch_forms(&tokens, &definition.body).into_iter().min();
                let guard = list
                    .iter()
                    .position(|statement| is_guard(&tokens, statement));
                match (guard, at) {
                    (Some(guard), Some(at)) => list[guard].end <= at,
                    (Some(_), None) => true,
                    (None, _) => false,
                }
            }
        };
        if !guarded {
            problems.push(format!(
                "{function} (line {}) has no guard statement {}",
                tokens[definition.body.start].line,
                match way {
                    Way::First => "first",
                    Way::Before => "before its first launch",
                }
            ));
        }
    }
    problems
}

/// The functions of `source` that hold a launch form and are not in `listed`.
fn unlisted_launches(source: &str, listed: &[&str]) -> Vec<String> {
    let tokens = code_tokens(source);
    functions(&tokens)
        .into_iter()
        .filter(|candidate| {
            !listed.contains(&candidate.name.as_str())
                && !launch_forms(&tokens, &candidate.body).is_empty()
        })
        .map(|candidate| candidate.name)
        .collect()
}

/// The source of a file of the repository.
fn read(relative: &str) -> String {
    std::fs::read_to_string(repository().join(relative))
        .unwrap_or_else(|error| panic!("{relative} is read: {error}"))
}

/// Whether the body holds a call of `Type::name`: the two identifiers with `::` between.
fn calls(tokens: &[Token], body: &std::ops::Range<usize>, path: &str) -> bool {
    let (owner, name) = path.split_once("::").expect("a path of two names");
    tokens[body.clone()].windows(4).any(|window| {
        window[0].ident() == Some(owner)
            && window[1].is_punct(':')
            && window[2].is_punct(':')
            && window[3].ident() == Some(name)
    })
}

/// Every funnel holds its guard statement first, or before its first launch.
#[test]
fn every_launch_function_holds_its_guard_statement_first_or_before_its_first_form() {
    let mut problems = Vec::new();
    for (file, function, way, _) in FUNNELS {
        problems.extend(guard_problems(&read(file), function, way));
    }
    assert!(
        problems.is_empty(),
        "these launch functions do not hold the guard statement first, or before the launch: {problems:?}"
    );

    // What the reading refuses, shown on sources of its own.
    let daemon = plain_daemon();
    let launch = format!("let mut command = Command::new(run.binary(\"{daemon}\"));");
    let guard = "kr_ipc::testing::account_launchd::require(\"x\");";
    let first = |body: &str| format!("pub fn start() {{\n{body}\n}}");
    assert!(guard_problems(&first(&format!("{guard}\n{launch}")), "start", Way::First).is_empty());
    // The other exact forms the helper has.
    for exact in [
        "account_launchd::require(\"x\");",
        "account_launchd::require_for_command(\"x\", program, &arguments);",
        "kr_ipc::testing::account_launchd::require_for_arguments(\"x\", &arguments);",
        "account_launchd::require_for_text(\"x\", command);",
        "account_launchd::require_given(asked, true, \"x\")?;",
        "account_launchd::require_given(asked.as_deref(), cfg!(target_os = \"macos\"), \"x\")?;",
    ] {
        assert!(
            guard_problems(&first(&format!("{exact}\n{launch}")), "start", Way::First).is_empty(),
            "{exact}"
        );
    }
    for (what, body) in [
        ("a guard after the launch", format!("{launch}\n{guard}")),
        ("a guard in a comment", format!("// {guard}\n{launch}")),
        (
            "a guard in a string",
            format!("let _ = \"{}\";\n{launch}", guard.replace('"', "'")),
        ),
        (
            "a guard in a closure",
            format!("let f = || {{ {guard} }};\n{launch}"),
        ),
        (
            "a guard in a branch",
            format!("if on() {{ {guard} }}\n{launch}"),
        ),
        (
            "a guard that is not a call of the rule",
            format!("account_launchd::asked();\n{launch}"),
        ),
        (
            "a refusal that never refuses, ended with unwrap",
            format!("account_launchd::require_given(None, false, \"x\").unwrap();\n{launch}"),
        ),
        (
            "a refusal given none and a platform that is not a Mac",
            format!("account_launchd::require_given(None, false, \"x\")?;\n{launch}"),
        ),
        (
            "a refusal given a value and a platform that is not a Mac",
            format!("account_launchd::require_given(asked, false, \"x\")?;\n{launch}"),
        ),
        (
            "a refusal whose result is left",
            format!("account_launchd::require_given(asked, true, \"x\");\n{launch}"),
        ),
        (
            "a name that only begins as a guard does",
            format!("account_launchd::require_given_up(\"x\");\n{launch}"),
        ),
        (
            "a guard with another end",
            format!("account_launchd::require(\"x\").ok();\n{launch}"),
        ),
        (
            "a guard with an argument too many",
            format!("account_launchd::require(\"x\", 1);\n{launch}"),
        ),
        (
            "a guard that is given no string",
            format!("account_launchd::require(what);\n{launch}"),
        ),
        (
            "a let that returns where the host is not made",
            format!("let Some(host) = Some(ServiceHost::create()) else {{ return; }};\n{launch}"),
        ),
        (
            "a let that stands in for the guard",
            format!("let None = ServiceHost::create() else {{ return; }};\n{launch}"),
        ),
    ] {
        assert!(
            !guard_problems(&first(&body), "start", Way::First).is_empty(),
            "{what} is no first guard"
        );
    }
    // A second definition of the name, unguarded, is reported; a name that is gone is stale.
    let two = format!(
        "{}\n{}",
        first(&format!("{guard}\n{launch}")),
        first(&launch)
    );
    assert_eq!(guard_problems(&two, "start", Way::First).len(), 1);
    assert!(!guard_problems(&first(&launch), "gone", Way::First).is_empty());
    // Before the launch: a head and a guard before the first form pass; a form of another kind
    // before the guard fails.
    let case = |body: &str| format!("fn a_case() {{\n{body}\n}}");
    let session = "let _ = Method::SessionCreate;";
    assert!(
        guard_problems(
            &case(&format!("{guard}\n{session}\n{launch}")),
            "a_case",
            Way::Before
        )
        .is_empty()
    );
    for body in [
        format!("{session}\n{guard}\n{launch}"),
        format!("{launch}\n{guard}"),
        format!("if on() {{ {guard} }}\n{launch}"),
        format!("let f = || {{ {guard} }};\n{launch}"),
        format!("let Some(host) = Some(ServiceHost::create()) else {{ return; }};\n{launch}"),
        format!("let None = ServiceHost::create() else {{ return; }};\n{launch}"),
        format!("account_launchd::require_given(None, false, \"x\").unwrap();\n{launch}"),
    ] {
        assert!(
            !guard_problems(&case(&body), "a_case", Way::Before).is_empty(),
            "{body}"
        );
    }
}

/// In each file with a funnel, every function that holds a launch form is a funnel on the list, and
/// every function the list names is there.
#[test]
fn every_launch_form_of_a_gated_file_stands_by_a_listed_way() {
    let mut files: Vec<&str> = FUNNELS.iter().map(|funnel| funnel.0).collect();
    files.sort_unstable();
    files.dedup();
    let mut sites = Vec::new();
    for file in files {
        let listed: Vec<&str> = FUNNELS
            .iter()
            .filter(|funnel| funnel.0 == file)
            .map(|funnel| funnel.1)
            .chain(
                THROUGH_A_FUNNEL
                    .iter()
                    .filter(|through| through.0 == file)
                    .map(|through| through.1),
            )
            .collect();
        sites.extend(
            unlisted_launches(&read(file), &listed)
                .into_iter()
                .map(|function| format!("{file}: {function}")),
        );
    }
    assert!(
        sites.is_empty(),
        "these launch sites stand by no listed way: {sites:?}"
    );

    // A function that starts nothing itself still calls the funnel that does.
    for (file, function, call) in THROUGH_A_FUNNEL {
        let tokens = code_tokens(&read(file));
        let found: Vec<Function> = functions(&tokens)
            .into_iter()
            .filter(|candidate| candidate.name == function)
            .collect();
        assert!(
            !found.is_empty(),
            "{file}: {function} is no longer in the source"
        );
        for definition in found {
            assert!(
                calls(&tokens, &definition.body, call),
                "{file}: {function} no longer calls {call}, which holds its guard"
            );
        }
    }
    let holds = |source: &str, call: &str| {
        let tokens = code_tokens(source);
        calls(&tokens, &(0..tokens.len()), call)
    };
    assert!(holds(
        "fn a() { Updated::prepare(x).await; }",
        "Updated::prepare"
    ));
    assert!(!holds("fn a() { prepare(x); }", "Updated::prepare"));
    assert!(!holds(
        "fn a() { // Updated::prepare(x)\n }",
        "Updated::prepare"
    ));

    // What the reading finds and does not find, on sources of its own.
    let daemon = plain_daemon();
    let daemon_start = format!("fn a() {{ let c = Command::new(run.binary(\"{daemon}\")); }}");
    let session_create = "fn b() { let m = Method::SessionCreate; }";
    let kr_new = "fn c() { open(&run.binary(\"kr\"), &[\"new\"]); }";
    for source in [daemon_start.as_str(), session_create, kr_new] {
        assert_eq!(unlisted_launches(source, &[]).len(), 1, "{source}");
        assert!(
            unlisted_launches(source, &["a", "b", "c"]).is_empty(),
            "{source}"
        );
    }
    for quiet in [
        format!("// Command::new(run.binary(\"{daemon}\"))\nfn a() {{}}"),
        "fn a() { let m = Method::Other; let s = \"Method::SessionCreate\"; }".to_owned(),
        "fn a() { host.command(&[\"new\"]); }".to_owned(),
        "fn a() { Command::new(run.binary(\"kr-hook\")); }".to_owned(),
    ] {
        assert!(unlisted_launches(&quiet, &[]).is_empty(), "{quiet}");
    }
}

/// The scripts that start a daemon and sessions, and the first line of each that may start one.
const SCRIPTS: [&str; 6] = [
    "scripts/e2e-desktop.sh",
    "scripts/e2e-fence.sh",
    "scripts/e2e-permissions.sh",
    "scripts/e2e-update.sh",
    "scripts/e2e-update-attach.py",
    "scripts/check-host-start.sh",
];

/// The 1-based line of the first line of `text` that is not a comment and satisfies `holds`.
fn first_line(text: &str, comment: &str, holds: impl Fn(&str) -> bool) -> Option<usize> {
    text.lines()
        .position(|line| !line.trim_start().starts_with(comment) && holds(line))
        .map(|at| at + 1)
}

/// Whether `line` of a shell script builds a program or starts one.
fn shell_launches(line: &str) -> bool {
    let words: Vec<&str> = line.split_whitespace().collect();
    words
        .windows(2)
        .any(|pair| pair[0] == "cargo" && matches!(pair[1], "build" | "run" | "test"))
        || words.iter().any(|word| matches!(*word, "mktemp" | "nohup"))
        || line.contains(&plain_daemon())
        || (line.contains("\"$kr\"") && words.contains(&"new"))
}

/// Whether `line` of the attach script starts a process or makes a file.
fn python_launches(line: &str) -> bool {
    ["tempfile.", "Popen(", "open("]
        .iter()
        .any(|word| line.contains(word))
}

/// Each script asks before it launches: its call comes before the first line that builds, makes a
/// temporary directory, or starts a daemon or a session.
#[test]
fn the_scripts_that_start_a_daemon_and_sessions_ask_before_they_launch() {
    let mut missing = Vec::new();
    for script in SCRIPTS {
        let text = read(script);
        let python = script.ends_with(".py");
        let (comment, call) = if python {
            ("#", "require_account_launchd(sys.platform")
        } else {
            ("#", "require_account_launchd \"$(uname -s)\"")
        };
        // The Python file defines the function before `main`, and its own text holds `open(` in the
        // docstring of nothing; only the body of `main` is read.
        let from = if python {
            text.find("def main(").unwrap_or(0)
        } else {
            0
        };
        let tail = &text[from..];
        let skipped = text[..from].lines().count();
        let called = first_line(tail, comment, |line| line.contains(call));
        let launched = first_line(tail, comment, |line| {
            if python {
                python_launches(line)
            } else {
                shell_launches(line)
            }
        });
        match (called, launched) {
            (Some(called), Some(launched)) if called < launched => {}
            (Some(_), None) => {}
            _ => missing.push(format!("{script} (line {})", skipped + 1)),
        }
    }
    assert!(
        missing.is_empty(),
        "these scripts do not ask for the account's own launchd before they start a daemon: {missing:?}"
    );

    // The reading refuses a call after the launch and a script with none.
    let before = "require_account_launchd \"$(uname -s)\"\ncargo build -p x\n";
    let after = "cargo build -p x\nrequire_account_launchd \"$(uname -s)\"\n";
    let call = "require_account_launchd \"$(uname -s)\"";
    let order = |text: &str| {
        let called = first_line(text, "#", |line| line.contains(call));
        let launched = first_line(text, "#", shell_launches);
        matches!((called, launched), (Some(called), Some(launched)) if called < launched)
    };
    assert!(order(before));
    assert!(!order(after));
    assert!(!order("cargo build -p x\n"));
    assert!(!order(
        "# require_account_launchd \"$(uname -s)\"\ncargo build -p x\n"
    ));
}

/// The refusal of the shell library: a Mac that did not ask is refused with the script's name and
/// the variable, and every other system, and a Mac that asked, passes. No branch launches anything.
#[test]
#[cfg(unix)]
fn the_script_functions_refuse_a_mac_run_that_did_not_ask_and_pass_every_other() {
    let run = |system: &str, value: Option<&str>| {
        let mut command = std::process::Command::new("/bin/bash");
        command
            .current_dir(repository())
            .args([
                "-c",
                ". scripts/lib/account-launchd.sh; require_account_launchd \"$1\"",
                "probe.sh",
                system,
            ])
            .env_remove("KR_ALLOW_ACCOUNT_LAUNCHD");
        if let Some(value) = value {
            command.env("KR_ALLOW_ACCOUNT_LAUNCHD", value);
        }
        command.output().expect("bash runs")
    };
    for value in [None, Some("yes"), Some("0"), Some("")] {
        let refused = run("Darwin", value);
        assert_eq!(refused.status.code(), Some(1), "{value:?}");
        let said = String::from_utf8_lossy(&refused.stderr);
        assert!(
            said.contains("KR_ALLOW_ACCOUNT_LAUNCHD=1") && said.contains("probe.sh"),
            "{said}"
        );
    }
    for (system, value) in [
        ("Darwin", Some("1")),
        ("Linux", None),
        ("Linux", Some("yes")),
    ] {
        let passed = run(system, value);
        assert_eq!(passed.status.code(), Some(0), "{system} {value:?}");
        assert!(passed.stderr.is_empty(), "{system} {value:?}");
    }
}

/// The start check's own self-test, which runs the check against a stand-in for `kr`, passes in a
/// run that did not ask for the account's own launchd: only the real run's function refuses, so a Mac
/// that did not ask can still prove the check.
#[test]
#[cfg(unix)]
fn the_start_checks_self_test_passes_where_the_run_did_not_ask() {
    let output = std::process::Command::new("/bin/bash")
        .current_dir(repository())
        .args(["scripts/check-host-start.sh", "self-test"])
        .env_remove("KR_ALLOW_ACCOUNT_LAUNCHD")
        .stdin(std::process::Stdio::null())
        .output()
        .expect("bash runs");
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.status.success() && said.contains("check-host-start: the self-test passed"),
        "the self-test of a run that did not ask: {said}"
    );
}

/// The refusal of the attach script: only a Mac run that did not ask raises, by the script's own
/// function, imported as a module so that nothing starts.
#[test]
#[cfg(unix)]
fn the_attach_script_refuses_a_mac_run_that_did_not_ask_and_passes_every_other() {
    let program = "\
import importlib.util, sys
spec = importlib.util.spec_from_file_location('attach', 'scripts/e2e-update-attach.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
for platform, value in (('darwin', None), ('darwin', 'yes'), ('darwin', '0'), ('darwin', '')):
    try:
        module.require_account_launchd(platform, value)
    except SystemExit as refusal:
        assert 'KR_ALLOW_ACCOUNT_LAUNCHD=1' in str(refusal), refusal
    else:
        sys.exit('no refusal for ' + repr((platform, value)))
for platform, value in (('darwin', '1'), ('linux', None), ('linux', 'yes')):
    module.require_account_launchd(platform, value)
";
    let output = std::process::Command::new("python3")
        .args(["-I", "-c", program])
        .current_dir(repository())
        .output()
        .expect("python3 runs");
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
