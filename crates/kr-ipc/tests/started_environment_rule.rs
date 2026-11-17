//! A test that starts a controller, a worker or a `kr` command gives it an environment of its own.
//!
//! A session's shell starts as a login shell and reads the startup files of the home folder it is
//! given. A program a test starts inherits the test program's environment, so a harness that does
//! not say otherwise gives the worker's shell the person's real home, and with it the person's
//! profile. This test reads the Rust sources under `crates`, `apps` and `tests` and fails, naming
//! the file and the line, for a test source that names one of those programs and neither uses
//! [`kr_ipc::testing::started_environment::StartedEnvironment`] nor builds the whole environment
//! of the program itself (it clears the inherited one and sets `HOME`).
//!
//! What it names: the three programs a test starts through cargo's own variables
//! (`CARGO_BIN_EXE_kr`, `CARGO_BIN_EXE_kr-controller`, `CARGO_BIN_EXE_kr-worker`), a program called
//! by its name (`"kr-controller"`, `"kr-worker"`), the command binaries of the `kr` crate's
//! support module (`command_binaries()`), and a call of the `kr` crate's `kr()` support function.
//!
//! What it cannot see:
//!
//! - which of a file's starts the helper covers: one use of the helper in a file satisfies the
//!   reading for every start in it, and so does one `env_clear` beside one `HOME`;
//! - that the home it is given lies inside the case's own root: the helper makes it so, and the
//!   hand-built form is the author's to keep;
//! - a worker that a daemon in the test's own process starts, which needs the environment given to
//!   that daemon (`Controller::set_host_environment`) and not to a command: the file names the
//!   helper there too, and the cases that read the shell's own home are the proof;
//! - a program started by a name this reading does not list, and a source under `src` that holds
//!   test modules, which are not test sources by their place.
//!
//! A Windows source is not read: a session's shell there reads the account's PowerShell profile,
//! which the helper does not give a home to, and the Windows harnesses are the work of a later
//! change.

use std::path::{Path, PathBuf};

/// The directories the reading covers, under the workspace's root.
const ROOTS: [&str; 3] = ["crates", "apps", "tests"];

/// The text that names a program a test starts.
const NAMES: [&str; 7] = [
    "CARGO_BIN_EXE_kr\"",
    "CARGO_BIN_EXE_kr-controller\"",
    "CARGO_BIN_EXE_kr-worker\"",
    "\"kr-controller\"",
    "\"kr-worker\"",
    "command_binaries()",
    "kr()",
];

/// The words that show a file gives what it starts an environment of its own: the helper, or an
/// environment cleared and a home set by the file itself.
const HELPER: &str = "StartedEnvironment";

/// Why a source that names a program starts no session: its daemon has no worker program that
/// exists.
const NO_WORKER: &str = "its daemon has no worker program that exists, so no session can start";

/// Why a source that names a program starts no session: it runs a command against a host that
/// already runs.
const NO_START: &str = "it runs a command against a host that already runs, with an environment of its own, and the \
     command starts no daemon and no session";

/// Why a source that names a program starts no session: it only names it.
const NAMES_ONLY: &str = "it names the programs without starting any";

/// Why a source that names a program starts no session: it places the programs other sources
/// start.
const PLACES_ONLY: &str = "it places the programs other sources start and starts none itself";

/// The sources that name a program a test starts and neither use the helper nor build the whole
/// environment themselves, as the file and the reason. Each is a source that starts no session
/// with a shell of a person's home to read.
const KEPT: &[(&str, &str)] = &[
    ("crates/kr-cli/tests/bridge.rs", NO_START),
    ("crates/kr-cli/tests/contact.rs", NO_START),
    ("crates/kr-cli/tests/container.rs", NO_START),
    ("crates/kr-cli/tests/probe.rs", NO_START),
    ("crates/kr-cli/tests/retained_surface.rs", NAMES_ONLY),
    ("crates/kr-cli/tests/descriptions.rs", NO_WORKER),
    ("crates/kr-cli/tests/host_clock.rs", NO_WORKER),
    ("crates/kr-cli/tests/host_network.rs", NO_WORKER),
    ("crates/kr-cli/tests/organisation.rs", NO_WORKER),
    ("crates/kr-cli/tests/pair.rs", NO_WORKER),
    ("crates/kr-controller/tests/agent_tools.rs", NO_WORKER),
    ("crates/kr-controller/tests/bridge.rs", NO_WORKER),
    (
        "crates/kr-controller/tests/bundled_agents_default_route.rs",
        NO_WORKER,
    ),
    ("crates/kr-controller/tests/bundled_seed.rs", NO_WORKER),
    ("crates/kr-controller/tests/configuration.rs", NO_WORKER),
    (
        "crates/kr-controller/tests/configuration_reader.rs",
        NO_WORKER,
    ),
    ("crates/kr-controller/tests/destinations.rs", NO_WORKER),
    ("crates/kr-controller/tests/managed_storage.rs", NO_WORKER),
    ("crates/kr-controller/tests/project.rs", NO_WORKER),
    ("crates/kr-controller/tests/storage_account.rs", NO_WORKER),
    ("crates/kr-controller/tests/transfer.rs", NO_WORKER),
    ("crates/kr-controller/tests/task_supervisor.rs", NO_WORKER),
    ("crates/kr-controller/tests/spawn_sites.rs", NAMES_ONLY),
    ("tests/conformance/src/plan.rs", NAMES_ONLY),
    ("tests/conformance/src/report.rs", NAMES_ONLY),
    ("crates/kr-cli/tests/support/mod.rs", PLACES_ONLY),
    (
        "crates/kr-controller/tests/plugin_world/mod.rs",
        "its supervisor is one in memory that records launches and starts no process",
    ),
    (
        "crates/kr-shell-integration/tests/qualification.rs",
        NAMES_ONLY,
    ),
    ("crates/kr-worker/tests/trusted_core.rs", NAMES_ONLY),
    ("tests/e2e/m1b/src/run.rs", NAMES_ONLY),
    ("tests/e2e/m1b/tests/checkpoint.rs", NAMES_ONLY),
    (
        "tests/perf/tests/stress.rs",
        "its in-process daemon can be given an environment only through the controller's testing feature, which this package's manifest does not enable; removed when the package enables that feature",
    ),
];

/// The sources whose daemon runs in the test's own process, starts a real worker, and is not given
/// an environment of its own, as the file and the reason. The program of such a source takes the
/// test program's environment for the sessions it starts. Each stands until its package enables the
/// controller's `testing` feature, which gives a daemon its environment; the entry is then removed
/// and the daemon is given what the helper makes.
const IN_PROCESS_WITHOUT_ENVIRONMENT: &[(&str, &str)] = &[
    (
        "tests/faults/tests/kills.rs",
        "the processes this source starts itself clear the environment and set a home of the tree's own, and its daemon has no host environment of its own",
    ),
    (
        "tests/perf/tests/stress.rs",
        "the measurement is of a daemon built without the testing hooks",
    ),
];

/// The source with its comments removed. Literals are kept, since a program is named in one.
fn without_comments(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut kept = String::with_capacity(text.len());
    let mut at = 0;
    while at < chars.len() {
        let c = chars[at];
        let next = chars.get(at + 1).copied();
        if c == '/' && next == Some('/') {
            while at < chars.len() && chars[at] != '\n' {
                at += 1;
            }
        } else if c == '/' && next == Some('*') {
            let mut depth = 0;
            while at < chars.len() {
                if chars[at] == '/' && chars.get(at + 1) == Some(&'*') {
                    depth += 1;
                    at += 2;
                } else if chars[at] == '*' && chars.get(at + 1) == Some(&'/') {
                    depth -= 1;
                    at += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    if chars[at] == '\n' {
                        kept.push('\n');
                    }
                    at += 1;
                }
            }
        } else if c == '"' {
            let begun = at;
            at += 1;
            while at < chars.len() && chars[at] != '"' {
                at += if chars[at] == '\\' { 2 } else { 1 };
            }
            at = (at + 1).min(chars.len());
            kept.extend(&chars[begun..at]);
        } else if c == '\'' && next == Some('\\') {
            let begun = at;
            at += 2;
            while at < chars.len() && chars[at] != '\'' {
                at += 1;
            }
            at = (at + 1).min(chars.len());
            kept.extend(&chars[begun..at]);
        } else if c == '\'' && chars.get(at + 2) == Some(&'\'') {
            kept.extend(&chars[at..at + 3]);
            at += 3;
        } else {
            kept.push(c);
            at += 1;
        }
    }
    kept
}

/// The line of the first place the text names a program a test starts, when it does.
fn first_start(text: &str) -> Option<(usize, &'static str)> {
    let mut first: Option<(usize, &'static str)> = None;
    for name in NAMES {
        let mut from = 0;
        while let Some(found) = text[from..].find(name) {
            let at = from + found;
            from = at + name.len();
            // `kr()` is a call only when it is not the end of a longer name.
            if name == "kr()"
                && text[..at]
                    .chars()
                    .next_back()
                    .is_some_and(|before| before.is_alphanumeric() || before == '_')
            {
                continue;
            }
            let line = text[..at].matches('\n').count() + 1;
            if first.is_none_or(|(earlier, _)| line < earlier) {
                first = Some((line, name));
            }
            break;
        }
    }
    first
}

/// Whether the text gives what it starts an environment of its own.
fn gives_an_environment(text: &str) -> bool {
    text.contains(HELPER) || (text.contains("env_clear()") && text.contains("\"HOME\""))
}

/// The line and the name of the first start in a source that gives its programs no environment, or
/// nothing when it starts none or gives one.
fn offence(text: &str) -> Option<(usize, &'static str)> {
    let code = without_comments(text);
    let start = first_start(&code)?;
    (!gives_an_environment(&code)).then_some(start)
}

fn sources(directory: &Path, found: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(directory) else {
        return;
    };
    let mut entries: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .collect();
    entries.sort();
    for entry in entries {
        let name = entry
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("");
        if entry.is_dir() {
            if !matches!(name, "target" | "node_modules" | ".git") {
                sources(&entry, found);
            }
        } else if entry.extension().is_some_and(|extension| extension == "rs") {
            found.push(entry);
        }
    }
}

/// The workspace's root.
fn workspace() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the workspace")
}

/// Whether a source, by its place under the workspace, is a test source this reading covers: it
/// is in a `tests` directory, is not this reading itself, and is not a Windows source.
fn is_read(relative: &str) -> bool {
    relative.split('/').any(|part| part == "tests")
        && !relative.contains("windows")
        && relative != "crates/kr-ipc/tests/started_environment_rule.rs"
}

/// Every test source of the workspace, as its place under the root and its text.
fn test_sources() -> Vec<(String, String)> {
    let workspace = workspace();
    let mut files = Vec::new();
    for root in ROOTS {
        sources(&workspace.join(root), &mut files);
    }
    assert!(
        files.len() > 100,
        "the reading finds the workspace's sources"
    );
    files
        .into_iter()
        .filter_map(|file| {
            let relative = file
                .strip_prefix(&workspace)
                .expect("under the workspace")
                .to_string_lossy()
                .replace('\\', "/");
            if !is_read(&relative) {
                return None;
            }
            Some((relative, std::fs::read_to_string(&file).ok()?))
        })
        .collect()
}

#[test]
fn a_test_that_starts_a_program_gives_it_an_environment_of_its_own() {
    let sources = test_sources();
    let found: Vec<(String, usize, &str)> = sources
        .iter()
        .filter_map(|(file, text)| offence(text).map(|(line, name)| (file.clone(), line, name)))
        .collect();
    let unkept: Vec<String> = found
        .iter()
        .filter(|(file, _, _)| !KEPT.iter().any(|(kept, _)| kept == file))
        .map(|(file, line, name)| format!("{file}:{line}: names {name}"))
        .collect();
    assert!(
        unkept.is_empty(),
        "a program a test starts inherits the test program's environment, and a session's shell \
         reads the startup files of the home it is given, which is then the person's. Give what \
         the test starts `kr_ipc::testing::started_environment::StartedEnvironment`:\n{}",
        unkept.join("\n")
    );
    let stale: Vec<String> = KEPT
        .iter()
        .filter(|(kept, _)| !found.iter().any(|(file, _, _)| file == kept))
        .map(|(file, reason)| format!("{file} ({reason})"))
        .collect();
    assert!(
        stale.is_empty(),
        "a source listed as one that starts a program without an environment of its own no longer \
         does:\n{}",
        stale.join("\n")
    );
}

#[test]
fn the_reading_finds_a_start_that_gives_no_environment_however_it_is_written() {
    let named =
        |program: &str| format!("fn daemon() -> Command {{ Command::new(env!(\"{program}\")) }}");
    for program in [
        "CARGO_BIN_EXE_kr",
        "CARGO_BIN_EXE_kr-controller",
        "CARGO_BIN_EXE_kr-worker",
    ] {
        assert!(offence(&named(program)).is_some(), "{program}");
    }
    for text in [
        "let worker = directory.join(\"kr-worker\");",
        "let program = beside_this_test(\"kr-controller\");",
        "let built = support::command_binaries();",
        "let mut command = std::process::Command::new(kr());",
        "let mut command = std::process::Command::new(support::kr());",
        // The helper's name in a comment, or an environment cleared with no home, is not an
        // environment given.
        "// StartedEnvironment\nlet worker = directory.join(\"kr-worker\");",
        "let c = Command::new(kr()).env_clear().env(\"PATH\", \"/usr/bin\");",
    ] {
        assert!(offence(text).is_some(), "{text}");
    }
}

#[test]
fn the_reading_passes_a_start_that_gives_one_and_words_that_are_not_a_start() {
    for text in [
        "let environment = StartedEnvironment::within(root);\nlet worker = directory.join(\"kr-worker\");",
        "let c = Command::new(kr()).env_clear().env(\"HOME\", home);",
        // Names in a comment are not a start, and neither is the end of a longer name.
        "// directory.join(\"kr-worker\")\nlet a = 1;",
        "/* command_binaries() */ let a = 1;",
        "let a = thekr();",
        "let a = \"/*\"; let b = 2;",
    ] {
        assert!(offence(text).is_none(), "{text}");
    }
}

#[test]
fn a_source_listed_as_giving_its_daemon_no_environment_still_starts_one_and_gives_it_none() {
    let sources = test_sources();
    let stale: Vec<String> = IN_PROCESS_WITHOUT_ENVIRONMENT
        .iter()
        .filter(|(listed, _)| {
            !sources.iter().any(|(file, text)| {
                file == listed
                    && text.contains("Controller::start(")
                    && !text.contains("set_host_environment")
            })
        })
        .map(|(file, reason)| format!("{file} ({reason})"))
        .collect();
    assert!(
        stale.is_empty(),
        "a source listed as one whose in-process daemon has no host environment of its own no \
         longer starts a daemon, or now gives it one, and is removed from the list:\n{}",
        stale.join("\n")
    );
}
