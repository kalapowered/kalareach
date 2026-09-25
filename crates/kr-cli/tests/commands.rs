//! Section 7's command table, walked row by row.
//!
//! Every command the table lists answers to its name and names the operations its row names, and a
//! command with a short form answers to that as well; the families the table gives no short form
//! answer to nothing shorter. `--help` is answered at every depth of the command line and
//! `--version` at its root, `--json` is an option of every command, a literal `--` ends option
//! parsing, and a refusal exits with a status other than zero.
//!
//! The command line is read two ways. Its own parser says which command a line names and what the
//! line's words became. The `kr` a person runs, copied to the internal disk and run against a host
//! tree of this test's own that nothing serves, says what a person is told and how it exits.

use std::process::{Command, Output, Stdio};

use clap::{CommandFactory as _, Parser as _};
use kr_cli::cli::{Cli, Command as Parsed, PairCommand};
use serde_json::Value;

mod support;

/// A well-formed identifier, for the lines that need one to parse.
const UUID: &str = "01234567-89ab-4def-8123-456789abcdef";

/// One row of the table: the words that name the command, its short form, and the operations its
/// brackets name.
struct Row {
    command: &'static [&'static str],
    short: Option<&'static str>,
    operations: &'static [&'static str],
}

/// Section 7's table, in its own order.
const TABLE: &[Row] = &[
    Row {
        command: &["new"],
        short: Some("n"),
        operations: &[],
    },
    Row {
        command: &["attach"],
        short: Some("a"),
        operations: &[],
    },
    Row {
        command: &["detach"],
        short: Some("d"),
        operations: &[],
    },
    Row {
        command: &["close"],
        short: Some("c"),
        operations: &[],
    },
    Row {
        command: &["list"],
        short: Some("l"),
        operations: &[],
    },
    Row {
        command: &["status"],
        short: Some("s"),
        operations: &[],
    },
    Row {
        command: &["project"],
        short: None,
        operations: &["list", "init", "clone", "adopt"],
    },
    Row {
        command: &["workspace"],
        short: None,
        operations: &["list", "create", "remove"],
    },
    Row {
        command: &["changeset"],
        short: None,
        operations: &["capture", "read", "materialize"],
    },
    Row {
        command: &["diff"],
        short: None,
        operations: &["read", "apply", "revert"],
    },
    Row {
        command: &["pair"],
        short: Some("p"),
        operations: &["invite", "confirm", "cancel", "status"],
    },
    Row {
        command: &["device"],
        short: None,
        operations: &["list", "revoke"],
    },
    Row {
        command: &["plugin"],
        short: None,
        operations: &["list", "install", "remove", "pin", "enable", "disable"],
    },
    Row {
        command: &["plugin", "repo"],
        short: None,
        operations: &["list", "add", "sync", "pin", "remove"],
    },
    Row {
        command: &["skill"],
        short: None,
        operations: &["install", "status", "remove"],
    },
    Row {
        command: &["agent-tools"],
        short: None,
        operations: &[],
    },
    Row {
        command: &["doctor"],
        short: None,
        operations: &[],
    },
];

/// One complete line for every operation the table names, and for every command that names none.
///
/// Each is a line a person could type: the words that name the operation, then whatever that
/// operation needs before it will parse.
const LINES: &[&[&str]] = &[
    &["new", "--invisible"],
    &["attach", "1"],
    &["detach", "--attachment", UUID],
    &["close", "1"],
    &["list"],
    &["status", "1"],
    &["project", "list"],
    &["project", "init", "/srv/fresh"],
    &[
        "project",
        "clone",
        "https://example.invalid/work.git",
        "/srv/copy",
    ],
    &["project", "adopt", "/srv/existing"],
    &["workspace", "list"],
    &["workspace", "create", UUID, "--kind", "shared"],
    &["workspace", "remove", UUID],
    &["changeset", "capture", UUID, "--label", "the work"],
    &["changeset", "read", UUID],
    &["changeset", "materialize", UUID, "1", "--purpose", "review"],
    &["diff", "read", "--workspace", UUID],
    &["diff", "apply", UUID, "1", "--to", "proposal"],
    &["diff", "revert", UUID, "1", "--to", "proposal"],
    &["pair", "invite", "--owner"],
    &["pair", "confirm", UUID],
    &["pair", "cancel", UUID],
    &["pair", "status", UUID],
    &["device", "list"],
    &["device", "revoke", UUID],
    &["plugin", "list"],
    &[
        "plugin",
        "install",
        "community",
        "kalareach/example-declarative",
        "0.1.0",
        "--digest",
        "f8434aef081de78d9b63e34d1172b9a64399182a7420bb4f0b3352762a5aeccb",
    ],
    &["plugin", "remove", "kalareach/example-declarative"],
    &["plugin", "pin", "kalareach/example-declarative"],
    &["plugin", "enable", "kalareach/example-declarative"],
    &["plugin", "disable", "kalareach/example-declarative"],
    &["plugin", "repo", "list"],
    &[
        "plugin",
        "repo",
        "add",
        "community",
        "--root",
        "/srv/root.json",
        "--metadata-url",
        "https://example.invalid/metadata/",
        "--targets-url",
        "https://example.invalid/targets/",
    ],
    &["plugin", "repo", "sync", "community"],
    &["plugin", "repo", "pin", "community", "--generation", "1"],
    &["plugin", "repo", "remove", "community"],
    &["skill", "install", "--agent", "codex", "--scope", "user"],
    &["skill", "status", "--agent", "codex", "--scope", "user"],
    &["skill", "remove", "--agent", "codex", "--scope", "user"],
    &["agent-tools", "--stdio"],
    &["doctor"],
];

/// Returns the parser's own definition of the command `path` names, or none when it has none.
fn defined(path: &[&str]) -> Option<clap::Command> {
    let mut command = Cli::command();
    command.build();
    for word in path {
        command = command.find_subcommand(word)?.clone();
    }
    Some(command)
}

/// Fails with every problem found, one to a line, when there is any.
fn none_of(problems: &[String]) {
    assert!(
        problems.is_empty(),
        "the command line differs from section 7's table:\n{}",
        problems.join("\n")
    );
}

/// Parses one command line, with `kr` in front of it.
fn parse(line: &[&str]) -> Result<Cli, clap::Error> {
    Cli::try_parse_from(std::iter::once("kr").chain(line.iter().copied()))
}

/// What the parser made of one command line, beneath the command `path` names.
fn matched(line: &[&str], path: &[&str]) -> clap::ArgMatches {
    let mut matches = Cli::command()
        .try_get_matches_from(std::iter::once("kr").chain(line.iter().copied()))
        .unwrap_or_else(|error| panic!("kr {} does not parse: {error}", line.join(" ")));
    for word in path {
        matches = matches
            .subcommand_matches(word)
            .unwrap_or_else(|| panic!("kr {} is not kr {}", line.join(" "), path.join(" ")))
            .clone();
    }
    matches
}

/// The words one argument received, as they were typed.
fn words(matches: &clap::ArgMatches, argument: &str) -> Vec<String> {
    matches
        .get_raw(argument)
        .map(|values| {
            values
                .map(|value| value.to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default()
}

/// Every command path the parser knows, from the root down, each with its words.
fn every_path() -> Vec<Vec<String>> {
    let mut root = Cli::command();
    root.build();
    let mut paths = Vec::new();
    let mut waiting = vec![(Vec::new(), root)];
    while let Some((path, command)) = waiting.pop() {
        for subcommand in command.get_subcommands() {
            let mut deeper = path.clone();
            deeper.push(subcommand.get_name().to_owned());
            waiting.push((deeper, subcommand.clone()));
        }
        paths.push(path);
    }
    paths.sort();
    paths
}

/// A host tree nothing serves, and the environment `kr` is run with inside it.
struct Tree {
    temp: kr_ipc::testing::TempHost,
}

impl Tree {
    fn new() -> Self {
        Self {
            temp: kr_ipc::testing::TempHost::create(),
        }
    }

    /// Runs `kr` with this tree's directories, on plain pipes, from the directory the binaries
    /// are in, which is on the internal disk.
    fn kr(&self, line: &[&str]) -> Output {
        Command::new(support::kr())
            .args(line)
            .env(
                kr_ipc::paths::RUNTIME_DIR_VARIABLE,
                self.temp.paths().runtime_root(),
            )
            .env(
                kr_ipc::paths::STATE_DIR_VARIABLE,
                self.temp.paths().state_root(),
            )
            // Whatever session the tests themselves run in is not the one these commands ask
            // about.
            .env_remove("KR_SESSION")
            .env_remove("KR_ATTACHMENT")
            .current_dir(support::command_binaries())
            .stdin(Stdio::null())
            .output()
            .expect("kr runs")
    }
}

/// KR-REQ-07.47: every command the table lists answers to its name and names every operation its
/// row names.
#[test]
fn every_command_in_the_table_names_the_operations_its_row_names() {
    let mut problems = Vec::new();
    for row in TABLE {
        let Some(command) = defined(row.command) else {
            problems.push(format!("there is no kr {}", row.command.join(" ")));
            continue;
        };
        let named: Vec<&str> = command
            .get_subcommands()
            .map(clap::Command::get_name)
            .collect();
        for operation in row.operations {
            if !named.contains(operation) {
                problems.push(format!(
                    "kr {} does not name {operation}: it names {named:?}",
                    row.command.join(" ")
                ));
            }
        }
    }
    none_of(&problems);
}

/// KR-REQ-07.47: every line in [`LINES`] parses, and together they reach every operation the
/// table names and every command that names none.
#[test]
fn a_line_for_every_operation_parses() {
    for line in LINES {
        if let Err(error) = parse(line) {
            panic!("kr {} does not parse: {error}", line.join(" "));
        }
    }
    for row in TABLE {
        let leaves: Vec<Vec<&str>> = if row.operations.is_empty() {
            vec![row.command.to_vec()]
        } else {
            row.operations
                .iter()
                .map(|operation| {
                    let mut leaf = row.command.to_vec();
                    leaf.push(*operation);
                    leaf
                })
                .collect()
        };
        for leaf in leaves {
            assert!(
                LINES.iter().any(|line| line.starts_with(&leaf)),
                "no line reaches kr {}",
                leaf.join(" ")
            );
        }
    }
}

/// KR-REQ-07.47: a short form is the command it stands for, and the families the table gives no
/// short form answer to nothing shorter, at any depth.
#[test]
fn a_short_form_names_its_command_and_the_families_have_none() {
    let mut problems = Vec::new();
    for row in TABLE {
        let Some(command) = defined(row.command) else {
            problems.push(format!("there is no kr {}", row.command.join(" ")));
            continue;
        };
        match row.short {
            Some(short) => {
                // Every short form is also shown in the command's help, so the two lists agree.
                let aliases: Vec<&str> = command.get_all_aliases().collect();
                let visible: Vec<&str> = command.get_visible_aliases().collect();
                if aliases != [short] || visible != [short] {
                    problems.push(format!(
                        "kr {} answers to {aliases:?} and shows {visible:?}; the table gives it \
                         {short}",
                        row.command.join(" ")
                    ));
                }
            }
            None => {
                let mut waiting = vec![command];
                while let Some(command) = waiting.pop() {
                    let aliases: Vec<&str> = command.get_all_aliases().collect();
                    if !aliases.is_empty() {
                        problems.push(format!(
                            "kr {} ({}) has no short form in the table and answers to {aliases:?}",
                            row.command.join(" "),
                            command.get_name()
                        ));
                    }
                    if row.operations.is_empty() {
                        break;
                    }
                    waiting.extend(command.get_subcommands().cloned());
                }
            }
        }
    }
    none_of(&problems);
    // Each short form parses to the command it stands for, with that command's own arguments.
    let pairs: [(&[&str], &[&str]); 7] = [
        (&["attach", "1"], &["a", "1"]),
        (
            &["detach", "--attachment", UUID],
            &["d", "--attachment", UUID],
        ),
        (&["close", "1"], &["c", "1"]),
        (&["list"], &["l"]),
        (&["status", "1"], &["s", "1"]),
        (&["new", "--invisible"], &["n", "--invisible"]),
        (&["pair", "status", UUID], &["p", "status", UUID]),
    ];
    for (long, short) in pairs {
        let full = parse(long).unwrap_or_else(|error| panic!("{long:?}: {error}"));
        let abbreviated = parse(short).unwrap_or_else(|error| panic!("{short:?}: {error}"));
        assert_eq!(
            std::mem::discriminant(&full.command),
            std::mem::discriminant(&abbreviated.command),
            "kr {} is kr {}",
            short.join(" "),
            long.join(" ")
        );
    }
    let Parsed::Pair(PairCommand::Status(status)) =
        parse(&["p", "status", UUID]).expect("parses").command
    else {
        panic!("kr p status is kr pair status");
    };
    assert_eq!(status.invitation, UUID);
}

/// KR-REQ-07.47: `--help` is answered by the command and by every command beneath it, at every
/// depth, and by every short form; `--version` is answered at the root. Each is a report that
/// exits with zero.
#[test]
fn help_is_answered_at_every_depth_and_the_version_at_the_root() {
    let tree = Tree::new();
    let mut asked: Vec<Vec<String>> = every_path();
    assert!(
        asked.iter().any(|path| path == &["plugin", "repo", "add"]),
        "the walk reaches the deepest commands: {asked:?}"
    );
    for row in TABLE {
        if let Some(short) = row.short {
            asked.push(vec![short.to_owned()]);
        }
    }
    for path in &asked {
        let mut line: Vec<&str> = path.iter().map(String::as_str).collect();
        line.push("--help");
        let output = tree.kr(&line);
        let printed = String::from_utf8_lossy(&output.stdout);
        assert_eq!(
            output.status.code(),
            Some(0),
            "kr {}: {}",
            line.join(" "),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            printed.contains("Usage: kr"),
            "kr {} prints its usage: {printed}",
            line.join(" ")
        );
    }
    let output = tree.kr(&["--version"]);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        format!("kr {}", kr_cli::RELEASE)
    );
}

/// KR-REQ-07.47: `--json` is an option of every command, before the command's words or after
/// them.
#[test]
fn json_is_an_option_of_every_command() {
    for line in LINES {
        let mut after: Vec<&str> = line.to_vec();
        after.push("--json");
        let parsed = parse(&after).unwrap_or_else(|error| panic!("{after:?}: {error}"));
        assert!(parsed.json, "kr {} takes --json after", line.join(" "));
        let mut before: Vec<&str> = vec!["--json"];
        before.extend_from_slice(line);
        let parsed = parse(&before).unwrap_or_else(|error| panic!("{before:?}: {error}"));
        assert!(parsed.json, "kr {} takes --json before", line.join(" "));
    }
}

/// KR-REQ-07.47: a literal `--` ends option parsing, so a word after it that looks like an option
/// is an argument, in the session commands and in the families alike.
#[test]
fn a_literal_double_dash_ends_option_parsing() {
    let Parsed::Attach(attach) = parse(&["attach", "--", "--json"]).expect("parses").command else {
        panic!("attach");
    };
    assert_eq!(attach.session, "--json");
    assert!(!parse(&["attach", "--", "--json"]).expect("parses").json);

    let line = ["project", "init", "--", "--label"];
    let init = matched(&line, &["project", "init"]);
    assert_eq!(words(&init, "path"), ["--label"]);
    assert!(words(&init, "label").is_empty(), "no label was given");

    let line = ["workspace", "remove", "--", "--remove-retained"];
    let remove = matched(&line, &["workspace", "remove"]);
    assert_eq!(words(&remove, "workspace"), ["--remove-retained"]);
    assert!(!remove.get_flag("remove_retained"));

    let line = [
        "diff",
        "apply",
        "--to",
        "proposal",
        "--",
        "--preflight",
        "2",
    ];
    let apply = matched(&line, &["diff", "apply"]);
    assert_eq!(words(&apply, "change_set"), ["--preflight"]);
    assert_eq!(words(&apply, "version"), ["2"]);
    assert!(!apply.get_flag("preflight"));

    let line = ["plugin", "repo", "remove", "--", "-h"];
    let repo = matched(&line, &["plugin", "repo", "remove"]);
    assert_eq!(words(&repo, "catalogue"), ["-h"]);
}

/// KR-REQ-07.47: a refusal exits with a status other than zero, and with `--json` the document it
/// prints carries that same status: a line that does not parse, a family whose host is not
/// running, and a session that is not there.
#[test]
fn a_refusal_exits_with_a_status_other_than_zero() {
    let tree = Tree::new();
    let refusals: [(&[&str], i32); 5] = [
        (&["frobnicate"], 2),
        (&["diff", "apply", UUID, "1"], 2),
        (&["project", "list"], 3),
        (&["device", "list"], 3),
        (&["plugin", "repo", "list"], 3),
    ];
    for (line, status) in refusals {
        let output = tree.kr(line);
        assert_eq!(
            output.status.code(),
            Some(status),
            "kr {}: {}",
            line.join(" "),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!output.stderr.is_empty(), "kr {} says why", line.join(" "));
        let mut json = line.to_vec();
        json.push("--json");
        let output = tree.kr(&json);
        let document: Value = serde_json::from_slice(&output.stdout)
            .unwrap_or_else(|error| panic!("kr {} prints JSON: {error}", json.join(" ")));
        assert_eq!(document["ok"], Value::Bool(false), "{document}");
        assert_eq!(
            document["exit_code"].as_i64(),
            output.status.code().map(i64::from),
            "{document}"
        );
    }
    let output = tree.kr(&["attach", "4242"]);
    assert_ne!(output.status.code(), Some(0));
    assert_ne!(
        output.status.code(),
        None,
        "kr exits rather than being killed"
    );
}
