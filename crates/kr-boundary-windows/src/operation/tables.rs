//! The argument tables of the eight commands, as data.
//!
//! A table lists every option its command accepts, how each takes its value, the words the broker
//! always adds, and the options it refuses by name. The parser in [`super`] accepts only what a
//! table lists. The names a table refuses are not a second list of what is allowed: an option that
//! no table lists is refused as well, and a name here only changes the rule the refusal reports.

use super::Writes;
use crate::frame::invocation::Command;

/// How an option is spelled and what it takes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Form {
    /// The name alone.
    Flag,
    /// The name, the separator and a value in one element: `--short=8`, `-U3`.
    Attached {
        /// What stands between the name and the value: `=` for a long option, nothing for `-U`.
        separator: &'static str,
        /// What the value may be.
        values: Values,
    },
    /// A dash and decimal digits and nothing else: `-5`.
    Digits {
        /// The least value.
        min: u32,
        /// The most value.
        max: u32,
    },
    /// The name, then the next element, which is typed: `-m`, then a message.
    Separate(Typed),
}

/// The values an attached option admits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Values {
    /// One of these words.
    Words(&'static [&'static str]),
    /// A decimal count with no sign and no leading zero.
    Count {
        /// The least value.
        min: u32,
        /// The most value.
        max: u32,
    },
}

/// The type of the element that follows a separate option.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Typed {
    /// A message.
    Message {
        /// The most bytes.
        max_bytes: usize,
        /// Whether the message must be one line.
        one_line: bool,
    },
    /// A log format, written into the option as `<name>=<format>`.
    Format,
}

/// One option of a table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Row {
    /// The option's name, spelled exactly. A digits option has the name `-`.
    pub name: &'static str,
    /// How it is spelled and what it takes.
    pub form: Form,
    /// At most one option of a group (not zero) may appear.
    pub group: u8,
    /// The option that must also appear, if any.
    pub requires: Option<&'static str>,
}

const fn row(name: &'static str, form: Form) -> Row {
    Row {
        name,
        form,
        group: 0,
        requires: None,
    }
}

const fn grouped(name: &'static str, form: Form, group: u8) -> Row {
    Row {
        name,
        form,
        group,
        requires: None,
    }
}

const fn flag(name: &'static str) -> Row {
    row(name, Form::Flag)
}

/// One command's table.
#[derive(Clone, Copy, Debug)]
pub struct Table {
    /// The command.
    pub command: Command,
    /// Its name as Git spells it.
    pub name: &'static str,
    /// The words the broker always adds, after the command's name.
    pub always: &'static [&'static str],
    /// Whether the command writes.
    pub writes: Writes,
    /// Whether an operation in progress in the repository stops the command.
    pub stops_on_state: bool,
    /// Whether the command's own `HEAD` must pass the symbolic-reference check.
    pub checks_implicit_head: bool,
    /// The options it accepts.
    pub options: &'static [Row],
    /// The options that must appear.
    pub required: &'static [&'static str],
    /// The options it refuses by name.
    pub refused: &'static [&'static str],
}

/// The options of every command that no command accepts: the global options and the host's own
/// settings, which belong to the broker. A name matches with or without a value attached.
pub const GLOBAL_REFUSED: &[&str] = &[
    "--git-dir",
    "--work-tree",
    "--exec-path",
    "-C",
    "-c",
    "--config-env",
    "--namespace",
    "--super-prefix",
    "--no-replace-objects",
    "--bare",
    "--no-optional-locks",
    "--literal-pathspecs",
    "--glob-pathspecs",
    "--noglob-pathspecs",
    "--icase-pathspecs",
    "--upload-pack",
];

/// The words of `rev-parse` that ask a question about the repository and take nothing else.
pub const INTROSPECTION: &[&str] = &[
    "--is-inside-work-tree",
    "--is-inside-git-dir",
    "--is-bare-repository",
    "--is-shallow-repository",
    "--show-toplevel",
    "--show-prefix",
    "--show-cdup",
    "--git-dir",
    "--absolute-git-dir",
    "--show-object-format",
];

/// The formats Git names that `log` accepts.
pub const NAMED_FORMATS: &[&str] = &["oneline", "short", "medium", "full", "fuller"];

/// The shortest abbreviation `rev-parse --short` accepts.
pub const MIN_SHORT: u32 = 4;
/// The longest abbreviation `rev-parse --short` accepts: a whole identifier.
pub const MAX_SHORT: u32 = 40;
/// The most a count of `log` or `diff` may be.
pub const MAX_OPTION_COUNT: u32 = 1000;

const PATCH_FORMATS: u8 = 1;
const LOG_FORMAT: u8 = 2;

const UNTRACKED: &[&str] = &["no", "normal", "all"];
const IGNORED: &[&str] = &["no", "traditional", "matching"];

/// `rev-parse`.
pub static REV_PARSE: Table = Table {
    command: Command::RevParse,
    name: "rev-parse",
    always: &[],
    writes: Writes::No,
    stops_on_state: false,
    checks_implicit_head: false,
    options: &[
        flag("--verify"),
        Row {
            name: "-q",
            form: Form::Flag,
            group: 0,
            requires: Some("--verify"),
        },
        row(
            "--short",
            Form::Attached {
                separator: "=",
                values: Values::Count {
                    min: MIN_SHORT,
                    max: MAX_SHORT,
                },
            },
        ),
        flag("--abbrev-ref"),
    ],
    required: &[],
    refused: &[
        "--resolve-git-dir",
        "--git-path",
        "--local-env-vars",
        "--shared-index-path",
        "--sq",
        "--sq-quote",
        "--parseopt",
        "--stdin",
        "--path-format",
        "--git-common-dir",
        "--show-superproject-working-tree",
    ],
};

/// `status`.
pub static STATUS: Table = Table {
    command: Command::Status,
    name: "status",
    always: &["--ignore-submodules=all"],
    writes: Writes::No,
    stops_on_state: false,
    checks_implicit_head: false,
    options: &[
        row(
            "--porcelain",
            Form::Attached {
                separator: "=",
                values: Values::Words(&["v2"]),
            },
        ),
        flag("--branch"),
        flag("-z"),
        flag("--no-renames"),
        row(
            "--untracked-files",
            Form::Attached {
                separator: "=",
                values: Values::Words(UNTRACKED),
            },
        ),
        row(
            "--ignored",
            Form::Attached {
                separator: "=",
                values: Values::Words(IGNORED),
            },
        ),
    ],
    required: &["--porcelain"],
    refused: &[
        "--ignore-submodules",
        "--short",
        "--long",
        "--column",
        "--show-stash",
        "--find-renames",
        "--ahead-behind",
    ],
};

/// `diff`.
pub static DIFF: Table = Table {
    command: Command::Diff,
    name: "diff",
    always: &[
        "--no-ext-diff",
        "--no-textconv",
        "--no-color",
        "--ignore-submodules=all",
    ],
    writes: Writes::No,
    stops_on_state: false,
    checks_implicit_head: false,
    options: &[
        flag("--cached"),
        flag("--no-renames"),
        flag("--quiet"),
        row(
            "-U",
            Form::Attached {
                separator: "",
                values: Values::Count {
                    min: 0,
                    max: MAX_OPTION_COUNT,
                },
            },
        ),
        row(
            "--unified",
            Form::Attached {
                separator: "=",
                values: Values::Count {
                    min: 0,
                    max: MAX_OPTION_COUNT,
                },
            },
        ),
        grouped("--name-only", Form::Flag, PATCH_FORMATS),
        grouped("--name-status", Form::Flag, PATCH_FORMATS),
        grouped("--stat", Form::Flag, PATCH_FORMATS),
        grouped("--numstat", Form::Flag, PATCH_FORMATS),
        grouped("--shortstat", Form::Flag, PATCH_FORMATS),
        grouped("--raw", Form::Flag, PATCH_FORMATS),
        grouped("--patch", Form::Flag, PATCH_FORMATS),
    ],
    required: &[],
    refused: &[
        "--no-index",
        "--output",
        "-O",
        "--ext-diff",
        "--textconv",
        "--submodule",
        "--word-diff",
        "--color-moved",
        "-S",
        "-G",
        "--find-copies",
        "--find-renames",
        "--relative",
        "--ignore-submodules",
        "--exit-code",
    ],
};

/// `log`.
pub static LOG: Table = Table {
    command: Command::Log,
    name: "log",
    always: &[
        "--no-ext-diff",
        "--no-textconv",
        "--no-show-signature",
        "--no-color",
        "--no-decorate",
        "--no-notes",
        "--no-use-mailmap",
        "--ignore-submodules=all",
    ],
    writes: Writes::No,
    stops_on_state: false,
    checks_implicit_head: false,
    options: &[
        row(
            "-",
            Form::Digits {
                min: 1,
                max: MAX_OPTION_COUNT,
            },
        ),
        row(
            "--max-count",
            Form::Attached {
                separator: "=",
                values: Values::Count {
                    min: 1,
                    max: MAX_OPTION_COUNT,
                },
            },
        ),
        flag("--oneline"),
        flag("--first-parent"),
        flag("--reverse"),
        flag("--name-only"),
        flag("--name-status"),
        flag("--stat"),
        grouped("--format", Form::Separate(Typed::Format), LOG_FORMAT),
        grouped("--pretty", Form::Separate(Typed::Format), LOG_FORMAT),
    ],
    required: &[],
    refused: &[
        "--show-signature",
        "--stdin",
        "-L",
        "--remerge-diff",
        "--follow",
        "--grep",
        "--author",
        "--since",
        "--until",
        "--use-mailmap",
        "--output",
        "-O",
        "--ext-diff",
        "--textconv",
        "--decorate",
        "--notes",
        "--all",
        "--branches",
        "--tags",
        "--remotes",
        "--glob",
    ],
};

/// `checkout`.
pub static CHECKOUT: Table = Table {
    command: Command::Checkout,
    name: "checkout",
    always: &["--no-guess", "--no-recurse-submodules", "--quiet"],
    writes: Writes::Yes,
    stops_on_state: true,
    checks_implicit_head: false,
    options: &[],
    required: &[],
    refused: &[
        "-b",
        "-B",
        "--orphan",
        "-t",
        "--track",
        "-f",
        "--force",
        "-m",
        "--merge",
        "-p",
        "--patch",
        "--pathspec-from-file",
        "--pathspec-file-nul",
        "--ours",
        "--theirs",
        "--ignore-other-worktrees",
        "--overwrite-ignore",
        "--conflict",
    ],
};

/// `add`.
pub static ADD: Table = Table {
    command: Command::Add,
    name: "add",
    always: &[],
    writes: Writes::Yes,
    stops_on_state: false,
    checks_implicit_head: false,
    options: &[],
    required: &[],
    refused: &[
        "-A",
        "--all",
        "-u",
        "--update",
        "-p",
        "--patch",
        "-i",
        "--interactive",
        "-e",
        "--edit",
        "--renormalize",
        "--chmod",
        "-f",
        "--force",
        "-N",
        "--intent-to-add",
        "--ignore-errors",
        "--pathspec-from-file",
        "--pathspec-file-nul",
        "-v",
        "-n",
    ],
};

/// The most bytes of the message `update-ref` records in the reflog.
pub const MAX_REFLOG_MESSAGE_BYTES: usize = 200;

/// `update-ref`.
pub static UPDATE_REF: Table = Table {
    command: Command::UpdateRef,
    name: "update-ref",
    always: &["--no-deref"],
    writes: Writes::Yes,
    stops_on_state: true,
    checks_implicit_head: true,
    options: &[row(
        "-m",
        Form::Separate(Typed::Message {
            max_bytes: MAX_REFLOG_MESSAGE_BYTES,
            one_line: true,
        }),
    )],
    required: &[],
    refused: &[
        "-d",
        "--stdin",
        "-z",
        "--create-reflog",
        "--no-create-reflog",
    ],
};

/// `commit`.
pub static COMMIT: Table = Table {
    command: Command::Commit,
    name: "commit",
    always: &[
        "--no-edit",
        "--no-gpg-sign",
        "--no-verify",
        "--no-post-rewrite",
        "--cleanup=whitespace",
        "--no-status",
    ],
    writes: Writes::Yes,
    stops_on_state: true,
    checks_implicit_head: true,
    options: &[
        flag("-q"),
        flag("--quiet"),
        flag("--allow-empty"),
        row(
            "-m",
            Form::Separate(Typed::Message {
                max_bytes: crate::frame::invocation::MAX_MESSAGE_BYTES,
                one_line: false,
            }),
        ),
    ],
    required: &["-m"],
    refused: &[
        "-a",
        "--all",
        "--amend",
        "-C",
        "-c",
        "--reuse-message",
        "--reedit-message",
        "--fixup",
        "--squash",
        "-F",
        "--file",
        "-t",
        "--template",
        "-e",
        "--edit",
        "--author",
        "--date",
        "-s",
        "--signoff",
        "-S",
        "--gpg-sign",
        "--trailer",
        "-i",
        "--include",
        "-o",
        "--only",
        "-p",
        "--patch",
        "--interactive",
        "--pathspec-from-file",
        "--pathspec-file-nul",
        "--reset-author",
        "--allow-empty-message",
        "--no-verify",
    ],
};

/// The table of a command.
#[must_use]
pub fn table(command: Command) -> &'static Table {
    match command {
        Command::RevParse => &REV_PARSE,
        Command::Status => &STATUS,
        Command::Diff => &DIFF,
        Command::Log => &LOG,
        Command::Add => &ADD,
        Command::Checkout => &CHECKOUT,
        Command::Commit => &COMMIT,
        Command::UpdateRef => &UPDATE_REF,
    }
}

/// The eight commands, in the order their tables are documented.
pub const COMMANDS: [Command; 8] = [
    Command::RevParse,
    Command::Status,
    Command::Diff,
    Command::Log,
    Command::Checkout,
    Command::Add,
    Command::UpdateRef,
    Command::Commit,
];
