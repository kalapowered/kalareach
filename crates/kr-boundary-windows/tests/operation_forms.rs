//! The argument tables of the eight commands: every form a table lists comes out as the line the
//! table gives, and every other form is refused with the rule's name and never with the argument.

use kr_boundary_windows::frame::invocation::{
    Arg, Command, Dots, Format, MAX_ARGUMENTS, MAX_FORMAT_PARTS, MAX_FORMAT_TEXT_BYTES,
    MAX_MESSAGE_BYTES, MAX_NAME_BYTES, MAX_PATH_BYTES, MAX_REF_NAME_BYTES, MAX_REV_BYTES,
    NamedFormat, Part, Placeholder, RefusedKind,
};
use kr_boundary_windows::operation::grammar::{
    MAX_PATH_COMPONENTS, MAX_PATHS, MAX_REVISION_STEPS, RULE_MESSAGE_LENGTH, RULE_MESSAGE_LINES,
    RULE_PATH, RULE_PATH_DEPTH, RULE_PATH_LENGTH, RULE_REVISION, RULE_REVISION_LENGTH,
};
use kr_boundary_windows::operation::tables::{self, Form, GLOBAL_REFUSED, INTROSPECTION, Row};
use kr_boundary_windows::operation::{
    Check, OperationLine, RULE_ARGUMENTS, RULE_CONTROL, RULE_FORM, RULE_FORMAT, RULE_MISSING,
    RULE_NAME, RULE_OID, RULE_OID_ZERO, RULE_OPTION_EXCLUSIVE, RULE_OPTION_GLOBAL,
    RULE_OPTION_REFUSED, RULE_OPTION_REPEATED, RULE_OPTION_REQUIRES, RULE_OPTION_SPELLING,
    RULE_OPTION_UNLISTED, RULE_OPTION_VALUE, RULE_ORDER, RULE_PATHS, RULE_REFNAME, RULE_RESOLVED,
    RULE_REVISIONS, RULE_SEPARATOR, RULE_TYPE, Writes, parse_operation, placeholder_text,
};
use kr_boundary_windows::repository::config::ConfigFacts;

const OID: &str = "0123456789abcdef0123456789abcdef01234567";
const OID2: &str = "fedcba9876543210fedcba9876543210fedcba98";
const ZERO: &str = "0000000000000000000000000000000000000000";

fn w(text: &str) -> Arg {
    Arg::Word(text.to_owned())
}
fn p(text: &str) -> Arg {
    Arg::Path(text.to_owned())
}
fn r(text: &str) -> Arg {
    Arg::Rev(text.to_owned())
}
fn n(text: &str) -> Arg {
    Arg::Name(text.to_owned())
}
fn rn(text: &str) -> Arg {
    Arg::RefName(text.to_owned())
}
fn o(text: &str) -> Arg {
    Arg::Oid(text.to_owned())
}
fn m(text: &str) -> Arg {
    Arg::Message(text.to_owned())
}
fn range(left: &str, dots: Dots, right: &str) -> Arg {
    Arg::Range {
        left: left.to_owned(),
        right: right.to_owned(),
        dots,
    }
}
fn named(format: NamedFormat) -> Arg {
    Arg::Format(Format::Named(format))
}
fn custom(parts: Vec<Part>) -> Arg {
    Arg::Format(Format::Custom(parts))
}
fn text(own: &str) -> Part {
    Part::Text(own.to_owned())
}
fn strings(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|part| (*part).to_owned()).collect()
}

fn parse(
    command: Command,
    args: &[Arg],
) -> Result<OperationLine, kr_boundary_windows::refusal::Refusal> {
    parse_operation(command, args, &ConfigFacts::default())
}

fn accepted(command: Command, args: &[Arg]) -> OperationLine {
    parse(command, args).unwrap_or_else(|refusal| panic!("{command:?} {args:?}: {refusal}"))
}

/// The rule that refuses the line; it also holds that the reply names the command and a position.
fn refused(command: Command, args: &[Arg]) -> &'static str {
    let refusal = parse(command, args).expect_err(&format!("{command:?} {args:?}"));
    assert_eq!(refusal.kind, RefusedKind::Operation, "{refusal}");
    let detail = refusal.detail();
    assert!(detail.contains("argument"), "{detail}");
    refusal.rule
}

const STATUS: &[&str] = &["status", "--ignore-submodules=all"];
const DIFF: &[&str] = &[
    "diff",
    "--no-ext-diff",
    "--no-textconv",
    "--no-color",
    "--ignore-submodules=all",
];
const LOG: &[&str] = &[
    "log",
    "--no-ext-diff",
    "--no-textconv",
    "--no-show-signature",
    "--no-color",
    "--no-decorate",
    "--no-notes",
    "--no-use-mailmap",
    "--ignore-submodules=all",
];
const CHECKOUT: &[&str] = &[
    "checkout",
    "--no-guess",
    "--no-recurse-submodules",
    "--quiet",
];
const UPDATE_REF: &[&str] = &["update-ref", "--no-deref"];
const COMMIT: &[&str] = &[
    "commit",
    "--no-edit",
    "--no-gpg-sign",
    "--no-verify",
    "--no-post-rewrite",
    "--cleanup=whitespace",
    "--no-status",
];

fn with(always: &[&str], rest: &[&str]) -> Vec<String> {
    always.iter().chain(rest).map(|s| (*s).to_owned()).collect()
}

fn resolve(spec: &str, at: usize) -> Check {
    Check::Resolve {
        spec: spec.to_owned(),
        replaces: Some(at),
        tree_target: false,
    }
}

#[test]
fn the_tables_say_which_commands_write_and_which_stop_on_a_state() {
    for (command, writes, state, head) in [
        (Command::RevParse, Writes::No, false, false),
        (Command::Status, Writes::No, false, false),
        (Command::Diff, Writes::No, false, false),
        (Command::Log, Writes::No, false, false),
        (Command::Add, Writes::Yes, false, false),
        (Command::Checkout, Writes::Yes, true, false),
        (Command::UpdateRef, Writes::Yes, true, true),
        (Command::Commit, Writes::Yes, true, true),
    ] {
        let table = tables::table(command);
        assert_eq!(table.command, command);
        assert_eq!(table.writes, writes, "{command:?}");
        assert_eq!(table.stops_on_state, state, "{command:?}");
        assert_eq!(table.checks_implicit_head, head, "{command:?}");
    }
    assert_eq!(tables::COMMANDS.len(), 8);
}

// rev-parse

#[test]
fn rev_parse_accepts_each_introspection_word_alone() {
    let words = [
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
    assert_eq!(INTROSPECTION, words);
    for word in words {
        let line = accepted(Command::RevParse, &[w(word)]);
        assert_eq!(line.argv, strings(&["rev-parse", word]));
        assert_eq!(line.writes, Writes::No);
        assert!(line.checks.is_empty());
    }
}

#[test]
fn rev_parse_takes_nothing_after_an_introspection_word() {
    for word in INTROSPECTION {
        assert_eq!(refused(Command::RevParse, &[w(word), r("HEAD")]), RULE_FORM);
        assert_eq!(refused(Command::RevParse, &[w(word), w(word)]), RULE_FORM);
    }
}

#[test]
fn rev_parse_revision_form_qualifies_each_revision_and_notes_its_resolution() {
    let line = accepted(Command::RevParse, &[r("HEAD")]);
    assert_eq!(line.argv, strings(&["rev-parse", "HEAD"]));
    assert_eq!(line.checks, vec![resolve("HEAD", 1)]);

    let line = accepted(Command::RevParse, &[r("main"), r(OID), r("feature/x~2^")]);
    assert_eq!(
        line.argv,
        strings(&[
            "rev-parse",
            "refs/heads/main",
            OID,
            "refs/heads/feature/x~2^"
        ])
    );
    assert_eq!(
        line.checks,
        vec![
            resolve("refs/heads/main", 1),
            resolve(OID, 2),
            resolve("refs/heads/feature/x~2^", 3)
        ]
    );
}

#[test]
fn rev_parse_revision_form_takes_each_option_alone_and_together() {
    let cases: Vec<(Vec<Arg>, Vec<&str>)> = vec![
        (vec![w("--verify"), r("HEAD")], vec!["--verify", "HEAD"]),
        (
            vec![w("--verify"), w("-q"), r("HEAD")],
            vec!["--verify", "-q", "HEAD"],
        ),
        (
            vec![w("-q"), w("--verify"), r("HEAD")],
            vec!["-q", "--verify", "HEAD"],
        ),
        (vec![w("--short=4"), r("HEAD")], vec!["--short=4", "HEAD"]),
        (vec![w("--short=40"), r("HEAD")], vec!["--short=40", "HEAD"]),
        (
            vec![w("--abbrev-ref"), r("HEAD")],
            vec!["--abbrev-ref", "HEAD"],
        ),
        (
            vec![w("--verify"), w("--short=12"), w("--abbrev-ref"), r("HEAD")],
            vec!["--verify", "--short=12", "--abbrev-ref", "HEAD"],
        ),
    ];
    for (args, expected) in cases {
        let line = accepted(Command::RevParse, &args);
        let mut want = vec!["rev-parse"];
        want.extend(expected);
        assert_eq!(line.argv, strings(&want), "{args:?}");
    }
}

#[test]
fn rev_parse_refusals() {
    // `-q` is the option of `--verify` and means nothing without it.
    assert_eq!(
        refused(Command::RevParse, &[w("-q"), r("HEAD")]),
        RULE_OPTION_REQUIRES
    );
    // `--verify` takes one revision.
    assert_eq!(
        refused(Command::RevParse, &[w("--verify"), r("HEAD"), r("main")]),
        RULE_REVISIONS
    );
    // A revision is needed.
    assert_eq!(refused(Command::RevParse, &[]), RULE_MISSING);
    assert_eq!(refused(Command::RevParse, &[w("--verify")]), RULE_MISSING);
    // `--short` is attached, and 4 to 40.
    for value in [
        "--short=3",
        "--short=41",
        "--short=",
        "--short=04",
        "--short=+5",
        "--short=x",
    ] {
        assert_eq!(
            refused(Command::RevParse, &[w(value), r("HEAD")]),
            RULE_OPTION_VALUE,
            "{value}"
        );
    }
    assert_eq!(
        refused(Command::RevParse, &[w("--short"), r("HEAD")]),
        RULE_OPTION_SPELLING
    );
    assert_eq!(
        refused(Command::RevParse, &[w("--verify=1"), r("HEAD")]),
        RULE_OPTION_SPELLING
    );
    // Repeats.
    assert_eq!(
        refused(
            Command::RevParse,
            &[w("--abbrev-ref"), w("--abbrev-ref"), r("HEAD")]
        ),
        RULE_OPTION_REPEATED
    );
    // No path, no range, no name as a revision, a revision before an option.
    assert_eq!(refused(Command::RevParse, &[r("HEAD"), p("a")]), RULE_FORM);
    assert_eq!(refused(Command::RevParse, &[r("HEAD"), w("--")]), RULE_FORM);
    assert_eq!(
        refused(Command::RevParse, &[range("a", Dots::Two, "b")]),
        RULE_MISSING
    );
    assert_eq!(refused(Command::RevParse, &[n("main")]), RULE_MISSING);
    assert_eq!(
        refused(Command::RevParse, &[r("HEAD"), w("--verify")]),
        RULE_ORDER
    );
    assert_eq!(
        refused(
            Command::RevParse,
            &[w("--verify"), w("--is-inside-work-tree")]
        ),
        RULE_OPTION_UNLISTED
    );
}

// status

#[test]
fn status_requires_porcelain_v2_and_takes_each_option() {
    let line = accepted(Command::Status, &[w("--porcelain=v2")]);
    assert_eq!(line.argv, with(STATUS, &["--porcelain=v2"]));
    assert_eq!(line.writes, Writes::No);

    let cases: Vec<(Vec<Arg>, Vec<&str>)> = vec![
        (
            vec![w("--porcelain=v2"), w("--branch")],
            vec!["--porcelain=v2", "--branch"],
        ),
        (
            vec![w("--porcelain=v2"), w("-z")],
            vec!["--porcelain=v2", "-z"],
        ),
        (
            vec![w("--porcelain=v2"), w("--no-renames")],
            vec!["--porcelain=v2", "--no-renames"],
        ),
        (
            vec![w("-z"), w("--porcelain=v2")],
            vec!["-z", "--porcelain=v2"],
        ),
        (
            vec![
                w("--porcelain=v2"),
                w("--branch"),
                w("-z"),
                w("--no-renames"),
            ],
            vec!["--porcelain=v2", "--branch", "-z", "--no-renames"],
        ),
    ];
    for (args, expected) in cases {
        assert_eq!(
            accepted(Command::Status, &args).argv,
            with(STATUS, &expected),
            "{args:?}"
        );
    }
    for value in ["no", "normal", "all"] {
        let option = format!("--untracked-files={value}");
        assert_eq!(
            accepted(Command::Status, &[w("--porcelain=v2"), w(&option)]).argv,
            with(STATUS, &["--porcelain=v2", &option])
        );
    }
    for value in ["no", "traditional", "matching"] {
        let option = format!("--ignored={value}");
        assert_eq!(
            accepted(Command::Status, &[w("--porcelain=v2"), w(&option)]).argv,
            with(STATUS, &["--porcelain=v2", &option])
        );
    }
}

#[test]
fn status_takes_paths_after_a_separator() {
    let line = accepted(
        Command::Status,
        &[w("--porcelain=v2"), w("--"), p("src"), p(".")],
    );
    assert_eq!(
        line.argv,
        with(STATUS, &["--porcelain=v2", "--", "src", "."])
    );
}

#[test]
fn status_refusals() {
    assert_eq!(refused(Command::Status, &[]), RULE_MISSING);
    assert_eq!(refused(Command::Status, &[w("--branch")]), RULE_MISSING);
    for value in [
        "--porcelain=v1",
        "--porcelain=",
        "--porcelain=V2",
        "--porcelain=v2 ",
    ] {
        assert_eq!(
            refused(Command::Status, &[w(value)]),
            RULE_OPTION_VALUE,
            "{value}"
        );
    }
    assert_eq!(
        refused(Command::Status, &[w("--porcelain")]),
        RULE_OPTION_SPELLING
    );
    for value in [
        "--untracked-files=",
        "--untracked-files=yes",
        "--ignored=all",
        "--ignored=",
    ] {
        assert_eq!(
            refused(Command::Status, &[w("--porcelain=v2"), w(value)]),
            RULE_OPTION_VALUE,
            "{value}"
        );
    }
    assert_eq!(
        refused(
            Command::Status,
            &[w("--porcelain=v2"), w("--untracked-files")]
        ),
        RULE_OPTION_SPELLING
    );
    // A path needs its separator, and the separator its path.
    assert_eq!(
        refused(Command::Status, &[w("--porcelain=v2"), p("a")]),
        RULE_SEPARATOR
    );
    assert_eq!(
        refused(Command::Status, &[w("--porcelain=v2"), w("--")]),
        RULE_SEPARATOR
    );
    // An option after the paths.
    assert_eq!(
        refused(
            Command::Status,
            &[w("--porcelain=v2"), w("--"), p("a"), w("-z")]
        ),
        RULE_ORDER
    );
    assert_eq!(
        refused(
            Command::Status,
            &[w("--porcelain=v2"), w("--"), p("a"), r("HEAD")]
        ),
        RULE_FORM
    );
    assert_eq!(
        refused(Command::Status, &[w("--porcelain=v2"), r("HEAD")]),
        RULE_FORM
    );
    assert_eq!(
        refused(Command::Status, &[w("--porcelain=v2"), w("-z"), w("-z")]),
        RULE_OPTION_REPEATED
    );
}

// diff

#[test]
fn diff_takes_each_option_each_revision_form_and_paths() {
    assert_eq!(accepted(Command::Diff, &[]).argv, strings(DIFF));
    for flag in ["--cached", "--no-renames", "--quiet"] {
        assert_eq!(
            accepted(Command::Diff, &[w(flag)]).argv,
            with(DIFF, &[flag])
        );
    }
    for format in [
        "--name-only",
        "--name-status",
        "--stat",
        "--numstat",
        "--shortstat",
        "--raw",
        "--patch",
    ] {
        assert_eq!(
            accepted(Command::Diff, &[w(format)]).argv,
            with(DIFF, &[format])
        );
    }
    for unified in [
        "-U0",
        "-U3",
        "-U1000",
        "--unified=0",
        "--unified=7",
        "--unified=1000",
    ] {
        assert_eq!(
            accepted(Command::Diff, &[w(unified)]).argv,
            with(DIFF, &[unified])
        );
    }
    let line = accepted(
        Command::Diff,
        &[
            w("--cached"),
            w("--no-renames"),
            w("--quiet"),
            w("-U5"),
            w("--stat"),
        ],
    );
    assert_eq!(
        line.argv,
        with(
            DIFF,
            &["--cached", "--no-renames", "--quiet", "-U5", "--stat"]
        )
    );

    let one = accepted(Command::Diff, &[r("main")]);
    assert_eq!(one.argv, with(DIFF, &["refs/heads/main"]));
    assert_eq!(one.checks, vec![resolve("refs/heads/main", 5)]);
    let two = accepted(Command::Diff, &[w("--cached"), r("HEAD~1"), r(OID)]);
    assert_eq!(two.argv, with(DIFF, &["--cached", "HEAD~1", OID]));
    assert_eq!(two.checks, vec![resolve("HEAD~1", 6), resolve(OID, 7)]);

    for (dots, text) in [(Dots::Two, ".."), (Dots::Three, "...")] {
        let line = accepted(Command::Diff, &[range("main", dots, "HEAD^")]);
        assert_eq!(
            line.argv,
            with(DIFF, &[&format!("refs/heads/main{text}HEAD^")])
        );
        assert_eq!(
            line.checks,
            vec![Check::ResolveRange {
                index: 5,
                left: "refs/heads/main".to_owned(),
                dots,
                right: "HEAD^".to_owned()
            }]
        );
    }

    let line = accepted(Command::Diff, &[r("HEAD"), w("--"), p("a/b.txt"), p("c")]);
    assert_eq!(line.argv, with(DIFF, &["HEAD", "--", "a/b.txt", "c"]));
    let line = accepted(Command::Diff, &[w("--"), p("a")]);
    assert_eq!(line.argv, with(DIFF, &["--", "a"]));
}

#[test]
fn diff_refusals() {
    // One format of the group at most, in either order.
    let group = [
        "--name-only",
        "--name-status",
        "--stat",
        "--numstat",
        "--shortstat",
        "--raw",
        "--patch",
    ];
    for first in group {
        for second in group {
            if first != second {
                assert_eq!(
                    refused(Command::Diff, &[w(first), w(second)]),
                    RULE_OPTION_EXCLUSIVE,
                    "{first} {second}"
                );
            } else {
                assert_eq!(
                    refused(Command::Diff, &[w(first), w(second)]),
                    RULE_OPTION_REPEATED
                );
            }
        }
    }
    // Both unified spellings are two options, and each is only given once.
    assert_eq!(
        refused(Command::Diff, &[w("-U1"), w("-U2")]),
        RULE_OPTION_REPEATED
    );
    assert!(parse(Command::Diff, &[w("-U1"), w("--unified=2")]).is_ok());
    for value in [
        "-U",
        "-U1001",
        "-U-1",
        "-U01",
        "-Ux",
        "--unified=1001",
        "--unified=",
        "--unified=01",
    ] {
        let rule = refused(Command::Diff, &[w(value)]);
        assert!(
            rule == RULE_OPTION_VALUE || rule == RULE_OPTION_SPELLING,
            "{value}: {rule}"
        );
    }
    assert_eq!(refused(Command::Diff, &[w("-U")]), RULE_OPTION_SPELLING);
    assert_eq!(refused(Command::Diff, &[w("-U1001")]), RULE_OPTION_VALUE);
    assert_eq!(
        refused(Command::Diff, &[w("--unified")]),
        RULE_OPTION_SPELLING
    );
    assert_eq!(
        refused(Command::Diff, &[w("--cached=1")]),
        RULE_OPTION_SPELLING
    );
    // Three revisions, a revision beside a range, two ranges.
    assert_eq!(
        refused(Command::Diff, &[r("a"), r("b"), r("c")]),
        RULE_REVISIONS
    );
    assert_eq!(
        refused(Command::Diff, &[r("a"), range("b", Dots::Two, "c")]),
        RULE_REVISIONS
    );
    assert_eq!(
        refused(Command::Diff, &[range("b", Dots::Two, "c"), r("a")]),
        RULE_REVISIONS
    );
    assert_eq!(
        refused(
            Command::Diff,
            &[range("a", Dots::Two, "b"), range("c", Dots::Three, "d")]
        ),
        RULE_REVISIONS
    );
    // A bad side of a range.
    assert_eq!(
        refused(Command::Diff, &[range("a", Dots::Two, "b@{1}")]),
        RULE_REVISION
    );
    assert_eq!(
        refused(Command::Diff, &[range("", Dots::Two, "b")]),
        RULE_REVISION
    );
    // An option after a revision.
    assert_eq!(refused(Command::Diff, &[r("a"), w("--cached")]), RULE_ORDER);
    // An argument type no position takes.
    assert_eq!(refused(Command::Diff, &[Arg::Count(3)]), RULE_FORM);
    assert_eq!(refused(Command::Diff, &[n("main")]), RULE_FORM);
    assert_eq!(
        refused(Command::Diff, &[named(NamedFormat::Full)]),
        RULE_FORM
    );
    assert_eq!(refused(Command::Diff, &[p("a")]), RULE_SEPARATOR);
}

// log

#[test]
fn log_takes_each_option_each_revision_form_and_paths() {
    assert_eq!(accepted(Command::Log, &[]).argv, strings(LOG));
    for count in ["-1", "-5", "-1000", "--max-count=1", "--max-count=1000"] {
        assert_eq!(
            accepted(Command::Log, &[w(count)]).argv,
            with(LOG, &[count])
        );
    }
    for flag in [
        "--oneline",
        "--first-parent",
        "--reverse",
        "--name-only",
        "--name-status",
        "--stat",
    ] {
        assert_eq!(accepted(Command::Log, &[w(flag)]).argv, with(LOG, &[flag]));
    }
    let line = accepted(
        Command::Log,
        &[
            w("-3"),
            w("--max-count=4"),
            w("--oneline"),
            w("--first-parent"),
            w("--reverse"),
        ],
    );
    assert_eq!(
        line.argv,
        with(
            LOG,
            &[
                "-3",
                "--max-count=4",
                "--oneline",
                "--first-parent",
                "--reverse"
            ]
        )
    );
    assert_eq!(line.writes, Writes::No);

    let line = accepted(Command::Log, &[r("main"), r("HEAD")]);
    assert_eq!(line.argv, with(LOG, &["refs/heads/main", "HEAD"]));
    assert_eq!(
        line.checks,
        vec![resolve("refs/heads/main", 9), resolve("HEAD", 10)]
    );
    let line = accepted(Command::Log, &[range("a", Dots::Two, "b"), w("--"), p("x")]);
    assert_eq!(
        line.argv,
        with(LOG, &["refs/heads/a..refs/heads/b", "--", "x"])
    );
}

#[test]
fn log_takes_a_named_format_or_a_custom_one_with_either_option() {
    for (format, spelled) in [
        (NamedFormat::Oneline, "oneline"),
        (NamedFormat::Short, "short"),
        (NamedFormat::Medium, "medium"),
        (NamedFormat::Full, "full"),
        (NamedFormat::Fuller, "fuller"),
    ] {
        for option in ["--format", "--pretty"] {
            let line = accepted(Command::Log, &[w(option), named(format)]);
            assert_eq!(line.argv, with(LOG, &[&format!("{option}={spelled}")]));
        }
    }
    let everything = [
        (Placeholder::CommitHash, "%H"),
        (Placeholder::CommitHashShort, "%h"),
        (Placeholder::TreeHash, "%T"),
        (Placeholder::TreeHashShort, "%t"),
        (Placeholder::ParentHashes, "%P"),
        (Placeholder::ParentHashesShort, "%p"),
        (Placeholder::AuthorName, "%an"),
        (Placeholder::AuthorEmail, "%ae"),
        (Placeholder::AuthorDate, "%ad"),
        (Placeholder::AuthorDateIso, "%aI"),
        (Placeholder::AuthorDateUnix, "%at"),
        (Placeholder::CommitterName, "%cn"),
        (Placeholder::CommitterEmail, "%ce"),
        (Placeholder::CommitterDate, "%cd"),
        (Placeholder::CommitterDateIso, "%cI"),
        (Placeholder::CommitterDateUnix, "%ct"),
        (Placeholder::Subject, "%s"),
        (Placeholder::Body, "%b"),
        (Placeholder::RawMessage, "%B"),
        (Placeholder::Newline, "%n"),
        (Placeholder::Percent, "%%"),
    ];
    for (placeholder, spelled) in everything {
        assert_eq!(placeholder_text(placeholder), spelled);
        let line = accepted(
            Command::Log,
            &[w("--format"), custom(vec![Part::Placeholder(placeholder)])],
        );
        assert_eq!(line.argv, with(LOG, &[&format!("--format={spelled}")]));
    }
    let parts = vec![
        Part::Placeholder(Placeholder::CommitHashShort),
        text(" by "),
        Part::Placeholder(Placeholder::AuthorName),
        text(": 100"),
        Part::Placeholder(Placeholder::Percent),
    ];
    let line = accepted(Command::Log, &[w("--pretty"), custom(parts)]);
    assert_eq!(line.argv, with(LOG, &["--pretty=%h by %an: 100%%"]));
    // Text that looks like a placeholder to a reader is text without its percent sign.
    let line = accepted(
        Command::Log,
        &[w("--format"), custom(vec![text("an"), text("-x")])],
    );
    assert_eq!(line.argv, with(LOG, &["--format=an-x"]));
}

#[test]
fn log_refusals() {
    assert_eq!(
        refused(
            Command::Log,
            &[
                w("--format"),
                named(NamedFormat::Short),
                w("--pretty"),
                named(NamedFormat::Full)
            ]
        ),
        RULE_OPTION_EXCLUSIVE
    );
    assert_eq!(
        refused(
            Command::Log,
            &[
                w("--format"),
                named(NamedFormat::Short),
                w("--format"),
                named(NamedFormat::Full)
            ]
        ),
        RULE_OPTION_REPEATED
    );
    // The attached spelling of an option that takes its value as the next element.
    for attached in ["--format=oneline", "--pretty=short", "--format=%H"] {
        assert_eq!(
            refused(Command::Log, &[w(attached)]),
            RULE_OPTION_SPELLING,
            "{attached}"
        );
    }
    // A format option needs a format, and the right type.
    assert_eq!(refused(Command::Log, &[w("--format")]), RULE_OPTION_VALUE);
    assert_eq!(
        refused(Command::Log, &[w("--format"), w("--oneline")]),
        RULE_TYPE
    );
    assert_eq!(refused(Command::Log, &[w("--format"), m("%H")]), RULE_TYPE);
    assert_eq!(
        refused(Command::Log, &[w("--format"), Arg::Count(1)]),
        RULE_TYPE
    );
    assert_eq!(
        refused(Command::Log, &[named(NamedFormat::Oneline)]),
        RULE_FORM
    );
    // A custom format outside the table.
    assert_eq!(
        refused(Command::Log, &[w("--format"), custom(vec![])]),
        RULE_FORMAT
    );
    assert_eq!(
        refused(Command::Log, &[w("--format"), custom(vec![text("100%")])]),
        RULE_FORMAT
    );
    assert_eq!(
        refused(Command::Log, &[w("--format"), custom(vec![text("%an")])]),
        RULE_FORMAT
    );
    assert_eq!(
        refused(Command::Log, &[w("--format"), custom(vec![text("a\nb")])]),
        RULE_FORMAT
    );
    assert_eq!(
        refused(Command::Log, &[w("--format"), custom(vec![text("a\tb")])]),
        RULE_FORMAT
    );
    assert_eq!(
        refused(Command::Log, &[w("--format"), custom(vec![text("")])]),
        RULE_FORMAT
    );
    // Counts: 1 to 1000, canonical.
    for count in [
        "-0",
        "-1001",
        "-01",
        "--max-count=0",
        "--max-count=1001",
        "--max-count=-1",
        "--max-count=007",
    ] {
        assert_eq!(
            refused(Command::Log, &[w(count)]),
            RULE_OPTION_VALUE,
            "{count}"
        );
    }
    assert_eq!(
        refused(Command::Log, &[w("--max-count")]),
        RULE_OPTION_SPELLING
    );
    // The two spellings of a count are two options.
    assert!(parse(Command::Log, &[w("-5"), w("--max-count=5")]).is_ok());
}

// checkout

#[test]
fn checkout_switch_carries_the_bare_name_and_checks_the_branch_and_the_tag() {
    let line = accepted(Command::Checkout, &[n("feature/x-1")]);
    assert_eq!(line.argv, with(CHECKOUT, &["feature/x-1", "--"]));
    assert_eq!(line.writes, Writes::Yes);
    assert_eq!(
        line.checks,
        vec![
            Check::OperationState,
            Check::Resolve {
                spec: "refs/heads/feature/x-1".to_owned(),
                replaces: None,
                tree_target: true
            },
            Check::NotSymbolic {
                refname: "refs/heads/feature/x-1".to_owned()
            },
            Check::NoTag {
                name: "feature/x-1".to_owned()
            },
        ]
    );
}

#[test]
fn checkout_detach_restore_from_a_revision_and_restore_from_the_index() {
    let line = accepted(Command::Checkout, &[w("--detach"), r("main~2")]);
    assert_eq!(
        line.argv,
        with(CHECKOUT, &["--detach", "refs/heads/main~2", "--"])
    );
    assert_eq!(
        line.checks,
        vec![
            Check::OperationState,
            Check::Resolve {
                spec: "refs/heads/main~2".to_owned(),
                replaces: Some(5),
                tree_target: true
            }
        ]
    );

    let line = accepted(Command::Checkout, &[r(OID), w("--"), p("a"), p("b/c")]);
    assert_eq!(line.argv, with(CHECKOUT, &[OID, "--", "a", "b/c"]));
    assert_eq!(
        line.checks,
        vec![
            Check::OperationState,
            Check::Resolve {
                spec: OID.to_owned(),
                replaces: Some(4),
                tree_target: true
            }
        ]
    );

    let line = accepted(Command::Checkout, &[w("--"), p("a"), p(".")]);
    assert_eq!(line.argv, with(CHECKOUT, &["--", "a", "."]));
    assert_eq!(line.checks, vec![Check::OperationState]);
}

#[test]
fn checkout_refusals() {
    assert_eq!(refused(Command::Checkout, &[]), RULE_MISSING);
    assert_eq!(refused(Command::Checkout, &[n("a"), n("b")]), RULE_FORM);
    assert_eq!(refused(Command::Checkout, &[n("a"), w("--")]), RULE_FORM);
    assert_eq!(refused(Command::Checkout, &[n("a..b")]), RULE_NAME);
    assert_eq!(
        refused(Command::Checkout, &[n("refs/heads/a.lock")]),
        RULE_NAME
    );
    assert_eq!(refused(Command::Checkout, &[n("-b")]), RULE_NAME);
    assert_eq!(refused(Command::Checkout, &[w("--detach")]), RULE_MISSING);
    assert_eq!(
        refused(Command::Checkout, &[w("--detach"), n("main")]),
        RULE_TYPE
    );
    assert_eq!(
        refused(Command::Checkout, &[w("--detach"), p("a")]),
        RULE_TYPE
    );
    assert_eq!(
        refused(Command::Checkout, &[w("--detach"), r("a"), r("b")]),
        RULE_FORM
    );
    assert_eq!(
        refused(Command::Checkout, &[w("--detach"), r("a"), w("--")]),
        RULE_FORM
    );
    assert_eq!(
        refused(Command::Checkout, &[w("--detach"), r("a@{1}")]),
        RULE_REVISION
    );
    assert_eq!(refused(Command::Checkout, &[r("a")]), RULE_MISSING);
    assert_eq!(
        refused(Command::Checkout, &[r("a"), w("--")]),
        RULE_SEPARATOR
    );
    assert_eq!(
        refused(Command::Checkout, &[r("a"), p("x")]),
        RULE_SEPARATOR
    );
    assert_eq!(
        refused(Command::Checkout, &[r("a"), w("--"), p("x"), r("b")]),
        RULE_FORM
    );
    assert_eq!(
        refused(Command::Checkout, &[r("a:x"), w("--"), p("x")]),
        RULE_REVISION
    );
    assert_eq!(refused(Command::Checkout, &[w("--")]), RULE_SEPARATOR);
    assert_eq!(refused(Command::Checkout, &[p("a")]), RULE_SEPARATOR);
    assert_eq!(
        refused(Command::Checkout, &[w("--"), p("a"), w("--detach")]),
        RULE_OPTION_UNLISTED
    );
    assert_eq!(refused(Command::Checkout, &[Arg::Count(1)]), RULE_TYPE);
    assert_eq!(refused(Command::Checkout, &[o(OID)]), RULE_TYPE);
    assert_eq!(refused(Command::Checkout, &[rn("refs/heads/a")]), RULE_TYPE);
    assert_eq!(
        refused(Command::Checkout, &[range("a", Dots::Two, "b")]),
        RULE_TYPE
    );
}

// add

#[test]
fn add_takes_paths_after_the_separator() {
    let line = accepted(Command::Add, &[w("--"), p("a"), p("b/c.txt"), p(".")]);
    assert_eq!(line.argv, strings(&["add", "--", "a", "b/c.txt", "."]));
    assert_eq!(line.writes, Writes::Yes);
    assert!(line.checks.is_empty());
}

#[test]
fn add_refusals() {
    assert_eq!(refused(Command::Add, &[]), RULE_MISSING);
    assert_eq!(refused(Command::Add, &[w("--")]), RULE_SEPARATOR);
    assert_eq!(refused(Command::Add, &[p("a")]), RULE_SEPARATOR);
    assert_eq!(refused(Command::Add, &[w("--"), r("HEAD")]), RULE_SEPARATOR);
    assert_eq!(
        refused(Command::Add, &[w("--"), p("a"), r("HEAD")]),
        RULE_FORM
    );
    assert_eq!(
        refused(Command::Add, &[w("--"), p("a"), w("-n")]),
        RULE_OPTION_REFUSED
    );
    assert_eq!(
        refused(Command::Add, &[w("--"), p("a"), w("--")]),
        RULE_FORM
    );
    assert_eq!(
        refused(Command::Add, &[w("-v"), w("--"), p("a")]),
        RULE_OPTION_REFUSED
    );
    assert_eq!(refused(Command::Add, &[Arg::Count(1)]), RULE_MISSING);
}

// update-ref

#[test]
fn update_ref_takes_a_reference_and_two_identifiers_with_an_optional_message() {
    let line = accepted(
        Command::UpdateRef,
        &[rn("refs/heads/main"), o(OID), o(OID2)],
    );
    assert_eq!(line.argv, with(UPDATE_REF, &["refs/heads/main", OID, OID2]));
    assert_eq!(line.writes, Writes::Yes);
    assert_eq!(
        line.checks,
        vec![
            Check::OperationState,
            Check::ImplicitHead,
            Check::NotSymbolic {
                refname: "refs/heads/main".to_owned()
            }
        ]
    );
    let line = accepted(
        Command::UpdateRef,
        &[
            w("-m"),
            m("move the branch"),
            rn("refs/heads/a/b"),
            o(OID),
            o(OID2),
        ],
    );
    assert_eq!(
        line.argv,
        with(
            UPDATE_REF,
            &["-m", "move the branch", "refs/heads/a/b", OID, OID2]
        )
    );
}

#[test]
fn update_ref_refusals() {
    let good = || vec![rn("refs/heads/main"), o(OID), o(OID2)];
    for missing in 0..3 {
        let mut args = good();
        args.truncate(missing);
        assert_eq!(
            refused(Command::UpdateRef, &args),
            RULE_MISSING,
            "{missing}"
        );
    }
    let mut extra = good();
    extra.push(o(OID));
    assert_eq!(refused(Command::UpdateRef, &extra), RULE_FORM);
    for bad in [
        "refs/tags/a",
        "refs/remotes/o/a",
        "HEAD",
        "refs/heads/",
        "refs/heads/a..b",
        "refs/heads//a",
        "main",
        "refs/replace/a",
    ] {
        assert_eq!(
            refused(Command::UpdateRef, &[rn(bad), o(OID), o(OID2)]),
            RULE_REFNAME,
            "{bad}"
        );
    }
    for bad in [&OID[..39], &format!("{OID}0"), "xyz"] {
        assert_eq!(
            refused(Command::UpdateRef, &[rn("refs/heads/a"), o(bad), o(OID2)]),
            RULE_OID
        );
        assert_eq!(
            refused(Command::UpdateRef, &[rn("refs/heads/a"), o(OID), o(bad)]),
            RULE_OID
        );
    }
    assert_eq!(
        refused(Command::UpdateRef, &[rn("refs/heads/a"), o(ZERO), o(OID2)]),
        RULE_OID_ZERO
    );
    assert_eq!(
        refused(Command::UpdateRef, &[rn("refs/heads/a"), o(OID), o(ZERO)]),
        RULE_OID_ZERO
    );
    // Types: a revision, a name, a path or a word where each element belongs.
    assert_eq!(
        refused(Command::UpdateRef, &[r("HEAD"), o(OID), o(OID2)]),
        RULE_TYPE
    );
    assert_eq!(
        refused(Command::UpdateRef, &[n("main"), o(OID), o(OID2)]),
        RULE_TYPE
    );
    assert_eq!(
        refused(Command::UpdateRef, &[rn("refs/heads/a"), r(OID), o(OID2)]),
        RULE_TYPE
    );
    assert_eq!(
        refused(Command::UpdateRef, &[rn("refs/heads/a"), o(OID), p(OID2)]),
        RULE_TYPE
    );
    assert_eq!(
        refused(
            Command::UpdateRef,
            &[w("--"), rn("refs/heads/a"), o(OID), o(OID2)]
        ),
        RULE_TYPE
    );
    // The message: one line, 200 bytes, a message type.
    let tail = [rn("refs/heads/a"), o(OID), o(OID2)];
    let with_message = |message: Arg| {
        let mut args = vec![w("-m"), message];
        args.extend(tail.clone());
        args
    };
    assert!(parse(Command::UpdateRef, &with_message(m(&"x".repeat(200)))).is_ok());
    assert_eq!(
        refused(Command::UpdateRef, &with_message(m(&"x".repeat(201)))),
        RULE_MESSAGE_LENGTH
    );
    assert_eq!(
        refused(Command::UpdateRef, &with_message(m("a\nb"))),
        RULE_MESSAGE_LINES
    );
    assert_eq!(
        refused(Command::UpdateRef, &with_message(m(""))),
        RULE_MESSAGE_LINES
    );
    assert_eq!(
        refused(Command::UpdateRef, &with_message(p("a"))),
        RULE_TYPE
    );
    let mut repeated = with_message(m("a"));
    repeated.splice(0..0, [w("-m"), m("b")]);
    assert_eq!(refused(Command::UpdateRef, &repeated), RULE_OPTION_REPEATED);
    assert_eq!(refused(Command::UpdateRef, &[w("-m")]), RULE_OPTION_VALUE);
    assert_eq!(
        refused(
            Command::UpdateRef,
            &[w("-mfix"), rn("refs/heads/a"), o(OID), o(OID2)]
        ),
        RULE_OPTION_UNLISTED
    );
    assert_eq!(
        refused(
            Command::UpdateRef,
            &[w("-m=fix"), rn("refs/heads/a"), o(OID), o(OID2)]
        ),
        RULE_OPTION_SPELLING
    );
}

// commit

#[test]
fn commit_takes_one_message_and_its_options() {
    let line = accepted(Command::Commit, &[w("-m"), m("subject\n\nbody")]);
    assert_eq!(line.argv, with(COMMIT, &["-m", "subject\n\nbody"]));
    assert_eq!(line.writes, Writes::Yes);
    assert_eq!(
        line.checks,
        vec![Check::OperationState, Check::ImplicitHead]
    );
    for (args, expected) in [
        (vec![w("-q"), w("-m"), m("x")], vec!["-q", "-m", "x"]),
        (
            vec![w("--quiet"), w("-m"), m("x")],
            vec!["--quiet", "-m", "x"],
        ),
        (
            vec![w("--allow-empty"), w("-m"), m("x")],
            vec!["--allow-empty", "-m", "x"],
        ),
        (
            vec![w("-m"), m("x"), w("-q"), w("--allow-empty")],
            vec!["-m", "x", "-q", "--allow-empty"],
        ),
        (
            vec![w("-q"), w("--quiet"), w("--allow-empty"), w("-m"), m("x")],
            vec!["-q", "--quiet", "--allow-empty", "-m", "x"],
        ),
    ] {
        assert_eq!(
            accepted(Command::Commit, &args).argv,
            with(COMMIT, &expected),
            "{args:?}"
        );
    }
    // A message that starts with a hash stays whole: the cleanup mode is a fixed word.
    assert_eq!(
        accepted(Command::Commit, &[w("-m"), m("# not a comment")]).argv,
        with(COMMIT, &["-m", "# not a comment"])
    );
    assert_eq!(
        accepted(
            Command::Commit,
            &[w("-m"), m("see https://x/y.git\twith\ttabs")]
        )
        .argv,
        with(COMMIT, &["-m", "see https://x/y.git\twith\ttabs"])
    );
    assert_eq!(
        accepted(Command::Commit, &[w("-m"), m("--amend")]).argv,
        with(COMMIT, &["-m", "--amend"])
    );
}

#[test]
fn commit_refusals() {
    assert_eq!(refused(Command::Commit, &[]), RULE_MISSING);
    assert_eq!(refused(Command::Commit, &[w("-q")]), RULE_MISSING);
    assert_eq!(refused(Command::Commit, &[w("-m")]), RULE_OPTION_VALUE);
    assert_eq!(refused(Command::Commit, &[w("-m"), w("-q")]), RULE_TYPE);
    assert_eq!(refused(Command::Commit, &[w("-m"), p("x")]), RULE_TYPE);
    assert_eq!(
        refused(Command::Commit, &[w("-m"), m("a"), w("-m"), m("b")]),
        RULE_OPTION_REPEATED
    );
    assert_eq!(
        refused(Command::Commit, &[w("-q"), w("-q"), w("-m"), m("a")]),
        RULE_OPTION_REPEATED
    );
    assert_eq!(
        refused(Command::Commit, &[w("-m"), m("a"), w("--"), p("f")]),
        RULE_FORM
    );
    assert_eq!(
        refused(Command::Commit, &[w("-m"), m("a"), p("f")]),
        RULE_FORM
    );
    assert_eq!(
        refused(Command::Commit, &[w("-m"), m("a"), r("HEAD")]),
        RULE_FORM
    );
    assert_eq!(
        refused(Command::Commit, &[w("-m"), m("a"), w("--")]),
        RULE_FORM
    );
    assert_eq!(refused(Command::Commit, &[w("-ma")]), RULE_OPTION_UNLISTED);
    assert_eq!(
        refused(Command::Commit, &[w("-qm"), m("a")]),
        RULE_OPTION_UNLISTED
    );
    assert_eq!(
        refused(Command::Commit, &[w("--message"), m("a")]),
        RULE_OPTION_UNLISTED
    );
    assert_eq!(
        refused(Command::Commit, &[w("--message=a")]),
        RULE_OPTION_UNLISTED
    );
    assert_eq!(
        refused(Command::Commit, &[w("--allow-empty=1"), w("-m"), m("a")]),
        RULE_OPTION_SPELLING
    );
    assert_eq!(refused(Command::Commit, &[w("-m=a")]), RULE_OPTION_SPELLING);
    // The message: 8,192 bytes, no control but tab and newline, a first line that is not empty.
    let at_bound = "x".repeat(MAX_MESSAGE_BYTES);
    assert!(parse(Command::Commit, &[w("-m"), m(&at_bound)]).is_ok());
    assert_eq!(
        refused(
            Command::Commit,
            &[w("-m"), m(&"x".repeat(MAX_MESSAGE_BYTES + 1))]
        ),
        RULE_MESSAGE_LENGTH
    );
    assert_eq!(
        refused(Command::Commit, &[w("-m"), m("")]),
        RULE_MESSAGE_LINES
    );
    assert_eq!(
        refused(Command::Commit, &[w("-m"), m("\nbody")]),
        RULE_MESSAGE_LINES
    );
    assert!(parse(Command::Commit, &[w("-m"), m("a\n")]).is_ok());
    for control in ['\r', '\u{0}', '\u{1}', '\u{1f}', '\u{7f}', '\u{8}'] {
        let message = format!("a{control}b");
        assert_eq!(
            refused(Command::Commit, &[w("-m"), m(&message)]),
            RULE_CONTROL,
            "{control:?}"
        );
    }
}

// Names the tables refuse.

fn refused_names(command: Command) -> &'static [&'static str] {
    match command {
        Command::RevParse => &[
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
        Command::Status => &[
            "--ignore-submodules",
            "--short",
            "--long",
            "--column",
            "--show-stash",
            "--find-renames",
            "--ahead-behind",
        ],
        Command::Diff => &[
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
        Command::Log => &[
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
        Command::Checkout => &[
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
        Command::Add => &[
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
        Command::UpdateRef => &[
            "-d",
            "--stdin",
            "-z",
            "--create-reflog",
            "--no-create-reflog",
        ],
        Command::Commit => &[
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
    }
}

/// A line that is accepted with the extra words inserted where options belong.
fn base(command: Command, extra: Vec<Arg>) -> Vec<Arg> {
    let tail: Vec<Arg> = match command {
        Command::RevParse => vec![r("HEAD")],
        Command::Status => vec![w("--porcelain=v2")],
        Command::Diff | Command::Log => vec![],
        Command::Checkout | Command::Add => vec![w("--"), p("a")],
        Command::UpdateRef => vec![rn("refs/heads/a"), o(OID), o(OID2)],
        Command::Commit => vec![w("-m"), m("x")],
    };
    extra.into_iter().chain(tail).collect()
}

#[test]
fn every_option_a_table_refuses_by_name_is_refused_with_its_own_rule() {
    for command in tables::COMMANDS {
        let listed = refused_names(command);
        assert_eq!(tables::table(command).refused, listed, "{command:?}");
        for name in listed {
            let expected = if GLOBAL_REFUSED.contains(name) {
                RULE_OPTION_GLOBAL
            } else {
                RULE_OPTION_REFUSED
            };
            assert_eq!(
                refused(command, &base(command, vec![w(name)])),
                expected,
                "{command:?} {name}"
            );
            // With a value attached, the name is still the name.
            if name.starts_with("--") {
                let attached = format!("{name}=x");
                let line = base(command, vec![w(&attached)]);
                assert_eq!(refused(command, &line), expected, "{command:?} {attached}");
            }
        }
    }
}

#[test]
fn the_options_no_command_takes_are_refused_for_every_command() {
    let global = [
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
    assert_eq!(GLOBAL_REFUSED, global);
    for command in tables::COMMANDS {
        for name in global {
            // `--git-dir` alone is also the word of `rev-parse` that prints it.
            if command == Command::RevParse && name == "--git-dir" {
                assert!(parse(command, &[w(name)]).is_ok());
                continue;
            }
            assert_eq!(
                refused(command, &base(command, vec![w(name)])),
                RULE_OPTION_GLOBAL,
                "{command:?} {name}"
            );
            let attached = format!("{name}=x");
            assert_eq!(
                refused(command, &base(command, vec![w(&attached)])),
                RULE_OPTION_GLOBAL,
                "{command:?} {attached}"
            );
        }
    }
    assert_eq!(
        refused(Command::RevParse, &[w("--git-dir=x")]),
        RULE_OPTION_GLOBAL
    );
}

#[test]
fn an_abbreviation_a_case_change_a_cluster_and_a_negation_are_refused() {
    for command in tables::COMMANDS {
        let table = tables::table(command);
        for row in table.options {
            if row.name == "-" {
                continue;
            }
            // Every proper prefix of a long option, longer than the dashes.
            if row.name.starts_with("--") {
                for end in 3..row.name.len() {
                    let prefix = &row.name[..end];
                    let line = base(command, vec![w(prefix)]);
                    assert!(
                        parse(command, &line).is_err() || listed_name(table, prefix),
                        "{command:?} accepted the abbreviation {prefix}"
                    );
                }
            }
            let upper = row.name.to_ascii_uppercase();
            if upper != row.name && !listed_name(table, &upper) {
                assert!(
                    parse(command, &base(command, vec![w(&upper)])).is_err(),
                    "{upper}"
                );
            }
            let negation = row.name.replacen("--", "--no-", 1);
            if negation != row.name && !listed_name(table, &negation) {
                assert!(
                    parse(command, &base(command, vec![w(&negation)])).is_err(),
                    "{negation}"
                );
            }
        }
        // Two short options in one element.
        for first in table
            .options
            .iter()
            .filter(|row| row.name.len() == 2 && row.form == Form::Flag)
        {
            for second in table
                .options
                .iter()
                .filter(|row| row.name.len() == 2 && row.form == Form::Flag)
            {
                let cluster = format!("-{}{}", &first.name[1..], &second.name[1..]);
                assert!(
                    parse(command, &base(command, vec![w(&cluster)])).is_err(),
                    "{command:?} accepted the cluster {cluster}"
                );
            }
        }
    }
    assert_eq!(
        refused(Command::Commit, &[w("-qn"), w("-m"), m("a")]),
        RULE_OPTION_UNLISTED
    );
    assert_eq!(
        refused(Command::Status, &[w("--porcelain=v2"), w("--branche")]),
        RULE_OPTION_UNLISTED
    );
    assert_eq!(
        refused(Command::Status, &[w("--porcelain=v2"), w("--no-branch")]),
        RULE_OPTION_UNLISTED
    );
    assert_eq!(
        refused(Command::Status, &[w("--Porcelain=v2")]),
        RULE_OPTION_UNLISTED
    );
}

fn listed_name(table: &tables::Table, word: &str) -> bool {
    table.options.iter().any(|row: &Row| row.name == word)
}

/// The names of an option, whatever its spelling.
fn option_name(word: &str) -> String {
    let name = word.split('=').next().unwrap_or(word);
    if name.len() > 2 && name.starts_with("-U") {
        return "-U".to_owned();
    }
    if name.len() > 1 && name[1..].bytes().all(|b| b.is_ascii_digit()) {
        return "-".to_owned();
    }
    name.to_owned()
}

#[test]
fn no_accepted_line_holds_an_option_outside_its_table() {
    // Every word that names any option of any table, in every spelling a request could try.
    let mut candidates: Vec<String> = Vec::new();
    for command in tables::COMMANDS {
        let table = tables::table(command);
        for row in table.options {
            candidates.push(row.name.to_owned());
            for end in 2..row.name.len() {
                candidates.push(row.name[..end].to_owned());
            }
            candidates.push(row.name.to_ascii_uppercase());
            candidates.push(format!("{}=v2", row.name));
            candidates.push(format!("{}3", row.name));
            candidates.push(format!("{}=3", row.name));
        }
        for name in table.refused {
            for end in 2..=name.len() {
                candidates.push(name[..end].to_owned());
            }
            candidates.push(name.to_ascii_uppercase());
        }
        candidates.extend(table.always.iter().map(|name| (*name).to_owned()));
    }
    candidates.extend(GLOBAL_REFUSED.iter().map(|name| (*name).to_owned()));
    candidates.extend(INTROSPECTION.iter().map(|name| (*name).to_owned()));
    candidates.extend(
        [
            "-5",
            "-1000",
            "-U0",
            "--unified=9",
            "--short=9",
            "--max-count=9",
            "-qm",
            "--no-verify",
            "--end-of-options",
            "-",
            "--",
            "---",
            "-x",
        ]
        .map(str::to_owned),
    );
    candidates.sort();
    candidates.dedup();
    assert!(candidates.len() > 150, "{}", candidates.len());

    let mut accepted_words = 0;
    for command in tables::COMMANDS {
        let table = tables::table(command);
        let allowed: Vec<String> = table
            .options
            .iter()
            .map(|row| row.name.to_owned())
            .chain(["--".to_owned()])
            .collect();
        for candidate in &candidates {
            for line in [
                base(command, vec![w(candidate)]),
                base(command, vec![w(candidate), w("--short=8")]),
                vec![w(candidate)],
            ] {
                let Ok(parsed) = parse(command, &line) else {
                    continue;
                };
                // Nothing that is not one of the table's own words is in the line.
                let introspection =
                    command == Command::RevParse && INTROSPECTION.contains(&candidate.as_str());
                if !introspection {
                    assert!(
                        allowed.contains(&option_name(candidate)),
                        "{command:?} accepted {candidate:?} as {:?}",
                        parsed.argv
                    );
                }
                accepted_words += 1;
                let fixed: Vec<&str> = std::iter::once(table.name)
                    .chain(table.always.iter().copied())
                    .collect();
                let mut after_separator = false;
                let mut skip = false;
                for element in &parsed.argv {
                    if skip {
                        skip = false;
                        continue;
                    }
                    if element == "--" {
                        after_separator = true;
                        continue;
                    }
                    if after_separator
                        || fixed.contains(&element.as_str())
                        || !element.starts_with('-')
                    {
                        continue;
                    }
                    if element == "-m" {
                        skip = true;
                    }
                    let name = option_name(element);
                    assert!(
                        allowed.contains(&name)
                            || (introspection && element == candidate)
                            || element == "--detach",
                        "{command:?}: {element:?} of {:?} is in no table row",
                        parsed.argv
                    );
                }
            }
        }
    }
    assert!(accepted_words > 50, "{accepted_words}");
}

// Types, controls, arguments

#[test]
fn an_element_that_is_not_the_type_of_its_position_is_refused() {
    assert_eq!(
        refused(Command::Status, &[w("--porcelain=v2"), w("--"), n("a")]),
        RULE_SEPARATOR
    );
    assert_eq!(refused(Command::Add, &[w("--"), r("HEAD")]), RULE_SEPARATOR);
    assert_eq!(refused(Command::Commit, &[w("-m"), o(OID)]), RULE_TYPE);
    assert_eq!(
        refused(Command::Log, &[w("--format"), Arg::Count(5)]),
        RULE_TYPE
    );
    assert_eq!(refused(Command::Log, &[Arg::Count(5)]), RULE_FORM);
    assert_eq!(refused(Command::Diff, &[o(OID)]), RULE_FORM);
    assert_eq!(refused(Command::Diff, &[rn("refs/heads/a")]), RULE_FORM);
    assert_eq!(refused(Command::Diff, &[m("x")]), RULE_FORM);
    assert_eq!(refused(Command::RevParse, &[o(OID)]), RULE_MISSING);
}

#[test]
fn no_element_holds_a_control_character_but_a_message_a_tab_or_a_newline() {
    for control in ['\u{0}', '\u{1}', '\t', '\n', '\r', '\u{1f}', '\u{7f}'] {
        let bad = format!("a{control}b");
        assert_eq!(
            refused(Command::Add, &[w("--"), p(&bad)]),
            RULE_CONTROL,
            "{control:?}"
        );
        assert_eq!(
            refused(Command::Diff, &[r(&bad)]),
            RULE_CONTROL,
            "{control:?}"
        );
        assert_eq!(
            refused(Command::Checkout, &[n(&bad)]),
            RULE_CONTROL,
            "{control:?}"
        );
        assert_eq!(
            refused(Command::UpdateRef, &[rn(&bad), o(OID), o(OID2)]),
            RULE_CONTROL,
            "{control:?}"
        );
        assert_eq!(
            refused(Command::UpdateRef, &[rn("refs/heads/a"), o(&bad), o(OID2)]),
            RULE_CONTROL,
            "{control:?}"
        );
        assert_eq!(
            refused(Command::Status, &[w(&bad)]),
            RULE_CONTROL,
            "{control:?}"
        );
        assert_eq!(
            refused(Command::Diff, &[range(&bad, Dots::Two, "b")]),
            RULE_CONTROL,
            "{control:?}"
        );
        assert_eq!(
            refused(Command::Diff, &[range("a", Dots::Two, &bad)]),
            RULE_CONTROL,
            "{control:?}"
        );
    }
    // A control character is refused wherever it stands in the list, before any other rule.
    assert_eq!(
        refused(Command::Add, &[w("--"), p("a"), p("b"), p("c\u{1}")]),
        RULE_CONTROL
    );
    assert_eq!(
        refused(Command::Status, &[w("--bogus"), p("a\u{1}")]),
        RULE_CONTROL
    );
}

#[test]
fn the_list_of_arguments_is_bounded_at_the_frames_own_limit() {
    let paths = |count: usize| {
        let mut args = vec![w("--")];
        args.extend((0..count).map(|_| p("a")));
        args
    };
    // 1 + 256 paths is under the argument limit; 513 elements is over it.
    assert!(parse(Command::Add, &paths(MAX_PATHS)).is_ok());
    let mut over = vec![w("-q"); MAX_ARGUMENTS + 1];
    over.push(w("-q"));
    assert_eq!(refused(Command::Commit, &over), RULE_ARGUMENTS);
    let exactly = vec![w("-q"); MAX_ARGUMENTS];
    assert_ne!(refused(Command::Commit, &exactly), RULE_ARGUMENTS);
}

// Bounds

#[test]
fn the_number_of_paths_is_bounded_for_every_command_that_takes_them() {
    let paths = |count: usize, lead: Vec<Arg>| {
        let mut args = lead;
        args.push(w("--"));
        args.extend((0..count).map(|at| p(&format!("f{at}"))));
        args
    };
    for (command, lead) in [
        (Command::Add, vec![]),
        (Command::Status, vec![w("--porcelain=v2")]),
        (Command::Diff, vec![]),
        (Command::Log, vec![]),
        (Command::Checkout, vec![]),
        (Command::Checkout, vec![r("HEAD")]),
    ] {
        assert!(
            parse(command, &paths(MAX_PATHS, lead.clone())).is_ok(),
            "{command:?}"
        );
        assert!(
            parse(command, &paths(1, lead.clone())).is_ok(),
            "{command:?}"
        );
        assert_eq!(
            refused(command, &paths(MAX_PATHS + 1, lead.clone())),
            RULE_PATHS,
            "{command:?}"
        );
        assert_eq!(
            refused(command, &paths(0, lead)),
            RULE_SEPARATOR,
            "{command:?}"
        );
    }
}

#[test]
fn a_path_is_bounded_in_bytes_and_in_components() {
    let add = |path: &str| parse(Command::Add, &[w("--"), p(path)]);
    let bytes = |len: usize| "a".repeat(len);
    assert!(add(&bytes(MAX_PATH_BYTES)).is_ok());
    assert_eq!(
        refused(Command::Add, &[w("--"), p(&bytes(MAX_PATH_BYTES + 1))]),
        RULE_PATH_LENGTH
    );
    // 240 bytes with 32 components: 31 of 7 bytes and slashes make 31 * 8 + ... keep it simple.
    let components = |count: usize| vec!["d"; count].join("/");
    assert!(add(&components(MAX_PATH_COMPONENTS)).is_ok());
    assert_eq!(
        refused(
            Command::Add,
            &[w("--"), p(&components(MAX_PATH_COMPONENTS + 1))]
        ),
        RULE_PATH_DEPTH
    );
    // The byte bound is on bytes, not characters.
    let wide = "é".repeat(MAX_PATH_BYTES / 2);
    assert_eq!(wide.len(), MAX_PATH_BYTES);
    assert!(add(&wide).is_ok());
    assert_eq!(
        refused(Command::Add, &[w("--"), p(&format!("{wide}a"))]),
        RULE_PATH_LENGTH
    );
}

#[test]
fn a_path_is_relative_with_forward_slashes_and_ordinary_components() {
    for good in [
        ".",
        "a",
        "a/b",
        "a b/c d",
        "a[1]/b",
        "a.b",
        ".hidden",
        "a-b_c",
        "é/ü",
        "x~1",
        "git",
        ".gitignore",
        ".gitattributes",
        "..a",
        "a..",
        "a./b",
        "gitx~1",
        "git~",
        "git~x",
        "con1",
        "conx",
        "comx",
        "com0",
        "com10",
        "lpt0",
        "lptx",
        "aux1",
        "nulx",
        "prn1",
        "c0n",
        "gi",
        "git-x",
        "a#b",
        "a'b",
        "a&b",
        "a(b)",
    ] {
        // `a..` and `a./b` end in a dot: refused below; the others are fine.
        let result = parse(Command::Add, &[w("--"), p(good)]);
        if good != "." && good.split('/').any(|c| c.ends_with('.')) {
            assert!(result.is_err(), "{good}");
        } else {
            assert!(result.is_ok(), "{good}: {result:?}");
        }
    }
    for bad in [
        "",
        "/",
        "/a",
        "a/",
        "a//b",
        "./a",
        "a/./b",
        "a/.",
        "..",
        "../a",
        "a/..",
        "a/../b",
        "a\\b",
        "\\a",
        "C:x",
        "C:/a",
        "a:b",
        "a/b:c",
        "a*",
        "a?",
        "a\"b",
        "a<b",
        "a>b",
        "a|b",
        "a.",
        "a ",
        "a/b.",
        "a/b ",
        ".git",
        ".GIT",
        ".Git",
        "a/.git",
        "a/.git/b",
        "git~1",
        "GIT~1",
        "git~2",
        "git~10",
        "a/git~1/b",
        ".git ",
        ".git.",
        ".git::$INDEX_ALLOCATION",
        "CON",
        "con",
        "Con.txt",
        "PRN",
        "AUX",
        "NUL",
        "nul.txt",
        "a/nul.tar.gz",
        "COM1",
        "com9",
        "Com5.x",
        "LPT1",
        "lpt9",
        "Lpt3.log",
        "con .txt",
        "\\\\?\\C:\\a",
        "\\\\.\\x",
        "//server/share",
        "a/b/CON",
    ] {
        assert_eq!(
            refused(Command::Add, &[w("--"), p(bad)]),
            RULE_PATH,
            "{bad:?}"
        );
    }
}

#[test]
fn a_dot_is_the_root_and_the_only_use_of_a_dot() {
    for command_args in [
        (Command::Add, vec![w("--"), p(".")]),
        (Command::Status, vec![w("--porcelain=v2"), w("--"), p(".")]),
        (Command::Checkout, vec![w("--"), p(".")]),
    ] {
        assert!(parse(command_args.0, &command_args.1).is_ok());
    }
    assert_eq!(refused(Command::Add, &[w("--"), p("./")]), RULE_PATH);
    assert_eq!(refused(Command::Add, &[w("--"), p("..")]), RULE_PATH);
    assert_eq!(refused(Command::Add, &[w("--"), p("...")]), RULE_PATH);
}

#[test]
fn a_revision_is_head_a_branch_or_an_identifier_with_a_bounded_chain_of_steps() {
    let ok = |text: &str| parse(Command::RevParse, &[r(text)]);
    for good in [
        "HEAD",
        "main",
        "feature/x",
        "a.b-c_d",
        OID,
        "HEAD^",
        "HEAD^^",
        "HEAD^{commit}",
        "HEAD~1",
        "HEAD~1000",
        "HEAD^1",
        "HEAD^2",
        "HEAD^1000",
        "main~3^2",
        "main^{commit}~2",
        "HEAD~1^^{commit}~2",
        "HEAD^^^^",
        "HEAD~1~1~1~1",
    ] {
        assert!(ok(good).is_ok(), "{good}: {:?}", ok(good));
    }
    assert_eq!(MAX_REVISION_STEPS, 4);
    for bad in [
        "HEAD^^^^^",
        "HEAD~1~1~1~1~1",
        "HEAD~",
        "HEAD~0",
        "HEAD~01",
        "HEAD~1001",
        "HEAD~-1",
        "HEAD~x",
        "HEAD^0",
        "HEAD^01",
        "HEAD^1001",
        "HEAD^{tree}",
        "HEAD^{/x}",
        "HEAD^{commit",
        "HEAD^{commit}x",
        "HEAD^@",
        "HEAD^!",
        "HEAD^-",
        "HEAD@{1}",
        "HEAD@{u}",
        "@",
        "@{1}",
        "HEAD:file",
        ":/msg",
        ":path",
        "HEAD:",
        "main:a",
        "a..b",
        "a...b",
        "origin/main^{}",
        "-x",
        "--all",
        "",
        "^",
        "~1",
        "^main",
        "!main",
        "main ",
        " main",
        "ma in",
        "main\u{a0}",
        "HEAD^{commit}^{commit}^{commit}^{commit}^{commit}",
        "main.lock",
        "a//b",
        "/a",
        "a/",
        "0123456789abcdef0123456789abcdef012345678~x",
        "v1.0^{tag}",
    ] {
        let rule = refused(Command::RevParse, &[r(bad)]);
        assert!(
            rule == RULE_REVISION || rule == RULE_CONTROL,
            "{bad:?}: {rule}"
        );
    }
    // A name that is not an identifier is a branch, even when it looks like a reference or a
    // tag: it is qualified under `refs/heads/`, so a tag has no spelling.
    for name in [
        "refs/heads/main",
        "refs/tags/v1",
        "0123456789ABCDEF0123456789abcdef01234567",
        "0123456789abcdef0123456789abcdef0123456",
    ] {
        assert_eq!(
            accepted(Command::RevParse, &[r(name)]).argv,
            strings(&["rev-parse", &format!("refs/heads/{name}")])
        );
    }
    // A branch named like an identifier is the identifier, and a branch named HEAD is HEAD.
    assert_eq!(
        accepted(Command::RevParse, &[r(OID)]).argv,
        strings(&["rev-parse", OID])
    );
    assert_eq!(
        accepted(Command::RevParse, &[r("HEAD")]).argv,
        strings(&["rev-parse", "HEAD"])
    );
    // The bound on bytes.
    let long = format!("a{}", "b".repeat(MAX_REV_BYTES - 1));
    let rule = refused(Command::RevParse, &[r(&format!("{long}c"))]);
    assert_eq!(rule, RULE_REVISION_LENGTH);
    // A name of 200 bytes is a revision; 201 is not.
    let name = |len: usize| "n".repeat(len);
    assert!(ok(&name(MAX_NAME_BYTES)).is_ok());
    assert_eq!(
        refused(Command::RevParse, &[r(&name(MAX_NAME_BYTES + 1))]),
        RULE_REVISION
    );
    // 240 bytes in all with steps: 200 of name and 40 of steps.
    let stepped = format!("{}{}", name(MAX_NAME_BYTES), "^".repeat(4));
    assert!(ok(&stepped).is_ok());
    let over = format!("{}~1000~1000~1000~1000", name(MAX_NAME_BYTES));
    assert_eq!(over.len(), MAX_NAME_BYTES + 20);
    assert!(ok(&over).is_ok());
    let beyond = format!("{}{}", name(MAX_REV_BYTES - 3), "^^^^");
    assert_eq!(
        refused(Command::RevParse, &[r(&beyond)]),
        RULE_REVISION_LENGTH
    );
}

#[test]
fn a_name_and_a_reference_are_bounded() {
    let switch = |name: &str| parse(Command::Checkout, &[n(name)]);
    let exactly = "n".repeat(MAX_NAME_BYTES);
    assert!(switch(&exactly).is_ok());
    assert_eq!(
        refused(Command::Checkout, &[n(&format!("{exactly}n"))]),
        RULE_NAME
    );
    for bad in [
        "", "a b", "a..b", "a//b", "/a", "a/", "a.", "a.lock", "a/b.lock", ".a", "a/.b", "-a",
        "a@{1}", "a~1", "a^", "a:b", "a?b", "a*b", "a[b", "a\\b",
    ] {
        assert_eq!(refused(Command::Checkout, &[n(bad)]), RULE_NAME, "{bad:?}");
    }
    for good in [
        "a",
        "a.b",
        "a_b",
        "a-b",
        "0",
        "feature/x/y",
        "a.lockx",
        "A/B",
    ] {
        assert!(switch(good).is_ok(), "{good}");
    }
    let refname = |name: &str| parse(Command::UpdateRef, &[rn(name), o(OID), o(OID2)]);
    let full = format!("refs/heads/{}", "n".repeat(MAX_NAME_BYTES));
    assert_eq!(full.len(), MAX_REF_NAME_BYTES);
    assert!(refname(&full).is_ok());
    assert_eq!(
        refused(
            Command::UpdateRef,
            &[rn(&format!("{full}n")), o(OID), o(OID2)]
        ),
        RULE_REFNAME
    );
}

#[test]
fn a_format_is_bounded_in_parts_and_in_text() {
    let format = |parts: Vec<Part>| parse(Command::Log, &[w("--format"), custom(parts)]);
    let parts = |count: usize| vec![Part::Placeholder(Placeholder::Newline); count];
    assert!(format(parts(MAX_FORMAT_PARTS)).is_ok());
    assert_eq!(
        refused(
            Command::Log,
            &[w("--format"), custom(parts(MAX_FORMAT_PARTS + 1))]
        ),
        RULE_FORMAT
    );
    assert!(format(vec![text(&"x".repeat(MAX_FORMAT_TEXT_BYTES))]).is_ok());
    assert_eq!(
        refused(
            Command::Log,
            &[
                w("--format"),
                custom(vec![text(&"x".repeat(MAX_FORMAT_TEXT_BYTES + 1))])
            ]
        ),
        RULE_FORMAT
    );
}

// What the readers resolve.

#[test]
fn the_identifiers_the_readers_return_take_the_place_of_the_revisions() {
    let line = accepted(Command::Diff, &[w("--cached"), r("main"), r("HEAD~1")]);
    let one = "1".repeat(40);
    let two = "2".repeat(40);
    assert_eq!(
        line.resolved(&[one.clone(), two.clone()]).unwrap(),
        with(DIFF, &["--cached", &one, &two])
    );
    let line = accepted(Command::Log, &[range("a", Dots::Two, "b"), w("--"), p("x")]);
    assert_eq!(
        line.resolved(&[one.clone(), two.clone()]).unwrap(),
        with(LOG, &[&format!("{one}..{two}"), "--", "x"])
    );
    let line = accepted(Command::Log, &[range("a", Dots::Three, "b")]);
    assert_eq!(
        line.resolved(&[one.clone(), two.clone()]).unwrap(),
        with(LOG, &[&format!("{one}...{two}")])
    );
    // The switch resolves its branch and keeps the name: one identifier, no replacement.
    let line = accepted(Command::Checkout, &[n("main")]);
    assert_eq!(
        line.resolved(std::slice::from_ref(&one)).unwrap(),
        line.argv
    );
    let line = accepted(Command::Checkout, &[w("--detach"), r("main")]);
    assert_eq!(
        line.resolved(std::slice::from_ref(&one)).unwrap(),
        with(CHECKOUT, &["--detach", &one, "--"])
    );
    let line = accepted(Command::Checkout, &[r("main"), w("--"), p("f")]);
    assert_eq!(
        line.resolved(std::slice::from_ref(&one)).unwrap(),
        with(CHECKOUT, &[&one, "--", "f"])
    );
    // No revisions, nothing to resolve.
    let line = accepted(Command::Status, &[w("--porcelain=v2")]);
    assert_eq!(line.resolved(&[]).unwrap(), line.argv);
}

#[test]
fn identifiers_that_do_not_fit_the_line_are_refused() {
    let line = accepted(Command::Diff, &[r("a"), r("b")]);
    let one = "1".repeat(40);
    for bad in [
        vec![],
        vec![one.clone()],
        vec![one.clone(), one.clone(), one.clone()],
        vec![one.clone(), "main".to_owned()],
        vec![one.clone(), "a".repeat(40).to_uppercase()],
        vec![one.clone(), "1".repeat(39)],
        vec![one.clone(), String::new()],
    ] {
        let refusal = line.resolved(&bad).expect_err(&format!("{bad:?}"));
        assert_eq!(refusal.rule, RULE_RESOLVED);
        assert_eq!(refusal.kind, RefusedKind::Operation);
    }
    let range_line = accepted(Command::Diff, &[range("a", Dots::Two, "b")]);
    assert_eq!(
        range_line
            .resolved(std::slice::from_ref(&one))
            .unwrap_err()
            .rule,
        RULE_RESOLVED
    );
    assert_eq!(
        range_line
            .resolved(&[one.clone(), one.clone(), one.clone()])
            .unwrap_err()
            .rule,
        RULE_RESOLVED
    );
    let switch = accepted(Command::Checkout, &[n("main")]);
    assert_eq!(switch.resolved(&[]).unwrap_err().rule, RULE_RESOLVED);
}

#[test]
fn a_refusal_carries_the_command_and_the_position_and_never_the_element() {
    let secret = "SECRET-TEXT-OF-THE-ELEMENT";
    for (command, args) in [
        (
            Command::Add,
            vec![w("--"), p("a"), p(&format!("{secret}:x"))],
        ),
        (Command::Diff, vec![r(&format!("{secret}@{{1}}"))]),
        (Command::Checkout, vec![n(&format!("{secret} x"))]),
        (Command::Status, vec![w(&format!("--{secret}"))]),
        (Command::Commit, vec![w("-m"), m(&format!("{secret}\u{1}"))]),
        (
            Command::UpdateRef,
            vec![rn(&format!("refs/tags/{secret}")), o(OID), o(OID2)],
        ),
        (
            Command::Log,
            vec![w("--format"), custom(vec![text(&format!("{secret}%"))])],
        ),
        (Command::Log, vec![w(&format!("--max-count={secret}"))]),
    ] {
        let refusal = parse(command, &args).expect_err("refused");
        assert!(!refusal.detail().contains(secret), "{}", refusal.detail());
        assert!(
            refusal.detail().starts_with(tables::table(command).name),
            "{}",
            refusal.detail()
        );
        assert!(refusal.detail().is_ascii());
    }
    // The position counts from one.
    let refusal = parse(Command::Add, &[w("--"), p("a"), p("b:c")]).unwrap_err();
    assert_eq!(
        refusal.detail().split_whitespace().nth(2),
        Some("3"),
        "{}",
        refusal.detail()
    );
}
