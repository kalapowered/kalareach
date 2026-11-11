//! The settings every command runs with, and the one rule for line endings.

use kr_boundary_windows::frame::invocation::{Arg, Command, Identity, LineEndings, RefusedKind};
use kr_boundary_windows::operation::settings::{
    FIXED_SETTINGS, RULE_LINE_ENDINGS, RULE_SAFE_DIRECTORY, SettingsInput, autocrlf_text,
    command_arguments, effective_autocrlf,
};
use kr_boundary_windows::operation::{OperationLine, Writes, parse_operation};
use kr_boundary_windows::repository::config::{AutoCrlf, ConfigFacts};

/// The settings whose value does not depend on the tree, the person or the installation, key by
/// key and written out apart from the code that holds them.
const EXPECTED: &[(&str, &str)] = &[
    ("credential.helper", ""),
    ("credential.useHttpPath", "false"),
    ("core.fsmonitor", ""),
    ("core.fsmonitorHookVersion", ""),
    ("core.untrackedCache", "false"),
    ("core.pager", "cat"),
    ("core.editor", "false"),
    ("sequence.editor", "false"),
    ("core.askPass", ""),
    ("core.gitProxy", ""),
    ("core.sshCommand", ""),
    ("core.alternateRefsCommand", ""),
    ("core.alternateRefsPrefixes", ""),
    ("core.attributesFile", ""),
    ("core.excludesFile", ""),
    ("diff.external", ""),
    ("uploadpack.packObjectsHook", ""),
    ("gpg.program", "false"),
    ("gpg.openpgp.program", "false"),
    ("gpg.x509.program", "false"),
    ("gpg.ssh.program", "false"),
    ("commit.gpgSign", "false"),
    ("tag.gpgSign", "false"),
    ("log.showSignature", "false"),
    ("gc.auto", "0"),
    ("gc.autoDetach", "false"),
    ("maintenance.auto", "false"),
    ("maintenance.autoDetach", "false"),
    ("submodule.recurse", "false"),
    ("fetch.recurseSubmodules", "no"),
    ("push.recurseSubmodules", "no"),
    ("diff.ignoreSubmodules", "all"),
    ("status.submoduleSummary", "false"),
    ("transfer.bundleURI", "false"),
    ("protocol.allow", "never"),
    ("core.protectNTFS", "true"),
    ("log.mailmap", "false"),
    ("core.symlinks", "false"),
    ("safe.bareRepository", "explicit"),
];

/// A host value, a command's kind and the value or the rule that refuses.
type Cell = (LineEndings, Writes, Result<Option<AutoCrlf>, &'static str>);

const BOUNDARY: &str = "C:\\ProgramData\\Kala\\Boundary";
const TREE: &str = "C:/Users/person/project";

fn identity() -> Identity {
    Identity {
        name: "A Person".to_owned(),
        email: "person@example.com".to_owned(),
    }
}

fn input<'a>(identity: &'a Identity, line_endings: LineEndings) -> SettingsInput<'a> {
    SettingsInput {
        boundary: BOUNDARY,
        tree: TREE,
        identity,
        line_endings,
    }
}

fn facts(held: Option<AutoCrlf>) -> ConfigFacts {
    ConfigFacts {
        autocrlf_local: held,
        ..ConfigFacts::default()
    }
}

fn line(command: Command, args: &[Arg]) -> OperationLine {
    parse_operation(command, args, &ConfigFacts::default()).expect("a form of the tables")
}

fn status() -> OperationLine {
    line(Command::Status, &[Arg::Word("--porcelain=v2".to_owned())])
}

fn commit() -> OperationLine {
    line(
        Command::Commit,
        &[Arg::Word("-m".to_owned()), Arg::Message("one".to_owned())],
    )
}

/// The `-c` pairs of a built argument list.
fn settings_of(arguments: &[String]) -> Vec<(String, String)> {
    let mut pairs = Vec::new();
    let mut at = 2;
    while arguments.get(at).map(String::as_str) == Some("-c") {
        let (key, value) = arguments[at + 1].split_once('=').expect("key=value");
        pairs.push((key.to_owned(), value.to_owned()));
        at += 2;
    }
    pairs
}

fn value_of<'a>(pairs: &'a [(String, String)], key: &str) -> Option<&'a str> {
    let mut found = pairs.iter().filter(|(own, _)| own == key);
    let value = found.next().map(|(_, value)| value.as_str());
    assert!(found.next().is_none(), "{key} is set twice");
    value
}

#[test]
fn the_fixed_settings_are_these_and_each_key_is_set_once() {
    let fixed: Vec<(&str, &str)> = FIXED_SETTINGS.iter().map(|s| (s.key, s.value)).collect();
    assert_eq!(fixed, EXPECTED);
    let mut keys: Vec<&str> = fixed.iter().map(|(key, _)| *key).collect();
    keys.sort_unstable();
    keys.dedup();
    assert_eq!(keys.len(), EXPECTED.len());
}

#[test]
fn core_symlinks_is_always_false_and_the_empty_values_are_empty() {
    let identity = identity();
    for line_endings in [
        LineEndings::Unset,
        LineEndings::True,
        LineEndings::False,
        LineEndings::Input,
        LineEndings::Unknown,
    ] {
        let arguments = command_arguments(
            &input(&identity, line_endings),
            &facts(Some(AutoCrlf::False)),
            &status(),
        )
        .unwrap();
        let pairs = settings_of(&arguments);
        assert_eq!(value_of(&pairs, "core.symlinks"), Some("false"));
        assert_eq!(value_of(&pairs, "core.fsmonitor"), Some(""));
        assert_eq!(value_of(&pairs, "credential.helper"), Some(""));
    }
}

#[test]
fn a_launch_is_the_global_options_the_settings_and_then_the_line() {
    let identity = identity();
    let operation = commit();
    let arguments = command_arguments(
        &input(&identity, LineEndings::True),
        &facts(None),
        &operation,
    )
    .unwrap();
    assert_eq!(&arguments[..2], ["--no-pager", "--literal-pathspecs"]);
    let pairs = settings_of(&arguments);
    let after = 2 + 2 * pairs.len();
    assert_eq!(arguments[after..], operation.argv[..]);
    // Every setting is one `-c` and one `key=value`, and nothing else sits among them.
    assert!(arguments[2..after].chunks(2).all(|chunk| chunk[0] == "-c"));

    for (key, value) in EXPECTED {
        assert_eq!(value_of(&pairs, key), Some(*value), "{key}");
    }
    assert_eq!(
        value_of(&pairs, "core.hooksPath"),
        Some("C:\\ProgramData\\Kala\\Boundary\\git\\hooks")
    );
    assert_eq!(
        value_of(&pairs, "init.templateDir"),
        Some("C:\\ProgramData\\Kala\\Boundary\\git\\template")
    );
    assert_eq!(value_of(&pairs, "safe.directory"), Some(TREE));
    assert_eq!(value_of(&pairs, "user.name"), Some("A Person"));
    assert_eq!(value_of(&pairs, "user.email"), Some("person@example.com"));
    assert_eq!(value_of(&pairs, "core.autocrlf"), Some("true"));
    assert_eq!(pairs.len(), EXPECTED.len() + 6);
}

#[test]
fn a_name_with_an_equals_sign_stays_whole() {
    let identity = Identity {
        name: "A=B".to_owned(),
        email: "a=b@example.com".to_owned(),
    };
    let arguments = command_arguments(
        &input(&identity, LineEndings::Unset),
        &facts(None),
        &status(),
    )
    .unwrap();
    assert!(arguments.contains(&"user.name=A=B".to_owned()));
    assert!(arguments.contains(&"user.email=a=b@example.com".to_owned()));
}

#[test]
fn the_effective_line_ending_has_one_value_for_every_cell() {
    use AutoCrlf::{False as HeldFalse, Input as HeldInput, True as HeldTrue};
    use LineEndings::{False, Input, True, Unknown, Unset};
    let ok = |value: Option<AutoCrlf>| Ok(value);
    let hosts = [Unset, True, False, Input, Unknown];
    // The held configuration's own value first, whatever the host says and whatever the command.
    for held in [HeldTrue, HeldFalse, HeldInput] {
        for host in hosts {
            for writes in [Writes::No, Writes::Yes] {
                assert_eq!(
                    effective_autocrlf(Some(held), host, writes).map_err(|r| r.rule),
                    ok(Some(held)),
                    "{held:?} {host:?} {writes:?}"
                );
            }
        }
    }
    // With none held, the host's value if it is one, nothing for unset, and unknown is refused for
    // a command that writes and ignored for one that reads.
    let cells: [Cell; 10] = [
        (Unset, Writes::No, ok(None)),
        (Unset, Writes::Yes, ok(None)),
        (True, Writes::No, ok(Some(HeldTrue))),
        (True, Writes::Yes, ok(Some(HeldTrue))),
        (False, Writes::No, ok(Some(HeldFalse))),
        (False, Writes::Yes, ok(Some(HeldFalse))),
        (Input, Writes::No, ok(Some(HeldInput))),
        (Input, Writes::Yes, ok(Some(HeldInput))),
        (Unknown, Writes::No, ok(None)),
        (Unknown, Writes::Yes, Err(RULE_LINE_ENDINGS)),
    ];
    for (host, writes, expected) in cells {
        assert_eq!(
            effective_autocrlf(None, host, writes).map_err(|r| r.rule),
            expected,
            "{host:?} {writes:?}"
        );
    }
    let refusal = effective_autocrlf(None, Unknown, Writes::Yes).unwrap_err();
    assert_eq!(refusal.kind, RefusedKind::Operation);
    assert!(refusal.detail().is_ascii());
}

#[test]
fn the_values_are_written_as_git_reads_them() {
    assert_eq!(autocrlf_text(AutoCrlf::True), "true");
    assert_eq!(autocrlf_text(AutoCrlf::False), "false");
    assert_eq!(autocrlf_text(AutoCrlf::Input), "input");
}

#[test]
fn a_launch_takes_the_line_ending_rule_for_its_own_command() {
    let identity = identity();
    let hosts = [
        (LineEndings::Unset, None),
        (LineEndings::True, Some("true")),
        (LineEndings::False, Some("false")),
        (LineEndings::Input, Some("input")),
        (LineEndings::Unknown, None),
    ];
    for (host, expected) in hosts {
        // A reading command with no held value takes the host's, or runs with none.
        let arguments =
            command_arguments(&input(&identity, host), &facts(None), &status()).unwrap();
        assert_eq!(
            value_of(&settings_of(&arguments), "core.autocrlf"),
            expected,
            "{host:?}"
        );
        // A writing command does too, except where the host does not know.
        let result = command_arguments(&input(&identity, host), &facts(None), &commit());
        if host == LineEndings::Unknown {
            let refusal = result.unwrap_err();
            assert_eq!(refusal.rule, RULE_LINE_ENDINGS);
        } else {
            let arguments = result.unwrap();
            assert_eq!(
                value_of(&settings_of(&arguments), "core.autocrlf"),
                expected,
                "{host:?}"
            );
        }
        // The held configuration's own value decides first, in both.
        for operation in [status(), commit()] {
            let arguments = command_arguments(
                &input(&identity, host),
                &facts(Some(AutoCrlf::Input)),
                &operation,
            )
            .unwrap();
            assert_eq!(
                value_of(&settings_of(&arguments), "core.autocrlf"),
                Some("input")
            );
        }
    }
    // `unknown` is never in a line: no element of any launch is the word.
    for host in [LineEndings::Unset, LineEndings::Unknown] {
        let arguments =
            command_arguments(&input(&identity, host), &facts(None), &status()).unwrap();
        assert!(!arguments.iter().any(|element| element.contains("unknown")));
    }
}

#[test]
fn a_tree_that_cannot_be_the_safe_directory_is_refused_for_every_command() {
    let identity = identity();
    for tree in ["", "*", "C:/a\u{1}b", "C:/a\nb", "\u{7f}"] {
        let settings = SettingsInput {
            tree,
            ..input(&identity, LineEndings::True)
        };
        let refusal = command_arguments(&settings, &facts(None), &status()).unwrap_err();
        assert_eq!(refusal.rule, RULE_SAFE_DIRECTORY, "{tree:?}");
        assert_eq!(refusal.kind, RefusedKind::Operation);
        assert!(!refusal.detail().contains('*'));
    }
    // A path that holds an asterisk among others is a path.
    let settings = SettingsInput {
        tree: "C:/a*b",
        ..input(&identity, LineEndings::True)
    };
    assert!(command_arguments(&settings, &facts(None), &status()).is_ok());
}
