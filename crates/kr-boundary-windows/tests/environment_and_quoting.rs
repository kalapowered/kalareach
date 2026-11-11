//! The environment every child gets and the command line it is started with, held to their exact
//! contents on every platform. The Windows cases that start real children and read both back are in
//! `windows_launch.rs`.

use kr_boundary_windows::env::{
    EnvError, Kind, QualifiedGit, RootPaths, TreePaths, build_env, names,
};
use kr_boundary_windows::quote::quote_command_line;

fn roots() -> RootPaths {
    RootPaths {
        system: r"C:\Windows".to_owned(),
        boundary: r"C:\Program Files\KalaReach\Boundary".to_owned(),
        private_root: r"C:\ProgramData\KalaReach\Boundary\run\0123456789abcdef".to_owned(),
    }
}

fn tree() -> TreePaths {
    TreePaths {
        tree: r"D:\work\project".to_owned(),
        parent: r"D:\work".to_owned(),
    }
}

fn git() -> QualifiedGit {
    QualifiedGit {
        dir: r"C:\Program Files\Git".to_owned(),
    }
}

/// The variables every child gets, with the value each must have for the inputs above.
fn common() -> Vec<(&'static str, &'static str)> {
    vec![
        ("SystemRoot", r"C:\Windows"),
        ("windir", r"C:\Windows"),
        ("SystemDrive", "C:"),
        (
            "PATH",
            r"C:\Program Files\Git\mingw64\bin;C:\Windows\System32",
        ),
        (
            "GIT_EXEC_PATH",
            r"C:\Program Files\Git\mingw64\libexec\git-core",
        ),
        (
            "TMP",
            r"C:\ProgramData\KalaReach\Boundary\run\0123456789abcdef\tmp",
        ),
        (
            "TEMP",
            r"C:\ProgramData\KalaReach\Boundary\run\0123456789abcdef\tmp",
        ),
        (
            "TMPDIR",
            r"C:\ProgramData\KalaReach\Boundary\run\0123456789abcdef\tmp",
        ),
        (
            "HOME",
            r"C:\ProgramData\KalaReach\Boundary\run\0123456789abcdef\home",
        ),
        ("GIT_CONFIG_NOSYSTEM", "1"),
        (
            "GIT_CONFIG_GLOBAL",
            r"C:\Program Files\KalaReach\Boundary\git\config",
        ),
        ("GIT_TERMINAL_PROMPT", "0"),
        ("GIT_NO_LAZY_FETCH", "1"),
        ("GIT_PROTOCOL_FROM_USER", "0"),
        ("GIT_NO_REPLACE_OBJECTS", "1"),
        ("GIT_ATTR_NOSYSTEM", "1"),
        ("GIT_OPTIONAL_LOCKS", "0"),
        ("GIT_ALLOW_PROTOCOL", ""),
        ("GIT_PAGER", "cat"),
        ("GIT_EDITOR", "false"),
        ("GIT_SEQUENCE_EDITOR", "false"),
        ("LC_ALL", "C"),
    ]
}

fn sorted(mut pairs: Vec<(String, String)>) -> Vec<(String, String)> {
    pairs.sort();
    pairs
}

fn expected(extra: &[(&str, &str)]) -> Vec<(String, String)> {
    sorted(
        common()
            .into_iter()
            .chain(extra.iter().copied())
            .map(|(name, value)| (name.to_owned(), value.to_owned()))
            .collect(),
    )
}

#[test]
fn an_operations_block_holds_every_variable_of_the_table_and_nothing_else() {
    let block = build_env(Kind::Operation, &roots(), Some(&tree()), &git()).unwrap();
    let extra = [
        ("GIT_DIR", r"D:\work\project\.git"),
        ("GIT_WORK_TREE", r"D:\work\project"),
        ("GIT_COMMON_DIR", r"D:\work\project\.git"),
        ("GIT_CEILING_DIRECTORIES", r"D:\work"),
    ];
    assert_eq!(sorted(block.pairs()), expected(&extra));
    let table = names();
    for (name, _) in block.pairs() {
        assert!(table.contains(&name.as_str()), "{name} is not in the table");
    }
}

#[test]
fn a_configuration_reader_names_no_repository_but_keeps_the_ceiling() {
    let block = build_env(Kind::ConfigRead, &roots(), Some(&tree()), &git()).unwrap();
    assert_eq!(
        sorted(block.pairs()),
        expected(&[("GIT_CEILING_DIRECTORIES", r"D:\work")])
    );
}

#[test]
fn a_proofs_block_names_no_repository_at_all() {
    let block = build_env(Kind::Proof, &roots(), None, &git()).unwrap();
    assert_eq!(sorted(block.pairs()), expected(&[]));
    // A tree that is given for a proof is not used.
    let given = build_env(Kind::Proof, &roots(), Some(&tree()), &git()).unwrap();
    assert_eq!(given, block);
}

#[test]
fn nothing_of_the_callers_environment_reaches_a_block() {
    // The process running this case has a PATH, a temporary folder and, usually, a home; none of
    // them is in the block, whose values come from the table and its inputs alone.
    let block = build_env(Kind::Operation, &roots(), Some(&tree()), &git()).unwrap();
    let pairs = block.pairs();
    for name in ["PATH", "TMP", "TEMP", "TMPDIR", "HOME"] {
        let ours = std::env::var(name).ok();
        let theirs = pairs
            .iter()
            .find(|pair| pair.0 == name)
            .map(|pair| pair.1.clone());
        assert!(theirs.is_some(), "{name} is in the table");
        assert!(
            ours.is_none() || ours != theirs,
            "{name} must not be the process's own"
        );
    }
    for (name, _) in std::env::vars() {
        let in_table = names()
            .iter()
            .any(|entry| entry.eq_ignore_ascii_case(&name));
        let in_block = pairs.iter().any(|pair| pair.0.eq_ignore_ascii_case(&name));
        assert_eq!(in_block, in_table, "{name}");
    }
}

#[test]
fn a_block_is_in_the_platforms_form() {
    let block = build_env(Kind::Operation, &roots(), Some(&tree()), &git()).unwrap();
    let units = block.units();
    assert_eq!(
        &units[units.len() - 2..],
        [0, 0],
        "the double NUL ends the block"
    );
    let entries: Vec<String> = units
        .split(|unit| *unit == 0)
        .take_while(|entry| !entry.is_empty())
        .map(String::from_utf16_lossy)
        .collect();
    let names: Vec<String> = entries
        .iter()
        .map(|entry| entry.split_once('=').unwrap().0.to_uppercase())
        .collect();
    let mut ordered = names.clone();
    ordered.sort();
    assert_eq!(
        names, ordered,
        "the entries are sorted by name without regard to case"
    );
    assert!(
        entries.iter().any(|entry| entry == "GIT_ALLOW_PROTOCOL="),
        "the empty protocol list is an entry of its own"
    );
}

#[test]
fn a_block_is_refused_for_a_repository_that_is_missing_or_a_path_that_is_not_one() {
    assert_eq!(
        build_env(Kind::Operation, &roots(), None, &git()),
        Err(EnvError::NoTree(Kind::Operation))
    );
    assert_eq!(
        build_env(Kind::ConfigRead, &roots(), None, &git()),
        Err(EnvError::NoTree(Kind::ConfigRead))
    );
    let mut empty_root = roots();
    empty_root.private_root.clear();
    assert!(build_env(Kind::Proof, &empty_root, None, &git()).is_err());
    let mut with_nul = tree();
    with_nul.tree.push('\0');
    assert!(build_env(Kind::Operation, &roots(), Some(&with_nul), &git()).is_err());
}

/// The platform's own splitting of the arguments after a program's name: the rules of
/// `CommandLineToArgvW` and of the C runtime since 2008.
fn split(line: &str) -> Vec<String> {
    let mut characters = line.chars().peekable();
    let mut name = String::new();
    if characters.peek() == Some(&'"') {
        characters.next();
        for character in characters.by_ref() {
            if character == '"' {
                break;
            }
            name.push(character);
        }
    } else {
        while let Some(character) = characters.peek().copied() {
            if character == ' ' || character == '\t' {
                break;
            }
            name.push(character);
            characters.next();
        }
    }
    let mut arguments = vec![name];
    loop {
        while matches!(characters.peek(), Some(' ' | '\t')) {
            characters.next();
        }
        if characters.peek().is_none() {
            return arguments;
        }
        let mut current = String::new();
        let mut quoted = false;
        loop {
            let mut backslashes = 0_usize;
            while characters.peek() == Some(&'\\') {
                backslashes += 1;
                characters.next();
            }
            if characters.peek() == Some(&'"') {
                current.extend(std::iter::repeat_n('\\', backslashes / 2));
                characters.next();
                if backslashes % 2 == 1 {
                    current.push('"');
                } else if quoted && characters.peek() == Some(&'"') {
                    characters.next();
                    current.push('"');
                } else {
                    quoted = !quoted;
                }
                continue;
            }
            current.extend(std::iter::repeat_n('\\', backslashes));
            match characters.peek().copied() {
                None => break,
                Some(' ' | '\t') if !quoted => break,
                Some(character) => {
                    current.push(character);
                    characters.next();
                }
            }
        }
        arguments.push(current);
    }
}

#[test]
fn each_quoted_part_comes_back_as_one_argument() {
    let program = r"C:\Program Files\Git\mingw64\bin\git.exe";
    let table: &[&str] = &[
        "",
        "plain",
        "two words",
        "tab\there",
        "a\"b",
        "\"",
        "\"\"",
        "ends with a backslash\\",
        "ends with two\\\\",
        "\\",
        "\\\\",
        "\\\"",
        "\\\\\"",
        "a\\b",
        "a\\\\b c",
        r"C:\path with space\dir\",
        "--format=%H %s",
        "--message=it's \"quoted\" and ends\\",
        "line\nbreak",
        "ünïcödé and 日本語",
        "-c",
        "=",
    ];
    for argument in table {
        let line = quote_command_line(&[program, argument]);
        assert_eq!(
            split(&line),
            [program, argument],
            "the argument {argument:?} in {line}"
        );
    }
    let line = quote_command_line(&[program, "a b", "", "c\"d", "e\\"]);
    assert_eq!(split(&line), [program, "a b", "", "c\"d", "e\\"]);
}

#[test]
fn every_short_string_of_the_awkward_characters_round_trips() {
    const ALPHABET: [&str; 5] = ["a", " ", "\"", "\\", "\t"];
    let mut count = 0_usize;
    let mut stack: Vec<String> = vec![String::new()];
    while let Some(argument) = stack.pop() {
        let line = quote_command_line(&["prog.exe", &argument, &argument]);
        assert_eq!(
            split(&line),
            ["prog.exe", argument.as_str(), argument.as_str()],
            "the argument {argument:?}"
        );
        count += 1;
        if argument.chars().count() < 6 {
            for piece in ALPHABET {
                stack.push(format!("{argument}{piece}"));
            }
        }
    }
    assert!(count > 19_000, "the whole set was tried: {count}");
}

#[test]
fn a_program_with_a_space_is_one_name_and_one_without_is_left_alone() {
    assert_eq!(
        quote_command_line(&[r"C:\Program Files\Git\git.exe", "status"]),
        r#""C:\Program Files\Git\git.exe" status"#
    );
    assert_eq!(
        quote_command_line(&[r"C:\Git\git.exe", "status"]),
        r"C:\Git\git.exe status"
    );
    assert_eq!(quote_command_line(&["x.exe"]), "x.exe");
}
