//! The report's own sources, apart from the items under `#[cfg(test)]`, hold none of the listed
//! names: the programs that end processes, remove files or read the system's logs and signatures,
//! and the functions that remove, replace or signal. The case reads tokens and refuses the names,
//! whatever follows them. It cannot see a name that a macro builds, a file taken in from outside
//! `src`, or a program started under a name that is not listed. That each step runs once is held by
//! the case that counts the runs of a failed step
//! (`a_step_that_could_not_run_a_program_fails_once_and_keeps_the_file_as_it_was_seen` in
//! `observation.rs`), and what the steps themselves run is the plan's.

use std::path::{Path, PathBuf};

use kr_conformance::rust_lex::{Tok, Token, lex};

/// The programs the report never starts, by the name a command is given or the path's last part.
const PROGRAMS: [&str; 11] = [
    "kill", "pkill", "killall", "taskkill", "ps", "codesign", "log", "sudo", "rm", "unlink",
    "rmdir",
];

/// Names of functions that remove from the disk, replace a file or signal a process, wherever
/// they are written: called, taken as a value, given type arguments, imported or renamed.
const NAMES: [&str; 10] = [
    "remove_dir_all",
    "remove_dir",
    "remove_file",
    "rename",
    "unlink",
    "rmdir",
    "kill",
    "killpg",
    "process_group",
    "TerminateProcess",
];

/// Names of signals, whenever they are written.
const SIGNALS: [&str; 2] = ["SIGKILL", "SIGTERM"];

/// Whether a command or a path names one of the programs the report never starts.
fn named(command: &str) -> bool {
    let last = command.rsplit(['/', '\\']).next().unwrap_or(command);
    let last = last.strip_suffix(".exe").unwrap_or(last);
    PROGRAMS.contains(&last)
}

/// Whether a string, taken as shell text, starts one of those programs: its first word, or the
/// first word after `;`, `|`, `&`, a new line, a back tick or `$(`.
fn runs_one(text: &str) -> bool {
    text.replace("$(", ";")
        .split([';', '|', '&', '\n', '`'])
        .any(|part| part.split_whitespace().next().is_some_and(named))
}

/// Whether `tokens` begin with `#[cfg(test)]`.
fn opens_a_test_item(tokens: &[Token]) -> bool {
    let shape = [
        Tok::Punct('#'),
        Tok::Punct('['),
        Tok::Ident("cfg".to_owned()),
        Tok::Punct('('),
        Tok::Ident("test".to_owned()),
        Tok::Punct(')'),
        Tok::Punct(']'),
    ];
    tokens.len() >= shape.len()
        && tokens
            .iter()
            .zip(&shape)
            .all(|(token, tok)| token.tok == *tok)
}

/// Where the item that begins at `from` ends: after its closing brace, or after the semicolon of an
/// item with no body. Braces and semicolons inside a string or a comment are not tokens of their
/// own, and a semicolon inside a bracket does not end an item.
fn end_of_item(tokens: &[Token], from: usize) -> usize {
    let (mut braces, mut brackets) = (0_usize, 0_usize);
    for (at, token) in tokens.iter().enumerate().skip(from) {
        match token.tok {
            Tok::Punct('{') => braces += 1,
            Tok::Punct('}') => {
                braces = braces.saturating_sub(1);
                if braces == 0 {
                    return at + 1;
                }
            }
            Tok::Punct('(' | '[') => brackets += 1,
            Tok::Punct(')' | ']') => brackets = brackets.saturating_sub(1),
            Tok::Punct(';') if braces == 0 && brackets == 0 => return at + 1,
            _ => {}
        }
    }
    tokens.len()
}

/// The tokens of `source` that are not a comment and not part of an item under `#[cfg(test)]`. A
/// `#[cfg(test)]` inside the input of a macro skips nothing: the macro may build code that is not
/// under it.
fn product_tokens(source: &str) -> Result<Vec<Token>, String> {
    let tokens: Vec<Token> = lex(source)
        .map_err(|error| format!("line {}: {}", error.line, error.what))?
        .into_iter()
        .filter(|token| !token.is_comment())
        .collect();
    let mut product = Vec::new();
    // For each open bracket: whether it holds a macro's input.
    let mut groups: Vec<bool> = Vec::new();
    let mut at = 0;
    while at < tokens.len() {
        if opens_a_test_item(&tokens[at..]) && !groups.contains(&true) {
            at = end_of_item(&tokens, at + 7);
            continue;
        }
        match tokens[at].tok {
            Tok::Punct('{' | '(' | '[') => {
                let named_call =
                    at >= 2 && tokens[at - 1].is_punct('!') && tokens[at - 2].ident().is_some();
                let definition = at >= 3
                    && tokens[at - 1].ident().is_some()
                    && tokens[at - 2].is_punct('!')
                    && tokens[at - 3].ident() == Some("macro_rules");
                groups.push(named_call || definition || groups.contains(&true));
            }
            Tok::Punct('}' | ')' | ']') => {
                groups.pop();
            }
            _ => {}
        }
        product.push(tokens[at].clone());
        at += 1;
    }
    Ok(product)
}

/// What in `source` removes, replaces, signals or starts a program that does, each with its line.
fn found(source: &str) -> Result<Vec<String>, String> {
    let tokens = product_tokens(source)?;
    let mut found = Vec::new();
    for (at, token) in tokens.iter().enumerate() {
        let what = match &token.tok {
            Tok::Str(text, _) if runs_one(text) || (text.contains(['/', '\\']) && named(text)) => {
                format!("the text {text:?}")
            }
            Tok::Ident(name)
                if SIGNALS.contains(&name.as_str())
                    || (NAMES.contains(&name.as_str())
                        // `rename = "x"` is the key of an attribute, as in `#[serde(rename = "x")]`.
                        && !(name == "rename"
                            && tokens.get(at + 1).is_some_and(|next| next.is_punct('=')))) =>
            {
                format!("`{name}`")
            }
            _ => continue,
        };
        found.push(format!("line {}: {what}", token.line));
    }
    Ok(found)
}

/// The Rust sources in `directory` and in each directory below it.
fn rust_files(directory: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for entry in std::fs::read_dir(directory).expect("a directory") {
        let path = entry.expect("an entry").path();
        if path.is_dir() {
            files.extend(rust_files(&path));
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            files.push(path);
        }
    }
    files.sort();
    files
}

#[test]
fn the_report_s_sources_remove_nothing_and_signal_and_read_no_one() {
    let files = rust_files(&Path::new(env!("CARGO_MANIFEST_DIR")).join("src"));
    assert!(files.len() > 10, "the sources were not found");
    for path in files {
        let source = std::fs::read_to_string(&path).expect("a source");
        match found(&source) {
            Ok(hits) => assert!(hits.is_empty(), "{}: {hits:#?}", path.display()),
            Err(problem) => panic!("{}: {problem}", path.display()),
        }
    }
}

#[test]
fn the_check_finds_what_it_is_there_for() {
    for code in [
        "std::process::Command::new(\"kill\")",
        "Command::new(\"/usr/bin/codesign\").arg(path)",
        "Command::new(\"/bin/ps\")",
        "Command::new(\"sudo\")",
        "Command::new(\"rm\").arg(path)",
        "Command::new(\"unlink\")",
        "Command::new(\"rmdir\")",
        "Command::new(r\"C:\\Windows\\System32\\taskkill.exe\")",
        "Command::new(r#\"C:\\Windows\\System32\\taskkill.exe\"#)",
        "let log = \"/usr/bin/log\";",
        "Command::new(\"sh\").args([\"-c\", \"kill $pid\"])",
        "let text = \"cd x; rm -rf y\";",
        "let text = \"true && kill 123\";",
        "let text = \"echo $(kill 123)\";",
        "std::fs::remove_dir_all(&target)?;",
        "std::fs::remove_file(path)",
        "std::fs::remove_file (path)",
        "std::fs::remove_file\n    (path)",
        "std::fs::rename(from, to)",
        "std::fs::rename (from, to)",
        "child.kill();",
        "child.kill ()",
        "Child::kill(&mut child)",
        "nix::sys::signal::kill(pid, signal)",
        "command.process_group(0);",
        "let signal = SIGKILL;",
        "let remove = std::fs::remove_file;",
        "std::fs::remove_file::<std::path::PathBuf>(path)",
        "(std::fs::remove_file)(path)",
        "use std::fs::remove_dir_all as clean;",
        "let signal_it = Child::kill;",
        "m! { #[cfg(test)] fn f() { std::fs::remove_file(x); } }",
        "macro_rules! m { () => { #[cfg(test)] fn f() { child.kill(); } } }",
    ] {
        assert!(
            !found(code).expect("a source").is_empty(),
            "not found: {code}"
        );
    }
    for code in [
        "// Command::new(\"kill\") is never made",
        "/* std::fs::remove_file(x) */",
        "let step = Command::new(&words[0]);",
        "Command::new(\"cargo\")",
        "let text = \"the log has all of it\";",
        "let text = \"step {step} did not pass: {} (log {})\";",
        "#[serde(rename_all = \"snake_case\")]\nstruct S;",
        "#[serde(rename = \"x\")]\nstruct S;",
        "let renamed = renamed;",
    ] {
        assert!(
            found(code).expect("a source").is_empty(),
            "found in: {code}"
        );
    }
}

#[test]
fn what_is_under_cfg_test_is_not_read_and_what_follows_it_is() {
    for code in [
        "#[cfg(test)]\nmod tests { fn f() { std::fs::remove_dir_all(x); } }",
        "#[cfg(test)]\nmod tests {\n    fn f() { let s = \"}\"; std::fs::rename(a, b); }\n}",
        "#[cfg(test)]\nfn helper() -> [u8; 2] { std::fs::remove_file(x); [0; 2] }",
        "#[cfg(test)]\nuse std::process::Command;\nfn product() {}",
        "#[cfg(test)]\nmod a {\n}\n#[cfg(test)]\nmod b { fn f() { child.kill(); } }",
    ] {
        assert!(
            found(code).expect("a source").is_empty(),
            "found in: {code}"
        );
    }
    for code in [
        "#[cfg(test)]\nmod tests {\n}\nfn product() { std::fs::remove_file(x); }",
        "#[cfg(test)]\nfn helper() {}\nfn product() { std::fs::remove_file(x); }",
        "#[cfg(test)]\nuse std::fs;\nfn product() { child.kill(); }",
        "#[cfg(test)]\nmod a { fn f() { let s = \"{\"; } }\nfn product() { std::fs::rename(a, b); }",
    ] {
        assert!(
            !found(code).expect("a source").is_empty(),
            "not found: {code}"
        );
    }
}

#[test]
fn the_sources_of_every_directory_below_the_source_directory_are_read() {
    let held = tempfile::tempdir().unwrap();
    let nested = held.path().join("a").join("b");
    std::fs::create_dir_all(&nested).unwrap();
    std::fs::write(nested.join("c.rs"), "fn f() {}").unwrap();
    std::fs::write(held.path().join("a").join("d.txt"), "not a source").unwrap();
    std::fs::write(held.path().join("e.rs"), "fn g() {}").unwrap();
    let names: Vec<String> = rust_files(held.path())
        .iter()
        .map(|path| {
            path.strip_prefix(held.path())
                .unwrap()
                .display()
                .to_string()
        })
        .collect();
    assert_eq!(names.len(), 2, "{names:?}");
    assert!(names.iter().any(|name| name.ends_with("c.rs")), "{names:?}");
    assert!(names.iter().any(|name| name == "e.rs"), "{names:?}");
}
