//! The report's own sources, apart from the items under `#[cfg(test)]`, hold none of the listed
//! names: the programs that end or list processes, run a command as another user, remove files or
//! read the system's logs and signatures, and the functions that remove, replace, make a process
//! group, signal or reap by number. The case reads tokens and refuses the names wherever they are
//! written, except a `rename` followed by `=` inside an attribute, which is the attribute's key; an
//! item under `#[cfg(test)]` is skipped only where the attribute is on an item. It cannot see a name
//! that a macro builds, a file taken in from outside `src`, or a program started under a name that
//! is not listed. That each step runs once is held by the case that counts the runs of a failed step
//! (`a_step_that_could_not_run_a_program_fails_once_and_keeps_the_file_as_it_was_seen` in
//! `observation.rs`), and what the steps themselves run is the plan's.
//!
//! The files of the cases that run processes under a time limit are read too: `tests/tree.rs`,
//! `tests/execution.rs` and the fixture `time-limits`. No case sends a signal, and no case reaps a
//! process by its number.

use std::path::{Path, PathBuf};

use kr_conformance::rust_lex::{Tok, Token, lex};

/// The programs the report never starts, by the name a command is given or the path's last part.
const PROGRAMS: [&str; 11] = [
    "kill", "pkill", "killall", "taskkill", "ps", "codesign", "log", "sudo", "rm", "unlink",
    "rmdir",
];

/// Names of functions that remove from the disk, replace a file, make a process the leader of a
/// group, signal a process or reap a process by its number, and of the type that names a signal,
/// wherever they are written: called, taken as a value, given type arguments, imported or renamed.
/// So is every name that begins with `kill`, which covers `kill`, `killpg` and
/// `kill_process_group`.
const NAMES: [&str; 11] = [
    "waitpid",
    "waitid",
    "wait4",
    "remove_dir_all",
    "remove_dir",
    "remove_file",
    "rename",
    "unlink",
    "rmdir",
    "process_group",
    "TerminateProcess",
];

/// The name of the type that names a signal.
const SIGNAL_TYPE: &str = "Signal";

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

/// The words that begin an item.
const ITEM_WORDS: [&str; 13] = [
    "mod", "fn", "use", "impl", "struct", "enum", "trait", "type", "const", "static", "extern",
    "unsafe", "async",
];

/// Whether `tokens`, which follow an attribute, begin an item: more attributes and a visibility
/// may come first. An attribute on a match arm, an argument, a field or a statement is on no item.
fn starts_an_item(tokens: &[Token]) -> bool {
    let mut at = 0;
    while tokens.get(at).is_some_and(|token| token.is_punct('#'))
        && tokens.get(at + 1).is_some_and(|token| token.is_punct('['))
    {
        at = after_brackets(tokens, at + 1);
    }
    if tokens.get(at).and_then(Token::ident) == Some("pub") {
        at += 1;
        if tokens.get(at).is_some_and(|token| token.is_punct('(')) {
            while tokens.get(at).is_some_and(|token| !token.is_punct(')')) {
                at += 1;
            }
            at += 1;
        }
    }
    let Some(word) = tokens.get(at).and_then(Token::ident) else {
        return false;
    };
    if !ITEM_WORDS.contains(&word) {
        return false;
    }
    // The lexer reads a raw identifier such as `r#type` as the keyword, so a field, an argument or
    // an assignment can look like an item. No item word is followed by a colon of its own, an `=`,
    // a comma, a closing bracket, a semicolon or a dot, nor by `::` (but for `use`, and `extern`
    // does not take it either) or by a parenthesis (but for `impl`).
    let punct = |at: usize, c: char| tokens.get(at).is_some_and(|token| token.is_punct(c));
    let colon = punct(at + 1, ':');
    let single_colon = colon && !punct(at + 2, ':');
    let double_colon = colon && word != "use";
    let ends = tokens.get(at + 1).is_none()
        || ['=', ',', ')', '}', ';', '.']
            .iter()
            .any(|c| punct(at + 1, *c));
    let paren = word != "impl" && punct(at + 1, '(');
    !(single_colon || double_colon || ends || paren)
}

/// The index after the `]` that closes the `[` at `open`, or the end of `tokens`.
fn after_brackets(tokens: &[Token], open: usize) -> usize {
    let mut depth = 0_usize;
    for (at, token) in tokens.iter().enumerate().skip(open) {
        match token.tok {
            Tok::Punct('[') => depth += 1,
            Tok::Punct(']') => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return at + 1;
                }
            }
            _ => {}
        }
    }
    tokens.len()
}

/// Whether each token of `tokens` is inside an attribute: from `#[` or `#![` to the `]` that closes it.
fn inside_attributes(tokens: &[Token]) -> Vec<bool> {
    let mut inside = vec![false; tokens.len()];
    let mut at = 0;
    while at < tokens.len() {
        let open = if tokens[at].is_punct('#') {
            match tokens.get(at + 1) {
                Some(next) if next.is_punct('[') => Some(at + 1),
                Some(next) if next.is_punct('!') => tokens
                    .get(at + 2)
                    .filter(|t| t.is_punct('['))
                    .map(|_| at + 2),
                _ => None,
            }
        } else {
            None
        };
        if let Some(open) = open {
            let end = after_brackets(tokens, open);
            inside[at..end].fill(true);
            at = end;
        } else {
            at += 1;
        }
    }
    inside
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
        if opens_a_test_item(&tokens[at..])
            && !groups.contains(&true)
            && starts_an_item(&tokens[at + 7..])
        {
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
    Ok(found_in(&product_tokens(source)?, &[]))
}

/// What in `tokens` does, each with its line, except the tokens at `excused`.
fn found_in(tokens: &[Token], excused: &[usize]) -> Vec<String> {
    let in_attribute = inside_attributes(tokens);
    let mut found = Vec::new();
    for (at, token) in tokens.iter().enumerate() {
        if excused.contains(&at) {
            continue;
        }
        let what = match &token.tok {
            Tok::Str(text, _) if runs_one(text) || (text.contains(['/', '\\']) && named(text)) => {
                format!("the text {text:?}")
            }
            Tok::Ident(name)
                if SIGNALS.contains(&name.as_str())
                    || name == SIGNAL_TYPE
                    || name.starts_with("kill")
                    || (NAMES.contains(&name.as_str())
                        // `rename = "x"` is the key of an attribute, as in `#[serde(rename = "x")]`,
                        // and is not one anywhere else.
                        && !(name == "rename"
                            && in_attribute[at]
                            && tokens.get(at + 1).is_some_and(|next| next.is_punct('=')))) =>
            {
                format!("`{name}`")
            }
            _ => continue,
        };
        found.push(format!("line {}: {what}", token.line));
    }
    found
}

/// The words of the one removal the report makes, in the order they are written: the directory of
/// the run's own scratch, which `Scratch` removes when it is dropped.
const SCRATCH_REMOVAL: [&str; 13] = [
    "std",
    ":",
    ":",
    "fs",
    ":",
    ":",
    "remove_dir_all",
    "(",
    "&",
    "self",
    ".",
    "path",
    ")",
];

/// The position of the `remove_dir_all` of [`SCRATCH_REMOVAL`] that is inside the block of
/// `impl Drop for Scratch`, the first such: no other call, operand or place is the one.
fn scratch_removal(tokens: &[Token]) -> Option<usize> {
    let word = |at: usize| match tokens.get(at).map(|token| &token.tok) {
        Some(Tok::Ident(name)) => Some(name.as_str()),
        _ => None,
    };
    let opens = (0..tokens.len()).find(|&at| {
        ["impl", "Drop", "for", "Scratch"]
            .iter()
            .enumerate()
            .all(|(offset, name)| word(at + offset) == Some(*name))
            && tokens.get(at + 4).is_some_and(|token| token.is_punct('{'))
    })? + 4;
    let closes = end_of_item(tokens, opens);
    (opens..closes).find_map(|at| {
        let written = SCRATCH_REMOVAL.iter().enumerate().all(|(offset, text)| {
            tokens
                .get(at + offset)
                .is_some_and(|token| match &token.tok {
                    Tok::Ident(name) => name == text,
                    Tok::Punct(c) => text.len() == 1 && text.starts_with(*c),
                    _ => false,
                })
        });
        (written && at + SCRATCH_REMOVAL.len() <= closes).then_some(at + 6)
    })
}

/// The runs of words, each written once in the block of `impl Group` in `tree.rs`, that start a
/// step's command as the leader of a process group of its own and signal that group and no other
/// process: the group is the one the child the report started leads, a `Child` that only a start
/// of a command gives, and the signal is `TERM`, then `KILL`, or the one of the two that the
/// report was sent (`INT` or `TERM`) and sends on. The fourth run names those two signals, the fifth
/// turns the number of the signal that was received into the type and the sixth sends it. The calls
/// are written as rustfmt writes them, with the comma that ends a wrapped call. The `0` of the
/// first run is the number `0` as it is written: the lexer keeps a number's spelling.
const GROUP_CALLS: [&[&str]; 6] = [
    &[
        "std",
        ":",
        ":",
        "os",
        ":",
        ":",
        "unix",
        ":",
        ":",
        "process",
        ":",
        ":",
        "CommandExt",
        ":",
        ":",
        "process_group",
        "(",
        "command",
        ",",
        "0",
        ")",
    ],
    &[
        "rustix",
        ":",
        ":",
        "process",
        ":",
        ":",
        "kill_process_group",
        "(",
        "rustix",
        ":",
        ":",
        "process",
        ":",
        ":",
        "Pid",
        ":",
        ":",
        "from_child",
        "(",
        "child",
        ")",
        ",",
        "rustix",
        ":",
        ":",
        "process",
        ":",
        ":",
        "Signal",
        ":",
        ":",
        "TERM",
        ",",
        ")",
    ],
    &[
        "rustix",
        ":",
        ":",
        "process",
        ":",
        ":",
        "kill_process_group",
        "(",
        "rustix",
        ":",
        ":",
        "process",
        ":",
        ":",
        "Pid",
        ":",
        ":",
        "from_child",
        "(",
        "child",
        ")",
        ",",
        "rustix",
        ":",
        ":",
        "process",
        ":",
        ":",
        "Signal",
        ":",
        ":",
        "KILL",
        ",",
        ")",
    ],
    &[
        "const",
        "FORWARDED",
        ":",
        "&",
        "[",
        "rustix",
        ":",
        ":",
        "process",
        ":",
        ":",
        "Signal",
        "]",
        "=",
        "&",
        "[",
        "rustix",
        ":",
        ":",
        "process",
        ":",
        ":",
        "Signal",
        ":",
        ":",
        "INT",
        ",",
        "rustix",
        ":",
        ":",
        "process",
        ":",
        ":",
        "Signal",
        ":",
        ":",
        "TERM",
        "]",
        ";",
    ],
    &[
        "rustix",
        ":",
        ":",
        "process",
        ":",
        ":",
        "Signal",
        ":",
        ":",
        "from_named_raw",
        "(",
        "number",
        ")",
    ],
    &[
        "rustix",
        ":",
        ":",
        "process",
        ":",
        ":",
        "kill_process_group",
        "(",
        "rustix",
        ":",
        ":",
        "process",
        ":",
        ":",
        "Pid",
        ":",
        ":",
        "from_child",
        "(",
        "child",
        ")",
        ",",
        "signal",
        ",",
        ")",
    ],
];

/// The positions of the names the check refuses inside the first written copy of each run of
/// [`GROUP_CALLS`] that lies in the block of `impl Group`: no other call, operand, signal or place
/// is one.
fn group_calls(tokens: &[Token]) -> Vec<usize> {
    let word = |at: usize| match tokens.get(at).map(|token| &token.tok) {
        Some(Tok::Ident(name)) => Some(name.as_str()),
        _ => None,
    };
    let Some(opens) = (0..tokens.len()).find(|&at| {
        word(at) == Some("impl")
            && word(at + 1) == Some("Group")
            && tokens.get(at + 2).is_some_and(|token| token.is_punct('{'))
    }) else {
        return Vec::new();
    };
    let closes = end_of_item(tokens, opens + 2);
    let mut excused = Vec::new();
    for run in GROUP_CALLS {
        let found = (opens..closes).find(|&at| {
            at + run.len() <= closes
                && run.iter().enumerate().all(|(offset, text)| {
                    tokens
                        .get(at + offset)
                        .is_some_and(|token| match &token.tok {
                            Tok::Ident(name) => name == text,
                            Tok::Punct(c) => text.len() == 1 && text.starts_with(*c),
                            Tok::Number(written) => *text == "0" && written == "0",
                            _ => false,
                        })
                })
        });
        if let Some(at) = found {
            excused.extend(
                run.iter()
                    .enumerate()
                    .filter(|(_, text)| {
                        matches!(**text, "process_group" | "kill_process_group" | SIGNAL_TYPE)
                    })
                    .map(|(offset, _)| at + offset),
            );
        }
    }
    excused
}

/// What in the source of the file `path` (below the sources' directory) the check refuses. The
/// report removes one thing, its run's scratch directory, and that call is allowed in `scratch.rs`
/// at the sources' top and nowhere else; it signals one kind of process group, a step's own, and
/// those calls are allowed in `tree.rs` at the sources' top and nowhere else.
fn refused(path: &Path, source: &str) -> Result<Vec<String>, String> {
    let tokens = product_tokens(source)?;
    let excused: Vec<usize> = if path == Path::new("scratch.rs") {
        scratch_removal(&tokens).into_iter().collect()
    } else if path == Path::new("tree.rs") {
        group_calls(&tokens)
    } else {
        Vec::new()
    };
    Ok(found_in(&tokens, &excused))
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
    let sources = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let files = rust_files(&sources);
    assert!(files.len() > 10, "the sources were not found");
    for path in files {
        let source = std::fs::read_to_string(&path).expect("a source");
        let below = path.strip_prefix(&sources).expect("below the sources");
        match refused(below, &source) {
            Ok(hits) => assert!(hits.is_empty(), "{}: {hits:#?}", path.display()),
            Err(problem) => panic!("{}: {problem}", path.display()),
        }
    }
}

/// The scratch directory's removal is the one the check lets through: the call in `Drop for
/// Scratch` in `scratch.rs`, and no other call, operand, form or place.
#[test]
fn the_check_lets_through_the_scratch_removal_and_no_other() {
    let drop_with = |call: &str| {
        format!(
            "impl Drop for Scratch {{\n    fn drop(&mut self) {{\n        let _ = {call};\n    }}\n}}\n"
        )
    };
    let the_call = "std::fs::remove_dir_all(&self.path)";
    let allowed = |path: &str, source: &str| {
        refused(Path::new(path), source)
            .expect("a source")
            .is_empty()
    };
    assert!(allowed("scratch.rs", &drop_with(the_call)));
    for (what, path, source) in [
        (
            "the same text in another file",
            "other.rs",
            drop_with(the_call),
        ),
        (
            "the same text in a scratch.rs below the top",
            "nested/scratch.rs",
            drop_with(the_call),
        ),
        (
            "a second call",
            "scratch.rs",
            drop_with(&format!("{the_call}; std::fs::remove_dir_all(&self.path)")),
        ),
        (
            "another operand",
            "scratch.rs",
            drop_with("std::fs::remove_dir_all(&self.other)"),
        ),
        (
            "another operand, the evidence",
            "scratch.rs",
            drop_with("std::fs::remove_dir_all(evidence)"),
        ),
        (
            "an import",
            "scratch.rs",
            format!("use std::fs::remove_dir_all;\n{}", drop_with(the_call)),
        ),
        (
            "a function value",
            "scratch.rs",
            format!(
                "fn clean() {{ let remove = std::fs::remove_dir_all; }}\n{}",
                drop_with(the_call)
            ),
        ),
        (
            "the call in another place",
            "scratch.rs",
            format!(
                "impl Scratch {{ fn clean(&self) {{ {the_call}; }} }}\n{}",
                drop_with("()")
            ),
        ),
    ] {
        assert!(!allowed(path, &source), "{what}: let through");
    }
}

/// The calls that start a step's command as a group's leader and signal that group are the ones the
/// check lets through: the six written in the block of `impl Group` in `tree.rs`, and no other
/// call, operand, signal, form or place.
#[test]
fn the_check_lets_through_the_groups_own_calls_and_no_other() {
    let group_with = |body: &str| {
        format!(
            "impl Group {{\n    fn f(&self, command: &mut Command) {{\n        {body}\n    }}\n}}\n"
        )
    };
    let start = "std::os::unix::process::CommandExt::process_group(command, 0);";
    let of_child = "rustix::process::Pid::from_child(child)";
    // The call as rustfmt writes it: it does not fit a line, and a wrapped call ends in a comma.
    let term = format!(
        "let _ = rustix::process::kill_process_group(\n    {of_child},\n    rustix::process::Signal::TERM,\n);"
    );
    let term = term.as_str();
    let kill = term.replace("TERM", "KILL");
    let allowed = |path: &str, source: &str| {
        refused(Path::new(path), source)
            .expect("a source")
            .is_empty()
    };
    // The signals sent on: the two the report forwards, the conversion of the number it received and
    // the call that sends the signal that gives.
    let signals = "const FORWARDED: &[rustix::process::Signal] =\n    &[rustix::process::Signal::INT, rustix::process::Signal::TERM];";
    let convert =
        "let Some(signal) = rustix::process::Signal::from_named_raw(number) else { return };";
    let send =
        format!("let _ = rustix::process::kill_process_group(\n    {of_child},\n    signal,\n);");
    let send = send.as_str();
    let all = format!("{start} {term} {kill} {signals} {convert} {send}");
    assert!(allowed("tree.rs", &group_with(&all)));
    assert!(allowed("tree.rs", &group_with(term)));
    assert!(allowed("tree.rs", &group_with(send)));
    assert!(allowed("tree.rs", &group_with(signals)));
    assert!(allowed("tree.rs", &group_with(convert)));
    let mut let_through = Vec::new();
    for (what, path, source) in [
        (
            "the same text in another file",
            "other.rs",
            group_with(&all),
        ),
        (
            "the same text in a tree.rs below the top",
            "nested/tree.rs",
            group_with(&all),
        ),
        (
            "a second signal call",
            "tree.rs",
            group_with(&format!("{term} {term}")),
        ),
        (
            "a second call that sends a received signal",
            "tree.rs",
            group_with(&format!("{send} {send}")),
        ),
        (
            "a second list of the forwarded signals",
            "tree.rs",
            group_with(&format!("{signals} {signals}")),
        ),
        (
            "a second conversion of a number into a signal",
            "tree.rs",
            group_with(&format!("{convert} {convert}")),
        ),
        (
            "a received signal sent to another operand, a pid",
            "tree.rs",
            group_with(&send.replace(of_child, "pid")),
        ),
        (
            "a received signal sent to another child",
            "tree.rs",
            group_with(&send.replace(of_child, "rustix::process::Pid::from_child(other)")),
        ),
        (
            "a received signal sent to the system's first process",
            "tree.rs",
            group_with(&send.replace(of_child, "rustix::process::Pid::INIT")),
        ),
        (
            "a received signal sent to the report's own process",
            "tree.rs",
            group_with(&send.replace(of_child, "rustix::process::getpid()")),
        ),
        (
            "a received signal sent to one process and not a group",
            "tree.rs",
            group_with(&send.replace("kill_process_group", "kill_process")),
        ),
        (
            "a signal that is not the one received",
            "tree.rs",
            group_with(&send.replace("signal,", "rustix::process::Signal::HUP,")),
        ),
        (
            "a list of the forwarded signals that adds one",
            "tree.rs",
            group_with(&signals.replace("TERM]", "TERM, rustix::process::Signal::HUP]")),
        ),
        (
            "a list of the forwarded signals that adds the one that cannot be caught",
            "tree.rs",
            group_with(&signals.replace("INT,", "INT, rustix::process::Signal::KILL,")),
        ),
        (
            "the signal that cannot be caught, named as a constant",
            "tree.rs",
            group_with(&convert.replace("Signal::from_named_raw(number)", "Signal::KILL")),
        ),
        (
            "the conversion of a number that is not the one received",
            "tree.rs",
            group_with(&convert.replace("(number)", "(9)")),
        ),
        (
            "the sends and the list outside the block of the impl",
            "tree.rs",
            format!(
                "fn stray(&self) {{ {send} {signals} {convert} }}\n{}",
                group_with("()")
            ),
        ),
        (
            "a second start",
            "tree.rs",
            group_with(&format!("{start} {start}")),
        ),
        (
            "a start with a decimal number that is not 0",
            "tree.rs",
            group_with(&start.replace(", 0)", ", 123)")),
        ),
        (
            "a start with a hexadecimal number",
            "tree.rs",
            group_with(&start.replace(", 0)", ", 0x7b)")),
        ),
        (
            "a start with a 0 that is written another way",
            "tree.rs",
            group_with(&start.replace(", 0)", ", 0x0)")),
        ),
        (
            "another operand, a pid",
            "tree.rs",
            group_with(&term.replace(of_child, "pid")),
        ),
        (
            "another operand, a field",
            "tree.rs",
            group_with(&term.replace(of_child, "self.other")),
        ),
        (
            "another child",
            "tree.rs",
            group_with(&term.replace(of_child, "rustix::process::Pid::from_child(other)")),
        ),
        (
            "the system's first process",
            "tree.rs",
            group_with(&term.replace(of_child, "rustix::process::Pid::INIT")),
        ),
        (
            "the report's own process",
            "tree.rs",
            group_with(&term.replace(of_child, "rustix::process::getpid()")),
        ),
        (
            "a pid made from a number",
            "tree.rs",
            group_with(&term.replace(of_child, "rustix::process::Pid::from_raw(1)")),
        ),
        (
            "another signal",
            "tree.rs",
            group_with(&term.replace("TERM", "HUP")),
        ),
        (
            "one process and not a group",
            "tree.rs",
            group_with(&term.replace("kill_process_group", "kill_process")),
        ),
        (
            "the report's own group",
            "tree.rs",
            group_with(
                "let _ = rustix::process::kill_current_process_group(rustix::process::Signal::TERM);",
            ),
        ),
        (
            "libc's call",
            "tree.rs",
            group_with("let _ = libc::killpg(child, 15);"),
        ),
        (
            "an import of the signal type",
            "tree.rs",
            format!("use rustix::process::Signal;\n{}", group_with(&all)),
        ),
        (
            "a start spelled as a method",
            "tree.rs",
            group_with("command.process_group(0);"),
        ),
        (
            "the calls outside the block of the impl",
            "tree.rs",
            format!("fn stray(&self) {{ {term} }}\n{}", group_with("()")),
        ),
        (
            "the calls in the block of another impl",
            "tree.rs",
            format!(
                "impl Other {{ fn f(&self) {{ {term} }} }}\n{}",
                group_with("()")
            ),
        ),
    ] {
        if allowed(path, &source) {
            let_through.push(what);
        }
    }
    assert!(let_through.is_empty(), "let through: {let_through:#?}");
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
        "rustix::process::kill_process_group(group, signal)",
        "rustix::process::kill_process(pid, signal)",
        "rustix::process::kill_current_process_group(signal)",
        "libc::killpg(group, 15)",
        "let signal: Signal = x;",
        "command.process_group(0);",
        "let signal = SIGKILL;",
        "let remove = std::fs::remove_file;",
        "std::fs::remove_file::<std::path::PathBuf>(path)",
        "(std::fs::remove_file)(path)",
        "use std::fs::remove_dir_all as clean;",
        "let signal_it = Child::kill;",
        "rustix::process::waitpid(Some(pid), options)",
        "let reaped = rustix::process::waitid(id, options);",
        "libc::wait4(pid, status, 0, usage)",
        "m! { #[cfg(test)] fn f() { std::fs::remove_file(x); } }",
        "macro_rules! m { () => { #[cfg(test)] fn f() { child.kill(); } } }",
        "let rename = 1;",
        "rename = other;",
        "state.rename = 1;",
        "call!(rename = (\"old\", \"new\"));",
        "macro_rules! call { ($f:ident = ($a:expr)) => { std::fs::$f($a) }; }\ncall!(rename = (\"o\", \"n\"));",
        "#[serde(rename = std::fs::rename)]\nstruct S;",
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
        "#[cfg_attr(feature = \"x\", serde(rename = \"y\"))]\nstruct S;",
        "#![serde(rename = \"x\")]",
        "#[serde(alias = \"y\", rename = \"x\")]\nfn f() {}",
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
        "#[cfg(test)]\n#[derive(Debug)]\nstruct X { a: u8 }\nfn product() {}",
        "#[cfg(test)]\n#[allow(dead_code)]\nfn helper() { std::fs::remove_file(x); }",
        "#[cfg(test)]\nunsafe { std::fs::remove_file(x); }\nfn product() {}",
        "#[cfg(test)]\npub(crate) fn helper() { std::fs::remove_file(x); }",
        "#[cfg(test)]\nimpl X { fn f(&self) { child.kill(); } }",
        "#[cfg(test)]\nconst X: u8 = { std::fs::remove_file(x); 1 };",
        "#[cfg(test)]\ntype T = u8;\nfn product() {}",
        "#[cfg(test)]\nuse ::std::fs;\nfn product() {}",
        "#[cfg(test)]\nunsafe impl Send for X {}\nfn product() {}",
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
        // A `#[cfg(test)]` that is on no item skips nothing: a match arm, an argument, a field.
        "fn p() { match x { #[cfg(test)] A => 1, B => { std::fs::remove_file(p); 2 } } }",
        "fn p() { foo(#[cfg(test)] 1, std::fs::remove_file(p)); }",
        "fn p() { let s = S { #[cfg(test)] a: 1, b: std::fs::remove_file(p) }; }",
        "fn p() { #[cfg(test)] let a = 1; std::fs::remove_file(p); }",
        // A field named by a raw identifier is read by the lexer as the keyword, and is no item.
        "fn p() { let _ = S { #[cfg(test)] r#type: 1, value: std::fs::remove_file(p) }; }",
        "fn p() { let _ = S { #[cfg(test)] r#type, value: std::fs::remove_file(p) }; }",
        "fn p() { let _ = S { #[cfg(test)] r#fn: 1, value: std::fs::remove_file(p) }; }",
        "fn p() { let _ = S { #[cfg(test)] r#use: 1, value: std::fs::remove_file(p) }; }",
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

/// The names of the programs that send a signal to a process: a word of shell text that holds one,
/// in any case, is read as the program.
const SIGNALLERS: [&str; 4] = ["kill", "pkill", "killall", "taskkill"];

/// The names of the calls that reap a process by its number.
const REAPS: [&str; 3] = ["waitpid", "waitid", "wait4"];

/// Whether `text`, taken as shell text, sends a signal: a part of it has a word that holds one of
/// the names of [`SIGNALLERS`], in any case and anywhere in the word (`pkill`, `taskkill.exe`,
/// `{kill,}`, `k=kill`), whatever comes before that word (a wrapper and its options, an assignment,
/// a keyword), unless the word is `kill`, with or without a path, and the next word is `-0`, which
/// asks whether a process exists and sends nothing, and no later word of the part is an option. The
/// text is decoded first, as far as the shell decodes it without running anything: a line
/// continuation is joined, the `$` that opens a `$'...'` or a `$"..."` quote and each quote and each
/// backslash are removed, so that a quoted or an escaped option is an option (`kill -0 "-s" KILL`,
/// `kill -0 \-s KILL`) and a quoted command, as in `trap 'kill -9 $c' TERM`, is read with the words
/// around it, which can only add refusals to what it says on its own. A `<` and a `>` end a word, so
/// that a redirection on a name hides nothing. The text is cut at `;`, `|`, `&`, a new line, a back
/// tick, `$(`, a bracket and a brace, and each word of a part is read with the complete list of the
/// words after it. The scan cannot see a name or an option that the shell makes when it runs, from
/// text that holds neither: `/bin/k?ll -9 1`, `$(printf ki)ll -9 1` and `kill -0 $'\x2ds' 9 "$p"`
/// pass.
fn signals_by_text(text: &str) -> bool {
    text.replace("\\\n", "")
        .replace("$'", "'")
        .replace("$\"", "\"")
        .replace(['\'', '"', '\\'], "")
        .replace("$(", ";")
        .replace(['<', '>'], " ")
        .split([';', '|', '&', '\n', '`', '(', ')', '{', '}'])
        .any(|part| {
            let words: Vec<&str> = part.split_whitespace().collect();
            words.iter().enumerate().any(|(at, word)| {
                let lower = word.to_ascii_lowercase();
                SIGNALLERS.iter().any(|name| lower.contains(name))
                    && !(word.rsplit('/').next() == Some("kill")
                        && words.get(at + 1) == Some(&"-0")
                        && !words[at + 2..].iter().any(|later| later.starts_with('-')))
            })
        })
}

/// Whether the `wait` at `at` is the wait of a `Child`: after a `.`, or after `Child::`.
fn waits_for_a_child(tokens: &[Token], at: usize) -> bool {
    (at >= 1 && tokens[at - 1].is_punct('.'))
        || (at >= 3
            && tokens[at - 1].is_punct(':')
            && tokens[at - 2].is_punct(':')
            && tokens[at - 3].ident() == Some("Child"))
}

/// What in the Rust source of a case file sends a signal or reaps a process by its number, each with
/// its line: a text that holds a program of [`SIGNALLERS`] (but for `kill -0`), the type `Signal`,
/// every name of a signal and every name that begins `kill` (which covers `Child::kill` and
/// `kill_process_group`), `start_kill`, and a call of [`REAPS`] or of a bare `wait`, which reaps any
/// child, none of which a case makes: the wait of a `Child` (`child.wait()`, `Child::wait`) is
/// let through.
fn case_refused(source: &str) -> Result<Vec<String>, String> {
    let tokens: Vec<Token> = lex(source)
        .map_err(|error| format!("line {}: {}", error.line, error.what))?
        .into_iter()
        .filter(|token| !token.is_comment())
        .collect();
    let mut found = Vec::new();
    for (at, token) in tokens.iter().enumerate() {
        let what = match &token.tok {
            Tok::Str(text, _) if signals_by_text(text) => format!("the text {text:?}"),
            Tok::Ident(name)
                if name == SIGNAL_TYPE
                    || name.starts_with("kill")
                    || (name.starts_with("SIG")
                        && name.chars().nth(3).is_some_and(char::is_uppercase))
                    || name == "start_kill"
                    || REAPS.contains(&name.as_str())
                    || (name == "wait" && !waits_for_a_child(&tokens, at)) =>
            {
                format!("`{name}`")
            }
            _ => continue,
        };
        found.push(format!("line {}: {what}", token.line));
    }
    Ok(found)
}

/// What in the text of a shell script sends a signal, each with its line; and, when no line does,
/// the text as a whole, in which a command can run across a line continuation.
fn script_refused(source: &str) -> Vec<String> {
    let mut found: Vec<String> = source
        .lines()
        .enumerate()
        .filter(|(_, line)| signals_by_text(line))
        .map(|(at, line)| format!("line {}: the text {line:?}", at + 1))
        .collect();
    if found.is_empty() && signals_by_text(source) {
        found.push("the text across a line continuation".to_owned());
    }
    found
}

/// The files of the fixture `time-limits` that run: its Rust sources and its scripts.
fn fixture_files(directory: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for entry in std::fs::read_dir(directory).expect("a directory") {
        let path = entry.expect("an entry").path();
        if path.is_dir() {
            if path.file_name().is_some_and(|name| name != "target") {
                files.extend(fixture_files(&path));
            }
        } else if path
            .extension()
            .is_some_and(|extension| extension == "rs" || extension == "sh")
        {
            files.push(path);
        }
    }
    files.sort();
    files
}

/// What in the file at `path` the check of the case files refuses.
fn case_file_refused(path: &Path, source: &str) -> Result<Vec<String>, String> {
    if path.extension().is_some_and(|extension| extension == "sh") {
        return Ok(script_refused(source));
    }
    case_refused(source)
}

#[test]
fn the_case_files_send_no_signal_and_reap_by_number_in_no_case() {
    let tests = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
    let mut files = vec![tests.join("tree.rs"), tests.join("execution.rs")];
    let fixture = fixture_files(&tests.join("fixtures").join("time-limits"));
    assert!(
        fixture.len() >= 5,
        "the fixture's files were not found: {fixture:?}"
    );
    files.extend(fixture);
    for path in files {
        let source = std::fs::read_to_string(&path).expect("a case file");
        match case_file_refused(&path, &source) {
            Ok(hits) => assert!(hits.is_empty(), "{}: {hits:#?}", path.display()),
            Err(problem) => panic!("{}: {problem}", path.display()),
        }
    }
}

/// The check of the case files refuses each way a case can send a signal and each call that reaps by
/// number, and lets through a look (`kill -0`).
#[test]
fn the_check_of_the_case_files_refuses_each_signal_and_reap_and_lets_through_a_look() {
    let refused_rust = [
        (
            "a signal to a group",
            "fn f() { rustix::process::kill_process_group(group, rustix::process::Signal::KILL); }",
        ),
        ("the type that names a signal", "fn f(signal: Signal) {}"),
        (
            "a kill of a child",
            "fn f(child: &mut Child) { child.kill(); }",
        ),
        ("the system's call", "fn f() { libc::killpg(1, 9); }"),
        ("a name of a signal", "fn f() { let s = SIGHUP; }"),
        (
            "a kill of a recorded pid",
            "fn f(pid: &str) { run(&format!(\"kill -9 {pid} 2>/dev/null\")); }",
        ),
        ("a kill by name", "fn f() { run(\"kill -KILL 123\"); }"),
        (
            "a kill with a signal named",
            "fn f() { run(\"kill -s KILL 123\"); }",
        ),
        ("a kill with TERM", "fn f() { run(\"kill -TERM 123\"); }"),
        (
            "a kill after another command",
            "fn f() { run(\"true; kill -9 123\"); }",
        ),
        (
            "a kill by its path",
            "fn f() { run(\"/bin/kill -9 123\"); }",
        ),
        (
            "a look that is also a kill",
            "fn f() { run(\"kill -0 -s KILL 123\"); }",
        ),
        (
            "a kill of every process of a name",
            "fn f() { run(\"pkill sleep\"); }",
        ),
        (
            "a kill of a name, all",
            "fn f() { run(\"killall sleep\"); }",
        ),
        (
            "a kill after a look, in an if",
            "fn f() { run(\"if kill -0 \\\"$p\\\"; then kill -9 \\\"$p\\\"; fi\"); }",
        ),
        ("a kill in parentheses", "fn f() { run(\"(kill -9 1)\"); }"),
        ("a kill in braces", "fn f() { run(\"{ kill -9 1; }\"); }"),
        ("a kill after exec", "fn f() { run(\"exec kill -9 1\"); }"),
        (
            "a kill after command",
            "fn f() { run(\"command kill -9 1\"); }",
        ),
        (
            "a kill in a trap",
            "fn f() { run(\"trap 'kill -9 $c' TERM\"); }",
        ),
        (
            "a kill after an assignment",
            "fn f() { run(\"PATH=/bin kill -9 1\"); }",
        ),
        (
            "a kill by tokio",
            "fn f(child: &mut Child) { child.start_kill(); }",
        ),
        (
            "a reap of any child",
            "fn f() { rustix::process::wait(WaitOptions::empty()); }",
        ),
        (
            "an import of a reap of any child",
            "use rustix::process::{wait, Pid};",
        ),
        (
            "a reap by number",
            "fn another() { waitpid(None, WaitOptions::empty()); }",
        ),
        ("an import of the reap", "use rustix::process::waitpid;"),
        (
            "a reap by `waitid`",
            "fn other() { waitid(P::Pid(x), W::EXITED); }",
        ),
        (
            "a look with a quoted option",
            r#"fn f() { run("kill -0 \"-s\" KILL \"$p\""); }"#,
        ),
        (
            "a look with an option in single quotes",
            r#"fn f() { run("kill -0 '-s' KILL $p"); }"#,
        ),
        (
            "a look with a quoted option in a trap",
            r#"fn f() { run("trap 'kill -0 \"-s\" KILL $c' TERM"); }"#,
        ),
        (
            "a kill whose name is quoted in part",
            r#"fn f() { run("ki\"ll\" -9 1"); }"#,
        ),
        (
            "a kill after env and its option",
            r#"fn f() { run("env -i kill -9 1"); }"#,
        ),
        (
            "a kill after command and its option",
            r#"fn f() { run("command -p kill -9 1"); }"#,
        ),
        (
            "a kill after exec and its option",
            r#"fn f() { run("exec -a name kill -9 1"); }"#,
        ),
        (
            "a kill by xargs, with an option",
            r#"fn f() { run("xargs -0 kill -9"); }"#,
        ),
        (
            "a kill by xargs, with a count",
            r#"fn f() { run("xargs -n 1 kill"); }"#,
        ),
        (
            "a kill after nohup and the end of its options",
            r#"fn f() { run("nohup -- kill -9 1"); }"#,
        ),
        (
            "a kill after time and its option",
            r#"fn f() { run("time -p kill -9 1"); }"#,
        ),
        ("a kill by eval", r#"fn f() { run("eval kill -9 1"); }"#),
        ("a kill after nice", r#"fn f() { run("nice kill -9 1"); }"#),
        ("a kill after sudo", r#"fn f() { run("sudo kill -9 1"); }"#),
        (
            "a kill after setsid",
            r#"fn f() { run("setsid kill -9 1"); }"#,
        ),
        (
            "a look with escaped quotes in a double-quoted trap",
            r#"fn f() { run("trap \"kill -0 \\\"-s\\\" KILL \\\"$p\\\"\" TERM"); }"#,
        ),
        (
            "a look with an escaped option",
            r#"fn f() { run("kill -0 \\-s KILL \"$p\""); }"#,
        ),
        (
            "a look with an escaped option in a trap",
            r#"fn f() { run("trap 'kill -0 \\-s KILL \"$p\"' TERM"); }"#,
        ),
        (
            "a look with an option in ANSI-C quotes",
            r#"fn f() { run("kill -0 $'-s' KILL \"$p\""); }"#,
        ),
        (
            "a look with an option in locale quotes",
            r#"fn f() { run("kill -0 $\"-s\" KILL \"$p\""); }"#,
        ),
        (
            "a look with an option after a line continuation",
            r#"fn f() { run("kill -0 \\\n-s KILL \"$p\""); }"#,
        ),
        (
            "a kill with an escaped letter",
            r#"fn f() { run("ki\\ll -9 \"$p\""); }"#,
        ),
        (
            "a kill with an escaped letter, short",
            r#"fn f() { run("k\\ill -9 1"); }"#,
        ),
        (
            "a kill with its name in ANSI-C quotes",
            r#"fn f() { run("$'kill' -9 1"); }"#,
        ),
        (
            "a kill with a line continuation in its name",
            r#"fn f() { run("ki\\\nll -9 1"); }"#,
        ),
        (
            "a kill with a redirection on its name",
            r#"fn f() { run("kill>/dev/null -9 \"$p\""); }"#,
        ),
        (
            "a kill with an input redirection on its name",
            r#"fn f() { run("kill</dev/null -9 1"); }"#,
        ),
        (
            "a kill with a descriptor redirection on its name",
            r#"fn f() { run("kill>&2 -9 1"); }"#,
        ),
        (
            "a kill with a capital letter",
            r#"fn f() { run("Kill -9 1"); }"#,
        ),
        (
            "a kill by a variable that holds its name",
            r#"fn f() { run("k=kill; $k -9 1"); }"#,
        ),
        (
            "a kill by a default for its name",
            r#"fn f() { run("${K:-kill} -9 1"); }"#,
        ),
        (
            "a kill by a brace expansion",
            r#"fn f() { run("{kill,} -9 1"); }"#,
        ),
        (
            "a kill with the field separator between its words",
            r#"fn f() { run("kill${IFS}-9${IFS}1"); }"#,
        ),
        (
            "a kill by a Windows name",
            r#"fn f() { run("taskkill.exe /F /PID 1"); }"#,
        ),
    ];
    let let_through_rust = [
        (
            "a look",
            "fn f(pid: &str) { run(&format!(\"kill -0 {pid} 2>/dev/null\")); }",
        ),
        ("a look, written alone", "fn f() { run(\"kill -0 123\"); }"),
        (
            "a look in an if",
            "fn f() { run(\"if kill -0 \\\"$p\\\"; then :; fi\"); }",
        ),
        (
            "a look with a quoted pid",
            r#"fn f() { run("kill -0 \"$p\" 2>/dev/null"); }"#,
        ),
        (
            "the wait of a child",
            "fn f(child: &mut Child) { child.wait(); }",
        ),
        (
            "the wait of Child, as a value",
            "fn f() { g(Child::wait); }",
        ),
        (
            "an ignored signal",
            "fn f() { run(\"trap '' TERM; sleep 61\"); }",
        ),
    ];
    let refused_script = [
        ("a script that kills a pid", "sleep 61 &\nkill -9 $!\n"),
        (
            "a script that looks and then kills",
            "if kill -0 \"$p\"; then kill -9 \"$p\"; fi\n",
        ),
        ("a script that kills in a trap", "trap 'kill -9 $c' TERM\n"),
        ("a script that kills after a pipe", "ps | kill -9 1\n"),
        (
            "a script that looks with a quoted option",
            "kill -0 \"-s\" KILL \"$p\"\n",
        ),
        ("a script that kills after env", "env -i kill -9 1\n"),
        ("a script that kills after setsid", "setsid kill -9 1\n"),
        (
            "a script that looks with escaped quotes in a trap",
            "trap \"kill -0 \\\"-s\\\" KILL \\\"$p\\\"\" TERM\n",
        ),
        (
            "a script that looks with an escaped option",
            "kill -0 \\-s KILL \"$p\" 2>/dev/null\n",
        ),
        (
            "a script that looks across a line continuation",
            "kill -0 \\\n-s KILL \"$p\"\n",
        ),
        (
            "a script that kills across a line continuation in its name",
            "ki\\\nll -9 1\n",
        ),
        (
            "a script that kills with an escaped letter",
            "k\\ill -9 1\n",
        ),
        (
            "a script that kills with a redirection on its name",
            "kill</dev/null -9 1\n",
        ),
    ];
    let let_through_script = [
        ("a script that waits", "trap '' TERM\nsleep 61 &\nwait\n"),
        ("a script that looks", "kill -0 $! 2>/dev/null\n"),
        (
            "a script that looks in an if",
            "if kill -0 \"$p\"; then :; fi\n",
        ),
        (
            "a script that looks at a quoted pid",
            "kill -0 \"$p\" 2>/dev/null\n",
        ),
    ];
    let mut wrong = Vec::new();
    for (what, code) in refused_rust {
        if case_refused(code).expect("a source").is_empty() {
            wrong.push(format!("{what}: let through"));
        }
    }
    for (what, code) in let_through_rust {
        if !case_refused(code).expect("a source").is_empty() {
            wrong.push(format!("{what}: refused"));
        }
    }
    for (what, text) in refused_script {
        if script_refused(text).is_empty() {
            wrong.push(format!("{what}: let through"));
        }
    }
    for (what, text) in let_through_script {
        if !script_refused(text).is_empty() {
            wrong.push(format!("{what}: refused"));
        }
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
}
