//! One place in the host's crates asks where its own program is: [`kr_ipc::install`].
//!
//! A program of an installed release that finds another program by its own path has to find the
//! one of its own release, and on macOS `std::env::current_exe` is the path the program was started
//! as, which after an update can resolve to another release's directory. So the host's crates ask
//! `kr_ipc::install` instead, which reads the kernel's record of the image, and this test reads
//! every source file under `crates/*/src` and fails, naming the file and the line, wherever
//! production code names `current_exe` outside `crates/kr-ipc/src/install.rs`.
//!
//! Test code is not held to the rule: a test finds its own binary to start copies of it. An item
//! whose `cfg` cannot hold without `test` or without the `testing` feature, which only this
//! workspace's tests turn on, is passed over, and so is every file such an item declares. An item
//! under any other condition, `cfg(any(test, unix))` among them, may compile into a program and is
//! read like any other.
//!
//! The reading is by tokens: comments and string and character literals are not code and are
//! passed over, so a sentence that mentions `current_exe` is not a use of it.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// The one file that may ask.
const ALLOWED: &str = "crates/kr-ipc/src/install.rs";

/// The name nothing else may use.
const NAME: &str = "current_exe";

/// One token of a source, as far as this reading needs to tell them apart.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Token {
    Ident(String),
    Punct(char),
    Literal(String),
}

/// A token and the line it starts on.
#[derive(Clone, Debug)]
struct Located {
    token: Token,
    line: usize,
}

/// Splits a source into tokens, dropping comments, whitespace and the contents of literals.
fn lex(text: &str) -> Vec<Located> {
    let chars: Vec<char> = text.chars().collect();
    let mut tokens = Vec::new();
    let mut at = 0;
    let mut line = 1;
    while at < chars.len() {
        let c = chars[at];
        if c == '\n' {
            line += 1;
            at += 1;
            continue;
        }
        if c.is_whitespace() {
            at += 1;
            continue;
        }
        if c == '/' && chars.get(at + 1) == Some(&'/') {
            while at < chars.len() && chars[at] != '\n' {
                at += 1;
            }
            continue;
        }
        if c == '/' && chars.get(at + 1) == Some(&'*') {
            let mut depth = 0;
            loop {
                if at + 1 >= chars.len() {
                    at = chars.len();
                    break;
                }
                if chars[at] == '/' && chars[at + 1] == '*' {
                    depth += 1;
                    at += 2;
                } else if chars[at] == '*' && chars[at + 1] == '/' {
                    depth -= 1;
                    at += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    if chars[at] == '\n' {
                        line += 1;
                    }
                    at += 1;
                }
            }
            continue;
        }
        // A raw string: `r"..."`, `r#"..."#`, and the byte and C forms.
        let raw_start = match (c, chars.get(at + 1), chars.get(at + 2)) {
            ('r', Some('"' | '#'), _) => Some(at + 1),
            ('b' | 'c', Some('r'), Some('"' | '#')) => Some(at + 2),
            _ => None,
        };
        if let Some(mut hashes_at) = raw_start {
            let mut hashes = 0;
            while chars.get(hashes_at) == Some(&'#') {
                hashes += 1;
                hashes_at += 1;
            }
            if chars.get(hashes_at) == Some(&'"') {
                let start_line = line;
                at = hashes_at + 1;
                let start = at;
                let mut end = chars.len();
                while at < chars.len() {
                    if chars[at] == '"'
                        && (0..hashes).all(|offset| chars.get(at + 1 + offset) == Some(&'#'))
                    {
                        end = at;
                        at += 1 + hashes;
                        break;
                    }
                    if chars[at] == '\n' {
                        line += 1;
                    }
                    at += 1;
                }
                tokens.push(Located {
                    token: Token::Literal(chars[start..end.min(chars.len())].iter().collect()),
                    line: start_line,
                });
                continue;
            }
        }
        // A string, byte string or C string.
        let quote_at = match (c, chars.get(at + 1)) {
            ('"', _) => Some(at),
            ('b' | 'c', Some('"')) => Some(at + 1),
            _ => None,
        };
        if let Some(quote_at) = quote_at {
            let start_line = line;
            at = quote_at + 1;
            let start = at;
            while at < chars.len() && chars[at] != '"' {
                if chars[at] == '\\' {
                    at += 1;
                }
                if chars.get(at) == Some(&'\n') {
                    line += 1;
                }
                at += 1;
            }
            // The text as written, escapes and all: a module's `#[path]` has none.
            let text: String = chars[start..at.min(chars.len())].iter().collect();
            at += 1;
            tokens.push(Located {
                token: Token::Literal(text),
                line: start_line,
            });
            continue;
        }
        // A character or byte literal, which a lifetime or a label is told apart from by its
        // closing quote.
        let char_at = match (c, chars.get(at + 1)) {
            ('\'', _) => Some(at),
            ('b', Some('\'')) => Some(at + 1),
            _ => None,
        };
        if let Some(char_at) = char_at {
            let escaped = chars.get(char_at + 1) == Some(&'\\');
            let closes = if escaped {
                // Past the escape's first character, which may itself be a quote.
                (char_at + 3..chars.len().min(char_at + 14)).find(|&index| chars[index] == '\'')
            } else if chars.get(char_at + 2) == Some(&'\'') {
                Some(char_at + 2)
            } else {
                None
            };
            if let Some(closes) = closes {
                at = closes + 1;
                tokens.push(Located {
                    token: Token::Literal(String::new()),
                    line,
                });
                continue;
            }
            // A lifetime or a label: the quote and the identifier after it.
            at = char_at + 1;
            while at < chars.len() && (chars[at].is_alphanumeric() || chars[at] == '_') {
                at += 1;
            }
            continue;
        }
        if c.is_alphabetic() || c == '_' {
            let start = at;
            while at < chars.len() && (chars[at].is_alphanumeric() || chars[at] == '_') {
                at += 1;
            }
            let mut word: String = chars[start..at].iter().collect();
            if let Some(stripped) = word.strip_prefix("r#") {
                word = stripped.to_owned();
            }
            tokens.push(Located {
                token: Token::Ident(word),
                line,
            });
            continue;
        }
        if c.is_ascii_digit() {
            while at < chars.len() && (chars[at].is_alphanumeric() || chars[at] == '_') {
                at += 1;
            }
            tokens.push(Located {
                token: Token::Literal(String::new()),
                line,
            });
            continue;
        }
        tokens.push(Located {
            token: Token::Punct(c),
            line,
        });
        at += 1;
    }
    tokens
}

/// What reading one file found.
#[derive(Debug, Default)]
struct Reading {
    /// The lines production code names [`NAME`] on.
    uses: Vec<usize>,
    /// The modules the file declares under `cfg(test)`, each as `(name, path attribute)`.
    test_modules: Vec<(String, Option<String>)>,
}

/// Whether a `cfg` predicate, its tokens from just inside `cfg(`, cannot hold without `test` or
/// without the `testing` feature, and the index just past it.
///
/// `all` needs one of its parts to; `any` needs every one of its parts to; `not` and anything else
/// is taken to hold in a program, which fails safe.
fn needs_a_test(tokens: &[&Token], at: usize) -> (bool, usize) {
    let word = |index: usize| match tokens.get(index) {
        Some(Token::Ident(word)) => Some(word.as_str()),
        _ => None,
    };
    let punct = |index: usize, wanted: char| matches!(tokens.get(index), Some(Token::Punct(found)) if *found == wanted);
    match word(at) {
        Some("test") => (true, at + 1),
        Some("feature") if punct(at + 1, '=') => {
            let testing =
                matches!(tokens.get(at + 2), Some(Token::Literal(text)) if text == "testing");
            (testing, at + 3)
        }
        Some(combinator @ ("all" | "any" | "not")) if punct(at + 1, '(') => {
            let mut parts = Vec::new();
            let mut next = at + 2;
            while next < tokens.len() && !punct(next, ')') {
                let (needs, after) = needs_a_test(tokens, next);
                parts.push(needs);
                next = if punct(after, ',') { after + 1 } else { after };
                if after == next && !punct(after, ',') && !punct(after, ')') {
                    // Something this reading does not follow: skip it.
                    next += 1;
                }
            }
            let needs = match combinator {
                "all" => parts.iter().any(|needs| *needs),
                "any" => !parts.is_empty() && parts.iter().all(|needs| *needs),
                _ => false,
            };
            (needs, next + 1)
        }
        // Any other predicate, `unix` or `target_os = "..."` among them, holds in some program.
        Some(_) if punct(at + 1, '=') => (false, at + 3),
        _ => (false, at + 1),
    }
}

/// Whether the attribute starting at `at` (just past `#[`) is a `cfg` that cannot hold without a
/// test, the path it names when it is a `#[path]`, and where it ends.
fn attribute(tokens: &[Located], at: usize) -> (bool, Option<String>, usize) {
    // Past the attribute's closing bracket, whatever is inside.
    let mut depth = 1;
    let mut end = at;
    while end < tokens.len() && depth > 0 {
        match tokens[end].token {
            Token::Punct('[') => depth += 1,
            Token::Punct(']') => depth -= 1,
            _ => {}
        }
        end += 1;
    }
    let inside: Vec<&Token> = tokens[at..end.saturating_sub(1)]
        .iter()
        .map(|located| &located.token)
        .collect();
    let ident = |index: usize, word: &str| matches!(inside.get(index), Some(Token::Ident(found)) if found == word);
    let punct = |index: usize, wanted: char| matches!(inside.get(index), Some(Token::Punct(found)) if *found == wanted);
    let only_test = ident(0, "cfg") && punct(1, '(') && needs_a_test(&inside, 2).0;
    // `#[path = "..."]`, which names the declared module's file relative to the declaring one's
    // directory.
    let path = match (ident(0, "path") && punct(1, '='), inside.get(2)) {
        (true, Some(Token::Literal(text))) => Some(text.clone()),
        _ => None,
    };
    (only_test, path, end)
}

/// Reads one source: every production use of [`NAME`], and the modules declared under `cfg(test)`.
fn read(text: &str) -> Reading {
    let tokens = lex(text);
    let mut reading = Reading::default();
    let mut at = 0;
    while at < tokens.len() {
        if tokens[at].token == Token::Punct('#')
            && tokens.get(at + 1).map(|located| &located.token) == Some(&Token::Punct('['))
        {
            // One or more attributes, then the item they are on.
            let mut test_only = false;
            let mut path = None;
            while at < tokens.len()
                && tokens[at].token == Token::Punct('#')
                && tokens.get(at + 1).map(|located| &located.token) == Some(&Token::Punct('['))
            {
                let (only_test, named_path, end) = attribute(&tokens, at + 2);
                test_only |= only_test;
                if named_path.is_some() {
                    path = named_path;
                }
                at = end;
            }
            if test_only {
                // The item the attributes are on: to the `;` or `,` that ends it at its own depth,
                // or through the braces it opens and a `;` or `,` right after them. A bracket that
                // closes what the item is inside ends the item without being part of it: an
                // attribute on the last field of a struct is followed by the struct's own `}`.
                let start = at;
                let mut depth = 0_i32;
                while at < tokens.len() {
                    match tokens[at].token {
                        Token::Punct('{' | '(' | '[') => depth += 1,
                        Token::Punct('}' | ')' | ']') => {
                            if depth == 0 {
                                break;
                            }
                            depth -= 1;
                            if depth == 0 && tokens[at].token == Token::Punct('}') {
                                at += 1;
                                if tokens.get(at).is_some_and(|next| {
                                    matches!(next.token, Token::Punct(';' | ','))
                                }) {
                                    at += 1;
                                }
                                break;
                            }
                        }
                        Token::Punct(';' | ',') if depth == 0 => {
                            at += 1;
                            break;
                        }
                        _ => {}
                    }
                    at += 1;
                }
                // `mod name;` declares a file that is test code as a whole.
                let item: Vec<&Token> = tokens[start..at]
                    .iter()
                    .map(|located| &located.token)
                    .collect();
                if let [
                    ..,
                    Token::Ident(keyword),
                    Token::Ident(name),
                    Token::Punct(';'),
                ] = item.as_slice()
                    && keyword == "mod"
                {
                    reading.test_modules.push((name.clone(), path));
                }
            }
            continue;
        }
        if tokens[at].token == Token::Ident(NAME.to_owned()) {
            reading.uses.push(tokens[at].line);
        }
        at += 1;
    }
    reading
}

/// Where the files a file's out-of-line modules live: beside `lib.rs`, `main.rs` and `mod.rs`, and
/// in the directory of the file's own name otherwise.
fn module_directory(file: &Path) -> PathBuf {
    let directory = file.parent().unwrap_or_else(|| Path::new("")).to_path_buf();
    match file.file_name().and_then(|name| name.to_str()) {
        Some("lib.rs" | "main.rs" | "mod.rs") => directory,
        _ => directory.join(file.file_stem().unwrap_or_default()),
    }
}

/// Every `.rs` file under `directory`, in path order.
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
        if entry.is_dir() {
            sources(&entry, found);
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

/// Every production use of [`NAME`] under `crates/*/src`, as `(file, line)` relative to the
/// workspace, and the number of files read.
fn uses_in(workspace: &Path) -> (Vec<(String, usize)>, usize) {
    let mut files = Vec::new();
    let crates = workspace.join("crates");
    let mut members: Vec<PathBuf> = std::fs::read_dir(&crates)
        .expect("the crates")
        .filter_map(Result::ok)
        .map(|entry| entry.path().join("src"))
        .filter(|source| source.is_dir())
        .collect();
    members.sort();
    for source in members {
        sources(&source, &mut files);
    }
    // Files a `cfg(test)` module declares are test code, and so is every file below them.
    let mut test_files: BTreeSet<PathBuf> = BTreeSet::new();
    let mut readings = Vec::new();
    for file in &files {
        let text = std::fs::read_to_string(file).expect("a source");
        let reading = read(&text);
        for (name, path) in &reading.test_modules {
            let directory = module_directory(file);
            match path {
                Some(path) => {
                    test_files.insert(file.parent().unwrap_or_else(|| Path::new("")).join(path));
                }
                None => {
                    test_files.insert(directory.join(format!("{name}.rs")));
                    test_files.insert(directory.join(name));
                }
            }
        }
        readings.push((file.clone(), reading));
    }
    let under_test = |file: &Path| {
        test_files
            .iter()
            .any(|test| file == test || file.starts_with(test))
    };
    let mut uses = Vec::new();
    for (file, reading) in readings {
        if under_test(&file) {
            continue;
        }
        let relative = file
            .strip_prefix(workspace)
            .expect("inside the workspace")
            .to_string_lossy()
            .replace('\\', "/");
        for line in reading.uses {
            uses.push((relative.clone(), line));
        }
    }
    (uses, files.len())
}

/// No production code in the host's crates asks where its program is, but the install module.
#[test]
fn only_the_install_module_asks_where_its_program_is() {
    let (uses, files) = uses_in(&workspace());
    assert!(
        files > 500,
        "the whole of crates/*/src was read, and it was: {files} files"
    );
    let outside: Vec<String> = uses
        .iter()
        .filter(|(file, _)| file != ALLOWED)
        .map(|(file, line)| format!("{file}:{line}"))
        .collect();
    assert!(
        outside.is_empty(),
        "these name `{NAME}` outside {ALLOWED}; ask kr_ipc::install for this process's own \
         release's program (`own`) or for the one an update replaces (`stable`) instead:\n{}",
        outside.join("\n")
    );
    // The control on the real tree: the reading does see production code, because the one
    // allowed use is found.
    assert!(
        uses.iter().any(|(file, _)| file == ALLOWED),
        "the reading found the install module's own use"
    );
}

/// The reading tells production code from test code, and code from what merely mentions it.
#[test]
fn the_reading_tells_code_from_tests_and_from_words() {
    // The controls: each of these is a use, and a reading that passed any of them over would let
    // one through.
    for source in [
        "fn f() { let _ = std::env::current_exe(); }",
        "#[cfg(any(test, unix))]\nfn f() { let _ = std::env::current_exe(); }",
        "#[cfg(unix)]\nmod inner { fn f() { let _ = std::env::current_exe(); } }",
        "use std::env::current_exe;",
        "fn f() -> &'static str { let _ = current_exe(); \"x\" }",
        "fn f() { let _ = ('\\'', 'a', b'\\\\'); let _ = current_exe(); }",
    ] {
        assert_eq!(read(source).uses.len(), 1, "{source}");
    }
    for source in [
        "// std::env::current_exe()\nfn f() {}",
        "/* current_exe */ fn f() {}",
        "fn f() { let _ = \"current_exe\"; let _ = r#\"current_exe\"#; }",
        "#[cfg(test)]\nmod tests { fn f() { let _ = std::env::current_exe(); } }",
        "#[cfg(test)]\n#[allow(dead_code)]\nfn f() { let _ = std::env::current_exe(); }",
        "#[cfg(all(test, unix))]\nmod tests { fn f() { let _ = std::env::current_exe(); } }",
        "#[cfg(all(windows, feature = \"testing\"))]\npub mod testing { fn f() { current_exe(); } }",
        "#[cfg(any(test, feature = \"testing\"))]\nfn f() { let _ = current_exe(); }",
    ] {
        assert!(read(source).uses.is_empty(), "{source}");
    }
    for source in [
        "#[cfg(feature = \"voice\")]\nfn f() { let _ = current_exe(); }",
        "#[cfg(not(test))]\nfn f() { let _ = current_exe(); }",
        "#[cfg(any(feature = \"testing\", target_os = \"linux\"))]\nfn f() { current_exe(); }",
    ] {
        assert_eq!(read(source).uses.len(), 1, "{source}");
    }
    // An attribute on a field ends with the field, and what follows the struct is read.
    let fields = read(
        "struct S {\n    a: u8,\n    #[cfg(feature = \"testing\")]\n    b: u8\n}\n\
         fn f() { let _ = S { a: 1, #[cfg(feature = \"testing\")] b: 2 }; current_exe(); }",
    );
    assert_eq!(fields.uses, vec![6]);
    // Code after a test module is production code again.
    let after =
        read("#[cfg(test)]\nmod tests { fn f() {} }\nfn g() { let _ = std::env::current_exe(); }");
    assert_eq!(after.uses, vec![3]);
    // A test module's own file is declared, and the declaration is found.
    let declared = read("#[cfg(test)]\nmod tests;\nfn g() {}");
    assert_eq!(declared.test_modules, vec![("tests".to_owned(), None)]);
    let by_path = read("#[cfg(test)]\n#[path = \"checks/one.rs\"]\nmod one;");
    assert_eq!(
        by_path.test_modules,
        vec![("one".to_owned(), Some("checks/one.rs".to_owned()))]
    );
    assert_eq!(
        module_directory(Path::new("crates/x/src/service.rs")),
        Path::new("crates/x/src/service")
    );
    assert_eq!(
        module_directory(Path::new("crates/x/src/lib.rs")),
        Path::new("crates/x/src")
    );
}
