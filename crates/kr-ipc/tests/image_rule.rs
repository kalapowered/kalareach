//! One place in the host's crates asks where its own program is: [`kr_ipc::install`].
//!
//! A program of an installed release that finds another program by its own path has to find the
//! one of its own release, and on macOS `std::env::current_exe` is the path the program was started
//! as, which after an update can resolve to another release's directory. So the host's crates ask
//! `kr_ipc::install` instead, which reads the kernel's record of the image, and this test reads
//! every source file under `crates/*/src` and fails, naming the file and the line, wherever
//! production code names `current_exe`, or macOS's `_NSGetExecutablePath`, outside
//! `crates/kr-ipc/src/install.rs`.
//!
//! Test code is not held to the rule: a test finds its own binary to start copies of it. An item
//! whose `cfg` cannot hold without `test` or without the `testing` feature, which only this
//! workspace's tests turn on, is passed over. An item under any other condition,
//! `cfg(any(test, unix))` among them, may compile into a program and is read like any other.
//!
//! A file is passed over only when nothing but test code declares it: every `mod` that names it
//! is under such a `cfg`, or is in a file that is itself test code. A file any production `mod`
//! names is read, whatever else names it, and so is a file no `mod` names. A crate's root, as Cargo
//! lists each target's, is read whatever names it, and the modules it declares live beside it. A
//! `mod` inside an inline module names its file under that module's directory, as the compiler
//! places it.
//!
//! What this reading cannot follow fails it rather than passing over the code: a production `mod`
//! whose file it does not hold (a `#[path]` out of `crates/*/src` among them), a `cfg_attr` that
//! names a module's path, an `include!` of source or an import of `include` that could rename it,
//! and a library or program root that is not under its crate's `src/`.
//!
//! The `testing` feature makes an item test code, so it must not be one a program turns on: a
//! normal or build dependency among the host's crates that asks for it, and a default feature that
//! enables it, fail the guard too. So does any other feature that exists for tests
//! ([`TEST_FEATURES`]), which compiles into a program a way in that only a test acts through, and
//! a feature of a host crate that is not named as one of those or as a part of the product
//! ([`PRODUCT_FEATURES`]), so that a feature added for tests cannot go unnamed.
//!
//! The reading is by tokens: comments and string and character literals are not code and are
//! passed over, so a sentence that mentions `current_exe` is not a use of it.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// The one file that may ask.
const ALLOWED: &str = "crates/kr-ipc/src/install.rs";

/// The names nothing else may use: the standard library's path of the running program, and macOS's
/// own call for it. The kernel's record of the image is `kr_ipc::install`'s to read.
const NAMES: [&str; 2] = ["current_exe", "_NSGetExecutablePath"];

/// The features that exist for tests, in whichever crate they are: each compiles seams into its
/// crate that only a test acts through, so a program built with one carries a way in that nothing
/// in the product uses. A host crate's feature that is for tests is named here.
const TEST_FEATURES: [&str; 3] = ["testing", "fault-injection", "git-fixtures"];

/// The features of the host's crates that are not for tests, as `(crate, feature)`: each adds code
/// or a dependency to the crate and none is a seam a test acts through.
const PRODUCT_FEATURES: [(&str, &str); 2] = [("kr-client", "terminal"), ("kr-term", "conformance")];

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

/// One `mod name;` a file declares.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Declaration {
    /// The module's name.
    name: String,
    /// The file its `#[path]` names, relative as written.
    path: Option<String>,
    /// The inline modules it is declared inside, outermost first, each as the directory it gives
    /// what is declared in it: its `#[path]`, or its name.
    inline: Vec<String>,
    /// Whether it compiles only into tests.
    test_only: bool,
}

/// What reading one file found.
#[derive(Debug, Default)]
struct Reading {
    /// The lines production code names one of [`NAMES`] on.
    uses: Vec<usize>,
    /// What production code does that this reading cannot follow, by line.
    unfollowed: Vec<(usize, &'static str)>,
    /// The modules the file declares out of line.
    declarations: Vec<Declaration>,
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
/// test, the path it names when it is a `#[path]`, whether it is a `cfg_attr` that names a path,
/// which puts a module's file where this reading does not follow, and where it ends.
fn attribute(tokens: &[Located], at: usize) -> (bool, Option<String>, bool, usize) {
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
    let via_cfg_attr = ident(0, "cfg_attr")
        && inside.windows(3).any(|window| {
            matches!(
                window,
                [Token::Ident(word), Token::Punct('='), Token::Literal(_)] if word == "path"
            )
        });
    (only_test, path, via_cfg_attr, end)
}

/// Reads one source: every production use of [`NAMES`], and every module it declares out of line.
fn read(text: &str) -> Reading {
    let tokens = lex(text);
    let mut reading = Reading::default();
    block(
        &tokens,
        0,
        tokens.len(),
        false,
        &mut Vec::new(),
        &mut reading,
    );
    reading
}

/// Reads the items of one module body, the tokens `at..end`: inside test code when `test_only`,
/// and inside the inline modules `inline` names.
fn block(
    tokens: &[Located],
    mut at: usize,
    end: usize,
    test_only: bool,
    inline: &mut Vec<String>,
    reading: &mut Reading,
) {
    let starts_attribute = |index: usize| {
        index + 1 < end
            && tokens[index].token == Token::Punct('#')
            && tokens[index + 1].token == Token::Punct('[')
    };
    while at < end {
        // One or more attributes, then the item they are on.
        let mut item_test_only = test_only;
        let mut path = None;
        let mut attributed = false;
        let mut cfg_attr_paths = Vec::new();
        while starts_attribute(at) {
            let (only_test, named_path, via_cfg_attr, after) = attribute(tokens, at + 2);
            item_test_only |= only_test;
            if named_path.is_some() {
                path = named_path;
            }
            if via_cfg_attr {
                cfg_attr_paths.push(tokens[at].line);
            }
            attributed = true;
            at = after;
        }
        if !item_test_only {
            for line in cfg_attr_paths {
                reading
                    .unfollowed
                    .push((line, "a cfg_attr names a module's path"));
            }
        }
        if let Some((name, after_name)) = module_item(tokens, at, end) {
            match tokens.get(after_name).map(|located| &located.token) {
                Some(Token::Punct(';')) => {
                    reading.declarations.push(Declaration {
                        name,
                        path,
                        inline: inline.clone(),
                        test_only: item_test_only,
                    });
                    at = after_name + 1;
                    continue;
                }
                Some(Token::Punct('{')) => {
                    let close = closing_brace(tokens, after_name, end);
                    inline.push(path.unwrap_or(name));
                    block(
                        tokens,
                        after_name + 1,
                        close,
                        item_test_only,
                        inline,
                        reading,
                    );
                    inline.pop();
                    at = close + 1;
                    continue;
                }
                _ => {}
            }
        }
        if attributed && item_test_only && !test_only {
            at = past_item(tokens, at, end);
            continue;
        }
        if at < end {
            if !test_only {
                if matches!(&tokens[at].token, Token::Ident(word) if NAMES.contains(&word.as_str()))
                {
                    reading.uses.push(tokens[at].line);
                }
                if tokens[at].token == Token::Ident("include".to_owned()) {
                    let next = tokens.get(at + 1).map(|next| &next.token);
                    if next == Some(&Token::Punct('!')) {
                        reading.unfollowed.push((
                            tokens[at].line,
                            "an include! brings in source where this reading does not follow",
                        ));
                    } else if matches!(next, Some(Token::Ident(word)) if word == "as") {
                        // `use std::include as load;`, `use std::{include as load};` and the like
                        // rename the macro, and `load!(..)` then brings in source under a name this
                        // reading does not look for. Whatever comes before it, an `include` that
                        // is renamed is refused.
                        reading.unfollowed.push((
                            tokens[at].line,
                            "an import of include under another name could bring in source",
                        ));
                    }
                }
            }
            at += 1;
        }
    }
}

/// When the tokens at `at` are `mod name`, after any visibility, the name and the index just past
/// it.
fn module_item(tokens: &[Located], at: usize, end: usize) -> Option<(String, usize)> {
    let token = |index: usize| (index < end).then(|| &tokens[index].token);
    let mut next = at;
    if token(next) == Some(&Token::Ident("pub".to_owned())) {
        next += 1;
        // `pub(crate)`, `pub(super)`, `pub(in path)`.
        if token(next) == Some(&Token::Punct('(')) {
            while next < end && token(next) != Some(&Token::Punct(')')) {
                next += 1;
            }
            next += 1;
        }
    }
    match (token(next), token(next + 1)) {
        (Some(Token::Ident(keyword)), Some(Token::Ident(name))) if keyword == "mod" => {
            Some((name.clone(), next + 2))
        }
        _ => None,
    }
}

/// The index of the brace that closes the one at `open`, or `end` when none does.
fn closing_brace(tokens: &[Located], open: usize, end: usize) -> usize {
    let mut depth = 0_usize;
    for (index, located) in tokens.iter().enumerate().take(end).skip(open) {
        match located.token {
            Token::Punct('{') => depth += 1,
            Token::Punct('}') => {
                depth -= 1;
                if depth == 0 {
                    return index;
                }
            }
            _ => {}
        }
    }
    end
}

/// The index just past the item starting at `at`: to the `;` or `,` that ends it at its own depth,
/// or through the braces it opens and a `;` or `,` right after them. A bracket that closes what the
/// item is inside ends the item without being part of it: an attribute on the last field of a
/// struct is followed by the struct's own `}`.
fn past_item(tokens: &[Located], mut at: usize, end: usize) -> usize {
    let mut depth = 0_i32;
    while at < end {
        match tokens[at].token {
            Token::Punct('{' | '(' | '[') => depth += 1,
            Token::Punct('}' | ')' | ']') => {
                if depth == 0 {
                    return at;
                }
                depth -= 1;
                if depth == 0 && tokens[at].token == Token::Punct('}') {
                    at += 1;
                    if at < end && matches!(tokens[at].token, Token::Punct(';' | ',')) {
                        at += 1;
                    }
                    return at;
                }
            }
            Token::Punct(';' | ',') if depth == 0 => return at + 1,
            _ => {}
        }
        at += 1;
    }
    at
}

/// Where the files a file's out-of-line modules live: beside a crate's root, one of `roots`, and
/// beside a `mod.rs`, and in the directory of the file's own name otherwise.
fn module_directory(file: &Path, roots: &BTreeSet<PathBuf>) -> PathBuf {
    let directory = file.parent().unwrap_or_else(|| Path::new("")).to_path_buf();
    if roots.contains(file) || file.file_name() == Some(std::ffi::OsStr::new("mod.rs")) {
        directory
    } else {
        directory.join(file.file_stem().unwrap_or_default())
    }
}

/// What Cargo says of the workspace's packages, without resolving any dependency.
fn cargo_metadata(workspace: &Path) -> serde_json::Value {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let output = std::process::Command::new(cargo)
        .args([
            "metadata",
            "--no-deps",
            "--format-version",
            "1",
            "--offline",
        ])
        .current_dir(workspace)
        .stdin(std::process::Stdio::null())
        .output()
        .expect("cargo metadata runs");
    assert!(
        output.status.success(),
        "cargo metadata: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("cargo metadata's JSON")
}

/// A target's root, as a path this reading compares.
fn root_of(target: &serde_json::Value) -> Option<PathBuf> {
    let path = target["src_path"].as_str()?;
    Some(normalise(
        &Path::new(path)
            .canonicalize()
            .unwrap_or_else(|_| PathBuf::from(path)),
    ))
}

/// The root of every target of the workspace's packages, as Cargo lists them.
fn crate_roots(metadata: &serde_json::Value) -> BTreeSet<PathBuf> {
    metadata["packages"]
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|package| package["targets"].as_array().into_iter().flatten())
        .filter_map(root_of)
        .collect()
}

/// The library and program roots of the packages under `crates/`, as paths relative to
/// `workspace`, and those of them that are not under their package's `src/`.
///
/// This reading covers `crates/*/src`, so a program whose root is elsewhere, a `path` in a
/// `[[bin]]` among them, would go unread: each is named in `outside`, and the guard fails on one
/// rather than pass over it. `examined` says which roots were looked at, so a reading that looked
/// at none cannot pass.
struct Roots {
    examined: Vec<String>,
    outside: Vec<String>,
}

fn production_roots(metadata: &serde_json::Value, workspace: &Path) -> Roots {
    const PRODUCTION: [&str; 7] = [
        "lib",
        "rlib",
        "dylib",
        "cdylib",
        "staticlib",
        "proc-macro",
        "bin",
    ];
    let mut roots = Roots {
        examined: Vec::new(),
        outside: Vec::new(),
    };
    for package in metadata["packages"].as_array().into_iter().flatten() {
        let Some(manifest) = package["manifest_path"].as_str() else {
            continue;
        };
        let directory = normalise(
            Path::new(manifest)
                .parent()
                .unwrap_or_else(|| Path::new("")),
        );
        if !directory.starts_with(workspace.join("crates")) {
            continue;
        }
        for target in package["targets"].as_array().into_iter().flatten() {
            let production = target["kind"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(serde_json::Value::as_str)
                .any(|kind| PRODUCTION.contains(&kind));
            let Some(root) = root_of(target) else {
                continue;
            };
            if !production {
                continue;
            }
            let relative = root
                .strip_prefix(workspace)
                .unwrap_or(&root)
                .to_string_lossy()
                .replace('\\', "/");
            if !root.starts_with(directory.join("src")) {
                roots.outside.push(relative.clone());
            }
            roots.examined.push(relative);
        }
    }
    roots.examined.sort();
    roots.outside.sort();
    roots
}

/// Where a feature that exists for tests ([`TEST_FEATURES`]) of one of the host's crates could be
/// turned on in a program, as `crate: how`.
///
/// A program is built from one of the host's crates with its default features and with what its
/// normal and build dependencies ask of theirs. Each of those starts a walk over the features that
/// turn others on, in the crate's own table and in its dependencies' (`feature`, `dep:name`,
/// `name/feature`, `name?/feature`), and any walk that reaches a test feature of one of the host's
/// crates is named. A dev dependency is not part of a program.
fn test_features_in_production(metadata: &serde_json::Value, workspace: &Path) -> Vec<String> {
    /// A package's dependency as its feature table names it, and what it asks of it.
    struct Asked<'a> {
        package: &'a str,
        features: Vec<&'a str>,
        defaults: bool,
    }

    let packages: BTreeMap<&str, &serde_json::Value> = metadata["packages"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|package| Some((package["name"].as_str()?, package)))
        .collect();
    let host_crates = workspace.join("crates");
    let is_host_crate = |package: &serde_json::Value| {
        package["manifest_path"]
            .as_str()
            .is_some_and(|manifest| normalise(Path::new(manifest)).starts_with(&host_crates))
    };
    /// The dependencies a program is built with, by the name the package's features know each by.
    /// A dependency that is listed more than once (normal, build and dev, or once for each target)
    /// is one: what the program's entries ask for is joined, and a dev entry is not part of it.
    fn dependencies_of(package: &serde_json::Value) -> BTreeMap<String, Asked<'_>> {
        let mut found: BTreeMap<String, Asked<'_>> = BTreeMap::new();
        for dependency in package["dependencies"].as_array().into_iter().flatten() {
            let Some(name) = dependency["name"].as_str() else {
                continue;
            };
            if !matches!(dependency["kind"].as_str(), None | Some("build")) {
                continue;
            }
            let key = dependency["rename"].as_str().unwrap_or(name).to_owned();
            let asked = found.entry(key).or_insert(Asked {
                package: name,
                features: Vec::new(),
                defaults: false,
            });
            asked.features.extend(
                dependency["features"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(serde_json::Value::as_str),
            );
            asked.defaults |= dependency["uses_default_features"]
                .as_bool()
                .unwrap_or(true);
        }
        found
    }
    // Every feature a walk from `start` turns on, as `(package, feature)`.
    let walk = |start: Vec<(String, String)>| -> BTreeSet<(String, String)> {
        let mut seen: BTreeSet<(String, String)> = BTreeSet::new();
        let mut pending = start;
        while let Some((name, feature)) = pending.pop() {
            if !seen.insert((name.clone(), feature.clone())) {
                continue;
            }
            let Some(package) = packages.get(name.as_str()) else {
                continue;
            };
            let dependencies = dependencies_of(package);
            let turns_on =
                |key: &str, pending: &mut Vec<(String, String)>, feature: Option<&str>| {
                    let Some(asked) = dependencies.get(key) else {
                        return;
                    };
                    let base: Vec<&str> = match feature {
                        Some(feature) => vec![feature],
                        None => asked.features.clone(),
                    };
                    for feature in base {
                        pending.push((asked.package.to_owned(), feature.to_owned()));
                    }
                    if feature.is_none() && asked.defaults {
                        pending.push((asked.package.to_owned(), "default".to_owned()));
                    }
                };
            let entries = package["features"][feature.as_str()].as_array();
            for entry in entries
                .into_iter()
                .flatten()
                .filter_map(serde_json::Value::as_str)
            {
                if let Some(key) = entry.strip_prefix("dep:") {
                    turns_on(key, &mut pending, None);
                } else if let Some((key, other)) = entry.split_once('/') {
                    let key = key.strip_suffix('?').unwrap_or(key);
                    turns_on(key, &mut pending, Some(other));
                    if !entry.contains("?/") {
                        turns_on(key, &mut pending, None);
                    }
                } else {
                    pending.push((name.clone(), entry.to_owned()));
                }
            }
        }
        seen
    };
    let mut found = BTreeSet::new();
    for package in packages.values().filter(|package| is_host_crate(package)) {
        let name = package["name"].as_str().unwrap_or("a package");
        let mut starts = vec![(
            "its default features".to_owned(),
            vec![(name.to_owned(), "default".to_owned())],
        )];
        for (key, asked) in dependencies_of(package) {
            let mut start: Vec<(String, String)> = asked
                .features
                .iter()
                .map(|feature| (asked.package.to_owned(), (*feature).to_owned()))
                .collect();
            if asked.defaults {
                start.push((asked.package.to_owned(), "default".to_owned()));
            }
            starts.push((format!("a normal or build dependency on {key}"), start));
        }
        for (how, start) in starts {
            for (turned_on, feature) in walk(start) {
                let host_feature = TEST_FEATURES.contains(&feature.as_str())
                    && packages
                        .get(turned_on.as_str())
                        .is_some_and(|turned_on| is_host_crate(turned_on));
                if host_feature {
                    found.insert(format!(
                        "{name}: the {feature} feature of {turned_on} is turned on by {how}"
                    ));
                }
            }
        }
    }
    found.into_iter().collect()
}

/// The features of the host's crates that [`TEST_FEATURES`] and [`PRODUCT_FEATURES`] both leave
/// unnamed, as `crate: feature`. A feature added for tests under a name the first list lacks would
/// otherwise be turned on in a program without anything noticing.
fn unclassified_features(metadata: &serde_json::Value, workspace: &Path) -> Vec<String> {
    let host_crates = workspace.join("crates");
    let mut found = Vec::new();
    for package in metadata["packages"].as_array().into_iter().flatten() {
        let (Some(name), Some(manifest)) =
            (package["name"].as_str(), package["manifest_path"].as_str())
        else {
            continue;
        };
        if !normalise(Path::new(manifest)).starts_with(&host_crates) {
            continue;
        }
        for feature in package["features"]
            .as_object()
            .into_iter()
            .flatten()
            .map(|(feature, _)| feature)
        {
            let named = feature == "default"
                || TEST_FEATURES.contains(&feature.as_str())
                || PRODUCT_FEATURES.contains(&(name, feature.as_str()));
            if !named {
                found.push(format!("{name}: {feature}"));
            }
        }
    }
    found.sort();
    found
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

/// The directory a declaration inside the inline modules `inline` of `file` names its files from.
fn inline_directory(file: &Path, inline: &[String], roots: &BTreeSet<PathBuf>) -> PathBuf {
    inline
        .iter()
        .fold(module_directory(file, roots), |directory, part| {
            directory.join(part)
        })
}

/// The files a declaration of `file` can name: its `#[path]`, relative to the declaring file's
/// directory outside an inline module and to the inline module's directory inside one, and
/// otherwise `name.rs` or `name/mod.rs`.
fn declared_files(
    file: &Path,
    declaration: &Declaration,
    roots: &BTreeSet<PathBuf>,
) -> Vec<PathBuf> {
    match &declaration.path {
        Some(path) if declaration.inline.is_empty() => vec![normalise(
            &file.parent().unwrap_or_else(|| Path::new("")).join(path),
        )],
        Some(path) => vec![normalise(
            &inline_directory(file, &declaration.inline, roots).join(path),
        )],
        None => {
            let directory = inline_directory(file, &declaration.inline, roots);
            vec![
                normalise(&directory.join(format!("{}.rs", declaration.name))),
                normalise(&directory.join(&declaration.name).join("mod.rs")),
            ]
        }
    }
}

/// A path with its `.` and `..` parts taken out, as far as the path itself says.
fn normalise(path: &Path) -> PathBuf {
    let mut normal = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                normal.pop();
            }
            other => normal.push(other),
        }
    }
    normal
}

/// What reading the sources found.
struct Found {
    /// Every production use of [`NAMES`], as `(file, line)`.
    uses: Vec<(PathBuf, usize)>,
    /// What this reading cannot follow in production code, as `(file, what)`.
    unfollowed: Vec<(PathBuf, String)>,
}

/// Reads `sources`, each `(file, text)`, where `roots` are the crates' roots.
///
/// A file is production code when it is a crate's root, when no `mod` names it, or when a `mod`
/// that is not test code names it from a file that is production code; the rest is test code. A
/// production `mod` none of whose files is among the sources, a `cfg_attr` that names a path and an
/// `include!` are what this reading cannot follow, and are returned rather than passed over.
fn read_sources(sources: &[(PathBuf, String)], roots: &BTreeSet<PathBuf>) -> Found {
    let readings: BTreeMap<PathBuf, Reading> = sources
        .iter()
        .map(|(file, text)| (normalise(file), read(text)))
        .collect();
    let named: BTreeSet<PathBuf> = readings
        .iter()
        .flat_map(|(file, reading)| {
            reading
                .declarations
                .iter()
                .flat_map(|declaration| declared_files(file, declaration, roots))
        })
        .collect();
    let mut production: BTreeSet<PathBuf> = readings
        .keys()
        .filter(|file| roots.contains(*file) || !named.contains(*file))
        .cloned()
        .collect();
    // What production code declares is production code, until nothing more is.
    loop {
        let found: Vec<PathBuf> = production
            .iter()
            .flat_map(|file| {
                readings[file]
                    .declarations
                    .iter()
                    .filter(|declaration| !declaration.test_only)
                    .flat_map(|declaration| declared_files(file, declaration, roots))
            })
            .filter(|declared| readings.contains_key(declared) && !production.contains(declared))
            .collect();
        if found.is_empty() {
            break;
        }
        production.extend(found);
    }
    let mut unfollowed = Vec::new();
    for file in &production {
        let reading = &readings[file];
        for declaration in reading
            .declarations
            .iter()
            .filter(|declaration| !declaration.test_only)
        {
            let held = declared_files(file, declaration, roots)
                .iter()
                .any(|candidate| readings.contains_key(candidate));
            if !held {
                unfollowed.push((
                    file.clone(),
                    format!(
                        "mod {} names a file this reading does not hold",
                        declaration.name
                    ),
                ));
            }
        }
        for (line, what) in &reading.unfollowed {
            unfollowed.push((file.clone(), format!("line {line}: {what}")));
        }
    }
    Found {
        uses: production
            .iter()
            .flat_map(|file| readings[file].uses.iter().map(|line| (file.clone(), *line)))
            .collect(),
        unfollowed,
    }
}

/// Every production use of [`NAMES`] under `crates/*/src`, as `(file, line)` relative to the
/// workspace, what the reading could not follow, as `file: what`, and the number of files read,
/// given the crates' `roots`.
fn uses_in(
    workspace: &Path,
    roots: &BTreeSet<PathBuf>,
) -> (Vec<(String, usize)>, Vec<String>, usize) {
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
    let sources: Vec<(PathBuf, String)> = files
        .iter()
        .map(|file| {
            (
                file.clone(),
                std::fs::read_to_string(file).expect("a source"),
            )
        })
        .collect();
    let relative = |file: &Path| {
        file.strip_prefix(workspace)
            .expect("inside the workspace")
            .to_string_lossy()
            .replace('\\', "/")
    };
    let found = read_sources(&sources, roots);
    let uses = found
        .uses
        .iter()
        .map(|(file, line)| (relative(file), *line))
        .collect();
    let unfollowed = found
        .unfollowed
        .iter()
        .map(|(file, what)| format!("{}: {what}", relative(file)))
        .collect();
    (uses, unfollowed, files.len())
}

/// No production code in the host's crates asks where its program is, but the install module.
#[test]
fn only_the_install_module_asks_where_its_program_is() {
    let workspace = workspace();
    let metadata = cargo_metadata(&workspace);
    let roots = crate_roots(&metadata);
    let (uses, unfollowed, files) = uses_in(&workspace, &roots);
    assert!(
        files > 500,
        "the whole of crates/*/src was read, and it was: {files} files"
    );
    let production = production_roots(&metadata, &workspace);
    assert!(
        production.outside.is_empty(),
        "these library and program roots of the host's crates are not under their crate's src/, \
         which this reading covers, so nothing of them was read:\n{}",
        production.outside.join("\n")
    );
    // The control on the real tree: the roots were looked at, the host's own among them.
    for root in ["crates/kr-ipc/src/lib.rs", "crates/kr-cli/src/bin/kr.rs"] {
        assert!(
            production.examined.iter().any(|examined| examined == root),
            "the reading examined {root} as a production root, and found only {} roots",
            production.examined.len()
        );
    }
    assert!(
        unfollowed.is_empty(),
        "production code this reading cannot follow, which could hide a use of a name it looks \
         for; either declare it where the reading follows or teach the reading:\n{}",
        unfollowed.join("\n")
    );
    for root in ["crates/kr-ipc/src/lib.rs", "crates/kr-cli/src/bin/kr.rs"] {
        assert!(
            roots.contains(&workspace.join(root)),
            "Cargo lists {root} as a crate's root"
        );
    }
    let outside: Vec<String> = uses
        .iter()
        .filter(|(file, _)| file != ALLOWED)
        .map(|(file, line)| format!("{file}:{line}"))
        .collect();
    assert!(
        outside.is_empty(),
        "these name {NAMES:?} outside {ALLOWED}; ask kr_ipc::install for this process's own \
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

/// No feature that exists for tests is on in a program built from the host's crates, and every
/// feature of those crates is named as one for tests or as one that is not. The `testing` feature
/// is the one whose items the reading above passes over as test code.
#[test]
fn no_feature_that_exists_for_tests_is_on_in_a_program() {
    let workspace = workspace();
    let metadata = cargo_metadata(&workspace);
    // The control on the real tree: the guard reads the crates that have the seams, as host crates
    // under `crates/`, so a reading that recognised none of them cannot pass.
    let has = |name: &str, feature: &str| {
        metadata["packages"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|package| {
                package["name"] == name
                    && package["manifest_path"].as_str().is_some_and(|manifest| {
                        normalise(Path::new(manifest)).starts_with(workspace.join("crates"))
                    })
                    && package["features"].get(feature).is_some()
            })
    };
    assert!(
        has("kr-changeset", "fault-injection") && has("kr-project", "git-fixtures"),
        "the workspace's metadata lists the features the guard is about, in host crates"
    );
    let turned_on = test_features_in_production(&metadata, &workspace);
    assert!(
        turned_on.is_empty(),
        "a feature that exists for tests could be turned on in a program; a crate's default \
         features and a normal or build dependency must not enable it, and a test turns it on \
         through a dev dependency:\n{}",
        turned_on.join("\n")
    );
    let unnamed = unclassified_features(&metadata, &workspace);
    assert!(
        unnamed.is_empty(),
        "these features are named neither in TEST_FEATURES nor in PRODUCT_FEATURES; say which \
         they are, so that a feature for tests is never left on in a program unnoticed:\n{}",
        unnamed.join("\n")
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
        "fn f() { let _ = _NSGetExecutablePath(); }",
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
    assert_eq!(
        declared.declarations,
        vec![Declaration {
            name: "tests".to_owned(),
            path: None,
            inline: Vec::new(),
            test_only: true,
        }]
    );
    let by_path = read("#[cfg(test)]\n#[path = \"checks/one.rs\"]\npub(crate) mod one;");
    assert_eq!(
        by_path.declarations,
        vec![Declaration {
            name: "one".to_owned(),
            path: Some("checks/one.rs".to_owned()),
            inline: Vec::new(),
            test_only: true,
        }]
    );
    // Inside inline modules, with the directory each gives, and test code inside a test module.
    let nested = read(
        "mod outer {\n    mod inner;\n    #[path = \"moved\"]\n    mod away { mod deep; }\n}\n\
         #[cfg(test)]\nmod tests { mod helpers; fn f() { current_exe(); } }",
    );
    assert!(nested.uses.is_empty());
    assert_eq!(
        nested
            .declarations
            .iter()
            .map(|declaration| (
                declaration.name.as_str(),
                declaration.inline.join("/"),
                declaration.test_only
            ))
            .collect::<Vec<_>>(),
        vec![
            ("inner", "outer".to_owned(), false),
            ("deep", "outer/moved".to_owned(), false),
            ("helpers", "tests".to_owned(), true),
        ]
    );
    let roots: BTreeSet<PathBuf> = ["crates/x/src/lib.rs", "crates/x/src/bin/tool.rs"]
        .into_iter()
        .map(PathBuf::from)
        .collect();
    for (file, directory) in [
        ("crates/x/src/service.rs", "crates/x/src/service"),
        ("crates/x/src/lib.rs", "crates/x/src"),
        ("crates/x/src/bin/tool.rs", "crates/x/src/bin"),
        ("crates/x/src/service/mod.rs", "crates/x/src/service"),
    ] {
        assert_eq!(
            module_directory(Path::new(file), &roots),
            Path::new(directory),
            "{file}"
        );
    }
    assert_eq!(
        normalise(Path::new("crates/x/src/../../y/tests/mod.rs")),
        Path::new("crates/y/tests/mod.rs")
    );
}

/// A file is passed over only when nothing but test code declares it, and a declaration inside an
/// inline module names the file the compiler reads for it.
#[test]
fn a_file_is_test_code_only_when_nothing_else_declares_it() {
    let with_roots = |roots: &[&str], files: &[(&str, &str)]| {
        let sources: Vec<(PathBuf, String)> = files
            .iter()
            .map(|(path, text)| (PathBuf::from(path), (*text).to_owned()))
            .collect();
        let roots: BTreeSet<PathBuf> = roots.iter().map(PathBuf::from).collect();
        let mut found: Vec<String> = read_sources(&sources, &roots)
            .uses
            .into_iter()
            .map(|(file, _)| file.to_string_lossy().replace('\\', "/"))
            .collect();
        found.sort();
        found
    };
    // What the reading could not follow, as `file: what`.
    let unfollowed = |files: &[(&str, &str)]| {
        let sources: Vec<(PathBuf, String)> = files
            .iter()
            .map(|(path, text)| (PathBuf::from(path), (*text).to_owned()))
            .collect();
        let roots: BTreeSet<PathBuf> = [PathBuf::from("src/lib.rs")].into_iter().collect();
        let mut found: Vec<String> = read_sources(&sources, &roots)
            .unfollowed
            .into_iter()
            .map(|(file, what)| format!("{}: {what}", file.to_string_lossy().replace('\\', "/")))
            .collect();
        found.sort();
        found
    };
    let uses = |files: &[(&str, &str)]| with_roots(&["src/lib.rs"], files);
    let asks = "pub fn f() { let _ = std::env::current_exe(); }";
    // A file a test module and a production module both load is production code.
    assert_eq!(
        uses(&[
            (
                "src/lib.rs",
                "#[cfg(test)]\n#[path = \"shared.rs\"]\nmod tests;\nmod shared;",
            ),
            ("src/shared.rs", asks),
        ]),
        vec!["src/shared.rs"]
    );
    // The control: loaded by the test module alone, it is test code.
    assert!(
        uses(&[
            (
                "src/lib.rs",
                "#[cfg(test)]\n#[path = \"shared.rs\"]\nmod tests;"
            ),
            ("src/shared.rs", asks),
        ])
        .is_empty()
    );
    // Nested: an inline module's declarations are under its directory, in a file named for its
    // module and in `lib.rs` alike; a test module's are test code, and so is what a test file
    // declares.
    assert_eq!(
        uses(&[
            (
                "src/lib.rs",
                "mod outer { mod inner; #[cfg(test)] mod checks; }\nmod a;\n#[cfg(test)]\nmod tests;",
            ),
            ("src/outer/inner.rs", asks),
            ("src/outer/checks.rs", asks),
            ("src/a.rs", "mod inline { #[path = \"other.rs\"] mod c; }"),
            ("src/a/inline/other.rs", asks),
            ("src/tests.rs", "mod deeper;"),
            ("src/tests/deeper.rs", asks),
        ]),
        vec!["src/a/inline/other.rs", "src/outer/inner.rs"]
    );
    // The control: a file at the place a reading that forgot the inline module would give is not
    // what the declaration names, and is read as a file nothing declares.
    assert_eq!(
        uses(&[
            ("src/lib.rs", "mod outer { #[cfg(test)] mod checks; }"),
            ("src/checks.rs", asks),
            ("src/outer/checks.rs", asks),
        ]),
        vec!["src/checks.rs"]
    );
    // A binary's root declares its modules beside itself, as `lib.rs` does, so its production
    // module is the file a test module of it also loads.
    assert_eq!(
        with_roots(
            &["src/bin/tool.rs"],
            &[
                (
                    "src/bin/tool.rs",
                    "mod shared;\n#[cfg(test)]\n#[path = \"shared.rs\"]\nmod checks;\nfn main() {}",
                ),
                ("src/bin/shared.rs", asks),
            ],
        ),
        vec!["src/bin/shared.rs"]
    );
    // And a crate's root is read whatever else declares it.
    assert_eq!(
        with_roots(
            &["src/lib.rs", "src/bin/tool.rs"],
            &[
                (
                    "src/lib.rs",
                    "#[cfg(test)]\n#[path = \"bin/tool.rs\"]\nmod tool_checks;"
                ),
                ("src/bin/tool.rs", asks),
            ],
        ),
        vec!["src/bin/tool.rs"]
    );

    // What the reading cannot follow is named, not passed over: a production module whose file it
    // does not hold, a `cfg_attr` that names a path, and an `include!` of source.
    assert_eq!(
        unfollowed(&[("src/lib.rs", "#[path = \"../tools/extra.rs\"]\nmod extra;")]),
        vec!["src/lib.rs: mod extra names a file this reading does not hold"]
    );
    assert_eq!(
        unfollowed(&[
            (
                "src/lib.rs",
                "#[cfg_attr(unix, path = \"other.rs\")]\nmod x;\n#[cfg(test)]\nmod tests;",
            ),
            ("src/x.rs", "")
        ]),
        vec!["src/lib.rs: line 1: a cfg_attr names a module's path"]
    );
    assert_eq!(
        unfollowed(&[("src/lib.rs", "fn f() {}\ninclude!(\"generated.rs\");")]),
        vec!["src/lib.rs: line 2: an include! brings in source where this reading does not follow"]
    );
    // An import of `include` that renames it could bring in source under another name, whatever
    // the import's shape.
    for import in [
        "use std::include as load;",
        "use std::{include as load};",
        "use std::{self, include as load};",
        "use include as load;",
    ] {
        let source = format!("{import}\nload!(\"../tools/extra.rs\");");
        assert_eq!(
            unfollowed(&[("src/lib.rs", source.as_str())]),
            vec![
                "src/lib.rs: line 1: an import of include under another name could bring in source"
            ],
            "{import}"
        );
    }
    // The controls: the same declarations are followed when their files are held, in test code
    // nothing is named, and `include_str!` is data, not source.
    assert!(
        unfollowed(&[
            ("src/lib.rs", "#[path = \"../tools/extra.rs\"]\nmod extra;"),
            ("tools/extra.rs", ""),
        ])
        .is_empty()
    );
    assert!(
        unfollowed(&[(
            "src/lib.rs",
            "#[cfg(test)]\nmod tests { include!(\"x.rs\"); #[cfg_attr(unix, path = \"a.rs\")] mod a; }\n\
             #[cfg(test)]\n#[path = \"../tests/x.rs\"]\nmod x;\n\
             const P: &str = include_str!(\"../package.json\");",
        )])
        .is_empty()
    );
}

/// A library or program whose root is not under its crate's `src/` is named, so the guard cannot
/// pass over it: only the targets that ship in a program are held to it, and only the crates of
/// the host.
#[test]
fn a_root_outside_the_source_directory_is_named() {
    let metadata = serde_json::json!({ "packages": [
        {
            "manifest_path": "/w/crates/a/Cargo.toml",
            "targets": [
                { "kind": ["lib"], "src_path": "/w/crates/a/src/lib.rs" },
                { "kind": ["bin"], "src_path": "/w/crates/a/src/bin/tool.rs" },
                { "kind": ["test"], "src_path": "/w/crates/a/tests/checks.rs" },
                { "kind": ["custom-build"], "src_path": "/w/crates/a/build.rs" },
            ],
        },
        {
            "manifest_path": "/w/crates/b/Cargo.toml",
            "targets": [
                { "kind": ["bin"], "src_path": "/w/crates/b/tools/tool.rs" },
                { "kind": ["cdylib", "rlib"], "src_path": "/w/crates/b/native/lib.rs" },
            ],
        },
        {
            "manifest_path": "/w/apps/c/Cargo.toml",
            "targets": [{ "kind": ["bin"], "src_path": "/w/apps/c/main.rs" }],
        },
    ]});
    let roots = production_roots(&metadata, Path::new("/w"));
    assert_eq!(
        roots.outside,
        vec!["crates/b/native/lib.rs", "crates/b/tools/tool.rs"]
    );
    assert_eq!(
        roots.examined,
        vec![
            "crates/a/src/bin/tool.rs",
            "crates/a/src/lib.rs",
            "crates/b/native/lib.rs",
            "crates/b/tools/tool.rs",
        ],
        "only what ships in a program is looked at, and only in the host's crates"
    );
    // The control: nothing is named when every root is where the reading looks.
    let inside = serde_json::json!({ "packages": [{
        "manifest_path": "/w/crates/a/Cargo.toml",
        "targets": [
            { "kind": ["lib"], "src_path": "/w/crates/a/src/lib.rs" },
            { "kind": ["bin"], "src_path": "/w/crates/a/src/bin/tool.rs" },
        ],
    }]});
    assert!(
        production_roots(&inside, Path::new("/w"))
            .outside
            .is_empty()
    );
}

/// A `testing` feature a program could turn on is named, so the reading's passing over of items
/// under it as test code cannot be undone by a dependency: a normal or build dependency that asks for
/// it, a default feature that enables it, and a feature that a dependency's request or a default
/// leads to, each directly or through other features and dependencies.
#[test]
fn a_testing_feature_a_program_could_turn_on_is_named() {
    let host = |name: &str, dependencies: serde_json::Value, features: serde_json::Value| {
        serde_json::json!({
            "name": name,
            "manifest_path": format!("/w/crates/{name}/Cargo.toml"),
            "dependencies": dependencies,
            "features": features,
        })
    };
    let dependency = |name: &str, kind: serde_json::Value, features: &[&str]| {
        serde_json::json!({
            "name": name,
            "kind": kind,
            "features": features,
            "uses_default_features": true,
        })
    };
    let metadata = serde_json::json!({ "packages": [
        host(
            "a",
            serde_json::json!([
                dependency("b", serde_json::Value::Null, &["testing"]),
                dependency("c", serde_json::json!("build"), &["testing"]),
                dependency("d", serde_json::json!("dev"), &["testing"]),
                dependency("e", serde_json::Value::Null, &["extra"]),
            ]),
            serde_json::json!({ "default": [] }),
        ),
        host("b", serde_json::json!([]), serde_json::json!({ "testing": [] })),
        host("c", serde_json::json!([]), serde_json::json!({ "testing": [] })),
        host("d", serde_json::json!([]), serde_json::json!({ "testing": [] })),
        host(
            "e",
            serde_json::json!([]),
            serde_json::json!({ "extra": ["testing"], "testing": [] }),
        ),
        host(
            "f",
            serde_json::json!([]),
            serde_json::json!({ "default": ["testing"], "testing": [] }),
        ),
        host(
            "i",
            serde_json::json!([dependency("j", serde_json::Value::Null, &[])]),
            serde_json::json!({ "default": ["more"], "more": ["j/testing"] }),
        ),
        host("j", serde_json::json!([]), serde_json::json!({ "testing": [] })),
        host(
            "k",
            serde_json::json!([dependency("l", serde_json::Value::Null, &[])]),
            serde_json::json!({}),
        ),
        host(
            "l",
            serde_json::json!([]),
            serde_json::json!({ "default": ["testing"], "testing": [] }),
        ),
        serde_json::json!({
            "name": "g",
            "manifest_path": "/w/apps/g/Cargo.toml",
            "dependencies": [dependency("b", serde_json::Value::Null, &["testing"])],
            "features": {},
        }),
    ]});
    assert_eq!(
        test_features_in_production(&metadata, Path::new("/w")),
        vec![
            "a: the testing feature of b is turned on by a normal or build dependency on b",
            "a: the testing feature of c is turned on by a normal or build dependency on c",
            "a: the testing feature of e is turned on by a normal or build dependency on e",
            "f: the testing feature of f is turned on by its default features",
            "i: the testing feature of j is turned on by its default features",
            "k: the testing feature of l is turned on by a normal or build dependency on l",
            "l: the testing feature of l is turned on by its default features",
        ]
    );
    // A dependency listed as a normal one and as a dev one is the same dependency: what the
    // program's entry asks is not lost to the dev entry, in either order, and what only the dev
    // entry asks is not counted.
    for (first, second) in [("null", "dev"), ("dev", "null")] {
        let kind = |kind: &str| {
            if kind == "null" {
                serde_json::Value::Null
            } else {
                serde_json::json!(kind)
            }
        };
        let listed = |normal_asks: &[&str], dev_asks: &[&str]| {
            let entry = |kind_name: &str| {
                let asks = if kind_name == "null" {
                    normal_asks
                } else {
                    dev_asks
                };
                dependency("b", kind(kind_name), asks)
            };
            serde_json::json!({ "packages": [
                host(
                    "a",
                    serde_json::json!([entry(first), entry(second)]),
                    serde_json::json!({ "default": [] }),
                ),
                host(
                    "b",
                    serde_json::json!([]),
                    serde_json::json!({ "extra": ["testing"], "testing": [] }),
                ),
            ]})
        };
        assert_eq!(
            test_features_in_production(&listed(&["extra"], &[]), Path::new("/w")),
            vec!["a: the testing feature of b is turned on by a normal or build dependency on b"],
            "the program's entry asks: {first} then {second}"
        );
        assert!(
            test_features_in_production(&listed(&[], &["extra"]), Path::new("/w")).is_empty(),
            "only the dev entry asks: {first} then {second}"
        );
    }
    // Two entries of a dependency that a program is built with (a normal one and a build one, or
    // one for each target) are joined, in either order: what either asks is asked.
    for (first_asks, second_asks) in [(&["extra"][..], &[][..]), (&[][..], &["extra"][..])] {
        let joined = serde_json::json!({ "packages": [
            host(
                "a",
                serde_json::json!([
                    dependency("b", serde_json::Value::Null, first_asks),
                    dependency("b", serde_json::json!("build"), second_asks),
                ]),
                serde_json::json!({ "default": [] }),
            ),
            host(
                "b",
                serde_json::json!([]),
                serde_json::json!({ "extra": ["testing"], "testing": [] }),
            ),
        ]});
        assert_eq!(
            test_features_in_production(&joined, Path::new("/w")),
            vec!["a: the testing feature of b is turned on by a normal or build dependency on b"],
            "{first_asks:?} then {second_asks:?}"
        );
    }
    // Default features on in one entry only are on: `b`'s defaults name `testing`. With every entry
    // asking for none, only `b` itself, built with its own defaults, is named.
    let without_defaults = |kind: serde_json::Value| {
        serde_json::json!({
            "name": "b",
            "kind": kind,
            "features": [],
            "uses_default_features": false,
        })
    };
    let defaults_of = |one: serde_json::Value, other: serde_json::Value| {
        serde_json::json!({ "packages": [
            host(
                "a",
                serde_json::json!([one, other]),
                serde_json::json!({ "default": [] }),
            ),
            host(
                "b",
                serde_json::json!([]),
                serde_json::json!({ "default": ["testing"], "testing": [] }),
            ),
        ]})
    };
    assert_eq!(
        test_features_in_production(
            &defaults_of(
                without_defaults(serde_json::Value::Null),
                dependency("b", serde_json::json!("build"), &[])
            ),
            Path::new("/w")
        ),
        vec![
            "a: the testing feature of b is turned on by a normal or build dependency on b",
            "b: the testing feature of b is turned on by its default features",
        ]
    );
    // The same with the entry that has them first, so that the last entry does not decide.
    assert_eq!(
        test_features_in_production(
            &defaults_of(
                dependency("b", serde_json::json!("build"), &[]),
                without_defaults(serde_json::Value::Null)
            ),
            Path::new("/w")
        ),
        vec![
            "a: the testing feature of b is turned on by a normal or build dependency on b",
            "b: the testing feature of b is turned on by its default features",
        ]
    );
    assert_eq!(
        test_features_in_production(
            &defaults_of(
                without_defaults(serde_json::Value::Null),
                without_defaults(serde_json::json!("build"))
            ),
            Path::new("/w")
        ),
        vec!["b: the testing feature of b is turned on by its default features"]
    );
    // A crate whose own default feature names a dependency's `testing`, where that dependency is
    // also a dev dependency, is named as well.
    let doubled = serde_json::json!({ "packages": [
        host(
            "a",
            serde_json::json!([
                dependency("b", serde_json::Value::Null, &[]),
                dependency("b", serde_json::json!("dev"), &[]),
            ]),
            serde_json::json!({ "default": ["b/testing"] }),
        ),
        host("b", serde_json::json!([]), serde_json::json!({ "testing": [] })),
    ]});
    assert_eq!(
        test_features_in_production(&doubled, Path::new("/w")),
        vec!["a: the testing feature of b is turned on by its default features"]
    );
    // The control: dev dependencies and a testing feature that nothing turns on are fine.
    let fine = serde_json::json!({ "packages": [
        host(
            "a",
            serde_json::json!([dependency("d", serde_json::json!("dev"), &["testing"])]),
            serde_json::json!({ "default": [], "testing": [] }),
        ),
        host("d", serde_json::json!([]), serde_json::json!({ "testing": [] })),
    ]});
    assert!(test_features_in_production(&fine, Path::new("/w")).is_empty());
}

/// A feature for tests is named under any of [`TEST_FEATURES`], and a feature of a host crate that
/// neither list names is found, while the product's own, the tests' and `default` are not.
#[test]
fn a_feature_for_tests_is_named_whatever_it_is_called_and_an_unnamed_one_is_found() {
    let package = |name: &str, dependencies: serde_json::Value, features: serde_json::Value| {
        serde_json::json!({
            "name": name,
            "manifest_path": format!("/w/crates/{name}/Cargo.toml"),
            "dependencies": dependencies,
            "features": features,
        })
    };
    let metadata = serde_json::json!({ "packages": [
        package(
            "a",
            serde_json::json!([]),
            serde_json::json!({ "default": ["fault-injection"], "fault-injection": [] }),
        ),
        package(
            "b",
            serde_json::json!([{
                "name": "c",
                "kind": null,
                "features": ["git-fixtures"],
                "uses_default_features": true,
            }]),
            serde_json::json!({}),
        ),
        package("c", serde_json::json!([]), serde_json::json!({ "git-fixtures": [] })),
        package(
            "kr-client",
            serde_json::json!([]),
            serde_json::json!({ "default": ["terminal"], "terminal": [], "testing": [] }),
        ),
        package(
            "d",
            serde_json::json!([]),
            serde_json::json!({ "default": [], "hooks": [], "terminal": [] }),
        ),
    ]});
    let named = test_features_in_production(&metadata, Path::new("/w"));
    let says = |named: &str, crate_name: &str, feature: &str, how: &str| {
        named.starts_with(&format!("{crate_name}: "))
            && named.contains(feature)
            && named.contains(how)
    };
    assert_eq!(named.len(), 2, "{named:?}");
    assert!(
        says(&named[0], "a", "fault-injection", "default"),
        "{named:?}"
    );
    assert!(
        says(&named[1], "b", "git-fixtures", "dependency on c"),
        "{named:?}"
    );
    assert_eq!(
        unclassified_features(&metadata, Path::new("/w")),
        vec!["d: hooks", "d: terminal"]
    );
}
