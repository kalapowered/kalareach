//! Rust items and the comments around them, module by module.
//!
//! A target's crate root is read, every `mod` it declares is followed to its file (a `#[path]`
//! attribute included), and each module is turned into an ordered list of what matters to the
//! report: test functions with the comments attached to them and inside them, other items with
//! theirs, and comment blocks that stand on their own and so open a section.
//!
//! A comment is attached to the item that follows it when nothing but attributes and other
//! comments separate them and no blank line does. Documentation comments (`///`, `/** */`) belong
//! to the item that follows whatever lies between, as they do for the compiler. A plain comment
//! block with a blank line after it stands on its own.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use crate::rust_lex::{CommentKind, LexError, Tok, Token, lex};

/// A comment and the line it starts on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Comment {
    /// The first line.
    pub line: usize,
    /// The text, without the comment markers.
    pub text: String,
}

/// A case-table field: the text of the strings a `covers` field holds, and its line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Covers {
    /// The line the field starts on.
    pub line: usize,
    /// The strings the field's value holds, joined by spaces.
    pub text: String,
}

/// What one entry of a module is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Entry {
    /// A test function.
    Test(Test),
    /// Any other item.
    Item(Item),
    /// A comment block that stands on its own, which opens a section.
    Section(Vec<Comment>),
}

/// A test function.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Test {
    /// The function's name.
    pub name: String,
    /// The line of the `fn`.
    pub line: usize,
    /// The comments attached to it.
    pub attached: Vec<Comment>,
    /// The comments inside its body.
    pub inside: Vec<Comment>,
    /// Every identifier its body uses, which is how a case table's consumers are found.
    pub uses: BTreeSet<String>,
    /// Every function its body calls, as the path it is called by: `helper()` is `[helper]` and
    /// `shellpkg::helper()` is `[shellpkg, helper]`. A method call, a macro and a name that is
    /// not called are not calls.
    pub calls: BTreeSet<Vec<String>>,
}

/// Any item that is not a test function.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Item {
    /// `fn`, `const`, `static`, `struct` and so on, or `macro` for an invocation.
    pub kind: String,
    /// Its name, where it has one.
    pub name: Option<String>,
    /// The line it starts on.
    pub line: usize,
    /// The comments attached to it.
    pub attached: Vec<Comment>,
    /// The comments inside it.
    pub inside: Vec<Comment>,
    /// Its `covers` fields, for a `const` or `static` case table.
    pub covers: Vec<Covers>,
}

/// One module: a file, or an inline `mod` block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Module {
    /// The module path within the crate, empty for the crate root.
    pub path: Vec<String>,
    /// The file it is in, relative to the root the scan was given.
    pub file: String,
    /// Whether it is test code: a module of a test or bench target, or one compiled under
    /// `cfg(test)`.
    pub test_code: bool,
    /// Its own documentation (`//!`, `/*! */`, `#![doc = ...]`).
    pub docs: Vec<Comment>,
    /// Its entries, in source order.
    pub entries: Vec<Entry>,
}

/// Why a crate could not be read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScanError {
    /// The file, relative to the scan's root.
    pub file: String,
    /// What went wrong.
    pub what: String,
}

/// A problem that does not stop the scan, such as a module file that is not there.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Warning {
    /// The file that declared it, relative to the scan's root.
    pub file: String,
    /// What was not found.
    pub what: String,
}

/// Reads files once, however many targets include them.
#[derive(Default)]
pub struct Sources {
    lexed: BTreeMap<PathBuf, Vec<Token>>,
}

impl Sources {
    fn tokens(&mut self, path: &Path) -> Result<&[Token], String> {
        if !self.lexed.contains_key(path) {
            let text = std::fs::read_to_string(path).map_err(|error| error.to_string())?;
            let tokens =
                lex(&text).map_err(|LexError { line, what }| format!("line {line}: {what}"))?;
            self.lexed.insert(path.to_owned(), tokens);
        }
        Ok(&self.lexed[path])
    }
}

/// Reads one target's module tree, from its crate root.
///
/// `test_target` says whether every module of it is test code, which is true of test and bench
/// targets.
///
/// # Errors
///
/// Returns the file that could not be read or lexed.
pub fn scan_target(
    sources: &mut Sources,
    root: &Path,
    crate_root: &Path,
    test_target: bool,
) -> Result<(Vec<Module>, Vec<Warning>), ScanError> {
    let mut modules = Vec::new();
    let mut warnings = Vec::new();
    let directory = crate_root.parent().unwrap_or(root).to_owned();
    scan_file(
        sources,
        root,
        crate_root,
        &FileModule {
            path: Vec::new(),
            directory,
            test_code: test_target,
        },
        &mut modules,
        &mut warnings,
    )?;
    Ok((modules, warnings))
}

/// What a module file is being read as.
struct FileModule {
    path: Vec<String>,
    /// The directory its child modules' files are in.
    directory: PathBuf,
    test_code: bool,
}

fn relative(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn scan_file(
    sources: &mut Sources,
    root: &Path,
    file: &Path,
    module: &FileModule,
    modules: &mut Vec<Module>,
    warnings: &mut Vec<Warning>,
) -> Result<(), ScanError> {
    let tokens = sources
        .tokens(file)
        .map_err(|what| ScanError {
            file: relative(root, file),
            what,
        })?
        .to_vec();
    let context = Context {
        file: file.to_owned(),
        relative: relative(root, file),
    };
    let mut parsed = Vec::new();
    parse_module(
        &tokens,
        &context,
        &module.path,
        module.test_code,
        &module.directory,
        &mut parsed,
    );
    for entry in parsed {
        match entry {
            Parsed::Module(scanned) => modules.push(scanned),
            Parsed::Declaration(declaration) => {
                let Some(child) = declaration
                    .candidates
                    .iter()
                    .find(|path| path.is_file())
                    .cloned()
                else {
                    warnings.push(Warning {
                        file: relative(root, file),
                        what: format!(
                            "module {} has no file at {}",
                            declaration.path.join("::"),
                            declaration
                                .candidates
                                .iter()
                                .map(|path| relative(root, path))
                                .collect::<Vec<_>>()
                                .join(" or ")
                        ),
                    });
                    continue;
                };
                let directory = if is_mod_rs(&child) {
                    child.parent().unwrap_or(root).to_owned()
                } else {
                    child.with_extension("")
                };
                scan_file(
                    sources,
                    root,
                    &child,
                    &FileModule {
                        path: declaration.path.clone(),
                        directory,
                        test_code: declaration.test_code,
                    },
                    modules,
                    warnings,
                )?;
            }
        }
    }
    Ok(())
}

fn is_mod_rs(path: &Path) -> bool {
    path.file_name().is_some_and(|name| name == "mod.rs")
}

struct Context {
    file: PathBuf,
    relative: String,
}

/// A `mod name;` to follow.
struct Declaration {
    path: Vec<String>,
    candidates: Vec<PathBuf>,
    test_code: bool,
}

enum Parsed {
    Module(Module),
    Declaration(Declaration),
}

/// One attribute: its path and the tokens of its arguments.
struct Attribute {
    path: Vec<String>,
    arguments: Vec<Token>,
    line: usize,
}

impl Attribute {
    fn is_test(&self) -> bool {
        self.path.last().is_some_and(|last| last == "test")
    }

    fn is_cfg_test(&self) -> bool {
        self.path == ["cfg"]
            && self.arguments.iter().any(|t| t.ident() == Some("test"))
            && !self.arguments.iter().any(|t| t.ident() == Some("not"))
    }

    /// The value of `#[name = "value"]`.
    fn value(&self, name: &str) -> Option<String> {
        if self.path != [name] {
            return None;
        }
        match self.arguments.as_slice() {
            [
                eq,
                Token {
                    tok: Tok::Str(value),
                    ..
                },
            ] if eq.is_punct('=') => Some(value.clone()),
            _ => None,
        }
    }
}

fn parse_module(
    tokens: &[Token],
    context: &Context,
    path: &[String],
    test_code: bool,
    directory: &Path,
    out: &mut Vec<Parsed>,
) {
    let mut module = Module {
        path: path.to_vec(),
        file: context.relative.clone(),
        test_code,
        docs: Vec::new(),
        entries: Vec::new(),
    };
    let mut children = Vec::new();
    let mut pending: Vec<&Token> = Vec::new();
    let mut attributes: Vec<Attribute> = Vec::new();
    let mut at = 0;
    while at < tokens.len() {
        let token = &tokens[at];
        match &token.tok {
            Tok::Comment(CommentKind::InnerDoc, text) => {
                module.docs.push(Comment {
                    line: token.line,
                    text: text.clone(),
                });
                at += 1;
            }
            Tok::Comment(..) => {
                pending.push(token);
                at += 1;
            }
            Tok::Punct('#') => {
                let inner = tokens.get(at + 1).is_some_and(|t| t.is_punct('!'));
                let open = at + if inner { 2 } else { 1 };
                let Some(close) = tokens
                    .get(open)
                    .filter(|t| t.is_punct('['))
                    .and_then(|_| matching(tokens, open))
                else {
                    at += 1;
                    continue;
                };
                let attribute = attribute(&tokens[open + 1..close], token.line);
                if inner {
                    if let Some(text) = attribute.value("doc") {
                        module.docs.push(Comment {
                            line: token.line,
                            text,
                        });
                    }
                    if attribute.is_cfg_test() {
                        module.test_code = true;
                    }
                } else {
                    attributes.push(attribute);
                }
                at = close + 1;
            }
            Tok::Punct(';') if attributes.is_empty() => {
                at += 1;
            }
            _ => {
                let head_line = attributes.first().map_or(token.line, |a| a.line);
                let (sections, attached) = split_pending(&pending, head_line);
                for section in sections {
                    module.entries.push(Entry::Section(section));
                }
                let end = item_end(tokens, at);
                let item = &tokens[at..end];
                let cfg_test = attributes.iter().any(Attribute::is_cfg_test);
                let entry = classify(item, &attributes, attached, token.line);
                match entry {
                    Classified::Test(test) => module.entries.push(Entry::Test(test)),
                    Classified::Item(item) => module.entries.push(Entry::Item(item)),
                    Classified::InlineModule { name, body } => {
                        let mut child_path = path.to_vec();
                        child_path.push(name.clone());
                        let child_directory = directory.join(&name);
                        parse_module(
                            &item[body.0..body.1],
                            context,
                            &child_path,
                            test_code || cfg_test,
                            &child_directory,
                            &mut children,
                        );
                    }
                    Classified::ModuleFile { name } => {
                        let mut child_path = path.to_vec();
                        child_path.push(name.clone());
                        let candidates = if let Some(explicit) =
                            attributes.iter().find_map(|a| a.value("path"))
                        {
                            vec![context.file.parent().unwrap_or(directory).join(explicit)]
                        } else {
                            vec![
                                directory.join(format!("{name}.rs")),
                                directory.join(&name).join("mod.rs"),
                            ]
                        };
                        children.push(Parsed::Declaration(Declaration {
                            path: child_path,
                            candidates,
                            test_code: test_code || cfg_test,
                        }));
                    }
                }
                pending.clear();
                attributes.clear();
                at = end.max(at + 1);
            }
        }
    }
    // What follows the last item stands on its own.
    let (sections, _) = split_pending(&pending, usize::MAX);
    module
        .entries
        .extend(sections.into_iter().map(Entry::Section));
    out.push(Parsed::Module(module));
    out.extend(children);
}

/// Splits the comments before an item into the blocks that stand on their own and the block
/// attached to the item, whose head (its first attribute, or itself) is on `head_line`.
fn split_pending(pending: &[&Token], head_line: usize) -> (Vec<Vec<Comment>>, Vec<Comment>) {
    let mut blocks: Vec<Vec<&Token>> = Vec::new();
    for token in pending {
        match blocks.last_mut() {
            Some(block)
                if block
                    .last()
                    .is_some_and(|last| token.line <= last.end_line + 1) =>
            {
                block.push(token);
            }
            _ => blocks.push(vec![*token]),
        }
    }
    let mut sections = Vec::new();
    let mut attached = Vec::new();
    let count = blocks.len();
    for (index, block) in blocks.into_iter().enumerate() {
        let last = index + 1 == count;
        let adjacent = block
            .last()
            .is_some_and(|t| head_line <= t.end_line + 1 || head_line < t.line);
        let documentation = block
            .iter()
            .all(|t| matches!(t.tok, Tok::Comment(CommentKind::OuterDoc, _)));
        let comments: Vec<Comment> = block
            .iter()
            .filter_map(|t| match &t.tok {
                Tok::Comment(_, text) => Some(Comment {
                    line: t.line,
                    text: text.clone(),
                }),
                _ => None,
            })
            .collect();
        if head_line != usize::MAX && ((last && adjacent) || documentation) {
            attached.extend(comments);
        } else {
            sections.push(comments);
        }
    }
    (sections, attached)
}

/// The index of the token that closes the group opened at `open`.
fn matching(tokens: &[Token], open: usize) -> Option<usize> {
    let mut depth = 0_i64;
    for (index, token) in tokens.iter().enumerate().skip(open) {
        match token.tok {
            Tok::Punct('(' | '[' | '{') => depth += 1,
            Tok::Punct(')' | ']' | '}') => {
                depth -= 1;
                if depth == 0 {
                    return Some(index);
                }
            }
            _ => {}
        }
    }
    None
}

fn attribute(tokens: &[Token], line: usize) -> Attribute {
    let mut path = Vec::new();
    let mut at = 0;
    while let Some(token) = tokens.get(at) {
        if let Some(name) = token.ident() {
            path.push(name.to_owned());
            at += 1;
        } else if token.is_punct(':') {
            at += 1;
        } else {
            break;
        }
    }
    let arguments = match tokens.get(at) {
        Some(open) if open.is_punct('(') => {
            let close = matching(tokens, at).unwrap_or(tokens.len());
            tokens[at + 1..close.min(tokens.len())].to_vec()
        }
        _ => tokens[at..].to_vec(),
    };
    Attribute {
        path,
        arguments,
        line,
    }
}

/// Where the item that starts at `start` ends (exclusive).
fn item_end(tokens: &[Token], start: usize) -> usize {
    let head = head(&tokens[start..]);
    let keyword = tokens.get(start + head).and_then(Token::ident);
    let extern_crate = keyword == Some("extern");
    let ends_at_semicolon =
        extern_crate || matches!(keyword, Some("const" | "static" | "type" | "use"));
    let mut depth = 0_i64;
    let mut at = start;
    while at < tokens.len() {
        match tokens[at].tok {
            Tok::Punct('(' | '[') => depth += 1,
            Tok::Punct(')' | ']') => depth -= 1,
            Tok::Punct('{') => {
                if depth == 0 && !ends_at_semicolon {
                    return matching(tokens, at).map_or(tokens.len(), |close| {
                        // `macro! { ... };` and `struct X {}` never need one, but a stray
                        // semicolon after a braced item is harmless to consume.
                        close + 1
                    });
                }
                depth += 1;
            }
            Tok::Punct('}') => {
                depth -= 1;
                if depth < 0 {
                    return at;
                }
            }
            Tok::Punct(';') if depth == 0 => return at + 1,
            _ => {}
        }
        at += 1;
    }
    tokens.len()
}

/// The index of an item's keyword: past its visibility and its qualifiers. `extern crate` stops at
/// `extern`, which is its keyword.
fn head(tokens: &[Token]) -> usize {
    let mut at = 0;
    while let Some(token) = tokens.get(at) {
        let next = tokens.get(at + 1).and_then(Token::ident);
        match token.ident() {
            Some("pub") => {
                at += 1;
                if tokens.get(at).is_some_and(|t| t.is_punct('(')) {
                    at = matching(tokens, at).map_or(tokens.len(), |close| close + 1);
                }
            }
            Some("default" | "async" | "unsafe" | "safe") => at += 1,
            Some("const") if matches!(next, Some("fn" | "unsafe" | "async" | "extern")) => at += 1,
            Some("extern") if next != Some("crate") => {
                at += 1;
                if matches!(tokens.get(at).map(|t| &t.tok), Some(Tok::Str(_))) {
                    at += 1;
                }
            }
            _ => break,
        }
    }
    at
}

enum Classified {
    Test(Test),
    Item(Item),
    InlineModule { name: String, body: (usize, usize) },
    ModuleFile { name: String },
}

fn classify(
    tokens: &[Token],
    attributes: &[Attribute],
    attached: Vec<Comment>,
    line: usize,
) -> Classified {
    let at = head(tokens);
    let keyword = tokens
        .get(at)
        .and_then(Token::ident)
        .unwrap_or_default()
        .to_owned();
    let name = tokens.get(at + 1).and_then(Token::ident).map(str::to_owned);
    let body = tokens
        .iter()
        .position(|t| t.is_punct('{'))
        .and_then(|open| matching(tokens, open).map(|close| (open + 1, close)));
    let comments_in = |range: Option<(usize, usize)>| -> Vec<Comment> {
        range.map_or_else(Vec::new, |(from, to)| {
            tokens[from..to]
                .iter()
                .filter_map(|t| match &t.tok {
                    Tok::Comment(_, text) => Some(Comment {
                        line: t.line,
                        text: text.clone(),
                    }),
                    _ => None,
                })
                .collect()
        })
    };
    match keyword.as_str() {
        "fn" if attributes.iter().any(Attribute::is_test) => {
            let uses = body.map_or_else(BTreeSet::new, |(from, to)| {
                tokens[from..to]
                    .iter()
                    .filter_map(|t| t.ident().map(str::to_owned))
                    .collect()
            });
            let calls = body.map_or_else(BTreeSet::new, |(from, to)| calls(&tokens[from..to]));
            Classified::Test(Test {
                name: name.unwrap_or_default(),
                line: tokens[at].line,
                attached,
                inside: comments_in(body),
                uses,
                calls,
            })
        }
        "mod" => {
            let name = name.unwrap_or_default();
            match body {
                Some((from, to)) if tokens.get(at + 2).is_some_and(|t| t.is_punct('{')) => {
                    Classified::InlineModule {
                        name,
                        body: (from, to),
                    }
                }
                _ => Classified::ModuleFile { name },
            }
        }
        "const" | "static" => {
            let equals = tokens.iter().position(|t| t.is_punct('='));
            let range = equals.map(|from| (from + 1, tokens.len()));
            Classified::Item(Item {
                kind: keyword.clone(),
                name,
                line,
                attached,
                inside: comments_in(range),
                covers: range.map_or_else(Vec::new, |(from, to)| covers(&tokens[from..to])),
            })
        }
        _ => {
            let is_macro = tokens.get(at + 1).is_some_and(|t| t.is_punct('!'));
            Classified::Item(Item {
                kind: if is_macro {
                    "macro".to_owned()
                } else {
                    keyword.clone()
                },
                name: if is_macro {
                    Some(keyword.clone())
                } else {
                    name
                },
                line,
                attached,
                inside: comments_in(body),
                covers: Vec::new(),
            })
        }
    }
}

/// Every function call in `tokens`, as the path it is called by.
///
/// A call is a name followed by an opening parenthesis, or by a turbofish and then one, with the
/// `::`-joined names before it as its path. A name after a full stop is a method, and a name before
/// `!` is a macro; neither is a call of a free function. A single name that a `let` in the same
/// body binds is a local, a closure say, and calling it calls no function of the module.
fn calls(tokens: &[Token]) -> BTreeSet<Vec<String>> {
    let locals: BTreeSet<&str> = tokens
        .windows(3)
        .filter(|window| window[0].ident() == Some("let"))
        .filter_map(|window| match window[1].ident() {
            Some("mut") => window[2].ident(),
            name => name,
        })
        .collect();
    let mut found = BTreeSet::new();
    for (index, token) in tokens.iter().enumerate() {
        let Some(name) = token.ident() else {
            continue;
        };
        if !called_after(tokens, index + 1) {
            continue;
        }
        let mut path = vec![name.to_owned()];
        let mut at = index;
        // Walk back over `segment ::` pairs.
        while at >= 3
            && tokens[at - 1].is_punct(':')
            && tokens[at - 2].is_punct(':')
            && let Some(segment) = tokens[at - 3].ident()
        {
            path.insert(0, segment.to_owned());
            at -= 3;
        }
        if at > 0 && tokens[at - 1].is_punct('.') {
            continue;
        }
        if path.len() == 1 && locals.contains(name) {
            continue;
        }
        found.insert(path);
    }
    found
}

/// Whether the tokens from `at` open a call's arguments: `(`, or a turbofish `::<...>` and then `(`.
fn called_after(tokens: &[Token], at: usize) -> bool {
    let is = |offset: usize, c: char| tokens.get(at + offset).is_some_and(|t| t.is_punct(c));
    if is(0, '(') {
        return true;
    }
    if !(is(0, ':') && is(1, ':') && is(2, '<')) {
        return false;
    }
    let mut depth = 0usize;
    for (offset, token) in tokens.iter().enumerate().skip(at + 2) {
        if token.is_punct('<') {
            depth += 1;
        } else if token.is_punct('>') {
            depth -= 1;
            if depth == 0 {
                return tokens.get(offset + 1).is_some_and(|t| t.is_punct('('));
            }
        } else if token.is_punct(';') || token.is_punct('{') {
            return false;
        }
    }
    false
}

/// Every `covers:` field in a case table's initialiser, with the strings its value holds.
fn covers(tokens: &[Token]) -> Vec<Covers> {
    let mut found = Vec::new();
    let mut at = 0;
    while at + 1 < tokens.len() {
        if tokens[at].ident() == Some("covers")
            && tokens[at + 1].is_punct(':')
            && !tokens.get(at + 2).is_some_and(|t| t.is_punct(':'))
        {
            let mut depth = 0_i64;
            let mut strings = Vec::new();
            let mut end = at + 2;
            while end < tokens.len() {
                match &tokens[end].tok {
                    Tok::Punct('(' | '[' | '{') => depth += 1,
                    Tok::Punct(')' | ']' | '}') => {
                        depth -= 1;
                        if depth < 0 {
                            break;
                        }
                    }
                    Tok::Punct(',') if depth == 0 => break,
                    Tok::Str(value) => strings.push(value.clone()),
                    _ => {}
                }
                end += 1;
            }
            found.push(Covers {
                line: tokens[at].line,
                text: strings.join(" "),
            });
            at = end;
        } else {
            at += 1;
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan_text(text: &str, test_target: bool) -> Vec<Module> {
        let directory =
            std::env::temp_dir().join(format!("kr-conformance-items-{}", std::process::id()));
        std::fs::create_dir_all(&directory).expect("a directory");
        let file = directory.join(format!("root-{}.rs", text.len()));
        std::fs::write(&file, text).expect("writes");
        let (modules, _) =
            scan_target(&mut Sources::default(), &directory, &file, test_target).expect("scans");
        std::fs::remove_file(&file).expect("removes");
        modules
    }

    fn tests_of(module: &Module) -> Vec<&Test> {
        module
            .entries
            .iter()
            .filter_map(|entry| match entry {
                Entry::Test(test) => Some(test),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn a_documentation_comment_and_an_adjacent_line_comment_are_attached() {
        let modules = scan_text(
            "/// KR-REQ-08.60.\n#[test]\nfn one() {}\n\n// KR-REQ-08.61: adjacent.\n#[tokio::test(flavor = \"multi_thread\")]\nasync fn two() {\n    // KR-REQ-08.62: inside.\n}\n",
            true,
        );
        let tests = tests_of(&modules[0]);
        assert_eq!(tests.len(), 2);
        assert_eq!(tests[0].attached[0].text, " KR-REQ-08.60.");
        assert_eq!(tests[1].attached[0].text, " KR-REQ-08.61: adjacent.");
        assert_eq!(tests[1].inside[0].text, " KR-REQ-08.62: inside.");
    }

    #[test]
    fn a_banner_with_a_blank_line_after_it_opens_a_section() {
        let modules = scan_text(
            "// ----\n// KR-REQ-07.68: the contract\n// ----\n\n#[test]\nfn one() {}\n\n#[test]\nfn two() {}\n",
            true,
        );
        let entries = &modules[0].entries;
        assert!(matches!(&entries[0], Entry::Section(block) if block.len() == 3));
        assert!(matches!(&entries[1], Entry::Test(test) if test.attached.is_empty()));
        assert!(matches!(&entries[2], Entry::Test(_)));
    }

    #[test]
    fn a_cfg_test_module_is_test_code_inside_product_code() {
        let modules = scan_text(
            "//! KR-PERF-003 is what this module keeps idle.\nfn product() {}\n#[cfg(test)]\nmod tests {\n    //! KR-REQ-01.01.\n    #[test]\n    fn inner() {}\n}\n",
            false,
        );
        assert!(!modules[0].test_code);
        let inner = modules
            .iter()
            .find(|m| m.path == ["tests"])
            .expect("the inline module");
        assert!(inner.test_code);
        assert_eq!(inner.docs[0].text, " KR-REQ-01.01.");
        assert_eq!(tests_of(inner)[0].name, "inner");
    }

    #[test]
    fn a_case_table_keeps_the_strings_of_its_covers_fields() {
        let modules = scan_text(
            "pub const CASES: &[Case] = &[\n    Case { id: \"a\", covers: \"KR-REQ-08.16 row text\", input: b\"x\" },\n    // KR-REQ-08.21: queries.\n    Case { id: \"b\", covers: covers(&[\"KR-ACC-001\", \"KR-REQ-08.21\"]), input: b\"y\" },\n];\n",
            false,
        );
        let Entry::Item(item) = &modules[0].entries[0] else {
            panic!("an item: {:?}", modules[0].entries);
        };
        assert_eq!(item.name.as_deref(), Some("CASES"));
        assert_eq!(item.covers.len(), 2);
        assert_eq!(item.covers[1].text, "KR-ACC-001 KR-REQ-08.21");
        assert_eq!(item.inside[0].text, " KR-REQ-08.21: queries.");
    }

    #[test]
    fn a_test_records_the_functions_it_calls_by_their_paths() {
        let modules = scan_text(
            "#[test]\nfn caller() {\n    let shared = 3;\n    let mut local = || 1;\n    helper(shared);\n    local();\n    shellpkg::cases::other(1);\n    generic::<Vec<u8>>(2);\n    value.method(2);\n    println!(\"x\");\n    shared;\n}\n",
            true,
        );
        let calls = &tests_of(&modules[0])[0].calls;
        let expected: BTreeSet<Vec<String>> = [
            vec!["helper".to_owned()],
            vec![
                "shellpkg".to_owned(),
                "cases".to_owned(),
                "other".to_owned(),
            ],
            vec!["generic".to_owned()],
        ]
        .into_iter()
        .collect();
        assert_eq!(calls, &expected);
    }

    #[test]
    fn a_test_records_what_its_body_uses() {
        let modules = scan_text("#[test]\nfn uses_the_table() { check(CASES); }\n", true);
        assert!(tests_of(&modules[0])[0].uses.contains("CASES"));
    }
}
