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

/// Who may name an item, as its `pub` says.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Visibility {
    /// No `pub`, or `pub(self)`: its own module and the modules inside it.
    #[default]
    Private,
    /// `pub(super)`: its module's parent and everything inside that.
    Parent,
    /// `pub` or `pub(crate)`: the whole crate.
    Crate,
    /// `pub(in <path>)`, which this reading does not work out.
    Restricted,
}

/// The visibility the tokens before an item's keyword give it.
fn visibility(tokens: &[Token]) -> Visibility {
    let Some(at) = tokens.iter().position(|token| token.ident() == Some("pub")) else {
        return Visibility::Private;
    };
    if !tokens.get(at + 1).is_some_and(|token| token.is_punct('(')) {
        return Visibility::Crate;
    }
    match tokens.get(at + 2).and_then(Token::ident) {
        Some("crate") => Visibility::Crate,
        Some("super") => Visibility::Parent,
        Some("self") => Visibility::Private,
        _ => Visibility::Restricted,
    }
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
    /// `shellpkg::helper()` is `[shellpkg, helper]`. A method call, a macro, a name that is not
    /// called and a call whose first name the body may bind for itself are left out.
    pub calls: BTreeSet<Vec<String>>,
    /// The names its body's own `use` declarations bring in.
    pub imports: Vec<Import>,
    /// Who may name it.
    pub visibility: Visibility,
}

/// One name, or every name of a module, that a `use` declaration brings into scope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Import {
    /// `use a::b::c;` brings `c`, and `use a::b::c as d;` brings `d`: `name` is the item at `path`
    /// (`[a, b, c]`).
    Name {
        /// The name it is known by here.
        name: String,
        /// Its path, as written.
        path: Vec<String>,
    },
    /// `use a::b::*;` brings every name of the module at `path` (`[a, b]`).
    Glob {
        /// The module's path, as written.
        path: Vec<String>,
    },
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
    /// What a `use` declaration brings into its module.
    pub imports: Vec<Import>,
    /// Who may name it.
    pub visibility: Visibility,
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
    /// Whether the attribute is taken to define and bind nothing: the built-in lint, test,
    /// documentation and configuration attributes, the tool attributes, `tokio::test`, which runs a
    /// test's body as written on a runtime, and a `derive` of the standard library's traits, which
    /// adds implementations only. Any other attribute may be a macro that defines items where the
    /// source cannot show them.
    fn inert(&self) -> bool {
        const BUILT_IN: &[&str] = &[
            "allow",
            "cfg",
            "cold",
            "deny",
            "doc",
            "expect",
            "forbid",
            "ignore",
            "inline",
            "must_use",
            "non_exhaustive",
            "repr",
            "should_panic",
            "test",
            "track_caller",
            "warn",
        ];
        const DERIVES: &[&str] = &[
            "Clone",
            "Copy",
            "Debug",
            "Default",
            "Eq",
            "Hash",
            "Ord",
            "PartialEq",
            "PartialOrd",
        ];
        let path: Vec<&str> = self.path.iter().map(String::as_str).collect();
        match path.as_slice() {
            ["derive"] => self
                .arguments
                .iter()
                .filter_map(Token::ident)
                .all(|name| DERIVES.contains(&name)),
            [name] => BUILT_IN.contains(name),
            ["tokio", "test"] | ["rustfmt" | "clippy", ..] => true,
            _ => false,
        }
    }

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
            let opaque = !attributes.iter().all(Attribute::inert);
            let calls =
                body.map_or_else(BTreeSet::new, |(from, to)| calls(&tokens[from..to], opaque));
            let imports = body.map_or_else(Vec::new, |(from, to)| body_imports(&tokens[from..to]));
            Classified::Test(Test {
                name: name.unwrap_or_default(),
                line: tokens[at].line,
                attached,
                inside: comments_in(body),
                uses,
                calls,
                imports,
                visibility: visibility(&tokens[..at]),
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
                imports: Vec::new(),
                visibility: visibility(&tokens[..at]),
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
                imports: if keyword == "use" {
                    let mut found = Vec::new();
                    use_tree(tokens, at + 1, &[], &mut found);
                    found
                } else {
                    Vec::new()
                },
                visibility: visibility(&tokens[..at]),
            })
        }
    }
}

/// The `use` declarations written inside a function's body, each as what it brings in.
fn body_imports(tokens: &[Token]) -> Vec<Import> {
    let mut found = Vec::new();
    for (index, token) in tokens.iter().enumerate() {
        if token.ident() == Some("use") {
            use_tree(tokens, index + 1, &[], &mut found);
        }
    }
    found
}

/// Reads one use tree from `at`: a path, then `*`, a group in braces, or a last name with an
/// optional `as`. Returns where it stopped.
fn use_tree(tokens: &[Token], mut at: usize, prefix: &[String], found: &mut Vec<Import>) -> usize {
    let mut path = prefix.to_vec();
    loop {
        let Some(token) = tokens.get(at) else {
            return at;
        };
        if token.is_punct(':') {
            // The `::` of a path that starts at the crate roots.
            at += 1;
        } else if token.is_punct('*') {
            found.push(Import::Glob { path });
            return at + 1;
        } else if token.is_punct('{') {
            at += 1;
            while tokens.get(at).is_some_and(|token| !token.is_punct('}')) {
                let next = use_tree(tokens, at, &path, found);
                at = if tokens.get(next).is_some_and(|token| token.is_punct(',')) {
                    next + 1
                } else if next == at {
                    // Nothing this reading understands: step over it rather than stop here.
                    at + 1
                } else {
                    next
                };
            }
            return at + 1;
        } else if let Some(segment) = token.ident() {
            let segment = segment.to_owned();
            at += 1;
            if tokens.get(at).is_some_and(|token| token.is_punct(':'))
                && tokens.get(at + 1).is_some_and(|token| token.is_punct(':'))
            {
                path.push(segment);
                at += 2;
                continue;
            }
            let mut name = segment.clone();
            path.push(segment);
            if tokens.get(at).and_then(Token::ident) == Some("as") {
                name = tokens
                    .get(at + 1)
                    .and_then(Token::ident)
                    .unwrap_or("_")
                    .to_owned();
                at += 2;
            }
            // `use a::{self}` brings the module `a` in, by its own name.
            if name == "self" && path.len() > 1 {
                path.pop();
                name = path.last().cloned().unwrap_or_default();
            }
            if name != "_" {
                found.push(Import::Name { name, path });
            }
            return at;
        } else {
            return at;
        }
    }
}

/// Every function call in `tokens`, a function's body, that may reach a function of the module, as
/// the path it is called by.
///
/// A call is a name followed by an opening parenthesis, or by a turbofish and then one, with the
/// `::`-joined names before it as its path. A name after a full stop is a method, a name before `!`
/// is a macro, and the name a definition gives after `fn`, `struct` or `macro_rules!` is what it
/// defines; none of them is a call of a free function.
///
/// A call is resolved from the body's own scope unless its path starts at `crate`, `self` or
/// `super`, and such a call is kept only when nothing in the body can bind its first name:
///
/// * The body shows that name nowhere but in calls and paths. Whatever binds a name in a body
///   shows it in a place no call has: a `let` of any pattern, an `if let` or `while let`, a
///   `match` arm, a `for`, a closure's parameters, a nested function's name or parameters, a
///   nested module, type or constant. So no form of binding needs reading one by one. Where the
///   name shows after a full stop or `::`, or before `::` or `!`, it is a method, a field, part of
///   a path or a macro, which binds nothing, and it does not count; a type annotation that starts
///   at the root (`name: ::std::...`) is no path and counts.
/// * Neither the body nor the test's own attributes invoke a macro but those [`transparent`] names
///   and the attributes [`Attribute::inert`] names, because any other expansion, a derive's or an
///   attribute macro's included, may define an item of that name where the source cannot show it.
///
/// So a call the body may have bound for itself is never taken for a function of the module. A
/// body's `use` declarations are the map's to read.
fn calls(tokens: &[Token], opaque: bool) -> BTreeSet<Vec<String>> {
    let mut found = BTreeSet::new();
    // Every name the body shows other than in a call, a method, a path or a macro.
    let mut elsewhere: BTreeSet<&str> = BTreeSet::new();
    // Whether a macro, the test's own attributes included, may bind a name out of sight.
    let mut opaque = opaque;
    // The end of an attribute being passed over.
    let mut skip_to = 0;
    for (index, token) in tokens.iter().enumerate() {
        if index < skip_to {
            continue;
        }
        if token.is_punct('#') {
            let open =
                index + usize::from(tokens.get(index + 1).is_some_and(|t| t.is_punct('!'))) + 1;
            if tokens.get(open).is_some_and(|t| t.is_punct('['))
                && let Some(close) = matching(tokens, open)
            {
                opaque |= !attribute(&tokens[open + 1..close], token.line).inert();
                skip_to = close + 1;
            }
            continue;
        }
        let Some(name) = token.ident() else {
            continue;
        };
        let punct_before = |back: usize, c: char| {
            index
                .checked_sub(back)
                .is_some_and(|at| tokens[at].is_punct(c))
        };
        let punct_after = |ahead: usize, c: char| {
            tokens
                .get(index + ahead)
                .is_some_and(|token| token.is_punct(c))
        };
        if punct_before(1, '.') {
            continue;
        }
        if punct_after(1, '!') && ['(', '[', '{'].into_iter().any(|c| punct_after(2, c)) {
            opaque |= !transparent(&path_to(tokens, index).0);
            continue;
        }
        let before = index.checked_sub(1).and_then(|at| tokens[at].ident());
        let defined = matches!(before, Some("fn" | "struct"))
            || (punct_before(1, '!')
                && index.checked_sub(2).and_then(|at| tokens[at].ident()) == Some("macro_rules"));
        if !defined && called_after(tokens, index + 1) {
            let (path, start) = path_to(tokens, index);
            if start > 0 && tokens[start - 1].is_punct('.') {
                continue;
            }
            found.insert(path);
        } else if !(punct_before(1, ':') && punct_before(2, ':'))
            && !(punct_after(1, ':') && punct_after(2, ':') && !punct_after(3, ':'))
            && !punct_after(1, '!')
        {
            elsewhere.insert(name);
        }
    }
    found.retain(|path| {
        matches!(path[0].as_str(), "crate" | "self" | "super")
            || !(opaque || elsewhere.contains(path[0].as_str()))
    });
    found
}

/// The path that ends at the name at `index`, the name and the `segment ::` pairs before it, and
/// the index of its first segment.
fn path_to(tokens: &[Token], index: usize) -> (Vec<String>, usize) {
    let mut path: Vec<String> = tokens[index]
        .ident()
        .map(str::to_owned)
        .into_iter()
        .collect();
    let mut at = index;
    while at >= 3
        && tokens[at - 1].is_punct(':')
        && tokens[at - 2].is_punct(':')
        && let Some(segment) = tokens[at - 3].ident()
    {
        path.insert(0, segment.to_owned());
        at -= 3;
    }
    (path, at)
}

/// Whether the macro `path` names is taken to bind nothing in a body beyond what its arguments
/// show, and to define no item a test's helper could be named after: the standard library's
/// macros that expand to an expression or to items named in their arguments, by name or by their
/// `std`, `core` or `alloc` path, and the pinned crates' of that kind the tests invoke by path.
fn transparent(path: &[String]) -> bool {
    const STANDARD: &[&str] = &[
        "assert",
        "assert_eq",
        "assert_ne",
        "cfg",
        "column",
        "compile_error",
        "concat",
        "dbg",
        "debug_assert",
        "debug_assert_eq",
        "debug_assert_ne",
        "env",
        "eprint",
        "eprintln",
        "file",
        "format",
        "format_args",
        "include_bytes",
        "include_str",
        "line",
        "matches",
        "module_path",
        "option_env",
        "panic",
        "print",
        "println",
        "stringify",
        "thread_local",
        "todo",
        "unimplemented",
        "unreachable",
        "vec",
        "write",
        "writeln",
    ];
    const BY_PATH: &[&str] = &[
        "core::mem::offset_of",
        "core::pin::pin",
        "rusqlite::params",
        "serde_json::json",
        "std::mem::offset_of",
        "std::pin::pin",
        "tokio::join",
        "tokio::pin",
        "tokio::select",
        "tokio::try_join",
    ];
    match path {
        [name] => STANDARD.contains(&name.as_str()),
        [root, name] if matches!(root.as_str(), "std" | "core" | "alloc") => {
            STANDARD.contains(&name.as_str())
        }
        _ => BY_PATH.contains(&path.join("::").as_str()),
    }
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
    fn an_items_visibility_is_read_from_its_pub() {
        let read = |text: &str| visibility(&lex(text).expect("lexes"));
        assert_eq!(read(""), Visibility::Private);
        assert_eq!(read("pub"), Visibility::Crate);
        assert_eq!(read("pub(crate)"), Visibility::Crate);
        assert_eq!(read("pub(super)"), Visibility::Parent);
        assert_eq!(read("pub(self)"), Visibility::Private);
        assert_eq!(read("pub(in crate::a)"), Visibility::Restricted);
    }

    #[test]
    fn a_use_declaration_is_read_as_the_names_it_brings_in() {
        let tokens =
            lex("use a::b::{self as _, c, d as e, f::*}; use ::g; use super::h;").expect("lexes");
        let found = body_imports(&tokens);
        let name = |name: &str, path: &[&str]| Import::Name {
            name: name.to_owned(),
            path: path.iter().map(|segment| (*segment).to_owned()).collect(),
        };
        assert_eq!(
            found,
            [
                name("c", &["a", "b", "c"]),
                name("e", &["a", "b", "d"]),
                Import::Glob {
                    path: vec!["a".to_owned(), "b".to_owned(), "f".to_owned()]
                },
                name("g", &["g"]),
                name("h", &["super", "h"]),
            ]
        );
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
    fn a_name_the_body_binds_for_itself_is_no_call_of_a_function_of_the_module() {
        let read = |body: &str| calls(&lex(body).expect("lexes"), false);
        let shared = vec!["shared".to_owned()];
        for body in [
            "let shared = || 1; shared();",
            "let mut shared = || 1; shared();",
            "let (shared,) = (|| 1,); shared();",
            "let Pair { first: shared, .. } = pair; shared();",
            "let [shared] = [|| 1]; shared();",
            "let ref shared = other; shared();",
            "if let Some(shared) = maybe { shared(); }",
            "while let Some(shared) = next() { shared(); }",
            "match maybe { Some(shared) => shared(), None => 0 };",
            "for shared in all { shared(); }",
            "let run = |shared: fn()| shared();",
            "all.iter().for_each(|shared| shared());",
            "fn shared() {} shared();",
            "fn inner(shared: fn()) { shared() }",
            "struct shared(u8); shared(1);",
            "const shared: fn() = other; shared();",
            "let shared: ::std::boxed::Box<dyn Fn()> = Box::new(|| {}); shared();",
            "let run = |shared: ::std::boxed::Box<dyn Fn()>| shared();",
            // A macro other than those taken to bind nothing out of sight may define it.
            "defines_it!(); shared();",
            "shared!(1); shared();",
            "helpers::defines_it! {} shared();",
            "include!(\"cases.rs\"); shared();",
            "std::include!(\"cases.rs\"); shared();",
            // So may an attribute macro or a derive other than the standard library's.
            "#[make_shared] struct Fixture; shared();",
            "#[derive(Debug, helpers::Shared)] struct Fixture; shared();",
            "#[cfg_attr(unix, make_shared)] fn inner() {} shared();",
            "#![make_shared] shared();",
        ] {
            assert!(!read(body).contains(&shared), "{body}: {:?}", read(body));
        }
        // The same holds for the first name of a path, which a nested module or type can bind.
        let nested = vec!["cases".to_owned(), "brought_up".to_owned()];
        for body in [
            "mod cases { pub fn brought_up() {} } cases::brought_up();",
            "enum cases {} cases::brought_up();",
            "defines_it!(); cases::brought_up();",
        ] {
            assert!(!read(body).contains(&nested), "{body}: {:?}", read(body));
        }
        assert!(read("cases::brought_up();").contains(&nested));
        // A path that starts at the crate, the module or its parent passes over the body's scope.
        let anchored = read(
            "defines_it!(); let shared = 1; crate::shared(); self::shared(); super::shared();",
        );
        for root in ["crate", "self", "super"] {
            assert!(
                anchored.contains(&vec![root.to_owned(), "shared".to_owned()]),
                "{root}: {anchored:?}"
            );
        }
        // What a definition names is no call of it.
        for body in [
            "fn shared() {}",
            "struct shared(u8);",
            "macro_rules! shared (() => {});",
        ] {
            assert!(!read(body).contains(&shared), "{body}: {:?}", read(body));
        }
        // A method, a segment of a path, a `use` declaration's included, and a turbofish bind
        // nothing in the body.
        for body in [
            "value.shared(); shared();",
            "let f = other::shared; shared();",
            "shared::inner(); shared();",
            "use other::shared as renamed; shared();",
            "shared(); shared(2);",
            "let f = shared::<u8>; shared();",
            // The standard library's macros and the pinned crates' taken by path bind nothing out
            // of sight.
            "assert_eq!(shared(), 1); println!(\"{}\", 1);",
            "let v = vec![1]; std::println!(\"{v:?}\"); shared();",
            "let value = serde_json::json!({ \"a\": 1 }); shared();",
            "tokio::select! { _ = first => {} } shared();",
            "let pinned = std::pin::pin!(future); shared();",
            // Built-in and tool attributes, and a derive of the standard library's traits, bind
            // nothing either.
            "#![allow(unused)] #[derive(Debug, Clone)] struct Fixture; shared();",
            "#[cfg(unix)] #[rustfmt::skip] let x = 1; #[expect(clippy::no_effect)] shared();",
        ] {
            assert!(read(body).contains(&shared), "{body}: {:?}", read(body));
        }
    }

    #[test]
    fn a_test_whose_own_attributes_may_be_macros_keeps_only_the_calls_that_pass_over_its_body() {
        let modules = scan_text(
            "#[tokio::test(flavor = \"multi_thread\")]\n#[ignore = \"needs a device\"]\nasync fn plain() { shared(); }\n\n#[test]\n#[make_shared]\nfn wrapped() { shared(); crate::shared(); }\n",
            true,
        );
        let tests = tests_of(&modules[0]);
        let shared = vec!["shared".to_owned()];
        assert!(tests[0].calls.contains(&shared), "{:?}", tests[0].calls);
        assert!(!tests[1].calls.contains(&shared), "{:?}", tests[1].calls);
        assert!(
            tests[1]
                .calls
                .contains(&vec!["crate".to_owned(), "shared".to_owned()]),
            "{:?}",
            tests[1].calls
        );
    }

    #[test]
    fn a_test_records_what_its_body_uses() {
        let modules = scan_text("#[test]\nfn uses_the_table() { check(CASES); }\n", true);
        assert!(tests_of(&modules[0])[0].uses.contains("CASES"));
    }
}
