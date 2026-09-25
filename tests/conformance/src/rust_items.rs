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
    /// called and a call whose first name the body may bind for itself are left out, and so is
    /// every call of a body a macro or attribute this reading cannot see into may rewrite.
    pub calls: BTreeSet<Vec<String>>,
    /// The macro and attribute names the reading of it took on trust as the standard library's (or,
    /// for `tokio::test`, as the Tokio crate's, written `tokio::`): its calls are proved only while
    /// its target neither defines nor imports any of them.
    pub assumes: BTreeSet<String>,
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
    /// Whether an attribute of its own may be a macro that rewrites it.
    pub rewritable: bool,
    /// Whether a `cfg` or `cfg_attr` of its own may leave it out of a build.
    pub conditional: bool,
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
    /// The macros a `macro_rules!` anywhere in its file defines, by name, those inside functions
    /// included: a file's top module holds them all.
    pub macros: Vec<String>,
    /// The macros a `macro_rules!` written in the arguments of a standard macro whose arguments
    /// are no code (`stringify!(macro_rules! ...)`) would define: text, unless the target gives
    /// that macro's name another meaning.
    pub macros_in_text: Vec<String>,
    /// Whether it brings in names its source does not list: an item under `#[macro_use]`, an
    /// `extern crate`, a macro invoked among its items, or an item under an attribute that may be
    /// a macro, whose expansion may define anything.
    pub unlisted_names: bool,
    /// The names the attributes of its items are taken on trust by, for the map to hold against
    /// what the target defines and imports.
    pub assumes: BTreeSet<String>,
    /// Whether an attribute on it, on the `mod` that declares it or on an enclosing module's, may be
    /// a macro that rewrites everything in it.
    pub rewritable: bool,
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
            rewritable: false,
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
    rewritable: bool,
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
        (module.test_code, module.rewritable),
        &module.directory,
        &mut parsed,
    );
    if let Some(Parsed::Module(top)) = parsed.first_mut() {
        (top.macros, top.macros_in_text) = macro_definitions(&tokens);
    }
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
                        rewritable: declaration.rewritable,
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
    rewritable: bool,
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
    /// The names this attribute is taken on trust by, when it leaves what it is on as written, and
    /// `None` when it may rewrite or add to it. The built-in attributes, whose names no macro may
    /// take, need no trust. The `rustfmt` and `clippy` tool attributes are trusted by their roots,
    /// `#[test]` and `#[derive]` are macros of the standard library's prelude, a derive of the
    /// standard library's traits adds implementations only, serde's derives put all they add
    /// inside an unnamed constant and read their `#[serde(...)]` helpers, and `#[tokio::test]` runs
    /// the test's block as written on a runtime; each is trusted by the names it is known by
    /// (`serde::` and `tokio::` for the crates), which the map holds against what the target
    /// defines and imports and what the package depends on. Any other attribute may be a macro
    /// that rewrites what it is on.
    fn trusted(&self) -> Option<Vec<String>> {
        const BUILT_IN: &[&str] = &[
            "allow",
            "cfg",
            "cold",
            "deny",
            "deprecated",
            "doc",
            "expect",
            "forbid",
            "ignore",
            "inline",
            "macro_export",
            "macro_use",
            "must_use",
            "non_exhaustive",
            "path",
            "recursion_limit",
            "repr",
            "should_panic",
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
            [name] if BUILT_IN.contains(name) => Some(Vec::new()),
            [root @ ("rustfmt" | "clippy"), ..] => Some(vec![format!("{root}::")]),
            ["test"] => Some(vec!["test".to_owned()]),
            ["tokio", "test"] => Some(vec!["tokio::".to_owned()]),
            // A derive helper of serde's, which its derive reads and nothing expands.
            ["serde"] => Some(vec!["serde::".to_owned()]),
            ["derive"] => {
                let mut names = vec!["derive".to_owned()];
                for derived in self.arguments.split(|token| token.is_punct(',')) {
                    let derived: Vec<&str> = derived.iter().filter_map(Token::ident).collect();
                    match derived.as_slice() {
                        [] => {}
                        [name] if DERIVES.contains(name) => names.push((*name).to_owned()),
                        [name] if SERDE_DERIVES.contains(name) => {
                            names.push((*name).to_owned());
                            names.push("serde::".to_owned());
                        }
                        ["serde", name] if SERDE_DERIVES.contains(name) => {
                            names.push("serde::".to_owned());
                        }
                        _ => return None,
                    }
                }
                Some(names)
            }
            _ => None,
        }
    }

    /// Whether the attribute is a built-in one, which no macro may take the name of, and so leaves
    /// a module or an item as written with nothing taken on trust.
    fn inert(&self) -> bool {
        self.trusted().is_some_and(|names| names.is_empty())
    }

    /// Whether it is a `cfg` or a `cfg_attr`, which may leave what it is on out of a build.
    fn is_conditional(&self) -> bool {
        matches!(self.path.as_slice(), [name] if name == "cfg" || name == "cfg_attr")
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

/// Reads one module's tokens; `(test_code, rewritable)` say whether it is test code and whether an
/// attribute on it or an enclosing module may rewrite it.
fn parse_module(
    tokens: &[Token],
    context: &Context,
    path: &[String],
    (test_code, rewritable): (bool, bool),
    directory: &Path,
    out: &mut Vec<Parsed>,
) {
    let mut module = Module {
        path: path.to_vec(),
        file: context.relative.clone(),
        test_code,
        docs: Vec::new(),
        entries: Vec::new(),
        macros: Vec::new(),
        macros_in_text: Vec::new(),
        unlisted_names: false,
        assumes: BTreeSet::new(),
        rewritable,
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
                let after = next_significant(tokens, at + 1);
                let inner = after.is_some_and(|next| tokens[next].is_punct('!'));
                let open = if inner {
                    after.and_then(|bang| next_significant(tokens, bang + 1))
                } else {
                    after
                };
                let Some((open, close)) = open
                    .filter(|&open| tokens[open].is_punct('['))
                    .and_then(|open| matching(tokens, open).map(|close| (open, close)))
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
                    module.rewritable |= !attribute.inert();
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
                let structure = significant(item);
                let keyword = head(&structure);
                let word = |offset: usize| structure.get(keyword + offset).and_then(Token::ident);
                let punct = |offset: usize, c: char| {
                    structure
                        .get(keyword + offset)
                        .is_some_and(|t| t.is_punct(c))
                };
                let opens = |offset: usize| ['(', '[', '{'].into_iter().any(|c| punct(offset, c));
                let definition = word(0) == Some("macro_rules")
                    && punct(1, '!')
                    && word(2).is_some()
                    && opens(3);
                let invoked = structure
                    .get(keyword..)
                    .and_then(|rest| {
                        rest.iter()
                            .position(|t| !t.is_punct(':') && t.ident().is_none())
                    })
                    .is_some_and(|stop| stop > 0 && punct(stop, '!'));
                module.unlisted_names |= (invoked && !definition)
                    || (word(0) == Some("extern") && word(1) == Some("crate"))
                    || attributes.iter().any(|a| a.path == ["macro_use"]);
                // An attribute macro or a derive on an item may add items beside it.
                for attribute in &attributes {
                    match attribute.trusted() {
                        Some(names) => module.assumes.extend(names),
                        None => module.unlisted_names = true,
                    }
                }
                let rewrites = module.rewritable || attributes.iter().any(|a| !a.inert());
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
                            (test_code || cfg_test, rewrites),
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
                            rewritable: rewrites,
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
    let tokens = &significant(tokens);
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
    let keyword = item_keyword(tokens, start);
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
/// The keyword of the item that starts at `start`: the first name after its visibility (however
/// long a `pub(in ...)` path it gives) and its qualifiers, with comments passed over.
fn item_keyword(tokens: &[Token], start: usize) -> Option<&str> {
    let next = |from: usize| next_significant(tokens, from);
    let mut at = next(start)?;
    loop {
        let following = next(at + 1);
        let following_name = following.and_then(|index| tokens[index].ident());
        match tokens[at].ident() {
            Some("pub") => {
                at = following?;
                if tokens[at].is_punct('(') {
                    at = next(matching(tokens, at)? + 1)?;
                }
            }
            Some("default" | "async" | "unsafe" | "safe") => at = following?,
            Some("const")
                if matches!(following_name, Some("fn" | "unsafe" | "async" | "extern")) =>
            {
                at = following?;
            }
            Some("extern") if following_name != Some("crate") => {
                at = following?;
                if matches!(tokens[at].tok, Tok::Str(_)) {
                    at = next(at + 1)?;
                }
            }
            keyword => return keyword,
        }
    }
}

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
    let structure = significant(tokens);
    let at = head(&structure);
    let keyword = structure
        .get(at)
        .and_then(Token::ident)
        .unwrap_or_default()
        .to_owned();
    let name = structure
        .get(at + 1)
        .and_then(Token::ident)
        .map(str::to_owned);
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
            let read = body.map_or_else(Read::default, |(from, to)| {
                calls(&tokens[from..to], attributes)
            });
            let imports = body.map_or_else(Vec::new, |(from, to)| body_imports(&tokens[from..to]));
            Classified::Test(Test {
                name: name.unwrap_or_default(),
                line: structure.get(at).map_or(line, |token| token.line),
                attached,
                inside: comments_in(body),
                uses,
                calls: read.calls,
                assumes: read.assumes,
                imports,
                visibility: visibility(&structure[..at]),
            })
        }
        "mod" => {
            let name = name.unwrap_or_default();
            match body {
                Some((from, to)) if structure.get(at + 2).is_some_and(|t| t.is_punct('{')) => {
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
                visibility: visibility(&structure[..at]),
                rewritable: attributes.iter().any(|a| !a.inert()),
                conditional: attributes.iter().any(Attribute::is_conditional),
            })
        }
        _ => {
            let is_macro = structure.get(at + 1).is_some_and(|t| t.is_punct('!'));
            // A function's inner attributes, at the start of its body, are its own.
            let own_inner = if keyword == "fn" {
                body.map_or_else(Vec::new, |(from, to)| inner_attributes(&tokens[from..to]))
            } else {
                Vec::new()
            };
            let inner = own_inner.iter().any(|a| !a.inert());
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
                    use_tree(&structure, at + 1, &[], &mut found);
                    found
                } else {
                    Vec::new()
                },
                visibility: visibility(&structure[..at]),
                rewritable: inner || attributes.iter().any(|a| !a.inert()),
                conditional: attributes
                    .iter()
                    .chain(&own_inner)
                    .any(Attribute::is_conditional),
            })
        }
    }
}

/// The `use` declarations written inside a function's body, each as what it brings in.
///
/// A macro definition in the body and the arguments of a standard macro that are no code, such as
/// `stringify!`'s, hold no declaration, and are passed over.
fn body_imports(body: &[Token]) -> Vec<Import> {
    let tokens = significant(body);
    let mut found = Vec::new();
    let mut skip_to = 0;
    for (index, token) in tokens.iter().enumerate() {
        if index < skip_to {
            continue;
        }
        let Some(name) = token.ident() else {
            continue;
        };
        if let Some(end) = passed_over(&tokens, index) {
            skip_to = end;
        } else if name == "use" {
            use_tree(&tokens, index + 1, &[], &mut found);
        }
    }
    found
}

/// Where the tokens a reading passes over end, when the name at `index` starts them: a macro
/// definition (`macro_rules! name { ... }`), which runs only where the macro is invoked, or the
/// arguments of a standard macro that are no code ([`NO_CODE`]).
fn passed_over(tokens: &[Token], index: usize) -> Option<usize> {
    let punct = |at: usize, c: char| tokens.get(at).is_some_and(|t| t.is_punct(c));
    let opens = |at: usize| ['(', '[', '{'].into_iter().any(|c| punct(at, c));
    let name = tokens[index].ident()?;
    let open = if name == "macro_rules"
        && punct(index + 1, '!')
        && tokens.get(index + 2).and_then(Token::ident).is_some()
        && opens(index + 3)
    {
        index + 3
    } else if NO_CODE.contains(&name)
        && punct(index + 1, '!')
        && opens(index + 2)
        && !(index >= 2 && punct(index - 1, ':') && punct(index - 2, ':'))
    {
        index + 2
    } else {
        return None;
    };
    Some(matching(tokens, open).map_or(tokens.len(), |close| close + 1))
}

/// A copy of `tokens` without their comments, for reading structure: a comment may stand
/// between any two tokens.
fn significant(tokens: &[Token]) -> Vec<Token> {
    tokens
        .iter()
        .filter(|token| !token.is_comment())
        .cloned()
        .collect()
}

/// The index of the first token from `from` that is not a comment.
fn next_significant(tokens: &[Token], from: usize) -> Option<usize> {
    (from..tokens.len()).find(|&at| !tokens[at].is_comment())
}

/// Every macro a `macro_rules!` in `tokens` defines, by name, wherever it stands; and apart, those
/// written in the arguments of a standard macro whose arguments are no code ([`NO_CODE`]).
fn macro_definitions(tokens: &[Token]) -> (Vec<String>, Vec<String>) {
    let tokens = significant(tokens);
    let mut code = Vec::new();
    let mut text = Vec::new();
    let mut text_to = 0;
    for index in 0..tokens.len() {
        let in_text = index < text_to;
        if !in_text
            && tokens[index].ident() != Some("macro_rules")
            && let Some(end) = passed_over(&tokens, index)
        {
            text_to = end;
            continue;
        }
        if tokens[index].ident() == Some("macro_rules")
            && tokens.get(index + 1).is_some_and(|t| t.is_punct('!'))
            && let Some(name) = tokens.get(index + 2).and_then(Token::ident)
            && tokens
                .get(index + 3)
                .is_some_and(|t| t.is_punct('(') || t.is_punct('[') || t.is_punct('{'))
        {
            let names = if in_text { &mut text } else { &mut code };
            if !names.iter().any(|known| known == name) {
                names.push(name.to_owned());
            }
        }
    }
    (code, text)
}

/// The inner attributes (`#![...]`) a body opens with.
fn inner_attributes(body: &[Token]) -> Vec<Attribute> {
    let tokens = significant(body);
    let mut found = Vec::new();
    let mut at = 0;
    while tokens.get(at).is_some_and(|t| t.is_punct('#'))
        && tokens.get(at + 1).is_some_and(|t| t.is_punct('!'))
        && tokens.get(at + 2).is_some_and(|t| t.is_punct('['))
        && let Some(close) = matching(&tokens, at + 2)
    {
        found.push(attribute(&tokens[at + 3..close], tokens[at].line));
        at = close + 1;
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

/// serde's derives, trusted by name where a `use serde::...` brings them in under their own names.
pub const SERDE_DERIVES: &[&str] = &["Deserialize", "Serialize"];

/// What the reading of a test's body proves it calls, and the names it took on trust to prove it.
#[derive(Debug, Default)]
struct Read {
    calls: BTreeSet<Vec<String>>,
    assumes: BTreeSet<String>,
}

/// The standard library's macros whose arguments run as they are written, as expressions or format
/// arguments, in a scope their expansion adds no name to.
const RUN_AS_WRITTEN: &[&str] = &[
    "assert",
    "assert_eq",
    "assert_ne",
    "dbg",
    "debug_assert",
    "debug_assert_eq",
    "debug_assert_ne",
    "eprint",
    "eprintln",
    "format",
    "format_args",
    "matches",
    "panic",
    "print",
    "println",
    "todo",
    "unimplemented",
    "unreachable",
    "vec",
    "write",
    "writeln",
];

/// The standard library's macros whose arguments are no code that runs: configuration, literals,
/// and `stringify!`, whose tokens become text.
pub const NO_CODE: &[&str] = &[
    "cfg",
    "column",
    "compile_error",
    "concat",
    "env",
    "file",
    "include_bytes",
    "include_str",
    "line",
    "module_path",
    "option_env",
    "stringify",
];

/// Every function call a test's body, `body`, makes that may reach a function of the module, as the
/// path it is called by, with the macro and attribute names the reading took on trust; `attributes`
/// are the test's own.
///
/// A call is a name followed by an opening parenthesis, or by a turbofish and then one, with the
/// `::`-joined names before it as its path. A name after a full stop (not a `..` range) is a
/// method, a name before `!` is a macro, and the name a definition gives after `fn` or `struct` is
/// what it defines; none of them is a call of a free function. Comments are passed over.
///
/// A macro's expansion is out of sight, so a call is proved only where every macro and attribute of
/// the test is known to add no name to, and rewrite nothing of, the code it is on: the standard
/// library's macros by their bare names, [`RUN_AS_WRITTEN`] ones with their arguments read as code
/// and [`NO_CODE`] ones passed over, and the attributes [`Attribute::trusted`] names. The names
/// they are taken on trust by are returned, for the map to hold against what the target defines
/// and imports. Any other macro, a macro the body defines, or any other attribute, in the body or
/// on the test, may rewrite or re-scope any call, so none is kept; so is a `cfg` in the body, which
/// may compile a call out of this platform's build. A macro definition (`macro_rules! name {`, in
/// full) in the body is passed over: it runs only where the macro is invoked. A module the body
/// declares is a scope of its own, and is passed over too.
///
/// A path that starts at `crate`, `self` or `super` passes over the body's own scope. Any other
/// call is kept only when the body shows its first name nowhere but in calls, methods, paths and
/// macro names: whatever binds a name in a body shows it elsewhere, in a `let` of any pattern, an
/// `if let` or `while let`, a `match` arm, a `for`, a closure's or nested function's parameters, a
/// nested function, module, type or constant, or a type annotation, so no form of binding needs
/// reading one by one. A path from the root (`::name`) or after a qualifier (`<T>::name`) is not
/// followed. A body's `use` declarations, and the attributes of the modules around it, are the map's
/// to read.
fn calls(body: &[Token], attributes: &[Attribute]) -> Read {
    let mut read = Read::default();
    for attribute in attributes {
        match attribute.trusted() {
            Some(names) => read.assumes.extend(names),
            None => return Read::default(),
        }
    }
    let tokens: Vec<Token> = body
        .iter()
        .filter(|token| !token.is_comment())
        .cloned()
        .collect();
    let mut found = BTreeSet::new();
    // Every name the body shows other than in a call, a method, a path or a macro.
    let mut elsewhere: BTreeSet<&str> = BTreeSet::new();
    let mut defined_here: BTreeSet<&str> = BTreeSet::new();
    let mut opaque = false;
    let mut skip_to = 0;
    for (index, token) in tokens.iter().enumerate() {
        if index < skip_to {
            continue;
        }
        let punct = |at: Option<usize>, c: char| {
            at.and_then(|at| tokens.get(at))
                .is_some_and(|token| token.is_punct(c))
        };
        let before = |back: usize| index.checked_sub(back);
        let after = |ahead: usize| Some(index + ahead);
        let opens = |at: Option<usize>| ['(', '[', '{'].into_iter().any(|c| punct(at, c));
        if token.is_punct('#') {
            let open = index + if punct(after(1), '!') { 2 } else { 1 };
            if punct(Some(open), '[')
                && let Some(close) = matching(&tokens, open)
            {
                let attribute = attribute(&tokens[open + 1..close], token.line);
                // `cfg` may compile a statement, a call with it, out of this platform's build.
                match attribute.trusted().filter(|_| attribute.path != ["cfg"]) {
                    Some(names) => read.assumes.extend(names),
                    None => opaque = true,
                }
                skip_to = close + 1;
            }
            continue;
        }
        let Some(name) = token.ident() else {
            continue;
        };
        if let Some(end) = passed_over(&tokens, index) {
            if name == "macro_rules" {
                if let Some(defined) = tokens.get(index + 2).and_then(Token::ident) {
                    defined_here.insert(defined);
                }
            } else if defined_here.contains(name) {
                opaque = true;
            } else {
                read.assumes.insert(name.to_owned());
            }
            skip_to = end;
            continue;
        }
        // A module the body declares is a scope of its own, which its calls are resolved from;
        // its name is bound in the body.
        if name == "mod"
            && let Some(declared) = tokens.get(index + 1).and_then(Token::ident)
            && punct(after(2), '{')
        {
            elsewhere.insert(declared);
            skip_to = matching(&tokens, index + 2).map_or(tokens.len(), |close| close + 1);
            continue;
        }
        if punct(after(1), '!') && opens(after(2)) {
            let standard = path_to(&tokens, index).0.len() == 1 && !defined_here.contains(name);
            if standard && RUN_AS_WRITTEN.contains(&name) {
                read.assumes.insert(name.to_owned());
            } else {
                opaque = true;
            }
            continue;
        }
        if punct(before(1), '.') && !punct(before(2), '.') {
            continue;
        }
        let defined = matches!(
            before(1).and_then(|at| tokens[at].ident()),
            Some("fn" | "struct")
        );
        // After `dyn`, `impl` or `?`, `name(...)` is a trait's sugar in a type, not a call.
        let in_type = matches!(
            before(1).and_then(|at| tokens[at].ident()),
            Some("dyn" | "impl")
        ) || punct(before(1), '?');
        if !defined && !in_type && called_after(&tokens, index + 1) {
            let (path, start) = path_to(&tokens, index);
            let led = start.checked_sub(1);
            if punct(led, ':') || (punct(led, '.') && !punct(start.checked_sub(2), '.')) {
                continue;
            }
            found.insert(path);
        } else if !(punct(before(1), ':') && punct(before(2), ':'))
            && !(punct(after(1), ':') && punct(after(2), ':') && !punct(after(3), ':'))
            && !punct(after(1), '!')
        {
            elsewhere.insert(name);
        }
    }
    if !opaque {
        read.calls = found
            .into_iter()
            .filter(|path| {
                matches!(path[0].as_str(), "crate" | "self" | "super")
                    || !elsewhere.contains(path[0].as_str())
            })
            .collect();
    }
    read
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
        let read = |body: &str| calls(&lex(body).expect("lexes"), &[]).calls;
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
            // A macro other than the standard library's by its bare name may define it, or rewrite
            // the call, however the invocation is spelt.
            "defines_it!(); shared();",
            "shared!(1); shared();",
            "helpers::defines_it! {} shared();",
            "defines_it /* a gap */ !(); shared();",
            "defines_it! /* a gap */ (); shared();",
            "let _ = 0..captures!(shared());",
            "include!(\"cases.rs\"); shared();",
            "std::println!(\"x\"); shared();",
            "let value = serde_json::json!({ \"a\": 1 }); shared();",
            "tokio::select! { _ = first => {} } shared();",
            "macro_rules! println { () => {} } println!(); shared();",
            // So may an attribute macro or a derive other than the standard library's.
            "#[make_shared] struct Fixture; shared();",
            "#[derive(Debug, helpers::Shared)] struct Fixture; shared();",
            "#[cfg_attr(unix, make_shared)] fn inner() {} shared();",
            "#![make_shared] shared();",
            "# /* a gap */ [make_shared] struct Fixture; shared();",
            // A raw `r#macro_rules` is an invocation of a macro of that name, not a definition.
            "r#macro_rules!(); shared();",
            // A `cfg` may compile the call out of the build.
            "#[cfg(any())] shared();",
            // After `dyn` or `impl`, the name is a trait's in a type, and the body names it.
            "let _: Option<&dyn shared()> = None; shared();",
            "fn inner(run: impl shared()) {} shared();",
        ] {
            assert!(!read(body).contains(&shared), "{body}: {:?}", read(body));
        }
        // The same holds for the first name of a path, which a nested module or type can bind; and
        // a path from the root or after a qualifier is not followed.
        let nested = vec!["cases".to_owned(), "brought_up".to_owned()];
        for body in [
            "mod cases { pub fn brought_up() {} } cases::brought_up();",
            "enum cases {} cases::brought_up();",
            "defines_it!(); cases::brought_up();",
        ] {
            assert!(!read(body).contains(&nested), "{body}: {:?}", read(body));
        }
        assert!(read("cases::brought_up();").contains(&nested));
        for body in [
            "::cases::brought_up();",
            "Container::<u8>::brought_up();",
            "<Container as Cases>::brought_up();",
        ] {
            assert!(read(body).is_empty(), "{body}: {:?}", read(body));
        }
        // A path that starts at the crate, the module or its parent passes over the body's own
        // bindings, but not a macro or attribute that may rewrite it.
        let anchored = read("let shared = 1; crate::shared(); self::shared(); super::shared();");
        for root in ["crate", "self", "super"] {
            assert!(
                anchored.contains(&vec![root.to_owned(), "shared".to_owned()]),
                "{root}: {anchored:?}"
            );
        }
        assert!(read("in_module!(self::shared()); crate::shared();").is_empty());
        // A module the body declares is a scope of its own: its calls are not the test's to
        // resolve, and its name is bound in the body.
        assert!(
            read("mod inner { fn shared() {} pub fn run() { self::shared(); } } inner::run();")
                .is_empty()
        );
        // What a definition names is no call of it, and a macro the body defines and never
        // invokes calls nothing.
        for body in [
            "fn shared() {}",
            "struct shared(u8);",
            "macro_rules! shared (() => {});",
            "macro_rules! unused { () => { shared() }; }",
        ] {
            assert!(!read(body).contains(&shared), "{body}: {:?}", read(body));
        }
        // A method, a segment of a path, a `use` declaration's included, a turbofish, a range and
        // comments bind nothing in the body, and the standard library's macros and attributes add
        // nothing to it.
        for body in [
            "value.shared(); shared();",
            "let f = other::shared; shared();",
            "shared::inner(); shared();",
            "use other::shared as renamed; shared();",
            "shared(); shared(2);",
            "let f = shared::<u8>; shared();",
            "let r = 0..shared();",
            "/* first */ shared /* then */ ();",
            "assert_eq!(shared(), 1); println!(\"{}\", 1);",
            "let v = vec![1]; println!(\"{v:?}\"); shared();",
            "#![allow(unused)] #[derive(Debug, Clone)] struct Fixture; shared();",
            "#[rustfmt::skip] let x = 1; #[expect(clippy::no_effect)] shared();",
        ] {
            assert!(read(body).contains(&shared), "{body}: {:?}", read(body));
        }
        // The arguments of a macro that are no code are passed over.
        assert!(
            read("let text = stringify!(shared()); let on = cfg!(any(unix, windows));").is_empty()
        );
        // What the reading took on trust is returned with the calls.
        let trusted = calls(
            &lex("assert_eq!(shared(), 1); #[derive(Clone)] struct F; let t = stringify!(x); #[rustfmt::skip] let y = 2;")
                .expect("lexes"),
            &[],
        )
        .assumes;
        let names: BTreeSet<String> = ["assert_eq", "derive", "Clone", "stringify", "rustfmt::"]
            .into_iter()
            .map(str::to_owned)
            .collect();
        assert_eq!(trusted, names);
        // A macro the body defines after invoking it is out of this reading's sight: the name is
        // handed on as trusted, for the map to hold against the target's definitions.
        let later = calls(
            &lex("println!(); shared(); #[macro_export] macro_rules! println { () => {} }")
                .expect("lexes"),
            &[],
        );
        assert!(later.calls.contains(&shared) && later.assumes.contains("println"));
    }

    #[test]
    fn a_test_whose_own_attributes_may_be_macros_keeps_no_call() {
        let modules = scan_text(
            "#[tokio::test(flavor = \"multi_thread\")]\n#[ignore = \"needs a device\"]\nasync fn plain() { shared(); }\n\n#[test]\n#[make_shared]\nfn wrapped() { shared(); crate::shared(); }\n\n#[test]\nfn ordinary() { shared(); }\n",
            true,
        );
        let tests = tests_of(&modules[0]);
        let shared = vec!["shared".to_owned()];
        assert!(tests[0].calls.contains(&shared), "{:?}", tests[0].calls);
        assert_eq!(tests[0].assumes, BTreeSet::from(["tokio::".to_owned()]));
        assert!(tests[1].calls.is_empty(), "{:?}", tests[1].calls);
        assert!(tests[2].calls.contains(&shared), "{:?}", tests[2].calls);
        assert_eq!(tests[2].assumes, BTreeSet::from(["test".to_owned()]));
    }

    #[test]
    fn a_module_records_the_macros_it_defines_and_the_names_it_cannot_list() {
        let modules = scan_text(
            "macro_rules! assert_eq { () => {} }\n#[macro_use]\nmod other {}\n",
            true,
        );
        assert_eq!(modules[0].macros, ["assert_eq"]);
        assert!(modules[0].unlisted_names);
        for text in [
            "extern crate core as other;\nfn plain() {}\n",
            "make_items!();\nfn plain() {}\n",
            "helpers::make_items! { a }\nfn plain() {}\n",
        ] {
            assert!(scan_text(text, true)[0].unlisted_names, "{text}");
        }
        assert!(!scan_text("fn plain() {}\nconst X: u8 = 1;\n", true)[0].unlisted_names);
        // Every definition in the file counts, inside functions and past comments too, and an
        // invocation of a macro named `macro_rules` is none.
        let modules = scan_text(
            "fn f() {\n    #[macro_export]\n    macro_rules! println { () => {} }\n}\nmacro_rules /* a gap */ ! assert_eq { () => {} }\nfn g() { r#macro_rules!(); }\n",
            true,
        );
        assert_eq!(modules[0].macros, ["println", "assert_eq"]);
        // An import is read past comments.
        let modules = scan_text("use std::stringify /* a gap */ as println;\n", true);
        let Entry::Item(item) = &modules[0].entries[0] else {
            panic!("an item: {:?}", modules[0].entries);
        };
        assert_eq!(
            item.imports,
            [Import::Name {
                name: "println".to_owned(),
                path: vec!["std".to_owned(), "stringify".to_owned()],
            }]
        );
    }

    #[test]
    fn a_macro_definition_written_as_text_is_kept_apart() {
        let (code, text) = macro_definitions(
            &lex("let _ = stringify!(macro_rules! println { () => {} }); macro_rules! real { () => {} } std::stringify!(macro_rules! pathed { () => {} });")
                .expect("lexes"),
        );
        assert_eq!(code, ["real", "pathed"]);
        assert_eq!(text, ["println"]);
    }

    #[test]
    fn an_item_ends_where_it_ends_however_long_its_visibility() {
        let path: Vec<String> = (0..30).map(|depth| format!("m{depth}")).collect();
        let text = format!(
            "pub(in crate::{}) const N: i32 = if true {{ 1 }} else {{ 2 }};\nfn next() {{}}\n",
            path.join("::")
        );
        let tokens = lex(&text).expect("lexes");
        let end = item_end(&tokens, 0);
        assert!(tokens[end - 1].is_punct(';'), "{:?}", tokens[end - 1]);
        assert_eq!(tokens[end].ident(), Some("fn"));
    }

    #[test]
    fn an_item_under_a_cfg_of_its_own_is_conditional() {
        let modules = scan_text(
            "#[cfg(unix)]\nfn outer() {}\nfn inner() {\n    #![cfg_attr(unix, allow(unused))]\n}\n#[allow(dead_code)]\nfn plain() {}\n",
            true,
        );
        let conditional = |name: &str| {
            modules[0]
                .entries
                .iter()
                .find_map(|entry| match entry {
                    Entry::Item(item) if item.name.as_deref() == Some(name) => {
                        Some(item.conditional)
                    }
                    _ => None,
                })
                .expect("the item")
        };
        assert!(conditional("outer"));
        assert!(conditional("inner"));
        assert!(!conditional("plain"));
    }

    #[test]
    fn an_attribute_is_trusted_by_the_names_it_is_known_by() {
        let trusted = |text: &str| {
            let tokens = lex(text).expect("lexes");
            attribute(&tokens, 1).trusted()
        };
        let names = |names: &[&str]| -> Option<Vec<String>> {
            Some(names.iter().map(|name| (*name).to_owned()).collect())
        };
        assert_eq!(trusted("allow(unused)"), names(&[]));
        assert_eq!(trusted("test"), names(&["test"]));
        assert_eq!(
            trusted("tokio::test(flavor = \"multi_thread\")"),
            names(&["tokio::"])
        );
        assert_eq!(trusted("rustfmt::skip"), names(&["rustfmt::"]));
        assert_eq!(
            trusted("derive(Debug, Deserialize)"),
            names(&["derive", "Debug", "Deserialize", "serde::"])
        );
        assert_eq!(
            trusted("derive(Clone, serde::Serialize)"),
            names(&["derive", "Clone", "serde::"])
        );
        assert_eq!(trusted("serde(deny_unknown_fields)"), names(&["serde::"]));
        assert_eq!(trusted("derive(Debug, helpers::Generate)"), None);
        assert_eq!(trusted("derive(schemars::JsonSchema)"), None);
        assert_eq!(trusted("cfg_attr(unix, allow(unused))"), None);
        assert_eq!(trusted("make_items"), None);
    }

    #[test]
    fn a_body_imports_nothing_it_writes_as_text_or_in_a_macro_definition() {
        let found = body_imports(
            &lex("let _ = stringify!(use external::*;); macro_rules! m { () => { use hidden::*; } } use other::name;")
                .expect("lexes"),
        );
        assert_eq!(
            found,
            [Import::Name {
                name: "name".to_owned(),
                path: vec!["other".to_owned(), "name".to_owned()],
            }]
        );
    }

    #[test]
    fn an_attribute_that_may_be_a_macro_marks_what_it_may_rewrite() {
        let modules = scan_text(
            "#[rewrite_all]\nmod inside {\n    mod deeper {}\n    fn case() {}\n}\n#[cfg(test)]\n#[path = \"x.rs\"]\nmod plain {}\n#[rename]\nfn renamed() {}\n#[allow(dead_code)]\nfn kept() {}\n",
            true,
        );
        let module = |path: &[&str]| {
            modules
                .iter()
                .find(|module| module.path == path)
                .expect("the module")
        };
        assert!(!module(&[]).rewritable);
        assert!(module(&["inside"]).rewritable);
        assert!(module(&["inside", "deeper"]).rewritable);
        assert!(!module(&["plain"]).rewritable);
        let item = |name: &str| {
            module(&[])
                .entries
                .iter()
                .find_map(|entry| match entry {
                    Entry::Item(item) if item.name.as_deref() == Some(name) => Some(item),
                    _ => None,
                })
                .expect("the item")
        };
        assert!(item("renamed").rewritable);
        assert!(!item("kept").rewritable);
        // Past comments, from an enclosing module's inner attribute, from a function's own inner
        // attribute, and for any attribute that is not built in.
        let modules = scan_text(
            "# /* a gap */ [rewrite_all]\nmod gapped {}\nmod outer {\n    #![rewrite]\n    mod inner {}\n}\nfn inside() {\n    #![rewrite]\n}\nfn plain() {\n    #![allow(unused)]\n}\n#[rustfmt::skip]\nfn formatted() {}\n",
            true,
        );
        let module = |path: &[&str]| {
            modules
                .iter()
                .find(|module| module.path == path)
                .expect("the module")
        };
        assert!(module(&["gapped"]).rewritable);
        assert!(module(&["outer", "inner"]).rewritable);
        let item = |name: &str| {
            module(&[])
                .entries
                .iter()
                .find_map(|entry| match entry {
                    Entry::Item(item) if item.name.as_deref() == Some(name) => Some(item),
                    _ => None,
                })
                .expect("the item")
        };
        assert!(item("inside").rewritable);
        assert!(!item("plain").rewritable);
        assert!(item("formatted").rewritable);
    }

    #[test]
    fn a_test_records_what_its_body_uses() {
        let modules = scan_text("#[test]\nfn uses_the_table() { check(CASES); }\n", true);
        assert!(tests_of(&modules[0])[0].uses.contains("CASES"));
    }
}
